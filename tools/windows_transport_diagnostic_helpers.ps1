[CmdletBinding()]
param([switch]$SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-WinsAdministrator {
    ([Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WinsPktMon {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $binary = Join-Path $env:SystemRoot 'System32\pktmon.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        return [pscustomobject]@{ exit_code = -1; stdout = ''; stderr = '' }
    }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $binary
    $psi.Arguments = ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' }
        else { $_ }
    }) -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) {
        return [pscustomobject]@{ exit_code = -1; stdout = ''; stderr = '' }
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
        try { $process.Kill() } catch {}
        return [pscustomobject]@{ exit_code = -2; stdout = ''; stderr = '' }
    }
    [pscustomobject]@{
        exit_code = $process.ExitCode
        stdout = $stdout.Result
        stderr = $stderr.Result
    }
}

function Test-WinsPktMonSessionIdle {
    $binary = Join-Path $env:SystemRoot 'System32\logman.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { return $false }
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $binary
    $psi.Arguments = 'query PktMon -ets'
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { return $false }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(10000)) {
        try { $process.Kill() } catch {}
        return $false
    }
    # logman uses its process exit status, not localized prose, to report
    # whether the named real-time ETW session exists. A second PktMon status
    # check below keeps any unexpected logman failure fail-closed.
    $process.ExitCode -ne 0
}

function New-WinsLoopbackCaptureState {
    param([Parameter(Mandatory)][string]$PrivateRoot,
          [ValidateRange(1, 65535)][int]$LocalPort = 42110)
    [ordered]@{
        available = $false
        started = $false
        stopped = $false
        parse_ok = $false
        unavailability_reason = 'not_started'
        port = $LocalPort
        private_root = $PrivateRoot
        etl_path = Join-Path $PrivateRoot 'loopback-udp.etl'
        text_path = Join-Path $PrivateRoot 'loopback-udp.txt'
        filter_owned = $false
    }
}

function Test-WinsPrivateCaptureAcl {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $acl = Get-Acl -LiteralPath $Path
        $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $allowed = @($owner, 'S-1-5-18')
        if (-not $acl.AreAccessRulesProtected -or
            $acl.Owner -notin @($owner,
                [Security.Principal.WindowsIdentity]::GetCurrent().Name)) {
            return $false
        }
        $rules = @($acl.GetAccessRules(
            $true, $true, [Security.Principal.SecurityIdentifier]
        ))
        if ($rules.Count -lt 2) { return $false }
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -notin $allowed -or
                $rule.AccessControlType -ne
                    [Security.AccessControl.AccessControlType]::Allow) {
                return $false
            }
        }
        foreach ($sid in $allowed) {
            if (@($rules | Where-Object {
                $_.IdentityReference.Value -ceq $sid
            }).Count -lt 1) { return $false }
        }
        $true
    } catch { $false }
}

function Start-WinsLoopbackCapture {
    param([Parameter(Mandatory)]$State)
    if (-not (Test-WinsAdministrator)) {
        $State.unavailability_reason = 'elevation_required'
        return
    }
    $binary = Join-Path $env:SystemRoot 'System32\pktmon.exe'
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        $State.unavailability_reason = 'pktmon_unavailable'
        return
    }
    if (-not (Test-WinsPrivateCaptureAcl -Path $State.private_root)) {
        $State.unavailability_reason = 'private_capture_acl_invalid'
        return
    }
    $status = Invoke-WinsPktMon @('status')
    if (-not (Test-WinsPktMonSessionIdle) -or
        $status.exit_code -ne 0 -or
        $status.stdout -notmatch '(?im)\b(?:not\s+running|inactive|stopped)\b') {
        $State.unavailability_reason = 'pktmon_capture_busy_or_unknown'
        return
    }
    $filters = Invoke-WinsPktMon @('filter', 'list')
    if ($filters.exit_code -ne 0 -or
        $filters.stdout -notmatch
            '(?im)^\s*(?:none|no\s+(?:packet\s+)?filters(?:\s+configured)?)\.?\s*$') {
        $State.unavailability_reason = 'pktmon_filters_busy_or_unknown'
        return
    }
    $added = Invoke-WinsPktMon @(
        'filter', 'add', 'WinsVpnXrayLoopback', '-d', 'IPv4', '-t', 'UDP',
        '-i', '127.0.0.1', '-p', [string][int]$State.port
    )
    if ($added.exit_code -ne 0) {
        $State.unavailability_reason = 'pktmon_filter_failed'
        return
    }
    $State.filter_owned = $true
    $started = Invoke-WinsPktMon @(
        'start', '--capture', '--comp', 'all',
        # IPv4 (20 bytes) plus UDP (8 bytes) is sufficient for tuple and
        # datagram-length metadata while retaining zero UDP payload bytes.
        '--pkt-size', '28', '--flags', '0x014', '--file-name',
        [string]$State.etl_path, '--file-size', '32', '--log-mode', 'circular'
    )
    if ($started.exit_code -ne 0) {
        [void](Invoke-WinsPktMon @('filter', 'remove'))
        $State.filter_owned = $false
        $State.unavailability_reason = 'pktmon_start_failed'
        return
    }
    $State.available = $true
    $State.started = $true
    $State.unavailability_reason = ''
}

function ConvertFrom-WinsPktMonLoopbackText {
    param([Parameter(Mandatory)][string[]]$Lines,
          [ValidateRange(1, 65535)][int]$LocalPort = 42110)
    $logical = @{}
    $currentTimestamp = ''
    foreach ($line in $Lines) {
        if ($line -match
            '::(?<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) .*PktGroupId ') {
            $currentTimestamp = $Matches.stamp
            continue
        }
        if ($line -notmatch
            '(?i)127\.0\.0\.1\.(?<source>\d+)\s*>\s*' +
            '127\.0\.0\.1\.(?<destination>\d+):\s*UDP,\s*length\s*' +
            '(?<length>\d+)') {
            continue
        }
        $source = [int]$Matches.source
        $destination = [int]$Matches.destination
        $length = [int]$Matches.length
        if ($source -ne $LocalPort -and $destination -ne $LocalPort) {
            continue
        }
        # PktMon can report the same loopback datagram at multiple stack
        # components with slightly different timestamps. A 10-ms bucket plus
        # the complete local UDP tuple removes those appearances without
        # conflating AWG handshake retries, which are seconds apart.
        $bucket = $currentTimestamp
        $parsed = [DateTime]::MinValue
        if ([DateTime]::TryParseExact(
                $currentTimestamp, 'yyyy-MM-dd HH:mm:ss.fffffff',
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeLocal, [ref]$parsed)) {
            $bucket = [string][Math]::Floor($parsed.Ticks / 100000)
        }
        $key = "$bucket|$source|$destination|$length"
        if (-not $logical.ContainsKey($key)) {
            $logical[$key] = [pscustomobject]@{
                source = $source
                destination = $destination
                length = $length
            }
        }
    }
    $towardXray = @($logical.Values | Where-Object {
        $_.destination -eq $LocalPort
    })
    $fromXray = @($logical.Values | Where-Object {
        $_.source -eq $LocalPort
    })
    $towardHistogram = [ordered]@{}
    foreach ($packet in $towardXray) {
        $key = [string]$packet.length
        if (-not $towardHistogram.Contains($key)) { $towardHistogram[$key] = 0 }
        $towardHistogram[$key]++
    }
    $fromHistogram = [ordered]@{}
    foreach ($packet in $fromXray) {
        $key = [string]$packet.length
        if (-not $fromHistogram.Contains($key)) { $fromHistogram[$key] = 0 }
        $fromHistogram[$key]++
    }
    $initiationPorts = @($towardXray | Where-Object { $_.length -eq 164 } |
        ForEach-Object { $_.source } | Sort-Object -Unique)
    $responsePorts = @($fromXray | Where-Object { $_.length -eq 172 } |
        ForEach-Object { $_.destination } | Sort-Object -Unique)
    $matchingPorts = @($initiationPorts | Where-Object {
        $responsePorts -contains $_
    })
    [ordered]@{
        parse_ok = $true
        logical_packet_count = $logical.Count
        awg_to_xray_packet_count = $towardXray.Count
        xray_to_awg_packet_count = $fromXray.Count
        awg_to_xray_payload_lengths = $towardHistogram
        xray_to_awg_payload_lengths = $fromHistogram
        awg_initiation_164_seen = $initiationPorts.Count -gt 0
        xray_response_172_seen = $responsePorts.Count -gt 0
        response_returned_to_initiating_socket = $matchingPorts.Count -gt 0
        initiating_socket_count = $initiationPorts.Count
        response_socket_count = $responsePorts.Count
    }
}

function Stop-WinsLoopbackCapture {
    param([Parameter(Mandatory)]$State)
    $empty = [ordered]@{
        available = [bool]$State.available
        capture_started = [bool]$State.started
        parse_ok = $false
        unavailability_reason = [string]$State.unavailability_reason
        logical_packet_count = 0
        awg_to_xray_packet_count = 0
        xray_to_awg_packet_count = 0
        awg_to_xray_payload_lengths = [ordered]@{}
        xray_to_awg_payload_lengths = [ordered]@{}
        awg_initiation_164_seen = $false
        xray_response_172_seen = $false
        response_returned_to_initiating_socket = $false
        initiating_socket_count = 0
        response_socket_count = 0
        raw_capture_preserved = $false
        raw_capture_delete_verified = $false
    }
    if ($State.stopped) {
        $empty.raw_capture_preserved = [bool](
            (Test-Path -LiteralPath $State.etl_path) -or
            (Test-Path -LiteralPath $State.text_path)
        )
        $empty.raw_capture_delete_verified = -not $empty.raw_capture_preserved
        return $empty
    }
    $State.stopped = $true
    try {
        if (-not $State.started) { return $empty }
        $stopped = Invoke-WinsPktMon @('stop')
        $State.started = $false
        if ($stopped.exit_code -ne 0) {
            $empty.unavailability_reason = 'pktmon_stop_failed'
            return $empty
        }
        $converted = Invoke-WinsPktMon @(
            'etl2txt', [string]$State.etl_path, '--out',
            [string]$State.text_path, '--timestamp', '--no-ethernet'
        )
        if ($converted.exit_code -ne 0 -or
            -not (Test-Path -LiteralPath $State.text_path -PathType Leaf)) {
            $empty.unavailability_reason = 'pktmon_parse_failed'
            return $empty
        }
        $parsed = ConvertFrom-WinsPktMonLoopbackText -Lines @(
            Get-Content -LiteralPath $State.text_path
        ) -LocalPort ([int]$State.port)
        foreach ($key in $parsed.Keys) { $empty[$key] = $parsed[$key] }
        $empty.unavailability_reason = ''
        $State.parse_ok = $true
        $empty
    } finally {
        if ($State.filter_owned) {
            [void](Invoke-WinsPktMon @('filter', 'remove'))
            $State.filter_owned = $false
        }
        foreach ($path in @($State.text_path, $State.etl_path)) {
            if (Test-Path -LiteralPath $path) {
                try { Remove-Item -LiteralPath $path -Force } catch {}
            }
        }
        $empty.raw_capture_preserved = [bool](
            (Test-Path -LiteralPath $State.etl_path) -or
            (Test-Path -LiteralPath $State.text_path)
        )
        $empty.raw_capture_delete_verified = -not $empty.raw_capture_preserved
    }
}

function Invoke-WinsBoundedProcess {
    param([Parameter(Mandatory)][string]$FileName,
          [Parameter(Mandatory)][string]$Arguments,
          [ValidateRange(1000, 60000)][int]$TimeoutMilliseconds = 30000)
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FileName
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    if (-not $process.Start()) { return -1 }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMilliseconds)) {
        try { $process.Kill() } catch {}
        return -2
    }
    $process.ExitCode
}

function New-WinsKernelNetworkCaptureState {
    param([Parameter(Mandatory)][string]$PrivateRoot,
          [ValidateRange(1, 65535)][int]$LocalPort = 42110)
    [ordered]@{
        available = $false
        started = $false
        stopped = $false
        unavailability_reason = 'not_started'
        private_root = $PrivateRoot
        port = $LocalPort
        session_name = 'WinsVpnTransport-' + [Guid]::NewGuid().ToString('N')
        etl_path = Join-Path $PrivateRoot 'kernel-network.etl'
        xml_path = Join-Path $PrivateRoot 'kernel-network.xml'
    }
}

function Get-WinsAdapterStatisticsSnapshot {
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
    if ($adapters.Count -ne 1) {
        return [ordered]@{ query_ok = $false }
    }
    $statistics = @(Get-NetAdapterStatistics -Name 'winsvpn' `
        -ErrorAction SilentlyContinue)
    if ($statistics.Count -ne 1) {
        return [ordered]@{ query_ok = $false }
    }
    $result = [ordered]@{ query_ok = $true }
    foreach ($name in @(
        'ReceivedBytes', 'SentBytes', 'ReceivedUnicastPackets',
        'SentUnicastPackets', 'ReceivedDiscardedPackets',
        'OutboundDiscardedPackets', 'ReceivedPacketErrors',
        'OutboundPacketErrors'
    )) {
        $property = $statistics[0].PSObject.Properties[$name]
        if (-not $property -or $null -eq $property.Value) {
            return [ordered]@{ query_ok = $false }
        }
        $result[$name] = [uint64]$property.Value
    }
    $result
}

function Get-WinsAdapterStatisticsDelta {
    param($Before, $After)
    $result = [ordered]@{
        before_query_ok = [bool]($Before -and $Before.query_ok)
        after_query_ok = [bool]($After -and $After.query_ok)
        received_bytes_delta = 0
        sent_bytes_delta = 0
        received_unicast_packets_delta = 0
        sent_unicast_packets_delta = 0
        received_discarded_packets_delta = 0
        outbound_discarded_packets_delta = 0
        received_packet_errors_delta = 0
        outbound_packet_errors_delta = 0
        inbound_traffic_advanced = $false
        outbound_traffic_advanced = $false
    }
    if (-not $result.before_query_ok -or -not $result.after_query_ok) {
        return $result
    }
    $mapping = [ordered]@{
        received_bytes_delta = 'ReceivedBytes'
        sent_bytes_delta = 'SentBytes'
        received_unicast_packets_delta = 'ReceivedUnicastPackets'
        sent_unicast_packets_delta = 'SentUnicastPackets'
        received_discarded_packets_delta = 'ReceivedDiscardedPackets'
        outbound_discarded_packets_delta = 'OutboundDiscardedPackets'
        received_packet_errors_delta = 'ReceivedPacketErrors'
        outbound_packet_errors_delta = 'OutboundPacketErrors'
    }
    foreach ($outputName in $mapping.Keys) {
        $propertyName = $mapping[$outputName]
        $result[$outputName] = [uint64][Math]::Max(
            0, [int64]$After[$propertyName] - [int64]$Before[$propertyName]
        )
    }
    $result.inbound_traffic_advanced =
        $result.received_bytes_delta -gt 0 -or
        $result.received_unicast_packets_delta -gt 0
    $result.outbound_traffic_advanced =
        $result.sent_bytes_delta -gt 0 -or
        $result.sent_unicast_packets_delta -gt 0
    $result
}

function Get-WinsBestRouteSelection {
    param([Parameter(Mandatory)][Net.IPAddress]$ExpectedClient,
          [Parameter(Mandatory)][Net.IPAddress]$Gateway)
    $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
    $adapterIndex = if ($adapter.Count -eq 1 -and
        $adapter[0].PSObject.Properties['ifIndex']) {
        [int]$adapter[0].PSObject.Properties['ifIndex'].Value
    } else { -1 }
    function Get-Selection {
        param([Parameter(Mandatory)][string]$Target)
        $records = @(Find-NetRoute -RemoteIPAddress $Target `
            -ErrorAction SilentlyContinue)
        $route = @($records | Where-Object {
            $_.CimClass -and $_.CimClass.CimClassName -ceq 'MSFT_NetRoute'
        })
        $source = @($records | Where-Object {
            $_.CimClass -and
            $_.CimClass.CimClassName -ceq 'MSFT_NetIPAddress'
        })
        $routeIndexProperty = if ($route.Count -eq 1) {
            $route[0].PSObject.Properties['InterfaceIndex']
        } else { $null }
        $sourceIndexProperty = if ($source.Count -eq 1) {
            $source[0].PSObject.Properties['InterfaceIndex']
        } else { $null }
        $sourceAddressProperty = if ($source.Count -eq 1) {
            $source[0].PSObject.Properties['IPAddress']
        } else { $null }
        $queryOk = $adapterIndex -gt 0 -and $routeIndexProperty -and
            $sourceIndexProperty -and $sourceAddressProperty
        [ordered]@{
            query_ok = [bool]$queryOk
            interface_index_matches_winsvpn = [bool]($queryOk -and
                [int]$routeIndexProperty.Value -eq $adapterIndex -and
                [int]$sourceIndexProperty.Value -eq $adapterIndex)
            selected_source_matches_config = [bool]($queryOk -and
                [string]$sourceAddressProperty.Value -ceq
                    $ExpectedClient.ToString())
        }
    }
    [ordered]@{
        gateway = Get-Selection -Target $Gateway.ToString()
        public_ipv4 = Get-Selection -Target '9.9.9.9'
    }
}

function Start-WinsKernelNetworkCapture {
    param([Parameter(Mandatory)]$State)
    if (-not (Test-WinsAdministrator)) {
        $State.unavailability_reason = 'elevation_required'
        return
    }
    if (-not (Test-WinsPrivateCaptureAcl -Path $State.private_root)) {
        $State.unavailability_reason = 'private_capture_acl_invalid'
        return
    }
    $logman = Join-Path $env:SystemRoot 'System32\logman.exe'
    $tracerpt = Join-Path $env:SystemRoot 'System32\tracerpt.exe'
    if (-not (Test-Path -LiteralPath $logman -PathType Leaf) -or
        -not (Test-Path -LiteralPath $tracerpt -PathType Leaf)) {
        $State.unavailability_reason = 'etw_tools_unavailable'
        return
    }
    $query = Invoke-WinsBoundedProcess -FileName $logman -Arguments (
        'query "' + $State.session_name + '" -ets'
    ) -TimeoutMilliseconds 10000
    if ($query -eq 0) {
        $State.unavailability_reason = 'private_etw_session_collision'
        return
    }
    # Keyword 0x10 is IPv4 metadata. This provider records PID, size, tuple,
    # sequence and connection identifiers; it does not record packet payload.
    $arguments = 'start "' + $State.session_name + '" -p ' +
        'Microsoft-Windows-Kernel-Network 0x10 4 -o "' +
        $State.etl_path + '" -ets'
    if ((Invoke-WinsBoundedProcess -FileName $logman -Arguments $arguments) -ne
            0) {
        $State.unavailability_reason = 'kernel_network_etw_start_failed'
        return
    }
    $State.available = $true
    $State.started = $true
    $State.unavailability_reason = ''
}

function ConvertFrom-WinsKernelNetworkXml {
    param([Parameter(Mandatory)][xml]$Document,
          [ValidateRange(1, 65535)][int]$LocalPort,
          [string[]]$ExpectedXrayProcessIds = @(),
          [string[]]$ExpectedAwgProcessIds = @(),
          [string]$ExpectedClientAddress = '',
          [string]$ExpectedGatewayAddress = '',
          [string]$ExpectedProbeProcessId = '',
          [ValidateRange(0, 65535)][int]$ProbeEchoPort = 0,
          [ValidateRange(0, 65535)][int]$ExpectedEchoPayloadLength = 0)
    $packets = @()
    $receivePackets = @()
    $allPackets = @()
    foreach ($event in @($Document.SelectNodes(
                '//*[local-name()="Event"]'))) {
        $eventIdNode = $event.SelectSingleNode(
            './*[local-name()="System"]/*[local-name()="EventID"]'
        )
        if (-not $eventIdNode) {
            continue
        }
        $eventId = [string]$eventIdNode.InnerText.Trim()
        if ($eventId -notin @('42', '43')) { continue }
        $data = @{}
        foreach ($node in @($event.SelectNodes(
                    './/*[local-name()="EventData"]/*[local-name()="Data"]'))) {
            if ($node.Attributes['Name']) {
                $data[[string]$node.Attributes['Name'].Value] =
                    [string]$node.InnerText.Trim()
            }
        }
        if (-not $data.ContainsKey('saddr') -or
            -not $data.ContainsKey('daddr')) { continue }
        [int]$source = 0
        [int]$destination = 0
        [int]$size = 0
        [int]$processId = 0
        if (-not [int]::TryParse([string]$data['sport'], [ref]$source) -or
            -not [int]::TryParse([string]$data['dport'], [ref]$destination) -or
            -not [int]::TryParse([string]$data['size'], [ref]$size) -or
            -not [int]::TryParse([string]$data['PID'], [ref]$processId) -or
            $size -notin 1..65535) { continue }
        $packet = [pscustomobject]@{
            event_id = [int]$eventId
            source_address = [string]$data['saddr']
            destination_address = [string]$data['daddr']
            source = $source
            destination = $destination
            length = $size
            process_id = $processId
        }
        $allPackets += $packet
        $loopback = $packet.source_address -ceq '127.0.0.1' -and
            $packet.destination_address -ceq '127.0.0.1' -and
            ($source -eq $LocalPort -or $destination -eq $LocalPort)
        if (-not $loopback) { continue }
        if ($eventId -ceq '42') { $packets += $packet }
        else { $receivePackets += $packet }
    }
    $towardXray = @($packets | Where-Object {
        $_.destination -eq $LocalPort
    })
    $fromXray = @($packets | Where-Object { $_.source -eq $LocalPort })
    $towardHistogram = [ordered]@{}
    foreach ($packet in $towardXray) {
        $key = [string]$packet.length
        if (-not $towardHistogram.Contains($key)) { $towardHistogram[$key] = 0 }
        $towardHistogram[$key]++
    }
    $fromHistogram = [ordered]@{}
    foreach ($packet in $fromXray) {
        $key = [string]$packet.length
        if (-not $fromHistogram.Contains($key)) { $fromHistogram[$key] = 0 }
        $fromHistogram[$key]++
    }
    $initiationPorts = @($towardXray | Where-Object { $_.length -eq 164 } |
        ForEach-Object { $_.source } | Sort-Object -Unique)
    $responsePackets = @($fromXray | Where-Object { $_.length -eq 172 })
    $responsePorts = @($responsePackets | ForEach-Object { $_.destination } |
        Sort-Object -Unique)
    $matchingPorts = @($initiationPorts | Where-Object {
        $responsePorts -contains $_
    })
    $expectedPidSet = @($ExpectedXrayProcessIds | ForEach-Object {
        [string]$_
    })
    $xrayPidMatches = @($responsePackets | Where-Object {
        $expectedPidSet -contains [string]$_.process_id
    })
    $responseReceivePackets = @($receivePackets | Where-Object {
        $receive = $_
        @($responsePackets | Where-Object {
            $_.source -eq $receive.source -and
            $_.destination -eq $receive.destination -and
            $_.length -eq $receive.length
        }).Count -gt 0
    })
    $expectedAwgPidSet = @($ExpectedAwgProcessIds | ForEach-Object {
        [string]$_
    })
    $awgSendPackets = @($allPackets | Where-Object {
        $_.event_id -eq 42 -and
        $expectedAwgPidSet -contains [string]$_.process_id
    })
    $awgExpectedLoopbackSends = @($awgSendPackets | Where-Object {
        $_.destination_address -ceq '127.0.0.1' -and
        $_.destination -eq $LocalPort
    })
    $awgElsewhereSends = @($awgSendPackets | Where-Object {
        -not ($_.destination_address -ceq '127.0.0.1' -and
            $_.destination -eq $LocalPort)
    })
    $awgElsewhereLengthHistogram = [ordered]@{}
    $awgElsewherePortHistogram = [ordered]@{}
    foreach ($packet in $awgElsewhereSends) {
        $lengthKey = [string]$packet.length
        if (-not $awgElsewhereLengthHistogram.Contains($lengthKey)) {
            $awgElsewhereLengthHistogram[$lengthKey] = 0
        }
        $awgElsewhereLengthHistogram[$lengthKey]++
        $portKey = [string]$packet.destination
        if (-not $awgElsewherePortHistogram.Contains($portKey)) {
            $awgElsewherePortHistogram[$portKey] = 0
        }
        $awgElsewherePortHistogram[$portKey]++
    }
    $awgReceivePidMatches = @($responseReceivePackets | Where-Object {
        $expectedAwgPidSet -contains [string]$_.process_id
    })
    $echoAttempted = $ProbeEchoPort -gt 0 -and
        $ExpectedEchoPayloadLength -gt 0
    $echoCandidates = @(if ($echoAttempted) {
        $allPackets | Where-Object {
            $_.event_id -eq 42 -and $_.destination -eq $ProbeEchoPort -and
            $_.length -eq $ExpectedEchoPayloadLength
        }
    })
    $echoSourceMatches = @($echoCandidates | Where-Object {
        $_.source_address -ceq $ExpectedClientAddress
    })
    $echoDestinationMatches = @($echoCandidates | Where-Object {
        $_.destination_address -ceq $ExpectedGatewayAddress
    })
    $echoPidMatches = @($echoCandidates | Where-Object {
        [string]$_.process_id -ceq $ExpectedProbeProcessId
    })
    $echoCorrelated = @($echoCandidates | Where-Object {
        $_.source_address -ceq $ExpectedClientAddress -and
        $_.destination_address -ceq $ExpectedGatewayAddress -and
        [string]$_.process_id -ceq $ExpectedProbeProcessId
    })
    [ordered]@{
        parse_ok = $true
        provider = 'Microsoft-Windows-Kernel-Network'
        keyword = '0x10'
        level = 4
        payload_capture_enabled = $false
        udp_send_event_id = 42
        udp_receive_event_id = 43
        logical_packet_count = $packets.Count
        awg_to_xray_packet_count = $towardXray.Count
        xray_to_awg_packet_count = $fromXray.Count
        awg_to_xray_payload_lengths = $towardHistogram
        xray_to_awg_payload_lengths = $fromHistogram
        awg_initiation_164_seen = $initiationPorts.Count -gt 0
        xray_response_172_seen = $responsePackets.Count -gt 0
        response_returned_to_initiating_socket = $matchingPorts.Count -gt 0
        xray_response_pid_matches = $xrayPidMatches.Count -gt 0
        response_receive_event_seen = $responseReceivePackets.Count -gt 0
        response_receive_pid_matches_awg_service =
            $awgReceivePidMatches.Count -gt 0
        awg_udp_send_packet_count = $awgSendPackets.Count
        awg_udp_send_to_expected_loopback_count =
            $awgExpectedLoopbackSends.Count
        awg_udp_send_elsewhere_count = $awgElsewhereSends.Count
        awg_udp_send_elsewhere_payload_lengths = $awgElsewhereLengthHistogram
        awg_udp_send_elsewhere_destination_ports = $awgElsewherePortHistogram
        echo_send_probe_attempted = $echoAttempted
        echo_send_candidate_count = $echoCandidates.Count
        echo_send_source_matches_config = $echoSourceMatches.Count -gt 0
        echo_send_destination_matches_gateway =
            $echoDestinationMatches.Count -gt 0
        echo_send_pid_matches_probe = $echoPidMatches.Count -gt 0
        echo_send_metadata_correlated = $echoCorrelated.Count -gt 0
        initiating_socket_count = $initiationPorts.Count
        response_socket_count = $responsePorts.Count
    }
}

function Stop-WinsKernelNetworkCapture {
    param([Parameter(Mandatory)]$State,
          [string[]]$ExpectedXrayProcessIds = @(),
          [string[]]$ExpectedAwgProcessIds = @(),
          [string]$ExpectedClientAddress = '',
          [string]$ExpectedGatewayAddress = '',
          [string]$ExpectedProbeProcessId = '',
          [ValidateRange(0, 65535)][int]$ProbeEchoPort = 0,
          [ValidateRange(0, 65535)][int]$ExpectedEchoPayloadLength = 0)
    $empty = [ordered]@{
        available = [bool]$State.available
        capture_started = [bool]$State.started
        parse_ok = $false
        unavailability_reason = [string]$State.unavailability_reason
        provider = 'Microsoft-Windows-Kernel-Network'
        keyword = '0x10'
        level = 4
        payload_capture_enabled = $false
        udp_send_event_id = 42
        udp_receive_event_id = 43
        logical_packet_count = 0
        awg_to_xray_packet_count = 0
        xray_to_awg_packet_count = 0
        awg_to_xray_payload_lengths = [ordered]@{}
        xray_to_awg_payload_lengths = [ordered]@{}
        awg_initiation_164_seen = $false
        xray_response_172_seen = $false
        response_returned_to_initiating_socket = $false
        xray_response_pid_matches = $false
        response_receive_event_seen = $false
        response_receive_pid_matches_awg_service = $false
        awg_udp_send_packet_count = 0
        awg_udp_send_to_expected_loopback_count = 0
        awg_udp_send_elsewhere_count = 0
        awg_udp_send_elsewhere_payload_lengths = [ordered]@{}
        awg_udp_send_elsewhere_destination_ports = [ordered]@{}
        echo_send_probe_attempted = $ProbeEchoPort -gt 0 -and
            $ExpectedEchoPayloadLength -gt 0
        echo_send_candidate_count = 0
        echo_send_source_matches_config = $false
        echo_send_destination_matches_gateway = $false
        echo_send_pid_matches_probe = $false
        echo_send_metadata_correlated = $false
        initiating_socket_count = 0
        response_socket_count = 0
        raw_trace_preserved = $false
        raw_trace_delete_verified = $false
    }
    if ($State.stopped) {
        $empty.raw_trace_preserved = [bool](
            (Test-Path -LiteralPath $State.etl_path) -or
            (Test-Path -LiteralPath $State.xml_path)
        )
        $empty.raw_trace_delete_verified = -not $empty.raw_trace_preserved
        return $empty
    }
    $State.stopped = $true
    $logman = Join-Path $env:SystemRoot 'System32\logman.exe'
    $tracerpt = Join-Path $env:SystemRoot 'System32\tracerpt.exe'
    try {
        if (-not $State.started) { return $empty }
        $stop = Invoke-WinsBoundedProcess -FileName $logman -Arguments (
            'stop "' + $State.session_name + '" -ets'
        )
        $State.started = $false
        if ($stop -ne 0) {
            $empty.unavailability_reason = 'kernel_network_etw_stop_failed'
            return $empty
        }
        $convert = Invoke-WinsBoundedProcess -FileName $tracerpt -Arguments (
            '"' + $State.etl_path + '" -o "' + $State.xml_path +
            '" -of XML -y'
        )
        if ($convert -ne 0 -or
            -not (Test-Path -LiteralPath $State.xml_path -PathType Leaf)) {
            $empty.unavailability_reason = 'kernel_network_etw_parse_failed'
            return $empty
        }
        [xml]$document = Get-Content -LiteralPath $State.xml_path -Raw
        $parsed = ConvertFrom-WinsKernelNetworkXml -Document $document `
            -LocalPort ([int]$State.port) `
            -ExpectedXrayProcessIds $ExpectedXrayProcessIds `
            -ExpectedAwgProcessIds $ExpectedAwgProcessIds `
            -ExpectedClientAddress $ExpectedClientAddress `
            -ExpectedGatewayAddress $ExpectedGatewayAddress `
            -ExpectedProbeProcessId $ExpectedProbeProcessId `
            -ProbeEchoPort $ProbeEchoPort `
            -ExpectedEchoPayloadLength $ExpectedEchoPayloadLength
        foreach ($key in $parsed.Keys) { $empty[$key] = $parsed[$key] }
        $empty.unavailability_reason = ''
        $empty
    } finally {
        if ($State.started) {
            [void](Invoke-WinsBoundedProcess -FileName $logman -Arguments (
                'stop "' + $State.session_name + '" -ets'
            ))
            $State.started = $false
        }
        foreach ($path in @($State.xml_path, $State.etl_path)) {
            if (Test-Path -LiteralPath $path) {
                try { Remove-Item -LiteralPath $path -Force } catch {}
            }
        }
        $empty.raw_trace_preserved = [bool](
            (Test-Path -LiteralPath $State.etl_path) -or
            (Test-Path -LiteralPath $State.xml_path)
        )
        $empty.raw_trace_delete_verified = -not $empty.raw_trace_preserved
    }
}

if (-not ('WinsVpnTcpEStats' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class WinsVpnTcpEStats {
  [StructLayout(LayoutKind.Sequential)]
  private struct MibTcpRowOwnerPid {
    public UInt32 State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct MibTcpRow {
    public UInt32 State, LocalAddr, LocalPort, RemoteAddr, RemotePort;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct DataRw {
    [MarshalAs(UnmanagedType.U1)] public bool EnableCollection;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct DataRod {
    public UInt64 DataBytesOut, DataSegsOut, DataBytesIn, DataSegsIn;
    public UInt64 SegsOut, SegsIn;
    public UInt32 SoftErrors, SoftErrorReason, SndUna, SndNxt, SndMax;
    public UInt64 ThruBytesAcked;
    public UInt32 RcvNxt;
    public UInt64 ThruBytesReceived;
  }
  public sealed class Snapshot {
    public string Key;
    public UInt32 ProcessId;
    public UInt32 EnableError, QueryError;
    public UInt64 BytesOut, BytesIn, SegmentsOut, SegmentsIn;
  }
  public sealed class ProcessIoSnapshot {
    public bool QueryOk;
    public UInt64 ReadBytes, WriteBytes;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct IoCounters {
    public UInt64 ReadOperationCount, WriteOperationCount, OtherOperationCount;
    public UInt64 ReadTransferCount, WriteTransferCount, OtherTransferCount;
  }
  [DllImport("iphlpapi.dll", SetLastError=true)]
  private static extern UInt32 GetExtendedTcpTable(
      IntPtr table, ref UInt32 size, bool order, UInt32 family,
      UInt32 tableClass, UInt32 reserved);
  [DllImport("iphlpapi.dll", SetLastError=true)]
  private static extern UInt32 SetPerTcpConnectionEStats(
      ref MibTcpRow row, UInt32 type, ref DataRw rw, UInt32 rwVersion,
      UInt32 rwSize, UInt32 offset);
  [DllImport("iphlpapi.dll", SetLastError=true)]
  private static extern UInt32 GetPerTcpConnectionEStats(
      ref MibTcpRow row, UInt32 type, IntPtr rw, UInt32 rwVersion,
      UInt32 rwSize, IntPtr ros, UInt32 rosVersion, UInt32 rosSize,
      ref DataRod rod, UInt32 rodVersion, UInt32 rodSize);
  [DllImport("kernel32.dll", SetLastError=true)]
  private static extern IntPtr OpenProcess(UInt32 access, bool inherit,
      UInt32 processId);
  [DllImport("kernel32.dll", SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool GetProcessIoCounters(IntPtr process,
      out IoCounters counters);
  [DllImport("kernel32.dll")]
  [return: MarshalAs(UnmanagedType.Bool)]
  private static extern bool CloseHandle(IntPtr handle);

  private static UInt16 Port(UInt32 raw) {
    return (UInt16)(((raw & 0xff) << 8) | ((raw >> 8) & 0xff));
  }
  public static ProcessIoSnapshot ReadProcessIo(UInt32 processId) {
    IntPtr process = OpenProcess(0x1000, false, processId);
    if (process == IntPtr.Zero) return new ProcessIoSnapshot();
    try {
      IoCounters counters;
      if (!GetProcessIoCounters(process, out counters))
        return new ProcessIoSnapshot();
      return new ProcessIoSnapshot { QueryOk=true,
        ReadBytes=counters.ReadTransferCount,
        WriteBytes=counters.WriteTransferCount };
    } finally { CloseHandle(process); }
  }
  public static Snapshot[] Read(UInt32 processId, UInt16 remotePort) {
    UInt32 size = 0;
    GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
    if (size < 4 || size > 16 * 1024 * 1024) return new Snapshot[0];
    IntPtr table = Marshal.AllocHGlobal((int)size);
    try {
      if (GetExtendedTcpTable(table, ref size, false, 2, 5, 0) != 0)
        return new Snapshot[0];
      UInt32 count = (UInt32)Marshal.ReadInt32(table);
      int rowSize = Marshal.SizeOf(typeof(MibTcpRowOwnerPid));
      var result = new List<Snapshot>();
      IntPtr cursor = IntPtr.Add(table, 4);
      for (UInt32 i = 0; i < count; ++i) {
        var owner = (MibTcpRowOwnerPid)Marshal.PtrToStructure(
            cursor, typeof(MibTcpRowOwnerPid));
        cursor = IntPtr.Add(cursor, rowSize);
        if (owner.OwningPid != processId || owner.State != 5 ||
            Port(owner.RemotePort) != remotePort) continue;
        var row = new MibTcpRow { State=owner.State,
          LocalAddr=owner.LocalAddr, LocalPort=owner.LocalPort,
          RemoteAddr=owner.RemoteAddr, RemotePort=owner.RemotePort };
        var rw = new DataRw { EnableCollection=true };
        UInt32 enableError = SetPerTcpConnectionEStats(ref row, 1, ref rw, 0,
            (UInt32)Marshal.SizeOf(typeof(DataRw)), 0);
        var rod = new DataRod();
        UInt32 queryError = enableError == 0 ? GetPerTcpConnectionEStats(
            ref row, 1, IntPtr.Zero, 0, 0,
            IntPtr.Zero, 0, 0, ref rod, 0,
            (UInt32)Marshal.SizeOf(typeof(DataRod))) : enableError;
        result.Add(new Snapshot { Key=owner.LocalAddr+":"+owner.LocalPort+
          ">"+owner.RemoteAddr+":"+owner.RemotePort,
          ProcessId=processId, EnableError=enableError, QueryError=queryError,
          BytesOut=rod.DataBytesOut,
          BytesIn=rod.DataBytesIn, SegmentsOut=rod.DataSegsOut,
          SegmentsIn=rod.DataSegsIn });
      }
      return result.ToArray();
    } finally { Marshal.FreeHGlobal(table); }
  }
}
'@
}

function New-WinsXrayCarrierState {
    [ordered]@{
        counters = @{}
        process_io = @{}
        process_ids = @{}
        connections_seen = @{}
        enable_error_codes = @{}
        query_error_codes = @{}
        read_attempted = $false
        read_succeeded = $false
    }
}

function Update-WinsXrayCarrierState {
    param([Parameter(Mandatory)]$State,
          [ValidateRange(1, 65535)][int]$RemotePort)
    $installed = [IO.Path]::GetFullPath(
        (Join-Path $env:ProgramFiles 'WinsVPN\xray.exe')
    )
    foreach ($process in @(Get-Process xray -ErrorAction SilentlyContinue)) {
        $trusted = try {
            [IO.Path]::GetFullPath($process.Path) -ceq $installed
        } catch { $false }
        if (-not $trusted) { continue }
        $pidKey = [string]$process.Id
        $State.process_ids[$pidKey] = $true
        $io = [WinsVpnTcpEStats]::ReadProcessIo([uint32]$process.Id)
        if ($io.QueryOk) {
            if (-not $State.process_io.ContainsKey($pidKey)) {
                $State.process_io[$pidKey] = [ordered]@{
                    read_base = [uint64]$io.ReadBytes
                    write_base = [uint64]$io.WriteBytes
                    read_last = [uint64]$io.ReadBytes
                    write_last = [uint64]$io.WriteBytes
                }
            } else {
                $State.process_io[$pidKey].read_last = [uint64]$io.ReadBytes
                $State.process_io[$pidKey].write_last = [uint64]$io.WriteBytes
            }
        }
        $State.read_attempted = $true
        foreach ($snapshot in @([WinsVpnTcpEStats]::Read(
                    [uint32]$process.Id, [uint16]$RemotePort))) {
            $key = $pidKey + '|' + $snapshot.Key
            $State.connections_seen[$key] = $true
            if ([uint32]$snapshot.EnableError -ne 0) {
                $State.enable_error_codes[[string][uint32]$snapshot.EnableError] = `
                    $true
                continue
            }
            if ([uint32]$snapshot.QueryError -ne 0) {
                $State.query_error_codes[[string][uint32]$snapshot.QueryError] = `
                    $true
                continue
            }
            $State.read_succeeded = $true
            if (-not $State.counters.ContainsKey($key)) {
                $State.counters[$key] = [ordered]@{
                    bytes_in_base = [uint64]$snapshot.BytesIn
                    bytes_out_base = [uint64]$snapshot.BytesOut
                    segments_in_base = [uint64]$snapshot.SegmentsIn
                    segments_out_base = [uint64]$snapshot.SegmentsOut
                    bytes_in_last = [uint64]$snapshot.BytesIn
                    bytes_out_last = [uint64]$snapshot.BytesOut
                    segments_in_last = [uint64]$snapshot.SegmentsIn
                    segments_out_last = [uint64]$snapshot.SegmentsOut
                }
            } else {
                $counter = $State.counters[$key]
                $counter.bytes_in_last = [Math]::Max(
                    [uint64]$counter.bytes_in_last, [uint64]$snapshot.BytesIn)
                $counter.bytes_out_last = [Math]::Max(
                    [uint64]$counter.bytes_out_last, [uint64]$snapshot.BytesOut)
                $counter.segments_in_last = [Math]::Max(
                    [uint64]$counter.segments_in_last,
                    [uint64]$snapshot.SegmentsIn)
                $counter.segments_out_last = [Math]::Max(
                    [uint64]$counter.segments_out_last,
                    [uint64]$snapshot.SegmentsOut)
            }
        }
    }
}

function Get-WinsXrayCarrierSummary {
    param([Parameter(Mandatory)]$State)
    [uint64]$bytesIn = 0
    [uint64]$bytesOut = 0
    [uint64]$segmentsIn = 0
    [uint64]$segmentsOut = 0
    foreach ($counter in $State.counters.Values) {
        $bytesIn += [Math]::Max(0,
            [int64]$counter.bytes_in_last - [int64]$counter.bytes_in_base)
        $bytesOut += [Math]::Max(0,
            [int64]$counter.bytes_out_last - [int64]$counter.bytes_out_base)
        $segmentsIn += [Math]::Max(0,
            [int64]$counter.segments_in_last - [int64]$counter.segments_in_base)
        $segmentsOut += [Math]::Max(0,
            [int64]$counter.segments_out_last - [int64]$counter.segments_out_base)
    }
    [uint64]$ioRead = 0
    [uint64]$ioWrite = 0
    foreach ($counter in $State.process_io.Values) {
        $ioRead += [Math]::Max(0,
            [int64]$counter.read_last - [int64]$counter.read_base)
        $ioWrite += [Math]::Max(0,
            [int64]$counter.write_last - [int64]$counter.write_base)
    }
    [ordered]@{
        estats_attempted = [bool]$State.read_attempted
        estats_query_succeeded = [bool]$State.read_succeeded
        xray_process_count = $State.process_ids.Count
        carrier_connection_count = $State.connections_seen.Count
        carrier_counter_connection_count = $State.counters.Count
        estats_enable_error_codes = @($State.enable_error_codes.Keys |
            Sort-Object)
        estats_query_error_codes = @($State.query_error_codes.Keys |
            Sort-Object)
        carrier_bytes_in_delta = $bytesIn
        carrier_bytes_out_delta = $bytesOut
        carrier_segments_in_delta = $segmentsIn
        carrier_segments_out_delta = $segmentsOut
        process_io_read_bytes_delta = $ioRead
        process_io_write_bytes_delta = $ioWrite
    }
}

if ($SelfTest) {
    $fixture = @(
        '[00]0004.0001::2026-07-19 01:02:03.1000000 [Microsoft-Windows-PktMon] PktGroupId 1, Direction Tx',
        "`t127.0.0.1.50001 > 127.0.0.1.42110: UDP, length 164",
        '[00]0004.0001::2026-07-19 01:02:03.1001000 [Microsoft-Windows-PktMon] PktGroupId 2, Direction Rx',
        "`t127.0.0.1.50001 > 127.0.0.1.42110: UDP, length 164",
        '[00]0004.0001::2026-07-19 01:02:03.2200000 [Microsoft-Windows-PktMon] PktGroupId 3, Direction Tx',
        "`t127.0.0.1.42110 > 127.0.0.1.50001: UDP, length 172"
    )
    $parsed = ConvertFrom-WinsPktMonLoopbackText -Lines $fixture
    if ($parsed.logical_packet_count -ne 2 -or
        $parsed.awg_to_xray_packet_count -ne 1 -or
        $parsed.xray_to_awg_packet_count -ne 1 -or
        -not $parsed.awg_initiation_164_seen -or
        -not $parsed.xray_response_172_seen -or
        -not $parsed.response_returned_to_initiating_socket) {
        throw 'The sanitized PktMon parser self-test failed.'
    }
    $empty = Get-WinsXrayCarrierSummary (New-WinsXrayCarrierState)
    if ($empty.xray_process_count -ne 0 -or
        $empty.carrier_connection_count -ne 0 -or
        $empty.carrier_bytes_in_delta -ne 0) {
        throw 'The sanitized carrier counter self-test failed.'
    }
    [xml]$etwFixture = @'
<Events>
  <Event><System><EventID>42</EventID></System><EventData>
    <Data Name="PID">100</Data><Data Name="size"> 164 </Data>
    <Data Name="daddr">127.0.0.1</Data><Data Name="saddr">127.0.0.1</Data>
    <Data Name="dport">42110</Data><Data Name="sport">50001</Data>
  </EventData></Event>
  <Event><System><EventID>42</EventID></System><EventData>
    <Data Name="PID">200</Data><Data Name="size"> 172 </Data>
    <Data Name="daddr">127.0.0.1</Data><Data Name="saddr">127.0.0.1</Data>
    <Data Name="dport">50001</Data><Data Name="sport">42110</Data>
  </EventData></Event>
  <Event><System><EventID>43</EventID></System><EventData>
    <Data Name="PID">300</Data><Data Name="size"> 172 </Data>
    <Data Name="daddr">127.0.0.1</Data><Data Name="saddr">127.0.0.1</Data>
    <Data Name="dport">50001</Data><Data Name="sport">42110</Data>
  </EventData></Event>
  <Event><System><EventID>42</EventID></System><EventData>
    <Data Name="PID">300</Data><Data Name="size"> 32 </Data>
    <Data Name="daddr"><NODE_ES_IP></Data><Data Name="saddr">192.168.50.10</Data>
    <Data Name="dport">9110</Data><Data Name="sport">50001</Data>
  </EventData></Event>
  <Event><System><EventID>42</EventID></System><EventData>
    <Data Name="PID">400</Data><Data Name="size"> 40 </Data>
    <Data Name="daddr">10.1.2.1</Data><Data Name="saddr">10.1.2.3</Data>
    <Data Name="dport">49152</Data><Data Name="sport">60000</Data>
  </EventData></Event>
</Events>
'@
    $etwParsed = ConvertFrom-WinsKernelNetworkXml -Document $etwFixture `
        -LocalPort 42110 -ExpectedXrayProcessIds @('200') `
        -ExpectedAwgProcessIds @('300') `
        -ExpectedClientAddress '10.1.2.3' `
        -ExpectedGatewayAddress '10.1.2.1' `
        -ExpectedProbeProcessId '400' -ProbeEchoPort 49152 `
        -ExpectedEchoPayloadLength 40
    if ($etwParsed.logical_packet_count -ne 2 -or
        -not $etwParsed.awg_initiation_164_seen -or
        -not $etwParsed.xray_response_172_seen -or
        -not $etwParsed.response_returned_to_initiating_socket -or
        -not $etwParsed.xray_response_pid_matches -or
        -not $etwParsed.response_receive_event_seen -or
        -not $etwParsed.response_receive_pid_matches_awg_service -or
        $etwParsed.awg_udp_send_packet_count -ne 1 -or
        $etwParsed.awg_udp_send_to_expected_loopback_count -ne 0 -or
        $etwParsed.awg_udp_send_elsewhere_count -ne 1 -or
        -not $etwParsed.echo_send_source_matches_config -or
        -not $etwParsed.echo_send_destination_matches_gateway -or
        -not $etwParsed.echo_send_pid_matches_probe -or
        -not $etwParsed.echo_send_metadata_correlated -or
        $etwParsed.payload_capture_enabled) {
        throw 'The metadata-only Kernel-Network parser self-test failed.'
    }
    $statisticsBefore = [ordered]@{
        query_ok = $true; ReceivedBytes = 10; SentBytes = 20
        ReceivedUnicastPackets = 1; SentUnicastPackets = 2
        ReceivedDiscardedPackets = 0; OutboundDiscardedPackets = 0
        ReceivedPacketErrors = 0; OutboundPacketErrors = 0
    }
    $statisticsAfter = [ordered]@{
        query_ok = $true; ReceivedBytes = 30; SentBytes = 60
        ReceivedUnicastPackets = 2; SentUnicastPackets = 4
        ReceivedDiscardedPackets = 0; OutboundDiscardedPackets = 0
        ReceivedPacketErrors = 0; OutboundPacketErrors = 0
    }
    $statisticsDelta = Get-WinsAdapterStatisticsDelta `
        -Before $statisticsBefore -After $statisticsAfter
    if ($statisticsDelta.received_bytes_delta -ne 20 -or
        $statisticsDelta.sent_bytes_delta -ne 40 -or
        -not $statisticsDelta.inbound_traffic_advanced -or
        -not $statisticsDelta.outbound_traffic_advanced) {
        throw 'The exact adapter statistics self-test failed.'
    }
    Write-Output 'WINDOWS_TRANSPORT_DIAGNOSTIC_HELPERS_SELFTEST=PASS'
}
