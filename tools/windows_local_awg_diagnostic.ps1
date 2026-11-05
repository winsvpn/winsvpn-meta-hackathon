[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(10, 90)][int]$ObserveSeconds = 35,
    [switch]$ForceXrayFallback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-MaxLastInteger {
    param([object[]]$Lines)
    [long]$maximum = 0
    foreach ($line in $Lines) {
        $parts = ([string]$line).Trim() -split '\s+'
        [long]$value = 0
        if ($parts.Count -gt 0 -and
            [long]::TryParse($parts[-1], [ref]$value)) {
            $maximum = [Math]::Max($maximum, $value)
        }
    }
    $maximum
}

function Get-TransferTotals {
    param([object[]]$Lines)
    [long]$received = 0
    [long]$sent = 0
    foreach ($line in $Lines) {
        $parts = ([string]$line).Trim() -split '\s+'
        [long]$lineReceived = 0
        [long]$lineSent = 0
        if ($parts.Count -ge 3 -and
            [long]::TryParse($parts[-2], [ref]$lineReceived) -and
            [long]::TryParse($parts[-1], [ref]$lineSent)) {
            $received += $lineReceived
            $sent += $lineSent
        }
    }
    [ordered]@{ received = $received; sent = $sent }
}

function Get-DirectEndpointAddress {
    param([Parameter(Mandatory)][string]$Endpoint)
    if ($Endpoint -notmatch '^((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5})$') {
        throw 'The cached direct endpoint is not an exact IPv4 endpoint.'
    }
    $address = $null
    [int]$port = 0
    if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or
        -not [int]::TryParse($Matches[2], [ref]$port) -or
        $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        [Net.IPAddress]::IsLoopback($address) -or $port -ne 9110) {
        throw 'The cached direct endpoint violates the public UDP/9110 contract.'
    }
    $address.ToString()
}

function Invoke-PowerAction {
    param([Parameter(Mandatory)][ValidateSet('Toggle', 'Cancel', 'Disconnect')]
          [string]$Action,
          [Parameter(Mandatory)][int]$WindowProcessId)
    $tool = Join-Path $PSScriptRoot 'windows_invoke_vpn_power.ps1'
    $result = @(& $tool -Action $Action -WindowProcessId $WindowProcessId `
        -SettleSeconds 0 2>&1)
    [ordered]@{
        passed = [bool]([string]($result -join "`n") -match
            '^WINDOWS_VPN_POWER_INVOKE=PASS ')
        label = if ([string]($result -join "`n") -match 'label=([^\r\n]+?) role=') {
            $Matches[1]
        } else { '' }
    }
}

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw 'The local AWG diagnostic requires an elevated interactive session.'
}

$outputFull = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputParent -PathType Container) -or
    (Test-Path -LiteralPath $outputFull)) {
    throw 'The local AWG diagnostic output path is unavailable or already exists.'
}

$guiPath = Join-Path $env:ProgramFiles 'WinsVPN\wins_vpn.exe'
$awgPath = Join-Path $env:ProgramFiles 'AmneziaWG\awg.exe'
foreach ($required in @($guiPath, $awgPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "A required installed runtime is missing: $required"
    }
}
if ((Get-Sha256 $guiPath) -cne $ExpectedGuiSha256.ToLowerInvariant()) {
    throw 'The installed GUI is not the pinned diagnostic candidate.'
}

$config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
$directEndpointAddress = Get-DirectEndpointAddress `
    ([string]$config.server_endpoint)
$xrayLocalPort = [int]$config.xray.local_port
if (-not [bool]$config.xray.enabled -or $xrayLocalPort -notin 1..65535 -or
    [string]$config.xray.remote_awg_host -cne '127.0.0.1' -or
    [int]$config.xray.remote_awg_port -ne 9110) {
    throw 'The cached configuration has no valid Xray-over-AWG contract.'
}
$xrayLoopbackEndpoint = "127.0.0.1:$xrayLocalPort"

$guiProcesses = @(Get-Process wins_vpn -ErrorAction SilentlyContinue |
    Where-Object {
        try {
            [IO.Path]::GetFullPath($_.Path) -ceq [IO.Path]::GetFullPath($guiPath)
        } catch { $false }
    })
if ($guiProcesses.Count -ne 1 -or
    $guiProcesses[0].MainWindowHandle -eq [IntPtr]::Zero) {
    throw 'Exactly one interactive pinned Win''s VPN window must be open.'
}
$gui = $guiProcesses[0]

$watch = [Diagnostics.Stopwatch]::StartNew()
$connect = $null
$cleanup = $null
[long]$firstServiceMs = -1
[long]$firstXrayMs = -1
[long]$maximumHandshakeEpoch = 0
[long]$maximumReceived = 0
[long]$maximumSent = 0
[long]$directMaximumHandshakeEpoch = 0
[long]$directMaximumReceived = 0
[long]$directMaximumSent = 0
[long]$xrayMaximumHandshakeEpoch = 0
[long]$xrayMaximumReceived = 0
[long]$xrayMaximumSent = 0
[int]$serviceRunningSamples = 0
[int]$xrayRunningSamples = 0
[int]$directEndpointSamples = 0
[int]$xrayEndpointSamples = 0
[int]$udpListenerSamples = 0
[int]$tcpEstablishedSamples = 0
[int]$awgQuerySuccesses = 0
[bool]$loopbackEndpointMatched = $false
[bool]$carrierRouteExact32Seen = $false
[bool]$tunnelDefaultRouteSeen = $false
[bool]$teardownClean = $false
[bool]$forcingRuleCreated = $false
[bool]$forcingRuleRemoved = -not $ForceXrayFallback
$forcingRuleName = 'WinsVPN-Diagnostic-ForceXray-' + [Guid]::NewGuid().ToString('N')
$forcingRuleGroup = 'WinsVPN ephemeral diagnostics'

try {
    if ($ForceXrayFallback) {
        New-NetFirewallRule -Name $forcingRuleName -DisplayName $forcingRuleName `
            -Group $forcingRuleGroup -PolicyStore ActiveStore `
            -Direction Outbound -Action Block -Enabled True -Profile Any `
            -Protocol UDP -RemoteAddress $directEndpointAddress `
            -RemotePort 9110 | Out-Null
        $forcingRuleCreated = @(
            Get-NetFirewallRule -Name $forcingRuleName `
                -PolicyStore ActiveStore -ErrorAction Stop
        ).Count -eq 1
        if (-not $forcingRuleCreated) {
            throw 'The exact temporary Xray forcing rule was not installed.'
        }
    }

    $connect = Invoke-PowerAction -Action Toggle -WindowProcessId $gui.Id
    if (-not $connect.passed -or $connect.label -cne 'Connect VPN') {
        throw 'The semantic bridge did not invoke the exact Connect VPN control.'
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($ObserveSeconds)
    do {
        $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
            -ErrorAction SilentlyContinue
        $xray = Get-Process xray -ErrorAction SilentlyContinue |
            Select-Object -First 1
        $adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' } |
            Select-Object -First 1

        if ($service -and $service.Status -eq 'Running') {
            ++$serviceRunningSamples
            if ($firstServiceMs -lt 0) { $firstServiceMs = $watch.ElapsedMilliseconds }

            $handshakes = @(& $awgPath show winsvpn latest-handshakes 2>$null)
            $handshakeExit = $LASTEXITCODE
            $transfer = @(& $awgPath show winsvpn transfer 2>$null)
            $transferExit = $LASTEXITCODE
            $endpoints = @(& $awgPath show winsvpn endpoints 2>$null)
            $endpointExit = $LASTEXITCODE
            if ($handshakeExit -eq 0 -and $transferExit -eq 0 -and
                $endpointExit -eq 0) {
                ++$awgQuerySuccesses
                $maximumHandshakeEpoch = [Math]::Max(
                    $maximumHandshakeEpoch,
                    (Get-MaxLastInteger $handshakes)
                )
                $totals = Get-TransferTotals $transfer
                $maximumReceived = [Math]::Max($maximumReceived, $totals.received)
                $maximumSent = [Math]::Max($maximumSent, $totals.sent)
                [bool]$sampleIsLoopback = $false
                foreach ($line in $endpoints) {
                    $parts = ([string]$line).Trim() -split '\s+'
                    if ($parts.Count -ge 2 -and
                        $parts[-1] -ceq $xrayLoopbackEndpoint) {
                        $loopbackEndpointMatched = $true
                        $sampleIsLoopback = $true
                    }
                }
                $sampleHandshake = Get-MaxLastInteger $handshakes
                if ($sampleIsLoopback) {
                    ++$xrayEndpointSamples
                    $xrayMaximumHandshakeEpoch = [Math]::Max(
                        $xrayMaximumHandshakeEpoch, $sampleHandshake
                    )
                    $xrayMaximumReceived = [Math]::Max(
                        $xrayMaximumReceived, $totals.received
                    )
                    $xrayMaximumSent = [Math]::Max(
                        $xrayMaximumSent, $totals.sent
                    )
                } else {
                    ++$directEndpointSamples
                    $directMaximumHandshakeEpoch = [Math]::Max(
                        $directMaximumHandshakeEpoch, $sampleHandshake
                    )
                    $directMaximumReceived = [Math]::Max(
                        $directMaximumReceived, $totals.received
                    )
                    $directMaximumSent = [Math]::Max(
                        $directMaximumSent, $totals.sent
                    )
                }
            }
        }

        if ($xray) {
            ++$xrayRunningSamples
            if ($firstXrayMs -lt 0) { $firstXrayMs = $watch.ElapsedMilliseconds }
            $udpListenerSamples += @(
                Get-NetUDPEndpoint -OwningProcess $xray.Id `
                    -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.LocalAddress -ceq '127.0.0.1' -and
                        $_.LocalPort -eq $xrayLocalPort
                    }
            ).Count
            foreach ($connection in @(
                Get-NetTCPConnection -OwningProcess $xray.Id `
                    -ErrorAction SilentlyContinue |
                    Where-Object { $_.State -eq 'Established' }
            )) {
                ++$tcpEstablishedSamples
                $exactPrefix = ([string]$connection.RemoteAddress) + '/32'
                if (Get-NetRoute -DestinationPrefix $exactPrefix `
                        -ErrorAction SilentlyContinue) {
                    $carrierRouteExact32Seen = $true
                }
            }
        }

        if ($adapter -and
            (Get-NetRoute -InterfaceIndex $adapter.ifIndex `
                -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)) {
            $tunnelDefaultRouteSeen = $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
} finally {
    foreach ($action in @('Disconnect', 'Cancel')) {
        try {
            $candidate = Invoke-PowerAction -Action $action `
                -WindowProcessId $gui.Id
            if ($candidate.passed) { $cleanup = $candidate; break }
        } catch {}
    }
    $cleanDeadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
            -ErrorAction SilentlyContinue
        $xray = @(Get-Process xray -ErrorAction SilentlyContinue)
        $adapter = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ceq 'winsvpn' -and $_.Status -eq 'Up' })
        if (-not $service -and $xray.Count -eq 0 -and $adapter.Count -eq 0) {
            $teardownClean = $true
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $cleanDeadline)
    if ($ForceXrayFallback) {
        Get-NetFirewallRule -Name $forcingRuleName -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue | Remove-NetFirewallRule `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        $forcingRuleRemoved = @(
            Get-NetFirewallRule -Name $forcingRuleName `
                -PolicyStore ActiveStore -ErrorAction SilentlyContinue
        ).Count -eq 0
    }
}

$capturedEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$result = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-local-awg-diagnostic-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    expected_gui_sha256 = $ExpectedGuiSha256.ToLowerInvariant()
    observe_seconds = $ObserveSeconds
    force_xray_fallback_requested = [bool]$ForceXrayFallback
    exact_direct_endpoint_validated = $true
    forcing_rule_created = $forcingRuleCreated
    forcing_rule_removed = $forcingRuleRemoved
    connect_semantic_passed = [bool]($connect -and $connect.passed)
    first_service_ms = if ($firstServiceMs -ge 0) { $firstServiceMs } else { $null }
    first_xray_ms = if ($firstXrayMs -ge 0) { $firstXrayMs } else { $null }
    service_running_samples = $serviceRunningSamples
    xray_running_samples = $xrayRunningSamples
    direct_endpoint_samples = $directEndpointSamples
    xray_endpoint_samples = $xrayEndpointSamples
    udp_listener_samples = $udpListenerSamples
    tcp_established_samples = $tcpEstablishedSamples
    awg_query_successes = $awgQuerySuccesses
    maximum_handshake_epoch = $maximumHandshakeEpoch
    maximum_received_bytes = $maximumReceived
    maximum_sent_bytes = $maximumSent
    direct_maximum_handshake_epoch = $directMaximumHandshakeEpoch
    direct_handshake_current = [bool](
        $directMaximumHandshakeEpoch -gt 0 -and
        ($capturedEpoch - $directMaximumHandshakeEpoch) -in 0..180
    )
    direct_maximum_received_bytes = $directMaximumReceived
    direct_maximum_sent_bytes = $directMaximumSent
    xray_maximum_handshake_epoch = $xrayMaximumHandshakeEpoch
    xray_handshake_current = [bool](
        $xrayMaximumHandshakeEpoch -gt 0 -and
        ($capturedEpoch - $xrayMaximumHandshakeEpoch) -in 0..180
    )
    xray_maximum_received_bytes = $xrayMaximumReceived
    xray_maximum_sent_bytes = $xrayMaximumSent
    loopback_endpoint_matched = $loopbackEndpointMatched
    carrier_route_exact32_seen = $carrierRouteExact32Seen
    tunnel_default_route_seen = $tunnelDefaultRouteSeen
    teardown_clean = $teardownClean
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
    ($result | ConvertTo-Json -Depth 6) + [Environment]::NewLine
)
$stream = [IO.File]::Open(
    $outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
Write-Output "WINDOWS_LOCAL_AWG_DIAGNOSTIC=$outputFull"
