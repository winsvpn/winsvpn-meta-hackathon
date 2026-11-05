[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Output,
    [ValidateRange(8, 30)][int]$LaneSeconds = 15,
    [Parameter(Mandatory)]
    [ValidateSet('Single', 'Double')]
    [string]$ExpectedMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

trap {
    try {
        $failurePath = [IO.Path]::GetFullPath($Output) + '.failure.json'
        $failure = [ordered]@{
            schema_version = 1
            contract = 'winsvpn-windows-xray-awg-handshake-matrix-failure-v1'
            captured_at_utc = [DateTime]::UtcNow.ToString('o')
            secret_material_redacted = $true
            exception_type = $_.Exception.GetType().Name
            message = $_.Exception.Message
        }
        [IO.File]::WriteAllText(
            $failurePath,
            ($failure | ConvertTo-Json -Depth 4) + [Environment]::NewLine,
            [Text.UTF8Encoding]::new($false)
        )
    } catch {}
    throw
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StringSha256 {
    param([AllowEmptyString()][string]$Value)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Set-DiagnosticAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = [Security.Principal.SecurityIdentifier]::new(
        [Security.Principal.WellKnownSidType]::LocalSystemSid, $null
    )
    $administrators = [Security.Principal.SecurityIdentifier]::new(
        [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null
    )
    if ($Directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
            -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($current, $system, $administrators)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $acl.SetOwner($current)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-PrivateText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Value
    )
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    Set-DiagnosticAcl $Path
}

function Assert-Key {
    param([AllowEmptyString()][string]$Value, [Parameter(Mandatory)][string]$Name)
    if ($Value -notmatch '^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$') {
        throw "The $Name does not satisfy the WireGuard key contract."
    }
}

function Get-EndpointHost {
    param([Parameter(Mandatory)][string]$Endpoint)
    if ($Endpoint -match '^\[([^\]]+)\]:(\d{1,5})$') { return $Matches[1] }
    if ($Endpoint -match '^([^:]+):(\d{1,5})$') { return $Matches[1] }
    throw 'The registered direct endpoint is invalid.'
}

function Get-EndpointPort {
    param([Parameter(Mandatory)][string]$Endpoint)
    if ($Endpoint -notmatch ':(?<port>[0-9]{1,5})$') {
        throw 'The registered direct endpoint has no explicit port.'
    }
    $port = [int]$Matches.port
    if ($port -notin 1..65535) {
        throw 'The registered direct endpoint port is invalid.'
    }
    $port
}

function Get-XrayRoutes {
    param([Parameter(Mandatory)]$Xray)
    $routes = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $candidates = [Collections.Generic.List[object]]::new()
    $candidates.Add([pscustomobject]@{
        port = $Xray.port
        security = $Xray.security
    })
    if ($Xray.PSObject.Properties['transports']) {
        foreach ($transport in @($Xray.transports)) {
            $candidates.Add($transport)
        }
    }
    foreach ($candidate in $candidates) {
        $port = [int]$candidate.port
        $security = ([string]$candidate.security).Trim().ToLowerInvariant()
        if ($port -notin 1..65535 -or $security -notin @('none', 'tls')) {
            throw 'The protected configuration contains an invalid Xray route.'
        }
        $key = "$port/$security"
        if ($seen.Add($key)) {
            $routes.Add([ordered]@{
                port = $port
                security = $security
            })
        }
    }
    if (-not $seen.Contains('80/none') -or -not $seen.Contains('443/tls')) {
        throw 'The protected configuration must advertise both TCP/80 plain WebSocket and TCP/443 TLS WebSocket fallback routes.'
    }
    @($routes)
}

function Get-LogCategories {
    param([AllowEmptyString()][string]$Text)
    [ordered]@{
        started = [regex]::Matches($Text, 'Xray [^\r\n]* started', 'IgnoreCase').Count
        websocket_dial_failure = [regex]::Matches(
            $Text, 'failed to dial WebSocket', 'IgnoreCase'
        ).Count
        response_header_failure = [regex]::Matches(
            $Text, 'failed to decode response header', 'IgnoreCase'
        ).Count
        request_transfer_failure = [regex]::Matches(
            $Text, 'failed to transfer request payload', 'IgnoreCase'
        ).Count
        connection_refused = [regex]::Matches(
            $Text, 'connection refused', 'IgnoreCase'
        ).Count
        connection_reset = [regex]::Matches(
            $Text, 'connection reset', 'IgnoreCase'
        ).Count
        unexpected_eof = [regex]::Matches(
            $Text, 'unexpected EOF', 'IgnoreCase'
        ).Count
    }
}

function Wait-DiagnosticTeardown {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$AdapterName,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 15
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $adapters = @(Get-NetAdapter -Name $AdapterName -IncludeHidden `
            -ErrorAction SilentlyContinue)
        if (-not $service -and $adapters.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'The diagnostic AWG service or adapter did not tear down within the bounded deadline.'
}

$secureStateHelpers = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
$secureStateHelperItem = Get-Item -LiteralPath $secureStateHelpers -Force `
    -ErrorAction Stop
if ($secureStateHelperItem.PSIsContainer -or
    ($secureStateHelperItem.Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The fail-closed Windows secure-state helpers are unavailable.'
}
. $secureStateHelpers

$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw 'The Xray/AWG handshake matrix requires elevation.'
}

$outputFull = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw 'The diagnostic output parent does not exist.'
}
if (Test-Path -LiteralPath $outputFull) {
    throw 'The diagnostic output already exists.'
}

$config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
$keypair = Read-WinsVpnSecureJson -Name 'client_keypair.json'
if ([string]$keypair.private_key -cne [string]$config.client_private_key -or
    [string]$keypair.public_key -cne [string]$config.client_public_key) {
    throw 'The app state and protected client keypair do not match.'
}
Assert-Key ([string]$config.client_private_key) 'client private key'
Assert-Key ([string]$config.client_public_key) 'client public key'
Assert-Key ([string]$config.server_public_key) 'server public key'
if (-not [string]::IsNullOrWhiteSpace([string]$config.preshared_key)) {
    Assert-Key ([string]$config.preshared_key) 'preshared key'
}
if ([string]$config.client_ip -notmatch '^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)' -or
    [string]$config.client_ip -notmatch '^(?:\d{1,3}\.){3}\d{1,3}$') {
    throw 'The registered client address is not a private IPv4 address.'
}
if ([string]$config.xray.uuid -notmatch
        '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or
    [string]$config.xray.path -notmatch '^/[!-~]{0,1023}$' -or
    [string]$config.xray.server_name -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
    [int]$config.xray.local_port -ne 42110 -or
    [string]$config.xray.remote_awg_host -cne '127.0.0.1') {
    throw 'The protected configuration has no valid production Xray/AWG carrier contract.'
}
$doubleVpnActive = $config.double_vpn_active -is [bool] -and
    [bool]$config.double_vpn_active
$directPort = Get-EndpointPort ([string]$config.server_endpoint)
$remoteAwgPort = [int]$config.xray.remote_awg_port
if ($remoteAwgPort -ne $directPort) {
    throw 'The Xray carrier destination does not match the registered direct first-hop port.'
}
if ($ExpectedMode -ceq 'Single') {
    if ($doubleVpnActive -or $directPort -ne 9110) {
        throw 'The protected configuration is not an exact Single VPN route.'
    }
} else {
    if (-not $doubleVpnActive -or $directPort -eq 9110 -or
        [string]::IsNullOrWhiteSpace([string]$config.double_vpn_core_id) -or
        [string]::IsNullOrWhiteSpace([string]$config.double_vpn_exit_slug)) {
        throw 'The protected configuration is not an exact Double VPN Core route.'
    }
}
$xrayRoutes = @(Get-XrayRoutes $config.xray)
foreach ($field in @('H1','H2','H3','H4','Jc','Jmax','Jmin','S1','S2','S3','S4')) {
    if (-not $config.obfuscation.PSObject.Properties[$field] -or
        [string]$config.obfuscation.$field -notmatch '^-?\d{1,10}$') {
        throw "The registered AWG obfuscation field $field is invalid."
    }
}

$xrayExe = Join-Path $env:ProgramFiles 'WinsVPN\xray.exe'
$amneziaExe = Join-Path $env:ProgramFiles 'AmneziaWG\amneziawg.exe'
$awgExe = Join-Path $env:ProgramFiles 'AmneziaWG\awg.exe'
foreach ($path in @($xrayExe, $amneziaExe, $awgExe)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "A required installed runtime is missing: $path"
    }
}
if (@(Get-Process xray,winsvpn_awg_engine -ErrorAction SilentlyContinue).Count `
        -gt 0 -or
    $null -ne (Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue) -or
    @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)winsvpn|amnezia|awg' }).Count -gt 0 -or
    @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
        $_.InterfaceAlias -match '(?i)winsvpn|amnezia|awg'
    }).Count -gt 0) {
    throw 'The matrix refuses to run while the production tunnel is active.'
}

$tunnelName = 'winsvpn-transport-diag'
$serviceName = 'AmneziaWGTunnel$winsvpn-transport-diag'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'A pre-existing diagnostic AWG service must be reviewed manually.'
}

$privateBase = Join-Path $env:ProgramData 'WinsVPN\TransportMatrix'
if (-not (Test-Path -LiteralPath $privateBase -PathType Container)) {
    New-Item -ItemType Directory -Path $privateBase | Out-Null
}
Set-DiagnosticAcl $privateBase -Directory
$privateRoot = Join-Path $privateBase ([Guid]::NewGuid().ToString('D'))
New-Item -ItemType Directory -Path $privateRoot | Out-Null
Set-DiagnosticAcl $privateRoot -Directory

$originHost = Get-EndpointHost ([string]$config.server_endpoint)
$lanes = [Collections.Generic.List[object]]::new()
foreach ($route in $xrayRoutes) {
    foreach ($target in @(
        [ordered]@{ name = 'advertised'; host = [string]$config.xray.host },
        [ordered]@{ name = 'origin'; host = $originHost }
    )) {
        $lanes.Add([ordered]@{
            name = "$($target.name)-tcp$($route.port)-$($route.security)"
            route = [string]$target.name
            target = [string]$target.host
            port = [int]$route.port
            security = [string]$route.security
        })
    }
}
$results = [Collections.Generic.List[object]]::new()
$xray = $null

try {
    foreach ($lane in $lanes) {
        $laneRoot = Join-Path $privateRoot ([string]$lane.name)
        New-Item -ItemType Directory -Path $laneRoot | Out-Null
        Set-DiagnosticAcl $laneRoot -Directory
        $xrayConfigPath = Join-Path $laneRoot 'xray.json'
        $xrayStdoutPath = Join-Path $laneRoot 'xray.stdout.log'
        $xrayStderrPath = Join-Path $laneRoot 'xray.stderr.log'
        $awgConfigPath = Join-Path $laneRoot "$tunnelName.conf"

        $wsSettings = [ordered]@{
            path = [string]$config.xray.path
            headers = [ordered]@{
                Host = [string]$config.xray.server_name
            }
        }
        $streamSettings = [ordered]@{
            network = 'ws'
            security = [string]$lane.security
            wsSettings = $wsSettings
            sockopt = [ordered]@{
                domainStrategy = 'UseIPv4'
                tcpFastOpen = $true
                tcpKeepAliveIdle = 30
                tcpKeepAliveInterval = 15
                tcpUserTimeout = 15000
                tcpMptcp = $false
            }
        }
        if ([string]$lane.security -ceq 'tls') {
            $streamSettings.tlsSettings = [ordered]@{
                serverName = [string]$config.xray.server_name
                allowInsecure = $false
            }
        }
        $xrayConfig = [ordered]@{
            log = [ordered]@{ loglevel = 'debug' }
            inbounds = @([ordered]@{
                tag = 'awg-local-in'
                listen = '127.0.0.1'
                port = 42110
                protocol = 'tunnel'
                settings = [ordered]@{
                    network = 'udp'
                    address = '127.0.0.1'
                    port = $remoteAwgPort
                    followRedirect = $false
                    userLevel = 0
                }
            })
            outbounds = @([ordered]@{
                tag = 'vless-ws-out'
                protocol = 'vless'
                settings = [ordered]@{
                    vnext = @([ordered]@{
                        address = [string]$lane.target
                        port = [int]$lane.port
                        users = @([ordered]@{
                            id = [string]$config.xray.uuid
                            encryption = 'none'
                            level = 0
                        })
                    })
                }
                streamSettings = $streamSettings
                targetStrategy = 'UseIPv4'
                mux = [ordered]@{
                    enabled = $false
                    concurrency = 0
                    xudpConcurrency = 0
                    xudpProxyUDP443 = 'skip'
                }
            })
            routing = [ordered]@{
                domainStrategy = 'IPIfNonMatch'
                rules = @([ordered]@{
                    type = 'field'
                    inboundTag = @('awg-local-in')
                    outboundTag = 'vless-ws-out'
                })
            }
        }
        Write-PrivateText $xrayConfigPath (
            ($xrayConfig | ConvertTo-Json -Depth 16 -Compress) +
                [Environment]::NewLine
        )

        $obfs = $config.obfuscation
        $presharedKeyLine = if (-not [string]::IsNullOrWhiteSpace(
                [string]$config.preshared_key
            )) {
            "PresharedKey = $($config.preshared_key)"
        } else { '' }
        $awgConfig = @"
[Interface]
PrivateKey = $($config.client_private_key)
Address = $($config.client_ip)/32
MTU = 1280
Jc = $($obfs.Jc)
Jmin = $($obfs.Jmin)
Jmax = $($obfs.Jmax)
S1 = $($obfs.S1)
S2 = $($obfs.S2)
S3 = $($obfs.S3)
S4 = $($obfs.S4)
H1 = $($obfs.H1)
H2 = $($obfs.H2)
H3 = $($obfs.H3)
H4 = $($obfs.H4)

[Peer]
PublicKey = $($config.server_public_key)
$presharedKeyLine
Endpoint = 127.0.0.1:42110
AllowedIPs = 192.0.2.1/32
PersistentKeepalive = 5
"@
        Write-PrivateText $awgConfigPath $awgConfig

        $xray = $null
        $installExit = -1
        $uninstallExit = -1
        $handshakeEpoch = 0L
        $receivedBytes = 0L
        $sentBytes = 0L
        $queryPassed = $false
        $started = [DateTime]::UtcNow
        try {
            $test = Start-Process -FilePath $xrayExe -ArgumentList @(
                'run', '-test', '-c', $xrayConfigPath
            ) -Wait -PassThru -WindowStyle Hidden
            if ($test.ExitCode -ne 0) {
                throw "Xray rejected the $($lane.name) diagnostic config."
            }
            $xray = Start-Process -FilePath $xrayExe -ArgumentList @(
                'run', '-c', $xrayConfigPath
            ) -RedirectStandardOutput $xrayStdoutPath `
                -RedirectStandardError $xrayStderrPath -PassThru -WindowStyle Hidden
            Start-Sleep -Milliseconds 1200
            if ($xray.HasExited) {
                throw "Xray exited during $($lane.name) startup."
            }

            $install = Start-Process -FilePath $amneziaExe -ArgumentList @(
                '/installtunnelservice', $awgConfigPath
            ) -Wait -PassThru -WindowStyle Hidden
            $installExit = $install.ExitCode
            if ($installExit -ne 0) {
                throw "The diagnostic AWG service install failed in $($lane.name)."
            }
            $deadline = [DateTime]::UtcNow.AddSeconds(12)
            do {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -eq 'Running') { break }
                Start-Sleep -Milliseconds 250
            } while ([DateTime]::UtcNow -lt $deadline)
            if (-not $service -or $service.Status -ne 'Running') {
                throw "The diagnostic AWG service did not start in $($lane.name)."
            }

            Start-Sleep -Seconds $LaneSeconds
            $handshakeRaw = @(& $awgExe show $tunnelName latest-handshakes 2>&1)
            $handshakeExit = $LASTEXITCODE
            $transferRaw = @(& $awgExe show $tunnelName transfer 2>&1)
            $transferExit = $LASTEXITCODE
            if ($handshakeExit -eq 0 -and $handshakeRaw.Count -gt 0) {
                $parts = ([string]$handshakeRaw[0]) -split '\s+'
                if ($parts.Count -ge 2) {
                    [void][long]::TryParse($parts[-1], [ref]$handshakeEpoch)
                }
            }
            if ($transferExit -eq 0 -and $transferRaw.Count -gt 0) {
                $parts = ([string]$transferRaw[0]) -split '\s+'
                if ($parts.Count -ge 3) {
                    [void][long]::TryParse($parts[-2], [ref]$receivedBytes)
                    [void][long]::TryParse($parts[-1], [ref]$sentBytes)
                }
            }
            $queryPassed = $handshakeExit -eq 0 -and $transferExit -eq 0
        } finally {
            if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
                $uninstall = Start-Process -FilePath $amneziaExe -ArgumentList @(
                    '/uninstalltunnelservice', $tunnelName
                ) -Wait -PassThru -WindowStyle Hidden
                $uninstallExit = $uninstall.ExitCode
            }
            if ($xray -and -not $xray.HasExited) {
                try { $xray.Kill() } catch {}
                try { [void]$xray.WaitForExit(5000) } catch {}
            }
        }

        $stdout = if (Test-Path -LiteralPath $xrayStdoutPath) {
            [IO.File]::ReadAllText($xrayStdoutPath)
        } else { '' }
        $stderr = if (Test-Path -LiteralPath $xrayStderrPath) {
            [IO.File]::ReadAllText($xrayStderrPath)
        } else { '' }
        $combined = $stdout + [Environment]::NewLine + $stderr
        $handshakeAge = if ($handshakeEpoch -gt 0) {
            [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $handshakeEpoch
        } else { $null }
        $results.Add([ordered]@{
            lane = [string]$lane.name
            route = [string]$lane.route
            transport_port = [int]$lane.port
            transport_security = [string]$lane.security
            production_parity_mux_disabled = $true
            started_at_utc = $started.ToString('o')
            query_passed = $queryPassed
            latest_handshake_present = $handshakeEpoch -gt 0
            latest_handshake_age_seconds = $handshakeAge
            received_bytes = $receivedBytes
            sent_bytes = $sentBytes
            install_exit_code = $installExit
            uninstall_exit_code = $uninstallExit
            xray_log_sha256 = Get-StringSha256 $combined
            xray_log_categories = Get-LogCategories $combined
            passed = $queryPassed -and $handshakeEpoch -gt 0 -and
                $receivedBytes -gt 0 -and $sentBytes -gt 0 -and
                $installExit -eq 0 -and $uninstallExit -eq 0
        })
        Wait-DiagnosticTeardown -ServiceName $serviceName `
            -AdapterName $tunnelName
        Start-Sleep -Milliseconds 750
    }
} finally {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        try {
            [void](Start-Process -FilePath $amneziaExe -ArgumentList @(
                '/uninstalltunnelservice', $tunnelName
            ) -Wait -PassThru -WindowStyle Hidden)
        } catch {}
    }
    if ($xray -and -not $xray.HasExited) {
        try { $xray.Kill() } catch {}
        try { [void]$xray.WaitForExit(5000) } catch {}
    }
    if (Test-Path -LiteralPath $privateRoot -PathType Container) {
        $resolvedPrivate = [IO.Path]::GetFullPath($privateRoot)
        $expectedBase = [IO.Path]::GetFullPath($privateBase).TrimEnd('\') + '\'
        if (-not $resolvedPrivate.StartsWith(
                $expectedBase, [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'The diagnostic cleanup path escaped its private root.'
        }
        Remove-Item -LiteralPath $resolvedPrivate -Recurse -Force
    }
}

$document = [ordered]@{
    schema_version = 2
    contract = 'winsvpn-windows-xray-awg-handshake-matrix-v2'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    expected_mode = $ExpectedMode
    observed_double_vpn_active = $doubleVpnActive
    direct_first_hop_port = $directPort
    xray_remote_awg_port = $remoteAwgPort
    double_vpn_core_id_sha256 = if ($doubleVpnActive) {
        Get-StringSha256 ([string]$config.double_vpn_core_id)
    } else { '' }
    double_vpn_exit_slug_sha256 = if ($doubleVpnActive) {
        Get-StringSha256 ([string]$config.double_vpn_exit_slug)
    } else { '' }
    direct_udp_unavailable_by_construction = $true
    diagnostic_awg_endpoint = '127.0.0.1:42110'
    local_awg_packet_engine_required = $true
    diagnostic_route = '192.0.2.1/32'
    xray_sha256 = Get-Sha256 $xrayExe
    amneziawg_sha256 = Get-Sha256 $amneziaExe
    lanes = $results
    all_lanes_passed = $results.Count -eq $lanes.Count -and
        @($results | Where-Object { -not $_.passed }).Count -eq 0
    teardown_clean = -not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and
        @(Get-NetAdapter -Name $tunnelName -IncludeHidden `
            -ErrorAction SilentlyContinue).Count -eq 0 -and
        @(Get-Process xray,winsvpn_awg_engine `
            -ErrorAction SilentlyContinue).Count -eq 0
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
    ($document | ConvertTo-Json -Depth 12) + [Environment]::NewLine
)
$stream = [IO.File]::Open(
    $outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
Write-Output "WINDOWS_XRAY_AWG_HANDSHAKE_MATRIX=$outputFull"
