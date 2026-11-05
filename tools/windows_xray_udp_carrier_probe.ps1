[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$ObserverScript,
    [Parameter(Mandatory)][string]$Output,
    [ValidateSet('Advertised', 'DirectOrigin')]
    [string]$RouteMode = 'Advertised',
    [ValidateSet('Probe', 'AppParity')]
    [string]$ConfigShape = 'Probe',
    [switch]$RoundTripEcho,
    [ValidateRange(20, 90)][int]$ObserveSeconds = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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
        ).ToUpperInvariant()
    } finally { $algorithm.Dispose() }
}

function Get-ObfuscationDigest {
    param([Parameter(Mandatory)]$Obfuscation)
    $keys = @('H1', 'H2', 'H3', 'H4', 'Jc', 'Jmax', 'Jmin',
        'S1', 'S2', 'S3', 'S4')
    $parts = foreach ($key in $keys) {
        $property = $Obfuscation.PSObject.Properties[$key]
        if (-not $property -or $null -eq $property.Value) {
            throw 'The current AWG obfuscation contract is incomplete.'
        }
        '"' + $key + '":' + [string][int]$property.Value
    }
    Get-StringSha256 ('{' + ($parts -join ',') + '}')
}

function Read-DpapiCredential {
    $encrypted = [IO.File]::ReadAllText(
        (Resolve-Path -LiteralPath $CredentialStore),
        [Text.UTF8Encoding]::new($false, $true)
    ).Trim()
    $secure = ConvertTo-SecureString $encrypted
    $plain = [Net.NetworkCredential]::new('', $secure).Password
    try { $credential = $plain | ConvertFrom-Json }
    finally { $plain = $null }
    if ($credential.contract -cne 'winsvpn-windows-lab-credentials-v1' -or
        [string]$credential.hub_host -notmatch '^[A-Za-z0-9.-]{1,253}$' -or
        [string]$credential.hub_user -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or
        [string]$credential.hub_private_key_base64 -notmatch
            '^[A-Za-z0-9+/=]{128,}$') {
        throw 'The protected lab observer credential contract is invalid.'
    }
    $credential
}

function Set-OwnerOnlyAcl {
    param([Parameter(Mandatory)][string]$Path, [switch]$Directory)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($Directory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        )
    }
    [void]$acl.AddAccessRule($rule)
    $acl.SetOwner($sid)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-PrivateBytes {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][byte[]]$Bytes)
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    Set-OwnerOnlyAcl $Path
}

function Get-EndpointHost {
    param([Parameter(Mandatory)][string]$Endpoint)
    if ($Endpoint -match '^\[([^\]]+)\]:(\d{1,5})$') {
        return $Matches[1]
    }
    if ($Endpoint -match '^([^:]+):(\d{1,5})$') {
        return $Matches[1]
    }
    throw 'The selected node endpoint is invalid.'
}

function Get-LogCategories {
    param([AllowEmptyString()][string]$Text)
    [ordered]@{
        core_started = [regex]::Matches(
            $Text, 'Xray [^\r\n]* started', 'IgnoreCase'
        ).Count
        outbound_request = [regex]::Matches(
            $Text, 'tunneling request to', 'IgnoreCase'
        ).Count
        websocket_dial_failure = [regex]::Matches(
            $Text, 'failed to dial WebSocket', 'IgnoreCase'
        ).Count
        response_header_failure = [regex]::Matches(
            $Text, 'failed to decode response header', 'IgnoreCase'
        ).Count
        request_transfer_failure = [regex]::Matches(
            $Text, 'failed to transfer request payload', 'IgnoreCase'
        ).Count
        invalid_user = [regex]::Matches(
            $Text, 'invalid (?:user|account)', 'IgnoreCase'
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

$secureStateHelpers = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
$secureStateHelperItem = Get-Item -LiteralPath $secureStateHelpers -Force `
    -ErrorAction Stop
if ($secureStateHelperItem.PSIsContainer -or
    ($secureStateHelperItem.Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The fail-closed Windows secure-state helpers are unavailable.'
}
. $secureStateHelpers

$outputFull = [IO.Path]::GetFullPath($Output)
$outputParent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw 'The diagnostic output parent does not exist.'
}
if (Test-Path -LiteralPath $outputFull) {
    throw 'The diagnostic output already exists.'
}

$existingService = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
    -ErrorAction SilentlyContinue
$existingAdapter = @(Get-NetAdapter -Name winsvpn -IncludeHidden `
    -ErrorAction SilentlyContinue)
$existingXray = @(Get-Process xray -ErrorAction SilentlyContinue)
if ($existingService -or $existingAdapter.Count -gt 0 -or
    $existingXray.Count -gt 0) {
    throw 'The isolated carrier probe requires a clean native tunnel state.'
}

$credential = Read-DpapiCredential
$config = Read-WinsVpnSecureJson -Name 'vpn_config.txt'
$keypair = Read-WinsVpnSecureJson -Name 'client_keypair.json'
if ((Get-StringSha256 ([string]$config.client_public_key)) -cne
        (Get-StringSha256 ([string]$credential.client_keypair.public_key)) -or
    (Get-StringSha256 ([string]$keypair.public_key)) -cne
        (Get-StringSha256 ([string]$credential.client_keypair.public_key)) -or
    (Get-StringSha256 ([string]$config.node_slug)) -cne
        (Get-StringSha256 ([string]$credential.node_cache.selected_slug))) {
    throw 'The restored app state does not match the pinned lab identity.'
}
if (-not [bool]$config.xray.enabled -or
    [string]$config.xray.uuid -notmatch
        '^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$' -or
    [int]$config.xray.local_port -ne 42110 -or
    [string]$config.xray.remote_awg_host -cne '127.0.0.1' -or
    [int]$config.xray.remote_awg_port -ne 9110) {
    throw 'The current app state has no valid Xray-over-AWG contract.'
}

$installedXray = Join-Path $env:ProgramFiles 'WinsVPN\xray.exe'
$sourceXray = Join-Path $PSScriptRoot '..\installer\windows\dependencies\xray.exe'
if (-not (Test-Path -LiteralPath $installedXray -PathType Leaf) -or
    -not (Test-Path -LiteralPath $sourceXray -PathType Leaf) -or
    (Get-Sha256 $installedXray) -cne (Get-Sha256 $sourceXray)) {
    throw 'The installed Xray runtime is not the pinned project binary.'
}

$targetHost = if ($RouteMode -ceq 'DirectOrigin') {
    Get-EndpointHost ([string]$config.server_endpoint)
} else {
    [string]$config.xray.host
}
$targetAddress = $null
if ([Net.IPAddress]::TryParse($targetHost, [ref]$targetAddress)) {
    if ($targetAddress.IsIPv6LinkLocal -or $targetAddress.IsIPv6Multicast -or
        [Net.IPAddress]::IsLoopback($targetAddress)) {
        throw 'The carrier probe target address is unsafe.'
    }
} elseif ($targetHost -notmatch '^[A-Za-z0-9.-]{1,253}$') {
    throw 'The carrier probe target host is invalid.'
}

$localPort = 42111
$remotePort = if ($RoundTripEcho) { 49152 } else { 9110 }
if (@(Get-NetUDPEndpoint -LocalPort $localPort -ErrorAction SilentlyContinue).Count) {
    throw 'The isolated carrier probe port is already occupied.'
}
$security = ([string]$config.xray.security).Trim().ToLowerInvariant()
if ($security -notin @('none', 'tls')) {
    throw 'The current Xray security mode is invalid.'
}
$wsSettings = [ordered]@{
    path = [string]$config.xray.path
}
if ($ConfigShape -ceq 'AppParity') {
    # Keep this branch byte-semantically aligned with BuildXrayConfig() so a
    # successful nonce probe proves the production child-process contract.
    $wsSettings.headers = [ordered]@{
        Host = [string]$config.xray.server_name
    }
} else {
    $wsSettings.host = [string]$config.xray.server_name
    $wsSettings.headers = [ordered]@{
        Host = [string]$config.xray.server_name
    }
}
$streamSettings = [ordered]@{
    network = 'ws'
    security = $security
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
if ($security -ceq 'tls') {
    $streamSettings.tlsSettings = [ordered]@{
        serverName = [string]$config.xray.server_name
        allowInsecure = $false
    }
}
# BuildXrayConfig uses Xray's native VLESS UDP-over-TCP path. Process-wide
# XUDP aggregation is not needed for the AWG carrier and would make this
# production-parity probe exercise a different transport contract.
$mux = [ordered]@{
    enabled = $false
    concurrency = 0
    xudpConcurrency = 0
    xudpProxyUDP443 = 'skip'
}
$xrayConfig = [ordered]@{
    log = [ordered]@{
        loglevel = if ($ConfigShape -ceq 'AppParity') { 'warning' } else { 'debug' }
    }
    inbounds = @([ordered]@{
        tag = 'awg-carrier-probe-in'
        listen = '127.0.0.1'
        port = $localPort
        protocol = 'tunnel'
        settings = [ordered]@{
            network = 'udp'
            address = '127.0.0.1'
            port = $remotePort
            followRedirect = $false
            userLevel = 0
        }
    })
    outbounds = @([ordered]@{
        tag = 'vless-ws-probe-out'
        protocol = 'vless'
        settings = [ordered]@{
            vnext = @([ordered]@{
                address = $targetHost
                port = [int]$config.xray.port
                users = @([ordered]@{
                    id = [string]$config.xray.uuid
                    encryption = 'none'
                    level = 0
                })
            })
        }
        streamSettings = $streamSettings
        targetStrategy = 'UseIPv4'
        mux = $mux
    })
    routing = [ordered]@{
        rules = @([ordered]@{
            type = 'field'
            inboundTag = @('awg-carrier-probe-in')
            outboundTag = 'vless-ws-probe-out'
        })
    }
}

$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
if (-not (Test-Path -LiteralPath $ssh -PathType Leaf)) {
    throw 'Windows OpenSSH is unavailable.'
}
$observerSource = [IO.File]::ReadAllText(
    (Resolve-Path -LiteralPath $ObserverScript),
    [Text.UTF8Encoding]::new($false, $true)
)
$clientEgress = (Invoke-WebRequest -UseBasicParsing `
    -Uri 'https://api.ipify.org' -TimeoutSec 15).Content.Trim()
$parsedEgress = $null
if (-not [Net.IPAddress]::TryParse($clientEgress, [ref]$parsedEgress)) {
    throw 'The disconnected client egress identity is unavailable.'
}
$nonce = 'WINSXRAY' + [Guid]::NewGuid().ToString('N').ToUpperInvariant()
$windowNonce = [Guid]::NewGuid().ToString('D')
$environment = [ordered]@{
    WINS_ACCOUNT_DIGEST = Get-StringSha256 `
        ([string]$credential.node_request.account_number)
    WINS_DEVICE_DIGEST = Get-StringSha256 `
        ([string]$credential.node_request.device_id)
    WINS_PUBLIC_KEY_DIGEST = Get-StringSha256 `
        ([string]$credential.client_keypair.public_key)
    WINS_NODE_SLUG_DIGEST = Get-StringSha256 ([string]$config.node_slug)
    WINS_CLIENT_EGRESS_DIGEST = Get-StringSha256 $parsedEgress.ToString()
    WINS_CLIENT_PSK_DIGEST = Get-StringSha256 ([string]$config.preshared_key)
    WINS_CLIENT_SERVER_KEY_DIGEST = Get-StringSha256 `
        ([string]$config.server_public_key)
    WINS_CLIENT_OBFUSCATION_DIGEST = Get-ObfuscationDigest `
        $config.obfuscation
    WINS_OBSERVE_SECONDS = [string]$ObserveSeconds
    WINS_OBSERVE_MODE = 'direct'
    WINS_TARGET_XRAY_PORT = [string][int]$config.xray.port
    WINS_OBSERVATION_NONCE = $windowNonce
    WINS_PROBE_PAYLOAD_NONCE = $nonce
    WINS_PROBE_ECHO_PORT = if ($RoundTripEcho) { [string]$remotePort } else { '0' }
    WINS_PROBE_ECHO_BIND = if ($RoundTripEcho) { 'loopback' } else { 'awg_gateway' }
    WINS_PROBE_GATEWAY_DIGEST = if ($RoundTripEcho) {
        Get-StringSha256 '127.0.0.1'
    } else { '' }
}
$remote = (($environment.Keys | ForEach-Object {
    "$_=$($environment[$_])"
}) -join ' ') + ' python3 -'

$privateBase = Join-Path $env:LOCALAPPDATA 'WinsVPN\CarrierProbe'
$privateRoot = Join-Path $privateBase ([Guid]::NewGuid().ToString('D'))
New-Item -ItemType Directory -Path $privateRoot | Out-Null
Set-OwnerOnlyAcl $privateRoot -Directory
$keyPath = Join-Path $privateRoot 'observer-key'
$knownPath = Join-Path $privateRoot 'known-hosts'
$configPath = Join-Path $privateRoot 'client.json'
Write-PrivateBytes $keyPath ([Convert]::FromBase64String(
    [string]$credential.hub_private_key_base64
))
Write-PrivateBytes $knownPath ([Text.UTF8Encoding]::new($false).GetBytes(
    ([string]$credential.hub_known_hosts).Trim() + [Environment]::NewLine
))
Write-PrivateBytes $configPath ([Text.UTF8Encoding]::new($false).GetBytes(
    ($xrayConfig | ConvertTo-Json -Depth 16 -Compress) +
        [Environment]::NewLine
))

$observer = $null
$xray = $null
$observerResult = $null
$xrayStarted = $false
$xrayExitedEarly = $false
$roundTripEchoMatches = 0
$stdoutText = ''
$stderrText = ''
try {
    $observerInfo = [Diagnostics.ProcessStartInfo]::new()
    $observerInfo.FileName = $ssh
    $observerInfo.Arguments = '-i "' + $keyPath + '" -o BatchMode=yes ' +
        '-o ConnectTimeout=12 -o ConnectionAttempts=1 ' +
        '-o StrictHostKeyChecking=yes -o UserKnownHostsFile="' +
        $knownPath + '" -o GlobalKnownHostsFile=NUL -o UpdateHostKeys=no ' +
        [string]$credential.hub_user + '@' + [string]$credential.hub_host +
        ' "' + $remote + '"'
    $observerInfo.UseShellExecute = $false
    $observerInfo.CreateNoWindow = $true
    $observerInfo.RedirectStandardInput = $true
    $observerInfo.RedirectStandardOutput = $true
    $observerInfo.RedirectStandardError = $true
    $observer = [Diagnostics.Process]::new()
    $observer.StartInfo = $observerInfo
    if (-not $observer.Start()) { throw 'The pinned observer did not start.' }
    $observerStdout = $observer.StandardOutput.ReadToEndAsync()
    $observerStderr = $observer.StandardError.ReadToEndAsync()
    $observer.StandardInput.Write($observerSource)
    $observer.StandardInput.Close()
    Start-Sleep -Seconds 2

    $xrayInfo = [Diagnostics.ProcessStartInfo]::new()
    $xrayInfo.FileName = $installedXray
    $xrayInfo.Arguments = 'run -c "' + $configPath + '"'
    $xrayInfo.UseShellExecute = $false
    $xrayInfo.CreateNoWindow = $true
    $xrayInfo.RedirectStandardOutput = $true
    $xrayInfo.RedirectStandardError = $true
    $xray = [Diagnostics.Process]::new()
    $xray.StartInfo = $xrayInfo
    if (-not $xray.Start()) { throw 'The isolated Xray process did not start.' }
    $xrayStarted = $true
    $xrayStdout = $xray.StandardOutput.ReadToEndAsync()
    $xrayStderr = $xray.StandardError.ReadToEndAsync()
    Start-Sleep -Milliseconds 1500
    if ($xray.HasExited) {
        $xrayExitedEarly = $true
    } else {
        $udp = [Net.Sockets.UdpClient]::new()
        try {
            $udp.Client.ReceiveTimeout = 3000
            $payload = [Text.Encoding]::ASCII.GetBytes($nonce)
            foreach ($attempt in 1..3) {
                [void]$udp.Send($payload, $payload.Length, '127.0.0.1', $localPort)
                if ($RoundTripEcho) {
                    $replyEndpoint = [Net.IPEndPoint]::new(
                        [Net.IPAddress]::Any, 0
                    )
                    try {
                        $reply = $udp.Receive([ref]$replyEndpoint)
                        if ([Linq.Enumerable]::SequenceEqual(
                                [byte[]]$payload, [byte[]]$reply
                            )) {
                            $roundTripEchoMatches++
                        }
                    } catch [Net.Sockets.SocketException] {}
                }
                Start-Sleep -Milliseconds 150
            }
        } finally { $udp.Dispose() }
    }

    if (-not $observer.WaitForExit(($ObserveSeconds + 60) * 1000)) {
        try { $observer.Kill() } catch {}
        throw 'The pinned server observation timed out.'
    }
    if ($observer.ExitCode -ne 0 -or
        [string]::IsNullOrWhiteSpace($observerStdout.Result)) {
        throw 'The pinned server observation failed: ' +
            (Get-StringSha256 $observerStderr.Result)
    }
    $observerResult = $observerStdout.Result | ConvertFrom-Json
    if ($observerResult.contract -cne
            'winsvpn-windows-spain-live-observation-v1' -or
        $observerResult.observer_authenticated -ne $true -or
        [string]$observerResult.observation_window_nonce -cne $windowNonce) {
        throw 'The pinned server observation contract is invalid.'
    }
} finally {
    if ($observer -and -not $observer.HasExited) {
        try { $observer.Kill() } catch {}
    }
    if ($xray -and -not $xray.HasExited) {
        try { $xray.Kill() } catch {}
        try { [void]$xray.WaitForExit(5000) } catch {}
    }
    if ($xrayStarted) {
        try { $stdoutText = $xrayStdout.Result } catch {}
        try { $stderrText = $xrayStderr.Result } catch {}
    }
    if (Test-Path -LiteralPath $privateRoot -PathType Container) {
        $resolvedPrivate = [IO.Path]::GetFullPath($privateRoot)
        $expectedBase = [IO.Path]::GetFullPath($privateBase).TrimEnd('\') + '\'
        if ($resolvedPrivate.StartsWith(
                $expectedBase, [StringComparison]::OrdinalIgnoreCase
            )) {
            Remove-Item -LiteralPath $privateRoot -Recurse -Force
        }
    }
}

$combinedLog = $stdoutText + [Environment]::NewLine + $stderrText
$forwardedToAwgListener = $false
if ($observerResult -and
    $observerResult.xray_redirects_all_vless_udp_to_awg9110 -eq $true -and
    [int]$observerResult.probe_payload_matches -ge 3) {
    $forwardedToAwgListener = $true
}
$result = [ordered]@{
    schema_version = 1
    contract = 'winsvpn-windows-xray-udp-carrier-probe-v1'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    route_mode = $RouteMode.ToLowerInvariant()
    config_shape = $ConfigShape.ToLowerInvariant()
    round_trip_echo_requested = [bool]$RoundTripEcho
    round_trip_echo_matches = $roundTripEchoMatches
    payload_forwarded_to_production_awg_listener = $forwardedToAwgListener
    round_trip_echo_supported_by_production_redirect = $false
    secret_material_redacted = $true
    publication_authorized = $false
    public_release_gate_eligible = $false
    installed_xray_sha256 = Get-Sha256 $installedXray
    target_is_advertised_host = $RouteMode -ceq 'Advertised'
    xray_started = $xrayStarted
    xray_exited_during_startup = $xrayExitedEarly
    xray_log_sha256 = Get-StringSha256 $combinedLog
    xray_log_categories = Get-LogCategories $combinedLog
    server = $observerResult
    teardown_clean = @(
        Get-Process xray -ErrorAction SilentlyContinue
    ).Count -eq 0
}
$bytes = [Text.UTF8Encoding]::new($false).GetBytes(
    ($result | ConvertTo-Json -Depth 16) + [Environment]::NewLine
)
$stream = [IO.File]::Open(
    $outputFull, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
    [IO.FileShare]::None
)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
finally { $stream.Dispose() }
Write-Output "WINDOWS_XRAY_UDP_CARRIER_PROBE=$outputFull"
