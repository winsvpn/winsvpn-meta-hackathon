param(
    [Parameter(Mandatory)]
    [ValidateSet('Start', 'Collect')]
    [string]$Action,
    [Parameter(Mandatory)]
    [ValidateSet('direct', 'xray')]
    [string]$Lane,
    [string]$AccountDigest,
    [string]$DeviceDigest,
    [string]$PublicKeyDigest,
    [string]$NodeSlugDigest,
    [string]$ClientEgressDigest,
    [int]$DurationSeconds = 60,
    [string]$CoreSudoCredentialStore = (Join-Path $env:LOCALAPPDATA 'WinsVPN\B661Observers\core-sudo.dpapi')
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$StateRoot = Join-Path $env:LOCALAPPDATA 'WinsVPN\B661Observers'
$StatePath = Join-Path $StateRoot "$Lane-state.json"
$Ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$Identity = Join-Path $env:USERPROFILE '.ssh\id_ed25519_wins_ionos'
$KnownHosts = Join-Path $env:USERPROFILE '.ssh\known_hosts'
$Hub = 'root@<KANSAS_IP>'

function Assert-Digest([string]$Value, [string]$Name) {
    if ($Value -cnotmatch '^[0-9A-F]{64}$') { throw "$Name is not an uppercase SHA-256 digest." }
}

function Start-Observer([string]$Kind, [hashtable]$Environment, [string]$Directory) {
    $helper = if ($Kind -ceq 'Core') {
        Join-Path $Root 'tools\windows_core_live_observation.py'
    } else {
        Join-Path $Root 'tools\windows_spain_live_observation.py'
    }
    $remoteEnvironment = (($Environment.Keys | Sort-Object | ForEach-Object {
        "$_=$($Environment[$_])"
    }) -join ' ')
    $remote = $remoteEnvironment + ' python3 -'
    $stdout = Join-Path $Directory "$($Kind.ToLowerInvariant()).json"
    $stderr = Join-Path $Directory "$($Kind.ToLowerInvariant()).stderr"
    if ($Kind -ceq 'Core') {
        if (-not (Test-Path -LiteralPath $CoreSudoCredentialStore -PathType Leaf)) {
            throw 'Protected Core observer credential store is missing.'
        }
        $runner = Join-Path $Root 'tools\b661_core_observer_runner.ps1'
        $arguments = @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$runner`"",
            '-Ssh', "`"$Ssh`"", '-Identity', "`"$Identity`"", '-KnownHosts', "`"$KnownHosts`"",
            '-Hub', $Hub, '-RemoteEnvironment', "`"$remoteEnvironment`"", '-HelperPath', "`"$helper`"",
            '-CredentialStore', "`"$CoreSudoCredentialStore`"", '-StdoutPath', "`"$stdout`"",
            '-StderrPath', "`"$stderr`""
        )
        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
            -WindowStyle Hidden -PassThru
        return [ordered]@{ pid = $process.Id; stdout = $stdout; stderr = $stderr; kind = $Kind }
    }
    $arguments = @(
        '-i', "`"$Identity`"", '-o', 'BatchMode=yes',
        '-o', 'ConnectTimeout=12', '-o', 'ConnectionAttempts=1',
        '-o', 'StrictHostKeyChecking=yes',
        '-o', "UserKnownHostsFile=`"$KnownHosts`"",
        '-o', 'GlobalKnownHostsFile=NUL', '-o', 'UpdateHostKeys=no',
        $Hub, "`"$remote`""
    )
    $process = Start-Process -FilePath $Ssh -ArgumentList $arguments `
        -WindowStyle Hidden -PassThru -RedirectStandardInput $helper `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    [ordered]@{ pid = $process.Id; stdout = $stdout; stderr = $stderr; kind = $Kind }
}

if ($Action -ceq 'Start') {
    foreach ($pair in @(
        @($AccountDigest, 'AccountDigest'), @($DeviceDigest, 'DeviceDigest'),
        @($PublicKeyDigest, 'PublicKeyDigest'), @($NodeSlugDigest, 'NodeSlugDigest'),
        @($ClientEgressDigest, 'ClientEgressDigest')
    )) { Assert-Digest $pair[0] $pair[1] }
    if ($DurationSeconds -lt 30 -or $DurationSeconds -gt 240) {
        throw 'DurationSeconds must be between 30 and 240.'
    }
    if (Test-Path -LiteralPath $StatePath) { throw 'Observer state already exists for this lane.' }
    [void](New-Item -ItemType Directory -Force -Path $StateRoot)
    $nonce = [Guid]::NewGuid().ToString()
    $directory = Join-Path $StateRoot "$Lane-$nonce"
    [void](New-Item -ItemType Directory -Path $directory)
    $common = @{
        WINS_ACCOUNT_DIGEST = $AccountDigest
        WINS_DEVICE_DIGEST = $DeviceDigest
        WINS_PUBLIC_KEY_DIGEST = $PublicKeyDigest
        WINS_NODE_SLUG_DIGEST = $NodeSlugDigest
        WINS_CLIENT_EGRESS_DIGEST = $ClientEgressDigest
        WINS_OBSERVE_SECONDS = [string]$DurationSeconds
        WINS_OBSERVE_MODE = 'double_exit'
        WINS_TARGET_XRAY_PORT = if ($Lane -ceq 'xray') { '80' } else { '80' }
        WINS_OBSERVATION_NONCE = $nonce
    }
    $node = Start-Observer Node $common $directory
    $coreEnvironment = @{} + $common
    $coreEnvironment.WINS_CORE_DIRECT_PORT = '9210'
    $coreEnvironment.WINS_CORE_XRAY_PORT = '80'
    $core = Start-Observer Core $coreEnvironment $directory
    Start-Sleep -Seconds 2
    $failed = @($node, $core) | Where-Object {
        -not (Get-Process -Id $_.pid -ErrorAction SilentlyContinue)
    }
    if ($failed.Count) {
        foreach ($item in @($node, $core)) {
            Stop-Process -Id $item.pid -Force -ErrorAction SilentlyContinue
        }
        throw 'A synchronized observer exited before the lane was armed.'
    }
    $state = [ordered]@{
        contract = 'winsvpn-b661-synchronized-observers-v1'
        lane = $Lane; nonce = $nonce; duration_seconds = $DurationSeconds
        started_at_utc = [DateTime]::UtcNow.ToString('o')
        directory = $directory; node = $node; core = $core
    }
    $state | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $StatePath -Encoding utf8NoBOM
    [ordered]@{ ok = $true; state = 'armed'; lane = $Lane; nonce = $nonce } |
        ConvertTo-Json -Compress
    exit 0
}

if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
    throw 'Observer state is missing for this lane.'
}
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
foreach ($item in @($state.node, $state.core)) {
    $process = Get-Process -Id ([int]$item.pid) -ErrorAction SilentlyContinue
    if ($process) { $process | Wait-Process -Timeout 150 }
}
$nodeResult = Get-Content -LiteralPath $state.node.stdout -Raw | ConvertFrom-Json
$coreResult = Get-Content -LiteralPath $state.core.stdout -Raw | ConvertFrom-Json
if ($nodeResult.contract -cne 'winsvpn-windows-spain-live-observation-v1' -or
    $coreResult.contract -cne 'winsvpn-windows-core-live-observation-v1' -or
    [string]$nodeResult.observation_window_nonce -cne [string]$state.nonce -or
    [string]$coreResult.observation_window_nonce -cne [string]$state.nonce -or
    $nodeResult.observer_authenticated -ne $true -or
    $coreResult.observer_authenticated -ne $true -or
    [int]$nodeResult.peer_match_count_after -ne 1 -or
    [long]$nodeResult.rx_delta -lt 1 -or [long]$nodeResult.tx_delta -lt 1 -or
    $coreResult.assignment_revision_ready -ne $true -or
    [int]$coreResult.exact_ingress_peer_match_count_after -ne 1 -or
    $coreResult.exact_ingress_allowed_ip -ne $true -or
    [long]$coreResult.exact_ingress_peer_rx_delta -lt 1 -or
    [long]$coreResult.exact_ingress_peer_tx_delta -lt 1 -or
    [long]$coreResult.exit_tx_bytes_delta -lt 1 -or
    $coreResult.client_policy_rule_matches -ne $true -or
    $coreResult.client_route_uses_corex -ne $true -or
    $coreResult.unexpected_core_direct_egress -ne $false) {
    throw 'Synchronized Hub/Core/Spain observation failed closed.'
}
$receipt = [ordered]@{
    contract = 'winsvpn-b661-synchronized-observers-result-v1'
    lane = $Lane; nonce = [string]$state.nonce
    assignment_revision_ready = [bool]$coreResult.assignment_revision_ready
    exact_client_ingress = $true
    corex_exit_bytes_delta = [long]$coreResult.exit_tx_bytes_delta
    spain_peer_rx_delta = [long]$nodeResult.rx_delta
    spain_peer_tx_delta = [long]$nodeResult.tx_delta
    unexpected_core_direct_egress = [bool]$coreResult.unexpected_core_direct_egress
    core_transport_mode = [string]$coreResult.transport_mode
    node_observer_identity_sha256 = [string]$nodeResult.observer_identity_digest
    core_observer_identity_sha256 = [string]$coreResult.observer_identity_digest
    passed = $true
}
$receiptPath = Join-Path $state.directory 'synchronized-receipt.json'
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $receiptPath -Encoding utf8NoBOM
Remove-Item -LiteralPath $StatePath -Force
$receipt | ConvertTo-Json -Compress
