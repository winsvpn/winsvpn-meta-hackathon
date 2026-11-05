[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$ArmPath,
    [Parameter(Mandatory)][string]$DisarmPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{32}$')]
        [string]$Nonce,
    [ValidateRange(60, 600)][int]$DeadlineSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
throw 'QUARANTINED: use windows_release_safe_watchdog.ps1 through the fixed physical collector.'

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        $identity.User.Value -eq 'S-1-5-18'
}

function Get-NativeState {
    $manager = Get-Service -Name 'WinsVpnTunnelManager' `
        -ErrorAction SilentlyContinue
    $awg = Get-Service -Name 'AmneziaWGTunnel$winsvpn' `
        -ErrorAction SilentlyContinue
    $split = Get-Service -Name 'WinsVPNSplitTunnel' `
        -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name 'winsvpn' -IncludeHidden `
        -ErrorAction SilentlyContinue
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq 'winsvpn' })
    [ordered]@{
        manager_running = $null -ne $manager -and $manager.Status -eq 'Running'
        tunnel_service_running = $null -ne $awg -and $awg.Status -eq 'Running'
        split_service_running = $null -ne $split -and $split.Status -eq 'Running'
        adapter_up = $null -ne $adapter -and $adapter.Status -eq 'Up'
        xray_process_count = @(Get-Process xray -ErrorAction SilentlyContinue).Count
        tunnel_route_count = $routes.Count
    }
}

function Test-CleanState([object]$State) {
    $State.manager_running -and
        -not $State.tunnel_service_running -and
        -not $State.split_service_running -and
        -not $State.adapter_up -and
        $State.xray_process_count -eq 0 -and
        $State.tunnel_route_count -eq 0
}

function Stop-VendorTunnelService {
    $candidates = @(
        'C:\Program Files\WinsVPN\amneziawg.exe',
        'C:\Program Files\AmneziaWG\amneziawg.exe',
        'C:\Program Files (x86)\AmneziaWG\amneziawg.exe'
    )
    $executable = $candidates | Where-Object {
        Test-Path -LiteralPath $_ -PathType Leaf
    } | Select-Object -First 1
    if (-not $executable) { return 'not_found' }
    $process = Start-Process -FilePath $executable `
        -ArgumentList @('/uninstalltunnelservice', 'winsvpn') `
        -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(60000)) {
        $process.Kill()
        $process.WaitForExit(5000) | Out-Null
        return 'timeout'
    }
    return "exit_$($process.ExitCode)"
}

function Invoke-ManagerSafeCleanup {
    Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500

    $manager = Get-Service -Name 'WinsVpnTunnelManager' -ErrorAction Stop
    if ($manager.Status -ne 'Stopped') {
        Stop-Service -Name 'WinsVpnTunnelManager' -Force -ErrorAction Stop
        $manager.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    Stop-Service -Name 'WinsVPNSplitTunnel' -Force `
        -ErrorAction SilentlyContinue
    Stop-Service -Name 'AmneziaWGTunnel$winsvpn' -Force `
        -ErrorAction SilentlyContinue
    Get-Process -Name xray -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    $vendorResult = Stop-VendorTunnelService
    Get-NetRoute -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq 'winsvpn' } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    Start-Service -Name 'WinsVpnTunnelManager' -ErrorAction Stop
    (Get-Service -Name 'WinsVpnTunnelManager').WaitForStatus(
        'Running', [TimeSpan]::FromSeconds(30))
    [ordered]@{
        vendor_cleanup = $vendorResult
        post_state = Get-NativeState
    }
}

if (-not (Test-Administrator)) {
    throw 'The fail-safe watchdog requires an elevated or SYSTEM token.'
}
$rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
foreach ($path in @($ArmPath, $DisarmPath, $OutputPath)) {
    if (-not [IO.Path]::GetFullPath($path).StartsWith(
        $rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Every watchdog file must remain below the owner-only root.'
    }
}
if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
    throw 'The owner-only watchdog root is missing.'
}
$arm = Get-Content -LiteralPath $ArmPath -Raw | ConvertFrom-Json
$armFields = @($arm.PSObject.Properties.Name | Sort-Object)
$expectedArmFields = @(
    'armed', 'armed_at_utc', 'nonce', 'schema'
) | Sort-Object
if (($armFields -join '|') -cne ($expectedArmFields -join '|') -or
    [string]$arm.schema -cne 'winsvpn-windows-test-failsafe-arm-v1' -or
    [string]$arm.nonce -cne $Nonce -or $arm.armed -ne $true) {
    throw 'The watchdog arm document is invalid.'
}
try {
    [void][DateTimeOffset]::Parse(
        [string]$arm.armed_at_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind
    )
} catch {
    throw 'The watchdog arm timestamp is invalid.'
}

$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DeadlineSeconds)
$normalProof = $null
do {
    if (Test-Path -LiteralPath $DisarmPath -PathType Leaf) {
        try {
            $candidate = Get-Content -LiteralPath $DisarmPath -Raw |
                ConvertFrom-Json
            if ([string]$candidate.nonce -ceq $Nonce -and
                $candidate.normal_teardown_proven -eq $true -and
                (Test-CleanState $candidate.clean_state) -and
                (Test-CleanState (Get-NativeState))) {
                $normalProof = $candidate
                break
            }
        } catch {}
    }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)

$preState = Get-NativeState
$triggered = $null -eq $normalProof
$cleanup = $null
if ($triggered) {
    $cleanup = Invoke-ManagerSafeCleanup
}
$finalState = Get-NativeState
$pass = Test-CleanState $finalState
$document = [ordered]@{
    schema = 'winsvpn-windows-test-failsafe-watchdog-v1'
    started_at_utc = $started.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    nonce_sha256 = ''
    deadline_seconds = $DeadlineSeconds
    normal_teardown_proven = $null -ne $normalProof
    fail_safe_triggered = $triggered
    pre_state = $preState
    cleanup = $cleanup
    final_state = $finalState
    pass = $pass
    secret_material_redacted = $true
    publication_authorized = $false
}
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $document.nonce_sha256 = ([BitConverter]::ToString(
        $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Nonce))
    )).Replace('-', '')
} finally {
    $sha.Dispose()
}
[IO.File]::WriteAllText(
    $OutputPath,
    (ConvertTo-Json $document -Depth 8) + [Environment]::NewLine,
    [Text.UTF8Encoding]::new($false)
)
if (-not $pass) {
    throw 'The fail-safe watchdog could not prove clean native state.'
}
Write-Output "WINDOWS_TEST_FAILSAFE=PASS triggered=$triggered"
