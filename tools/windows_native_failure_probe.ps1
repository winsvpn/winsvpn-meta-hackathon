[CmdletBinding()]
param(
    [string]$InputTool = "$PSScriptRoot\windows_interactive_input.ps1",
    [string]$CaptureTool = "$PSScriptRoot\windows_interactive_uia_probe.ps1",
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\native-probe',
    [ValidateRange(10, 90)][int]$ObserveSeconds = 45,
    [ValidateRange(0.0, 1.0)][double]$PowerXFraction = 0.5,
    [ValidateRange(0.0, 1.0)][double]$PowerYFraction = 0.795
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN native probe must run in the signed-in interactive session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN native probe requires an elevated interactive session."
}
foreach ($tool in @($InputTool, $CaptureTool)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Required probe tool is missing: $tool"
    }
}

$amnezia = 'C:\Program Files\AmneziaWG\amneziawg.exe'
if (-not (Test-Path -LiteralPath $amnezia -PathType Leaf)) {
    throw 'The installed AmneziaWG executable is missing.'
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$evidencePath = Join-Path $OutputRoot "native-probe-$stamp.json"
$dumpPath = Join-Path $OutputRoot "amnezia-dumplog-$stamp.txt"
$uiJson = Join-Path $OutputRoot "native-probe-ui-$stamp.json"
$uiPng = Join-Path $OutputRoot "native-probe-ui-$stamp.png"
$configPath = 'C:\ProgramData\WinsVPN\winsvpn.conf'
$timeline = [Collections.Generic.List[object]]::new()
$lastSignature = ''
$dumpCaptured = $false
$sawTunnelService = $false

function Get-NativeState {
    $service = Get-Service -Name 'AmneziaWGTunnel$winsvpn' -ErrorAction SilentlyContinue
    $adapter = Get-NetAdapter -Name winsvpn -IncludeHidden -ErrorAction SilentlyContinue
    [pscustomobject]@{
        at_utc = [DateTime]::UtcNow.ToString('o')
        service = if ($service) { $service.Status.ToString() } else { 'absent' }
        adapter = if ($adapter) { [string]$adapter.Status } else { 'absent' }
        config_present = Test-Path -LiteralPath $configPath -PathType Leaf
        xray_running = $null -ne (Get-Process -Name xray -ErrorAction SilentlyContinue)
    }
}

$initial = Get-NativeState
if ($initial.service -ne 'absent' -or $initial.adapter -ne 'absent') {
    throw 'Refusing to start the native probe while a tunnel is already present.'
}

& $InputTool -Action Click -XFraction $PowerXFraction `
    -YFraction $PowerYFraction -SettleSeconds 0 | Out-Null

$deadline = [DateTime]::UtcNow.AddSeconds($ObserveSeconds)
do {
    $state = Get-NativeState
    $signature = "$($state.service)|$($state.adapter)|$($state.config_present)|$($state.xray_running)"
    if ($signature -cne $lastSignature) {
        $timeline.Add($state)
        $lastSignature = $signature
    }
    if ($state.service -ne 'absent') {
        $sawTunnelService = $true
        if (-not $dumpCaptured) {
            try {
                & $amnezia /dumplog 2>&1 | Set-Content -LiteralPath $dumpPath -Encoding UTF8
                $dumpCaptured = Test-Path -LiteralPath $dumpPath -PathType Leaf
            } catch {}
        }
    }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)

& $CaptureTool -OutputPath $uiJson -ScreenshotPath $uiPng -WarmupSeconds 1 | Out-Null
$final = Get-NativeState

if ($final.service -ne 'absent' -or $final.adapter -ne 'absent') {
    & $InputTool -Action Click -XFraction $PowerXFraction `
        -YFraction $PowerYFraction -SettleSeconds 2 | Out-Null
    $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        Start-Sleep -Milliseconds 500
        $final = Get-NativeState
    } while (($final.service -ne 'absent' -or $final.adapter -ne 'absent') -and
        [DateTime]::UtcNow -lt $cleanupDeadline)
}

$evidence = [ordered]@{
    schema_version = 1
    tested_at_utc = [DateTime]::UtcNow.ToString('o')
    secret_material_redacted = $true
    saw_tunnel_service = $sawTunnelService
    dump_captured = $dumpCaptured
    dump_sha256 = if ($dumpCaptured) {
        (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256).Hash.ToLowerInvariant()
    } else { '' }
    final_service = $final.service
    final_adapter = $final.adapter
    cleanup_ok = $final.service -eq 'absent' -and $final.adapter -eq 'absent'
    ui_screenshot_sha256 = (Get-FileHash -LiteralPath $uiPng -Algorithm SHA256).Hash.ToLowerInvariant()
    timeline = @($timeline)
}
$evidence | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $evidencePath -Encoding UTF8

Write-Output 'WINDOWS_NATIVE_FAILURE_PROBE=PASS'
Write-Output "WINDOWS_NATIVE_FAILURE_EVIDENCE=$evidencePath"
