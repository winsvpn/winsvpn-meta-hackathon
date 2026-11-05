[CmdletBinding()]
param(
    [string]$AppPath = 'C:\Program Files\WinsVPN\wins_vpn.exe',
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\click-diagnostic',
    [ValidateRange(0.0, 1.0)][double]$PowerXFraction = 0.5,
    [ValidateRange(0.0, 1.0)][double]$PowerYFraction = 0.795
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN click diagnostic requires an interactive session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN click diagnostic requires elevation."
}
if (-not (Test-Path -LiteralPath $AppPath -PathType Leaf)) {
    throw "Win's VPN executable not found: $AppPath"
}

$captureTool = Join-Path $PSScriptRoot 'windows_interactive_uia_probe.ps1'
if (-not (Test-Path -LiteralPath $captureTool -PathType Leaf)) {
    throw "Win's VPN capture tool not found: $captureTool"
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WinsVpnClickDiagnosticNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }
    [DllImport("user32.dll")]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr value);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out RECT rect);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")]
    public static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")]
    public static extern bool GetCursorPos(out POINT point);
    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
}
'@

function Get-ServiceState {
    param([Parameter(Mandatory)][string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) { return 'absent' }
    return $service.Status.ToString().ToLowerInvariant()
}

function Get-SecureSettingsSha256 {
    [void](Read-WinsVpnSecureJson -Name 'vpn_settings.txt')
    $paths = Get-WinsVpnSecureStatePaths -Name 'vpn_settings.txt'
    (Get-FileHash -LiteralPath $paths.Secure -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Save-Capture {
    param([Parameter(Mandatory)][string]$Phase)
    $json = Join-Path $OutputRoot "$Phase.json"
    $png = Join-Path $OutputRoot "$Phase.png"
    & $captureTool -AppPath $AppPath -OutputPath $json `
        -ScreenshotPath $png -WarmupSeconds 1 | Out-Null
    if (-not (Test-Path -LiteralPath $png -PathType Leaf)) {
        throw "Win's VPN $Phase capture was not created."
    }
    return [ordered]@{
        json = $json
        png = $png
        screenshot_sha256 = (Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

[WinsVpnClickDiagnosticNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) | Out-Null
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$evidencePath = Join-Path $OutputRoot 'last-run.json'
$failurePath = Join-Path $env:APPDATA 'wins_vpn\last_tunnel_failure.json'
$settingsHash = Get-SecureSettingsSha256
$failureBeforeUtc = if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
    (Get-Item -LiteralPath $failurePath).LastWriteTimeUtc.ToString('o')
} else { '' }

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$app = $null
try {
    $app = Start-Process -FilePath $AppPath -PassThru
    for ($attempt = 0; $attempt -lt 40; ++$attempt) {
        Start-Sleep -Milliseconds 250
        $app.Refresh()
        if ($app.MainWindowHandle -ne [IntPtr]::Zero) { break }
    }
    if ($app.MainWindowHandle -eq [IntPtr]::Zero) {
        throw "Win's VPN did not expose its main window."
    }

    $baseline = Save-Capture -Phase 'before-click'
    $rect = [WinsVpnClickDiagnosticNative+RECT]::new()
    if (-not [WinsVpnClickDiagnosticNative]::GetWindowRect(
        $app.MainWindowHandle, [ref]$rect)) {
        throw "Win's VPN physical window rectangle could not be read."
    }
    $x = $rect.Left + [Math]::Round(($rect.Right - $rect.Left) * $PowerXFraction)
    $y = $rect.Top + [Math]::Round(($rect.Bottom - $rect.Top) * $PowerYFraction)
    [WinsVpnClickDiagnosticNative]::SetForegroundWindow($app.MainWindowHandle) | Out-Null
    Start-Sleep -Milliseconds 500
    if (-not [WinsVpnClickDiagnosticNative]::SetCursorPos($x, $y)) {
        throw "Windows rejected the diagnostic cursor position."
    }
    $cursor = [WinsVpnClickDiagnosticNative+POINT]::new()
    if (-not [WinsVpnClickDiagnosticNative]::GetCursorPos([ref]$cursor) -or
        $cursor.X -ne $x -or $cursor.Y -ne $y) {
        throw "The diagnostic cursor did not reach the power-button coordinate."
    }
    [WinsVpnClickDiagnosticNative]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
    [WinsVpnClickDiagnosticNative]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)

    Start-Sleep -Seconds 3
    $after3 = Save-Capture -Phase 'after-click-3s'
    Start-Sleep -Seconds 17
    $after20 = Save-Capture -Phase 'after-click-20s'
    $failure = $null
    if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
        try { $failure = Get-Content -LiteralPath $failurePath -Raw | ConvertFrom-Json } catch {}
    }
    $evidence = [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        platform = 'windows'
        secret_material_redacted = $true
        app_sha256 = (Get-FileHash -LiteralPath $AppPath -Algorithm SHA256).Hash.ToLowerInvariant()
        settings_sha256_before = $settingsHash
        settings_sha256_after = Get-SecureSettingsSha256
        click = [ordered]@{
            x_fraction = $PowerXFraction
            y_fraction = $PowerYFraction
            x = $x
            y = $y
            cursor_verified = $true
        }
        before_click = $baseline
        after_click_3s = $after3
        after_click_20s = $after20
        awg_service = Get-ServiceState -Name 'AmneziaWGTunnel$winsvpn'
        split_service = Get-ServiceState -Name 'WinsVPNSplitTunnel'
        xray_process_running = $null -ne (Get-Process -Name xray -ErrorAction SilentlyContinue)
        failure_file_changed = (Test-Path -LiteralPath $failurePath -PathType Leaf) -and
            (Get-Item -LiteralPath $failurePath).LastWriteTimeUtc.ToString('o') -cne $failureBeforeUtc
        failure = if ($null -ne $failure -and $failure.secret_material_redacted -eq $true) {
            [ordered]@{
                protocol = [string]$failure.protocol
                failure = [string]$failure.failure
            }
        } else { $null }
    }
    [IO.File]::WriteAllText(
        $evidencePath,
        ($evidence | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
} finally {
    Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    $awg = Get-Service -Name 'AmneziaWGTunnel$winsvpn' -ErrorAction SilentlyContinue
    $split = Get-Service -Name 'WinsVPNSplitTunnel' -ErrorAction SilentlyContinue
    if (($null -ne $awg -and $awg.Status -ne 'Stopped') -or
        ($null -ne $split -and $split.Status -ne 'Stopped')) {
        Stop-Service -Name 'WinsVpnTunnelManager' -Force -ErrorAction Stop
        (Get-Service -Name 'WinsVpnTunnelManager').WaitForStatus(
            'Stopped', [TimeSpan]::FromSeconds(180))
        Start-Service -Name 'WinsVpnTunnelManager' -ErrorAction Stop
        (Get-Service -Name 'WinsVpnTunnelManager').WaitForStatus(
            'Running', [TimeSpan]::FromSeconds(30))
    }
}

Write-Output "WINDOWS_CONNECT_CLICK_DIAGNOSTIC=$evidencePath"
