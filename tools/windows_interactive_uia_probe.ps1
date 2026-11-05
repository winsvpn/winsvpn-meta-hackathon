[CmdletBinding()]
param(
    [string]$AppPath = 'C:\Program Files\WinsVPN\wins_vpn.exe',
    [string]$OutputPath = "$env:ProgramData\WinsVPN\uia-probe.json",
    [string]$ScreenshotPath = "$env:ProgramData\WinsVPN\uia-probe.png",
    [ValidateRange(1, 60)][int]$WarmupSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [Environment]::UserInteractive) {
    throw 'The Windows UI Automation probe must run in the signed-in interactive user session.'
}
if (-not (Test-Path -LiteralPath $AppPath -PathType Leaf)) {
    throw "Win's VPN executable not found: $AppPath"
}

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class WinsVpnUiaNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr value);

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr window, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr window);

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync(IntPtr window, int command);

    [DllImport("user32.dll")]
    public static extern bool SetWindowPos(IntPtr window, IntPtr insertAfter,
        int x, int y, int width, int height, uint flags);
}
'@

# UI Automation reports logical rectangles to a DPI-unaware process, while
# screen capture consumes physical pixels.  Opt into per-monitor awareness
# before querying the target window so a multi-monitor capture remains exact.
[WinsVpnUiaNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) | Out-Null

$outputDirectory = Split-Path -Parent $OutputPath
$screenshotDirectory = Split-Path -Parent $ScreenshotPath
New-Item -ItemType Directory -Force -Path $outputDirectory, $screenshotDirectory | Out-Null

$sessionId = (Get-Process -Id $PID).SessionId
$process = Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Where-Object {
        $_.SessionId -eq $sessionId -and
        $_.MainWindowHandle -ne [IntPtr]::Zero
    } |
    Select-Object -First 1
if (-not $process) {
    Start-Process -FilePath $AppPath | Out-Null
}
# Flutter can briefly replace its HWND while restoring persisted navigation
# after a fresh install. Keep the caller's warmup intent, but always allow a
# bounded 10-second readiness window so a one-second screenshot warmup cannot
# race that replacement.
$readinessSeconds = [Math]::Max($WarmupSeconds, 10)
$deadline = [DateTime]::UtcNow.AddSeconds($readinessSeconds)
do {
    Start-Sleep -Milliseconds 250
    $process = Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Where-Object {
            $_.SessionId -eq $sessionId -and
            $_.MainWindowHandle -ne [IntPtr]::Zero
        } |
        Select-Object -First 1
} while (-not $process -and [DateTime]::UtcNow -lt $deadline)
if (-not $process) {
    throw "Win's VPN did not expose a main window after $readinessSeconds seconds."
}
$process = Get-Process -Id $process.Id -ErrorAction Stop

$root = [Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
if (-not $root) {
    throw "Win's VPN main window could not be opened through Windows UI Automation."
}

$condition = [Windows.Automation.Condition]::TrueCondition
$elements = @($root.FindAll([Windows.Automation.TreeScope]::Subtree, $condition))
$records = foreach ($element in $elements) {
    $current = $element.Current
    $name = [string]$current.Name
    $automationId = [string]$current.AutomationId
    if ([string]::IsNullOrWhiteSpace($name) -and [string]::IsNullOrWhiteSpace($automationId)) {
        continue
    }
    $patterns = @($element.GetSupportedPatterns() | ForEach-Object { $_.ProgrammaticName })
    [ordered]@{
        name = $name
        automation_id = $automationId
        class_name = [string]$current.ClassName
        control_type = [string]$current.ControlType.ProgrammaticName
        enabled = [bool]$current.IsEnabled
        offscreen = [bool]$current.IsOffscreen
        bounds = [ordered]@{
            x = [double]$current.BoundingRectangle.X
            y = [double]$current.BoundingRectangle.Y
            width = [double]$current.BoundingRectangle.Width
            height = [double]$current.BoundingRectangle.Height
        }
        patterns = $patterns
    }
}

[WinsVpnUiaNative]::ShowWindowAsync($process.MainWindowHandle, 9) | Out-Null
[WinsVpnUiaNative]::SetWindowPos(
    $process.MainWindowHandle, [IntPtr]::new(-1), 0, 0, 0, 0, 0x0043) | Out-Null
[WinsVpnUiaNative]::SetWindowPos(
    $process.MainWindowHandle, [IntPtr]::new(-2), 0, 0, 0, 0, 0x0043) | Out-Null
[WinsVpnUiaNative]::SetForegroundWindow($process.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 500
$windowRect = [WinsVpnUiaNative+RECT]::new()
if (-not [WinsVpnUiaNative]::GetWindowRect($process.MainWindowHandle, [ref]$windowRect)) {
    throw "Win's VPN physical window rectangle could not be read."
}
$windowWidth = $windowRect.Right - $windowRect.Left
$windowHeight = $windowRect.Bottom - $windowRect.Top
if ($windowWidth -lt 320 -or $windowHeight -lt 480) {
    throw "Win's VPN reported an implausible window size: ${windowWidth}x${windowHeight}."
}
$bitmap = [Drawing.Bitmap]::new($windowWidth, $windowHeight)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try {
    $graphics.CopyFromScreen($windowRect.Left, $windowRect.Top, 0, 0, $bitmap.Size)
    $bitmap.Save($ScreenshotPath, [Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}

$document = [ordered]@{
    schema_version = 1
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    process_id = $process.Id
    process_session_id = $process.SessionId
    app_sha256 = (Get-FileHash -LiteralPath $AppPath -Algorithm SHA256).Hash.ToLowerInvariant()
    window_title = [string]$root.Current.Name
    physical_window_bounds = [ordered]@{
        x = $windowRect.Left
        y = $windowRect.Top
        width = $windowWidth
        height = $windowHeight
    }
    element_count = @($records).Count
    elements = @($records)
    screenshot_sha256 = (Get-FileHash -LiteralPath $ScreenshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
$document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output 'WINDOWS_INTERACTIVE_UIA_PROBE=PASS'
Write-Output "UIA_ELEMENT_COUNT=$(@($records).Count)"
Write-Output "UIA_OUTPUT=$OutputPath"
Write-Output "UIA_SCREENSHOT=$ScreenshotPath"
