[CmdletBinding()]
param(
    [ValidateSet('Click', 'Scroll')][string]$Action,
    [ValidateRange(0.0, 1.0)][double]$XFraction = 0.5,
    [ValidateRange(0.0, 1.0)][double]$YFraction = 0.5,
    [ValidateRange(-12000, 12000)][int]$WheelDelta = -720,
    [ValidateRange(0, 30)][int]$SettleSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN input automation must run in the signed-in interactive user session."
}

Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class WinsVpnInputNative {
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
    public static extern bool SetCursorPos(int x, int y);

    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extraInfo);
}
'@

[WinsVpnInputNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) | Out-Null
$sessionId = (Get-Process -Id $PID).SessionId
$process = Get-Process -Name wins_vpn -ErrorAction Stop |
    Where-Object { $_.SessionId -eq $sessionId } |
    Select-Object -First 1
if (-not $process -or $process.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "Win's VPN does not have an interactive main window in session $sessionId."
}

$rect = [WinsVpnInputNative+RECT]::new()
if (-not [WinsVpnInputNative]::GetWindowRect($process.MainWindowHandle, [ref]$rect)) {
    throw "Win's VPN physical window rectangle could not be read."
}
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
if ($width -lt 320 -or $height -lt 480) {
    throw "Win's VPN reported an implausible window size: ${width}x${height}."
}
$x = $rect.Left + [Math]::Round($width * $XFraction)
$y = $rect.Top + [Math]::Round($height * $YFraction)

[WinsVpnInputNative]::SetForegroundWindow($process.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 400
[WinsVpnInputNative]::SetCursorPos($x, $y) | Out-Null
Start-Sleep -Milliseconds 150

switch ($Action) {
    'Click' {
        [WinsVpnInputNative]::mouse_event(0x0002, 0, 0, 0, [UIntPtr]::Zero)
        [WinsVpnInputNative]::mouse_event(0x0004, 0, 0, 0, [UIntPtr]::Zero)
    }
    'Scroll' {
        $wheelBits = [BitConverter]::ToUInt32([BitConverter]::GetBytes($WheelDelta), 0)
        [WinsVpnInputNative]::mouse_event(0x0800, 0, 0, $wheelBits, [UIntPtr]::Zero)
    }
}
if ($SettleSeconds -gt 0) {
    Start-Sleep -Seconds $SettleSeconds
}
Write-Output "WINDOWS_INTERACTIVE_INPUT=PASS action=$Action x=$x y=$y"
