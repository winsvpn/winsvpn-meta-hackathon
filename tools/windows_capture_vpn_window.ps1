[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN capture must run in the signed-in interactive user session."
}

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class WinsVpnCaptureNative {
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
}
'@

[WinsVpnCaptureNative]::SetProcessDpiAwarenessContext([IntPtr]::new(-4)) |
    Out-Null
$sessionId = (Get-Process -Id $PID).SessionId
$process = Get-Process -Name wins_vpn -ErrorAction Stop |
    Where-Object { $_.SessionId -eq $sessionId } |
    Select-Object -First 1
if (-not $process -or $process.MainWindowHandle -eq [IntPtr]::Zero) {
    throw "Win's VPN does not have an interactive main window in session $sessionId."
}

$rect = [WinsVpnCaptureNative+RECT]::new()
if (-not [WinsVpnCaptureNative]::GetWindowRect(
        $process.MainWindowHandle,
        [ref]$rect
    )) {
    throw "Win's VPN physical window rectangle could not be read."
}
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
if ($width -lt 320 -or $height -lt 480) {
    throw "Win's VPN reported an implausible window size: ${width}x${height}."
}

[WinsVpnCaptureNative]::SetForegroundWindow($process.MainWindowHandle) |
    Out-Null
Start-Sleep -Milliseconds 500
$bitmap = [Drawing.Bitmap]::new($width, $height)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
try {
    $graphics.CopyFromScreen(
        $rect.Left,
        $rect.Top,
        0,
        0,
        [Drawing.Size]::new($width, $height)
    )
    $bitmap.Save($OutputPath, [Drawing.Imaging.ImageFormat]::Png)
}
finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}

Write-Output "WINDOWS_VPN_CAPTURE=PASS width=$width height=$height"
