[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PWD 'winsvpn-window.png'),
    [string]$ProcessName = 'wins_vpn',
    [string]$WindowTitle = "Win's VPN",
    [int]$TimeoutSeconds = 20,
    [int]$MinimumWidth = 600,
    [int]$MinimumHeight = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($TimeoutSeconds -lt 1 -or $TimeoutSeconds -gt 120) {
    throw 'TimeoutSeconds must be from 1 through 120.'
}
if ($MinimumWidth -lt 1 -or $MinimumHeight -lt 1) {
    throw 'Minimum window dimensions must be positive.'
}

$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class WinsWindowCapture {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [DllImport("user32.dll")]
    public static extern bool SetProcessDpiAwarenessContext(IntPtr value);

    [DllImport("user32.dll")]
    public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdcBlt, uint flags);
}
'@

# GetWindowRect is DPI-virtualized for an ordinary PowerShell process. Opt in
# before reading the app bounds so a 150% display produces a complete physical
# pixel capture instead of clipping the right and bottom thirds of the window.
try {
    [void][WinsWindowCapture]::SetProcessDpiAwarenessContext([IntPtr](-4))
} catch {
    Write-Warning "Per-monitor DPI awareness was unavailable: $($_.Exception.Message)"
}

$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$process = $null
do {
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 } |
        Select-Object -First 1
    if (-not $process) { Start-Sleep -Milliseconds 250 }
} while (-not $process -and [DateTime]::UtcNow -lt $deadline)

if (-not $process) {
    throw "No visible $ProcessName window appeared within $TimeoutSeconds seconds."
}

try {
    $shell = New-Object -ComObject WScript.Shell
    [void]$shell.AppActivate($WindowTitle)
    Start-Sleep -Milliseconds 750
} catch {
    Write-Warning "Could not activate $WindowTitle before capture: $($_.Exception.Message)"
}

$rect = New-Object WinsWindowCapture+RECT
if (-not [WinsWindowCapture]::GetWindowRect($process.MainWindowHandle, [ref]$rect)) {
    throw 'GetWindowRect failed for the Win''s VPN process.'
}
$width = $rect.Right - $rect.Left
$height = $rect.Bottom - $rect.Top
if ($width -lt $MinimumWidth -or $height -lt $MinimumHeight) {
    throw "Win's VPN window is unexpectedly small: ${width}x${height}."
}

$bitmap = New-Object System.Drawing.Bitmap($width, $height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$temporary = "$OutputPath.$([Guid]::NewGuid().ToString('N')).tmp.png"
try {
    try {
        $graphics.CopyFromScreen(
            $rect.Left,
            $rect.Top,
            0,
            0,
            (New-Object System.Drawing.Size($width, $height))
        )
    } catch {
        # CopyFromScreen is unavailable when the interactive desktop is locked.
        # Print the selected top-level window into the bitmap instead so remote
        # release verification can inspect the app without capturing unrelated
        # desktop content or requiring the owner to disable the lock screen.
        $hdc = $graphics.GetHdc()
        try {
            $printed = [WinsWindowCapture]::PrintWindow(
                $process.MainWindowHandle,
                $hdc,
                2 # PW_RENDERFULLCONTENT
            )
            if (-not $printed) {
                $printed = [WinsWindowCapture]::PrintWindow(
                    $process.MainWindowHandle,
                    $hdc,
                    0
                )
            }
            if (-not $printed) {
                throw 'PrintWindow failed after CopyFromScreen was unavailable.'
            }
        } finally {
            $graphics.ReleaseHdc($hdc)
        }
    }
    $sampleStepX = [Math]::Max(1, [int]($width / 96))
    $sampleStepY = [Math]::Max(1, [int]($height / 72))
    $sampleColors = [Collections.Generic.HashSet[int]]::new()
    $minimumLuminance = 255
    $maximumLuminance = 0
    $nonDarkSampleCount = 0
    $sampleCount = 0
    for ($y = 0; $y -lt $height; $y += $sampleStepY) {
        for ($x = 0; $x -lt $width; $x += $sampleStepX) {
            $color = $bitmap.GetPixel($x, $y)
            [void]$sampleColors.Add($color.ToArgb())
            $luminance = [int](
                (0.2126 * $color.R) +
                (0.7152 * $color.G) +
                (0.0722 * $color.B)
            )
            if ($luminance -lt $minimumLuminance) { $minimumLuminance = $luminance }
            if ($luminance -gt $maximumLuminance) { $maximumLuminance = $luminance }
            if ($luminance -gt 24) { $nonDarkSampleCount++ }
            $sampleCount++
        }
    }
    $nonDarkSampleRatio = if ($sampleCount -gt 0) {
        $nonDarkSampleCount / $sampleCount
    } else {
        0
    }
    if ($sampleColors.Count -lt 8 -or
        ($maximumLuminance - $minimumLuminance) -lt 16 -or
        $nonDarkSampleRatio -lt 0.05) {
        throw "Captured Win's VPN window failed visual-sanity checks; the desktop may be locked or hardware rendering may be unavailable."
    }
    $bitmap.Save($temporary, [System.Drawing.Imaging.ImageFormat]::Png)
} finally {
    $graphics.Dispose()
    $bitmap.Dispose()
}

Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
$item = Get-Item -LiteralPath $OutputPath
$sha256 = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host '[WINDOWS-WINDOW-CAPTURE] PASS'
Write-Host "[WINDOWS-WINDOW-CAPTURE] Path: $OutputPath"
Write-Host "[WINDOWS-WINDOW-CAPTURE] Dimensions: ${width}x${height}"
Write-Host "[WINDOWS-WINDOW-CAPTURE] Bytes: $($item.Length)"
Write-Host "[WINDOWS-WINDOW-CAPTURE] SHA-256: $sha256"
