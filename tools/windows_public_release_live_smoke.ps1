[CmdletBinding()]
param(
    [string]$Artifact = 'build\windows-installer\WinsVPN-Setup.exe',
    [string]$EvidenceBundleIndex = '',
    [string]$MapScreenshot = '',
    [string]$ReleaseInputIndex = '',
    [string]$BuildReceipt = '',
    [string]$OutputRoot = '.artifacts\release-evidence',
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Python = if (Get-Command python.exe -ErrorAction SilentlyContinue) {
    (Get-Command python.exe).Source
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    (Get-Command python3).Source
} else {
    throw 'Python 3 is required for the Windows public-release live-smoke producer.'
}
$arguments = @(
    (Join-Path $PSScriptRoot 'public_release_live_smoke_common.py'),
    '--platform', 'windows',
    '--producer', 'tools/windows_public_release_live_smoke.ps1'
)
if ($SelfTest) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $PSScriptRoot 'windows_release_matrix_driver.ps1') -SelfTest
    if ($LASTEXITCODE -ne 0) {
        throw "Windows machine-evidence driver self-test failed with exit code $LASTEXITCODE."
    }
    $arguments += '--self-test'
} else {
    if ([string]::IsNullOrWhiteSpace($EvidenceBundleIndex) -or [string]::IsNullOrWhiteSpace($MapScreenshot) -or
        [string]::IsNullOrWhiteSpace($ReleaseInputIndex) -or [string]::IsNullOrWhiteSpace($BuildReceipt)) {
        throw 'EvidenceBundleIndex, MapScreenshot, ReleaseInputIndex, and BuildReceipt are required from the fixed Windows physical collector.'
    }
    $artifactPath = if ([IO.Path]::IsPathRooted($Artifact)) { $Artifact } else { Join-Path $RepoRoot $Artifact }
    $bundlePath = if ([IO.Path]::IsPathRooted($EvidenceBundleIndex)) { $EvidenceBundleIndex } else { Join-Path $RepoRoot $EvidenceBundleIndex }
    $mapScreenshotPath = if ([IO.Path]::IsPathRooted($MapScreenshot)) { $MapScreenshot } else { Join-Path $RepoRoot $MapScreenshot }
    $indexPath = if ([IO.Path]::IsPathRooted($ReleaseInputIndex)) { $ReleaseInputIndex } else { Join-Path $RepoRoot $ReleaseInputIndex }
    $receiptPath = if ([IO.Path]::IsPathRooted($BuildReceipt)) { $BuildReceipt } else { Join-Path $RepoRoot $BuildReceipt }
    $compiledDir = Join-Path $RepoRoot ('.artifacts\release-evidence\windows-compiled\' + [Guid]::NewGuid().ToString())
    $transcriptPath = Join-Path $compiledDir 'native-transcript.json'
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
        (Join-Path $PSScriptRoot 'windows_release_matrix_driver.ps1') `
        -EvidenceBundleIndex $bundlePath -Artifact $artifactPath `
        -MapScreenshot $mapScreenshotPath -ReleaseInputIndex $indexPath `
        -BuildReceipt $receiptPath -Output $transcriptPath
    if ($LASTEXITCODE -ne 0) {
        throw "Windows machine-evidence driver failed with exit code $LASTEXITCODE."
    }
    $arguments += @('--artifact', $artifactPath, '--native-transcript', $transcriptPath, '--map-screenshot', $mapScreenshotPath, '--release-input-index', $indexPath, '--build-receipt', $receiptPath, '--output-root', $OutputRoot)
}
& $Python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Windows public-release live-smoke producer failed with exit code $LASTEXITCODE."
}
