#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Output,
    [string]$DartBin = $env:DART_BIN
)

$ErrorActionPreference = 'Stop'
$HostDir = Join-Path $PSScriptRoot 'host'
if (-not $DartBin) {
    $resolved = Get-Command dart.exe -ErrorAction SilentlyContinue
    if ($resolved) { $DartBin = $resolved.Source }
}
if (-not $DartBin -or -not (Test-Path -LiteralPath $DartBin -PathType Leaf)) {
    throw 'Native-host build refused: reviewed dart.exe is unavailable.'
}
$Output = [IO.Path]::GetFullPath($Output)
# The temporary keeps an .exe suffix: PowerShell refuses to run a path with any other
# extension ("Cannot run a document in the middle of a pipeline") at the --selftest call below.
$temporary = "$Output.new.$PID.exe"
New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($Output)) | Out-Null
Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
try {
    Push-Location $HostDir
    try {
        & $DartBin pub get --offline --enforce-lockfile
        if ($LASTEXITCODE -ne 0) { throw 'dart pub get --offline --enforce-lockfile failed for native host.' }
        & $DartBin compile exe bin/wins_bridge_host.dart -o $temporary
        if ($LASTEXITCODE -ne 0) { throw 'dart compile exe failed for native host.' }
    } finally {
        Pop-Location
    }
    & $temporary --selftest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Compiled native host failed --selftest.' }
    Move-Item -LiteralPath $temporary -Destination $Output -Force
} finally {
    Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
}
Write-Host "Native host built and self-tested: $Output"
