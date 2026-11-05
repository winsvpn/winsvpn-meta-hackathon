# Builds and runs tools/verify_windows_winn_seam.cpp on a Windows machine
# against the REAL cmd/winn-datapath engine.
#
# Run it from a checkout on the Windows box:
#
#   powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_seam.ps1 `
#       -Engine C:\path\to\winn-datapath.exe
#
# Take the engine from a signed Winn release (any host with /usr/bin/python3):
#
#   ./tools/build_windows_winn_engine.sh --release /path/to/signed-release
#
# which verifies the release and stages build/windows/winn3/x64/winn-datapath.exe
# (and arm64/). For a dev engine from a clean git checkout, either run that
# script without --release (an UNSIGNED driver build) or:
#
#   ./tools/build_winn_protocol_engine.sh datapath-windows-amd64 winn-datapath.exe
#
# WHAT THIS COVERS, and what it deliberately does not.
#
# It drives the shipping host entry points in
# windows/runner/windows_winn_engine.cpp in the order InstallPrivilegedTunnel
# calls them, and it stands in for AmneziaWG with a plain loopback UDP socket
# speaking AmneziaWG-SHAPED datagrams. That is the whole point of the seam: it
# carries opaque outer datagrams and never looks inside one.
#
# It needs no administrator rights and touches no adapter, route or DNS server,
# so the pinned /32 on the physical LUID and the live AmneziaWG peer-endpoint
# rewrite are NOT covered here. Those live in InstallPrivilegedTunnel and need
# the privileged service, the AmneziaWG payload and a real gateway.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Engine,
    [string]$VsInstallPath = '',
    [string]$WorkDir = ''
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $PSScriptRoot 'verify_windows_winn_seam.cpp'
$engineSource = Join-Path $repoRoot 'windows\runner\windows_winn_engine.cpp'
foreach ($required in @($source, $engineSource)) {
    if (-not (Test-Path $required)) { throw "missing $required" }
}
if (-not (Test-Path $Engine)) { throw "missing engine binary $Engine" }

if ([string]::IsNullOrWhiteSpace($VsInstallPath)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; pass -VsInstallPath' }
    $VsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($VsInstallPath)) { throw 'no MSVC x64 toolset found' }
}
$vcvars = Join-Path $VsInstallPath 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $VsInstallPath" }

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP ('winnseam-' + [Guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# The configuration is written here rather than committed because the [winn]
# section must come from the SHIPPING Dart gate. Regenerate it with
# resolveWinnProtocolStart and paste it in, or point -WorkDir at a directory
# that already holds winn_e2e.conf and it is reused untouched.
$configPath = Join-Path $WorkDir 'winn_e2e.conf'
if (-not (Test-Path $configPath)) {
    @'
[Interface]
Address = 10.66.0.2/32
MTU = 1420
DNS = 10.66.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 16
S2 = 80
S3 = 16
S4 = 0
H1 = 11
H2 = 22
H3 = 33
H4 = 44
Table = off

[Peer]
PublicKey = <REDACTED_WG_KEY>
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/0

[winsapp]
tunnelgatewayipv4 = 10.66.0.1

[winn]
enabled = true
endpoint = 127.0.0.1:51820
carrier = direct-awg
max_datagram = 1400
session_id = winpc-e2e
h1 = 11
h2 = 22
h3 = 33
h4 = 44
s1 = 16
s2 = 80
s3 = 16
s4 = 0
'@ | Set-Content -Path $configPath -Encoding ASCII
}

$build = @"
@echo off
call "$vcvars" x64 >nul || exit /b 1
cd /d "$WorkDir"
cl /nologo /W4 /WX /EHsc /std:c++17 /DNOMINMAX /DWINS_TUNNEL_SERVICE_CORE=1 /DUNICODE /D_UNICODE /wd4505 /c "$engineSource" "$source" || exit /b 1
link /nologo /OUT:verify_windows_winn_seam.exe windows_winn_engine.obj verify_windows_winn_seam.obj ws2_32.lib advapi32.lib || exit /b 1
"@
$buildScript = Join-Path $WorkDir 'build.bat'
Set-Content -Path $buildScript -Value $build -Encoding ASCII
& cmd.exe /c $buildScript
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

$exe = Join-Path $WorkDir 'verify_windows_winn_seam.exe'
& $exe $configPath $Engine
$verifyExit = $LASTEXITCODE
Write-Host ''
Write-Host "workdir: $WorkDir"
exit $verifyExit
