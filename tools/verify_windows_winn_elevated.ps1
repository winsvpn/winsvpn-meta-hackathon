# Builds and runs tools/verify_windows_winn_elevated.cpp on a Windows machine,
# AS ADMINISTRATOR.
#
# THE ONE COMMAND (from an Administrator PowerShell, at the repo root):
#
#   powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1
#
# That alone builds and runs TIER A's route-pin test (item 1) plus TIER B's
# read-only status probe. If you still have winn-datapath.exe from the
# tools/verify_windows_winn_seam.ps1 run, add it to also run the engine-kill
# test (item 4, partial):
#
#   powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1 `
#       -Engine C:\path\to\winn-datapath.exe
#
# Don't have that binary handy? Stage it from a signed Winn release on any
# host with /usr/bin/python3:
#
#   ./tools/build_windows_winn_engine.sh --release /path/to/signed-release
#
# which writes build/windows/winn3/x64/winn-datapath.exe. For a dev engine from
# a clean git checkout:
#
#   ./tools/build_winn_protocol_engine.sh datapath-windows-amd64 winn-datapath.exe
#
# See tools/README_WINDOWS_ELEVATED_VERIFY.md for what a pass looks like and
# exactly what to paste back.
#
# WHAT THIS COVERS, and what it deliberately does not: see the header comment
# at the top of tools/verify_windows_winn_elevated.cpp. Short version: TIER A
# needs administrator rights only and runs unconditionally (a synthetic route
# pin, and the engine-kill test if -Engine is given); TIER B is a read-only
# status probe that only reports something once you separately connect a real
# winn/3 tunnel through the app against a real AmneziaWG gateway.

[CmdletBinding()]
param(
    [string]$Engine = '',
    [string]$Config = '',
    [string]$VsInstallPath = '',
    [string]$WorkDir = ''
)

$ErrorActionPreference = 'Stop'

# --- Elevation, checked before anything else: it is the single most likely
# failure and the cheapest thing to check. Every Tier A check needs it. -----
# (::new() rather than New-Object's parenthetical-argument form, to match the
# unambiguous constructor idiom tools/windows_non_elevated_uapi_probe.ps1
# already uses elsewhere in this repo.)
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host 'FAIL: this PowerShell window is not running as Administrator.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'Open the Start menu, right-click "Windows Terminal" or "PowerShell",'
    Write-Host 'choose "Run as administrator", cd back into this repository, and re-run:'
    Write-Host ''
    Write-Host '  powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1'
    Write-Host ''
    exit 2
}
Write-Host 'ok   this PowerShell window is running as Administrator'

# --- Engine/Config must arrive together or not at all. ----------------------
if ([string]::IsNullOrWhiteSpace($Engine) -and -not [string]::IsNullOrWhiteSpace($Config)) {
    throw '-Config was given without -Engine. Both are needed together for the engine-kill test, or pass neither to run only the route-pin test.'
}
if (-not [string]::IsNullOrWhiteSpace($Engine) -and -not (Test-Path $Engine)) {
    throw "missing engine binary $Engine"
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$source = Join-Path $PSScriptRoot 'verify_windows_winn_elevated.cpp'
$engineSource = Join-Path $repoRoot 'windows\runner\windows_winn_engine.cpp'
$clientSource = Join-Path $repoRoot 'windows\runner\windows_tunnel_service_client.cpp'
foreach ($required in @($source, $engineSource, $clientSource)) {
    if (-not (Test-Path $required)) { throw "missing $required" }
}

if ([string]::IsNullOrWhiteSpace($VsInstallPath)) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path $vswhere)) { throw 'vswhere.exe not found; pass -VsInstallPath' }
    $VsInstallPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ([string]::IsNullOrWhiteSpace($VsInstallPath)) { throw 'no MSVC x64 toolset found' }
}
$vcvars = Join-Path $VsInstallPath 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path $vcvars)) { throw "vcvarsall.bat not found under $VsInstallPath" }

if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $env:TEMP ('winnelevated-' + [Guid]::NewGuid().ToString('N'))
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

# If -Engine was given but -Config was not, write the same synthetic config
# tools/verify_windows_winn_seam.ps1 uses -- it carries no key material, and
# the [winn] half must come from the shipping Dart gate
# (resolveWinnProtocolStart) if you want it to be more than a shape check.
# Point -Config at a real one (e.g. the one verify_windows_winn_seam.ps1's
# -WorkDir already holds) to reuse it untouched.
$configPath = ''
if (-not [string]::IsNullOrWhiteSpace($Engine)) {
    if ([string]::IsNullOrWhiteSpace($Config)) {
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
session_id = winpc-elevated
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
    } else {
        if (-not (Test-Path $Config)) { throw "missing config $Config" }
        $configPath = $Config
    }
}

# Same flags as tools/verify_windows_winn_seam.ps1's build, plus iphlpapi.lib
# for the route APIs (CreateIpForwardEntry2/GetBestRoute2/GetIpForwardTable2)
# and windows_tunnel_service_client.cpp for the Tier B status probe.
# /DWINS_TUNNEL_SERVICE_CORE=1 applies to every .cpp in this one invocation,
# which matters: windows_winn_engine.h gates BindWindowsWinnSeam and friends
# behind that macro, and it must be defined the same way for the .cpp that
# calls them as for the .cpp that implements them.
$build = @"
@echo off
call "$vcvars" x64 >nul || exit /b 1
cd /d "$WorkDir"
cl /nologo /W4 /WX /EHsc /std:c++17 /DNOMINMAX /DWINS_TUNNEL_SERVICE_CORE=1 /DUNICODE /D_UNICODE /wd4505 /c "$engineSource" "$clientSource" "$source" || exit /b 1
link /nologo /OUT:verify_windows_winn_elevated.exe windows_winn_engine.obj windows_tunnel_service_client.obj verify_windows_winn_elevated.obj ws2_32.lib advapi32.lib iphlpapi.lib || exit /b 1
"@
$buildScript = Join-Path $WorkDir 'build.bat'
Set-Content -Path $buildScript -Value $build -Encoding ASCII
Write-Host ''
Write-Host "building in $WorkDir ..."
& cmd.exe /c $buildScript
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host 'FAIL: the build itself did not succeed (see the compiler/linker' -ForegroundColor Red
    Write-Host 'output above). This is a COMPILE failure, not a verification' -ForegroundColor Red
    Write-Host 'failure -- nothing ran yet. Paste the output above back verbatim.' -ForegroundColor Red
    exit 1
}

$exe = Join-Path $WorkDir 'verify_windows_winn_elevated.exe'
Write-Host ''
Write-Host 'running (as Administrator) ...'
Write-Host ''
if ([string]::IsNullOrWhiteSpace($Engine)) {
    & $exe
} else {
    & $exe $configPath $Engine
}
$verifyExit = $LASTEXITCODE
Write-Host ''
Write-Host "workdir: $WorkDir"
exit $verifyExit
