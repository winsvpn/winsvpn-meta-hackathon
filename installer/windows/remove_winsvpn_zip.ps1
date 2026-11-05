#Requires -Version 5.1
<#
remove_winsvpn_zip.ps1 — uninstallation for the zip + PowerShell install route.

Mirrors winsvpn.iss CurUninstallStepChanged:

  * the protected tunnel manager is stopped and deregistered and the
    split-tunnel driver removed by the service's own --uninstall verb, exactly
    as the Inno uninstaller does; if that fails, NOTHING is deleted and the
    uninstall aborts;
  * the Microsoft VC++ runtime and the AmneziaWG MSI are shared machine
    prerequisites and are deliberately RETAINED (Win's VPN does not claim
    exclusive ownership, and never downgrades them);

Run with elevation:  powershell -ExecutionPolicy Bypass -File remove_winsvpn_zip.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WinsVPN'),
    [switch]$NoForce
)

$ErrorActionPreference = 'Stop'
$ServiceExeName = 'wins_vpn_tunnel_service.exe'

function Fail-Fatal {
    param([string]$Message)
    Write-Host "[remove_winsvpn_zip] FATAL: $Message" -ForegroundColor Red
    exit 1
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail-Fatal 'Elevation required to stop the tunnel manager and remove the driver.'
}

$service = Join-Path $InstallDir $ServiceExeName
if (Test-Path -LiteralPath $service -PathType Leaf) {
    $psi = Start-Process -FilePath $service -ArgumentList '--uninstall' -WorkingDirectory $InstallDir -NoNewWindow -Wait -PassThru
    if ($psi.ExitCode -ne 0) {
        Fail-Fatal "Win's VPN could not safely stop its tunnel manager and remove the split-tunnel driver (--uninstall exit $($psi.ExitCode)). The uninstall was stopped before deleting the privileged service or driver payload."
    }
    Write-Host "[remove_winsvpn_zip] Tunnel manager stopped and driver removed by wins_vpn_tunnel_service.exe --uninstall."
} else {
    Write-Host "[remove_winsvpn_zip] No $ServiceExeName found at $InstallDir; skipping privileged removal."
}

if (-not $NoForce -and (Test-Path -LiteralPath $InstallDir)) {
    Write-Host "[remove_winsvpn_zip] Removing application files under $InstallDir"
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
}

Write-Host "[remove_winsvpn_zip] Done. Retained shared prerequisites: Microsoft VC runtime and AmneziaWG MSI."
exit 0