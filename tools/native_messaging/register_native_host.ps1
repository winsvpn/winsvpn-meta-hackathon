#Requires -Version 5.1
<#
.SYNOPSIS
  Local Windows native-messaging registration for org.winsvpn.bridge.

.DESCRIPTION
  Renders a final host manifest (never a placeholder template) and writes the
  HKCU registry key each browser consults. Chrome and Edge require a
  store-issued or caller-supplied 32-letter id; this script will not invent
  one. Firefox uses the pinned add-on id companion@winsvpn.org.

  Machine-wide HKLM registration is the Inno installer. This script is the
  per-user local contract, including uninstall.

.PARAMETER Browser
  chrome, edge, or firefox.

.PARAMETER HostPath
  Path to wins_bridge_host.exe. Relative names are allowed and stored as-is
  when they live beside the manifest, matching Chromium/Firefox Windows rules.

.PARAMETER ManifestDir
  Directory that receives the rendered JSON. Default: the host's directory.

.PARAMETER ExtensionId
  Caller-supplied extension identity. Firefox may omit it. Chrome/Edge fall
  back to WINSVPN_CHROME_STORE_ID / WINSVPN_EDGE_STORE_ID and refuse if unset.

.PARAMETER Uninstall
  Delete the HKCU key and the rendered manifest. Idempotent.

.PARAMETER PlanOnly
  Print the JSON plan and write nothing (used by tests and review).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('chrome', 'edge', 'firefox')]
    [string]$Browser,

    [string]$HostPath = 'wins_bridge_host.exe',
    [string]$ManifestDir = '',
    [string]$ExtensionId = '',
    [string]$Python = '',
    [switch]$Uninstall,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$Layout = Join-Path $PSScriptRoot 'native_host_layout.py'
if (-not (Test-Path -LiteralPath $Layout -PathType Leaf)) {
    throw "native-host layout is missing: $Layout"
}

if (-not $Python) {
    $resolved = Get-Command python -ErrorAction SilentlyContinue
    if ($resolved) { $Python = $resolved.Source }
}
if (-not $Python) {
    $resolved = Get-Command python3 -ErrorAction SilentlyContinue
    if ($resolved) { $Python = $resolved.Source }
}
if (-not $Python -or -not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Native-host registration refused: python is unavailable to render the manifest.'
}

if (-not $ManifestDir) {
    if ([IO.Path]::IsPathRooted($HostPath) -and (Test-Path -LiteralPath $HostPath -PathType Leaf)) {
        $ManifestDir = [IO.Path]::GetDirectoryName($HostPath)
    } else {
        $ManifestDir = $PSScriptRoot
    }
}
$ManifestDir = [IO.Path]::GetFullPath($ManifestDir)
$ManifestPath = Join-Path $ManifestDir "org.winsvpn.bridge.$Browser.json"

function Invoke-Layout {
    param([Parameter(Mandatory = $true)][string[]]$LayoutArgs)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Python $Layout @LayoutArgs 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    return @{ Code = $code; Output = $output }
}

if ($Uninstall) {
    $subkey = @{
        chrome  = 'Software\Google\Chrome\NativeMessagingHosts\org.winsvpn.bridge'
        edge    = 'Software\Microsoft\Edge\NativeMessagingHosts\org.winsvpn.bridge'
        firefox = 'Software\Mozilla\NativeMessagingHosts\org.winsvpn.bridge'
    }[$Browser]
    if ($PlanOnly) {
        $plan = [ordered]@{
            browser       = $Browser
            uninstall     = $true
            manifest_path = $ManifestPath
            registry      = @(@{ hive = 'HKCU'; subkey = $subkey; uninstall = 'delete_key' })
        }
        $plan | ConvertTo-Json -Depth 6
        return
    }
    $result = Invoke-Layout -LayoutArgs @('uninstall-manifest', '--output', $ManifestPath)
    if ($result.Code -ne 0) {
        throw "Native-host uninstall refused: $($result.Output)"
    }
    Remove-Item -LiteralPath "HKCU:\$subkey" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "uninstalled: $ManifestPath"
    Write-Host "removed HKCU\$subkey"
    return
}

$layoutArgs = @(
    'plan',
    '--browser', $Browser,
    '--host-path', $HostPath,
    '--manifest-path', $ManifestPath,
    '--allow-relative-host-path',
    '--windows-hive', 'HKCU'
)
if ($ExtensionId) {
    $layoutArgs += @('--extension-id', $ExtensionId)
}

$planResult = Invoke-Layout -LayoutArgs $layoutArgs
if ($planResult.Code -eq 78) {
    throw "Native-host registration refused for ${Browser}: its store-listing id is missing from tools\native_messaging\manifests\store_ids.json. Record it there or pass -ExtensionId (WINSVPN_$($Browser.ToUpperInvariant())_STORE_ID may only repeat the recorded id). No store id will be invented and no registry key will be written."
}
if ($planResult.Code -ne 0) {
    throw "Native-host registration refused: $($planResult.Output)"
}

$planJson = ($planResult.Output | Out-String).Trim()
if ($PlanOnly) {
    Write-Output $planJson
    return
}

$installArgs = @(
    'install-manifest',
    '--browser', $Browser,
    '--host-path', $HostPath,
    '--output', $ManifestPath,
    '--allow-relative-host-path'
)
if ($ExtensionId) {
    $installArgs += @('--extension-id', $ExtensionId)
}
$installResult = Invoke-Layout -LayoutArgs $installArgs
if ($installResult.Code -ne 0) {
    throw "Native-host manifest rendering failed: $($installResult.Output)"
}

$plan = $planJson | ConvertFrom-Json
foreach ($entry in $plan.registry) {
    $path = "HKCU:\$($entry.subkey)"
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -Force | Out-Null
    }
    Set-ItemProperty -LiteralPath $path -Name '(default)' -Value $entry.value
}
Write-Host "installed: $ManifestPath"
Write-Host "registered HKCU\$($plan.registry[0].subkey)"
