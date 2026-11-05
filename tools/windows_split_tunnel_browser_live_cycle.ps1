[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$BrowserExecutable =
        'C:\Program Files\Google\Chrome\Application\chrome.exe',
    [string]$OutputRoot =
        'C:\ProgramData\WinsVPN\split-browser-live-cycle',
    [switch]$AllowSingleHop,
    [switch]$RunNetworkChangeMatrix,
    [switch]$DiagnosticRemoveManualTunnelDefault,
    [switch]$DiagnosticReplaceManualTunnelGateway,
    [ValidateRange(30, 240)][int]$ConnectTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN browser split-tunnel cycle requires an interactive session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN browser split-tunnel cycle requires elevation."
}
if (-not (Test-Path -LiteralPath $BrowserExecutable -PathType Leaf)) {
    throw "Split-tunnel browser executable not found: $BrowserExecutable"
}
$browserFullPath = [IO.Path]::GetFullPath($BrowserExecutable)
$browserSignature = Get-AuthenticodeSignature -LiteralPath $browserFullPath
if ($browserSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $browserSignature.SignerCertificate) {
    throw 'The split-tunnel browser must have a valid Authenticode signature.'
}

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$originalSettings = Read-WinsVpnSecureText -Name 'vpn_settings.txt'
$settings = $originalSettings | ConvertFrom-Json
$settings | Add-Member -NotePropertyName double_vpn_requested `
    -NotePropertyValue (-not $AllowSingleHop) -Force
$settings | Add-Member -NotePropertyName excluded_vpn_packages `
    -NotePropertyValue @($browserFullPath) -Force
$temporarySettings = $settings | ConvertTo-Json -Depth 20 -Compress

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

try {
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $temporarySettings

    & (Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1') `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -ExcludedBrowserExecutable $browserFullPath `
        -OutputRoot $OutputRoot `
        -AllowSingleHop:$AllowSingleHop `
        -RunNetworkChangeMatrix:$RunNetworkChangeMatrix `
        -DiagnosticRemoveManualTunnelDefault:$DiagnosticRemoveManualTunnelDefault `
        -DiagnosticReplaceManualTunnelGateway:$DiagnosticReplaceManualTunnelGateway `
        -ConnectTimeoutSeconds $ConnectTimeoutSeconds
    if ($LASTEXITCODE -ne 0) {
        throw "The Windows browser split-tunnel live cycle exited $LASTEXITCODE."
    }
} catch {
    $errorEvidence = [ordered]@{
        schema_version = 1
        platform = 'windows'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        exception_type = $_.Exception.GetType().FullName
        message = [string]$_.Exception.Message
        script_stack_trace = [string]$_.ScriptStackTrace
    }
    $errorEvidence | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $OutputRoot 'last-run-error.json') `
            -Encoding UTF8
    throw
} finally {
    Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $originalSettings
}
