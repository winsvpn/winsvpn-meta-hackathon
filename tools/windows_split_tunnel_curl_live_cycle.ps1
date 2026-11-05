[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$CurlSourceExecutable = 'C:\Windows\System32\curl.exe',
    [string]$CurlExecutable = '',
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\split-curl-live-cycle',
    [switch]$AllowSingleHop,
    [switch]$RunNetworkChangeMatrix,
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
    throw "Win's VPN curl split-tunnel cycle requires an interactive session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN curl split-tunnel cycle requires elevation."
}
if (-not (Test-Path -LiteralPath $CurlSourceExecutable -PathType Leaf)) {
    throw "Split-tunnel curl source executable not found: $CurlSourceExecutable"
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
if ([string]::IsNullOrWhiteSpace($CurlExecutable)) {
    $CurlExecutable = Join-Path $OutputRoot 'winsvpn-split-canary-curl.exe'
}

$sourceFullPath = [IO.Path]::GetFullPath($CurlSourceExecutable)
$canaryFullPath = [IO.Path]::GetFullPath($CurlExecutable)
if ($sourceFullPath -ceq $canaryFullPath) {
    throw 'The excluded curl canary must use a path distinct from protected app processes.'
}
$sourceSignature = Get-AuthenticodeSignature -LiteralPath $sourceFullPath
if ($sourceSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $sourceSignature.SignerCertificate -or
    $sourceSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The curl split-tunnel canary source must have a valid Microsoft signature.'
}
[IO.File]::Copy($sourceFullPath, $canaryFullPath, $true)
$sourceHash = (Get-FileHash -LiteralPath $sourceFullPath -Algorithm SHA256).Hash
$canaryHash = (Get-FileHash -LiteralPath $canaryFullPath -Algorithm SHA256).Hash
$canarySignature = Get-AuthenticodeSignature -LiteralPath $canaryFullPath
if ($sourceHash -cne $canaryHash -or
    $canarySignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $canarySignature.SignerCertificate.Thumbprint -cne
        $sourceSignature.SignerCertificate.Thumbprint) {
    throw 'The copied curl canary did not preserve its signed source identity.'
}

$originalSettings = Read-WinsVpnSecureText -Name 'vpn_settings.txt'
$settings = $originalSettings | ConvertFrom-Json
$settings | Add-Member -NotePropertyName double_vpn_requested `
    -NotePropertyValue (-not $AllowSingleHop) -Force
$settings | Add-Member -NotePropertyName excluded_vpn_packages `
    -NotePropertyValue @($canaryFullPath) -Force
$temporarySettings = $settings | ConvertTo-Json -Depth 20 -Compress

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

try {
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $temporarySettings

    & (Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1') `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -ExcludedCurlExecutable $canaryFullPath `
        -OutputRoot $OutputRoot `
        -AllowSingleHop:$AllowSingleHop `
        -RunNetworkChangeMatrix:$RunNetworkChangeMatrix `
        -ConnectTimeoutSeconds $ConnectTimeoutSeconds
    # The nested PowerShell collector is fail-closed and throws on every
    # unsuccessful gate. Do not treat a stale LASTEXITCODE from a recovered
    # native command (for example, an early WLAN reconnect retry) as the
    # collector's exit status.
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
    Remove-Item -LiteralPath $canaryFullPath -Force -ErrorAction SilentlyContinue
}
