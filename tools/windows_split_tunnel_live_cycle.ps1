[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$CanarySourceExecutable = 'C:\Windows\System32\cscript.exe',
    [string]$CanaryExecutable = '',
    [string]$CanaryScript = '',
    [string]$RawCanarySourceExecutable = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
    [string]$RawCanaryExecutable = '',
    [string]$RawCanaryScript = '',
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\split-live-cycle'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $PSScriptRoot 'windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper

if (-not [Environment]::UserInteractive) {
    throw "Win's VPN split-tunnel live cycle requires an interactive session."
}
$isAdministrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdministrator) {
    throw "Win's VPN split-tunnel live cycle requires elevation."
}
if (-not (Test-Path -LiteralPath $CanarySourceExecutable -PathType Leaf)) {
    throw "Split-tunnel canary source executable not found: $CanarySourceExecutable"
}
if ([string]::IsNullOrWhiteSpace($CanaryScript)) {
    $CanaryScript = Join-Path $PSScriptRoot 'windows_https_egress_canary.vbs'
}
if (-not (Test-Path -LiteralPath $CanaryScript -PathType Leaf)) {
    throw "Split-tunnel HTTPS canary script not found: $CanaryScript"
}
if ([string]::IsNullOrWhiteSpace($RawCanaryScript)) {
    $RawCanaryScript = Join-Path $PSScriptRoot 'windows_raw_tcp_egress_canary.ps1'
}
if (-not (Test-Path -LiteralPath $RawCanarySourceExecutable -PathType Leaf) -or
    -not (Test-Path -LiteralPath $RawCanaryScript -PathType Leaf)) {
    throw 'The raw TCP split diagnostic source or script is missing.'
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
if ([string]::IsNullOrWhiteSpace($CanaryExecutable)) {
    $CanaryExecutable = Join-Path $OutputRoot 'winsvpn-split-canary-cscript.exe'
}
if ([string]::IsNullOrWhiteSpace($RawCanaryExecutable)) {
    $RawCanaryExecutable = Join-Path $OutputRoot `
        'winsvpn-split-canary-powershell.exe'
}
$sourceFullPath = [IO.Path]::GetFullPath($CanarySourceExecutable)
$canaryFullPath = [IO.Path]::GetFullPath($CanaryExecutable)
if ($sourceFullPath -ceq $canaryFullPath) {
    throw 'The excluded split canary must use a path distinct from protected app processes.'
}
$sourceSignature = Get-AuthenticodeSignature -LiteralPath $sourceFullPath
if ($sourceSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $sourceSignature.SignerCertificate -or
    $sourceSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The split-tunnel canary source must have a valid Microsoft signature.'
}
[IO.File]::Copy($sourceFullPath, $canaryFullPath, $true)
$sourceHash = (Get-FileHash -LiteralPath $sourceFullPath -Algorithm SHA256).Hash
$canaryHash = (Get-FileHash -LiteralPath $canaryFullPath -Algorithm SHA256).Hash
$canarySignature = Get-AuthenticodeSignature -LiteralPath $canaryFullPath
if ($sourceHash -cne $canaryHash -or
    $canarySignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $canarySignature.SignerCertificate.Thumbprint -cne
        $sourceSignature.SignerCertificate.Thumbprint) {
    throw 'The copied split-tunnel canary did not preserve its signed source identity.'
}
$rawSourceSignature = Get-AuthenticodeSignature -LiteralPath `
    $RawCanarySourceExecutable
if ($rawSourceSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $null -eq $rawSourceSignature.SignerCertificate -or
    $rawSourceSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    throw 'The raw TCP diagnostic source must have a valid Microsoft signature.'
}
[IO.File]::Copy($RawCanarySourceExecutable, $RawCanaryExecutable, $true)
$rawSourceHash = (Get-FileHash -LiteralPath $RawCanarySourceExecutable `
    -Algorithm SHA256).Hash
$rawCanaryHash = (Get-FileHash -LiteralPath $RawCanaryExecutable `
    -Algorithm SHA256).Hash
$rawCanarySignature = Get-AuthenticodeSignature -LiteralPath $RawCanaryExecutable
if ($rawSourceHash -cne $rawCanaryHash -or
    $rawCanarySignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
    $rawCanarySignature.SignerCertificate.Thumbprint -cne
        $rawSourceSignature.SignerCertificate.Thumbprint) {
    throw 'The copied raw TCP diagnostic did not preserve its signed source identity.'
}

$originalSettings = Read-WinsVpnSecureText -Name 'vpn_settings.txt'
$settings = $originalSettings | ConvertFrom-Json
$settings | Add-Member -NotePropertyName excluded_vpn_packages `
    -NotePropertyValue @($canaryFullPath, $RawCanaryExecutable) -Force
$temporarySettings = $settings | ConvertTo-Json -Depth 20 -Compress

Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

try {
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $temporarySettings

    & (Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1') `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -ExcludedCscriptExecutable $canaryFullPath `
        -ExcludedCscriptScript $CanaryScript `
        -ExcludedRawExecutable $RawCanaryExecutable `
        -ExcludedRawScript $RawCanaryScript `
        -OutputRoot $OutputRoot
    if ($LASTEXITCODE -ne 0) {
        throw "The Windows split-tunnel live cycle exited $LASTEXITCODE."
    }
} catch {
    New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
    $errorEvidence = [ordered]@{
        schema_version = 1
        platform = 'windows'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        exception_type = $_.Exception.GetType().FullName
        message = [string]$_.Exception.Message
        script_stack_trace = [string]$_.ScriptStackTrace
    }
    $errorPath = Join-Path $OutputRoot 'last-run-error.json'
    $errorEvidence | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $errorPath -Encoding UTF8
    throw
} finally {
    Get-Process -Name wins_vpn -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $originalSettings
    Remove-Item -LiteralPath $canaryFullPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $RawCanaryExecutable -Force -ErrorAction SilentlyContinue
}
