[CmdletBinding()]
param(
    [string]$RepositoryRoot = 'C:\WinsVPNBuild\final-exact-76f5',
    [string]$ExpectedPublicEgressSha256 =
        '00741EB37875196E7CA7F94A8FAF779F6F4D24DF0DF4B55052F1FF59F2352D71',
    [string]$OutputRoot =
        'C:\WinsVPNBuild\final-exact-76f5\.artifacts\windows-browser-split-double-diagnostic-20260720'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$secureStateHelper = Join-Path $RepositoryRoot `
    'tools\windows_secure_state_helpers.ps1'
if (-not (Test-Path -LiteralPath $secureStateHelper -PathType Leaf)) {
    throw "Win's VPN secure-state helper is missing: $secureStateHelper"
}
. $secureStateHelper
$originalSettings = Read-WinsVpnSecureText -Name 'vpn_settings.txt'
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

try {
    & (Join-Path $RepositoryRoot `
        'tools\windows_split_tunnel_browser_live_cycle.ps1') `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -OutputRoot $OutputRoot `
        -ConnectTimeoutSeconds 240

    [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        passed = $true
    } | ConvertTo-Json | Set-Content -LiteralPath `
        (Join-Path $OutputRoot 'scheduled-runner-status.json') -Encoding UTF8
} catch {
    [ordered]@{
        schema_version = 1
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        passed = $false
        error_type = $_.Exception.GetType().FullName
        error_message = [string]$_.Exception.Message
        error_location = [string]$_.ScriptStackTrace
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath `
        (Join-Path $OutputRoot 'scheduled-runner-status.json') -Encoding UTF8
    throw
} finally {
    Write-WinsVpnSecureText -Name 'vpn_settings.txt' -Value $originalSettings
}
