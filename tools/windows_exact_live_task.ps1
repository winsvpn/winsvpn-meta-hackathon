[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExpectedPublicEgressSha256,
    [string]$OutputRoot = 'C:\ProgramData\WinsVPN\live-cycle',
    [ValidateRange(30, 240)][int]$ConnectTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null
$logPath = Join-Path $OutputRoot 'last-task-output.log'
$errorPath = Join-Path $OutputRoot 'last-task-error.json'
Remove-Item -LiteralPath $logPath, $errorPath -Force -ErrorAction SilentlyContinue

try {
    & (Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1') `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -OutputRoot $OutputRoot `
        -ConnectTimeoutSeconds $ConnectTimeoutSeconds *>&1 |
        Tee-Object -LiteralPath $logPath
} catch {
    $evidence = [ordered]@{
        schema_version = 1
        platform = 'windows'
        tested_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
        exception_type = $_.Exception.GetType().FullName
        message = [string]$_.Exception.Message
        script_stack_trace = [string]$_.ScriptStackTrace
    }
    $evidence | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $errorPath -Encoding UTF8
    throw
}
