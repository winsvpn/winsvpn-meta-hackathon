[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][string]$CredentialStore,
    [Parameter(Mandatory)][string]$ObserverScript,
    [Parameter(Mandatory)][string]$Output,
    [Parameter(Mandatory)][string]$StatusOutput,
    [ValidateRange(30, 180)][int]$ObserveSeconds = 90,
    [switch]$DiagnosticOnLinkDefaultRoute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TextSha256 {
    param([AllowEmptyString()][string]$Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Value)
        ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace(
            '-', ''
        ).ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

$statusPath = [IO.Path]::GetFullPath($StatusOutput)
if (Test-Path -LiteralPath $statusPath) {
    throw 'The transport diagnostic status output already exists.'
}
$status = [ordered]@{
    contract = 'winsvpn-windows-transport-live-probe-runner-v1'
    completed = $false
    evidence_written = $false
    error_type = ''
    error_id = ''
    error_message_sha256 = ''
    error_script = ''
    error_line = 0
}
$exitCode = 1
try {
    $probeArguments = @{
        ExpectedGuiSha256 = $ExpectedGuiSha256
        CredentialStore = $CredentialStore
        ObserverScript = $ObserverScript
        Output = $Output
        ObserveSeconds = $ObserveSeconds
        DiagnosticOnLinkDefaultRoute = $DiagnosticOnLinkDefaultRoute
    }
    & (Join-Path $PSScriptRoot 'windows_transport_live_probe.ps1') `
        @probeArguments
    $status.completed = $true
    $status.evidence_written = Test-Path -LiteralPath $Output -PathType Leaf
    if (-not $status.evidence_written) {
        throw 'The transport diagnostic returned without evidence.'
    }
    $exitCode = 0
} catch {
    $status.error_type = $_.Exception.GetType().FullName
    $status.error_id = [string]$_.FullyQualifiedErrorId
    $status.error_message_sha256 = Get-TextSha256 ([string]$_.Exception.Message)
    $status.error_script = [IO.Path]::GetFileName(
        [string]$_.InvocationInfo.ScriptName
    )
    $status.error_line = [int]$_.InvocationInfo.ScriptLineNumber
} finally {
    $json = ($status | ConvertTo-Json -Depth 4) + [Environment]::NewLine
    [IO.File]::WriteAllText(
        $statusPath, $json, [Text.UTF8Encoding]::new($false)
    )
}
exit $exitCode
