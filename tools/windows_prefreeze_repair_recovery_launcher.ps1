[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepairScriptPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRepairScriptSha256,
    [Parameter(Mandatory)][string]$RunRoot,
    [Parameter(Mandatory)][string]$TargetProfile,
    [Parameter(Mandatory)][string]$TargetUserSid,
    [Parameter(Mandatory)][int]$TargetSessionId,
    [Parameter(Mandatory)][string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][string]$ExpectedSecureClosureSha256,
    [Parameter(Mandatory)][string]$ExpectedLegacyClosureSha256,
    [Parameter(Mandatory)][string]$RepairTaskName,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepairScriptPath = [IO.Path]::GetFullPath($RepairScriptPath)
$RunRoot = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$allowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'
if (-not $RepairScriptPath.StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or -not ($RunRoot + '\').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or -not $OutputPath.StartsWith(
        ($RunRoot + '\'), [StringComparison]::OrdinalIgnoreCase
    ) -or
    (Get-FileHash -LiteralPath $RepairScriptPath -Algorithm SHA256).Hash -cne
        $ExpectedRepairScriptSha256) {
    throw 'The recovery launcher boundary or repair hash changed.'
}
try {
    & $RepairScriptPath -RunRoot $RunRoot -TargetProfile $TargetProfile `
        -TargetUserSid $TargetUserSid -TargetSessionId $TargetSessionId `
        -ExpectedGuiSha256 $ExpectedGuiSha256 `
        -ExpectedSecureClosureSha256 $ExpectedSecureClosureSha256 `
        -ExpectedLegacyClosureSha256 $ExpectedLegacyClosureSha256 `
        -RepairTaskName $RepairTaskName -OutputPath $OutputPath
} catch {
    $failure = [ordered]@{
        schema_version = 1
        contract = 'winsvpn-windows-prefreeze-recovery-repair-failure-v1'
        repaired = $false
        error = $_.Exception.Message
        fully_qualified_error_id = $_.FullyQualifiedErrorId
        observed_at_utc = [DateTime]::UtcNow.ToString('o')
        secret_material_redacted = $true
    } | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText(
        ($OutputPath + '.error.json'),
        $failure,
        [Text.UTF8Encoding]::new($false)
    )
    throw
}
