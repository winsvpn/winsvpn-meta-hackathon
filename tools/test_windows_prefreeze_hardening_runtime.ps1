[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runnerPath = Join-Path $PSScriptRoot 'windows_prefreeze_exact_matrix_case.ps1'
$testRoot = Join-Path $projectRoot (
    '.tmp-windows-prefreeze-hardening-' + [Guid]::NewGuid().ToString('N')
)
$target = Join-Path $testRoot 'target'
$junction = Join-Path $testRoot 'junction'
$providerFailedLoud = $false
$providerErrorStructured = $false
$rootReparseRejected = $false
$fileBelowReparseRejected = $false
$cleanupVerified = $false
$script:residueProviderErrors = @()

function Import-FunctionDefinition {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$Name
    )
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$tokens, [ref]$errors
    )
    if ($errors.Count -ne 0) { throw ($errors | Out-String) }
    $definition = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    if ($definition.Count -ne 1) {
        throw "Expected exactly one function named $Name."
    }
    Set-Item -Path ("Function:\script:" + $Name) `
        -Value $definition[0].Body.GetScriptBlock()
}

try {
    Import-FunctionDefinition -ScriptPath $runnerPath `
        -Name 'Invoke-ResidueProviderQuery'
    Import-FunctionDefinition -ScriptPath $runnerPath `
        -Name 'Assert-NoReparsePath'

    try {
        Invoke-ResidueProviderQuery -Provider route -Query {
            throw [InvalidOperationException]::new('synthetic provider failure')
        }
    } catch {
        $providerFailedLoud = $true
        try {
            $payload = $_.Exception.Message | ConvertFrom-Json
            $providerErrorStructured = (
                $payload.error_id -ceq 'WINS_PREFREEZE_RESIDUE_PROVIDER_FAILURE'
            ) -and
                $payload.provider -ceq 'route' -and
                -not [string]::IsNullOrWhiteSpace($payload.exception_type) -and
                $script:residueProviderErrors.Count -eq 1
        } catch {
            $providerErrorStructured = $false
        }
    }

    New-Item -ItemType Directory -Path $target -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $target 'state.wvdp'),
        'synthetic-state',
        [Text.UTF8Encoding]::new($false)
    )
    New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
    try { Assert-NoReparsePath $junction } catch { $rootReparseRejected = $true }
    try {
        Assert-NoReparsePath (Join-Path $junction 'state.wvdp')
    } catch { $fileBelowReparseRejected = $true }
} finally {
    if (Test-Path -LiteralPath $junction) {
        [IO.Directory]::Delete($junction)
    }
    $resolvedProject = $projectRoot.TrimEnd('\') + '\'
    $resolvedTest = [IO.Path]::GetFullPath($testRoot)
    if (-not ($resolvedTest + '\').StartsWith(
            $resolvedProject, [StringComparison]::OrdinalIgnoreCase
        ) -or (Split-Path -Leaf $resolvedTest) -notmatch
            '^\.tmp-windows-prefreeze-hardening-[0-9a-f]{32}$') {
        throw 'The synthetic hardening test cleanup root is invalid.'
    }
    if (Test-Path -LiteralPath $resolvedTest) {
        Remove-Item -LiteralPath $resolvedTest -Recurse -Force
    }
    $cleanupVerified = -not (Test-Path -LiteralPath $resolvedTest)
}

$pass = $providerFailedLoud -and $providerErrorStructured -and
    $rootReparseRejected -and $fileBelowReparseRejected -and $cleanupVerified
[ordered]@{
    contract = 'winsvpn-prefreeze-hardening-runtime-regression-v1'
    provider_failed_loud = $providerFailedLoud
    provider_error_structured = $providerErrorStructured
    root_reparse_rejected = $rootReparseRejected
    file_below_reparse_rejected = $fileBelowReparseRejected
    cleanup_verified = $cleanupVerified
    pass = $pass
} | ConvertTo-Json -Compress

if (-not $pass) { exit 1 }
