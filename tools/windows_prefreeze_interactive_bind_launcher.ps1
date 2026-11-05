[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BinderPath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedBinderSha256,
    [Parameter(Mandatory)][string]$ReadyPath,
    [Parameter(Mandatory)][ValidateSet('double-natural')][string]$Case,
    [Parameter(Mandatory)][string]$ToolRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedRunnerSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedWatchdogSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiVerifierSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedGuiSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedServiceSha256,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedPublicEgressSha256,
    [ValidateRange(60, 120)][int]$ConnectTimeoutSeconds = 90,
    [ValidateRange(600, 720)][int]$MainExecutionLimitSeconds = 600,
    [ValidateRange(660, 900)][int]$WatchdogDeadlineSeconds = 660,
    [ValidateRange(300, 360)][int]$WatchdogRecoveryReserveSeconds = 360
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$BinderPath = [IO.Path]::GetFullPath($BinderPath)
$ToolRoot = [IO.Path]::GetFullPath($ToolRoot).TrimEnd('\')
$ReadyPath = [IO.Path]::GetFullPath($ReadyPath)
$ExpectedBinderSha256 = $ExpectedBinderSha256.ToLowerInvariant()
$ExpectedRunnerSha256 = $ExpectedRunnerSha256.ToLowerInvariant()
$ExpectedWatchdogSha256 = $ExpectedWatchdogSha256.ToLowerInvariant()
$ExpectedGuiVerifierSha256 = $ExpectedGuiVerifierSha256.ToLowerInvariant()
$ExpectedGuiSha256 = $ExpectedGuiSha256.ToLowerInvariant()
$ExpectedServiceSha256 = $ExpectedServiceSha256.ToLowerInvariant()
$ExpectedPublicEgressSha256 = $ExpectedPublicEgressSha256.ToLowerInvariant()
$allowedRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:ProgramData 'WinsVPN\PreFreezeMatrix')
).TrimEnd('\') + '\'

if (-not [Environment]::UserInteractive) {
    throw 'The binder launcher must run in the signed-in interactive session.'
}
if (-not ($BinderPath + '').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or -not ($ToolRoot + '\').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or -not ($ReadyPath + '').StartsWith(
        $allowedRoot, [StringComparison]::OrdinalIgnoreCase
    ) -or [IO.Path]::GetExtension($ReadyPath) -cne '.json') {
    throw 'Binder, tools, and READY receipt must remain under the matrix root.'
}
$actualBinderSha256 = (Get-FileHash -LiteralPath $BinderPath `
    -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualBinderSha256 -cne $ExpectedBinderSha256) {
    throw 'The staged binder changed before interactive launch.'
}
if (Test-Path -LiteralPath $ReadyPath) {
    throw 'The one-use READY receipt already exists.'
}

try {
    $json = & $BinderPath -Case $Case -ToolRoot $ToolRoot `
        -ExpectedRunnerSha256 $ExpectedRunnerSha256 `
        -ExpectedWatchdogSha256 $ExpectedWatchdogSha256 `
        -ExpectedGuiVerifierSha256 $ExpectedGuiVerifierSha256 `
        -ExpectedGuiSha256 $ExpectedGuiSha256 `
        -ExpectedServiceSha256 $ExpectedServiceSha256 `
        -ExpectedPublicEgressSha256 $ExpectedPublicEgressSha256 `
        -ConnectTimeoutSeconds $ConnectTimeoutSeconds `
        -MainExecutionLimitSeconds $MainExecutionLimitSeconds `
        -WatchdogDeadlineSeconds $WatchdogDeadlineSeconds `
        -WatchdogRecoveryReserveSeconds $WatchdogRecoveryReserveSeconds
    $ready = $json | ConvertFrom-Json -ErrorAction Stop
    if (-not $ready.ready -or $ready.case -cne 'double-natural' -or
        $ready.tasks_started) {
        throw 'The binder did not return the exact unstarted READY contract.'
    }
    $temporary = $ReadyPath + '.tmp-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($ready | ConvertTo-Json -Depth 8 -Compress),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporary -Destination $ReadyPath `
            -ErrorAction Stop
    } finally {
        Remove-Item -LiteralPath $temporary -Force `
            -ErrorAction SilentlyContinue
    }
} catch {
    $failure = [ordered]@{
        contract = 'winsvpn-windows-prefreeze-bind-failure-v1'
        ready = $false
        case = $Case
        error = $_.Exception.Message
        fully_qualified_error_id = $_.FullyQualifiedErrorId
        no_case_started = $true
    } | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText(
        ($ReadyPath + '.error.json'),
        $failure,
        [Text.UTF8Encoding]::new($false)
    )
    throw
}
