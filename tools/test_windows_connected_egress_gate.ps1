[CmdletBinding()]
param(
    [string]$LiveCyclePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($LiveCyclePath)) {
    $LiveCyclePath = Join-Path $PSScriptRoot 'windows_interactive_live_cycle.ps1'
}

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -cne $Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $LiveCyclePath, [ref]$tokens, [ref]$errors
)
if ($errors.Count -ne 0) {
    throw "Live-cycle parser error: $($errors[0].Message)"
}
$gate = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-ConnectedEgressDisposition'
}, $true))
if ($gate.Count -ne 1) {
    throw 'Expected exactly one connected-egress disposition gate.'
}
Invoke-Expression $gate[0].Extent.Text

$expected = 'A' * 64
$unexpected = 'B' * 64
Assert-Equal (Get-ConnectedEgressDisposition -Digest $expected `
    -ExpectedDigest $expected) 'match' 'Exact egress was not accepted.'
Assert-Equal (Get-ConnectedEgressDisposition -Digest $unexpected `
    -ExpectedDigest $expected) 'mismatch' 'Unexpected egress was not rejected.'
Assert-Equal (Get-ConnectedEgressDisposition -Digest '' `
    -ExpectedDigest $expected) 'probe_failed' 'Empty probe was not classified.'

$source = Get-Content -LiteralPath $LiveCyclePath -Raw
$routeProbe = $source.IndexOf(
    'if ($tunnel.adapter_up -and $tunnel.default_route -and',
    [StringComparison]::Ordinal
)
$committedPrecondition = $source.IndexOf(
    '$tunnel.phase -ceq ''committed'' -and $tunnel.generation -gt 0) {',
    [StringComparison]::Ordinal
)
$postStateProbe = $source.IndexOf(
    '$attempt.generation_stable_across_canary =',
    [StringComparison]::Ordinal
)
$stateChanged = $source.IndexOf(
    '$attempt.egress_disposition = ''state_changed''',
    [StringComparison]::Ordinal
)
$stableMismatch = $source.IndexOf(
    'if ($attempt.egress_disposition -ceq ''mismatch'' -and',
    [StringComparison]::Ordinal
)
$stickyMismatch = $source.IndexOf(
    '$connectedEgressMismatchObserved = $true',
    [StringComparison]::Ordinal
)
$attemptRecorded = $source.IndexOf(
    '[void]$connectionAttempts.Add([pscustomobject]$attempt)',
    [StringComparison]::Ordinal
)
$stickyBreak = $source.IndexOf(
    'if ($connected -or $connectedEgressMismatchObserved) { break }',
    [StringComparison]::Ordinal
)
$attemptEvidence = $source.IndexOf(
    'connected_egress_mismatch_observed = $connectedEgressMismatchObserved',
    [StringComparison]::Ordinal
)
$failClosed = $source.IndexOf(
    "throw 'An active Win''s VPN route exposed unexpected public egress.'",
    [StringComparison]::Ordinal
)
$indices = @($routeProbe, $committedPrecondition, $postStateProbe,
    $stateChanged, $stableMismatch, $stickyMismatch, $attemptRecorded,
    $stickyBreak, $attemptEvidence, $failClosed)
if (@($indices | Where-Object { $_ -lt 0 }).Count -ne 0) {
    throw 'The connected-egress fail-closed sequence is incomplete.'
}
if (-not ($routeProbe -lt $committedPrecondition -and
        $committedPrecondition -lt $postStateProbe -and
        $postStateProbe -lt $stateChanged -and
        $stateChanged -lt $stableMismatch -and
        $stableMismatch -lt $stickyMismatch -and
        $stickyMismatch -lt $attemptRecorded -and
        $attemptRecorded -lt $stickyBreak -and
        $stickyBreak -lt $attemptEvidence -and
        $attemptEvidence -lt $failClosed)) {
    throw 'The connected-egress fail-closed sequence is ordered incorrectly.'
}
if ($source.Contains(
        'if ($tunnel.adapter_up -and $tunnel.default_route)'
    )) {
    throw 'Egress probing is not scoped to a committed manager generation.'
}
if ($source.Contains(
        'if ($egress -cne $ExpectedPublicEgressSha256) { continue }'
    ) -or -not $source.Contains(
        "throw 'Network transition exposed unexpected public egress.'"
    ) -or -not $source.Contains('if ($egressMismatch) { throw }')) {
    throw 'Network-transition egress mismatches remain retryable.'
}

Write-Host '[WINDOWS-LIVE-CYCLE] CONNECTED EGRESS GATE TEST PASS'
