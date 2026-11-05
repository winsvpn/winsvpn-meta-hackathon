param(
    [ValidateCount(5, 5)][string[]]$RawEvidenceFiles = @(),
    [string]$ReleaseInputIndex = "",
    [string]$OutputFile = "",
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$RawEvidenceMaxAge = [TimeSpan]::FromHours(72)
$AggregateEvidenceMaxAge = [TimeSpan]::FromHours(24)
Set-Location $RepoRoot
if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $OutputFile = Join-Path $RepoRoot "release\public-release-evidence.json"
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-ProducerContractHash {
    param([Parameter(Mandatory)][string]$ProducerPath)
    $normalizedProducer = $ProducerPath.Replace('\', '/')
    $extraDependencies = switch ($normalizedProducer) {
        'tools/android_public_release_live_smoke.ps1' {
            @(
                'tools/android_final_evidence_collector.py',
                'tools/android_release_matrix_evidence.py',
                'tools/android_release_ui_driver.py',
                'tools/android_remote_route_control.py',
                'tools/android_remote_route_guard.sh',
                'tools/android_fresh_release_regression.ps1',
                'tools/android_exact_installed_live_cycle.ps1'
            )
        }
        'tools/windows_public_release_live_smoke.ps1' {
            @(
                'tools/windows_release_matrix_driver.ps1',
                'tools/windows_release_matrix_evidence.py',
                'tools/windows_invoke_vpn_power.ps1',
                'tools/windows_semantic_transition_probe.ps1',
                'tools/windows_test_failsafe_watchdog.ps1'
            )
        }
        'tools/linux_public_release_live_smoke.sh' {
            @(
                'tools/linux_final_evidence_collector.py',
                'tools/linux_release_ui_driver.py',
                'tools/install_linux_release_ui_driver.sh',
                'tools/linux_split_tunnel_live_canary.sh',
                'tools/linux_apple_release_matrix_evidence.py',
                'tools/linux_installed_artifact_manifest.py',
                'tools/linux_live_tunnel_assertions.sh',
                'tools/linux_live_split_assertions.sh',
                'tools/linux_live_tunnel_teardown_assertions.sh'
            )
        }
        'tools/apple_public_release_live_smoke.sh' {
            @(
                'tools/apple_final_evidence_collector.py',
                'tools/apple_release_ui_driver.py',
                'tools/apple_map_semantic_observer.swift',
                'tools/install_apple_release_ui_driver.sh',
                'tools/android_remote_route_control.py',
                'ios/RunnerUITests/VpnPermissionUITests.swift',
                'ios/RunnerUITests/RunnerUITests.entitlements',
                'ios/Runner.xcodeproj/project.pbxproj',
                'ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme',
                'tools/linux_apple_release_matrix_evidence.py',
                'tools/apple_runtime_smoke.sh'
            )
        }
        default { @() }
    }
    $dependencies = @($normalizedProducer) + @($extraDependencies) + @(
        'tools/public_release_live_smoke_common.py',
        'tools/validate_release_artifact_privacy.py',
        'tools/release_obfuscation_contract.py',
        'tools/release_dependency_freeze.py'
    )
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    foreach ($relative in $dependencies) {
        $absolute = Join-Path $RepoRoot $relative
        if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
            throw "Approved live-smoke producer dependency is missing: $relative"
        }
        $hash.AppendData([Text.Encoding]::UTF8.GetBytes("$relative`0"))
        $hash.AppendData([IO.File]::ReadAllBytes($absolute))
        $hash.AppendData([byte[]]@(0))
    }
    return ([BitConverter]::ToString($hash.GetHashAndReset())).Replace('-', '').ToLowerInvariant()
}

function Get-XrayManifestHash {
    param([Parameter(Mandatory)][object[]]$Routes)
    $lines = @($Routes | Sort-Object @{ Expression = { [int]$_.port } }, @{ Expression = { [string]$_.security } } | ForEach-Object {
        "tcp|$([int]$_.port)|$(([string]$_.security).Trim().ToLowerInvariant())"
    })
    $canonical = ($lines -join "`n") + "`n"
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Test-ExactSha256 {
    param([string]$Expected, [string]$Actual)
    return $Expected -cmatch '^[0-9a-f]{64}$' -and $Actual -cmatch '^[0-9a-f]{64}$' -and $Expected -ceq $Actual
}

function Test-NoReparseAncestors {
    param([Parameter(Mandatory)][string]$AbsolutePath)
    $repo = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/')
    $absolute = [IO.Path]::GetFullPath($AbsolutePath)
    $prefix = $repo + [IO.Path]::DirectorySeparatorChar
    if ($absolute -cne $repo -and -not $absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $rootItem = Get-Item -LiteralPath $repo -Force -ErrorAction SilentlyContinue
    if (-not $rootItem -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    $cursor = $repo
    foreach ($part in $absolute.Substring($repo.Length).TrimStart('\', '/').Split([char[]]@('\', '/'), [StringSplitOptions]::RemoveEmptyEntries)) {
        $cursor = Join-Path $cursor $part
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if (-not $item) { break }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
    }
    return $true
}

function Test-RawEvidenceTime {
    param([DateTime]$TestedAt, [DateTime]$NotBefore, [DateTime]$Now)
    return $TestedAt -ge $NotBefore -and
        $TestedAt -ge $Now.Subtract($RawEvidenceMaxAge) -and
        $TestedAt -le $Now.AddMinutes(5)
}

function ConvertFrom-StrictUtcTimestamp {
    param([AllowNull()][object]$Value)
    $text = [string]$Value
    if ($text -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$') { return [DateTime]::MinValue }
    try { return [DateTimeOffset]::Parse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime } catch { return [DateTime]::MinValue }
}

function Resolve-ContainedRepoPath {
    param([string]$Path, [Parameter(Mandatory)][string]$RequiredPrefix)
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path)) { return $null }
    $normalized = $Path.Replace('/', '\')
    if (@($normalized.Split('\') | Where-Object { $_ -eq '..' }).Count -gt 0) { return $null }
    $prefixRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot $RequiredPrefix)).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath((Join-Path $RepoRoot $normalized))
    if (-not $resolved.StartsWith($prefixRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-NoReparseAncestors -AbsolutePath $resolved)) { return $null }
    return $resolved
}

function Get-WebsiteSourceState {
    $helper = Join-Path $RepoRoot 'tools\release_source_freeze.py'
    $output = & python $helper --repo $RepoRoot --website-only --json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Website source fingerprint failed: $($output -join ' ')"
    }
    try { $state = ($output -join "`n") | ConvertFrom-Json } catch {
        throw "Website source fingerprint helper returned invalid JSON."
    }
    return [pscustomobject]@{
        WebsiteSha256 = [string]$state.website_source_fingerprint_sha256
        WebsiteFileCount = [int]$state.website_source_file_count
        ImmutableWebsiteSha256 = [string]$state.immutable_website_source_fingerprint_sha256
        ImmutableWebsiteFileCount = [int]$state.immutable_website_source_file_count
    }
}

function Get-ReleaseInputState {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'ReleaseInputIndex is required and must explicitly name RELEASE_INPUT_INDEX.json.'
    }
    $absolute = if ([IO.Path]::IsPathRooted($Path)) {
        [IO.Path]::GetFullPath($Path)
    } else {
        [IO.Path]::GetFullPath((Join-Path $RepoRoot $Path))
    }
    $repoPrefix = [IO.Path]::GetFullPath($RepoRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($absolute) -cne 'RELEASE_INPUT_INDEX.json' -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf) -or
        -not (Test-NoReparseAncestors -AbsolutePath $absolute)) {
        throw 'ReleaseInputIndex must be an existing RELEASE_INPUT_INDEX.json inside the repository.'
    }
    $helper = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'
    $output = & python $helper verify-index --repo $RepoRoot --index $absolute 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Release input index verification failed: $($output -join ' ')"
    }
    try {
        $verified = ($output -join "`n") | ConvertFrom-Json
        $index = Get-Content -LiteralPath $absolute -Raw | ConvertFrom-Json
        $indexCreated = [DateTime]::Parse([string]$index.created_utc).ToUniversalTime()
    } catch {
        throw 'Release input index verifier returned invalid metadata.'
    }
    $platforms = @{}
    foreach ($platform in @('android', 'windows', 'linux', 'ios', 'macos')) {
        $reference = $index.platform_manifests.$platform
        $manifestPath = Join-Path (Split-Path -Parent $absolute) ([string]$reference.path)
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            $manifestCreated = [DateTime]::Parse([string]$manifest.created_utc).ToUniversalTime()
        } catch {
            throw "$platform release input manifest metadata is unreadable."
        }
        $fingerprint = [string]$verified.platforms.$platform
        if (-not (Test-ExactSha256 -Expected (Get-Sha256 $manifestPath) -Actual ([string]$reference.sha256)) -or
            -not (Test-ExactSha256 -Expected $fingerprint -Actual ([string]$reference.artifact_input_fingerprint_sha256))) {
            throw "$platform release input manifest binding is inconsistent."
        }
        $platforms[$platform] = [pscustomobject]@{
            ManifestSha256 = [string]$reference.sha256
            ArtifactInputFingerprintSha256 = $fingerprint
            EvidenceNotBeforeUtc = if ($manifestCreated -gt $indexCreated) { $manifestCreated } else { $indexCreated }
        }
    }
    return [pscustomobject]@{
        Path = $absolute
        Sha256 = Get-Sha256 $absolute
        SharedRevision = [string]$verified.shared_revision
        Platforms = $platforms
    }
}

function Get-BuildReceiptState {
    param(
        [Parameter(Mandatory)][string]$Platform,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][object]$ReleaseInputs
    )
    $receipt = Resolve-ContainedRepoPath -Path $RelativePath -RequiredPrefix '.artifacts'
    if (-not $receipt -or -not (Test-Path -LiteralPath $receipt -PathType Leaf)) {
        throw "$Platform build receipt is missing, escapes .artifacts, or uses a reparse path."
    }
    $helper = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'
    $output = & python $helper verify-receipt --repo $RepoRoot --index $ReleaseInputs.Path `
        --platform $Platform --receipt $receipt 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Platform build receipt verification failed: $($output -join ' ')"
    }
    try { $state = ($output -join "`n") | ConvertFrom-Json } catch {
        throw "$Platform build receipt verifier returned invalid JSON."
    }
    return [pscustomobject]@{
        Path = $receipt
        Sha256 = [string]$state.receipt_sha256
        ArtifactSha256 = [string]$state.artifact_sha256
        ArtifactSizeBytes = [long]$state.artifact_size_bytes
        FinishedUtc = ConvertFrom-StrictUtcTimestamp $state.finished_utc
    }
}

if ($SelfTest) {
    $routes = @(
        [pscustomobject]@{ protocol = 'tcp'; port = 443; security = 'tls'; passed = $true },
        [pscustomobject]@{ protocol = 'tcp'; port = 80; security = 'none'; passed = $true }
    )
    $knownManifest = 'd5a09e1a803ce25e13c57274abbc69bc2af2c9c387de1f624217b92b12dc24f5'
    if ((Get-XrayManifestHash $routes) -cne $knownManifest -or
        (Get-XrayManifestHash @($routes[1], $routes[0])) -cne $knownManifest) {
        throw 'Evidence assembler Xray manifest hashing is not canonical.'
    }
    $producerHash = Get-ProducerContractHash 'tools/android_public_release_live_smoke.ps1'
    if ($producerHash -cnotmatch '^[0-9a-f]{64}$' -or
        $producerHash -ceq (Get-Sha256 'tools/android_public_release_live_smoke.ps1')) {
        throw 'Evidence assembler producer hash does not bind the common validator.'
    }
    $python = (Get-Command python -ErrorAction Stop).Source
    foreach ($producer in @(
        'tools/android_public_release_live_smoke.ps1',
        'tools/windows_public_release_live_smoke.ps1',
        'tools/linux_public_release_live_smoke.sh',
        'tools/apple_public_release_live_smoke.sh'
    )) {
        $pythonHash = (& $python -c "import pathlib,sys; sys.path.insert(0, 'tools'); from public_release_live_smoke_common import producer_contract_hash; print(producer_contract_hash(pathlib.Path('.').resolve(), sys.argv[1]))" $producer).Trim()
        if ($LASTEXITCODE -ne 0 -or (Get-ProducerContractHash $producer) -cne $pythonHash) {
            throw "Evidence assembler producer closure differs from the Python producer: $producer"
        }
    }
    $contained = Resolve-ContainedRepoPath -Path '.artifacts/release-evidence/android/test/run.json' -RequiredPrefix '.artifacts/release-evidence'
    if (-not $contained -or (Resolve-ContainedRepoPath -Path '../run.json' -RequiredPrefix '.artifacts/release-evidence')) {
        throw 'Evidence assembler path containment self-test failed.'
    }
    $missingIndexRejected = $false
    try { $null = Get-ReleaseInputState -Path '' } catch { $missingIndexRejected = $true }
    if (-not $missingIndexRejected) {
        throw 'Evidence assembler accepted a missing RELEASE_INPUT_INDEX.'
    }
    $now = [DateTime]::UtcNow
    if (Test-RawEvidenceTime -TestedAt $now.AddHours(-73) -NotBefore $now.AddHours(-80) -Now $now) {
        throw 'Evidence assembler accepted raw evidence older than 72 hours.'
    }
    Write-Host 'PUBLIC RELEASE EVIDENCE ASSEMBLER SELF-TEST: PASS'
    exit 0
}

if ($RawEvidenceFiles.Count -ne 5) {
    throw 'Exactly five platform raw-evidence files are required.'
}

$versionLine = Select-String -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Pattern '^version:\s*([^+\s]+)\+(\d+)\s*$' | Select-Object -First 1
if (-not $versionLine) { throw "pubspec.yaml must contain version: <semver>+<integer>." }
$appVersion = $versionLine.Matches[0].Groups[1].Value
$buildNumber = $versionLine.Matches[0].Groups[2].Value
$releaseInputs = Get-ReleaseInputState -Path $ReleaseInputIndex
$websiteState = Get-WebsiteSourceState
$requiredResults = @(
    'artifact_signature_passed', 'clean_install_passed', 'direct_awg_passed',
    'xray_all_backup_routes_passed', 'ip_map_50_mile_city_context_passed',
    'split_tunneling_contract_passed',
    'double_vpn_passed', 'leak_test_passed'
)
$approvedEvidenceProducers = @{
    android = 'tools/android_public_release_live_smoke.ps1'
    windows = 'tools/windows_public_release_live_smoke.ps1'
    linux = 'tools/linux_public_release_live_smoke.sh'
    ios = 'tools/apple_public_release_live_smoke.sh'
    macos = 'tools/apple_public_release_live_smoke.sh'
}
$platforms = [ordered]@{}
$runIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$latestRawTestedAt = [DateTime]::MinValue

foreach ($inputPath in $RawEvidenceFiles) {
    $absolute = if ([IO.Path]::IsPathRooted($inputPath)) { [IO.Path]::GetFullPath($inputPath) } else { [IO.Path]::GetFullPath((Join-Path $RepoRoot $inputPath)) }
    $evidenceRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot '.artifacts\release-evidence')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($evidenceRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf) -or
        -not (Test-NoReparseAncestors -AbsolutePath $absolute)) {
        throw "Raw evidence must be an existing file under .artifacts/release-evidence: $inputPath"
    }
    $raw = Get-Content -LiteralPath $absolute -Raw | ConvertFrom-Json
    $platform = [string]$raw.platform
    if ($platform -cnotin @('android', 'windows', 'linux', 'ios', 'macos') -or $platforms.Contains($platform)) {
        throw "Raw evidence platform is missing, unsupported, or duplicated: $platform"
    }
    $platformInputs = $releaseInputs.Platforms[$platform]
    if ([int]$raw.schema_version -ne 3 -or [string]$raw.app_version -ne $appVersion -or
        [string]$raw.build_number -ne $buildNumber -or
        -not (Test-ExactSha256 -Expected $releaseInputs.Sha256 -Actual ([string]$raw.release_input_index_sha256)) -or
        -not (Test-ExactSha256 -Expected $platformInputs.ManifestSha256 -Actual ([string]$raw.platform_manifest_sha256)) -or
        [string]$raw.shared_revision -cne $releaseInputs.SharedRevision -or
        -not (Test-ExactSha256 -Expected $platformInputs.ArtifactInputFingerprintSha256 -Actual ([string]$raw.artifact_input_fingerprint_sha256))) {
        throw "$platform raw evidence is not bound to the verified release input index for $appVersion+$buildNumber."
    }
    $runId = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$raw.run_id, [ref]$runId) -or $runId -eq [Guid]::Empty -or -not $runIds.Add($runId.ToString('D'))) {
        throw "$platform raw evidence lacks a unique non-empty run ID."
    }
    if ($raw.secret_material_redacted -isnot [bool] -or $raw.secret_material_redacted -ne $true) {
        throw "$platform raw evidence must explicitly state secret_material_redacted=true."
    }
    if ([string]$raw.producer.contract -cne 'winsvpn-public-release-live-smoke-v3') {
        throw "$platform raw evidence was not created under the approved live-smoke producer contract."
    }
    if (([string]$raw.producer.path).Replace('\', '/') -cne $approvedEvidenceProducers[$platform]) {
        throw "$platform raw evidence names an unapproved producer script."
    }
    $producer = Resolve-ContainedRepoPath -Path ([string]$raw.producer.path) -RequiredPrefix 'tools'
    if (-not $producer -or -not (Test-Path -LiteralPath $producer -PathType Leaf) -or
        -not (Test-ExactSha256 -Expected (Get-ProducerContractHash ([string]$raw.producer.path)) -Actual ([string]$raw.producer.sha256))) {
        throw "$platform raw evidence is not bound to its current tools/ producer script."
    }
    $transcript = Resolve-ContainedRepoPath -Path ([string]$raw.transcript.path) -RequiredPrefix '.artifacts/release-evidence'
    if (-not $transcript -or -not (Test-Path -LiteralPath $transcript -PathType Leaf) -or
        (Get-Item -LiteralPath $transcript).Length -eq 0 -or
        -not (Test-ExactSha256 -Expected (Get-Sha256 $transcript) -Actual ([string]$raw.transcript.sha256))) {
        throw "$platform raw evidence is not bound to a non-empty transcript under .artifacts/release-evidence."
    }
    $bundleIndexSha256 = [string]$raw.evidence_bundle_index_sha256
    if ($bundleIndexSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $bundleIndexSha256 -ceq ('0' * 64)) {
        throw "$platform raw evidence lacks a real immutable evidence-bundle index SHA-256."
    }
    try { $nativeTranscript = Get-Content -LiteralPath $transcript -Raw | ConvertFrom-Json } catch {
        throw "$platform sanitized native transcript is not valid JSON."
    }
    if ([string]$nativeTranscript.evidence_bundle_index_sha256 -cne $bundleIndexSha256) {
        throw "$platform raw evidence does not match its sanitized transcript evidence-bundle index binding."
    }
    $mapScreenshot = Resolve-ContainedRepoPath -Path ([string]$raw.map_screenshot.path) -RequiredPrefix '.artifacts/release-evidence'
    if (-not $mapScreenshot -or -not (Test-Path -LiteralPath $mapScreenshot -PathType Leaf) -or
        [IO.Path]::GetExtension($mapScreenshot).ToLowerInvariant() -notin @('.png', '.jpg', '.jpeg') -or
        (Get-Item -LiteralPath $mapScreenshot).Length -lt 10000 -or
        -not (Test-ExactSha256 -Expected (Get-Sha256 $mapScreenshot) -Actual ([string]$raw.map_screenshot.sha256))) {
        throw "$platform raw evidence is not bound to its exact map screenshot."
    }
    if ([string]$raw.artifact_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$platform raw evidence lacks a lowercase exact-artifact SHA-256."
    }
    $receiptState = Get-BuildReceiptState -Platform $platform -RelativePath ([string]$raw.build_receipt.path) -ReleaseInputs $releaseInputs
    if (-not (Test-ExactSha256 -Expected $receiptState.Sha256 -Actual ([string]$raw.build_receipt.sha256)) -or
        -not (Test-ExactSha256 -Expected $receiptState.ArtifactSha256 -Actual ([string]$raw.artifact_sha256)) -or
        [long]$raw.artifact_size_bytes -ne $receiptState.ArtifactSizeBytes) {
        throw "$platform raw evidence is not bound to its immutable build receipt and exact artifact."
    }
    foreach ($field in $requiredResults) {
        if ($raw.$field -isnot [bool] -or $raw.$field -ne $true) { throw "$platform raw evidence does not prove $field." }
    }
    $hasWindowsMatrixResult = $null -ne $raw.PSObject.Properties['windows_matrix_passed']
    if ($platform -eq 'windows') {
        if (-not $hasWindowsMatrixResult -or
            $raw.windows_matrix_passed -isnot [bool] -or
            $raw.windows_matrix_passed -ne $true) {
            throw 'windows raw evidence does not prove the mandatory cancellation, fallback, split, network-change, teardown, and rollback matrix.'
        }
    } elseif ($hasWindowsMatrixResult) {
        throw "$platform raw evidence contains a Windows-only matrix result."
    }
    $directAwgPort = 0
    try { $directAwgPort = [int]$raw.route_matrix.direct_awg.port } catch { $directAwgPort = 0 }
    if ($raw.route_matrix.direct_awg.passed -isnot [bool] -or $raw.route_matrix.direct_awg.passed -ne $true -or
        $directAwgPort -ne 9110 -or [string]$raw.route_matrix.direct_awg.protocol -cne 'udp') {
        throw "$platform raw evidence does not prove direct AWG on UDP 9110."
    }
    $advertisedXrayCount = 0
    $testedXrayCount = 0
    try { $advertisedXrayCount = [int]$raw.route_matrix.xray.advertised_route_count } catch { $advertisedXrayCount = 0 }
    try { $testedXrayCount = [int]$raw.route_matrix.xray.tested_route_count } catch { $testedXrayCount = 0 }
    $xrayRoutes = @($raw.route_matrix.xray.routes)
    if ($advertisedXrayCount -lt 1 -or $testedXrayCount -ne $advertisedXrayCount -or $xrayRoutes.Count -ne $advertisedXrayCount -or
        [string]$raw.route_matrix.xray.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "$platform raw evidence does not bind every advertised Xray route to a sanitized manifest."
    }
    $seenXrayRoutes = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($route in $xrayRoutes) {
        $routePort = 0
        try { $routePort = [int]$route.port } catch { $routePort = 0 }
        $routeSecurity = ([string]$route.security).Trim().ToLowerInvariant()
        $propertyNames = @($route.PSObject.Properties.Name | ForEach-Object { $_.ToLowerInvariant() })
        if ([string]$route.protocol -cne 'tcp' -or $routePort -lt 1 -or $routePort -gt 65535 -or $routeSecurity -notin @('none', 'tls') -or
            $route.passed -isnot [bool] -or $route.passed -ne $true -or
            -not $seenXrayRoutes.Add("$routePort/$routeSecurity") -or
            @($propertyNames | Where-Object { $_ -match 'host|endpoint|(^|_)ip($|_)|address' }).Count -gt 0) {
            throw "$platform Xray route evidence is invalid, duplicated, failed, or exposes an endpoint identity."
        }
    }
    if (-not (Test-ExactSha256 -Expected (Get-XrayManifestHash $xrayRoutes) -Actual ([string]$raw.route_matrix.xray.manifest_sha256))) {
        throw "$platform Xray manifest SHA-256 does not match the complete sanitized route set."
    }
    $testedAt = ConvertFrom-StrictUtcTimestamp $raw.tested_at_utc
    $notBefore = if ($receiptState.FinishedUtc -gt $platformInputs.EvidenceNotBeforeUtc) { $receiptState.FinishedUtc } else { $platformInputs.EvidenceNotBeforeUtc }
    if (-not (Test-RawEvidenceTime -TestedAt $testedAt -NotBefore $notBefore -Now ([DateTime]::UtcNow))) {
        throw "$platform raw evidence timestamp predates its build receipt/platform inputs, exceeds 72 hours, is invalid, or is in the future."
    }
    if ($testedAt -gt $latestRawTestedAt) { $latestRawTestedAt = $testedAt }
    $relative = $absolute.Substring($RepoRoot.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
    $platforms[$platform] = [ordered]@{
        raw_evidence_path = $relative
        raw_evidence_sha256 = Get-Sha256 $absolute
    }
}

$outputAbsolute = [IO.Path]::GetFullPath($OutputFile)
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'release')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $outputAbsolute.StartsWith($releaseRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "OutputFile must stay under release/."
}
$generatedAt = [DateTime]::UtcNow
if ($generatedAt -lt $latestRawTestedAt -or $generatedAt -lt [DateTime]::UtcNow.Subtract($AggregateEvidenceMaxAge)) {
    throw 'Aggregate evidence generation time is invalid or predates raw evidence.'
}
if (-not (Test-NoReparseAncestors -AbsolutePath $outputAbsolute)) {
    throw 'OutputFile uses a symlink, junction, or reparse-point ancestor.'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $outputAbsolute) | Out-Null
[ordered]@{
    schema_version = 3
    app_version = $appVersion
    build_number = $buildNumber
    release_input_index_sha256 = $releaseInputs.Sha256
    shared_revision = $releaseInputs.SharedRevision
    website_source_fingerprint_sha256 = $websiteState.WebsiteSha256
    website_source_file_count = $websiteState.WebsiteFileCount
    generated_at_utc = $generatedAt.ToString('o')
    platforms = $platforms
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outputAbsolute -Encoding UTF8

Write-Host "PUBLIC RELEASE EVIDENCE ASSEMBLY: PASS"
Write-Host "Output: $outputAbsolute"
Write-Host "Release input index SHA-256: $($releaseInputs.Sha256)"
Write-Host "Shared revision: $($releaseInputs.SharedRevision)"
Write-Host "Website staging fingerprint: $($websiteState.WebsiteSha256)"
