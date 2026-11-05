param(
    [string]$EvidenceFile = "",
    [string]$ReleaseInputIndex = "",
    [switch]$VerifyLive,
    [switch]$SelfTest
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$RawEvidenceMaxAge = [TimeSpan]::FromHours(72)
$AggregateEvidenceMaxAge = [TimeSpan]::FromHours(24)
Set-Location $RepoRoot

if ([string]::IsNullOrWhiteSpace($EvidenceFile)) {
    $EvidenceFile = Join-Path $RepoRoot "release\public-release-evidence.json"
}

$failures = [System.Collections.Generic.List[string]]::new()
$passes = [System.Collections.Generic.List[string]]::new()
$approvedEvidenceProducers = @{
    android = 'tools/android_public_release_live_smoke.ps1'
    windows = 'tools/windows_public_release_live_smoke.ps1'
    linux = 'tools/linux_public_release_live_smoke.sh'
    ios = 'tools/apple_public_release_live_smoke.sh'
    macos = 'tools/apple_public_release_live_smoke.sh'
}

function Add-Failure {
    param([Parameter(Mandatory)][string]$Message)
    $failures.Add($Message)
}

function Add-Pass {
    param([Parameter(Mandatory)][string]$Message)
    $passes.Add($Message)
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-PrivateReleaseToolDirectory {
    $parent = Join-Path $RepoRoot '.dart_tool\winsvpn-release-tools'
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $directory = Join-Path $parent ([Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($directory) | Out-Null

    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl = Get-Acl -LiteralPath $directory
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($acl.Access)) {
            [void]$acl.RemoveAccessRuleAll($rule)
        }
        $acl.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
        Set-Acl -LiteralPath $directory -AclObject $acl
    } else {
        & chmod 700 -- $directory
        if ($LASTEXITCODE -ne 0) {
            Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue
            throw 'Could not restrict the private release-tool staging directory.'
        }
    }
    return $directory
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
            return ''
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

function Test-ArtifactEvidenceHash {
    param(
        [Parameter(Mandatory)][string]$Expected,
        [AllowNull()][AllowEmptyString()][string]$Actual
    )
    return $Expected -cmatch '^[0-9a-f]{64}$' -and
        $Actual -cmatch '^[0-9a-f]{64}$' -and
        $Actual -ceq $Expected
}

function Test-NoReparseAncestors {
    param([Parameter(Mandatory)][string]$AbsolutePath)
    $repo = [IO.Path]::GetFullPath($RepoRoot.Path).TrimEnd('\', '/')
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

function Test-AggregateEvidenceTime {
    param([DateTime]$GeneratedAt, [DateTime]$LatestRawAt, [DateTime]$Now)
    return $GeneratedAt -ge $LatestRawAt -and
        $GeneratedAt -ge $Now.Subtract($AggregateEvidenceMaxAge) -and
        $GeneratedAt -le $Now.AddMinutes(5)
}

function ConvertFrom-StrictUtcTimestamp {
    param([AllowNull()][object]$Value)
    $text = [string]$Value
    if ($text -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$') { return [DateTime]::MinValue }
    try { return [DateTimeOffset]::Parse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime } catch { return [DateTime]::MinValue }
}

function Resolve-ContainedRepoPath {
    param(
        [AllowNull()][AllowEmptyString()][string]$RelativePath,
        [Parameter(Mandatory)][string]$RequiredPrefix
    )
    if ([string]::IsNullOrWhiteSpace($RelativePath) -or [IO.Path]::IsPathRooted($RelativePath)) {
        return $null
    }
    $normalized = $RelativePath.Replace('/', '\')
    if (@($normalized.Split('\') | Where-Object { $_ -eq '..' }).Count -gt 0) {
        return $null
    }
    $prefixRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot $RequiredPrefix)).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $resolved = [IO.Path]::GetFullPath((Join-Path $RepoRoot $normalized))
    if (-not $resolved.StartsWith($prefixRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-NoReparseAncestors -AbsolutePath $resolved)) {
        return $null
    }
    return $resolved
}

if ($SelfTest) {
    $known = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    if (-not (Test-ArtifactEvidenceHash -Expected $known -Actual $known)) {
        throw 'Exact release artifact hash must be accepted.'
    }
    foreach ($invalid in @('', $known.ToUpperInvariant(), ('f' + $known.Substring(1)), 'not-a-hash')) {
        if (Test-ArtifactEvidenceHash -Expected $known -Actual $invalid) {
            throw "Invalid or non-exact artifact evidence hash was accepted: $invalid"
        }
    }
    $contained = Resolve-ContainedRepoPath -RelativePath '.artifacts/release-evidence/android/run.json' -RequiredPrefix '.artifacts/release-evidence'
    if (-not $contained -or -not $contained.EndsWith('run.json', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Contained raw-evidence path must be accepted.'
    }
    foreach ($invalidPath in @('../run.json', '.artifacts/release-evidence/../../release/run.json', 'C:\temp\run.json', 'tools/run.json')) {
        if (Resolve-ContainedRepoPath -RelativePath $invalidPath -RequiredPrefix '.artifacts/release-evidence') {
            throw "Escaping raw-evidence path was accepted: $invalidPath"
        }
    }
    $manifestRoutes = @(
        [pscustomobject]@{ protocol = 'tcp'; port = 443; security = 'tls'; passed = $true },
        [pscustomobject]@{ protocol = 'tcp'; port = 80; security = 'none'; passed = $true }
    )
    $knownManifest = 'd5a09e1a803ce25e13c57274abbc69bc2af2c9c387de1f624217b92b12dc24f5'
    if ((Get-XrayManifestHash $manifestRoutes) -cne $knownManifest -or
        (Get-XrayManifestHash @($manifestRoutes[1], $manifestRoutes[0])) -cne $knownManifest) {
        throw 'Canonical Xray route-manifest hashing is not stable or order independent.'
    }
    $androidProducerHash = Get-ProducerContractHash 'tools/android_public_release_live_smoke.ps1'
    if ($androidProducerHash -cnotmatch '^[0-9a-f]{64}$' -or
        $androidProducerHash -ceq (Get-Sha256 'tools/android_public_release_live_smoke.ps1')) {
        throw 'Live-smoke producer hash must bind its wrapper, common validator, and artifact-privacy validator.'
    }
    $python = (Get-Command python -ErrorAction Stop).Source
    foreach ($producer in @($approvedEvidenceProducers.Values | Sort-Object -Unique)) {
        $pythonHash = (& $python -c "import pathlib,sys; sys.path.insert(0, 'tools'); from public_release_live_smoke_common import producer_contract_hash; print(producer_contract_hash(pathlib.Path('.').resolve(), sys.argv[1]))" $producer).Trim()
        if ($LASTEXITCODE -ne 0 -or (Get-ProducerContractHash $producer) -cne $pythonHash) {
            throw "Public release gate producer closure differs from the Python producer: $producer"
        }
    }
    if ($approvedEvidenceProducers.Count -ne 5 -or
        @($approvedEvidenceProducers.Values | Where-Object { $_ -notmatch '^tools/.+public_release_live_smoke\.(ps1|sh)$' }).Count -gt 0) {
        throw 'Every platform must be pinned to a dedicated public-release live-smoke producer.'
    }
    $now = [DateTime]::UtcNow
    if (Test-RawEvidenceTime -TestedAt $now.AddHours(-73) -NotBefore $now.AddHours(-80) -Now $now) {
        throw 'Public release gate accepted raw evidence older than 72 hours.'
    }
    if (Test-AggregateEvidenceTime -GeneratedAt $now.AddMinutes(-1) -LatestRawAt $now -Now $now) {
        throw 'Public release gate accepted aggregate evidence generated before raw evidence.'
    }
    if (Test-AggregateEvidenceTime -GeneratedAt $now.AddHours(-25) -LatestRawAt $now.AddHours(-26) -Now $now) {
        throw 'Public release gate accepted aggregate evidence older than 24 hours.'
    }
    Write-Host 'PUBLIC RELEASE GATE EVIDENCE-BINDING SELF-TEST: PASS' -ForegroundColor Green
    exit 0
}

# -VerifyLive proves the public bytes are the candidate bytes, not only that
# the URL answers: the body is downloaded and its size and SHA-256 must equal
# the local candidate's (R23 W1-10).
function Test-LiveDownloadMatches {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][long]$ExpectedSize
    )
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('winsvpn-live-' + [Guid]::NewGuid().ToString('N'))
    try {
        Invoke-WebRequest -UseBasicParsing -Method Get -MaximumRedirection 5 -TimeoutSec 600 `
            -Uri $Url -OutFile $temporary | Out-Null
        if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) { return $false }
        if ((Get-Item -LiteralPath $temporary).Length -ne $ExpectedSize) { return $false }
        return ((Get-Sha256 $temporary) -ceq $ExpectedSha256.ToLowerInvariant())
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Assert-ChecksumSidecar {
    param([Parameter(Mandatory)][string]$Artifact)

    $sidecar = "$Artifact.sha256"
    if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf)) {
        Add-Failure "Missing SHA-256 sidecar for $Artifact"
        return
    }
    $line = (Get-Content -LiteralPath $sidecar -Raw).Trim()
    if ($line -notmatch '^(?<hash>[0-9A-Fa-f]{64})\s+\*?(?<name>.+)$') {
        Add-Failure "Malformed SHA-256 sidecar: $sidecar"
        return
    }
    $declaredName = [IO.Path]::GetFileName($Matches.name.Trim())
    $actualName = [IO.Path]::GetFileName($Artifact)
    if ($declaredName -cne $actualName) {
        Add-Failure "Checksum sidecar $sidecar names $declaredName instead of $actualName"
        return
    }
    $actual = Get-Sha256 $Artifact
    if ($actual -ne $Matches.hash.ToLowerInvariant()) {
        Add-Failure "SHA-256 mismatch for $Artifact"
        return
    }
    Add-Pass "Checksum matches $actualName"
}

function Find-AndroidTool {
    param([Parameter(Mandatory)][string]$Name)

    $fromPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    $sdk = if ($env:ANDROID_SDK_ROOT) {
        $env:ANDROID_SDK_ROOT
    } elseif ($env:ANDROID_HOME) {
        $env:ANDROID_HOME
    } else {
        Join-Path $env:LOCALAPPDATA "Android\Sdk"
    }
    if ($Name -like 'apkanalyzer*') {
        $candidate = Join-Path $sdk "cmdline-tools\latest\bin\apkanalyzer.bat"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $candidate = Get-ChildItem (Join-Path $sdk "build-tools") -Recurse -File -Filter "$Name.bat" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($candidate) { return $candidate.FullName }
    return $null
}

function Get-VerifiedBundletool {
    $version = '1.18.3'
    $expectedHash = 'a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29'
    $downloadUrl = "https://github.com/google/bundletool/releases/download/$version/bundletool-all-$version.jar"
    $configured = [string]$env:WINS_BUNDLETOOL_JAR
    $stage = New-PrivateReleaseToolDirectory
    $partial = Join-Path $stage 'bundletool.jar.partial'
    $jar = Join-Path $stage 'bundletool.jar'
    try {
        if (-not [string]::IsNullOrWhiteSpace($configured)) {
            $configured = [IO.Path]::GetFullPath($configured)
            if (-not (Test-Path -LiteralPath $configured -PathType Leaf) -or
                (Get-Sha256 $configured) -cne $expectedHash) {
                throw 'WINS_BUNDLETOOL_JAR does not match the pinned Google release digest.'
            }
            Copy-Item -LiteralPath $configured -Destination $partial
        } else {
            Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'WinsVPN-public-release-gate' } `
                -Uri $downloadUrl -OutFile $partial | Out-Null
        }
        if ((Get-Sha256 $partial) -cne $expectedHash) {
            throw "Downloaded bundletool $version failed its pinned SHA-256 check."
        }
        Move-Item -LiteralPath $partial -Destination $jar
        if ((Get-Sha256 $jar) -cne $expectedHash) {
            throw "Staged bundletool $version failed its pinned SHA-256 recheck."
        }
        if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
            throw 'Java is required to validate Android App Bundles.'
        }
        $reported = ((& java -jar $jar version 2>&1) -join "`n").Trim()
        if ($LASTEXITCODE -ne 0 -or $reported -cne $version) {
            throw "Pinned bundletool did not report version $version."
        }
        return [pscustomobject]@{
            Jar = $jar
            PrivateDirectory = $stage
        }
    } catch {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Get-WebsiteSourceState {
    $helper = Join-Path $RepoRoot 'tools\release_source_freeze.py'
    $output = & python $helper --repo $RepoRoot.Path --website-only --json 2>&1
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
        [IO.Path]::GetFullPath((Join-Path $RepoRoot.Path $Path))
    }
    $repoPrefix = [IO.Path]::GetFullPath($RepoRoot.Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $absolute.StartsWith($repoPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($absolute) -cne 'RELEASE_INPUT_INDEX.json' -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf) -or
        -not (Test-NoReparseAncestors -AbsolutePath $absolute)) {
        throw 'ReleaseInputIndex must be an existing RELEASE_INPUT_INDEX.json inside the repository.'
    }
    $helper = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'
    $output = & python $helper verify-index --repo $RepoRoot.Path --index $absolute 2>&1
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
        if (-not (Test-ArtifactEvidenceHash -Expected (Get-Sha256 $manifestPath) -Actual ([string]$reference.sha256)) -or
            -not (Test-ArtifactEvidenceHash -Expected $fingerprint -Actual ([string]$reference.artifact_input_fingerprint_sha256))) {
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
    $receipt = Resolve-ContainedRepoPath -RelativePath $RelativePath -RequiredPrefix '.artifacts'
    if (-not $receipt -or -not (Test-Path -LiteralPath $receipt -PathType Leaf)) {
        throw "$Platform build receipt is missing, escapes .artifacts, or uses a reparse path."
    }
    $helper = Join-Path $RepoRoot 'tools\release_dependency_freeze.py'
    $output = & python $helper verify-receipt --repo $RepoRoot.Path --index $ReleaseInputs.Path `
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

function Get-TarText {
    param(
        [Parameter(Mandatory)][string]$Archive,
        [Parameter(Mandatory)][string]$Member
    )
    $output = & tar -xOzf $Archive $Member 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "Could not extract $Member from $Archive"
        return $null
    }
    return ($output -join "`n")
}

function Invoke-ExactArtifactPrivacyScan {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$Scanner
    )

    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & python $Scanner --artifacts --artifact $Artifact 2>&1
        $scannerExitCode = $LASTEXITCODE
        $ErrorActionPreference = $previousErrorActionPreference
        if ($scannerExitCode -ne 0) {
            Add-Failure ("$Label failed hidden-origin/secret-literal privacy validation: " + ($output -join ' '))
            return $false
        }
        Add-Pass "$Label passed exact-artifact privacy validation"
        return $true
    } catch {
        $ErrorActionPreference = $previousErrorActionPreference
        Add-Failure "Could not privacy-scan $Label`: $($_.Exception.Message)"
        return $false
    }
}

function Test-WindowsPayloadManifest {
    param(
        [Parameter(Mandatory)][string]$Installer,
        [Parameter(Mandatory)][string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { return $false }
    try {
        $manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
        if ([int]$manifest.schema_version -ne 3 -or
            [string]$manifest.installer.sha256 -cne (Get-Sha256 $Installer) -or
            [long]$manifest.installer.size -ne (Get-Item -LiteralPath $Installer).Length) {
            return $false
        }
        $producer = Join-Path $RepoRoot ([string]$manifest.producer.path)
        $innoScript = Join-Path $RepoRoot ([string]$manifest.producer.inno_script_path)
        $innoSigningWrapper = Join-Path $RepoRoot ([string]$manifest.producer.inno_signing_wrapper_path)
        if (-not (Test-Path -LiteralPath $producer -PathType Leaf) -or
            -not (Test-Path -LiteralPath $innoScript -PathType Leaf) -or
            -not (Test-Path -LiteralPath $innoSigningWrapper -PathType Leaf) -or
            [string]$manifest.producer.sha256 -cne (Get-Sha256 $producer) -or
            [string]$manifest.producer.inno_script_sha256 -cne (Get-Sha256 $innoScript) -or
            [string]$manifest.producer.inno_signing_wrapper_sha256 -cne (Get-Sha256 $innoSigningWrapper)) {
            return $false
        }
        if (-not [bool]$manifest.signing.production_signed -or
            -not [bool]$manifest.signing.every_loose_pe_verified -or
            -not [bool]$manifest.signing.staged_xray_product_signed -or
            -not [bool]$manifest.signing.inno_setup_and_uninstaller_signed -or
            -not [bool]$manifest.signing.self_signed_certificate_forbidden) {
            return $false
        }
        $payload = @($manifest.payload)
        if ($payload.Count -eq 0) { return $false }
        foreach ($entry in $payload) {
            $relative = ([string]$entry.path).Replace('/', '\')
            if ([IO.Path]::IsPathRooted($relative) -or @($relative.Split('\') | Where-Object { $_ -eq '..' }).Count -gt 0) {
                return $false
            }
            $absolute = Join-Path $RepoRoot $relative
            if (-not (Test-Path -LiteralPath $absolute -PathType Leaf) -or
                [long]$entry.size -ne (Get-Item -LiteralPath $absolute).Length -or
                [string]$entry.sha256 -cne (Get-Sha256 $absolute)) {
                return $false
            }
            if ([IO.Path]::GetExtension($absolute) -in @('.exe','.dll','.sys','.msi')) {
                $payloadSignature = Get-AuthenticodeSignature -LiteralPath $absolute
                if ($payloadSignature.Status -ne 'Valid' -or
                    -not $payloadSignature.SignerCertificate -or
                    $payloadSignature.SignerCertificate.Subject -eq $payloadSignature.SignerCertificate.Issuer -or
                    -not (Test-MicrosoftTrustedRootProgramChain -Certificate $payloadSignature.SignerCertificate)) {
                    return $false
                }
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-MicrosoftTrustedRootProgramChain {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if (-not $Certificate) { return $false }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
        [void]$chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { return $false }
        $rootThumbprint = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Thumbprint
        $installedRoot = $false
        foreach ($location in @(
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )) {
            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('AuthRoot', $location)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($store.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { return $true }
            } finally { $store.Close() }
            $rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root', $location)
            try {
                $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                if (@($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $rootThumbprint }).Count -gt 0) { $installedRoot = $true }
            } finally { $rootStore.Close() }
        }
        return $installedRoot -and $rootThumbprint -in @(
            '3B1EFD3A66EA28B16697394703A72CA340A05BD5',
            '8F43288AD272F3103B6FB1428485EA3014C0BCFE'
        )
    } catch {
        return $false
    } finally { $chain.Dispose() }
}

$privacyScanner = Join-Path $RepoRoot 'tools\validate_release_artifact_privacy.py'
try {
    $privacyOutput = & python $privacyScanner --static --artifacts 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Failure ('Current release artifacts failed hidden-origin/secret-literal privacy validation: ' + ($privacyOutput -join ' '))
    } else {
        Add-Pass 'Current release artifacts contain no forbidden control-origin or legacy SPA literals'
    }
} catch {
    Add-Failure "Could not run release artifact privacy validation: $($_.Exception.Message)"
}

# Inventory every client route exposed by the static page, Pages Worker, or
# redirect file. A stale alias remains a public release surface even when it is
# no longer linked by the main download menu.
$publicSurfaceText = @(
    'web\index.html',
    'web\_worker.js',
    'web\_redirects'
) | ForEach-Object {
    $path = Join-Path $RepoRoot $_
    if (Test-Path -LiteralPath $path -PathType Leaf) { Get-Content -LiteralPath $path -Raw }
} | Out-String
$publicSurfaceNames = @(
    [regex]::Matches(
        $publicSurfaceText,
        '(?i)/downloads/(?<name>[^"''\s<>\]]+\.(?:apk|aab|exe|tar\.gz))'
    ) | ForEach-Object { [Uri]::UnescapeDataString($_.Groups['name'].Value) } | Sort-Object -Unique
)
$publicSurfaceLocalArtifacts = @()
foreach ($name in $publicSurfaceNames) {
    $artifact = Join-Path $RepoRoot ("web\downloads\" + $name)
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        Add-Failure "Public client route /downloads/$name has no exact local artifact for privacy verification."
        continue
    }
    $publicSurfaceLocalArtifacts += [pscustomobject]@{
        Name = $name
        Path = $artifact
        Hash = Get-Sha256 $artifact
        Platform = if ($name -match '(?i)\.(?:apk|aab)$') { 'Android' } elseif ($name -match '(?i)\.tar\.gz$') { 'Linux' } else { 'Windows' }
    }
    Assert-ChecksumSidecar $artifact
}
foreach ($group in @($publicSurfaceLocalArtifacts | Where-Object Platform -in @('Android', 'Linux') | Group-Object Platform, Hash)) {
    $representative = $group.Group[0]
    $aliases = @($group.Group.Name | Sort-Object) -join ', '
    $null = Invoke-ExactArtifactPrivacyScan -Label "Public $($representative.Platform) payload aliases [$aliases]" -Artifact $representative.Path -Scanner $privacyScanner
}

$versionLine = Select-String -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Pattern '^version:\s*([^+\s]+)\+(\d+)\s*$' | Select-Object -First 1
if (-not $versionLine) { throw "pubspec.yaml must contain version: <semver>+<integer>." }
$appVersion = $versionLine.Matches[0].Groups[1].Value
$buildNumber = $versionLine.Matches[0].Groups[2].Value
$releaseInputs = Get-ReleaseInputState -Path $ReleaseInputIndex
$websiteState = Get-WebsiteSourceState
Add-Pass "Verified dependency-scoped release input index for $appVersion+$buildNumber SHA-256=$($releaseInputs.Sha256) shared_revision=$($releaseInputs.SharedRevision)"
Add-Pass "Current website staging fingerprint=$($websiteState.WebsiteSha256) files=$($websiteState.WebsiteFileCount)"
Add-Pass "Independent immutable website fingerprint=$($websiteState.ImmutableWebsiteSha256) files=$($websiteState.ImmutableWebsiteFileCount)"

# M-1: a public release must never ship a committed Xray/AmneziaWG binary
# whose embedded Go runtime predates the minimums this repo has reviewed
# and fixed against (see docs/RELEASE_ENGINE_BINARY_REFRESH.md).
try {
    $python = (Get-Command python.exe -ErrorAction SilentlyContinue)
    if (-not $python) { $python = Get-Command python -ErrorAction Stop }
    $engineOutput = & $python.Source (Join-Path $RepoRoot 'tools\verify_embedded_engine_runtime_versions.py') 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Failure "Embedded engine (Xray/AmneziaWG) Go runtime freshness check failed: $($engineOutput -join ' ')"
    } else {
        Add-Pass "Embedded Xray/AmneziaWG binaries all report a current Go runtime"
    }
} catch {
    Add-Failure "Could not run the embedded engine Go runtime freshness check: $($_.Exception.Message)"
}

# QUERY_ALL_PACKAGES is a Google Play sensitive-permission declaration, not a
# code defect: Play Console approval of that declaration is a publication
# gate, checked here only while the manifest still requests the permission so
# a future redesign that drops it (see docs\GOOGLE_PLAY_RELEASE_DECLARATIONS.md)
# retires this gate automatically instead of needing a manual removal.
$androidManifestText = Get-Content -LiteralPath (Join-Path $RepoRoot 'android\app\src\main\AndroidManifest.xml') -Raw
$manifestRequiresQueryAllPackages = $androidManifestText -match 'android\.permission\.QUERY_ALL_PACKAGES'
function Assert-QueryAllPackagesDeclarationApproved {
    param([Parameter(Mandatory)][string]$Declaration)
    if (-not $manifestRequiresQueryAllPackages) { return }
    if ($Declaration -notmatch 'Approval status:\s*`(?<status>[^`]+)`') {
        Add-Failure "Could not read the QUERY_ALL_PACKAGES Play Console approval status from docs\GOOGLE_PLAY_RELEASE_DECLARATIONS.md."
        return
    }
    # Captured before the next -match/-notmatch below, which would otherwise
    # overwrite the shared $Matches automatic variable and lose this value.
    $approvalStatus = $Matches.status
    if ($approvalStatus -notmatch '^APPROVED\b') {
        Add-Failure "QUERY_ALL_PACKAGES Play Console declaration approval status is '$approvalStatus', not APPROVED; a public Android release must not ship this permission until Play Console approves the declaration."
    } else {
        Add-Pass "QUERY_ALL_PACKAGES Play Console declaration approval status is $approvalStatus"
    }
}

$publicAndroidAabs = @($publicSurfaceLocalArtifacts | Where-Object { $_.Name -match '(?i)\.aab$' })
if ($publicAndroidAabs.Count -gt 0) {
    $bundletoolState = $null
    try {
        $bundletoolState = Get-VerifiedBundletool
        $bundletool = [string]$bundletoolState.Jar
        $jarsigner = (Get-Command jarsigner -ErrorAction Stop).Source
        $keytool = (Get-Command keytool -ErrorAction Stop).Source
        $declaration = Get-Content -LiteralPath (Join-Path $RepoRoot 'docs\GOOGLE_PLAY_RELEASE_DECLARATIONS.md') -Raw
        if ($declaration -notmatch 'Upload certificate SHA-256:\s*`(?<digest>[0-9A-Fa-f:]{64,})`') {
            throw 'Could not read the reviewed Android upload-certificate fingerprint.'
        }
        $expectedUploadDigest = $Matches.digest.Replace(':', '').ToLowerInvariant()
        Assert-QueryAllPackagesDeclarationApproved -Declaration $declaration
        foreach ($entry in $publicAndroidAabs) {
            $aabPath = [string]$entry.Path
            $validateOutput = (& java -jar $bundletool validate --bundle=$aabPath 2>&1) -join "`n"
            if ($LASTEXITCODE -ne 0) {
                Add-Failure "Public Android App Bundle $($entry.Name) failed bundletool validation: $validateOutput"
                continue
            }
            $aabVersion = ((& java -jar $bundletool dump manifest --bundle=$aabPath --xpath='/manifest/@android:versionName' 2>&1) -join "`n").Trim()
            $versionExit = $LASTEXITCODE
            $aabBuild = ((& java -jar $bundletool dump manifest --bundle=$aabPath --xpath='/manifest/@android:versionCode' 2>&1) -join "`n").Trim()
            $buildExit = $LASTEXITCODE
            if ($versionExit -ne 0 -or $buildExit -ne 0 -or $aabVersion -cne $appVersion -or $aabBuild -cne $buildNumber) {
                Add-Failure "Public Android App Bundle $($entry.Name) is $aabVersion+$aabBuild, expected $appVersion+$buildNumber."
            } else {
                Add-Pass "Public Android App Bundle $($entry.Name) is bundletool-valid version $aabVersion+$aabBuild"
            }
            $jarOutput = (& $jarsigner -verify -verbose -certs $aabPath 2>&1) -join "`n"
            if ($LASTEXITCODE -ne 0 -or $jarOutput -notmatch '(?im)^jar verified\.$') {
                Add-Failure "Public Android App Bundle $($entry.Name) failed JAR signature verification."
                continue
            }
            $certOutput = (& $keytool -printcert -jarfile $aabPath 2>&1) -join "`n"
            $certExit = $LASTEXITCODE
            $signerCount = [regex]::Matches($certOutput, '(?m)^Signer #\d+:\s*$').Count
            $digestMatch = [regex]::Match($certOutput, '(?im)^\s*SHA256:\s*(?<digest>(?:[0-9A-F]{2}:){31}[0-9A-F]{2})\s*$')
            if ($certExit -ne 0 -or $signerCount -ne 1 -or -not $digestMatch.Success) {
                Add-Failure "Public Android App Bundle $($entry.Name) did not expose exactly one readable signer certificate."
            } elseif ($digestMatch.Groups['digest'].Value.Replace(':', '').ToLowerInvariant() -cne $expectedUploadDigest) {
                Add-Failure "Public Android App Bundle $($entry.Name) signer does not match the reviewed upload certificate."
            } else {
                Add-Pass "Public Android App Bundle $($entry.Name) has the reviewed one-signer upload signature"
            }
        }
        $genericAab = Join-Path $RepoRoot 'web\downloads\wins-vpn-android.aab'
        $localAab = Join-Path $RepoRoot 'build\app\outputs\bundle\release\app-release.aab'
        if (-not (Test-Path -LiteralPath $localAab -PathType Leaf)) {
            Add-Failure 'Fresh local Android release AAB is missing.'
        } elseif (-not (Test-Path -LiteralPath $genericAab -PathType Leaf) -or (Get-Sha256 $genericAab) -cne (Get-Sha256 $localAab)) {
            Add-Failure 'Generic website Android AAB does not match the latest locally verified release AAB.'
        } else {
            Add-Pass 'Generic website Android AAB matches the locally verified release AAB'
        }
    } catch {
        Add-Failure "Could not verify public Android App Bundles: $($_.Exception.Message)"
    } finally {
        if ($null -ne $bundletoolState -and
            (Test-Path -LiteralPath ([string]$bundletoolState.PrivateDirectory))) {
            Remove-Item -LiteralPath ([string]$bundletoolState.PrivateDirectory) -Recurse -Force
        }
    }
}

# The linked segment stays escaped: the live URL and the name checks use it
# exactly as the website links it (R24 V2 F-08). Only the local file name is
# unescaped, and it must stay a plain file name under web\downloads.
function Get-LinkedDownloadNames {
    param([Parameter(Mandatory)][string]$Index)
    @(
        [regex]::Matches($Index, 'https://www\.winsvpn\.org/downloads/([^"''\s<>]+)') |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    )
}

function Get-LocalDownloadFileName {
    param([Parameter(Mandatory)][string]$LinkedName)
    $local = [Uri]::UnescapeDataString($LinkedName)
    if ($local -match '[\\/]' -or $local -in @('.', '..')) { return $null }
    return $local
}

$indexPath = Join-Path $RepoRoot "web\index.html"
$index = Get-Content -LiteralPath $indexPath -Raw
$downloadNames = @(Get-LinkedDownloadNames -Index $index)
$windowsNames = @($downloadNames | Where-Object { $_ -match '(?i)\.exe$' })
$androidNames = @($downloadNames | Where-Object { $_ -match '(?i)\.apk$' })
$linuxNames = @($downloadNames | Where-Object { $_ -match '(?i)\.tar\.gz$' })
foreach ($entry in @(
    @{ Label = 'Windows'; Names = $windowsNames },
    @{ Label = 'Android'; Names = $androidNames },
    @{ Label = 'Linux'; Names = $linuxNames }
)) {
    if ($entry.Names.Count -ne 1) {
        Add-Failure "Website must link exactly one current $($entry.Label) artifact; found $($entry.Names -join ', ')"
    }
}

$publishedArtifacts = @{}
$publishedNames = @{}
$expectedArtifactHashes = @{}
$expectedArtifactSizes = @{}
foreach ($pair in @(
    @{ Platform = 'windows'; Names = $windowsNames },
    @{ Platform = 'android'; Names = $androidNames },
    @{ Platform = 'linux'; Names = $linuxNames }
)) {
    if ($pair.Names.Count -ne 1) { continue }
    $localName = Get-LocalDownloadFileName -LinkedName $pair.Names[0]
    if ($null -eq $localName) {
        Add-Failure "Website download name is not a plain file name: $($pair.Names[0])"
        continue
    }
    $artifact = Join-Path $RepoRoot ("web\downloads\" + $localName)
    if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
        Add-Failure "Website links missing local artifact $artifact"
        continue
    }
    $publishedArtifacts[$pair.Platform] = $artifact
    $publishedNames[$pair.Platform] = $pair.Names[0]
    $expectedArtifactHashes[$pair.Platform] = Get-Sha256 $artifact
    $expectedArtifactSizes[$pair.Platform] = (Get-Item -LiteralPath $artifact).Length
    Assert-ChecksumSidecar $artifact
}

if ($publishedArtifacts.ContainsKey('android')) {
    $artifact = $publishedArtifacts.android
    $apkanalyzer = Find-AndroidTool 'apkanalyzer'
    $apksigner = Find-AndroidTool 'apksigner'
    if (-not $apkanalyzer -or -not $apksigner) {
        Add-Failure "Android SDK apkanalyzer and apksigner are required for publication."
    } else {
        $actualVersion = (& $apkanalyzer manifest version-name $artifact 2>&1 | Select-Object -Last 1).ToString().Trim()
        $actualBuild = (& $apkanalyzer manifest version-code $artifact 2>&1 | Select-Object -Last 1).ToString().Trim()
        if ($actualVersion -ne $appVersion -or $actualBuild -ne $buildNumber) {
            Add-Failure "Published Android artifact is $actualVersion+$actualBuild, expected $appVersion+$buildNumber"
        } else {
            Add-Pass "Published Android version is $actualVersion+$actualBuild"
        }
        $signatureOutput = (& $apksigner verify --verbose --print-certs $artifact 2>&1) -join "`n"
        if ($LASTEXITCODE -ne 0 -or $signatureOutput -notmatch 'Verified using v2 scheme .*:\s*true' -or $signatureOutput -notmatch 'Number of signers:\s*1') {
            Add-Failure "Published Android APK did not pass the one-signer APK v2 signature contract."
        }
        $declaration = Get-Content -LiteralPath (Join-Path $RepoRoot "docs\GOOGLE_PLAY_RELEASE_DECLARATIONS.md") -Raw
        if ($declaration -notmatch 'Upload certificate SHA-256:\s*`(?<digest>[0-9A-Fa-f:]{64,})`') {
            Add-Failure "Could not read the reviewed Android upload-certificate fingerprint."
        } else {
            $expectedDigest = $Matches.digest.Replace(':', '').ToLowerInvariant()
            Assert-QueryAllPackagesDeclarationApproved -Declaration $declaration
            if ($signatureOutput -notmatch 'Signer #1 certificate SHA-256 digest:\s*(?<digest>[0-9A-Fa-f]{64})') {
                Add-Failure "Android APK signer digest is missing."
            } elseif ($Matches.digest.ToLowerInvariant() -ne $expectedDigest) {
                Add-Failure "Android APK signer fingerprint does not match the reviewed release certificate."
            } else {
                Add-Pass "Android APK signer fingerprint matches the reviewed release certificate"
            }
        }
    }
    $localApk = Join-Path $RepoRoot "build\app\outputs\flutter-apk\app-release.apk"
    if (-not (Test-Path -LiteralPath $localApk -PathType Leaf)) {
        Add-Failure "Fresh local Android release APK is missing."
    } elseif ((Get-Sha256 $localApk) -ne (Get-Sha256 $artifact)) {
        Add-Failure "Website Android APK does not match the latest locally tested release APK."
    } else {
        Add-Pass "Website Android APK matches the locally tested release APK"
    }
}

if ($publishedArtifacts.ContainsKey('windows')) {
    $artifact = $publishedArtifacts.windows
    $productVersion = (Get-Item -LiteralPath $artifact).VersionInfo.ProductVersion.Trim()
    if ($productVersion -ne $appVersion) {
        Add-Failure "Published Windows installer product version is $productVersion, expected $appVersion"
    } else {
        Add-Pass "Published Windows installer product version is $productVersion"
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact
    $expectedWindowsSigner = [string]$env:WINS_WINDOWS_SIGNER_SUBJECT_REGEX
    if ([string]::IsNullOrWhiteSpace($expectedWindowsSigner)) {
        Add-Failure "WINS_WINDOWS_SIGNER_SUBJECT_REGEX is required to pin the Windows publisher identity."
    }
    $hasCodeSigningEku = $false
    if ($signature.SignerCertificate) {
        $hasCodeSigningEku = @(
            $signature.SignerCertificate.EnhancedKeyUsageList |
                Where-Object { $_.ObjectId.Value -eq '1.3.6.1.5.5.7.3.3' }
        ).Count -eq 1
    }
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or -not $signature.TimeStamperCertificate -or -not $hasCodeSigningEku) {
        Add-Failure "Published Windows installer must have a valid Authenticode signature and trusted timestamp."
    } elseif ($signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) {
        Add-Failure "Published Windows installer must not use a self-signed certificate."
    } elseif (-not (Test-MicrosoftTrustedRootProgramChain -Certificate $signature.SignerCertificate)) {
        Add-Failure "Published Windows installer signer must chain to AuthRoot or an explicitly pinned Microsoft system root."
    } elseif (-not [string]::IsNullOrWhiteSpace($expectedWindowsSigner) -and $signature.SignerCertificate.Subject -notmatch $expectedWindowsSigner) {
        Add-Failure "Published Windows signer does not match WINS_WINDOWS_SIGNER_SUBJECT_REGEX."
    } else {
        Add-Pass "Windows Authenticode signer and timestamp are valid"
    }
    $localInstaller = Join-Path $RepoRoot "build\windows-installer\WinsVPN-Setup.exe"
    if (-not (Test-Path -LiteralPath $localInstaller -PathType Leaf)) {
        Add-Failure "Fresh signed Windows installer is missing from build/windows-installer."
    } elseif ((Get-Sha256 $localInstaller) -ne (Get-Sha256 $artifact)) {
        Add-Failure "Website Windows installer does not match the latest locally verified installer."
        Add-Failure "Website Windows installer payload privacy is unverifiable: the opaque Inno archive does not match the pre-package-scanned local installer."
    } elseif (-not (Test-WindowsPayloadManifest -Installer $localInstaller -ManifestPath "$localInstaller.payload-manifest.json")) {
        Add-Failure "Website Windows installer lacks a valid payload manifest binding the opaque Inno archive to its scanned build inputs."
    } else {
        Add-Pass "Website Windows installer matches its locally scanned payload manifest"
    }
}

$publicWindowsArtifacts = @($publicSurfaceLocalArtifacts | Where-Object Platform -eq 'Windows')
if ($publicWindowsArtifacts.Count -gt 0) {
    $localInstaller = Join-Path $RepoRoot "build\windows-installer\WinsVPN-Setup.exe"
    $verifiedHash = if (Test-Path -LiteralPath $localInstaller -PathType Leaf) { Get-Sha256 $localInstaller } else { '' }
    $opaqueHashes = @($publicWindowsArtifacts | Where-Object Hash -ne $verifiedHash | Select-Object -ExpandProperty Hash -Unique)
    if ($opaqueHashes.Count -gt 0) {
        Add-Failure "Public Windows routes expose $($opaqueHashes.Count) opaque installer payload hash(es) that cannot be tied to the scanned local build."
    }
}

if ($publishedArtifacts.ContainsKey('linux')) {
    $artifact = $publishedArtifacts.linux
    $versionJson = Get-TarText -Archive $artifact -Member './data/flutter_assets/version.json'
    if ($versionJson) {
        try { $linuxVersion = $versionJson | ConvertFrom-Json } catch { $linuxVersion = $null }
        if (-not $linuxVersion -or [string]$linuxVersion.version -ne $appVersion -or [string]$linuxVersion.build_number -ne $buildNumber) {
            Add-Failure "Published Linux archive does not contain version $appVersion+$buildNumber."
        } else {
            Add-Pass "Published Linux version is $appVersion+$buildNumber"
        }
    }
    $metainfo = Get-TarText -Archive $artifact -Member './share/metainfo/org.winsvpn.app.metainfo.xml'
    if (-not $metainfo -or $metainfo -notmatch ('<release\s+version="' + [regex]::Escape($appVersion) + '"')) {
        Add-Failure "Published Linux AppStream metadata is not current version $appVersion."
    } else {
        Add-Pass "Published Linux AppStream metadata is current"
    }
    $temp = Join-Path ([IO.Path]::GetTempPath()) ("wins-public-release-" + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $temp | Out-Null
        $linuxRuntimes = [ordered]@{
            'xray' = '09e63d5420f26db2bc6144f6d047601909541acf21792878d3859e4fc4980a12'
            'awg' = '23d29323258166183eeeb288c1f9f08b879f3707e54591b1bfb2402413f6d8d8'
            'awg-quick' = '89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db'
            'amneziawg-go' = '5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f'
        }
        foreach ($runtime in $linuxRuntimes.GetEnumerator()) {
            & tar -xzf $artifact -C $temp ("./{0}" -f $runtime.Key) 2>&1 | Out-Null
            $runtimePath = Join-Path $temp $runtime.Key
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $runtimePath) -or
                (Get-Sha256 $runtimePath) -ne $runtime.Value) {
                Add-Failure "Published Linux archive does not contain the reviewed $($runtime.Key) executable."
            } else {
                Add-Pass "Linux archive contains the reviewed $($runtime.Key) executable"
            }
        }
        $installScript = Get-TarText -Archive $artifact -Member './install.sh'
        if (-not $installScript -or $installScript -notmatch 'Dpkg::Options::=--force-confold' -or
            $installScript -notmatch 'nftables' -or $installScript -notmatch 'systemd-resolved' -or
            $installScript -notmatch 'openresolv' -or $installScript -notmatch 'util-linux' -or
            $installScript -notmatch 'useradd --system --no-create-home' -or
            $installScript -notmatch 'winsvpn-xray') {
            Add-Failure "Published Linux archive lacks the reviewed one-touch host dependency installer."
        } else {
            Add-Pass "Linux archive contains the reviewed one-touch host dependency installer"
        }
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
    }
    $freshArchive = Join-Path $RepoRoot "web\downloads\wins-vpn-linux-x64.tar.gz"
    if (-not (Test-Path -LiteralPath $freshArchive -PathType Leaf)) {
        Add-Failure "Fresh local Linux release archive is missing."
    } elseif ((Get-Sha256 $freshArchive) -ne (Get-Sha256 $artifact)) {
        Add-Failure "Website Linux archive does not match the latest locally built release archive."
    } elseif ((Get-Item -LiteralPath $freshArchive).LastWriteTimeUtc -lt $releaseInputs.Platforms['linux'].EvidenceNotBeforeUtc) {
        Add-Failure "Local Linux release archive predates its immutable platform manifest/index."
    } else {
        Add-Pass "Website Linux archive matches an index-current local build"
    }
}

$appleCandidatePath = Join-Path $RepoRoot "app_store\apple\artifacts\release_candidate.json"
$appleCandidate = $null
if (-not (Test-Path -LiteralPath $appleCandidatePath -PathType Leaf)) {
    Add-Failure "Apple release candidate manifest is missing."
} else {
    $appleCandidate = Get-Content -LiteralPath $appleCandidatePath -Raw | ConvertFrom-Json
    if ([string]$appleCandidate.app_version -ne $appVersion -or [string]$appleCandidate.build_number -ne $buildNumber) {
        Add-Failure "Apple candidate is $($appleCandidate.app_version)+$($appleCandidate.build_number), expected $appVersion+$buildNumber."
    }
    $appleArtifacts = @($appleCandidate.artifacts)
    foreach ($platform in @('ios', 'macos')) {
        $candidateArtifact = @($appleArtifacts | Where-Object platform -eq $platform)
        if ($candidateArtifact.Count -ne 1 -or $candidateArtifact[0].processing_state -ne 'VALID' -or $candidateArtifact[0].upload_status -ne 'uploaded_processed_and_attached') {
            Add-Failure "Current $platform App Store artifact is not uniquely uploaded, processed, VALID, and attached."
            continue
        }
        $candidateHash = [string]$candidateArtifact[0].sha256
        if ($candidateHash -notmatch '^[0-9a-f]{64}$') {
            Add-Failure "Current $platform App Store artifact lacks a lowercase SHA-256 identity."
        } else {
            $expectedArtifactHashes[$platform] = $candidateHash
            $expectedArtifactSizes[$platform] = [long]$candidateArtifact[0].size_bytes
        }
    }
}
if ($index -match '(?i)iOS\s*(?:<[^>]+>)*\s*\(coming soon\)' -or $index -match '(?i)MacOS\s*(?:<[^>]+>)*\s*\(coming soon\)') {
    Add-Failure "Website still marks iOS or macOS as coming soon."
}
if ($index -notmatch 'https://apps\.apple\.com/') {
    Add-Failure "Website does not link the current Apple App Store listing."
}

$evidence = $null
$evidenceAbsolute = if ([IO.Path]::IsPathRooted($EvidenceFile)) { [IO.Path]::GetFullPath($EvidenceFile) } else { [IO.Path]::GetFullPath((Join-Path $RepoRoot.Path $EvidenceFile)) }
$releaseEvidenceRoot = [IO.Path]::GetFullPath((Join-Path $RepoRoot 'release')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
if (-not $evidenceAbsolute.StartsWith($releaseEvidenceRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not (Test-NoReparseAncestors -AbsolutePath $evidenceAbsolute)) {
    Add-Failure "Public release evidence must stay under release/ without reparse ancestors."
} elseif (-not (Test-Path -LiteralPath $evidenceAbsolute -PathType Leaf)) {
    Add-Failure "Missing exact-artifact live-test evidence: $EvidenceFile"
} else {
    try { $evidence = Get-Content -LiteralPath $evidenceAbsolute -Raw | ConvertFrom-Json } catch { Add-Failure "Invalid public release evidence JSON: $EvidenceFile" }
}
if ($evidence) {
    $aggregateGeneratedAt = ConvertFrom-StrictUtcTimestamp $evidence.generated_at_utc
    if ([int]$evidence.schema_version -ne 3 -or [string]$evidence.app_version -ne $appVersion -or [string]$evidence.build_number -ne $buildNumber) {
        Add-Failure "Public release evidence schema/version does not match $appVersion+$buildNumber."
    }
    if (-not (Test-ArtifactEvidenceHash -Expected $releaseInputs.Sha256 -Actual ([string]$evidence.release_input_index_sha256)) -or
        [string]$evidence.shared_revision -cne $releaseInputs.SharedRevision) {
        Add-Failure "Public release evidence does not match the explicit verified RELEASE_INPUT_INDEX."
    }
    if ([string]$evidence.website_source_fingerprint_sha256 -ne $websiteState.WebsiteSha256 -or
        [int]$evidence.website_source_file_count -ne $websiteState.WebsiteFileCount) {
        Add-Failure "Public release evidence does not bind the exact current website staging source."
    }
    $requiredResults = @(
        'artifact_signature_passed', 'clean_install_passed', 'direct_awg_passed',
        'xray_all_backup_routes_passed', 'ip_map_50_mile_city_context_passed',
        'split_tunneling_contract_passed',
        'double_vpn_passed', 'leak_test_passed'
    )
    $rawEvidencePaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $rawEvidenceRunIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $latestRawTestedAt = [DateTime]::MinValue
    foreach ($platform in @('android', 'windows', 'linux', 'ios', 'macos')) {
        $platformFailureCount = $failures.Count
        $reference = $evidence.platforms.$platform
        $platformInputs = $releaseInputs.Platforms[$platform]
        if (-not $reference) {
            Add-Failure "Public release evidence lacks $platform raw-evidence reference."
            continue
        }
        $rawEvidencePath = Resolve-ContainedRepoPath -RelativePath ([string]$reference.raw_evidence_path) -RequiredPrefix '.artifacts/release-evidence'
        if (-not $rawEvidencePath -or -not (Test-Path -LiteralPath $rawEvidencePath -PathType Leaf)) {
            Add-Failure "$platform raw evidence is missing or escapes .artifacts/release-evidence."
            continue
        }
        if (-not $rawEvidencePaths.Add($rawEvidencePath)) {
            Add-Failure "$platform reuses another platform's raw evidence file."
            continue
        }
        $rawEvidenceHash = Get-Sha256 $rawEvidencePath
        if (-not (Test-ArtifactEvidenceHash -Expected $rawEvidenceHash -Actual ([string]$reference.raw_evidence_sha256))) {
            Add-Failure "$platform raw evidence SHA-256 does not match its referenced file."
            continue
        }
        try { $result = Get-Content -LiteralPath $rawEvidencePath -Raw | ConvertFrom-Json } catch {
            Add-Failure "$platform raw evidence is not valid JSON."
            continue
        }
        if ([int]$result.schema_version -ne 3 -or [string]$result.platform -cne $platform -or
            [string]$result.app_version -ne $appVersion -or [string]$result.build_number -ne $buildNumber -or
            -not (Test-ArtifactEvidenceHash -Expected $releaseInputs.Sha256 -Actual ([string]$result.release_input_index_sha256)) -or
            -not (Test-ArtifactEvidenceHash -Expected $platformInputs.ManifestSha256 -Actual ([string]$result.platform_manifest_sha256)) -or
            [string]$result.shared_revision -cne $releaseInputs.SharedRevision -or
            -not (Test-ArtifactEvidenceHash -Expected $platformInputs.ArtifactInputFingerprintSha256 -Actual ([string]$result.artifact_input_fingerprint_sha256))) {
            Add-Failure "$platform raw evidence does not match its platform, release identity, and immutable platform release-input binding."
        }
        $runId = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$result.run_id, [ref]$runId) -or $runId -eq [Guid]::Empty) {
            Add-Failure "$platform raw evidence lacks a non-empty unique run ID."
        } elseif (-not $rawEvidenceRunIds.Add($runId.ToString('D'))) {
            Add-Failure "$platform reuses another platform's raw-evidence run ID."
        }
        if ($result.secret_material_redacted -isnot [bool] -or $result.secret_material_redacted -ne $true) {
            Add-Failure "$platform raw evidence is not explicitly sanitized."
        }
        if ([string]$result.producer.contract -cne 'winsvpn-public-release-live-smoke-v3') {
            Add-Failure "$platform raw evidence was not produced under the approved live-smoke contract."
        }
        $producerRelativePath = ([string]$result.producer.path).Replace('\', '/')
        if ($producerRelativePath -cne $approvedEvidenceProducers[$platform]) {
            Add-Failure "$platform raw evidence names an unapproved producer script."
        }
        $producerPath = Resolve-ContainedRepoPath -RelativePath ([string]$result.producer.path) -RequiredPrefix 'tools'
        if (-not $producerPath -or -not (Test-Path -LiteralPath $producerPath -PathType Leaf)) {
            Add-Failure "$platform raw evidence producer is missing or outside tools/."
        } elseif (-not (Test-ArtifactEvidenceHash -Expected (Get-ProducerContractHash ([string]$result.producer.path)) -Actual ([string]$result.producer.sha256))) {
            Add-Failure "$platform raw evidence is not bound to the current producer script."
        }
        $transcriptPath = Resolve-ContainedRepoPath -RelativePath ([string]$result.transcript.path) -RequiredPrefix '.artifacts/release-evidence'
        if (-not $transcriptPath -or -not (Test-Path -LiteralPath $transcriptPath -PathType Leaf) -or (Get-Item -LiteralPath $transcriptPath).Length -eq 0) {
            Add-Failure "$platform raw evidence transcript is missing, empty, or outside .artifacts/release-evidence."
        } elseif (-not (Test-ArtifactEvidenceHash -Expected (Get-Sha256 $transcriptPath) -Actual ([string]$result.transcript.sha256))) {
            Add-Failure "$platform raw evidence transcript SHA-256 does not match."
        } else {
            $bundleIndexSha256 = [string]$result.evidence_bundle_index_sha256
            if ($bundleIndexSha256 -cnotmatch '^[0-9a-f]{64}$' -or
                $bundleIndexSha256 -ceq ('0' * 64)) {
                Add-Failure "$platform raw evidence lacks a real immutable evidence-bundle index SHA-256."
            }
            try {
                $nativeTranscript = Get-Content -LiteralPath $transcriptPath -Raw | ConvertFrom-Json
                if ([string]$nativeTranscript.evidence_bundle_index_sha256 -cne $bundleIndexSha256) {
                    Add-Failure "$platform raw evidence does not match its sanitized transcript evidence-bundle index binding."
                }
            } catch {
                Add-Failure "$platform sanitized native transcript is not valid JSON."
            }
        }
        $mapScreenshotPath = Resolve-ContainedRepoPath -RelativePath ([string]$result.map_screenshot.path) -RequiredPrefix '.artifacts/release-evidence'
        if (-not $mapScreenshotPath -or -not (Test-Path -LiteralPath $mapScreenshotPath -PathType Leaf) -or
            [IO.Path]::GetExtension($mapScreenshotPath).ToLowerInvariant() -notin @('.png', '.jpg', '.jpeg') -or
            (Get-Item -LiteralPath $mapScreenshotPath).Length -lt 10000) {
            Add-Failure "$platform map screenshot is missing, undersized, or outside .artifacts/release-evidence."
        } elseif (-not (Test-ArtifactEvidenceHash -Expected (Get-Sha256 $mapScreenshotPath) -Actual ([string]$result.map_screenshot.sha256))) {
            Add-Failure "$platform map screenshot SHA-256 does not match."
        }
        $receiptState = $null
        try {
            $receiptState = Get-BuildReceiptState -Platform $platform -RelativePath ([string]$result.build_receipt.path) -ReleaseInputs $releaseInputs
        } catch {
            Add-Failure "$platform build receipt is invalid: $($_.Exception.Message)"
        }
        if ($receiptState) {
            if (-not (Test-ArtifactEvidenceHash -Expected $receiptState.Sha256 -Actual ([string]$result.build_receipt.sha256)) -or
                -not (Test-ArtifactEvidenceHash -Expected $receiptState.ArtifactSha256 -Actual ([string]$result.artifact_sha256)) -or
                [long]$result.artifact_size_bytes -ne $receiptState.ArtifactSizeBytes) {
                Add-Failure "$platform raw evidence is not bound to its immutable build receipt and exact artifact."
            }
        }
        if ($expectedArtifactHashes.ContainsKey($platform)) {
            $testedArtifactHash = [string]$result.artifact_sha256
            if (-not (Test-ArtifactEvidenceHash -Expected $expectedArtifactHashes[$platform] -Actual $testedArtifactHash)) {
                Add-Failure "$platform live-test evidence is not bound to the exact release artifact SHA-256."
            } elseif (-not $expectedArtifactSizes.ContainsKey($platform) -or
                [long]$result.artifact_size_bytes -ne [long]$expectedArtifactSizes[$platform]) {
                Add-Failure "$platform live-test evidence size does not match the exact release artifact."
            } else {
                Add-Pass "$platform live-test evidence matches the exact release artifact SHA-256"
            }
        }
        foreach ($field in $requiredResults) {
            if ($result.$field -isnot [bool] -or $result.$field -ne $true) { Add-Failure "$platform evidence does not prove $field." }
        }
        $hasWindowsMatrixResult = $null -ne $result.PSObject.Properties['windows_matrix_passed']
        if ($platform -eq 'windows') {
            if (-not $hasWindowsMatrixResult -or
                $result.windows_matrix_passed -isnot [bool] -or
                $result.windows_matrix_passed -ne $true) {
                Add-Failure 'windows raw evidence does not prove the mandatory cancellation, fallback, split, network-change, teardown, and rollback matrix.'
            }
        } elseif ($hasWindowsMatrixResult) {
            Add-Failure "$platform raw evidence contains a Windows-only matrix result."
        }
        $directAwgPort = 0
        try { $directAwgPort = [int]$result.route_matrix.direct_awg.port } catch { $directAwgPort = 0 }
        if ($result.route_matrix.direct_awg.passed -isnot [bool] -or
            $result.route_matrix.direct_awg.passed -ne $true -or $directAwgPort -ne 9110 -or
            [string]$result.route_matrix.direct_awg.protocol -cne 'udp') {
            Add-Failure "$platform route matrix does not prove direct AWG on UDP 9110."
        }
        $advertisedXrayCount = 0
        $testedXrayCount = 0
        try { $advertisedXrayCount = [int]$result.route_matrix.xray.advertised_route_count } catch { $advertisedXrayCount = 0 }
        try { $testedXrayCount = [int]$result.route_matrix.xray.tested_route_count } catch { $testedXrayCount = 0 }
        $xrayRoutes = @($result.route_matrix.xray.routes)
        if ($advertisedXrayCount -lt 1 -or $testedXrayCount -ne $advertisedXrayCount -or $xrayRoutes.Count -ne $advertisedXrayCount -or
            [string]$result.route_matrix.xray.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$') {
            Add-Failure "$platform route matrix does not bind every advertised Xray backup route to a sanitized manifest."
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
                Add-Failure "$platform Xray route evidence is invalid, duplicated, failed, or exposes an endpoint identity."
            }
        }
        if (-not (Test-ArtifactEvidenceHash -Expected (Get-XrayManifestHash $xrayRoutes) -Actual ([string]$result.route_matrix.xray.manifest_sha256))) {
            Add-Failure "$platform Xray manifest SHA-256 does not match its complete sanitized route set."
        }
        $testedAt = ConvertFrom-StrictUtcTimestamp $result.tested_at_utc
        $notBefore = $platformInputs.EvidenceNotBeforeUtc
        if ($receiptState -and $receiptState.FinishedUtc -gt $notBefore) { $notBefore = $receiptState.FinishedUtc }
        if (-not (Test-RawEvidenceTime -TestedAt $testedAt -NotBefore $notBefore -Now ([DateTime]::UtcNow))) {
            Add-Failure "$platform live-test timestamp predates its build receipt/platform inputs, exceeds 72 hours, is missing, or is in the future."
        }
        if ($testedAt -gt $latestRawTestedAt) { $latestRawTestedAt = $testedAt }
        if ($failures.Count -eq $platformFailureCount) {
            Add-Pass "$platform raw test evidence, producer, and transcript are SHA-256 bound"
        }
    }
    if (-not (Test-AggregateEvidenceTime -GeneratedAt $aggregateGeneratedAt -LatestRawAt $latestRawTestedAt -Now ([DateTime]::UtcNow))) {
        Add-Failure "Aggregate evidence timestamp is missing, older than 24 hours, in the future, or predates raw evidence."
    }
}

if ($VerifyLive) {
    foreach ($name in $downloadNames) {
        $url = "https://www.winsvpn.org/downloads/$name"
        $platform = @($publishedNames.Keys | Where-Object { $publishedNames[$_] -ceq $name })
        if ($platform.Count -ne 1) {
            Add-Failure "Live download has no local candidate to compare against: $url"
            continue
        }
        try {
            if (Test-LiveDownloadMatches -Url $url `
                    -ExpectedSha256 ([string]$expectedArtifactHashes[$platform[0]]) `
                    -ExpectedSize ([long]$expectedArtifactSizes[$platform[0]])) {
                Add-Pass "Live download is the exact candidate (size and SHA-256): $url"
            } else {
                Add-Failure "Live download bytes differ from the candidate artifact: $url"
            }
        } catch {
            Add-Failure "Live download check failed: $url"
        }
    }
}

foreach ($message in $passes) { Write-Host "PASS $message" -ForegroundColor Green }
foreach ($message in $failures) { Write-Host "BLOCK $message" -ForegroundColor Red }
if ($failures.Count -gt 0) {
    Write-Host "PUBLIC RELEASE GATE: BLOCKED ($($failures.Count) finding(s))" -ForegroundColor Red
    exit 1
}
Write-Host "PUBLIC RELEASE GATE: PASS" -ForegroundColor Green
