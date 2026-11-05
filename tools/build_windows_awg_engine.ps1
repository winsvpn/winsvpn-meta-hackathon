[CmdletBinding()]
param(
    [string]$Output,
    # Additive, and deliberately defaulted to the historical behaviour: every
    # invocation that predates this parameter -- including
    # installer\windows\build_installer.ps1, which is what produces a signed
    # shipping artifact -- keeps building exactly the amd64 engine it always
    # built, from the same pinned toolchain, into the same default path, with
    # the same execution guard. Passing 'arm64' is the only way to change any
    # of that.
    [ValidateSet('amd64', 'arm64')]
    [string]$TargetArchitecture = 'amd64',
    [switch]$SkipToolchainDownload,
    [switch]$DeferExecutionGuard,
    [switch]$FinalizeExecutionGuard,
    [switch]$RequireValidAuthenticode
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
# Flutter's Windows output directory is named for the architecture, and it
# spells amd64 'x64'. Keeping that mapping here means the default output path
# is byte-for-byte the historical one.
$flutterArchDirectory = @{ 'amd64' = 'x64'; 'arm64' = 'arm64' }[$TargetArchitecture]
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $repo `
        "build\windows\$flutterArchDirectory\runner\Release\winsvpn_awg_engine.exe"
}
$outputFull = [IO.Path]::GetFullPath($Output)
$sourceMain = Join-Path $repo 'windows\awg_engine\main.go'
$toolchainRoot = Join-Path $repo '.artifacts\toolchains'
$goVersion = '1.27.1'
$goArchive = "go$goVersion.windows-amd64.zip"
# Independently verified 2026-08-23 against both go.dev/dl/?mode=json&include=all
# (the "sha256" field of the go1.27.1 windows-amd64 "archive" entry) and the
# dedicated per-file checksum at https://dl.google.com/go/go1.27.1.windows-amd64.zip.sha256
# -- the two agree. Re-verify against both the same way before ever bumping
# this pin; never trust a hash you did not fetch and check yourself.
# Only the amd64 archive is pinned, and that stays correct for every value of
# -TargetArchitecture: this is the pin for the *toolchain*, not for the
# artifact. A windows-amd64 Go cross-compiles a windows/arm64 binary with
# nothing but GOARCH, the engine is CGO-free, and an ARM64 Windows host runs
# the amd64 toolchain under emulation. Pinning a second archive would mean a
# second hash to independently verify for no gain in what is produced.
$goArchiveSha256 =
    'a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d'
$goArchiveUrl = "https://go.dev/dl/$goArchive"
$engineVersion = 'v3.1.20260828'
$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
$engineRepository = 'https://github.com/amnezia-vpn/amneziawg-go.git'
$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'
# GitHub archive/${engineCommit}.tar.gz. This builder clones git and verifies
# Windows CRLF go.mod/go.sum bytes; the archive hash is the LF GitHub identity.
$engineSourceArchiveSha256 =
    '10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4'
$engineGoModSha256 =
    'e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4'
$engineGoSumSha256 =
    'fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719'
$legacyEntrypointModulePrefix = '"github.com/amnezia-vpn/amneziawg-go/'
$v3EntrypointModulePrefix = '"github.com/amnezia-vpn/amneziawg-go/v3/'
$sourceRoot = Join-Path $repo '.artifacts\vendor\amneziawg-go'
$commandRoot = Join-Path $sourceRoot 'cmd\winsvpn-awg-engine'
$manifestPath = "$outputFull.provenance.json"

if ($DeferExecutionGuard -and $FinalizeExecutionGuard) {
    throw '-DeferExecutionGuard and -FinalizeExecutionGuard are mutually exclusive.'
}
if ($RequireValidAuthenticode -and -not $FinalizeExecutionGuard) {
    throw '-RequireValidAuthenticode is valid only with -FinalizeExecutionGuard.'
}

# The execution guard proves the LocalSystem-only refusal by *running* the
# artifact and requiring exit code 2, so it can only ever run where the
# artifact's machine type is executable. Windows on ARM64 executes both arm64
# and (emulated) amd64 images -- that emulation is already load-bearing here,
# because the pinned Go toolchain this script insists on is itself
# windows-amd64. Windows on x64 executes only amd64. Use the OS architecture
# rather than PROCESSOR_ARCHITECTURE: an amd64-emulated PowerShell on an ARM64
# host reports AMD64 for the process and would hide the ARM64 capability.
$hostOsArchitecture =
    [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$targetIsExecutableHere =
    ($TargetArchitecture -ceq 'amd64') -or
    ($hostOsArchitecture -eq 'Arm64')
if ($FinalizeExecutionGuard -and -not $targetIsExecutableHere) {
    throw "The $TargetArchitecture AWG engine execution guard cannot run on a $hostOsArchitecture host. Finalize on a host that can execute the artifact."
}
if (-not $FinalizeExecutionGuard -and -not $DeferExecutionGuard -and
    -not $targetIsExecutableHere) {
    throw "Building the $TargetArchitecture AWG engine on a $hostOsArchitecture host requires -DeferExecutionGuard; the execution guard must be finalized where the artifact can execute."
}

function Test-Sha256 {
    param([Parameter(Mandatory)][string]$Path,
          [Parameter(Mandatory)][string]$Expected)
    (Test-Path -LiteralPath $Path -PathType Leaf) -and
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.Equals(
            $Expected, [StringComparison]::OrdinalIgnoreCase)
}

function Write-ProvenanceDocument {
    param([Parameter(Mandatory)]$Document)
    $temporaryPath = "$manifestPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText(
            $temporaryPath,
            (($Document | ConvertTo-Json -Depth 6) + [Environment]::NewLine),
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryPath -Destination $manifestPath -Force
    } finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-Utf8TextSha256 {
    param([Parameter(Mandatory)][string]$Text)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        ($sha256.ComputeHash($bytes) |
            ForEach-Object { $_.ToString('x2') }) -join ''
    } finally {
        $sha256.Dispose()
    }
}

function Get-PreparedEngineEntrypoint {
    $text = [IO.File]::ReadAllText($sourceMain)
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $v3Count = [regex]::Matches(
        $text,
        [regex]::Escape($v3EntrypointModulePrefix)
    ).Count
    # The legacy prefix is a prefix of the /v3 one ("...amneziawg-go/" versus
    # "...amneziawg-go/v3/"), so every /v3 import also matches it; count only
    # the imports that are not already on the /v3 module path.
    $legacyCount = [regex]::Matches(
        $text,
        [regex]::Escape($legacyEntrypointModulePrefix)
    ).Count - $v3Count
    if ($v3Count -eq 4 -and $legacyCount -eq 0) {
        # The reviewed entry point already imports the /v3 module path.
        return $text
    }
    if ($legacyCount -ne 4 -or $v3Count -ne 0) {
        throw "The reviewed AWG entry point does not have exactly four imports on one module path (legacy=$legacyCount, v3=$v3Count); a mixed or unexpected import set is refused."
    }
    $prepared = $text.Replace(
        $legacyEntrypointModulePrefix,
        $v3EntrypointModulePrefix
    )
    $preparedV3Count = [regex]::Matches(
        $prepared,
        [regex]::Escape($v3EntrypointModulePrefix)
    ).Count
    $preparedLegacyCount = [regex]::Matches(
        $prepared,
        [regex]::Escape($legacyEntrypointModulePrefix)
    ).Count - $preparedV3Count
    if ($preparedLegacyCount -ne 0 -or $preparedV3Count -ne 4) {
        throw 'The AWG /v3 entry-point import migration was incomplete.'
    }
    return $prepared
}

function Complete-ExecutionGuardProvenance {
    if (-not (Test-Path -LiteralPath $outputFull -PathType Leaf) -or
        -not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'The deferred AWG engine artifact and provisional provenance are required for finalization.'
    }
    if (-not (Test-Path -LiteralPath $sourceMain -PathType Leaf)) {
        throw 'The reviewed Win''s VPN AWG engine entry point is missing.'
    }
    $document = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $entrypointSha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $sourceMain).Hash.ToLowerInvariant()
    $buildEntrypointSha256 = Get-Utf8TextSha256 -Text (
        Get-PreparedEngineEntrypoint
    )
    # A provisional document written before -TargetArchitecture existed carries
    # no architecture, and could only ever have described an amd64 artifact:
    # that script asserted a windows/amd64 toolchain and passed no GOARCH.
    # Reading the absent field as amd64 therefore keeps every pre-existing
    # defer/finalize pair meaning exactly what it meant, while a mismatch --
    # finalizing an arm64 artifact as though it were amd64 -- still fails.
    $documentArchitecture = [string]$document.target_architecture
    if ([string]::IsNullOrWhiteSpace($documentArchitecture)) {
        $documentArchitecture = 'amd64'
    }
    if ($documentArchitecture -cne $TargetArchitecture) {
        throw "The provisional AWG engine provenance records target architecture '$documentArchitecture', but finalization was asked for '$TargetArchitecture'."
    }
    if ([int]$document.schema_version -ne 3 -or
        [string]$document.engine_module -cne $engineModule -or
        [string]$document.engine_version -cne $engineVersion -or
        [string]$document.engine_commit -cne $engineCommit -or
        [string]$document.engine_source_archive_sha256 -cne
            $engineSourceArchiveSha256 -or
        [string]$document.go_version -cne $goVersion -or
        [string]$document.go_archive_sha256 -cne $goArchiveSha256 -or
        [string]$document.go_mod_sha256 -cne $engineGoModSha256 -or
        [string]$document.go_sum_sha256 -cne $engineGoSumSha256 -or
        [string]$document.go_toolchain_policy -cne 'local' -or
        [string]$document.go_module_policy -cne 'readonly' -or
        [string]$document.go_checksum_database -cne 'sum.golang.org' -or
        [string]$document.entrypoint_sha256 -cne $entrypointSha256 -or
        [string]$document.build_entrypoint_sha256 -cne
            $buildEntrypointSha256 -or
        [string]$document.entrypoint_module_migration -cne
            'github.com/amnezia-vpn/amneziawg-go=>github.com/amnezia-vpn/amneziawg-go/v3' -or
        [string]$document.execution_guard_status -cne 'pending_authenticode' -or
        [string]$document.unsigned_artifact_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [int]$document.non_system_exit_code -ne 2) {
        throw 'The provisional AWG engine provenance contract is invalid.'
    }

    $signatureStatus = (Get-AuthenticodeSignature -LiteralPath $outputFull).Status.ToString()
    if ($RequireValidAuthenticode -and $signatureStatus -cne 'Valid') {
        throw "The AWG engine must have valid Authenticode before its execution guard runs. Status=$signatureStatus"
    }
    $artifactSha256Before = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $outputFull).Hash.ToLowerInvariant()
    # A no-argument launch must be rejected before any adapter or UAPI endpoint
    # can be created. In production this probe now runs only after signing.
    & $outputFull
    $guardExitCode = $LASTEXITCODE
    if ($guardExitCode -ne 2) {
        throw 'The AWG engine LocalSystem-only execution guard failed.'
    }
    $artifactSha256After = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $outputFull).Hash.ToLowerInvariant()
    if ($artifactSha256After -cne $artifactSha256Before) {
        throw 'The AWG engine changed while its execution guard was being verified.'
    }

    $document.artifact_sha256 = $artifactSha256After
    $document.execution_guard_status = 'verified_after_authenticode_phase'
    $document.execution_guard_verified_at_utc = [DateTime]::UtcNow.ToString('o')
    $document.authenticode_required = [bool]$RequireValidAuthenticode
    $document.authenticode_status = $signatureStatus
    Write-ProvenanceDocument -Document $document
    Write-Host "WINDOWS AWG ENGINE EXECUTION GUARD: PASS ($artifactSha256After)" `
        -ForegroundColor Green
}

if ($FinalizeExecutionGuard) {
    Complete-ExecutionGuardProvenance
    $global:LASTEXITCODE = 0
    return
}

# H-5-class remediation (Windows counterpart to prepare_reviewed_go() in
# tools/build_apple_wg_go_bridge.sh, tools/build_xray_engine.sh, and
# tools/build_amneziawg_android_engine.sh): this script must never trust an
# ambient `go` -- a stale toolchain silently reintroduces fixed
# standard-library CVEs, and a malicious go.exe earlier on a build agent's
# PATH, or one planted into a previously-extracted toolchain directory,
# could inject code into every AWG engine binary this produces. Every call
# resolves ONLY a SHA-256-verified pinned archive (downloading it if a
# verified copy is not already cached) and then always re-extracts go.exe
# fresh from that verified archive -- a stale or tampered extracted copy is
# never trusted merely because it already exists on disk with a matching
# self-reported `go version` string. No environment-variable override and
# no ambient PATH lookup of any kind are trusted here, at all, ever.
function Resolve-GoExecutable {
    $exactVersionPattern =
        "^go version go$([regex]::Escape($goVersion)) windows/amd64$"
    [void][IO.Directory]::CreateDirectory($toolchainRoot)
    $archive = Join-Path $toolchainRoot $goArchive
    if (-not (Test-Sha256 -Path $archive -Expected $goArchiveSha256)) {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        if ($SkipToolchainDownload) {
            throw "The pinned Go $goVersion toolchain archive is not already present and SHA-256-verified, and downloading is disabled."
        }
        Invoke-WebRequest -UseBasicParsing -Uri $goArchiveUrl -OutFile $archive
    }
    if (-not (Test-Sha256 -Path $archive -Expected $goArchiveSha256)) {
        Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue
        throw 'The pinned Go toolchain archive failed SHA-256 verification.'
    }
    $portableRoot = Join-Path $toolchainRoot 'go'
    if (Test-Path -LiteralPath $portableRoot) {
        Remove-Item -LiteralPath $portableRoot -Recurse -Force
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $toolchainRoot -Force
    $portable = Join-Path $toolchainRoot 'go\bin\go.exe'
    if (-not (Test-Path -LiteralPath $portable -PathType Leaf)) {
        throw 'The pinned Go toolchain archive did not produce go.exe.'
    }
    $portableVersion = (& $portable version 2>$null).Trim()
    if ($portableVersion -notmatch $exactVersionPattern) {
        throw "The verified Go archive did not produce the pinned $goVersion toolchain. Found: $portableVersion"
    }
    return $portable
}

if (-not (Test-Path -LiteralPath $sourceMain -PathType Leaf)) {
    throw 'The reviewed Win''s VPN AWG engine entry point is missing.'
}
$git = (Get-Command git.exe -ErrorAction Stop).Source
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot '.git'))) {
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $sourceRoot))
    & $git clone --filter=blob:none --no-checkout $engineRepository $sourceRoot
    if ($LASTEXITCODE -ne 0) { throw 'Unable to clone the pinned AWG engine source.' }
}
& $git -C $sourceRoot cat-file -e "${engineCommit}^{commit}" 2>$null
$hasPinnedCommit = $LASTEXITCODE -eq 0
if (-not $hasPinnedCommit) {
    & $git -C $sourceRoot fetch --depth 1 origin $engineCommit
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to fetch the pinned AWG engine commit.'
    }
}
& $git -C $sourceRoot checkout --detach --force $engineCommit
if ($LASTEXITCODE -ne 0 -or
    ((& $git -C $sourceRoot rev-parse HEAD).Trim() -cne $engineCommit)) {
    throw 'The AWG engine source checkout does not match the reviewed commit.'
}
$tagCommit = (& $git -C $sourceRoot rev-list -n 1 $engineVersion 2>$null).Trim()
if ($tagCommit -cne $engineCommit) {
    & $git -C $sourceRoot fetch --depth 1 origin `
        "refs/tags/${engineVersion}:refs/tags/${engineVersion}"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to fetch the pinned AWG engine tag $engineVersion."
    }
    $tagCommit = (& $git -C $sourceRoot rev-list -n 1 $engineVersion).Trim()
}
if ($tagCommit -cne $engineCommit) {
    throw "AmneziaWG engine tag $engineVersion is not bound to the reviewed commit."
}
if ($engineVersion -ceq '3.1.0') {
    throw 'The Go engine tag must not be confused with the Windows client 3.1.0 release.'
}
# This is a Windows-only builder. Materialize the reviewed tree with one
# deterministic line-ending policy before applying byte-level module pins.
& $git -C $sourceRoot -c core.autocrlf=true checkout-index --force --all
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to materialize the pinned AWG source with deterministic Windows line endings.'
}
$engineGoMod = Join-Path $sourceRoot 'go.mod'
$engineGoSum = Join-Path $sourceRoot 'go.sum'
if (-not (Test-Sha256 -Path $engineGoMod -Expected $engineGoModSha256) -or
    -not (Test-Sha256 -Path $engineGoSum -Expected $engineGoSumSha256)) {
    throw 'The pinned AWG engine module graph does not match the reviewed go.mod/go.sum checksums.'
}

if (Test-Path -LiteralPath $commandRoot) {
    Remove-Item -LiteralPath $commandRoot -Recurse -Force
}
[void][IO.Directory]::CreateDirectory($commandRoot)
$preparedEntrypoint = Get-PreparedEngineEntrypoint
$preparedEntrypointSha256 = Get-Utf8TextSha256 -Text $preparedEntrypoint
$commandMain = Join-Path $commandRoot 'main.go'
[IO.File]::WriteAllText(
    $commandMain,
    $preparedEntrypoint,
    [Text.UTF8Encoding]::new($false)
)

$go = Resolve-GoExecutable
$reportedVersion = (& $go version).Trim()
if ($reportedVersion -notmatch "^go version go$([regex]::Escape($goVersion)) windows/amd64$") {
    throw "The AWG engine requires the exact pinned Go $goVersion windows/amd64 toolchain. Found: $reportedVersion"
}
$goEnvironment = [ordered]@{
    GOTOOLCHAIN = 'local'
    GOFLAGS = '-mod=readonly'
    GOSUMDB = 'sum.golang.org'
    GOPROXY = 'https://proxy.golang.org,direct'
    GONOSUMDB = ''
    GOPRIVATE = ''
    GONOPROXY = ''
    # Stated rather than inherited. For the default amd64 target these are
    # exactly what the pinned windows-amd64 toolchain already used implicitly,
    # so the shipping artifact is unchanged; stating them also means an
    # ambient GOOS/GOARCH in a build agent's environment can no longer silently
    # decide what this produces. CGO stays off: the engine needs no cgo, and a
    # cross build must not start looking for a C toolchain.
    GOOS = 'windows'
    GOARCH = $TargetArchitecture
    GOAMD64 = 'v1'
    GOARM64 = 'v8.0'
    CGO_ENABLED = '0'
}
$previousGoEnvironment = @{}
foreach ($entry in $goEnvironment.GetEnumerator()) {
    $existing = Get-Item -LiteralPath "Env:$($entry.Key)" -ErrorAction SilentlyContinue
    $previousGoEnvironment[$entry.Key] = if ($null -eq $existing) { $null } else { [string]$existing.Value }
    Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
}
Push-Location $sourceRoot
try {
    if ((& $go env GOTOOLCHAIN).Trim() -ne 'local' -or
        (& $go env GOFLAGS).Trim() -ne '-mod=readonly' -or
        (& $go env GOSUMDB).Trim() -ne 'sum.golang.org' -or
        (& $go env GOPROXY).Trim() -ne 'https://proxy.golang.org,direct') {
        throw 'The pinned Go toolchain did not honor the required local/read-only/checksum policy.'
    }
    # Read back the target the toolchain actually resolved, so a build that
    # silently produced the wrong machine type fails here rather than at
    # `awg setconf` time on the target host.
    if ((& $go env GOOS).Trim() -cne 'windows' -or
        (& $go env GOARCH).Trim() -cne $TargetArchitecture -or
        (& $go env CGO_ENABLED).Trim() -ne '0') {
        throw "The pinned Go toolchain did not honor the requested windows/$TargetArchitecture CGO-free target."
    }
    & $go fmt '.\cmd\winsvpn-awg-engine'
    if ($LASTEXITCODE -ne 0) { throw 'AWG engine formatting validation failed.' }
    if (-not (Test-Sha256 -Path $commandMain `
            -Expected $preparedEntrypointSha256)) {
        throw 'The AWG /v3 build entry point changed during formatting validation.'
    }
    & $go test -buildvcs=false '.\cmd\winsvpn-awg-engine'
    if ($LASTEXITCODE -ne 0) { throw 'AWG engine compilation test failed.' }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $outputFull))
    & $go build -trimpath -buildvcs=false '-ldflags=-s -w -buildid=' `
        -o $outputFull '.\cmd\winsvpn-awg-engine'
    if ($LASTEXITCODE -ne 0 -or
        -not (Test-Path -LiteralPath $outputFull -PathType Leaf)) {
        throw 'The pinned Win''s VPN AWG engine build failed.'
    }
    $peBytes = [IO.File]::ReadAllBytes($outputFull)
    if ($peBytes.Length -lt 512 -or $peBytes[0] -ne 0x4d -or $peBytes[1] -ne 0x5a) {
        throw 'The pinned Win''s VPN AWG engine is not a valid DOS/PE executable.'
    }
    $peOffset = [BitConverter]::ToInt32($peBytes, 0x3c)
    $peMachine = [BitConverter]::ToUInt16($peBytes, $peOffset + 4)
    $expectedPe = @{ 'amd64' = [uint16]0x8664; 'arm64' = [uint16]0xAA64 }[$TargetArchitecture]
    if ($peMachine -ne $expectedPe) {
        throw ('The pinned Win''s VPN AWG engine has COFF machine 0x{0:X4}; windows/{1} requires 0x{2:X4}.' -f $peMachine, $TargetArchitecture, $expectedPe)
    }
} finally {
    Pop-Location
    foreach ($entry in $previousGoEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            Remove-Item -LiteralPath "Env:$($entry.Key)" -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
        }
    }
}

$manifest = [ordered]@{
    schema_version = 3
    generated_at_utc = [DateTime]::UtcNow.ToString('o')
    engine_module = $engineModule
    engine_version = $engineVersion
    engine_commit = $engineCommit
    engine_source_archive_sha256 = $engineSourceArchiveSha256
    go_version = $goVersion
    target_architecture = $TargetArchitecture
    go_archive_sha256 = $goArchiveSha256
    go_mod_sha256 = $engineGoModSha256
    go_sum_sha256 = $engineGoSumSha256
    go_toolchain_policy = 'local'
    go_module_policy = 'readonly'
    go_checksum_database = 'sum.golang.org'
    entrypoint_sha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $sourceMain).Hash.ToLowerInvariant()
    build_entrypoint_sha256 = $preparedEntrypointSha256
    entrypoint_module_migration = 'github.com/amnezia-vpn/amneziawg-go=>github.com/amnezia-vpn/amneziawg-go/v3'
    unsigned_artifact_sha256 = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $outputFull).Hash.ToLowerInvariant()
    artifact_sha256 = $null
    non_system_exit_code = 2
    execution_guard_status = 'pending_authenticode'
    execution_guard_verified_at_utc = $null
    authenticode_required = $null
    authenticode_status = $null
}
Write-ProvenanceDocument -Document $manifest
Write-Host "WINDOWS AWG ENGINE BUILD: PASS ($($manifest.unsigned_artifact_sha256))" `
    -ForegroundColor Green
if ($DeferExecutionGuard) {
    Write-Host 'AWG engine execution guard deferred until the Authenticode phase.'
    $global:LASTEXITCODE = 0
    return
}

# Standalone development builds preserve the historical fail-closed guard,
# while the installer producer always selects the deferred signing-safe path.
Complete-ExecutionGuardProvenance
# The installer producer invokes this script with the call operator. `exit 0`
# would terminate that parent PowerShell runspace immediately after the AWG
# build, before Inno packaging and receipt sealing. Normalize the intentional
# guard exit code and return only from this script.
$global:LASTEXITCODE = 0
return
