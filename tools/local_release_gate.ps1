param(
    [switch]$BuildArtifacts,
    [switch]$Phone,
    [switch]$SkipFlutter,
    [switch]$SkipWebsite,
    [switch]$SkipSmartBoost,
    [switch]$RequirePublishReady,
    [string]$ReleaseInputIndex = $env:WINS_RELEASE_INPUT_INDEX
)

$ErrorActionPreference = "Stop"
$RunningOnWindows = ($PSVersionTable.PSEdition -eq "Desktop") -or $IsWindows
if (-not $RunningOnWindows) {
    throw "tools/local_release_gate.ps1 is the Windows release coordinator and cannot run on macOS or Linux. Use the platform-specific validators; for Apple candidates, use tools/build_apple_release_candidates.sh with WINS_RELEASE_INPUT_INDEX. Skipping the Windows gates is not publish-ready evidence."
}
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$env:CI = "true"
$env:FLUTTER_SUPPRESS_ANALYTICS = "true"
$env:DART_SUPPRESS_ANALYTICS = "true"
$RuntimeRoot = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies"
$RuntimeNode = Join-Path $RuntimeRoot "node\bin\node.exe"
$RuntimePython = Join-Path $RuntimeRoot "python\python.exe"
$Python = if (Test-Path -LiteralPath $RuntimePython) {
    $RuntimePython
} else {
    (Get-Command python -ErrorAction Stop).Source
}
$VersionLine = Select-String -LiteralPath (Join-Path $RepoRoot "pubspec.yaml") -Pattern '^version:\s*([^+\s]+)\+(\d+)\s*$' | Select-Object -First 1
if (-not $VersionLine) { throw "pubspec.yaml must contain version: <semver>+<build>." }
$DeploymentPreseed = Join-Path $RepoRoot "tools\wins_deployment_preseed.ps1"
$DeploymentPreseedStore = Join-Path $env:LOCALAPPDATA "WinsVPN\Deployment\preseed.dpapi"
$BuildLockDir = Join-Path $RepoRoot ".dart_tool\winsvpn-release-build.lock"
$BuildLockOwnerFile = Join-Path $BuildLockDir "owner.txt"
$script:LocalReleaseBuildLockAcquired = $false

function Enter-LocalReleaseBuildLock {
    param([Parameter(Mandatory = $true)][string]$Purpose)
    if ($script:LocalReleaseBuildLockAcquired) {
        throw 'The local release coordinator cannot acquire its release lock recursively.'
    }
    [void][IO.Directory]::CreateDirectory((Split-Path -Parent $BuildLockDir))
    $directoryCreated = $false
    $temporaryOwnerFile = Join-Path $BuildLockDir `
        ("owner.$PID." + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        New-Item -ItemType Directory -Path $BuildLockDir -ErrorAction Stop |
            Out-Null
        $directoryCreated = $true
        $ownerText = @(
            'platform=windows-local-release-gate'
            "purpose=$Purpose"
            "pid=$PID"
            "started_utc=$([DateTime]::UtcNow.ToString('o'))"
        ) -join "`n"
        [IO.File]::WriteAllText(
            $temporaryOwnerFile,
            $ownerText + "`n",
            [Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporaryOwnerFile `
            -Destination $BuildLockOwnerFile -ErrorAction Stop
        $script:LocalReleaseBuildLockAcquired = $true
    } catch {
        $initializationError = $_.Exception.Message
        if ($directoryCreated) {
            Remove-Item -LiteralPath $BuildLockDir -Recurse -Force `
                -ErrorAction SilentlyContinue
            throw "Unable to initialize the local release build lock transactionally: $initializationError"
        }
        $owner = 'owner metadata is not available'
        if (Test-Path -LiteralPath $BuildLockOwnerFile -PathType Leaf) {
            $owner = ((Get-Content -LiteralPath $BuildLockOwnerFile -Raw `
                -ErrorAction SilentlyContinue) + '').Trim()
        }
        throw "Another platform release build owns $BuildLockDir. $owner. Wait for it to finish; never delete an active lock."
    }
}

function Exit-LocalReleaseBuildLock {
    if (-not $script:LocalReleaseBuildLockAcquired) { return }
    $releasedLockDir = "$BuildLockDir.released.$PID.$([guid]::NewGuid().ToString('N'))"
    # Rename the complete lock directory first. This makes release atomic and
    # never leaves an ownerless directory at the canonical lock path.
    Move-Item -LiteralPath $BuildLockDir -Destination $releasedLockDir `
        -ErrorAction Stop
    $script:LocalReleaseBuildLockAcquired = $false
    Remove-Item -LiteralPath $releasedLockDir -Recurse -Force `
        -ErrorAction SilentlyContinue
}

function Invoke-WithReleaseBuildLock {
    param(
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Enter-LocalReleaseBuildLock -Purpose $Purpose
    try {
        & $Action
    } finally {
        Exit-LocalReleaseBuildLock
    }
}

function Invoke-Gate {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    Write-Host ""
    Write-Host "== $Name ==" -ForegroundColor Cyan
    $start = Get-Date
    & $Action
    $elapsed = (Get-Date) - $start
    Write-Host "[PASS] $Name ($([Math]::Round($elapsed.TotalSeconds, 1))s)" -ForegroundColor Green
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE"
    }
}

Set-Location $RepoRoot

if ($RequirePublishReady -and $BuildArtifacts) {
    throw 'RequirePublishReady cannot be combined with BuildArtifacts. Build in a separate run, then run final publish readiness last.'
}
if ($BuildArtifacts -and [string]::IsNullOrWhiteSpace($ReleaseInputIndex)) {
    throw 'BuildArtifacts requires -ReleaseInputIndex or WINS_RELEASE_INPUT_INDEX so inputs can be re-verified after the build.'
}

Invoke-Gate "Tool availability" {
    foreach ($cmd in @("flutter", "dart", "python", "shellcheck", "Get-FileHash", "Get-AuthenticodeSignature")) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            throw "$cmd is not available on PATH"
        }
    }
    if (-not (Test-Path -LiteralPath $RuntimeNode) -and -not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw "Node is not available on PATH and bundled Node was not found"
    }
}

Invoke-Gate "PowerShell release tooling parse" {
    # Parse every Git-known authoritative PowerShell entry point, including
    # untracked reviewed worktree source. A hand-maintained subset allowed
    # remote builders, signing helpers, and archive producers to reach a much
    # later release phase before a syntax error was discovered.
    $authoritativeRoots = @(
        '.github', 'android', 'apple', 'installer', 'ios', 'linux', 'macos',
        'server', 'tools', 'windows'
    )
    $scripts = @(& git ls-files --cached --others --exclude-standard -- '*.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate PowerShell release tooling from Git.'
    }
    $scripts = @($scripts | ForEach-Object {
        ([string]$_).Replace('\', '/')
    } | Where-Object {
        $top = ($_ -split '/', 2)[0]
        ($_ -notmatch '/') -or ($authoritativeRoots -contains $top)
    } | Sort-Object -Unique)
    if ($scripts.Count -lt 20) {
        throw "PowerShell release-tool inventory is unexpectedly small: $($scripts.Count)"
    }
    foreach ($script in $scripts) {
        if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
            throw "Git-known PowerShell release tool is missing: $script"
        }
        $tokens = $null
        $parseErrors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile(
            (Resolve-Path -LiteralPath $script),
            [ref]$tokens,
            [ref]$parseErrors
        )
        if ($parseErrors.Count -gt 0) {
            throw "$script failed PowerShell parsing: $($parseErrors.Message -join '; ')"
        }
    }
    Write-Host "Parsed $($scripts.Count) authoritative PowerShell release tools."
}

if (Test-Path -LiteralPath $DeploymentPreseedStore -PathType Leaf) {
    Invoke-Gate "Current source contains no active deployment credential" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $DeploymentPreseed -Action AuditWorktree
        if ($LASTEXITCODE -ne 0) {
            throw "Current source active-credential audit failed with code $LASTEXITCODE"
        }
    }
}
elseif ($RequirePublishReady) {
    throw "Publish-ready validation requires the current-user DPAPI deployment preseed: $DeploymentPreseedStore"
}

if ($RequirePublishReady) {
    Invoke-Gate "Active deployment credentials absent from all Git objects" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $DeploymentPreseed -Action AuditGitHistory
        if ($LASTEXITCODE -ne 0) {
            throw "Git history active-credential audit failed with code $LASTEXITCODE"
        }
    }
}

if (-not $SkipFlutter) {
    Invoke-WithReleaseBuildLock -Purpose 'flutter-validation' -Action {
        Invoke-Gate "Flutter dependency refresh" {
            Invoke-Native "flutter" "pub" "get"
        }
        Invoke-Gate "Dart formatting check" {
            Invoke-Native "dart" "format" "--output=none" "--set-exit-if-changed" "lib" "test"
        }
        Invoke-Gate "Flutter analyze" {
            Invoke-Native "flutter" "analyze" "lib" "test"
        }
        Invoke-Gate "Flutter tests" {
            Invoke-Native "flutter" "test"
        }
    }
}

Invoke-Gate "Deployment script shellcheck" {
    Invoke-Native "shellcheck" "server/wins_control_plane_setup_ONETOUCH.sh" "server/wins_data_plane_setup_ONETOUCH.sh" "server/wins_core_server_setup_ONETOUCH.sh" "server/wins_honeynet_setup_ONETOUCH.sh" "tools/recover_home_core_ssh.sh" "tools/recover_ionos_hub_ssh.sh" "tools/linux_public_release_live_smoke.sh" "tools/apple_public_release_live_smoke.sh" "backup_to_gdrive.sh" "decoder.sh" "optimize_vps.sh" "weekly_maintenance.sh"
}

Invoke-Gate "Deployment structure and generated artifacts" {
    Invoke-Native $Python "tools/validate_deployment_scripts.py"
    Invoke-Native $Python "tools/test_control_core_peer_resync.py"
    Invoke-Native $Python "tools/test_data_plane_dns_readonly_diagnostic.py"
}

Invoke-Gate "Project file-purpose inventory coverage" {
    Invoke-Native $Python "tools/validate_project_file_inventory.py" "--self-test"
    Invoke-Native $Python "tools/validate_project_file_inventory.py"
}

Invoke-Gate "Native tunnel readiness fail-closed contract" {
    Invoke-Native $Python "tools/validate_desktop_tunnel_readiness.py"
    Invoke-Native $Python "tools/test_linux_kill_switch.py"
    Invoke-Native $Python "tools/test_windows_wfp_repair_policy.py"
}

Invoke-Gate "PayPal entitlement fail-closed contract" {
    Invoke-Native $Python "tools/test_paypal_entitlement_contract.py"
}

Invoke-Gate "Deployment supply-chain pins" {
    Invoke-Native $Python "tools/verify_deployment_supply_chain.py"
}

Invoke-Gate "Embedded engine (Xray/AmneziaWG) Go runtime freshness" {
    Invoke-Native $Python "tools/verify_embedded_engine_runtime_versions.py"
}

Invoke-Gate "Release client privacy regression" {
    Invoke-Native $Python "tools/validate_release_artifact_privacy.py" "--self-test" "--static"
}

Invoke-Gate "Five-platform release obfuscation contract" {
    Invoke-Native $Python "tools/release_obfuscation_contract.py" "self-test"
    Invoke-Native $Python "tools/release_obfuscation_contract.py" "static"
}

Invoke-Gate "Windows Store MSIX contract" {
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "installer/windows/build_store_msix.ps1" "-SelfTest"
    $storeBuilder = Get-Content -LiteralPath "installer/windows/build_store_msix.ps1" -Raw
    $storeNotes = Get-Content -LiteralPath "installer/windows/store/certification-notes.md" -Raw
    foreach ($required in @(
        'Windows service and offline-installer architecture',
        'Microsoft Store Win32-installer path',
        "throw `$ProductionMsixBlockedReason"
    )) {
        if (-not $storeBuilder.Contains($required)) {
            throw "Store builder no longer fails closed for the production Win32-installer path: $required"
        }
    }
    foreach ($required in @(
        'signed, standalone/offline Inno Setup EXE',
        'immutable, versioned HTTPS',
        '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART',
        '/RESTARTEXITCODE=3010 /SP-'
    )) {
        if (-not $storeNotes.Contains($required)) {
            throw "Store Win32 certification contract is incomplete: $required"
        }
    }
}

Invoke-Gate "Linux Sigstore signing command contract" {
    $wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
    Invoke-Native $wsl "--user" "root" "--cd" $RepoRoot.Path "bash" "tools/build_linux_release.sh" "--self-test-signing"
}

Invoke-Gate "Exact-artifact evidence binding self-test" {
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/public_release_gate.ps1" "-SelfTest"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/assemble_public_release_evidence.ps1" "-SelfTest"
}

Invoke-Gate "Dependency-scoped artifact boundary" {
    Invoke-Native $Python "tools/test_release_dependency_freeze.py"
    Invoke-Native $Python "tools/test_windows_release_matrix_evidence.py"
    Invoke-Native $Python "tools/test_windows_semantic_watchdog.py"
    Invoke-Native $Python "tools/test_strip_image_metadata.py"
    Invoke-Native $Python "tools/strip_image_metadata.py" "--check" "assets"
    if (-not $SkipWebsite) {
        Invoke-Native $Python "tools/strip_image_metadata.py" "--check" "web"
    }
    if ($RequirePublishReady) {
        if ([string]::IsNullOrWhiteSpace($ReleaseInputIndex)) {
            throw "Publish-ready validation requires -ReleaseInputIndex or WINS_RELEASE_INPUT_INDEX. Create the immutable dependency-scoped index only after Windows/shared stabilization."
        }
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
}

Invoke-Gate "Legacy website-stage boundary self-test" {
    Invoke-Native $Python "tools/test_release_source_freeze.py"
}

Invoke-Gate "Public release raw-evidence schema" {
    $schemaPath = Resolve-Path -LiteralPath "tools/public_release_live_smoke.schema.json"
    $schema = Get-Content -LiteralPath $schemaPath -Raw | ConvertFrom-Json
    if ([string]$schema.'$schema' -ne 'https://json-schema.org/draft/2020-12/schema') {
        throw "Raw-evidence schema must use JSON Schema draft 2020-12."
    }
    if ([int]$schema.properties.route_matrix.properties.direct_awg.properties.port.const -ne 9110) {
        throw "Raw-evidence schema must bind direct AWG to UDP 9110."
    }
    $producerPaths = @($schema.properties.producer.properties.path.enum)
    if ($producerPaths.Count -ne 4 -or @($producerPaths | Where-Object { $_ -notmatch '^tools/.+public_release_live_smoke\.(ps1|sh)$' }).Count -gt 0) {
        throw "Raw-evidence schema must allow only dedicated public-release live-smoke producers."
    }
    $nativeSchema = Get-Content -LiteralPath "tools/public_release_native_smoke.schema.json" -Raw | ConvertFrom-Json
    if ([int]$schema.properties.schema_version.const -ne 3 -or
        [string]$schema.properties.producer.properties.contract.const -ne 'winsvpn-public-release-live-smoke-v3' -or
        @($schema.required | Where-Object { $_ -in @(
            'release_input_index_sha256',
            'platform_manifest_sha256',
            'shared_revision',
            'artifact_input_fingerprint_sha256',
            'artifact_size_bytes',
            'build_receipt'
        ) }).Count -ne 6 -or
        [bool]$schema.properties.ip_map_50_mile_city_context_passed.const -ne $true -or
        [string]$nativeSchema.properties.contract.const -ne 'winsvpn-native-live-smoke-v2' -or
        [int]$nativeSchema.properties.schema_version.const -ne 2 -or
        [int]$nativeSchema.properties.map_visual.properties.radius_miles.const -ne 50 -or
        [bool]$nativeSchema.properties.map_visual.properties.city_labels_visible.const -ne $true -or
        [int]$nativeSchema.properties.direct_awg.properties.port.const -ne 9110 -or
        @($nativeSchema.properties.windows_matrix.required).Count -ne 8 -or
        [bool]$nativeSchema.properties.windows_matrix.properties.rapid_connect_cancel_no_late_restart.const -ne $true -or
        [bool]$schema.properties.windows_matrix_passed.const -ne $true -or
        $nativeSchema.additionalProperties -ne $false) {
        throw "Platform-native live-smoke schema must stay strict and bind direct AWG plus the Windows mandatory matrix."
    }
}

Invoke-Gate "Public release live-smoke producer self-tests" {
    Invoke-Native "python" "tools/android_route_guard_release_bootstrap.py" "self-test"
    Invoke-Native "python" "tools/test_android_route_guard_release_bootstrap.py" "-v"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/android_public_release_live_smoke.ps1" "-SelfTest"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/windows_public_release_live_smoke.ps1" "-SelfTest"
    $wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
    Invoke-Native $wsl "--user" "root" "--cd" $RepoRoot.Path "bash" "tools/linux_public_release_live_smoke.sh" "--self-test"
    Invoke-Native $wsl "--user" "root" "--cd" $RepoRoot.Path "bash" "tools/apple_public_release_live_smoke.sh" "--self-test"
}

Invoke-Gate "Apple pre-release source-smoke safety self-test" {
    $wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
    Invoke-Native $wsl "--user" "root" "--cd" $RepoRoot.Path "env" "WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST=1" "bash" "tools/apple_runtime_smoke.sh"
}

Invoke-Gate "Windows Authenticode certificate policy self-test" {
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "installer/windows/build_installer.ps1" "-SelfTestSigningPolicy"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/windows_inno_sign.ps1" "-SelfTest"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/windows_artifact_signing_prepare.ps1" "-SelfTest"
    $innoScript = Get-Content -LiteralPath "installer/windows/winsvpn.iss" -Raw
    $builder = Get-Content -LiteralPath "installer/windows/build_installer.ps1" -Raw
    foreach ($required in @('SignTool=winsvpn','SignedUninstaller=yes','SignedUninstallerDir={#DependenciesDir}\signed-uninstaller-cache')) {
        if (-not $innoScript.Contains($required)) { throw "Signed Inno uninstaller contract missing: $required" }
    }
    foreach ($required in @(
        'Flags: dontcopy noencryption',
        'ExtractTemporaryFile(''VC_redist.x64.exe'')',
        'VcRuntimeInstalledAtLeastRequired',
        'SuppressibleMsgBox('
    )) {
        if (-not $innoScript.Contains($required)) { throw "Windows prerequisite fail-closed contract missing: $required" }
    }
    foreach ($required in @(
        'Invoke-ProductSigning -Path $stagedAmneziaWg',
        'Invoke-ProductSigning -Path $stagedXray',
        '/Swinsvpn=',
        'Assert-AmneziaWgPayloadSignatures',
        'Assert-RebuiltAmneziaWgHelper',
        'A self-signed certificate is forbidden'
    )) {
        if (-not $builder.Contains($required)) { throw "Complete Windows PE signing contract missing: $required" }
    }
    foreach ($required in @('/DVcRuntimeMajor=', '/DVcRuntimeMinor=', '/DVcRuntimeBuild=', '/DVcRuntimeRevision=')) {
        if (-not $builder.Contains($required)) { throw "Windows VC++ prerequisite version binding missing: $required" }
    }
    foreach ($required in @(
        '/DAmneziaWgExeSha256=',
        '/DUpstreamAmneziaWgExeSha256=',
        '/DAwgToolExeSha256=',
        '/DWintunDllSha256='
    )) {
        if (-not $builder.Contains($required)) { throw "Windows AmneziaWG runtime hash binding missing: $required" }
    }
    foreach ($required in @(
        'FatalPostInstallExitCode = 1603;',
        'FatalPostInstallFailure := True;',
        'RaiseFatalPostInstallException',
        'function GetCustomSetupExitCode: Integer;',
        'Result := FatalPostInstallExitCode'
    )) {
        if (-not $innoScript.Contains($required)) {
            throw "Windows deterministic post-install failure exit contract missing: $required"
        }
    }
    if ($innoScript -match '(?m)^\s*MsgBox\(') {
        throw 'Windows silent setup still contains a blocking raw modal dialog.'
    }
    $tunnelBackend = Get-Content -LiteralPath 'windows/runner/windows_tunnel_backend.cpp' -Raw
    $tunnelServiceMain = Get-Content -LiteralPath 'windows/runner/windows_tunnel_service_main.cpp' -Raw
    if (-not $tunnelBackend.Contains('initial_status.query_ok && !initial_status.exists')) {
        throw 'Windows protected-service uninstall must skip the slow vendor cleanup command when no managed tunnel exists.'
    }
    if (($tunnelServiceMain | Select-String -Pattern 'WaitForServiceState\(service, SERVICE_STOPPED, 180000\)' -AllMatches).Matches.Count -lt 2 -or
        ($tunnelServiceMain | Select-String -Pattern 'SERVICE_STOP_PENDING, NO_ERROR, 180000' -AllMatches).Matches.Count -lt 2) {
        throw 'Windows protected-service stop/uninstall contract must allow bounded active-tunnel cleanup without a false timeout.'
    }
    if ($builder.Contains('-AllowPrivateTestRoot')) {
        throw 'Production Windows builder must never bypass the Microsoft AuthRoot requirement.'
    }
}

Invoke-Gate "Cross-platform release build lock" {
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "installer/windows/build_installer.ps1" "-SelfTestBuildLock"
    Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" "tools/build_android_release.ps1" "-SelfTestBuildLock"
    $wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
    Invoke-Native $wsl "--user" "root" "--cd" $RepoRoot.Path "bash" "tools/build_linux_release.sh" "--self-test-build-lock"

    $lockDir = Join-Path $RepoRoot ".dart_tool\winsvpn-release-build.lock"
    $ownerFile = Join-Path $lockDir "owner.txt"
    New-Item -ItemType Directory -Path $lockDir -ErrorAction Stop | Out-Null
    try {
        [IO.File]::WriteAllText(
            $ownerFile,
            "platform=windows-cross-contention-selftest`npid=$PID`n",
            [Text.UTF8Encoding]::new($false)
        )
        & $wsl "--user" "root" "--cd" $RepoRoot.Path "bash" "tools/build_linux_release.sh" "--self-test-build-lock"
        $contentionExit = $LASTEXITCODE
        if ($contentionExit -ne 73) {
            throw "Linux builder must return 73 when the Windows-side release lock is held; got $contentionExit."
        }
    } finally {
        Remove-Item -LiteralPath $ownerFile -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $lockDir) {
            [IO.Directory]::Delete($lockDir, $false)
        }
    }

    $windowsBuilder = Get-Content -LiteralPath "installer/windows/build_installer.ps1" -Raw
    $linuxBuilder = Get-Content -LiteralPath "tools/build_linux_release.sh" -Raw
    if ($windowsBuilder -notmatch '\.dart_tool\\winsvpn-release-build\.lock' -or
        $linuxBuilder -notmatch '\.dart_tool/winsvpn-release-build\.lock') {
        throw "Windows and Linux builders must use the same repository-local release-build lock."
    }
    foreach ($contract in @(
        @{ Text = $windowsBuilder; Needle = 'finally {' },
        @{ Text = $windowsBuilder; Needle = 'Exit-ReleaseBuildLock' },
        @{ Text = $linuxBuilder; Needle = 'trap cleanup EXIT' },
        @{ Text = $linuxBuilder; Needle = 'release_build_lock' }
    )) {
        if (-not $contract.Text.Contains($contract.Needle)) {
            throw "Release-build lock cleanup contract is missing: $($contract.Needle)"
        }
    }
}

Invoke-Gate "Deployment runtime configuration simulation" {
    $wsl = (Get-Command wsl.exe -ErrorAction Stop).Source
    $windowsRepo = $RepoRoot.Path
    Invoke-Native $wsl "--user" "root" "--cd" $windowsRepo "bash" "tools/test_deployment_runtime_configs.sh"
}

Invoke-Gate "Smart Boost parked in stable deployment path" {
    $script = Get-Content server/wins_data_plane_setup_ONETOUCH.sh -Raw
    if ($script -match "cat > /usr/local/sbin/wins-boostd") {
        throw "Stable data-plane script still embeds wins-boostd."
    }
    if ($script -notmatch "systemctl disable --now wins-boostd.service") {
        throw "Stable data-plane script does not clean up legacy wins-boostd service."
    }
    $androidService = Get-Content android/app/src/main/kotlin/org/winsvpn/app/VpnTunnelService.kt -Raw
    if ($androidService -match "SmartBoostEngine|shouldUseSmartBoost") {
        throw "Compiled Android service still contains active Smart Boost engine code."
    }
    $appSource = Get-Content lib/main.dart -Raw
    if ($appSource -match "_buildWifiMobileDataToggle|wifi_mobile_data_enabled'\\s*=") {
        throw "Flutter UI still exposes or saves Wi-Fi + Mobile Data mode."
    }
}

if (-not $SkipSmartBoost) {
    foreach ($profile in @("clean", "lossy", "asymmetric", "bursty", "v3-adaptive")) {
        Invoke-Gate "Smart Boost stress profile: $profile" {
            Invoke-Native $Python "tools/smart_boost_stress.py" "--profile" $profile
        }
    }
}

if (-not $SkipWebsite) {
    Invoke-Gate "Cloudflare Pages Worker syntax" {
        $node = if (Get-Command node -ErrorAction SilentlyContinue) {
            (Get-Command node).Source
        } else {
            $RuntimeNode
        }
        # web/_worker.js is an ES module (export default {...}), which
        # --check only accepts via stdin under --input-type=module, not as
        # a positional filename argument -- Invoke-Native has no stdin
        # piping, so this one check bypasses it and mirrors its own
        # exit-code-based failure handling directly.
        Get-Content -Raw "web/_worker.js" | & $node "--input-type=module" "--check"
        if ($LASTEXITCODE -ne 0) {
            throw "web/_worker.js failed Node syntax check with code $LASTEXITCODE"
        }
    }
    Invoke-Gate "Website OWASP local audit" {
        Invoke-Native $Python "tools/website_security_audit.py"
    }
    Invoke-Gate "Cloudflare map worker contract" {
        $node = if (Get-Command node -ErrorAction SilentlyContinue) {
            (Get-Command node).Source
        } else {
            $RuntimeNode
        }
        Invoke-Native $node "tools/test_map_worker.mjs"
    }
}

if ($BuildArtifacts) {
    foreach ($name in @('DART_DEFINES', 'EXTRA_FRONT_END_OPTIONS', 'EXTRA_GEN_SNAPSHOT_OPTIONS', 'FLUTTER_TARGET')) {
        Remove-Item "Env:$name" -ErrorAction SilentlyContinue
    }
    Invoke-Gate "Android owner-only signing preseed" {
        Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" `
            "tools/android_signing_preseed.ps1" "-Action" "SelfTest"
        Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" `
            "tools/build_android_release.ps1" "-SelfTestSigningStore"
        if (Test-Path -LiteralPath "android/key.properties") {
            throw 'Repository-local Android key.properties is forbidden; use the current-user DPAPI preseed.'
        }
    }
    # Keep the stable android-cache-reset purpose marker: the static release
    # contract binds this coordinator ordering as part of the frozen producer.
    Invoke-WithReleaseBuildLock -Purpose 'android-cache-reset' -Action {
        Invoke-Gate "Android release build cache reset" {
            foreach ($relative in @(
                ".dart_tool\flutter_build",
                "build\flutter_assets",
                "build\native_assets",
                "build\.last_build_id",
                "build\app",
                "build\windows"
            )) {
                $target = Join-Path $RepoRoot $relative
                if (Test-Path -LiteralPath $target) {
                    Remove-Item -LiteralPath $target -Recurse -Force
                }
            }
            Invoke-Native "flutter" "pub" "get"
        }
        Invoke-Gate "Android native unit tests" {
            # Gradle writes android/.gradle and the shared build tree. Keep it
            # inside the same cross-platform lock as the Flutter cache reset.
            Invoke-Native "android/gradlew.bat" "-p" "android" "testDebugUnitTest"
        }
    }
    Invoke-Gate "Pre-Android-build release input index verification" {
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
    Invoke-Gate "Android release APK and AAB build" {
        Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" "-File" `
            "tools/build_android_release.ps1" "-ReleaseInputIndex" $ReleaseInputIndex
    }
    Invoke-Gate "Post-Android-build release input index verification" {
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
    Invoke-Gate "Pre-Windows-build release input index verification" {
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
    Invoke-Gate "Canonical Windows application and installer build" {
        # The producer owns the shared release lock from cache cleanup through
        # privacy-bound Flutter compilation, PE signing, and installer sealing.
        # Never split this into a stale prebuilt-output packaging handoff.
        Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" `
            "-File" "installer/windows/build_installer.ps1" `
            "-ReleaseInputIndex" $ReleaseInputIndex
    }
    Invoke-Gate "Post-Windows-build release input index verification" {
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
    Invoke-Gate "Built artifact privacy" {
        Invoke-Native $Python "tools/validate_release_artifact_privacy.py" "--artifacts"
    }
}

if ($Phone) {
    Invoke-Gate "Android phone fresh-install smoke" {
        Invoke-Native "powershell" "-ExecutionPolicy" "Bypass" "-File" "tools/android_phone_stress.ps1"
    }
}

if ($RequirePublishReady) {
    Invoke-Gate "Exact-artifact public release readiness" {
        Invoke-Native "powershell" "-NoProfile" "-ExecutionPolicy" "Bypass" `
            "-File" "tools/public_release_gate.ps1" "-ReleaseInputIndex" $ReleaseInputIndex
    }
}

if ($RequirePublishReady -or $BuildArtifacts) {
    Invoke-Gate "Final release input index verification" {
        Invoke-Native $Python "tools/release_dependency_freeze.py" "verify-index" `
            "--repo" $RepoRoot.Path "--index" $ReleaseInputIndex
    }
}

Write-Host ""
Write-Host "LOCAL RELEASE GATE: PASS" -ForegroundColor Green
