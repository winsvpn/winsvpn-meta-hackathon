import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER_PATH = ROOT / "installer/windows/build_installer.ps1"
INSTALLER = INSTALLER_PATH.read_text(encoding="utf-8")
PWSH = shutil.which("pwsh")
FAKE_RENDERER = """import json, os, sys
args = sys.argv[1:]
browser = args[args.index('--browser') + 1]
out = args[args.index('--output') + 1]
mode = os.environ.get('FAKE_CHROMIUM_MODE', 'missing')
def write(payload):
    with open(out, 'w') as handle:
        handle.write(json.dumps(payload))
if browser == 'firefox':
    if os.environ.get('FAKE_FIREFOX_MODE') == 'wrong-id':
        write({'allowed_extensions': ['someone-else@example.org']})
    else:
        write({'allowed_extensions': ['companion@winsvpn.org']})
    sys.exit(0)
if mode == 'missing':
    sys.exit(78)
if mode == 'leak':
    write({})
    sys.exit(78)
if mode == 'fail':
    sys.exit(1)
if mode == 'placeholder':
    write({'allowed_origins': ['chrome-extension://placeholder/']})
    sys.exit(0)
write({'allowed_origins': ['chrome-extension://abcdefghijklmnopabcdefghijklmnop/']})
sys.exit(0)
"""
FAKE_LAYOUT = "print('companion@winsvpn.org')\n"
FAKE_BUILDER = (
    "param([string]$Output, [string]$DartBin)\n"
    "[IO.File]::WriteAllText($Output, 'MZ host')\n"
    "exit 0\n"
)


def load_functions(path: pathlib.Path, names: tuple) -> str:
    """PowerShell prelude that defines the named functions from the real file."""
    quoted = ", ".join("'" + name + "'" for name in names)
    return (
        "$ErrorActionPreference = 'Stop'\n"
        "$__ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$null, [ref]$null)\n"
        f"foreach ($__name in @({quoted})) {{\n"
        "    $__predicate = { param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -ceq $__name }.GetNewClosure()\n"
        "    $__def = @($__ast.FindAll($__predicate, $true)) | Select-Object -First 1\n"
        "    if (-not $__def) { throw \"function $__name is missing\" }\n"
        "    . ([scriptblock]::Create($__def.Extent.Text))\n"
        "}\n"
    )
REMOTE = (ROOT / "tools/windows_remote_candidate_build.ps1").read_text(
    encoding="utf-8"
)
LOCAL_GATE = (ROOT / "tools/local_release_gate.ps1").read_text(encoding="utf-8")
STORE_BUILDER = (ROOT / "installer/windows/build_store_msix.ps1").read_text(
    encoding="utf-8"
)
WINDOWS_LICENSE_INDEXES = tuple(
    path.read_text(encoding="utf-8")
    for path in sorted((ROOT / "installer/windows/licenses").glob("README*.txt"))
)
STARTUP_SMOKE = (ROOT / "tools/windows_install_startup_smoke.ps1").read_text(
    encoding="utf-8"
)
ROLLBACK_SMOKE = (ROOT / "tools/windows_rollback_reinstall_smoke.ps1").read_text(
    encoding="utf-8"
)
LAB_WORKER = (ROOT / "tools/windows_lab_interactive_worker.ps1").read_text(
    encoding="utf-8"
)
RELEASE_WORKER = (ROOT / "tools/windows_release_interactive_worker.ps1").read_text(
    encoding="utf-8"
)
STORE_NOTES = (ROOT / "installer/windows/store/certification-notes.md").read_text(
    encoding="utf-8"
)
INNO_SCRIPT = (ROOT / "installer/windows/winsvpn.iss").read_text(encoding="utf-8")


class WindowsInstallerToolchainIndexTests(unittest.TestCase):
    def test_withdrawn_mullvad_payload_is_not_a_positive_release_input(self) -> None:
        self.assertGreaterEqual(len(WINDOWS_LICENSE_INDEXES), 2)
        for source in (LOCAL_GATE, STORE_BUILDER, *WINDOWS_LICENSE_INDEXES):
            self.assertNotIn("mullvad", source.casefold())

    def test_startup_smoke_tracks_packed_tunnel_protocol_v4_header(self) -> None:
        self.assertIn("$request = [byte[]]::new(24)", STARTUP_SMOKE)
        self.assertIn(
            "[BitConverter]::GetBytes([uint16]4), 0, $request, 4, 2",
            STARTUP_SMOKE,
        )
        self.assertIn(
            "[BitConverter]::GetBytes([uint16]1), 0, $request, 6, 2",
            STARTUP_SMOKE,
        )
        self.assertIn("$version -ne 4", STARTUP_SMOKE)
        self.assertNotIn("$request = [byte[]]::new(16)", STARTUP_SMOKE)
        self.assertNotIn("$version -ne 3", STARTUP_SMOKE)
        self.assertNotIn("$version -ne 2", STARTUP_SMOKE)

    def test_all_silent_installer_lanes_preserve_reboot_required_exit(self) -> None:
        for source in (
            STARTUP_SMOKE,
            ROLLBACK_SMOKE,
            LAB_WORKER,
            RELEASE_WORKER,
            STORE_NOTES,
        ):
            self.assertIn("/RESTARTEXITCODE=3010", source)
        self.assertIn("$install.ExitCode -eq 3010", STARTUP_SMOKE)

    def test_canonical_installer_requires_exact_release_index(self) -> None:
        main = INSTALLER[INSTALLER.index("Enter-ReleaseBuildLock\ntry {") :]
        self.assertIn("[string]$ReleaseInputIndex = $env:WINS_RELEASE_INPUT_INDEX", INSTALLER)
        self.assertIn("Every Windows installer build requires", INSTALLER)
        self.assertIn("release_dependency_freeze.py", INSTALLER)
        self.assertIn("--platform windows", INSTALLER)
        self.assertGreaterEqual(INSTALLER.count("Assert-ReleaseInputIndexUnchanged"), 4)
        self.assertIn("function Assert-EmbeddedEngineRuntimeFreshness", INSTALLER)
        self.assertLess(
            main.index("Assert-ReleaseInputIndexUnchanged"),
            main.index("Quarantine-CanonicalInstallerOutputs"),
        )
        self.assertLess(
            main.index("# The staged installer is not publishable"),
            main.index("[IO.File]::Move($stagedInstaller, $CanonicalInstaller)"),
        )
        self.assertIn("release_input = [ordered]@{", INSTALLER)

    def test_windows_flutter_identity_is_exact_and_recorded(self) -> None:
        # The installer now reads the reviewed version and revision from
        # tools/toolchain-pins.json at run time instead of carrying literals.
        self.assertIn("$RequiredFlutterVersion = Read-WinsToolchainPin", INSTALLER)
        self.assertIn("$RequiredFlutterRevision = Read-WinsToolchainPin", INSTALLER)
        self.assertIn(r"tools\toolchain-pins.json", INSTALLER)
        self.assertIn("'tools.flutter.version'", INSTALLER)
        self.assertIn("'tools.flutter.revision'", INSTALLER)
        self.assertIn("--version --machine", INSTALLER)
        self.assertIn("frameworkRevision -cne $RequiredFlutterRevision", INSTALLER)
        self.assertIn("$script:FlutterCommand = $flutterCommand.Source", INSTALLER)
        self.assertIn("& $script:FlutterCommand pub get", INSTALLER)
        self.assertIn("& $script:FlutterCommand build windows", INSTALLER)
        self.assertNotIn("\n    flutter pub get", INSTALLER)
        self.assertNotIn("\n    flutter build windows", INSTALLER)
        self.assertIn("toolchain = $script:FlutterIdentity", INSTALLER)
        self.assertIn("A signed Windows release cannot use -SkipFlutterBuild", INSTALLER)
        self.assertIn("'windows-x64-inno-signed'", INSTALLER)
        self.assertIn("'windows-x64-inno-unsigned'", INSTALLER)
        self.assertIn("'windows-x64-inno-unsigned-prebuilt'", INSTALLER)
        self.assertIn("'windows-arm64-inno-signed'", INSTALLER)
        self.assertIn("'windows-arm64-inno-unsigned'", INSTALLER)
        self.assertIn("'windows-arm64-inno-unsigned-prebuilt'", INSTALLER)
        self.assertIn("[ValidateSet('x64', 'arm64')]", INSTALLER)
        self.assertIn("[string]$TargetArchitecture = 'x64'", INSTALLER)
        self.assertIn("function Assert-WindowsReleaseArchitecture", INSTALLER)
        self.assertNotIn("Windows arm64 release is fail-closed until", INSTALLER)
        self.assertIn("Mixing $normalizedHost Flutter output with $TargetArchitecture dependencies is refused.", INSTALLER)
        self.assertIn("No reviewed Windows Inno freeze target exists for $TargetArchitecture", INSTALLER)
        for define in (
            '"/DAmneziaWgExeSha256=$stagedAmneziaWgSha256"',
            '"/DUpstreamAmneziaWgExeSha256=$UpstreamAmneziaWgExeSha256"',
            '"/DAwgToolExeSha256=$AwgToolExeSha256"',
            '"/DWintunDllSha256=$WintunDllSha256"',
        ):
            self.assertIn(define, INSTALLER)

    def test_windows_producer_seals_and_verifies_exact_build_receipt(self) -> None:
        main = INSTALLER[INSTALLER.index("Enter-ReleaseBuildLock\ntry {") :]
        for marker in (
            "[string]$BuildReceiptDirectory = $env:WINS_WINDOWS_BUILD_RECEIPT_DIR",
            "WINDOWS_BUILD_BEGIN.json",
            "WINDOWS_BUILD_RECEIPT.json",
            "begin-build",
            "finish-build",
            "verify-receipt",
            "--platform windows",
            "--artifact $CanonicalInstaller",
            "--producer 'installer/windows/build_installer.ps1'",
            "Release-manifest directories are immutable eight-file control sets",
            "'.artifacts\\release-build-receipts\\windows\\' + $indexHash",
            "Windows build receipt namespace is not a regular directory",
        ):
            self.assertIn(marker, INSTALLER)

        begin = main.index("Initialize-WindowsBuildReceipt")
        quarantine = main.index("Quarantine-CanonicalInstallerOutputs")
        publish = main.index("[IO.File]::Move($stagedInstaller, $CanonicalInstaller)")
        preserve = main.index("$preservationReceiptPath =")
        finish = main.index("Complete-WindowsBuildReceipt", preserve)
        final_verify = main.index("Assert-ReleaseInputIndexUnchanged", finish)
        success = main.index('Write-Host "Created installer:', final_verify)
        self.assertLess(begin, quarantine)
        self.assertLess(quarantine, publish)
        self.assertLess(publish, preserve)
        self.assertLess(preserve, finish)
        self.assertLess(finish, final_verify)
        self.assertLess(final_verify, success)

        cleanup = main[main.rindex("} catch {") :]
        self.assertIn("retained as forensic evidence", cleanup)
        self.assertIn("Remove-Item -LiteralPath $CanonicalInstaller", cleanup)
        self.assertNotIn(
            "Remove-Item -LiteralPath $script:WindowsBuildReceipt", cleanup
        )

    def test_windows_producer_consumes_provenance_bound_winn_datapath_before_signing(
        self,
    ) -> None:
        # The installer is a consumer, not a compiler. It takes the requested
        # architecture's datapath and relay from one signed Winn release,
        # verified by tools/winn_release.py (manifest signature and digests),
        # role-checked, and product-signed before custody, all before the
        # signing loop. Missing v3 is fatal unless the owner explicitly asks
        # for an AWG/Xray-only release.
        self.assertIn(
            '$WinnEngineArtifact = Join-Path $ReleaseDir "winn-datapath.exe"',
            INSTALLER,
        )
        self.assertIn('$Winn3ArtifactProvenanceTool = Join-Path $RepoRoot "tools\\windows_winn3_artifact_provenance.py"', INSTALLER)
        self.assertIn('$WinnReleaseTool = Join-Path $RepoRoot "tools\\winn_release.py"', INSTALLER)
        self.assertIn("[string]$WinnReleaseDir = $env:WINS_WINN_RELEASE_DIR", INSTALLER)
        self.assertIn("$releaseTool.Path, 'verify', '--release', $releaseRoot, '--print-manifest'", INSTALLER)
        self.assertIn("$manifest = ([string]$verification.Stdout[0]) | ConvertFrom-Json -ErrorAction Stop", INSTALLER)
        self.assertNotIn("'--print-artifact'", INSTALLER)
        self.assertIn('$target = "datapath-windows-$($script:WindowsAwgGoArch)"', INSTALLER)
        self.assertIn('$relayTarget = "winn3-relay-windows-$($script:WindowsAwgGoArch)"', INSTALLER)
        self.assertIn("-AllowUnsignedWinnRelease is refused on a build that must be signed.", INSTALLER)
        self.assertIn("function Build-WinnDatapathEngine {", INSTALLER)
        self.assertIn("Invoke-Winn3ArtifactProvenanceVerification", INSTALLER)
        self.assertIn("ReleaseManifestSha256 = $manifestSha256", INSTALLER)
        self.assertIn("RelayReleaseManifestSha256 = $relayManifestSha256", INSTALLER)
        for retired in (
            "WINS_WINDOWS_WINN3_CANDIDATE_ID",
            "WINS_WINDOWS_WINN3_RECEIPT_SHA256",
            "WINS_WINDOWS_WINN3_SEALED_GENERATION",
            "verify-sealed-pair",
            "PairBuildIdentity",
        ):
            self.assertNotIn(retired, INSTALLER)
        self.assertNotIn("$Winn3ArtifactInputDir", INSTALLER)
        self.assertNotIn("$Winn3ArtifactReceipt", INSTALLER)
        self.assertIn("Write-Winn3CarrierCompleteness", INSTALLER)
        self.assertIn("-AllowMissingWinn3Carrier", INSTALLER)

        # Ordering: called after the pinned AWG engine build, before the
        # recursive product-signing loop, and before the next release-input
        # re-verification -- so a freshly built engine is Authenticode-signed
        # exactly like every other binary in $ReleaseDir and cannot itself
        # change what the freeze already measured.
        awg_stage = INSTALLER.index(
            "& $AwgEngineBuilder -Output $AwgEngineArtifact -DeferExecutionGuard"
        )
        winn_build_call = INSTALLER.index("\nBuild-WinnDatapathEngine\n", awg_stage)
        first_product_sign = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName", winn_build_call
        )
        reverify = INSTALLER.index(
            "Assert-ReleaseInputIndexUnchanged", first_product_sign
        )
        self.assertLess(awg_stage, winn_build_call)
        self.assertLess(winn_build_call, first_product_sign)
        self.assertLess(first_product_sign, reverify)

    def test_windows_installer_does_not_cross_build_arm64_winn_components(
        self,
    ) -> None:
        # Native arm64 packages are built on an arm64 Windows host. The x64
        # installer must not create unsigned cross-built side-channel output.
        self.assertIn("function Build-Arm64WinnComponentsBestEffort {", INSTALLER)
        self.assertIn("if ($TargetArchitecture -ceq 'x64') {", INSTALLER)
        self.assertIn("Build-Arm64WinnComponentsBestEffort", INSTALLER)
        self.assertIn("function Assert-StagedReleasePeMachines {", INSTALLER)
        self.assertIn("Assert-StagedReleasePeMachines", INSTALLER)
        self.assertIn('$script:WindowsPeMachine', INSTALLER)
        self.assertIn('[uint16]0x8664', INSTALLER)
        self.assertIn('[uint16]0xAA64', INSTALLER)
        self.assertIn(
            "Skipping optional arm64 Winn component production from the Windows installer",
            INSTALLER,
        )
        self.assertNotIn("datapath-windows-arm64", INSTALLER)
        arm64_function = INSTALLER[
            INSTALLER.index("function Build-Arm64WinnComponentsBestEffort {") :
            INSTALLER.index("function Assert-WindowsReleaseArchitecture")
        ]
        self.assertNotIn("build_windows_tunnel_service_xcompile.sh", arm64_function)
        self.assertNotIn("Find-Bash", arm64_function)

        # Ordering: called after Build-WinnDatapathEngine, before the
        # mandatory x64 artifact existence checks, so a missing/broken arm64
        # toolchain cannot affect what those mandatory checks see. Native
        # arm64 installer builds skip this x64-host side-channel.
        winn_build_call = INSTALLER.index("\nBuild-WinnDatapathEngine\n")
        arm64_call = INSTALLER.index(
            "if ($TargetArchitecture -ceq 'x64') {\n"
            "    Build-Arm64WinnComponentsBestEffort\n"
            "}",
            winn_build_call,
        )
        mandatory_check = INSTALLER.index(
            'if (-not (Test-Path (Join-Path $ReleaseDir "wins_vpn.exe")))',
            arm64_call,
        )
        pe_check = INSTALLER.index("\nAssert-StagedReleasePeMachines\n", mandatory_check)
        self.assertLess(winn_build_call, arm64_call)
        self.assertLess(arm64_call, mandatory_check)
        self.assertLess(mandatory_check, pe_check)

    def test_winsvpn_iss_selects_one_exact_native_architecture(
        self,
    ) -> None:
        for marker in (
            '#define ArchitectureLabel "x64"',
            '#define ArchitectureLabel "arm64"',
            '#define SetupArchitecture "arm64"',
            '#define SetupArchitecture "x64os"',
            "ArchitecturesAllowed={#SetupArchitecture}",
            "ArchitecturesInstallIn64BitMode={#SetupArchitecture}",
            '#define VcRedistFile "VC_redist.arm64.exe"',
            '#define AmneziaWgMsiFile "amneziawg-arm64.msi"',
            '#define OutputArchitectureSuffix "-arm64"',
            'Excludes: "*.pdb,*.ilk,*.iobj,*.ipdb,*.map,*.sym,*.dbg,*.debug,*-test.exe,*_test.exe"',
            "VersionInfoDescription=Win's VPN {#ArchitectureLabel} website installer",
            "VersionInfoDescription=Win's VPN {#ArchitectureLabel} Partner Center Win32 installer",
            "VersionInfoOriginalFileName=WinsVPN-Setup{#OutputArchitectureSuffix}.exe",
            "VersionInfoOriginalFileName=WinsVPN-PartnerCenter{#OutputArchitectureSuffix}.exe",
        ):
            self.assertIn(marker, INNO_SCRIPT)
        for affected_driver_file in (
            "mullvad-split-tunnel.sys",
            "mullvad-split-tunnel.cat",
            "mullvad-split-tunnel.inf",
        ):
            self.assertNotIn(
                f'Source: "{{#DependenciesDir}}\\\\{affected_driver_file}"',
                INNO_SCRIPT,
            )
        self.assertNotIn("ArchitecturesAllowed=x64compatible", INNO_SCRIPT)
        self.assertEqual(
            INNO_SCRIPT.count(
                "'SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\{#VcRuntimeRegistryArchitecture}'"
            ),
            5,
        )

    def test_windows_dependency_pins_include_native_arm64(self) -> None:
        for exact in (
            "5139e1440c3a20b92153a4db561c069a0175aaf76c276c3e5b6f56099edcf4b0",
            "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa",
            "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
            "c6edaa0e535b81d8c4c4a25378e6717b4406a8a0d72b751f4d0a1f171817e7af",
        ):
            self.assertIn(exact, INSTALLER)

    def test_remote_candidate_forwards_mandatory_index_and_revision(self) -> None:
        self.assertIn("[Parameter(Mandatory = $true)][string]$ReleaseInputIndex", REMOTE)
        self.assertIn("-ReleaseInputIndex $ReleaseInputIndex", REMOTE)
        # The candidate resolves the reviewed revision from the pin at run
        # time rather than carrying it as a literal.
        self.assertIn(r"tools\toolchain-pins.json", REMOTE)
        self.assertIn("$pin.tools.flutter.revision", REMOTE)
        self.assertNotIn("ee80f08bbf97172ec030b8751ceab557177a34a6", REMOTE)
        self.assertIn('"-ReleaseInputIndex" $ReleaseInputIndex', LOCAL_GATE)

    def test_remote_candidate_uses_new_run_scoped_status_and_refuses_reuse(self) -> None:
        publish = (
            "Write-RemoteBuildStatusAtomic -Path $statusPath "
            "-Status $runningStatus"
        )
        self.assertIn(
            "$runStateDirectory = Initialize-RunStateDirectory -Root $StateDir",
            REMOTE,
        )
        self.assertIn(
            '[string]$StateDir = "$env:LOCALAPPDATA\\WinsVPN\\RemoteBuildState"',
            REMOTE,
        )
        self.assertNotIn('[string]$StateDir = "$env:ProgramData', REMOTE)
        self.assertIn(
            "$statusPath = Join-Path $runStateDirectory "
            "'remote-build-status.json'",
            REMOTE,
        )
        self.assertIn("RunId state already exists; refusing reuse or overwrite", REMOTE)
        self.assertIn("refusing collision before status publication", REMOTE)
        self.assertNotIn("Join-Path $StateDir 'remote-build-status.json'", REMOTE)
        self.assertIn("run_id = $RunId", REMOTE)
        self.assertIn("state = 'running'", REMOTE)
        self.assertIn("done = $false", REMOTE)
        self.assertIn("state = 'succeeded'", REMOTE)
        self.assertIn("state = 'failed'", REMOTE)
        self.assertIn(publish, REMOTE)
        self.assertLess(REMOTE.index(publish), REMOTE.index("Get-Command flutter.bat"))
        self.assertIn("RunId state reuse was accepted", REMOTE)
        self.assertIn("Remote build status is terminal and immutable", REMOTE)
        self.assertIn("Terminal remote build status was mutable", REMOTE)

    def test_remote_candidate_launch_tests_powershell_before_flutter(self) -> None:
        self.assertIn(
            "[string]$PowerShellExecutable = "
            "$env:WINS_WINDOWS_POWERSHELL_EXECUTABLE",
            REMOTE,
        )
        self.assertIn("function Test-PowerShellExecutableLaunch", REMOTE)
        self.assertIn("WINSVPN_POWERSHELL_OK|", REMOTE)
        self.assertIn("function Set-SafePowerShellProcessEnvironment", REMOTE)
        self.assertIn(r"\\Microsoft\\WindowsApps$", REMOTE)
        resolve = REMOTE.index(
            "$resolvedPowerShell = Resolve-LaunchTestedPowerShellExecutable"
        )
        sanitize = REMOTE.index("Set-SafePowerShellProcessEnvironment", resolve)
        flutter_path = REMOTE.index("$flutterBin = Join-Path", sanitize)
        flutter_command = REMOTE.index("Get-Command flutter.bat", flutter_path)
        self.assertLess(resolve, sanitize)
        self.assertLess(sanitize, flutter_path)
        self.assertLess(flutter_path, flutter_command)

    def test_remote_candidate_is_signed_by_default_with_explicit_engineering_mode(
        self,
    ) -> None:
        self.assertIn("[switch]$AllowUnsignedEngineering", REMOTE)
        self.assertNotIn("[switch]$AllowUnsigned,", REMOTE)
        self.assertIn("$signingRequired = -not [bool]$AllowUnsignedEngineering", REMOTE)
        self.assertIn("'production_signed'", REMOTE)
        self.assertIn("'unsigned_engineering'", REMOTE)
        self.assertIn("'-RequireCodeSigning'", REMOTE)
        self.assertIn("'-AllowUnsigned'", REMOTE)
        mode = REMOTE.index("$installerModeArgument = if ($AllowUnsignedEngineering)")
        child = REMOTE.index("& $resolvedPowerShell.Path", mode)
        self.assertLess(mode, child)
        self.assertIn("$installerModeArgument -SkipRuntimeDownload", REMOTE[child:])

    def test_remote_candidate_status_v2_records_mode_signing_and_publishability(
        self,
    ) -> None:
        self.assertGreaterEqual(REMOTE.count("schema_version = 2"), 4)
        self.assertGreaterEqual(
            REMOTE.count("winsvpn-windows-remote-build-status-v2"), 5
        )
        for marker in (
            "build_mode = $buildMode",
            "signing = New-StatusSigningRecord",
            "publishability = New-StatusPublishabilityRecord",
            "store_submission_eligible = $StoreSubmissionEligible",
            "publication_authorized = $false",
            "'unsigned_engineering_nonpublishable'",
            "Separate release approval and evidence are required",
        ):
            self.assertIn(marker, REMOTE)
        self.assertNotIn(
            "-StoreSubmissionEligible $signingRequired",
            REMOTE,
        )

    def test_remote_candidate_status_publication_is_atomic(self) -> None:
        self.assertIn("[IO.FileMode]::CreateNew", REMOTE)
        self.assertIn("$stream.Flush($true)", REMOTE)
        self.assertIn(
            "[IO.File]::Replace($temporary, $resolvedPath, $backup, $true)",
            REMOTE,
        )
        self.assertIn("[IO.File]::Move($temporary, $resolvedPath)", REMOTE)
        self.assertNotIn("[IO.File]::WriteAllText(\n        $statusPath", REMOTE)
        self.assertGreaterEqual(
            REMOTE.count(
                "Write-RemoteBuildStatusAtomic -Path $statusPath -Status $result"
            ),
            2,
        )

    def test_remote_candidate_reverifies_index_before_success_evidence(self) -> None:
        child = REMOTE.index("& $resolvedPowerShell.Path")
        post_verify = REMOTE.index(
            "tools\\release_dependency_freeze.py verify-index", child
        )
        platform_scope = REMOTE.index("--platform windows", post_verify)
        hash_evidence = REMOTE.index("$installer = Join-Path", platform_scope)
        success_status = REMOTE.index("state = 'succeeded'", hash_evidence)
        self.assertLess(child, post_verify)
        self.assertLess(post_verify, platform_scope)
        self.assertLess(platform_scope, hash_evidence)
        self.assertLess(hash_evidence, success_status)
        self.assertIn("Post-installer Windows release input verification", REMOTE)

    def test_remote_candidate_verifies_payload_signing_matches_build_mode(
        self,
    ) -> None:
        verify_receipt = REMOTE.index(
            "tools\\release_dependency_freeze.py verify-receipt"
        )
        verify_payload = REMOTE.index(
            "$payloadDocument = Assert-PayloadManifestSigningMode",
            verify_receipt,
        )
        verify_formal_mode = REMOTE.index(
            "$buildReceiptDocument = Assert-FormalBuildReceiptMode",
            verify_receipt,
        )
        resolve_preserved = REMOTE.index(
            "$preserved = Resolve-PreservedArtifactSet", verify_payload
        )
        copyback = REMOTE.index(
            "$copyback = Publish-ImmutableCopybackBundle", resolve_preserved
        )
        success = REMOTE.index("state = 'succeeded'", copyback)
        self.assertLess(verify_receipt, verify_payload)
        self.assertLess(verify_receipt, verify_formal_mode)
        self.assertLess(verify_formal_mode, verify_payload)
        self.assertLess(verify_payload, resolve_preserved)
        self.assertLess(resolve_preserved, copyback)
        self.assertLess(copyback, success)
        for field in (
            "production_signed",
            "every_loose_pe_verified",
            "staged_xray_product_signed",
            "inno_setup_and_uninstaller_signed",
            "self_signed_certificate_forbidden",
        ):
            self.assertIn(field, REMOTE)
        for marker in (
            "winsvpn-build-receipt-v1",
            '"windows-$Architecture-inno-"',
            "-Architecture $TargetArchitecture",
            "$receipt.artifact.size_bytes",
        ):
            self.assertIn(marker, REMOTE)

    def test_remote_candidate_seals_immutable_run_owned_copyback(self) -> None:
        for marker in (
            ".artifacts\\remote-windows-copyback",
            "RunId already owns a copyback bundle",
            "winsvpn-windows-remote-copyback-v1",
            "COPYBACK_MANIFEST.json",
            "preserved_installer",
            "preserved_payload_manifest",
            "PRESERVED_ARTIFACT.json",
            "WINDOWS_BUILD_BEGIN.json",
            "WINDOWS_BUILD_BEGIN.json.sha256",
            "WINDOWS_BUILD_RECEIPT.json",
            "WINDOWS_BUILD_RECEIPT.json.sha256",
            "release-input-control/RELEASE_INPUT_INDEX.json",
            "Release input control directory must remain an exact eight-file set",
            "Write-AtomicNewUtf8File -Path $manifestPath",
            "Copyback bundle contains an unbound file",
            "copyback_manifest = [ordered]@{",
        ):
            self.assertIn(marker, REMOTE)
        self.assertIn("size = $copyback.ManifestSize", REMOTE)
        self.assertIn("sha256 = $copyback.ManifestSha256", REMOTE)

    def test_remote_candidate_binds_run_to_formal_build_receipt(self) -> None:
        receipt_directory = REMOTE.index(
            "$buildReceiptDirectory = Join-Path $buildReceiptParent $RunId"
        )
        child = REMOTE.index("-BuildReceiptDirectory $buildReceiptDirectory")
        post_index = REMOTE.index(
            "tools\\release_dependency_freeze.py verify-index", child
        )
        require_receipt = REMOTE.index(
            "$buildReceipt = Join-Path $buildReceiptDirectory "
            "'WINDOWS_BUILD_RECEIPT.json'",
            post_index,
        )
        verify_receipt = REMOTE.index(
            "tools\\release_dependency_freeze.py verify-receipt", require_receipt
        )
        receipt_hash = REMOTE.index("build_receipt_sha256 =", verify_receipt)
        success_publish = REMOTE.index(
            "Write-RemoteBuildStatusAtomic -Path $statusPath -Status $result",
            receipt_hash,
        )
        self.assertLess(receipt_directory, child)
        self.assertLess(child, post_index)
        self.assertLess(post_index, require_receipt)
        self.assertLess(require_receipt, verify_receipt)
        self.assertLess(verify_receipt, receipt_hash)
        self.assertLess(receipt_hash, success_publish)
        self.assertIn(".artifacts\\remote-windows-build-receipts", REMOTE)
        self.assertIn("build_receipt_path = $buildReceiptRelative", REMOTE)

    def test_producer_and_iss_register_signed_native_host_without_placeholders(
        self,
    ) -> None:
        self.assertIn("function Build-BrowserNativeHost {", INSTALLER)
        self.assertIn("\nBuild-BrowserNativeHost\n", INSTALLER)
        winn_build = INSTALLER.index("\nBuild-WinnDatapathEngine\n")
        native_host = INSTALLER.index("\nBuild-BrowserNativeHost\n", winn_build)
        signing = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName", native_host
        )
        self.assertLess(native_host, signing)
        self.assertIn(
            "Refusing to stage native-host manifest",
            INSTALLER,
        )
        self.assertIn("placeholder", INSTALLER)
        self.assertNotIn("owner-issued identity receipt", INSTALLER)
        self.assertNotIn("requires Firefox, Chrome, and Edge contracts", INSTALLER)
        self.assertIn(
            'Write-Warning "$browser native host is not registered: no pinned $browser store id is recorded."',
            INSTALLER,
        )
        self.assertIn("$renderedManifests = @('org.winsvpn.bridge.firefox.json')", INSTALLER)
        self.assertIn("/DEnableChromeNativeHost=1", INSTALLER)
        self.assertIn("/DEnableEdgeNativeHost=1", INSTALLER)
        self.assertIn(
            'Subkey: "Software\\Mozilla\\NativeMessagingHosts\\org.winsvpn.bridge"',
            INNO_SCRIPT,
        )
        self.assertIn("#ifdef EnableChromeNativeHost", INNO_SCRIPT)
        self.assertIn("#ifdef EnableEdgeNativeHost", INNO_SCRIPT)
        chrome_block = INNO_SCRIPT[
            INNO_SCRIPT.index("#ifdef EnableChromeNativeHost") : INNO_SCRIPT.index(
                "#endif", INNO_SCRIPT.index("#ifdef EnableChromeNativeHost")
            )
        ]
        self.assertIn("Google\\Chrome\\NativeMessagingHosts", chrome_block)

    @unittest.skipUnless(PWSH, "pwsh is unavailable for native-host probes")
    def test_native_host_skips_chromium_without_store_id_and_requires_firefox(
        self,
    ) -> None:
        cases = {
            "missing": (0, ["firefox"]),
            "present": (0, ["firefox", "chrome", "edge"]),
            "leak": (2, None),
            "fail": (2, None),
            "placeholder": (2, None),
            "firefox-wrong-id": (2, None),
        }
        for mode, (expected_rc, expected_browsers) in cases.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as raw:
                tmp = pathlib.Path(raw)
                (tmp / "render.py").write_text(FAKE_RENDERER, encoding="utf-8")
                (tmp / "layout.py").write_text(FAKE_LAYOUT, encoding="utf-8")
                (tmp / "builder.ps1").write_text(FAKE_BUILDER, encoding="utf-8")
                (tmp / "dart").write_text("dart", encoding="utf-8")
                stage = tmp / "stage"
                script = (
                    load_functions(INSTALLER_PATH, ("Build-BrowserNativeHost",))
                    + "function Assert-PeCoffMachine { param($Path, $Expected) }\n"
                    + f"$NativeHostStageDir = '{stage}'\n"
                    + f"$NativeHostArtifact = '{stage / 'wins_bridge_host.exe'}'\n"
                    + f"$NativeHostManifestRenderer = '{tmp / 'render.py'}'\n"
                    + f"$NativeHostLayout = '{tmp / 'layout.py'}'\n"
                    + f"$NativeHostBuilder = '{tmp / 'builder.ps1'}'\n"
                    + f"$env:DART_BIN = '{tmp / 'dart'}'\n"
                    + "$script:FlutterCommand = $null\n"
                    + "$script:WindowsPeMachine = [uint16]0x8664\n"
                    + "try { Build-BrowserNativeHost } catch { Write-Output ('REFUSED: ' + $_.Exception.Message); exit 2 }\n"
                    + "exit 0\n"
                )
                completed = subprocess.run(
                    [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                    cwd=raw,
                    capture_output=True,
                    text=True,
                    check=False,
                    env={
                        **os.environ,
                        "FAKE_CHROMIUM_MODE": "missing" if mode == "firefox-wrong-id" else mode,
                        "FAKE_FIREFOX_MODE": "wrong-id" if mode == "firefox-wrong-id" else "",
                        "NO_COLOR": "1",
                    },
                )
                output = completed.stdout + completed.stderr
                self.assertEqual(completed.returncode, expected_rc, output)
                self.assertNotIn("owner", output.lower())
                if expected_browsers is None:
                    self.assertIn("REFUSED:", output)
                    if mode == "firefox-wrong-id":
                        self.assertIn("not bound to companion@winsvpn.org", output)
                    if mode == "leak":
                        self.assertIn("left a manifest", output)
                    if mode == "placeholder":
                        # A rendered Chromium manifest is validated like Firefox.
                        self.assertIn("still contains a placeholder", output)
                    continue
                staged = sorted(path.name for path in stage.glob("*.json"))
                self.assertEqual(
                    staged,
                    sorted(f"org.winsvpn.bridge.{name}.json" for name in expected_browsers),
                )
                if mode == "missing":
                    self.assertIn("chrome native host is not registered", output)
                    self.assertIn("edge native host is not registered", output)

    def test_inno_compiler_custody_messages_are_plain(self) -> None:
        self.assertNotIn("OWNER INPUT REQUIRED", INSTALLER)
        for message in (
            "Inno Setup 7.1.0 ISCC.exe was not found at ",
            "throw 'tools/inno-toolchain-pins.json is absent.'",
            "throw 'Inno Setup 7.1.0 compiler identity is absent.'",
            "PATH, INNO_SETUP_ISCC, and package-manager discovery are not accepted",
        ):
            self.assertIn(message, INSTALLER)
        # The checks behind the messages stay: exact Program Files root and
        # the verify-compiler bind before and again immediately before ISCC.
        self.assertIn("Join-Path $programFiles 'Inno Setup 7\\ISCC.exe'", INSTALLER)
        self.assertGreaterEqual(INSTALLER.count("Bind-WinsInnoCompilerCustody -Architecture $TargetArchitecture"), 2)

    def test_arm64_release_path_is_native_and_distinct(
        self,
    ) -> None:
        self.assertIn("Assert-WindowsReleaseArchitecture", INSTALLER)
        self.assertIn("VC_redist.arm64.exe", INSTALLER)
        self.assertIn("amneziawg-arm64.msi", INSTALLER)
        self.assertIn('#define SetupArchitecture "arm64"', INNO_SCRIPT)
        self.assertIn("WinsVPN-Setup-arm64.exe", REMOTE)
        self.assertNotIn("Windows arm64 remote candidates are fail-closed", REMOTE)
        self.assertIn("[switch]$StandaloneWinn3Release", REMOTE)
        self.assertIn("@standaloneArgument", REMOTE)
        self.assertNotIn(
            "-SkipRuntimeDownload -StandaloneWinn3Release",
            REMOTE,
        )

    def test_signed_release_requires_winn_v3_and_excludes_debug_symbols(self) -> None:
        self.assertIn("function Get-WindowsPayloadDebugSymbolFiles {", INSTALLER)
        self.assertIn("function Move-WindowsPayloadDebugSymbolsToPrivateCustody {", INSTALLER)
        self.assertIn("function Assert-WindowsPayloadContainsNoDebugSymbols {", INSTALLER)
        self.assertIn("'.pdb', '.ilk', '.iobj', '.ipdb', '.map', '.sym', '.dbg', '.debug'", INSTALLER)
        self.assertIn(
            "if ($mustSign -and $AllowMissingWinn3Carrier) {",
            INSTALLER,
        )
        self.assertIn(
            "A signed Windows release cannot omit the Winn Protocol v3 carrier.",
            INSTALLER,
        )
        completeness = INSTALLER.index("Write-Winn3CarrierCompleteness\n")
        first_pdb_move = INSTALLER.index(
            "Move-WindowsPayloadDebugSymbolsToPrivateCustody -PayloadRoot $ReleaseDir",
            completeness,
        )
        signing_loop = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName", first_pdb_move
        )
        iscc = INSTALLER.index("& $iscc @innoArguments", first_pdb_move)
        pre_iscc_assert = INSTALLER.index(
            "Assert-WindowsPayloadContainsNoDebugSymbols -PayloadRoot $ReleaseDir "
            "-Label 'Windows Inno source directory'",
            first_pdb_move,
        )
        self.assertLess(completeness, first_pdb_move)
        self.assertLess(first_pdb_move, signing_loop)
        self.assertLess(pre_iscc_assert, iscc)
        self.assertIn(
            "Excludes: \"*.pdb,*.ilk,*.iobj,*.ipdb,*.map,*.sym,*.dbg,*.debug,*-test.exe,*_test.exe\"",
            INNO_SCRIPT,
        )
        self.assertIn(
            "Win's VPN $TargetArchitecture website installer",
            INSTALLER,
        )
        self.assertIn(
            "Win's VPN $TargetArchitecture Partner Center Win32 installer",
            INSTALLER,
        )
        self.assertIn(
            "-ExpectedOriginalFilename $CanonicalInstallerName",
            INSTALLER,
        )
        self.assertGreaterEqual(
            INSTALLER.count("Assert-WindowsPayloadContainsNoDebugSymbols"),
            3,
        )

    def test_signed_release_requires_timestamp_and_honours_optional_leaf_pin(
        self,
    ) -> None:
        self.assertIn("verify /pa /all /v /tw", INSTALLER)
        self.assertIn("TimeStamperCertificate", INSTALLER)
        self.assertIn(
            "A self-signed certificate is forbidden for production distribution",
            INSTALLER,
        )
        self.assertIn(
            "Assert-MicrosoftTrustedRootProgramChain -Certificate $matches[0]",
            INSTALLER,
        )
        self.assertNotIn("OWNER-BLOCKED", INSTALLER)
        self.assertNotIn("$OwnerAuthenticodeLeafSha256", INSTALLER)
        self.assertIn(
            "timestamp_verified = [bool]$script:AuthenticodeTimestampVerified",
            INSTALLER,
        )
        self.assertIn(
            "-ExpectedLeafSha256 $WindowsAuthenticodeLeafPin -Path $Path",
            INSTALLER,
        )
        self.assertIn(
            "authenticode_leaf_sha256 = $script:AuthenticodeLeafSha256",
            INSTALLER,
        )
        self.assertNotIn(
            "A signed release candidate cannot be produced until the owner records the public-trust leaf SHA-256.",
            INSTALLER,
        )
        self.assertNotIn("verify /pa /all /q", INSTALLER)
        self.assertNotIn("timestamp_verified = [bool]$mustSign", INSTALLER)
        self.assertNotIn("[switch]$AllowPrivateTestRoot", INSTALLER)

    def test_signed_inno_staging_rejects_nested_or_renamed_mullvad_payloads(
        self,
    ) -> None:
        for marker in (
            "function Get-ValidatedInnoContainerRoot {",
            "function Assert-InnoNoReparsePointChain {",
            "function Get-ContainedInnoStagingFiles {",
            "function Assert-InnoStagingPayloadAllowed {",
            "function Assert-InnoStagingPayloadHashAllowed {",
            "function Assert-InnoStagingContainsNoWithdrawnMullvadPayloads {",
            "function Invoke-WithdrawnMullvadStagingSelfTest {",
            "$ForbiddenInnoMullvadPayloadSha256 = @(",
            "$ForbiddenInnoMullvadPayloadLeafPrefixes = @('mullvad-split-tunnel')",
            "$ForbiddenInnoMullvadPayloadExtensions = @('.sys', '.cat', '.inf')",
            "withdrawn kernel split-tunnel bytes, including when renamed",
            "Refusing a filesystem-root container",
            "[switch]$SelfTestWithdrawnMullvadStaging",
        ):
            self.assertIn(marker, INSTALLER)
        walker = INSTALLER[
            INSTALLER.index("function Get-ContainedInnoStagingFiles {") : INSTALLER.index(
                "function Assert-InnoStagingPayloadAllowed {"
            )
        ]
        self.assertNotIn("-Recurse", walker)
        self.assertIn("ReparsePoint", walker)
        self.assertIn("System.Collections.Generic.Stack[string]", walker)
        self.assertGreaterEqual(
            INSTALLER.count("Assert-InnoStagingContainsNoWithdrawnMullvadPayloads"),
            2,
        )
        stage_copy = INSTALLER.index(
            "Copy-Item -LiteralPath $entry.Value -Destination $destination -Force"
        )
        first_gate = INSTALLER.index(
            "Assert-InnoStagingContainsNoWithdrawnMullvadPayloads", stage_copy
        )
        staged_sign = INSTALLER.index(
            "Invoke-ProductSigning -Path $stagedAmneziaWg", first_gate
        )
        signed_define = INSTALLER.index("$innoArguments += '/DEnableSigning=1'")
        iscc = INSTALLER.index("& $iscc @innoArguments")
        last_gate = INSTALLER.rindex(
            "Assert-InnoStagingContainsNoWithdrawnMullvadPayloads", 0, iscc
        )
        self.assertLess(first_gate, staged_sign)
        self.assertLess(signed_define, last_gate)
        self.assertLess(last_gate, iscc)
        self.assertIn("recursesubdirs createallsubdirs", INNO_SCRIPT)
        self.assertIn(
            "withdrawn kernel split-tunnel SYS/CAT/INF bytes",
            INNO_SCRIPT,
        )
        for affected_driver_file in (
            "mullvad-split-tunnel.sys",
            "mullvad-split-tunnel.cat",
            "mullvad-split-tunnel.inf",
        ):
            self.assertNotIn(affected_driver_file, INNO_SCRIPT)

    def test_direct_iscc_cannot_emit_a_canonical_unsigned_candidate(self) -> None:
        self.assertIn("#ifndef EnableSigning", INNO_SCRIPT)
        self.assertIn("#ifndef AllowUnsignedLocal", INNO_SCRIPT)
        self.assertIn("#error \"Direct ISCC invocation is forbidden.", INNO_SCRIPT)
        self.assertIn("OutputBaseFilename=WinsVPN-Setup", INNO_SCRIPT)
        self.assertIn(
            "OutputBaseFilename=WinsVPN-UNSIGNED-LOCAL-Setup", INNO_SCRIPT
        )
        self.assertIn("$innoArguments += '/DAllowUnsignedLocal=1'", INSTALLER)
        self.assertIn("if (-not $mustSign) {", INSTALLER)
        self.assertIn(
            "WinsVPN-UNSIGNED-LOCAL-Setup$installerArchitectureSuffix.exe",
            INSTALLER,
        )
        signed_define = INSTALLER.index("$innoArguments += '/DEnableSigning=1'")
        unsigned_define = INSTALLER.index(
            "$innoArguments += '/DAllowUnsignedLocal=1'", signed_define
        )
        self.assertLess(signed_define, unsigned_define)


if __name__ == "__main__":
    unittest.main()
