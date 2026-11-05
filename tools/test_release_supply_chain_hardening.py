import hashlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "installer/windows/build_installer.ps1").read_text(
    encoding="utf-8"
)
AWG_BUILDER = (ROOT / "tools/build_windows_awg_engine.ps1").read_text(
    encoding="utf-8"
)
PRESEED = (ROOT / "tools/wins_deployment_preseed.ps1").read_text(
    encoding="utf-8"
)
HISTORY_AUDIT = (ROOT / "tools/audit_git_history_for_secrets.py").read_text(
    encoding="utf-8"
)
PUBLIC_RELEASE_GATE = (ROOT / "tools/public_release_gate.ps1").read_text(
    encoding="utf-8"
)
SOURCE_ARCHIVE = (ROOT / "tools/create_cross_machine_source_archive.ps1").read_text(
    encoding="utf-8"
)
SOURCE_EXTRACTOR_PATH = ROOT / "tools/extract_cross_machine_source_archive.sh"
SOURCE_EXTRACTOR = SOURCE_EXTRACTOR_PATH.read_text(encoding="utf-8")
PRIVATE_HANDOFF_EXPORTER = (
    ROOT / "tools/export_windows_private_handoff.ps1"
).read_text(encoding="utf-8")
EXECUTABLE_MANIFEST = ".artifacts/cross-machine-sync-stage/source-executables.txt"
NDK_BUILDER = (ROOT / "tools/build_amneziawg_android_engine.sh").read_text(
    encoding="utf-8"
)
WINN3_GO_MOD = (ROOT / "winn_protocol_experimental/go.mod").read_text(
    encoding="utf-8"
)
WINN3_REPRO_GATE = (
    ROOT / "winn_protocol_experimental/scripts/v3_reproducible_build_gate.sh"
).read_text(encoding="utf-8")
DEPLOYMENT_SUPPLY_CHAIN = (
    ROOT / "tools/verify_deployment_supply_chain.py"
).read_text(encoding="utf-8")


class ReleaseSupplyChainHardeningTests(unittest.TestCase):
    def test_affected_mullvad_driver_is_not_a_positive_supply_chain_input(self) -> None:
        self.assertNotIn("mullvadvpn-app-binaries", DEPLOYMENT_SUPPLY_CHAIN)
        self.assertNotIn("verify_mullvad_desktop_release_and_driver", DEPLOYMENT_SUPPLY_CHAIN)
        self.assertNotIn("mullvad-split-tunnel-driver-1.3.0.0", DEPLOYMENT_SUPPLY_CHAIN)

    def test_winn3_reproducible_gate_requires_the_exact_go_toolchain(self) -> None:
        self.assertIn("go 1.27.1", WINN3_GO_MOD)
        self.assertIn('EXPECTED_GO_VERSION="go1.27.1"', WINN3_REPRO_GATE)
        self.assertIn("export GOTOOLCHAIN=local", WINN3_REPRO_GATE)
        self.assertIn(
            'fail "toolchain drift: got $GO_VERSION, require exactly $EXPECTED_GO_VERSION"',
            WINN3_REPRO_GATE,
        )
        self.assertNotIn("WARN: toolchain drift", WINN3_REPRO_GATE)

    def test_private_handoff_publishes_an_immutable_verified_pair(self) -> None:
        exporter = PRIVATE_HANDOFF_EXPORTER
        for required in (
            "Refusing to overwrite an existing private handoff bundle",
            "Refusing to overwrite an existing private handoff password",
            "[IO.FileMode]::CreateNew",
            "$passwordStream.Flush($true)",
            "private_handoff_crypto.py",
            "verify --input $stagedOutputPath",
            "[IO.File]::Move($stagedOutputPath, $OutputPath)",
            "$bundlePublishedByThisRun = $true",
            'Remove-Item -LiteralPath $PasswordFile -Force',
        ):
            self.assertIn(required, exporter)
        encrypt = exporter.index("encrypt --source-dir $staging")
        verify = exporter.index("verify --input $stagedOutputPath", encrypt)
        publish = exporter.index(
            "[IO.File]::Move($stagedOutputPath, $OutputPath)", verify
        )
        self.assertLess(encrypt, verify)
        self.assertLess(verify, publish)

    def test_vc_runtime_is_exactly_pinned_and_inno_is_never_auto_installed(self) -> None:
        for required in (
            '$VcRedistVersion = "14.44.35211.0"',
            'cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b',
            "function Assert-PinnedVcRedist",
            "OriginalFilename",
            "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
            "Automatic package-manager installation is forbidden",
            "Invoke-WebRequest -UseBasicParsing",
        ):
            self.assertIn(required, INSTALLER)
        self.assertNotIn("winget install", INSTALLER.lower())

    def test_windows_awg_build_uses_frozen_module_and_checksum_policy(self) -> None:
        for required in (
            "$engineVersion = 'v3.1.20260828'",
            "$engineCommit = 'b5928efb6ca19f0153958460c3d141f04abc5c2e'",
            "$engineModule = 'github.com/amnezia-vpn/amneziawg-go/v3'",
            "e447b49513d1fc452fa7cb2f87b15c40b88ab6f0656e22b4eccdfe238fa623e4",
            "fbec66bcbe1cf3603eb5b0f6c7c2041aea6749dc8c1d36b91726a7a479df4719",
            "GOTOOLCHAIN = 'local'",
            "GOFLAGS = '-mod=readonly'",
            "GOSUMDB = 'sum.golang.org'",
            "GOPROXY = 'https://proxy.golang.org,direct'",
            "-buildvcs=false",
            "go_module_policy = 'readonly'",
        ):
            self.assertIn(required, AWG_BUILDER)

    def test_windows_awg_go_toolchain_is_never_trusted_ambiently(self) -> None:
        # H-5-class remediation (Windows counterpart to prepare_reviewed_go()
        # in tools/build_apple_wg_go_bridge.sh, tools/build_xray_engine.sh,
        # and tools/build_amneziawg_android_engine.sh). Resolve-GoExecutable
        # used to trust $env:WINS_GO_EXE by mere path existence (zero
        # verification), and an ambient PATH go.exe by a spoofable
        # self-reported `go version` string (no hash check at all) -- with
        # real SHA-256 verification reachable only as a last-resort
        # fallback if both weaker checks failed. Neither ambient-trust
        # shortcut may ever come back.
        self.assertNotIn("WINS_GO_EXE", AWG_BUILDER)
        self.assertNotIn("Get-Command go.exe", AWG_BUILDER)

        function_start = AWG_BUILDER.index("function Resolve-GoExecutable")
        function_end = AWG_BUILDER.index(
            "if (-not (Test-Path -LiteralPath $sourceMain -PathType Leaf))",
            function_start,
        )
        resolver = AWG_BUILDER[function_start:function_end]

        # No ambient environment-variable or PATH lookup of any kind may
        # exist anywhere in the toolchain resolver, not just under the old
        # variable name -- this is a structural check, not just a name check.
        self.assertNotIn("env:", resolver)
        self.assertNotIn("Get-Command", resolver)

        # The pinned hash itself lives in the script-scoped $goArchiveSha256
        # constant (checked separately, file-wide), not inlined in the
        # function -- the function must reference that variable.
        self.assertIn(
            "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
            AWG_BUILDER,
        )
        for required in (
            "Test-Sha256 -Path $archive -Expected $goArchiveSha256",
            "throw 'The pinned Go toolchain archive failed SHA-256 verification.'",
            "Expand-Archive -LiteralPath $archive -DestinationPath $toolchainRoot -Force",
            "$portableVersion -notmatch $exactVersionPattern",
            "Remove-Item -LiteralPath $portableRoot -Recurse -Force",
        ):
            self.assertIn(required, resolver)

        # The archive must be SHA-256-verified before it is ever extracted
        # and trusted -- not downloaded-then-assumed-good, and not reused
        # from a previously-extracted, merely-version-string-matching copy.
        verify_offset = resolver.index(
            "Test-Sha256 -Path $archive -Expected $goArchiveSha256"
        )
        extract_offset = resolver.index("Expand-Archive")
        self.assertLess(verify_offset, extract_offset)

    def test_android_ndk_clang_and_strip_are_version_pinned_and_never_symlinks(
        self,
    ) -> None:
        # resolve_ndk_clang()/resolve_llvm_strip() used to accept any file at
        # a conventional path with a bare -x check -- no version identity of
        # the NDK itself, and no rejection of a symlink standing in for the
        # real toolchain binary. The NDK's own source.properties Pkg.Revision
        # must now match the same 30.0.16248370 pin
        # android/app/build.gradle.kts's ndkVersion already declares.
        self.assertIn('REVIEWED_NDK_VERSION="30.0.16248370"', NDK_BUILDER)

        home_start = NDK_BUILDER.index("resolve_ndk_home() {")
        home_end = NDK_BUILDER.index("\n}\n", home_start)
        home_body = NDK_BUILDER[home_start:home_end]
        self.assertIn("source.properties", home_body)
        self.assertIn("Pkg\\.Revision", home_body)
        self.assertIn('"${revision}" == "${REVIEWED_NDK_VERSION}"', home_body)

        tool_start = NDK_BUILDER.index("resolve_real_ndk_tool() {")
        tool_end = NDK_BUILDER.index("\n}\n", tool_start)
        tool_body = NDK_BUILDER[tool_start:tool_end]
        self.assertIn("realpath -e --", tool_body)
        self.assertIn("! -L", tool_body, "must explicitly reject symlinks")

        clang_start = NDK_BUILDER.index("resolve_ndk_clang() {")
        clang_end = NDK_BUILDER.index("\n}\n", clang_start)
        clang_body = NDK_BUILDER[clang_start:clang_end]
        self.assertIn("resolve_ndk_home", clang_body)
        self.assertIn("resolve_real_ndk_tool", clang_body)
        self.assertNotIn('[[ -x "${candidate}" ]]', clang_body)

        strip_start = NDK_BUILDER.index("resolve_llvm_strip() {")
        strip_end = NDK_BUILDER.index("\n}\n", strip_start)
        strip_body = NDK_BUILDER[strip_start:strip_end]
        self.assertIn("resolve_ndk_home", strip_body)
        self.assertIn("resolve_real_ndk_tool", strip_body)
        self.assertNotIn('[[ -x "${candidate}" ]]', strip_body)

    def test_windows_build_removes_copied_generated_plugin_links(self) -> None:
        for required in (
            "windows\\flutter\\ephemeral\\.plugin_symlinks",
            "linux\\flutter\\ephemeral\\.plugin_symlinks",
            "macos\\Flutter\\ephemeral\\.symlinks",
            "ios\\.symlinks",
            "causing errno 183",
        ):
            self.assertIn(required, INSTALLER)

    def test_windows_product_signing_precedes_exact_service_self_test(self) -> None:
        self.assertEqual(
            INSTALLER.count("& $TunnelServiceArtifact --protocol-self-test"), 1
        )
        product_enumeration = INSTALLER.index("$productBinaries = @(")
        signing_loop = INSTALLER.index("foreach ($binary in $productBinaries)")
        signing_call = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName", signing_loop
        )
        protocol_self_test = INSTALLER.index(
            "& $TunnelServiceArtifact --protocol-self-test"
        )
        runtime_validation = INSTALLER.index(
            "$VcRuntimeVersion = Assert-PinnedVcRedist", protocol_self_test
        )
        self.assertLess(product_enumeration, signing_loop)
        self.assertLess(signing_loop, signing_call)
        self.assertLess(signing_call, protocol_self_test)
        self.assertLess(protocol_self_test, runtime_validation)

    def test_windows_product_signing_precedes_awg_execution_guard(self) -> None:
        deferred_build = INSTALLER.index(
            "& $AwgEngineBuilder -Output $AwgEngineArtifact -DeferExecutionGuard"
        )
        signing_call = INSTALLER.index(
            "Invoke-ProductSigning -Path $binary.FullName"
        )
        guard_finalization = INSTALLER.index(
            "& $AwgEngineBuilder -Output $AwgEngineArtifact -FinalizeExecutionGuard"
        )
        self.assertLess(deferred_build, signing_call)
        self.assertLess(signing_call, guard_finalization)
        self.assertIn("-RequireValidAuthenticode:$mustSign", INSTALLER)

    def test_preseed_never_recovers_deleted_secrets_from_git(self) -> None:
        self.assertNotIn("backup keys.txt", PRESEED)
        self.assertNotIn("git -C $ProjectRoot show", PRESEED)
        self.assertIn("Recovery from deleted files or Git history is forbidden", PRESEED)
        self.assertEqual(
            PRESEED.count("Invoke-RestMethod"),
            PRESEED.count("Invoke-RestMethod -UseBasicParsing"),
        )

    def test_preseed_uses_env_or_protected_prompt_by_default(self) -> None:
        for required in (
            "function Read-DeploymentSecret",
            "if ($SecretFromStdin -and $SecretFromClipboard)",
            "[EnvironmentVariableTarget]::Process",
            "Read-Host -Prompt $Prompt -AsSecureString",
            "ZeroFreeBSTR",
            "WINS_CLOUDFLARE_TUNNEL_API_TOKEN",
            "WINS_CLOUDFLARE_ACCESS_API_TOKEN",
            "WINS_CLOUDFLARE_APPCLOUD_API_TOKEN",
            "Clipboard input requires explicit -SecretFromClipboard",
        ):
            self.assertIn(required, PRESEED)
        self.assertEqual(PRESEED.count("Read-DeploymentSecret `"), 3)
        self.assertEqual(PRESEED.count("Get-Clipboard -Raw"), 2)

    def test_bundletool_uses_private_ephemeral_staging(self) -> None:
        for required in (
            "function New-PrivateReleaseToolDirectory",
            ".dart_tool\\winsvpn-release-tools",
            "[Guid]::NewGuid().ToString('N')",
            "bundletool.jar.partial",
            "Staged bundletool $version failed its pinned SHA-256 recheck.",
            "PrivateDirectory = $stage",
            "Remove-Item -LiteralPath ([string]$bundletoolState.PrivateDirectory) -Recurse -Force",
        ):
            self.assertIn(required, PUBLIC_RELEASE_GATE)
        self.assertNotIn(
            'Join-Path ([IO.Path]::GetTempPath()) "bundletool-all-$version.jar"',
            PUBLIC_RELEASE_GATE,
        )

    def test_source_archive_is_tracked_only_unless_hash_reviewed(self) -> None:
        for required in (
            "& git ls-files --cached",
            "[string]$ReviewedUntrackedManifest",
            "[string]$ReviewedApprovedPathManifest",
            "<sha256><two spaces><repo-relative-path>",
            "& git ls-files --others --exclude-standard",
            "Reviewed approved file changed before archive creation",
            "reviewed_untracked_file_count = $reviewedUntracked.Count",
            "reviewed_approved_file_count = $reviewedApproved.Count",
            "selection_mode",
            "Assert-SafeSourcePath",
        ):
            self.assertIn(required, SOURCE_ARCHIVE)
        self.assertNotIn(
            "git ls-files --cached --others --exclude-standard", SOURCE_ARCHIVE
        )
        self.assertIn("function Get-FileSha256", SOURCE_ARCHIVE)
        self.assertNotIn("Get-FileHash -LiteralPath", SOURCE_ARCHIVE)

    def test_source_archive_cleans_embedded_manifest_for_all_late_failures(self) -> None:
        cleanup_scope = SOURCE_ARCHIVE.index("try {", SOURCE_ARCHIVE.index("$embeddedExecutableListPath"))
        embedded_write = SOURCE_ARCHIVE.index(
            "[IO.File]::WriteAllText(\n        $embeddedExecutableListPath",
            cleanup_scope,
        )
        approved_recheck = SOURCE_ARCHIVE.index(
            "foreach ($entry in $approvedForRecheck.GetEnumerator())", embedded_write
        )
        tar_call = SOURCE_ARCHIVE.index("& tar.exe -czf", approved_recheck)
        cleanup = SOURCE_ARCHIVE.index(
            "[IO.File]::Delete($embeddedExecutableListPath)", tar_call
        )
        self.assertLess(cleanup_scope, embedded_write)
        self.assertLess(embedded_write, approved_recheck)
        self.assertLess(approved_recheck, tar_call)
        self.assertLess(tar_call, cleanup)

    @unittest.skipUnless(os.name == "posix", "Fake tar fixture requires POSIX.")
    def test_source_archive_removes_partial_archive_after_tar_failure(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is required for the archive producer fixture.")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            repo = temporary_path / "repo"
            tools = repo / "tools"
            tools.mkdir(parents=True)
            fixture_script = tools / "create_cross_machine_source_archive.ps1"
            shutil.copy2(ROOT / "tools/create_cross_machine_source_archive.ps1", fixture_script)
            tracked_file = tools / "payload.txt"
            tracked_file.write_text("reviewed bytes", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "add", "tools/payload.txt"], check=True
            )

            approved_manifest = temporary_path / "approved.txt"
            approved_manifest.write_text(
                f"{hashlib.sha256(tracked_file.read_bytes()).hexdigest()}  "
                "tools/payload.txt\n",
                encoding="utf-8",
            )
            fake_bin = temporary_path / "bin"
            fake_bin.mkdir()
            fake_tar = fake_bin / "tar.exe"
            fake_tar.write_text(
                "#!/bin/sh\nprintf 'partial archive' > \"$2\"\nexit 9\n",
                encoding="utf-8",
            )
            fake_tar.chmod(0o755)
            output = temporary_path / "output"
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join(
                (str(fake_bin), environment.get("PATH", ""))
            )
            completed = subprocess.run(
                [
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(fixture_script),
                    "-OutputDirectory",
                    str(output),
                    "-ReviewedApprovedPathManifest",
                    str(approved_manifest),
                ],
                cwd=repo,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "source archive creation failed",
                (completed.stdout + completed.stderr).lower(),
            )
            self.assertFalse((output / "wins-vpn-current-source.tar.gz").exists())
            self.assertFalse(
                (repo / ".artifacts/cross-machine-sync-stage/source-executables.txt").exists()
            )

    def test_source_archive_privacy_validator_path_is_cross_platform(self) -> None:
        self.assertIn(
            "$privacyValidator = Join-Path $root 'tools/validate_release_artifact_privacy.py'",
            SOURCE_ARCHIVE,
        )
        self.assertIn("& python.exe $privacyValidator --static", SOURCE_ARCHIVE)
        self.assertNotIn(
            "& python.exe tools\\validate_release_artifact_privacy.py --static",
            SOURCE_ARCHIVE,
        )

    def test_source_archive_rejects_symlinked_tracked_parent(self) -> None:
        powershell = (
            shutil.which("pwsh")
            or shutil.which("powershell.exe")
            or shutil.which("powershell")
        )
        if powershell is None:
            self.skipTest("PowerShell is required for the archive producer fixture.")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            repo = temporary_path / "repo"
            tools = repo / "tools"
            tracked_parent = tools / "linked"
            tracked_parent.mkdir(parents=True)
            fixture_script = tools / "create_cross_machine_source_archive.ps1"
            shutil.copy2(ROOT / "tools/create_cross_machine_source_archive.ps1", fixture_script)
            tracked_file = tracked_parent / "payload.txt"
            tracked_file.write_text("tracked placeholder", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "add", "tools/linked/payload.txt"],
                check=True,
            )

            shutil.rmtree(tracked_parent)
            outside = temporary_path / "outside"
            outside.mkdir()
            outside_file = outside / "payload.txt"
            outside_file.write_text("outside bytes", encoding="utf-8")
            try:
                tracked_parent.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"Directory symlinks are unavailable: {exc}")

            digest = hashlib.sha256(outside_file.read_bytes()).hexdigest()
            approved_manifest = temporary_path / "approved.txt"
            approved_manifest.write_text(
                f"{digest}  tools/linked/payload.txt\n", encoding="utf-8"
            )
            output = temporary_path / "output"
            completed = subprocess.run(
                [
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(fixture_script),
                    "-OutputDirectory",
                    str(output),
                    "-ReviewedApprovedPathManifest",
                    str(approved_manifest),
                ],
                cwd=repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "contains a symbolic link or reparse point",
                (completed.stdout + completed.stderr).lower(),
            )
            self.assertFalse((output / "wins-vpn-current-source.tar.gz").exists())

    @unittest.skipUnless(os.name == "posix", "FIFO fixture requires a POSIX host.")
    def test_source_archive_rejects_tracked_fifo_before_hashing(self) -> None:
        powershell = shutil.which("pwsh") or shutil.which("powershell")
        if powershell is None:
            self.skipTest("PowerShell is required for the archive producer fixture.")

        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            repo = temporary_path / "repo"
            tools = repo / "tools"
            tools.mkdir(parents=True)
            fixture_script = tools / "create_cross_machine_source_archive.ps1"
            shutil.copy2(ROOT / "tools/create_cross_machine_source_archive.ps1", fixture_script)
            tracked_file = tools / "payload.txt"
            tracked_file.write_text("tracked placeholder", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "add", "tools/payload.txt"], check=True
            )
            tracked_file.unlink()
            os.mkfifo(tracked_file)

            approved_manifest = temporary_path / "approved.txt"
            approved_manifest.write_text(
                f"{'0' * 64}  tools/payload.txt\n", encoding="utf-8"
            )
            output = temporary_path / "output"
            completed = subprocess.run(
                [
                    powershell,
                    "-NoLogo",
                    "-NoProfile",
                    "-File",
                    str(fixture_script),
                    "-OutputDirectory",
                    str(output),
                    "-ReviewedApprovedPathManifest",
                    str(approved_manifest),
                ],
                cwd=repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "path is not a regular file",
                (completed.stdout + completed.stderr).lower(),
            )
            self.assertFalse((output / "wins-vpn-current-source.tar.gz").exists())

    def _write_source_archive_fixture(
        self, path: pathlib.Path, members, *, archive_format=tarfile.USTAR_FORMAT
    ) -> None:
        with tarfile.open(path, "w:gz", format=archive_format) as archive:
            for member in members:
                info = tarfile.TarInfo(member["name"])
                info.mode = member.get("mode", 0o644)
                info.type = member.get("type", tarfile.REGTYPE)
                info.linkname = member.get("linkname", "")
                info.pax_headers = member.get("pax_headers", {})
                data = member.get("data", b"")
                if info.type == tarfile.REGTYPE:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                else:
                    archive.addfile(info)

    def _run_source_extractor(
        self, archive: pathlib.Path, target: pathlib.Path, digest=None
    ) -> subprocess.CompletedProcess:
        if digest is None:
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        return subprocess.run(
            ["bash", str(SOURCE_EXTRACTOR_PATH), str(archive), str(target), digest],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    @staticmethod
    def _valid_source_archive_members():
        return [
            {"name": "tools/run.sh", "data": b"#!/bin/sh\nexit 0\n"},
            {"name": EXECUTABLE_MANIFEST, "data": b"tools/run.sh\n"},
        ]

    def test_source_extractor_stages_valid_archive_and_applies_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            archive = temporary_path / "source.tar.gz"
            target = temporary_path / "source"
            target.mkdir()
            self._write_source_archive_fixture(
                archive, self._valid_source_archive_members()
            )

            completed = self._run_source_extractor(archive, target)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("CROSS_MACHINE_SOURCE_EXTRACT=PASS", completed.stdout)
            self.assertIn("EXECUTABLES_APPLIED=1", completed.stdout)
            extracted = target / "tools/run.sh"
            self.assertEqual(extracted.read_bytes(), b"#!/bin/sh\nexit 0\n")
            self.assertTrue(os.access(extracted, os.X_OK))

    def test_source_extractor_rejects_dotdot_before_target_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            archive = temporary_path / "source.tar.gz"
            target = temporary_path / "source"
            members = self._valid_source_archive_members() + [
                {"name": "../escaped.txt", "data": b"escape"},
            ]
            self._write_source_archive_fixture(archive, members)

            completed = self._run_source_extractor(archive, target)

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("dot-dot", completed.stderr.lower())
            self.assertFalse(target.exists())
            self.assertFalse((temporary_path / "escaped.txt").exists())

    def test_source_extractor_rejects_absolute_special_and_pax_members(self) -> None:
        fixtures = (
            (
                {"name": "/absolute.txt", "data": b"outside"},
                tarfile.USTAR_FORMAT,
                "absolute archive member path",
            ),
            (
                {
                    "name": "tools/link",
                    "type": tarfile.SYMTYPE,
                    "linkname": "../../outside",
                },
                tarfile.USTAR_FORMAT,
                "member type is forbidden",
            ),
            (
                {"name": "tools/device", "type": tarfile.CHRTYPE},
                tarfile.USTAR_FORMAT,
                "member type is forbidden",
            ),
            (
                {
                    "name": "tools/metadata.txt",
                    "data": b"metadata",
                    "pax_headers": {"comment": "unexpected"},
                },
                tarfile.PAX_FORMAT,
                "pax metadata",
            ),
        )
        for malicious_member, archive_format, expected_error in fixtures:
            with self.subTest(expected_error=expected_error), tempfile.TemporaryDirectory() as temporary:
                temporary_path = pathlib.Path(temporary)
                archive = temporary_path / "source.tar.gz"
                target = temporary_path / "source"
                members = self._valid_source_archive_members() + [malicious_member]
                self._write_source_archive_fixture(
                    archive, members, archive_format=archive_format
                )

                completed = self._run_source_extractor(archive, target)

                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(expected_error, completed.stderr.lower())
                self.assertFalse(target.exists())

    def test_source_extractor_rejects_nonempty_target_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            archive = temporary_path / "source.tar.gz"
            target = temporary_path / "source"
            target.mkdir()
            marker = target / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            self._write_source_archive_fixture(
                archive, self._valid_source_archive_members()
            )

            completed = self._run_source_extractor(archive, target)

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("must be empty", completed.stderr.lower())
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

    def test_source_extractor_rejects_wrong_hash_before_target_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = pathlib.Path(temporary)
            archive = temporary_path / "source.tar.gz"
            target = temporary_path / "source"
            self._write_source_archive_fixture(
                archive, self._valid_source_archive_members()
            )

            completed = self._run_source_extractor(archive, target, "0" * 64)

            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("sha-256 mismatch", completed.stderr.lower())
            self.assertFalse(target.exists())

    def test_source_extractor_validates_all_members_before_staged_install(self) -> None:
        for required in (
            "source.getmembers()",
            "member.isreg() or member.isdir()",
            "member.pax_headers",
            "member.offset_data != member.offset + 512",
            "stage.replace(target)",
        ):
            self.assertIn(required, SOURCE_EXTRACTOR)

    def test_source_archive_rejects_apple_private_keys_and_profiles(self) -> None:
        for forbidden_extension in (
            ".p8",
            ".p12",
            ".pfx",
            ".mobileprovision",
            ".provisionprofile",
        ):
            self.assertIn(f"'{forbidden_extension}'", SOURCE_ARCHIVE)

    def test_source_archive_includes_linux_packaging_notices_root(self) -> None:
        self.assertIn("'docs'", SOURCE_ARCHIVE)
        self.assertIn("'README_FINAL_DEPLOYMENT.md'", SOURCE_ARCHIVE)
        linux_builder = (ROOT / "tools/build_linux_release.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md",
            linux_builder,
        )

    def test_history_audit_has_redacted_generic_detection(self) -> None:
        for required in (
            "PRIVATE_KEY_MATERIAL",
            "GITHUB_TOKEN",
            "GOOGLE_OAUTH_CLIENT_SECRET",
            "GENERIC_SECRET_ASSIGNMENT",
            "generic_secret_labels",
            "--exact-only",
            "No credential values were printed",
        ):
            self.assertIn(required, HISTORY_AUDIT)

    def test_history_audit_self_test(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/audit_git_history_for_secrets.py"), "--self-test"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("self-test PASS", completed.stdout)

    def test_obfuscation_static_contract_accepts_exact_windows_builder(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools/release_obfuscation_contract.py"),
                "static",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("RELEASE OBFUSCATION STATIC CONTRACT: PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main()
