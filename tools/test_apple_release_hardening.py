#!/usr/bin/env python3
"""Focused static tests for Apple release stripping, symbols, and privacy."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {relative}")
    module = importlib.util.module_from_spec(spec)
    # Register before exec_module, matching importlib's own documented
    # pattern: some stdlib machinery (e.g. Python 3.14's dataclasses, for a
    # class whose annotations are strings under `from __future__ import
    # annotations`) looks the module up via sys.modules[cls.__module__]
    # while the module body is still executing, and fails with a confusing
    # AttributeError on `None.__dict__` if it isn't registered yet.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AppleReleaseHardeningTests(unittest.TestCase):
    def test_runtime_readiness_failure_stops_before_builds(self) -> None:
        runtime = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        run_function = re.search(r"(?ms)^run\(\) \{\n.*?^\}", runtime)
        self.assertIsNotNone(run_function)
        assert run_function is not None
        main = runtime.index('rerun_macos_pkg_install_lane_as_user_if_root "$@"')
        start = runtime.index('if [[ "${WINS_PRE_RELEASE_SOURCE_SMOKE}" == "1" ]]; then', main)
        end = runtime.index('\nif [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY}"', start)
        gate = runtime[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "tools").mkdir()
            readiness = root / "tools/verify_apple_readiness.sh"
            for status in (0, 23):
                with self.subTest(readiness_exit=status):
                    readiness.write_text(f"exit {status}\n", encoding="utf-8")
                    script = "\n".join((
                        "set -Eeuo pipefail",
                        "print_redacted_command() { :; }",
                        "sanitize_apple_log_output() { cat; }",
                        "section() { :; }",
                        "WINS_PRE_RELEASE_SOURCE_SMOKE=0",
                        run_function.group(0),
                        gate,
                        "printf 'BUILD_REACHED\\n'",
                    ))
                    result = subprocess.run(
                        ["bash", "-c", script], cwd=root,
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertEqual("BUILD_REACHED" in result.stdout, status == 0)

    def test_flutter_347_macos_delegate_does_not_call_missing_super_selector(self) -> None:
        delegate = (ROOT / "macos/Runner/AppDelegate.swift").read_text(encoding="utf-8")
        self.assertIn("override func applicationDidFinishLaunching", delegate)
        self.assertNotIn("super.applicationDidFinishLaunching", delegate)

        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("WINS_MACOS_XCTEST_DERIVED_DATA", readiness)
        self.assertIn("winsvpn-macos-xctest-readiness.XXXXXX", readiness)
        self.assertIn('"${MACOS_XCTEST_TMP:-}"', readiness)
        self.assertIn('-derivedDataPath "${macos_xctest_derived_data}"', readiness)

    def test_reviewed_apple_toolchains_are_discovered_and_fail_closed(self) -> None:
        paths = (
            ROOT / "tools/build_apple_release_candidates.sh",
            ROOT / "tools/apple_runtime_smoke.sh",
            ROOT / "tools/verify_apple_readiness.sh",
        )
        for path in paths:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("/Users/winsvpn/development/flutter", text)
            # The gates MUST read the reviewed toolchain from
            # tools/toolchain-pins.json at run time. A bare literal that agrees
            # today would silently desynchronise the Apple builds on the next
            # pin bump, which is the defect this wiring exists to remove.
            self.assertIn("read_wins_toolchain_pin", text)
            self.assertIn("tools/toolchain-pins.json", text)
            self.assertIn(
                'REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"',
                text,
            )
            self.assertIn(
                'REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"',
                text,
            )
            self.assertNotIn('REQUIRED_FLUTTER_VERSION="3.44.6"', text)
            self.assertIn("Library/Application Support/WinsVPN/toolchains/flutter-", text)
            self.assertIn("resolve_reviewed_flutter_bin", text)

        for path in paths[1:]:
            text = path.read_text(encoding="utf-8")
            self.assertIn('PATH="${flutter_dir}:${PATH}"', text)
            self.assertIn(
                'REQUIRED_COCOAPODS_VERSION="$(read_wins_toolchain_pin tools.cocoapods.version)"',
                text,
            )
            self.assertNotIn('REQUIRED_COCOAPODS_VERSION="1.16.2"', text)
            self.assertIn("resolve_reviewed_pod_bin", text)
            self.assertIn("Gem.user_dir", text)
            self.assertIn("require_reviewed_cocoapods", text)
            self.assertIn('PATH="${pod_dir}:${PATH}"', text)

    def test_apple_gates_resolve_the_manifest_pins_at_runtime(self) -> None:
        manifest = json.loads(
            (ROOT / "tools/toolchain-pins.json").read_text(encoding="utf-8")
        )
        expected = {
            "tools.flutter.version": manifest["tools"]["flutter"]["version"],
            "tools.flutter.revision": manifest["tools"]["flutter"]["revision"],
            "tools.cocoapods.version": manifest["tools"]["cocoapods"]["version"],
        }
        for rel in (
            "tools/build_apple_release_candidates.sh",
            "tools/apple_runtime_smoke.sh",
            "tools/verify_apple_readiness.sh",
        ):
            text = (ROOT / rel).read_text(encoding="utf-8")
            match = re.search(r"(?m)^read_wins_toolchain_pin\(\) \{", text)
            self.assertIsNotNone(match, f"{rel}: resolver not present")
            assert match is not None
            close = re.search(r"(?m)^\}$", text[match.start():])
            self.assertIsNotNone(close, f"{rel}: resolver never closes")
            assert close is not None
            resolver = text[match.start(): match.start() + close.start() + 1]
            env = dict(os.environ, ROOT=str(ROOT), ROOT_DIR=str(ROOT), PYTHON_BIN="python3")
            for key, want in expected.items():
                script = resolver + f"\nread_wins_toolchain_pin {key}\n"
                completed = subprocess.run(
                    ["bash", "-c", script],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                got = completed.stdout.strip()
                self.assertEqual(
                    (completed.returncode, got),
                    (0, want),
                    f"{rel}: {key} resolved {got!r}; manifest says {want!r}. "
                    f"A resolver that returns the wrong value means the gate "
                    f"enforces a different toolchain than the manifest pins.",
                )

    def test_clean_checkout_bootstraps_pods_before_native_xctests(self) -> None:
        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(
            encoding="utf-8"
        )
        pub_get = readiness.index('"${FLUTTER_BIN}" pub get')
        platform_precache = readiness.index(
            '"${FLUTTER_BIN}" precache --ios --macos', pub_get
        )
        ios_pods = readiness.index(
            '"${POD_BIN}" install --deployment', platform_precache
        )
        macos_pods = readiness.index(
            '"${POD_BIN}" install --deployment', ios_pods + 1
        )
        macos_xctest_config = readiness.index(
            '"${FLUTTER_BIN}" build macos --debug --config-only', macos_pods
        )
        flutter_inputs = readiness.index(
            "test -f macos/Flutter/ephemeral/FlutterInputs.xcfilelist",
            macos_xctest_config,
        )
        flutter_outputs = readiness.index(
            "test -f macos/Flutter/ephemeral/FlutterOutputs.xcfilelist",
            flutter_inputs,
        )
        native_xctest = readiness.index(
            '"${XCODE_TOOLCHAIN_BIN}/xcodebuild" -quiet test', flutter_outputs
        )
        self.assertLess(pub_get, ios_pods)
        self.assertLess(pub_get, platform_precache)
        self.assertLess(platform_precache, ios_pods)
        self.assertLess(ios_pods, macos_pods)
        self.assertLess(macos_pods, macos_xctest_config)
        self.assertLess(macos_xctest_config, flutter_inputs)
        self.assertLess(flutter_inputs, flutter_outputs)
        self.assertLess(flutter_outputs, native_xctest)

        self.assertIn("**/Pods/", (ROOT / "ios/.gitignore").read_text())
        self.assertIn("**/Pods/", (ROOT / "macos/.gitignore").read_text())

        section_cleanup = readiness[readiness.index("run_section() {") :]
        for temp_name in (
            "IOS_XCTEST_TMP",
            "WATCHOS_XCTEST_TMP",
            "MACOS_XCTEST_TMP",
        ):
            self.assertIn(
                f'"${{{temp_name}:-}}"',
                section_cleanup,
                f"isolated Apple XCTest sections must clean {temp_name} locally",
            )

        runtime = (ROOT / "tools/apple_runtime_smoke.sh").read_text(
            encoding="utf-8"
        )
        runtime_main = runtime.index(
            'rerun_macos_pkg_install_lane_as_user_if_root "$@"'
        )
        flutter_guard = runtime.index(
            "require_reviewed_flutter_toolchain", runtime_main
        )
        pods_guard = runtime.index("require_reviewed_cocoapods", flutter_guard)
        signed_prereqs = runtime.index(
            "require_requested_signed_prereqs", pods_guard
        )
        keychain_probe = runtime.index("apple_signing_keychain_probe", signed_prereqs)
        runtime_report = runtime.index("runtime_preflight_report", keychain_probe)
        preflight_exit = runtime.index(
            'if [[ "${WINS_PREFLIGHT_ONLY}" == "1" ]]', runtime_report
        )
        readiness_gate = runtime.index(
            "run bash tools/verify_apple_readiness.sh", preflight_exit
        )
        self.assertLess(flutter_guard, pods_guard)
        self.assertLess(pods_guard, signed_prereqs)
        self.assertLess(signed_prereqs, keychain_probe)
        self.assertLess(keychain_probe, runtime_report)
        self.assertLess(runtime_report, preflight_exit)
        self.assertLess(preflight_exit, readiness_gate)

        runtime_main_tail = runtime[runtime_main:]
        self.assertEqual(runtime_main_tail.count("require_requested_signed_prereqs"), 1)

        website_audit = (ROOT / "tools/website_security_audit.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("Website security self-test passed", website_audit)
        self.assertIn(
            "grep -q 'Website security self-test passed' "
            "tools/website_security_audit.py",
            readiness,
        )
        self.assertNotIn("Apple public release gate self-test passed", readiness)
        self.assertIn(
            "grep -Fq '\"${POD_BIN}\" install --deployment' "
            "tools/apple_runtime_smoke.sh",
            readiness,
        )
        self.assertNotIn(
            "grep -q 'pod install' tools/apple_runtime_smoke.sh", readiness
        )

    def test_release_candidate_producer_owns_lock_index_and_receipts(self) -> None:
        text = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        main = text.index('RELEASE_INDEX="$(resolve_repo_file')
        lock = text.index("acquire_release_build_lock", main)
        begin = text.index("begin_receipts", lock)
        build = text.index('/bin/bash "${APPLE_RUNTIME}"', begin)
        post_index = text.index(
            '/bin/bash "${DEPENDENCY_FREEZE}" verify-index', build
        )
        finish_ios = text.index('finish_receipt ios', post_index)
        finish_macos = text.index('finish_receipt macos', finish_ios)
        freeze = text.index("freeze_apple_release_candidates.py", finish_macos)
        self.assertLess(lock, begin)
        self.assertLess(begin, build)
        self.assertLess(build, post_index)
        self.assertLess(post_index, finish_ios)
        self.assertLess(finish_ios, finish_macos)
        self.assertLess(finish_macos, freeze)
        for marker in (
            "IOS_BUILD_BEGIN.json",
            "MACOS_BUILD_BEGIN.json",
            "IOS_BUILD_RECEIPT.json",
            "MACOS_BUILD_RECEIPT.json",
            "--producer tools/apple_runtime_smoke.sh",
            "verify-receipt",
            'REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"',
            'REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"',
            "No upload or App Review mutation occurred.",
            'RUN_LOG="${RECEIPT_DIR}/APPLE_ARCHIVE_EXPORT.log"',
            'VERIFICATION_LOG="${RECEIPT_DIR}/APPLE_CANDIDATE_VERIFICATION.log"',
            '--receipt-directory "${RECEIPT_DIR}"',
            '--release-input-index "${RELEASE_INDEX}"',
            '--ios-build-receipt "${IOS_RECEIPT}"',
            '--macos-build-receipt "${MACOS_RECEIPT}"',
        ):
            self.assertIn(marker, text)

    def test_candidate_freeze_hash_binds_owner_only_durable_receipt_logs(self) -> None:
        freeze = (ROOT / "tools/freeze_apple_release_candidates.py").read_text(
            encoding="utf-8"
        )
        validator = (ROOT / "tools/validate_apple_submission_package.py").read_text(
            encoding="utf-8"
        )
        for marker in (
            "require_owner_only_artifacts_path",
            "require_receipt_log",
            "require_build_receipt",
            "verify_build_receipt",
            '"archive_export_log_sha256": sha256_file(archive_log)',
            '"verification_log_sha256": sha256_file(verification_log)',
            '"build_receipt_sha256": str(build_receipt_result["receipt_sha256"])',
            '"release_input_index_sha256": sha256_file(release_input_index)',
            'parser.add_argument("--receipt-directory", required=True)',
            'parser.add_argument("--release-input-index", required=True)',
            'parser.add_argument("--ios-build-receipt", required=True)',
            'parser.add_argument("--macos-build-receipt", required=True)',
        ):
            self.assertIn(marker, freeze)
        for marker in (
            "require_durable_receipt_evidence_file",
            'artifact.get("archive_export_log_sha256")',
            'artifact.get("verification_log_sha256")',
            "validate_formal_build_receipt_binding",
            'artifact.get("build_receipt_sha256")',
            "archive_export_log must prove two successful archives",
            "archive_export_log must prove two successful exports",
        ):
            self.assertIn(marker, validator)
        self.assertNotIn("must be an absolute /tmp/wins_* path", freeze)

    def test_receipt_binding_failure_cannot_advance_canonical_manifest(self) -> None:
        freezer = load_module(
            "wins_apple_receipt_atomicity",
            "tools/freeze_apple_release_candidates.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            artifacts_root = root / ".artifacts"
            receipt_dir = artifacts_root / "apple-build"
            index_dir = artifacts_root / "release-index"
            receipt_dir.mkdir(parents=True, mode=0o700)
            index_dir.mkdir(parents=True, mode=0o700)
            artifacts_root.chmod(0o700)
            receipt_dir.chmod(0o700)
            index_dir.chmod(0o700)

            ios_relative = pathlib.Path("build/apple/ios.ipa")
            macos_relative = pathlib.Path("build/apple/macos.pkg")
            ios_artifact = root / ios_relative
            macos_artifact = root / macos_relative
            ios_artifact.parent.mkdir(parents=True)
            ios_artifact.write_bytes(b"ios-candidate")
            macos_artifact.write_bytes(b"macos-candidate")

            release_index = index_dir / "RELEASE_INPUT_INDEX.json"
            ios_receipt = receipt_dir / "IOS_BUILD_RECEIPT.json"
            macos_receipt = receipt_dir / "MACOS_BUILD_RECEIPT.json"
            archive_log = receipt_dir / "APPLE_ARCHIVE_EXPORT.log"
            verification_log = receipt_dir / "APPLE_CANDIDATE_VERIFICATION.log"
            privacy_inventory = receipt_dir / "APPLE_ARCHIVE_PRIVACY_INVENTORY.json"
            for path in (
                release_index,
                ios_receipt,
                macos_receipt,
                archive_log,
                verification_log,
                privacy_inventory,
            ):
                path.write_text("fixture\n", encoding="utf-8")
                path.chmod(0o600)
                anchor = path.with_name(path.name + ".sha256")
                if path in (release_index, ios_receipt, macos_receipt):
                    anchor.write_text("0" * 64 + f"  {path.name}\n", encoding="utf-8")
                    anchor.chmod(0o600)

            manifest_path = root / "app_store/apple/artifacts/release_candidate.json"
            manifest_path.parent.mkdir(parents=True)
            original = b'{"canonical":"old"}\n'
            manifest_path.write_bytes(original)

            args = SimpleNamespace(
                ios_artifact=ios_relative.as_posix(),
                macos_artifact=macos_relative.as_posix(),
                receipt_directory=str(receipt_dir),
                release_input_index=str(release_index),
                ios_build_receipt=str(ios_receipt),
                macos_build_receipt=str(macos_receipt),
                archive_export_log=str(archive_log),
                verification_log=str(verification_log),
                archive_privacy_inventory=str(privacy_inventory),
            )

            def receipt_result(repo, index, platform, receipt, artifact):
                return {
                    "platform": platform,
                    "receipt_sha256": freezer.sha256_file(receipt),
                    "artifact_sha256": freezer.sha256_file(artifact),
                    "artifact_size_bytes": artifact.stat().st_size,
                    "artifact_input_fingerprint_sha256": "a" * 64,
                    "platform_manifest_sha256": "b" * 64,
                }

            for failing_platform in ("ios", "macos"):
                manifest_path.write_bytes(original)

                def verify(repo, index, platform, receipt, artifact):
                    if platform == failing_platform:
                        raise freezer.FreezeError(
                            f"injected {platform} receipt binding failure"
                        )
                    return receipt_result(repo, index, platform, receipt, artifact)

                with mock.patch.object(
                    freezer, "ROOT", root
                ), mock.patch.object(
                    freezer, "ARTIFACT_MANIFEST", manifest_path
                ), mock.patch.object(
                    freezer, "require_archive_export_markers"
                ), mock.patch.object(
                    freezer, "verify_build_receipt", side_effect=verify
                ):
                    with self.assertRaisesRegex(
                        freezer.FreezeError,
                        f"injected {failing_platform} receipt binding failure",
                    ):
                        freezer.freeze(args)
                self.assertEqual(manifest_path.read_bytes(), original)

    def test_durable_receipt_evidence_rejects_temp_symlink_and_open_modes(self) -> None:
        validator = load_module(
            "wins_apple_durable_evidence",
            "tools/validate_apple_submission_package.py",
        )
        # A private repository root: the live checkout's .artifacts mode is
        # whatever an earlier suite left (Path.mkdir(parents=True) gives new
        # parents the umask default), so the fixture must not depend on it.
        with tempfile.TemporaryDirectory(prefix="apple-durable-evidence-") as temporary:
            root = pathlib.Path(temporary)
            artifacts_root = root / ".artifacts"
            artifacts_root.mkdir(mode=0o700)
            artifacts_root.chmod(0o700)
            receipt = artifacts_root / "apple-build-fixture"
            receipt.mkdir(mode=0o700)
            receipt.chmod(0o700)
            evidence = receipt / "verification.log"
            evidence.write_text("proof\n", encoding="utf-8")
            evidence.chmod(0o600)
            relative = evidence.relative_to(root).as_posix()
            with mock.patch.object(validator, "ROOT", root):
                self.assertEqual(
                    validator.require_durable_receipt_evidence_file(relative, "fixture"),
                    evidence,
                )
                with self.assertRaisesRegex(AssertionError, "repository-relative"):
                    validator.require_durable_receipt_evidence_file(
                        "/tmp/wins_ephemeral.log", "fixture"
                    )

                artifacts_root.chmod(0o755)
                with self.assertRaisesRegex(AssertionError, "owner-only"):
                    validator.require_durable_receipt_evidence_file(relative, "fixture")
                artifacts_root.chmod(0o700)

                evidence.chmod(0o640)
                with self.assertRaisesRegex(AssertionError, "owner-only"):
                    validator.require_durable_receipt_evidence_file(relative, "fixture")
                evidence.chmod(0o600)

                alias = receipt / "verification-alias.log"
                try:
                    alias.symlink_to(evidence)
                except (OSError, NotImplementedError):
                    return
                with self.assertRaisesRegex(AssertionError, "symbolic link"):
                    validator.require_durable_receipt_evidence_file(
                        alias.relative_to(root).as_posix(), "fixture"
                    )

    def test_gui_rebuild_routes_through_receipt_owning_producer(self) -> None:
        text = (ROOT / "tools/run_apple_release_candidate_rebuild.applescript").read_text(
            encoding="utf-8"
        )
        self.assertIn("tools/build_apple_release_candidates.sh", text)
        self.assertIn('system attribute "WINS_RELEASE_INPUT_INDEX"', text)
        self.assertIn("WINS_APPLE_BUILD_RECEIPT_DIR=", text)
        self.assertNotIn("WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE=1", text)
        readiness = (ROOT / "tools/verify_apple_readiness.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "grep -q 'tools/build_apple_release_candidates.sh' "
            "tools/run_apple_release_candidate_rebuild.applescript",
            readiness,
        )
        self.assertNotIn(
            "grep -q 'tools/freeze_apple_release_candidates.py' "
            "tools/run_apple_release_candidate_rebuild.applescript",
            readiness,
        )

    def test_release_and_profile_emit_dsym_then_strip_all_local_symbols(self) -> None:
        for relative in (
            "ios/Runner.xcodeproj/project.pbxproj",
            "macos/Runner.xcodeproj/project.pbxproj",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertGreaterEqual(text.count('DEBUG_INFORMATION_FORMAT = "dwarf-with-dsym";'), 2)
            self.assertGreaterEqual(text.count("COPY_PHASE_STRIP = YES;"), 2)
            self.assertGreaterEqual(text.count("DEPLOYMENT_POSTPROCESSING = YES;"), 2)
            self.assertGreaterEqual(text.count("STRIP_INSTALLED_PRODUCT = YES;"), 2)
            self.assertGreaterEqual(text.count("STRIP_STYLE = all;"), 2)
            self.assertNotIn('STRIP_STYLE = "non-global";', text)
            self.assertIn("COPY_PHASE_STRIP = NO;", text, "Debug must retain symbols")

    def test_macos_app_pkg_minimum_os_follows_the_runner_deployment_target(self) -> None:
        project = (ROOT / "macos/Runner.xcodeproj/project.pbxproj").read_text(encoding="utf-8")
        targets = set(re.findall(r"MACOSX_DEPLOYMENT_TARGET = ([0-9.]+);", project))
        # 14.0 is the RunnerTests bundle; the shipped app and extension use 13.0.
        self.assertIn("13.0", targets)
        runtime = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        self.assertIn('os_version.attrib.get("min") != "13.0"', runtime)
        self.assertNotIn('os_version.attrib.get("min") != "11.0"', runtime)
        info = (ROOT / "macos/Runner/Info.plist").read_text(encoding="utf-8")
        self.assertNotIn("<key>LSMinimumSystemVersion</key>\n\t<string>11", info)

    def test_packet_tunnel_strip_all_keeps_exactly_the_dlsym_winn_abi(self) -> None:
        # STRIP_STYLE = all removes the export trie entries that dlsym needs unless strip
        # is told to keep them; the same list also limits what the linker exports.
        exports_path = "$(PROJECT_DIR)/../apple/WinsTunnelCore/WinnTunnelExports.exp"
        exported = [
            line.strip()
            for line in (ROOT / "apple/WinsTunnelCore/WinnTunnelExports.exp")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        swift = (ROOT / "apple/WinsTunnelCore/WinsWinn3Datapath.swift").read_text(encoding="utf-8")
        resolved = re.findall(r'static let \w+Symbol = "(\w+)"', swift)
        self.assertGreaterEqual(len(resolved), 7)
        for name in resolved:
            self.assertIn(f"_{name}", exported)
        # WinsWinn3.createSymbol lives in WinsWinn3HostContract.swift, and the
        # produced-artifact gate requires every REQUIRED_WINN3_SYMBOLS name in the
        # nm -gU output of the shipped PacketTunnel, so this list must cover both
        # and not only the seven names spelled in WinsWinn3Datapath.swift.
        host_contract = (ROOT / "apple/WinsTunnelCore/WinsWinn3HostContract.swift").read_text(
            encoding="utf-8"
        )
        created = re.findall(r'static let \w*[Cc]reate\w*Symbol = "(\w+)"', host_contract)
        self.assertIn("WinnTunnelCreateWinn3", created)
        for name in created:
            self.assertIn(f"_{name}", exported)
        verifier = load_module(
            "wins_ios_release_verifier_hardening",
            "tools/verify_ios_release_artifact.py",
        )
        self.assertGreaterEqual(len(verifier.REQUIRED_WINN3_SYMBOLS), 11)
        for name in sorted(verifier.REQUIRED_WINN3_SYMBOLS):
            self.assertIn(f"_{name}", exported, name)
        block_re = re.compile(
            r"\t\t[0-9A-F]{24} /\* (\w+) \*/ = \{\n\t\t\tisa = XCBuildConfiguration;(.*?)\n\t\t\};",
            re.DOTALL,
        )
        for relative in (
            "ios/Runner.xcodeproj/project.pbxproj",
            "macos/Runner.xcodeproj/project.pbxproj",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            packet = {
                match.group(1): match.group(2)
                for match in block_re.finditer(text)
                if '"-Wl,-u,_WinnTunnelContractVersion",' in match.group(2)
            }
            self.assertEqual(set(packet), {"Debug", "Release", "Profile"}, relative)
            for name, block in packet.items():
                self.assertEqual(
                    re.findall(r'"-Wl,-u,(_\w+)",', block), exported, f"{relative} {name}"
                )
                self.assertIn(f'"-Wl,-exported_symbols_list,{exports_path}",', block)
                self.assertNotIn("-Wl,-exported_symbol,", block)
            self.assertIn("STRIP_STYLE = all;", packet["Release"])
            stripflags = (
                f'STRIPFLAGS = (\n\t\t\t\t\t"-s",\n\t\t\t\t\t"{exports_path}",\n\t\t\t\t);'
            )
            # Profile has no target-level STRIP_STYLE or STRIP_INSTALLED_PRODUCT, so it
            # inherits the project-level STRIP_STYLE = all, STRIP_INSTALLED_PRODUCT = YES
            # and DEPLOYMENT_POSTPROCESSING = YES and strips too. Without the same retain
            # list a Profile PacketTunnel loses the export trie that WinsWinn3ABI.resolve
            # dlsyms, and Profile is what the physical-device live-tunnel smoke builds.
            for name in ("Release", "Profile"):
                self.assertIn(stripflags, packet[name], f"{relative} {name}")

    def test_release_apple_smoke_requires_compile_time_opt_in_and_no_bundled_pin(self) -> None:
        text = (ROOT / "lib/main.dart").read_text(encoding="utf-8")
        self.assertIn(
            "(kReleaseMode && !_appleLiveTunnelSmokeEnabled)",
            text,
        )
        gate = text.index("Future<bool> _shouldRunAppleLiveTunnelSmoke() async")
        request_read = text.index(
            "final request = await _readAppleLiveTunnelSmokeRequest();",
            gate,
        )
        release_guard = text.index(
            "(kReleaseMode && !_appleLiveTunnelSmokeEnabled)",
            gate,
        )
        self.assertLess(release_guard, request_read)
        pin_define = re.search(
            r"String\.fromEnvironment\(\s*'WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN',"
            r"\s*defaultValue: '([^']*)',\s*\)",
            text,
        )
        self.assertIsNotNone(pin_define)
        self.assertEqual(pin_define.group(1), "")
        self.assertIn(
            "throw StateError('apple_live_tunnel_smoke_pin_missing_or_invalid')",
            text,
        )
        self.assertNotIn("defaultValue: '8642'", text)
        self.assertNotIn("return pinPolicyRejectionReason(pin) == null ? pin : '830472'", text)

        runtime = (ROOT / "tools/apple_runtime_smoke.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN="${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN:-}"',
            runtime,
        )
        self.assertIn(
            "Apple distribution archives must not compile live-tunnel smoke defines.",
            runtime,
        )
        define_start = runtime.index("flutter_build_define_args() {")
        define_end = runtime.index("\nlog_winn3_descriptor_pubkey_status_for_defines() {", define_start)
        define_function = runtime[define_start:define_end]
        for distribution_flag in (
            "WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE",
            "WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE",
            "WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE",
            "WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE",
            "WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE",
            "WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE",
            "WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE",
        ):
            self.assertRegex(
                define_function,
                rf'\$\{{{distribution_flag}\}}" == "1"',
            )
        refusal = define_function.index(
            "Apple distribution archives must not compile live-tunnel smoke defines."
        )
        self.assertLess(
            define_function.index('${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1"'),
            refusal,
        )

        producer = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("WINS_APPLE_LIVE_TUNNEL_SMOKE=0", producer)
        self.assertIn("WINS_IOS_LIVE_TUNNEL_SMOKE=0", producer)

    def test_go_bridge_has_reproducible_reviewed_flags_and_export_gate(self) -> None:
        text = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        self.assertIn('APPLE_WG_GO_REPRODUCIBLE_GOFLAGS="-mod=readonly -trimpath -buildvcs=false"', text)
        self.assertIn('APPLE_WG_GO_REVIEWED_LDFLAGS="-s -w -buildid="', text)
        flags = text.split("apple_wg_go_flags() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('"${APPLE_WG_GO_REPRODUCIBLE_GOFLAGS}"', flags)
        self.assertIn('"${APPLE_WG_GO_REVIEWED_LDFLAGS}"', flags)
        # The real build environment takes its GOFLAGS only from the reviewed set.
        self.assertIn('"GOFLAGS=$(apple_wg_go_flags)"', text)
        self.assertNotIn('GOFLAGS="${PATCHED_GOFLAGS}${GOFLAGS:+ ${GOFLAGS}}"', text)
        self.assertNotIn("${GOFLAGS:+", text)
        hostile = text.split("reject_hostile_go_environment() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("for name in GOFLAGS GOWORK GOPROXY GOSUMDB GOEXPERIMENT; do", hostile)
        self.assertIn('validate_symbols "${archive}"', text)

    def test_go_bridge_never_trusts_ambient_go(self) -> None:
        """H-5: release builds take Go only from WINS_RELEASE_GO_ROOT (extracted
        by tools/winn_release.py prepare-go) and re-measure bin/go and the whole
        install tree against the pins before and after the build. No PATH go,
        no caller-supplied GO_BIN, and no WINS_RELEASE_GO executable export."""
        text = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        self.assertNotIn("find_go_bin", text)
        self.assertNotIn("command -v go", text)
        self.assertNotIn('GO_BIN="${GO_BIN:-', text)
        self.assertNotIn(": ${GO_BIN:=", text)

        self.assertIn('REVIEWED_GO_VERSION="1.27.1"', text)
        self.assertIn(
            'REVIEWED_GO_DARWIN_ARM64_SHA256="ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"',
            text,
        )
        self.assertIn(
            'REVIEWED_GO_DARWIN_AMD64_SHA256="8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"',
            text,
        )
        prepare = text.split("prepare_reviewed_go() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('[[ -z "${WINS_RELEASE_GO:-}" ]]', prepare)
        self.assertIn('go_root="${WINS_RELEASE_GO_ROOT:-}"', prepare)
        self.assertIn('[[ "${canonical}" == "${go_root}" ]]', prepare)
        self.assertIn('GO_BIN="${go_root}/bin/go"', prepare)
        self.assertIn('verify_reviewed_go_root "before build"', prepare)
        self.assertIn('"go version go${REVIEWED_GO_VERSION} darwin/arm64"', prepare)
        self.assertLess(
            prepare.index('GO_BIN="${go_root}/bin/go"'),
            prepare.index('verify_reviewed_go_root "before build"'),
        )
        verify = text.split("verify_reviewed_go_root() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(
            'require_sha256 "${GO_BIN}" "${REVIEWED_GO_DARWIN_ARM64_EXECUTABLE_SHA256}"',
            verify,
        )
        self.assertIn("digest --kind go-tree", verify)
        self.assertIn('"${REVIEWED_GO_DARWIN_ARM64_TREE_SHA256}"', verify)
        main_body = text.split("\nmain() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('verify_reviewed_go_root "after build"', main_body)
        ensure_tools_body = text.split("ensure_tools() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("prepare_reviewed_go", ensure_tools_body)
        self.assertNotIn("find_go_bin", ensure_tools_body)

    def test_go_bridge_reviewed_go_workdir_is_cleaned_up_safely(self) -> None:
        """The private per-run Go HOME/GOPATH/GOCACHE live under a mode-0700
        mktemp directory that the cleanup trap removes only when it still
        matches the fixed prefix, never a blanket rm -rf of an arbitrary path."""
        text = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        self.assertIn(
            'REVIEWED_GO_WORK_ROOT="$(mktemp -d "/private/tmp/wins-apple-reviewed-go.XXXXXX")"',
            text,
        )
        self.assertIn('chmod 700 "${REVIEWED_GO_WORK_ROOT}"', text)
        self.assertIn("trap cleanup_patch_work_root EXIT", text)
        cleanup_body = text.split("cleanup_patch_work_root() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("/private/tmp/wins-apple-reviewed-go.*)", cleanup_body)
        self.assertIn('rm -rf "${REVIEWED_GO_WORK_ROOT}"', cleanup_body)
        self.assertIn('die "Refusing to remove an unsafe reviewed-Go work root."', cleanup_body)
        self.assertLess(
            cleanup_body.index("/private/tmp/wins-apple-reviewed-go.*)"),
            cleanup_body.index('rm -rf "${REVIEWED_GO_WORK_ROOT}"'),
        )

    def test_flutter_resolution_rejects_symlinks_and_shell_functions(self) -> None:
        """A Flutter binary resolved from a configured path, the reviewed
        toolchain directory, or ambient PATH must be a real, on-disk regular
        executable file -- never a symlink, alias, or shell function -- so
        the exact version+revision check afterward actually binds to one
        concrete file, not to whatever a substituted `flutter` reports."""
        text = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("resolve_real_executable() {", text)
        helper_body = text.split("resolve_real_executable() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("realpath -e --", helper_body)
        self.assertIn("! -L", helper_body, "must explicitly reject symlinks")
        self.assertIn("-f", helper_body)
        self.assertIn("-x", helper_body)

        resolve_body = text.split(
            "resolve_reviewed_flutter_bin() {", 1
        )[1].split("\n}\n", 1)[0]
        # Every candidate path this function can return must go through the
        # hardened resolver -- none of its three branches (configured
        # FLUTTER_BIN, the pinned toolchain directory, or ambient PATH) may
        # fall back to a bare -x check.
        self.assertEqual(resolve_body.count("resolve_real_executable"), 4)
        self.assertNotIn("[[ -x \"${configured}\" ]]", resolve_body)
        self.assertNotIn("[[ -x \"${candidate}\" ]]", resolve_body)

    def test_xcodebuild_resolution_rejects_symlinks_and_shell_functions(self) -> None:
        """xcodebuild used to be existence-checked only (`command -v
        xcodebuild`), with no proof the reported version/build metadata --
        recorded into the build receipt and used nowhere else for
        enforcement -- came from a real, on-disk regular executable file
        rather than a symlink, alias, or shell function. It now goes
        through the same resolve_real_executable() helper already used for
        Flutter, and the actual invocation uses the resolved path."""
        text = (ROOT / "tools/build_apple_release_candidates.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'XCODEBUILD_BIN="$(resolve_real_executable "${XCODEBUILD_PATH}")"', text
        )
        self.assertIn('XCODE_REPORT="$("${XCODEBUILD_BIN}" -version)"', text)
        self.assertNotIn("command -v xcodebuild >/dev/null", text)
        self.assertNotIn('XCODE_REPORT="$(xcodebuild -version)"', text)

    def test_engine_wrapper_toolchain_resolution_rejects_symlinks(self) -> None:
        """clang/nm/vtool/lipo/ar/otool used to be resolved fresh via a bare
        `xcrun <tool>` at every call site -- existence-checked once via
        `xcrun -f <tool>` at preflight, then never verified again, with no
        proof any later call landed on the same real, on-disk regular file.
        Since this script compiles and inspects the shipped engine dylibs,
        each tool is now resolved and verified exactly once in
        ensure_tools(), and every call site uses that one resolved path."""
        text = (ROOT / "tools/build_apple_engine_wrappers.sh").read_text(
            encoding="utf-8"
        )
        ensure_tools_body = text.split("ensure_tools() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        # This used to be `assertIn("realpath -e --", ensure_tools_body)`.
        # That assertion had two faults and failed on both counts.
        #
        # 1. It pinned WHERE the text lives, not what the script does. The
        #    realpath call was factored out into resolve_real_file(), which
        #    ensure_tools() calls -- the hardening is intact, the literal
        #    simply moved one function away, and the test went red on a
        #    refactor that changed no behaviour.
        # 2. `-e` is not the load-bearing part on the only platform this
        #    script runs on. macOS /bin/realpath rejects `-e` outright
        #    ("illegal option -- e"), so on this host the `realpath -e --`
        #    line always fails and the plain `realpath --` fallback is what
        #    actually resolves. A test that passes only when a no-op flag is
        #    present, and says nothing about the check that really runs, is
        #    not evidence.
        #
        # So assert the property instead, across both functions: every tool is
        # resolved through the helper, the helper resolves through realpath
        # (keeping the GNU `-e` form for Linux CI, where it does bind), and
        # the resolved path is proved to be a real, executable, non-symlink
        # regular file before anything uses it. That last conjunction is what
        # actually rejects a symlink, alias or shadowing shell function, and
        # the old assertion never checked it was still there.
        self.assertIn('resolved="$(resolve_real_file "${candidate}"', ensure_tools_body)
        self.assertIn(
            '[[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" '
            '&& ! -L "${resolved}" ]]',
            ensure_tools_body,
        )
        resolve_real_file_body = text.split("resolve_real_file() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        self.assertIn("realpath -e --", resolve_real_file_body)
        self.assertIn("realpath --", resolve_real_file_body)
        # The helper must fail closed. If it ever returned 0 with empty
        # output, the conjunction above would still reject it via -f, but the
        # die() message would name the wrong cause; more importantly a helper
        # that cannot fail is a helper that cannot be trusted to have run.
        self.assertIn("return 1", resolve_real_file_body)
        self.assertIn("clang nm vtool lipo ar otool", ensure_tools_body)
        for tool, var in (
            ("clang", "CLANG_BIN"),
            ("nm", "NM_BIN"),
            ("vtool", "VTOOL_BIN"),
            ("lipo", "LIPO_BIN"),
            ("ar", "AR_BIN"),
            ("otool", "OTOOL_BIN"),
        ):
            self.assertIn(f'{tool}) {var}="${{resolved}}" ;;', ensure_tools_body)
            # Every actual invocation must use the resolved variable, not a
            # fresh `xcrun <tool>` call re-resolved at that call site.
            self.assertNotIn(f"xcrun {tool} ", text)
            self.assertNotIn(f"xcrun -f {tool}\n", text)
            self.assertIn(f'"${{{var}}}"', text)

    def test_go_bridge_sets_gotoolchain_local(self) -> None:
        """H-5 follow-up gap 1: without GOTOOLCHAIN=local, Go's default
        GOTOOLCHAIN=auto lets a go.mod `go`/`toolchain` directive in
        amneziawg-apple, the hostname-safe amnezia-xray-core replacement
        module, or any transitive dependency silently download and re-exec
        an *unverified* newer toolchain over the network. Every Go invocation
        in this producer runs under `env -i` with GOTOOLCHAIN=local: the
        reviewed_go wrapper (module, list, version calls) and the build pass."""
        text = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        wrapper = text.split("\nreviewed_go() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("/usr/bin/env -i", wrapper)
        self.assertIn('"GOTOOLCHAIN=local"', wrapper)
        self.assertIn('"GOENV=off"', wrapper)
        self.assertIn('"GOWORK=off"', wrapper)
        self.assertIn('"${GO_BIN:?}" "$@"', wrapper)
        self.assertEqual(text.count('"GOTOOLCHAIN=local"'), text.count("/usr/bin/env -i \\\n    \"HOME=${REVIEWED_GO_HOME:?}\" \\\n    \"PATH=${WINS_RELEASE_GO_ROOT:?}/bin"))
        self.assertGreaterEqual(text.count('"GOTOOLCHAIN=local"'), 2)
        self.assertNotIn("GOTOOLCHAIN=auto", text)
        ensure_tools_body = text.split("ensure_tools() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(
            ensure_tools_body.index("prepare_reviewed_go"),
            ensure_tools_body.index("reviewed_go '' version"),
        )

    def test_go_bridge_runs_embedded_runtime_gate_after_building_before_packaging(
        self,
    ) -> None:
        """H-5 follow-up gap 2: Final Recommendations.md's exact fix text
        for this script says to 'run the embedded-runtime gate on the
        finished slices before packaging.' build_apple_wg_go_bridge.sh must
        call tools/verify_embedded_engine_runtime_versions.py itself, after
        all three platform slices are built and before it reports
        completion -- build_apple_engine_wrappers.sh (which links the
        slices into wrapper dylibs later staged into the Xcode project)
        only runs after this script returns, so this is the last point
        where a stale/unpinned slice can still be caught before packaging."""
        text = (ROOT / "tools/build_apple_wg_go_bridge.sh").read_text(encoding="utf-8")
        gate_invocation = (
            'python3 "${PROJECT_ROOT}/tools/verify_embedded_engine_runtime_versions.py"'
        )
        self.assertIn("run_embedded_runtime_gate", text)
        self.assertIn(gate_invocation, text)

        gate_body = text.split("run_embedded_runtime_gate() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn(gate_invocation, gate_body)
        self.assertIn(
            "die ",
            gate_body,
            "a failed gate must abort the build (die), not just print a warning",
        )

        main_body = text.split("\nmain() {", 1)[1].split("\n}\n", 1)[0]
        macosx = main_body.index("build_platform macosx")
        iphoneos = main_body.index("build_platform iphoneos")
        iphonesimulator = main_body.index("build_platform iphonesimulator")
        gate_call = main_body.index("run_embedded_runtime_gate")
        complete_message = main_body.index("Apple Go bridge build complete")
        self.assertLess(macosx, iphoneos)
        self.assertLess(iphoneos, iphonesimulator)
        self.assertLess(
            iphonesimulator,
            gate_call,
            "the runtime gate must run after all three slices are built",
        )
        self.assertLess(
            gate_call,
            complete_message,
            "the build must not be reported complete until the runtime gate passes",
        )

    def test_embedded_runtime_gate_recognizes_apple_wg_go_bridge_slices(self) -> None:
        """H-5 follow-up gap 2, Python half: extend
        tools/verify_embedded_engine_runtime_versions.py itself to actually
        recognize and version-check the Apple libwg-go.a slices
        build_apple_wg_go_bridge.sh produces, using the same
        go-version-detection technique already proven for the Windows/
        Android binaries (go version -m, falling back to a buildinfo string
        scan). Apple slices are gitignored build output, not files
        committed to the repo, so (like the existing Android jniLibs
        handling) they must be optional-if-present, never unconditionally
        required -- every other caller of this gate (Windows/Linux/Android
        release scripts) must keep passing on a checkout that never ran an
        Apple build."""
        gate = load_module(
            "wins_embedded_engine_runtime_gate",
            "tools/verify_embedded_engine_runtime_versions.py",
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)

            with mock.patch.object(gate, "ROOT", root):
                # No Apple build has ever run in this checkout: must not
                # invent a requirement out of thin air.
                self.assertEqual(gate._apple_wg_go_bridge_candidates(), [])

                output_dir = root / ".artifacts" / "apple-wg-go"
                fresh = (
                    b"\xfa\xed\xfe\xcf" + b"\x00" * 16 + b"\x00go1.27.1\x00" + b"filler" * 20
                )
                stale = (
                    b"\xfa\xed\xfe\xcf" + b"\x00" * 16 + b"\x00go1.24.4\x00" + b"filler" * 20
                )

                for platform in ("macosx", "iphoneos", "iphonesimulator"):
                    platform_dir = output_dir / platform
                    platform_dir.mkdir(parents=True)
                    (platform_dir / "libwg-go.a").write_bytes(fresh)

                candidates = gate._apple_wg_go_bridge_candidates()
                self.assertEqual(len(candidates), 3)
                labels = {c.label for c in candidates}
                self.assertTrue(
                    all("Apple" in label and "libwg-go.a" in label for label in labels)
                )
                # A fresh, current-enough embedded Go version must pass.
                for engine in candidates:
                    self.assertIsNone(gate.check_binary(engine))

                # Now regress just the iphoneos slice to an old Go version
                # and confirm the gate actually catches it, identifying the
                # specific failing platform slice.
                (output_dir / "iphoneos" / "libwg-go.a").write_bytes(stale)
                candidates = gate._apple_wg_go_bridge_candidates()
                errors = [gate.check_binary(engine) for engine in candidates]
                errors = [error for error in errors if error is not None]
                self.assertEqual(len(errors), 1)
                self.assertIn("iphoneos", errors[0])
                self.assertIn("go1.24.4", errors[0])
                self.assertIn("go1.27.1", errors[0])
                self.assertIn("requires exactly reviewed Go", errors[0])

                (output_dir / "iphoneos" / "libwg-go.a").write_bytes(fresh)
                (output_dir / "macosx" / "libwg-go.a").write_bytes(
                    b"\xfa\xed\xfe\xcf" + b"\x00" * 16 + b"\x00go1.27.2\x00" + b"filler" * 20
                )
                candidates = gate._apple_wg_go_bridge_candidates()
                errors = [gate.check_binary(engine) for engine in candidates]
                errors = [error for error in errors if error is not None]
                self.assertEqual(len(errors), 1)
                self.assertIn("macosx", errors[0])
                self.assertIn("go1.27.2", errors[0])
                self.assertIn("requires exactly reviewed Go go1.27.1", errors[0])

    def test_final_export_lanes_collect_exact_artifact_symbols(self) -> None:
        text = (ROOT / "tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
        self.assertIn("tools/apple_release_symbol_custody.py", text)
        self.assertIn(
            'record_apple_private_symbol_custody ios "${ipa_path}" "${archive_path}"',
            text,
        )
        self.assertIn(
            'record_apple_private_symbol_custody macos "${pkg_path}" "${archive_path}"',
            text,
        )
        self.assertIn('--private-root "${APPLE_RELEASE_SYMBOL_ROOT}"', text)

    def test_private_symbol_root_is_explicitly_ignored(self) -> None:
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/.artifacts/private-release-symbols/", text)

    def test_privacy_scanner_rejects_local_paths_and_defaults_to_ipa_pkg(self) -> None:
        privacy = load_module("wins_privacy", "tools/validate_release_artifact_privacy.py")
        with self.assertRaises(privacy.PrivacyError):
            privacy.reject_local_build_paths(
                "fixture", b"/Users/builder/Downloads/wins_vpn/ios/Runner.app"
            )
        with self.assertRaises(privacy.PrivacyError):
            privacy.reject_local_build_paths(
                "fixture", b"C:\\Users\\builder\\src\\wins_vpn\\macos\\Runner.app"
            )
        privacy.reject_local_build_paths(
            "fixture", b"Library/Group Containers/group.org.winsvpn.app/status.json"
        )
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            ipa = root / "WinsVPN.ipa"
            pkg = root / "WinsVPN.pkg"
            ipa.write_bytes(b"test-ipa")
            pkg.write_bytes(b"test-pkg")
            manifest = root / "APPLE_RELEASE_CANDIDATES.json"
            manifest.write_text(
                json.dumps(
                    {
                        "artifacts": [
                            {
                                "platform": "ios",
                                "path": ipa.name,
                                "size_bytes": ipa.stat().st_size,
                                "sha256": hashlib.sha256(ipa.read_bytes()).hexdigest(),
                            },
                            {
                                "platform": "macos",
                                "path": pkg.name,
                                "size_bytes": pkg.stat().st_size,
                                "sha256": hashlib.sha256(pkg.read_bytes()).hexdigest(),
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            apple = privacy.apple_default_artifacts(manifest, root)
            self.assertEqual([path.suffix.lower() for path in apple], [".ipa", ".pkg"])

    def test_privacy_scanner_expands_macos_pkg_payload(self) -> None:
        privacy = load_module("wins_pkg_privacy", "tools/validate_release_artifact_privacy.py")
        with tempfile.TemporaryDirectory() as temp_name:
            root = pathlib.Path(temp_name)
            payload = root / "Payload"
            leaked = b"/Users/release-builder/Downloads/wins_vpn/macos/Runner.app"
            info = tarfile.TarInfo("Wins VPN.app/Contents/MacOS/Wins VPN")
            info.size = len(leaked)
            with tarfile.open(payload, "w") as archive:
                archive.addfile(info, io.BytesIO(leaked))
            package = root / "WinsVPN.pkg"
            with tarfile.open(package, "w") as archive:
                archive.add(payload, arcname="org.winsvpn.app.pkg/Payload")
            with self.assertRaises(privacy.PrivacyError):
                privacy.validate_artifacts((package,), {})

    def test_symbol_custody_binds_original_paths_without_following(self) -> None:
        text = (ROOT / "tools/apple_release_symbol_custody.py").read_text(encoding="ascii")
        self.assertIn("O_NOFOLLOW", text)
        self.assertIn(".lstat(", text)
        self.assertNotIn("expanduser().resolve(strict=True)", text)

    def test_symbol_custody_self_test(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(ROOT / "tools/apple_release_symbol_custody.py"), "self-test"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("APPLE PRIVATE SYMBOL CUSTODY SELF-TEST: PASS", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
