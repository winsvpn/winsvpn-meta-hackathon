#!/usr/bin/env python3
"""Fail-closed source contracts for Android dual-engine release provenance."""

from __future__ import annotations

import json
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CURRENT_SIGNER = "4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
RETIRED_SIGNER = "542ea1881a4807643e071d4ee6f961f1cf5045412394943b8ad9896fd7e7adcb"
SIGNER_PATHS = (
    "tools/android_final_evidence_collector.py",
    "tools/android_fresh_release_regression.ps1",
    "tools/android_release_matrix_evidence.py",
    "tools/build_android_release.ps1",
    "tools/build_android_release_macos.sh",
)
AUTHENTICATED_PUBLICATION_COMMIT = (
    'wins_release_python_run "${PUBLICATION_TOOL}" commit'
)
RETIRED_PUBLICATION_COMMIT = '"${PYTHON_BIN}" "${PUBLICATION_TOOL}" commit'
PUBLICATION_TV_REQUIREMENTS = (
    '"${PREPARED_TV_APK_SYMBOLS}" "${ROOT_TV_APK_SYMBOLS}"',
    '"${PREPARED_TV_APK}" "${ROOT_TV_APK}"',
    'finish_receipt "${TV_APK_BEGIN}"',
)


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class AndroidReleaseProvenanceTest(unittest.TestCase):
    def test_release_producers_fail_closed_on_signers_alignment_and_exact_secrets(self) -> None:
        mac = source("tools/build_android_release_macos.sh")
        windows = source("tools/build_android_release.ps1")
        for text in (mac, windows):
            self.assertIn("verify_android_aab_page_alignment.py", text)
            self.assertIn("verify_android_aab_signers.py", text)
            self.assertIn("WINS_ANDROID_KEY_PASSWORD", text)
            self.assertIn("WINS_ANDROID_STORE_PASSWORD", text)
            self.assertIn("--secret-env", text)
            self.assertIn("-Werr", text)
            self.assertNotIn("-verify -strict", text)
            self.assertIn("verify_android_aab_signers.py", text)
        self.assertIn('ZIPALIGN="$(find_android_tool zipalign)"', mac)
        self.assertIn("-c -P 16 -v 4", mac)
        self.assertIn("Get-ZipAlign", windows)
        self.assertIn("exactly one signer certificate", windows)

    def test_every_invoked_aab_verifier_is_a_neutral_and_frozen_input(self) -> None:
        mac = source("tools/build_android_release_macos.sh")
        windows = source("tools/build_android_release.ps1")
        freeze = source("tools/release_dependency_freeze.py")
        for verifier in (
            "tools/verify_android_aab_page_alignment.py",
            "tools/verify_android_aab_signers.py",
        ):
            self.assertGreaterEqual(mac.count(verifier), 2)
            self.assertGreaterEqual(windows.replace("\\", "/").count(verifier), 2)
            self.assertIn(f'"{verifier}"', freeze)

    def assert_macos_publication_transaction(self, text: str) -> None:
        self.assertNotIn(RETIRED_PUBLICATION_COMMIT, text)
        self.assertEqual(text.count(AUTHENTICATED_PUBLICATION_COMMIT), 1)
        commit = text[text.index(AUTHENTICATED_PUBLICATION_COMMIT):]
        for required in PUBLICATION_TV_REQUIREMENTS:
            self.assertIn(required, commit)

    def test_macos_publication_transaction_includes_tv_artifact_and_symbols(self) -> None:
        mac = source("tools/build_android_release_macos.sh")
        self.assert_macos_publication_transaction(mac)
        bypassed = mac.replace(
            AUTHENTICATED_PUBLICATION_COMMIT,
            RETIRED_PUBLICATION_COMMIT,
            1,
        )
        self.assertNotEqual(bypassed, mac)
        with self.assertRaises(AssertionError):
            self.assert_macos_publication_transaction(bypassed)

    def test_operational_signer_pins_match_registered_play_upload_key(self) -> None:
        for path in SIGNER_PATHS:
            with self.subTest(path=path):
                text = source(path)
                self.assertIn(CURRENT_SIGNER, text)
                self.assertNotIn(RETIRED_SIGNER, text)
        declaration = source("docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md")
        normalized = re.sub(r"[^0-9a-f]", "", declaration.lower())
        self.assertIn(CURRENT_SIGNER, normalized)
        self.assertNotIn(RETIRED_SIGNER, normalized)

    def test_every_packaged_abi_has_an_explicit_goarch_mapping_and_inventory(self) -> None:
        stage = source("android/tools/prepare_android_winn_assets.sh")
        for mapping in (
            "arm64-v8a) printf 'arm64\\n'",
            "armeabi-v7a) printf 'arm\\n'",
            "x86_64) printf 'amd64\\n'",
        ):
            self.assertIn(mapping, stage)
        self.assertGreaterEqual(stage.count('goarch_for_abi "${abi}"'), 2)
        # The Winn engine for every packaged ABI comes out of a verified Winn
        # release (tools/winn_release.py), never a bare builder call.
        self.assertIn("RELEASE_DIR/artifacts/datapath-android-{arm64,arm,amd64}/${ENGINE_NAME} -> <tmp>/{arm64-v8a,armeabi-v7a,x86_64}/${ENGINE_NAME}", stage)
        self.assertIn("verify --release RELEASE_DIR --print-manifest", stage)
        self.assertIn("printf 'datapath-android-%s\\n' \"${goarch}\"", stage)
        self.assertIn("jniLibs/armeabi-v7a/{${ENGINE_NAME},${XRAY_ENGINE_NAME}}", stage)
        self.assertNotIn('bash "${BUILD_ENGINE}"', stage)
        self.assertIn("required standalone-v3 staged engine is missing", stage)

    def test_release_producers_gate_staged_winn_engines_after_freeze_verification(self) -> None:
        mac = source("tools/build_android_release_macos.sh")
        mac_start = mac.index("initialize_receipts()")
        mac_end = mac.index("snapshot_inputs()", mac_start)
        mac_init = mac[mac_start:mac_end]
        self.assertLess(
            mac_init.index("verify-index"),
            mac_init.index("run_reviewed_android_engine_freshness_gate"),
        )
        self.assertIn('/bin/bash "${WINN_ENGINE_SOURCE_GATE}" --verify', mac)

        windows = source("tools/build_android_release.ps1")
        win_start = windows.index("function Initialize-FormalBuildReceipts")
        win_end = windows.index("function Complete-FormalBuildReceipt", win_start)
        win_init = windows[win_start:win_end]
        self.assertLess(win_init.index("'verify-index'"), win_init.index("'--verify'"))
        self.assertIn("prepare_android_winn_assets.sh", win_init)

    def test_phone_debug_unit_test_classpaths_are_locked(self) -> None:
        lockfile = source("android/gradle/dependency-locking/app.lockfile")
        for configuration in (
            "phoneDebugUnitTestCompileClasspath",
            "phoneDebugUnitTestRuntimeClasspath",
            "phoneDebugUnitTestLintChecksClasspath",
        ):
            with self.subTest(configuration=configuration):
                self.assertIn(configuration, lockfile)
        gradle = source("android/build.gradle.kts") + source("android/app/build.gradle.kts")
        self.assertIn("lockAllConfigurations()", gradle)
        self.assertNotIn("deactivateDependencyLocking", gradle)

    def test_release_kotlin_stdlib_lock_matches_the_reviewed_plugin(self) -> None:
        # The expected stdlib is the reviewed Kotlin plugin pin, read from the
        # toolchain manifest, so a Kotlin bump without a regenerated lock is red.
        kotlin = json.loads(source("tools/toolchain-pins.json"))["tools"]["kotlin"][
            "version"
        ]
        self.assertEqual(kotlin, "2.4.20")
        expectations = {
            "android/gradle/dependency-locking/app.lockfile": (
                "phoneReleaseCompileClasspath",
                "tvReleaseCompileClasspath",
            ),
            "android/gradle/dependency-locking/jni.lockfile": (
                "releaseCompileClasspath",
            ),
            "android/gradle/dependency-locking/jni_flutter.lockfile": (
                "releaseCompileClasspath",
            ),
        }
        for path, configurations in expectations.items():
            with self.subTest(path=path):
                lines = source(path).splitlines()
                for configuration in configurations:
                    release_lines = [
                        line
                        for line in lines
                        if line.startswith("org.jetbrains.kotlin:kotlin-stdlib:")
                        and configuration in line.split("=", 1)[1].split(",")
                    ]
                    self.assertEqual(len(release_lines), 1)
                    self.assertTrue(
                        release_lines[0].startswith(
                            f"org.jetbrains.kotlin:kotlin-stdlib:{kotlin}="
                        ),
                        release_lines[0],
                    )

    def test_phone_and_tv_codes_follow_pubspec_build_number(self) -> None:
        pubspec = source("pubspec.yaml")
        match = re.search(r"^version:\s*[^+\s]+\+(\d+)\s*$", pubspec, re.MULTILINE)
        self.assertIsNotNone(match)
        build_number = int(match.group(1))
        gradle = source("android/app/build.gradle.kts")
        self.assertIn(f"versionCode = {build_number}", gradle)
        self.assertIn(f"versionCode = {build_number * 100 + 2}", gradle)


if __name__ == "__main__":
    unittest.main()
