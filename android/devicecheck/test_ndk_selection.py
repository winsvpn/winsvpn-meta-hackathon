#!/usr/bin/env python3
"""NDK custody tests for the intentionally disabled DeviceCheck producer.

The workspace shell is an authenticated, fail-closed owner gate. It must not
select or execute an SDK or NDK and cannot claim a physical build. Reviewed
NDK and Gradle facts are read only through devicecheck_build_receipt.py, which
descriptor-holds every fact input before parsing those facts.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


_RECEIPT_TOOL = Path(__file__).resolve().with_name("devicecheck_build_receipt.py")
_RECEIPT_SPEC = importlib.util.spec_from_file_location(
    "winsvpn_devicecheck_build_receipt_test_dependency",
    _RECEIPT_TOOL,
)
if _RECEIPT_SPEC is None or _RECEIPT_SPEC.loader is None:
    raise RuntimeError("cannot load exact DeviceCheck build-receipt dependency")
receipt = importlib.util.module_from_spec(_RECEIPT_SPEC)
sys.modules[_RECEIPT_SPEC.name] = receipt
_RECEIPT_SPEC.loader.exec_module(receipt)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "android" / "devicecheck" / "build_devicecheck.sh"
RECEIPT_TOOL = ROOT / "android" / "devicecheck" / "devicecheck_build_receipt.py"
DISABLED_MARKER = "# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1"
FINAL_BLOCKER = (
    "OWNER-BLOCKED: immutable compiler-input handoff is not implemented "
    "by the external controller/loader."
)
RETIRED_SUCCESS_KEYS = ("REVIEWED_NDK_VERSION", "NDK_BUILD")
AMBIENT_COMMANDS = (
    "adb",
    "clang",
    "cmake",
    "go",
    "gradle",
    "gradlew",
    "java",
    "ndk-build",
    "ninja",
    "sdkmanager",
)
FACT_INPUTS = (
    "android/app/build.gradle.kts",
    "android/devicecheck/app/build.gradle.kts",
    "android/devicecheck/build_devicecheck.sh",
    "android/devicecheck/devicecheck_build_receipt.py",
    "android/devicecheck/gradle/wrapper/gradle-wrapper.properties",
    "android/devicecheck/settings.gradle.kts",
)


def executable_lines(source: str) -> str:
    return "\n".join(
        line
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="ascii")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class DeviceCheckNdkSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        held = {
            relative: receipt.hold_relative_file(
                ROOT,
                relative,
                f"DeviceCheck NDK fact input {relative}",
                max_bytes=receipt.MAX_SOURCE_BYTES,
                capture=True,
            )
            for relative in FACT_INPUTS
        }
        cls.closure = receipt.SourceClosure(
            repo=ROOT,
            paths=FACT_INPUTS,
            held=held,
        )
        cls.script_source = cls.closure.text(
            "android/devicecheck/build_devicecheck.sh"
        )
        cls.receipt_source = cls.closure.text(
            "android/devicecheck/devicecheck_build_receipt.py"
        )
        cls.facts = receipt.build_facts(cls.closure)
        for value in held.values():
            value.revalidate()

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="wins-devicecheck-ndk-")
        self.root = Path(self._temporary.name)
        self.devicecheck = self.root / "android" / "devicecheck"
        self.devicecheck.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.devicecheck / SCRIPT.name)
        self.marker = self.root / "ambient-command-ran"
        self.hostile_bin = self.root / "hostile-bin"
        for command in AMBIENT_COMMANDS:
            write_executable(
                self.hostile_bin / command,
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$0\" >> '{self.marker}'\n"
                "exit 97\n",
            )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _hostile_environment(self, **overrides: str) -> dict[str, str]:
        hostile_sdk = self.root / "hostile-sdk"
        hostile_ndk = self.root / "hostile-ndk"
        environment = {
            "PATH": f"{self.hostile_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.root),
            "TMPDIR": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "ANDROID_HOME": str(hostile_sdk),
            "ANDROID_SDK_ROOT": str(hostile_sdk),
            "ANDROID_NDK_HOME": str(hostile_ndk),
            "ANDROID_NDK_ROOT": str(hostile_ndk),
            "NDK_HOME": str(hostile_ndk),
            "REVIEWED_NDK_VERSION": "99.99.99999999",
            "NDK_BUILD": str(self.hostile_bin / "ndk-build"),
            "SDK_DIR": str(hostile_sdk),
            "WINN_DEVICECHECK_NDK_PROBE": "1",
        }
        environment.update(overrides)
        return environment

    def _run_gate(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(self.devicecheck / SCRIPT.name)],
            cwd=self.devicecheck,
            env=self._hostile_environment(**overrides),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )

    def test_no_ambient_or_floating_ndk_selection_exists(self) -> None:
        source = self.script_source
        body = executable_lines(source)
        for token in (
            "ANDROID_NDK_HOME",
            "ANDROID_NDK_ROOT",
            "NDK_HOME",
            "ANDROID_HOME",
            "ANDROID_SDK_ROOT",
            "ANDROID_APP_GRADLE=",
            "WINN_DEVICECHECK_NDK_PROBE",
            "command -v",
            "sort -V",
            "sort -v",
            "sdkmanager",
            "source.properties",
            "ndk-build",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        self.assertNotRegex(body, r"\bfind\b.*(?:sdk|ndk)")
        self.assertNotRegex(body, r"\$\{PATH(?::-[^}]*)?\}")

    def test_no_probe_build_or_success_producer_body_exists(self) -> None:
        body = executable_lines(self.script_source)
        for token in (
            "REVIEWED_NDK_VERSION=",
            "NDK_BUILD=",
            '"${ANDROID_DIR}/gradlew"',
            "assembleDebug",
            "assembleRelease",
            "go build",
            "adb install",
            "/dev/fd/16 record",
            "WINN_DEVICECHECK_PRODUCER_ONLY",
            "exit 0",
        ):
            with self.subTest(token=token):
                self.assertNotIn(token, body)

    def test_private_non_root_workspace_is_fixed_and_checked_first(self) -> None:
        source = self.script_source
        for token in (
            'BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"',
            'BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"',
            'if [[ "$(id -u)" == "0" ]]',
            '"$(stat -f \'%Lp\' "${PROJECT_ROOT}")" != "700"',
            '"$(stat -f \'%u\' "${PROJECT_ROOT}")" != "$(id -u)"',
            "/private/var/winsvpn-devicecheck-build/*) ;;",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertLess(
            source.index('if [[ "$(id -u)" == "0" ]]'),
            source.index("require_held_path_fd 9"),
        )

    def test_exact_owner_descriptors_and_authenticated_gate_are_required(self) -> None:
        required = (
            r'require_held_path_fd 9 "transaction ticket"\s+\\\s+"\$\{PROJECT_ROOT\}/\.devicecheck-source-transaction\.json" 0 400 yes',
            r'require_held_path_fd 10 "ReleasePython" "\$\{RELEASE_PYTHON\}" 0 555 yes',
            r'require_held_path_fd 11 "release loader" "\$\{RELEASE_LOADER\}" 0 444 yes',
            r'require_held_path_fd 12 "release controller" "\$\{RELEASE_CONTROLLER\}" 0 444 yes',
            r'require_held_path_fd 14 "owner authority" "\$\{OWNER_AUTHORITY\}" 0 444 yes',
            r'require_held_path_fd 15 "owner signer certificate" "\$\{OWNER_SIGNER_CERTIFICATE\}" 0 444 yes',
            r'require_held_path_fd 16 "authority-bound receipt tool" "\$\{RECEIPT_TOOL\}" "\$\(id -u\)" 444 no',
        )
        for pattern in required:
            with self.subTest(pattern=pattern):
                self.assertRegex(self.script_source, pattern)
        self.assertIn(
            '"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate', self.script_source
        )
        self.assertIn('--repo-root "${PROJECT_ROOT}"', self.script_source)

    def test_held_paths_reject_identity_mode_symlink_and_immutable_drift(self) -> None:
        source = self.script_source
        for token in (
            '! -r "/dev/fd/${fd}"',
            '! -e "${path}"',
            '-L "${path}"',
            "fd_meta=\"$(stat -Lf '%d:%i:%u:%Lp:%Sf' \"/dev/fd/${fd}\")\"",
            "path_meta=\"$(stat -f '%d:%i:%u:%Lp:%Sf' \"${path}\")\"",
            '"${fd_device}:${fd_inode}" != "${path_device}:${path_inode}"',
            '"${fd_uid}:${fd_mode}" != "${expected_uid}:${expected_mode}"',
            '"${path_uid}:${path_mode}" != "${expected_uid}:${expected_mode}"',
            '"${fd_flags}" != *schg*',
            '"${path_flags}" != *schg*',
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)

    def test_monotonic_single_use_state_is_descriptor_bound(self) -> None:
        source = self.script_source
        self.assertIn("! -r /dev/fd/13 || ! -w /dev/fd/13", source)
        self.assertIn("stat -Lf '%u:%Lp' /dev/fd/13", source)
        self.assertIn('!= "0:600"', source)
        self.assertIn("monotonic controller state descriptor is absent or invalid", source)
        for token in (
            "CONTROLLER_STATE_FD",
            "monotonic_sequence",
            "transaction nonce was forged, replayed, expired, or consumed",
            "monotonic controller state transition failed",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.receipt_source)

    def test_receipt_authority_rejects_symlink_hardlink_and_path_substitution(self) -> None:
        for token in (
            'getattr(os, "O_NOFOLLOW", None)',
            "metadata.st_nlink != 1",
            "follow_symlinks=False",
            "changed while its descriptor was opened",
            "path changed after descriptor-held read",
        ):
            with self.subTest(token=token):
                self.assertIn(token, self.receipt_source)
        original = self.root / "one-link"
        alias = self.root / "hard-link"
        original.write_bytes(b"held")
        os.link(original, alias)
        with self.assertRaisesRegex(receipt.ReceiptError, "not a one-link file"):
            receipt._require_regular_one_link(os.stat(original), "hostile NDK input")

    def test_sdk_tools_are_sealed_while_ndk_remains_receipt_fact_only(self) -> None:
        source = self.receipt_source
        for token in (
            '"aapt": f"build-tools/{BUILD_TOOLS_VERSION}/aapt"',
            '"apksigner": f"build-tools/{BUILD_TOOLS_VERSION}/apksigner"',
            '"apksigner_jar": f"build-tools/{BUILD_TOOLS_VERSION}/lib/apksigner.jar"',
            "info.st_uid != 0",
            "path lacks SF_IMMUTABLE",
            "_require_regular_one_link(info, label)",
            "require_sealed_execution=runner is None",
        ):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertIn("Gradle layout, SDK, NDK, Go layout", self.script_source)
        self.assertNotIn("ndk-build", executable_lines(self.script_source))

    def test_final_owner_blocked_handoff_is_explicit_and_unintegrated(self) -> None:
        source = self.script_source
        self.assertIn(DISABLED_MARKER, source)
        self.assertIn('SOURCE_CONSUMER_STATUS="unintegrated"', source)
        self.assertIn(FINAL_BLOCKER, source)
        gate = source.index('"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate')
        blocker = source.index(FINAL_BLOCKER)
        final_exit = source.index("exit 1", blocker)
        self.assertLess(gate, blocker)
        self.assertLess(blocker, final_exit)

    def test_hostile_ndk_environment_cannot_execute_ambient_commands(self) -> None:
        completed = self._run_gate()
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("OWNER-BLOCKED", combined)
        self.assertFalse(self.marker.exists(), combined)
        for hostile_value in ("hostile-sdk", "hostile-ndk", "99.99.99999999"):
            with self.subTest(hostile_value=hostile_value):
                self.assertNotIn(hostile_value, combined)

    def test_legacy_ndk_probe_never_emits_retired_success_keys(self) -> None:
        completed = self._run_gate(WINN_DEVICECHECK_NDK_PROBE="success")
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("OWNER-BLOCKED", combined)
        for key in RETIRED_SUCCESS_KEYS:
            with self.subTest(key=key):
                self.assertIsNone(re.search(rf"(?m)^{re.escape(key)}=", combined))
        self.assertNotIn("Android SDK pinned", combined)
        self.assertNotIn("assembling", combined.lower())
        self.assertFalse(self.marker.exists(), combined)

    def test_receipt_contract_binds_current_ndk_gradle_facts_and_refuses_build_claim(self) -> None:
        self.assertEqual(
            self.facts,
            receipt.BuildFacts(
                agp_version="9.4.1",
                compile_sdk=37,
                gradle_version="9.8.0",
                min_sdk=24,
                ndk_version="30.0.16248370",
                target_sdk=35,
            ),
        )
        for value in self.closure.held.values():
            value.revalidate()
        for policy in receipt.VARIANT_POLICIES.values():
            with self.subTest(variant=policy.name):
                with self.assertRaisesRegex(
                    receipt.ReceiptError,
                    "OWNER-BLOCKED: DeviceCheck build producer is intentionally disabled",
                ):
                    receipt._validate_build_script_policy(
                        self.closure,
                        policy,
                        schema_fixture=False,
                    )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
