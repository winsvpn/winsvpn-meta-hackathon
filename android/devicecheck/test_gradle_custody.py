#!/usr/bin/env python3
"""Focused refuse tests for the disabled DeviceCheck workspace producer.

The Gradle lock and verification files are validated independently. The
workspace script must not inspect or execute an ambient Gradle/SDK/NDK setup;
it remains OWNER-BLOCKED until the fixed external controller supplies an
authenticated immutable compiler-input transaction. These tests prove that
legacy probe variables and hostile fixture bytes cannot restore that path.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "android" / "devicecheck" / "build_devicecheck.sh"
FAKE_COMMANDS = (
    "gradle",
    "gradlew",
    "go",
    "java",
    "javac",
    "kotlinc",
    "ndk-build",
    "sdkmanager",
    "adb",
    "cmake",
    "ninja",
    "clang",
    "clang++",
    "zip",
    "tar",
    "rsync",
)


def write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="ascii")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class DeviceCheckGradleCustodyScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="wins-devicecheck-gradle-")
        self.root = Path(self._temporary.name)
        self.android = self.root / "android"
        self.devicecheck = self.android / "devicecheck"
        self.devicecheck.mkdir(parents=True)
        shutil.copy2(SCRIPT, self.devicecheck / "build_devicecheck.sh")
        self.marker = self.root / "ambient-command-ran"
        self.fake_bin = self.root / "fake-bin"
        for command in FAKE_COMMANDS:
            write_executable(
                self.fake_bin / command,
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$0\" >> '{self.marker}'\n"
                "exit 97\n",
            )

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def _write_settings(self, agp: str = "9.4.1") -> None:
        (self.devicecheck / "settings.gradle.kts").write_text(
            'plugins {\n'
            f'    id("com.android.application") version "{agp}" apply false\n'
            "}\n",
            encoding="ascii",
        )

    def _write_wrapper_props(self, zip_name: str = "gradle-9.8.0-all.zip") -> None:
        wrapper = self.devicecheck / "gradle" / "wrapper"
        wrapper.mkdir(parents=True, exist_ok=True)
        (wrapper / "gradle-wrapper.properties").write_text(
            f"distributionUrl=https\\://services.gradle.org/distributions/{zip_name}\n",
            encoding="ascii",
        )

    def _write_lockfile(self) -> None:
        lock_dir = self.devicecheck / "gradle" / "dependency-locking"
        lock_dir.mkdir(parents=True, exist_ok=True)
        (lock_dir / "app.lockfile").write_text(
            "# test lockfile\nandroidx.annotation:annotation:1.11.0=debugCompileClasspath\n",
            encoding="ascii",
        )

    def _write_verification(self, verify_metadata: bool = True) -> None:
        gradle = self.devicecheck / "gradle"
        gradle.mkdir(parents=True, exist_ok=True)
        flag = "true" if verify_metadata else "false"
        (gradle / "verification-metadata.xml").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<verification-metadata>\n"
            "   <configuration>\n"
            f"      <verify-metadata>{flag}</verify-metadata>\n"
            "   </configuration>\n"
            "</verification-metadata>\n",
            encoding="ascii",
        )

    def _env(self) -> dict[str, str]:
        return {
            "PATH": f"{self.fake_bin}:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(self.root),
            "TMPDIR": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "WINN_DEVICECHECK_GRADLE_PROBE": "1",
            "ANDROID_HOME": str(self.root / "hostile-sdk"),
            "ANDROID_SDK_ROOT": str(self.root / "hostile-sdk"),
            "ANDROID_NDK_HOME": str(self.root / "hostile-ndk"),
            "ANDROID_NDK_ROOT": str(self.root / "hostile-ndk"),
            "NDK_HOME": str(self.root / "hostile-ndk"),
            "GRADLE_HOME": str(self.root / "hostile-gradle"),
            "GRADLE_USER_HOME": str(self.root / "hostile-gradle-cache"),
            "JAVA_HOME": str(self.root / "hostile-jdk"),
            "GOMODCACHE": str(self.root / "hostile-go-cache"),
        }

    def _probe(
        self,
        script: Optional[Path] = None,
        environment: Optional[dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(script or self.devicecheck / "build_devicecheck.sh")],
            cwd=self.devicecheck,
            env=environment or self._env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )

    def _assert_owner_blocked(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(completed.returncode, 0)
        combined = completed.stdout + completed.stderr
        self.assertIn("OWNER-BLOCKED:", combined)
        self.assertFalse(self.marker.exists(), "an ambient build command executed")
        self.assertNotIn("DEVICECHECK_GRADLE_LOCK=", completed.stdout)
        self.assertNotIn("REVIEWED_NDK_VERSION=", completed.stdout)
        self.assertNotIn("assembling", combined.lower())
        self.assertNotIn("receipt recorded", combined.lower())

    def test_legacy_gradle_and_ndk_probe_variables_cannot_enable_a_build(self) -> None:
        environment = self._env()
        environment["WINN_DEVICECHECK_NDK_PROBE"] = "1"
        self._assert_owner_blocked(self._probe(environment=environment))

    def test_valid_gradle_fixture_cannot_authorize_the_disabled_producer(self) -> None:
        self._write_settings()
        self._write_wrapper_props()
        self._write_lockfile()
        self._write_verification()
        self._assert_owner_blocked(self._probe())

    def test_hostile_environment_strings_cannot_authorize_a_build(self) -> None:
        environment = self._env()
        environment.update(
            {
                "WINN_DEVICECHECK_PRODUCER_ONLY": "1",
                "WINN_DEVICECHECK_IMMUTABLE_INPUT_HANDOFF": "1",
                "WINS_DEVICECHECK_AUTHENTICATED_TRANSACTION": "v3",
                "WINS_DEVICECHECK_AUTHENTICATED_WORKSPACE": str(self.root),
                "WINS_DEVICECHECK_SOURCE_TRANSACTION_FD": "9",
                "WINS_DEVICECHECK_RECEIPT_SELFTEST": "1",
                "WINS_DEVICECHECK_SOURCE_AUTHORITY": str(self.root / "authority.json"),
                "WINS_DEVICECHECK_SOURCE_SNAPSHOT": str(self.root / "snapshot"),
                "WINS_DEVICECHECK_SOURCE_MANIFEST": str(self.root / "manifest.json"),
                "WINS_DEVICECHECK_BUILD_WORKSPACE_ROOT": str(self.root),
                "WINS_DEVICECHECK_BUILD_CACHE_ROOT": str(self.root / "cache"),
                "WINS_DEVICECHECK_TARGET_APK_SHA256": "a" * 64,
                "WINS_DEVICECHECK_ANDROID_TEST_APK_SHA256": "a" * 64,
            }
        )
        self._assert_owner_blocked(self._probe(environment=environment))

    def test_hostile_gradle_sdk_ndk_and_compiler_bins_are_never_executed(self) -> None:
        for path in (
            self.root / "hostile-sdk",
            self.root / "hostile-ndk",
            self.root / "hostile-gradle",
            self.root / "hostile-gradle-cache",
            self.root / "hostile-jdk",
            self.root / "hostile-go-cache",
        ):
            path.mkdir(parents=True, exist_ok=True)
        self._write_settings()
        self._write_wrapper_props()
        self._write_lockfile()
        self._write_verification()
        self._assert_owner_blocked(self._probe())

    def test_script_names_only_the_v3_content_addressed_private_contract(self) -> None:
        source = (self.devicecheck / "build_devicecheck.sh").read_text(encoding="ascii")
        for required in (
            'SOURCE_AUTHORITY_ROOT="/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"',
            'SOURCE_SNAPSHOT_BASE="${SOURCE_AUTHORITY_ROOT}/snapshots/sha256"',
            'SOURCE_MANIFEST_BASE="${SOURCE_AUTHORITY_ROOT}/manifests/sha256"',
            'OWNER_AUTHORITY_CONTRACT="winsvpn-devicecheck-owner-authority-v4"',
            'BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"',
            'BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"',
            'BUILD_HANDOFF_CONTRACT="winsvpn-devicecheck-private-build-handoff-v1"',
            'SOURCE_CONSUMER_STATUS="unintegrated"',
        ):
            with self.subTest(required=required):
                self.assertEqual(source.count(required), 1)
        self.assertNotIn("devicecheck-v2", source)
        self.assertNotIn("sudo", source)

    def test_workspace_environment_cannot_replace_fixed_private_roots(self) -> None:
        environment = self._env()
        environment.update(
            {
                "PROJECT_ROOT": str(self.root),
                "BUILD_WORKSPACE_ROOT": str(self.root),
                "BUILD_CACHE_ROOT": str(self.root / "cache"),
                "TMPDIR": str(self.root),
                "HOME": str(self.root),
            }
        )
        completed = self._probe(environment=environment)
        self._assert_owner_blocked(completed)
        self.assertIn("outside the fixed private root", completed.stderr)

    def test_mutable_workspace_is_rejected(self) -> None:
        self.root.chmod(0o755)
        completed = self._probe()
        self._assert_owner_blocked(completed)
        self.assertIn("must be private 0700", completed.stderr)

    def test_symlinked_script_cannot_bypass_owner_block(self) -> None:
        linked = self.devicecheck / "build_devicecheck-symlink.sh"
        linked.symlink_to(self.devicecheck / "build_devicecheck.sh")
        completed = self._probe(script=linked)
        self._assert_owner_blocked(completed)
        self.assertIn("producer script must be a one-link regular file", completed.stderr)

    def test_hardlinked_script_cannot_bypass_owner_block(self) -> None:
        linked = self.devicecheck / "build_devicecheck-hardlink.sh"
        os.link(self.devicecheck / "build_devicecheck.sh", linked)
        completed = self._probe(script=linked)
        self._assert_owner_blocked(completed)
        self.assertIn("producer script must be a one-link regular file", completed.stderr)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
