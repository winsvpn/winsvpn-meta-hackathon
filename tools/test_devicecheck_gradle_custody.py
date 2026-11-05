#!/usr/bin/env python3
"""Fail-closed DeviceCheck Gradle dependency locking and verification custody.

Scope is only `android/devicecheck/` plus this file. The harness is a
standalone Gradle project, so phone Android locking, Wear OS locking, and
Play upload producers are not evidence that DeviceCheck is pinned.

WHAT THIS GUARD ASSERTS.

  1. Dependency locking is STRICT and covers the configurations a debug
     DeviceCheck assemble actually resolves. Hash integrity is a separate
     verification-metadata.xml with sha256 rows for every direct Maven pin.
  2. The plugin pin is AGP 9.4.1 and the wrapper distribution is the current
     Gradle 9.8.0 pin from tools/toolchain-pins.json. gradlePluginPortal stays
     closed. Project repositories are forbidden.
  3. build_devicecheck.sh is the intentionally disabled workspace entrypoint.
     It accepts only the fixed private transaction root and retained external
     v4 authority/controller descriptors at the content-addressed
     devicecheck-v3 authority, invokes the authenticated loader under
     ReleasePython with -I -S, and then remains OWNER-BLOCKED because immutable
     compiler-input handoff is not implemented. It contains no ambient Gradle,
     NDK, SDK, Go, ADB, receipt-publication, build, or successful exit path, and
     never substitutes source hashes for direct target/androidTest APK custody.

A green that cannot be made to fail is not evidence: the script-source
assertions below fail if the refuse path or the parent-wrapper invocation is
removed.
"""

from __future__ import annotations

import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEVICECHECK = ROOT / "android" / "devicecheck"
APP_GRADLE = DEVICECHECK / "app/build.gradle.kts"
ROOT_GRADLE = DEVICECHECK / "build.gradle.kts"
SETTINGS = DEVICECHECK / "settings.gradle.kts"
LOCKFILE = DEVICECHECK / "gradle/dependency-locking/app.lockfile"
VERIFICATION = DEVICECHECK / "gradle/verification-metadata.xml"
WRAPPER_PROPS = DEVICECHECK / "gradle/wrapper/gradle-wrapper.properties"
BUILD_SH = DEVICECHECK / "build_devicecheck.sh"
PINS = ROOT / "tools/toolchain-pins.json"

DIRECT_PINS = (
    "androidx.annotation:annotation:1.11.0",
    "androidx.test.ext:junit:1.3.0",
    "androidx.test:core:1.7.0",
)

LOCKED_CONFIGS = (
    "debugCompileClasspath",
    "debugRuntimeClasspath",
    "debugAndroidTestCompileClasspath",
    "releaseCompileClasspath",
    "releaseRuntimeClasspath",
)

PLUGIN_PORTAL_CALL = re.compile(r"^[ \t]*gradlePluginPortal\s*\(", re.MULTILINE)
PLUGIN_LINE = re.compile(r'id\("([^"]+)"\)\s+version\s+"([^"]+)"')
DYNAMIC_VERSION = re.compile(r"[+\]\[]")


def source(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


class DeviceCheckGradleCustodyTests(unittest.TestCase):
    def test_dependency_locking_is_strict_and_covers_resolved_configs(self) -> None:
        root = source(ROOT_GRADLE)
        app = source(APP_GRADLE)
        gradle = root + app
        self.assertIn("lockAllConfigurations()", gradle)
        self.assertIn("LockMode.STRICT", gradle)
        self.assertNotIn("deactivateDependencyLocking", gradle)
        self.assertTrue(LOCKFILE.is_file(), "devicecheck is missing app.lockfile")
        lock = source(LOCKFILE)
        for configuration in LOCKED_CONFIGS:
            with self.subTest(configuration=configuration):
                self.assertIn(configuration, lock)
        for pin in DIRECT_PINS:
            with self.subTest(lock_pin=pin):
                self.assertIn(pin, lock)
        agp = json.loads(source(PINS))["tools"]["android_gradle_plugin"]["version"]
        self.assertEqual(agp, "9.4.1")
        self.assertIn(f"com.android.tools.build:builder-model:{agp}", lock)
        self.assertIn("gradle/dependency-locking/", root)
        self.assertIn('id("com.android.application") apply false', root)

    def test_verification_metadata_hash_pins_direct_artifacts(self) -> None:
        self.assertTrue(VERIFICATION.is_file())
        text = source(VERIFICATION)
        agp = json.loads(source(PINS))["tools"]["android_gradle_plugin"]["version"]
        self.assertIn("<verify-metadata>true</verify-metadata>", text)
        self.assertIn("<verify-signatures>false</verify-signatures>", text)
        self.assertGreaterEqual(text.count("<sha256 "), 20)
        for group, name, version in (
            ("androidx.annotation", "annotation", "1.11.0"),
            ("androidx.test.ext", "junit", "1.3.0"),
            ("androidx.test", "core", "1.7.0"),
            ("com.android.application", "com.android.application.gradle.plugin", agp),
        ):
            with self.subTest(artifact=f"{group}:{name}:{version}"):
                needle = (
                    f'<component group="{group}" name="{name}" version="{version}">'
                )
                self.assertIn(needle, text)
        for host in ("linux", "osx", "windows"):
            self.assertRegex(text, rf"aapt2-{re.escape(agp)}-\d+-{host}\.jar")

    def test_plugin_versions_are_exact_and_portal_stays_closed(self) -> None:
        settings = source(SETTINGS)
        root = source(ROOT_GRADLE)
        self.assertFalse(PLUGIN_PORTAL_CALL.search(settings))
        self.assertFalse(PLUGIN_PORTAL_CALL.search(root))
        self.assertIn("google()", settings)
        self.assertIn("mavenCentral()", settings)
        self.assertIn("FAIL_ON_PROJECT_REPOS", settings)
        found = list(PLUGIN_LINE.finditer(settings))
        self.assertTrue(found, "devicecheck settings declare no versioned plugins")
        by_id = {match.group(1): match.group(2) for match in found}
        pins = json.loads(source(PINS))["tools"]
        self.assertEqual(
            by_id.get("com.android.application"),
            pins["android_gradle_plugin"]["version"],
        )
        self.assertEqual(by_id.get("com.android.application"), "9.4.1")
        self.assertNotIn("org.jetbrains.kotlin.android", by_id)
        for plugin_id, version in by_id.items():
            with self.subTest(plugin=plugin_id, version=version):
                self.assertIsNone(DYNAMIC_VERSION.search(version), version)

    def test_wrapper_distribution_is_current_gradle_and_hash_pinned(self) -> None:
        pins = json.loads(source(PINS))["tools"]["gradle"]
        declared = pins["distribution_version"]
        self.assertEqual(declared, "9.8.0")
        expected_sha = pins["distribution_sha256_by_flavour"]["all"]
        props = source(WRAPPER_PROPS)
        self.assertIn(
            "distributionUrl=https\\://services.gradle.org/distributions/"
            f"gradle-{declared}-all.zip",
            props,
        )
        self.assertIn(f"distributionSha256Sum={expected_sha}", props)
        self.assertIn("validateDistributionUrl=true", props)

    def test_direct_pins_match_the_standalone_app_contract(self) -> None:
        gradle = source(APP_GRADLE)
        for pin in DIRECT_PINS:
            with self.subTest(pin=pin):
                self.assertIn(f'("{pin}")', gradle)
        self.assertIn("compileSdk = 37", gradle)
        self.assertIn('applicationId = "org.winsvpn.devicecheck"', gradle)
        self.assertIn("id(\"com.android.application\")", gradle)
        self.assertNotIn("org.jetbrains.kotlin.android", gradle)
        self.assertIn("amneziawg.aar", gradle)

    def test_build_script_is_disabled_until_authenticated_compiler_input_handoff(self) -> None:
        text = source(BUILD_SH)
        self.assertEqual(
            text.count("# DEVICECHECK_PRODUCER_DISABLED=immutable-compiler-input-v1"),
            1,
        )
        required = (
            'SOURCE_AUTHORITY_ROOT="/Library/WinsVPN/ReleaseAndroidSource/devicecheck-v3"',
            'SOURCE_SNAPSHOT_BASE="${SOURCE_AUTHORITY_ROOT}/snapshots/sha256"',
            'SOURCE_MANIFEST_BASE="${SOURCE_AUTHORITY_ROOT}/manifests/sha256"',
            'RELEASE_LOADER="${SOURCE_AUTHORITY_ROOT}/loader.py"',
            'RELEASE_CONTROLLER="${SOURCE_AUTHORITY_ROOT}/controller.py"',
            'OWNER_AUTHORITY="${SOURCE_AUTHORITY_ROOT}.authority.json"',
            'BUILD_WORKSPACE_ROOT="/private/var/winsvpn-devicecheck-build"',
            'BUILD_CACHE_ROOT="/private/var/winsvpn-devicecheck-cache"',
            'OWNER_AUTHORITY_CONTRACT="winsvpn-devicecheck-owner-authority-v4"',
            'BUILD_HANDOFF_CONTRACT="winsvpn-devicecheck-private-build-handoff-v1"',
            'ATOMIC_PUBLICATION_CONTRACT="winsvpn-devicecheck-content-addressed-publication-v1"',
            'SOURCE_CONSUMER_STATUS="unintegrated"',
            '"$(stat -f \'%l\' "${BASH_SOURCE[0]}")" != "1"',
            "DeviceCheck producer script must be a one-link regular file.",
            '/private/var/winsvpn-devicecheck-build/*)',
            'require_held_path_fd 9 "transaction ticket"',
            'require_held_path_fd 10 "ReleasePython"',
            'require_held_path_fd 11 "release loader"',
            'require_held_path_fd 12 "release controller"',
            'require_held_path_fd 14 "owner authority"',
            'require_held_path_fd 15 "owner signer certificate"',
            'require_held_path_fd 16 "authority-bound receipt tool"',
            '"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate',
            'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest',
            "OWNER-BLOCKED: immutable compiler-input handoff is not implemented",
        )
        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertEqual(text.count(fragment), 1)
        self.assertNotIn("devicecheck-v2", text)
        self.assertNotIn("sudo", text)

        gate = text.index('"${RELEASE_PYTHON}" -I -S /dev/fd/11 gate')
        selftest = text.index(
            'exec "${RELEASE_PYTHON}" -I -S /dev/fd/16 selftest'
        )
        blocker = text.index(
            "OWNER-BLOCKED: immutable compiler-input handoff is not implemented"
        )
        self.assertLess(gate, selftest)
        self.assertLess(selftest, blocker)

        active = "\n".join(
            line
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        self.assertEqual(active.splitlines()[-1].strip(), "exit 1")
        for forbidden in (
            "WINN_DEVICECHECK_GRADLE_PROBE",
            "WINN_DEVICECHECK_NDK_PROBE",
            '"${ANDROID_DIR}/gradlew"',
            "gradle :",
            "ndk-build",
            "sdkmanager",
            "command -v go",
            "go build",
            "adb ",
            "cmake ",
            "ninja ",
            "/dev/fd/16 record",
            "exit 0",
            "return 0",
            "curl ",
            "wget ",
            "TARGET_APK_SHA256=",
            "ANDROID_TEST_APK_SHA256=",
            "BUILT_ARTIFACT_SHA256=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, active)


if __name__ == "__main__":
    unittest.main()
