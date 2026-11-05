#!/usr/bin/env python3
"""Fail-closed Wear OS release supply-chain and Play-form-factor contracts.

Scope is only `wear_os/` plus this file. The watch is a standalone Gradle
project, so phone Android locking, wrapper jars, and Play upload producers
are not evidence that the watch APK is pinned.

WHAT THIS GUARD ASSERTS.

  1. Dependency locking is STRICT and covers the configurations a debug/release
     Wear build actually resolves. Hash integrity is a separate
     verification-metadata.xml with sha256 rows for every direct pin.
  2. The Gradle wrapper is the official current stable bootstrap (jar bytes plus
     unix/windows scripts) and the distribution URL is hash-pinned to
     tools/toolchain-pins.json. AGP and Kotlin plugin pins are checked against
     the same manifest so a partial toolchain bump fails closed.
  3. Direct Maven pins are the newest stables that compile against
     compileSdk 37 (the newest stable platform AGP 9.4 supports).
     play-services-wearable is the phone's 20.0.1 because the Data Layer
     pairing contract requires the same artifact on both ends.
  4. Store readiness: watch hardware feature, non-standalone companion, no
     INTERNET, same applicationId as the phone, versionCode = pubspec*100+1,
     fail-closed release signing, minify+resource shrink, and the AAB inspector
     is repo-relative rather than a stale absolute path.

A green that cannot be made to fail is not evidence: the AAB inspector is
exercised against synthetic zips, not only the live tree.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import re
import sys
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

from test_wear_os_assert_release_aab import r8_mapping_bytes

WEAR = ROOT / "wear_os"
APP_GRADLE = WEAR / "app/build.gradle.kts"
ROOT_GRADLE = WEAR / "build.gradle.kts"
SETTINGS = WEAR / "settings.gradle.kts"
LOCKFILE = WEAR / "gradle/dependency-locking/app.lockfile"
VERIFICATION = WEAR / "gradle/verification-metadata.xml"
WRAPPER_PROPS = WEAR / "gradle/wrapper/gradle-wrapper.properties"
WRAPPER_JAR = WEAR / "gradle/wrapper/gradle-wrapper.jar"
GRADLEW = WEAR / "gradlew"
GRADLEW_BAT = WEAR / "gradlew.bat"
MANIFEST = WEAR / "app/src/main/AndroidManifest.xml"
EXTRACTION = WEAR / "app/src/main/res/xml/data_extraction_rules.xml"
PINS = ROOT / "tools/toolchain-pins.json"
PUBSPEC = ROOT / "pubspec.yaml"
ASSERT_AAB = WEAR / "tools/assert_release_aab.py"

VALID_MANIFEST_XML = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.winsvpn.app" android:versionName="1.0.16" android:versionCode="3301">
  <uses-sdk android:minSdkVersion="30" android:targetSdkVersion="37" />
  <uses-feature android:name="android.hardware.type.watch" />
  <application>
    <meta-data android:name="com.google.android.wearable.standalone" android:value="false" />
    <activity android:name="org.winsvpn.app.wear.MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>'''

DECODER_EVIDENCE = {
    "decoder": "bundletool",
    "version": "1.18.3",
    "jar_sha256": "a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29",
}

DIRECT_PINS = (
    "androidx.core:core-ktx:1.19.1",
    "androidx.activity:activity-compose:1.13.0",
    "androidx.lifecycle:lifecycle-runtime-compose:2.11.0",
    "androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0",
    "androidx.wear.compose:compose-material:1.7.0",
    "androidx.wear.compose:compose-foundation:1.7.0",
    "com.google.android.gms:play-services-wearable:20.0.1",
    "org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.11.0",
    "junit:junit:4.13.2",
    "org.json:json:20260814",
)

LOCKED_CONFIGS = (
    "debugCompileClasspath",
    "debugRuntimeClasspath",
    "debugUnitTestCompileClasspath",
    "debugUnitTestRuntimeClasspath",
    "releaseCompileClasspath",
    "releaseRuntimeClasspath",
)

PLUGIN_PORTAL_CALL = re.compile(r"^[ \t]*gradlePluginPortal\s*\(", re.MULTILINE)
PLUGIN_LINE = re.compile(r'id\("([^"]+)"\)\s+version\s+"([^"]+)"')
DYNAMIC_VERSION = re.compile(r"[+\]\[]")
AAPT2_RELEASE_HOSTS = ("linux", "osx", "windows")


def source(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def load_assert_aab():
    spec = importlib.util.spec_from_file_location("wear_assert_release_aab", ASSERT_AAB)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _agp_pin() -> str:
    return json.loads(source(PINS))["tools"]["android_gradle_plugin"]["version"]


def _android_tools_version(agp_version: str) -> str:
    major, minor, patch = agp_version.split(".")
    if not (major.isdigit() and minor.isdigit() and patch.isdigit()):
        raise ValueError(f"AGP pin is not major.minor.patch: {agp_version}")
    return f"{int(major) + 23}.{minor}.{patch}"


def _stale_series_pattern(version: str) -> re.Pattern[str]:
    major, minor, patch = version.split(".")
    return re.compile(
        rf"(?<!\d){re.escape(major)}\.{re.escape(minor)}\."
        rf"(?!{re.escape(patch)}(?:\D|$))\d+"
    )


def _aapt2_proto_build_ids(lock_text: str, agp_version: str) -> set[str]:
    return set(
        re.findall(
            rf"com\.android\.tools\.build:aapt2-proto:{re.escape(agp_version)}-(\d+)=",
            lock_text,
        )
    )


class WearOsReleaseSupplyChainTests(unittest.TestCase):
    def test_dependency_locking_is_strict_and_covers_resolved_configs(self) -> None:
        root = source(ROOT_GRADLE)
        app = source(APP_GRADLE)
        gradle = root + app
        self.assertIn("lockAllConfigurations()", gradle)
        self.assertIn("LockMode.STRICT", gradle)
        self.assertNotIn("deactivateDependencyLocking", gradle)
        self.assertTrue(LOCKFILE.is_file(), "wear_os is missing app.lockfile")
        lock = source(LOCKFILE)
        for configuration in LOCKED_CONFIGS:
            with self.subTest(configuration=configuration):
                self.assertIn(configuration, lock)
        for pin in DIRECT_PINS:
            with self.subTest(lock_pin=pin):
                self.assertIn(pin, lock)

    def test_verification_metadata_hash_pins_direct_artifacts(self) -> None:
        self.assertTrue(VERIFICATION.is_file())
        text = source(VERIFICATION)
        self.assertIn("<verify-metadata>true</verify-metadata>", text)
        self.assertIn("<verify-signatures>false</verify-signatures>", text)
        self.assertGreaterEqual(text.count("<sha256 "), 50)
        for group_name_version in (
            ('androidx.core', 'core-ktx', '1.19.1'),
            ('androidx.wear.compose', 'compose-material', '1.7.0'),
            ('com.google.android.gms', 'play-services-wearable', '20.0.1'),
            ('org.json', 'json', '20260814'),
        ):
            group, name, version = group_name_version
            with self.subTest(artifact=f"{group}:{name}:{version}"):
                needle = (
                    f'<component group="{group}" name="{name}" version="{version}">'
                )
                self.assertIn(needle, text)

    def test_agp_aapt2_verification_covers_all_release_hosts(self) -> None:
        agp = _agp_pin()
        tools = _android_tools_version(agp)
        self.assertRegex(agp, r"^\d+\.\d+\.\d+$")
        stale_agp = _stale_series_pattern(agp)
        stale_tools = _stale_series_pattern(tools)
        major, minor, patch = agp.split(".")
        other_agp = f"{major}.{minor}.{int(patch) + 1}"
        other_tools = _android_tools_version(other_agp)
        self.assertIsNotNone(stale_agp.search(f"aapt2-{other_agp}-1-linux.jar"))
        self.assertIsNone(stale_agp.search(f"aapt2-{agp}-1-linux.jar"))
        self.assertIsNotNone(stale_tools.search(f"annotations-{other_tools}.jar"))
        self.assertIsNone(stale_tools.search(f"annotations-{tools}.jar"))
        if int(patch) > 0:
            previous_agp = f"{major}.{minor}.{int(patch) - 1}"
            previous_tools = _android_tools_version(previous_agp)
            self.assertIsNotNone(
                stale_agp.search(f"aapt2-{previous_agp}-1-linux.jar")
            )
            self.assertIsNotNone(
                stale_tools.search(f"annotations-{previous_tools}.jar")
            )
        lock_text = source(LOCKFILE)
        metadata = source(VERIFICATION)
        for label, text in (
            ("wear_os/gradle/dependency-locking/app.lockfile", lock_text),
            ("wear_os/gradle/verification-metadata.xml", metadata),
        ):
            stale = stale_agp.search(text) or stale_tools.search(text)
            self.assertIsNone(
                stale,
                f"{label} still carries stale AGP/tools train "
                f"{stale.group(0) if stale else ''}",
            )
        found = _aapt2_proto_build_ids(lock_text, agp)
        self.assertEqual(
            len(found),
            1,
            f"wear lockfile must lock exactly one aapt2-proto build for AGP {agp}",
        )
        build_id = next(iter(found))
        # Host coverage is name-only. Hashes in verification-metadata.xml are
        # Gradle-written and must not authenticate the same artifacts they
        # describe. All three release hosts are required on every machine.
        for host in AAPT2_RELEASE_HOSTS:
            self.assertIn(f"aapt2-{agp}-{build_id}-{host}.jar", metadata)

    def test_wrapper_is_official_current_gradle_and_hash_pinned(self) -> None:
        pins = json.loads(source(PINS))
        gradle = pins["tools"]["gradle"]
        declared = gradle["distribution_version"]
        self.assertEqual(declared, "9.8.0")
        expected_sha = gradle["distribution_sha256_by_flavour"]["all"]
        expected_wrapper_sha = gradle["wrapper_jar_sha256"]
        props = source(WRAPPER_PROPS)
        self.assertIn(
            "distributionUrl=https\\://services.gradle.org/distributions/"
            f"gradle-{declared}-all.zip",
            props,
        )
        self.assertIn(f"distributionSha256Sum={expected_sha}", props)
        self.assertIn("validateDistributionUrl=true", props)

        digest = hashlib.sha256(WRAPPER_JAR.read_bytes()).hexdigest()
        self.assertEqual(digest, expected_wrapper_sha)
        with zipfile.ZipFile(WRAPPER_JAR) as zipped:
            self.assertTrue(
                any(name.endswith("GradleWrapperMain.class") for name in zipped.namelist()),
                "wrapper jar is not the official Gradle bootstrap",
            )

        unix = source(GRADLEW)
        windows = source(GRADLEW_BAT)
        self.assertIn('-jar "$APP_HOME/gradle/wrapper/gradle-wrapper.jar"', unix)
        self.assertNotIn(
            "CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar",
            unix,
        )
        self.assertIn('-jar "%APP_HOME%\\gradle\\wrapper\\gradle-wrapper.jar"', windows)
        self.assertTrue(GRADLEW.stat().st_mode & 0o111, "gradlew must be executable")

        dist_hits = list(
            pathlib.Path.home().glob(
                f".gradle/wrapper/dists/gradle-{declared}-all/*/gradle-{declared}/"
                f"lib/plugins/gradle-wrapper-main-{declared}.jar"
            )
        )
        if dist_hits:
            with zipfile.ZipFile(dist_hits[0]) as plugin:
                official = plugin.read("gradle-wrapper.jar")
            self.assertEqual(
                hashlib.sha256(official).hexdigest(),
                digest,
                f"in-tree wrapper jar drifted from the official {declared} bootstrap",
            )

    def test_plugin_versions_are_exact_and_portal_stays_closed(self) -> None:
        settings = source(SETTINGS)
        root = source(ROOT_GRADLE)
        self.assertFalse(PLUGIN_PORTAL_CALL.search(settings))
        self.assertFalse(PLUGIN_PORTAL_CALL.search(root))
        self.assertIn("google()", settings)
        self.assertIn("mavenCentral()", settings)
        self.assertIn("FAIL_ON_PROJECT_REPOS", settings)
        found = list(PLUGIN_LINE.finditer(root))
        self.assertTrue(found, "wear_os/build.gradle.kts declares no versioned plugins")
        by_id = {match.group(1): match.group(2) for match in found}
        pins = json.loads(source(PINS))["tools"]
        self.assertEqual(
            by_id.get("com.android.application"),
            pins["android_gradle_plugin"]["version"],
        )
        self.assertEqual(
            by_id.get("org.jetbrains.kotlin.plugin.compose"),
            pins["kotlin"]["version"],
        )
        for plugin_id, version in by_id.items():
            with self.subTest(plugin=plugin_id, version=version):
                self.assertIsNone(DYNAMIC_VERSION.search(version), version)

    def test_direct_pins_are_the_newest_stables_that_fit_compilesdk_37(self) -> None:
        gradle = source(APP_GRADLE)
        for pin in DIRECT_PINS:
            with self.subTest(pin=pin):
                self.assertIn(f'("{pin}")', gradle)
        # Anti-vacuity: the pre-2026-10-06 pins (compileSdk 36 era) must be gone,
        # and the watch must resolve the same Data Layer artifact as the phone.
        self.assertNotIn("core-ktx:1.18.0", gradle)
        self.assertNotIn("lifecycle-runtime-compose:2.10.0", gradle)
        self.assertNotIn("play-services-wearable:19.0.0", gradle)
        self.assertIn(
            "play-services-wearable:20.0.1",
            source(ROOT / "android/app/build.gradle.kts"),
        )
        self.assertIn("compileSdk = 37", gradle)
        self.assertIn("targetSdk = 37", gradle)
        self.assertIn("minSdk = 30", gradle)
        self.assertIn("JvmTarget.JVM_17", gradle)

    def test_play_form_factor_and_signing_fail_closed(self) -> None:
        manifest = source(MANIFEST)
        gradle = source(APP_GRADLE)
        extraction = source(EXTRACTION)
        self.assertIn('android:name="android.hardware.type.watch"', manifest)
        self.assertIn('android:name="com.google.android.wearable.standalone"', manifest)
        self.assertIn('android:value="false"', manifest)
        self.assertNotIn("android.permission.INTERNET", manifest)
        self.assertIn('android:allowBackup="false"', manifest)
        self.assertIn('applicationId = "org.winsvpn.app"', gradle)
        self.assertIn("isMinifyEnabled = true", gradle)
        self.assertIn("isShrinkResources = true", gradle)
        for name in (
            "WINS_ANDROID_KEYSTORE",
            "WINS_ANDROID_KEY_ALIAS",
            "WINS_ANDROID_KEY_PASSWORD",
            "WINS_ANDROID_STORE_PASSWORD",
        ):
            self.assertIn(name, gradle)
        self.assertIn("wearReleaseSigningIsOwnerUploadKey", gradle)
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", gradle)
        self.assertIn("debug or test key", gradle)
        self.assertIn('task.name == "assembleRelease"', gradle)
        self.assertIn('task.name == "bundleRelease"', gradle)
        self.assertIn('task.name == "packageRelease"', gradle)
        self.assertNotIn("jniLibs.srcDirs", gradle)
        self.assertNotIn("src/main/jniLibs", gradle)
        self.assertNotIn('implementation(files("libs/amneziawg.aar"))', gradle)
        self.assertIn("wearCompanionMustNotPackagePhoneVpnEngines", gradle)
        self.assertIn("libwinnengine.so", gradle)
        self.assertIn("libam-go.so", gradle)
        self.assertIn("libxray.so", gradle)
        self.assertIn("amneziawg.aar", gradle)
        self.assertIn('abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")', gradle)
        self.assertIn("useLegacyPackaging = false", gradle)
        self.assertFalse(any((WEAR / "app/src").rglob("*.so")))
        libs = WEAR / "app/libs"
        self.assertFalse(libs.exists() and any(libs.rglob("*.so")))
        for domain in ("root", "file", "database", "sharedpref", "external"):
            self.assertGreaterEqual(extraction.count(f'<exclude domain="{domain}" />'), 2)

    def test_version_code_follows_pubspec_watch_scheme(self) -> None:
        pubspec = source(PUBSPEC)
        match = re.search(r"^version:\s*([^+\s]+)\+(\d+)\s*$", pubspec, re.MULTILINE)
        self.assertIsNotNone(match)
        version_name, build = match.group(1), int(match.group(2))
        gradle = source(APP_GRADLE)
        self.assertIn(f"versionCode = {build * 100 + 1}", gradle)
        self.assertIn(f'versionName = "{version_name}"', gradle)

    def test_aab_inspector_requires_decoded_structure_and_rejects_native_payloads(self) -> None:
        module = load_assert_aab()
        allowlist_patch = mock.patch.dict(module.APPROVED_NATIVE_LIBRARIES, {}, clear=True)
        allowlist_patch.start()
        self.addCleanup(allowlist_patch.stop)
        canonical = pathlib.Path(module.CANONICAL)
        self.assertTrue(str(canonical).startswith(str(WEAR)))
        self.assertNotIn("/Users/owner/Documents/wins/source/", source(ASSERT_AAB))
        missing = module.inspect(WEAR / "does-not-exist.aab")
        self.assertFalse(missing["ok"])

        def write_bundle(path: pathlib.Path, extra: dict[str, bytes] | None = None) -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as zipped:
                zipped.writestr("BundleConfig.pb", b"ok")
                zipped.writestr(
                    "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
                    r8_mapping_bytes(),
                )
                # These spoofing strings used to make a phone bundle pass.
                zipped.writestr(
                    "base/manifest/AndroidManifest.xml",
                    b"android.hardware.type.watch org.winsvpn.app.wear.MainActivity",
                )
                for name, data in (extra or {}).items():
                    zipped.writestr(name, data)

        candidate = WEAR / "app/build" / "_wear_os_supply_chain_candidate.aab"
        try:
            write_bundle(candidate)
            phone_xml = VALID_MANIFEST_XML.replace(
                b'<uses-feature android:name="android.hardware.type.watch" />',
                b'<uses-feature android:name="android.hardware.camera" />',
            )
            with mock.patch.object(
                module, "_decoded_manifest_xml", return_value=(phone_xml, DECODER_EVIDENCE)
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(any("watch uses-feature" in item for item in result["failures"]))

            required_false = VALID_MANIFEST_XML.replace(
                b'android:name="android.hardware.type.watch"',
                b'android:name="android.hardware.type.watch" android:required="false"',
            )
            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(required_false, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(any("must be required" in item for item in result["failures"]))

            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(VALID_MANIFEST_XML, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertTrue(result["ok"], result["failures"])
            self.assertEqual(result["manifest"]["package"], "org.winsvpn.app")
            self.assertEqual(result["manifest"]["version_name"], "1.0.16")
            self.assertEqual(result["manifest"]["version_code"], 3301)
            self.assertEqual(result["manifest"]["min_sdk"], 30)
            self.assertEqual(result["manifest"]["target_sdk"], 37)
            self.assertTrue(result["manifest"]["minify_enabled"])
            self.assertEqual(result["companion_protocol"]["primary"], "winn-v3")
            self.assertEqual(result["companion_protocol"]["fallback"], ["awg", "xray"])
            self.assertFalse(result["companion_protocol"]["local_wear_inclusion"])

            write_bundle(candidate, {"base/lib/arm64-v8a/libwinnengine.so": b"\x7fELFwinn-v3"})
            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(VALID_MANIFEST_XML, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(
                any("must not include phone VPN engine" in item for item in result["failures"])
            )

            write_bundle(candidate, {"base/assets/libxray.so": b"not-elf"})
            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(VALID_MANIFEST_XML, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(
                any("must not include phone VPN engine" in item for item in result["failures"])
            )

            write_bundle(candidate, {"base/assets/route-model.dat": b"\x7fELFrenamed-engine"})
            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(VALID_MANIFEST_XML, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(any("unapproved native or ELF" in item for item in result["failures"]))

            write_bundle(candidate, {"base/lib/arm64-v8a/libharmless.so": b"not-elf"})
            with mock.patch.object(
                module,
                "_decoded_manifest_xml",
                return_value=(VALID_MANIFEST_XML, DECODER_EVIDENCE),
            ):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(any("not an ELF" in item for item in result["failures"]))

            write_bundle(candidate)
            with mock.patch.dict(os.environ, {}, clear=True):
                result = module.inspect(candidate)
            self.assertFalse(result["ok"])
            self.assertTrue(
                any("OWNER-BLOCKED" in item and "JDK" in item for item in result["failures"])
            )
        finally:
            candidate.unlink(missing_ok=True)

    def test_signed_aab_receipt_and_producer_are_independent_of_phone_tv(self) -> None:
        receipt = WEAR / "tools/signed_aab_receipt.py"
        create_receipt = WEAR / "tools/create_signed_aab_receipt.py"
        producer = WEAR / "tools/prepare_release.sh"
        pins = WEAR / "tools/external_tool_pins.json"
        self.assertTrue(receipt.is_file())
        self.assertTrue(create_receipt.is_file())
        self.assertTrue(producer.is_file())
        self.assertTrue(pins.is_file())
        receipt_text = source(receipt)
        create_text = source(create_receipt)
        producer_text = source(producer)
        pin_text = source(pins)
        self.assertIn("winsvpn-wear-os-signed-aab-receipt-v2", receipt_text)
        self.assertIn("winsvpn-wear-os-signed-aab-receipt-v2", create_text)
        self.assertIn("winsvpn-wear-os-private-symbol-custody-v2", create_text)
        self.assertIn('"publication_authorized": False', receipt_text)
        self.assertIn('"upload_performed": False', receipt_text)
        self.assertIn('"protection": "permission-frozen"', receipt_text)
        self.assertIn('"os_immutability_claimed": False', receipt_text)
        self.assertIn("EXPECTED_UPLOAD_CERTIFICATE_SHA256", receipt_text)
        for gate in (
            "prepare_release.sh",
            "private_release_symbol_custody.py",
            "validate_release_artifact_privacy.py",
            "verify_android_aab_signers.py",
        ):
            self.assertIn(gate, receipt_text)
        self.assertIn(":app:bundleRelease", producer_text)
        self.assertIn("android-release.env", producer_text)
        self.assertIn("create_signed_aab_receipt.py", producer_text)
        self.assertIn("OWNER-BLOCKED: exact latest-stable bundletool archive is absent", producer_text)
        self.assertIn("OWNER-BLOCKED: missing Android upload keystore", producer_text)
        self.assertIn("stale Wear AAB already exists", producer_text)
        self.assertIn("No Play Console upload or publication occurred.", producer_text)
        self.assertIn("Publication remains unauthorized", producer_text)
        self.assertNotIn("upload-ready", producer_text)
        self.assertIn("chmod 0444", producer_text)
        self.assertIn("latest_stable", pin_text)
        self.assertIn("bundletool-all-1.18.3.jar", pin_text)
        self.assertNotIn("curl ", producer_text)
        self.assertNotIn("wget ", producer_text)
        self.assertNotIn("android_release_publication.py commit", producer_text)
        self.assertNotIn("build_android_release_macos.sh", producer_text)
        self.assertNotIn("build_android_release.ps1", producer_text)

    def test_store_metadata_is_the_canonical_1015_companion_contract(self) -> None:
        privacy = json.loads(
            source(ROOT / "app_store/android/wear/review/privacy_label_manifest.json")
        )
        signoff = json.loads(source(ROOT / "app_store/android/wear/review/owner_signoff.json"))
        candidate = json.loads(
            source(ROOT / "app_store/android/wear/artifacts/release_candidate.json")
        )
        listing = source(ROOT / "app_store/android/wear/metadata/en-US/full_description.txt")
        title = source(ROOT / "app_store/android/wear/metadata/en-US/title.txt").strip()
        for payload in (privacy, signoff, candidate):
            self.assertEqual(payload["canonical_release"], "1.0.16+33")
        self.assertEqual(privacy["application_id"], "org.winsvpn.app")
        self.assertEqual(privacy["version_name"], "1.0.16")
        self.assertEqual(privacy["version_code"], 3301)
        self.assertFalse(privacy["standalone"])
        self.assertFalse(privacy["internet_permission"])
        self.assertFalse(privacy["vpn_service"])
        self.assertFalse(privacy["query_all_packages"])
        self.assertFalse(privacy["account_or_keys_on_watch"])
        self.assertFalse(privacy["data_collected"])
        self.assertEqual(privacy["listing_screenshot_inventory"], "owner-blocked")
        self.assertEqual(privacy["phone_tunnel_protocol"]["primary"], "winn-v3")
        self.assertEqual(privacy["phone_tunnel_protocol"]["fallback"], ["awg", "xray"])
        self.assertFalse(privacy["phone_tunnel_protocol"]["local_wear_inclusion"])
        self.assertIn("libwinnengine.so", privacy["phone_tunnel_protocol"]["forbidden_local_engines"])
        self.assertIn("libxray.so", privacy["phone_tunnel_protocol"]["forbidden_local_engines"])
        self.assertFalse(signoff["submission_approved"])
        self.assertFalse(signoff["upload_authorized"])
        self.assertEqual(signoff["version_code"], 3301)
        self.assertFalse(candidate["artifact"]["produced"])
        self.assertFalse(candidate["artifact"]["upload_performed"])
        self.assertEqual(candidate["package"], "org.winsvpn.app")
        self.assertEqual(candidate["version_code"], 3301)
        self.assertEqual(title, "Win's VPN")
        self.assertIn("Winn v3", listing)
        self.assertIn("AWG", listing)
        self.assertIn("Xray", listing)
        self.assertIn("not in this Wear package", listing)


if __name__ == "__main__":
    unittest.main()
