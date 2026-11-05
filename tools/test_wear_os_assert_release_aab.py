#!/usr/bin/env python3
"""Focused Wear AAB inspector regressions for R8 mapping evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import tempfile
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSERT_AAB = ROOT / "wear_os/tools/assert_release_aab.py"
REAL_MAPPING = ROOT / "wear_os/app/build/outputs/mapping/release/mapping.txt"


def load_assert_aab():
    spec = importlib.util.spec_from_file_location("wear_assert_release_aab", ASSERT_AAB)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def r8_mapping_bytes(class_count: int = 40, *, newline: str = "\n") -> bytes:
    body_lines = []
    for index in range(class_count):
        body_lines.append(f"org.winsvpn.app.wear.Synthetic{index:04d} -> a{index:04d}:")
        body_lines.append("    1:1:void run():0:0 -> a")
    body = "\n".join(body_lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    header = (
        "# compiler: R8\n"
        "# compiler_version: 9.3.16\n"
        "# min_api: 30\n"
        "# common_typos_disable\n"
        '# {"id":"com.android.tools.r8.mapping","version":"2.2"}\n'
        f"# pg_map_hash: SHA-256 {digest}\n"
    )
    text = header + body
    if newline != "\n":
        text = text.replace("\n", newline)
    return text.encode("utf-8")


def padded_trivial_r8_mapping(class_count: int = 1) -> bytes:
    body_lines = []
    for index in range(class_count):
        body_lines.append(f"org.winsvpn.app.wear.Tiny{index} -> t{index}:")
    body_lines.extend(["# padding"] * 250)
    body = "\n".join(body_lines) + "\n"
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    header = (
        "# compiler: R8\n"
        f"# pg_map_hash: SHA-256 {digest}\n"
    )
    return (header + body).encode("utf-8")


def canonical_wear_manifest_xml(
    *,
    package: str = "org.winsvpn.app",
    version_name: str = "1.0.16",
    version_code: str = "3301",
    extra_permission: bytes | None = None,
    extra_category: bytes | None = None,
    min_sdk: str = "30",
    target_sdk: str = "37",
    include_uses_sdk: bool = True,
) -> bytes:
    permission = extra_permission or b""
    category = extra_category or b""
    uses_sdk = b""
    if include_uses_sdk:
        uses_sdk = (
            b'<uses-sdk android:minSdkVersion="'
            + min_sdk.encode("ascii")
            + b'" android:targetSdkVersion="'
            + target_sdk.encode("ascii")
            + b'" />'
        )
    return (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="' + package.encode("ascii") + b'" '
        b'android:versionName="' + version_name.encode("ascii") + b'" '
        b'android:versionCode="' + version_code.encode("ascii") + b'">'
        + uses_sdk
        + b'<uses-feature android:name="android.hardware.type.watch" '
        b'android:required="true" />'
        + permission
        + b"<application>"
        b'<meta-data android:name="com.google.android.wearable.standalone" '
        b'android:value="false" />'
        b'<activity android:name="org.winsvpn.app.wear.MainActivity" '
        b'android:exported="true">'
        b"<intent-filter>"
        b'<action android:name="android.intent.action.MAIN" />'
        b'<category android:name="android.intent.category.LAUNCHER" />'
        + category
        + b"</intent-filter></activity></application></manifest>"
    )


class WearOsAssertReleaseAabMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_assert_aab()
        cls.approved_native_libraries = dict(cls.module.APPROVED_NATIVE_LIBRARIES)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wear-assert-aab-")
        self.work = pathlib.Path(self.temporary.name)
        allowlist = mock.patch.dict(self.module.APPROVED_NATIVE_LIBRARIES, {}, clear=True)
        allowlist.start()
        self.addCleanup(allowlist.stop)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_bundle(
        self,
        name: str = "candidate.aab",
        *,
        mapping: bytes | None = None,
        extra: dict[str, bytes] | None = None,
        include_official_map: bool = True,
    ) -> pathlib.Path:
        path = self.work / name
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("BundleConfig.pb", b"ok")
            if include_official_map:
                archive.writestr(
                    self.module.OFFICIAL_PROGUARD_MAP,
                    r8_mapping_bytes() if mapping is None else mapping,
                )
            archive.writestr("base/manifest/AndroidManifest.xml", b"compiled-manifest")
            for member, data in (extra or {}).items():
                archive.writestr(member, data)
        return path

    def test_exact_bytes_bind_records_matching_hashes(self) -> None:
        mapping = r8_mapping_bytes()
        bound = self.module.bind_r8_mapping_bytes(mapping, mapping)
        digest = hashlib.sha256(mapping).hexdigest()
        self.assertTrue(bound["bound"])
        self.assertTrue(bound["exact_bytes"])
        self.assertEqual(bound["canonicalization"], self.module.CANONICALIZATION_IDENTITY)
        self.assertEqual(bound["external_sha256"], digest)
        self.assertEqual(bound["embedded_sha256"], digest)
        self.assertEqual(bound["canonical_sha256"], digest)
        self.assertEqual(bound["embedded_path"], self.module.OFFICIAL_PROGUARD_MAP)

    def test_crlf_packaging_uses_documented_utf8_lf_canonicalization(self) -> None:
        lf = r8_mapping_bytes()
        crlf = r8_mapping_bytes(newline="\r\n")
        self.assertNotEqual(lf, crlf)
        bound = self.module.bind_r8_mapping_bytes(lf, crlf)
        self.assertTrue(bound["bound"])
        self.assertFalse(bound["exact_bytes"])
        self.assertEqual(bound["canonicalization"], self.module.CANONICALIZATION_UTF8_LF)
        self.assertEqual(bound["external_sha256"], hashlib.sha256(lf).hexdigest())
        self.assertEqual(bound["embedded_sha256"], hashlib.sha256(crlf).hexdigest())
        self.assertNotEqual(bound["external_sha256"], bound["embedded_sha256"])
        self.assertEqual(bound["canonical_sha256"], hashlib.sha256(lf).hexdigest())

    def test_mismatched_mappings_fail_closed(self) -> None:
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module.bind_r8_mapping_bytes(r8_mapping_bytes(40), r8_mapping_bytes(41))
        self.assertIn("not bound", str(raised.exception))

    def test_tiny_placeholder_mapping_fails_closed(self) -> None:
        tiny = b"# compiler: R8\nclass org.winsvpn.app.wear.MainActivity\n"
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module.validate_r8_mapping_bytes(tiny, "external R8 mapping")
        self.assertIn("too small", str(raised.exception))

    def test_valid_hash_with_too_few_class_mappings_is_trivial(self) -> None:
        padded = padded_trivial_r8_mapping(1)
        self.assertGreaterEqual(len(padded), self.module.MIN_R8_MAPPING_BYTES)
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module.validate_r8_mapping_bytes(padded, "embedded AAB proguard.map")
        self.assertIn("too trivial", str(raised.exception))

    def test_broken_pg_map_hash_fails_closed(self) -> None:
        mapping = bytearray(r8_mapping_bytes())
        marker = b"pg_map_hash: SHA-256 "
        index = mapping.find(marker)
        self.assertGreater(index, 0)
        mapping[index + len(marker)] ^= 0x01
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module.validate_r8_mapping_bytes(bytes(mapping), "external R8 mapping")
        self.assertIn("pg_map_hash", str(raised.exception))

    def test_inspector_rejects_absent_proguard_map(self) -> None:
        path = self.write_bundle(include_official_map=False)
        result = self.module.inspect(path)
        self.assertFalse(result["ok"])
        self.assertTrue(any("missing release proguard.map" in item for item in result["failures"]))

    def test_inspector_rejects_non_official_proguard_map_path(self) -> None:
        path = self.write_bundle(
            include_official_map=False,
            extra={"BUNDLE-METADATA/other/proguard.map": r8_mapping_bytes()},
        )
        result = self.module.inspect(path)
        self.assertFalse(result["ok"])
        self.assertTrue(any("missing release proguard.map" in item for item in result["failures"]))

    def test_inspector_rejects_duplicate_proguard_map_members(self) -> None:
        mapping = r8_mapping_bytes()
        path = self.write_bundle(
            mapping=mapping,
            extra={"assets/proguard.map": mapping},
        )
        result = self.module.inspect(path)
        self.assertFalse(result["ok"])
        self.assertTrue(any("duplicate proguard.map" in item for item in result["failures"]))
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module.read_embedded_proguard_map(path)
        self.assertIn("duplicate proguard.map", str(raised.exception))

    def test_inspector_rejects_embedded_tiny_mapping_without_bundletool(self) -> None:
        path = self.write_bundle(mapping=b"mapping-placeholder")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WINS_BUNDLETOOL_JAR", None)
            os.environ.pop(self.module.JAVA_HOME_ENV, None)
            result = self.module.inspect(path)
        self.assertFalse(result["ok"])
        self.assertTrue(any("too small" in item for item in result["failures"]))
        self.assertFalse(any("WINS_BUNDLETOOL_JAR" in item for item in result["failures"]))
        self.assertFalse(any("OWNER-BLOCKED" in item for item in result["failures"]))

    def test_missing_bundletool_archive_is_owner_blocked(self) -> None:
        pin = dict(self.module.bundletool_pin())
        pin["archive_path"] = "/no/such/winsvpn-bundletool.jar"
        with mock.patch.dict(
            os.environ,
            {self.module.JAVA_HOME_ENV: "/usr"},
            clear=False,
        ), mock.patch.object(self.module, "bundletool_pin", return_value=pin):
            os.environ.pop("WINS_BUNDLETOOL_JAR", None)
            with self.assertRaises(self.module.InspectionError) as raised:
                self.module._bundletool_jar()
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        self.assertIn("bundletool", str(raised.exception))

    def test_ambient_bundletool_env_and_path_java_are_refused(self) -> None:
        source = ASSERT_AAB.read_text(encoding="utf-8")
        self.assertNotIn("shutil.which", source)
        self.assertNotIn('os.environ.get("PATH"', source)
        with mock.patch.dict(os.environ, {"WINS_BUNDLETOOL_JAR": "/hostile/bundletool.jar"}, clear=False):
            with self.assertRaises(self.module.InspectionError) as raised:
                self.module.authenticated_java()
        self.assertIn("ambient WINS_BUNDLETOOL_JAR", str(raised.exception))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self.module.JAVA_HOME_ENV, None)
            os.environ.pop("WINS_BUNDLETOOL_JAR", None)
            with self.assertRaises(self.module.InspectionError) as raised:
                self.module.authenticated_java()
        self.assertIn("OWNER-BLOCKED", str(raised.exception))
        self.assertIn("JDK", str(raised.exception))

    def test_inspector_records_exact_embedded_hash_on_valid_mapping(self) -> None:
        mapping = r8_mapping_bytes()
        path = self.write_bundle(mapping=mapping)
        decoder = {
            "decoder": "bundletool",
            "version": "1.18.3",
            "jar_sha256": self.module.BUNDLETOOL_ALL_SHA256,
        }
        xml = canonical_wear_manifest_xml()
        with mock.patch.object(
            self.module, "_decoded_manifest_xml", return_value=(xml, decoder)
        ):
            result = self.module.inspect(path)
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(
            result["proguard_map"]["sha256"], hashlib.sha256(mapping).hexdigest()
        )
        self.assertEqual(result["proguard_map"]["path"], self.module.OFFICIAL_PROGUARD_MAP)

    def test_decoded_manifest_refuses_query_all_packages(self) -> None:
        xml = canonical_wear_manifest_xml(
            extra_permission=b'<uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />',
        )
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(xml)
        self.assertIn("QUERY_ALL_PACKAGES", str(raised.exception))

    def test_companion_protocol_stays_on_the_paired_phone(self) -> None:
        contract = self.module.companion_protocol_contract()
        self.assertEqual(contract["primary"], "winn-v3")
        self.assertEqual(contract["fallback"], ["awg", "xray"])
        self.assertEqual(contract["executed_on"], "paired-phone")
        self.assertFalse(contract["local_wear_inclusion"])
        self.assertFalse(contract["local_tunnel"])
        self.assertEqual(
            contract["forbidden_local_engines"],
            sorted(self.module.FORBIDDEN_VPN_ENGINE_BASENAMES),
        )
        allowlisted = {
            pathlib.Path(path).name.casefold()
            for path in self.approved_native_libraries
        }
        forbidden = {name.casefold() for name in self.module.FORBIDDEN_VPN_ENGINE_BASENAMES}
        self.assertFalse(allowlisted & forbidden)

    def test_phone_vpn_engines_fail_before_the_native_allowlist(self) -> None:
        decoder = {
            "decoder": "bundletool",
            "version": "1.18.3",
            "jar_sha256": self.module.BUNDLETOOL_ALL_SHA256,
        }
        xml = canonical_wear_manifest_xml()
        payloads = (
            ("base/lib/arm64-v8a/libwinnengine.so", b"\x7fELFwinn-v3"),
            ("base/lib/arm64-v8a/libxray.so", b"\x7fELFxray"),
            ("base/assets/amneziawg.aar", b"PK\x03\x04aar"),
        )
        for member, data in payloads:
            with self.subTest(member=member):
                digest = hashlib.sha256(data).hexdigest()
                with mock.patch.dict(
                    self.module.APPROVED_NATIVE_LIBRARIES,
                    {member: digest},
                    clear=False,
                ), mock.patch.object(
                    self.module, "_decoded_manifest_xml", return_value=(xml, decoder)
                ):
                    result = self.module.inspect(self.write_bundle(extra={member: data}))
                self.assertFalse(result["ok"])
                self.assertTrue(
                    any(
                        "must not include phone VPN engine" in item
                        for item in result["failures"]
                    ),
                    result["failures"],
                )

    def test_decoded_manifest_binds_canonical_watch_identity(self) -> None:
        identity = self.module._validate_manifest(canonical_wear_manifest_xml())
        self.assertEqual(identity["package"], "org.winsvpn.app")
        self.assertEqual(identity["version_name"], "1.0.16")
        self.assertEqual(identity["version_code"], 3301)
        self.assertEqual(identity["min_sdk"], 30)
        self.assertEqual(identity["target_sdk"], 37)

    def test_decoded_manifest_refuses_wrong_min_or_target_sdk(self) -> None:
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(canonical_wear_manifest_xml(target_sdk="35"))
        self.assertIn("targetSdkVersion", str(raised.exception))
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(canonical_wear_manifest_xml(min_sdk="26"))
        self.assertIn("minSdkVersion", str(raised.exception))
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(
                canonical_wear_manifest_xml(include_uses_sdk=False)
            )
        self.assertIn("uses-sdk", str(raised.exception))

    def test_decoded_manifest_refuses_phone_and_tv_version_codes(self) -> None:
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(canonical_wear_manifest_xml(version_code="33"))
        self.assertIn("phone target", str(raised.exception))
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(canonical_wear_manifest_xml(version_code="3302"))
        self.assertIn("Android TV target", str(raised.exception))

    def test_decoded_manifest_refuses_contaminated_packages(self) -> None:
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(
                canonical_wear_manifest_xml(package="org.winsvpn.app.tv")
            )
        self.assertIn("contaminated TV identity", str(raised.exception))
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(
                canonical_wear_manifest_xml(package="com.example.wins_vpn")
            )
        self.assertIn("stale debug application ID", str(raised.exception))

    def test_decoded_manifest_refuses_leanback_launcher(self) -> None:
        xml = canonical_wear_manifest_xml(
            extra_category=b'<category android:name="android.intent.category.LEANBACK_LAUNCHER" />',
        )
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(xml)
        self.assertIn("LEANBACK_LAUNCHER", str(raised.exception))

    def test_decoded_manifest_refuses_missing_version_identity(self) -> None:
        xml = (
            b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
            b'package="org.winsvpn.app">'
            b'<uses-feature android:name="android.hardware.type.watch" '
            b'android:required="true" />'
            b"<application>"
            b'<meta-data android:name="com.google.android.wearable.standalone" '
            b'android:value="false" />'
            b'<activity android:name="org.winsvpn.app.wear.MainActivity" '
            b'android:exported="true">'
            b"<intent-filter>"
            b'<action android:name="android.intent.action.MAIN" />'
            b'<category android:name="android.intent.category.LAUNCHER" />'
            b"</intent-filter></activity></application></manifest>"
        )
        with self.assertRaises(self.module.InspectionError) as raised:
            self.module._validate_manifest(xml)
        self.assertIn("canonical 1.0.16+33 watch identity", str(raised.exception))

    def test_local_wear_r8_mapping_output_is_nontrivial_when_present(self) -> None:
        if not REAL_MAPPING.is_file() or REAL_MAPPING.is_symlink():
            self.skipTest("local Wear R8 mapping output is not present")
        evidence = self.module.validate_r8_mapping_bytes(
            REAL_MAPPING.read_bytes(), "local Wear mapping.txt"
        )
        self.assertGreaterEqual(
            int(evidence["class_mapping_count"]), self.module.MIN_R8_CLASS_MAPPINGS
        )
        self.assertGreaterEqual(int(evidence["size_bytes"]), self.module.MIN_R8_MAPPING_BYTES)


if __name__ == "__main__":
    unittest.main()
