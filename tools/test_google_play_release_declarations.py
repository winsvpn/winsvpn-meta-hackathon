#!/usr/bin/env python3
"""Static metadata contract for Google Play release declarations.

Ground truth is current repository behavior, not historical Play copy. This
module only reads docs/GOOGLE_PLAY_RELEASE_DECLARATIONS.md and the source
files that document names. It does not call networks, stores, signing,
packaging, or release gates.
"""

from __future__ import annotations

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PLAY_PATH = ROOT / "docs" / "GOOGLE_PLAY_RELEASE_DECLARATIONS.md"
MAIN_MANIFEST = ROOT / "android" / "app" / "src" / "main" / "AndroidManifest.xml"
TV_MANIFEST = ROOT / "android" / "app" / "src" / "tv" / "AndroidManifest.xml"
WEAR_MANIFEST = ROOT / "wear_os" / "app" / "src" / "main" / "AndroidManifest.xml"
CAMOUFLAGE = ROOT / "lib" / "camouflage_policy.dart"
LOCAL_SECURITY = ROOT / "lib" / "local_security.dart"
CLIENT = ROOT / "lib" / "main.dart"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
QUERY_ALL = "android.permission.QUERY_ALL_PACKAGES"
# Copied from tools/cross_store_upload_readiness.py so this test can assert the
# declarations document still exposes exactly one machine-readable status line
# without importing or editing that release-gate module.
QUERY_STATUS_RE = re.compile(r"Approval status:\s*`([A-Z]+)(?: \([^)]+\))?`")
INVENTORY_RE = re.compile(
    r"^- (phone|TV|Wear) listing/screenshot inventory: owner-blocked$",
    re.MULTILINE,
)


def source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def permission_names(xml: str) -> set[str]:
    root = ET.fromstring(xml)
    return {
        node.attrib.get(f"{ANDROID_NS}name", "")
        for node in root.findall("uses-permission")
    }


def dart_const_int(text: str, name: str) -> int:
    match = re.search(rf"const int {name} = (\d+);", text)
    if match is None:
        raise AssertionError(f"missing Dart constant {name}")
    return int(match.group(1))


def dart_getter(text: str, signature: str) -> str:
    start = text.index(signature)
    end = text.index(";", start)
    return re.sub(r"\s+", " ", text[start:end])


class GooglePlayReleaseDeclarationsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.play = source(PLAY_PATH)
        self.play_text = re.sub(r"\s+", " ", self.play)
        self.client = source(CLIENT)
        self.camouflage = source(CAMOUFLAGE)
        self.local_security = source(LOCAL_SECURITY)
        self.main_manifest = source(MAIN_MANIFEST)
        self.tv_manifest = source(TV_MANIFEST)
        self.wear_manifest = source(WEAR_MANIFEST)

    def test_document_is_ascii_only(self) -> None:
        self.play.encode("ascii")

    def test_reviewer_access_uses_six_digit_enrollment_pin_contract(self) -> None:
        pin_length = dart_const_int(self.camouflage, "kCamouflagePinLength")
        legacy_length = dart_const_int(self.camouflage, "kLegacyCamouflagePinLength")
        self.assertEqual(pin_length, 6)
        self.assertEqual(legacy_length, 4)
        self.assertIn(
            "PIN must contain exactly $kCamouflagePinLength digits",
            self.local_security,
        )
        self.assertIn("000000", self.local_security)
        self.assertIn("six-digit PIN", self.play)
        self.assertIn("`kCamouflagePinLength`", self.play)
        self.assertIn("Set a six-digit PIN", self.play)
        self.assertNotIn("Set a 4-digit PIN", self.play)
        self.assertNotIn("configured 4-digit PIN", self.play)
        self.assertNotIn("PIN `0000`", self.play)
        self.assertIn("Do not instruct reviewers to use `0000`", self.play)
        self.assertIn("`000000` is refused", self.play)
        self.assertIn("cannot enroll a four-digit PIN", self.play)

    def test_tv_inherits_query_all_packages_and_exposes_per_app_picker(self) -> None:
        self.assertIn(QUERY_ALL, permission_names(self.main_manifest))
        self.assertNotIn(QUERY_ALL, permission_names(self.tv_manifest))
        self.assertNotIn(QUERY_ALL, self.tv_manifest)
        self.assertNotRegex(self.tv_manifest, r'<uses-permission[^>]*tools:node="remove"')
        getter = dart_getter(self.client, "bool get _supportsPerAppSplitTunneling")
        self.assertIn("Platform.isAndroid || Platform.isLinux", getter)
        self.assertNotIn("DeviceFormFactor.tv", getter)
        self.assertNotIn("_isAndroidTv", getter)
        self.assertIn("The TV flavor inherits `QUERY_ALL_PACKAGES`", self.play)
        self.assertIn("does not remove that permission", self.play)
        self.assertIn("TV UI exposes the same per-app picker", self.play)
        self.assertIn("Exclude Apps From VPN (Split Tunneling)", self.play)
        self.assertIn("Do not claim phone-only `QUERY_ALL_PACKAGES`", self.play)
        self.assertNotIn(
            "`QUERY_ALL_PACKAGES` remains a phone split-tunnel declaration",
            self.play,
        )
        self.assertNotIn("Do not invent a TV all-apps picker story", self.play)

    def test_query_all_packages_pending_status_covers_tv_and_appears_once(self) -> None:
        statuses = QUERY_STATUS_RE.findall(self.play)
        self.assertEqual(statuses, ["PENDING"])
        self.assertIn("Approval status: `PENDING`", self.play)
        self.assertIn(
            "including the TV flavor of the same application ID",
            self.play,
        )
        self.assertIn(
            "declaration remains `PENDING` for this shared application ID, including TV",
            self.play,
        )
        self.assertNotIn(QUERY_ALL, permission_names(self.wear_manifest))
        self.assertNotIn("android.permission.INTERNET", permission_names(self.wear_manifest))
        self.assertIn(
            "Wear OS does not request `QUERY_ALL_PACKAGES`",
            self.play,
        )

    def test_owner_blocked_listing_screenshot_inventory_fields(self) -> None:
        fields = INVENTORY_RE.findall(self.play)
        self.assertEqual(fields, ["phone", "TV", "Wear"])
        self.assertIn("phone listing/screenshot inventory: owner-blocked", self.play)
        self.assertIn("TV listing/screenshot inventory: owner-blocked", self.play)
        self.assertIn("Wear listing/screenshot inventory: owner-blocked", self.play)
        self.assertIn("Do not invent those assets", self.play_text)
        self.assertIn("store-portal", self.play)
        self.assertIn(
            "treat this document as Play Console graphics approval",
            self.play_text,
        )
        self.assertNotRegex(
            self.play,
            r"(?im)^- (phone|TV|Wear) listing/screenshot inventory: "
            r"(approved|ready|uploaded)",
        )

    def test_preserves_winn_v3_primary_and_winn_v1_awg_fallback_without_android_xray(
        self,
    ) -> None:
        self.assertIn(
            "Winn v3 is the product's primary protocol",
            self.client,
        )
        self.assertIn(
            "Winn v1 is an ordered compatibility pair: AWG first, then Xray",
            self.client,
        )
        self.assertIn("Winn v3 is the product's primary protocol", self.play)
        self.assertIn("Winn v1 AWG fallback", self.play)
        self.assertIn("The Android build ships and runs no Xray", self.play)
        self.assertNotIn("Winn v1 AWG then Xray fallback", self.play)
        self.assertIn("before its first AWG or Xray candidate", self.play)
        self.assertIn(
            "neither direct AWG nor Xray fallback has a separate request site",
            self.play_text,
        )

    def test_tv_camouflage_is_disabled_in_source_and_declarations(self) -> None:
        start = self.camouflage.index("bool supportsInAppCalculatorCamouflage")
        fragment = self.camouflage[start : start + 400]
        self.assertIn(
            "if (formFactor == DeviceFormFactor.tv) return false;",
            fragment,
        )
        self.assertIn("Calculator camouflage is disabled on TV", self.play)
        self.assertIn("Android TV never presents the decoy calculator", self.play)
        self.assertIn("Calculator camouflage is phone-only", self.play)


if __name__ == "__main__":
    unittest.main()
