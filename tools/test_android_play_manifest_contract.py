#!/usr/bin/env python3
"""Source-level Google Play permission and foreground-service manifest gates."""

from __future__ import annotations

import pathlib
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "android/app/src/main/AndroidManifest.xml"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def validate_manifest(xml: str) -> list[str]:
    root = ET.fromstring(xml)
    errors: list[str] = []
    permissions = {
        node.attrib.get(f"{ANDROID}name", "")
        for node in root.findall("uses-permission")
    }
    if "android.permission.SEND_SMS" in permissions:
        errors.append("SEND_SMS must not be present in a Play release manifest")
    if "android.permission.MANAGE_EXTERNAL_STORAGE" in permissions:
        errors.append("MANAGE_EXTERNAL_STORAGE must not be present")
    if "android.permission.QUERY_ALL_PACKAGES" not in permissions:
        errors.append("QUERY_ALL_PACKAGES split-tunnel visibility contract is missing")

    service = next(
        (
            node
            for node in root.findall("./application/service")
            if node.attrib.get(f"{ANDROID}name") == ".VpnTunnelService"
        ),
        None,
    )
    if service is None:
        errors.append("VpnTunnelService is missing")
        return errors
    if service.attrib.get(f"{ANDROID}foregroundServiceType") != "specialUse":
        errors.append("VpnTunnelService must declare specialUse")
    subtype = [
        node
        for node in service.findall("property")
        if node.attrib.get(f"{ANDROID}name")
        == "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
    ]
    if len(subtype) != 1 or not subtype[0].attrib.get(f"{ANDROID}value", "").strip():
        errors.append("specialUse requires one nonempty PROPERTY_SPECIAL_USE_FGS_SUBTYPE")
    if any(
        node.attrib.get(f"{ANDROID}name")
        in {
            "android.app.PROPERTY_SPECIAL_USE_DESCRIPTION",
            "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE",
        }
        for node in service.findall("meta-data")
    ):
        errors.append("specialUse subtype must be a property, not meta-data")
    return errors


class AndroidPlayManifestContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.xml = MANIFEST.read_text(encoding="utf-8")

    def test_live_manifest(self) -> None:
        self.assertEqual([], validate_manifest(self.xml))

    def test_rejects_obsolete_metadata_shape(self) -> None:
        broken = self.xml.replace(
            "<property\n                android:name=\"android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE\"",
            "<meta-data\n                android:name=\"android.app.PROPERTY_SPECIAL_USE_DESCRIPTION\"",
        )
        self.assertIn("specialUse subtype must be a property, not meta-data", validate_manifest(broken))

    def test_rejects_restricted_storage_and_sms_permissions(self) -> None:
        marker = '<uses-permission android:name="android.permission.INTERNET" />'
        broken = self.xml.replace(
            marker,
            marker
            + '\n    <uses-permission android:name="android.permission.SEND_SMS" />'
            + '\n    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />',
        )
        errors = validate_manifest(broken)
        self.assertTrue(any("SEND_SMS" in error for error in errors))
        self.assertTrue(any("MANAGE_EXTERNAL_STORAGE" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
