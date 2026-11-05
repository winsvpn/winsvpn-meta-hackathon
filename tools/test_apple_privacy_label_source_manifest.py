#!/usr/bin/env python3
"""Exact source-to-manifest checks for Apple Product Interaction disclosure."""

from __future__ import annotations

import json
import plistlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAIN_DART = ROOT / "lib" / "main.dart"
PRIVACY_ANSWERS = ROOT / "app_store" / "apple" / "review" / "privacy_answers.md"
PRIVACY_MANIFEST = ROOT / "app_store" / "apple" / "review" / "privacy_label_manifest.json"
PRIVACY_AUDIT = ROOT / "docs" / "APPLE_APP_PRIVACY_LABEL_AUDIT.md"
IOS_HOST = ROOT / "ios" / "Runner" / "PrivacyInfo.xcprivacy"
MACOS_HOST = ROOT / "macos" / "Runner" / "PrivacyInfo.xcprivacy"
NON_HOST_PRIVACY = (
    ROOT / "ios" / "PacketTunnel" / "PrivacyInfo.xcprivacy",
    ROOT / "macos" / "PacketTunnel" / "PrivacyInfo.xcprivacy",
    ROOT / "ios" / "WinsWatch Watch App" / "PrivacyInfo.xcprivacy",
)
NON_HOST_SCAN_ROOTS = (
    ROOT / "ios" / "PacketTunnel",
    ROOT / "macos" / "PacketTunnel",
    ROOT / "ios" / "WinsWatch Watch App",
)

APPLE_PRIVACY_DETAILS_URL = (
    "https://developer.apple.com/app-store/app-privacy-details/"
)
PRODUCT_INTERACTION = "NSPrivacyCollectedDataTypeProductInteraction"
PURCHASE_HISTORY = "NSPrivacyCollectedDataTypePurchaseHistory"
APP_FUNCTIONALITY = "NSPrivacyCollectedDataTypePurposeAppFunctionality"
PRESERVED_TYPES = (
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypeUserID",
)
SOURCE_PAYLOAD_KEYS = ("location", "stealth_mode", "double_vpn_enabled")
SOURCE_TO_MANIFEST = {
    "location": PRODUCT_INTERACTION,
    "stealth_mode": PRODUCT_INTERACTION,
    "double_vpn_enabled": PRODUCT_INTERACTION,
}
PAYLOAD_SITES = (
    (
        "paid_activation",
        "  Future<void> _loginWithAccountNumber() async {",
        "  Map<String, dynamic> _freeAccessPayload(",
        True,
    ),
    (
        "free_access",
        "  Map<String, dynamic> _freeAccessPayload(",
        "  Future<void> _loginWithFreeAccess() async {",
        False,
    ),
    (
        "paid_config_refresh",
        "  Future<bool> _refreshVpnConfigForCurrentSelection(",
        "  Future<bool> _waitForTunnelState(",
        True,
    ),
)
KEY_RE = re.compile(r"""['"]([A-Za-z0-9_]+)['"]\s*:""")
LOCATION_VALUE_RE = re.compile(
    r"""['"]location['"]\s*:\s*(_requestedLocationSlug\(\)|requestLocation)"""
)
ASCII_SCOPED_FILES = (
    PRIVACY_ANSWERS,
    PRIVACY_MANIFEST,
    PRIVACY_AUDIT,
    IOS_HOST,
    MACOS_HOST,
    Path(__file__),
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _load_plist(path: Path) -> dict:
    with path.open("rb") as handle:
        return plistlib.load(handle)


def _collected_entries(manifest: dict) -> dict[str, dict]:
    entries = {}
    for item in manifest.get("NSPrivacyCollectedDataTypes") or []:
        data_type = item.get("NSPrivacyCollectedDataType")
        if not isinstance(data_type, str) or not data_type:
            raise AssertionError(f"privacy collected data type missing in {item!r}")
        entries[data_type] = item
    return entries


def _extract_brace_map(source: str, start: int) -> str:
    """Return the map literal at the first brace after start, comments blanked.

    Comments are skipped (an apostrophe in a comment is not a quote) and
    blanked in the result, so a commented-out key never counts as sent."""
    index = source.find("{", start)
    if index < 0:
        raise AssertionError("no Dart map literal after payload marker")
    depth = 0
    in_quote = None
    escape = False
    kept = []
    offset = index
    while offset < len(source):
        char = source[offset]
        if in_quote is not None:
            kept.append(char)
            offset += 1
            if escape:
                escape = False
                continue
            if char == "\\":
                escape = True
                continue
            if char == in_quote:
                in_quote = None
            continue
        if source.startswith("//", offset):
            stop = source.find("\n", offset)
            stop = len(source) if stop < 0 else stop
            kept.append(" " * (stop - offset))
            offset = stop
            continue
        if source.startswith("/*", offset):
            stop = source.find("*/", offset + 2)
            if stop < 0:
                raise AssertionError("unterminated comment in Dart map literal")
            kept.append(re.sub(r"[^\n]", " ", source[offset : stop + 2]))
            offset = stop + 2
            continue
        kept.append(char)
        offset += 1
        if char in ("'", '"'):
            in_quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return "".join(kept)
    raise AssertionError("unbalanced Dart map literal")


def _named_payload_map(body: str, name: str, encode_at: int) -> str:
    """The map literal a single `final` local holds when jsonEncode(name) runs.

    The local must be declared once before the encode and must not be
    reassigned, indexed or have a method called on it before the encode, so
    the parsed literal is exactly what goes on the wire."""
    declarations = list(
        re.finditer(
            rf"\bfinal\s+(?:Map<String,\s*dynamic>\s+)?{re.escape(name)}\s*="
            rf"\s*(?:<String,\s*dynamic>\s*)?\{{",
            body[:encode_at],
        )
    )
    if len(declarations) != 1:
        raise AssertionError(
            f"expected one final map declaration of {name} before jsonEncode, "
            f"found {len(declarations)}"
        )
    literal_at = declarations[0].end() - 1
    payload = _extract_brace_map(body, literal_at)
    between = body[literal_at + len(payload) : encode_at]
    if re.search(rf"\b{re.escape(name)}\s*(?:\.|\[|\?|=(?!=))", between):
        raise AssertionError(f"{name} is changed between its literal and jsonEncode")
    return payload


def _payload_map(source: str, start_sig: str, end_sig: str) -> str:
    start = source.index(start_sig)
    end = source.index(end_sig, start + len(start_sig))
    body = source[start:end]
    marker = "jsonEncode("
    if marker in body:
        encode_at = body.index(marker)
        named = re.compile(r"jsonEncode\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)").match(
            body, encode_at
        )
        if named is not None:
            return _named_payload_map(body, named.group(1), encode_at)
        return _extract_brace_map(body, encode_at)
    return_at = body.index("return {")
    return _extract_brace_map(body, return_at)


def _map_keys(payload: str) -> set[str]:
    return set(KEY_RE.findall(payload))


class ApplePrivacyLabelSourceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.main = _read(MAIN_DART)
        cls.answers = _read(PRIVACY_ANSWERS)
        cls.audit = _read(PRIVACY_AUDIT)
        cls.manifest = json.loads(_read(PRIVACY_MANIFEST))
        cls.ios_host = _load_plist(IOS_HOST)
        cls.macos_host = _load_plist(MACOS_HOST)

    def test_scoped_privacy_files_are_ascii(self) -> None:
        for path in ASCII_SCOPED_FILES:
            with self.subTest(path=str(path.relative_to(ROOT))):
                path.read_text(encoding="ascii")

    def test_control_plane_payloads_send_product_interaction_with_ids(self) -> None:
        found_sites = []
        for name, start_sig, end_sig, require_account in PAYLOAD_SITES:
            with self.subTest(site=name):
                payload = _payload_map(self.main, start_sig, end_sig)
                keys = _map_keys(payload)
                found_sites.append(name)
                for key in SOURCE_PAYLOAD_KEYS:
                    self.assertIn(key, keys, f"{name} missing {key}")
                self.assertRegex(payload, LOCATION_VALUE_RE)
                self.assertIn("device_id", keys, f"{name} missing device_id")
                if require_account:
                    self.assertIn(
                        "account_number", keys, f"{name} missing account_number"
                    )
                self.assertIn("stealth_mode", keys)
                self.assertIn("double_vpn_enabled", keys)
        self.assertEqual(
            found_sites,
            ["paid_activation", "free_access", "paid_config_refresh"],
        )

    def test_source_keys_map_exactly_to_product_interaction(self) -> None:
        summary = self.manifest["app_store_connect_summary"]
        linked = {
            item["apple_manifest_data_type"]: item
            for item in summary["data_linked_to_user"]
        }
        product = linked[PRODUCT_INTERACTION]
        self.assertEqual(product["category"], "Usage Data")
        self.assertEqual(product["label"], "Product Interaction")
        self.assertIs(product["linked"], True)
        self.assertIs(product["tracking"], False)
        self.assertEqual(product["purposes"], [APP_FUNCTIONALITY])
        self.assertEqual(
            tuple(product["source_payload_keys"]),
            SOURCE_PAYLOAD_KEYS,
        )
        self.assertEqual(
            product["covers"],
            [
                "selected VPN location",
                "stealth mode",
                "Double VPN",
            ],
        )
        for key, data_type in SOURCE_TO_MANIFEST.items():
            self.assertEqual(data_type, PRODUCT_INTERACTION, key)
            self.assertIn(key, product["source_payload_keys"])

    def test_host_privacy_manifests_match_source_truth(self) -> None:
        expected = set(self.manifest["binary_evidence"]["source_host_collected_data_types"])
        self.assertEqual(
            expected,
            set(PRESERVED_TYPES) | {PRODUCT_INTERACTION},
        )
        linked_types = {
            item["apple_manifest_data_type"]
            for item in self.manifest["app_store_connect_summary"]["data_linked_to_user"]
        }
        self.assertEqual(linked_types, expected)
        for path, manifest in (
            (IOS_HOST, self.ios_host),
            (MACOS_HOST, self.macos_host),
        ):
            with self.subTest(path=str(path.relative_to(ROOT))):
                collected = _collected_entries(manifest)
                self.assertEqual(set(collected), expected)
                self.assertNotIn(PURCHASE_HISTORY, collected)
                self.assertIs(manifest["NSPrivacyTracking"], False)
                self.assertEqual(manifest.get("NSPrivacyTrackingDomains") or [], [])
                for data_type in expected:
                    item = collected[data_type]
                    self.assertIs(item["NSPrivacyCollectedDataTypeLinked"], True)
                    self.assertIs(item["NSPrivacyCollectedDataTypeTracking"], False)
                    self.assertEqual(
                        item["NSPrivacyCollectedDataTypePurposes"],
                        [APP_FUNCTIONALITY],
                    )

    def test_purchase_history_stays_uncollected_in_source(self) -> None:
        summary = self.manifest["app_store_connect_summary"]
        linked_labels = {item["label"] for item in summary["data_linked_to_user"]}
        self.assertNotIn("Purchase History", linked_labels)
        self.assertEqual(
            summary["purchase_history_status"],
            "source_truth_not_collected_live_portal_over_declared",
        )
        self.assertIn("Purchase History: **not collected by the Apple app.**", self.answers)
        self.assertIn("Purchase History: not collected by the Apple app", self.audit)
        self.assertIn("stale live portal declaration must be removed", self.audit)
        self.assertIn(
            "stale live App Store Connect Purchase History declaration must be removed",
            self.answers,
        )

    def test_live_portal_still_requires_reconcile_and_was_not_updated(self) -> None:
        live = self.manifest["live_app_store_connect_sync"]
        self.assertIs(live["app_store_connect_updated"], False)
        self.assertEqual(
            live["published_data_types"],
            ["Coarse Location", "User ID", "Device ID", "Purchase History"],
        )
        self.assertNotIn("Product Interaction", live["published_data_types"])
        note = live["reconcile_note"]
        self.assertIn("NOT re-synchronized", note)
        self.assertIn("must remove Purchase History", note)
        self.assertIn("add Product Interaction", note)
        self.assertIn("does not claim App Store Connect was updated", note)
        self.assertIn("does not claim App Store Connect was updated", self.answers)
        self.assertIn("does not claim App Store Connect was updated", self.audit)
        self.assertEqual(
            self.manifest["app_store_connect_summary"]["product_interaction_status"],
            "source_truth_disclosed_linked_app_functionality_live_portal_under_declared",
        )

    def test_last_archive_evidence_is_not_rewritten_as_source_truth(self) -> None:
        evidence = self.manifest["binary_evidence"]
        source_types = set(evidence["source_host_collected_data_types"])
        self.assertIn(PRODUCT_INTERACTION, source_types)
        for archive in evidence["expected_archives"]:
            archive_types = set(archive["host_app_collected_data_types"])
            self.assertEqual(archive_types, set(PRESERVED_TYPES))
            self.assertNotIn(PRODUCT_INTERACTION, archive_types)
            self.assertEqual(archive["packet_tunnel_collected_data_types"], [])

    def test_non_host_targets_do_not_declare_or_transmit_the_fields(self) -> None:
        for path in NON_HOST_PRIVACY:
            with self.subTest(manifest=str(path.relative_to(ROOT))):
                collected = _collected_entries(_load_plist(path))
                self.assertEqual(collected, {})
        payload_needles = (
            '"stealth_mode"',
            "'stealth_mode'",
            '"double_vpn_enabled"',
            "'double_vpn_enabled'",
            "_requestedLocationSlug",
        )
        for root in NON_HOST_SCAN_ROOTS:
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in {".swift", ".plist", ".xcprivacy"}:
                    continue
                if path.name.startswith("._"):
                    continue
                text = path.read_text(encoding="utf-8")
                for needle in payload_needles:
                    self.assertNotIn(
                        needle,
                        text,
                        f"{path.relative_to(ROOT)} must not transmit {needle}",
                    )

    def test_answers_and_audit_cite_apple_taxonomy_and_payload_sites(self) -> None:
        self.assertEqual(
            self.manifest["apple_privacy_details_url"],
            APPLE_PRIVACY_DETAILS_URL,
        )
        for text in (self.answers, self.audit):
            self.assertIn(APPLE_PRIVACY_DETAILS_URL, text)
            self.assertIn("Usage Data: Product Interaction", text)
            self.assertIn("selected VPN location", text)
            self.assertIn("stealth mode", text)
            self.assertIn("Double VPN", text)
            self.assertIn("linked to the user", text.lower())
            self.assertIn("not used for tracking", text.lower())
            self.assertIn("App Functionality", text)
            self.assertIn("_loginWithAccountNumber", text)
            self.assertIn("_freeAccessPayload", text)
            self.assertIn("_refreshVpnConfigForCurrentSelection", text)
            self.assertIn("`location`", text)
            self.assertIn("`stealth_mode`", text)
            self.assertIn("`double_vpn_enabled`", text)
        self.assertNotIn(
            "selected VPN location, and build capability flags",
            self.answers,
        )
        self.assertIn(
            "Coarse Location: linked to the user for app functionality",
            self.answers,
        )
        self.assertIn(
            "Coarse Location: linked to the user for app functionality",
            self.audit,
        )
        self.assertIn("Identifiers: User ID", self.answers)
        self.assertIn("Identifiers: Device ID", self.answers)
        self.assertIn("Identifiers: User ID", self.audit)
        self.assertIn("Identifiers: Device ID", self.audit)


if __name__ == "__main__":
    unittest.main()
