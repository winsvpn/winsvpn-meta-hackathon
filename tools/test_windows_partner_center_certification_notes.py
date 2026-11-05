#!/usr/bin/env python3
"""Focused static checks for Windows Partner Center certification notes."""

from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
NOTES_PATH = ROOT / "installer/windows/store/certification-notes.md"
POLICY = (
    "Standalone Winn Protocol v3 is primary. Winn Protocol v1 is fallback and "
    "tries current reviewed AmneziaWG first, then current reviewed Xray only if "
    "AWG fails."
)
OWNER_BLOCKED_ABSENT = "OWNER-BLOCKED: ABSENT"
PLACEHOLDER_MARKERS = (
    "[provide",
    "[attach",
    "TODO",
    "TBD",
    "FIXME",
    "<insert",
    "your-hash-here",
    "example.com",
    "REPLACE_ME",
)
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class WindowsPartnerCenterCertificationNotesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = NOTES_PATH.read_bytes()
        self.text = self.raw.decode("ascii")
        self.collapsed = re.sub(r"\s+", " ", self.text)

    def _field_block(self, field: str) -> str:
        start = self.text.index(field)
        return self.text[start : start + 400]

    def test_notes_are_ascii_only(self) -> None:
        self.assertEqual(self.raw.decode("ascii"), self.text)

    def test_malformed_intro_is_removed(self) -> None:
        self.assertNotIn("route. Microsoft\n", self.text)
        self.assertNotIn("Microsoft\nThe release", self.text)
        self.assertNotIn("submission template", self.text)
        self.assertIn("do not claim upload readiness", self.collapsed)

    def test_product_selection_policy_is_exact(self) -> None:
        self.assertIn(POLICY, self.collapsed)
        self.assertIn("## Product selection policy", self.text)
        self.assertNotIn(
            "current production ordering starts with Xray",
            self.text,
        )
        self.assertNotIn("Direct AmneziaWG uses the configured UDP route", self.text)

    def test_owner_blocked_fields_cannot_pass_as_completed_evidence(self) -> None:
        for field, label in (
            ("Test account:", "Partner Center reviewer"),
            ("Test regions/routes:", "Reviewer-safe standalone Winn"),
            ("Versioned HTTPS direct URL:", "immutable, versioned HTTPS"),
            ("Exact installer SHA-256:", "No installer hash is recorded"),
        ):
            with self.subTest(field=field):
                block = self._field_block(field)
                self.assertIn(OWNER_BLOCKED_ABSENT, block)
                self.assertIn("This field is not completed evidence", block)
                self.assertIn(label, block)
                self.assertNotIn("https://", block)
                self.assertIsNone(SHA256_RE.search(block))
                self.assertIsNone(IPV4_RE.search(block))
        self.assertGreaterEqual(self.text.count(OWNER_BLOCKED_ABSENT), 4)
        self.assertIn("Upload readiness: not claimed", self.text)
        self.assertIn("do not authorize Partner Center upload", self.collapsed)
        self.assertIn("1.0.17+34", self.text)
        self.assertIn("separate x64", self.text)
        self.assertIn("native ARM64", self.text)
        self.assertIn("port 80", self.text)
        self.assertIn("port 443", self.text)
        self.assertIn("9110", self.text)

    def test_unresolved_placeholders_are_absent(self) -> None:
        for marker in PLACEHOLDER_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, self.text)
        self.assertIsNone(SHA256_RE.search(self.text))

    def test_win32_installer_path_contract_strings_remain(self) -> None:
        for required in (
            "signed, standalone/offline Inno Setup EXE",
            "immutable, versioned HTTPS",
            "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "/RESTARTEXITCODE=3010 /SP-",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.text)

    def test_notes_do_not_invent_zip_or_msix_or_claim_signing_receipt(self) -> None:
        self.assertIn("WinsVPN-PartnerCenter.exe", self.text)
        self.assertIn("WinsVPN-PartnerCenter-arm64.exe", self.text)
        self.assertNotIn("WinsVPN-PartnerCenter.zip", self.text)
        self.assertNotIn("WinsVPN-PartnerCenter.msix", self.text)
        self.assertNotIn("WinsVPN-Setup.zip", self.text)
        self.assertNotIn("WinsVPN-Setup.msix", self.text)
        self.assertNotIn(".appx", self.text.casefold())
        self.assertIn("These notes do not attach a signed installer", self.collapsed)
        self.assertIn(
            "not evidence that either candidate exists or is upload-ready",
            self.collapsed,
        )
        self.assertIn("OWNER-BLOCKED: ABSENT", self.text)
        self.assertNotIn("Authenticode completed", self.text)
        self.assertNotIn("submission approved", self.text.casefold())


if __name__ == "__main__":
    unittest.main()
