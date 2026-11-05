#!/usr/bin/env python3
"""Focused tests for Go 1.27.1 custody metadata.

Official current stable is Go 1.27.1. Official go.dev documents macOS 13
Ventura or later for Go 1.27; WinsVPN also uses macOS 13 as the Apple app
deployment floor. Exact Go archive hashes and versions stay frozen.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

PROOF_GO_MOD = ROOT / "tools" / "gcp_proof_client" / "go.mod"
PINS = ROOT / "tools" / "toolchain-pins.json"
THIRD_PARTY = ROOT / "docs" / "THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md"
REFRESH = ROOT / "docs" / "RELEASE_ENGINE_BINARY_REFRESH.md"
GATE = ROOT / "tools" / "verify_embedded_engine_runtime_versions.py"
PROFILES = ROOT / "winn_protocol_experimental" / "ALGORITHM_PROFILES.md"
WINN_GO_MOD = ROOT / "winn_protocol_experimental" / "go.mod"

FROZEN_GO_ARCHIVE_SHA256 = {
    "darwin_amd64": "8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4",
    "darwin_arm64": "ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12",
    "linux_amd64": "63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445",
    "linux_arm64": "3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec",
    "windows_amd64": "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d",
    "windows_arm64": "13b69b87bb0e83f96bc68560a8cace7f0343b1e03469f1110ea18d17e3234069",
}
FROZEN_INSTALL_TREE_SHA256 = {
    "darwin_arm64": "f8de74060cc6cfa4a52c3768a6999c0eb4119dec0281d75d225d44a35a2975ac"
}
FROZEN_EXECUTABLE_SHA256 = "132b69336a1f809932a8a20b0201dbbb980e86e3a323ae32e893639d83d71598"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class ProofClientGoDirectiveTests(unittest.TestCase):
    def test_go_directive_is_exact_1_27_1(self) -> None:
        text = _text(PROOF_GO_MOD)
        text.encode("ascii")
        self.assertEqual(
            text,
            "module winsvpn.local/gcpproofclient\n\ngo 1.27.1\n",
        )
        self.assertNotIn("go 1.26.0", text)
        self.assertNotIn("toolchain ", text)


class ToolchainPinGoCustodyTests(unittest.TestCase):
    def test_pins_json_is_valid_and_freezes_go_1_27_1_hashes(self) -> None:
        payload = json.loads(_text(PINS))
        go = payload["tools"]["go"]
        self.assertEqual(go["version"], "1.27.1")
        self.assertEqual(go["archive_sha256"], FROZEN_GO_ARCHIVE_SHA256)
        self.assertEqual(go["install_tree_sha256"], FROZEN_INSTALL_TREE_SHA256)
        self.assertEqual(go["executable_sha256"], FROZEN_EXECUTABLE_SHA256)
        self.assertIn("go1.27.1", go["note"])
        note = go["compatibility_note"]
        self.assertIn("requires macOS 13 Ventura or later", note)
        self.assertIn("WinsVPN also uses macOS 13", note)
        self.assertNotIn("macOS 12 or later", note)


class AlgorithmProfileGoDirectiveTests(unittest.TestCase):
    def test_profiles_cite_go_mod_1_27_1_not_1_26_0(self) -> None:
        profiles = _text(PROFILES)
        go_mod = _text(WINN_GO_MOD)
        go_mod.encode("ascii")
        self.assertRegex(go_mod, r"(?m)^go 1\.27\.1$")
        self.assertIn("`go.mod:3 go 1.27.1`", profiles)
        self.assertIn("Go 1.27 `crypto/tls`", profiles)
        self.assertIn("https://go.dev/doc/go1.27", profiles)
        self.assertNotIn("go 1.26.0", profiles)
        self.assertNotIn("toolchain go1.26.5", profiles)
        self.assertNotIn("Go 1.26 `crypto/tls`", profiles)
        self.assertNotIn("https://go.dev/doc/go1.26", profiles)


class CustodyDocsMacosFloorTests(unittest.TestCase):
    def test_in_scope_docs_and_gate_match_official_and_project_macos_13(self) -> None:
        paths = (THIRD_PARTY, REFRESH, GATE, PINS)
        for path in paths:
            text = _text(path)
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                self.assertIn("1.27.1", text)
                self.assertNotIn("macOS 12 or later", text)
                self.assertTrue(
                    "macOS 13 Ventura or later" in text
                    or "macOS 13 or later" in text,
                    text,
                )
                self.assertTrue(
                    "also uses macOS 13" in text
                    or "uses macOS 13" in text
                    or "keeps a macOS 13" in text,
                    text,
                )
                self.assertTrue(
                    "project policy" in text.lower()
                    or "app, extension, native verifier, and package deployment floor"
                    in text.lower(),
                    text,
                )


class FrozenHashLiteralTests(unittest.TestCase):
    def test_pin_file_still_contains_exact_archive_hash_literals(self) -> None:
        text = _text(PINS)
        text.encode("ascii")
        for digest in FROZEN_GO_ARCHIVE_SHA256.values():
            self.assertIn(digest, text)
        self.assertIn(FROZEN_INSTALL_TREE_SHA256["darwin_arm64"], text)
        self.assertIn(FROZEN_EXECUTABLE_SHA256, text)
        self.assertEqual(len(re.findall(r'"version": "1.27.1"', text)), 1)


if __name__ == "__main__":
    raise SystemExit(unittest.main())
