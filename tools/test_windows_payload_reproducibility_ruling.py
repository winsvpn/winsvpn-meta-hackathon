#!/usr/bin/env python3
"""The non-reproducible Windows payload is a recorded owner-side ruling, not a silent fact.

Two builds of one freeze produce different Windows installers. The Arbiter accepted that
for release 1.0.16+33 on 2026-10-22; the ruling record names the evidence, is guarded by
docs/rulings/RULINGS.lock, and is referenced from the cross-store checklist.

Run: python3 -B tools/test_windows_payload_reproducibility_ruling.py
"""

from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RULING = "docs/rulings/WINDOWS_PAYLOAD_NONREPRODUCIBLE_ACCEPTANCE_20261022.md"


class WindowsPayloadReproducibilityRulingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ruling = (ROOT / RULING).read_text(encoding="utf-8")

    def test_the_ruling_is_scoped_dated_and_names_its_evidence(self) -> None:
        for literal in (
            "# Windows installer payload is not byte-reproducible: accepted for 1.0.16+33 (2026-10-22)",
            "Status: in force for release 1.0.16+33 only.",
            "Nothing may claim that a Windows installer can be rebuilt to the same digest.",
            "wins_vpn.exe",
            "wins_vpn_tunnel_service.exe",
            "wins_bridge_host.exe",
            "winsvpn_awg_engine.exe.provenance.json",
            "69648253",
            "69643834",
            "326 entries",
            "/Brepro",
        ):
            self.assertIn(literal, self.ruling)
        self.assertNotIn("—", self.ruling)

    def test_the_lock_file_guards_the_ruling_against_a_silent_revert(self) -> None:
        lock = (ROOT / "docs/rulings/RULINGS.lock").read_text(encoding="utf-8")
        required = [
            line.split(" :: ", 2)
            for line in lock.splitlines()
            if line.startswith(f"REQUIRE :: {RULING} :: ")
        ]
        self.assertGreaterEqual(len(required), 3)
        for _kind, _path, literal in required:
            self.assertIn(literal, self.ruling)

    def test_the_checklist_points_at_the_ruling(self) -> None:
        checklist = (ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        self.assertIn(RULING, checklist)
        self.assertIn("not byte-reproducible", checklist)


if __name__ == "__main__":
    unittest.main()
