#!/usr/bin/env python3
"""The Windows section of the release checklist states the secret inventory binding.

A Windows receipt binds the digest and revision of the inventory its installer was scanned
with, and verify-receipt runs the exact scan again and refuses any other inventory file. An
operator who rotates or edits the inventory after finish would find every older receipt
unverifiable, so the checklist says to keep the exact file and to treat a change as a new
remote run (tools/release_dependency_freeze.py, _require_release_host_secret_scan_rerun).

Run: python3 -B tools/test_windows_receipt_inventory_checklist.py
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs/CROSS_STORE_RELEASE_CHECKLIST.md"
FREEZE = (ROOT / "tools/release_dependency_freeze.py").read_text(encoding="utf-8")


class WindowsReceiptInventoryChecklistTests(unittest.TestCase):
    def _windows_section(self) -> str:
        text = CHECKLIST.read_text(encoding="ascii")
        start = text.index("## Microsoft Store / Windows Win32")
        return re.sub(r"\s+", " ", text[start : text.index("\n## Linux", start)])

    def test_the_windows_section_says_the_inventory_is_bound_and_must_be_kept(self) -> None:
        section = self._windows_section()
        for phrase in (
            "binds the digest and revision of the secret inventory",
            "`verify-receipt` runs the exact scan again and refuses any other inventory file",
            "Keep the exact inventory file that finish used for the receipt's whole lifetime",
            "An inventory change means a new remote run, a new finish and a new receipt",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, section)

    def test_the_statement_matches_what_the_worker_enforces(self) -> None:
        # The worker refuses a different inventory by its digest and compares the revision and
        # the counts of the fresh scan with the bound record.
        self.assertIn("supplied for verification is not the inventory", FREEZE)
        self.assertIn("the receipt's scan was made with.", FREEZE)
        self.assertIn('"sha256": report["inventory"]', FREEZE)
        self.assertIn('"revision": report["revision"]', FREEZE)


if __name__ == "__main__":
    unittest.main()
