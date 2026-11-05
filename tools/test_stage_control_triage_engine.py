#!/usr/bin/env python3
"""Tests for deterministic triage-engine staging from the one-touch source."""

from __future__ import annotations

import pathlib
import tempfile
import unittest

from tools.stage_control_triage_engine import EXPECTED_MODEL, TARGETS, stage


ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"


class StageControlTriageEngineTests(unittest.TestCase):
    def test_current_source_stages_exact_v3_closure(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            output = pathlib.Path(value) / "stage"
            result = stage(SOURCE, output)
            self.assertEqual(result["contract"], "winsvpn-control-triage-staging-v1")
            self.assertEqual(result["model_version"], "wins-triage-v3-local-health-context")
            self.assertFalse(result["secret_material_present"])
            self.assertFalse(result["publication_authorized"])
            self.assertEqual(
                {entry["name"] for entry in result["files"]},
                {name for name, _ in TARGETS.values()},
            )
            module = (output / "wins_threat_triage.py").read_text(encoding="utf-8")
            self.assertIn(EXPECTED_MODEL, module)

    def test_nonempty_output_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            output = pathlib.Path(value) / "stage"
            output.mkdir()
            (output / "untrusted.txt").write_text("fixture", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent or an empty"):
                stage(SOURCE, output)


if __name__ == "__main__":
    unittest.main()
