#!/usr/bin/env python3
"""Regression tests for the complete ReleasePython closure repinner."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "repin_macos_release_python_closure.py"
SPEC = importlib.util.spec_from_file_location("repin_macos_release_python_closure", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RepinProducerClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for relative in MODULE.PRODUCER_PATHS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"payload:{relative}\n".encode("ascii"))
        self.records = [
            {"path": relative, "sha256": "0" * 64}
            for relative in MODULE.PRODUCER_PATHS
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repin(self, records: list[dict[str, str]]) -> dict[str, object]:
        metadata: dict[str, object] = {"producer_closure": records}
        staged_path = self.root / MODULE.PRODUCER_PATHS[7]
        staged = {staged_path: b"staged-wrapper\n"}
        with mock.patch.object(MODULE, "ROOT", self.root):
            MODULE.repin_producer_closure(metadata, staged)
        return metadata

    def test_repins_stale_records_from_staged_and_live_raw_bytes(self) -> None:
        metadata = self.repin(copy.deepcopy(self.records))
        records = {record["path"]: record["sha256"] for record in metadata["producer_closure"]}
        wrapper = MODULE.PRODUCER_PATHS[7]
        self.assertEqual(records[wrapper], MODULE.digest(b"staged-wrapper\n"))
        live = MODULE.PRODUCER_PATHS[0]
        self.assertEqual(records[live], MODULE.digest((self.root / live).read_bytes()))
        self.assertNotIn(MODULE.PRODUCER_RELATIVE, records)

    def test_replaces_exactly_one_named_python_digest_assignment(self) -> None:
        source = b'EXPECTED_CUSTODY_SHA256 = "' + (b"0" * 64) + b'"\n'
        expected = "1" * 64
        self.assertEqual(
            MODULE.replace_python_assignment(source, "EXPECTED_CUSTODY_SHA256", expected),
            f'EXPECTED_CUSTODY_SHA256 = "{expected}"\n'.encode("ascii"),
        )
        with self.assertRaises(MODULE.RepinError):
            MODULE.replace_python_assignment(source + source, "EXPECTED_CUSTODY_SHA256", expected)

    def test_rejects_malformed_or_inexact_record_sets_without_mutation(self) -> None:
        cases = {
            "duplicate": self.records + [copy.deepcopy(self.records[0])],
            "missing": self.records[:-1],
            "extra": self.records + [{"path": "tools/extra", "sha256": "0" * 64}],
            "missing-key": [{"path": MODULE.PRODUCER_PATHS[0]}] + self.records[1:],
            "extra-key": [dict(self.records[0], note="bad")] + self.records[1:],
            "uppercase": [dict(self.records[0], sha256="A" * 64)] + self.records[1:],
        }
        for name, records in cases.items():
            with self.subTest(name=name):
                before = json.dumps(records, sort_keys=True)
                with self.assertRaises(MODULE.RepinError):
                    self.repin(records)
                self.assertEqual(json.dumps(records, sort_keys=True), before)


if __name__ == "__main__":
    unittest.main()
