#!/usr/bin/env python3
"""Round R2: tools/redemption_export.py turns a mint response into a delivery file.

Run: python3 tools/test_redemption_export.py
The age round trip runs only where `age` and `age-keygen` are installed; the
throwaway identity lives in a temporary directory and is never printed.
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("redemption_export", ROOT / "tools" / "redemption_export.py")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)
ALPHABET = exporter.ALPHABET


def make_code() -> str:
    while True:
        payload = "".join(secrets.choice(ALPHABET) for _ in range(26))
        value = 0
        for ch in payload:
            value = value * 32 + ALPHABET.index(ch)
        if value % 37 < 32:
            raw = payload + ALPHABET[value % 37]
            return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def mint(batch="amz-1m-001", channel="amazon", count=4, canaries=(1,)):
    return {
        "status": "ok", "batch_id": batch, "channel": channel, "key_version": "v1",
        "count": count, "canaries": len(canaries), "duration": "1m", "expires_at": "",
        "codes": [{"code": make_code(), "canary": i in canaries, "serial": f"{batch.upper()}-{i + 1:05d}"}
                  for i in range(count)],
        "warning": "x",
    }


class RedemptionExportTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="r2-export-"))
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write_mint(self, data) -> str:
        path = self.dir / "mint.json"
        path.write_text(json.dumps(data))
        return str(path)

    def run_export(self, data, name="out.csv", **kw):
        options = dict(recipients=[], recipients_file="", plaintext=True, printer_canaries=False,
                       redeem_url=exporter.DEFAULT_REDEEM_URL)
        options.update(kw)
        return exporter.export(self.write_mint(data), self.dir / name, **options)

    def test_plaintext_drops_canaries_and_manifest_holds_no_codes(self):
        data = mint()
        manifest = self.run_export(data)
        out = self.dir / "out.csv"
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        rows = list(csv.reader(io.StringIO(out.read_text())))
        self.assertEqual(rows[0], exporter.FIELDS)
        self.assertEqual(len(rows), 4)  # header + 3 sale codes
        sold = {c["code"] for c in data["codes"] if not c["canary"]}
        self.assertEqual({r[1] for r in rows[1:]}, sold)
        self.assertNotIn(data["codes"][1]["code"], out.read_text())
        text = (self.dir / "out.csv.manifest.json").read_text()
        for item in data["codes"]:
            self.assertNotIn(item["code"], text)
        self.assertEqual(manifest["plaintext_csv_sha256"], hashlib.sha256(out.read_bytes()).hexdigest())
        self.assertEqual(manifest["canary_pull_list"], [])
        self.assertEqual(manifest["rows"], 3)

    def test_delivery_and_manifest_names_are_made_durable(self):
        # R22 Y3-10: each new file is fsynced, then its directory, so a crash
        # after a successful export cannot drop the only plaintext copy.
        real_fsync = os.fsync
        synced = []

        def recording_fsync(fd):
            synced.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            real_fsync(fd)

        with mock.patch.object(exporter.os, "fsync", side_effect=recording_fsync):
            self.run_export(mint())
        self.assertEqual(synced, ["file", "directory", "file", "directory"])

    def test_printer_canaries_are_kept_and_listed_for_pulling(self):
        data = mint(batch="print-1y-002", channel="printer", canaries=(0, 2))
        manifest = self.run_export(data, printer_canaries=True)
        self.assertEqual(manifest["rows"], 4)
        self.assertEqual(manifest["canary_pull_list"], ["PRINT-1Y-002-00001", "PRINT-1Y-002-00003"])
        with self.assertRaises(exporter.ExportError):
            self.run_export(mint(), name="other.csv", printer_canaries=True)

    def test_refuses_clobber_symlink_and_bad_input(self):
        self.run_export(mint())
        with self.assertRaises(exporter.ExportError):
            self.run_export(mint())
        target = self.dir / "elsewhere.csv"
        os.symlink(target, self.dir / "link.csv")
        with self.assertRaises(exporter.ExportError):
            self.run_export(mint(), name="link.csv")
        self.assertFalse(target.exists())
        bad = mint()
        bad["codes"][0]["code"] = bad["codes"][0]["code"][:-1] + ("0" if bad["codes"][0]["code"][-1] != "0" else "1")
        dup = mint()
        dup["codes"][2]["serial"] = dup["codes"][0]["serial"]
        foreign = mint()
        foreign["codes"][0]["serial"] = "OTHER-BATCH-00001"
        no_channel = mint()
        del no_channel["channel"]
        for index, broken in enumerate((bad, dup, foreign, no_channel)):
            with self.assertRaises(exporter.ExportError):
                self.run_export(broken, name=f"bad{index}.csv")
            self.assertFalse((self.dir / f"bad{index}.csv").exists())
        with self.assertRaises(exporter.ExportError):
            self.run_export(mint(), name="noenc.csv", plaintext=False)
        with self.assertRaises(exporter.ExportError):
            self.run_export(mint(), name="badkey.csv", plaintext=False, recipients=["not-a-key"])

    def test_cli_reads_stdin_and_never_echoes_codes_on_failure(self):
        data = mint()
        broken = dict(data, channel="pigeon")
        completed = subprocess.run(
            ["python3", str(ROOT / "tools" / "redemption_export.py"), "-", str(self.dir / "cli.csv"), "--plaintext"],
            input=json.dumps(broken), capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 1)
        for item in data["codes"]:
            self.assertNotIn(item["code"], completed.stderr + completed.stdout)
        completed = subprocess.run(
            ["python3", str(ROOT / "tools" / "redemption_export.py"), "-", str(self.dir / "cli.csv"), "--plaintext"],
            input=json.dumps(data), capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("PLAINTEXT", completed.stdout)

    @unittest.skipUnless(shutil.which("age") and shutil.which("age-keygen"), "age is not installed")
    def test_age_round_trip_writes_only_ciphertext(self):
        identity = self.dir / "identity.txt"
        subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True, timeout=30)
        recipient = subprocess.run(["age-keygen", "-y", str(identity)], capture_output=True, text=True,
                                   check=True, timeout=30).stdout.strip()
        data = mint()
        manifest = self.run_export(data, name="sale.csv.age", plaintext=False, recipients=[recipient])
        sealed = (self.dir / "sale.csv.age").read_bytes()
        self.assertTrue(sealed.startswith(b"age-encryption.org/v1"))
        for item in data["codes"]:
            self.assertNotIn(item["code"].encode(), sealed)
        opened = subprocess.run(["age", "-d", "-i", str(identity), str(self.dir / "sale.csv.age")],
                                capture_output=True, check=True, timeout=30).stdout
        self.assertEqual(hashlib.sha256(opened).hexdigest(), manifest["plaintext_csv_sha256"])
        self.assertTrue(manifest["encrypted"])
        leftovers = sorted(p.name for p in self.dir.iterdir())
        self.assertEqual(leftovers, ["identity.txt", "mint.json", "sale.csv.age", "sale.csv.age.manifest.json"])


if __name__ == "__main__":
    unittest.main()
