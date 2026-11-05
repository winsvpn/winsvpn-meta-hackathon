#!/usr/bin/env python3
"""Minimal G00 check: reviewed Python custody cannot false-green on this Mac."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIN_GATE = ROOT / "tools" / "fin_release_gate.sh"
PROVISIONER = ROOT / "tools" / "provision_macos_release_python_runtime.sh"
CUSTODY = ROOT / "tools" / "macos_release_python_runtime.custody.json"
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Python tree "
    "immutable against same-user path replacement through execution"
)


class FinReleaseGateG00PythonCustodyTest(unittest.TestCase):
    def test_schema_v3_binds_exact_fin_gate_and_direct_source_closure(self) -> None:
        document = json.loads(CUSTODY.read_text(encoding="ascii"))
        expected = {
            "fin_release_gate": FIN_GATE,
            "android_custody": ROOT / "tools/release_android_toolchain_archive_custody.sh",
            "openssl_custody": ROOT / "tools/release_openssl_archive_custody.sh",
            "node_custody": ROOT / "tools/release_node_archive_custody.sh",
            "browser_custody": ROOT / "tools/release_browser_archive_custody.sh",
            "go_custody": ROOT / "tools/release_go_archive_custody.sh",
        }
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["contract"], "winsvpn-macos-release-python-runtime-v2")
        gate_source = FIN_GATE.read_text(encoding="utf-8")
        for key, path in expected.items():
            self.assertEqual(document[key], f"tools/{path.name}")
            self.assertEqual(document[f"{key}_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            if key != "fin_release_gate":
                self.assertIn(f'source "${{SCRIPT_DIR}}/{path.name}"', gate_source)
        for key, path in {
            "gcp_proof_collector": ROOT / "tools/gcp_proof_evidence.py",
            "gcp_proof_live_probe": ROOT / "tools/gcp_proof_live_probe.py",
        }.items():
            self.assertEqual(document[key], f"tools/{path.name}")
            self.assertEqual(
                document[f"{key}_sha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

    def test_g00_uses_authenticated_python_custody(self) -> None:
        source = FIN_GATE.read_text(encoding="utf-8")
        g00 = source.split("gate_G00()", 1)[1].split("gate_G01()", 1)[0]
        self.assertIn("authenticate_release_python", g00)
        self.assertIn("run_release_python", g00)
        self.assertIn("reviewed python custody matches pins", g00)

    def test_g00_is_not_a_false_green_without_owner_runtime(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", "-p", str(FIN_GATE), "G00"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined = completed.stdout + completed.stderr
        if completed.returncode == 0:
            self.assertIn("G00", completed.stdout)
            self.assertIn("PASS", completed.stdout)
            self.assertIn("reviewed python custody matches pins", completed.stdout)
            self.assertIn("python=3.14.7/cpython", completed.stdout)
            return
        self.assertNotEqual(completed.returncode, 0, combined)
        self.assertNotIn("ALL-PASS", completed.stdout)
        self.assertNotRegex(completed.stdout, r"^G00\s+PASS\b", combined)
        self.assertIn("authenticated release Python custody", combined)
        self.assertIn(EXECUTION_BLOCKER, combined)
        self.assertIn(
            "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision", combined
        )
        self.assertIn("fixed ReleasePython owner-provisioning boundary", combined)
        self.assertNotIn("sudo", combined.lower())
        self.assertNotIn(str(PROVISIONER.resolve()), combined)


if __name__ == "__main__":
    unittest.main()
