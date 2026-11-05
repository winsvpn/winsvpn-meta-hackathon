#!/usr/bin/env python3
"""Non-root tests for the fixed macOS ReleasePython owner boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PROVISIONER = TOOLS / "provision_macos_release_python_runtime.sh"
WRAPPER = TOOLS / "release_python_archive_custody.sh"
CONTROLLER = TOOLS / "macos_release_python_runtime_receipt.py"
CUSTODY = TOOLS / "macos_release_python_runtime.custody.json"
PIN_MANIFEST = TOOLS / "toolchain-pins.json"
OWNER_BOUNDARY = "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision"
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Python tree "
    "immutable against same-user path replacement through execution"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class ProvisionMacosReleasePythonRuntimeTest(unittest.TestCase):
    def test_shell_syntax(self) -> None:
        for path in (PROVISIONER, WRAPPER):
            completed = subprocess.run(
                ["/bin/bash", "-n", str(path)], capture_output=True, text=True
            )
            self.assertEqual(completed.returncode, 0, path.name + completed.stderr)

    def test_repository_provisioner_is_diagnostic_only(self) -> None:
        source = PROVISIONER.read_text(encoding="ascii")
        lowered = source.lower()
        self.assertNotIn("write-receipt", source)
        self.assertNotIn("chflags", source)
        self.assertNotIn("password prompt", lowered)
        self.assertNotIn("sudo", lowered)
        self.assertNotIn("rm -rf", source)
        self.assertNotIn("mkdir", source)
        self.assertIn("never elevates privilege", source)
        self.assertIn(OWNER_BOUNDARY, source)

    def test_custody_metadata_authenticates_every_closure_digest(self) -> None:
        document = json.loads(CUSTODY.read_text(encoding="ascii"))
        expected = {
            "wrapper": WRAPPER,
            "provisioner": PROVISIONER,
            "custody_controller": CONTROLLER,
            "receipt_test": TOOLS / "test_macos_release_python_runtime_receipt.py",
            "provision_test": Path(__file__).resolve(),
            "archive_test": TOOLS / "test_release_python_archive_custody.py",
            "fin_g00_test": TOOLS / "test_fin_release_gate_g00_python_custody.py",
            "fin_release_gate": TOOLS / "fin_release_gate.sh",
            "android_custody": TOOLS / "release_android_toolchain_archive_custody.sh",
            "openssl_custody": TOOLS / "release_openssl_archive_custody.sh",
            "node_custody": TOOLS / "release_node_archive_custody.sh",
            "browser_custody": TOOLS / "release_browser_archive_custody.sh",
            "go_custody": TOOLS / "release_go_archive_custody.sh",
            "gcp_proof_collector": TOOLS / "gcp_proof_evidence.py",
            "gcp_proof_live_probe": TOOLS / "gcp_proof_live_probe.py",
            "pin_manifest": PIN_MANIFEST,
        }
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["contract"], "winsvpn-macos-release-python-runtime-v2")
        self.assertEqual(document["owner_provision_boundary"], OWNER_BOUNDARY)
        for key, path in expected.items():
            self.assertEqual(document[key], f"tools/{path.name}")
            self.assertEqual(document[f"{key}_sha256"], sha256(path))

    def test_root_guard_precedes_every_mutable_source(self) -> None:
        source = PROVISIONER.read_text(encoding="ascii")
        guard = source.index('if [[ "$("$_WINS_PR_ID" -u)" == 0 ]]')
        mutable_source = source.index("source /dev/fd/8")
        self.assertLess(guard, mutable_source)
        self.assertIn("refuse root execution", source)
        self.assertIn("held ReleasePython wrapper digest mismatch", source)
        self.assertIn(
            f"_WINS_PR_REVIEWED_WRAPPER_SHA256={hashlib.sha256(WRAPPER.read_bytes()).hexdigest()}",
            source,
        )

    def test_nonroot_diagnostic_prints_only_fixed_owner_action(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(PIN_MANIFEST)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, combined)
        self.assertIn(OWNER_BOUNDARY, combined)
        self.assertIn("fixed ReleasePython owner-provisioning boundary", combined)
        self.assertNotIn("sudo", combined.lower())
        self.assertNotIn(str(PROVISIONER), combined)

    def test_stale_custody_digest_is_refused_before_runtime_diagnosis(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wins-pr-stale-", dir="/private/tmp") as raw:
            tools = Path(raw) / "tools"
            tools.mkdir(mode=0o700)
            for path in TOOLS.iterdir():
                if path.name in {
                    PROVISIONER.name,
                    WRAPPER.name,
                    CONTROLLER.name,
                    CUSTODY.name,
                    PIN_MANIFEST.name,
                    "test_macos_release_python_runtime_receipt.py",
                    "test_provision_macos_release_python_runtime.py",
                    "test_release_python_archive_custody.py",
                    "test_fin_release_gate_g00_python_custody.py",
                    "fin_release_gate.sh",
                    "release_android_toolchain_archive_custody.sh",
                    "release_openssl_archive_custody.sh",
                    "release_node_archive_custody.sh",
                    "release_browser_archive_custody.sh",
                    "release_go_archive_custody.sh",
                    "gcp_proof_evidence.py",
                    "gcp_proof_live_probe.py",
                }:
                    shutil.copy2(path, tools / path.name)
            helper = tools / PROVISIONER.name
            wrapper = tools / WRAPPER.name
            wrapper.write_bytes(wrapper.read_bytes() + b"\n")
            completed = subprocess.run(
                ["/bin/bash", str(helper), str(tools / PIN_MANIFEST.name)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
            )
            combined = completed.stdout + completed.stderr
            self.assertNotEqual(completed.returncode, 0, combined)
            self.assertIn("held ReleasePython wrapper digest mismatch", combined)
            self.assertNotIn("installed runtime diagnosis", combined)

    def test_receipt_override_is_refused(self) -> None:
        completed = subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(PIN_MANIFEST)],
            cwd=ROOT,
            env={**os.environ, "WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT": "/tmp/fake.json"},
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("receipt override is refused", completed.stderr)

    def test_invalid_installed_signature_diagnosis_is_preserved(self) -> None:
        script = f"""
        set -euo pipefail
        source '{PROVISIONER}'
        _wins_pr_verify_custody_metadata() {{ return 0; }}
        _wins_rp_receipt_py() {{ printf '%s\\n' 'MISMATCH:owner/environment blocker: code signature strict validation failed'; }}
        wins_release_python_provision_owner_runtime '{PIN_MANIFEST}'
        """
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, combined)
        self.assertIn("installed runtime diagnosis", combined)
        self.assertIn("code signature strict validation failed", combined)
        self.assertNotIn("receipt MATCH", combined)

    def test_even_authenticated_match_remains_diagnostic_only(self) -> None:
        script = f"""
        set -euo pipefail
        source '{PROVISIONER}'
        _wins_pr_verify_custody_metadata() {{ return 0; }}
        _wins_rp_receipt_py() {{ printf '%s\\n' MATCH; }}
        wins_release_python_provision_owner_runtime '{PIN_MANIFEST}'
        """
        completed = subprocess.run(
            ["/bin/bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        combined = completed.stdout + completed.stderr
        self.assertNotEqual(completed.returncode, 0, combined)
        self.assertIn("authenticated MATCH", combined)
        self.assertIn("diagnostic-only", combined)
        self.assertIn("fixed ReleasePython owner-provisioning boundary", combined)

    def test_diagnostic_never_mutates_library_tree(self) -> None:
        library = Path("/Library/WinsVPN")
        before = sorted(str(path) for path in library.glob("**/*")) if library.exists() else []
        subprocess.run(
            ["/bin/bash", str(PROVISIONER), str(PIN_MANIFEST)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        after = sorted(str(path) for path in library.glob("**/*")) if library.exists() else []
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
