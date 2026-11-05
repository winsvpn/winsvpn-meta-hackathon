#!/usr/bin/env python3
"""Exact native-standalone gate regressions.

Write-scope companion to tools/verify_native_standalone_tests.sh. These
cases are the independently reproduced P0/P1 holes: a copy of /usr/bin/true
as CXX, a compiler whose --version fails, Bash 3.2 missing a stale known-red
index 0, one executed test claiming universal coverage, and the Apple v1
seam redaction sentinel.
"""

from __future__ import annotations

import base64
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "tools" / "verify_native_standalone_tests.sh"
HARNESS = ROOT / "tools" / "verify_apple_winn_seam_harness.swift"
BASH32 = "/bin/bash"
DETERMINISTIC_WG_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


def run_gate(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [BASH32, str(GATE), *args],
        cwd=str(ROOT),
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


class NativeStandaloneGateTests(unittest.TestCase):
    def test_inventory_is_exactly_eleven_tests(self) -> None:
        source = GATE.read_text(encoding="utf-8")
        entries = re.findall(r'^  "((?:linux|windows)/runner/\S+_test\.cc\|)', source, re.M)
        self.assertEqual(len(entries), 11, entries)
        self.assertIn('EXPECTED_TEST_COUNT=11', source)
        self.assertNotIn('CXX_BIN="${CXX:-c++}"', source)
        self.assertNotRegex(source, r'\$\{CXX_BIN\}" --version 2>&1 \|')
        self.assertNotIn(
            "printf 'Standalone native tests: gate satisfied.\\n'",
            source,
        )
        self.assertIn(
            "host-scoped coverage only. This is not universal release coverage.",
            source,
        )
        self.assertIn("while [[ ${i} -lt ${KNOWN_RED_COUNT} ]]; do", source)

    def test_fake_cxx_copy_of_usr_bin_true_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake = pathlib.Path(tmp) / "c++"
            shutil.copy("/usr/bin/true", fake)
            fake.chmod(0o755)
            result = run_gate("--probe-cxx", env={"CXX": str(fake)})
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("arbitrary CXX is refused", result.stderr)
        self.assertIn(str(fake), result.stderr)

    def test_path_and_trampoline_cxx_are_refused(self) -> None:
        basename = run_gate("--probe-cxx", env={"CXX": "c++"})
        self.assertNotEqual(basename.returncode, 0, basename.stderr)
        self.assertIn("PATH compilers are refused", basename.stderr)

        trampoline = run_gate("--probe-cxx", env={"CXX": "/usr/bin/c++"})
        self.assertNotEqual(trampoline.returncode, 0, trampoline.stderr)
        self.assertIn("arbitrary CXX is refused", trampoline.stderr)
        self.assertIn("/usr/bin/c++", trampoline.stderr)

    def test_failed_version_status_is_not_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stub = pathlib.Path(tmp) / "cxx"
            stub.write_text("#!/bin/sh\necho failed-version-probe >&2\nexit 9\n", encoding="utf-8")
            stub.chmod(0o755)
            result = run_gate("--probe-version", str(stub))
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("compiler --version failed with exit status 9", result.stderr)
        self.assertNotIn("gate satisfied", result.stdout)

    def test_stale_known_red_index_zero_on_bash_32(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            listed = pathlib.Path(tmp) / "known-red.txt"
            listed.write_text(
                "winn3_posture_test  fabricated: this test is green, so this entry is stale\n",
                encoding="utf-8",
            )
            result = run_gate(
                "--probe-index",
                "winn3_posture_test",
                env={"KNOWN_RED_FILE": str(listed)},
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "0")

    def test_host_vacuity_is_not_universal_coverage(self) -> None:
        result = run_gate("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        combined = result.stdout
        self.assertIn("fake-CXX copies-/usr/bin/true", combined)
        self.assertIn("failed --version", combined)
        self.assertIn("stale known-red", combined)
        self.assertIn("host-vacuity", combined)
        self.assertIn("seam-key", combined)
        self.assertIn("one PASS stays host-scoped with required receipts", combined)
        self.assertNotIn("UNIVERSAL CLAIM", combined)
        self.assertNotIn("ACCEPTED \\u2014 WRONG", combined)
        self.assertNotIn("MASKED \\u2014 WRONG", combined)

    def test_seam_key_is_deterministic_valid_non_secret(self) -> None:
        source = HARNESS.read_text(encoding="utf-8")
        self.assertNotIn("<REDACTED_WG_KEY>", source)
        self.assertIn(DETERMINISTIC_WG_KEY, source)
        self.assertIn("WinsTunnelConfig.parseAndValidate(baseConfig())", source)
        self.assertIn(
            "the real validator accepted the deterministic non-secret interface private key",
            source,
        )
        decoded = base64.b64decode(DETERMINISTIC_WG_KEY, validate=True)
        self.assertEqual(len(decoded), 32)
        self.assertEqual(decoded, bytes(range(32)))


if __name__ == "__main__":
    unittest.main()
