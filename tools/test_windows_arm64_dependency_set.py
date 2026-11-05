#!/usr/bin/env python3
"""The committed Windows ARM64 dependency set is the reviewed one, and the old one stays rejected.

docs/CROSS_STORE_RELEASE_CHECKLIST.md requires tools/build_windows_amneziawg_client.ps1
-TargetArchitecture arm64 before an ARM64 release is frozen: it verifies the official 3.1.0 ARM64
MSI, rebuilds the maintenance helper twice with Go 1.27.1 and publishes the architecture-specific
inputs. Those outputs are committed under installer/windows/dependencies/, replacing the unreviewed
amneziawg-arm64.msi (1699f9e6) that was committed before. The unreviewed digest stays in the reject
lists (build_store_msix.ps1 and the artifact-gate tests) so nothing that hashes to it, or to anything
else unreviewed, is accepted again.

Run: python3 -B tools/test_windows_arm64_dependency_set.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPENDENCIES = ROOT / "installer/windows/dependencies"
PRODUCER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
MSIX = (ROOT / "installer/windows/build_store_msix.ps1").read_text(encoding="utf-8")
ZIP_BUILD = (ROOT / "installer/windows/build_zip_installer.ps1").read_text(encoding="utf-8")
GATE_TESTS = (ROOT / "installer/windows/tests/test_artifact_gates.py").read_text(encoding="utf-8")

UNREVIEWED_ARM64_MSI = "1699f9e6b313d8b90ec812f1ed0ec70b7d8d2e129010d179029d6990d9955fca"
OFFICIAL_ARM64_MSI = "3aec023884944890fac151f9cd4be3e92d39f9987c49da248837529c006ea2aa"


def _producer_pin(name: str) -> str:
    match = re.search(
        rf"\${name}\s*=\s*@\{{\s*'x64'\s*=\s*'[0-9a-f]{{64}}'\s*'arm64'\s*=\s*'([0-9a-f]{{64}})'",
        PRODUCER,
    )
    assert match is not None, name
    return match.group(1)


def _sha256(name: str) -> str:
    return hashlib.sha256((DEPENDENCIES / name).read_bytes()).hexdigest()


class CommittedArm64DependencySetTests(unittest.TestCase):
    def test_every_committed_arm64_input_is_the_one_the_producer_pins(self) -> None:
        expected = {
            "amneziawg-arm64.msi": _producer_pin("AmneziaWgSha256"),
            "amneziawg-arm64.exe": _producer_pin("AmneziaWgHelperUnsignedSha256"),
            "awg-arm64.exe": _producer_pin("AwgToolExeSha256"),
            "wintun-arm64.dll": _producer_pin("WintunDllSha256"),
            "xray-arm64.exe": _producer_pin("XrayExeSha256"),
            "VC_redist.arm64.exe": _producer_pin("VcRedistSha256"),
        }
        self.assertEqual(expected["amneziawg-arm64.msi"], OFFICIAL_ARM64_MSI)
        for name, pin in expected.items():
            with self.subTest(file=name):
                self.assertEqual(_sha256(name), pin)

    def test_the_provenance_describes_the_committed_helper_and_the_official_inputs(self) -> None:
        provenance = json.loads((DEPENDENCIES / "amneziawg-arm64.exe.provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["schema_version"], 2)
        self.assertEqual(provenance["target"], "windows-arm64")
        self.assertEqual(provenance["unsigned_artifact_sha256"], _sha256("amneziawg-arm64.exe"))
        self.assertEqual(provenance["unsigned_artifact_sha256"], provenance["expected_unsigned_artifact_sha256"])
        self.assertEqual(provenance["reproducibility_status"], "two_clean_builds_byte_identical")
        self.assertEqual(provenance["reproducibility_builds"], 2)
        self.assertEqual(provenance["upstream_asset_name"], "amneziawg-arm64-3.1.0.msi")
        self.assertEqual(provenance["upstream_msi_sha256"], _sha256("amneziawg-arm64.msi"))
        self.assertEqual(provenance["upstream_awg_exe_sha256"], _sha256("awg-arm64.exe"))
        self.assertEqual(provenance["upstream_wintun_dll_sha256"], _sha256("wintun-arm64.dll"))

    def test_the_unreviewed_msi_is_gone_from_the_tree_and_stays_a_reject_value(self) -> None:
        self.assertNotEqual(_sha256("amneziawg-arm64.msi"), UNREVIEWED_ARM64_MSI)
        # The digest stays in the store packager's reject check, which refuses it as an official pin ...
        self.assertIn(f"$UnreviewedArm64MsiSha256 = '{UNREVIEWED_ARM64_MSI}'", MSIX)
        self.assertIn(
            "if ($OfficialArm64Pins['amneziawg-arm64.msi'] -ceq $UnreviewedArm64MsiSha256) {", MSIX
        )
        self.assertNotRegex(MSIX, rf"(?i)'amneziawg-arm64\.msi'\s*=\s*'{UNREVIEWED_ARM64_MSI}'")
        # ... in the artifact-gate tests, which keep asserting it is not packaged ...
        self.assertIn(f'    "{UNREVIEWED_ARM64_MSI}"\n', GATE_TESTS)
        # ... and the ZIP producer accepts nothing but the one reviewed digest.
        self.assertNotIn(UNREVIEWED_ARM64_MSI, ZIP_BUILD)
        self.assertIn(f"sha256 = '{OFFICIAL_ARM64_MSI}'", ZIP_BUILD)
        self.assertIn("Pinned dependency $sourceName has SHA-256 $actual; expected $expected.", ZIP_BUILD)

    def test_the_zip_route_test_no_longer_reads_the_unreviewed_file_from_the_tree(self) -> None:
        source = (ROOT / "tools/test_windows_zip_route_security.py").read_text(encoding="utf-8")
        self.assertNotIn(UNREVIEWED_ARM64_MSI, source)
        self.assertIn('unreviewed = b"unreviewed arm64 msi fixture"', source)

    def test_the_committed_files_are_plain_non_executable_blobs(self) -> None:
        try:
            listing = subprocess.run(
                ["git", "ls-files", "-s", "--", "installer/windows/dependencies"],
                cwd=ROOT, capture_output=True, text=True, check=True,
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("git metadata is not available")
        modes = {line.split("\t", 1)[1].rsplit("/", 1)[-1]: line.split()[0] for line in listing.splitlines()}
        for name in (
            "amneziawg-arm64.msi",
            "amneziawg-arm64.exe",
            "amneziawg-arm64.exe.provenance.json",
            "awg-arm64.exe",
        ):
            with self.subTest(file=name):
                self.assertEqual(modes.get(name), "100644")


if __name__ == "__main__":
    unittest.main()
