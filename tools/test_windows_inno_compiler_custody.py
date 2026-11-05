#!/usr/bin/env python3
"""Producer-source tests for exact Inno Setup compiler custody."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER_PATH = ROOT / "installer/windows/build_installer.ps1"
PRODUCER = PRODUCER_PATH.read_text(encoding="utf-8")
VERIFIER = (ROOT / "tools/release_inno_toolchain_custody.py").read_text(encoding="utf-8")
BEGIN = "# BEGIN-WINDOWS-INNO-COMPILER-CUSTODY"
END = "# END-WINDOWS-INNO-COMPILER-CUSTODY"
SECRET_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "password=",
    "AccessToken",
    "WINS_WINDOWS_SIGN_PFX_PASSWORD",
)


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin)]


class WindowsInnoCompilerCustodyProducerTests(unittest.TestCase):
    def test_producer_binds_reviewed_iscc_and_records_identity(self) -> None:
        custody = section(PRODUCER, BEGIN, END)
        for marker in (
            "tools/inno-toolchain-pins.json",
            "verify-compiler",
            "GetFolderPath('ProgramFiles')",
            "Inno Setup 7",
            "ISCC.exe",
            "winsvpn-inno-compiler-receipt-v1",
            "install_tree_sha256",
            "authenticode_leaf_sha256",
            "product_version_string",
            "Pyrsys B.V.",
            "function Bind-WinsInnoCompilerCustody",
            "function Get-WinsInnoCompilerIdentity",
            "PATH, INNO_SETUP_ISCC, and package-manager discovery are not accepted",
        ):
            self.assertIn(marker, custody)
        self.assertIn("inno_compiler = $script:InnoCompilerIdentity", PRODUCER)
        self.assertIn("release_inno_toolchain_custody.py", PRODUCER)
        self.assertIn("INNO_COMPILER_RECEIPT.json", PRODUCER)
        self.assertIn(
            "Re-verifying exact Inno Setup compiler custody immediately before ISCC",
            PRODUCER,
        )
        self.assertGreaterEqual(PRODUCER.count("Bind-WinsInnoCompilerCustody"), 2)
        self.assertIn("Write-WinsInnoCompilerReceipt", PRODUCER)
        self.assertIn("Windows payload manifest is missing exact Inno Setup compiler identity", PRODUCER)

    def test_verifier_called_by_producer_refuses_unmeasured_pin_plainly(self) -> None:
        custody = section(PRODUCER, BEGIN, END)
        self.assertIn("verify-compiler --arch $Architecture --path $IsccPath --pin $InnoToolchainPin", custody)
        self.assertNotIn("--measure", custody)
        self.assertNotIn("OWNER INPUT REQUIRED", VERIFIER)
        self.assertNotIn("owner_inputs_required", VERIFIER)
        self.assertIn("pin not measured; run verify-compiler --measure on a Windows ", VERIFIER)
        self.assertIn("host and record the printed values in tools/inno-toolchain-pins.json", VERIFIER)
        self.assertIn('"--measure",', VERIFIER)

    def test_producer_does_not_discover_iscc_from_env_path_or_winget(self) -> None:
        custody = section(PRODUCER, BEGIN, END)
        self.assertNotIn("Get-Command ISCC.exe", PRODUCER)
        self.assertNotIn("$env:INNO_SETUP_ISCC", PRODUCER)
        self.assertNotIn("Inno Setup 6\\ISCC.exe", PRODUCER)
        self.assertNotIn("JRSoftware.InnoSetup", PRODUCER)
        self.assertNotIn("WinGet\\Packages", custody)
        self.assertNotIn("Uninstall\\Inno Setup", PRODUCER)
        self.assertNotIn("Get-Command ISCC", custody)
        fail_fast = PRODUCER.index("Bind-WinsInnoCompilerCustody -Architecture $TargetArchitecture")
        compile_call = PRODUCER.index("& $iscc @innoArguments")
        reverify = PRODUCER.index(
            "Re-verifying exact Inno Setup compiler custody immediately before ISCC"
        )
        self.assertLess(fail_fast, reverify)
        self.assertLess(reverify, compile_call)

    def test_producer_receipt_and_payload_manifest_share_compiler_identity(self) -> None:
        self.assertLess(
            PRODUCER.index("inno_compiler = $script:InnoCompilerIdentity"),
            PRODUCER.index("INNO_COMPILER_RECEIPT.json"),
        )
        self.assertIn("existingPreservation.inno_compiler.sha256", PRODUCER)
        self.assertIn("existingPreservation.inno_compiler.install_tree_sha256", PRODUCER)
        self.assertNotIn("github.actions", PRODUCER[PRODUCER.index(BEGIN) : PRODUCER.index(END)].lower())
        self.assertNotIn("Invoke-WebRequest", section(PRODUCER, BEGIN, END))
        self.assertNotIn("Start-Process", section(PRODUCER, BEGIN, END))
        for marker in SECRET_MARKERS:
            self.assertNotIn(marker, section(PRODUCER, BEGIN, END))

    def test_new_custody_source_is_ascii(self) -> None:
        custody = section(PRODUCER, BEGIN, END)
        custody.encode("ascii")
        (ROOT / "tools" / "inno-toolchain-pins.schema.json").read_text(encoding="ascii")
        (ROOT / "tools" / "inno-toolchain-pins.example.json").read_text(encoding="ascii")


if __name__ == "__main__":
    unittest.main(verbosity=2)
