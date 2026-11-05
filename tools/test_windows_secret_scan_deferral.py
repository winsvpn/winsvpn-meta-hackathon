#!/usr/bin/env python3
"""The Windows producer defers the exact secret scan to the release host, and only there.

The authenticated inventory loader needs descriptor-relative open and stat, which
Windows does not have. A remote-attested Windows build therefore passes
--defer-secret-scan-to-release-host (with its REMOTE_INPUT.json) to every tool that
would run the scan, and records secret_scan=deferred-to-release-host in REMOTE_RUN.json.
tools/release_remote_build.py finish then runs the scan on the Mac. These tests read the
producer source, so a call site added later cannot skip the scan quietly.

Run: python3 -B tools/test_windows_secret_scan_deferral.py
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRODUCER = (ROOT / "installer/windows/build_installer.ps1").read_text(encoding="utf-8")
TOOLS = ROOT / "tools"


class WindowsSecretScanDeferralTests(unittest.TestCase):
    def test_every_scan_call_site_carries_the_deferral_arguments(self) -> None:
        calls = re.findall(
            r"(?ms)^\s*&\s+\$python\.Source\s+(?:\$privacyScanner|\$ObfuscationContract)\b.*?(?=^\S|\Z)",
            PRODUCER,
        )
        scanning = [
            call
            for call in calls
            if "$privacyScanner" in call
            or re.search(r"\$ObfuscationContract\s+(?:record|verify)\b", call)
        ]
        self.assertEqual(len(scanning), 5, "AOT record/verify, privacy scan, final record and verify")
        for call in scanning:
            with self.subTest(call=call.splitlines()[0]):
                self.assertIn("@secretScanDeferral", call)

    def test_the_deferral_exists_only_for_a_remote_attested_build(self) -> None:
        body = PRODUCER[PRODUCER.index("function Get-WindowsSecretScanDeferralArguments {") :]
        body = body[: body.index("\n}\n")]
        self.assertLess(body.index("Test-WindowsRemoteAttested"), body.index("--defer-secret-scan-to-release-host"))
        self.assertIn("(Get-WindowsRemoteAttestationInput)", body)
        self.assertIn("return @()", body)
        self.assertIn("$secretScanDeferral = @(Get-WindowsSecretScanDeferralArguments)", PRODUCER)

    def test_the_run_record_states_the_deferral(self) -> None:
        self.assertIn("'--secret-scan', 'deferred-to-release-host'", PRODUCER)

    def test_no_environment_switch_can_skip_the_scan(self) -> None:
        for path in (
            PRODUCER,
            (TOOLS / "validate_release_artifact_privacy.py").read_text(encoding="utf-8"),
            (TOOLS / "release_obfuscation_contract.py").read_text(encoding="utf-8"),
        ):
            self.assertNotRegex(path, r"EXPLORE|SKIP_SECRET|skip_secret_scan", "no skip path may ship")


if __name__ == "__main__":
    unittest.main()
