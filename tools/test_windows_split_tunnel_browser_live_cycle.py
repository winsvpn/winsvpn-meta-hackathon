#!/usr/bin/env python3
"""Static fail-closed checks for the real-browser Windows split cycle."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tools" / "windows_split_tunnel_browser_live_cycle.ps1").read_text(
    encoding="utf-8"
)


class WindowsSplitTunnelBrowserLiveCycleTests(unittest.TestCase):
    def test_real_signed_browser_is_required(self) -> None:
        self.assertIn("Get-AuthenticodeSignature", SOURCE)
        self.assertIn("SignatureStatus]::Valid", SOURCE)
        self.assertIn("-ExcludedBrowserExecutable $browserFullPath", SOURCE)

    def test_route_mode_and_network_matrix_are_explicitly_forwarded(self) -> None:
        for fragment in (
            "[switch]$AllowSingleHop",
            "[switch]$RunNetworkChangeMatrix",
            "-NotePropertyValue (-not $AllowSingleHop) -Force",
            "-AllowSingleHop:$AllowSingleHop",
            "-RunNetworkChangeMatrix:$RunNetworkChangeMatrix",
        ):
            self.assertIn(fragment, SOURCE)

    def test_settings_are_restored_in_finally(self) -> None:
        load = SOURCE.index("$originalSettings =")
        mutate = SOURCE.index("-NotePropertyName excluded_vpn_packages")
        finally_block = SOURCE[SOURCE.index("} finally {") :]
        self.assertLess(load, mutate)
        self.assertIn("$originalSettings", finally_block)
        self.assertIn(
            "Write-WinsVpnSecureText -Name 'vpn_settings.txt' "
            "-Value $originalSettings",
            finally_block,
        )
        self.assertIn("Stop-Process -Force", finally_block)
        self.assertIn(". $secureStateHelper", SOURCE)
        self.assertNotIn("$settingsPath", SOURCE)
        self.assertNotIn("split-test.tmp", SOURCE)


if __name__ == "__main__":
    unittest.main()
