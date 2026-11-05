#!/usr/bin/env python3
"""Regression contracts for protected state in Windows release/lab harnesses."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"


def source(name: str) -> str:
    return (TOOLS / name).read_text(encoding="utf-8")


class WindowsHarnessSecureStateTests(unittest.TestCase):
    def test_workers_bind_helper_and_restore_both_state_roots(self) -> None:
        for name in (
            "windows_release_interactive_worker.ps1",
            "windows_lab_interactive_worker.ps1",
        ):
            text = source(name)
            with self.subTest(name=name):
                for marker in (
                    "tools/windows_secure_state_helpers.ps1",
                    "$state.secure_state_present -notin @($true, $false)",
                    "'preexisting-secure-state'",
                    "WinsVPN\\SecureState",
                    "Write-WinsVpnSecureJson -Name 'vpn_settings.txt'",
                    "Write-WinsVpnSecureJson -Name 'vpn_config.txt'",
                    "Write-WinsVpnSecureText -Name 'user_pin.txt'",
                    ". $secureStateHelper",
                ):
                    self.assertIn(marker, text)
                self.assertLess(
                    text.index("$verifiedClosureSha256 = Assert-ExactHelperClosure"),
                    text.rindex(". $secureStateHelper"),
                )

    def test_standalone_consumers_have_no_legacy_sensitive_paths(self) -> None:
        names = (
            "windows_interactive_live_cycle.ps1",
            "windows_split_tunnel_live_cycle.ps1",
            "windows_split_tunnel_curl_live_cycle.ps1",
            "windows_split_tunnel_browser_live_cycle.ps1",
            "windows_browser_split_scheduled_runner.ps1",
            "windows_local_awg_diagnostic.ps1",
            "windows_connect_click_diagnostic.ps1",
            "prepare_windows_lab_evidence.ps1",
        )
        sensitive_legacy = (
            "wins_vpn\\vpn_settings.txt",
            "wins_vpn\\vpn_config.txt",
            "wins_vpn\\client_keypair.json",
            "wins_vpn\\user_pin.txt",
        )
        for name in names:
            text = source(name)
            with self.subTest(name=name):
                self.assertIn("windows_secure_state_helpers.ps1", text)
                self.assertIn(". $secureStateHelper", text)
                for marker in sensitive_legacy:
                    self.assertNotIn(marker, text)
                self.assertNotIn("split-test.tmp", text)

    def test_verified_collector_closures_include_secure_helper(self) -> None:
        for name in (
            "windows_release_physical_collector.ps1",
            "windows_lab_physical_collector.ps1",
            "windows_release_matrix_driver.ps1",
            "windows_release_safe_watchdog.ps1",
            "windows_lab_safe_watchdog.ps1",
        ):
            with self.subTest(name=name):
                self.assertIn(
                    "tools/windows_secure_state_helpers.ps1", source(name)
                )


if __name__ == "__main__":
    unittest.main()
