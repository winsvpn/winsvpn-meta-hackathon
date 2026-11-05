#!/usr/bin/env python3
"""Static fail-closed checks for the combined Windows split/Double live cycle."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tools" / "windows_split_tunnel_curl_live_cycle.ps1").read_text(
    encoding="utf-8"
)
INTERACTIVE = (ROOT / "tools" / "windows_interactive_live_cycle.ps1").read_text(
    encoding="utf-8"
)


class WindowsSplitTunnelCurlLiveCycleTests(unittest.TestCase):
    def test_enables_double_vpn_only_in_temporary_settings(self) -> None:
        load = SOURCE.index("$originalSettings =")
        enable = SOURCE.index("-NotePropertyName double_vpn_requested")
        write_temp = SOURCE.index(
            "Write-WinsVpnSecureText -Name 'vpn_settings.txt' "
            "-Value $temporarySettings"
        )
        restore = SOURCE.rindex(
            "Write-WinsVpnSecureText -Name 'vpn_settings.txt' "
            "-Value $originalSettings"
        )
        self.assertLess(load, enable)
        self.assertLess(enable, write_temp)
        self.assertLess(write_temp, restore)
        self.assertIn(
            "-NotePropertyValue (-not $AllowSingleHop) -Force",
            SOURCE[enable:write_temp],
        )

    def test_single_hop_mode_is_explicitly_forwarded(self) -> None:
        self.assertIn("[switch]$AllowSingleHop", SOURCE)
        self.assertIn("-AllowSingleHop:$AllowSingleHop", SOURCE)
        for fragment in (
            "$doubleVpnExpected = -not $AllowSingleHop",
            "Get-Process -Name 'winsvpn_awg_engine'",
            "$null -ne $productEngine",
            "single-hop live cycle requires Double VPN to be disabled",
            "single-hop Windows runtime unexpectedly activated Double VPN",
            "WINDOWS_EXACT_SINGLE_HOP_LIVE_CYCLE=PASS",
        ):
            self.assertIn(fragment, INTERACTIVE)

    def test_restores_settings_and_removes_canary_in_finally(self) -> None:
        finally_block = SOURCE[SOURCE.index("} finally {") :]
        self.assertIn("$originalSettings", finally_block)
        self.assertIn("Write-WinsVpnSecureText", finally_block)
        self.assertIn("Remove-Item -LiteralPath $canaryFullPath", finally_block)
        self.assertIn(". $secureStateHelper", SOURCE)
        self.assertNotIn("$settingsPath", SOURCE)
        self.assertNotIn("split-test.tmp", SOURCE)

    def test_protected_egress_probes_do_not_reuse_pre_tunnel_sockets(self) -> None:
        probe_start = INTERACTIVE.index("function Get-PublicEgressDigest")
        probe_end = INTERACTIVE.index("function Get-CurlEgressDigest")
        probe = INTERACTIVE[probe_start:probe_end]
        self.assertIn("Invoke-WebRequest -UseBasicParsing -DisableKeepAlive", probe)

    def test_any_active_route_egress_mismatch_is_sticky_and_fail_closed(self) -> None:
        route_probe = INTERACTIVE.index(
            "if ($tunnel.adapter_up -and $tunnel.default_route -and"
        )
        generation_gate = INTERACTIVE.index(
            "$postTunnel.generation -eq $tunnel.generation", route_probe
        )
        mismatch = INTERACTIVE.index(
            "$connectedEgressMismatchObserved = $true", generation_gate
        )
        recorded = INTERACTIVE.index(
            "[void]$connectionAttempts.Add([pscustomobject]$attempt)", mismatch
        )
        sticky_break = INTERACTIVE.index(
            "if ($connected -or $connectedEgressMismatchObserved) { break }",
            recorded,
        )
        attempts_written = INTERACTIVE.index(
            "connected_egress_mismatch_observed = "
            "$connectedEgressMismatchObserved",
            sticky_break,
        )
        rejected = INTERACTIVE.index(
            "An active Win''s VPN route exposed unexpected public egress.",
            attempts_written,
        )
        self.assertLess(route_probe, mismatch)
        self.assertLess(mismatch, recorded)
        self.assertLess(recorded, sticky_break)
        self.assertLess(sticky_break, attempts_written)
        self.assertLess(attempts_written, rejected)
        self.assertNotIn(
            "if ($tunnel.service_running -and $tunnel.adapter_up -and "
            "$tunnel.default_route)",
            INTERACTIVE,
        )
        self.assertNotIn(
            "if ($egress -cne $ExpectedPublicEgressSha256) { continue }",
            INTERACTIVE,
        )
        self.assertIn(
            "throw 'Network transition exposed unexpected public egress.'",
            INTERACTIVE,
        )
        self.assertIn("if ($egressMismatch) { throw }", INTERACTIVE)

    def test_network_change_matrix_is_explicit_and_fail_closed(self) -> None:
        self.assertIn("[switch]$RunNetworkChangeMatrix", SOURCE)
        self.assertIn("-RunNetworkChangeMatrix:$RunNetworkChangeMatrix", SOURCE)
        for fragment in (
            "function Invoke-NetworkChangeMatrix",
            "'wifi_to_ethernet'",
            "'ethernet_to_wifi'",
            "'dhcp_renew'",
            "'ipv6_binding_recovery'",
            "Test-TransitionProtection",
            "wlan show interfaces",
            "Groups['profile'].Value",
            "network_change_passed",
        ):
            self.assertIn(fragment, INTERACTIVE)
        self.assertNotIn(
            "The Windows curl split-tunnel live cycle exited $LASTEXITCODE",
            SOURCE,
        )


if __name__ == "__main__":
    unittest.main()
