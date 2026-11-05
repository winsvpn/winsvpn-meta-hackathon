#!/usr/bin/env python3
"""Contracts for the transport-only Windows Single/Double Xray matrix."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX = (ROOT / "tools" / "windows_xray_awg_handshake_matrix.ps1").read_text(
    encoding="utf-8"
)


class WindowsXrayHandshakeMatrixContractTests(unittest.TestCase):
    def test_mode_is_explicit_and_bound_to_protected_registration(self) -> None:
        for marker in (
            "[ValidateSet('Single', 'Double')]",
            "[string]$ExpectedMode",
            "Read-WinsVpnSecureJson -Name 'vpn_config.txt'",
            "Read-WinsVpnSecureJson -Name 'client_keypair.json'",
            "$config.double_vpn_active -is [bool]",
            "$remoteAwgPort -ne $directPort",
            "$directPort -ne 9110",
            "$directPort -eq 9110",
            "$config.double_vpn_core_id",
            "$config.double_vpn_exit_slug",
        ):
            self.assertIn(marker, MATRIX)

    def test_every_advertised_80_and_443_route_uses_production_shape(self) -> None:
        for marker in (
            "function Get-XrayRoutes",
            "$Xray.PSObject.Properties['transports']",
            "$seen.Contains('80/none')",
            "$seen.Contains('443/tls')",
            "port = $remoteAwgPort",
            "port = [int]$lane.port",
            "security = [string]$lane.security",
            "headers = [ordered]@{",
            "Host = [string]$config.xray.server_name",
            "$streamSettings.tlsSettings",
            "allowInsecure = $false",
            "enabled = $false",
            "xudpProxyUDP443 = 'skip'",
        ):
            self.assertIn(marker, MATRIX)
        self.assertNotIn("xudpProxyUDP443 = 'allow'", MATRIX)

    def test_direct_udp_is_bypassed_but_local_awg_is_mandatory(self) -> None:
        for marker in (
            "Endpoint = 127.0.0.1:42110",
            "AllowedIPs = 192.0.2.1/32",
            "A required installed runtime is missing",
            "Get-Process xray,winsvpn_awg_engine",
            "Get-NetAdapter -IncludeHidden",
            "Get-NetRoute -ErrorAction SilentlyContinue",
            "latest-handshakes",
            "received_bytes = $receivedBytes",
            "sent_bytes = $sentBytes",
            "direct_udp_unavailable_by_construction = $true",
            "local_awg_packet_engine_required = $true",
            "function Wait-DiagnosticTeardown",
            "Get-NetAdapter -Name $AdapterName -IncludeHidden",
            "teardown_clean =",
        ):
            self.assertIn(marker, MATRIX)

    def test_evidence_binds_mode_ports_and_double_identity(self) -> None:
        for marker in (
            "schema_version = 2",
            "winsvpn-windows-xray-awg-handshake-matrix-v2",
            "expected_mode = $ExpectedMode",
            "observed_double_vpn_active = $doubleVpnActive",
            "direct_first_hop_port = $directPort",
            "xray_remote_awg_port = $remoteAwgPort",
            "double_vpn_core_id_sha256",
            "double_vpn_exit_slug_sha256",
            "transport_port = [int]$lane.port",
            "transport_security = [string]$lane.security",
        ):
            self.assertIn(marker, MATRIX)


if __name__ == "__main__":
    unittest.main()
