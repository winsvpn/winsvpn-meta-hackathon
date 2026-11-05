from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
PROJECT = ROOT.parent


class WindowsSemanticWatchdogStaticTest(unittest.TestCase):
    def test_disconnect_is_an_exact_semantic_action(self) -> None:
        text = (PROJECT / "tools" / "windows_invoke_vpn_power.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("'Toggle', 'Cancel', 'Disconnect'", text)
        self.assertIn("'Disconnect' { @('Disconnect VPN') }", text)
        self.assertIn("[int]$WindowProcessId = 0", text)
        self.assertIn("Get-Process -Id $WindowProcessId", text)

        probe = (PROJECT / "tools" / "windows_transport_live_probe.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("-WindowProcessId $process.Id", probe)
        self.assertIn("$PSVersionTable.PSEdition -eq 'Core'", probe)
        self.assertIn("System32\\WindowsPowerShell\\v1.0\\powershell.exe", probe)
        self.assertIn("exit $LASTEXITCODE", probe)
        self.assertIn("WINS_PROBE_PAYLOAD_NONCE", probe)
        self.assertIn("WINS_PROBE_GATEWAY_DIGEST", probe)
        self.assertIn("Invoke-VpnEchoProbe", probe)
        self.assertIn("Invoke-BoundHttpsProbe", probe)
        self.assertIn("Get-TunnelManagerAwgStatus", probe)
        self.assertIn("'latest-handshakes'", probe)
        self.assertIn("'transfer'", probe)
        self.assertIn("WinsVPN\\awg.exe", probe)
        self.assertIn("[ValidateSet('latest-handshakes', 'transfer')]", probe)
        self.assertIn('$start.Arguments = "show winsvpn $Field"', probe)
        self.assertNotIn("$start.ArgumentList.Add", probe)
        self.assertIn("Get-AwgLogClassification", probe)
        self.assertIn("O=Privacy Technologies OU", probe)
        self.assertIn("Received message with unknown type", probe)
        self.assertIn("Received packet with invalid mac1", probe)
        self.assertIn("Received invalid response message", probe)
        self.assertIn("Received handshake response", probe)
        self.assertIn("Failed to derive keypair", probe)
        self.assertIn("Sending keepalive packet", probe)
        self.assertIn("Failed to send data packets", probe)
        self.assertIn("Failed to read packet from TUN device", probe)
        self.assertIn("Routine: TUN reader - started", probe)
        self.assertIn("Routine: sequential sender - started", probe)
        self.assertNotIn("NamedPipeClientStream", probe)
        self.assertIn("Get-LocalTunnelState", probe)
        self.assertIn("tunnel_ipv4_matches_config", probe)
        self.assertIn("full_tunnel_route_present", probe)
        self.assertIn("dns_matches_config", probe)
        self.assertIn("mtu_matches_config", probe)
        self.assertIn("vpn_echo_round_trip", probe)
        self.assertIn("bound_https_reachable", probe)
        self.assertIn("awg_runtime_query", probe)
        self.assertIn("awg_received_bytes_nonzero", probe)
        self.assertIn("awg_sent_bytes_nonzero", probe)
        self.assertIn("awg_log_invalid_response_delta", probe)
        self.assertIn("awg_log_unknown_message_type_delta", probe)
        self.assertIn("awg_log_invalid_mac1_delta", probe)
        self.assertIn("awg_log_valid_response_delta", probe)
        self.assertIn("awg_log_derive_keypair_failure_delta", probe)
        self.assertIn("awg_log_keepalive_send_delta", probe)
        self.assertIn("awg_log_data_send_failure_delta", probe)
        self.assertIn("awg_log_tun_read_failure_delta", probe)
        self.assertIn("awg_log_tun_reader_start_delta", probe)
        self.assertIn("awg_log_encryption_worker_start_delta", probe)
        self.assertIn("awg_log_sequential_sender_start_delta", probe)
        self.assertIn("windows_transport_diagnostic_helpers.ps1", probe)
        self.assertIn("Start-WinsKernelNetworkCapture", probe)
        self.assertIn("Stop-WinsKernelNetworkCapture", probe)
        self.assertIn("Update-WinsXrayCarrierState", probe)
        self.assertIn("transport_path_diagnostic", probe)
        self.assertIn("raw_secrets_or_packet_payloads_emitted", probe)

        helpers = (
            PROJECT / "tools" / "windows_transport_diagnostic_helpers.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("--pkt-size', '28'", helpers)
        self.assertIn("zero UDP payload bytes", helpers)
        self.assertIn("Test-WinsPrivateCaptureAcl", helpers)
        self.assertIn("Test-WinsPktMonSessionIdle", helpers)
        self.assertIn("logman.exe", helpers)
        self.assertIn("no\\s+(?:packet\\s+)?filters", helpers)
        self.assertIn("127.0.0.1", helpers)
        self.assertIn("response_returned_to_initiating_socket", helpers)
        self.assertIn("GetPerTcpConnectionEStats", helpers)
        self.assertIn("carrier_bytes_in_delta", helpers)
        self.assertIn("raw_capture_preserved = $false", helpers)
        self.assertIn("raw_capture_delete_verified", helpers)
        self.assertNotIn("--hex", helpers)
        self.assertNotIn("'--type', 'flow'", helpers)
        self.assertIn("Microsoft-Windows-Kernel-Network 0x10 4", helpers)
        self.assertIn("payload_capture_enabled = $false", helpers)
        self.assertIn("udp_send_event_id = 42", helpers)
        self.assertIn("udp_receive_event_id = 43", helpers)
        self.assertIn("response_receive_event_seen", helpers)
        self.assertIn("response_receive_pid_matches_awg_service", helpers)
        self.assertIn("awg_udp_send_elsewhere_count", helpers)
        self.assertIn("awg_udp_send_elsewhere_destination_ports", helpers)
        self.assertIn("Get-WinsAdapterStatisticsSnapshot", helpers)
        self.assertIn("Get-WinsAdapterStatisticsDelta", helpers)
        self.assertIn("Get-WinsBestRouteSelection", helpers)
        self.assertIn("echo_send_metadata_correlated", helpers)
        self.assertIn("selected_source_matches_config", helpers)
        self.assertIn("winsvpn_adapter_statistics", probe)
        self.assertIn("best_route_selection", probe)
        self.assertIn("raw_trace_delete_verified", helpers)

        combined = (
            PROJECT / "tools" / "windows_install_transport_diagnostic.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("windows_install_startup_smoke.ps1", combined)
        self.assertIn("windows_transport_live_probe.ps1", combined)
        self.assertIn("Get-FileHash", combined)
        self.assertIn("-AllowUnsignedLocalCandidate", combined)

        runner = (
            PROJECT / "tools" / "windows_transport_live_probe_runner.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("error_message_sha256", runner)
        self.assertIn("windows_transport_live_probe.ps1", runner)
        self.assertNotIn("Exception.Message =", runner)

    def test_physical_collector_arms_fixed_watchdog_before_execute(self) -> None:
        text = (ROOT / "windows_release_physical_collector.ps1").read_text(
            encoding="utf-8"
        )
        armed = text.index("Start-ScheduledTask -TaskName $TaskName")
        execute = text.index("-File $worker -RunId $RunId -Phase Execute")
        self.assertLess(armed, execute)
        self.assertIn("System32\\WindowsPowerShell", text)
        self.assertIn("Fixed watchdog command grammar changed unexpectedly", text)
        self.assertNotIn("WatchdogScript", text)
        self.assertNotIn("InvokeTool", text)
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName", text)

    def test_watchdog_has_manager_safe_deadline_cleanup(self) -> None:
        legacy = (ROOT / "windows_test_failsafe_watchdog.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("QUARANTINED", legacy)
        text = (ROOT / "windows_release_safe_watchdog.ps1").read_text(
            encoding="utf-8"
        )
        for required in (
            "Stop-Process -Id",
            "Get-Process xray",
            "normal_teardown_proven",
            "fail_safe_triggered",
            "kill_switch_wfp_state",
            "FileShare]::None",
            "Assert-NoReparsePath",
            "Assert-OwnerOnlyAcl",
        ):
            self.assertIn(required, text)
        self.assertIn("winsvpn-windows-release-watchdog-arm-v1", text)
        self.assertIn("$pass = $normal -and -not $emergency", text)
        self.assertIn("Unregister-ScheduledTask -TaskName $TaskName", text)


if __name__ == "__main__":
    unittest.main()
