import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "core_runtime_readonly_diagnostic.py"
CORE_SETUP = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"


def load_diagnostic_module():
    spec = importlib.util.spec_from_file_location("core_runtime_readonly_diagnostic", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load Core runtime diagnostic module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CoreRuntimeReadonlyDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.core_source = CORE_SETUP.read_text(encoding="utf-8")
        cls.diagnostic = load_diagnostic_module()

    def test_output_contract_is_sanitized(self):
        self.assertIn("winsvpn-core-runtime-readonly-diagnostic-v1", self.source)
        self.assertIn('"role": "core"', self.source)
        self.assertIn("stderr=subprocess.DEVNULL", self.source)
        self.assertNotIn("management_host", self.source)
        self.assertNotIn("ingress_endpoint", self.source)
        self.assertNotIn("public_key", self.source)

    def test_failure_classes_cover_every_sync_fail_closed_branch(self):
        for marker in (
            "assignment_payload_invalid",
            "exit_interface_setup_failed",
            "ingress_peer_update_failed",
            "client_policy_rule_update_failed",
            "exit_metadata_invalid",
            "exit_state_directory_failed",
            "exit_local_port_invalid",
            "exit_xray_selection_failed",
            "exit_transport_state_write_failed",
            "exit_config_staging_failed",
            "exit_container_replace_failed",
            "exit_config_install_failed",
            "exit_image_unavailable",
            "exit_container_start_failed",
            "exit_interface_restart_failed",
            "exit_interface_missing_after_restart",
            "exit_route_update_failed",
            "management_path_failed",
            "assignment_sync_failed",
            "assignment_set_failed",
            "runtime_validation_failed",
            "ingress_container_down",
            "ingress_key_mismatch",
            "exit_container_down",
            "exit_key_mismatch",
            "transport_state_invalid",
            "exit_handshake_stale",
            "xray_preflight_failed",
            "latest_failure_stage",
            "ready-registration",
        ):
            self.assertIn(marker, self.source)

    def test_runtime_validation_classes_exactly_cover_core_emissions(self):
        emitted = set(
            re.findall(
                r'Core runtime validation failed class=([a-z0-9_]+)',
                self.core_source,
            )
        )
        self.assertTrue(emitted)
        self.assertEqual(emitted, set(self.diagnostic.RUNTIME_VALIDATION_CLASSES))

    def test_each_runtime_validation_log_line_is_classified_exactly(self):
        emitted = set(self.diagnostic.RUNTIME_VALIDATION_CLASSES)
        journal = "\n".join(
            f"Core runtime validation failed class={name}" for name in sorted(emitted)
        )
        with mock.patch.object(self.diagnostic, "run", return_value=(0, journal)):
            result = self.diagnostic.failure_classes()
        self.assertEqual(emitted, set(result["failure_classes"]))
        self.assertFalse(result["unclassified_failure_present"])

    def test_handshake_recovery_classes_exactly_cover_core_emissions(self):
        emitted = set(
            re.findall(
                r'Core handshake recovery failed class=([a-z0-9_]+)',
                self.core_source,
            )
        )
        self.assertTrue(emitted)
        self.assertEqual(emitted, set(self.diagnostic.HANDSHAKE_RECOVERY_CLASSES))

    def test_each_handshake_recovery_log_line_is_classified_exactly(self):
        emitted = set(self.diagnostic.HANDSHAKE_RECOVERY_CLASSES)
        journal = "\n".join(
            f"Core handshake recovery failed class={name}"
            for name in sorted(emitted)
        )
        with mock.patch.object(self.diagnostic, "run", return_value=(0, journal)):
            result = self.diagnostic.failure_classes()
        self.assertEqual(emitted, set(result["failure_classes"]))
        self.assertFalse(result["unclassified_failure_present"])

    def test_legacy_and_exact_markers_do_not_duplicate_a_class(self):
        journal = "\n".join(
            (
                "Core runtime validation failed class=ingress_container_down",
                "Core ingress container is not running",
            )
        )
        with mock.patch.object(self.diagnostic, "run", return_value=(0, journal)):
            result = self.diagnostic.failure_classes()
        self.assertEqual(["ingress_container_down"], result["failure_classes"])

    def test_journal_window_and_line_count_are_bounded(self):
        self.assertIn('"-20 minutes"', self.source)
        self.assertIn('"500"', self.source)

    def test_systemd_properties_use_one_bounded_snapshot(self):
        self.assertIn('args = ["systemctl", "show", "wins-core-sync.service"]', self.source)
        self.assertIn('args.extend(["-p", name])', self.source)
        self.assertIn('rc, output = run(args, 12)', self.source)
        self.assertNotIn('"--value"', self.source)

    def test_transport_output_is_aggregate_and_bounded(self):
        for field in (
            "expected_exits_count",
            "running_containers_count",
            "host_interfaces_count",
            "valid_routes_count",
            "active_xray_services_count",
            "valid_xray_configs_count",
            "native_udp_mux_disabled_configs_count",
            "legacy_xudp_enabled_configs_count",
            "other_mux_configs_count",
            "local_loopback_listeners_count",
            "fresh_handshakes_count",
            "xray_failure_categories",
            "installed_sync_agent_contract",
            "stale_handshake_cause",
            "observation_limit_reached",
        ):
            self.assertIn(field, self.source)
        self.assertIn("MAX_OBSERVED_EXITS = 128", self.source)
        self.assertNotIn('"exit_names"', self.source)
        self.assertNotIn('"interfaces"', self.source)
        self.assertNotIn('"raw_journal"', self.source)
        self.assertNotIn('"sync_agent_source"', self.source)
        self.assertNotIn('"sync_agent_sha256"', self.source)

    def test_transport_predicates_report_healthy_stealth_aggregates_only(self):
        now = 2_000_000_000
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp) / "state"
            config_dir = Path(temp) / "xray"
            state_dir.mkdir()
            config_dir.mkdir()
            (state_dir / "corex7.conf").write_text(
                "PostUp = ip route replace default dev corex7 table 52007\n",
                encoding="utf-8",
            )
            (state_dir / "corex7.transport").write_text("mode=stealth\n", encoding="utf-8")
            (config_dir / "corex7.json").write_text(
                json.dumps({
                    "inbounds": [{
                        "listen": "127.0.0.1",
                        "port": 43007,
                        "protocol": "tunnel",
                        "settings": {"network": "udp"},
                    }],
                    "outbounds": [{
                        "tag": "vless-ws-out",
                        "protocol": "vless",
                        "mux": {
                            "enabled": False,
                            "concurrency": 0,
                            "xudpConcurrency": 0,
                            "xudpProxyUDP443": "skip",
                        },
                    }],
                }),
                encoding="utf-8",
            )

            def fake_run(args, timeout=15):
                if args[:4] == ["ss", "-H", "-l", "-u"]:
                    return 0, "UNCONN 0 0 127.0.0.1:43007 0.0.0.0:*\n"
                if args and args[0] == "journalctl":
                    return 0, ""
                if args[:3] == ["docker", "inspect", "-f"]:
                    return 0, "true\n"
                if args[:4] == ["ip", "link", "show", "dev"]:
                    return 0, "present but never returned"
                if args[:6] == ["ip", "-4", "route", "show", "table", "52007"]:
                    return 0, "default dev corex7"
                if args[:3] == ["systemctl", "is-active", "--quiet"]:
                    return 0, ""
                if args[:3] == ["xray", "-test", "-config"]:
                    return 0, ""
                if args[:3] == ["docker", "exec", "wins-core-exit-corex7"]:
                    return 0, f"redacted {now - 10}\n"
                return 1, ""

            with mock.patch.object(self.diagnostic, "run", side_effect=fake_run):
                result = self.diagnostic.transport_predicates(state_dir, config_dir, now)

        self.assertEqual(1, result["expected_exits_count"])
        self.assertEqual(1, result["running_containers_count"])
        self.assertEqual(1, result["host_interfaces_count"])
        self.assertEqual(1, result["valid_routes_count"])
        self.assertEqual(1, result["active_xray_services_count"])
        self.assertEqual(1, result["valid_xray_configs_count"])
        self.assertEqual(1, result["native_udp_mux_disabled_configs_count"])
        self.assertEqual(0, result["legacy_xudp_enabled_configs_count"])
        self.assertEqual(0, result["other_mux_configs_count"])
        self.assertEqual(1, result["local_loopback_listeners_count"])
        self.assertEqual(1, result["fresh_handshakes_count"])
        self.assertEqual("healthy", result["stale_handshake_cause"])
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("corex7", serialized)
        self.assertNotIn("43007", serialized)

    def test_xray_mux_contract_counts_native_legacy_and_other_without_content(self):
        with tempfile.TemporaryDirectory() as temp:
            config_dir = Path(temp)

            def write_config(name, mux):
                (config_dir / f"{name}.json").write_text(
                    json.dumps({
                        "inbounds": [{"protocol": "tunnel", "settings": {"network": "udp"}}],
                        "outbounds": [{"tag": "vless-ws-out", "protocol": "vless", "mux": mux}],
                    }),
                    encoding="utf-8",
                )

            write_config("corex1", {
                "enabled": False,
                "concurrency": 0,
                "xudpConcurrency": 0,
                "xudpProxyUDP443": "skip",
            })
            write_config("corex2", {
                "enabled": True,
                "concurrency": -1,
                "xudpConcurrency": 16,
                "xudpProxyUDP443": "allow",
            })
            write_config("corex3", {"enabled": False})
            self.assertEqual("native_udp", self.diagnostic._xray_mux_contract(config_dir, "corex1"))
            self.assertEqual("legacy_xudp", self.diagnostic._xray_mux_contract(config_dir, "corex2"))
            self.assertEqual("other", self.diagnostic._xray_mux_contract(config_dir, "corex3"))

    def test_installed_sync_agent_contract_is_strictly_allow_listed(self):
        native = 'mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}'
        legacy = 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "agent"
            self.assertEqual("unreadable", self.diagnostic._installed_sync_agent_contract(path))
            path.write_text(native, encoding="utf-8")
            self.assertEqual("native_udp", self.diagnostic._installed_sync_agent_contract(path))
            path.write_text(legacy, encoding="utf-8")
            self.assertEqual("legacy_xudp", self.diagnostic._installed_sync_agent_contract(path))
            path.write_text(native + "\n" + legacy, encoding="utf-8")
            self.assertEqual("other", self.diagnostic._installed_sync_agent_contract(path))

    def test_transport_cause_distinguishes_xray_failure_from_missing_listener(self):
        counts = {
            "expected_exits_count": 1,
            "running_containers_count": 1,
            "host_interfaces_count": 1,
            "valid_routes_count": 1,
            "valid_transport_states_count": 1,
            "stealth_exits_count": 1,
            "active_xray_services_count": 1,
            "valid_xray_configs_count": 1,
            "local_loopback_listeners_count": 1,
            "fresh_handshakes_count": 0,
        }
        self.assertEqual(
            "xray_runtime_failure",
            self.diagnostic._stale_handshake_cause(counts, ["connection_timeout"], False),
        )
        counts["local_loopback_listeners_count"] = 0
        self.assertEqual(
            "xray_listener_incomplete",
            self.diagnostic._stale_handshake_cause(counts, ["connection_timeout"], False),
        )

    def test_xray_journal_categories_are_allow_listed(self):
        journal = "connection refused\ncertificate verification failed\nunrelated secret-bearing line"
        with mock.patch.object(self.diagnostic, "run", return_value=(0, journal)):
            categories, readable = self.diagnostic._xray_journal_categories()
        self.assertTrue(readable)
        self.assertEqual(["connection_refused", "tls_failure"], categories)


if __name__ == "__main__":
    unittest.main()
