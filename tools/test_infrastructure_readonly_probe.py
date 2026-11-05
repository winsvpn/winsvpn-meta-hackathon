#!/usr/bin/env python3
"""Fail-closed fixtures for the sanitized infrastructure probe."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("infrastructure_readonly_probe.py")
SPEC = importlib.util.spec_from_file_location("infrastructure_readonly_probe", MODULE_PATH)
assert SPEC and SPEC.loader
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)

RELAY_PATH = pathlib.Path(__file__).with_name("infrastructure_readonly_relay.py")
RELAY_SPEC = importlib.util.spec_from_file_location(
    "infrastructure_readonly_relay", RELAY_PATH
)
assert RELAY_SPEC and RELAY_SPEC.loader
RELAY = importlib.util.module_from_spec(RELAY_SPEC)
RELAY_SPEC.loader.exec_module(RELAY)


class SuricataRuleResolutionTests(unittest.TestCase):
    def test_alternate_etc_rule_tree_is_resolved_from_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            rules = root / "etc" / "suricata" / "rules"
            rules.mkdir(parents=True)
            configured = rules / "stream-events.rules"
            configured.write_text(
                'drop tcp any any -> any any (msg:"fixture"; sid:2210057; rev:1;)\n',
                encoding="utf-8",
            )
            config = root / "suricata.yaml"
            config.write_text("fixture\n", encoding="utf-8")

            def loader(_: str) -> dict[str, object]:
                return {
                    "default-rule-path": str(rules),
                    "rule-files": ["stream-events.rules"],
                }

            paths, names, tree, error = PROBE.resolve_suricata_rule_paths(
                config, loader
            )
            self.assertEqual(error, "")
            self.assertEqual(paths, [configured.resolve()])
            self.assertEqual(names, ["stream-events.rules"])
            self.assertEqual(tree, "other")

    def test_missing_yaml_parser_is_inconclusive_without_default_paths(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            config = pathlib.Path(value) / "suricata.yaml"
            config.write_text("fixture\n", encoding="utf-8")

            def missing(_: str) -> object:
                raise ModuleNotFoundError("fixture parser unavailable")

            paths, names, tree, error = PROBE.resolve_suricata_rule_paths(
                config, missing
            )
            self.assertEqual(paths, [])
            self.assertEqual(names, [])
            self.assertEqual(tree, "unresolved")
            self.assertEqual(error, "ModuleNotFoundError")

    def test_configured_directory_is_inconclusive_not_a_rule_file(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            root = pathlib.Path(value)
            rules = root / "etc" / "suricata" / "rules"
            configured = rules / "not-a-file.rules"
            configured.mkdir(parents=True)
            config = root / "suricata.yaml"
            config.write_text("fixture\n", encoding="utf-8")

            def loader(_: str) -> dict[str, object]:
                return {
                    "default-rule-path": str(rules),
                    "rule-files": ["not-a-file.rules"],
                }

            paths, names, tree, error = PROBE.resolve_suricata_rule_paths(
                config, loader
            )
            self.assertEqual(paths, [])
            self.assertEqual(names, [])
            self.assertEqual(tree, "unresolved")
            self.assertEqual(error, "ConfiguredRuleInvalid")


class RoleFileParityTests(unittest.TestCase):
    def test_role_specific_nginx_paths_match_installers(self) -> None:
        expected = {
            "control": "/etc/nginx/sites-available/wins-hub.conf",
            "data": "/etc/nginx/sites-available/wins-node.conf",
            "core": "/etc/nginx/sites-available/wins-core.conf",
        }
        for role, path in expected.items():
            with self.subTest(role=role):
                files = PROBE.role_files(role)
                self.assertIn(path, files)
                self.assertNotIn("/etc/nginx/sites-available/winsvpn", files)

    def test_control_probe_tracks_recovery_and_zram_contracts(self) -> None:
        files = PROBE.role_files("control")
        self.assertIn("/usr/local/bin/wins-hub-restore-preflight", files)
        self.assertIn("/etc/winsvpn/hub-install-contract.env", files)
        self.assertIn("/etc/systemd/zram-generator.conf", files)

    def test_control_probe_tracks_the_on_demand_canary_job(self) -> None:
        # Slice P2 (design 10.3, P-12) on H3's on-demand job (P2-SEAM-H3): a
        # root job started by a path unit, so it is listed beside the other
        # privileged hub jobs and their triggers.
        files = PROBE.role_files("control")
        units = PROBE.role_units("control")
        self.assertIn("/usr/local/bin/wins-winn3-canary-requests", files)
        self.assertIn("wins-winn3-canary-requests.path", units)
        self.assertIn("wins-winn3-canary-requests.service", units)
        installer = (MODULE_PATH.parent.parent / "server" / "wins_control_plane_setup_ONETOUCH.sh").read_text(
            encoding="utf-8")
        for written in ("cat > /usr/local/bin/wins-winn3-canary-requests <<",
                        "cat > /etc/systemd/system/wins-winn3-canary-requests.service <<",
                        "cat > /etc/systemd/system/wins-winn3-canary-requests.path <<"):
            self.assertIn(written, installer, "the probe lists only what the installer writes")

    def test_core_probe_includes_sync_service_and_timer(self) -> None:
        units = PROBE.role_units("core")
        self.assertIn("wins-core-sync.service", units)
        self.assertIn("wins-core-sync.timer", units)


class HardeningProbeCoverageTests(unittest.TestCase):
    def test_probe_captures_capability_and_namespace_restrictions(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for property_name in (
            "MemoryDenyWriteExecute",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "RestrictNamespaces",
            "RestrictAddressFamilies",
            "SystemCallArchitectures",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectControlGroups",
            "ProtectClock",
            "ProtectHostname",
        ):
            with self.subTest(property_name=property_name):
                self.assertIn(f'"{property_name}"', source)

    def test_storage_probe_distinguishes_ram_encrypted_and_unprotected_swap(
        self,
    ) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for fragment in (
            '"ram_backed"',
            '"encrypted_backing"',
            '"unprotected"',
            '"unprotected_swap_count"',
            '"protected_swap_only"',
        ):
            self.assertIn(fragment, source)


class FirewallDataPathProbeTests(unittest.TestCase):
    def test_forwarding_nat_dns_and_mss_are_proved_without_addresses(self) -> None:
        rules = "\n".join(
            (
                ":WINVPN-FORWARD - [0:0]",
                ":WINVPN-NAT-PREROUTING - [0:0]",
                ":WINVPN-NAT-POSTROUTING - [0:0]",
                "-A FORWARD -i awg0 -j WINVPN-FORWARD",
                "-A FORWARD -o awg0 -j WINVPN-FORWARD",
                "-A WINVPN-FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                "-A WINVPN-FORWARD -i awg0 -o ens6 -j ACCEPT",
                "-A WINVPN-NAT-PREROUTING -i awg0 -p udp --dport 53 -j REDIRECT --to-ports 53",
                "-A WINVPN-NAT-PREROUTING -i awg0 -p tcp --dport 53 -j REDIRECT --to-ports 53",
                "-A WINVPN-NAT-POSTROUTING -s 10.8.0.0/16 -o ens6 -j MASQUERADE",
                "-A WINVPN-MANGLE-FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
            )
        )
        counters = "\n".join(
            f"[{index}:100] {line}"
            for index, line in enumerate(rules.splitlines(), start=1)
            if line.startswith("-A ")
        )
        result = PROBE.iptables_vpn_data_path(rules, counters)
        for field in (
            "forward_chain_present",
            "nat_postrouting_chain_present",
            "forward_jump_in_awg0",
            "forward_jump_out_awg0",
            "forward_return_established_accept",
            "forward_awg0_to_wan_accept",
            "masquerade_present",
            "dns_udp_redirect_present",
            "dns_tcp_redirect_present",
            "tcp_mss_policy_present",
        ):
            with self.subTest(field=field):
                self.assertTrue(result[field])
        self.assertGreater(result["forward_awg0_to_wan_packets"], 0)
        self.assertGreater(result["forward_return_packets"], 0)
        self.assertGreater(result["masquerade_packets"], 0)
        self.assertNotIn("10.8.0.0", str(result))
        self.assertNotIn("ens6", str(result))

    def test_missing_rules_fail_closed(self) -> None:
        result = PROBE.iptables_vpn_data_path("", "")
        self.assertFalse(result["counter_inspection_complete"])
        self.assertFalse(result["forward_awg0_to_wan_accept"])
        self.assertFalse(result["masquerade_present"])

    def test_hidden_hub_origin_has_only_source_restricted_recovery_ssh(self) -> None:
        rules = "\n".join(
            (
                ":WINVPN-HUB-INPUT - [0:0]",
                "-A INPUT -j WINVPN-HUB-INPUT",
                "-A WINVPN-HUB-INPUT -i lo -j ACCEPT",
                "-A WINVPN-HUB-INPUT -s 203.0.113.10/32 -p tcp --dport 22 -j ACCEPT",
                "-A WINVPN-HUB-INPUT -j DROP",
            )
        )
        result = PROBE.iptables_origin_exposure(rules)
        self.assertTrue(result["hub_input_chain_present"])
        self.assertTrue(result["hub_input_jump_present"])
        self.assertTrue(result["hub_input_terminal_drop_present"])
        self.assertEqual(result["ssh_accept_rule_count"], 1)
        self.assertEqual(result["ssh_source_restricted_rule_count"], 1)
        self.assertFalse(result["ssh_unrestricted_accept_present"])
        self.assertEqual(result["web_accept_rule_count"], 0)
        self.assertNotIn("203.0.113.10", str(result))

    def test_global_ssh_and_web_accepts_are_detected(self) -> None:
        rules = "\n".join(
            (
                "-A WINVPN-HUB-INPUT -p tcp --dport 22 -j ACCEPT",
                "-A WINVPN-HUB-INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT",
            )
        )
        result = PROBE.iptables_origin_exposure(rules)
        self.assertTrue(result["ssh_unrestricted_accept_present"])
        self.assertTrue(result["web_unrestricted_accept_present"])


class ControlIntegrationMaterialTests(unittest.TestCase):
    def test_complete_contract_reports_only_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = pathlib.Path(value) / "hub.env"
            path.write_text(
                "\n".join(
                    (
                        "ADMIN_TOKEN=admin-secret",
                        "SMTP_SERVER='mail.smtp2go.com'",
                        "SMTP_PORT='2525'",
                        "SMTP_USER=smtp-user",
                        "SMTP_PASS=smtp-secret",
                        "PAYPAL_MODE=live",
                        "PAYPAL_PUBLIC_CLIENT_ID=paypal-client",
                        "PAYPAL_CLIENT_ID=paypal-client",
                        "PAYPAL_CLIENT_SECRET=paypal-secret",
                        "PAYPAL_WEBHOOK_ID=webhook-id",
                        "PAYPAL_WEBHOOK_AUTO_ENSURE=1",
                        "PAYPAL_WEBHOOK_URL=https://sync.example/webhook/paypal",
                        "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS=false",
                        "PAYPAL_PLAN_1M=plan-1m",
                        "PAYPAL_PLAN_1Y=plan-1y",
                        "PAYPAL_PLAN_PERSONAL=plan-personal",
                        "PAYPAL_LIFETIME_SUPPORT_URL=https://www.paypal.com/ncp/payment/support",
                        "PAYPAL_LIFETIME_NO_SUPPORT_URL=https://www.paypal.com/ncp/payment/basic",
                        "PAYPAL_LIFETIME_SUPPORT_AMOUNT=1000.00",
                        "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT=100.00",
                        "PAYPAL_LIFETIME_CURRENCY=USD",
                        "CLOUDFLARE_TUNNEL_ACCOUNT_ID=account",
                        "CLOUDFLARE_TUNNEL_API_TOKEN=tunnel-token",
                        "CLOUDFLARE_WINS_API_TOKEN=wins-token",
                        "CLOUDFLARE_WINSVPN_ORG_ZONE_ID=org-zone",
                        "CLOUDFLARE_WINSVPN_COM_ZONE_ID=com-zone",
                        "CLOUDFLARE_ACCESS_API_TOKEN=access-token",
                        "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID=uuid",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            path.chmod(0o600)
            result = PROBE.control_integration_material(
                path, require_root_owner=False, enforce_owner_only=False
            )
        self.assertTrue(result["one_touch_material_complete"])
        self.assertFalse(result["secret_values_emitted"])
        self.assertNotIn("admin-secret", str(result))
        self.assertNotIn("paypal-secret", str(result))

    def test_world_readable_or_incomplete_environment_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as value:
            path = pathlib.Path(value) / "hub.env"
            path.write_text("ADMIN_TOKEN=value\n", encoding="utf-8")
            path.chmod(0o644)
            result = PROBE.control_integration_material(
                path, require_root_owner=False
            )
        self.assertFalse(result["environment_owner_only"])
        self.assertNotIn("one_touch_material_complete", result)


class RelayPrivilegeModeTests(unittest.TestCase):
    def test_default_remote_probe_has_no_privilege_change(self) -> None:
        self.assertEqual(
            RELAY.build_remote_probe_command("core", False),
            "env WINS_PROBE_ROLE_OVERRIDE=core python3 -",
        )

    def test_privileged_probe_is_noninteractive_and_constant_shape(self) -> None:
        self.assertEqual(
            RELAY.build_remote_probe_command("data", True),
            "sudo -n env WINS_PROBE_ROLE_OVERRIDE=data python3 -",
        )

    def test_unready_core_remains_diagnosable_over_healthy_management_path(self) -> None:
        source = RELAY_PATH.read_text(encoding="utf-8")
        core_query = source[source.index("FROM core_servers") : source.index(
            "ORDER BY core_id", source.index("FROM core_servers")
        )]
        self.assertIn("status='online'", core_query)
        self.assertIn("management_status='ok'", core_query)
        self.assertNotIn("runtime_ready", core_query)


if __name__ == "__main__":
    unittest.main()
