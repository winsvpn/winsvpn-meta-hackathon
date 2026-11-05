#!/usr/bin/env python3
"""FREE-CAP hub publication and installer regressions without remote effects."""

import ast
import base64
import hashlib
import hmac
import importlib.util
import ipaddress
import json
import pathlib
import re
import sqlite3
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from typing import Any, Optional
from unittest.mock import patch

from validate_deployment_scripts import parse_heredocs
import winn3_gateway_block as gateway_block

ROOT = pathlib.Path(__file__).resolve().parents[1]
HUB = ROOT / "server/wins_control_plane_setup_ONETOUCH.sh"
INSTALLERS = [ROOT / "server/wins_data_plane_setup_ONETOUCH.sh",
              ROOT / "server/wins_core_server_setup_ONETOUCH.sh"]


def hub_block():
    return next(item.body for item in parse_heredocs(HUB)
                if item.header.strip() == 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'')


def hub_functions(*names):
    nodes = [item for item in ast.parse(hub_block()).body
             if isinstance(item, ast.FunctionDef) and item.name in names]
    if len(nodes) != len(names):
        raise AssertionError("missing hub function")
    return compile(ast.Module(body=nodes, type_ignores=[]), str(HUB), "exec")


def hub_constants(*names):
    nodes = [item for item in ast.parse(hub_block()).body
             if isinstance(item, ast.Assign) and any(
                 isinstance(target, ast.Name) and target.id in names for target in item.targets)]
    found = {target.id for item in nodes for target in item.targets if isinstance(target, ast.Name)}
    if not set(names) <= found:
        raise AssertionError("missing hub constant")
    return compile(ast.Module(body=nodes, type_ignores=[]), str(HUB), "exec")


class HubTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE nodes(slug TEXT);
            INSERT INTO nodes VALUES('node-a'),('node-b');
            CREATE TABLE users(account_number TEXT,status TEXT,expiration_date TEXT,renewal_source TEXT);
            CREATE TABLE devices(device_id TEXT,account_number TEXT,location_slug TEXT,
                                 winn3_static_public TEXT,winn3_inner_v4 TEXT);
            CREATE TABLE winn3_departure_grants(grant_id TEXT,device_id TEXT,account_number TEXT,
                    node_slug TEXT,static_public TEXT,inner_v4 TEXT,expires_at REAL);
        """)
        self.ns = dict(sqlite3=sqlite3, Optional=Optional, Any=Any,
                       FREE_ACCESS_ACCOUNT_NUMBER="9999-9999-9999", FREE_ACCESS_LABEL="Free Access",
                       base64=base64, ipaddress=ipaddress, WINN3_X25519_KEY_BYTES=32,
                       utcnow=lambda: datetime.now(timezone.utc), winn3_clock=lambda: 1000,
                       node_admits_peer=lambda node, row: True,
                       winn3_inner_pool=lambda: ipaddress.ip_network("10.10.0.0/24"),
                       winn3_canary_binding_for=lambda slug: None,
                       parse_iso_datetime=lambda value: None)
        # The tier publication gate. True reproduces a node whose gateway
        # binary reported peer-registry-tier; the gated-off shape is a
        # separate test below.
        self.peer_tier_reports = True
        self.ns["winn3_node_reports_peer_tier"] = lambda node: self.peer_tier_reports
        exec(hub_functions("freecap_tier", "winn3_peer_registry_publication", "select_free_node"), self.ns)
        self.db.execute("INSERT INTO users VALUES(?, 'active', 'Free Access', 'free_access')", (self.ns["FREE_ACCESS_ACCOUNT_NUMBER"],))
        self.db.execute("INSERT INTO users VALUES('paid-account','active','Lifetime Access','manual')")
        self.keys = [base64.b64encode(bytes([n])*32).decode() for n in (1, 2, 3)]
        for number, account in enumerate([self.ns["FREE_ACCESS_ACCOUNT_NUMBER"],
                                          self.ns["FREE_ACCESS_ACCOUNT_NUMBER"], "paid-account"]):
            self.db.execute("INSERT INTO devices VALUES(?,?,?,?,?)",
                            (str(number), account, "node-a", self.keys[number], "10.10.0."+str(number+2)))

    def test_registry_marks_each_free_device_and_paid_without_identity(self):
        doc, meta = self.ns["winn3_peer_registry_publication"](self.db, "node-a")
        self.assertEqual(doc["version"], 1)
        self.assertEqual([entry["tier"] for entry in doc["peers"]], ["free", "free", "premium"])
        for entry in doc["peers"]:
            self.assertEqual(set(entry), {"tier", "static_public", "inner_v4", "not_after"})
        self.assertNotIn("9999-9999-9999", json.dumps(doc))
        self.assertEqual(len(meta), 3)

    def test_node_without_the_feature_gets_todays_document(self):
        self.peer_tier_reports = False
        doc, meta = self.ns["winn3_peer_registry_publication"](self.db, "node-a")
        self.assertEqual(doc["version"], 1)
        for entry in doc["peers"]:
            self.assertEqual(set(entry), {"static_public", "inner_v4", "not_after"})
        self.assertNotIn("tier", json.dumps(doc))

    def test_publication_gates_the_tier_on_the_reported_feature(self):
        # Source-level: the publication must ask the node's report (the gate)
        # and version the document on its answer, so a node whose decoder
        # cannot read a tier is never handed one.
        block = next(item.body for item in parse_heredocs(HUB)
                     if item.header.strip() == 'cat > "${APP_DIR}/main.py" <<\'PYEOF\'')
        source = next(node for node in ast.parse(block).body
                      if isinstance(node, ast.FunctionDef)
                      and node.name == "winn3_peer_registry_publication")
        text = ast.get_source_segment(block, source)
        self.assertIn("winn3_node_reports_peer_tier(registry_node)", text)
        self.assertIn('return {"version": 1, "peers": peers}', text)
        self.assertIn("if tier_enabled:", text)

    def test_reconnect_provisional_and_server_switch_keep_free_plan(self):
        publish = self.ns["winn3_peer_registry_publication"]
        first, _ = publish(self.db, "node-a")
        second, _ = publish(self.db, "node-a", {self.keys[0]: 1100})
        self.assertEqual(first["peers"][0]["tier"], second["peers"][0]["tier"])
        self.assertEqual(second["peers"][0]["not_after"], 1100)
        self.db.execute("UPDATE devices SET location_slug='node-b' WHERE device_id='0'")
        third, _ = publish(self.db, "node-b")
        self.assertEqual(third["peers"][0]["tier"], "free")
        self.assertEqual(third["peers"][0]["static_public"], self.keys[0])

    def test_departure_and_canary_have_explicit_plan(self):
        self.db.execute("UPDATE devices SET location_slug='node-b' WHERE device_id='0'")
        self.db.execute("INSERT INTO winn3_departure_grants VALUES(?,?,?,?,?,?,?)",
                        ("grant", "0", self.ns["FREE_ACCESS_ACCOUNT_NUMBER"], "node-a",
                         self.keys[0], "10.10.0.2", 1100))
        self.ns["winn3_canary_binding_for"] = lambda slug: {
            "static_public": base64.b64encode(bytes([4])*32).decode(), "inner_v4": "10.10.0.5"}
        doc, meta = self.ns["winn3_peer_registry_publication"](self.db, "node-a")
        tiers = dict(zip((item["kind"] for item in meta), (item["tier"] for item in doc["peers"])))
        self.assertEqual(tiers["departure"], "free")
        self.assertEqual(tiers["canary"], "premium")

    def test_renewal_source_marks_live_and_departure_peers(self):
        self.db.execute("UPDATE users SET renewal_source='free_access' WHERE account_number='paid-account'")
        publish = self.ns["winn3_peer_registry_publication"]
        doc, _ = publish(self.db, "node-a")
        self.assertEqual(doc["peers"][2]["tier"], "free")
        self.db.execute("UPDATE devices SET location_slug='node-b' WHERE device_id='2'")
        self.db.execute("INSERT INTO winn3_departure_grants VALUES(?,?,?,?,?,?,?)",
                        ("renewal-grant", "2", "paid-account", "node-a", self.keys[2], "10.10.0.4", 1100))
        doc, meta = publish(self.db, "node-a")
        self.assertEqual(doc["peers"][2]["tier"], "free")
        self.assertEqual(meta[2]["kind"], "departure")
        self.assertEqual(self.ns["freecap_tier"]("paid-account", "Lifetime Access", "manual"), "premium")
        self.assertEqual(self.ns["freecap_tier"]("renamed-free", "Lifetime Access", "free_access"), "free")

    def test_core_assignment_carries_the_tier_and_its_revision_moves_with_it(self):
        ns = dict(hmac=hmac, hashlib=hashlib, json=json, Any=Any,
                  MANAGEMENT_NAME_HMAC_KEY="fixture-management-key", ADMIN_SECRET_TOKEN="fixture-admin")
        exec(hub_constants("CORE_ASSIGNMENT_REVISION_FIELDS"), ns)
        exec(hub_functions("core_assignment_revision"), ns)
        self.assertIn("traffic_tier", ns["CORE_ASSIGNMENT_REVISION_FIELDS"])
        free = {"device_id": "d", "client_ip": "10.9.1.2", "traffic_tier": "free"}
        premium = dict(free, traffic_tier="premium")
        self.assertNotEqual(ns["core_assignment_revision"](free), ns["core_assignment_revision"](premium))
        self.assertIn('"traffic_tier": freecap_tier(row["account_number"], row["expiration_date"], '
                      'str(row["renewal_source"] or ""))', hub_block())

    def test_free_user_can_select_premium_labelled_server(self):
        observed = []
        self.ns["FREE_ACCESS_ENABLED"] = True
        def choose(conn, slug, **kwargs):
            observed.append(kwargs)
            return {"slug": "node-b", "free_access_enabled": 0}
        self.ns["select_online_node"] = choose
        node = self.ns["select_free_node"](self.db, "node-b")
        self.assertEqual(node["slug"], "node-b")
        self.assertFalse(observed[0]["free_only"])

    def test_the_free_tier_is_decided_from_hub_state_only(self):
        tier = self.ns["freecap_tier"]
        self.assertEqual(tier("9999-9999-9999"), "free")
        self.assertEqual(tier("renamed-free", "Lifetime Access", "free_access"), "free")
        self.assertEqual(tier("legacy", "Free Access"), "free")
        for account, expiration, source in [("paid-account", "Lifetime Access", "manual"),
                                            ("paid-account", "2099-01-01T00:00:00+00:00", ""),
                                            ("", "", "")]:
            self.assertEqual(tier(account, expiration, source), "premium")


class ReportGateTests(unittest.TestCase):
    """The register report's peer_tier is the only thing that lets the hub write a tier word."""

    def setUp(self):
        self.ns = dict(Any=Any, Optional=Optional, json=json, re=re,
                       winn3_is_inner_ipv4=lambda value: bool(re.fullmatch(r"10\.10\.[0-9]{1,3}\.[0-9]{1,3}", value)))
        exec(hub_constants("WINN3_GATEWAY_REPORT_STATES", "WINN3_GATEWAY_REPORT_PLAN_RE",
                           "WINN3_GATEWAY_REPORT_LISTEN_RE", "WINN3_GATEWAY_REPORT_ID_RE",
                           "WINN3_GATEWAY_REPORT_CIDR_RE"), self.ns)
        exec(hub_functions("_node_field", "sanitize_winn3_gateway_report",
                           "parse_winn3_gateway_report", "winn3_node_reports_peer_tier"), self.ns)

    def node(self, report):
        return {"winn3_gateway_report_json": None if report is None else json.dumps(report)}

    def test_only_a_reported_true_enables_the_tier_word(self):
        gate = self.ns["winn3_node_reports_peer_tier"]
        self.assertTrue(gate(self.node({"state": "active", "peer_tier": True})))
        for report in [None, {"state": "active"}, {"state": "active", "peer_tier": False},
                       {"state": "active", "peer_tier": None}, {"state": "active", "peer_tier": "true"},
                       {"state": "active", "peer_tier": 1}]:
            self.assertFalse(gate(self.node(report)), report)
        self.assertFalse(gate(None))
        self.assertFalse(gate({"winn3_gateway_report_json": "not json"}))

    def test_an_unreported_value_keeps_the_report_shape_it_always_had(self):
        sanitize = self.ns["sanitize_winn3_gateway_report"]
        self.assertNotIn("peer_tier", sanitize({"state": "active"}))
        self.assertNotIn("peer_tier", sanitize({"state": "active", "peer_tier": "yes"}))
        self.assertIs(sanitize({"state": "active", "peer_tier": True})["peer_tier"], True)
        self.assertIs(sanitize({"state": "active", "peer_tier": False})["peer_tier"], False)


class V1HostPolicyTests(unittest.TestCase):
    """The shell the hub runs on a v1 node before it installs a peer."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ns = dict(shlex=__import__("shlex"), AWG_CONTAINER_CANDIDATES=["awg-test"], ipaddress=ipaddress)
        exec(hub_constants("FREE_BANDWIDTH_HELPER"), self.ns)
        exec(hub_functions("free_bandwidth_host_before"), self.ns)

    def run_shell(self, tier, helper_rc):
        """Run the generated shell with a stub helper (None means not installed)."""
        helper = pathlib.Path(self.tmp.name) / "wins-free-bandwidth"
        if helper_rc is not None:
            helper.write_text('#!/bin/sh\necho "helper:$*"\nexit %d\n' % helper_rc)
            helper.chmod(0o755)
        fragment = self.ns["free_bandwidth_host_before"](tier, "10.8.2.2", "PEERKEY", helper=str(helper))
        script = ('docker() { case "$1" in ps) echo awg-test;; exec) echo "docker:$*";; esac; }\n'
                  "set -e\n{ " + fragment + " echo ADMITTED; }\n")
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)

    def test_a_free_peer_is_admitted_only_after_the_policy_took(self):
        result = self.run_shell("free", 0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("helper:awg0 10.8.2.2 free", result.stdout)
        self.assertIn("ADMITTED", result.stdout)

    def test_a_failing_policy_refuses_and_removes_the_peer(self):
        for tier in ("free", "premium"):
            result = self.run_shell(tier, 1)
            self.assertEqual(result.returncode, 1, tier)
            self.assertNotIn("ADMITTED", result.stdout)
            self.assertIn("docker:exec awg-test awg set awg0 peer PEERKEY remove", result.stdout)
            self.assertIn("bandwidth-policy-failed", result.stderr)

    def test_a_node_without_the_helper_admits_both_tiers_so_the_hub_never_fails_it(self):
        # An un-updated node has no cap yet; refusing free peers there made the hub mark the
        # node failed and drop it for paying users too (FREE-CAP Turn 3, Sonnet seat).
        for tier in ("premium", "free"):
            result = self.run_shell(tier, None)
            self.assertEqual(result.returncode, 0, (tier, result.stderr))
            self.assertIn("ADMITTED", result.stdout)
            self.assertNotIn("helper:", result.stdout)
            self.assertNotIn("bandwidth-policy-failed", result.stderr)

    def test_the_production_call_site_uses_the_installed_helper_path(self):
        text = hub_block()
        self.assertIn('FREE_BANDWIDTH_HELPER = "/usr/local/sbin/wins-free-bandwidth"', text)
        self.assertIn("free_bandwidth_host_before(tier, address, peer_pub)", text)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        spec = importlib.util.spec_from_file_location("freecap_policy", ROOT / "server/free_bandwidth_policy.py")
        self.policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.policy)
        self.policy.STATE = pathlib.Path(self.tmp.name) / "state"
        self.policy.RATE_PATH = pathlib.Path(self.tmp.name) / "rate"
        self.policy.RATE_PATH.write_text("100\n")
        self.filters = {"ingress": [], "egress": []}
        self.writes = []
        self.next_index = 1
        self.qdiscs = [{"kind": "fq"}]
        self.policy.tc = self.tc
        read = pathlib.Path.read_text
        def read_text(path, *args, **kwargs):
            if str(path) == "/sys/class/net/awg0/ifindex":
                return "7"
            return read(path, *args, **kwargs)
        patcher = patch.object(pathlib.Path, "read_text", read_text)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tc(self, *args):
        if args[:3] == ("-j", "qdisc", "show"):
            return json.dumps(self.qdiscs)
        if args[:3] == ("-j", "filter", "show"):
            return json.dumps(self.filters[args[5]])
        self.writes.append(args)
        if args[:2] == ("qdisc", "add"):
            self.qdiscs.append({"kind": "clsact"})
        elif args[:2] == ("filter", "replace"):
            direction = args[4]
            handle = int(args[args.index("handle")+1], 0)
            field = "src_ip" if direction == "ingress" else "dst_ip"
            address = args[args.index(field)+1]
            index = self.next_index
            self.next_index += 1
            self.filters[direction] = [entry for entry in self.filters[direction]
                                       if entry["options"]["handle"] != handle]
            self.filters[direction].append({"options": {"handle": handle, "keys": {field: address},
                "actions": [{"kind": "police", "index": index}]}})
        elif args[:2] == ("filter", "delete"):
            handle = int(args[args.index("handle")+1], 0)
            self.filters[args[4]] = [entry for entry in self.filters[args[4]]
                                    if entry["options"]["handle"] != handle]
        return ""

    def test_free_both_directions_and_reconnect_preserve_policers(self):
        self.policy.apply("awg0", "10.8.2.2", "free")
        replacements = [item for item in self.writes if item[:2] == ("filter", "replace")]
        self.assertEqual(len(replacements), 2)
        for item in replacements:
            self.assertIn("100mbit", item)
            # 100 ms of the 100 Mbit/s rate: the same burst rule as the v3
            # gateway's freeBandwidthBurstBytes.
            self.assertIn("1250000", item)
            self.assertIn("drop/ok", item)
            self.assertNotIn("root", item)
        for item in replacements:
            self.assertNotIn("index", item, "action index was reused across interfaces")
        ingress = self.filters["ingress"][0]["options"]["actions"][0]["index"]
        egress = self.filters["egress"][0]["options"]["actions"][0]["index"]
        self.assertNotEqual(ingress, egress)
        self.writes.clear()
        self.policy.apply("awg0", "10.8.2.2", "free")
        self.assertEqual(self.writes, [], "reconnect reset a kernel bucket")

    def test_two_free_addresses_have_distinct_directional_actions(self):
        for address in ["10.8.2.2", "10.8.2.3"]:
            self.policy.apply("awg0", address, "free")
        indices = [entry["options"]["actions"][0]["index"]
                   for filters in self.filters.values() for entry in filters]
        self.assertEqual(len(set(indices)), 4)
        self.writes.clear()
        self.policy.apply("awg0", "10.8.2.2", "free")
        self.assertEqual(self.writes, [], "another address reset the first peer's budget")

    def test_paid_promotion_removes_both_owned_filters(self):
        self.policy.apply("awg0", "10.8.2.2", "free")
        self.writes.clear()
        self.policy.apply("awg0", "10.8.2.2", "premium")
        self.assertEqual(len(self.writes), 2)
        self.assertTrue(all(item[:2] == ("filter", "delete") for item in self.writes))
        self.assertFalse(list(self.policy.STATE.iterdir()))

    def test_zero_disables_and_forged_tier_refuses(self):
        self.policy.RATE_PATH.write_text("0\n")
        self.policy.apply("awg0", "10.8.2.2", "free")
        self.assertEqual(self.writes, [])
        for tier in ["paid", "", "premium; true"]:
            with self.assertRaises(ValueError):
                self.policy.apply("awg0", "10.8.2.2", tier)

    def test_partial_failure_does_not_record_success(self):
        normal = self.policy.tc
        def fail(*args):
            if args[:2] == ("filter", "replace") and args[4] == "egress":
                raise subprocess.CalledProcessError(1, "tc")
            return normal(*args)
        self.policy.tc = fail
        with self.assertRaises(subprocess.CalledProcessError):
            self.policy.apply("awg0", "10.8.2.2", "free")
        self.assertFalse(list(self.policy.STATE.iterdir()))

    def test_each_installer_embeds_the_exact_policy(self):
        source = (ROOT / "server/free_bandwidth_policy.py").read_text()
        for installer in INSTALLERS:
            bodies = [item.body for item in parse_heredocs(installer) if "<<'FREECAP_PY'" in item.header]
            self.assertEqual(bodies, [source])
            self.assertIn("install_free_bandwidth_policy || return 1", installer.read_text())

    def test_installers_validate_the_rate_before_emission(self):
        for installer in INSTALLERS:
            text = installer.read_text()
            function = re.search(r"^validate_free_bandwidth_rate\(\) \{.*?^\}", text, re.M | re.S).group()
            for rate, expected in [("100", 0), ("0", 0), ("100000", 0),
                                   ("-1", 1), ("100001", 1), ("001", 1), ("100; true", 1)]:
                script = function + '\nWINS_FREE_MBIT="$1"\nvalidate_free_bandwidth_rate\n'
                result = subprocess.run(["bash", "-c", script, "freecap-test", rate],
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected, (installer.name, rate))
            if "data_plane" in installer.name:
                # The gateway reads WINN3_GATEWAY_FREE_MBIT, so the installer
                # refuses a bad value there too, not only in WINS_FREE_MBIT.
                for value, expected in [("50", 0), ("0", 0), ("100001", 1), ("abc", 1), ("", 0)]:
                    script = function + '\nWINS_FREE_MBIT=100\nWINN3_GATEWAY_FREE_MBIT="$1"\nvalidate_free_bandwidth_rate\n'
                    result = subprocess.run(["bash", "-c", script, "freecap-test", value],
                                            capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, expected, ("gateway", value))
                for name in ["validate_config", "emit_env_text", "emit_unit_text"]:
                    body = re.search(r"^" + name + r"\(\) \{.*?^\}", text, re.M | re.S).group()
                    self.assertIn("validate_free_bandwidth_rate ||", body)
                env = re.search(r"^emit_env_text\(\) \{.*?^\}", text, re.M | re.S).group()
                self.assertIn("WINN3_GATEWAY_FREE_MBIT=${WINN3_GATEWAY_FREE_MBIT}", env)

    def test_gateway_block_preserves_exact_cap_generation(self):
        source = (ROOT / gateway_block.SOURCE).read_text()
        installer = INSTALLERS[0].read_text()
        self.assertEqual(gateway_block.check(source, installer), [])
        for fragment in ["  validate_free_bandwidth_rate || bad=1",
                         "WINN3_GATEWAY_FREE_MBIT=${WINN3_GATEWAY_FREE_MBIT}",
                         'WINN3_GATEWAY_FREE_MBIT="${WINN3_GATEWAY_FREE_MBIT:-${WINS_FREE_MBIT:-100}}"',
                         "      WINN3_GATEWAY_TCP_INGRESS WINN3_GATEWAY_FREE_MBIT \\",
                         "      WINN3_GATEWAY_FREE_MBIT|\\"]:
            self.assertTrue(gateway_block.check(source, installer.replace(fragment, "", 1)))

    def test_all_emitted_gateway_keys_pass_the_closed_firewall_parser(self):
        text = INSTALLERS[0].read_text()
        emit = re.search(r"^emit_env_text\(\) \{.*?^\}", text, re.M | re.S).group()
        names = re.findall(r"^([A-Z][A-Z0-9_]*)=", emit, re.M)
        parser = re.search(r'    case "\$\{line_name\}" in\n.*?    esac', text, re.S).group()
        self.assertIn("WINN3_GATEWAY_FREE_MBIT", names)
        self.assertGreater(len(names), 15)
        for name in names + ["PATH", "LD_PRELOAD", "WINN3_UNKNOWN"]:
            result = subprocess.run(["bash", "-c", 'line_name="$1"\n' + parser,
                                     "freecap-firewall-test", name], capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0 if name in names else 1, name)

    def test_register_report_names_the_binary_feature_probe_result(self):
        register = next(item.body for item in parse_heredocs(INSTALLERS[0])
                        if item.header.strip() == "cat > /usr/local/bin/wins-node-register <<'EOF'")
        function = re.search(r"^winn3_gateway_peer_tier_value\(\) \{.*?^\}", register, re.M | re.S).group()
        binary = pathlib.Path(self.tmp.name) / "winn3-gateway"
        cases = [("#!/bin/sh\necho peer-registry-tier\n", "true"),
                 ("#!/bin/sh\necho something-else\n", "false"),
                 ("#!/bin/sh\necho 'use keygen' >&2\nexit 1\n", "null")]
        for body, expected in cases:
            binary.write_text(body)
            binary.chmod(0o755)
            script = ("timeout() { shift 3; \"$@\"; }\n" + function +
                      '\nwinn3_gateway_peer_tier_value "path=$1 ; argv[]=$1 -mode serve"\n')
            result = subprocess.run(["bash", "-c", script, "peer-tier-test", str(binary)],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.stdout, expected, (body, result.stderr))
        binary.unlink()
        script = function + '\nwinn3_gateway_peer_tier_value "path=/nonexistent/winn3-gateway ; argv[]="\n'
        result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=10)
        self.assertIn(result.stdout, ("null", "true", "false"))

    def test_the_off_node_check_digest_matches_both_pins_and_accepts_the_tier_word(self):
        import hashlib
        dp_text = INSTALLERS[0].read_text()
        hub_text = HUB.read_text()
        program = subprocess.run(
            ["bash", "-c", 'source <(sed -n "/^winn3_offnode_check_program() {/,/^}/p" "$1"); winn3_offnode_check_program',
             "offnode", str(INSTALLERS[0])], capture_output=True, timeout=10).stdout
        digest = hashlib.sha256(program).hexdigest()
        self.assertIn("WINN3_OFFNODE_CHECK_SHA256=" + digest, dp_text)
        self.assertIn('HUB_OFFNODE_CHECK_SHA256 = "' + digest + '"', hub_text)
        text = program.decode()
        self.assertIn('set(p) - {"static_public", "inner_v4", "not_after", "tier"}', text)
        self.assertIn('if "tier" in p and p["tier"] not in ("free", "premium"):', text)
        self.assertIn('doc.get("version") != 1', text)

    def test_extracted_gateway_keeps_rate_validation(self):
        text = gateway_block.sourceable(INSTALLERS[0].read_text())
        for rate, expected in [("100", 0), ("100001", 1)]:
            script = text + '\nWINS_FREE_MBIT="$1"\nvalidate_free_bandwidth_rate\n'
            result = subprocess.run(["bash", "-c", script, "freecap-extract-test", rate],
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, expected)

    def test_core_policy_precedes_peer_and_failure_removes_existing_peer(self):
        text = INSTALLERS[1].read_text()
        function = re.search(r"^sync_assignment\(\) \{.*?^\}", text, re.M | re.S).group()
        self.assertEqual(function.count("/usr/local/sbin/wins-free-bandwidth"), 1)
        function = function.replace("/usr/local/sbin/wins-free-bandwidth", "freecap_stub")
        # sync_assignment validates keys and endpoints before any mutation
        # (audit core F-1): load the installer's own validators and use a
        # well-formed key so the policy ordering below is still exercised.
        validators = "\n".join(
            re.search(r"^%s\(\) \{.*?^\}" % name, text, re.M | re.S).group()
            for name in ("valid_awg_key", "valid_awg_endpoint"))
        fixture_key = "A" * 43 + "="
        stubs = '''
CORE_INGRESS_IFACE=awg-test
jq() {
  case "$2" in
    '.client_public_key // empty') printf '%s' "$FREECAP_TEST_KEY" ;;
    '.client_ip // empty') printf '10.9.1.2' ;;
    '.table_id // empty') printf '52001' ;;
    '.traffic_tier // empty') printf '%s' "$FREECAP_TEST_TIER" ;;
  esac
}
ensure_exit_iface() { return 0; }
warn() { printf 'warn:%s\\n' "$*"; }
freecap_stub() { printf 'policy:%s\\n' "$*"; return "$FREECAP_TEST_RC"; }
docker() { printf 'docker:%s\\n' "$*"; return 0; }
ip() { [[ "$1 $2" != 'rule del' ]]; }
'''
        for tier, policy_rc in [("free", 0), ("premium", 0), ("free", 1), ("premium", 1), ("", 0)]:
            script = (stubs + validators + '\n' + function + '\nFREECAP_TEST_KEY="' + fixture_key + '"\nFREECAP_TEST_TIER="$1"\n'
                      'FREECAP_TEST_RC="$2"\nsync_assignment "{}"\n')
            result = subprocess.run(["bash", "-c", script, "freecap-core-test", tier, str(policy_rc)],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, policy_rc, result.stderr)
            lines = result.stdout.splitlines()
            # A tier the hub did not name (an older hub) is the premium behaviour.
            self.assertEqual(lines[0], "policy:awg-test 10.9.1.2 " + (tier or "premium"))
            if policy_rc:
                self.assertTrue(any(line.endswith(fixture_key + " remove") for line in lines))
                self.assertFalse(any("allowed-ips" in line for line in lines))
            else:
                self.assertTrue(any("allowed-ips 10.9.1.2/32" in line for line in lines))



class DoubleVpnIsPaidOnly(unittest.TestCase):
    """Owner ruling 2026-10-13: Double VPN is for paid accounts only."""

    def test_a_fresh_hub_seeds_free_double_vpn_off(self):
        text = HUB.read_text(encoding="utf-8")
        self.assertIn("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('double_vpn_free_access_enabled', 'false');", text)
        self.assertNotIn("VALUES ('double_vpn_free_access_enabled', 'true')", text)
        self.assertIn('DOUBLE_VPN_FREE_ACCESS_ENABLED_DEFAULT="${DOUBLE_VPN_FREE_ACCESS_ENABLED:-0}"', text)

    def test_an_existing_hub_holding_the_released_true_row_is_flipped_once(self):
        # INSERT OR IGNORE never overrides a row the release already seeded as 'true'.
        text = hub_block()
        self.assertIn('if get_setting(conn, "double_vpn_free_paid_only_applied", "false") != "true":', text)
        self.assertIn('set_setting(conn, "double_vpn_free_access_enabled", "false")', text)
        self.assertIn('set_setting(conn, "double_vpn_free_paid_only_applied", "true")', text)

    def test_admin_menu_item_20_defaults_to_no_and_needs_an_explicit_yes(self):
        # Enter used to mean yes, which turned free Double VPN on against the ruling.
        admin = next(item.body for item in parse_heredocs(HUB)
                     if item.header.strip() == "cat > /usr/local/bin/wins-admin <<'PYEOF'")
        node = next(item for item in ast.parse(admin).body
                    if isinstance(item, ast.FunctionDef) and item.name == "set_double_vpn_free_access")
        self.assertIn("'20': set_double_vpn_free_access,", admin)
        code = compile(ast.Module(body=[node], type_ignores=[]), str(HUB), "exec")
        # Only y or yes (any case, surrounding spaces ignored) is a yes. A menu
        # number such as 1 or 20 typed at this prompt, or true/on, stays false.
        cases = [("", "false"), ("   ", "false"), ("n", "false"), ("no", "false"), ("N", "false"),
                 ("maybe", "false"), ("yess", "false"), ("yeah", "false"), ("0", "false"),
                 ("off", "false"), ("1", "false"), ("20", "false"), ("true", "false"), ("on", "false"),
                 ("y", "true"), ("Y", "true"), (" yes ", "true"), ("YES", "true")]
        for answer, expected in cases:
            prompts, posted = [], []
            namespace = {"input": lambda prompt, answer=answer: prompts.append(prompt) or answer,
                         "post_form": lambda path, data: posted.append((path, data))}
            exec(code, namespace)
            namespace["set_double_vpn_free_access"]()
            self.assertEqual(posted, [("/admin/double-vpn/free-access", {"enabled": expected})], repr(answer))
            self.assertEqual(len(prompts), 1, repr(answer))
            self.assertTrue(prompts[0].endswith("[y/N]: "), prompts[0])


if __name__ == "__main__":
    unittest.main()
