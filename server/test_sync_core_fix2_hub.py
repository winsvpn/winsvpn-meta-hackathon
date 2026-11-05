#!/usr/bin/env python3
"""IA-SYNC fix wave 2, lane sync_core: hub-side regressions.

SYNC-02: AmneziaWG obfuscation parameters across the Double VPN chain. The
client's first hop is the Core's core0, its second is corexN to the exit's
awg0; neither is negotiated. The hub must hand the client core0's profile and
hand the Core the exit's profile, and the Core's rendered corexN must carry it.
SYNC-18: one node self-resync pass per node at a time.

Runs the generated hub against real SQLite with the shared harness stubs. No
network, no SSH: node pushes and the Core's acknowledgement are fakes.
"""
import _toolchain  # noqa: F401
import asyncio
from contextlib import closing
import json
import logging
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving


CORE_INSTALLER = Path(__file__).resolve().parent / "wins_core_server_setup_ONETOUCH.sh"
CORE_TOKEN = "test-core-token-with-enough-entropy"
EXIT_PROFILE = {
    "Jc": 5, "Jmin": 40, "Jmax": 70, "S1": 37, "S2": 91, "S3": 16, "S4": 0,
    "H1": 1034567891, "H2": "2000000000-2000000999", "H3": 3100000000, "H4": 4200000000,
}
CORE_PROFILE = {
    "Jc": 3, "Jmin": 12, "Jmax": 33, "S1": 21, "S2": 64, "S3": 16, "S4": 0,
    "H1": 555000111, "H2": 666000222, "H3": 777000333, "H4": 888000444,
}


def _served_obfuscation(result):
    found = []

    def walk(value):
        if isinstance(value, dict):
            if isinstance(value.get("obfuscation"), dict):
                found.append(value["obfuscation"])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(result)
    if not found:
        raise AssertionError("no obfuscation block in the served config")
    return found[0]


class DoubleVpnObfuscationTests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0", DOUBLE_VPN_ENABLED="1")
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.mod.sync_peer_to_node = lambda *args, **kwargs: True
        self.tokens = harness.seed_account(self.mod, devices=1)
        serving.seed_node(self.mod, slug="test-node", obfuscation=EXIT_PROFILE)
        with self.mod.get_db() as conn:
            self.secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)

    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def seed_core(self, obfuscation_json):
        with self.db() as conn, conn:
            self.mod.ensure_schema(conn)
            columns = {row[1] for row in conn.execute("PRAGMA table_info(core_servers)")}
            if "obfuscation_json" not in columns:
                # Lets the snapshot hub reach the assertions instead of a
                # schema error; the fixed hub adds this column itself.
                conn.execute("ALTER TABLE core_servers ADD COLUMN obfuscation_json TEXT")
            conn.execute(
                "INSERT OR REPLACE INTO core_servers (core_id, name, region, ingress_endpoint,"
                " tunnel_gateway_ipv4, stealth_endpoint, ingress_public_key, exit_public_key,"
                " xray_uuid, status, runtime_ready, promoted, active_promotion_id, obfuscation_json)"
                " VALUES (?, 'Core', 'Test', 'core.example.test:9210', '10.9.1.1',"
                " 'core.example.test:80', ?, ?, '11111111-2222-4333-8444-666666666666',"
                " 'online', 1, 1, 'p1', ?)",
                (self.mod.DOUBLE_VPN_CORE_ID, "I" * 43 + "=", "D" * 43 + "=", obfuscation_json),
            )

    def core_row(self):
        with self.db() as conn:
            return conn.execute("SELECT * FROM core_servers WHERE core_id = ?",
                                (self.mod.DOUBLE_VPN_CORE_ID,)).fetchone()

    def admission(self):
        request = harness.FakeRequest(path="/verify", headers={
            "content-type": "application/json", "x-wins-activation": self.secret})
        login = serving.build_login(
            self.mod, device_id="sync-core-device", device_fingerprint="sync-core-fingerprint",
            device_model="audit-harness", location="test-node", double_vpn=True,
            selection_generation="a" * 32, ordinary_v3_failure_generation="a" * 32)
        core = self.core_row()
        with patch.object(self.mod, "select_double_vpn_core", return_value=core), \
                patch.object(self.mod, "_wait_for_core_assignment_ready_sync", return_value=True):
            return asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))

    def payloads(self):
        with self.db() as conn:
            return self.mod.active_core_assignment_payloads(conn, self.mod.DOUBLE_VPN_CORE_ID)

    def test_double_vpn_client_is_handed_core0_profile_not_the_exit_profile(self):
        self.seed_core(json.dumps(CORE_PROFILE))
        served = _served_obfuscation(self.admission())
        self.assertEqual(served, CORE_PROFILE)

    def test_core_without_a_reported_profile_withholds_double_vpn(self):
        # Round 2 (OI-SYNC_CORE-2): no report, no proof of what core0 runs, so
        # nothing is guessed, whether the exit is strong or default.
        for exit_profile in (EXIT_PROFILE, serving.GOOD_OBFUSCATION):
            with self.subTest(exit_default=exit_profile is serving.GOOD_OBFUSCATION):
                serving.seed_node(self.mod, slug="test-node", obfuscation=exit_profile)
                self.seed_core(None)
                with self.mod.get_db() as conn:
                    self.secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
                with self.assertRaises(harness.HTTPException) as error:
                    self.admission()
                self.assertEqual(error.exception.status_code, 503)
                self.assertIn("has not reported its obfuscation profile", error.exception.detail)

    def test_core_reporting_the_default_profile_is_served_the_default(self):
        self.seed_core(json.dumps(serving.GOOD_OBFUSCATION))
        served = _served_obfuscation(self.admission())
        self.assertEqual(served, serving.GOOD_OBFUSCATION)

    def test_unusable_core_profile_refuses_double_vpn(self):
        self.seed_core(json.dumps({"Jc": 2}))
        with self.assertRaises(harness.HTTPException) as error:
            self.admission()
        self.assertEqual(error.exception.status_code, 503)
        self.assertIn("obfuscation", error.exception.detail)

    def test_assignment_carries_exit_profile_and_revision_tracks_it(self):
        self.seed_core(json.dumps(CORE_PROFILE))
        self.admission()
        first = self.payloads()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["exit_obfuscation"],
                         self.mod.parse_obfuscation(json.dumps(EXIT_PROFILE)))
        self.assertIn("exit_obfuscation", self.mod.CORE_ASSIGNMENT_REVISION_FIELDS)
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET obfuscation_json = ? WHERE slug = 'test-node'",
                         (json.dumps(dict(EXIT_PROFILE, H1=424242)),))
        second = self.payloads()
        self.assertEqual(second[0]["exit_obfuscation"]["H1"], 424242)
        self.assertNotEqual(first[0]["assignment_revision"], second[0]["assignment_revision"])

    def test_unusable_exit_profile_withholds_the_assignment(self):
        self.seed_core(json.dumps(CORE_PROFILE))
        self.admission()
        self.assertEqual(len(self.payloads()), 1)
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET obfuscation_json = '{\"Jc\": 2}' WHERE slug = 'test-node'")
        self.assertEqual(self.payloads(), [])

    def test_core_renders_the_hub_assignment_into_corex(self):
        """Contract: the hub's real assignment JSON drives the Core's real renderer."""
        self.seed_core(json.dumps(CORE_PROFILE))
        self.admission()
        item = self.payloads()[0]
        text = CORE_INSTALLER.read_text(encoding="utf-8")
        start = text.index("cat > \"${sync_tmp}\" <<'EOF'\n")
        agent = text[start:text.index("\nEOF\n", start + 1)]

        def function(name):
            match = re.search(rf"(?m)^{name}\(\) [{{(]\n", agent)
            end = re.compile(r"(?m)^[})]\n").search(agent, match.end())
            return agent[match.start():end.end()]

        bash = shutil.which("bash")
        tmp = Path(tempfile.mkdtemp(prefix="synccore-contract-"))
        try:
            script = "\n".join([
                "set -Eeuo pipefail", "declare -A ENSURED_EXIT_IFACES=()",
                "warn() { printf '%s\\n' \"$*\" >&2; }", "log() { :; }",
                "docker() { [[ \"$1\" == ps ]] && printf '%s\\n' \"wins-core-exit-${ITEM_IFACE}\"; return 0; }",
                "ip() { return 0; }", "select_awg_image() { printf image; }",
                f"CORE_SYNC_STATE_DIR='{tmp}'", "CORE_EXIT_IFACE_PREFIX=corex CORE_EXIT_TRANSPORT_MODE=direct",
                "CORE_EXIT_DIRECT_GRACE_SECONDS=20 CORE_EXIT_XRAY_LOCAL_PORT_BASE=43000 CORE_AWG_MTU=1280",
                "CORE_EXIT_PRIVATE_KEY=k AWG_JC=2 AWG_JMIN=10 AWG_JMAX=30 AWG_S1=16 AWG_S2=80 AWG_S3=16",
                "AWG_S4=0 AWG_H1=11 AWG_H2=22 AWG_H3=33 AWG_H4=44",
                *(function(name) for name in ("valid_iface_name", "write_exit_transport_state",
                                              "remove_exit_container_if_present",
                                              "valid_awg_obfuscation_value", "ensure_exit_iface")),
                'ITEM_IFACE="$(jq -r .iface <<<"$1")"', 'ensure_exit_iface "$1"',
            ])
            result = subprocess.run([bash, "-c", script, "contract", json.dumps(item)],
                                    text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            conf = (tmp / f"{item['iface']}.conf").read_text(encoding="utf-8").split("[Peer]")[0]
            rendered = dict(re.findall(r"(?m)^(Jc|Jmin|Jmax|S[1-4]|H[1-4]) = (\S+)$", conf))
            self.assertEqual(rendered, {k: str(v) for k, v in EXIT_PROFILE.items()})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class CoreRegistrationProfileTests(unittest.TestCase):
    def setUp(self):
        self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0", DOUBLE_VPN_ENABLED="1")
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.logger.propagate = False
        with closing(sqlite3.connect(self.mod._DB)) as conn, conn:
            conn.row_factory = sqlite3.Row
            self.mod.ensure_schema(conn)
            conn.execute("INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
                         (self.mod.DOUBLE_VPN_CORE_ID, self.mod.token_digest(CORE_TOKEN)))

    def tearDown(self):
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)

    def register(self, **extra):
        payload = self.mod.CoreRegistration(
            core_id=self.mod.DOUBLE_VPN_CORE_ID, name="Core", region="Test",
            management_host="core-management.test", management_user="ubuntu",
            ingress_endpoint="core.test:9210", tunnel_gateway_ipv4="10.255.0.1",
            ingress_public_key="ingress-key", exit_public_key="exit-key",
            stealth_endpoint="core.test:80", xray_uuid="u", xray_path="/wins-core-tunnel",
            xray_security="none", stealth_transports=[], regional_aliases=["core.test"],
            direct_awg_enabled=True, status="online", runtime_ready=False,
            applied_assignment_revisions=[], **extra)
        return self.mod.register_core(payload, harness.FakeRequest(path="/api/v1/core/register"),
                                      x_core_token=CORE_TOKEN)

    def stored(self):
        with closing(sqlite3.connect(self.mod._DB)) as conn:
            return conn.execute("SELECT obfuscation_json FROM core_servers WHERE core_id = ?",
                                (self.mod.DOUBLE_VPN_CORE_ID,)).fetchone()[0]

    def test_reported_profile_is_stored_canonically(self):
        # The Core agent sends every value as a string, exactly as awk read it.
        sent = {k: str(v) for k, v in EXIT_PROFILE.items()}
        self.register(obfuscation_json=json.dumps(sent))
        self.assertEqual(json.loads(self.stored()), self.mod.parse_obfuscation(json.dumps(EXIT_PROFILE)))

    def test_unusable_profile_is_refused_at_intake(self):
        for bad in ('{"Jc": 2}', "not-json", json.dumps(dict(CORE_PROFILE, S1="1-2"))):
            with self.subTest(bad=bad), self.assertRaises(harness.HTTPException) as error:
                self.register(obfuscation_json=bad)
            self.assertEqual(error.exception.status_code, 400)
        self.assertIsNone(self.stored())

    def test_older_core_without_profile_is_recorded_as_not_reported(self):
        self.register(obfuscation_json=json.dumps(CORE_PROFILE))
        self.register()
        self.assertIsNone(self.stored())


class NodeSelfResyncExclusionTests(unittest.TestCase):
    """SYNC-18: one pass per target, bounded join, and reuse of a finished pass."""

    def setUp(self):
        self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.logger.propagate = False
        self.mod.require_node_token = lambda *args, **kwargs: None
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.running = {}
        self.total_running = 0
        self.peak_total = 0
        self.calls = []
        self.fail_slugs = set()
        self.mod.PEER_RESYNC_JOIN_WAIT_SECONDS = 5.0

    def tearDown(self):
        self.release.set()
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)

    def slow_pass(self, node_slug=""):
        with self.lock:
            self.calls.append(node_slug)
            self.running[node_slug] = self.running.get(node_slug, 0) + 1
            self.total_running += 1
            self.peak_total = max(self.peak_total, self.total_running)
        try:
            self.release.wait(10)
            if node_slug == "boom":
                raise RuntimeError("pass failed")
            failed = 1 if node_slug in self.fail_slugs else 0
            return {"ok": failed == 0, "failed": failed, "node_slug": node_slug}
        finally:
            with self.lock:
                self.running[node_slug] -= 1
                self.total_running -= 1

    def request(self, slug, identity=None, fresh=None):
        request = harness.FakeRequest(path=f"/api/v1/nodes/{slug}/resync-peers")
        if identity is not None:
            request.query_params["runtime_identity"] = identity
        if fresh is not None:
            request.query_params["fresh"] = fresh
        return request

    def call(self, slug, results, identity=None, fresh=None):
        try:
            results.append(self.mod.node_resync_own_peers(
                slug, self.request(slug, identity, fresh), x_node_token="t"))
        except (harness.HTTPException, RuntimeError) as exc:
            results.append(exc)

    def call_fleet(self, results):
        try:
            results.append(self.mod.resync_active_peers_to_node_exclusive(""))
        except (self.mod.PeerResyncBusy, RuntimeError) as exc:
            results.append(exc)

    def call_node_direct(self, slug, results):
        # The exclusion itself, without the route's schema work in front of it,
        # so a pass that wrongly starts is seen well inside the window.
        try:
            results.append(self.mod.resync_active_peers_to_node_exclusive(slug, None))
        except (self.mod.PeerResyncBusy, RuntimeError) as exc:
            results.append(exc)

    def enters_within(self, slug, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.running.get(slug, 0):
                return True
            time.sleep(0.01)
        return False

    def wait_running(self, slug):
        deadline = time.monotonic() + 5
        while self.running.get(slug, 0) == 0 and time.monotonic() < deadline:
            time.sleep(0.01)

    def start(self, target, *args):
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread

    def test_second_caller_gets_409_only_after_its_bounded_wait(self):
        self.mod.PEER_RESYNC_JOIN_WAIT_SECONDS = 0.2
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            first = []
            thread = self.start(self.call, "node-a", first)
            self.wait_running("node-a")
            started = time.monotonic()
            second = []
            self.call("node-a", second)
            waited = time.monotonic() - started
            self.release.set()
            thread.join(10)
        self.assertIsInstance(second[0], harness.HTTPException)
        self.assertEqual(second[0].status_code, 409)
        self.assertGreaterEqual(waited, 0.18)
        self.assertEqual(first[0]["ok"], True)
        self.assertEqual(self.peak_total, 1)

    def test_second_caller_waits_for_the_running_pass_instead_of_409(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            first, second = [], []
            t1 = self.start(self.call, "node-a", first)
            self.wait_running("node-a")
            t2 = self.start(self.call, "node-a", second)
            time.sleep(0.2)
            self.release.set()
            t1.join(10)
            t2.join(10)
        self.assertEqual(first[0]["ok"], True)
        self.assertEqual(second[0]["ok"], True)
        self.assertEqual(self.peak_total, 1)

    def test_fleet_and_node_passes_exclude_each_other(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            fleet, node = [], []
            tf = self.start(self.call_fleet, fleet)
            self.wait_running("")
            tn = self.start(self.call_node_direct, "node-a", node)
            self.assertFalse(self.enters_within("node-a", 1.0))
            self.release.set()
            tf.join(10)
            tn.join(10)
            self.release.clear()
            node2, fleet2 = [], []
            tn2 = self.start(self.call, "node-b", node2)
            self.wait_running("node-b")
            tf2 = self.start(self.call_fleet, fleet2)
            self.assertFalse(self.enters_within("", 1.0))
            self.release.set()
            tn2.join(10)
            tf2.join(10)
        self.assertEqual(self.peak_total, 1)
        for result in (fleet, node, node2, fleet2):
            self.assertEqual(result[0]["ok"], True)

    def test_other_nodes_are_not_blocked(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            a, b = [], []
            ta = self.start(self.call, "node-a", a)
            self.wait_running("node-a")
            tb = self.start(self.call, "node-b", b)
            self.wait_running("node-b")
            self.assertEqual(self.running.get("node-b"), 1)
            self.release.set()
            ta.join(10)
            tb.join(10)
        self.assertEqual((a[0]["ok"], b[0]["ok"]), (True, True))

    def test_a_failed_pass_releases_the_lock(self):
        self.release.set()
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            failed, after = [], []
            self.call("boom", failed)
            self.call("boom", after)
        self.assertIsInstance(failed[0], RuntimeError)
        self.assertIsInstance(after[0], RuntimeError)

    def test_finished_pass_is_reused_for_the_same_runtime_only(self):
        self.release.set()
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            results = []
            self.call("node-a", results, "amnezia-awg2:2026-09-30T01:00:00.1Z")
            self.call("node-a", results, "amnezia-awg2:2026-09-30T01:00:00.1Z")
            self.assertEqual(self.calls, ["node-a"])
            self.assertTrue(results[1]["reused_completed_pass"])
            self.assertEqual(results[1]["ok"], True)
            self.call("node-a", results, "amnezia-awg2:2026-09-30T02:00:00.1Z")
            self.call("node-a", results)
            self.assertEqual(self.calls, ["node-a"] * 3)
            self.mod.PEER_RESYNC_REUSE_SECONDS = 0.0
            self.call("node-a", results, "amnezia-awg2:2026-09-30T02:00:00.1Z")
            self.assertEqual(len(self.calls), 4)

    def test_a_pass_with_failures_is_never_reused(self):
        self.release.set()
        self.fail_slugs.add("node-a")
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            results = []
            self.call("node-a", results, "awg:1")
            self.call("node-a", results, "awg:1")
        self.assertEqual(self.calls, ["node-a", "node-a"])
        self.assertNotIn("reused_completed_pass", results[1])

    def test_a_failed_pass_evicts_the_remembered_result(self):
        """Sol N-4: newer contrary evidence wins over a remembered success."""
        self.release.set()
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            results = []
            self.call("node-a", results, "awg:1")
            self.fail_slugs.add("node-a")
            admin = self.mod.resync_active_peers_to_node_exclusive("node-a")
            self.assertEqual(admin["failed"], 1)
            self.fail_slugs.discard("node-a")
            self.call("node-a", results, "awg:1")
            self.assertEqual(self.calls, ["node-a"] * 3)
            self.assertNotIn("reused_completed_pass", results[1])
            # A failed fleet pass evicts every node's remembered result.
            self.call("node-b", results, "awg:2")
            self.fail_slugs.add("")
            self.mod.resync_active_peers_to_node_exclusive("")
            self.fail_slugs.discard("")
            self.call("node-b", results, "awg:2")
            self.assertEqual(self.calls[-3:], ["node-b", "", "node-b"])
            self.assertNotIn("reused_completed_pass", results[-1])
            # A pass that raises evicts too.
            self.call("node-c", results, "awg:3")
            with patch.object(self.mod, "resync_active_peers_to_node", side_effect=RuntimeError("ssh")):
                with self.assertRaises(RuntimeError):
                    self.mod.resync_active_peers_to_node_exclusive("node-c")
            self.call("node-c", results, "awg:3")
            self.assertEqual(self.calls[-2:], ["node-c", "node-c"])

    def test_fresh_token_needs_a_pass_that_started_after_it(self):
        """Sol OI-6: the check after hardening cannot reuse a pass from before."""
        self.release.set()
        t1, t2 = "a" * 32, "b" * 32
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            results = []
            self.call("node-a", results, "awg:1")          # pre-hardening pass
            self.call("node-a", results, "awg:1", t1)      # post-hardening check
            self.assertEqual(self.calls, ["node-a", "node-a"])
            self.assertNotIn("reused_completed_pass", results[1])
            self.call("node-a", results, "awg:1", t1)      # same check, next attempt
            self.assertTrue(results[2]["reused_completed_pass"])
            self.call("node-a", results, "awg:1")          # the timer may still reuse
            self.assertTrue(results[3]["reused_completed_pass"])
            self.call("node-a", results, "awg:1", t2)      # a new check needs a new pass
            self.assertEqual(len(self.calls), 3)

    def test_fresh_caller_never_takes_a_pass_already_running(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            first, check = [], []
            t1 = self.start(self.call, "node-a", first, "awg:1")
            self.wait_running("node-a")
            t2 = self.start(self.call, "node-a", check, "awg:1", "c" * 32)
            time.sleep(0.2)
            self.release.set()
            t1.join(10)
            t2.join(10)
        self.assertEqual(self.calls, ["node-a", "node-a"])
        self.assertEqual(check[0]["ok"], True)
        self.assertNotIn("reused_completed_pass", check[0])
        self.assertEqual(self.peak_total, 1)

    def test_tokens_keep_their_own_floor_a_b_a(self):
        """Sol N-7: A, then B, then A again. A keeps its first-seen floor, so
        A's retry and B's retry both take B's pass: two passes, not four."""
        self.release.set()
        a, b = "a" * 32, "b" * 32
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            results = []
            self.call("node-a", results, "awg:1", a)
            self.call("node-a", results, "awg:1", b)
            self.call("node-a", results, "awg:1", a)
            self.call("node-a", results, "awg:1", b)
        self.assertEqual(self.calls, ["node-a", "node-a"])
        self.assertTrue(results[2]["reused_completed_pass"])
        self.assertTrue(results[3]["reused_completed_pass"])

    def test_two_checks_alternating_on_one_node_both_converge(self):
        """Sol SYNC-18 round 3, scaled 1:100: two checks for one runtime take
        turns, each attempt's request giving up after 100 s, with a 250 s pass
        and a 75 s hub wait. Both checks succeed within their 12 attempts."""
        scale = 0.01
        self.mod.PEER_RESYNC_JOIN_WAIT_SECONDS = 75 * scale
        identity = "amnezia-awg2:2026-09-30T04:00:00.5Z"

        def long_pass(node_slug=""):
            with self.lock:
                self.calls.append(node_slug)
                self.total_running += 1
                self.peak_total = max(self.peak_total, self.total_running)
            time.sleep(250 * scale)
            with self.lock:
                self.total_running -= 1
            return {"ok": True, "failed": 0, "node_slug": node_slug}

        def check_request(token):
            results = []
            thread = self.start(self.call, "node-a", results, identity, token)
            thread.join(100 * scale)
            return results[0] if results else None

        done = {"a" * 32: None, "b" * 32: None}
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=long_pass):
            for attempt in range(12):
                for token in done:
                    if done[token] is None:
                        outcome = check_request(token)
                        if isinstance(outcome, dict) and outcome.get("ok") is True:
                            done[token] = attempt + 1
                if all(done.values()):
                    break
                time.sleep(5 * scale)
            deadline = time.monotonic() + 5
            while self.total_running and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertTrue(all(done.values()), done)
        self.assertLessEqual(len(self.calls), 3)
        self.assertEqual(self.peak_total, 1)

    def test_fresh_tokens_are_bounded_per_node_and_expire(self):
        mod = self.mod
        for n in range(mod.PEER_RESYNC_FRESH_TOKENS_PER_NODE + 3):
            mod._peer_resync_fresh_floor("node-a", f"{n:032x}", 100.0 + n)
        tokens = mod._PEER_RESYNC_FRESH["node-a"]
        self.assertEqual(len(tokens), mod.PEER_RESYNC_FRESH_TOKENS_PER_NODE)
        # The oldest went first; the newest are kept with their own times.
        self.assertNotIn(f"{0:032x}", tokens)
        self.assertEqual(tokens[f"{10:032x}"], 110.0)
        # A dropped token that returns gets a new, later floor.
        self.assertEqual(mod._peer_resync_fresh_floor("node-a", f"{0:032x}", 200.0), 200.0)
        # Another node's tokens never touch this node's.
        mod._peer_resync_fresh_floor("node-b", "f" * 32, 201.0)
        self.assertEqual(tokens[f"{10:032x}"], 110.0)
        # Everything expires after the TTL.
        later = 201.0 + mod.PEER_RESYNC_FRESH_TOKEN_TTL_SECONDS + 1
        mod._peer_resync_fresh_floor("node-c", "c" * 32, later)
        self.assertEqual(set(mod._PEER_RESYNC_FRESH), {"node-c"})

    def test_malformed_fresh_token_is_refused(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            for bad in ("A" * 32, "abc", "g" * 32, "a" * 65):
                results = []
                self.call("node-a", results, None, bad)
                self.assertIsInstance(results[0], harness.HTTPException, bad)
                self.assertEqual(results[0].status_code, 400)
        self.assertEqual(self.calls, [])

    def test_waiters_are_capped_and_the_rest_get_409_at_once(self):
        """Sol OI-7: waiting callers never take more than the cap of threads."""
        self.mod.PEER_RESYNC_MAX_WAITERS = 3
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            fleet = []
            tf = self.start(self.call_fleet, fleet)
            self.wait_running("")
            outcomes = []
            threads = [self.start(self.call_node_direct, f"node-{n}", outcomes) for n in range(10)]
            deadline = time.monotonic() + 3
            while len(outcomes) < 7 and time.monotonic() < deadline:
                time.sleep(0.01)
            busy = [o for o in outcomes if isinstance(o, self.mod.PeerResyncBusy)]
            self.assertEqual(len(busy), 7)
            self.assertEqual(self.mod._PEER_RESYNC_WAITERS[0], 3)
            self.release.set()
            tf.join(10)
            for thread in threads:
                thread.join(10)
        self.assertEqual(sum(1 for o in outcomes if isinstance(o, dict) and o["ok"]), 3)
        self.assertEqual(self.mod._PEER_RESYNC_WAITERS[0], 0)

    def test_waiters_leave_the_shared_worker_pool_usable(self):
        """Sol OI-7, measured on AnyIO's real default limiter (40 tokens, the
        hub's pinned anyio 4.14.2): 40 node callers blocked behind a fleet pass
        leave room for an unrelated synchronous handler."""
        import anyio
        import anyio.to_thread
        self.mod.PEER_RESYNC_JOIN_WAIT_SECONDS = 3.0
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            fleet = []
            tf = self.start(self.call_fleet, fleet)
            self.wait_running("")
            probe = {}

            def blocked(n):
                try:
                    return self.mod.resync_active_peers_to_node_exclusive(f"node-{n}", None)
                except self.mod.PeerResyncBusy:
                    return "409"

            async def main():
                probe["tokens"] = anyio.to_thread.current_default_thread_limiter().total_tokens
                async with anyio.create_task_group() as group:
                    for n in range(40):
                        group.start_soon(anyio.to_thread.run_sync, blocked, n)
                    await anyio.sleep(0.3)
                    started = time.monotonic()
                    await anyio.to_thread.run_sync(lambda: None)
                    probe["latency"] = time.monotonic() - started
                    self.release.set()

            anyio.run(main)
            tf.join(10)
        self.assertEqual(probe["tokens"], 40)
        self.assertLess(probe["latency"], 0.5)

    def test_a_waiting_fleet_pass_is_not_starved_by_node_passes(self):
        """Seat C N-5: node passes that arrive while the fleet waits queue behind it."""
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            a, fleet, b = [], [], []
            ta = self.start(self.call_node_direct, "node-a", a)
            self.wait_running("node-a")
            tf = self.start(self.call_fleet, fleet)
            deadline = time.monotonic() + 3
            while self.mod._PEER_RESYNC_FLEET_WAITERS[0] == 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            tb = self.start(self.call_node_direct, "node-b", b)
            self.assertFalse(self.enters_within("node-b", 0.5))
            self.release.set()
            for thread in (ta, tf, tb):
                thread.join(10)
        self.assertEqual(self.calls, ["node-a", "", "node-b"])
        self.assertEqual(self.peak_total, 1)

    def test_malformed_runtime_identity_is_refused(self):
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=self.slow_pass):
            for bad in ("a b", "x" * 201, "id\n", "a/b", "a?b"):
                results = []
                self.call("node-a", results, bad)
                self.assertIsInstance(results[0], harness.HTTPException, bad)
                self.assertEqual(results[0].status_code, 400)
        self.assertEqual(self.calls, [])

    def test_install_check_converges_when_a_pass_outlasts_every_request(self):
        """Seat C N-1 and Sol OI-4, scaled 1:100: a 250 s pass, 90 s node
        requests, a 75 s hub join wait, verify_hub_node_management's 12
        attempts. One pass runs, the check passes, and the timer's next
        request gets the finished pass so the node can write its marker."""
        scale = 0.01
        self.mod.PEER_RESYNC_JOIN_WAIT_SECONDS = 75 * scale
        identity = "amnezia-awg2:2026-09-30T03:00:00.5Z"

        def long_pass(node_slug=""):
            with self.lock:
                self.calls.append(node_slug)
                self.total_running += 1
                self.peak_total = max(self.peak_total, self.total_running)
            time.sleep(250 * scale)
            with self.lock:
                self.total_running -= 1
            return {"ok": True, "failed": 0, "node_slug": node_slug}

        def node_request(timeout, fresh=None):
            # The node's curl gives up after `timeout`; the hub request goes on.
            results = []
            thread = self.start(self.call, "node-a", results, identity, fresh)
            thread.join(timeout)
            return results[0] if results else None

        token = "0123456789abcdef0123456789abcdef"
        with patch.object(self.mod, "resync_active_peers_to_node", side_effect=long_pass):
            outcome = None
            for attempt in range(12):
                node_request(90 * scale)                    # wins-node-register's own resync
                outcome = node_request(100 * scale, token)  # the check's request
                if isinstance(outcome, dict) and outcome.get("ok") is True:
                    break
                time.sleep(5 * scale)
            timer = node_request(90 * scale)
        self.assertIsInstance(outcome, dict, outcome)
        self.assertEqual(outcome["ok"], True)
        # Round 3: the register run's pass started before the check first
        # reached the hub, so the check needs one pass of its own.
        self.assertEqual(self.calls, ["node-a", "node-a"])
        self.assertEqual(self.peak_total, 1)
        self.assertEqual(timer["ok"], True)
        self.assertTrue(timer["reused_completed_pass"])


if __name__ == "__main__":
    unittest.main()
