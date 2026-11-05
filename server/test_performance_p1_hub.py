#!/usr/bin/env python3
"""Slice P1 (design 10.2, 5.5, 5.7): the hub side of the performance read-backs.

  * the register route stores a node's performance report, narrowed to known
    keys and shapes, overwrites it on every register, and never answers 422 for
    a malformed one (closed-vocabulary rule: an unknown drift reason is kept as
    one sentinel, never raised);
  * the contract audit flags drift from a CURRENT report only, at an emailed
    priority for a real drift and the log-only priority for a harness trial or
    an operator's queue override;
  * P-8: a node whose gateway is at 90 percent of -max-sessions is full for a
    new assignment. It is passed over while another node can take the client,
    used when every candidate is full, and a reconnect, an explicit choice, a
    stale report and a node that reports no forwarding gateway are unchanged.

Usage:  TZ=UTC python3 -m pytest -q -p no:cacheprovider server/test_performance_p1_hub.py
        TZ=UTC python3 server/test_performance_p1_hub.py [unittest args]
Real FastAPI/pydantic/starlette, in-process TestClient, temp SQLite DB.
"""
import json
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from contextlib import closing
from datetime import timedelta

sys.dont_write_bytecode = True
if os.environ.get("TZ") != "UTC":
    raise SystemExit("run with TZ=UTC (the hub's timezone)")
HERE = os.path.dirname(os.path.abspath(__file__))
INSTALLER = os.path.abspath(os.environ.get("P1_CONTROL_PLANE_INSTALLER",
                                           os.path.join(HERE, "wins_control_plane_setup_ONETOUCH.sh")))
_lines = open(INSTALLER, encoding="utf-8").read().splitlines(keepends=True)
_start = next(i for i, l in enumerate(_lines) if "<<'PYEOF'" in l and "main.py" in l)
_end = next(j for j in range(_start + 1, len(_lines)) if _lines[j].rstrip("\n") == "PYEOF")
SOURCE = "".join(_lines[_start + 1:_end])

from fastapi.testclient import TestClient  # noqa: E402

TMP = tempfile.mkdtemp(prefix="p1-hub-")
ADMIN = "test-admin-token"
_SEQ = [0]


def load():
    logdir = os.path.join(TMP, "log")
    os.makedirs(logdir, exist_ok=True)
    os.environ.update({
        "DATABASE_PATH": os.path.join(TMP, "vpn_users.db"),
        "RATE_LIMIT_SECRET": "test-rate-limit-secret",
        "ADMIN_TOKEN": ADMIN,
        "SPA_HMAC": "test-spa-hmac",
        "SECURITY_EVENTS_DB": os.path.join(TMP, "security_events.db"),
        "SMTP_PASS": "",
        "DEVICE_LIMIT": "3",
    })
    src = SOURCE
    src = src.replace('"/var/log/winsvpn"', repr(logdir))
    src = src.replace('"/var/log/winsvpn/master.log"', repr(os.path.join(logdir, "master.log")))
    src = src.replace('"/var/lib/wins-security-alerts"', repr(TMP))
    mod = types.ModuleType("wins_hub_p1")
    mod.__dict__["__file__"] = os.path.join(TMP, "main.py")
    sys.modules["wins_hub_p1"] = mod
    exec(compile(src, "wins_hub_main.py", "exec"), mod.__dict__)
    return mod


HUB = load()
ALERTS = []
HUB.security_alert = lambda priority, event, *args, **kwargs: ALERTS.append((priority, event, kwargs.get("details")))
CLIENT = TestClient(HUB.app, raise_server_exceptions=False)


def db():
    conn = sqlite3.connect(HUB.DB_PATH)
    conn.row_factory = sqlite3.Row
    return closing(conn)


def iso(delta_seconds=0.0):
    return (HUB.utcnow() + timedelta(seconds=delta_seconds)).isoformat()


class Node:
    def __init__(self, **overrides):
        _SEQ[0] += 1
        self.n = _SEQ[0]
        self.slug = f"lab-perf-{self.n}"
        self.name = overrides.get("name", f"Lab {self.n:03d}")
        self.token = f"p1-node-token-{self.n}-not-a-secret"
        now = iso()
        row = {
            "slug": self.slug, "name": f"Lab {self.n:03d}", "flag": "NL",
            "endpoint": f"192.0.2.{self.n}:9110", "public_key": f"{self.n:04d}" + "A" * 39 + "=",
            "ssh_host": HUB.node_management_hostname(self.slug),
            "status": "online", "last_heartbeat": now,
            "management_status": "ok", "management_checked_at": now, "operator_enabled": 1,
            "data_plane_status": "ok", "data_plane_ok_at": now,
            "data_plane_udp_status": "ok", "data_plane_udp_ok_at": now,
            "stealth_endpoint": "", "stealth_transports": "[]", "regional_aliases": "[]",
            "node_token_hash": HUB.token_digest(self.token),
            # P-8 applies to nodes that serve winn/3; a test of the legacy case
            # passes protocol_version="winn/1".
            "protocol_version": "winn/3", "protocol_params_json": json.dumps({"carrier": "winn3"}),
        }
        row.update(overrides)
        with db() as conn, conn:
            HUB.ensure_schema(conn)
            conn.execute(f"INSERT INTO nodes ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
                         tuple(row.values()))

    def register(self, **extra):
        body = {
            "slug": self.slug, "name": self.name, "flag": "NL",
            "endpoint": f"192.0.2.{self.n}:9110", "public_key": f"{self.n:04d}" + "A" * 39 + "=",
            "secret_token": self.token, "status": "online",
            "ssh_host": HUB.node_management_hostname(self.slug),
            "obfuscation_json": json.dumps(HUB.DEFAULT_OBFUSCATION),
            "tunnel_gateway_ipv4": "10.66.0.1",
        }
        body.update(extra)
        return CLIENT.post("/api/v1/nodes/register", json=body)

    def row(self):
        with db() as conn:
            return conn.execute("SELECT * FROM nodes WHERE slug = ?", (self.slug,)).fetchone()

    def set(self, **cols):
        with db() as conn, conn:
            conn.execute(f"UPDATE nodes SET {', '.join(f'{k} = ?' for k in cols)} WHERE slug = ?",
                         (*cols.values(), self.slug))

    def report(self, carrying=None, maximum=None, mode="active", age=0.0, drift=(), **extra):
        """Seed a stored performance report, as register would have stored it."""
        body = {"v": 1, "gateway": {"state": "active", "mode": mode, "carrying": carrying,
                                    "max_sessions": maximum}, "drift": list(drift)}
        body.update(extra)
        self.set(performance_report_json=json.dumps(HUB.sanitize_performance_report(body), sort_keys=True),
                 performance_reported_at=iso(-age))


def good_report():
    return {
        "v": 1, "interval_s": 120, "softnet": {"dropped_delta": 4},
        "gateway": {"state": "active", "mode": "active", "carrying": 19, "max_sessions": 22,
                    "inbox_drops_delta": 0, "udp_read_buffer": 33554432, "udp_write_buffer": 33554432,
                    "udp_rcvbuf_errors": 0, "udp_rcvbuf_errors_delta": 12,
                    "inbox_drops_source": "pipe_recv_errors_live_sessions", "async_flag": True, "async_gate": "enabled",
                    "gate_line": "winn3-gateway: -forward-async-write enabled: 6.00 usable CPUs (affinity 6)", "usable_cpus": 6.0,
                    "usable_cpus_source": "computed"},
        "sysctl": {"rmem_max": 134217728, "wmem_max": 134217728, "ok": True, "floor": 134217728},
        "wan_qdisc": {"dev": "eth0", "root": "fq", "limit": 20480, "flow_limit": 256, "match": True},
        "winn3gw": {"queues": "absent", "root": None, "qlen": None, "match": None},
        "env_overrides": [], "perf_trial_env": False,
        "nic": {"result": "ok", "recorded_at": 1790000000, "dev": "eth0",
                "features": {"rx-gro": "on", "tx-udp-segmentation": "off [fixed]"},
                "ring": {"max": {"rx": 4096, "tx": 4096}, "current": {"rx": 256, "tx": 256}}},
        "drift": [],
    }


class SanitizerP1(unittest.TestCase):
    def test_a_good_report_round_trips(self):
        report = HUB.sanitize_performance_report(good_report())
        self.assertEqual(report["softnet"]["dropped_delta"], 4)
        self.assertEqual(report["gateway"]["carrying"], 19)
        self.assertEqual(report["gateway"]["usable_cpus"], 6.0)
        self.assertEqual(report["gateway"]["gate_line"], "winn3-gateway: -forward-async-write enabled: 6.00 usable CPUs (affinity 6)")
        self.assertEqual(report["wan_qdisc"]["root"], "fq")
        self.assertEqual(report["nic"]["ring"]["max"], {"rx": 4096, "tx": 4096})
        self.assertEqual(report["nic"]["features"]["tx-udp-segmentation"], "off [fixed]")
        self.assertEqual(HUB.sanitize_performance_report(report), report)

    def test_the_host_wide_drop_delta_and_the_inbox_label_are_kept_and_bounded(self):
        report = HUB.sanitize_performance_report(good_report())
        self.assertEqual(report["gateway"]["udp_rcvbuf_errors_delta"], 12)
        self.assertEqual(report["gateway"]["inbox_drops_source"], "pipe_recv_errors_live_sessions")
        bad = good_report()
        bad["gateway"].update({"udp_rcvbuf_errors_delta": -5, "inbox_drops_source": "an exact count"})
        report = HUB.sanitize_performance_report(bad)
        self.assertIsNone(report["gateway"]["udp_rcvbuf_errors_delta"])
        self.assertIsNone(report["gateway"]["inbox_drops_source"])
        bad["gateway"]["udp_rcvbuf_errors_delta"] = True
        self.assertIsNone(HUB.sanitize_performance_report(bad)["gateway"]["udp_rcvbuf_errors_delta"])

    def test_not_an_object_is_not_reported(self):
        for raw in (None, "x", 3, [], [1]):
            self.assertIsNone(HUB.sanitize_performance_report(raw))

    def test_wrong_shapes_become_unknown_never_an_error(self):
        report = HUB.sanitize_performance_report({
            "interval_s": -1, "softnet": "x",
            "gateway": {"state": "weird", "mode": 7, "carrying": True, "max_sessions": -3,
                        "usable_cpus": "many", "async_gate": "ENABLED!", "udp_read_buffer": 2 ** 70,
                        "gate_line": "bad\x00line"},
            "sysctl": [], "wan_qdisc": {"root": "x" * 50, "dev": "eth0; rm -rf /", "limit": 1.5},
            "winn3gw": {"queues": "great"}, "env_overrides": "WAN_FQ_X", "drift": "all",
            "nic": {"result": "fine", "features": {"rx-gro": "maybe", "Bad Name": "on"}, "ring": {"max": {"rx": -1}}},
        })
        self.assertIsNone(report["interval_s"])
        self.assertIsNone(report["softnet"]["dropped_delta"])
        for key, value in report["gateway"].items():
            self.assertIsNone(value, key)
        self.assertIsNone(report["sysctl"]["rmem_max"])
        self.assertEqual((report["wan_qdisc"]["root"], report["wan_qdisc"]["dev"], report["wan_qdisc"]["limit"]),
                         (None, None, None))
        self.assertIsNone(report["winn3gw"]["queues"])
        self.assertEqual((report["env_overrides"], report["drift"]), ([], []))
        self.assertEqual(report["nic"]["features"], {})
        self.assertEqual(report["nic"]["ring"], {"max": {}})

    def test_an_unknown_drift_reason_is_one_sentinel(self):
        report = HUB.sanitize_performance_report({"drift": ["wan_qdisc_root", "from_the_future", "other", 5,
                                                            "wan_qdisc_root"]})
        self.assertEqual(report["drift"], ["wan_qdisc_root", HUB.NODE_PERF_UNRECOGNISED_REASON])

    def test_every_reason_the_node_can_name_is_known(self):
        import re
        script = open(INSTALLER.replace("wins_control_plane", "wins_data_plane"), encoding="utf-8").read()
        body = script[script.index("cat > /usr/local/bin/wins-node-perf-readback <<'EOF_PERF'"):
                      script.index("\nEOF_PERF\n")]
        named = set(re.findall(r'drift\.append\("([a-z_0-9]+)"\)', body))
        self.assertTrue(named)
        self.assertEqual(named - set(HUB.NODE_PERF_DRIFT_REASONS), set())

    def test_override_names_are_bounded_to_the_queue_variables(self):
        report = HUB.sanitize_performance_report({
            "env_overrides": ["WAN_FQ_FLOW_LIMIT", "RPS_CPU_MASK", "NODE_TOKEN", "WAN_FQ_x", "WAN_FQ_A=1"] + [f"WAN_FQ_V{i}" for i in range(30)]})
        self.assertNotIn("NODE_TOKEN", report["env_overrides"])
        self.assertNotIn("WAN_FQ_A=1", report["env_overrides"])
        self.assertLessEqual(len(report["env_overrides"]), 16)

    def test_a_stored_unreadable_report_is_not_reported(self):
        for stored in (None, "", "{", "[]", "3"):
            self.assertIsNone(HUB.parse_performance_report(stored))


class RegisterP1(unittest.TestCase):
    def test_a_report_is_stored_and_overwritten_on_each_register(self):
        node = Node()
        self.assertEqual(node.register(performance=good_report()).status_code, 200)
        row = node.row()
        stored = json.loads(row["performance_report_json"])
        self.assertEqual(stored["gateway"]["carrying"], 19)
        self.assertIsNotNone(HUB.parse_iso_datetime(row["performance_reported_at"]))
        self.assertEqual(node.register().status_code, 200)
        row = node.row()
        self.assertIsNone(row["performance_report_json"])
        self.assertIsNone(row["performance_reported_at"])

    def test_null_and_malformed_reports_are_accepted_as_not_reported(self):
        node = Node()
        for value in (None, "oops", [1], {"gateway": "x", "drift": 5}):
            response = node.register(performance=value)
            self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(node.register(performance={"gateway": "x", "drift": 5}).status_code, 200)

    def test_the_stored_report_carries_no_secret_and_no_unknown_key(self):
        node = Node()
        raw = good_report()
        raw["node_token"] = "never-stored"
        raw["gateway"]["address"] = "203.0.113.9"
        node.register(performance=raw)
        text = node.row()["performance_report_json"]
        self.assertNotIn("never-stored", text)
        self.assertNotIn("203.0.113.9", text)

    def test_an_old_node_that_sends_no_performance_field_still_registers(self):
        node = Node()
        self.assertEqual(node.register().status_code, 200)


class DriftAlertP1(unittest.TestCase):
    def setUp(self):
        del ALERTS[:]

    def audit(self):
        result = HUB.audit_winn3_contract_once()
        return result, [a for a in ALERTS if a[1] == "node performance read-back drift"]

    def mine(self, alerts, node):
        return [a for a in alerts if a[2]["slug"] == node.slug]

    def test_a_real_drift_alerts_at_an_emailed_priority(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_flow_limit", "winn3gw_queues_failed"])
        result, alerts = self.audit()
        self.assertEqual(self.mine(alerts, node),
                         [(2, "node performance read-back drift",
                           {"slug": node.slug, "reasons": ["wan_qdisc_flow_limit", "winn3gw_queues_failed"]})])
        self.assertGreaterEqual(result["performance_drift_nodes"], 1)
        self.assertLessEqual(2, max(HUB.SECURITY_ALERT_EMAIL_PRIORITIES))
        self.assertIn(2, HUB.SECURITY_ALERT_EMAIL_PRIORITIES)

    def test_a_trial_or_an_override_alone_is_log_only(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["perf_trial_env", "wan_env_override"])
        _, alerts = self.audit()
        self.assertEqual([a[0] for a in self.mine(alerts, node)], [3])
        self.assertNotIn(3, HUB.SECURITY_ALERT_EMAIL_PRIORITIES)

    def test_a_trial_beside_a_real_drift_is_emailed(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["perf_trial_env", "wan_qdisc_root"])
        _, alerts = self.audit()
        self.assertEqual([a[0] for a in self.mine(alerts, node)], [2])

    def test_an_older_report_without_the_token_still_names_a_failed_helper(self):
        node = Node()
        node.report(carrying=1, maximum=22, winn3gw={"queues": "stale"})
        _, alerts = self.audit()
        self.assertEqual(self.mine(alerts, node)[0][2]["reasons"], ["winn3gw_queues_stale"])

    # F-1: the sweep runs every FLEET_AVAILABILITY_AUDIT_SECONDS (120 s) and the
    # generic throttle is 300 s, so a drift that persists must not alert on every
    # sweep: one alert per node and reason set, a reminder every six hours.
    def test_a_persistent_drift_alerts_once_not_on_every_sweep(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_flow_limit"])
        counts = []
        for _ in range(5):
            _, alerts = self.audit()
            counts.append(len(self.mine(alerts, node)))
        self.assertEqual(counts, [1, 1, 1, 1, 1], "ALERTS is cumulative: one for this node, never more")

    def test_a_changed_reason_set_alerts_again_and_so_does_a_return_after_clearing(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_flow_limit"])
        self.audit()
        self.audit()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_flow_limit", "winn3gw0_qdisc_mismatch"])
        self.audit()
        self.audit()
        _, alerts = self.audit()
        self.assertEqual(len(self.mine(alerts, node)), 2)
        node.report(carrying=1, maximum=22)
        self.audit()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_flow_limit", "winn3gw0_qdisc_mismatch"])
        _, alerts = self.audit()
        self.assertEqual(len(self.mine(alerts, node)), 3)

    def test_a_persistent_drift_is_repeated_after_the_reminder_interval(self):
        node = Node()
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_root"])
        self.audit()
        signature, stamp = HUB._NODE_PERF_DRIFT_ALERTED[node.slug]
        HUB._NODE_PERF_DRIFT_ALERTED[node.slug] = (signature, stamp - HUB.NODE_PERF_DRIFT_REALERT_SECONDS + 60)
        _, alerts = self.audit()
        self.assertEqual(len(self.mine(alerts, node)), 1)
        HUB._NODE_PERF_DRIFT_ALERTED[node.slug] = (signature, stamp - HUB.NODE_PERF_DRIFT_REALERT_SECONDS - 1)
        _, alerts = self.audit()
        self.assertEqual(len(self.mine(alerts, node)), 2)
        self.assertEqual(HUB.NODE_PERF_DRIFT_REALERT_SECONDS, 6 * 3600)

    def test_each_node_is_throttled_on_its_own(self):
        first, second = Node(), Node()
        first.report(carrying=1, maximum=22, drift=["wan_qdisc_root"])
        self.audit()
        second.report(carrying=1, maximum=22, drift=["wan_qdisc_root"])
        _, alerts = self.audit()
        self.assertEqual((len(self.mine(alerts, first)), len(self.mine(alerts, second))), (1, 1))

    def test_a_clean_stale_or_missing_report_raises_nothing(self):
        clean, stale, missing = Node(), Node(), Node()
        clean.report(carrying=1, maximum=22)
        stale.report(carrying=1, maximum=22, age=HUB.NODE_PERF_FRESH_SECONDS + 60, drift=["wan_qdisc_root"])
        _, alerts = self.audit()
        for node in (clean, stale, missing):
            self.assertEqual(self.mine(alerts, node), [], node.slug)

    def test_a_retired_node_is_not_alerted(self):
        node = Node(retired_at=iso())
        node.report(carrying=1, maximum=22, drift=["wan_qdisc_root"])
        _, alerts = self.audit()
        self.assertEqual(self.mine(alerts, node), [])

    def test_the_result_shape_is_unchanged_when_nothing_drifts(self):
        # Mirrors alert_winn3_descriptor_expiry: the key appears only when needed.
        fresh = HUB.audit_winn3_contract_once.__code__.co_consts
        self.assertIn("performance_drift_nodes", fresh)
        with db() as conn, conn:
            conn.execute("UPDATE nodes SET performance_reported_at = NULL, performance_report_json = NULL")
        result, _ = self.audit()
        self.assertNotIn("performance_drift_nodes", result)


class SteeringP1(unittest.TestCase):
    """P-8. Two nodes with equal load: the lower name wins a tie, so a node that is
    passed over is passed over for the stated reason."""

    def pair(self, **first_report):
        # Seed both with a distinct, quiet name prefix so only these two compete.
        for slug in [r["slug"] for r in self.rows()]:
            with db() as conn, conn:
                conn.execute("UPDATE nodes SET operator_enabled = 0 WHERE slug = ?", (slug,))
        a, b = Node(name="AAA steering"), Node(name="BBB steering")
        a.report(**first_report)
        return a, b

    def rows(self):
        with db() as conn, conn:
            HUB.ensure_schema(conn)
            return conn.execute("SELECT slug FROM nodes WHERE operator_enabled = 1").fetchall()

    def pick(self, **kwargs):
        with db() as conn:
            row = HUB.select_online_node(conn, "auto", platform="android", **kwargs)
        return row["slug"] if row else None

    def test_a_node_at_ninety_percent_is_passed_over(self):
        a, b = self.pair(carrying=9, maximum=10)
        self.assertEqual(self.pick(), b.slug)

    def test_a_node_below_ninety_percent_still_wins_its_tie(self):
        a, b = self.pair(carrying=8, maximum=10)
        self.assertEqual(self.pick(), a.slug)

    def test_the_fifth_device_on_a_four_session_node_is_steered_not_refused(self):
        a, b = self.pair(carrying=4, maximum=4)
        self.assertEqual(self.pick(), b.slug)

    def test_a_full_node_is_still_used_when_every_node_is_full(self):
        a, b = self.pair(carrying=9, maximum=10)
        b.report(carrying=10, maximum=10)
        self.assertEqual(self.pick(), a.slug)

    def test_a_node_with_no_report_is_not_full(self):
        a, b = self.pair(carrying=9, maximum=10)
        a.set(performance_report_json=None, performance_reported_at=None)
        self.assertEqual(self.pick(), a.slug)

    def test_a_stale_report_is_ignored(self):
        a, b = self.pair(carrying=10, maximum=10, age=HUB.NODE_PERF_FRESH_SECONDS + 5)
        self.assertEqual(self.pick(), a.slug)

    def test_no_forwarding_gateway_means_no_session_limit_to_hit(self):
        for mode in ("reflector", "stopped"):
            a, b = self.pair(carrying=10, maximum=10, mode=mode)
            self.assertEqual(self.pick(), a.slug, mode)

    def test_unreadable_figures_are_not_full(self):
        a, b = self.pair(carrying=None, maximum=10)
        self.assertEqual(self.pick(), a.slug)
        a.report(carrying=10, maximum=None)
        self.assertEqual(self.pick(), a.slug)
        a.report(carrying=10, maximum=0)
        self.assertEqual(self.pick(), a.slug)

    def test_a_reconnect_to_the_current_node_is_never_steered(self):
        a, b = self.pair(carrying=10, maximum=10)
        self.assertEqual(self.pick(existing_slug=a.slug), a.slug)

    def test_a_distress_move_back_to_the_current_node_is_not_steered(self):
        a, b = self.pair(carrying=10, maximum=10)
        self.assertEqual(self.pick(preferred_slug=a.slug, existing_slug=a.slug, advisory_is_distress=True), a.slug)

    def test_an_explicit_choice_is_not_overridden(self):
        a, b = self.pair(carrying=10, maximum=10)
        with db() as conn:
            row = HUB.select_online_node(conn, a.slug, platform="android")
        self.assertEqual(row["slug"], a.slug)

    def test_a_preferred_node_that_is_full_is_not_taken(self):
        a, b = self.pair(carrying=9, maximum=10)
        self.assertEqual(self.pick(preferred_slug=a.slug), b.slug)
        self.assertEqual(self.pick(preferred_slug=a.slug, advisory_is_distress=True), b.slug)

    def test_a_preferred_node_with_room_is_taken(self):
        a, b = self.pair(carrying=1, maximum=10)
        self.assertEqual(self.pick(preferred_slug=b.slug), b.slug)

    @staticmethod
    def add_devices(node, count, v3, updated_at, tag):
        """Devices assigned to `node`. v3 devices hold an inner address."""
        with db() as conn, conn:
            for i in range(count):
                conn.execute(
                    "INSERT INTO devices (device_id, location_slug, winn3_inner_v4, updated_at) VALUES (?, ?, ?, ?)",
                    (f"{tag}-{node.slug}-{i}", node.slug, f"10.10.{node.n % 200}.{i + 2}" if v3 else None, updated_at))

    def test_assignments_since_the_report_count_before_the_next_heartbeat(self):
        # The report said 3 of 10. Six v3 devices were assigned after it, and
        # the next heartbeat has not come: 3 + 6 reaches 90 percent. The other
        # node holds six plain devices, so the two are equally loaded and only
        # the full rule can separate them.
        a, b = self.pair(carrying=3, maximum=10)
        self.add_devices(b, 6, False, iso(-600), "plain")
        self.add_devices(a, 6, True, iso(-600), "before")
        self.assertEqual(self.pick(), a.slug)
        with db() as conn, conn:
            conn.execute("UPDATE devices SET updated_at = ? WHERE device_id LIKE ?", (iso(+5), "before-%"))
        self.assertEqual(self.pick(), b.slug)

    def test_devices_before_the_report_or_without_v3_do_not_count_twice(self):
        a, b = self.pair(carrying=3, maximum=10)
        self.add_devices(a, 6, True, iso(-600), "old")
        self.add_devices(a, 6, False, iso(+5), "awg")
        self.add_devices(b, 12, False, iso(-600), "plain")
        with db() as conn:
            self.assertFalse(HUB.node_v3_sessions_full(conn, a.row()))
        self.assertEqual(self.pick(), a.slug)

    def test_the_predicate_is_exactly_the_stated_threshold(self):
        node = Node()
        with db() as conn:
            for carrying, maximum, full in ((17, 19, False), (18, 20, True), (4, 4, True), (3, 4, False), (0, 1, False)):
                node.report(carrying=carrying, maximum=maximum)
                self.assertIs(HUB.node_v3_sessions_full(conn, node.row()), full, (carrying, maximum))

    # S5: P-8 is for new v3 assignments. A winn/1 node that happens to report a
    # full gateway keeps the legacy placement it had before the slice.
    def test_a_node_that_does_not_serve_winn3_is_never_steered_away(self):
        self.isolate()
        a, b = Node(name="AAA legacy", protocol_version="winn/1"), Node(name="BBB legacy", protocol_version="winn/1")
        a.report(carrying=10, maximum=10)
        with db() as conn:
            self.assertFalse(HUB.node_v3_sessions_full(conn, a.row()))
        self.assertEqual(self.pick(), a.slug)
        # A row with no usable protocol is not v3 either (it is not selectable at all).
        for version in ("", None, "winn/2"):
            a.set(protocol_version=version)
            with db() as conn:
                self.assertFalse(HUB.node_v3_sessions_full(conn, a.row()), version)

    def test_a_winn3_node_beside_a_full_winn1_node_is_judged_on_its_own_report(self):
        for slug in [r["slug"] for r in self.rows()]:
            with db() as conn, conn:
                conn.execute("UPDATE nodes SET operator_enabled = 0 WHERE slug = ?", (slug,))
        v3 = Node(name="AAA v3")
        v3.report(carrying=9, maximum=10)
        with db() as conn:
            self.assertTrue(HUB.node_v3_sessions_full(conn, v3.row()))
            v1 = Node(name="BBB v1", protocol_version="winn/1")
            v1.report(carrying=10, maximum=10)
            self.assertFalse(HUB.node_v3_sessions_full(conn, v1.row()))

    def isolate(self):
        for slug in [r["slug"] for r in self.rows()]:
            with db() as conn, conn:
                conn.execute("UPDATE nodes SET operator_enabled = 0 WHERE slug = ?", (slug,))

    def test_a_full_node_that_is_not_protocol_eligible_is_not_used_as_the_last_resort(self):
        # The eligibility filter applies to the all-full fallback too: a full node
        # whose protocol metadata is unusable (a winn/3 row without a carrier) is
        # not a node the old rule would have given anyone.
        self.isolate()
        unusable = Node(name="AAA no carrier", protocol_params_json="{}")
        unusable.report(carrying=10, maximum=10)
        self.assertIsNone(self.pick())
        usable = Node(name="BBB usable")
        usable.report(carrying=10, maximum=10)
        self.assertEqual(self.pick(), usable.slug)

    def test_the_result_matches_the_old_rule_for_every_mix_of_full_nodes(self):
        # Old rule: take the first node, in (load, used, name, slug) order, that is
        # not full; when every node is full, take the first of them.
        self.isolate()
        nodes = [Node(name=f"{chr(ord('A') + i) * 3} mix") for i in range(4)]
        for mask in range(16):
            for i, node in enumerate(nodes):
                node.report(carrying=10 if mask >> i & 1 else 1, maximum=10)
            expected = next((n.slug for i, n in enumerate(nodes) if not mask >> i & 1), nodes[0].slug)
            self.assertEqual(self.pick(), expected, mask)

    def test_the_least_loaded_node_comes_first_in_the_walk(self):
        self.isolate()
        a, b = Node(name="AAA loaded"), Node(name="BBB idle")
        self.add_devices(a, 3, False, iso(-600), "load")
        a.report(carrying=1, maximum=10)
        b.report(carrying=1, maximum=10)
        self.assertEqual(self.pick(), b.slug)
        b.report(carrying=10, maximum=10)
        self.assertEqual(self.pick(), a.slug)

    def test_the_walk_stops_at_the_first_node_with_room(self):
        # Perf: the session check runs a devices query, so it runs for as few
        # nodes as the answer needs: one when the first candidate has room.
        self.isolate()
        nodes = [Node(name=f"{chr(ord('A') + i) * 3} walk") for i in range(5)]
        for node in nodes:
            node.report(carrying=1, maximum=10)
        calls = []
        real = HUB.node_v3_sessions_full
        HUB.node_v3_sessions_full = lambda conn, node: calls.append(node["slug"]) or real(conn, node)
        try:
            self.assertEqual(self.pick(), nodes[0].slug)
            self.assertEqual(calls, [nodes[0].slug])
            del calls[:]
            nodes[0].report(carrying=10, maximum=10)
            nodes[1].report(carrying=10, maximum=10)
            self.assertEqual(self.pick(), nodes[2].slug)
            self.assertEqual(calls, [nodes[0].slug, nodes[1].slug, nodes[2].slug])
        finally:
            HUB.node_v3_sessions_full = real

    def test_a_register_with_the_node_report_feeds_the_steering(self):
        a, b = self.pair()
        raw = good_report()
        raw["gateway"].update({"carrying": 21, "max_sessions": 22})
        self.assertEqual(a.register(performance=raw).status_code, 200)
        self.assertEqual(self.pick(), b.slug)
        raw["gateway"].update({"carrying": 3})
        self.assertEqual(a.register(performance=raw).status_code, 200)
        self.assertEqual(self.pick(), a.slug)


class DevicesIndexP1(unittest.TestCase):
    def test_a_nodes_devices_are_found_by_an_index_not_a_scan(self):
        # node_v3_sessions_full and node_capacity_snapshot count a node's devices by
        # location_slug for every candidate of every assignment.
        with db() as conn:
            HUB.ensure_schema(conn)
            indexes = {row["name"]: [c["name"] for c in conn.execute(f"PRAGMA index_info({row['name']})")]
                       for row in conn.execute("PRAGMA index_list(devices)")}
            self.assertEqual(indexes.get("idx_devices_location_slug"), ["location_slug"])
            plan = " ".join(str(row["detail"]) for row in conn.execute(
                "EXPLAIN QUERY PLAN SELECT updated_at FROM devices WHERE location_slug = ? "
                "AND COALESCE(winn3_inner_v4, '') != ''", ("x",)))
            self.assertIn("USING INDEX idx_devices_location_slug", plan)
            self.assertNotIn("SCAN devices", plan)
            plan = " ".join(str(row["detail"]) for row in conn.execute(
                "EXPLAIN QUERY PLAN SELECT COUNT(*) AS cnt FROM devices WHERE location_slug = ?", ("x",)))
            self.assertNotIn("SCAN devices", plan)

    def test_the_index_is_created_idempotently(self):
        with db() as conn, conn:
            HUB.ensure_schema(conn)
            HUB.ensure_schema(conn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
