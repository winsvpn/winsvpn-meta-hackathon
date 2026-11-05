#!/usr/bin/env python3
"""Round LD2 (lane L102): per-server load_pct on GET /nodes.

The bar means CONGESTION by users (owner ruling 2026-09-29):
    raw = max(cpu, active-users ratio[, WAN ratio])
CPU and users are REQUIRED; the WAN ratio exists only when an operator
configured a link capacity, so it is optional and can only raise the figure.
The users ratio travels in the existing `load_sessions_pct` key.

Adapted from lane L85's suite, which asserted the superseded "CPU and WAN both
required" rule.

Usage:  TZ=UTC python3 test_hub_load_congestion_ld2.py [unittest args]
            (tests the control-plane installer next to this file)
        TZ=UTC python3 test_hub_load_congestion_ld2.py --main <main.py> [unittest args]
        TZ=UTC python3 test_hub_load_congestion_ld2.py --repo-installer <ONETOUCH.sh> [unittest args]

Real FastAPI/pydantic/starlette, in-process TestClient, temp SQLite DB.
Registration goes through the real POST /api/v1/nodes/register with a seeded
per-node token, and the listing through the real GET /nodes.
"""
import hashlib
import json
import math
import sqlite3
import tempfile
import types
import unittest
from contextlib import closing
from datetime import timedelta

import os
import sys

sys.dont_write_bytecode = True
if os.environ.get("TZ") != "UTC":
    raise SystemExit("run with TZ=UTC (the hub's timezone)")
_DEFAULT_INSTALLER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "wins_control_plane_setup_ONETOUCH.sh")
_args = sys.argv[1:]
if not _args or _args[0] not in ("--main", "--repo-installer"):
    _args = ["--repo-installer", _DEFAULT_INSTALLER, *_args]
if _args[0] == "--repo-installer":
    INSTALLER = os.path.abspath(_args[1])
    _lines = open(INSTALLER, encoding="utf-8").read().splitlines(keepends=True)
    _start = next(i for i, l in enumerate(_lines) if "<<'PYEOF'" in l and "main.py" in l)
    _end = next(j for j in range(_start + 1, len(_lines)) if _lines[j].rstrip("\n") == "PYEOF")
    SOURCE = "".join(_lines[_start + 1:_end])
    LABEL = f"{INSTALLER} (main.py heredoc)"
else:
    TARGET = os.path.abspath(_args[1])
    SOURCE = open(TARGET, encoding="utf-8").read()
    LABEL = TARGET
ARGV_REST = _args[2:]

import fastapi  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TMP = tempfile.mkdtemp(prefix="ld2-hub-")
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
    mod = types.ModuleType("wins_hub_ld2")
    mod.__dict__["__file__"] = os.path.join(TMP, "main.py")
    sys.modules["wins_hub_ld2"] = mod
    exec(compile(src, "wins_hub_main.py", "exec"), mod.__dict__)
    return mod


print(f"hub source: {LABEL} sha256={hashlib.sha256(SOURCE.encode()).hexdigest()} "
      f"fastapi={fastapi.__version__}", flush=True)
HUB = load()
HUB.security_alert = lambda *args, **kwargs: None
CLIENT = TestClient(HUB.app, raise_server_exceptions=False)


def db():
    conn = sqlite3.connect(HUB.DB_PATH)
    conn.row_factory = sqlite3.Row
    return closing(conn)


def iso(delta_seconds=0.0):
    return (HUB.utcnow() + timedelta(seconds=delta_seconds)).isoformat()


class Node:
    """One seeded, operator-enabled, healthy winn/1 node plus its token."""

    def __init__(self, **overrides):
        _SEQ[0] += 1
        self.n = _SEQ[0]
        self.slug = f"lab-load-{self.n}"
        self.token = f"ld2-node-token-{self.n}-not-a-secret"
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
        }
        row.update(overrides)
        with db() as conn, conn:
            HUB.ensure_schema(conn)
            cols = ", ".join(row)
            conn.execute(f"INSERT INTO nodes ({cols}) VALUES ({', '.join('?' * len(row))})",
                         tuple(row.values()))

    def register(self, raw_body=None, **load):
        body = {
            "slug": self.slug, "name": f"Lab {self.n:03d}", "flag": "NL",
            "endpoint": f"192.0.2.{self.n}:9110", "public_key": f"{self.n:04d}" + "A" * 39 + "=",
            "secret_token": self.token, "status": load.pop("status", "online"),
            "ssh_host": HUB.node_management_hostname(self.slug),
            "obfuscation_json": json.dumps(HUB.DEFAULT_OBFUSCATION),
            "tunnel_gateway_ipv4": "10.66.0.1",
        }
        body.update(load)
        if raw_body is not None:
            text = raw_body(json.dumps(body))
            return CLIENT.post("/api/v1/nodes/register", content=text,
                               headers={"content-type": "application/json"})
        return CLIENT.post("/api/v1/nodes/register", json=body)

    def set(self, **cols):
        with db() as conn, conn:
            sets = ", ".join(f"{k} = ?" for k in cols)
            conn.execute(f"UPDATE nodes SET {sets} WHERE slug = ?", (*cols.values(), self.slug))

    def listed(self, platform="android"):
        response = CLIENT.get("/nodes", params={"platform": platform})
        assert response.status_code == 200, response.text
        items = json.loads(response.text)["nodes"]
        check_types(items)
        for item in items:
            if item["slug"] == self.slug:
                return item
        return None

    def load(self, platform="android"):
        item = self.listed(platform)
        assert item is not None, f"{self.slug} not listed"
        return item["load_pct"]


BAND_VALUES = {25, 60, 90}


def check_types(items):
    """Contract: key present on every item; exactly int (not bool) in 0..100 step 5, or null.
    Round LD: the hub only ever emits the band values 25/60/90."""
    for item in items:
        if "load_pct" not in item:
            raise AssertionError(f"{item.get('slug')}: load_pct missing")
        value = item["load_pct"]
        if value is None:
            continue
        if type(value) is not int or not 0 <= value <= 100 or value % 5 or value not in BAND_VALUES:
            raise AssertionError(f"{item.get('slug')}: load_pct={value!r} ({type(value).__name__})")


def feed(node, *raws, users=0.0, net=None):
    """One register per raw value. CPU carries the value; the active-users ratio
    is `users` (0 unless given); the WAN ratio is omitted unless `net` is given."""
    for raw in raws:
        fields = {"load_cpu_pct": raw, "load_sessions_pct": users}
        if net is not None:
            fields["load_net_pct"] = net
        r = node.register(**fields)
        assert r.status_code == 200, r.text


def feed_users(node, *raws, cpu=0.0, net=None):
    """One register per active-users ratio, with a fixed (default idle) CPU."""
    for raw in raws:
        fields = {"load_cpu_pct": cpu, "load_sessions_pct": raw}
        if net is not None:
            fields["load_net_pct"] = net
        r = node.register(**fields)
        assert r.status_code == 200, r.text


class Bands(unittest.TestCase):
    def test_target_boundaries_from_every_state(self):
        t = HUB.node_load_band_target
        table = [
            (None, 39.99, "low"), (None, 40, "busy"), (None, 74.99, "busy"), (None, 75, "full"),
            ("low", 49.99, "low"), ("low", 50, "busy"), ("low", 84.99, "busy"), ("low", 85, "full"),
            ("busy", 30, "busy"), ("busy", 29.99, "low"), ("busy", 84.99, "busy"), ("busy", 85, "full"),
            ("full", 65, "full"), ("full", 64.99, "busy"), ("full", 30, "busy"), ("full", 29.99, "low"),
        ]
        for current, raw, want in table:
            self.assertEqual(t(raw, current), want, (current, raw))

    def test_step_needs_two_consecutive_reports(self):
        step = HUB.node_load_band_step
        self.assertEqual(step(10.0, None, None, 0), (None, "low", 1))
        self.assertEqual(step(10.0, None, "low", 1), ("low", None, 0))
        self.assertEqual(step(90.0, "low", None, 0), ("low", "full", 1))
        self.assertEqual(step(60.0, "low", "full", 1), ("busy", None, 0))   # both point up: least extreme wins
        self.assertEqual(step(90.0, "low", "busy", 1), ("busy", None, 0))
        self.assertEqual(step(60.0, "low", "busy", 1), ("busy", None, 0))
        self.assertEqual(step(90.0, "low", "full", 1), ("full", None, 0))
        self.assertEqual(step(50.0, "full", "low", 1), ("busy", None, 0))   # both point down
        self.assertEqual(step(10.0, "busy", "full", 1), ("busy", "low", 1))  # opposite direction restarts
        self.assertEqual(step(90.0, None, "busy", 1), (None, "full", 1))     # unconfirmed: exact match needed
        self.assertEqual(step(90.0, None, "full", 1), ("full", None, 0))
        self.assertEqual(step(45.0, "busy", "low", 1), ("busy", None, 0))    # back inside: candidate dropped
        self.assertEqual(step(None, "busy", None, 0), (None, None, 0))
        self.assertEqual(step(10.0, "bogus", "junk", "x"), (None, "low", 1))

    def test_raw_is_max_of_cpu_and_users_with_wan_optional(self):
        raw = HUB.node_load_raw_pct
        ns = types.SimpleNamespace
        # The headline: no WAN figure at all, and a figure is still computable.
        self.assertEqual(raw(ns(load_cpu_pct=20.0, load_net_pct=None, load_sessions_pct=35.0)), 35.0)
        self.assertEqual(raw(ns(load_cpu_pct=40.0, load_net_pct=None, load_sessions_pct=35.0)), 40.0)
        self.assertEqual(raw(ns(load_cpu_pct=0.0, load_sessions_pct=0.0)), 0.0)  # key absent, not just None
        # CPU and users are both required.
        self.assertIsNone(raw(ns(load_cpu_pct=50.0, load_net_pct=None, load_sessions_pct=None)))
        self.assertIsNone(raw(ns(load_cpu_pct=None, load_net_pct=None, load_sessions_pct=50.0)))
        self.assertIsNone(raw(ns(load_cpu_pct=50.0, load_net_pct=90.0, load_sessions_pct=None)))
        self.assertIsNone(raw(ns(load_cpu_pct=None, load_net_pct=90.0, load_sessions_pct=90.0)))
        self.assertIsNone(raw(ns(load_cpu_pct="50", load_net_pct=None, load_sessions_pct=50.0)))
        # WAN, when present, only raises.
        self.assertEqual(raw(ns(load_cpu_pct=20.0, load_net_pct=70.0, load_sessions_pct=35.0)), 70.0)
        self.assertEqual(raw(ns(load_cpu_pct=20.0, load_net_pct=5.0, load_sessions_pct=35.0)), 35.0)
        self.assertEqual(raw(ns(load_cpu_pct=20.0, load_net_pct="junk", load_sessions_pct=35.0)), 35.0)
        self.assertEqual(raw(ns(load_cpu_pct=-5, load_net_pct=None, load_sessions_pct=1e9)), 100.0)

    def test_sanitizer(self):
        s = HUB.sanitize_node_load_ratio
        for bad in (None, float("nan"), float("inf"), float("-inf"), "50", b"50", True, False, [], {}):
            self.assertIsNone(s(bad), repr(bad))
        self.assertEqual(s(-3), 0.0)
        self.assertEqual(s(150), 100.0)


class Listing(unittest.TestCase):
    def test_01_first_report_is_unknown_second_confirms_low(self):
        node = Node()
        feed(node, 10)
        self.assertIsNone(node.load())
        feed(node, 12)
        self.assertEqual(node.load(), 25)

    def test_02_wan_ratio_counts_when_present(self):
        node = Node()
        feed(node, 5, 5, net=60.0)
        self.assertEqual(node.load(), 60)

    def test_03_low_to_busy_needs_two_reports_at_50_or_more(self):
        node = Node()
        feed(node, 10, 10, 49.9, 49.9, 49.9)
        self.assertEqual(node.load(), 25)
        feed(node, 55)
        self.assertEqual(node.load(), 25)
        feed(node, 55)
        self.assertEqual(node.load(), 60)

    def test_04_busy_holds_until_below_30(self):
        node = Node()
        feed(node, 60, 60)
        self.assertEqual(node.load(), 60)
        feed(node, 35, 35, 30, 30)
        self.assertEqual(node.load(), 60)
        feed(node, 25)
        self.assertEqual(node.load(), 60)
        feed(node, 25)
        self.assertEqual(node.load(), 25)

    def test_05_full_entry_85_and_exit_below_65(self):
        node = Node()
        feed(node, 10, 10, 84, 84)
        self.assertEqual(node.load(), 60)
        feed(node, 85, 85)
        self.assertEqual(node.load(), 90)
        feed(node, 70, 70, 65, 65)
        self.assertEqual(node.load(), 90)
        feed(node, 60, 60)
        self.assertEqual(node.load(), 60)

    def test_06_low_straight_to_full(self):
        node = Node()
        feed(node, 5, 5, 95, 95)
        self.assertEqual(node.load(), 90)

    def test_06b_rising_through_two_bands_shows_busy_then_full(self):
        node = Node()
        feed(node, 3, 3, 67.5, 90)
        self.assertEqual(node.load(), 60)
        feed(node, 90)
        self.assertEqual(node.load(), 60)
        feed(node, 90)
        self.assertEqual(node.load(), 90)

    def test_06c_falling_through_two_bands_shows_busy_first(self):
        node = Node()
        feed(node, 95, 95, 50, 10)
        self.assertEqual(node.load(), 60)
        feed(node, 10, 10)
        self.assertEqual(node.load(), 25)

    def test_07_sol_counterexample_single_burst_is_invisible(self):
        node = Node()
        feed(node, 0, 0)
        seen = []
        for raw in (100, 0, 0, 0, 0, 0, 0):
            feed(node, raw)
            seen.append(node.load())
        self.assertEqual(seen, [25] * 7)

    def test_08_alternating_spikes_never_confirm(self):
        node = Node()
        feed(node, 0, 0)
        for raw in (90, 10, 90, 10, 90, 10):
            feed(node, raw)
            self.assertEqual(node.load(), 25)

    def test_10_missing_ratio_resets_confirmation(self):
        node = Node()
        feed(node, 90, 90)
        self.assertEqual(node.load(), 90)
        node.register(load_cpu_pct=90.0)  # users ratio missing
        self.assertIsNone(node.load())    # never published while unknown
        # Round LD2 (Seat C G4): the confirmed band is HELD across ONE unknown
        # report, so the next usable report is judged against it, not against
        # the plain unconfirmed boundaries.
        feed(node, 90)
        self.assertEqual(node.load(), 90)

    def test_11_stale_window_179_known_181_unknown(self):
        node = Node()
        feed(node, 60, 60)
        node.set(load_reported_at=iso(-179))
        self.assertEqual(node.load(), 60)
        node.set(load_reported_at=iso(-181))
        self.assertIsNone(node.load())

    def test_12_future_stamp_is_unknown(self):
        node = Node()
        feed(node, 60, 60)
        node.set(load_reported_at=iso(300))
        self.assertIsNone(node.load())

    def test_13_gap_restarts_confirmation(self):
        node = Node()
        feed(node, 90, 90)
        node.set(load_reported_at=iso(-200))
        feed(node, 10)
        self.assertIsNone(node.load())  # the old "full" must not carry across a gap
        feed(node, 10)
        self.assertEqual(node.load(), 25)

    def test_14_never_reported_is_unknown(self):
        node = Node()
        self.assertEqual(node.register().status_code, 200)
        self.assertIsNone(node.load())
        self.assertIsNone(Node().load())

    def test_15_status_only_heartbeat_does_not_refresh(self):
        node = Node()
        feed(node, 60, 60)
        node.set(load_reported_at=iso(-200))
        r = CLIENT.post("/api/v1/nodes/heartbeat", json={"slug": node.slug, "secret_token": node.token})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(node.load())

    def test_16_closed_and_offline_are_not_listed(self):
        closed = Node()
        feed(closed, 60, 60)
        closed.set(operator_enabled=0)
        self.assertIsNone(closed.listed())
        offline = Node()
        feed(offline, 60, 60)
        offline.set(last_heartbeat=iso(-(HUB.NODE_HEARTBEAT_STALE_SECONDS + 60)))
        self.assertIsNone(offline.listed())

    def test_17_unreachable_and_maintenance_are_unknown(self):
        node = Node(data_plane_udp_status="unreachable")
        feed(node, 60, 60)
        self.assertEqual(node.load("android"), 60)
        item = node.listed("linux")
        self.assertEqual(item["status"], "unreachable")
        self.assertIsNone(item["load_pct"])
        m = Node()
        for _ in range(2):
            m.register(load_cpu_pct=60.0, load_sessions_pct=0.0, status="maintenance")
        item = m.listed()
        self.assertEqual(item["status"], "maintenance")
        self.assertIsNone(item["load_pct"])

    def test_18_congested_status_never_moves_the_bar(self):
        # Round LD OI-6b: a confirmed low band on a node whose listed status
        # turns congested must stay 25; the status is published separately.
        node = Node()
        feed(node, 10, 10)
        self.assertEqual(node.load(), 25)
        for _ in range(3):
            node.register(load_cpu_pct=10.0, load_sessions_pct=0.0, status="congested")
            item = node.listed()
            self.assertEqual(item["status"], "congested")
            self.assertEqual(item["load_pct"], 25)
        # congestion from placement capacity (hub-derived: devices against max_peers)
        cap = Node()
        for _ in range(2):
            cap.register(load_cpu_pct=60.0, load_sessions_pct=0.0, max_peers=1)
        self.assertEqual(cap.listed()["status"], "online")
        with db() as conn, conn:
            conn.execute("INSERT INTO devices (device_id, account_number, location_slug) VALUES (?, ?, ?)",
                         (f"ld2-dev-{cap.n}", "1111-2222-3333", cap.slug))
        item = cap.listed()
        self.assertEqual(item["status"], "congested", "capacity congestion not reproduced")
        self.assertEqual(item["load_pct"], 60)
        # a band only moves on measured load, confirmed twice
        cap.register(load_cpu_pct=90.0, load_sessions_pct=0.0, max_peers=1)
        self.assertEqual(cap.load(), 60)
        cap.register(load_cpu_pct=90.0, load_sessions_pct=0.0, max_peers=1)
        self.assertEqual(cap.load(), 90)
        # unknown load on a congested node stays unknown
        unknown = Node()
        for _ in range(2):
            unknown.register(load_cpu_pct=10.0, status="congested")
        self.assertIsNone(unknown.listed()["load_pct"])

    def test_19_malformed_inputs_never_fail_the_heartbeat(self):
        for load in ({"load_cpu_pct": "abc", "load_sessions_pct": 1}, {"load_cpu_pct": True, "load_sessions_pct": 1},
                     {"load_cpu_pct": [50], "load_sessions_pct": {"v": 1}}, {"load_sessions_pct": "x"},
                     {"load_cpu_pct": 5, "load_sessions_pct": 5, "load_net_pct": "junk"}):
            node = Node()
            for _ in range(2):
                r = node.register(**load)
                self.assertEqual(r.status_code, 200, (load, r.text))
            if load.get("load_net_pct") == "junk":
                self.assertEqual(node.load(), 25, "a junk WAN figure is ignored, not fatal")
            else:
                self.assertIsNone(node.load(), load)
        clamp = Node()
        for _ in range(2):
            clamp.register(load_cpu_pct=-5, load_sessions_pct=1e9)
        self.assertEqual(clamp.load(), 90)

    def test_20_nan_and_infinity_literals_are_unknown(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            node = Node()
            for _ in range(2):
                r = node.register(raw_body=lambda text, lit=literal:
                                  text[:-1] + f', "load_cpu_pct": {lit}, "load_sessions_pct": 10}}')
                self.assertEqual(r.status_code, 200, (literal, r.text))
            self.assertIsNone(node.load(), literal)
            other = Node()
            for _ in range(2):
                r = other.register(raw_body=lambda text, lit=literal:
                                   text[:-1] + f', "load_cpu_pct": 10, "load_sessions_pct": {lit}}}')
                self.assertEqual(r.status_code, 200, (literal, r.text))
            self.assertIsNone(other.load(), literal)

    def test_21_internal_columns_do_not_leak(self):
        node = Node()
        feed(node, 60, 60)
        item = node.listed()
        self.assertEqual({k for k in item if "load" in k}, {"load_pct"})

    def test_23_unusable_report_clears_the_stamp_and_holds_only_the_band(self):
        node = Node()
        feed(node, 60, 60)
        self.assertEqual(node.load(), 60)
        node.register(load_cpu_pct=60.0)  # no users ratio: unusable
        with db() as conn:
            row = conn.execute("SELECT load_band, load_candidate, load_candidate_count, load_reported_at, load_band_at "
                               "FROM nodes WHERE slug = ?", (node.slug,)).fetchone()
        self.assertEqual(tuple(row)[:4], ("busy", None, 0, None))
        self.assertIsNotNone(row["load_band_at"])
        self.assertIsNone(node.load())
        # a node that never had a confirmed band holds nothing
        cold = Node()
        cold.register(load_cpu_pct=60.0)
        with db() as conn:
            row = conn.execute("SELECT load_band, load_band_at FROM nodes WHERE slug = ?", (cold.slug,)).fetchone()
        self.assertEqual(tuple(row), (None, None))

    def test_22_type_contract_every_item_every_platform(self):
        feed(Node(), 12, 12)
        feed(Node(), 70, 70)
        Node().register()
        for platform in ("android", "ios", "linux", "windows", "macos", "unknown"):
            response = CLIENT.get("/nodes", params={"platform": platform})
            self.assertEqual(response.status_code, 200)
            items = json.loads(response.text)["nodes"]
            self.assertTrue(items)
            check_types(items)


class CongestionByUsers(unittest.TestCase):
    """Round LD2: the bar follows how many people are on the node."""

    def test_30_band_is_computable_with_no_wan_figure(self):
        # The state that made every server's bar empty: the WAN ratio is null.
        for wan in ({"load_net_pct": None}, {}):
            node = Node()
            for _ in range(2):
                r = node.register(load_cpu_pct=8.0, load_sessions_pct=12.0, **wan)
                self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(node.load(), 25, wan)

    def test_31_users_alone_drive_the_band(self):
        # A crowd on an idle CPU is congestion: CPU 5 %, users at 60 % of capacity.
        node = Node()
        feed_users(node, 60, 60, cpu=5.0)
        self.assertEqual(node.load(), 60)
        feed_users(node, 90, 90, cpu=5.0)
        self.assertEqual(node.load(), 90)

    def test_32_cpu_alone_drives_the_band_when_users_are_few(self):
        node = Node()
        feed_users(node, 2, 2, cpu=92.0)
        self.assertEqual(node.load(), 90)

    def test_33_wan_raises_but_never_lowers(self):
        node = Node()
        feed(node, 5, 5, users=5.0, net=90.0)
        self.assertEqual(node.load(), 90)
        node2 = Node()
        feed(node2, 60, 60, users=60.0, net=1.0)
        self.assertEqual(node2.load(), 60)

    def test_34_users_ratio_is_required(self):
        for load in ({"load_cpu_pct": 80.0},
                     {"load_cpu_pct": 80.0, "load_net_pct": 80.0},         # a pre-LD2 node with a WAN figure
                     {"load_cpu_pct": 80.0, "load_sessions_pct": None},
                     {"load_cpu_pct": 80.0, "load_sessions_pct": "n/a"}):
            node = Node()
            for _ in range(4):
                self.assertEqual(node.register(**load).status_code, 200)
            self.assertIsNone(node.load(), load)

    def test_35_cpu_ratio_is_required(self):
        for load in ({"load_sessions_pct": 80.0},
                     {"load_sessions_pct": 80.0, "load_net_pct": 80.0},
                     {"load_cpu_pct": None, "load_sessions_pct": 80.0},
                     {"load_cpu_pct": "n/a", "load_sessions_pct": 80.0}):
            node = Node()
            for _ in range(4):
                self.assertEqual(node.register(**load).status_code, 200)
            self.assertIsNone(node.load(), load)

    def test_36_old_node_script_reports_unknown_not_an_error(self):
        # Node script before LD2 on a fleet without a link capacity: CPU only.
        node = Node()
        for _ in range(3):
            r = node.register(load_cpu_pct=10.0, load_net_pct=None, load_sessions_pct=None)
            self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(node.load())

    def test_37_missing_users_ratio_clears_a_confirmed_band(self):
        node = Node()
        feed_users(node, 60, 60, cpu=1.0)
        self.assertEqual(node.load(), 60)
        node.register(load_cpu_pct=1.0)
        self.assertIsNone(node.load())

    def test_38_user_step_inside_a_band_is_invisible(self):
        # One person more or less is 100/270 = 0.37 points on a 3+ vCPU node
        # and 1.1 points on a 1 vCPU node; neither may move the published value.
        node = Node()
        feed_users(node, 20.0, 20.0)
        seen = set()
        for step in (20.0, 20.4, 20.7, 21.1, 21.5, 20.0, 19.6, 30.0, 45.0, 49.9, 45.0, 20.0):
            feed_users(node, step)
            seen.add(node.load())
        self.assertEqual(seen, {25})

    def test_39_ratio_jitter_at_the_band_edge_never_flaps(self):
        # Alternating one-user changes around the busy entry point (50 %) must
        # not flap: entry needs two consecutive reports, exit needs < 30.
        node = Node()
        feed_users(node, 10.0, 10.0)
        seen = []
        for step in (50.4, 49.6, 50.4, 49.6, 50.4, 49.6):
            feed_users(node, step)
            seen.append(node.load())
        self.assertEqual(seen, [25] * 6)
        feed_users(node, 50.4, 50.4)
        self.assertEqual(node.load(), 60)
        seen = []
        for step in (49.6, 50.4, 49.6, 35.0, 30.0, 29.9):
            feed_users(node, step)
            seen.append(node.load())
        self.assertEqual(seen, [60] * 6)


class HoldAcrossUnknown(unittest.TestCase):
    """Round LD2 (Seat C G4): one unknown report must not reset hysteresis."""

    def confirmed_low_at_45(self):
        node = Node()
        feed_users(node, 20.0, 20.0)
        self.assertEqual(node.load(), 25)
        return node

    def test_50_one_unknown_report_keeps_the_confirmed_band(self):
        node = self.confirmed_low_at_45()
        node.register(load_cpu_pct=1.0)                # unknown: the users figure is missing
        self.assertIsNone(node.load())                  # never published while unknown
        seen = []
        for _ in range(4):
            feed_users(node, 45.0)                      # 45 % is below the confirmed 50 % entry point
            seen.append(node.load())
        self.assertEqual(seen, [25] * 4)                # a cold start would have read busy (>= 40) after two

    def test_51_control_without_the_unknown_report(self):
        node = Node()
        feed_users(node, 45.0, 45.0)                    # never confirmed: plain 40 % boundary
        self.assertEqual(node.load(), 60)

    def test_52_two_unknown_reports_in_a_row_reset(self):
        node = self.confirmed_low_at_45()
        node.register(load_cpu_pct=1.0)
        node.register(load_cpu_pct=1.0)
        # the second unknown arrives 240 s after the last usable report; the next
        # usable one arrives after 360 s, beyond the 300 s hold
        node.set(load_band_at=iso(-360))
        feed_users(node, 45.0, 45.0)
        self.assertEqual(node.load(), 60)

    def test_53_hold_window_boundary(self):
        for age, want in ((250, 25), (299, 25), (301, 60)):
            node = self.confirmed_low_at_45()
            node.register(load_cpu_pct=1.0)
            node.set(load_band_at=iso(-age))
            feed_users(node, 45.0, 45.0)
            self.assertEqual(node.load(), want, age)

    def test_54_only_an_unknown_report_is_held_not_a_silent_node(self):
        node = self.confirmed_low_at_45()
        node.set(load_reported_at=iso(-200))            # the node simply stopped reporting
        feed_users(node, 45.0, 45.0)
        self.assertEqual(node.load(), 60)

    def test_55_a_held_band_does_not_carry_a_half_confirmed_candidate(self):
        node = self.confirmed_low_at_45()
        feed_users(node, 55.0)                          # candidate busy, count 1
        node.register(load_cpu_pct=1.0)                 # unknown
        feed_users(node, 55.0)                          # only 1 report toward busy again
        self.assertEqual(node.load(), 25)
        feed_users(node, 55.0)
        self.assertEqual(node.load(), 60)

    def test_57_good_reports_refresh_the_hold_stamp_and_unknown_ones_do_not(self):
        node = self.confirmed_low_at_45()
        node.set(load_band_at=iso(-1000))               # an old hold stamp on a fresh, usable report
        feed_users(node, 20.0)                          # a usable report refreshes it
        node.register(load_cpu_pct=1.0)                 # unknown: must NOT refresh it
        feed_users(node, 45.0, 45.0)
        self.assertEqual(node.load(), 25)               # held: the stamp was refreshed by the usable report
        other = self.confirmed_low_at_45()
        other.set(load_band_at=iso(-250))
        other.register(load_cpu_pct=1.0)
        with db() as conn:
            stamp = conn.execute("SELECT load_band_at FROM nodes WHERE slug = ?", (other.slug,)).fetchone()[0]
        age = (HUB.utcnow() - HUB.parse_iso_datetime(stamp)).total_seconds()
        self.assertTrue(249 <= age <= 260, age)          # unchanged by the unknown report

    def test_56_prior_state_helper(self):
        now = HUB.utcnow()
        stamp = lambda s: (now + timedelta(seconds=s)).isoformat()
        row = lambda **kw: {"load_band": "busy", "load_candidate": "full", "load_candidate_count": 1,
                            "load_reported_at": None, "load_band_at": None, **kw}
        prior = HUB.node_load_prior_state
        self.assertEqual(prior(None, now), (None, None, 0))
        self.assertEqual(prior(row(load_reported_at=stamp(-100)), now), ("busy", "full", 1))
        self.assertEqual(prior(row(load_band_at=stamp(-240)), now), ("busy", None, 0))
        self.assertEqual(prior(row(load_band_at=stamp(-301)), now), (None, None, 0))
        self.assertEqual(prior(row(load_band_at=stamp(60)), now), (None, None, 0))      # future stamp
        self.assertEqual(prior(row(load_band_at=None), now), (None, None, 0))
        self.assertEqual(prior(row(load_reported_at=stamp(-200), load_band_at=stamp(-200)), now), (None, None, 0))


class NoCountLeak(unittest.TestCase):
    """Round LD2 privacy: a user count is never stored or published."""

    def test_40_listing_holds_only_the_band_whatever_the_head_count(self):
        few, many = Node(), Node()
        feed_users(few, 1.0, 1.0, cpu=2.0)          # about 3 people on a 270-user node
        feed_users(many, 33.3125, 33.3125, cpu=2.0)  # about 90 people
        self.assertEqual(few.load(), many.load())
        self.assertEqual(few.load(), 25)
        raw = CLIENT.get("/nodes").text
        self.assertNotIn("33.3125", raw)
        for node in (few, many):
            item = node.listed()
            self.assertEqual({k for k in item if "load" in k or "user" in k or "session" in k}, {"load_pct"})

    def test_41_database_stores_no_ratio(self):
        node = Node()
        feed_users(node, 37.25, 37.25, cpu=12.5, net=3.75)
        with db() as conn:
            row = dict(conn.execute("SELECT * FROM nodes WHERE slug = ?", (node.slug,)).fetchone())
        for column, value in row.items():
            self.assertNotIn(value, (37.25, 12.5, 3.75, "37.25", "12.5", "3.75"), column)
        self.assertEqual(row["load_band"], "low")
        self.assertEqual({k for k in row if "load" in k},
                         {"load_band", "load_candidate", "load_candidate_count", "load_reported_at", "load_band_at"})

    def test_42_only_band_values_on_every_platform(self):
        for users, cpu in ((0.0, 0.0), (33.0, 3.0), (60.0, 3.0), (95.0, 3.0), (3.0, 95.0)):
            feed_users(Node(), users, users, cpu=cpu)
        for platform in ("android", "ios", "linux", "windows", "macos", "unknown"):
            items = json.loads(CLIENT.get("/nodes", params={"platform": platform}).text)["nodes"]
            check_types(items)
            self.assertTrue({i["load_pct"] for i in items} <= {None, 25, 60, 90})


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], "-v", *ARGV_REST])
