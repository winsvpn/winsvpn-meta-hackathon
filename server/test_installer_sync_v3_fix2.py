#!/usr/bin/env python3
"""Installer fix wave 2, lane sync_v3: IA-SYNC SYNC-03, -06, -15, -16, -21, -22.

Every case runs the SHIPPED code: bash functions and heredocs are cut out of
the three installers and executed; the hub app is the real main.py heredoc,
loaded through test_account_deletion_hub.load_hub. Nothing is reimplemented.

  SYNC-03  one external v3 canary per winn/3 node (WINN3_CANARY_NODES), each
           recorded against its own slug; canary addresses are never issued
           to a device; the admin listing reads the canary columns.
  SYNC-06  (guard only, fable ruling Q2 Stage 0) each node's pool is the /24
           around its descriptor router; its free count is listed and alerts
           under 20; no allocation behaviour changes beyond the SYNC-03
           canary reservation.
  SYNC-15  the data plane reports -forward and -resolver from the gateway
           unit; readiness names a resolver-less or reflector gateway.
  SYNC-16  the data plane reports gateway id, listen, inner, plan and path
           MTU; readiness names each disagreement with the descriptor, the
           hub plan, and the registered endpoint.
  SYNC-21  (guard only) the edge redirect expression alerts at 80 % of its cap.
  SYNC-22  a weekly timer renews the origin certificate with the installer's
           own functions; the register reports notAfter; the hub alerts.

  Round 2 (2026-09-30): the canary passes each node's served path MTU and
           queries DNS through the gateway resolver; a self-reported
           resolver-off or reflector gateway is refused on the serve path; a
           canary binding a device already holds is refused at config time
           and named in readiness; the report reads every field from the unit
           ExecStart; the three origin-cert writers share one lock, commit the
           pair by rename and keep a pending activation until a reload works;
           the register reports the certificate nginx serves.

Run:  python3 server/test_installer_sync_v3_fix2.py
Cases that need GNU date or coreutils timeout (the served-certificate report)
SKIP on a host without them and say so; run the suite on Linux for those. The
origin-cert timer cases use a Python flock shim where flock(1) is missing.
RealProbeCanaryTests run only with WINN3_REAL_PROBE_DIR set to a directory
holding winn3-probe, winn3-gateway and winn-ech-keygen built from source.
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from contextlib import closing
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import test_account_deletion_hub as harness  # noqa: E402
import test_winn3_descriptor_hub as ddesc  # noqa: E402
import test_winn3_pathmtu_hub as pm  # noqa: E402
import test_data_plane_dark_start_latch as node_latch  # noqa: E402
import test_winn3_hub_env_write as envw  # noqa: E402
from winn3_gateway_test_support import gateway_source  # noqa: E402

HUB = HERE / "wins_control_plane_setup_ONETOUCH.sh"
DATA = HERE / "wins_data_plane_setup_ONETOUCH.sh"
# Slice S6: the standalone installer is a tombstone. The gateway text these
# tests read is the block the data-plane installer carries (design v17 2.2).
GATEWAY = gateway_source(DATA)
SOURCES = {
    "hub": HUB.read_text(encoding="utf-8"),
    "data": DATA.read_text(encoding="utf-8"),
    "gateway": GATEWAY.read_text(encoding="utf-8"),
}
BASH = shutil.which("bash") or "/bin/bash"

PUB_A = base64.b64encode(bytes(range(32))).decode()
PUB_B = base64.b64encode(bytes(range(1, 33))).decode()
PUB_C = base64.b64encode(bytes(range(2, 34))).decode()


def entry(slug, pub=PUB_A, inner="10.10.0.250", key_dir=None, gw="203.0.113.10:9111", gid=None):
    key_dir = key_dir or f"/etc/winn/canary/{slug}"
    gid = gid or f"gw-{slug}"
    return "|".join((slug, pub, inner, key_dir, gw, gid))


def function_definition(source: str, name: str) -> str:
    """The text of `name() {...}` or `name() (...)`, by bracket matching."""
    match = re.search(rf"(?m)^{re.escape(name)}\(\)\s+([{{(])", source)
    if not match:
        raise AssertionError(f"function {name} not found")
    opener = match.group(1)
    closer = "}" if opener == "{" else ")"
    depth = 0
    for idx in range(match.end() - 1, len(source)):
        char = source[idx]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return source[match.start(): idx + 1]
    raise AssertionError(f"unbalanced {name}")


def heredoc_body(source: str, opener: str, marker: str) -> str:
    start = source.index(opener)
    body = source.index("\n", start) + 1
    end = source.index(f"\n{marker}\n", body)
    return source[body:end]


def run_bash(script: str, env: dict, cwd: str) -> subprocess.CompletedProcess:
    path = Path(cwd) / "driver.sh"
    path.write_text(script, encoding="utf-8")
    return subprocess.run([BASH, str(path)], cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


def base_env(tmp: str) -> dict:
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": tmp, "LC_ALL": "C"}


def write_exe(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


FLOCK_SHIM = r"""#!/usr/bin/env python3
# flock(1) subset for hosts without util-linux: flock [-n] [-w secs] FD|FILE [cmd...]
import fcntl, os, subprocess, sys, time
args = sys.argv[1:]
wait, nonblock = None, False
while args and args[0].startswith("-"):
    flag = args.pop(0)
    if flag == "-n":
        nonblock = True
    elif flag == "-w":
        wait = float(args.pop(0))
target = args.pop(0)
fd = int(target) if target.isdigit() else os.open(target, os.O_RDWR | os.O_CREAT, 0o600)
deadline = None if wait is None else time.time() + wait
while True:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except BlockingIOError:
        if nonblock or (deadline is not None and time.time() >= deadline):
            sys.exit(1)
        time.sleep(0.05)
sys.exit(subprocess.call(args) if args else 0)
"""


def install_flock_if_missing(bindir: Path) -> None:
    if shutil.which("flock") is None:
        write_exe(bindir / "flock", FLOCK_SHIM)


def gnu_date_available() -> bool:
    try:
        out = subprocess.run(["date", "--version"], capture_output=True, text=True, timeout=10)
    except Exception:
        return False
    return out.returncode == 0 and "GNU" in out.stdout


# ============================ SYNC-03: hub writer ============================


class HubCanaryWriterTests(unittest.TestCase):
    source = SOURCES["hub"]

    def run_writers(self, env):
        return envw.run_writers(self.source, env)

    def test_list_form_is_validated_and_written_on_one_line(self):
        nodes = entry("lab-alpha") + "\n   " + entry("lab-beta", pub=PUB_B, gw="203.0.113.11:9111")
        proc = self.run_writers({"WINN3_CANARY_NODES": nodes, "WINN3_CANARY_BIN": "/usr/local/bin/winn3-probe"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            envw.kv_lines(proc.stdout, "WINN3_CANARY_NODES"),
            ["WINN3_CANARY_NODES='" + entry("lab-alpha") + " "
             + entry("lab-beta", pub=PUB_B, gw="203.0.113.11:9111") + "'"],
        )
        self.assertEqual(envw.kv_lines(proc.stdout, "WINN3_CANARY_BIN"),
                         ["WINN3_CANARY_BIN='/usr/local/bin/winn3-probe'"])
        self.assertEqual(envw.kv_lines(proc.stdout, "WINN3_CANARY_NODE_SLUG"), [])

    def test_list_without_bin_uses_the_probe_default_and_writes_no_bin(self):
        proc = self.run_writers({"WINN3_CANARY_NODES": entry("lab-alpha")})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(envw.kv_lines(proc.stdout, "WINN3_CANARY_NODES")), 1)
        self.assertEqual(envw.kv_lines(proc.stdout, "WINN3_CANARY_BIN"), [])

    def test_rerun_is_idempotent(self):
        env = {"WINN3_CANARY_NODES": entry("lab-alpha") + " " + entry("lab-beta", pub=PUB_B)}
        first = self.run_writers(env)
        second = self.run_writers(env)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_legacy_tuple_and_list_are_both_written(self):
        env = dict(envw.CANARY_ENV)
        env["WINN3_CANARY_NODES"] = entry("lab-beta", pub=PUB_B)
        proc = self.run_writers(env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name, value in envw.CANARY_ENV.items():
            self.assertEqual(envw.kv_lines(proc.stdout, name), [f"{name}='{value}'"])
        self.assertEqual(envw.kv_lines(proc.stdout, "WINN3_CANARY_NODES"),
                         [f"WINN3_CANARY_NODES='{entry('lab-beta', pub=PUB_B)}'"])

    def test_bin_alone_without_a_list_is_still_partial(self):
        proc = self.run_writers({"WINN3_CANARY_BIN": "/usr/local/bin/winn3-probe"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("configuration is partial", proc.stderr)

    def test_bad_list_entries_are_refused_atomically(self):
        bad = {
            "duplicate slug": entry("lab-alpha") + " " + entry("lab-alpha", pub=PUB_B),
            "five fields": "lab-alpha|" + PUB_A + "|10.10.0.250|/etc/winn/canary/a|203.0.113.10:9111",
            "gateway id alphabet": entry("lab-alpha", gid="gw/a"),
            "key dir alphabet": entry("lab-alpha", key_dir="/etc/winn/canary%a"),
            "key dir relative": entry("lab-alpha", key_dir="etc/winn/canary"),
            "inner outside pool": entry("lab-alpha", inner="10.10.1.5"),
            "public not 32 bytes": entry("lab-alpha", pub=base64.b64encode(b"x" * 31).decode()),
            "endpoint hostname": entry("lab-alpha", gw="gw.example:9111"),
            "slug uppercase": entry("Lab-alpha"),
        }
        for label, nodes in bad.items():
            with self.subTest(label):
                proc = self.run_writers({"WINN3_CANARY_NODES": nodes})
                self.assertNotEqual(proc.returncode, 0, label)
                self.assertEqual(proc.stdout, "", label)
                self.assertIn("invalid Winn3 external canary", proc.stderr, label)

    def test_list_may_not_repeat_the_legacy_slug(self):
        env = dict(envw.CANARY_ENV)
        env["WINN3_CANARY_NODES"] = entry(envw.CANARY_ENV["WINN3_CANARY_NODE_SLUG"], pub=PUB_B)
        proc = self.run_writers(env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("already has a canary binding", proc.stderr)

    # ---- round 2 (Seat C N-1): refused at configuration time ----

    def make_db(self, rows):
        tmp = tempfile.mkdtemp(prefix="sync-v3-db-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = Path(tmp) / "vpn_users.db"
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute("CREATE TABLE devices (device_id TEXT, winn3_inner_v4 TEXT, winn3_static_public TEXT)")
            conn.executemany("INSERT INTO devices VALUES (?, ?, ?)", rows)
        return path

    def test_a_canary_value_a_device_holds_is_refused_at_config_time(self):
        cases = {
            "list inner_v4": ({"WINN3_CANARY_NODES": entry("lab-alpha")}, [("dev-1", "10.10.0.250", PUB_C)]),
            "list static_public": ({"WINN3_CANARY_NODES": entry("lab-alpha")}, [("dev-1", "10.10.0.9", PUB_A)]),
            "legacy inner_v4": (dict(envw.CANARY_ENV), [("dev-1", envw.CANARY_ENV["WINN3_CANARY_INNER_V4"], PUB_C)]),
        }
        for label, (env, rows) in cases.items():
            with self.subTest(label):
                proc = self.run_writers(dict(env, DB_PATH=str(self.make_db(rows))))
                self.assertNotEqual(proc.returncode, 0, label)
                self.assertEqual(proc.stdout, "", label)
                self.assertIn("is already held by a device", proc.stderr, label)

    def test_config_time_check_passes_free_values_and_a_fresh_install(self):
        env = {"WINN3_CANARY_NODES": entry("lab-alpha")}
        free = self.run_writers(dict(env, DB_PATH=str(self.make_db([("dev-1", "10.10.0.2", PUB_C)]))))
        self.assertEqual(free.returncode, 0, free.stderr)
        fresh = self.run_writers(dict(env, DB_PATH=str(Path(tempfile.gettempdir()) / "sync-v3-no-such.db")))
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertEqual(free.stdout, fresh.stdout)


# =========================== hub app fixtures ==============================


def hub():
    for name in ("WINN3_CANARY_NODE_SLUG", "WINN3_CANARY_STATIC_PUBLIC", "WINN3_CANARY_INNER_V4",
                 "WINN3_CANARY_NODES"):
        os.environ.pop(name, None)
    mod = ddesc.load_hub_with_ring()
    for handler in list(mod.logger.handlers):
        mod.logger.removeHandler(handler)
    return mod


class EnvPatch:
    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.saved[key] = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        return self

    def __exit__(self, *exc):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def capture_alerts(mod):
    alerts = []
    mod.security_alert = lambda priority, event_type, **kw: alerts.append((priority, event_type, kw.get("details")))
    return alerts


def db(mod):
    conn = sqlite3.connect(mod._DB)
    conn.row_factory = sqlite3.Row
    return closing(conn)


def add_device(mod, device_id, slug, inner, pub):
    with db(mod) as conn, conn:
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT INTO devices (device_id, account_number, location_slug, winn3_inner_v4,"
            " winn3_static_private, winn3_static_public) VALUES (?, ?, ?, ?, 'x', ?)",
            (device_id, harness.ACCOUNT, slug, inner, pub),
        )


# ======================== SYNC-03: hub app =================================


class HubCanaryBindingTests(unittest.TestCase):
    def test_each_listed_node_publishes_its_own_canary_binding(self):
        mod = hub()
        pm.standalone_node(mod, slug="lab-alpha")
        pm.standalone_node(mod, slug="lab-beta")
        nodes = entry("lab-alpha", pub=PUB_A, inner="10.10.0.250") + " " + entry("lab-beta", pub=PUB_B, inner="10.10.0.251")
        with EnvPatch(WINN3_CANARY_NODES=nodes), db(mod) as conn:
            alpha = mod.winn3_peer_registry_document(conn, "lab-alpha")
            beta = mod.winn3_peer_registry_document(conn, "lab-beta")
        self.assertEqual(alpha["peers"], [{"static_public": PUB_A, "inner_v4": "10.10.0.250", "not_after": 0}])
        self.assertEqual(beta["peers"], [{"static_public": PUB_B, "inner_v4": "10.10.0.251", "not_after": 0}])

    def test_legacy_tuple_still_binds_its_node(self):
        mod = hub()
        pm.standalone_node(mod, slug="lab-alpha")
        with EnvPatch(WINN3_CANARY_NODE_SLUG="lab-alpha", WINN3_CANARY_STATIC_PUBLIC=PUB_C,
                      WINN3_CANARY_INNER_V4="10.10.0.44"), db(mod) as conn:
            doc = mod.winn3_peer_registry_document(conn, "lab-alpha")
        self.assertEqual(doc["peers"], [{"static_public": PUB_C, "inner_v4": "10.10.0.44", "not_after": 0}])

    def test_a_node_named_twice_refuses_its_own_snapshot_only(self):
        mod = hub()
        pm.standalone_node(mod, slug="lab-alpha")
        pm.standalone_node(mod, slug="lab-beta")
        with EnvPatch(WINN3_CANARY_NODE_SLUG="lab-alpha", WINN3_CANARY_STATIC_PUBLIC=PUB_C,
                      WINN3_CANARY_INNER_V4="10.10.0.44",
                      WINN3_CANARY_NODES=entry("lab-alpha") + " " + entry("lab-beta", pub=PUB_B)), db(mod) as conn:
            with self.assertRaises(ValueError):
                mod.winn3_peer_registry_document(conn, "lab-alpha")
            beta = mod.winn3_peer_registry_document(conn, "lab-beta")
        self.assertEqual([p["static_public"] for p in beta["peers"]], [PUB_B])

    def test_allocator_never_issues_a_canary_address(self):
        mod = hub()
        with EnvPatch(WINN3_CANARY_NODES=entry("lab-alpha", inner="10.10.0.1") + " " + entry("lab-beta", inner="10.10.0.2"),
                      WINN3_CANARY_NODE_SLUG="lab-gamma", WINN3_CANARY_STATIC_PUBLIC=PUB_C,
                      WINN3_CANARY_INNER_V4="10.10.0.3"), db(mod) as conn:
            mod.ensure_schema(conn)
            self.assertEqual(mod.allocate_winn3_inner_ip(conn), "10.10.0.4")

    def test_reserved_publics_cover_both_forms(self):
        mod = hub()
        with EnvPatch(WINN3_CANARY_NODES=entry("lab-alpha", pub=PUB_A),
                      WINN3_CANARY_NODE_SLUG="lab-gamma", WINN3_CANARY_STATIC_PUBLIC=PUB_C,
                      WINN3_CANARY_INNER_V4="10.10.0.3"):
            self.assertEqual(mod.winn3_canary_reserved_publics(), {PUB_A, PUB_C})

    def test_admin_listing_reads_the_canary_columns(self):
        mod = hub()
        pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
                       descriptor_json=pm.stored_descriptor_json())
        out = pm.admin_list_winn3(mod)
        entry_ = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
        # standalone_node seeds a fresh ok canary; the listing must see it.
        self.assertNotIn("winn3_external_canary_not_fresh", entry_["blockers"])
        with db(mod) as conn, conn:
            conn.execute("UPDATE nodes SET winn3_canary_status='failed' WHERE slug='lab-alpha'")
        out = pm.admin_list_winn3(mod)
        entry_ = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
        self.assertIn("winn3_external_canary_not_fresh", entry_["blockers"])

    def test_a_device_holding_a_canary_value_is_named_and_alerted(self):
        cases = {
            "winn3_canary_inner_v4_held_by_device": ("10.10.0.250", PUB_C),
            "winn3_canary_static_public_held_by_device": ("10.10.0.9", PUB_A),
        }
        for blocker, (inner, pub) in cases.items():
            with self.subTest(blocker):
                mod = hub()
                pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
                               descriptor_json=pm.stored_descriptor_json())
                add_device(mod, "dev-1", "lab-alpha", inner, pub)
                alerts = capture_alerts(mod)
                with EnvPatch(WINN3_CANARY_NODES=entry("lab-alpha", pub=PUB_A, inner="10.10.0.250")):
                    listing = pm.admin_list_winn3(mod)
                    result = mod.audit_winn3_contract_once()
                entry_ = [n for n in listing["nodes"] if n["slug"] == "lab-alpha"][0]
                held = sorted(b for b in entry_["blockers"] if b.endswith("_held_by_device"))
                self.assertEqual(held, [blocker])
                self.assertFalse(entry_["ready"])
                self.assertEqual([a for a in alerts if a[1] == "winn3 canary binding held by a device"],
                                 [(2, "winn3 canary binding held by a device",
                                   {"slug": "lab-alpha", "blockers": [blocker]})])
                self.assertEqual(result["canary_collision_nodes"], 1)

    def test_no_collision_names_nothing(self):
        mod = hub()
        pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
                       descriptor_json=pm.stored_descriptor_json())
        add_device(mod, "dev-1", "lab-alpha", "10.10.0.2", PUB_C)
        alerts = capture_alerts(mod)
        with EnvPatch(WINN3_CANARY_NODES=entry("lab-alpha", pub=PUB_A, inner="10.10.0.250")):
            listing = pm.admin_list_winn3(mod)
            mod.audit_winn3_contract_once()
        entry_ = [n for n in listing["nodes"] if n["slug"] == "lab-alpha"][0]
        self.assertEqual([b for b in entry_["blockers"] if b.endswith("_held_by_device")], [])
        self.assertEqual([a for a in alerts if "canary binding" in a[1]], [])


# ============================ SYNC-06 guard ================================


class InnerPoolGuardTests(unittest.TestCase):
    """fable_ruling_sync08_sync06_20260929 Q2, Stage 0 (and its test 12)."""

    def fill(self, mod, count, first=2):
        with db(mod) as conn, conn:
            mod.ensure_schema(conn)
            conn.executemany(
                "INSERT INTO devices (device_id, account_number, location_slug, winn3_inner_v4,"
                " winn3_static_private, winn3_static_public) VALUES (?, ?, 'lab-alpha', ?, 'x', ?)",
                [(f"fill-{i}", harness.ACCOUNT, f"10.10.0.{i}",
                  base64.b64encode(i.to_bytes(2, "big") * 16).decode())
                 for i in range(first, first + count)],
            )

    def test_each_node_lists_its_pool_and_free_count(self):
        mod = hub()
        pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
                       descriptor_json=pm.stored_descriptor_json())
        add_device(mod, "dev-1", "lab-alpha", "10.10.0.2", PUB_B)
        with EnvPatch(WINN3_CANARY_NODES=entry("lab-alpha", inner="10.10.0.254")):
            listing = pm.admin_list_winn3(mod)
        entry_ = [n for n in listing["nodes"] if n["slug"] == "lab-alpha"][0]
        # devices .2, the descriptor router .1 and the canary .254: the allocator's own set.
        self.assertEqual((entry_["inner_pool"], entry_["winn3_inner_free"]), ("10.10.0.0/24", 251))
        self.assertEqual(listing["inner_pools"],
                         {"10.10.0.0/24": {"pool": "10.10.0.0/24", "capacity": 254, "used": 3, "free": 251}})

    def test_low_pool_alert_fires_under_20_free_and_not_at_20(self):
        mod = hub()
        pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls",
                       descriptor_json=pm.stored_descriptor_json())
        # 254 hosts; the router .1 plus 233 devices leaves exactly 20 free.
        self.fill(mod, 233)
        alerts = capture_alerts(mod)
        result = mod.audit_winn3_contract_once()
        self.assertEqual(result["inner_pools"]["10.10.0.0/24"]["free"], 20)
        self.assertEqual([a for a in alerts if a[1] == "winn3 inner pool low"], [])
        self.fill(mod, 1, first=235)
        with db(mod) as conn:
            before = mod.allocate_winn3_inner_ip(conn)
        result = mod.audit_winn3_contract_once()
        with db(mod) as conn:
            after = mod.allocate_winn3_inner_ip(conn)
        self.assertEqual(before, after)
        self.assertEqual([a for a in alerts if a[1] == "winn3 inner pool low"],
                         [(3, "winn3 inner pool low", {"slug": "lab-alpha", "free": 19, "pool": "10.10.0.0/24"})])
        self.assertEqual(result["inner_pool_low_nodes"], 1)

    def test_stage1_envelope_counts_and_compares_each_node_slice(self):
        # Q2 Stage 1 widens WINN3_INNER_POOL_CIDR to the /16 envelope; forced
        # here, as the validator still pins /24 today.
        mod = hub()
        mod.winn3_inner_pool = lambda: ipaddress.ip_network("10.10.0.0/16")
        on3 = {"inner_router_v4": "10.10.3.1", "inner_resolver_v4": "10.10.3.1"}
        rows = {
            "lab-alpha": standalone_with_report(
                mod, dict(MATCHING_REPORT, inner_v4="10.10.3.1", forward_cidr="10.10.3.0/24"),
                descriptor_kw=on3, slug="lab-alpha"),
            "lab-beta": standalone_with_report(mod, MATCHING_REPORT, slug="lab-beta"),
            "lab-gamma": standalone_with_report(
                mod, dict(MATCHING_REPORT, inner_v4="10.10.3.1", forward_cidr="10.10.0.0/24"),
                descriptor_kw=on3, slug="lab-gamma"),
        }
        self.assertEqual(report_blockers(mod, rows["lab-alpha"])[0], [])
        self.assertEqual(report_blockers(mod, rows["lab-beta"])[0], [])
        self.assertEqual(report_blockers(mod, rows["lab-gamma"])[0],
                         ["winn3_gateway_forward_cidr_differs_from_node_pool"])
        listing = pm.admin_list_winn3(mod)
        pools = {n["slug"]: (n["inner_pool"], n["winn3_inner_free"]) for n in listing["nodes"]}
        # One /24 each, 254 hosts, the router taken: never the envelope's 65534.
        self.assertEqual(pools["lab-alpha"], ("10.10.3.0/24", 253))
        self.assertEqual(pools["lab-beta"], ("10.10.0.0/24", 253))

    def test_a_node_without_a_descriptor_uses_the_legacy_slice_only_at_24(self):
        mod = hub()
        row = pm._standalone(mod, path_mtu=1450, carrier_classes="udp,tcp,tls")
        self.assertEqual(str(mod.winn3_node_inner_slice(row)), "10.10.0.0/24")
        mod.winn3_inner_pool = lambda: ipaddress.ip_network("10.10.0.0/16")
        self.assertIsNone(mod.winn3_node_inner_slice(row))


# ======================= SYNC-15 / SYNC-16: hub side =======================

MATCHING_REPORT = {
    "state": "active", "forward": True, "resolver": True, "listen": "0.0.0.0:51820",
    "gateway_id": "G" * 16, "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24",
    "plan": "udp,tcp,tls", "path_mtu": 1500,
}


def standalone_with_report(mod, report, *, descriptor_kw=None, slug="lab-alpha"):
    pm._standalone(mod, slug=slug, path_mtu=1500, carrier_classes="udp,tcp,tls",
                   descriptor_json=pm.stored_descriptor_json(slug=slug, **(descriptor_kw or {})))
    with db(mod) as conn, conn:
        conn.execute("UPDATE nodes SET winn3_gateway_report_json=? WHERE slug=?",
                     (None if report is None else json.dumps(report), slug))
    return pm.node_row(mod, slug)


def report_blockers(mod, row):
    ready = mod.winn3_node_readiness(row, ddesc.GOOD_OBFUSCATION)
    return sorted(b for b in ready["blockers"] if b in mod.WINN3_GATEWAY_REPORT_BLOCKERS), ready


class GatewayReportReadinessTests(unittest.TestCase):
    def test_matching_report_names_nothing(self):
        mod = hub()
        blockers, ready = report_blockers(mod, standalone_with_report(mod, MATCHING_REPORT))
        self.assertEqual(blockers, [])
        self.assertEqual(ready["gateway_report"], MATCHING_REPORT)

    def test_missing_report_is_named(self):
        mod = hub()
        blockers, _ = report_blockers(mod, standalone_with_report(mod, None))
        self.assertEqual(blockers, ["winn3_gateway_not_reported"])

    def test_each_disagreement_is_named_on_its_own(self):
        cases = {
            "winn3_gateway_resolver_off": {"resolver": False},
            "winn3_gateway_not_forwarding": {"forward": False},
            "winn3_gateway_id_differs_from_descriptor": {"gateway_id": "H" * 16},
            "winn3_gateway_inner_v4_differs_from_descriptor": {"inner_v4": "10.10.0.9"},
            "winn3_gateway_listen_port_differs_from_descriptor": {"listen": "0.0.0.0:9111"},
            "winn3_gateway_path_mtu_differs_from_hub": {"path_mtu": 1450},
            "winn3_gateway_plan_differs_from_hub": {"plan": "udp"},
            "winn3_gateway_not_running": {"state": "failed"},
            "winn3_gateway_forward_cidr_differs_from_node_pool": {"forward_cidr": "10.64.0.0/24"},
        }
        for blocker, change in cases.items():
            with self.subTest(blocker):
                mod = hub()
                report = dict(MATCHING_REPORT, **change)
                blockers, _ = report_blockers(mod, standalone_with_report(mod, report))
                self.assertEqual(blockers, [blocker])

    def test_plan_is_compared_by_membership(self):
        mod = hub()
        blockers, _ = report_blockers(mod, standalone_with_report(mod, dict(MATCHING_REPORT, plan="tls,udp,tcp")))
        self.assertEqual(blockers, [])

    def test_absent_gateway_and_incomplete_report(self):
        mod = hub()
        blockers, _ = report_blockers(mod, standalone_with_report(mod, {"state": "absent"}))
        self.assertEqual(blockers, ["winn3_gateway_not_installed"])
        mod = hub()
        blockers, _ = report_blockers(mod, standalone_with_report(mod, dict(MATCHING_REPORT, gateway_id="")))
        self.assertEqual(blockers, ["winn3_gateway_report_incomplete"])

    def test_descriptor_endpoint_that_left_the_registered_address_is_named(self):
        mod = hub()
        row = standalone_with_report(mod, MATCHING_REPORT, descriptor_kw={"endpoint": ddesc.OTHER_ENDPOINT})
        blockers, _ = report_blockers(mod, row)
        self.assertEqual(blockers, ["winn3_descriptor_endpoint_differs_from_registered_endpoint"])

    def test_listing_carries_the_report(self):
        mod = hub()
        standalone_with_report(mod, dict(MATCHING_REPORT, resolver=False))
        out = pm.admin_list_winn3(mod)
        entry_ = [n for n in out["nodes"] if n["slug"] == "lab-alpha"][0]
        self.assertIn("winn3_gateway_resolver_off", entry_["blockers"])
        self.assertEqual(entry_["gateway_report"]["resolver"], False)

    def test_contract_audit_alerts_on_definite_disagreement_only(self):
        mod = hub()
        standalone_with_report(mod, dict(MATCHING_REPORT, path_mtu=1450))
        standalone_with_report(mod, None, slug="lab-beta")
        alerts = capture_alerts(mod)
        result = mod.audit_winn3_contract_once()
        events = [a for a in alerts if a[1] == "winn3 gateway disagrees with the hub"]
        self.assertEqual(events, [(3, "winn3 gateway disagrees with the hub",
                                   {"slug": "lab-alpha", "blockers": ["winn3_gateway_path_mtu_differs_from_hub"]})])
        self.assertEqual(result["gateway_mismatch_nodes"], 1)

    def test_sanitizer_narrows_every_field(self):
        mod = hub()
        self.assertIsNone(mod.sanitize_winn3_gateway_report("not a dict"))
        out = mod.sanitize_winn3_gateway_report({
            "state": "weird", "forward": "yes", "resolver": 1, "listen": "0.0.0.0:9111; rm",
            "gateway_id": "gw id", "inner_v4": "127.0.0.1", "forward_cidr": "10.10.0.0/24 x",
            "plan": "udp,quic", "path_mtu": True, "extra": "dropped",
        })
        self.assertEqual(out, {"state": "unknown", "forward": None, "resolver": None, "listen": "",
                               "gateway_id": "", "inner_v4": "", "forward_cidr": "", "plan": "",
                               "path_mtu": None})
        self.assertEqual(mod.sanitize_origin_cert_not_after("2028-01-02T03:04:05Z"), "2028-01-02T03:04:05Z")
        self.assertIsNone(mod.sanitize_origin_cert_not_after("Jan 2 2028"))


class GatewayReportServingGateTests(unittest.TestCase):
    """Round 2, Sol OI-SYNC_V3-7: a definite self-reported defect refuses v3."""

    def serve(self, mod, row):
        return pm.resolve(mod, row, capabilities=pm.caps(supports_winn3=True, supports_winn3_descriptor=True))

    def test_resolver_off_and_reflector_are_refused_on_the_serve_path(self):
        for change, reason in (({"resolver": False}, "winn3_gateway_resolver_off"),
                               ({"forward": False}, "winn3_gateway_not_forwarding")):
            with self.subTest(reason):
                mod = hub()
                row = standalone_with_report(mod, dict(MATCHING_REPORT, **change))
                with self.assertRaises(mod.Winn3ContractError) as caught:
                    self.serve(mod, row)
                self.assertEqual(caught.exception.reason, reason)

    def test_no_report_or_an_unknown_field_is_still_served(self):
        cases = {
            "matching": MATCHING_REPORT,
            "not reported (older data plane)": None,
            "resolver unknown": dict(MATCHING_REPORT, resolver=None),
            "forward unknown": dict(MATCHING_REPORT, forward=None),
            "gateway absent here": {"state": "absent"},
            "readiness-only disagreement": dict(MATCHING_REPORT, path_mtu=1450),
        }
        for label, report in cases.items():
            with self.subTest(label):
                mod = hub()
                version, _, reason = self.serve(mod, standalone_with_report(mod, report))
                self.assertEqual((version, reason), ("winn/3", "winn3"))


class RegisterStoresReportsTests(unittest.TestCase):
    def register(self, mod, **fields):
        with db(mod) as conn, conn:
            mod.ensure_schema(conn)
            conn.execute("INSERT OR IGNORE INTO nodes (slug, node_token_hash, operator_enabled) VALUES (?, ?, 0)",
                         ("lab-alpha", mod.token_digest(node_latch.NODE_TOKEN)))
        payload = node_latch.registration_payload("lab-alpha")
        for key, value in fields.items():
            setattr(payload, key, value)
        return mod.register_node(payload, harness.FakeRequest(path="/api/v1/nodes/register"))

    def stored(self, mod):
        with db(mod) as conn:
            return conn.execute(
                "SELECT winn3_gateway_report_json, winn3_gateway_reported_at, origin_cert_not_after"
                " FROM nodes WHERE slug='lab-alpha'").fetchone()

    def test_reports_are_stored_and_cleared_when_a_register_omits_them(self):
        mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
        self.assertEqual(self.register(mod, winn3_gateway=dict(MATCHING_REPORT),
                                       origin_cert_not_after="2028-01-02T03:04:05Z"), {"ok": True})
        row = self.stored(mod)
        self.assertEqual(json.loads(row["winn3_gateway_report_json"]), MATCHING_REPORT)
        self.assertTrue(row["winn3_gateway_reported_at"])
        self.assertEqual(row["origin_cert_not_after"], "2028-01-02T03:04:05Z")
        # An older installer sends neither field (SimpleNamespace has no attribute).
        self.assertEqual(self.register(mod), {"ok": True})
        row = self.stored(mod)
        self.assertIsNone(row["winn3_gateway_report_json"])
        self.assertIsNone(row["winn3_gateway_reported_at"])
        self.assertIsNone(row["origin_cert_not_after"])

    def test_origin_cert_near_expiry_alerts(self):
        mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
        soon = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.register(mod, origin_cert_not_after=soon)
        alerts = capture_alerts(mod)
        result = mod.audit_winn3_contract_once()
        self.assertEqual([a for a in alerts if a[1] == "node origin certificate close to expiry"],
                         [(2, "node origin certificate close to expiry", {"slug": "lab-alpha", "not_after": soon})])
        self.assertEqual(result["origin_cert_expiring_nodes"], 1)
        self.register(mod, origin_cert_not_after=later)
        alerts.clear()
        mod.audit_winn3_contract_once()
        self.assertEqual([a for a in alerts if "certificate" in a[1]], [])


# ============================ SYNC-21 guard ================================


class EdgeExpressionGuardTests(unittest.TestCase):
    def test_alert_at_eighty_percent_and_the_rule_is_unchanged(self):
        mod = hub()
        alerts = capture_alerts(mod)

        def pairs(n):
            return [(f"node-{i:02d}.app-cloud-sync.net", "/" + "p" * 23) for i in range(n)]

        small = mod.edge_render_pairs(pairs(5))
        self.assertEqual(alerts, [])
        self.assertTrue(small.startswith("(not ssl and not ("))
        # 102-106 characters per clause: 31 pairs cross 80 % of 4000.
        mod.edge_render_pairs(pairs(31))
        self.assertEqual([a[1] for a in alerts], ["edge plaintext exception rule nearing the expression cap"])
        self.assertEqual(alerts[0][2], {"used_pct_at_least": 80, "limit": mod.EDGE_MAX_EXPRESSION_LENGTH})
        alerts.clear()
        with self.assertRaises(harness.HTTPException) as caught:
            mod.edge_render_pairs(pairs(60))
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(alerts[0][0], 2)
        self.assertEqual(alerts[0][2]["used_pct_at_least"], 100)


# =================== SYNC-03: the canary script itself =====================

CANARY_HARNESS = r"""#!/usr/bin/env bash
set -Eeuo pipefail
failed=0
log() { echo "$*"; }
fail() { failed=1; log "FAIL $*"; }
ok() { log "OK $*"; }
warn() { log "WARN $*"; }
__FUNCTIONS__
rc=0
run_external_winn3_canary || rc=$?
echo "RESULT rc=${rc} failed=${failed}"
"""

FAKE_PROBE = r"""#!/usr/bin/env bash
if [[ "${1:-}" == "-h" ]]; then
  if [[ "${PROBE_NO_DNS:-0}" == "1" ]]; then echo "  -gw string"; echo "  -path-mtu int"; exit 2; fi
  echo "  -dns string"; echo "  -dns-server string"; echo "  -path-mtu int"; exit 0
fi
gw="" dns=""
line="$*"
while (($#)); do
  case "$1" in -gw) gw="$2"; shift 2 ;; -dns) dns="$2"; shift 2 ;; *) shift ;; esac
done
printf '%s\n' "${line}" >> "${PROBE_LOG}"
if [[ -n "${dns}" ]]; then
  case " ${PROBE_DNS_FAIL:-} " in *" ${gw} "*) exit 1 ;; esac
  exit 0
fi
case " ${PROBE_OK_GATEWAYS} " in *" ${gw} "*) exit 0 ;; esac
exit 1
"""


def descriptor_envelope_with_resolver(resolver):
    payload = base64.b64encode(json.dumps({"inner_resolver_v4": resolver}).encode()).decode()
    return json.dumps({"payload": payload, "sig": "unused-by-the-canary"})


class CanaryScriptTests(unittest.TestCase):
    """SYNC-03 retargeted to H3's verified, read-only root runtime."""
    def setUp(self):
        import pytest
        from test_hub_h3_canary import Canary
        self.tmp = Path(tempfile.mkdtemp(prefix="sync-v3-canary-"))
        self.patch = pytest.MonkeyPatch()
        self.lane = Canary(self.tmp, self.patch)
        self.assertTrue(self.lane.run()["ok"])
        self.runtime = self.lane.runtime(self.tmp)

    def tearDown(self):
        self.patch.undo()
        self.lane.database.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_live(self):
        return self.runtime.run_canary_slug(self.lane.database, self.lane.slug)

    def result(self):
        return json.loads((self.runtime.CANARY_RESULT_DIR / (self.lane.slug + ".json")).read_text())

    def test_every_listed_node_is_probed_and_recorded_on_its_own_slug(self):
        self.assertTrue(self.run_live())
        self.assertEqual(self.result()["slug"], self.lane.slug)
        self.assertEqual(len(list(self.runtime.CANARY_RESULT_DIR.glob("*.json"))), 1)
        self.assertFalse(self.runtime.run_canary_slug(self.lane.database, "lab-beta"))
        self.assertFalse((self.runtime.CANARY_RESULT_DIR / "lab-beta.json").exists())

    def test_prepublication_advisory_records_but_does_not_fail(self):
        self.lane.failure = "icmp"
        self.assertFalse(self.run_live())
        self.assertEqual(self.result()["status"], "fail")
        script = heredoc_body(SOURCES["hub"], "cat > /usr/local/bin/wins-gateway-canary <<'EOF'", "EOF")
        start = script.index("winn3_canary_fail() {")
        end = script.index("# The root-owned", start)
        proc = run_bash(CANARY_HARNESS.replace("__FUNCTIONS__", script[start:end] +
                       '\nrun_external_winn3_canary() { winn3_canary_fail test; return 1; }\n'),
                       dict(base_env(str(self.tmp)), WINS_CANARY_WINN3_ADVISORY="1"), str(self.tmp))
        self.assertIn("RESULT rc=1 failed=0", proc.stdout)
        self.assertIn("WARN test", proc.stdout)

    def test_legacy_tuple_and_list_are_both_probed(self):
        binding = self.lane.binding()
        self.patch.setenv("WINN3_CANARY_NODE_SLUG", "lab-gamma")
        self.patch.setenv("WINN3_CANARY_STATIC_PUBLIC", PUB_C)
        self.patch.setenv("WINN3_CANARY_INNER_V4", "10.10.0.44")
        self.patch.setenv("WINN3_CANARY_NODES", "|".join((self.lane.slug, binding["static_public"],
            binding["inner_v4"], binding["key_dir"], binding["gateway_endpoint"], binding["gateway_id"])))
        found, conflicts = self.lane.mod.winn3_canary_bindings()
        self.assertEqual(set(found), {self.lane.slug, "lab-gamma"})
        self.assertFalse(conflicts)
        self.assertTrue(self.run_live())

    def test_a_malformed_entry_is_a_probe_error_and_is_not_probed(self):
        self.patch.setenv("WINN3_CANARY_NODES", entry(self.lane.slug) + "|extra")
        before = len(self.lane.calls)
        self.assertFalse(self.run_live())
        self.assertEqual(len(self.lane.calls), before)

    def test_nothing_configured_is_a_warning(self):
        self.lane.database.execute("DELETE FROM winn3_canary_bindings")
        self.lane.database.commit()
        self.assertFalse(self.run_live())
        self.assertFalse(list(self.runtime.CANARY_RESULT_DIR.iterdir()))

    def test_each_probe_gets_its_nodes_served_path_mtu(self):
        self.assertTrue(self.run_live())
        for argv, _, _ in self.lane.calls[-2:]:
            self.assertEqual(argv[argv.index("-path-mtu") + 1], str(self.lane.row()["path_mtu"]))
        self.lane.update(path_mtu=1500)
        with self.assertRaises(ValueError):
            self.run_live()  # An unsigned MTU change cannot match the verified report.

    def test_the_canary_default_is_the_hubs_default(self):
        self.assertEqual(self.runtime.WINN3_DEFAULT_PATH_MTU, self.lane.mod.WINN3_DEFAULT_PATH_MTU)

    def test_an_unregistered_node_is_a_probe_error_and_is_not_probed(self):
        before = len(self.lane.calls)
        self.assertFalse(self.runtime.run_canary_slug(self.lane.database, "lab-delta"))
        self.assertEqual(len(self.lane.calls), before)

    def test_dns_is_asked_of_the_descriptors_resolver(self):
        self.assertTrue(self.run_live())
        descriptor = self.lane.mod.winn3_stored_descriptor(self.lane.row())
        argv = self.lane.calls[-1][0]
        self.assertEqual(argv[argv.index("-dns-server") + 1], descriptor["inner_resolver_v4"])
        self.assertEqual(argv[argv.index("-inner") + 1], self.lane.binding()["inner_v4"])

    def test_a_failed_dns_answer_is_a_failed_canary(self):
        self.lane.failure = "dns"
        self.assertFalse(self.run_live())
        self.assertEqual(self.result()["status"], "fail")

    def test_a_probe_without_dns_support_cannot_record_success(self):
        actual = self.runtime.subprocess.run
        def no_dns(argv, **kwargs):
            if "-dns" in argv:
                return type("Failed", (), {"returncode": 2, "stdout": b"", "stderr": b""})()
            return actual(argv, **kwargs)
        self.patch.setattr(self.runtime.subprocess, "run", no_dns)
        self.assertFalse(self.run_live())
        self.assertEqual(self.result()["status"], "fail")

    def test_no_descriptor_resolver_refuses_instead_of_skipping_dns(self):
        self.lane.update(winn3_descriptor_json=descriptor_envelope_with_resolver("10.10.0.1"))
        before = len(self.lane.calls)
        with self.assertRaises(ValueError):
            self.run_live()
        self.assertEqual(len(self.lane.calls), before)

    def test_missing_probe_fails_without_publishing_success(self):
        self.patch.setenv("WINN3_CANARY_BIN", str(self.tmp / "missing-probe"))
        self.assertFalse(self.run_live())
        self.assertEqual(self.result()["status"], "fail")
        self.assertEqual(self.result()["detail"], "canary-probe-failed")

    def test_prepublication_passes_the_advisory_flag(self):
        body = function_definition(SOURCES["hub"], "run_prepublication_gateway_canary")
        self.assertIn("systemctl start wins-gateway-canary-prepublication.service", body)
        self.assertIn("Environment=WINS_CANARY_WINN3_ADVISORY=1", SOURCES["hub"])


REAL_PROBE_WRAPPER = r"""#!/usr/bin/env bash
# The shipped canary sends ICMP echo (it needs a -forward gateway); a loopback
# gateway is a reflector, so the ICMP step becomes -canary -reflect-to with
# every flag the canary chose, -path-mtu included. The DNS step and -h run
# the real probe unchanged.
real="${REAL_PROBE_DIR}/winn3-probe"
case " $* " in
  *" -h "*|*" -dns "*) exec "${real}" "$@" ;;
  *) exec "${real}" "$@" -canary -reflect-to 10.10.0.1 ;;
esac
"""


@unittest.skipUnless(os.environ.get("WINN3_REAL_PROBE_DIR"), "set WINN3_REAL_PROBE_DIR to real winn3-probe/winn3-gateway/winn-ech-keygen builds")
class RealProbeCanaryTests(unittest.TestCase):
    """The shipped canary against a REAL winn3-gateway at a nondefault path MTU (Sol N-3)."""

    @classmethod
    def setUpClass(cls):
        cls.bins = Path(os.environ["WINN3_REAL_PROBE_DIR"])
        cls.tmp = Path(tempfile.mkdtemp(prefix="sync-v3-real-"))
        keys = cls.tmp / "keys"
        subprocess.run([str(cls.bins / "winn3-gateway"), "-mode", "keygen", "-out", str(keys)],
                       check=True, capture_output=True, timeout=60)
        name = "cover.lab-mtu-canary.net"
        (cls.tmp / "ech").mkdir()
        subprocess.run([str(cls.bins / "winn-ech-keygen"), "-out", str(cls.tmp / "ech"), "-public-name", name],
                       check=True, capture_output=True, timeout=60)
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-days", "2", "-keyout", str(cls.tmp / "leaf.key"), "-out", str(cls.tmp / "leaf.crt"),
                        "-subj", "/CN=" + name, "-addext", "subjectAltName=DNS:" + name],
                       check=True, capture_output=True, timeout=60)
        import socket
        import threading
        cls.upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cls.upstream.bind(("127.0.0.1", 0))
        cls.upstream.settimeout(0.5)
        cls.stop = False

        def answer():
            while not cls.stop:
                try:
                    query, peer = cls.upstream.recvfrom(2048)
                except OSError:
                    continue
                cls.upstream.sendto(query[:2] + b"\x81\x80" + query[4:6] + b"\x00" * 6 + query[12:], peer)
        cls.thread = threading.Thread(target=answer, daemon=True)
        cls.thread.start()
        cls.gateways = {}
        for label, extra in (("resolver", ["-resolver", "-resolver-upstream",
                                           "127.0.0.1:%d" % cls.upstream.getsockname()[1],
                                           "-resolver-timeout", "2s"]),
                             ("none", [])):
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            journal = cls.tmp / f"replay.{label}.journal"
            journal.write_bytes(b"")
            journal.chmod(0o600)
            env = dict(os.environ, WINN3_REPLAY_JOURNAL=str(journal))
            proc = subprocess.Popen(
                [str(cls.bins / "winn3-gateway"), "-mode", "serve", "-listen", f"127.0.0.1:{port}",
                 "-static", str(keys / "static.key"), "-admission", str(keys / "admission.key"),
                 "-gateway-id", "gw-real", "-inner-v4", "10.10.0.1", "-plan", "udp", "-path-mtu", "1500",
                 "-cert", str(cls.tmp / "leaf.crt"), "-key", str(cls.tmp / "leaf.key"),
                 "-ech-keys", str(cls.tmp / "ech" / "ech-server-keys.json"),
                 "-insecure-cover-reuses-winn-leaf", *extra],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            cls.gateways[label] = (proc, f"127.0.0.1:{port}")
        import time
        time.sleep(2)
        for proc, _ in cls.gateways.values():
            assert proc.poll() is None, "real winn3-gateway exited at start"
        cls.keys = keys

    @classmethod
    def tearDownClass(cls):
        cls.stop = True
        for proc, _ in cls.gateways.values():
            proc.terminate()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=20)
        cls.upstream.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_real(self, gateway_label, path_mtu):
        work = Path(tempfile.mkdtemp(prefix="sync-v3-real-run-"))
        self.addCleanup(shutil.rmtree, work, True)
        wrapper = work / "winn3-probe"
        write_exe(wrapper, REAL_PROBE_WRAPPER)
        dbfile = work / "hub.db"
        with closing(sqlite3.connect(dbfile)) as conn, conn:
            conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY, path_mtu INTEGER, winn3_descriptor_json TEXT)")
            conn.execute("INSERT INTO nodes VALUES ('lab-alpha', ?, ?)",
                         (path_mtu, descriptor_envelope_with_resolver("10.10.0.1")))
        script = heredoc_body(SOURCES["hub"], "cat > /usr/local/bin/wins-gateway-canary <<'EOF'", "EOF")
        driver = CANARY_HARNESS.replace(
            "__FUNCTIONS__", script[script.index("record_winn3_canary() {"):script.index('log "Gateway canary started"')])
        env = base_env(str(work))
        env.update({"DATABASE_PATH": str(dbfile), "WINN3_CANARY_BIN": str(wrapper), "REAL_PROBE_DIR": str(self.bins),
                    "WINN3_CANARY_NODES": entry("lab-alpha", inner="10.10.0.5", key_dir=str(self.keys),
                                                gw=self.gateways[gateway_label][1], gid="gw-real")})
        proc = run_bash(driver, env, str(work))
        with closing(sqlite3.connect(dbfile)) as conn:
            status, error = conn.execute(
                "SELECT winn3_canary_status, winn3_canary_error FROM nodes WHERE slug='lab-alpha'").fetchone()
        return proc, status, error

    def test_a_1500_gateway_passes_only_with_the_served_1500(self):
        proc, status, _ = self.run_real("resolver", 1500)
        self.assertEqual(status, "ok", proc.stdout + proc.stderr)
        proc, status, error = self.run_real("resolver", None)
        self.assertEqual(status, "failed", proc.stdout + proc.stderr)
        self.assertIn("probe returned nonzero", error)

    def test_a_gateway_without_resolver_fails_the_dns_step(self):
        proc, status, error = self.run_real("none", 1500)
        self.assertEqual(status, "failed", proc.stdout + proc.stderr)
        self.assertIn("resolver", error)


# ================= SYNC-15 / SYNC-16: the data-plane report =================

FAKE_SYSTEMCTL = r"""#!/usr/bin/env bash
case "$*" in
  "show winn3-gateway.service -p LoadState --value") printf '%s\n' "${FAKE_LOADSTATE}" ;;
  "is-active winn3-gateway.service") printf '%s\n' "${FAKE_ACTIVE}"; [[ "${FAKE_ACTIVE}" == active ]] ;;
  "show winn3-gateway.service -p ExecStart")
    printf 'ExecStart={ path=/usr/local/bin/winn3-gateway ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n' "$(cat "${FAKE_ARGV_FILE}")" ;;
  *) exit 1 ;;
esac
"""


def gateway_unit_argv(tmp, *, forward="1", resolver="1", plan="udp,tcp", mtu="1450", forward_cidr="10.10.0.0/24"):
    """ExecStart argv exactly as the real gateway installer's emit_unit_text writes it."""
    script = f"""set -euo pipefail
source {json.dumps(str(GATEWAY))}
WINN3_GATEWAY_PATH_MTU={mtu}
WINN3_GATEWAY_PLAN={plan}
WINN3_GATEWAY_FORWARD={forward}
WINN3_GATEWAY_FORWARD_CIDR={forward_cidr}
WINN3_GATEWAY_RESOLVER={resolver}
WINN3_GATEWAY_RESOLVER_UPSTREAM=127.0.0.1:53
WINN3_GATEWAY_RESOLVER_TIMEOUT=2s
emit_unit_text
"""
    env = base_env(tmp)
    env["WINN3_GATEWAY_MEMINFO"] = str(HERE / "testdata" / "winn3_gateway_meminfo" / "large")
    proc = run_bash(script, env, tmp)
    assert proc.returncode == 0, proc.stderr[-2000:]
    lines = proc.stdout.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("ExecStart="))
    parts = []
    for line in lines[start:]:
        text = line[len("ExecStart="):] if line.startswith("ExecStart=") else line
        cont = text.endswith("\\")
        parts.append(text.rstrip("\\").strip())
        if not cont:
            break
    return " ".join(p for p in parts if p)


class DataPlaneGatewayReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sync-v3-report-")
        bindir = Path(self.tmp) / "bin"
        bindir.mkdir()
        write_exe(bindir / "systemctl", FAKE_SYSTEMCTL)
        self.path = f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}"
        register = heredoc_body(SOURCES["data"], "cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
        self.functions = "\n".join(function_definition(register, n) for n in (
            "winn3_gateway_env_value", "winn3_gateway_exec_flag", "winn3_gateway_peer_tier_value",
            "winn3_gateway_report_value"))
        self.register = register
        self.envfile = Path(self.tmp) / "winn3-gateway.env"
        self.envfile.write_text(
            "WINN3_GATEWAY_LISTEN=0.0.0.0:9111\nWINN3_GATEWAY_ID=gw-lab-alpha\n"
            "WINN3_GATEWAY_INNER_V4=10.10.0.1\nWINN3_GATEWAY_FORWARD=1\n"
            "WINN3_GATEWAY_FORWARD_CIDR=10.10.0.0/24\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def report(self, *, loadstate="loaded", active="active", argv=None, **unit):
        argv_file = Path(self.tmp) / "argv"
        argv_file.write_text(argv if argv is not None else gateway_unit_argv(self.tmp, **unit), encoding="utf-8")
        env = base_env(self.tmp)
        env.update({"PATH": self.path, "FAKE_LOADSTATE": loadstate, "FAKE_ACTIVE": active,
                    "FAKE_ARGV_FILE": str(argv_file), "WINN3_GATEWAY_ENV_FILE": str(self.envfile)})
        proc = run_bash("set -Eeuo pipefail\n" + self.functions + "\nwinn3_gateway_report_value\n", env, self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_forwarding_resolver_unit_is_reported_from_the_real_generator(self):
        self.assertEqual(self.report(), {
            "state": "active", "forward": True, "resolver": True, "listen": "0.0.0.0:9111",
            "gateway_id": "gw-lab-alpha", "inner_v4": "10.10.0.1", "forward_cidr": "10.10.0.0/24",
            "plan": "udp,tcp", "path_mtu": 1450,
        })

    def test_reflector_without_resolver_is_reported_as_such(self):
        out = self.report(forward="0", resolver="0", plan="udp", mtu="1400")
        self.assertEqual((out["forward"], out["resolver"], out["plan"], out["path_mtu"]), (False, False, "udp", 1400))

    # ---- round 2 (Sol SYNC-16/N-2): the unit, not the env file ----

    def test_forward_cidr_is_the_one_baked_into_the_unit(self):
        # The env file (setUp) says 10.10.0.0/24; the unit was generated with
        # 10.64.0.0/24 and that is what the gateway runs.
        out = self.report(forward_cidr="10.64.0.0/24")
        self.assertEqual(out["forward_cidr"], "10.64.0.0/24")
        mod = hub()
        row = standalone_with_report(mod, mod.sanitize_winn3_gateway_report(dict(MATCHING_REPORT, **{
            k: out[k] for k in ("forward", "resolver", "forward_cidr")})))
        self.assertIn("winn3_gateway_forward_cidr_differs_from_node_pool", report_blockers(mod, row)[0])

    def test_literal_flags_win_and_references_follow_the_env_file(self):
        argv = gateway_unit_argv(self.tmp).replace("-listen ${WINN3_GATEWAY_LISTEN}", "-listen 0.0.0.0:7000")
        self.assertIn("-listen 0.0.0.0:7000", argv)
        self.assertIn("-gateway-id ${WINN3_GATEWAY_ID}", argv)
        out = self.report(argv=argv)
        self.assertEqual((out["listen"], out["gateway_id"], out["inner_v4"]),
                         ("0.0.0.0:7000", "gw-lab-alpha", "10.10.0.1"))

    def test_absent_and_unknown_units(self):
        self.assertEqual(self.report(loadstate="not-found"), {"state": "absent"})
        self.assertEqual(self.report(loadstate=""), {"state": "unknown"})
        self.assertEqual(self.report(active="failed")["state"], "failed")

    def test_the_hub_accepts_what_the_node_sends(self):
        mod = hub()
        self.assertEqual(mod.sanitize_winn3_gateway_report(self.report()), self.report())

    def test_merge_keeps_the_payload_and_survives_a_bad_report(self):
        start = self.register.index("# SYNC-15/16/22: the reports join the payload here")
        end = self.register.index('registration_response=""', start)
        merge = self.register[start:end]
        base = {"slug": "lab-alpha", "secret_token": "t"}
        for report, expected in (('{"state":"absent"}', {"state": "absent"}), ("not json", None)):
            script = ("set -Eeuo pipefail\n"
                      f"payload={json.dumps(json.dumps(base))}\n"
                      f"winn3_gateway_report={json.dumps(report)}\n"
                      "winn3_identity_ready=true\n"
                      f"winn3_identity_sha256={'a' * 64}\n"
                      "origin_cert_not_after=2028-01-02T03:04:05Z\n"
                      + merge + "\nprintf '%s' \"${payload}\"\n")
            proc = run_bash(script, base_env(self.tmp), self.tmp)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout)
            if expected is None:
                self.assertEqual(out, base)
            else:
                self.assertEqual(out, dict(base, winn3_gateway=expected, winn3_identity_ready=True,
                                           winn3_identity_sha256="a" * 64,
                                           origin_cert_not_after="2028-01-02T03:04:05Z"))

    def served_block(self):
        start = self.register.index('origin_cert_not_after=""\norigin_tls_port=""')
        end = self.register.index("# Load inputs for the per-server load bar", start)
        return self.register[start:end]

    def test_origin_cert_not_after_is_the_certificate_nginx_serves(self):
        # Round 2 (Sol N-1): a renewed file on disk that nginx has not
        # reloaded must not be reported; the served certificate is.
        if not gnu_date_available() or shutil.which("timeout") is None:
            self.skipTest("needs GNU date and coreutils timeout; run on Linux")
        import socket
        import time
        tmp = Path(self.tmp)
        served, disk = tmp / "served.crt", tmp / "disk.crt"
        for cert, days in ((served, 10), (disk, 400)):
            subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", str(days),
                            "-keyout", str(cert) + ".key", "-out", str(cert), "-subj", "/CN=lab-alpha.example.test",
                            "-addext", "subjectAltName=DNS:lab-alpha.example.test"],
                           check=True, capture_output=True, timeout=60)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = subprocess.Popen(["openssl", "s_server", "-quiet", "-accept", f"127.0.0.1:{port}",
                                   "-cert", str(served), "-key", str(served) + ".key"],
                                  stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (server.kill(), server.wait(timeout=20)))
        time.sleep(1)
        env = base_env(self.tmp)
        env.update({"STEALTH_TRANSPORTS": f"80:none,{port}:tls", "STEALTH_HOST": "lab-alpha.example.test",
                    "NODE_ORIGIN_CERT_FILE": str(disk)})
        proc = run_bash("set -Eeuo pipefail\n" + self.served_block() + '\nprintf "%s" "${origin_cert_not_after}"\n',
                        env, self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        left = dt.datetime.strptime(proc.stdout, "%Y-%m-%dT%H:%M:%SZ") - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        self.assertTrue(dt.timedelta(days=9) < left < dt.timedelta(days=11), left)

    def test_no_tls_listener_reports_nothing(self):
        env = base_env(self.tmp)
        env.update({"STEALTH_TRANSPORTS": "80:none", "STEALTH_HOST": "lab-alpha.example.test"})
        proc = run_bash("set -Eeuo pipefail\n" + self.served_block() + '\nprintf "[%s]" "${origin_cert_not_after}"\n',
                        env, self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "[]")


# =================== SYNC-22: the origin certificate timer =================

FAKE_CURL = r"""#!/usr/bin/env python3
import json, subprocess, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
body = [a for a in args if a.startswith("@")]
req = json.load(open(body[-1][1:]))
open(sys.argv[0] + ".calls", "a").write(args[-1] + "\n")
csr = sys.argv[0] + ".csr"
open(csr, "w").write(req["csr"])
cert = subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", "__CA__", "-CAkey", "__CAKEY__",
                       "-days", "400", "-set_serial", "7", "-copy_extensions", "copy"],
                      capture_output=True, text=True, check=True).stdout
json.dump({"ok": True, "certificate": cert}, open(out, "w"))
sys.stdout.write("200")
"""


class _OriginCertSandbox(unittest.TestCase):
    """Shared sandbox for the origin-certificate writers; holds no tests."""
    FUNCTIONS = ("log", "warn", "err", "valid_dns_hostname", "stealth_tls_required", "edge_valid_hub_base",
                 "edge_hub_error_summary", "edge_hub_call", "node_origin_cert_valid", "node_origin_cert_lock",
                 "node_origin_cert_unlock", "node_origin_pair_matches", "node_origin_install_pair",
                 "write_edge_acme_hook", "request_acme_dns_certificate", "request_cloudflare_origin_certificate",
                 "ensure_node_origin_cert", "write_node_origin_cert_renewal")

    def setUp(self):
        if shutil.which("sha256sum") is None:
            self.skipTest("needs sha256sum")
        self.tmp = Path(tempfile.mkdtemp(prefix="sync-v3-renew-"))
        self.root = self.tmp / "root"
        for sub in ("sbin", "systemd", "node-origin", "bin", "letsencrypt", "run"):
            (self.root / sub).mkdir(parents=True)
        self.calls = self.tmp / "calls.log"
        self.nginx_fail = self.tmp / "nginx.fail"
        write_exe(self.root / "bin" / "systemctl", f'#!/usr/bin/env bash\necho "systemctl $*" >> "{self.calls}"\n')
        write_exe(self.root / "bin" / "certbot", f'#!/usr/bin/env bash\necho "certbot $*" >> "{self.calls}"\n')
        write_exe(self.root / "bin" / "nginx",
                  f'#!/usr/bin/env bash\necho "nginx $*" >> "{self.calls}"\n[[ ! -e "{self.nginx_fail}" ]]\n')
        install_flock_if_missing(self.root / "bin")
        # A test CA whose subject names Cloudflare Origin, so node_origin_cert_valid
        # takes its Origin CA branch exactly as for a real Cloudflare issuance.
        self.ca = self.tmp / "ca.pem"
        self.cakey = self.tmp / "ca.key"
        subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "30",
                        "-keyout", str(self.cakey), "-out", str(self.ca),
                        "-subj", "/O=CloudFlare, Inc./CN=CloudFlare Origin Certificate"],
                       check=True, capture_output=True, timeout=60)
        write_exe(self.root / "bin" / "curl",
                  FAKE_CURL.replace("__CA__", str(self.ca)).replace("__CAKEY__", str(self.cakey)))
        self.node_env = self.tmp / "node.env"
        self.node_env.write_text(
            "NODE_SLUG=lab-alpha\nNODE_TOKEN=test-node-token\nHUB_API_BASE=https://hub.example.test\n"
            "STEALTH_HOST=lab-alpha.example.test\nSTEALTH_TRANSPORTS=443:tls\n", encoding="utf-8")
        self.cert = self.root / "node-origin" / "origin.crt"
        self.key = self.root / "node-origin" / "origin.key"
        self.pending = self.root / "node-origin" / ".activation-pending"
        self.lock = self.root / "run" / "lock"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def rewrite(self, text: str) -> str:
        return (text.replace("/usr/local/sbin/wins-node-origin-renew", str(self.root / "sbin" / "wins-node-origin-renew"))
                .replace("install -d -m 755 /usr/local/sbin\n", f"install -d -m 755 {self.root / 'sbin'}\n")
                .replace("/etc/systemd/system/", str(self.root / "systemd") + "/")
                .replace("/etc/winsvpn/node-origin", str(self.root / "node-origin"))
                .replace("/etc/letsencrypt", str(self.root / "letsencrypt"))
                .replace("/run/wins-node-origin.lock", str(self.lock))
                # The deploy hook's own lock wait, bounded so a hook stuck on
                # its caller's lock fails the test in seconds, not ten minutes.
                .replace("flock -w 600 9", f"flock -w {self.HOOK_WAIT} 9"))

    def env(self, **extra):
        env = base_env(str(self.tmp))
        env["PATH"] = f"{self.root / 'bin'}:{env['PATH']}"
        env.update(extra)
        return env

    def installer(self, tail: str, **extra) -> subprocess.CompletedProcess:
        """The shipped installer functions, rewritten to this sandbox, then `tail`."""
        funcs = "\n".join(self.rewrite(function_definition(SOURCES["data"], n)) for n in self.FUNCTIONS)
        script = ("set -Eeuo pipefail\n"
                  f"NODE_ENV_FILE={json.dumps(str(self.node_env))}\n"
                  "CLOUDFLARE_ORIGIN_CA_VALIDITY_DAYS_DEFAULT=730\nACME_CONTACT_EMAIL_DEFAULT=\n"
                  f"WINS_EDGE_ACME_HOOK={json.dumps(str(self.root / 'sbin' / 'wins-edge-acme-hook'))}\n"
                  f"NODE_ORIGIN_CERT_DIR={json.dumps(str(self.root / 'node-origin'))}\n"
                  f"NODE_ORIGIN_CERT_LOCK={json.dumps(str(self.lock))}\n"
                  + funcs + "\n" + tail + "\n")
        return run_bash(script, self.env(**extra), str(self.tmp))

    def install(self):
        proc = self.installer("write_node_origin_cert_renewal")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return self.env()

    def make_pair(self, days: int, stem: str):
        key, cert = self.tmp / f"{stem}.key", self.tmp / f"{stem}.crt"
        cfg = self.tmp / "leaf.cnf"
        cfg.write_text("[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nCN=lab-alpha.example.test\n"
                       "[ext]\nsubjectAltName=DNS:lab-alpha.example.test\n", encoding="utf-8")
        csr = self.tmp / f"{stem}.csr"
        subprocess.run(["openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048", "-keyout", str(key),
                        "-out", str(csr), "-config", str(cfg)], check=True, capture_output=True, timeout=60)
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.ca), "-CAkey", str(self.cakey),
                        "-days", str(days), "-set_serial", "3", "-copy_extensions", "copy", "-out", str(cert)],
                       check=True, capture_output=True, timeout=60)
        return cert, key

    def issue(self, days: int) -> str:
        cert, key = self.make_pair(days, "issued")
        shutil.copyfile(key, self.key)
        shutil.copyfile(cert, self.cert)
        return self.sha(self.cert)

    @staticmethod
    def sha(path) -> str:
        return subprocess.run(["sha256sum", str(path)], capture_output=True, text=True, check=True).stdout.split()[0]

    def pair_matches(self) -> bool:
        pub = lambda args: subprocess.run(args, capture_output=True, check=True).stdout
        cert_pub = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                                  input=pub(["openssl", "x509", "-in", str(self.cert), "-pubkey", "-noout"]),
                                  capture_output=True, check=True).stdout
        return cert_pub == pub(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"])

    def run_timer_script(self, env, **extra):
        script = self.root / "sbin" / "wins-node-origin-renew"
        clean = {k: v for k, v in env.items() if k in ("PATH", "HOME", "LC_ALL")}
        clean.update(extra)
        return subprocess.run([BASH, str(script)], env=clean, capture_output=True, text=True, timeout=180)

    def calls_text(self) -> str:
        return self.calls.read_text(encoding="utf-8") if self.calls.exists() else ""

    def hub_calls(self) -> list:
        path = self.root / "bin" / "curl.calls"
        return path.read_text(encoding="utf-8").split() if path.exists() else []

    HOOK_WAIT = 5
    HOOK_PATH_IN_SOURCE = "/etc/letsencrypt/renewal-hooks/deploy/winsvpn-node-origin"

    def hook_path(self) -> Path:
        return Path(self.rewrite(self.HOOK_PATH_IN_SOURCE))

    def write_hook(self) -> str:
        """Run the shipped hook writer (the block inside request_acme_dns_certificate)."""
        acme = self.rewrite(function_definition(SOURCES["data"], "request_acme_dns_certificate"))
        marker = "  {\n    printf '#!/usr/bin/env bash\\n'"
        if marker not in acme:
            # The Round 2 writer (a bare heredoc), so a fail-before run
            # exercises the hook that tree actually ships.
            marker = "  cat > \"${hook}\" <<'HOOK'\n"
        start = acme.index(marker)
        end = acme.index("  chmod 750 \"${hook}\"\n", start)
        path = self.hook_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        proc = self.installer(f"hook={json.dumps(str(path))}\n" + acme[start:end] + '  chmod 750 "${hook}"\n')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return path.read_text(encoding="utf-8")

    def inject_mv_failure(self, basename):
        """mv that exits 73 when its destination is the named live file."""
        real = shutil.which("mv")
        write_exe(self.root / "bin" / "mv",
                  "#!/usr/bin/env bash\n"
                  'case "${@: -1}" in */%s) echo "mv: injected failure" >&2; exit 73 ;; esac\n'
                  'exec %s "$@"\n' % (basename, real))

    def leftovers(self):
        return sorted(p.name for p in (self.root / "node-origin").iterdir()
                      if p.name not in ("origin.crt", "origin.key", ".activation-pending"))

    def shim(self, tool, condition, action='echo "%s: injected failure" >&2; exit 73'):
        """`tool` that runs `action` instead of itself while the bash `condition` holds over its arguments."""
        real = shutil.which(tool)
        write_exe(self.root / "bin" / tool,
                  "#!/usr/bin/env bash\n"
                  f"if {condition}; then {action % tool if '%s' in action else action}; fi\n"
                  f'exec {real} "$@"\n')

    def commit(self, cert, key) -> subprocess.CompletedProcess:
        """node_origin_install_pair onto the live pair, called the way every caller calls it."""
        return self.installer(f"rc=0\nnode_origin_install_pair {json.dumps(str(cert))} {json.dumps(str(key))} "
                              f"{json.dumps(str(self.cert))} {json.dumps(str(self.key))} || rc=$?\n"
                              'exit "${rc}"')

    def hold_lock(self):
        ready = self.tmp / "holder.ready"
        holder = subprocess.Popen([sys.executable, "-c", (
            "import fcntl, os, sys, time\n"
            f"fd = os.open({str(self.lock)!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            f"open({str(ready)!r}, 'w').close()\n"
            "time.sleep(60)\n")])
        self.addCleanup(lambda: (holder.kill(), holder.wait(timeout=20)))
        import time
        for _ in range(200):
            if ready.exists():
                break
            time.sleep(0.05)
        self.assertTrue(ready.exists())
        return holder


class OriginCertRenewalTests(_OriginCertSandbox):

    def test_units_and_script_are_written_and_the_timer_enabled(self):
        # write_nginx has just restarted nginx on the pair: its activation is done.
        self.pending.write_text("", encoding="utf-8")
        self.install()
        self.assertFalse(self.pending.exists())
        unit = (self.root / "systemd" / "wins-node-origin-renew.timer").read_text(encoding="utf-8")
        self.assertIn("OnCalendar=weekly", unit)
        self.assertIn("Persistent=true", unit)
        service = (self.root / "systemd" / "wins-node-origin-renew.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=" + str(self.root / "sbin" / "wins-node-origin-renew"), service)
        self.assertIn("systemctl enable --now wins-node-origin-renew.timer", self.calls_text())
        mode = (self.root / "sbin" / "wins-node-origin-renew").stat().st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_a_valid_certificate_is_left_alone(self):
        env = self.install()
        before = self.issue(200)
        proc = self.run_timer_script(env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(before, self.sha(self.cert))
        self.assertNotIn("nginx", self.calls_text())

    def test_an_expiring_certificate_is_renewed_and_nginx_reloaded(self):
        env = self.install()
        before = self.issue(10)
        proc = self.run_timer_script(env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertNotEqual(before, self.sha(self.cert))
        check = subprocess.run(["openssl", "x509", "-in", str(self.cert), "-noout", "-checkend", str(300 * 86400)],
                               capture_output=True, timeout=30)
        self.assertEqual(check.returncode, 0, "renewed certificate is not valid for 300 more days")
        self.assertTrue(self.pair_matches())
        self.assertIn("nginx -t", self.calls_text())
        self.assertIn("systemctl reload nginx.service", self.calls_text())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.hub_calls(), ["https://hub.example.test/api/v1/nodes/lab-alpha/edge/origin-certificate"])

    # ---- round 2 (Sol N-1): a failed reload is retried ----

    def test_a_failed_reload_is_retried_on_the_next_run(self):
        env = self.install()
        before = self.issue(10)
        self.nginx_fail.write_text("", encoding="utf-8")
        first = self.run_timer_script(env)
        self.assertNotEqual(first.returncode, 0)
        self.assertNotEqual(before, self.sha(self.cert))      # renewed on disk
        self.assertTrue(self.pending.exists())                # not yet served
        self.assertNotIn("systemctl reload", self.calls_text())
        self.nginx_fail.unlink()
        self.calls.unlink()
        second = self.run_timer_script(env)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("nginx -t", self.calls_text())
        self.assertIn("systemctl reload nginx.service", self.calls_text())
        self.assertFalse(self.pending.exists())
        self.assertEqual(len(self.hub_calls()), 1)            # no second issuance

    # ---- round 2 (Sol OI-SYNC_V3-6): one lock for every writer ----

    def test_the_installer_and_the_timer_take_the_same_lock(self):
        env = self.install()
        before = self.issue(10)
        ready = self.tmp / "holder.ready"
        holder = subprocess.Popen([sys.executable, "-c", (
            "import fcntl, os, sys, time\n"
            f"fd = os.open({str(self.lock)!r}, os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            f"open({str(ready)!r}, 'w').close()\n"
            "time.sleep(60)\n")])
        self.addCleanup(lambda: (holder.kill(), holder.wait(timeout=20)))
        for _ in range(200):
            if ready.exists():
                break
            import time
            time.sleep(0.05)
        self.assertTrue(ready.exists())
        timer = self.run_timer_script(env, NODE_ORIGIN_CERT_LOCK_WAIT="1")
        self.assertNotEqual(timer.returncode, 0)
        installer = self.installer("ensure_node_origin_cert", NODE_ORIGIN_CERT_LOCK_WAIT="1")
        self.assertNotEqual(installer.returncode, 0)
        self.assertIn("holds", installer.stderr)
        self.assertEqual(before, self.sha(self.cert))
        self.assertEqual(self.hub_calls(), [])
        holder.kill()
        holder.wait(timeout=20)
        installer = self.installer("ensure_node_origin_cert", NODE_ORIGIN_CERT_LOCK_WAIT="1")
        self.assertEqual(installer.returncode, 0, installer.stdout + installer.stderr)
        self.assertNotEqual(before, self.sha(self.cert))
        self.assertTrue(self.pair_matches())
        self.assertTrue(self.pending.exists())                # the installer's restart clears it

    def test_the_certbot_hook_takes_the_lock_and_keeps_pending_until_reload(self):
        source = SOURCES["data"]
        hook = self.write_hook()
        installer_lock = re.search(r'(?m)^NODE_ORIGIN_CERT_LOCK="([^"]+)"$', source).group(1)
        self.assertEqual(installer_lock, "/run/wins-node-origin.lock")
        self.assertIn(f"exec 9>{self.lock}\nif ! flock -w {self.HOOK_WAIT} 9; then\n", hook)
        lineage = self.root / "letsencrypt" / "live" / "winsvpn-node-origin"
        lineage.mkdir(parents=True)
        cert, key = self.make_pair(90, "acme")
        shutil.copyfile(cert, lineage / "fullchain.pem")
        shutil.copyfile(key, lineage / "privkey.pem")
        self.issue(200)
        path = self.hook_path()
        self.nginx_fail.write_text("", encoding="utf-8")
        failed = subprocess.run([BASH, str(path)], env=self.env(RENEWED_LINEAGE=str(lineage)),
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.sha(self.cert), self.sha(lineage / "fullchain.pem"))
        self.assertTrue(self.pair_matches())
        self.assertTrue(self.pending.exists())
        self.nginx_fail.unlink()
        done = subprocess.run([BASH, str(path)], env=self.env(RENEWED_LINEAGE=str(lineage)),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse(self.pending.exists())
        self.assertIn("systemctl reload nginx.service", self.calls_text())
        self.assertEqual(sorted(p.name for p in (self.root / "node-origin").iterdir()), ["origin.crt", "origin.key"])

    # ---- round 3 (Sol N-1): the hook checks the staged pair first ----

    def test_the_certbot_hook_refuses_a_mismatched_lineage(self):
        self.write_hook()
        lineage = self.root / "letsencrypt" / "live" / "winsvpn-node-origin"
        lineage.mkdir(parents=True)
        cert_a, _ = self.make_pair(90, "lin-a")
        _, key_b = self.make_pair(90, "lin-b")
        shutil.copyfile(cert_a, lineage / "fullchain.pem")
        shutil.copyfile(key_b, lineage / "privkey.pem")
        self.issue(200)
        before = (self.sha(self.cert), self.sha(self.key))
        proc = subprocess.run([BASH, str(self.hook_path())], env=self.env(RENEWED_LINEAGE=str(lineage)),
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("did not stage as a matching pair", proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertFalse(self.pending.exists())
        self.assertNotIn("nginx", self.calls_text())
        self.assertEqual(sorted(p.name for p in (self.root / "node-origin").iterdir()), ["origin.crt", "origin.key"])

    # ---- round 3 (Sol N-2 / Seat C N-3): a hook run inside a locked writer ----

    def test_the_hook_leaves_the_commit_to_a_writer_that_holds_the_lock(self):
        import time
        self.write_hook()
        lineage = self.root / "letsencrypt" / "live" / "winsvpn-node-origin"
        lineage.mkdir(parents=True)
        cert, key = self.make_pair(90, "acme")
        shutil.copyfile(cert, lineage / "fullchain.pem")
        shutil.copyfile(key, lineage / "privkey.pem")
        self.issue(200)
        before = (self.sha(self.cert), self.sha(self.key))
        self.hold_lock()
        started = time.time()
        proc = subprocess.run([BASH, str(self.hook_path())],
                              env=self.env(RENEWED_LINEAGE=str(lineage), WINS_NODE_ORIGIN_LOCK_HELD="1"),
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertLess(time.time() - started, self.HOOK_WAIT)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertNotIn("nginx", self.calls_text())

    # ---- round 4 (Sol N-6): every rename is checked ----

    def test_a_failed_key_rename_leaves_the_live_pair_and_fails(self):
        self.issue(10)                                   # due: Origin CA re-issues
        before = (self.sha(self.cert), self.sha(self.key))
        self.inject_mv_failure("origin.key")
        proc = self.installer("ensure_node_origin_cert")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertTrue(self.pair_matches())
        self.assertFalse(self.pending.exists())          # nothing changed, so nothing is owed
        self.assertEqual(self.leftovers(), [])
        self.assertIn("new origin key into place", proc.stdout + proc.stderr)

    def test_a_failed_certificate_rename_restores_the_previous_key_and_fails(self):
        self.issue(10)
        before = (self.sha(self.cert), self.sha(self.key))
        self.inject_mv_failure("origin.crt")
        proc = self.installer("ensure_node_origin_cert")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertTrue(self.pair_matches())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.leftovers(), [])
        self.assertIn("previous key was restored", proc.stdout + proc.stderr)

    def test_a_failed_rename_keeps_an_activation_that_was_already_owed(self):
        self.issue(10)
        self.pending.write_text("", encoding="utf-8")     # an earlier commit not yet reloaded
        self.inject_mv_failure("origin.key")
        proc = self.installer("ensure_node_origin_cert")
        self.assertNotEqual(proc.returncode, 0)
        self.assertTrue(self.pending.exists())

    def test_the_hook_commits_through_the_same_checked_pair_install(self):
        hook = self.write_hook()
        self.assertIn("node_origin_install_pair ()", hook)
        self.assertNotIn("mv -f -- \"${tmp_key}\" \"${dir}/origin.key\"", hook)
        lineage = self.root / "letsencrypt" / "live" / "winsvpn-node-origin"
        lineage.mkdir(parents=True)
        cert, key = self.make_pair(90, "acme")
        shutil.copyfile(cert, lineage / "fullchain.pem")
        shutil.copyfile(key, lineage / "privkey.pem")
        self.issue(200)
        before = (self.sha(self.cert), self.sha(self.key))
        self.inject_mv_failure("origin.crt")
        proc = subprocess.run([BASH, str(self.hook_path())], env=self.env(RENEWED_LINEAGE=str(lineage)),
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertTrue(self.pair_matches())
        self.assertFalse(self.pending.exists())
        self.assertNotIn("nginx", self.calls_text())
        self.assertEqual(self.leftovers(), [])

    def test_a_mismatched_pair_is_never_committed(self):
        self.issue(200)
        before_cert, before_key = self.sha(self.cert), self.sha(self.key)
        cert_a, _ = self.make_pair(200, "a")
        _, key_b = self.make_pair(200, "b")
        proc = self.installer(f"node_origin_install_pair {json.dumps(str(cert_a))} {json.dumps(str(key_b))} "
                              f"{json.dumps(str(self.cert))} {json.dumps(str(self.key))}")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), (before_cert, before_key))
        self.assertFalse(self.pending.exists())
        self.assertEqual(sorted(p.name for p in (self.root / "node-origin").iterdir()), ["origin.crt", "origin.key"])

    def test_a_torn_pair_is_reissued_and_activated(self):
        # A crash between the key rename and the certificate rename leaves a
        # new key beside the old certificate; the next run repairs it.
        env = self.install()
        self.issue(200)
        _, other_key = self.make_pair(200, "other")
        shutil.copyfile(other_key, self.key)
        self.assertFalse(self.pair_matches())
        proc = self.run_timer_script(env)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.pair_matches())
        self.assertIn("systemctl reload nginx.service", self.calls_text())
        self.assertEqual(len(self.hub_calls()), 1)

    # ---- follow-up 2026-10-01 (Seat C N-7): one pin per commit branch ----

    def test_a_pending_mark_that_cannot_be_written_aborts_the_commit(self):
        # X1: a dangling link into a missing directory, so `: >` really fails.
        self.issue(200)
        before = (self.sha(self.cert), self.sha(self.key))
        cert, key = self.make_pair(200, "new")
        os.symlink(self.tmp / "no-such-dir" / "pending", self.pending)
        proc = self.commit(cert, key)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Could not mark the origin certificate activation pending", proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertTrue(self.pair_matches())
        self.assertEqual(self.leftovers(), [])

    def test_a_kept_copy_that_cannot_be_made_aborts_the_commit(self):
        # X2: mktemp fails, cp fails, cp writes part of the key then fails.
        prev = '[[ "${@: -1}" == */.origin.key.prev.* ]]'
        cases = {"mktemp": ("mktemp", prev, None), "cp": ("cp", prev, None),
                 "cp partial": ("cp", prev, 'printf 0123456789 > "${@: -1}"; exit 73')}
        cert, key = self.make_pair(200, "new")
        for name, (tool, condition, action) in cases.items():
            with self.subTest(name):
                for path in (self.root / "bin" / "mktemp", self.root / "bin" / "cp"):
                    path.unlink(missing_ok=True)
                self.issue(200)
                before = (self.sha(self.cert), self.sha(self.key))
                if action is None:
                    self.shim(tool, condition)
                else:
                    self.shim(tool, condition, action)
                proc = self.commit(cert, key)
                self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn("Could not keep a copy of the live origin key", proc.stderr)
                self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
                self.assertFalse(self.pending.exists())
                self.assertEqual(self.leftovers(), [])

    def test_a_failed_first_install_removes_the_new_key_again(self):
        # X3: no live pair, so there is no kept copy to restore.
        cert, key = self.make_pair(200, "new")
        self.inject_mv_failure("origin.crt")
        proc = self.commit(cert, key)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the new key was removed again", proc.stderr)
        self.assertFalse(self.key.exists())
        self.assertFalse(self.cert.exists())
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.leftovers(), [])

    def tear(self):
        """A double fault: the certificate rename fails and so does the restore of the kept key."""
        self.issue(200)
        retired = self.sha(self.key)
        cert, key = self.make_pair(200, "new")
        self.shim("mv", '[[ "${@: -1}" == */origin.crt || ( "${@: -1}" == */origin.key '
                        '&& "${@: -2:1}" == */.origin.key.prev.* ) ]]')
        proc = self.commit(cert, key)
        (self.root / "bin" / "mv").unlink()
        return proc, retired

    def test_a_double_fault_is_reported_torn_and_the_next_run_repairs_it(self):
        # X4 (the torn branch returns failure) and X11 (a failed restore is
        # never reported as restored).
        proc, retired = self.tear()
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the previous key could not be restored; the live pair is torn", proc.stderr)
        self.assertNotIn("was restored", proc.stderr)
        self.assertFalse(self.pair_matches())
        self.assertTrue(self.pending.exists())                  # the reload stays owed
        kept = [name for name in self.leftovers() if name.startswith(".origin.key.prev.")]
        self.assertEqual(len(kept), 1, self.leftovers())         # the only copy of the retired key
        self.assertEqual(self.sha(self.root / "node-origin" / kept[0]), retired)
        repair = self.installer("ensure_node_origin_cert")
        self.assertEqual(repair.returncode, 0, repair.stdout + repair.stderr)
        self.assertTrue(self.pair_matches())
        self.assertTrue(self.pending.exists())

    def test_the_self_signed_branch_fails_when_its_commit_fails(self):
        # X8: no TLS transport and a torn live pair take the self-signed branch.
        self.node_env.write_text(self.node_env.read_text(encoding="utf-8")
                                 .replace("STEALTH_TRANSPORTS=443:tls", "STEALTH_TRANSPORTS=443:reality"),
                                 encoding="utf-8")
        self.issue(200)
        _, other = self.make_pair(200, "other")
        shutil.copyfile(other, self.key)
        before = (self.sha(self.cert), self.sha(self.key))
        self.inject_mv_failure("origin.key")
        proc = self.installer("ensure_node_origin_cert")
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("new origin key into place", proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertEqual(self.leftovers(), [])

    # ---- follow-up 2026-10-01 (Seat C O2): the first-install torn message ----

    def test_a_first_install_double_fault_names_the_new_key(self):
        cert, key = self.make_pair(200, "new")
        self.inject_mv_failure("origin.crt")
        self.shim("rm", '[[ "${@: -1}" == */origin.key ]]')
        proc = self.commit(cert, key)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("the new key could not be removed again; the live pair is torn", proc.stderr)
        self.assertNotIn("previous key", proc.stderr)

    # ---- follow-up 2026-10-01 (Seat C O1): stray kept copies are swept ----

    def strays_and_decoys(self):
        d = self.root / "node-origin"
        strays = [d / ".origin.key.prev.AbC123", d / ".origin.key.prev.x"]
        for path in strays:
            shutil.copyfile(self.key, path)
            path.chmod(0o600)
        target = self.tmp / "outside.key"
        target.write_text("outside\n", encoding="utf-8")
        decoys = [d / ".origin.key.keep", d / "origin.key.prev.1", d / ".origin.crt.prev.1"]
        for path in decoys:
            path.write_text("decoy\n", encoding="utf-8")
        link = d / ".origin.key.prev.link"
        os.symlink(target, link)
        subdir = d / ".origin.key.prev.d"
        subdir.mkdir()
        return strays, decoys + [link, subdir, target]

    def test_a_verified_commit_sweeps_stray_kept_key_copies(self):
        self.issue(200)
        strays, keep = self.strays_and_decoys()
        cert, key = self.make_pair(200, "new")
        proc = self.commit(cert, key)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.pair_matches())
        self.assertEqual([p.name for p in strays if os.path.lexists(p)], [])
        self.assertEqual([p.name for p in keep if not os.path.lexists(p)], [])

    def test_a_commit_that_does_not_verify_keeps_the_stray_copies(self):
        # An mv that reports success without moving the certificate leaves a
        # pair that does not match: nothing is swept.
        self.issue(200)
        strays, _ = self.strays_and_decoys()
        cert, key = self.make_pair(200, "new")
        self.shim("mv", '[[ "${@: -1}" == */origin.crt ]]', "exit 0")
        self.commit(cert, key)
        self.assertFalse(self.pair_matches())
        self.assertEqual([p.name for p in strays if not p.exists()], [])

    def test_the_repair_run_sweeps_the_copy_a_double_fault_left(self):
        proc, _ = self.tear()
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(len(self.leftovers()), 1, self.leftovers())
        repair = self.installer("ensure_node_origin_cert")
        self.assertEqual(repair.returncode, 0, repair.stdout + repair.stderr)
        self.assertTrue(self.pair_matches())
        self.assertEqual(self.leftovers(), [])


CURL_DENIED = r"""#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
out = args[args.index("-o") + 1]
open(sys.argv[0] + ".calls", "a").write(args[-1] + "\n")
json.dump({"ok": False, "detail": "Origin CA issuance denied"}, open(out, "w"))
sys.stdout.write("403")
"""

# certbot's directory deploy hooks, as its SOURCE runs them (round 4, Seat C
# N-6; read at tags v2.9.0 and v4.0.0, 2026-09-30):
#   * certonly on an EXISTING lineage that is due goes main._get_and_save_cert
#     -> renewal.renew_cert -> hooks.renew_hook, which runs every executable in
#     renewal-hooks/deploy gated only on config.directory_hooks: certbot 2.9.0
#     (Ubuntu 24.04) does it, not only 3.2 and later;
#   * certonly on a NEW lineage runs hooks.deploy_hook, which runs no
#     directory hook until 5.3.0 (CHANGELOG 2026-02-03);
#   * --no-directory-hooks sets directory_hooks False (defined in 2.9.0);
#   * a dry run runs no deploy hook; a failing hook does not fail certbot.
# "flag_ignored" is a certbot that runs the hooks anyway, which is what the
# lock marker guards.
CERTBOT_STUB = r"""#!/usr/bin/env bash
echo "certbot $*" >> "__CALLS__"
verb="$1"
lineage="__LE__/live/winsvpn-node-origin"
hosts=()
prev=""
for arg in "$@"; do [[ "${prev}" == "-d" ]] && hosts+=("${arg}"); prev="${arg}"; done
existing=0
[[ -s "${lineage}/fullchain.pem" ]] && existing=1
if [[ "${verb}" == certonly ]]; then
  mkdir -p "${lineage}"
  { printf '[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nCN=%s\n[ext]\nsubjectAltName=' "${hosts[0]}"
    sep=""; for h in "${hosts[@]}"; do printf '%sDNS:%s' "${sep}" "${h}"; sep=","; done; printf '\n'; } > "${lineage}/req.cnf"
  openssl req -new -nodes -newkey rsa:2048 -keyout "${lineage}/privkey.pem" -out "${lineage}/req.csr" -config "${lineage}/req.cnf" >/dev/null 2>&1
  openssl x509 -req -in "${lineage}/req.csr" -CA "__CA__" -CAkey "__CAKEY__" -days 90 -set_serial 9 \
    -copy_extensions copy -out "${lineage}/fullchain.pem" >/dev/null 2>&1
fi
run=0
case "${CERTBOT_STUB_MODE:-certbot_2_9}" in
  certbot_2_9) [[ "${verb}" == renew || ( "${verb}" == certonly && ${existing} == 1 ) ]] && run=1 ;;
  certbot_5_3|flag_ignored) run=1 ;;
esac
[[ " $* " == *" --dry-run "* ]] && run=0
if [[ "${CERTBOT_STUB_MODE:-certbot_2_9}" != flag_ignored && " $* " == *" --no-directory-hooks "* ]]; then run=0; fi
if (( run )); then
  for hook in "__LE__/renewal-hooks/deploy/"*; do
    [[ -x "${hook}" ]] || continue
    started=$(date +%s)
    rc=0
    RENEWED_LINEAGE="${lineage}" "${hook}" || rc=$?
    echo "hook $(basename "${hook}") rc=${rc} waited=$(( $(date +%s) - started ))s" >> "__CALLS__"
  done
fi
exit 0
"""


class OriginCertAcmeTests(_OriginCertSandbox):
    """Rounds 3 and 4: the ACME fallback run by a writer that holds the origin lock."""

    def arm(self, mode, existing_lineage):
        write_exe(self.root / "bin" / "curl", CURL_DENIED)
        write_exe(self.root / "bin" / "certbot",
                  CERTBOT_STUB.replace("__CALLS__", str(self.calls)).replace("__LE__", str(self.root / "letsencrypt"))
                  .replace("__CA__", str(self.ca)).replace("__CAKEY__", str(self.cakey)))
        self.write_hook()            # the hook an earlier ACME install left behind
        if existing_lineage:
            # ...beside the lineage that install created, now due (10 days):
            # certonly takes certbot's renewal path for it.
            lineage = self.root / "letsencrypt" / "live" / "winsvpn-node-origin"
            lineage.mkdir(parents=True, exist_ok=True)
            cert, key = self.make_pair(10, "old-lineage")
            shutil.copyfile(cert, lineage / "fullchain.pem")
            shutil.copyfile(key, lineage / "privkey.pem")
            self.before_lineage = self.sha(lineage / "fullchain.pem")
        self.issue(10)               # the live pair, due for renewal
        return {"CERTBOT_STUB_MODE": mode}

    def lineage_sha(self):
        return self.sha(self.root / "letsencrypt" / "live" / "winsvpn-node-origin" / "fullchain.pem")

    def hook_lines(self):
        return [line for line in self.calls_text().splitlines() if line.startswith("hook ")]

    def certbot_lines(self):
        return [line for line in self.calls_text().splitlines() if line.startswith("certbot ")]

    def check_committed(self, proc, elapsed):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertLess(elapsed, self.HOOK_WAIT, self.hook_lines())
        self.assertEqual([line for line in self.hook_lines() if " rc=0 " not in line + " "], [])
        self.assertEqual(self.sha(self.cert), self.lineage_sha())
        self.assertTrue(self.pair_matches())
        self.assertTrue(self.pending.exists())

    def run_installer(self, mode, existing_lineage=True):
        import time
        extra = self.arm(mode, existing_lineage)
        started = time.time()
        proc = self.installer("ensure_node_origin_cert", **extra)
        return proc, time.time() - started

    def test_certbot_2_9_renewing_the_existing_lineage_runs_no_hook(self):
        # Ubuntu 24.04's certbot: the normal case on a node whose first ACME
        # install wrote the hook (Seat C N-6). Round 2 stalled here.
        proc, elapsed = self.run_installer("certbot_2_9", existing_lineage=True)
        self.check_committed(proc, elapsed)
        self.assertNotEqual(self.lineage_sha(), self.before_lineage)     # it did renew
        self.assertEqual(self.hook_lines(), [])
        self.assertTrue(self.certbot_lines())
        for line in self.certbot_lines():
            self.assertIn("--no-directory-hooks", line)

    def test_certbot_2_9_new_lineage_runs_no_hook_either_way(self):
        # Control: a new lineage takes hooks.deploy_hook, which runs no
        # directory hook before 5.3.
        proc, elapsed = self.run_installer("certbot_2_9", existing_lineage=False)
        self.check_committed(proc, elapsed)
        self.assertEqual(self.hook_lines(), [])

    def test_certbot_5_3_new_lineage_is_told_not_to_run_directory_hooks(self):
        proc, elapsed = self.run_installer("certbot_5_3", existing_lineage=False)
        self.check_committed(proc, elapsed)
        self.assertEqual(self.hook_lines(), [])
        for line in self.certbot_lines():
            self.assertIn("--no-directory-hooks", line)

    def test_a_hook_run_anyway_sees_the_lock_marker_and_returns_at_once(self):
        proc, elapsed = self.run_installer("flag_ignored", existing_lineage=True)
        self.check_committed(proc, elapsed)
        self.assertEqual(len(self.hook_lines()), 1, self.hook_lines())    # certonly; the dry run runs none
        self.assertTrue(all(" rc=0 " in line + " " for line in self.hook_lines()))

    def test_the_weekly_timer_renews_with_certbot_2_9_without_waiting_on_itself(self):
        import time
        env = self.install()
        extra = self.arm("certbot_2_9", existing_lineage=True)
        started = time.time()
        proc = self.run_timer_script(env, **extra)
        self.check_committed_timer(proc, time.time() - started)

    def check_committed_timer(self, proc, elapsed):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertLess(elapsed, self.HOOK_WAIT)
        self.assertEqual(self.hook_lines(), [])
        self.assertEqual(self.sha(self.cert), self.lineage_sha())
        self.assertFalse(self.pending.exists())                     # the timer reloaded
        self.assertIn("systemctl reload nginx.service", self.calls_text())

    def test_the_marker_leaves_with_the_lock(self):
        proc = self.installer('node_origin_cert_lock\nprintf "held=%s\\n" "${WINS_NODE_ORIGIN_LOCK_HELD:-}"\n'
                              'node_origin_cert_unlock\nprintf "after=%s\\n" "${WINS_NODE_ORIGIN_LOCK_HELD:-}"\n'
                              'bash -c \'printf "child=%s\\n" "${WINS_NODE_ORIGIN_LOCK_HELD:-}"\'')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split(), ["held=1", "after=", "child="])


    def test_a_failed_commit_of_the_acme_lineage_fails_the_install(self):
        # Follow-up 2026-10-01 (Seat C N-7, X10): the ACME caller's commit.
        extra = self.arm("certbot_2_9", existing_lineage=True)
        before = (self.sha(self.cert), self.sha(self.key))
        self.inject_mv_failure("origin.key")
        proc = self.installer("ensure_node_origin_cert", **extra)
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("new origin key into place", proc.stderr)
        self.assertEqual((self.sha(self.cert), self.sha(self.key)), before)
        self.assertFalse(self.pending.exists())
        self.assertEqual(self.leftovers(), [])


class OriginCertRenewalWiringTests(unittest.TestCase):
    def test_report_block_stays_outside_the_ld2_load_block(self):
        # server/test_node_load_congestion_ld2.sh cuts the register script
        # from the load-bar comment to the provenance comment and runs that
        # span alone; the gateway report must not ride into it.
        register = heredoc_body(SOURCES["data"], "cat > /usr/local/bin/wins-node-register <<'EOF'", "EOF")
        start = register.index("# Load inputs for the per-server load bar")
        end = register.index("# Data-plane code provenance, recomputed", start)
        self.assertNotIn("winn3_gateway_report_value", register[start:end])
        self.assertNotIn("origin_cert_not_after", register[start:end])

    def test_main_installs_the_timer_after_nginx(self):
        main = function_definition(SOURCES["data"], "main")
        self.assertIn("  write_nginx\n  write_node_origin_cert_renewal\n", main)


if __name__ == "__main__":
    unittest.main(verbosity=2)
