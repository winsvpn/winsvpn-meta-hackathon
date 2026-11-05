#!/usr/bin/env python3
"""Slice H5 (design 3.15, ruling E): the AWG carrying canary on the hub.

Every test runs the REAL source extracted from the ONETOUCH control-plane
installer: the hub app (main.py heredoc) against temporary SQLite files, the
carrying probe (wins_node_dataplane_probe.py heredoc, `--carry` mode) with a
fake userspace client and a fake WebSocket/VLESS node, and the installer's own
key and env functions under bash with a fake `wg`. Nothing contacts a node, a
hub or the network. Every key here is a throwaway drawn from os.urandom.

Covered (design 5.5 "Off-node and AWG canary", section 3.15, 5.6 mutants):
  * node_admits_peer admits ONLY the exact canary peer on a closed node and
    still refuses a customer device and a Core exit peer;
  * allocate_core_exit_ip never returns .1, even if the range ever starts at 1;
  * the carry columns, the 600 s / 120 s cadence, the system peer push and the
    fact that a failed carry proof never closes an open node;
  * the probe verdict is a validated DNS reply carried through the tunnel;
  * the installer creates one hub key, keeps it, and writes only the public half;
  * the installer never writes key or secret material through a link the hub
    app planted in a directory it can write (canary key and record names, the
    legacy env mirror, the hub SSH key, the database and its backup name).

Mutants (5.6) are applied to the extracted source and each must be KILLED.

Run:  python3 server/test_hub_awg_carry_canary_h5.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import socket
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness

HERE = Path(__file__).resolve().parent
HUB_INSTALLER = HERE / "wins_control_plane_setup_ONETOUCH.sh"
# The probe heredoc, wherever the installer writes it (H0 moves it out of APP_DIR).
PROBE_HEAD = re.compile(r"cat > \S*wins_node_dataplane_probe\.py\S* <<'DPPROBEEOF'\n")
BASH = os.environ.get("WINS_TEST_BASH") or shutil.which("bash")
for _candidate in (os.path.expanduser("~/.homebrew/Homebrew/bin/bash"), "/opt/homebrew/bin/bash"):
    if os.path.exists(_candidate):
        BASH = _candidate
        break


def throwaway_key():
    return base64.b64encode(os.urandom(32)).decode()


CANARY = throwaway_key()
OTHER = throwaway_key()
CORE_KEY = throwaway_key()
EXACT = "10.8.255.1/32"
NODE_KEY = throwaway_key()
XRAY_UUID = "00000000-0000-4000-8000-0000000000aa"
OBFUSCATION = json.dumps({"Jc": 4, "Jmin": 8, "Jmax": 80, "S1": 15, "S2": 20, "H1": 1, "H2": 2, "H3": 3, "H4": 4})


def quiet(mod):
    for handler in list(mod.logger.handlers):
        handler.close()
        mod.logger.removeHandler(handler)
    mod.logger.addHandler(logging.NullHandler())
    mod.logger.propagate = False


def hub_source():
    return HUB_INSTALLER.read_text(encoding="utf-8")


def load_hub(source=None, canary=CANARY):
    """The real hub, optionally from mutated source."""
    original = harness._extract_main_block
    if source is not None:
        def extract():
            lines = source.split("\n")
            for i, line in enumerate(lines):
                if re.search(r"<<'PYEOF'", line) and "main.py" in line:
                    j = i + 1
                    while lines[j] != "PYEOF":
                        j += 1
                    return "\n".join(lines[i + 1:j]) + "\n"
            raise RuntimeError("main.py heredoc not found")
        harness._extract_main_block = extract
    try:
        mod = harness.load_hub()
    finally:
        harness._extract_main_block = original
    quiet(mod)
    mod.AWG_CANARY_PUBLIC_KEY = canary
    return mod


def probe_source(source=None):
    text = source if source is not None else hub_source()
    start = PROBE_HEAD.search(text).end()
    return text[start:text.index("\nDPPROBEEOF\n", start) + 1]


def load_probe(source=None, **overrides):
    namespace = {"__name__": "wins_node_dataplane_probe_h5_test"}
    exec(compile(probe_source(source), "wins_node_dataplane_probe.py", "exec"), namespace)
    namespace["log"] = lambda _msg: None
    namespace.update(overrides)
    return namespace


_SEQ = [0]


def seed_node(mod, **overrides):
    """One nodes row (the live fleet shape) in the hub database."""
    _SEQ[0] += 1
    row = {
        "slug": f"lab-node-{_SEQ[0]}", "name": "Lab", "status": "online",
        "management_status": "ok", "operator_enabled": 0, "ssh_host": "192.0.2.10",
        "endpoint": "192.0.2.10:9110", "wg_port": 9110, "public_key": NODE_KEY,
        "direct_awg_enabled": 1, "obfuscation_json": OBFUSCATION, "max_peers": 40,
        "stealth_endpoint": "stealth.example.test:80", "xray_security": "none",
        "stealth_transports": '[{"port":80,"security":"none"},{"port":443,"security":"tls"}]',
        "xray_path": "/stealth", "xray_uuid": XRAY_UUID, "stealth_public_port": 80,
    }
    row.update(overrides)
    with mod.get_db() as conn:
        mod.ensure_schema(conn)
        conn.execute(
            f"INSERT INTO nodes ({', '.join(row)}) VALUES ({', '.join('?' * len(row))})",
            tuple(row.values()))
    return row["slug"]


def node_row(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()


# ============================================================ admission ====

def admission_checks(mod):
    """The node_admits_peer and allocator facts. Raises AssertionError on the
    first violated one; the mutant tests run exactly this against mutated
    source."""
    closed = {"operator_enabled": 0, "retired_at": None, "deployment_withdrawal_id": None}
    open_node = dict(closed, operator_enabled=1)
    canary = (CANARY, EXACT)

    def admits(node, device=None, peer=canary):
        return mod.node_admits_peer(node, device, peer)

    assert admits(closed) is True, "the exact canary peer must be admitted on a closed node"
    assert admits(closed, peer=[CANARY, " " + EXACT + " "]) is True, "surrounding space is not a different address"
    assert admits(open_node) is True
    # Everything else keeps today's answer on a closed node.
    assert mod.node_admits_peer(closed) is False, "no system peer, no admission"
    assert mod.node_admits_peer(closed, None, None) is False
    assert admits(closed, peer=(OTHER, EXACT)) is False, "another key at .1"
    near = CANARY[:-2] + ("A" if CANARY[-2] != "A" else "B") + CANARY[-1]
    assert admits(closed, peer=(near, EXACT)) is False, "a key equal but for its last character"
    assert admits(closed, peer=(CANARY.swapcase(), EXACT)) is False, "a case-folded key"
    assert admits(closed, peer=(CORE_KEY, "10.8.255.2/32")) is False, "a Core exit peer"
    assert admits(closed, peer=(CANARY, "10.8.255.2/32")) is False, "the canary key at a Core exit address"
    assert admits(closed, peer=(CANARY, EXACT + ",10.8.255.2/32")) is False, "an additional address"
    assert admits(closed, peer=(CANARY, "10.8.255.2/32," + EXACT)) is False, "an additional address first"
    assert admits(closed, peer=(CANARY, "10.8.255.0/24")) is False, "the whole range"
    assert admits(closed, peer=(CANARY, "10.8.255.1")) is False, "not exactly /32"
    assert admits(closed, peer=(CANARY, "10.8.255.1/31")) is False
    assert admits(closed, peer=(CANARY, "")) is False
    assert admits(closed, peer=("", EXACT)) is False, "an empty key must never match"
    assert admits(closed, peer=(None, EXACT)) is False
    assert admits(closed, peer=(CANARY,)) is False, "a malformed peer tuple"
    assert admits(closed, device={"device_id": "d1"}) is False, "a customer device"
    assert admits(None) is False
    assert admits(dict(closed, retired_at="2026-01-01T00:00:00")) is False, "a retired node"
    assert admits(dict(closed, deployment_withdrawal_id="w1")) is False, "an installer withdrawal"
    saved = mod.AWG_CANARY_PUBLIC_KEY
    mod.AWG_CANARY_PUBLIC_KEY = ""
    try:
        assert admits(closed, peer=("", EXACT)) is False, "an unconfigured canary admits nothing"
        assert admits(closed) is False
    finally:
        mod.AWG_CANARY_PUBLIC_KEY = saved
    # An operator-open node never needs the exception, whatever the peer.
    assert admits(open_node, peer=(CORE_KEY, "10.8.255.2/32")) is True


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_hub()

    def test_node_admits_peer_admits_only_the_exact_canary_peer_on_a_closed_node(self):
        admission_checks(self.mod)

    def test_peer_push_re_reads_the_latch_with_the_system_peer(self):
        slug = seed_node(self.mod)
        self.assertTrue(self.mod.peer_push_still_admitted(slug, system_peer=(CANARY, EXACT)))
        self.assertFalse(self.mod.peer_push_still_admitted(slug, system_peer=(CORE_KEY, "10.8.255.2/32")))
        self.assertFalse(self.mod.peer_push_still_admitted(slug))
        self.assertFalse(self.mod.peer_push_still_admitted("no-such-node", system_peer=(CANARY, EXACT)))
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET retired_at = ? WHERE slug = ?", ("2026-01-01T00:00:00", slug))
        self.assertFalse(self.mod.peer_push_still_admitted(slug, system_peer=(CANARY, EXACT)))

    def test_the_hub_gate_evaluator_is_not_widened_by_this_slice(self):
        """H5 adds no exemption to the off-node evaluator (the AWGSYSPEER rule is
        H6): every AWGPEER line, canary or Core exit, still fails a closed node."""
        for line in ("AWGPEER aaaa core_exit bbbb ok", "AWGPEER cccc canary dddd ok"):
            failures = self.mod.offnode_node_report_failures("AWG_READ ok\n" + line + "\n", "winn/1", "")
            self.assertTrue(any("AWG peer(s) present" in f for f in failures), line)
        self.assertEqual(self.mod.offnode_node_report_failures("AWG_READ ok\nV3_FILE absent\n", "winn/1", ""), [])

    def test_the_canary_address_and_reserved_set_are_explicit(self):
        self.assertEqual(self.mod.AWG_CANARY_ADDRESS, "10.8.255.1")
        self.assertEqual(self.mod.AWG_CANARY_ALLOWED_IPS, EXACT)
        self.assertIn("10.8.255.1", self.mod.AWG_CORE_EXIT_RESERVED_ADDRESSES)

    def test_a_bad_canary_public_key_in_the_environment_is_refused(self):
        with patch.dict(os.environ, {"AWG_CANARY_PUBLIC_KEY": "not-a-key"}):
            self.assertEqual(self.mod._awg_canary_public_key_from_env(), "")
        with patch.dict(os.environ, {"AWG_CANARY_PUBLIC_KEY": base64.b64encode(b"x" * 31).decode()}):
            self.assertEqual(self.mod._awg_canary_public_key_from_env(), "")
        with patch.dict(os.environ, {"AWG_CANARY_PUBLIC_KEY": " " + CANARY + " "}):
            self.assertEqual(self.mod._awg_canary_public_key_from_env(), CANARY)
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AWG_CANARY_PUBLIC_KEY", None)
            self.assertEqual(self.mod._awg_canary_public_key_from_env(), "")


class CoreExitAllocatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_hub()

    def fresh_db(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute("DELETE FROM core_exit_peers")

    def test_allocate_core_exit_ip_never_returns_dot_one(self):
        self.fresh_db()
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod.allocate_core_exit_ip(conn), "10.8.255.2")

    def test_it_walks_dot_two_to_dot_254_and_then_refuses(self):
        self.fresh_db()
        exit_slug = seed_node(self.mod)
        with self.mod.get_db() as conn:
            seen = []
            for index in range(2, 255):
                address = self.mod.allocate_core_exit_ip(conn)
                self.assertEqual(address, f"10.8.255.{index}")
                seen.append(address)
                conn.execute("INSERT OR IGNORE INTO core_servers (core_id) VALUES (?)", (f"c{index}",))
                conn.execute(
                    "INSERT INTO core_exit_peers (core_id, exit_slug, core_exit_ip) VALUES (?, ?, ?)",
                    (f"c{index}", exit_slug, address))
            self.assertNotIn("10.8.255.1", seen)
            with self.assertRaises(harness.HTTPException) as caught:
                self.mod.allocate_core_exit_ip(conn)
            self.assertEqual(caught.exception.status_code, 503)

    def test_a_later_range_change_cannot_reach_the_canary_address(self):
        """The reserved set, not the range, keeps .1 out: start the range at 1."""
        source = hub_source()
        self.assertEqual(source.count("for y in range(2, 255):\n        candidate = f\"10.8.255.{y}\""), 1)
        widened = source.replace(
            "for y in range(2, 255):\n        candidate = f\"10.8.255.{y}\"",
            "for y in range(1, 255):\n        candidate = f\"10.8.255.{y}\"")
        mod = load_hub(widened)
        with mod.get_db() as conn:
            mod.ensure_schema(conn)
            conn.execute("DELETE FROM core_exit_peers")
            self.assertEqual(mod.allocate_core_exit_ip(conn), "10.8.255.2")


# ============================================================== columns ====

class ColumnAndRerunGateTests(unittest.TestCase):
    TRANSPORTS = ("udp", "stealth", "stealth_tls")

    @classmethod
    def setUpClass(cls):
        cls.mod = load_hub()

    def test_the_six_carry_columns_exist_with_unknown_defaults_and_migrate_twice(self):
        slug = seed_node(self.mod)
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            self.mod.ensure_schema(conn)
        row = node_row(self.mod, slug)
        for transport in self.TRANSPORTS:
            self.assertEqual(row[f"data_plane_{transport}_carry_status"], "unknown")
            self.assertIsNone(row[f"data_plane_{transport}_carry_ok_at"])

    def test_the_attempt_time_columns_exist_and_the_probe_mirrors_them(self):
        slug = seed_node(self.mod)
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            self.mod.ensure_schema(conn)
        row = node_row(self.mod, slug)
        probe = load_probe()
        for transport in self.TRANSPORTS:
            self.assertIsNone(row[f"data_plane_{transport}_carry_checked_at"])
            self.assertIn(f"data_plane_{transport}_carry_checked_at", probe["COLUMNS"])

    def test_the_probe_mirror_of_the_columns_matches_the_hub(self):
        probe = load_probe()
        for transport in self.TRANSPORTS:
            for suffix in ("status", "ok_at"):
                self.assertIn(f"data_plane_{transport}_carry_{suffix}", probe["COLUMNS"])
        hub = hub_source()
        for transport in self.TRANSPORTS:
            self.assertIn(f'"data_plane_{transport}_carry_status", "TEXT DEFAULT \'unknown\'"', hub)

    def test_a_row_with_the_columns_is_gated_on_the_proof_not_on_availability(self):
        completed = self.mod.utcnow()
        after = (completed + timedelta(minutes=5)).isoformat()
        before = (completed - timedelta(minutes=5)).isoformat()
        base = {
            "deployment_completed_at": completed.isoformat(), "direct_awg_enabled": 1,
            "endpoint": "192.0.2.10:9110", "public_key": NODE_KEY, "ssh_host": "192.0.2.10",
            "stealth_endpoint": "", "protocol_version": "winn/1",
            "data_plane_udp_carry_status": "unknown", "data_plane_udp_carry_ok_at": None,
        }
        fn = self.mod.installer_rerun_carry_failures
        (failure,) = fn(base)
        self.assertTrue(failure.startswith("udp: no carrying proof newer than the rerun completion"), failure)
        self.assertNotIn("not available", failure)
        ok = dict(base, data_plane_udp_carry_status="ok", data_plane_udp_carry_ok_at=after)
        self.assertEqual(fn(ok), [])
        self.assertEqual(len(fn(dict(ok, data_plane_udp_carry_ok_at=before))), 1, "a proof older than the completion")
        for status in ("failed", "probe_error", "unconfigured", "unknown"):
            self.assertEqual(len(fn(dict(ok, data_plane_udp_carry_status=status))), 1, status)

    def test_a_carrying_proof_is_read_only_while_it_is_fresh(self):
        """Newer than the completion is not enough: a success left by a probe that
        stopped must age out of the reopen gate (900 s)."""
        now = self.mod.utcnow()
        base = {
            "deployment_completed_at": (now - timedelta(hours=2)).isoformat(), "direct_awg_enabled": 1,
            "endpoint": "192.0.2.10:9110", "public_key": NODE_KEY, "ssh_host": "192.0.2.10",
            "stealth_endpoint": "", "protocol_version": "winn/1",
        }

        def proof(age):
            return dict(base, data_plane_udp_carry_status="ok",
                        data_plane_udp_carry_ok_at=(now - timedelta(seconds=age)).isoformat())

        fn = self.mod.installer_rerun_carry_failures
        self.assertEqual(self.mod.AWG_CARRY_PROOF_MAX_AGE_SECONDS, 900)
        self.assertEqual(fn(proof(60)), [])
        self.assertEqual(fn(proof(880)), [])
        for age in (930, 3600, 5400):
            (failure,) = fn(proof(age))
            self.assertIn("older than 900 s", failure, age)
        (failure,) = fn(dict(proof(60), data_plane_udp_carry_ok_at="garbage"))
        self.assertTrue(failure.startswith("udp: no carrying proof newer"), failure)

    def test_a_failed_carry_proof_never_closes_an_open_node(self):
        """The hub app has no writer of operator_enabled for a carry verdict."""
        hub = hub_source()
        self.assertNotRegex(hub, r"data_plane_\w*carry\w*[^\n]*operator_enabled\s*=")
        self.assertNotRegex(hub, r"operator_enabled\s*=[^\n]*data_plane_\w*carry")


# =========================================================== peer push ====

class CanaryPeerPushTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = load_hub()

    def setUp(self):
        self.mod._AWG_CANARY_PEER_LAST.clear()
        self.pushes = []
        self.push_ok = True

        def push(node_ip, cfg):
            self.pushes.append((node_ip, dict(cfg)))
            return self.push_ok

        self.patches = [patch.object(self.mod, "sync_peer_to_node", side_effect=push)]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in self.patches])

    def sweep(self, slug="", force=False):
        return self.mod.sync_awg_canary_peers_once(slug, force=force)

    def test_an_open_node_receives_exactly_the_canary_peer(self):
        slug = seed_node(self.mod, operator_enabled=1)
        out = self.sweep(slug)
        self.assertEqual((out["attempted"], out["synced"], out["failed"]), (1, 1, 0))
        ((node_ip, cfg),) = self.pushes
        self.assertEqual(node_ip, "192.0.2.10")
        self.assertEqual(cfg["client_public_key"], CANARY)
        self.assertEqual(cfg["vpn_internal_ip"], "10.8.255.1")
        self.assertEqual(cfg["preshared_key"], "")

    def test_a_pending_closed_node_holds_the_canary_peer(self):
        now = self.mod.utcnow().isoformat()
        for reason in ("installer_rerun", "fresh_install"):
            slug = seed_node(self.mod, operator_enabled=0, health_closed_reason=reason,
                             deployment_completed_at=now)
            self.assertEqual(self.sweep(slug)["synced"], 1, reason)

    def test_other_closed_retired_and_withdrawn_nodes_get_nothing(self):
        now = self.mod.utcnow().isoformat()
        cases = {
            "operator closed": dict(operator_enabled=0),
            "health closed, no completion": dict(operator_enabled=0, health_closed_reason="installer_rerun"),
            "completion, other reason": dict(operator_enabled=0, health_closed_reason="health_unreachable",
                                             deployment_completed_at=now),
            "retired": dict(operator_enabled=1, retired_at=now),
            "withdrawn": dict(operator_enabled=1, deployment_withdrawal_id="w1"),
            "maintenance": dict(operator_enabled=1, status="maintenance"),
            "offline": dict(operator_enabled=1, status="offline"),
        }
        for label, fields in cases.items():
            slug = seed_node(self.mod, **fields)
            out = self.sweep(slug)
            self.assertEqual(out["attempted"], 0, label)
            self.assertEqual(out["synced"], 0, label)
        self.assertEqual(self.pushes, [])

    def test_nothing_is_pushed_without_a_configured_canary_key(self):
        slug = seed_node(self.mod, operator_enabled=1)
        with patch.object(self.mod, "AWG_CANARY_PUBLIC_KEY", ""):
            self.assertEqual(self.sweep(slug), {"attempted": 0, "synced": 0, "failed": 0, "skipped": 0})
        self.assertEqual(self.pushes, [])

    def test_cadence_is_600_seconds_open_and_120_seconds_pending(self):
        now = self.mod.utcnow().isoformat()
        open_slug = seed_node(self.mod, operator_enabled=1)
        pending = seed_node(self.mod, operator_enabled=0, health_closed_reason="fresh_install",
                            deployment_completed_at=now)
        clock = [1000.0]
        with patch.object(self.mod.time, "monotonic", side_effect=lambda: clock[0]):
            self.assertEqual(self.sweep(open_slug)["synced"], 1)
            self.assertEqual(self.sweep(pending)["synced"], 1)
            clock[0] += 119
            self.assertEqual(self.sweep(open_slug)["skipped"], 1)
            self.assertEqual(self.sweep(pending)["skipped"], 1)
            clock[0] += 2          # 121 s: pending is due, open is not
            self.assertEqual(self.sweep(open_slug)["skipped"], 1)
            self.assertEqual(self.sweep(pending)["synced"], 1)
            clock[0] += 480        # 601 s since the first open push
            self.assertEqual(self.sweep(open_slug)["synced"], 1)
            self.assertEqual(self.sweep(open_slug, force=True)["synced"], 1, "an explicit resync ignores the throttle")

    def test_a_failed_push_is_counted_and_retried_only_after_its_interval(self):
        slug = seed_node(self.mod, operator_enabled=1)
        self.push_ok = False
        clock = [1000.0]
        with patch.object(self.mod.time, "monotonic", side_effect=lambda: clock[0]):
            self.assertEqual(self.sweep(slug)["failed"], 1)
            self.push_ok = True
            clock[0] += 60
            self.assertEqual(self.sweep(slug)["skipped"], 1, "a dead node costs one attempt per interval")
            clock[0] += 600
            self.assertEqual(self.sweep(slug)["synced"], 1)

    def test_a_node_closed_by_retirement_during_the_push_is_taken_back(self):
        slug = seed_node(self.mod, operator_enabled=1)
        calls = [0]
        real = self.mod.peer_push_still_admitted

        def admitted(node_slug, device_id=None, system_peer=None):
            calls[0] += 1
            return real(node_slug, device_id, system_peer) if calls[0] <= 1 else False

        with patch.object(self.mod, "peer_push_still_admitted", side_effect=admitted):
            out = self.sweep(slug)
        self.assertEqual((out["synced"], out["skipped"]), (0, 1))
        with self.mod.get_db() as conn:
            queued = [r["client_public_key"] for r in conn.execute(
                "SELECT client_public_key FROM peer_revocations WHERE node_ip = ?", ("192.0.2.10",))]
        self.assertEqual(queued, [CANARY])

    def patched_loop_collaborators(self, seen, audits=None):
        return [
            patch.object(self.mod, "audit_fleet_availability_once",
                         side_effect=(lambda: audits.append(1)) if audits is not None else None),
            patch.object(self.mod, "audit_winn3_contract_once"),
            patch.object(self.mod, "auto_reopen_health_closed_nodes"),
            patch.object(self.mod, "drain_node_latch_events"),
            patch.object(self.mod, "sync_awg_canary_peers_once", side_effect=seen),
        ]

    def test_the_canary_push_is_its_own_task_and_not_a_step_of_the_fleet_sweep(self):
        import asyncio
        for loop_name, expected in (("fleet_availability_sweep_loop", []), ("awg_canary_sync_loop", [1])):
            seen = []

            async def stop(_seconds):
                raise asyncio.CancelledError()

            patches = self.patched_loop_collaborators(lambda *a, **k: seen.append(1))
            patches.append(patch.object(self.mod.asyncio, "sleep", stop))
            for item in patches:
                item.start()
            try:
                with self.assertRaises(asyncio.CancelledError):
                    asyncio.run(getattr(self.mod, loop_name)())
            finally:
                for item in patches:
                    item.stop()
            self.assertEqual(seen, expected, loop_name)
        source = hub_source()
        self.assertEqual(source.count("asyncio.create_task(awg_canary_sync_loop())"), 1)
        self.assertLess(source.index("asyncio.create_task(fleet_availability_sweep_loop())"),
                        source.index("asyncio.create_task(awg_canary_sync_loop())"))

    def test_a_stuck_canary_push_cannot_delay_the_audit_and_reopen_passes(self):
        """Sol 5: 64 pushes waiting out a 15 s SSH timeout used to hold the next
        audit and reopen pass. The two loops now run side by side."""
        import asyncio
        mod = self.mod
        real_sleep = asyncio.sleep
        release = threading.Event()
        audits = []

        async def fast_sleep(_seconds):
            await real_sleep(0)

        async def scenario():
            patches = self.patched_loop_collaborators(lambda *a, **k: release.wait(10), audits)
            patches.append(patch.object(mod.asyncio, "sleep", fast_sleep))
            for item in patches:
                item.start()
            try:
                tasks = [asyncio.create_task(mod.awg_canary_sync_loop()),
                         asyncio.create_task(mod.fleet_availability_sweep_loop())]
                for _ in range(300):
                    if len(audits) >= 3:
                        break
                    await real_sleep(0.01)
                progressed = len(audits) >= 3
                release.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                for item in patches:
                    item.stop()
            return progressed

        self.assertTrue(asyncio.run(scenario()), "the audit loop kept iterating while a push was stuck")

    def test_a_throttled_node_costs_no_database_connection(self):
        slug = seed_node(self.mod, operator_enabled=1)
        calls = []
        real = self.mod.peer_push_still_admitted
        with patch.object(self.mod, "peer_push_still_admitted",
                          side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
            self.assertEqual(self.sweep(slug)["synced"], 1)
            opened = len(calls)
            self.assertGreaterEqual(opened, 1)
            self.assertEqual(self.sweep(slug)["skipped"], 1)
            self.assertEqual(len(calls), opened, "a node inside its interval is not re-read from the database")

    def test_one_node_raising_does_not_stop_the_others(self):
        first = seed_node(self.mod, operator_enabled=1, ssh_host="192.0.2.31")
        second = seed_node(self.mod, operator_enabled=1, ssh_host="192.0.2.32")

        def push(node_ip, cfg):
            if node_ip == "192.0.2.31":
                raise RuntimeError("boom")
            self.pushes.append((node_ip, dict(cfg)))
            return True

        with patch.object(self.mod, "sync_peer_to_node", side_effect=push):
            out = self.mod.sync_awg_canary_peers_once("", force=True)
        self.assertGreaterEqual(out["failed"], 1)
        self.assertIn("192.0.2.32", [ip for ip, _ in self.pushes])

    def test_due_nodes_are_pushed_concurrently_and_boundedly(self):
        for _ in range(12):
            seed_node(self.mod, operator_enabled=1)
        live, peak, lock = [0], [0], threading.Lock()

        def slow(node_ip, cfg):
            with lock:
                live[0] += 1
                peak[0] = max(peak[0], live[0])
            time.sleep(0.15)
            with lock:
                live[0] -= 1
            return True

        with patch.object(self.mod, "sync_peer_to_node", side_effect=slow):
            out = self.sweep()
        self.assertGreaterEqual(out["synced"], 12)
        self.assertGreater(peak[0], 1, "pushes overlap")
        self.assertLessEqual(peak[0], self.mod.AWG_CANARY_PUSH_WORKERS, "and are bounded")

    def resync(self, slug):
        with patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True), \
                patch.object(self.mod, "verify_node_management_access", return_value=True), \
                patch.object(self.mod, "remove_peer_from_node", return_value=True):
            return self.mod.resync_active_peers_to_node(slug)

    def test_resync_pushes_the_canary_peer_without_touching_the_customer_counters(self):
        slug = seed_node(self.mod, operator_enabled=1)
        out = self.resync(slug)
        self.assertTrue(out["ok"], out)
        self.assertEqual((out["awg_canary_attempted"], out["awg_canary_synced"]), (1, 1))
        self.assertEqual(out["core_attempted"], 0)
        self.assertEqual(len(self.pushes), 1)

    def test_a_canary_push_failure_does_not_fail_the_resync(self):
        slug = seed_node(self.mod, operator_enabled=1)
        self.push_ok = False
        out = self.resync(slug)
        self.assertEqual(out["awg_canary_failed"], 1)
        self.assertEqual(out["failed"], 0)
        self.assertTrue(out["ok"], out)

    def test_resync_without_a_canary_key_adds_no_keys(self):
        slug = seed_node(self.mod, operator_enabled=1)
        with patch.object(self.mod, "AWG_CANARY_PUBLIC_KEY", ""):
            out = self.resync(slug)
        self.assertFalse([key for key in out if key.startswith("awg_canary_")])

    def test_closure_still_revokes_a_core_exit_peer_and_never_the_canary(self):
        slug = seed_node(self.mod, operator_enabled=0, ssh_host="192.0.2.77", endpoint="192.0.2.77:9110")
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO core_servers (core_id, exit_public_key) VALUES ('core-1', ?)", (CORE_KEY,))
            conn.execute(
                "INSERT INTO core_exit_peers (core_id, exit_slug, core_exit_ip) VALUES ('core-1', ?, '10.8.255.2')",
                (slug,))
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            out = self.mod.close_node_runtime(conn, slug)
            conn.commit()
            queued = {r["client_public_key"] for r in conn.execute(
                "SELECT client_public_key FROM peer_revocations WHERE node_ip = ?", ("192.0.2.77",))}
        self.assertEqual(out["core_exit_revocations_queued"], 1)
        self.assertEqual(queued, {CORE_KEY})
        self.assertTrue(self.mod.node_admits_peer(node_row(self.mod, slug), system_peer=(CANARY, EXACT)))
        self.assertFalse(self.mod.node_admits_peer(node_row(self.mod, slug), system_peer=(CORE_KEY, "10.8.255.2/32")))

    def test_node_class_rule_matches_the_probe_copy(self):
        probe = load_probe()
        now = self.mod.utcnow().isoformat()
        rows = [
            {}, {"operator_enabled": 1}, {"operator_enabled": None}, {"operator_enabled": 1, "retired_at": now},
            {"operator_enabled": 1, "deployment_withdrawal_id": "w"},
            {"deployment_completed_at": now, "health_closed_reason": "installer_rerun"},
            {"deployment_completed_at": now, "health_closed_reason": "fresh_install"},
            {"deployment_completed_at": now, "health_closed_reason": "health_unreachable"},
            {"deployment_completed_at": "", "health_closed_reason": "installer_rerun"},
            {"deployment_completed_at": now, "health_closed_reason": "installer_rerun", "retired_at": now},
            {"deployment_completed_at": now, "health_closed_reason": "fresh_install", "deployment_withdrawal_id": "w"},
        ]
        for fields in rows:
            with self.subTest(fields=fields):
                self.assertEqual(self.mod.awg_canary_node_class(fields), probe["carry_node_class"](fields))
        self.assertEqual(self.mod.AWG_CANARY_OPEN_INTERVAL_SECONDS, probe["CARRY_OPEN_INTERVAL_SECONDS"])
        self.assertEqual(self.mod.AWG_CANARY_PENDING_INTERVAL_SECONDS, probe["CARRY_PENDING_INTERVAL_SECONDS"])
        self.assertEqual(tuple(self.mod.AWG_CANARY_PENDING_REASONS), tuple(probe["CARRY_PENDING_REASONS"]))


# ======================================================== the probe: DNS ====

def dns_response(query, answers=1, rcode=0, qid=None, response=True, echo=True):
    ident = struct.unpack("!H", query[:2])[0] if qid is None else qid
    flags = (0x8180 if response else 0x0100) | rcode
    # Another question of exactly the same length, so a validator that stops
    # comparing it cannot be caught by a length accident further on.
    other = bytearray(query[12:])
    other[1] ^= 0x01
    question = query[12:] if echo else bytes(other)
    body = struct.pack("!HHHHHH", ident, flags, 1, answers, 0, 0) + question
    for _ in range(answers):
        body += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
    return body


def dns_record(rtype=1, rclass=1, rdata=bytes([192, 0, 2, 7]), name=b"\xc0\x0c", rdlength=None):
    length = len(rdata) if rdlength is None else rdlength
    return name + struct.pack("!HHIH", rtype, rclass, 60, length) + rdata


def dns_message(query, records, count=None, questions=1):
    qid = struct.unpack("!H", query[:2])[0]
    return (struct.pack("!HHHHHH", qid, 0x8180, questions, len(records) if count is None else count, 0, 0)
            + query[12:] + b"".join(records))


def dns_reply_variants(query):
    plain = b"\x03hub\x07example\x04test\x00"
    good = dns_message(query, [dns_record()])
    return {
        "accepted": {
            "one compressed A record": good,
            "an uncompressed owner name": dns_message(query, [dns_record(name=plain)]),
            "a CNAME and then an A record": dns_message(query, [
                dns_record(rtype=5, rdata=b"\x03www\xc0\x0c"), dns_record()]),
            "trailing bytes after the answers": good + b"\x00\x00",
        },
        "rejected": {
            "the header claims an answer and none follows": dns_message(query, [], count=1),
            "the header claims two and one follows": dns_message(query, [dns_record()], count=2),
            "a record cut inside its fixed part": good[:-(4 + 4)],
            "record data that runs past the reply": good[:-1],
            "record data length larger than the reply": dns_message(query, [dns_record(rdlength=60)]),
            "class CH": dns_message(query, [dns_record(rclass=3)]),
            "an A record of five bytes": dns_message(query, [dns_record(rdata=bytes(5))]),
            "an A record of three bytes": dns_message(query, [dns_record(rdata=bytes(3))]),
            "only a CNAME": dns_message(query, [dns_record(rtype=5, rdata=b"\x03www\xc0\x0c")]),
            "a compression pointer forward": dns_message(query, [dns_record(name=b"\xc0\xff")]),
            "a compression pointer into the header": dns_message(query, [dns_record(name=b"\xc0\x04")]),
            "a name label running out of the reply": dns_message(query, [dns_record(name=b"\x3fabc")]),
            "a reserved label type": dns_message(query, [dns_record(name=b"\x41" + b"a" * 65 + b"\x00")]),
            "two questions": dns_message(query, [dns_record()], questions=2),
            "no question counted": dns_message(query, [dns_record()], questions=0),
        },
    }


class DnsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()

    def test_the_query_is_a_real_question_for_the_hub_name(self):
        query, qid = self.probe["build_dns_query"]("hub.example.test")
        self.assertEqual(struct.unpack("!H", query[:2])[0], qid)
        self.assertEqual(query[12:], b"\x03hub\x07example\x04test\x00\x00\x01\x00\x01")

    def test_only_a_real_answer_to_this_query_counts_as_carried(self):
        query, _ = self.probe["build_dns_query"]("hub.example.test")
        check = self.probe["dns_reply_carries"]
        self.assertTrue(check(dns_response(query), query)[0])
        wrong = {
            "wrong id": dns_response(query, qid=(struct.unpack("!H", query[:2])[0] + 1) % 65536),
            "not a response": dns_response(query, response=False),
            "nxdomain": dns_response(query, rcode=3),
            "no answer": dns_response(query, answers=0),
            "another question": dns_response(query, echo=False),
            "short": b"\x00\x01",
        }
        for label, reply in wrong.items():
            self.assertFalse(check(reply, query)[0], label)

    def test_a_header_count_is_not_an_answer_record(self):
        """Sol 3: a header claiming one answer, followed only by the echoed
        question, was accepted. Every record is parsed, with its bounds."""
        query, _ = self.probe["build_dns_query"]("hub.example.test")
        check = self.probe["dns_reply_carries"]
        for label, reply in dns_reply_variants(query)["rejected"].items():
            with self.subTest(label):
                try:
                    carried = check(reply, query)[0]
                except Exception:  # noqa: BLE001  (a crash is not a carried reply either, but must not be needed)
                    self.fail(f"{label}: the validator raised instead of refusing")
                self.assertFalse(carried, label)
        for label, reply in dns_reply_variants(query)["accepted"].items():
            with self.subTest(label):
                self.assertTrue(check(reply, query)[0], label)


# ===================================================== the probe: cadence ====

class DueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.probe = load_probe()

    def test_due_follows_the_two_intervals_with_a_timer_slack(self):
        due = self.probe["carry_due"]
        now = datetime(2026, 10, 7, 12, 0, 0)

        def ago(seconds):
            return (now - timedelta(seconds=seconds)).isoformat()

        self.assertTrue(due("unknown", None, "open", now))
        for status in ("failed", "probe_error", "unconfigured", "unknown", None):
            self.assertTrue(due(status, ago(1), "open", now), status)
        self.assertFalse(due("ok", ago(100), "open", now))
        self.assertFalse(due("ok", ago(569), "open", now))
        self.assertTrue(due("ok", ago(570), "open", now), "within the slack of 600 s")
        self.assertTrue(due("ok", ago(700), "open", now))
        self.assertFalse(due("ok", ago(60), "pending", now))
        self.assertFalse(due("ok", ago(89), "pending", now))
        self.assertTrue(due("ok", ago(90), "pending", now), "within the slack of 120 s")
        self.assertTrue(due("ok", "garbage", "open", now))
        self.assertTrue(due("ok", None, "open", now))
        self.assertTrue(due("ok", (now + timedelta(hours=1)).isoformat(), "open", now), "clock skew re-probes")

    def test_a_failing_transport_is_retried_at_its_cadence_counted_from_the_last_attempt(self):
        """Sol 5: a transport that is not ok used to be due on every 120 s run, so
        a broken flavour cost five times the budget. The stamp is the attempt."""
        due = self.probe["carry_due"]
        now = datetime(2026, 10, 7, 12, 0, 0)

        def ago(seconds):
            return (now - timedelta(seconds=seconds)).isoformat()

        for status in ("failed", "probe_error", "unconfigured", "unknown", None):
            with self.subTest(status):
                self.assertFalse(due(status, ago(9999), "open", now, ago(100)), "attempted 100 s ago")
                self.assertFalse(due(status, None, "open", now, ago(569)))
                self.assertTrue(due(status, ago(1), "open", now, ago(570)), "within the slack of 600 s")
                self.assertFalse(due(status, ago(9999), "pending", now, ago(60)))
                self.assertTrue(due(status, ago(1), "pending", now, ago(90)), "within the slack of 120 s")
                self.assertTrue(due(status, ago(1), "open", now, None), "never attempted")
                self.assertTrue(due(status, ago(1), "open", now, "garbage"))
                self.assertTrue(due(status, ago(1), "open", now, (now + timedelta(hours=1)).isoformat()))
        self.assertFalse(due("ok", ago(100), "open", now, ago(9999)), "an ok transport follows its success time")


# ================================================= the probe: fake client ====

# P2-SEAM-H5: the client is long-lived (P-16): one JSON request per line in,
# one JSON reply per line out, echoing id, slug and transport. These fakes
# answer one request and exit, which the probe treats as a client to restart.
CLIENT_PRELUDE = ("#!{python}\nimport json, os, socket, sys\nrequest = json.loads(sys.stdin.readline())\n"
                  "def answer(extra):\n"
                  "    echo = {{key: request[key] for key in (\"id\", \"slug\", \"transport\")}}\n"
                  "    print(json.dumps(dict(echo, **extra)), flush=True)\n")

CLIENT_UDP = CLIENT_PRELUDE + textwrap.dedent('''
    open({record!r}, "w").write(json.dumps({{"argv": sys.argv, "env": dict(os.environ), "request": request}}))
    host, port = request["endpoint"].rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    sock.sendto(bytes.fromhex(request["dns_query_hex"]), (host, int(port)))
    try:
        reply, _ = sock.recvfrom(65535)
    except socket.timeout:
        reply = b""
    answer({{"dns_reply_hex": reply.hex()}})
''')


class FakeDnsNode(threading.Thread):
    """A UDP endpoint that answers the canary's DNS query, standing in for a
    node and the tunnel behind it."""

    def __init__(self, **answer):
        super().__init__(daemon=True)
        self.answer = answer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(8)
        self.port = self.sock.getsockname()[1]
        self.received = []

    def run(self):
        try:
            data, addr = self.sock.recvfrom(65535)
        except OSError:
            return
        self.received.append(data)
        if self.answer.get("silent"):
            return
        answer = {k: v for k, v in self.answer.items() if k != "silent"}
        if answer.get("qid") == "off":
            answer["qid"] = (struct.unpack("!H", data[:2])[0] + 1) % 65536
        self.sock.sendto(dns_response(data, **answer), addr)

    def close(self):
        self.sock.close()


def ws_read_frame(sock):
    def exact(count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError
            data += chunk
        return data
    head = exact(2)
    size = head[1] & 0x7F
    if size == 126:
        size = struct.unpack("!H", exact(2))[0]
    mask = exact(4) if head[1] & 0x80 else b""
    payload = exact(size)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return head[0] & 0x0F, payload


def ws_frame(payload, opcode=2):
    if len(payload) < 126:
        return bytes([0x80 | opcode, len(payload)]) + payload
    return bytes([0x80 | opcode, 126]) + struct.pack("!H", len(payload)) + payload


class FakeVlessNode(threading.Thread):
    """A plaintext WebSocket + VLESS v0 UDP endpoint. It checks the upgrade, the
    VLESS request header (uuid, UDP command, loopback AWG port) and answers each
    datagram with a DNS reply framed the way Xray frames it."""

    def __init__(self, uid, awg_port, status=b"101 Switching Protocols"):
        super().__init__(daemon=True)
        self.uid, self.awg_port, self.status = uid, awg_port, status
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(8)
        self.port = self.server.getsockname()[1]
        self.request = b""
        self.header_ok = False
        self.datagrams = []

    def run(self):
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(8)
            while b"\r\n\r\n" not in self.request:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                self.request += chunk
            conn.sendall(b"HTTP/1.1 " + self.status + b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            if b"101" not in self.status:
                return
            first = True
            try:
                while True:
                    opcode, payload = ws_read_frame(conn)
                    if opcode == 8:
                        return
                    if first:
                        self.header_ok = (
                            payload[0] == 0 and payload[1:17] == self.uid and payload[17] == 0
                            and payload[18] == 2 and struct.unpack("!H", payload[19:21])[0] == self.awg_port
                            and payload[21] == 1 and payload[22:26] == bytes([127, 0, 0, 1]))
                        payload = payload[26:]
                    size = struct.unpack("!H", payload[:2])[0]
                    query = payload[2:2 + size]
                    self.datagrams.append(query)
                    reply = dns_response(query)
                    body = struct.pack("!H", len(reply)) + reply
                    conn.sendall(ws_frame((b"\x00\x00" if first else b"") + body))
                    first = False
            except (ConnectionError, OSError):
                return

    def close(self):
        self.server.close()


class HostileUpgradeNode(threading.Thread):
    """A TCP endpoint that answers the WebSocket upgrade badly: `flood` sends a
    header that never ends, `drip` sends one byte at a time and keeps going."""

    def __init__(self, mode):
        super().__init__(daemon=True)
        self.mode = mode
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(1)
        self.server.settimeout(10)
        self.port = self.server.getsockname()[1]
        self.sent = 0

    def run(self):
        try:
            conn, _ = self.server.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2)
            try:
                conn.recv(4096)
                end = time.monotonic() + 12
                while time.monotonic() < end:
                    chunk = b"X" * 4096 if self.mode == "flood" else b"X"
                    conn.sendall(chunk)
                    self.sent += len(chunk)
                    time.sleep(0 if self.mode == "flood" else 0.3)
            except OSError:
                return

    def close(self):
        self.server.close()


class ProbeCarryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="h5-probe-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.record = os.path.join(self.dir, "record.json")
        self.key = throwaway_key()

    def client(self, source):
        path = os.path.join(self.dir, "client")
        Path(path).write_text(source.format(python=sys.executable, record=self.record))
        os.chmod(path, 0o755)
        return path

    def probe(self, client=None, **overrides):
        values = {"CARRY_CLIENT_BIN": client or "", "CARRY_DNS_NAME": "hub.example.test",
                  "CARRY_CLIENT_TIMEOUT": 5,
                  # The fake client lives in a temp dir; D6 placement has its own test.
                  "carry_client_untrusted": lambda _path: ""}
        values.update(overrides)
        return load_probe(**values)

    def row(self, **fields):
        row = {
            "slug": "lab-1", "endpoint": "127.0.0.1:9110", "wg_port": 9110, "public_key": NODE_KEY,
            "direct_awg_enabled": 1, "obfuscation_json": OBFUSCATION,
            "stealth_endpoint": "127.0.0.1:80", "xray_security": "none", "stealth_transports": "[]",
            "xray_path": "/stealth", "xray_uuid": XRAY_UUID,
        }
        row.update(fields)
        return row

    def test_udp_carries_a_validated_dns_reply_and_the_key_travels_only_on_stdin(self):
        node = FakeDnsNode()
        node.start()
        self.addCleanup(node.close)
        with patch.dict(os.environ, {"ADMIN_TOKEN": "sentinel-secret"}):
            verdict, detail = self.probe(self.client(CLIENT_UDP))["probe_carry"](
                self.row(endpoint=f"127.0.0.1:{node.port}", wg_port=node.port), "udp", self.key)
        self.assertEqual(verdict, "reachable", detail)
        seen = json.loads(Path(self.record).read_text())
        request = seen["request"]
        self.assertEqual(request["private_key"], self.key)
        self.assertEqual(request["peer_public_key"], NODE_KEY)
        self.assertEqual(request["local_address"], EXACT)
        self.assertEqual(request["dns_server"], "10.8.1.1")
        self.assertEqual(request["endpoint"], f"127.0.0.1:{node.port}")
        self.assertEqual(request["obfuscation"], json.loads(OBFUSCATION), "the node's served profile, verbatim")
        self.assertEqual(bytes.fromhex(request["dns_query_hex"])[12:], b"\x03hub\x07example\x04test\x00\x00\x01\x00\x01")
        self.assertNotIn(self.key, json.dumps(seen["argv"]), "the private key is never an argument")
        self.assertNotIn(self.key, json.dumps(seen["env"]), "the private key is never in the environment")
        self.assertNotIn("ADMIN_TOKEN", seen["env"], "the hub environment never reaches the client")
        allowed = {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "LC_CTYPE", "PWD", "SHLVL", "_", "__CF_USER_TEXT_ENCODING"}
        self.assertEqual(set(seen["env"]) - allowed, set(), "the client gets a narrowed environment")

    def test_a_reply_that_does_not_validate_is_not_carrying(self):
        for label, answer in {"no answer record": {"answers": 0}, "nxdomain": {"rcode": 3},
                              "wrong id": {"qid": "off"}, "silence": {"silent": True}}.items():
            node = FakeDnsNode(**answer)
            node.start()
            self.addCleanup(node.close)
            with self.subTest(label):
                verdict, _ = self.probe(self.client(CLIENT_UDP), CARRY_CLIENT_TIMEOUT=5)["probe_carry"](
                    self.row(endpoint=f"127.0.0.1:{node.port}", wg_port=node.port), "udp", self.key)
                self.assertEqual(verdict, "unreachable")

    def test_a_client_that_claims_success_without_a_reply_is_not_believed(self):
        # P2-SEAM-H5: a reply with the request's id, slug and transport but no
        # DNS reply is no verdict ("error"), so nothing is written for it.
        lying = CLIENT_PRELUDE + 'answer({{"carried": True, "detail": "trust me"}})\n'
        verdict, _ = self.probe(self.client(lying))["probe_carry"](self.row(), "udp", self.key)
        self.assertEqual(verdict, "error")

    def test_a_client_that_cannot_run_is_a_probe_error_and_never_leaks_the_key(self):
        # P2-SEAM-H5 (P-16 status rules): a client that took the request and
        # gave no valid reply is "error"; no usable client is "unavailable".
        # Neither is a verdict, so neither is ever written as probe_error.
        failing = CLIENT_PRELUDE + 'sys.stderr.write("boom " + request["private_key"] + " tail\\n")\nsys.exit(3)\n'
        verdict, detail = self.probe(self.client(failing))["probe_carry"](self.row(), "udp", self.key)
        self.assertEqual(verdict, "error")
        self.assertIn("exit 3", detail)
        self.assertNotIn(self.key, detail)
        garbage = CLIENT_PRELUDE + 'print("not json")\n'
        self.assertEqual(self.probe(self.client(garbage))["probe_carry"](self.row(), "udp", self.key)[0], "error")
        plain = "AWG carry client printed no readable result"
        for label, error, expected in (
                ("the client's own refusal text",
                 "local fault: device did not come up: address family not supported by protocol",
                 ": local fault: device did not come up: address family not supported by protocol"),
                ("non-printable characters become spaces", "bad\x00text\x1b[31m\u00e9\n", ": bad text [31m  "),
                ("at most 120 characters", "x" * 300, ": " + "x" * 120)):
            with self.subTest(label):
                sent = CLIENT_PRELUDE + f"answer({{{{\"error\": {error!r}}}}})\n"
                verdict, detail = self.probe(self.client(sent))["probe_carry"](self.row(), "udp", self.key)
                self.assertEqual(verdict, "error")
                self.assertTrue(detail.startswith(plain + expected), detail)
                rest = detail[len(plain + expected):]
                self.assertRegex(rest, r"^( \(exit \d+\))? \(udp [0-9.]+:\d+\)$")
                self.assertRegex(detail, r"^[ -~]*$")
                self.assertNotIn(self.key, detail)
        for label, extra in (("no error key", "{{}}"), ("an error that is not text", '{{"error": 5}}'),
                             ("an error list", '{{"error": ["x"]}}')):
            with self.subTest(label):
                verdict, detail = self.probe(self.client(CLIENT_PRELUDE + f"answer({extra})\n"))["probe_carry"](
                    self.row(), "udp", self.key)
                self.assertEqual(verdict, "error")
                self.assertTrue(detail.startswith(plain), detail)
                self.assertNotIn(plain + ":", detail)
        verdict, detail = self.probe("")["probe_carry"](self.row(), "udp", self.key)
        self.assertEqual(verdict, "unavailable")
        self.assertIn("no AWG carry client installed", detail)
        verdict, _ = self.probe(os.path.join(self.dir, "absent"))["probe_carry"](self.row(), "udp", self.key)
        self.assertEqual(verdict, "unavailable")

    def test_a_client_the_hub_app_could_write_is_never_run(self):
        ran = os.path.join(self.dir, "ran")
        client = self.client("#!/bin/sh\ntouch " + ran + "\n")
        probe = load_probe(CARRY_CLIENT_BIN=client, CARRY_DNS_NAME="hub.example.test", CARRY_CLIENT_TIMEOUT=5)
        query, _ = probe["build_dns_query"]("hub.example.test")
        verdict, detail = probe["run_carry_client"]({"private_key": self.key}, query, self.key)
        self.assertEqual(verdict, "unavailable", "P2-SEAM-H5: no request reached a client")
        self.assertIn("H0 D6", detail)
        self.assertFalse(os.path.exists(ran))

    def test_a_client_that_hangs_is_a_probe_error(self):
        hang = CLIENT_PRELUDE + "import time\ntime.sleep(60)\n"
        probe = self.probe(self.client(hang), CARRY_CLIENT_TIMEOUT=-9.5)
        verdict, detail = probe["probe_carry"](self.row(), "udp", self.key)
        self.assertEqual(verdict, "error", "P2-SEAM-H5: a request with no reply is no verdict")
        self.assertIn("timed out", detail)

    def test_unadvertised_or_unreadable_inputs_are_reported_by_kind(self):
        fn = self.probe(self.client(CLIENT_UDP))["probe_carry"]
        self.assertEqual(fn(self.row(direct_awg_enabled=0), "udp", self.key)[0], "unconfigured")
        self.assertEqual(fn(self.row(public_key=""), "udp", self.key)[0], "unconfigured")
        self.assertEqual(fn(self.row(stealth_endpoint="", stealth_transports="[]"), "stealth", self.key)[0], "unconfigured")
        self.assertEqual(fn(self.row(stealth_transports="[]"), "stealth_tls", self.key)[0], "unconfigured")
        self.assertEqual(fn(self.row(xray_path=""), "stealth", self.key)[0], "unconfigured")
        self.assertEqual(fn(self.row(obfuscation_json="not json"), "udp", self.key)[0], "probe_error")
        self.assertEqual(fn(self.row(xray_uuid="zz"), "stealth", self.key)[0], "probe_error")

    def test_stealth_goes_through_websocket_and_vless_to_the_loopback_awg_port(self):
        node = FakeVlessNode(uuid.UUID(XRAY_UUID).bytes, 9110)
        node.start()
        self.addCleanup(node.close)
        row = self.row(stealth_endpoint=f"127.0.0.1:{node.port}")
        verdict, detail = self.probe(self.client(CLIENT_UDP))["probe_carry"](row, "stealth", self.key)
        self.assertEqual(verdict, "reachable", detail)
        self.assertTrue(node.header_ok, "VLESS v0 UDP request to 127.0.0.1:<awg port> with the node uuid")
        self.assertIn(b"GET /stealth HTTP/1.1", node.request)
        self.assertIn(b"Upgrade: websocket", node.request)
        self.assertEqual(len(node.datagrams), 1)
        request = json.loads(Path(self.record).read_text())["request"]
        self.assertTrue(request["endpoint"].startswith("127.0.0.1:"), "the client sees a local UDP relay")
        self.assertNotEqual(request["endpoint"], row["stealth_endpoint"])

    def test_a_stealth_path_that_does_not_upgrade_is_unreachable(self):
        node = FakeVlessNode(uuid.UUID(XRAY_UUID).bytes, 9110, status=b"400 Bad Request")
        node.start()
        self.addCleanup(node.close)
        verdict, detail = self.probe(self.client(CLIENT_UDP))["probe_carry"](
            self.row(stealth_endpoint=f"127.0.0.1:{node.port}"), "stealth", self.key)
        self.assertEqual(verdict, "unreachable")
        self.assertIn("did not switch protocols", detail)

    def test_client_placement_needs_a_root_owned_closed_path_under_usr(self):
        """Sol 1 and Claude D6: the file and every directory above it are root-owned
        and closed to group and other writes, with no symlink on the way, under
        /usr. The test runs as an ordinary user, so lstat reports uid 0 for the
        paths under test and a clean root-owned directory above them."""
        base = os.path.realpath(self.dir)
        usr = os.path.join(base, "usr")
        bin_dir = os.path.join(usr, "bin")
        os.makedirs(bin_dir)
        client = os.path.join(bin_dir, "carry")
        Path(client).write_text("#!/bin/sh\n")
        os.chmod(client, 0o755)
        for directory in (usr, bin_dir):
            os.chmod(directory, 0o755)
        real_lstat = os.lstat

        def as_root(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            inside = str(path).startswith(usr)
            mode = info.st_mode if inside else stat.S_IFDIR | 0o755
            return os.stat_result((mode, info.st_ino, info.st_dev, info.st_nlink, 0, info.st_gid,
                                   info.st_size, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))

        place = self.probe(CARRY_CLIENT_ROOTS=(usr + "/",))["carry_client_placement"]
        outside = os.path.join(base, "elsewhere")
        os.makedirs(outside)
        stray = os.path.join(outside, "carry")
        Path(stray).write_text("#!/bin/sh\n")
        os.chmod(stray, 0o755)
        link = os.path.join(bin_dir, "link")
        os.symlink(client, link)
        with patch.object(os, "lstat", as_root):
            self.assertEqual(place(client), "")
            self.assertIn("D6", place(stray), "outside /usr")
            self.assertIn("D6", place(link), "a symlink")
            self.assertIn("D6", place(os.path.join(bin_dir, "absent")), "absent")
            self.assertIn("D6", place(bin_dir), "a directory is not a client")
            for mode in (0o775, 0o757, 0o777, 0o722):
                os.chmod(client, mode)
                self.assertIn("root-only", place(client), oct(mode))
            os.chmod(client, 0o755)
            for directory in (bin_dir, usr):
                os.chmod(directory, 0o777)
                self.assertIn("root-only", place(client), directory)
                os.chmod(directory, 0o755)
            self.assertEqual(place(client), "")
        if os.geteuid() != 0:
            self.assertIn("root-only", place(client), "owned by an ordinary user")

    def test_the_client_must_be_the_pinned_bytes(self):
        """Sol 1: placement and ownership are not provenance. The installer writes
        the digest with the path; the probe runs only bytes that match it."""
        client = self.client(CLIENT_UDP)
        digest = hashlib.sha256(Path(client).read_bytes()).hexdigest()
        wrong = "0" * 64
        for pin, expected in ((digest, ""), (wrong, "does not match"), ("", "no pinned SHA-256"),
                              ("abc", "no pinned SHA-256"), (digest[:-1], "no pinned SHA-256")):
            probe = load_probe(CARRY_CLIENT_BIN=client, CARRY_CLIENT_SHA256=pin)
            reason = probe["carry_client_unpinned"](client)
            self.assertTrue(reason == "" if not expected else expected in reason, (pin, reason))
        self.assertIn("unreadable", load_probe(CARRY_CLIENT_SHA256=digest)["carry_client_unpinned"](client + ".gone"))
        # The whole gate: placement (stubbed here, tested above) and then the pin.
        for pin, runs in ((digest, True), (wrong, False)):
            ran = os.path.join(self.dir, f"ran-{runs}")
            runner = self.client("#!/bin/sh\ntouch " + ran + "\n")
            pin = hashlib.sha256(Path(runner).read_bytes()).hexdigest() if runs else wrong
            probe = load_probe(CARRY_CLIENT_BIN=runner, CARRY_CLIENT_SHA256=pin, CARRY_CLIENT_TIMEOUT=5,
                               CARRY_DNS_NAME="hub.example.test", carry_client_placement=lambda _p: "")
            query, _ = probe["build_dns_query"]("hub.example.test")
            verdict, detail = probe["run_carry_client"]({"private_key": self.key}, query, self.key)
            self.assertEqual(os.path.exists(ran), runs, (runs, verdict, detail))
            if not runs:
                self.assertEqual(verdict, "unavailable", "P2-SEAM-H5: no request reached a client")
                self.assertIn("pinned SHA-256", detail)

    def test_the_run_deadline_leaves_room_for_the_workers_that_outlive_it(self):
        """Claude perf 5: a worker still running at the deadline is joined at exit.
        The deadline, one relay open and one client run must end inside the unit's
        TimeoutStartSec, or systemd kills the run."""
        probe = load_probe()
        text = hub_source()
        service = text.index("cat > /etc/systemd/system/wins-awg-carry-probe.service <<'EOF'\n")
        timeout = int(re.search(r"TimeoutStartSec=(\d+)", text[service:text.index("\nEOF\n", service)]).group(1))
        # P2-SEAM-H5: plus the 5 s reap wait when a timed-out client is killed.
        worst = (probe["CARRY_RUN_DEADLINE_SECONDS"] + probe["CARRY_RELAY_OPEN_SECONDS"]
                 + probe["CARRY_CLIENT_TIMEOUT"] + 10 + 5)
        self.assertLess(worst, timeout, (worst, timeout))

    def test_a_hostile_upgrade_response_cannot_grow_memory_or_pin_a_worker(self):
        """Claude perf 4: the upgrade response had no size cap and only a per-recv
        timeout, so a node that never ended its header, or dripped it, held a
        worker and grew the buffer for as long as it liked."""
        uid = uuid.UUID(XRAY_UUID).bytes
        for mode, expected, limit in (("flood", "too large", 5.0), ("drip", "in time", 6.0)):
            node = HostileUpgradeNode(mode)
            node.start()
            self.addCleanup(node.close)
            probe = load_probe(CARRY_RELAY_OPEN_SECONDS=2.0)
            relay = probe["StealthRelay"]("127.0.0.1", node.port, "none", "/stealth", uid, 9110)
            started = time.monotonic()
            try:
                with self.assertRaises(ConnectionError) as caught:
                    relay.start()
            finally:
                relay.close()
            self.assertIn(expected, str(caught.exception), mode)
            self.assertLess(time.monotonic() - started, limit, mode)
            if mode == "flood":
                self.assertLess(node.sent, 4 * 1024 * 1024)

    def test_the_private_key_file_must_be_owner_only_and_a_real_key(self):
        path = os.path.join(self.dir, "private.key")
        for content, mode, ok in ((self.key, 0o600, True), (self.key, 0o644, False), (self.key, 0o640, False),
                                  ("short", 0o600, False), ("!!!not-base64!!!", 0o600, False),
                                  (base64.b64encode(b"x" * 31).decode(), 0o600, False)):
            Path(path).write_text(content + "\n")
            os.chmod(path, mode)
            probe = self.probe(CARRY_KEY_FILE=path)
            key, error = probe["read_carry_private_key"]()
            self.assertEqual(bool(key), ok, (content, oct(mode), error))
        probe = self.probe(CARRY_KEY_FILE=os.path.join(self.dir, "absent"))
        self.assertEqual(probe["read_carry_private_key"]()[0], "")


# =================================================== the probe: the run ====

class CarryRunTests(unittest.TestCase):
    CARRY = ("udp", "stealth", "stealth_tls")

    def setUp(self):
        self.mod = load_hub()      # a database of its own: the run probes every due node in it
        self.key_file = os.path.join(self.mod._TMPDIR, f"carry-{id(self)}.key")
        Path(self.key_file).write_text(throwaway_key() + "\n")
        os.chmod(self.key_file, 0o600)
        self.calls = []
        self.verdicts = {}

    def run_carry(self, slug="", dry_run=False, source=None, **overrides):
        def probe_carry(row, transport, private_key):
            self.calls.append((row["slug"], transport))
            return self.verdicts.get((row["slug"], transport), self.verdicts.get(transport, ("reachable", "carried")))

        values = {"DB_PATH": self.mod._DB, "CARRY_PUBLIC_KEY": CANARY, "CARRY_KEY_FILE": self.key_file,
                  "probe_carry": probe_carry}
        values.update(overrides)
        probe = load_probe(source, **values)
        probe["probe_carry"] = values["probe_carry"]
        args = type("Args", (), {"slug": slug, "dry_run": dry_run})()
        return probe["carry_main"](args)

    def status(self, slug):
        row = node_row(self.mod, slug)
        return {t: (row[f"data_plane_{t}_carry_status"], row[f"data_plane_{t}_carry_ok_at"]) for t in self.CARRY}

    def aged(self, seconds):
        return (self.mod.utcnow() - timedelta(seconds=seconds)).isoformat()

    def test_an_open_node_gets_a_proof_per_transport_and_nothing_else_changes(self):
        slug = seed_node(self.mod, operator_enabled=1)
        before = dict(node_row(self.mod, slug))
        self.assertEqual(self.run_carry(), 0)
        status = self.status(slug)
        for transport in self.CARRY:
            self.assertEqual(status[transport][0], "ok")
            self.assertTrue(status[transport][1])
        after = dict(node_row(self.mod, slug))
        changed = {k for k in before if before[k] != after[k]}
        self.assertEqual(changed, {f"data_plane_{t}_carry_{s}" for t in self.CARRY
                                   for s in ("status", "ok_at", "checked_at")})

    def test_a_failure_records_failed_keeps_the_last_success_and_never_closes_the_node(self):
        last_success = self.aged(700)
        slug = seed_node(self.mod, operator_enabled=1, data_plane_status="ok",
                         data_plane_udp_carry_status="ok", data_plane_udp_carry_ok_at=last_success)
        self.verdicts["udp"] = ("unreachable", "no DNS reply")
        self.verdicts["stealth"] = ("probe_error", "client missing")
        self.verdicts["stealth_tls"] = ("unconfigured", "none")
        self.run_carry()
        status = self.status(slug)
        self.assertEqual(status["udp"][0], "failed")
        self.assertEqual(status["udp"][1], last_success, "the last success time is kept")
        self.assertEqual(status["stealth"][0], "probe_error")
        self.assertEqual(status["stealth_tls"][0], "unconfigured")
        row = node_row(self.mod, slug)
        self.assertEqual(row["operator_enabled"], 1, "a carry failure never closes an open node")
        self.assertIsNone(row["health_closed_at"])

    def test_cadence_open_600_pending_120_and_unprobed_classes(self):
        now = self.mod.utcnow().isoformat()
        fresh = {f"data_plane_{t}_carry_{s}": v for t in self.CARRY for s, v in (("status", "ok"), ("ok_at", self.aged(100)))}
        open_fresh = seed_node(self.mod, operator_enabled=1, **fresh)
        open_old = seed_node(self.mod, operator_enabled=1, **{k: (self.aged(650) if k.endswith("ok_at") else v) for k, v in fresh.items()})
        pending_fresh = seed_node(self.mod, operator_enabled=0, health_closed_reason="installer_rerun",
                                  deployment_completed_at=now, **{k: (self.aged(30) if k.endswith("ok_at") else v) for k, v in fresh.items()})
        pending_old = seed_node(self.mod, operator_enabled=0, health_closed_reason="fresh_install",
                                deployment_completed_at=now, **fresh)
        closed = seed_node(self.mod, operator_enabled=0)
        retired = seed_node(self.mod, operator_enabled=1, retired_at=now)
        withdrawn = seed_node(self.mod, operator_enabled=1, deployment_withdrawal_id="w1")
        self.run_carry()
        probed = {slug for slug, _ in self.calls}
        self.assertEqual(probed, {open_old, pending_old})
        self.assertNotIn(open_fresh, probed)
        self.assertNotIn(pending_fresh, probed)
        for slug in (closed, retired, withdrawn):
            self.assertNotIn(slug, probed)

    def test_nothing_is_written_without_a_key_or_on_a_dry_run(self):
        slug = seed_node(self.mod, operator_enabled=1)
        self.assertEqual(self.run_carry(CARRY_PUBLIC_KEY=""), 0)
        self.assertEqual(self.calls, [])
        os.chmod(self.key_file, 0o644)
        self.assertEqual(self.run_carry(), 0)
        self.assertEqual(self.calls, [], "a key file open to others is refused")
        os.chmod(self.key_file, 0o600)
        self.run_carry(dry_run=True)
        self.assertTrue(self.calls)
        self.assertEqual({v[0] for v in self.status(slug).values()}, {"unknown"})

    def test_an_explicit_slug_is_probed_even_when_not_due(self):
        fresh = {f"data_plane_{t}_carry_{s}": v for t in self.CARRY for s, v in (("status", "ok"), ("ok_at", self.aged(5)))}
        slug = seed_node(self.mod, operator_enabled=1, **fresh)
        other = seed_node(self.mod, operator_enabled=1)
        self.run_carry(slug=slug)
        self.assertEqual({s for s, _ in self.calls}, {slug})
        self.assertNotIn(other, {s for s, _ in self.calls})

    def test_every_turn_2_run_level_mutant_is_killed(self):
        sound = run_level_facts(self)
        self.assertEqual({k: v for k, v in sound.items() if not v}, {}, "the shipped source")
        for name, (old, new) in RUN_FIX_MUTANTS.items():
            with self.subTest(name):
                broken = {k: v for k, v in run_level_facts(self, replace_once(hub_source(), old, new)).items() if not v}
                self.assertTrue(broken, f"mutant survived: {name}")

    def test_pending_nodes_run_first_so_slow_open_failures_cannot_starve_them(self):
        opens = [seed_node(self.mod, operator_enabled=1) for _ in range(12)]
        pending = seed_node(self.mod, operator_enabled=0, health_closed_reason="fresh_install",
                            deployment_completed_at=self.mod.utcnow().isoformat())
        order = []
        values = {"DB_PATH": self.mod._DB, "CARRY_PUBLIC_KEY": CANARY, "CARRY_KEY_FILE": self.key_file}
        probe = load_probe(**values)
        probe["probe_carry"] = lambda row, transport, _key: (order.append((row["slug"], transport))
                                                              or ("reachable", "ok"))
        probe["carry_main"](type("Args", (), {"slug": "", "dry_run": True})())
        # P2-SEAM-H5: each transport is one lane with one client (P-16), so the
        # order that matters is each lane's own.
        for transport in self.CARRY:
            lane = [slug for slug, name in order if name == transport]
            self.assertEqual(lane[0], pending, transport)
            self.assertEqual(len(lane), len(opens) + 1, transport)

    def test_an_unchanged_failure_refreshes_only_the_attempt_time(self):
        """The attempt time drives the cadence, so a repeated failure must advance
        it; the status and the last success stay as they were."""
        slug = seed_node(self.mod, operator_enabled=1, data_plane_udp_carry_status="probe_error",
                         data_plane_udp_carry_ok_at="2026-10-06T00:00:00")
        probe = load_probe(DB_PATH=self.mod._DB)
        with closing(probe["connect_db"]()) as conn:
            probe["ensure_columns"](conn)
            self.assertTrue(probe["apply_carry_verdict"](conn, slug, "udp", "probe_error", "2026-10-07T00:00:00"))
        row = node_row(self.mod, slug)
        self.assertEqual((row["data_plane_udp_carry_status"], row["data_plane_udp_carry_ok_at"],
                          row["data_plane_udp_carry_checked_at"]),
                         ("probe_error", "2026-10-06T00:00:00", "2026-10-07T00:00:00"))
        with closing(probe["connect_db"]()) as conn:
            probe["apply_carry_verdict"](conn, slug, "udp", "reachable", "2026-10-07T00:02:00")
        row = node_row(self.mod, slug)
        self.assertEqual((row["data_plane_udp_carry_status"], row["data_plane_udp_carry_ok_at"],
                          row["data_plane_udp_carry_checked_at"]),
                         ("ok", "2026-10-07T00:02:00", "2026-10-07T00:02:00"))

    def test_a_failing_transport_waits_its_cadence_so_the_unattempted_nodes_get_the_run(self):
        """Sol 6: failed jobs stayed due on every run, so the same front of the
        queue was retried while later nodes were never reached. An attempt now
        starts the interval."""
        attempted = self.aged(100)
        failing = {f"data_plane_{t}_carry_{k}": v for t in self.CARRY
                   for k, v in (("status", "failed"), ("checked_at", attempted))}
        stale = [seed_node(self.mod, operator_enabled=1, **failing) for _ in range(3)]
        fresh = seed_node(self.mod, operator_enabled=1)
        pending = seed_node(self.mod, operator_enabled=0, health_closed_reason="installer_rerun",
                            deployment_completed_at=self.mod.utcnow().isoformat(),
                            **dict(failing, **{f"data_plane_{t}_carry_checked_at": self.aged(100) for t in self.CARRY}))
        self.run_carry()
        self.assertEqual({slug for slug, _ in self.calls}, {fresh, pending},
                         "attempted 100 s ago: an open node waits for 600 s, a pending one is due at 120 s")
        for slug in stale:
            self.assertNotIn(slug, {s for s, _ in self.calls})
        self.calls.clear()
        later = {f"data_plane_{t}_carry_checked_at": self.aged(650) for t in self.CARRY}
        with self.mod.get_db() as conn:
            for slug in stale:
                conn.execute("UPDATE nodes SET " + ", ".join(f"{c} = ?" for c in later) + " WHERE slug = ?",
                             (*later.values(), slug))
        self.run_carry()
        self.assertTrue({slug for slug, _ in self.calls} >= set(stale), "due again after the cadence")

    def test_slow_failures_under_a_short_deadline_do_not_hide_later_nodes_across_runs(self):
        for _ in range(4):
            seed_node(self.mod, operator_enabled=1)

        def slow_failure(row, transport, _key):
            time.sleep(0.3)
            return "unreachable", "slow"

        reached = []
        for run in range(8):
            self.run_carry(CARRY_WORKERS=1, CARRY_RUN_DEADLINE_SECONDS=1.0, probe_carry=slow_failure)
            with closing(sqlite3.connect(self.mod._DB)) as conn:
                count = conn.execute(
                    "SELECT " + " + ".join(f"({'data_plane_' + t + '_carry_checked_at'} IS NOT NULL)" for t in self.CARRY)
                    + " FROM nodes WHERE operator_enabled = 1").fetchall()
            reached.append(sum(row[0] for row in count))
            if reached[-1] == 12:
                break
        self.assertEqual(reached[-1], 12, f"every (node, transport) attempted within 8 short runs: {reached}")
        self.assertEqual(reached, sorted(set(reached)), f"each run reaches new jobs: {reached}")

    def test_a_proof_is_stamped_with_the_run_start_not_the_write_time(self):
        """Sol 4: a verdict written after a slow probe must not look newer than a
        deployment completed while it ran."""
        slug = seed_node(self.mod, operator_enabled=1)

        def slow_success(row, transport, _key):
            time.sleep(0.6)
            return "reachable", "carried"

        before = self.mod.utcnow().replace(tzinfo=None)
        self.run_carry(CARRY_WORKERS=3, probe_carry=slow_success)
        stamp = datetime.fromisoformat(self.status(slug)["udp"][1])
        self.assertLess(stamp, before + timedelta(seconds=0.4), "stamped when the run started")
        self.assertEqual(self.status(slug)["udp"][1], node_row(self.mod, slug)["data_plane_udp_carry_checked_at"])

    def test_a_verdict_about_a_deployment_that_changed_during_the_probe_is_discarded(self):
        """Sol 4: publication re-reads the node row; a changed deployment, key,
        endpoint, profile, withdrawal or retirement makes the verdict stale."""
        changes = {
            "deployment_completed_at": "2026-10-07T23:00:00",
            "deployment_withdrawal_id": "w-1",
            "retired_at": "2026-10-07T23:00:00",
            "public_key": throwaway_key(),
            "endpoint": "192.0.2.99:9110",
            "wg_port": 9999,
            "obfuscation_json": json.dumps({"Jc": 9}),
            "stealth_endpoint": "other.example.test:80",
            "xray_uuid": "00000000-0000-4000-8000-0000000000bb",
        }
        for column, value in changes.items():
            with self.subTest(column):
                slug = seed_node(self.mod, operator_enabled=1)

                def probe_and_change(row, transport, _key, slug=slug, column=column, value=value):
                    with self.mod.get_db() as conn:
                        conn.execute(f"UPDATE nodes SET {column} = ? WHERE slug = ?", (value, slug))
                    return "reachable", "carried"

                self.run_carry(slug=slug, probe_carry=probe_and_change)
                status = self.status(slug)
                for transport in self.CARRY:
                    self.assertEqual(status[transport], ("unknown", None), (column, transport))
                    self.assertIsNone(node_row(self.mod, slug)[f"data_plane_{transport}_carry_checked_at"])
        slug = seed_node(self.mod, operator_enabled=1)

        def rename(row, transport, _key):
            with self.mod.get_db() as conn:
                conn.execute("UPDATE nodes SET name = 'renamed' WHERE slug = ?", (slug,))
            return "reachable", "carried"

        self.run_carry(slug=slug, probe_carry=rename)
        self.assertEqual(self.status(slug)["udp"][0], "ok", "a change that is not part of the deployment identity")


# ================================================== installer shell side ====

class InstallerKeyTests(unittest.TestCase):
    """The installer's own functions under bash, with a fake wg and no root."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="h5-install-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        shims = os.path.join(self.dir, "shims")
        os.makedirs(shims)
        Path(shims, "wg").write_text(textwrap.dedent(f"""\
            #!{sys.executable}
            import base64, hashlib, os, sys
            if sys.argv[1] == "genkey":
                print(base64.b64encode(os.urandom(32)).decode())
            elif sys.argv[1] == "pubkey":
                # A link the app plants while the installer derives the public key.
                at = os.environ.get("WG_PLANT_AT")
                if at and not os.path.lexists(at):
                    os.symlink(os.environ["WG_PLANT_TO"], at)
                print(base64.b64encode(hashlib.sha256(sys.stdin.read().strip().encode()).digest()).decode())
            else:
                sys.exit(2)
            """))
        os.chmod(os.path.join(shims, "wg"), 0o755)
        self.shims = shims
        self.canary_dir = os.path.join(self.dir, "awg-canary")

    def extract(self, source=None):
        text = hub_source() if source is None else source
        a = text.index("awg_canary_key_is_raw32_b64() {")
        b = text.index("backup_existing_db() {", a)
        return text[a:b]

    def run_bash(self, body, path=None, extra_env=None, source=None):
        script = textwrap.dedent(f"""\
            set -uo pipefail
            log() {{ echo "[INFO] $*"; }}
            err() {{ echo "[ERR] $*"; }}
            install() {{ mkdir -p "${{@: -1}}" && chmod 700 "${{@: -1}}"; }}
            chown() {{ :; }}
            HUB_DOMAIN=hub.example.test
            AWG_CANARY_DIR={self.canary_dir!r}
            """) + self.extract(source) + textwrap.dedent("""
            env_kv_buffer=''
            write_env_kv() { env_kv_buffer+="$1='$2'"$'\\n'; }
            """) + body
        env = {"PATH": (path if path is not None else self.shims + os.pathsep + os.environ["PATH"]),
               "HOME": self.dir, "LC_ALL": "C"}
        env.update(extra_env or {})
        return subprocess.run([BASH, "--noprofile", "--norc", "-c", script], capture_output=True, text=True, env=env)

    def private(self):
        return Path(self.canary_dir, "private.key")

    def test_first_run_creates_one_owner_only_key_and_writes_only_the_public_half(self):
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"')
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        private = self.private().read_text().strip()
        self.assertEqual(stat.S_IMODE(self.private().stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.canary_dir).st_mode), 0o700)
        public = base64.b64encode(hashlib.sha256(private.encode()).digest()).decode()
        self.assertIn(f"AWG_CANARY_PUBLIC_KEY='{public}'", done.stdout)
        self.assertIn(f"AWG_CANARY_KEY_FILE='{self.canary_dir}/private.key'", done.stdout)
        self.assertIn("AWG_CANARY_DNS_NAME='hub.example.test'", done.stdout)
        self.assertNotIn(private, done.stdout + done.stderr, "the private key never reaches the env or the log")
        self.assertEqual(Path(self.canary_dir, "public.key").read_text().strip(), public)
        # The installer stages wins-awg-carry-client (install_awg_carry_client)
        # and the env names it with this machine's pin unless the operator
        # names another client; test_hub_awg_carry_client.py holds the pins
        # to the built binaries and the receipt.
        self.assertIn("AWG_CARRY_CLIENT_BIN='/usr/local/bin/wins-awg-carry-client'", done.stdout)
        self.assertRegex(done.stdout, r"AWG_CARRY_CLIENT_SHA256='[0-9a-f]{64}'")

    def test_a_rerun_keeps_the_key(self):
        self.run_bash("write_awg_canary_runtime_env")
        first = self.private().read_text()
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"')
        self.assertIn("rc=0", done.stdout)
        self.assertEqual(self.private().read_text(), first)
        self.assertEqual(stat.S_IMODE(self.private().stat().st_mode), 0o600)

    def test_a_loose_key_file_is_tightened_not_trusted(self):
        self.run_bash("write_awg_canary_runtime_env")
        os.chmod(self.private(), 0o644)
        self.run_bash("write_awg_canary_runtime_env")
        self.assertEqual(stat.S_IMODE(self.private().stat().st_mode), 0o600)

    def test_a_missing_wg_or_a_bad_derived_key_stops_the_env_write(self):
        bare = os.path.join(self.dir, "bare")
        os.makedirs(bare)
        for tool in ("base64", "wc", "tr", "mv", "rm", "chmod", "mkdir", "printf", "cat"):
            found = shutil.which(tool)
            if found:
                os.symlink(found, os.path.join(bare, tool))
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"', path=bare)
        self.assertIn("rc=1", done.stdout)
        self.assertNotIn("AWG_CANARY_PUBLIC_KEY", done.stdout)
        Path(self.shims, "wg").write_text(f"#!{sys.executable}\nimport sys\nprint('short') if sys.argv[1] == 'pubkey' else print('AAAA')\n")
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"')
        self.assertIn("rc=1", done.stdout)
        self.assertNotIn("AWG_CANARY_PUBLIC_KEY", done.stdout)

    def test_the_operator_client_path_is_validated_and_written(self):
        for value, ok in (("/usr/local/bin/wins-awg-carry-client", True), ("relative/client", False),
                          ("/root/vpn_auth/awg-carry-client", False), ("/var/log/winsvpn/client", False),
                          ("/usr/local/bin/../../../root/vpn_auth/client", False), ("/opt/client", False),
                          ("/usr/local/bin/a b", False), ("/usr/local/bin/a;b", False), ("/x/$(id)", False)):
            done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"',
                                 extra_env={"AWG_CARRY_CLIENT_BIN": value, "AWG_CARRY_CLIENT_SHA256": "ab" * 32})
            self.assertEqual("rc=0" in done.stdout, ok, (value, done.stdout))
            self.assertEqual(f"AWG_CARRY_CLIENT_BIN='{value}'" in done.stdout, ok, value)

    def test_the_operator_client_must_come_with_its_pinned_digest(self):
        for digest, ok in (("ab" * 32, True), ("", False), ("AB" * 32, False), ("ab" * 31, False),
                           ("ab" * 33, False), ("zz" * 32, False)):
            done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"',
                                 extra_env={"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/wins-awg-carry-client",
                                            "AWG_CARRY_CLIENT_SHA256": digest})
            self.assertEqual("rc=0" in done.stdout, ok, (digest, done.stdout))
            self.assertEqual(f"AWG_CARRY_CLIENT_SHA256='{digest}'" in done.stdout, ok, digest)

    def test_a_replaced_private_key_is_refused_not_adopted(self):
        """Sol Q6: the nodes keep the old public key and nothing revokes it, so a
        silently replaced key would leave a stale canary peer on every node."""
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"')
        self.assertIn("rc=0", done.stdout)
        recorded = Path(self.canary_dir, "public.key").read_text()
        self.private().write_text(throwaway_key() + "\n")
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"')
        self.assertIn("rc=1", done.stdout, done.stdout)
        self.assertIn("Rotation is not supported", done.stdout + done.stderr)
        self.assertNotIn("AWG_CANARY_PUBLIC_KEY", done.stdout, "the new key never reaches the env")
        self.assertEqual(Path(self.canary_dir, "public.key").read_text(), recorded)
        Path(self.canary_dir, "public.key").unlink()
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"')
        self.assertIn("rc=0", done.stdout, "removing the record is the explicit way to adopt a new key")

    def test_a_symlinked_or_irregular_key_path_is_refused(self):
        """Sol Q7: the hub app runs as root with this directory writable, so the
        installer does not follow what the app could have put in its place."""
        elsewhere = os.path.join(self.dir, "elsewhere")
        os.makedirs(elsewhere)
        os.symlink(elsewhere, self.canary_dir)
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"')
        self.assertIn("rc=1", done.stdout, done.stdout)
        self.assertEqual(os.listdir(elsewhere), [], "nothing was written through the link")
        os.unlink(self.canary_dir)
        os.makedirs(self.canary_dir)
        os.symlink(os.path.join(elsewhere, "k"), os.path.join(self.canary_dir, "private.key"))
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"')
        self.assertIn("rc=1", done.stdout, done.stdout)
        os.unlink(os.path.join(self.canary_dir, "private.key"))
        os.makedirs(os.path.join(self.canary_dir, "private.key"))
        done = self.run_bash('write_awg_canary_runtime_env; echo "rc=$?"')
        self.assertIn("rc=1", done.stdout, done.stdout)

    # Fable, Turn 2 vote: the app can plant a link at ANY name in the canary
    # directory, not only at the directory and private.key. Turn 2 wrote the
    # fresh key through a link at private.key.new and the public key through a
    # link at public.key (rc 0 both times).
    READ = 'write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"'

    def victim(self, name, content=None):
        """A file outside the canary directory a link may point at: existing
        (content given, mode 0600) or absent (a dangling link)."""
        path = Path(self.dir, name)
        if os.path.lexists(path):
            os.unlink(path)
        if content is not None:
            path.write_text(content)
            os.chmod(path, 0o600)
        return path

    def untouched(self, victim, content):
        if content is None:
            return not os.path.lexists(victim)
        return victim.read_text() == content and stat.S_IMODE(victim.stat().st_mode) == 0o600

    def run_planted(self, at, to, when, source=None):
        """Run the env writer with a link canary_dir/`at` -> `to` planted by the
        app: "before" the run; "install" right after the link checks (the
        directory is created next); "pubkey" while the public key is derived;
        "rm" the instant after the installer unlinks that very name."""
        link = os.path.join(self.canary_dir, at)
        done_marker = os.path.join(self.dir, "planted")
        if os.path.lexists(done_marker):
            os.unlink(done_marker)
        env = {"PLANT_AT": link, "PLANT_TO": str(to), "PLANT_DONE": done_marker}
        body, path = self.READ, None
        if when == "before":
            os.makedirs(self.canary_dir, exist_ok=True)
            os.symlink(to, link)
        elif when == "install":
            body = textwrap.dedent("""\
                install() {
                  mkdir -p "${@: -1}" && chmod 700 "${@: -1}" || return 1
                  [[ -e "${PLANT_DONE}" ]] || { : > "${PLANT_DONE}"; ln -s "${PLANT_TO}" "${PLANT_AT}"; }
                }
                """) + body
        elif when == "pubkey":
            env.update({"WG_PLANT_AT": link, "WG_PLANT_TO": str(to)})
        elif when == "rm":
            race = os.path.join(self.dir, "race")
            os.makedirs(race, exist_ok=True)
            Path(race, "rm").write_text(textwrap.dedent(f"""\
                #!{BASH}
                {shutil.which("rm")} "$@"; rc=$?
                for a in "$@"; do
                  if [[ "$a" == "$PLANT_AT" && ! -e "$PLANT_DONE" ]]; then
                    : > "$PLANT_DONE"; ln -s "$PLANT_TO" "$a"
                  fi
                done
                exit $rc
                """))
            os.chmod(os.path.join(race, "rm"), 0o755)
            path = os.pathsep.join((race, self.shims, os.environ["PATH"]))
        else:
            raise ValueError(when)
        return self.run_bash(body, path=path, extra_env=env, source=source)

    def first_run_without_record(self, source=None):
        """A hub that already has its key, with the public-key record absent."""
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        done = self.run_bash(self.READ, source=source)
        assert "rc=0" in done.stdout, done.stdout + done.stderr
        Path(self.canary_dir, "public.key").unlink()
        return self.private().read_text()

    def test_a_link_planted_at_the_private_key_staging_name_is_refused(self):
        """Fable case A: no key yet, private.key.new links to a victim. Turn 2
        overwrote the victim with a fresh private key (rc 0) and private.key
        became the link."""
        for kind, content in (("existing", "untouched"), ("dangling", None)):
            with self.subTest(kind):
                shutil.rmtree(self.canary_dir, ignore_errors=True)
                victim = self.victim(f"victim-private-{kind}", content)
                done = self.run_planted("private.key.new", victim, "before")
                self.assertTrue(self.untouched(victim, content), "nothing was written through the link")
                self.assertIn("rc=1", done.stdout, done.stdout)
                self.assertNotIn("AWG_CANARY_PUBLIC_KEY", done.stdout)
                self.assertTrue(os.path.islink(os.path.join(self.canary_dir, "private.key.new")), "nothing was changed")
                self.assertFalse(os.path.lexists(self.private()), "no key was adopted through the link")

    def test_a_link_planted_at_the_public_key_record_is_refused(self):
        """Fable case B: valid key, public.key a dangling link. Turn 2 created the
        target 0644 through it (rc 0); a link to an existing empty file was
        written and chmodded 0644 the same way. Case C (a link to a file holding
        another key) was already refused by the rotation compare and stays so."""
        for kind, content in (("dangling", None), ("empty", ""), ("another key", throwaway_key() + "\n")):
            with self.subTest(kind):
                key = self.first_run_without_record()
                victim = self.victim("victim-public-" + kind.replace(" ", "-"), content)
                done = self.run_planted("public.key", victim, "before")
                self.assertTrue(self.untouched(victim, content), "nothing written or chmodded through the link")
                self.assertIn("rc=1", done.stdout, done.stdout)
                self.assertNotIn("AWG_CANARY_PUBLIC_KEY", done.stdout)
                self.assertTrue(os.path.islink(os.path.join(self.canary_dir, "public.key")), "nothing was changed")
                self.assertEqual(self.private().read_text(), key)

    def test_a_link_planted_at_the_public_key_staging_name_is_refused(self):
        """public.key.new is the staging name this turn introduces; a link
        already there is refused like the other two names."""
        key = self.first_run_without_record()
        victim = self.victim("victim-public-new", "untouched")
        done = self.run_planted("public.key.new", victim, "before")
        self.assertIn("rc=1", done.stdout, done.stdout)
        self.assertTrue(self.untouched(victim, "untouched"))
        self.assertFalse(os.path.lexists(Path(self.canary_dir, "public.key")))
        self.assertEqual(self.private().read_text(), key)

    def test_a_link_planted_after_the_checks_is_never_written_through(self):
        """The directory stays app-writable, so a link can appear between the
        checks and the writes. Each staging name is unlinked right before it is
        created, the create refuses a name that reappears (noclobber, O_EXCL on
        an absent name, refusal on a regular file), and the record is replaced
        by rename, which replaces a link instead of following it."""
        rows = (  # name, when the app plants, a fresh key (else an existing one), rc
            ("private.key.new", "install", True, 0),
            ("private.key.new", "rm", True, 1),
            ("public.key", "pubkey", False, 0),
            ("public.key.new", "pubkey", False, 0),
            ("public.key.new", "rm", False, 1),
        )
        for at, when, fresh, rc in rows:
            for kind, content in (("existing", ""), ("dangling", None)):
                with self.subTest(at=at, when=when, kind=kind):
                    if fresh:
                        shutil.rmtree(self.canary_dir, ignore_errors=True)
                        key = None
                    else:
                        key = self.first_run_without_record()
                    victim = self.victim(f"victim-race-{kind}", content)
                    done = self.run_planted(at, victim, when)
                    self.assertTrue(self.untouched(victim, content), "nothing written or chmodded through the link")
                    self.assertIn(f"rc={rc}", done.stdout, done.stdout + done.stderr)
                    self.assertFalse(os.path.islink(self.private()))
                    if key is not None:
                        self.assertEqual(self.private().read_text(), key)
                    if rc == 0:
                        record = Path(self.canary_dir, "public.key")
                        self.assertFalse(record.is_symlink())
                        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o644)
                        self.assertIn(f"AWG_CANARY_PUBLIC_KEY='{record.read_text().strip()}'", done.stdout)
                        self.assertEqual(stat.S_IMODE(self.private().stat().st_mode), 0o600)

    def test_stale_staging_files_from_an_interrupted_run_do_not_block_a_rerun(self):
        """A regular file left at a staging name (an interrupted run) is
        unlinked and replaced; noclobber must not turn it into a refusal."""
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        os.makedirs(self.canary_dir)
        Path(self.canary_dir, "private.key.new").write_text("stale")
        done = self.run_bash(self.READ)
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertNotEqual(self.private().read_text().strip(), "stale")
        key = self.first_run_without_record()
        Path(self.canary_dir, "public.key.new").write_text("stale")
        done = self.run_bash(self.READ)
        self.assertIn("rc=0", done.stdout, done.stdout + done.stderr)
        self.assertEqual(self.private().read_text(), key)
        self.assertNotEqual(Path(self.canary_dir, "public.key").read_text().strip(), "stale")

    def link_facts(self, source=None):
        """Every value is True for the shipped source; each link mutant must make
        the named one False."""
        facts = {}

        def planted(at, when, content, fresh):
            if fresh:
                shutil.rmtree(self.canary_dir, ignore_errors=True)
            else:
                self.first_run_without_record(source)
            victim = self.victim("victim-fact", content)
            done = self.run_planted(at, victim, when, source=source)
            return done, self.untouched(victim, content), os.path.islink(os.path.join(self.canary_dir, at))

        done, intact, kept = planted("private.key.new", "before", "untouched", True)
        facts["a private staging link is refused and left in place"] = "rc=1" in done.stdout and intact and kept
        done, intact, kept = planted("public.key", "before", None, False)
        facts["a public record link is refused and left in place"] = "rc=1" in done.stdout and intact and kept
        done, intact, kept = planted("public.key.new", "before", "untouched", False)
        facts["a public staging link is refused and left in place"] = "rc=1" in done.stdout and intact and kept
        done, intact, _ = planted("private.key.new", "install", "", True)
        facts["a private staging link planted after the checks is unlinked"] = "rc=0" in done.stdout and intact
        done, intact, _ = planted("private.key.new", "rm", None, True)
        facts["a private staging link planted after the unlink is refused by noclobber"] = "rc=1" in done.stdout and intact
        done, intact, _ = planted("public.key", "pubkey", None, False)
        facts["a public record link planted after the checks is replaced, not followed"] = (
            "rc=0" in done.stdout and intact and not Path(self.canary_dir, "public.key").is_symlink())
        done, intact, _ = planted("public.key.new", "pubkey", "", False)
        facts["a public staging link planted after the checks is unlinked"] = "rc=0" in done.stdout and intact
        done, intact, _ = planted("public.key.new", "rm", None, False)
        facts["a public staging link planted after the unlink is refused by noclobber"] = "rc=1" in done.stdout and intact
        return facts

    def test_link_mutants_are_killed(self):
        self.assertEqual({k: v for k, v in self.link_facts().items() if not v}, {}, "the shipped source")
        mutants = {  # name: (edits, the fact that must turn False)
            "staging names and the record are not refused as links": ([(
                'if [[ -L "${private_file}.new" || -L "${AWG_CANARY_DIR}/public.key" || -L "${AWG_CANARY_DIR}/public.key.new" ]]; then',
                "if false; then")], "a public record link is refused and left in place"),
            "the private staging write follows a link (no noclobber)": ([(
                "( umask 077; set -C; wg genkey >", "( umask 077; wg genkey >")],
                "a private staging link planted after the unlink is refused by noclobber"),
            "the private staging name is not unlinked first": ([(
                '    rm -f -- "${private_file}.new" || return 1\n', "")],
                "a private staging link planted after the checks is unlinked"),
            "the public record is written in place (Turn 2)": ([(
                '  rm -f -- "${AWG_CANARY_DIR}/public.key.new" || return 1\n'
                '  ( set -C; printf \'%s\\n\' "${public_key}" > "${AWG_CANARY_DIR}/public.key.new" ) || { rm -f -- "${AWG_CANARY_DIR}/public.key.new"; return 1; }\n'
                '  chmod 644 "${AWG_CANARY_DIR}/public.key.new" || return 1\n'
                '  mv -f -- "${AWG_CANARY_DIR}/public.key.new" "${AWG_CANARY_DIR}/public.key" || return 1\n',
                '  printf \'%s\\n\' "${public_key}" > "${AWG_CANARY_DIR}/public.key"\n'
                '  chmod 644 "${AWG_CANARY_DIR}/public.key"\n')],
                "a public record link planted after the checks is replaced, not followed"),
            "the public staging write follows a link (no noclobber)": ([(
                "( set -C; printf '%s\\n' \"${public_key}\" >", "( printf '%s\\n' \"${public_key}\" >")],
                "a public staging link planted after the unlink is refused by noclobber"),
            "the public staging name is not unlinked first": ([(
                '  rm -f -- "${AWG_CANARY_DIR}/public.key.new" || return 1\n', "")],
                "a public staging link planted after the checks is unlinked"),
        }
        for name, (edits, fact) in mutants.items():
            with self.subTest(name):
                mutated = hub_source()
                for old, new in edits:
                    mutated = replace_once(mutated, old, new)
                self.assertFalse(self.link_facts(mutated)[fact], f"mutant survived: {name}")

    def battery(self, source=None):
        """Facts about the installer's key and client handling; every one is True
        for the shipped source. Used by the mutant test."""
        facts = {}
        read = 'write_awg_canary_runtime_env; echo "rc=$?"; printf "%s" "$env_kv_buffer"'
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        self.run_bash("write_awg_canary_runtime_env", source=source)
        if self.private().exists():
            self.private().write_text(throwaway_key() + "\n")
        facts["a replaced key is refused"] = "rc=1" in self.run_bash(read, source=source).stdout
        shutil.rmtree(self.canary_dir, ignore_errors=True)
        elsewhere = os.path.join(self.dir, "elsewhere2")
        os.makedirs(elsewhere, exist_ok=True)
        os.symlink(elsewhere, self.canary_dir)
        facts["a symlinked directory is refused"] = "rc=1" in self.run_bash(read, source=source).stdout
        os.unlink(self.canary_dir)
        pin = "ab" * 32
        for label, extra, refused in (
                ("a client in the app directory", {"AWG_CARRY_CLIENT_BIN": "/root/vpn_auth/c", "AWG_CARRY_CLIENT_SHA256": pin}, True),
                ("a client reached through ..", {"AWG_CARRY_CLIENT_BIN": "/usr/local/bin/../../../root/c", "AWG_CARRY_CLIENT_SHA256": pin}, True),
                ("a client without a digest", {"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/c"}, True),
                ("a pinned client under /usr", {"AWG_CARRY_CLIENT_BIN": "/usr/local/lib/c", "AWG_CARRY_CLIENT_SHA256": pin}, False)):
            shutil.rmtree(self.canary_dir, ignore_errors=True)
            done = self.run_bash(read, source=source, extra_env=extra)
            facts[label + (" is refused" if refused else " is accepted")] = ("rc=1" in done.stdout) == refused
        return facts

    def test_installer_mutants_are_killed(self):
        self.assertEqual({k: v for k, v in self.battery().items() if not v}, {}, "the shipped source")
        mutants = {
            "the recorded public key is not compared": [(
                "  if [[ -s \"${AWG_CANARY_DIR}/public.key\" ]] \\\n     && [[ \"$(tr -d '[:space:]' < \"${AWG_CANARY_DIR}/public.key\")\" != \"${public_key}\" ]]; then",
                "  if false; then")],
            "a symlinked key directory is followed": [(
                'if [[ -L "${AWG_CANARY_DIR}" || -L "${private_file}" ]]; then', "if false; then")],
            "the client may sit anywhere": [(
                "^/usr/(local/)?(bin|sbin|lib|libexec)(/[A-Za-z0-9_.-]+)+$", "^(/[A-Za-z0-9_.-]+)+$")],
            "the client path may climb out with ..": [(
                ' \\\n       && "${AWG_CARRY_CLIENT_BIN}/" != *"/../"* && "${AWG_CARRY_CLIENT_BIN}/" != *"/./"*', "")],
            "no digest is required with the client": [(
                '[[ "${AWG_CARRY_CLIENT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {', "true || {")],
        }
        for name, edits in mutants.items():
            with self.subTest(name):
                mutated = hub_source()
                for old, new in edits:
                    mutated = replace_once(mutated, old, new)
                self.assertTrue({k: v for k, v in self.battery(mutated).items() if not v},
                                f"mutant survived: {name}")

    def test_the_env_writer_runs_inside_write_env_before_the_buffer_is_committed(self):
        text = hub_source()
        call = text.index("  write_awg_canary_runtime_env || return 1\n")
        self.assertGreater(call, text.index("  write_winn3_runtime_env || return 1\n"))
        self.assertLess(call, text.index("  unset -f write_env_kv\n", call - 200))
        self.assertLess(call, text.index("atomic_replace_file \"${ENV_FILE}\" \"${env_kv_buffer}\" 600"))

    def test_the_carry_unit_runs_the_same_script_in_carry_mode_and_is_enabled(self):
        text = hub_source()
        service = text.index("cat > /etc/systemd/system/wins-awg-carry-probe.service <<'EOF'\n")
        body = text[service:text.index("\nEOF\n", service)]
        self.assertIn("wins_node_dataplane_probe.py --carry", body)
        timeout = int(re.search(r"TimeoutStartSec=(\d+)", body).group(1))
        self.assertLess(timeout, 120, "a run must end before the next timer tick")
        timer = text.index("cat > /etc/systemd/system/wins-awg-carry-probe.timer <<'EOF'\n")
        self.assertIn("OnUnitActiveSec=120s", text[timer:text.index("\nEOF\n", timer)])
        self.assertIn("systemctl enable --now wins-awg-carry-probe.timer", text)
        self.assertLess(text.index("systemctl daemon-reload", timer), text.index("systemctl enable --now wins-awg-carry-probe.timer"))


def shell_function(text, name):
    start = text.index(f"\n{name}() {{\n") + 1
    return text[start:text.index("\n}\n", start) + 3]


class InstallerSecretLinkTests(unittest.TestCase):
    """The same pattern Fable measured in the canary directory, elsewhere in the
    installer: key or secret material written by root to a name inside a
    directory the hub app can write (wins-hub.service ReadWritePaths: ${APP_DIR},
    /root/.ssh, ...). A link planted there must be refused, not followed. Each
    case below wrote through the link on Turn 2."""

    maxDiff = None

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="h5-secret-links-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.app = os.path.join(self.dir, "vpn_auth")
        os.makedirs(self.app)
        self.shims = os.path.join(self.dir, "shims")
        os.makedirs(self.shims)
        # Writes both halves through whatever is at the names, as ssh-keygen does.
        Path(self.shims, "ssh-keygen").write_text(textwrap.dedent(f"""\
            #!{BASH}
            while [[ $# -gt 0 ]]; do [[ "$1" == "-f" ]] && f="$2"; shift; done
            printf 'PRIVATE-KEY\\n' > "$f"; printf 'PUBLIC-KEY\\n' > "$f.pub"
            """))
        os.chmod(os.path.join(self.shims, "ssh-keygen"), 0o755)

    def victim(self, name, content):
        path = Path(self.dir, name)
        if content is not None:
            path.write_text(content)
            os.chmod(path, 0o600)
        return path

    def untouched(self, victim, content, mode=0o600):
        if content is None:
            return not os.path.lexists(victim)
        # Bytes: a write through the link may leave binary (SQLite) content.
        return victim.read_bytes() == content.encode() and stat.S_IMODE(victim.stat().st_mode) == mode

    def run_bash(self, functions, body):
        script = textwrap.dedent(f"""\
            set -uo pipefail
            log() {{ echo "[INFO] $*"; }}
            warn() {{ echo "[WARN] $*"; }}
            err() {{ echo "[ERR] $*"; }}
            date() {{ echo 20261008_000000; }}
            APP_DIR={self.app!r}
            ENV_FILE={os.path.join(self.dir, 'vpn_auth.env')!r}
            LEGACY_ENV_FILE={os.path.join(self.app, '.env')!r}
            DB_PATH={os.path.join(self.app, 'vpn_users.db')!r}
            """) + "".join(functions) + "\n" + body + '\necho "rc=$?"\n'
        env = {"PATH": self.shims + os.pathsep + os.environ["PATH"], "HOME": self.dir, "LC_ALL": "C"}
        return subprocess.run([BASH, "--noprofile", "--norc", "-c", script], capture_output=True, text=True, env=env)

    def legacy(self):
        return os.path.join(self.app, ".env")

    def write_env_commit(self, source):
        """The commit tail of write_env: from the buffer being sealed to the end."""
        body = shell_function(source, "write_env")
        tail = body[body.index("  unset -f write_env_kv\n"):]
        return "write_env_commit() {\n" + tail

    # Each case: (functions, setup, run) -> facts True for the shipped source.
    def facts(self, source=None):
        text = hub_source() if source is None else source
        atomic = shell_function(text, "atomic_replace_file")
        facts = {}

        def fresh():
            shutil.rmtree(self.dir, ignore_errors=True)
            self.setUp()

        for kind, content in (("an existing", "untouched\n"), ("a dangling", None)):
            fresh()
            victim = self.victim("victim", content)
            os.symlink(victim, self.legacy())
            done = self.run_bash([atomic, self.write_env_commit(text)],
                                 "env_kv_buffer=\"ADMIN_TOKEN='s3cret'\"$'\\n'; smtp_user=u; smtp_pass=p\nwrite_env_commit")
            facts[f"write_env refuses {kind} link at the legacy mirror"] = (
                self.untouched(victim, content) and "rc=1" in done.stdout
                and not os.path.exists(os.path.join(self.dir, "vpn_auth.env")))

        fresh()
        Path(self.dir, "vpn_auth.env").write_text("A='1'\n")
        victim = self.victim("victim", "B='2'\n")
        os.symlink(victim, self.legacy())
        done = self.run_bash([atomic, shell_function(text, "replace_runtime_env_kv")],
                             "replace_runtime_env_kv PAYPAL_CLIENT_SECRET lab-secret")
        facts["replace_runtime_env_kv refuses a link at the legacy mirror"] = (
            self.untouched(victim, "B='2'\n") and "rc=1" in done.stdout
            and Path(self.dir, "vpn_auth.env").read_text() == "A='1'\n")

        fresh()
        Path(self.dir, "vpn_auth.env").write_text("A='1'\n")
        victim = self.victim("victim", None)
        os.symlink(victim, self.legacy())
        done = self.run_bash([shell_function(text, "append_runtime_env_kv")],
                             "append_runtime_env_kv PAYPAL_CLIENT_SECRET lab-secret")
        facts["append_runtime_env_kv refuses a link at the legacy mirror"] = (
            self.untouched(victim, None) and "rc=1" in done.stdout)

        fresh()
        victim = self.victim("victim", "untouched\n")
        os.chmod(victim, 0o644)
        os.symlink(victim, self.legacy())
        line = next(l for l in shell_function(text, "apply_commerce_secrets").splitlines()
                    if 'chmod 600 "${LEGACY_ENV_FILE}"' in l)
        self.run_bash([], line)
        facts["the commerce apply does not chmod through a link at the legacy mirror"] = (
            self.untouched(victim, "untouched\n", 0o644))

        for name in ("id_rsa", "id_rsa.pub"):
            fresh()
            ssh = os.path.join(self.dir, "ssh")
            os.makedirs(ssh)
            victim = self.victim("victim", None)
            os.symlink(victim, os.path.join(ssh, name))
            done = self.run_bash([shell_function(text, "ensure_hub_ssh_key").replace("/root/.ssh", ssh)],
                                 "ensure_hub_ssh_key")
            facts[f"ensure_hub_ssh_key refuses a link at {name}"] = self.untouched(victim, None) and "rc=1" in done.stdout

        # backup_existing_db takes an SQLite online snapshot, which refuses to
        # write over a file that is not a database. The source is therefore a
        # real database and the existing targets are empty files (an empty
        # file is an empty database), so an unguarded snapshot overwrites them.
        for kind, content in (("link", ""), ("file", ""), ("dangling link", None)):
            fresh()
            with sqlite3.connect(os.path.join(self.app, "vpn_users.db")) as db:
                db.execute("CREATE TABLE fixture(value TEXT)")
                db.execute("INSERT INTO fixture VALUES ('DATABASE')")
            db.close()
            name = os.path.join(self.app, "vpn_users.db.pre-fixed-20261008_000000.bak")
            if kind != "file":
                victim = self.victim("victim", content)
                os.symlink(victim, name)
            else:
                victim = Path(name)
                victim.write_text(content)
                os.chmod(victim, 0o600)
            done = self.run_bash([shell_function(text, "backup_existing_db")], "backup_existing_db")
            facts[f"backup_existing_db refuses an existing {kind} at the backup name"] = (
                self.untouched(victim, content) and "rc=1" in done.stdout)

        fresh()
        victim = self.victim("victim", None)
        os.symlink(victim, os.path.join(self.app, "vpn_users.db"))
        done = self.run_bash([shell_function(text, "write_sqlite_bootstrap")], "write_sqlite_bootstrap")
        facts["write_sqlite_bootstrap refuses a link at vpn_users.db"] = (
            self.untouched(victim, None) and "rc=1" in done.stdout)
        return facts

    def test_secret_material_is_never_written_through_an_app_planted_link(self):
        self.assertEqual({k: v for k, v in self.facts().items() if not v}, {})

    def test_secret_link_mutants_are_killed(self):
        mutants = {  # name: (old, new, a fact that must turn False)
            "write_env commits through a link at the legacy mirror": (
                '  unset -f write_env_kv\n  # ${LEGACY_ENV_FILE} sits in ${APP_DIR}, which the hub app can write, and\n'
                '  # atomic_replace_file follows a link (for the vault\'s ${ENV_FILE}). No step\n'
                '  # links the mirror, so a link there was planted: refuse it before either\n'
                '  # file is written, rather than write every hub secret through it.\n'
                '  if [[ -L "${LEGACY_ENV_FILE}" ]]; then\n',
                '  unset -f write_env_kv\n  if false; then\n',
                "write_env refuses a dangling link at the legacy mirror"),
            "replace_runtime_env_kv rewrites through a link": (
                '  # is rewritten, rather than read and write every hub secret through it.\n'
                '  if [[ -L "${LEGACY_ENV_FILE}" ]]; then\n',
                '  if false; then\n',
                "replace_runtime_env_kv refuses a link at the legacy mirror"),
            "append_runtime_env_kv appends through a link": (
                '  # there was planted, so nothing is appended through it.\n'
                '  if [[ -L "${LEGACY_ENV_FILE}" ]]; then\n',
                '  if false; then\n',
                "append_runtime_env_kv refuses a link at the legacy mirror"),
            "the commerce apply chmods through a link": (
                '[[ -f "${LEGACY_ENV_FILE}" && ! -L "${LEGACY_ENV_FILE}" ]] && chmod 600',
                '[[ -f "${LEGACY_ENV_FILE}" ]] && chmod 600',
                "the commerce apply does not chmod through a link at the legacy mirror"),
            "ensure_hub_ssh_key follows a link": (
                'if [[ -L /root/.ssh/id_rsa || -L /root/.ssh/id_rsa.pub ]]; then',
                "if false; then",
                "ensure_hub_ssh_key refuses a link at id_rsa"),
            "ensure_hub_ssh_key checks only the private half": (
                'if [[ -L /root/.ssh/id_rsa || -L /root/.ssh/id_rsa.pub ]]; then',
                'if [[ -L /root/.ssh/id_rsa ]]; then',
                "ensure_hub_ssh_key refuses a link at id_rsa.pub"),
            "backup_existing_db copies onto an existing name": (
                'if [[ -e "${backup}" || -L "${backup}" ]]; then', "if false; then",
                "backup_existing_db refuses an existing link at the backup name"),
            "backup_existing_db overwrites an earlier backup": (
                'if [[ -e "${backup}" || -L "${backup}" ]]; then', 'if [[ -L "${backup}" ]]; then',
                "backup_existing_db refuses an existing file at the backup name"),
            "backup_existing_db follows a dangling link": (
                'if [[ -e "${backup}" || -L "${backup}" ]]; then', 'if [[ -e "${backup}" ]]; then',
                "backup_existing_db refuses an existing dangling link at the backup name"),
            "write_sqlite_bootstrap opens a linked database": (
                '  if [[ -L "${DB_PATH}" ]]; then\n    err "${DB_PATH} is a symlink; refusing to open',
                '  if false; then\n    err "${DB_PATH} is a symlink; refusing to open',
                "write_sqlite_bootstrap refuses a link at vpn_users.db"),
        }
        for name, (old, new, fact) in mutants.items():
            with self.subTest(name):
                facts = self.facts(replace_once(hub_source(), old, new))
                self.assertFalse(facts[fact], f"mutant survived: {name}")


# ======================================================= the carry unit ====

def carry_unit_facts(source):
    """Sandbox facts of wins-awg-carry-probe.service in the H0 form. Raises
    SkipTest where the integration has not moved the probe under /usr/local/lib
    (this slice's own tree predates H0); every value is True for the shipped
    integration source."""
    start = source.index("cat > /etc/systemd/system/wins-awg-carry-probe.service <<'EOF'\n")
    body = source[start:source.index("\nEOF\n", start)]
    if "ExecStart=/usr/bin/python3 -I /usr/local/lib/wins_node_dataplane_probe.py --carry" not in body:
        raise unittest.SkipTest("the H0 sandbox profile arrives with the integration, not with this slice's tree")
    values = {}
    for line in body.splitlines():
        if line and not line.startswith(("#", "[")) and "=" in line:
            key, _, value = line.partition("=")
            values.setdefault(key, []).append(value)
    tokens = lambda key: [t for value in values.get(key, []) for t in value.split()]  # noqa: E731
    resolver = {"-/run/systemd/resolve/stub-resolv.conf", "-/run/systemd/resolve/resolv.conf"}
    signer = {"/etc/winsvpn/descriptor-signer", "/var/lib/wins-descriptor-signer", "/etc/wins-descriptor-signer-input"}
    return {
        "an empty read-only /run": values.get("TemporaryFileSystem") == ["/run:ro"],
        "only the resolver files bound back into it": bool(tokens("BindReadOnlyPaths"))
            and set(tokens("BindReadOnlyPaths")) <= resolver,
        "no unix socket family": set(tokens("RestrictAddressFamilies")) == {"AF_INET", "AF_INET6", "AF_NETLINK"},
        "the descriptor signer is out of reach": signer <= {t.lstrip("-") for t in tokens("InaccessiblePaths")},
        "no capability": values.get("CapabilityBoundingSet") == [""] and values.get("AmbientCapabilities") == [""],
        "writes only the hub database directory": values.get("ReadWritePaths") == ["/root/vpn_auth"],
        "no privilege gain": values.get("NoNewPrivileges") == ["true"] and values.get("ProtectSystem") == ["strict"],
    }


CARRY_UNIT_MUTANTS = {
    "/run is the host's": ("need only IP.\nTemporaryFileSystem=/run:ro\n", "need only IP.\n"),
    "a broker socket directory is bound back": (
        "TemporaryFileSystem=/run:ro\n"
        "BindReadOnlyPaths=-/run/systemd/resolve/stub-resolv.conf -/run/systemd/resolve/resolv.conf\n"
        "InaccessiblePaths=-/etc/winsvpn/descriptor-signer",
        "TemporaryFileSystem=/run:ro\n"
        "BindReadOnlyPaths=-/run/systemd/resolve/stub-resolv.conf -/run/systemd/resolve/resolv.conf /run/litestream\n"
        "InaccessiblePaths=-/etc/winsvpn/descriptor-signer"),
    "unix sockets are allowed": (
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK\n",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"),
    "netlink is refused again": (
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK\n", "RestrictAddressFamilies=AF_INET AF_INET6\n"),
    "the signer is readable": (
        "InaccessiblePaths=-/etc/winsvpn/descriptor-signer -/var/lib/wins-descriptor-signer -/etc/wins-descriptor-signer-input\n",
        ""),
    "the unit may write anywhere under /root": ("ReadWritePaths=/root/vpn_auth\n", "ReadWritePaths=/root\n"),
}


class CarryUnitTests(unittest.TestCase):
    """Sol 1: the carry unit runs an operator-staged client as root, so it gets
    the hub unit's barriers: no host /run (no service manager, system bus,
    Litestream, SPA helper or signer socket), no unix socket family, the signer's
    key and ledger paths unreadable."""

    def test_the_carry_unit_keeps_the_broker_and_signer_barriers(self):
        facts = carry_unit_facts(hub_source())
        self.assertEqual({k: v for k, v in facts.items() if not v}, {})

    def test_every_carry_unit_mutant_is_killed(self):
        carry_unit_facts(hub_source())      # skips where the H0 form is absent
        for name, (old, new) in CARRY_UNIT_MUTANTS.items():
            with self.subTest(name):
                mutated = replace_once(hub_source(), old, new)
                self.assertTrue({k: v for k, v in carry_unit_facts(mutated).items() if not v},
                                f"mutant survived: {name}")


# ======================================================== mutants (5.6) ====

def probe_checks(source):
    """Probe facts a mutant of the carrying logic must break."""
    probe = load_probe(source)
    query, qid = probe["build_dns_query"]("hub.example.test")
    check = probe["dns_reply_carries"]
    assert check(dns_response(query), query)[0]
    assert not check(dns_response(query, qid=(qid + 1) % 65536), query)[0], "reply id"
    assert not check(dns_response(query, answers=0), query)[0], "answer count"
    assert not check(dns_response(query, rcode=3), query)[0], "rcode"
    assert not check(dns_response(query, response=False), query)[0], "QR"
    assert not check(dns_response(query, echo=False), query)[0], "question"
    now = datetime(2026, 10, 7, 12)
    ago = lambda s: (now - timedelta(seconds=s)).isoformat()  # noqa: E731
    assert probe["carry_due"]("failed", ago(1), "open", now)
    assert not probe["carry_due"]("ok", ago(100), "open", now)
    assert probe["carry_due"]("ok", ago(700), "open", now)
    assert not probe["carry_due"]("ok", ago(60), "pending", now)
    assert probe["carry_due"]("ok", ago(100), "pending", now)
    assert probe["carry_node_class"]({"operator_enabled": 1}) == "open"
    assert probe["carry_node_class"]({"operator_enabled": 1, "retired_at": "x"}) == ""
    assert probe["carry_node_class"]({"operator_enabled": 0}) == ""
    assert probe["carry_node_class"]({"deployment_completed_at": "x", "health_closed_reason": "installer_rerun"}) == "pending"
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "k")
        Path(path).write_text(CANARY + "\n")
        os.chmod(path, 0o644)
        probe["CARRY_KEY_FILE"] = path
        assert probe["read_carry_private_key"]()[0] == "", "a key open to others is refused"
        client = os.path.join(tmp, "client")
        Path(client).write_text(CLIENT_PRELUDE.format(python=sys.executable) + 'answer({"carried": True})\n')
        os.chmod(client, 0o755)
        probe["CARRY_CLIENT_BIN"] = client
        probe["CARRY_CLIENT_TIMEOUT"] = 5
        probe["carry_client_untrusted"] = lambda _path: ""
        row = {"endpoint": "127.0.0.1:9110", "wg_port": 9110, "public_key": NODE_KEY, "direct_awg_enabled": 1,
               "obfuscation_json": OBFUSCATION, "stealth_endpoint": "", "stealth_transports": "[]",
               "xray_security": "none", "xray_path": "", "xray_uuid": ""}
        assert probe["probe_carry"](row, "udp", CANARY)[0] == "error", "the client's say-so is not a verdict"


def hub_checks(source):
    mod = load_hub(source)
    admission_checks(mod)
    with mod.get_db() as conn:
        mod.ensure_schema(conn)
        conn.execute("DELETE FROM core_exit_peers")
        assert mod.allocate_core_exit_ip(conn) == "10.8.255.2"


def probe_fix_checks(source):
    """Probe facts for the Turn 2 fixes: the DNS record parse, the attempt-time
    cadence, the publication snapshot, the client gate and the relay bounds. A
    mutant of any of them must fail an assertion here."""
    probe = load_probe(source)
    query, _qid = probe["build_dns_query"]("hub.example.test")
    check = probe["dns_reply_carries"]

    def refuses(reply):
        try:
            return not check(reply, query)[0]
        except Exception:  # noqa: BLE001  (a crash is not a refusal)
            return False

    variants = dns_reply_variants(query)
    for label, reply in variants["rejected"].items():
        assert refuses(reply), f"refused: {label}"
    for label, reply in variants["accepted"].items():
        assert check(reply, query)[0], f"accepted: {label}"
    now = datetime(2026, 10, 7, 12)
    ago = lambda s: (now - timedelta(seconds=s)).isoformat()  # noqa: E731
    due = probe["carry_due"]
    assert not due("failed", ago(9999), "open", now, ago(100)), "an attempt 100 s ago, open"
    assert due("failed", ago(1), "open", now, ago(9999)), "an old attempt, open"
    assert not due("failed", ago(9999), "pending", now, ago(60)), "an attempt 60 s ago, pending"
    assert due("failed", ago(1), "pending", now, ago(90)), "pending is due after 90 s"
    assert due("unknown", None, "open", now, None), "never attempted"
    # --- publication: attempt time, observed time, snapshot
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    columns = ("deployment_completed_at", "deployment_withdrawal_id", "retired_at", "public_key", "endpoint",
               "wg_port", "direct_awg_enabled", "obfuscation_json", "stealth_endpoint", "stealth_public_port",
               "stealth_transports", "xray_security", "xray_path", "xray_uuid")
    conn.execute("CREATE TABLE nodes (slug TEXT PRIMARY KEY, " + ", ".join(f"{c} TEXT" for c in columns) + ")")
    conn.execute("INSERT INTO nodes (slug, " + ", ".join(columns) + ") VALUES ('n', " + ", ".join("'v'" for _ in columns) + ")")
    for transport in ("udp", "stealth", "stealth_tls"):
        for suffix, decl in (("status", "TEXT DEFAULT 'unknown'"), ("ok_at", "TEXT"), ("checked_at", "TEXT")):
            conn.execute(f"ALTER TABLE nodes ADD COLUMN data_plane_{transport}_carry_{suffix} {decl}")
    conn.commit()
    snapshot = probe["carry_snapshot"](conn.execute("SELECT * FROM nodes").fetchone())
    for column in columns:
        conn.execute(f"UPDATE nodes SET {column} = 'changed' WHERE slug = 'n'")
        conn.commit()
        wrote = probe["apply_carry_verdict"](conn, "n", "udp", "reachable", "2026-10-07T00:00:00", snapshot)
        row = conn.execute("SELECT * FROM nodes").fetchone()
        assert wrote is False and row["data_plane_udp_carry_status"] == "unknown", f"stale when {column} changed"
        conn.execute(f"UPDATE nodes SET {column} = 'v' WHERE slug = 'n'")
        conn.commit()
    assert probe["apply_carry_verdict"](conn, "n", "udp", "reachable", "2026-10-07T00:00:00", snapshot) is True
    assert probe["apply_carry_verdict"](conn, "n", "udp", "unreachable", "2026-10-07T00:10:00", snapshot) is True
    row = conn.execute("SELECT * FROM nodes").fetchone()
    assert (row["data_plane_udp_carry_status"], row["data_plane_udp_carry_ok_at"],
            row["data_plane_udp_carry_checked_at"]) == ("failed", "2026-10-07T00:00:00", "2026-10-07T00:10:00")
    conn.close()
    # --- the client gate: placement, then the pin
    with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as tmp2:
        root = os.path.realpath(tmp)
        client = os.path.join(root, "client")
        Path(client).write_text("#!/bin/sh\n")
        os.chmod(client, 0o755)
        stray = os.path.join(os.path.realpath(tmp2), "client")
        Path(stray).write_text("#!/bin/sh\n")
        os.chmod(stray, 0o755)
        pinned = hashlib.sha256(Path(client).read_bytes()).hexdigest()
        place = load_probe(source, CARRY_CLIENT_ROOTS=(root + "/",))["carry_client_placement"]
        if os.geteuid() != 0:
            assert place(client), "an ordinary user's file is not root-only"
        link = os.path.join(root, "link")
        os.symlink(client, link)
        real_lstat = os.lstat

        def as_root(path, *a, **k):
            info = real_lstat(path, *a, **k)
            inside = str(path) == root or str(path).startswith(root + os.sep)
            mode = info.st_mode if inside else stat.S_IFDIR | 0o755
            return os.stat_result((mode, info.st_ino, info.st_dev, info.st_nlink, 0, info.st_gid,
                                   info.st_size, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))

        os.chmod(root, 0o755)
        with patch.object(os, "lstat", as_root):
            assert place(client) == "", "a root-owned closed file in a closed directory"
            assert place(link), "a symlink"
            assert place(stray), "outside the allowed roots"
            assert place(os.path.join(root, "absent")), "absent"
            os.chmod(client, 0o775)
            assert place(client), "a group-writable file"
            os.chmod(client, 0o755)
            os.chmod(root, 0o777)
            assert place(client), "a writable directory above it"
            os.chmod(root, 0o700)
        for pin, reason in ((pinned, ""), ("0" * 64, "does not match"), ("", "no pinned")):
            unpinned = load_probe(source, CARRY_CLIENT_SHA256=pin)["carry_client_unpinned"](client)
            assert (unpinned == "") if not reason else (reason in unpinned), (pin, unpinned)
        gate = load_probe(source, CARRY_CLIENT_SHA256="0" * 64, carry_client_placement=lambda _p: "")
        assert gate["carry_client_untrusted"](client), "the gate includes the pin"
        gate = load_probe(source, CARRY_CLIENT_SHA256=pinned, carry_client_placement=lambda _p: "elsewhere")
        assert gate["carry_client_untrusted"](client), "the gate includes the placement"
        ran = os.path.join(tmp, "ran")
        Path(client).write_text("#!/bin/sh\ntouch " + ran + "\n")
        os.chmod(client, 0o755)
        probe2 = load_probe(source, CARRY_CLIENT_BIN=client, CARRY_CLIENT_TIMEOUT=5)
        probe2["run_carry_client"]({"private_key": CANARY}, query, CANARY)
        assert not os.path.exists(ran), "run_carry_client consults the gate"
    # --- the relay: size cap and an absolute deadline
    uid = uuid.UUID(XRAY_UUID).bytes
    for mode, budget, expected in (("flood", 30.0, "too large"), ("drip", 1.5, "in time")):
        node = HostileUpgradeNode(mode)
        node.start()
        relay = load_probe(source, CARRY_RELAY_OPEN_SECONDS=budget)["StealthRelay"](
            "127.0.0.1", node.port, "none", "/stealth", uid, 9110)
        started = time.monotonic()
        try:
            try:
                relay.start()
                raise AssertionError(f"{mode}: the upgrade was accepted")
            except ConnectionError as exc:
                assert expected in str(exc), f"{mode}: {exc}"
        finally:
            relay.close()
            node.close()
        assert time.monotonic() - started < 6, f"{mode}: the relay open is bounded"
    assert load_probe(source)["CARRY_RUN_DEADLINE_SECONDS"] == 60


def hub_fix_checks(source):
    """Hub facts for the Turn 2 fixes: the freshness limit on the rerun gate, the
    throttle before the database, concurrent pushes and the separate push task."""
    import asyncio
    mod = load_hub(source)
    now = mod.utcnow()
    base = {"deployment_completed_at": (now - timedelta(hours=2)).isoformat(), "direct_awg_enabled": 1,
            "endpoint": "192.0.2.10:9110", "public_key": NODE_KEY, "ssh_host": "192.0.2.10",
            "stealth_endpoint": "", "protocol_version": "winn/1"}

    def proof(age):
        return dict(base, data_plane_udp_carry_status="ok",
                    data_plane_udp_carry_ok_at=(now - timedelta(seconds=age)).isoformat())

    assert mod.installer_rerun_carry_failures(proof(60)) == [], "a fresh proof passes"
    assert len(mod.installer_rerun_carry_failures(proof(3600))) == 1, "a proof an hour old is held"
    # throttle before the database
    mod._AWG_CANARY_PEER_LAST.clear()
    slug = seed_node(mod, operator_enabled=1)
    calls = []
    real = mod.peer_push_still_admitted
    with patch.object(mod, "sync_peer_to_node", return_value=True), \
            patch.object(mod, "peer_push_still_admitted", side_effect=lambda *a, **k: calls.append(1) or real(*a, **k)):
        assert mod.sync_awg_canary_peers_once(slug)["synced"] == 1
        opened = len(calls)
        assert mod.sync_awg_canary_peers_once(slug)["skipped"] == 1
        assert len(calls) == opened, "a throttled node is not re-read"
    # one node raising does not stop the others
    mod._AWG_CANARY_PEER_LAST.clear()
    seed_node(mod, operator_enabled=1, ssh_host="192.0.2.41")
    seed_node(mod, operator_enabled=1, ssh_host="192.0.2.42")
    reached = []

    def maybe_raise(node_ip, cfg):
        if node_ip == "192.0.2.41":
            raise RuntimeError("boom")
        reached.append(node_ip)
        return True

    with patch.object(mod, "sync_peer_to_node", side_effect=maybe_raise):
        try:
            mod.sync_awg_canary_peers_once("", force=True)
        except Exception as exc:  # noqa: BLE001
            raise AssertionError("one node raising aborts the sweep") from exc
    assert "192.0.2.42" in reached, "one node raising stops the others"
    # concurrent pushes
    mod._AWG_CANARY_PEER_LAST.clear()
    for _ in range(8):
        seed_node(mod, operator_enabled=1)
    live, peak, lock = [0], [0], threading.Lock()

    def slow(node_ip, cfg):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.1)
        with lock:
            live[0] -= 1
        return True

    with patch.object(mod, "sync_peer_to_node", side_effect=slow):
        mod.sync_awg_canary_peers_once()
    assert peak[0] > 1, "pushes overlap"
    # the push is its own task: a stuck push does not stop the audit loop
    real_sleep = asyncio.sleep
    release = threading.Event()
    audits = []

    async def fast_sleep(_seconds):
        await real_sleep(0)

    async def scenario():
        patches = [patch.object(mod, "audit_fleet_availability_once", side_effect=lambda: audits.append(1)),
                   patch.object(mod, "audit_winn3_contract_once"), patch.object(mod, "auto_reopen_health_closed_nodes"),
                   patch.object(mod, "drain_node_latch_events"),
                   patch.object(mod, "sync_awg_canary_peers_once", side_effect=lambda *a, **k: release.wait(5)),
                   patch.object(mod.asyncio, "sleep", fast_sleep)]
        for item in patches:
            item.start()
        try:
            tasks = [asyncio.create_task(mod.awg_canary_sync_loop()),
                     asyncio.create_task(mod.fleet_availability_sweep_loop())]
            for _ in range(200):
                if len(audits) >= 3:
                    break
                await real_sleep(0.01)
            done = len(audits) >= 3
            release.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for item in patches:
                item.stop()
        return done

    assert asyncio.run(scenario()), "the audit loop kept iterating while a push was stuck"
    assert "asyncio.create_task(awg_canary_sync_loop())" in source, "the push task is started"


def run_level_facts(case, source=None):
    """Run-level facts for the Turn 2 fixes, on a CarryRunTests instance with its
    own database. Every value is True for the shipped source."""
    case.mod = load_hub()
    case.calls = []
    case.verdicts = {}
    facts = {}
    # stamped with the run start
    slug = seed_node(case.mod, operator_enabled=1)

    def slow_success(row, transport, _key):
        time.sleep(0.5)
        return "reachable", "carried"

    before = case.mod.utcnow().replace(tzinfo=None)
    case.run_carry(source=source, CARRY_WORKERS=3, probe_carry=slow_success)
    stamp = case.status(slug)["udp"][1]
    facts["the proof carries the run start"] = bool(stamp) and datetime.fromisoformat(stamp) < before + timedelta(seconds=0.35)
    # a changed deployment during the probe
    other = seed_node(case.mod, operator_enabled=1)

    def change_key(row, transport, _key):
        with case.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET public_key = ? WHERE slug = ?", (throwaway_key(), other))
        return "reachable", "carried"

    case.run_carry(source=source, slug=other, probe_carry=change_key)
    facts["a verdict about a changed node is discarded"] = case.status(other)["udp"] == ("unknown", None)
    # an attempt starts the interval
    attempted = {f"data_plane_{t}_carry_{k}": v for t in case.CARRY
                 for k, v in (("status", "failed"), ("checked_at", case.aged(100)))}
    waiting = seed_node(case.mod, operator_enabled=1, **attempted)
    case.calls.clear()
    case.run_carry(source=source)
    facts["a recent failure waits its cadence"] = waiting not in {s for s, _ in case.calls}
    # pending first, then a fresh random order
    case.mod = load_hub()
    opens = [seed_node(case.mod, operator_enabled=1) for _ in range(10)]
    pending = seed_node(case.mod, operator_enabled=0, health_closed_reason="fresh_install",
                        deployment_completed_at=case.mod.utcnow().isoformat())
    firsts, pending_first = set(), True
    for _ in range(14):
        order = []
        probe = load_probe(source, DB_PATH=case.mod._DB, CARRY_PUBLIC_KEY=CANARY, CARRY_KEY_FILE=case.key_file)
        probe["probe_carry"] = lambda row, transport, _k, order=order: (order.append((row["slug"], transport))
                                                                         or ("reachable", "ok"))
        probe["carry_main"](type("Args", (), {"slug": "", "dry_run": True})())
        # P2-SEAM-H5: one lane per transport (P-16); the order is each lane's.
        lanes = {t: [slug for slug, name in order if name == t] for t in case.CARRY}
        pending_first = pending_first and all(lane[:1] == [pending] for lane in lanes.values())
        firsts.add(tuple(lane[1] for lane in lanes.values()))
    facts["pending nodes come first"] = pending_first
    facts["the rest of the order is not fixed"] = len(firsts) > 1
    return facts


def replace_once(text, old, new):
    assert text.count(old) == 1, (text.count(old), old)
    return text.replace(old, new)


WIDEN = ('for y in range(2, 255):\n        candidate = f"10.8.255.{y}"',
         'for y in range(1, 255):\n        candidate = f"10.8.255.{y}"')
RESERVED_CHECK = ("        if candidate in AWG_CORE_EXIT_RESERVED_ADDRESSES:\n            continue\n", "")
GATE = "if key != AWG_CANARY_PUBLIC_KEY or allowed_ips.strip() != AWG_CANARY_ALLOWED_IPS:"
CONFIGURED = "if node is None or device is not None or system_peer is None or not AWG_CANARY_PUBLIC_KEY:"

# Each mutant is a list of (old, new) edits applied to the installer source.
HUB_MUTANTS = {
    "exception admits any key": [(GATE, "if allowed_ips.strip() != AWG_CANARY_ALLOWED_IPS:")],
    "exception widened to the whole /24 (the off-node exemption mutant)": [
        (GATE, "if key != AWG_CANARY_PUBLIC_KEY or not allowed_ips.strip().startswith('10.8.255.'):")],
    "exception ignores the allowed address": [(GATE, "if key != AWG_CANARY_PUBLIC_KEY:")],
    "exception compares only the first 40 characters of the key": [
        (GATE, "if key[:40] != AWG_CANARY_PUBLIC_KEY[:40] or allowed_ips.strip() != AWG_CANARY_ALLOWED_IPS:")],
    "exception compares the key case-insensitively": [
        (GATE, "if key.lower() != AWG_CANARY_PUBLIC_KEY.lower() or allowed_ips.strip() != AWG_CANARY_ALLOWED_IPS:")],
    "exception accepts a list of addresses": [
        ("allowed_ips.strip() != AWG_CANARY_ALLOWED_IPS:", "AWG_CANARY_ALLOWED_IPS not in allowed_ips:")],
    "node_admits_peer admits a Core exit peer on a closed node": [
        ("    return awg_canary_peer_admitted(node, device, system_peer)\n",
         "    return awg_canary_peer_admitted(node, device, system_peer) or system_peer is not None\n")],
    "exception admits a customer device": [
        (CONFIGURED, "if node is None or system_peer is None or not AWG_CANARY_PUBLIC_KEY:")],
    "exception admits when no canary key is configured": [
        (CONFIGURED, "if node is None or device is not None or system_peer is None:")],
    "exception admits a retired node": [
        ('    if str(data.get("retired_at") or "").strip():\n        return False\n    return not str(data.get("deployment_withdrawal_id")',
         '    return not str(data.get("deployment_withdrawal_id")')],
    "exception admits a node under installer withdrawal": [
        ('    return not str(data.get("deployment_withdrawal_id") or "").strip()\n', "    return True\n")],
    "allocator loses its reserved check and the range starts at 1": [RESERVED_CHECK, WIDEN],
    "reserved set is empty and the range starts at 1": [
        ("AWG_CORE_EXIT_RESERVED_ADDRESSES = frozenset({AWG_CANARY_ADDRESS})\n",
         "AWG_CORE_EXIT_RESERVED_ADDRESSES = frozenset()\n"), WIDEN],
}


PROBE_FIX_MUTANTS = {
    "a count in the header is an answer": ("        if end is None or end + 10 > len(reply):\n", "        if False:\n"),
    "a record's data may run past the reply": ("        if offset > len(reply):\n", "        if False:\n"),
    "a record of another class counts": ("        if rclass != 1:\n", "        if False:\n"),
    "an address record of any length counts": ("            if rdlength != 4:\n", "            if False:\n"),
    "no address record is needed": ("    if not addresses:\n", "    if False:\n"),
    "two questions are fine": ("    if qd != 1:\n", "    if False:\n"),
    "a compression pointer may point anywhere": (
        "            return offset + 2 if 12 <= target < offset else None\n", "            return offset + 2\n"),
    "a reserved label type is a label": ("        if length & 0xC0:\n            return None\n", ""),
    "a failed transport is timed by its last success": (
        '    stamp = ok_at if str(status or "unknown").strip().lower() == "ok" else checked_at\n',
        "    stamp = ok_at\n"),
    "the publication snapshot is ignored": (
        "    if row is None or (snapshot is not None and carry_snapshot(row) != snapshot):\n",
        "    if row is None:\n"),
    "the snapshot omits the node key": (
        '"deployment_completed_at", "deployment_withdrawal_id", "retired_at", "public_key",\n',
        '"deployment_completed_at", "deployment_withdrawal_id", "retired_at",\n'),
    "the snapshot omits the deployment completion": (
        '"deployment_completed_at", "deployment_withdrawal_id", "retired_at", "public_key",\n',
        '"deployment_withdrawal_id", "retired_at", "public_key",\n'),
    "the attempt time is not recorded": (
        '        f"UPDATE nodes SET {column}_status = ?, {column}_ok_at = ?, {column}_checked_at = ? WHERE slug = ?",\n'
        "        (status, ok_at, observed_iso, slug))",
        '        f"UPDATE nodes SET {column}_status = ?, {column}_ok_at = ? WHERE slug = ?",\n'
        "        (status, ok_at, slug))"),
    "a client may be a symlink or sit anywhere": (
        "    if real != path or not real.startswith(CARRY_CLIENT_ROOTS) or not os.path.isfile(real):\n",
        "    if not os.path.isfile(real):\n"),
    "client ownership is not checked": (
        "        if info.st_uid != 0 or info.st_mode & 0o022:\n", "        if info.st_mode & 0o022:\n"),
    "client write bits are not checked": (
        "        if info.st_uid != 0 or info.st_mode & 0o022:\n", "        if info.st_uid != 0:\n"),
    "only the client file is checked, not the directories above it": (
        '        if current == "/":\n            return ""\n        current = os.path.dirname(current)\n',
        '        return ""\n'),
    "a client with another digest runs": ("    if digest.hexdigest() != CARRY_CLIENT_SHA256:\n", "    if False:\n"),
    "a client without a pin runs": (
        '    if not re.fullmatch(r"[0-9a-f]{64}", CARRY_CLIENT_SHA256):\n', "    if False:\n"),
    "the client gate leaves out the pin": (
        "    return carry_client_placement(path) or carry_client_unpinned(path)\n",
        "    return carry_client_placement(path)\n"),
    "the client gate leaves out the placement": (
        "    return carry_client_placement(path) or carry_client_unpinned(path)\n",
        "    return carry_client_unpinned(path)\n"),
    # P2-SEAM-H5: the gate now runs before every client start (ready()).
    "the client runs without the gate": (
        '        untrusted = carry_client_untrusted(CARRY_CLIENT_BIN)\n        if untrusted:\n'
        '            self.unusable = untrusted\n            return untrusted\n',
        ""),
    "the upgrade header is not capped": ("            if len(buf) > CARRY_RELAY_HEADER_LIMIT:\n", "            if False:\n"),
    "the upgrade has no absolute deadline": (
        "            remaining = CARRY_RELAY_OPEN_SECONDS - (time.monotonic() - opened)\n",
        "            remaining = CARRY_RELAY_OPEN_SECONDS\n"),
    "the run deadline is back to 75 s": (
        '"AWG_CARRY_RUN_DEADLINE_SECONDS", "60") or 60', '"AWG_CARRY_RUN_DEADLINE_SECONDS", "75") or 75'),
}

RUN_FIX_MUTANTS = {
    "the proof is stamped when it is written": (
        "apply_carry_verdict(conn, slug, transport, verdict, run_started, carry_snapshot(row))",
        "apply_carry_verdict(conn, slug, transport, verdict, utcnow_iso(), carry_snapshot(row))"),
    "no snapshot is passed to the write": (
        "verdict, run_started, carry_snapshot(row))", "verdict, run_started)"),
    "the attempt time is never read for the cadence": (
        '                         row[f"{column}_checked_at"]) or args.slug:', "                         None) or args.slug:"),
    "pending nodes are not first": ('    jobs.sort(key=lambda job: job[2] != "pending")\n', ""),
    "the job order is not shuffled": ("    secrets.SystemRandom().shuffle(jobs)\n", ""),
}

HUB_FIX_MUTANTS = {
    "a proof of any age is read": (
        "    return taken is not None and (utcnow() - taken).total_seconds() <= AWG_CARRY_PROOF_MAX_AGE_SECONDS\n",
        "    return taken is not None\n"),
    "the age limit is a day": (
        "AWG_CARRY_PROOF_MAX_AGE_SECONDS = 900\n", "AWG_CARRY_PROOF_MAX_AGE_SECONDS = 86400\n"),
    "the push is a step of the audit loop": (
        "        await asyncio.sleep(FLEET_AVAILABILITY_AUDIT_SECONDS)\n\nasync def awg_canary_sync_loop():",
        "        await asyncio.to_thread(sync_awg_canary_peers_once)\n"
        "        await asyncio.sleep(FLEET_AVAILABILITY_AUDIT_SECONDS)\n\nasync def awg_canary_sync_loop():"),
    "one node raising aborts the sweep": (
        "    try:\n        ok = sync_peer_to_node(node_ip, {\n"
        "            \"client_public_key\": peer[0],\n"
        "            \"vpn_internal_ip\": AWG_CANARY_ADDRESS,\n"
        "            \"preshared_key\": \"\",\n"
        "            \"node_max_peers\": row[\"max_peers\"],\n"
        "        })\n    except Exception as exc:\n",
        "    try:\n        ok = sync_peer_to_node(node_ip, {\n"
        "            \"client_public_key\": peer[0],\n"
        "            \"vpn_internal_ip\": AWG_CANARY_ADDRESS,\n"
        "            \"preshared_key\": \"\",\n"
        "            \"node_max_peers\": row[\"max_peers\"],\n"
        "        })\n    except ZeroDivisionError as exc:\n"),
    "pushes run one at a time": (
        "max_workers=max(1, min(AWG_CANARY_PUSH_WORKERS, len(due)))", "max_workers=1"),
    "the push task is never started": (
        "    asyncio.create_task(awg_canary_sync_loop())\n", "    pass\n"),
}


class MutantTests(unittest.TestCase):
    """5.6: each of these must fail the checks that guard it."""

    def test_the_unmutated_sources_pass_every_check(self):
        hub_checks(hub_source())
        probe_checks(hub_source())

    def test_every_hub_mutant_is_killed(self):
        for name, edits in HUB_MUTANTS.items():
            with self.subTest(name):
                mutated = hub_source()
                for old, new in edits:
                    mutated = replace_once(mutated, old, new)
                with self.assertRaises(AssertionError, msg=f"mutant survived: {name}"):
                    hub_checks(mutated)

    def test_the_unmutated_sources_pass_the_turn_2_checks(self):
        probe_fix_checks(hub_source())
        hub_fix_checks(hub_source())

    def test_every_probe_fix_mutant_is_killed(self):
        for name, (old, new) in PROBE_FIX_MUTANTS.items():
            with self.subTest(name):
                mutated = replace_once(hub_source(), old, new)
                with self.assertRaises(AssertionError, msg=f"mutant survived: {name}"):
                    probe_fix_checks(mutated)

    def test_every_hub_fix_mutant_is_killed(self):
        for name, (old, new) in HUB_FIX_MUTANTS.items():
            with self.subTest(name):
                mutated = replace_once(hub_source(), old, new)
                with self.assertRaises(AssertionError, msg=f"mutant survived: {name}"):
                    hub_fix_checks(mutated)

    def test_the_throttle_read_before_the_admission_read_is_pinned(self):
        """Claude perf 3: the in-memory throttle comes before the call that opens a
        database connection. The mutant puts the admission re-read first again."""
        mutated = replace_once(
            hub_source(),
            '                or not node_admits_peer(row, system_peer=peer)):\n',
            '                or not node_admits_peer(row, system_peer=peer)\n'
            '                or not peer_push_still_admitted(slug, system_peer=peer)):\n')
        with self.assertRaises(AssertionError, msg="mutant survived: admission re-read before the throttle"):
            hub_fix_checks(mutated)

    def test_every_probe_mutant_is_killed(self):
        mutants = {
            "reply id is not compared": ("if qid != struct.unpack(\"!H\", query[:2])[0]:", "if False:"),
            "an error rcode counts": ("    if flags & 0x000F:\n", "    if False:\n"),
            "a query is accepted as a response": ("    if not flags & 0x8000:\n", "    if False:\n"),
            "the question is not echoed": ("    if reply[12:12 + len(query) - 12] != query[12:]:\n", "    if False:\n"),
            # P2-SEAM-H5: the reply is read in CarryClientProcess.exchange().
            "the client's own say-so is a verdict": (
                '        if not valid:\n            # The stream is out of step; nothing read from it can be trusted.\n',
                '        if not valid and isinstance(reply, dict) and reply.get("carried") is True:\n'
                '            return "reachable", "client says so", b""\n'
                '        if not valid:\n            # The stream is out of step; nothing read from it can be trusted.\n'),
            "a proof is never due again": ("    return age is None or age < 0 or age >= interval - CARRY_DUE_SLACK_SECONDS",
                                           "    return False"),
            "open cadence is the pending cadence": ("CARRY_OPEN_INTERVAL_SECONDS = 600", "CARRY_OPEN_INTERVAL_SECONDS = 120"),
            "pending cadence is the open cadence": ("CARRY_PENDING_INTERVAL_SECONDS = 120", "CARRY_PENDING_INTERVAL_SECONDS = 600"),
            "a closed node is probed as open": (
                '    if int(data.get("operator_enabled") or 0) == 1:\n        return "open"\n'
                '    if (str(data.get("deployment_completed_at") or "").strip()\n'
                '            and str(data.get("health_closed_reason") or "").strip() in CARRY_PENDING_REASONS):',
                '    if True:\n        return "open"\n'
                '    if (str(data.get("deployment_completed_at") or "").strip()\n'
                '            and str(data.get("health_closed_reason") or "").strip() in CARRY_PENDING_REASONS):'),
            "a retired node is probed": ('    data = dict(row)\n    if str(data.get("retired_at") or "").strip():\n        return ""\n',
                                         '    data = dict(row)\n'),
            "a key open to others is accepted": ("        if info.st_uid != os.geteuid() or info.st_mode & 0o077:\n",
                                                 "        if False:\n"),
        }
        for name, (old, new) in mutants.items():
            with self.subTest(name):
                mutated = replace_once(hub_source(), old, new)
                with self.assertRaises(AssertionError, msg=f"mutant survived: {name}"):
                    probe_checks(mutated)

    def test_run_level_mutants_are_killed(self):
        """A carry write that closes a node, writes a success on failure, or
        probes outside the cadence classes must fail the run-level tests."""
        mod = load_hub()
        source = hub_source()
        cases = {
            "a failure refreshes the success time": (
                "    ok_at = observed_iso if status == \"ok\" else row[f\"{column}_ok_at\"]\n",
                "    ok_at = observed_iso\n"),
            "a failure closes the node": (
                "        f\"UPDATE nodes SET {column}_status = ?, {column}_ok_at = ?, {column}_checked_at = ? WHERE slug = ?\",\n"
                "        (status, ok_at, observed_iso, slug))\n",
                "        f\"UPDATE nodes SET {column}_status = ?, {column}_ok_at = ?, {column}_checked_at = ?, operator_enabled = CASE WHEN ? = 'ok' THEN operator_enabled ELSE 0 END WHERE slug = ?\",\n"
                "        (status, ok_at, observed_iso, status, slug))\n"),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name):
                mutated = replace_once(source, old, new)
                probe = load_probe(mutated, DB_PATH=mod._DB)
                slug = seed_node(mod, operator_enabled=1, data_plane_udp_carry_status="ok",
                                 data_plane_udp_carry_ok_at="2026-10-07T00:00:00")
                with closing(probe["connect_db"]()) as conn:
                    probe["ensure_columns"](conn)
                    probe["apply_carry_verdict"](conn, slug, "udp", "unreachable", "2026-10-08T00:00:00")
                row = node_row(mod, slug)
                survived = (row["data_plane_udp_carry_ok_at"] == "2026-10-07T00:00:00" and row["operator_enabled"] == 1)
                self.assertFalse(survived, f"mutant survived: {name}")

    def test_peer_push_mutants_are_killed(self):
        def pushes_for(source):
            mod = load_hub(source)
            mod._AWG_CANARY_PEER_LAST.clear()
            pushes = []
            now = mod.utcnow().isoformat()
            seed_node(mod, operator_enabled=1, retired_at=now)
            seed_node(mod, operator_enabled=0, health_closed_reason="installer_rerun", deployment_completed_at=now)
            seed_node(mod, operator_enabled=1)
            seed_node(mod, operator_enabled=0)
            with patch.object(mod, "sync_peer_to_node", side_effect=lambda ip, cfg: pushes.append(dict(cfg)) or True):
                mod.sync_awg_canary_peers_once("", force=True)
            return pushes

        def sound(pushes):
            # the open node and the pending node, the canary key at .1, nobody else
            return (len(pushes) == 2 and all(
                p["vpn_internal_ip"] == "10.8.255.1" and p["client_public_key"] == CANARY for p in pushes))

        source = hub_source()
        self.assertTrue(sound(pushes_for(source)))
        cases = {
            "retired nodes receive the canary (query, class and admission all loosened)": [
                ("WHERE retired_at IS NULL AND (? = '' OR slug = ?)\",\n            (slug_filter, slug_filter),",
                 "WHERE (? = '' OR slug = ?)\",\n            (slug_filter, slug_filter),"),
                ('    data = dict(node)\n    if str(data.get("retired_at") or "").strip():\n        return ""\n'
                 '    if str(data.get("deployment_withdrawal_id") or "").strip():\n        return ""\n',
                 '    data = dict(node)\n'),
                ('    if str(data.get("retired_at") or "").strip():\n        return False\n    return not str(data.get("deployment_withdrawal_id")',
                 '    return not str(data.get("deployment_withdrawal_id")')],
            "the push sends another address": [('"vpn_internal_ip": AWG_CANARY_ADDRESS,', '"vpn_internal_ip": "10.8.255.2",')],
            "the push sends another key": [('"client_public_key": peer[0],', '"client_public_key": peer[0][::-1],')],
            "the push skips the admission predicate and the class": [(
                "        if (not klass or (row[\"status\"] or \"\") in {\"offline\", \"maintenance\"}\n"
                "                or not node_admits_peer(row, system_peer=peer)):\n",
                "        if False:\n"), (
                "        if not peer_push_still_admitted(slug, system_peer=peer):\n"
                "            result[\"skipped\"] += 1\n"
                "            continue\n", "")],
            "pending nodes are not served": [(
                "            and str(data.get(\"health_closed_reason\") or \"\").strip() in AWG_CANARY_PENDING_REASONS):\n"
                "        return \"pending\"",
                "            and False):\n        return \"pending\"")],
            "operator-closed nodes are served as open": [(
                "    if int(data.get(\"operator_enabled\") or 0) == 1:\n        return \"open\"\n"
                "    if (str(data.get(\"deployment_completed_at\") or \"\").strip()\n"
                "            and str(data.get(\"health_closed_reason\") or \"\").strip() in AWG_CANARY_PENDING_REASONS):",
                "    if True:\n        return \"open\"\n"
                "    if (str(data.get(\"deployment_completed_at\") or \"\").strip()\n"
                "            and str(data.get(\"health_closed_reason\") or \"\").strip() in AWG_CANARY_PENDING_REASONS):")],
        }
        for name, edits in cases.items():
            with self.subTest(name):
                mutated = source
                for old, new in edits:
                    mutated = replace_once(mutated, old, new)
                self.assertFalse(sound(pushes_for(mutated)), f"mutant survived: {name}")



if __name__ == "__main__":
    unittest.main(verbosity=2)
