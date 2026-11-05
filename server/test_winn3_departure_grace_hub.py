#!/usr/bin/env python3
"""Winn3 departure grace: a switch made while connected must be answerable,
and every authorization the hub may have published stays bounded and counted.

A server switch made WHILE connected sends its /verify request through the
CURRENT tunnel. The hub used to republish the previous gateway's registry
without the device before replying, so that gateway's one-second registry
refresh could refuse the reply and every retry (lane L15, Round M). Lane L17
keeps the departing identity at the previous gateway for a bounded grace, and
(v2, Round O) records every publication in a durable authority ledger before
the remote write, reserves authorization capacity and the account's departure
budget before anything is published, and publishes a destination provisional
until its transaction commits.

These tests run the REAL hub source (extracted from the ONETOUCH heredoc by
the shared harness) against real SQLite files. Publication goes through the
REAL sync_winn3_registry_to_node, and the REAL remote shell command it builds
is executed by bash against a scratch directory per node, with only getent,
install, chown and flock shimmed. The files that land are the gateway's input.
Authorization is then judged with the gateway's own rules: an entry authorizes
while not_after == 0 or now < not_after (peer_registry.go reloadLocked and
innerForPeer), and a replaced file may still be answered from the cached
snapshot for up to registryFreshness = 1 s after it lands.

No test contacts a node, a live hub, or the network. Addresses are RFC 5737
documentation literals.

Run:  python3 server/test_winn3_departure_grace_hub.py
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import base64
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import errno
import json
import logging
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_descriptor_hub as descriptor

NODES = ("lab-alpha", "lab-beta", "lab-gamma", "lab-delta")
GRACE = 120
PROVISIONAL = 600
DEVICE_ID = "device-abcdef0123456789"
GATEWAY_FRESHNESS = 1.0  # peer_registry.go registryFreshness
REAL_RUN = subprocess.run
# include/uapi/linux/binfmts.h: MAX_ARG_STRLEN = 32 pages of 4 KiB. execve
# returns E2BIG for one argument string above it, counting its NUL. macOS
# allows far more, so without this check a change that puts a registry back in
# the ssh command would pass on a Mac and fail only on the production hub.
LINUX_MAX_ARG_STRLEN = 131072


class Crash(BaseException):
    """The hub process dies: no except-Exception handler runs."""


class RecordingHTTPException(harness.HTTPException):
    def __init__(self, status_code, detail="", headers=None, **kwargs):
        super().__init__(status_code, detail)
        self.headers = dict(headers or {})


class Clock:
    """Wall time plus a test offset, so it never runs behind SQLite's own
    'now' (which v1's triggers read) and only ever moves forward."""

    def __init__(self):
        self.offset = 0.0

    @property
    def now(self):
        return time.time() + self.offset

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.offset += seconds


class HubTime:
    """The hub module's `time`, with time.time() on the test clock.

    Replacing the hub module's global (never the real time module) moves every
    hub clock read to the test clock, on v1 and v2 alike, so a red result on an
    older hub is a behavioural result and not a clock mismatch.
    """

    def __init__(self, clock):
        self._clock = clock

    def time(self):
        return self._clock.now

    def __getattr__(self, name):
        return getattr(time, name)


# Defaults for hubs that predate the constants (v1), so v1 runs the same
# assertions and fails on behaviour.
REFRESH = 2.0
SKEW = 5.0
RETENTION = 600


def entry_authorizes(document, static_public, at):
    for entry in (document or {}).get("peers", []):
        if entry["static_public"] == static_public:
            not_after = int(entry["not_after"])
            return not_after == 0 or int(at) < not_after
    return False


class Fleet:
    """Scratch /etc/winn per node, written only by the hub's real command."""

    def __init__(self, clock):
        self.clock = clock
        self.root = tempfile.mkdtemp(prefix="winn3-fleet-")
        self.shims = os.path.join(self.root, "shims")
        os.makedirs(self.shims)
        tools = [
            ("getent", "exit 0"),
            ("chown", "exit 0"),
            ("flock", "exit 0"),
            ("install", 'for last; do :; done; mkdir -p "$last"'),
            # The registry command bounds its stdin read with timeout(1),
            # which macOS does not ship, and syncs the temp file. macOS sync(8)
            # flushes the whole machine, and this clock is wall time plus an
            # offset, so a slow sync would move every test's clock.
            ("timeout", 'shift; exec "$@"'),
            ("sync", "exit 0"),
        ]
        if shutil.which("sha256sum") is None:  # older macOS ships shasum only
            tools.append(("sha256sum", 'exec shasum -a 256 "$@"'))
        for name, body in tools:
            path = os.path.join(self.shims, name)
            with open(path, "w") as handle:
                handle.write("#!/bin/bash\n" + body + "\n")
            os.chmod(path, stat.S_IRWXU)
        self.history = {slug: [] for slug in NODES}
        self.mode = {}
        self.commands = []

    def directory(self, slug):
        return os.path.join(self.root, slug, "etc_winn")

    def execute(self, slug, command, stdin=None):
        target = self.directory(slug)
        os.makedirs(target, exist_ok=True)
        registry = os.path.join(target, "winn3-peers.json")
        before = self.identity(registry)
        env = dict(os.environ, PATH=self.shims + os.pathsep + os.environ.get("PATH", ""))
        result = REAL_RUN(
            ["bash", "--noprofile", "--norc", "-c", command.replace("/etc/winn", target)],
            input=stdin, capture_output=True, text=True, env=env, check=False,
        )
        # A landing is a replaced registry file (new inode from mv -f), which
        # is what the gateway's stat notices; any hub version is observed.
        if self.identity(registry) != before:
            with open(registry) as handle:
                self.history.setdefault(slug, []).append((self.clock.now, json.load(handle)))
        return result

    @staticmethod
    def identity(path):
        try:
            info = os.stat(path)
        except FileNotFoundError:
            return None
        return (info.st_ino, info.st_mtime_ns, info.st_size)

    def run(self, slug, command, stdin=None):
        self.commands.append((slug, command))
        mode = self.mode.get(slug, "ok")

        class Result:
            def __init__(self, returncode, stderr="", stdout=""):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        if mode == "down":
            return Result(255, "ssh: connect to host: Connection timed out")
        result = self.execute(slug, command, stdin)
        if mode == "lost_ack":
            return Result(255, "client_loop: send disconnect: Broken pipe")
        if mode == "crash":
            raise Crash()
        return Result(result.returncode, result.stderr, result.stdout)

    def landed(self, slug):
        return self.history[slug][-1][1] if self.history.get(slug) else None

    def authorizes(self, slug, static_public, at):
        """The gateway's view at hub time `at`, including its cached snapshot."""
        files = [(t, doc) for t, doc in self.history.get(slug, []) if t <= at]
        if not files:
            return False
        landed_at, current = files[-1]
        if entry_authorizes(current, static_public, at):
            return True
        if len(files) > 1 and at < landed_at + GATEWAY_FRESHNESS:
            return entry_authorizes(files[-2][1], static_public, at)
        return False

    def effective(self, static_public, at):
        """Every simulated gateway machine, including one a slug has moved
        away from (keyed "slug@host")."""
        return sorted(s for s in self.history if self.authorizes(s, static_public, at))

    def instants(self):
        points = set()
        for files in self.history.values():
            for landed_at, _ in files:
                points.update((landed_at, landed_at + 0.5, landed_at + GATEWAY_FRESHNESS - 0.01))
        return sorted(points)


class DepartureGraceTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.fleet = Fleet(self.clock)
        self.mod = self.load()
        self.addCleanup(self.cleanup)
        harness.seed_account(self.mod, devices=0)
        for slug in NODES:
            payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=slug))
            descriptor.seed_node(
                self.mod, slug=slug, protocol_version="winn/3", protocol_params_json="{}",
                descriptor_json=json.dumps({"payload": payload, "sig": signature}),
            )
            with self.mod.get_db() as conn:
                conn.execute("UPDATE nodes SET ssh_host='127.0.0.1' WHERE slug=?", (slug,))
        self.bearer = None
        self.awg = []
        self.tasks = []

    def load(self, **env):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        settings = dict(
            DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0,
            WINN3_INNER_POOL_CIDR="10.10.0.0/24", WINN3_CANARY_NODE_SLUG="",
            HIDE_CONTROL_ORIGIN=0, DEVICE_LIMIT=1,
        )
        settings.update(env)
        with patch("logging.basicConfig", side_effect=close_handlers):
            mod = descriptor.load_hub_with_ring(**settings)
        mod.logger.propagate = False
        mod.logger.addHandler(logging.NullHandler())
        mod.security_alert = lambda *args, **kwargs: None
        mod.time = HubTime(self.clock)
        # utcnow() reads now_utc(): account expiry is judged on the same clock.
        mod.now_utc = lambda: datetime.fromtimestamp(self.clock.now, timezone.utc)
        return mod

    def cleanup(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)
        shutil.rmtree(self.fleet.root, ignore_errors=True)

    # ------------------------------------------------------------ plumbing

    def patched(self, mod):
        real_sync = mod.sync_winn3_registry_to_node
        current = [None]

        def fake_run(args, **kwargs):
            for item in args if isinstance(args, list) else ():
                if len(str(item).encode("utf-8")) + 1 > LINUX_MAX_ARG_STRLEN:
                    raise OSError(errno.E2BIG, "Argument list too long", str(args[0]))
            command = args[2] if isinstance(args, list) and len(args) == 3 else ""
            if "/etc/winn/" in command and current[0] is None:
                raise AssertionError("a node command ran without a target node")
            if "/etc/winn/winn3-peers.json" not in command:
                return REAL_RUN(args, **kwargs)
            return self.fleet.run(current[0], command, kwargs.get("input"))

        def machine(slug, node_ip):
            # One simulated gateway per (slug, host): the fixture's hosts are
            # all 127.0.0.1, so a slug registered at any other host is a
            # different machine, and the one it left stays online.
            return slug if str(node_ip or "") in {"", "127.0.0.1"} else f"{slug}@{node_ip}"

        def publish(conn, node_ip, slug, *args, **kwargs):
            current[0] = machine(slug, node_ip)
            return real_sync(conn, "127.0.0.1", slug, *args, **kwargs)

        real_observe = getattr(mod, "observe_winn3_node", None)

        def observe(node_ip, slug, *args, **kwargs):
            current[0] = machine(slug, node_ip)
            return real_observe("127.0.0.1", slug, *args, **kwargs)

        def awg(host, cfg):
            self.awg.append(host)
            return True

        def ssh(node_host, remote_command, **kwargs):
            # H0 (D3): the hub no longer runs a node command locally for a
            # loopback host, so the simulated fleet stands in for the SSH
            # transport, with the argv the local branch used to build.
            return ["bash", "-lc", remote_command]

        patches = [
            patch.object(mod, "sync_winn3_registry_to_node", side_effect=publish),
            patch.object(mod, "node_ssh_command", side_effect=ssh),
            patch.object(mod.subprocess, "run", side_effect=fake_run),
            patch.object(mod, "sync_peer_to_node", side_effect=awg),
            patch.object(mod, "HTTPException", RecordingHTTPException),
        ]
        if real_observe is not None:
            patches.append(patch.object(mod, "observe_winn3_node", side_effect=observe))
        return patches

    def publish_now(self, conn, slug, mod=None):
        mod = mod or self.mod
        return self.run_patched(
            mod, lambda: mod.sync_winn3_registry_to_node(conn, "127.0.0.1", slug))

    def run_patched(self, mod, fn, *args, **kwargs):
        with ExitStack() as stack:
            for item in self.patched(mod):
                stack.enter_context(item)
            return fn(*args, **kwargs)

    def verify(self, location, *, enroll=False, mod=None, background=True, **overrides):
        mod = mod or self.mod
        if enroll or self.bearer is None:
            descriptor.arm_activation(mod)
            headers = {"x-wins-activation": descriptor.ACTIVATION_SECRET}
        else:
            headers = {"authorization": "Bearer " + self.bearer}
        login = descriptor.build_login(
            mod, location=location, supports_winn3=True,
            supports_winn3_descriptor=True, **overrides)
        tasks = harness.BackgroundTasks()

        def call():
            return asyncio.run(mod.verify_account(
                harness.FakeRequest(path="/verify", headers=headers), login, tasks))

        result = self.run_patched(mod, call)
        body = json.loads(result.body) if hasattr(result, "body") else result
        if body.get("device_auth_token"):
            self.bearer = body["device_auth_token"]
        self.tasks = tasks.tasks
        if background:
            self.run_background(mod)
        return body

    def run_background(self, mod=None):
        mod = mod or self.mod
        for fn, args, kwargs in self.tasks:
            self.run_patched(mod, fn, *args, **kwargs)
        self.tasks = []

    def deferred(self, location, **kwargs):
        with self.assertRaises(RecordingHTTPException) as caught:
            self.verify(location, **kwargs)
        self.assertEqual(caught.exception.status_code, 503)
        return caught.exception

    def drain(self, mod=None):
        mod = mod or self.mod
        return self.run_patched(mod, mod.drain_winn3_registry_refreshes, 32)

    def reconcile(self, mod=None):
        mod = mod or self.mod
        if not hasattr(mod, "reconcile_winn3_authority_ledger"):
            return {"queued": 0, "pruned": 0}
        # Patched like every remote operation: v4 reconcile reads nodes back.
        return self.run_patched(mod, mod.reconcile_winn3_authority_ledger)

    def device(self, mod=None):
        with (mod or self.mod).get_db() as conn:
            return dict(conn.execute("SELECT * FROM devices").fetchone())

    def document(self, slug, mod=None):
        with (mod or self.mod).get_db() as conn:
            return (mod or self.mod).winn3_peer_registry_document(conn, slug)

    def grants(self, mod=None):
        with (mod or self.mod).get_db() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM winn3_departure_grants ORDER BY issued_at, grant_id")]

    def live_grant_nodes(self):
        return sorted(g["node_slug"] for g in self.grants() if g["expires_at"] > self.clock.now)

    def queued(self, mod=None):
        with (mod or self.mod).get_db() as conn:
            return {row[0] for row in conn.execute(
                "SELECT node_slug FROM winn3_registry_refreshes WHERE next_attempt_at<=?",
                (self.clock.now,))}

    def clear_queue(self):
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM winn3_registry_refreshes")

    def hub_effective(self, key, mod=None):
        mod = mod or self.mod
        if not hasattr(mod, "winn3_effective_authorizations"):
            return []  # an older hub counts nothing it has published
        return sorted(mod.winn3_effective_authorizations(key, self.clock.now))

    def charges(self, mod=None):
        mod = mod or self.mod
        if not hasattr(mod, "winn3_departure_charges_in_window"):
            with mod.get_db() as conn:  # v1 counted its database grant rows
                return conn.execute(
                    "SELECT COUNT(*) FROM winn3_departure_grants WHERE issued_at>?",
                    (self.clock.now - 3600,)).fetchone()[0]
        return len(mod.winn3_departure_charges_in_window(harness.ACCOUNT, self.clock.now))

    def account_bound(self, mod=None):
        mod = mod or self.mod
        with mod.get_db() as conn:
            raw = conn.execute("SELECT expiration_date FROM users").fetchone()[0]
        return int(mod.parse_iso_datetime(raw).timestamp())

    def connected_at(self, slug):
        """Enrol, finalize, and settle on `slug` as a connected device on a
        hub whose authority recovery has completed (v3): every node confirmed,
        and the rolling charge window since recovery began has passed."""
        self.verify(slug, enroll=True)
        self.recover()
        self.clear_queue()
        self.awg.clear()
        return self.device()["winn3_static_public"]

    def tick(self, seconds):
        """Advance the hub clock; nodes keep heartbeating meanwhile."""
        self.clock.advance(seconds)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET last_heartbeat=?", (self.mod.utcnow().isoformat(),))

    def recover(self):
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.tick(3600)
        self.reconcile()
        self.drain()

    def assert_fleet_bounded(self, key):
        """Published files never authorize the identity at more than three
        gateways, at any landing instant or within the refresh window."""
        for instant in self.fleet.instants():
            self.assertLessEqual(
                len(self.fleet.effective(key, instant)), 3,
                f"published files authorize {self.fleet.effective(key, instant)} at {instant}")

    def assert_bounded(self, key):
        """assert_fleet_bounded, and the hub never counts fewer gateways than
        the published files authorize right now."""
        self.assert_fleet_bounded(key)
        now = self.clock.now
        self.assertTrue(
            set(self.fleet.effective(key, now)) <= set(self.hub_effective(key)),
            f"hub counts {self.hub_effective(key)} but gateways authorize {self.fleet.effective(key, now)}")

    # ---------------------------------------------------- the live failure

    def test_red_switch_reply_path_stays_authorized_at_previous_gateway(self):
        """THE LIVE FAILURE. Pristine: alpha's file is {"peers":[]} on reply."""
        key = self.connected_at("lab-alpha")
        started = self.clock.now
        self.verify("lab-beta")
        self.assertEqual(self.device()["location_slug"], "lab-beta")
        alpha = self.fleet.landed("lab-alpha")
        self.assertTrue(entry_authorizes(alpha, key, started),
                        "previous gateway refuses the switch reply: " + json.dumps(alpha))
        self.assertTrue(entry_authorizes(alpha, key, started + 30))
        self.assertFalse(entry_authorizes(alpha, key, started + GRACE + 1))
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-beta"), key, started))
        self.assert_bounded(key)

    def test_new_node_is_published_before_previous_node(self):
        self.connected_at("lab-alpha")
        self.fleet.commands.clear()
        self.verify("lab-beta", background=False)
        self.assertEqual([slug for slug, _ in self.fleet.commands], ["lab-beta", "lab-alpha"])

    # ------------------------------------------- Defect 2: provisional destination

    def test_destination_is_provisional_until_commit_then_finalized(self):
        key = self.connected_at("lab-alpha")
        self.assertEqual([p["not_after"] for p in self.fleet.landed("lab-alpha")["peers"]],
                         [self.account_bound()])
        self.verify("lab-beta", background=False)
        first = [p for p in self.fleet.landed("lab-beta")["peers"] if p["static_public"] == key]
        self.assertEqual(len(first), 1)
        self.assertNotEqual(first[0]["not_after"], 0)
        self.assertLessEqual(first[0]["not_after"], int(self.clock.now) + PROVISIONAL,
                             "destination published with its full bound before commit")
        self.assertIn("lab-beta", self.queued())
        self.run_background()
        final = [p for p in self.fleet.landed("lab-beta")["peers"] if p["static_public"] == key]
        self.assertEqual([p["not_after"] for p in final], [self.account_bound()])
        self.assertNotIn("lab-beta", self.queued())

    def test_reconnect_to_the_same_node_is_not_provisional(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-alpha", background=False)
        self.assertEqual(
            [(p["static_public"], p["not_after"]) for p in self.fleet.landed("lab-alpha")["peers"]],
            [(key, self.account_bound())])
        self.assertEqual(self.tasks, [])

    def test_lost_ack_at_destination_stays_represented_and_bounded(self):
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        caught = self.deferred("lab-beta")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_peer_registry_sync_failed")
        self.assertEqual(self.device()["location_slug"], "lab-alpha")
        landed = [p for p in self.fleet.landed("lab-beta")["peers"] if p["static_public"] == key]
        self.assertEqual(len(landed), 1, "the lost write did land")
        self.assertNotEqual(landed[0]["not_after"], 0)
        bound = landed[0]["not_after"]
        self.assertLessEqual(bound, int(self.clock.now) + PROVISIONAL)
        # Represented although the transaction rolled back.
        self.assertIn("lab-beta", self.hub_effective(key))
        self.assertEqual(self.charges(), 0, "no departure allowance was published")
        self.assert_bounded(key)
        # Cleanup is unavailable: the residue ends at its own bound.
        self.fleet.mode["lab-beta"] = "down"
        self.clear_queue()
        self.reconcile()
        self.assertIn("lab-beta", self.queued())
        self.assertEqual(self.drain()["retry"], 1)
        self.assertEqual(self.fleet.landed("lab-beta")["peers"][0]["not_after"], bound)
        self.tick(bound - self.clock.now - 1)
        self.assertTrue(self.fleet.authorizes("lab-beta", key, self.clock.now))
        self.assertIn("lab-beta", self.hub_effective(key))
        self.tick(1)
        self.assertFalse(self.fleet.authorizes("lab-beta", key, self.clock.now))
        self.assertIn("lab-beta", self.hub_effective(key), "released before the skew bound")
        self.tick(SKEW)
        self.assertNotIn("lab-beta", self.hub_effective(key))
        self.assert_bounded(key)

    def test_lost_ack_at_destination_is_withdrawn_when_cleanup_returns(self):
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        self.deferred("lab-beta")
        self.fleet.mode["lab-beta"] = "ok"
        self.drain()
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-beta"), key, self.clock.now))
        self.assertIn("lab-beta", self.hub_effective(key), "gateway refresh not yet established")
        self.tick(REFRESH + 0.01)
        self.assertNotIn("lab-beta", self.hub_effective(key))
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))

    def test_lost_ack_at_previous_node_keeps_charge_and_representation(self):
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-alpha"] = "lost_ack"
        caught = self.deferred("lab-beta")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"),
                         "winn3_peer_registry_stale_removal_failed")
        self.assertEqual(self.device()["location_slug"], "lab-alpha")
        self.assertEqual(self.grants(), [], "the database grant rolled back")
        self.assertEqual(self.charges(), 1, "an allowance that may have reached a gateway stays charged")
        alpha = [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key]
        self.assertTrue(0 < alpha[0]["not_after"] <= int(self.clock.now) + GRACE)
        beta = [p for p in self.fleet.landed("lab-beta")["peers"] if p["static_public"] == key]
        self.assertTrue(0 < beta[0]["not_after"] <= int(self.clock.now) + PROVISIONAL)
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta"])
        self.assertEqual(self.queued(), {"lab-alpha", "lab-beta"})
        self.assert_bounded(key)
        self.fleet.mode["lab-alpha"] = "ok"
        self.drain()
        self.assertEqual(
            [(p["static_public"], p["not_after"]) for p in self.fleet.landed("lab-alpha")["peers"]],
            [(key, self.account_bound())], "the device, still at alpha, gets its full entry back")
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-beta"), key, self.clock.now))
        self.assertEqual(self.charges(), 1)
        self.assert_bounded(key)

    def test_crash_after_publication_is_reconciled_after_restart(self):
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-alpha"] = "crash"
        with self.assertRaises(Crash):
            self.verify("lab-beta")
        self.fleet.mode.clear()
        # Both remote writes landed, bounded, with nothing committed.
        self.assertTrue(0 < self.fleet.landed("lab-beta")["peers"][0]["not_after"])
        self.assertTrue(0 < self.fleet.landed("lab-alpha")["peers"][0]["not_after"])
        restarted = self.load(DATABASE_PATH=self.mod._DB)
        self.assertEqual(getattr(restarted, "WINN3_AUTHORITY_LEDGER_PATH", None),
                         getattr(self.mod, "WINN3_AUTHORITY_LEDGER_PATH", None))
        self.assertEqual(self.device(mod=restarted)["location_slug"], "lab-alpha")
        self.assertEqual(self.hub_effective(key, mod=restarted), ["lab-alpha", "lab-beta"])
        self.assertEqual(self.charges(mod=restarted), 1)
        self.reconcile(mod=restarted)
        self.assertTrue({"lab-alpha", "lab-beta"} <= self.queued(mod=restarted))
        self.drain(mod=restarted)
        self.assertEqual(
            [(p["static_public"], p["not_after"]) for p in self.fleet.landed("lab-alpha")["peers"]],
            [(key, self.account_bound())])
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-beta"), key, self.clock.now))
        self.assert_bounded(key)

    def test_failed_previous_node_withdraws_the_already_published_destination(self):
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-alpha"] = "down"
        self.deferred("lab-beta")
        self.assertEqual(self.device()["location_slug"], "lab-alpha")
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.charges(), 1, "the grant publication was attempted")
        beta = [p for p in self.fleet.landed("lab-beta")["peers"] if p["static_public"] == key]
        self.assertTrue(0 < beta[0]["not_after"] <= int(self.clock.now) + PROVISIONAL,
                        "destination published before the failure is unbounded")
        self.assertIn("lab-beta", self.hub_effective(key))
        self.assertEqual(self.queued(), {"lab-alpha", "lab-beta"})
        self.fleet.mode["lab-alpha"] = "ok"
        self.drain()
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-beta"), key, self.clock.now),
                         "already-published destination was not withdrawn")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.hub_effective(key), ["lab-alpha"])

    def test_remote_sequence_guard_refuses_a_stale_publication(self):
        key = self.connected_at("lab-alpha")
        captured = []

        def capture(slug, command, stdin=None):
            captured.append((command, stdin))

            class Result:
                returncode = 255
                stdout = ""
                stderr = "timeout"
            return Result()

        with patch.object(self.fleet, "run", side_effect=capture):
            with self.mod.get_db() as conn:
                self.publish_now(conn, "lab-alpha")
            self.tick(1)
            with self.mod.get_db() as conn:
                conn.execute("UPDATE users SET status='disabled'")
                self.publish_now(conn, "lab-alpha")
        older, newer = captured
        self.assertEqual(self.fleet.execute("lab-alpha", *newer).returncode, 0)
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        late = self.fleet.execute("lab-alpha", *older)
        self.assertEqual(late.returncode, 3)
        self.assertIn("winn3-registry-stale-sequence", late.stderr)
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now),
                         "an older, unacknowledged write landed over a newer one")
        # Through the hub: a refused write is recorded as refused, not uncertain.
        seq_path = os.path.join(self.fleet.directory("lab-alpha"), ".winn3-peers.seq")
        with open(seq_path, "w") as handle:
            handle.write(str(10 ** 18))
        self.fleet.mode.clear()
        with self.mod.get_db() as conn:
            self.assertFalse(self.publish_now(conn, "lab-alpha"))
        with self.mod.winn3_authority_ledger() as ledger:
            outcome = ledger.execute(
                "SELECT outcome FROM winn3_publications ORDER BY seq DESC LIMIT 1").fetchone()[0]
        self.assertEqual(outcome, "refused")

    # ------------------------------------------- Defect 1: capacity

    def test_rapid_chain_never_exceeds_three_effective_authorizations(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.assert_fleet_bounded(key)
        self.verify("lab-gamma")
        self.assert_fleet_bounded(key)
        landings = sum(len(files) for files in self.fleet.history.values())
        self.awg.clear()
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        # Judged on the published files first: v1 lets delta through and
        # alpha, beta, gamma and delta all authorize.
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "the fourth gateway was published")
        self.assertEqual(caught.status_code, 503)
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta", "lab-gamma"])
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_capacity")
        retry = int(caught.headers["Retry-After"])
        self.assertTrue(1 <= retry <= GRACE + 6, retry)
        # Nothing remote changed: no AWG peer, no registry write, no move.
        self.assertEqual(self.awg, [])
        self.assertEqual(sum(len(files) for files in self.fleet.history.values()), landings)
        self.assertEqual(self.device()["location_slug"], "lab-gamma")
        self.assertTrue(self.fleet.authorizes("lab-gamma", key, self.clock.now),
                        "the current connection must keep working")
        self.assertEqual(self.fleet.effective(key, self.clock.now), ["lab-alpha", "lab-beta", "lab-gamma"])
        # A retired database grant is NOT released capacity.
        with self.mod.get_db() as conn:
            self.mod.retire_winn3_departure_grants(conn, DEVICE_ID, ["lab-alpha"])
        self.assertEqual(self.deferred("lab-delta").headers["X-Wins-Error-Code"],
                         "winn3_switch_deferred_capacity")
        # Once alpha's published grant has provably ended, delta is allowed.
        self.tick(retry)
        self.verify("lab-delta")
        self.assert_bounded(key)
        self.assertEqual(self.device()["location_slug"], "lab-delta")
        self.assertLessEqual(len(self.hub_effective(key)), 3)

    def test_switch_back_inside_the_window_supersedes_the_grant(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.verify("lab-alpha")
        self.assertEqual(self.live_grant_nodes(), ["lab-beta"])
        alpha = self.fleet.landed("lab-alpha")["peers"]
        self.assertEqual([(p["static_public"], p["not_after"]) for p in alpha],
                         [(key, self.account_bound())])
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-beta"), key, self.clock.now))
        self.assert_bounded(key)

    # ------------------------------------------- Defect 3: budget

    def test_budget_exhaustion_defers_before_any_publication(self):
        key = self.connected_at("lab-alpha")
        for index, slug in enumerate(["lab-beta", "lab-alpha"] * 3):
            self.verify(slug)
            self.assertEqual(self.charges(), index + 1)
            self.assert_fleet_bounded(key)
            self.tick(10)
        landings = sum(len(files) for files in self.fleet.history.values())
        self.awg.clear()
        caught = self.deferred("lab-beta")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_budget")
        retry = int(caught.headers["Retry-After"])
        self.assertTrue(3600 - 70 <= retry <= 3600, retry)
        self.assertEqual(self.awg, [])
        self.assertEqual(sum(len(files) for files in self.fleet.history.values()), landings)
        self.assertEqual(self.device()["location_slug"], "lab-alpha")
        self.assertTrue(self.fleet.authorizes("lab-alpha", key, self.clock.now))
        self.assertEqual(self.charges(), 6)
        self.tick(retry)
        self.verify("lab-beta")
        self.assertEqual(self.device()["location_slug"], "lab-beta")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.assertEqual(self.charges(), 6, "the first charge aged out, one new charge")

    def test_retry_after_committed_switch_reuses_the_grant_without_spending_budget(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.assertEqual(self.charges(), 1)
        first = self.grants()
        self.verify("lab-beta")
        self.assertEqual(self.grants(), first)
        self.assertEqual(self.charges(), 1)
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))

    def test_grace_is_capped_at_the_policy_ceiling_and_zero_disables_it(self):
        self.mod.WINN3_DEPARTURE_GRACE_SECONDS = 10_000
        self.assertEqual(self.mod.winn3_departure_grace_seconds(), 120)
        self.mod.WINN3_DEPARTURE_GRACE_SECONDS = "junk"
        self.assertEqual(self.mod.winn3_departure_grace_seconds(), 0)
        self.mod.WINN3_DEPARTURE_GRACE_SECONDS = 0
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.assertEqual(self.fleet.landed("lab-alpha"), {"version": 1, "peers": []})
        self.assertEqual(self.grants(), [])
        self.assertEqual(self.charges(), 0)
        self.assert_bounded(key)

    # ------------------------------------------- revocation during the window

    def assert_revoked_everywhere_but(self, key, allowed=()):
        for slug in NODES:
            self.assertEqual(
                entry_authorizes(self.document(slug), key, self.clock.now), slug in allowed, slug)

    def test_device_deletion_during_window_revokes_everywhere(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM devices WHERE device_id=?", (DEVICE_ID,))
        self.assertEqual(self.live_grant_nodes(), [])
        self.assertEqual(self.queued(), {"lab-alpha", "lab-beta"})
        self.assert_revoked_everywhere_but(key)
        # Revocation is effective only once published and refreshed.
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta"])
        self.drain()
        for slug in ("lab-alpha", "lab-beta"):
            self.assertFalse(entry_authorizes(self.fleet.landed(slug), key, self.clock.now), slug)
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.hub_effective(key), [])

    def test_account_expiry_during_window_revokes_everywhere(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date=?",
                         ((self.mod.utcnow() - timedelta(seconds=1)).isoformat(),))
            self.assertTrue(self.mod.expire_account_runtime_if_due(conn, harness.ACCOUNT))
        self.assertEqual(self.live_grant_nodes(), [])
        self.assertTrue({"lab-alpha", "lab-beta"} <= self.queued())
        self.assert_revoked_everywhere_but(key)

    def test_account_disable_during_window_revokes_everywhere(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET status='disabled'")
        self.assertEqual(self.live_grant_nodes(), [])
        self.assertTrue({"lab-alpha", "lab-beta"} <= self.queued())
        self.assert_revoked_everywhere_but(key)

    def test_expiry_shortening_queues_propagation_without_retiring(self):
        """Behaviour pin for the certified sentence (green on v1 by design)."""
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        published = [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key][0]
        self.clear_queue()
        sooner = self.mod.utcnow() + timedelta(seconds=30)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date=?", (sooner.isoformat(),))
        self.assertEqual(self.live_grant_nodes(), ["lab-alpha"], "expiry change alone retired the grant")
        self.assertTrue({"lab-alpha", "lab-beta"} <= self.queued())
        self.assertEqual(
            [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key][0],
            published, "the published allowance stands until republished")
        self.drain()
        capped = [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key][0]
        self.assertLessEqual(capped["not_after"], int(sooner.timestamp()))

    def test_admin_expiry_shortening_during_window_queues_the_grant_node(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date=?",
                         ((self.mod.utcnow() - timedelta(seconds=1)).isoformat(),))
        self.assertTrue({"lab-alpha", "lab-beta"} <= self.queued())
        self.assert_revoked_everywhere_but(key)

    def test_identity_rotation_issues_no_grant_and_ends_live_grants(self):
        old_key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.assertEqual(self.live_grant_nodes(), ["lab-alpha"])
        self.verify("lab-gamma", enroll=True)
        new_key = self.device()["winn3_static_public"]
        self.assertNotEqual(new_key, old_key)
        self.assertEqual(self.live_grant_nodes(), [])
        self.assert_revoked_everywhere_but(old_key)
        self.assert_revoked_everywhere_but(new_key, allowed=("lab-gamma",))
        self.assertEqual(self.charges(), 1)

    def test_freed_inner_address_reuse_never_breaks_the_previous_node_snapshot(self):
        self.connected_at("lab-alpha")
        self.verify("lab-beta")
        grant = self.grants()[0]
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET winn3_inner_v4=NULL, winn3_static_private=NULL, "
                         "winn3_static_public=NULL")
        self.assertEqual(self.live_grant_nodes(), [])
        self.assertIn("lab-alpha", self.queued())
        with self.mod.get_db() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, account_number, location_slug, "
                "winn3_inner_v4, winn3_static_private, winn3_static_public) "
                "VALUES ('second-device', ?, 'lab-alpha', ?, 'x', ?)",
                (harness.ACCOUNT, grant["inner_v4"], base64.b64encode(b"N" * 32).decode()))
        document = self.document("lab-alpha")
        self.assertEqual([p["static_public"] for p in document["peers"]],
                         [base64.b64encode(b"N" * 32).decode()])
        self.assertFalse(entry_authorizes(document, grant["static_public"], self.clock.now))

    def test_canary_binding_wins_over_a_grant(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        inner = self.device()["winn3_inner_v4"]
        canary_key = base64.b64encode(b"K" * 32).decode()
        env = {"WINN3_CANARY_NODE_SLUG": "lab-alpha",
               "WINN3_CANARY_STATIC_PUBLIC": canary_key,
               "WINN3_CANARY_INNER_V4": inner}
        with patch.dict("os.environ", env):
            document = self.document("lab-alpha")
        self.assertEqual(document["peers"], [{
            "static_public": canary_key, "inner_v4": inner, "not_after": 0}])
        self.assertFalse(entry_authorizes(document, key, self.clock.now))

    # ------------------------------------------- v3: recovery barrier

    def enrolled_at(self, slug):
        """Enrol with NO recovery pass: the state of a freshly deployed hub, or
        one whose ledger has just been lost."""
        self.verify(slug, enroll=True, background=False)
        self.awg.clear()
        return self.device()["winn3_static_public"]

    def landings(self):
        return sum(len(files) for files in self.fleet.history.values())

    def recovery(self):
        """The hub's recovery view, or None on a hub without a barrier (v2)."""
        state = getattr(self.mod, "winn3_recovery_state", None)
        if state is None:
            return None
        with self.mod.get_db() as conn:
            return state(conn, self.clock.now)

    def unrecovered(self):
        view = self.recovery()
        return None if view is None else view["unrecovered"]

    def recovery_complete(self):
        view = self.recovery()
        return None if view is None else view["complete"]

    def assert_deferred_before_publication(self, location, code):
        self.awg.clear()
        landings = self.landings()
        before = self.device()
        key = before["winn3_static_public"]
        caught = self.deferred(location)
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), code)
        self.assertEqual(self.landings(), landings, "a deferred switch published something")
        self.assertEqual(self.awg, [], "a deferred switch installed an AWG peer")
        self.assertEqual(self.device()["location_slug"], before["location_slug"])
        self.assertTrue(self.fleet.authorizes(before["location_slug"], key, self.clock.now),
                        "the current connection must keep working")
        return caught

    def replace_ledger_with_an_empty_one(self, mod=None):
        path = (mod or self.mod).WINN3_AUTHORITY_LEDGER_PATH
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)

    def copy_files(self, path):
        copies = {}
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                with open(path + suffix, "rb") as handle:
                    copies[suffix] = handle.read()
        return copies

    def restore_files(self, path, copies):
        for suffix in ("", "-wal", "-shm"):
            if os.path.exists(path + suffix):
                os.remove(path + suffix)
        for suffix, data in copies.items():
            with open(path + suffix, "wb") as handle:
                handle.write(data)

    def test_admission_before_first_reconciliation_is_deferred(self):
        key = self.enrolled_at("lab-alpha")
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_admission_after_enqueue_before_confirmation_is_deferred(self):
        key = self.enrolled_at("lab-alpha")
        self.all_down()  # neither read-back nor publication can confirm
        self.reconcile()
        self.assertTrue(set(NODES) <= self.queued(), "recovery queues every v3 node")
        # Queued, not confirmed: still deferred, and after a restart too.
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.mod = self.load(DATABASE_PATH=self.mod._DB)
        self.reconcile()
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        # Confirmed but inside the refresh allowance: still deferred.
        self.fleet.mode.clear()
        self.reconcile()
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assertEqual(self.device()["location_slug"], "lab-beta")
        self.assert_bounded(key)

    def test_confirmation_before_the_refresh_allowance_does_not_release_a_node(self):
        self.enrolled_at("lab-alpha")
        self.reconcile()
        self.drain()
        self.assertEqual(self.unrecovered(), set(NODES))
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.unrecovered(), set())

    def test_empty_ledger_with_residues_never_admits_a_fourth_gateway(self):
        """Astra's probe: residues at beta and gamma, then an empty ledger."""
        key = self.connected_at("lab-alpha")
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.assertEqual(self.fleet.effective(key, self.clock.now),
                         ["lab-alpha", "lab-beta", "lab-gamma"])
        self.replace_ledger_with_an_empty_one()
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "a fourth gateway was published")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        self.assertEqual(self.charges(), 0)
        # Recovery republishes every node from the database and confirms it.
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertEqual(self.fleet.effective(key, self.clock.now), ["lab-alpha"])
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_missing_charge_history_is_not_a_fresh_budget(self):
        """An empty ledger reads as no charges; the node journals say six."""
        key = self.connected_at("lab-alpha")
        for slug in ["lab-beta", "lab-alpha"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        self.replace_ledger_with_an_empty_one()
        self.assertEqual(self.charges(), 0, "the lost history reads as empty")
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        # The restored charges age out on their own times, not the loss time.
        self.tick(3600)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.assert_bounded(key)

    def test_unreachable_recovery_node_stays_counted_until_confirmed(self):
        key = self.enrolled_at("lab-alpha")
        self.fleet.mode["lab-delta"] = "down"
        self.reconcile()
        self.drain()
        self.tick(3600 + REFRESH)
        self.reconcile()
        if self.recovery() is not None:
            self.assertEqual(self.unrecovered(), {"lab-delta"})
        # One unknown node leaves room for an ordinary switch.
        self.verify("lab-beta")
        self.assertEqual(self.live_grant_nodes(), ["lab-alpha"])
        # A second hop would make four with the unknown node: deferred, and
        # time alone does not release an unknown node.
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.tick(GRACE + SKEW + 1)
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        self.verify("lab-gamma")
        self.tick(7200)
        self.reconcile()
        if self.recovery() is not None:
            self.assertEqual(self.unrecovered(), {"lab-delta"}, "two hours later delta is still unknown")
        self.verify("lab-alpha")
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        # The node comes back: one confirmed publication releases it.
        self.fleet.mode.clear()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE winn3_registry_refreshes SET next_attempt_at=0")
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        if self.recovery() is not None:
            self.assertTrue(self.recovery_complete())
        self.verify("lab-beta")
        self.assert_bounded(key)

    # ------------------------------------------- operator waiver of a lost node

    def lost_closed_node(self):
        """Recovery that cannot finish: lab-delta is gone for good (unreachable)
        while every other node has been read back and the charge window passed."""
        key = self.enrolled_at("lab-alpha")
        self.fleet.mode["lab-delta"] = "down"
        self.reconcile()
        self.drain()
        self.tick(3600 + REFRESH)
        self.reconcile()
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        return key

    def close_node(self, slug, enabled=0):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET operator_enabled=? WHERE slug=?", (enabled, slug))

    def waive(self, slug, token="waive-token", **overrides):
        form = dict(slug=slug, confirm_slug=slug, reason="machine destroyed, never coming back")
        form.update(overrides)
        with patch.object(self.mod, "admin_secret_matches", side_effect=lambda value: value == "waive-token"):
            return self.mod.admin_winn3_recovery_waive(request=None, x_admin_token=token, **form)

    def refused(self, status, slug="lab-delta", **kwargs):
        with self.assertRaises(self.mod.HTTPException) as caught:
            self.waive(slug, **kwargs)
        self.assertEqual(caught.exception.status_code, status, caught.exception.detail)
        return caught.exception.detail

    def arm(self):
        with self.mod.get_db() as conn:
            return self.mod.node_auto_reopen_arm(conn)

    def waived_record(self):
        with self.mod.winn3_authority_ledger() as ledger:
            return json.loads(self.mod.winn3_ledger_meta(ledger).get("recovery_waived") or "{}")

    def test_a_lost_closed_node_can_be_waived_and_arming_unblocks(self):
        self.lost_closed_node()
        self.assertIsNone(self.arm(), "one unreachable node holds recovery open, so nothing arms")
        self.close_node("lab-delta")
        result = self.waive("lab-delta")
        self.assertTrue(result["waived"] and result["recovery_complete"], result)
        self.assertEqual(self.unrecovered(), set())
        self.assertTrue(self.recovery_complete())
        self.assertIsNotNone(self.arm(), "recovery is complete and budget-trusted: auto-reopen arms")
        record = self.waived_record()
        self.assertEqual(sorted(record), ["lab-delta"])
        self.assertIn("never coming back", record["lab-delta"]["reason"])
        self.assertTrue(record["lab-delta"]["at"])
        again = self.waive("lab-delta")
        self.assertTrue(again["already_waived"])

    def inject_entry(self, slug, not_after, kind="live"):
        """A confirmed publication from before this recovery began, the way a
        restored ledger or a file the hub can no longer reach would show it."""
        with self.mod.winn3_authority_ledger() as ledger:
            since = float(self.mod.winn3_ledger_meta(ledger)["recovery_since"])
            seq = int((since - 100) * 1_000_000) + ledger.execute(
                "SELECT COUNT(*) FROM winn3_publications WHERE started_at < ?", (since,)).fetchone()[0]
            ledger.execute(
                "INSERT INTO winn3_publications (seq, node_slug, started_at, outcome, finished_at, gateway) "
                "VALUES (?, ?, ?, 'confirmed', ?, '127.0.0.1')", (seq, slug, since - 100, since - 99))
            ledger.execute(
                "INSERT INTO winn3_publication_entries (seq, static_public, inner_v4, not_after, kind) "
                "VALUES (?, ?, '10.10.0.9', ?, ?)",
                (seq, self.device()["winn3_static_public"], not_after, kind))
        return seq

    def test_a_waiver_is_refused_for_an_open_node(self):
        self.lost_closed_node()
        self.close_node("lab-delta", enabled=1)
        self.assertIn("open", self.refused(409))
        self.assertEqual(self.waived_record(), {})
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        self.assertIsNone(self.arm())

    def test_a_waiver_is_refused_while_an_entry_is_in_force_and_accepted_once_it_lapses(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.inject_entry("lab-delta", int(self.clock.now) + 86400)
        self.assertIn("still in force", self.refused(409))
        self.assertEqual(self.waived_record(), {})
        self.assertIsNone(self.arm())
        self.tick(86400 + 2 * SKEW)
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        self.assertTrue(self.waive("lab-delta")["waived"])
        self.assertTrue(self.recovery_complete())

    def test_a_lifetime_entry_never_lapses_but_the_canary_binding_is_not_customer_authority(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        seq = self.inject_entry("lab-delta", 0)
        self.tick(10 * 86400)
        self.assertIn("still in force", self.refused(409))
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute("UPDATE winn3_publication_entries SET kind='canary' WHERE seq=?", (seq,))
        self.assertTrue(self.waive("lab-delta")["waived"])

    def test_a_waiver_needs_the_admin_token_the_exact_slug_a_reason_and_a_blocking_node(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        with self.assertRaises(self.mod.HTTPException) as caught:
            self.waive("lab-delta", token="wrong")
        self.assertEqual(caught.exception.status_code, 401)
        self.refused(400, confirm_slug="lab-gamma")
        self.refused(400, reason="lost")
        self.close_node("lab-alpha")
        self.assertIn("not holding", self.refused(409, slug="lab-alpha"))
        self.assertEqual(self.waived_record(), {})

    def test_a_waiver_lasts_only_while_its_evidence_does(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.waive("lab-delta")
        self.assertEqual(self.unrecovered(), set())
        self.close_node("lab-delta", enabled=1)
        self.assertEqual(self.unrecovered(), {"lab-delta"}, "an opened node counts again")
        self.close_node("lab-delta")
        self.assertEqual(self.unrecovered(), set())
        self.mod = self.load(DATABASE_PATH=self.mod._DB)
        self.reconcile()
        self.assertEqual(self.waived_record(), {}, "a new recovery drops every waiver")
        self.assertIn("lab-delta", self.unrecovered())

    def test_a_reconcile_pass_after_a_waiver_does_not_make_it_permanent(self):
        # R25-F1: the pass that found recovery complete wrote recovery_complete=1,
        # and from then on nothing looked at the waiver again.
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.waive("lab-delta")
        self.reconcile()
        self.assertTrue(self.recovery_complete())
        self.assertIsNotNone(self.arm())
        self.close_node("lab-delta", enabled=1)
        self.assertEqual(self.unrecovered(), {"lab-delta"}, "an opened node counts again")
        self.assertIsNone(self.arm(), "auto-reopen disarms while recovery is incomplete")
        self.reconcile()
        self.assertEqual(self.unrecovered(), {"lab-delta"}, "a later pass does not forget it")
        self.close_node("lab-delta")
        self.assertEqual(self.unrecovered(), set())

    def test_an_entry_in_force_ends_a_waiver_even_after_a_reconcile_pass(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.waive("lab-delta")
        self.reconcile()
        self.assertEqual(self.unrecovered(), set())
        self.inject_entry("lab-delta", 0)
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        self.assertIsNone(self.arm())

    def test_a_waiver_ends_when_the_node_is_registered_at_another_gateway(self):
        # R25-F3: a waiver is for the machine that was named when it was granted,
        # even when the ledger holds nothing at all of that machine.
        self.lost_closed_node()
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node="lab-echo"))
        descriptor.seed_node(
            self.mod, slug="lab-echo", protocol_version="winn/3", protocol_params_json="{}",
            descriptor_json=json.dumps({"payload": payload, "sig": signature}))
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='127.0.0.1', operator_enabled=0 WHERE slug='lab-echo'")
        self.assertEqual(self.unrecovered(), {"lab-delta", "lab-echo"})
        self.assertTrue(self.waive("lab-echo")["waived"])
        self.assertEqual(self.waived_record()["lab-echo"]["gateway"], "127.0.0.1")
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='198.51.100.77' WHERE slug='lab-echo'")
        self.assertEqual(self.unrecovered(), {"lab-delta", "lab-echo"},
                         "another machine needs its own recovery")

    def refused_with_a_live_entry_after(self, change):
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.inject_entry("lab-delta", int(self.clock.now) + 86400)
        with self.mod.get_db() as conn:
            conn.execute(change)
        self.assertIn("still in force", self.refused(409))
        self.assertEqual(self.waived_record(), {})

    def test_a_deleted_row_cannot_hide_a_live_entry_at_an_old_gateway(self):
        # R25-F3 (second half, rebutted): the in-force check is keyed by slug across
        # every gateway the ledger names, so a row winn3_node_hosts does not map
        # cannot hide an entry, and authority recovery uses that same map.
        self.refused_with_a_live_entry_after("DELETE FROM nodes WHERE slug='lab-delta'")

    def test_a_row_that_is_not_winn3_any_more_cannot_hide_a_live_entry_either(self):
        self.refused_with_a_live_entry_after(
            "UPDATE nodes SET protocol_version='winn/1' WHERE slug='lab-delta'")

    def test_an_observed_canary_binding_is_not_customer_authority(self):
        # R25-F4: a recovery read-back records every entry it finds as 'observed',
        # the node's own canary binding (not_after 0) included.
        canary = base64.b64encode(os.urandom(32)).decode()
        env = dict(DATABASE_PATH=self.mod._DB, WINN3_CANARY_NODE_SLUG="lab-delta",
                   WINN3_CANARY_STATIC_PUBLIC=canary, WINN3_CANARY_INNER_V4="10.10.0.250")
        self.mod = self.load(**env)
        self.close_node("lab-delta")
        self.enrolled_at("lab-alpha")
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertIn(canary, [p["static_public"] for p in self.fleet.landed("lab-delta")["peers"]])
        self.mod = self.load(**env)   # a new process reads the node back
        self.reconcile()
        with self.mod.winn3_authority_ledger() as ledger:
            observed = ledger.execute(
                "SELECT COUNT(*) FROM winn3_publication_entries e JOIN winn3_publications p ON p.seq=e.seq "
                "WHERE p.node_slug='lab-delta' AND e.kind='observed' AND e.static_public=? AND e.not_after=0",
                (canary,)).fetchone()[0]
        self.assertGreaterEqual(observed, 1, "the read-back recorded the canary as an observed entry")
        self.mod = self.load(**env)   # and the node is lost for good
        self.fleet.mode["lab-delta"] = "down"
        self.reconcile()
        self.drain()
        self.tick(3600 + REFRESH)
        self.reconcile()
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        self.assertTrue(self.waive("lab-delta")["waived"])
        self.assertTrue(self.recovery_complete())

    def test_an_observed_lifetime_entry_that_is_not_the_canary_still_refuses(self):
        self.lost_closed_node()
        self.close_node("lab-delta")
        self.inject_entry("lab-delta", 0, kind="observed")
        self.assertIn("still in force", self.refused(409))
        self.assertEqual(self.waived_record(), {})

    def test_a_waived_node_still_holds_budget_trust_for_the_charge_window(self):
        self.enrolled_at("lab-alpha")
        self.fleet.mode["lab-delta"] = "down"
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertEqual(self.unrecovered(), {"lab-delta"})
        self.close_node("lab-delta")
        self.waive("lab-delta")
        self.assertTrue(self.recovery_complete())
        self.assertFalse(self.recovery()["budget_trusted"], "its journal cannot be read")
        self.assertIsNone(self.arm(), "arming still waits for budget trust")
        self.tick(3600)
        self.reconcile()
        self.assertTrue(self.recovery()["budget_trusted"])
        self.assertIsNotNone(self.arm())

    def test_stale_ledger_copy_restored_enters_recovery(self):
        key = self.connected_at("lab-alpha")
        path = self.mod.WINN3_AUTHORITY_LEDGER_PATH
        stale = self.copy_files(path)
        self.verify("lab-beta")
        self.reconcile()
        self.restore_files(path, stale)
        self.assertNotIn("lab-beta", self.hub_effective(key), "the stale copy has forgotten beta")
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_stale_main_database_copy_restored_enters_recovery(self):
        key = self.connected_at("lab-alpha")
        path = self.mod._DB
        stale = self.copy_files(path)
        self.reconcile()
        self.restore_files(path, stale)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_recovery_does_not_block_current_node_new_devices_or_revocation(self):
        key = self.enrolled_at("lab-alpha")
        # Reconnecting to the node the device is already on.
        self.verify("lab-alpha")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        # Revocation still propagates.
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM devices WHERE device_id=?", (DEVICE_ID,))
        self.assertIn("lab-alpha", self.queued())
        self.drain()
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        # A new device mints a fresh key, which no lost history can hold.
        self.bearer = None
        self.verify("lab-beta", enroll=True, device_id="device-fresh-000000000001",
                    device_fingerprint="fp-fresh-000000000001")
        fresh = self.device()["winn3_static_public"]
        self.assertNotEqual(fresh, key)
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-beta"), fresh, self.clock.now))

    def test_existing_identity_without_a_departure_is_also_barriered(self):
        key = self.enrolled_at("lab-alpha")
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET location_slug=NULL")
        self.clear_queue()
        landings = self.landings()
        self.awg.clear()
        caught = self.deferred("lab-beta")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        self.assertEqual(self.landings(), landings)
        self.assertEqual(self.awg, [])
        self.assert_fleet_bounded(key)

    def test_recovery_includes_nodes_the_ledger_names(self):
        """A node no longer registered winn/3 may still run a gateway holding
        what an earlier publication gave it."""
        self.connected_at("lab-alpha")
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1' WHERE slug='lab-delta'")
            conn.execute("DELETE FROM system_settings WHERE key='winn3_authority_epoch'")
        self.reconcile()
        self.assertIn("lab-delta", self.unrecovered() or set())

    def test_a_stale_sequence_refusal_raises_the_floor(self):
        self.connected_at("lab-alpha")
        seq_path = os.path.join(self.fleet.directory("lab-alpha"), ".winn3-peers.seq")
        with open(seq_path, "w") as handle:
            handle.write(str(10 ** 17))
        with self.mod.get_db() as conn:
            self.assertFalse(self.publish_now(conn, "lab-alpha"))
        with self.mod.get_db() as conn:
            self.assertTrue(self.publish_now(conn, "lab-alpha"),
                            "a node ahead of the hub's clock must not refuse forever")

    # ------------------------------------------- v4: restore trust and budget

    def all_down(self):
        for slug in NODES:
            self.fleet.mode[slug] = "down"

    def test_every_process_start_enters_recovery(self):
        key = self.connected_at("lab-alpha")
        self.mod = self.load(DATABASE_PATH=self.mod._DB)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.reconcile()
        # Read back, but inside the refresh allowance: still deferred.
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assertEqual(self.device()["location_slug"], "lab-beta")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.assert_bounded(key)

    def test_same_epoch_ledger_restore_is_detected_without_a_sweep(self):
        key = self.connected_at("lab-alpha")
        path = self.mod.WINN3_AUTHORITY_LEDGER_PATH
        earlier = self.copy_files(path)
        self.verify("lab-beta")
        self.restore_files(path, earlier)  # same epoch: no sweep in between
        self.assertEqual(sorted(self.hub_effective(key)), ["lab-alpha"],
                         "the restored ledger has forgotten beta")
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_matching_pair_restore_is_detected_while_running_and_after_restart(self):
        key = self.connected_at("lab-alpha")
        ledger_path, main_path = self.mod.WINN3_AUTHORITY_LEDGER_PATH, self.mod._DB
        ledger_copy, main_copy = self.copy_files(ledger_path), self.copy_files(main_path)
        self.verify("lab-beta")
        self.verify("lab-gamma")
        self.reconcile()  # a later epoch now exists
        self.restore_files(ledger_path, ledger_copy)
        self.restore_files(main_path, main_copy)
        # The restored main database puts the device back on alpha.
        self.assertEqual(self.device()["location_slug"], "lab-alpha")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        self.mod = self.load(DATABASE_PATH=main_path)
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_restored_charge_history_is_read_back_from_node_journals(self):
        """Astra: six charges, then an earlier same-epoch ledger restored."""
        key = self.connected_at("lab-alpha")
        path = self.mod.WINN3_AUTHORITY_LEDGER_PATH
        earlier = self.copy_files(path)
        for slug in ["lab-beta", "lab-alpha"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        self.restore_files(path, earlier)
        self.assertEqual(self.charges(), 0, "the restored ledger has lost them")
        # No sweep yet: deferred on trust, before anything is published.
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6, "the node journals restore the charge history")
        caught = self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertTrue(1 <= int(caught.headers["Retry-After"]) <= 3600)
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.assert_fleet_bounded(key)

    def test_unreadable_journal_defers_rather_than_removing_immediately(self):
        key = self.connected_at("lab-alpha")
        self.replace_ledger_with_an_empty_one()
        self.fleet.mode["lab-delta"] = "down"
        self.reconcile()
        self.drain()
        self.tick(REFRESH + 0.01)
        view = self.recovery()
        if view is not None and "budget_trusted" in view:
            self.assertEqual(view["unrecovered"], {"lab-delta"})
            self.assertFalse(view["budget_trusted"])
        # Room for the switch, but no trustworthy budget: a literal deferral.
        # Immediate removal would kill the reply in alpha's tunnel.
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now),
                        "the previous node keeps a bounded allowance")
        self.assert_bounded(key)

    def test_read_back_counts_exactly_what_the_nodes_hold(self):
        key = self.connected_at("lab-alpha")
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.replace_ledger_with_an_empty_one()
        self.reconcile()
        self.tick(REFRESH + 0.01)
        # Known now, not unknown: the residues are counted with their bounds.
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta", "lab-gamma"])
        caught = self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        bound = max(p["not_after"] for s in ("lab-beta", "lab-gamma")
                    for p in self.fleet.landed(s)["peers"] if p["static_public"] == key)
        self.assertLessEqual(int(caught.headers["Retry-After"]), bound + SKEW - self.clock.now + 1)
        self.drain()
        self.tick(REFRESH + 0.01)
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_read_back_fences_an_older_write_still_in_flight(self):
        key = self.connected_at("lab-alpha")
        captured = []

        def capture(slug, command, stdin=None):
            captured.append((command, stdin))

            class Result:
                returncode = 255
                stdout = ""
                stderr = "timeout"
            return Result()

        with patch.object(self.fleet, "run", side_effect=capture):
            with self.mod.get_db() as conn:
                conn.execute("UPDATE devices SET location_slug='lab-beta'")
                self.publish_now(conn, "lab-alpha")
        self.mod = self.load(DATABASE_PATH=self.mod._DB)
        self.reconcile()  # fences alpha with a newer sequence
        late = self.fleet.execute("lab-alpha", *captured[0])
        self.assertEqual(late.returncode, 3, "an older write landed after the read-back")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))

    # ------------------------------------------- v5: latched rollback, key continuity

    def snapshot_ledger(self):
        return self.copy_files(self.mod.WINN3_AUTHORITY_LEDGER_PATH)

    def restore_ledger(self, copy):
        self.restore_files(self.mod.WINN3_AUTHORITY_LEDGER_PATH, copy)

    def test_restore_then_same_node_reconnect_cannot_clear_the_latch(self):
        """Astra's probe: residues at beta and gamma, same-epoch restore,
        then a reconnect to alpha whose publication outruns the high-water."""
        key = self.connected_at("lab-alpha")
        earlier = self.snapshot_ledger()
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.restore_ledger(earlier)
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        # A safe reconnect still works and still publishes.
        landings = self.landings()
        self.verify("lab-alpha")
        self.assertGreater(self.landings(), landings)
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        # It does not re-establish trust in the missing history.
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "the reconnect cleared the detected rollback")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        # Neither does an unrelated publication.
        with self.mod.get_db() as conn:
            self.publish_now(conn, "lab-delta")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        # Only the recovery procedure does, and it counts the residues.
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta", "lab-gamma"])
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.drain()
        self.tick(REFRESH + 0.01)
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_immediate_publication_after_restore_cannot_clear_the_latch(self):
        key = self.connected_at("lab-alpha")
        earlier = self.snapshot_ledger()
        self.verify("lab-beta")
        self.restore_ledger(earlier)
        # The very first thing after the restore is a publication.
        with self.mod.get_db() as conn:
            self.assertTrue(self.publish_now(conn, "lab-delta"))
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)

    def test_publication_after_a_rejected_recovery_admission_cannot_clear_the_latch(self):
        key = self.connected_at("lab-alpha")
        earlier = self.snapshot_ledger()
        for slug in ["lab-beta", "lab-alpha"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        self.restore_ledger(earlier)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.verify("lab-alpha")  # reconnect: allowed, publishes
        self.assertEqual(self.charges(), 0, "the restored ledger has lost the charges")
        # Missing charges are not budget: still deferred, before publication.
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6, "the journals restored them")
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assert_fleet_bounded(key)

    def latched(self):
        """Whether a detected rollback still awaits its completed recovery:
        v5 held one latch timestamp, v6 a process-held regression generation."""
        trust = getattr(self.mod, "_WINN3_PROCESS_TRUST", {})
        if "regressions" in trust:
            return trust["regressions"] > trust["cleared"]
        return bool(trust.get("latched_at"))

    def test_the_latch_clears_only_through_completed_recovery(self):
        key = self.connected_at("lab-alpha")
        earlier = self.snapshot_ledger()
        self.verify("lab-beta")
        self.restore_ledger(earlier)
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.assertTrue(self.latched(), "the rollback was not latched")
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertFalse(self.latched())
        self.verify("lab-gamma")
        self.assert_bounded(key)

    # ------------------------------------------- v6: repeated regression

    def inside_a_latched_recovery(self):
        """Astra (Round O Turn 5), steps 1 to 3: a first restore is detected
        and recovery entered; every node is read back and the refresh
        allowance passes, so the recovery view is complete and budget-trusted,
        but no maintenance pass has yet cleared the latch. Returns the device
        key and a ledger snapshot taken inside that interval."""
        key = self.connected_at("lab-alpha")
        first = self.snapshot_ledger()
        with self.mod.get_db() as conn:
            self.assertTrue(self.publish_now(conn, "lab-delta"))
        self.restore_ledger(first)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.reconcile()  # enters recovery and reads every node back
        self.clear_queue()
        self.tick(REFRESH + 0.01)
        view = self.recovery()
        self.assertTrue(view["complete"], "every node was read back")
        self.assertTrue(view["budget_trusted"], "every journal was read back")
        self.assertTrue(self.latched(), "no maintenance pass has cleared the first latch")
        return key, self.snapshot_ledger()

    def residues_at_beta_and_gamma(self, key):
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.assertEqual(self.fleet.effective(key, self.clock.now),
                         ["lab-alpha", "lab-beta", "lab-gamma"])
        # Intact accounting defers the fourth gateway.
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")

    def assert_fourth_gateway_withheld_then_recovered(self, key):
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "a fourth gateway was admitted after a second restore")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        self.assertTrue(self.latched())
        # A new recovery, entered after the second regression, counts the
        # residues exactly; its completion then admits delta within the bound.
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.hub_effective(key), ["lab-alpha", "lab-beta", "lab-gamma"])
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertFalse(self.latched())
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_second_restore_then_immediate_publication_keeps_the_fourth_gateway_out(self):
        """Astra's probe, first variant: the reconnect to alpha is the very
        first thing after the second restore."""
        key, second = self.inside_a_latched_recovery()
        self.residues_at_beta_and_gamma(key)
        self.restore_ledger(second)
        landings = self.landings()
        self.verify("lab-alpha")  # a safe reconnect still works and publishes
        self.assertGreater(self.landings(), landings)
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.assert_fourth_gateway_withheld_then_recovered(key)

    def test_second_restore_then_publication_after_rejected_admission_keeps_it_out(self):
        """Astra's probe, second variant: a trust check has already detected
        the second restore before the reconnect publishes."""
        key, second = self.inside_a_latched_recovery()
        self.residues_at_beta_and_gamma(key)
        self.restore_ledger(second)
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        landings = self.landings()
        self.verify("lab-alpha")
        self.assertGreater(self.landings(), landings)
        self.assert_fourth_gateway_withheld_then_recovered(key)

    def test_second_restore_keeps_missing_charges_uncertain(self):
        """Six allowances charged inside the latched interval, then the
        earlier snapshot restored and a publication made at once: the missing
        charges must stay uncertain, never become budget."""
        key, second = self.inside_a_latched_recovery()
        for slug in ["lab-beta", "lab-alpha"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        self.restore_ledger(second)
        self.assertEqual(self.charges(), 0, "the restored ledger has lost them")
        self.verify("lab-alpha")  # immediate publication after the second restore
        self.assertEqual(self.charges(), 0)
        self.assertFalse(self.recovery()["budget_trusted"],
                         "missing charge history became budget")
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.assert_fleet_bounded(key)
        # The new recovery reads the journals back: exhausted, not untrusted.
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6, "the journals restored them")
        caught = self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")
        self.assert_fleet_bounded(key)

    # ------------------------------------------- v7: node set grows after recovery

    NEW_NODE = "lab-epsilon"

    def register_node_with_unrecorded_state(self, key, *, live, charges):
        """Sol (Round O Turn 6): after a completed recovery, a v3 node is
        registered whose gateway already holds state this ledger never
        recorded: optionally a live registry entry for `key`, and `charges`
        recent departure charges for the account, signed by the hub's key."""
        slug = self.NEW_NODE
        self.fleet.history.setdefault(slug, [])
        target = self.fleet.directory(slug)
        os.makedirs(target, exist_ok=True)
        if live:
            inner = self.device()["winn3_inner_v4"]
            document = {"version": 1, "peers": [
                {"static_public": key, "inner_v4": inner, "not_after": 0}]}
            with open(os.path.join(target, "winn3-peers.json"), "w") as handle:
                json.dump(document, handle)
            self.fleet.history[slug].append((self.clock.now, document))
        if charges:
            ring = self.mod.winn3_charge_keyring()
            key_id = ring["active"]
            with open(os.path.join(target, ".winn3-charges.log"), "w") as handle:
                for index in range(charges):
                    charge_id = f"{index:032x}"
                    token = self.mod.winn3_charge_token(
                        key_id, ring["keys"][key_id]["key"], harness.ACCOUNT, charge_id)
                    handle.write(f"{charge_id} {int(self.clock.now) - 300 + index} {key_id} {token}\n")
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=slug))
        descriptor.seed_node(
            self.mod, slug=slug, protocol_version="winn/3", protocol_params_json="{}",
            descriptor_json=json.dumps({"payload": payload, "sig": signature}),
        )
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='127.0.0.1' WHERE slug=?", (slug,))
        return slug

    def everywhere(self, key, at):
        return sorted(s for s in self.fleet.history if self.fleet.authorizes(s, key, at))

    def assert_bounded_including_new_node(self, key):
        for instant in self.fleet.instants() + [self.clock.now]:
            self.assertLessEqual(
                len(self.everywhere(key, instant)), 3,
                f"published files authorize {self.everywhere(key, instant)} at {instant}")

    def test_node_added_after_completed_recovery_is_unknown_authority(self):
        """Sol's probe: recovery complete with alpha and beta recorded, then a
        v3 node arrives holding an unrecorded live entry and recent charges.
        A switch from alpha to gamma would make four gateways authorize."""
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        self.deferred("lab-beta")
        self.fleet.mode.clear()
        self.clear_queue()
        self.assertTrue(self.recovery_complete())
        self.assertEqual(self.everywhere(key, self.clock.now), ["lab-alpha", "lab-beta"])
        slug = self.register_node_with_unrecorded_state(key, live=True, charges=6)
        self.assertEqual(self.everywhere(key, self.clock.now), ["lab-alpha", "lab-beta", slug])
        caught = None
        try:
            self.verify("lab-gamma")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_bounded_including_new_node(key)
        self.assertIsNotNone(caught, "a fourth gateway was published")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        self.assertIn(slug, self.unrecovered())
        self.assertFalse(self.recovery()["budget_trusted"], "the new node's charges are unknown")
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        # A fresh fenced read-back of the new node establishes both.
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertNotIn(slug, self.unrecovered())
        self.assertIn(slug, self.hub_effective(key), "the read-back counts what the node holds")
        self.assertEqual(self.charges(), 6, "the read-back imports the node's charges")
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_capacity")
        # Republished from the database, the leftovers go; the budget is spent.
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.assertEqual(self.everywhere(key, self.clock.now), ["lab-alpha"])
        caught = self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")
        self.tick(3600)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-gamma")
        self.assert_bounded_including_new_node(key)

    def test_node_added_after_completed_recovery_is_unknown_charge_history(self):
        """Room for the switch, but the new node's journal is unread: the
        departure allowance is withheld, not charged against an empty ledger."""
        key = self.connected_at("lab-alpha")
        slug = self.register_node_with_unrecorded_state(key, live=False, charges=6)
        self.assertEqual(self.charges(), 0)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6)
        caught = self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")
        self.assertNotIn(slug, self.unrecovered())
        self.assert_bounded_including_new_node(key)

    def test_unreachable_new_node_stays_counted_across_maintenance(self):
        """Maintenance passes that cannot read the new node back must not
        promote it into the covered set."""
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        self.deferred("lab-beta")
        self.fleet.mode.clear()
        self.clear_queue()
        slug = self.register_node_with_unrecorded_state(key, live=True, charges=6)
        self.fleet.mode[slug] = "down"
        for _ in range(2):
            self.reconcile()
            self.tick(REFRESH + 0.01)
        self.clear_queue()
        self.assertIn(slug, self.unrecovered())
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_recovery")
        self.assert_bounded_including_new_node(key)
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertIn(slug, self.hub_effective(key))
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_capacity")

    def test_removed_node_keeps_its_recorded_authority_counted(self):
        """Removal is not release: a node row deleted while its gateway still
        holds a recorded provisional entry keeps counting from the ledger."""
        key = self.connected_at("lab-alpha")
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM nodes WHERE slug='lab-gamma'")
        self.assertIn("lab-gamma", self.hub_effective(key))
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.reconcile()
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.assert_fleet_bounded(key)

    def test_gateway_re_registered_under_a_new_slug_is_counted_under_both(self):
        """Rename: gamma's gateway is re-registered as a new slug. The old slug
        keeps counting from the ledger; the new slug is newly encountered and
        is counted, then read back, before anything is published beyond it."""
        key = self.connected_at("lab-alpha")
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        renamed = self.NEW_NODE
        os.makedirs(os.path.dirname(self.fleet.directory(renamed)), exist_ok=True)
        os.symlink(self.fleet.directory("lab-gamma"), self.fleet.directory(renamed))
        self.fleet.history.setdefault(renamed, [])
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM nodes WHERE slug='lab-gamma'")
        payload, signature = descriptor.envelope_for(descriptor.descriptor_payload(node=renamed))
        descriptor.seed_node(
            self.mod, slug=renamed, protocol_version="winn/3", protocol_params_json="{}",
            descriptor_json=json.dumps({"payload": payload, "sig": signature}),
        )
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='127.0.0.1' WHERE slug=?", (renamed,))
        view = self.recovery()
        self.assertIn(renamed, view["unrecovered"])
        self.assertIn("lab-gamma", self.hub_effective(key))
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertNotIn(renamed, self.unrecovered())
        self.assertTrue({"lab-gamma", renamed} <= set(self.hub_effective(key)),
                        "the same residue is counted under both slugs")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.assert_fleet_bounded(key)

    def test_slug_re_registered_at_another_gateway_is_unknown_authority(self):
        """Same slug, different machine: gamma is re-registered at a new host
        whose gateway holds an unrecorded live entry. The ledger's evidence
        describes the old machine and must not vouch for the new one."""
        key = self.connected_at("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        self.deferred("lab-beta")
        self.fleet.mode.clear()
        self.clear_queue()
        inner = self.device()["winn3_inner_v4"]
        document = {"version": 1, "peers": [
            {"static_public": key, "inner_v4": inner, "not_after": 0}]}
        # The new machine; the old one stays online holding what it held.
        moved = "lab-gamma@192.0.2.77"
        target = self.fleet.directory(moved)
        os.makedirs(target)
        with open(os.path.join(target, "winn3-peers.json"), "w") as handle:
            json.dump(document, handle)
        self.fleet.history[moved] = [(self.clock.now, document)]
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host='192.0.2.77' WHERE slug='lab-gamma'")
        self.assertEqual(self.fleet.effective(key, self.clock.now),
                         ["lab-alpha", "lab-beta", moved])
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "a fourth gateway was published")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_recovery")
        self.assertIn("lab-gamma", self.unrecovered())
        # Evidence recorded before the move does not count; a fresh read does.
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertIn("lab-gamma", self.hub_effective(key))
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.verify("lab-delta")
        self.assert_bounded(key)

    # ------------------------------------------- v8: a slug moved to another gateway

    MOVED_HOST = "192.0.2.77"

    def move_slug(self, slug):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET ssh_host=? WHERE slug=?", (self.MOVED_HOST, slug))
        return f"{slug}@{self.MOVED_HOST}"

    def queue(self, slug):
        with self.mod.get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO winn3_registry_refreshes "
                "(node_slug, attempts, next_attempt_at) VALUES (?, 0, 0)", (slug,))

    def residues_then_move_gamma(self, old_reachable=True):
        """Alpha current, provisional residues at beta and at gamma's machine;
        then gamma's slug is registered at a new, empty machine and read back,
        while the old machine stays online and authorizing (optionally with
        its management path down, so the hub cannot read it)."""
        key = self.connected_at("lab-alpha")
        for slug in ("lab-beta", "lab-gamma"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        new_machine = self.move_slug("lab-gamma")
        if not old_reachable:
            self.fleet.mode["lab-gamma"] = "down"
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.clear_queue()
        self.assertNotIn("lab-gamma", self.unrecovered(), "the new machine was read back")
        self.assertFalse(entry_authorizes(self.fleet.landed(new_machine), key, self.clock.now),
                         "the new machine holds nothing for the identity")
        self.assertTrue(self.fleet.authorizes("lab-gamma", key, self.clock.now),
                        "the old machine is still online and authorizing")
        return key, new_machine

    def test_moved_slug_keeps_the_old_gateway_counted_until_expiry(self):
        """Sol (Round O Turn 7): an empty read-back of the new host must not
        release the old host, which still authorizes."""
        key, _ = self.residues_then_move_gamma(old_reachable=False)
        self.assertEqual(self.fleet.effective(key, self.clock.now),
                         ["lab-alpha", "lab-beta", "lab-gamma"])
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "a fourth physical gateway was published")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_capacity")
        self.assertEqual(len(self.hub_effective(key)), 3,
                         f"hub counts {self.hub_effective(key)}: both of gamma's machines and beta")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        # Publications keep going to the new machine and never release the old.
        self.queue("lab-gamma")
        landings = len(self.fleet.history.get(f"lab-gamma@{self.MOVED_HOST}", []))
        self.drain()
        self.tick(REFRESH + 0.01)
        self.assertGreater(len(self.fleet.history.get(f"lab-gamma@{self.MOVED_HOST}", [])), landings,
                           "the new machine was published to")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        # The old machine's residue expires on its own; only then is delta admitted.
        self.fleet.mode.clear()
        self.tick(PROVISIONAL + SKEW + 1)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertFalse(self.fleet.authorizes("lab-gamma", key, self.clock.now))
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_switch_to_a_moved_slug_counts_its_old_machine_separately(self):
        """The destination slug's new machine and its old one are two
        gateways: alpha, beta's residue, gamma's old machine and gamma's new
        one would be four."""
        # Gamma is not failed here (a failed destination is not selectable):
        # its old machine holds an ordinary departure allowance instead.
        key = self.connected_at("lab-alpha")
        self.verify("lab-gamma")
        self.verify("lab-alpha")
        self.fleet.mode["lab-beta"] = "lost_ack"
        self.deferred("lab-beta")
        self.fleet.mode.clear()
        self.clear_queue()
        new_machine = self.move_slug("lab-gamma")
        self.fleet.mode["lab-gamma"] = "down"
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.clear_queue()
        self.assertNotIn("lab-gamma", self.unrecovered())
        self.assertTrue(self.fleet.authorizes("lab-gamma", key, self.clock.now))
        self.assertEqual(self.fleet.effective(key, self.clock.now),
                         ["lab-alpha", "lab-beta", "lab-gamma"])
        caught = None
        try:
            self.verify("lab-gamma")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "gamma's new machine was published as a fourth gateway")
        self.assertEqual(caught.headers.get("X-Wins-Error-Code"), "winn3_switch_deferred_capacity")
        self.assert_deferred_before_publication("lab-gamma", "winn3_switch_deferred_capacity")

    def test_restore_after_a_move_keeps_an_unreadable_old_machine_unknown(self):
        """A residue reached gamma's old machine after the ledger snapshot;
        then gamma moved and the snapshot was restored. The restored record
        says the old machine holds nothing, so while it cannot be read it is
        unknown authority, not an empty one."""
        key = self.connected_at("lab-alpha")
        earlier = self.snapshot_ledger()
        for slug in ("lab-gamma", "lab-beta"):
            self.fleet.mode[slug] = "lost_ack"
            self.deferred(slug)
            self.fleet.mode.clear()
        self.clear_queue()
        self.move_slug("lab-gamma")
        self.restore_ledger(earlier)
        self.fleet.mode["lab-gamma"] = "down"
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.clear_queue()
        self.assertTrue(self.fleet.authorizes("lab-gamma", key, self.clock.now))
        self.assertIn("lab-gamma@127.0.0.1", self.unrecovered())
        caught = None
        try:
            self.verify("lab-delta")
        except RecordingHTTPException as exc:
            caught = exc
        self.assert_fleet_bounded(key)
        self.assertIsNotNone(caught, "a fourth physical gateway was published")
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_recovery")
        # Read back at its own host, it is counted exactly.
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertNotIn("lab-gamma@127.0.0.1", self.unrecovered())
        self.assertIn("lab-gamma@127.0.0.1", self.hub_effective(key))
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")

    def test_moved_slug_old_gateway_is_released_by_its_own_empty_read_back(self):
        """Verified release: the old machine itself, read back empty."""
        key, _ = self.residues_then_move_gamma()
        self.assert_deferred_before_publication("lab-delta", "winn3_switch_deferred_capacity")
        with open(os.path.join(self.fleet.directory("lab-gamma"), "winn3-peers.json"), "w") as handle:
            json.dump({"version": 1, "peers": []}, handle)
        self.fleet.history["lab-gamma"].append((self.clock.now, {"version": 1, "peers": []}))
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.drain()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.verify("lab-delta")
        self.assert_bounded(key)

    def test_moved_slug_old_gateway_stays_a_charge_history_source(self):
        """Charges journaled at gamma's old machine, gamma moved, then an
        earlier ledger restored: recovery must read the old machine's journal
        too, not accept the new machine's empty one for the slug."""
        key = self.connected_at("lab-gamma")
        earlier = self.snapshot_ledger()
        for slug in ["lab-alpha", "lab-gamma"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        self.move_slug("lab-gamma")
        self.restore_ledger(earlier)
        # The old machine's journal cannot be read: its charges are unknown,
        # and the new machine's empty journal does not stand in for it.
        self.fleet.mode["lab-gamma"] = "down"
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 3, "only alpha's journal has been read")
        self.assertFalse(self.recovery()["budget_trusted"])
        self.assert_deferred_before_publication("lab-alpha", "winn3_switch_deferred_budget")
        self.fleet.mode.clear()
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.assertEqual(self.charges(), 6, "the old machine's journal was not read")
        caught = self.assert_deferred_before_publication("lab-alpha", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")
        self.assert_fleet_bounded(key)

    def test_recovery_evidence_is_pinned_to_the_entry_this_process_made(self):
        """A ledger whose recovery entry is not the one this process wrote
        (same epoch, same sequence) cannot lend that entry's evidence."""
        key = self.connected_at("lab-alpha")
        with self.mod.winn3_authority_ledger() as ledger:
            ledger.execute(
                "UPDATE winn3_ledger_meta SET value=? WHERE key='recovery_since'", (repr(1.0),))
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_recovery")
        self.assertTrue(self.latched())
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assert_bounded(key)

    def lose_history_and_restart(self, **env):
        self.replace_ledger_with_an_empty_one()
        self.mod = self.load(DATABASE_PATH=self.mod._DB, **env)
        self.reconcile()
        self.tick(REFRESH + 0.01)

    def six_charges(self):
        key = self.connected_at("lab-alpha")
        for slug in ["lab-beta", "lab-alpha"] * 3:
            self.verify(slug)
            self.tick(10)
        self.assertEqual(self.charges(), 6)
        return key

    def test_key_change_with_missing_history_still_defers_the_seventh_allowance(self):
        """Astra: six charges, missing ledger history, a key change, a restart
        and successful journal reads."""
        key = self.six_charges()
        keyring = getattr(self.mod, "WINN3_CHARGE_KEYRING_PATH", None)
        if keyring and os.path.exists(keyring):
            os.remove(keyring)  # the journal key is lost
        self.lose_history_and_restart(RATE_LIMIT_SECRET="a-different-rate-limit-secret")
        view = self.recovery()
        if view is not None:
            self.assertEqual(view["unrecovered"], set(), "every journal was read")
        caught = self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertTrue(entry_authorizes(self.fleet.landed("lab-alpha"), key, self.clock.now))
        self.tick(3600)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assert_bounded(key)

    def test_rotation_keeps_retired_keys_attributable(self):
        self.six_charges()
        self.mod.rotate_winn3_charge_key()
        self.lose_history_and_restart()
        self.assertEqual(self.charges(), 6, "charges signed by the retired key were lost")
        caught = self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.assertGreater(int(caught.headers["Retry-After"]), 60, "exhausted, not merely untrusted")

    def test_rate_limit_secret_rotation_does_not_orphan_charges(self):
        self.six_charges()
        self.lose_history_and_restart(RATE_LIMIT_SECRET="a-different-rate-limit-secret")
        self.assertEqual(self.charges(), 6)
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")

    def test_legacy_journal_lines_are_unattributable(self):
        key = self.connected_at("lab-alpha")
        journal = os.path.join(self.fleet.directory("lab-beta"), ".winn3-charges.log")
        with open(journal, "a") as handle:
            handle.write(f"{'e' * 32} {int(self.clock.now)} {'f' * 32}\n")
        self.lose_history_and_restart()
        self.assert_deferred_before_publication("lab-beta", "winn3_switch_deferred_budget")
        self.tick(3600)
        self.reconcile()
        self.tick(REFRESH + 0.01)
        self.verify("lab-beta")
        self.assert_bounded(key)

    def test_unreadable_keyring_is_set_aside_not_overwritten(self):
        self.connected_at("lab-alpha")
        path = self.mod.WINN3_CHARGE_KEYRING_PATH
        with open(path, "w") as handle:
            handle.write("not json")
        ring = self.mod.winn3_charge_keyring()
        self.assertIn(ring["active"], ring["keys"])
        aside = [name for name in os.listdir(os.path.dirname(path))
                 if name.startswith(os.path.basename(path) + ".unreadable.")]
        self.assertEqual(len(aside), 1)
        with open(os.path.join(os.path.dirname(path), aside[0])) as handle:
            self.assertEqual(handle.read(), "not json")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")

    # ------------------------------------------- restart, cleanup, refresh

    def test_hub_restart_mid_window_keeps_the_grant_ledger_and_bound(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        bound = [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key][0]["not_after"]
        restarted = self.load(DATABASE_PATH=self.mod._DB)
        after = self.document("lab-alpha", mod=restarted)
        self.assertEqual([(p["static_public"], p["not_after"]) for p in after["peers"]], [(key, bound)])
        self.assertEqual(self.hub_effective(key, mod=restarted), ["lab-alpha", "lab-beta"])
        self.assertEqual(self.charges(mod=restarted), 1)
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-alpha"), key, bound))

    def test_lapsed_grant_cleanup_failure_is_bounded_and_retried(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        bound = [p for p in self.fleet.landed("lab-alpha")["peers"] if p["static_public"] == key][0]["not_after"]
        self.clear_queue()
        self.fleet.mode["lab-alpha"] = "down"
        self.tick(bound - self.clock.now + 1)
        self.assertEqual(self.mod.expire_winn3_departure_grants(), {"queued": 1, "pruned": 0})
        self.reconcile()
        self.assertIn("lab-alpha", self.queued())
        self.assertEqual(self.drain(), {"published": 0, "retry": 1})
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT attempts, next_attempt_at FROM winn3_registry_refreshes "
                               "WHERE node_slug='lab-alpha'").fetchone()
        self.assertEqual(row[0], 1)
        self.assertGreater(row[1], self.clock.now + 30)
        # The reconcile pass keeps the existing backoff instead of resetting it.
        self.reconcile()
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT attempts FROM winn3_registry_refreshes "
                                          "WHERE node_slug='lab-alpha'").fetchone()[0], 1)
        # SSH still down: the gateway already stopped; the hub counts alpha
        # until its published bound plus the skew allowance.
        self.assertFalse(self.fleet.authorizes("lab-alpha", key, self.clock.now))
        self.assertIn("lab-alpha", self.hub_effective(key))
        self.tick(SKEW)
        self.assertNotIn("lab-alpha", self.hub_effective(key))
        self.fleet.mode.clear()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE winn3_registry_refreshes SET next_attempt_at=0")
        self.assertEqual(self.drain(), {"published": 1, "retry": 0})
        self.assertEqual(self.fleet.landed("lab-alpha"), {"version": 1, "peers": []})
        self.tick(3601)
        self.assertEqual(self.mod.expire_winn3_departure_grants(), {"queued": 0, "pruned": 1})
        self.assertEqual(self.grants(), [])

    def test_gateway_refresh_delay_is_counted_after_a_confirmed_withdrawal(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.tick(10)
        with self.mod.get_db() as conn:
            self.mod.retire_winn3_departure_grants(conn, DEVICE_ID, ["lab-alpha"])
        self.drain()
        withdrawn_at = self.clock.now
        self.assertFalse(entry_authorizes(self.fleet.landed("lab-alpha"), key, withdrawn_at))
        self.tick(0.5)
        self.assertTrue(self.fleet.authorizes("lab-alpha", key, self.clock.now),
                        "model: cached snapshot still answers")
        self.assertIn("lab-alpha", self.hub_effective(key))
        self.tick(1.0)
        self.assertIn("lab-alpha", self.hub_effective(key), "released before the refresh bound")
        self.tick(REFRESH)
        self.assertNotIn("lab-alpha", self.hub_effective(key))
        self.assertEqual(self.hub_effective(key), ["lab-beta"])

    def test_ledger_history_is_pruned_but_the_latest_state_is_kept(self):
        key = self.connected_at("lab-alpha")
        self.verify("lab-beta")
        self.tick(3600)
        self.drain()
        self.reconcile()
        self.drain()
        self.tick(RETENTION + 10)
        result = self.reconcile()
        self.assertGreater(result["pruned"], 0)
        self.assertEqual(self.hub_effective(key), ["lab-beta"])
        with self.mod.winn3_authority_ledger() as ledger:
            per_node = dict(ledger.execute(
                "SELECT node_slug, COUNT(*) FROM winn3_publications GROUP BY node_slug").fetchall())
        self.assertTrue({"lab-alpha", "lab-beta"} <= set(per_node))
        self.assertEqual(set(per_node.values()), {1}, per_node)

    def test_publication_names_no_account_or_device(self):
        self.connected_at("lab-alpha")
        self.verify("lab-beta")
        for _slug, command in self.fleet.commands:
            self.assertNotIn(harness.ACCOUNT, command)
            self.assertNotIn(DEVICE_ID, command)
        self.assertEqual(set(self.fleet.landed("lab-alpha")["peers"][0]),
                         {"static_public", "inner_v4", "not_after"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
