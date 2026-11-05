#!/usr/bin/env python3
"""Slice P2 (design 10.3, 10.4, 5.7) on the integrated tree: go-live latency
and hub cost, ported onto H2, H3 and H5 as the seam rulings say.

  P-11  completion-triggered provisioning. One in-process scheduler starts
        H2's winn3_auto_provision: every committed deployment release (both
        completion routes) and every committed registration or heartbeat (H2's
        post-commit job) triggers it, at most one pass per slug runs, and a
        trigger that lands during a pass costs exactly one more pass.
  P-12  the on-demand proof request (A-3). The request, its consumer, its path
        unit and the result ingest are H3's (P2-SEAM-H3). P2's app-side gate
        stays in front of H3's writer: a known, unretired fleet slug, at most
        once per slug per 60 s, a request inside the limit deferred to the end
        of the limit, never dropped, and retirement cancelling both. The
        post-flip request follows the operator flip's commit and H2's flip.
  P-13  reopen on the last proof: one slug's reopen is evaluated when its last
        required proof is in (installer_rerun and fresh_install), with every
        condition, switch and budget of the fleet pass.
  P-16  one long-lived AWG carrying client per transport, inside H5's carrying
        probe, its unit and its sandbox (P2-SEAM-H5), with P-16's status rules
        in front of H5's apply_carry_verdict and H5's result binding.

The hub is the REAL control-plane source extracted from the ONETOUCH heredoc
(the harness the other hub suites use); the carrying probe is the real
wins_node_dataplane_probe.py heredoc, run in-process against the hub's
temporary database with a fake client process. No test contacts a node, a
hub or the network.

Each guard has an anti-vacuity arm, and MutantTests applies one source change
per guard and requires the named test to fail an assertion.

Run: python3 server/test_performance_p2_golive.py
P2_CONTROL_PLANE_INSTALLER selects another installer (a red run).
"""
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import base64
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
INSTALLER = Path(os.environ.get("P2_CONTROL_PLANE_INSTALLER",
                                HERE / "wins_control_plane_setup_ONETOUCH.sh")).resolve()

import test_account_deletion_hub as harness  # noqa: E402
import test_data_plane_dark_start_latch as dark  # noqa: E402

harness.HUB = str(INSTALLER)
TEXT = INSTALLER.read_text(encoding="utf-8")
SOURCE = harness._extract_main_block()
REV = "sha256:" + "a" * 64
MEASUREMENTS = {}
_IDENT = {}
CARRY = ("udp", "stealth", "stealth_tls")
CARRY_COLUMNS = [f"data_plane_{n}_carry_{k}" for n in CARRY for k in ("status", "ok_at")]
SECRET_ENV = {"ADMIN_TOKEN", "RATE_LIMIT_SECRET", "SPA_HMAC", "SMTP_PASS"}
PROBE_HEAD = re.compile(r"cat > \S*wins_node_dataplane_probe\.py\S* <<'DPPROBEEOF'\n")
CANARY_KEY = base64.b64encode(os.urandom(32)).decode()


def block_of(source, start_marker, end_marker):
    start = source.index(start_marker)
    return source[start:source.index(end_marker, start)]


def p2_block(source=None):
    return block_of(source or SOURCE, "# --- Design 10.3 and 10.4 (slice P2)", "def node_is_retired(row: Any) -> bool:")


def probe_source(text=None):
    text = text if text is not None else TEXT
    start = PROBE_HEAD.search(text).end()
    return text[start:text.index("\nDPPROBEEOF\n", start) + 1]


def load_probe(source=None, **overrides):
    """The real carrying probe (H5's heredoc) as a namespace, optionally from a
    mutated probe source."""
    namespace = {"__name__": "wins_node_dataplane_probe_p2_test"}
    exec(compile(source if source is not None else probe_source(), "wins_node_dataplane_probe.py", "exec"),
         namespace)
    namespace["log"] = lambda _msg: None
    namespace.update(overrides)
    return namespace


def quiet(mod):
    for handler in list(mod.logger.handlers):
        handler.close()
        mod.logger.removeHandler(handler)
    mod.logger.addHandler(logging.NullHandler())
    mod.logger.propagate = False


class RerunHarness:
    """Helpers the data-plane dark-start suite already proves, reused as they
    are (not subclassed, so its own tests are not run a second time)."""


for _name in ("db", "node", "seed_placeholder", "offnode_gate", "promote"):
    setattr(RerunHarness, _name, dark.DataPlaneDarkStartTests.__dict__[_name])


class Hub(RerunHarness, unittest.TestCase):
    source = None

    def setUp(self):
        text = self.source if self.source is not None else SOURCE
        with patch.object(harness, "_extract_main_block", lambda: text):
            self.mod = harness.load_hub(HIDE_CONTROL_ORIGIN="0")
        quiet(self.mod)
        self.request = harness.FakeRequest(headers={"x-admin-token": dark.ADMIN_TOKEN}, path="/admin/nodes/tier")
        self.alerts = []
        self.mod.security_alert = lambda *a, **k: self.alerts.append((a[0], a[1], k.get("details")))
        # H3's request spool (a Path in the integrated hub).
        self.spool = Path(tempfile.mkdtemp(prefix="p2-spool-"))
        self.mod.WINN3_CANARY_REQUEST_DIR = self.spool
        self.provisioned = []
        self.mod.winn3_auto_provision = self.provisioned.append
        self.mod._winn3_provision_start_thread = lambda target, slug: target(slug)
        # H6's hub-run off-node check runs over SSH; it is never run here.
        self.mod.hub_offnode_check_run = lambda host: (None, ["hub-run off-node check is not run by this suite"])
        # Deferred canary requests are recorded, not timed, so tests are exact.
        self.real_defer_start = getattr(self.mod, "_winn3_canary_defer_start", None)
        self.deferred = []
        self.mod._winn3_canary_defer_start = (
            lambda delay, slug, reason: self.deferred.append((delay, slug, reason))
            or types.SimpleNamespace(cancel=lambda: self.deferred.append(("cancelled", slug, reason))))
        self.addCleanup(shutil.rmtree, self.spool, True)
        self.addCleanup(shutil.rmtree, self.mod._TMPDIR, True)

    # ---- node fixtures (the shapes InstallerRerunTests uses) ------------------
    def reg_payload(self, slug, revision=REV, **overrides):
        index = _IDENT.setdefault(slug, len(_IDENT) + 10)
        payload = dark.registration_payload(slug)
        payload.data_plane_code_revision = revision
        payload.endpoint = f"198.51.100.{index}:9110"
        payload.ssh_host = f"198.51.100.{index}"
        payload.public_key = (slug + "A" * 43)[:43] + "="
        for key, value in overrides.items():
            setattr(payload, key, value)
        return payload

    def register_rev(self, slug, revision=REV, **overrides):
        return self.mod.register_node(self.reg_payload(slug, revision, **overrides),
                                      harness.FakeRequest(path="/api/v1/nodes/register"))

    def live_node(self, slug, revision=REV):
        self.seed_placeholder(slug)
        self.register_rev(slug, revision)
        now = self.mod.utcnow().isoformat()
        with self.db() as conn:
            conn.execute(
                "UPDATE nodes SET management_status='ok', data_plane_status='ok', data_plane_ok_at=?,"
                " data_plane_udp_status='ok', data_plane_udp_ok_at=? WHERE slug=?", (now, now, slug))
        self.promote(slug)

    def withdraw(self, slug):
        return self.mod.withdraw_node_for_deployment(
            slug, harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/withdraw"),
            x_node_token=dark.NODE_TOKEN)

    def complete(self, slug, withdrawal_id):
        return self.mod.complete_node_deployment(
            slug, self.mod.DeploymentWithdrawalCompletion(withdrawal_id=withdrawal_id),
            harness.FakeRequest(path=f"/api/v1/nodes/{slug}/deployment/complete"),
            x_node_token=dark.NODE_TOKEN)

    def rerun(self, slug, revision=REV, **overrides):
        withdrawn = self.withdraw(slug)
        time.sleep(0.002)
        self.register_rev(slug, revision, **overrides)
        return self.complete(slug, withdrawn["withdrawal_id"])

    def add_carry_columns(self):
        with self.db() as conn:
            self.mod.ensure_schema(conn)
            for column in CARRY_COLUMNS:
                self.mod.add_column_if_missing(conn, "nodes", column, "TEXT")

    def set_row(self, slug, **columns):
        with self.db() as conn:
            conn.execute(f"UPDATE nodes SET {', '.join(f'{k} = ?' for k in columns)} WHERE slug = ?",
                         (*columns.values(), slug))

    def iso(self, seconds=0.0):
        return (self.mod.utcnow() + timedelta(seconds=seconds)).isoformat()

    def spool_names(self):
        return sorted(os.listdir(self.spool))


# =========================================================== P-11 ===========

class P11CompletionTriggerTests(Hub):
    def test_released_at_column_is_set_on_release_and_cleared_by_the_withdrawal(self):
        # P2-SEAM-H2: the column and both UPDATE edits are H2's; this pins the
        # behaviour P-11 relies on.
        slug = "p11-column"
        self.live_node(slug)
        self.assertIsNone(self.node(slug)["deployment_released_at"])
        withdrawn = self.withdraw(slug)
        self.assertIsNone(self.node(slug)["deployment_released_at"])
        time.sleep(0.002)
        self.register_rev(slug)
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertTrue(out["ok"])
        released = self.node(slug)["deployment_released_at"]
        self.assertTrue(released)
        self.withdraw(slug)
        self.assertIsNone(self.node(slug)["deployment_released_at"], "the next withdrawal clears it")

    def test_a_release_starts_provisioning_once_and_after_the_commit(self):
        slug = "p11-commit"
        self.live_node(slug)
        seen = []

        def job(name):
            conn = sqlite3.connect(self.mod._DB)
            try:
                seen.append((name, conn.execute(
                    "SELECT deployment_released_at, deployment_withdrawal_id FROM nodes WHERE slug=?",
                    (name,)).fetchone()))
            finally:
                conn.close()

        withdrawn = self.withdraw(slug)
        time.sleep(0.002)
        self.register_rev(slug)
        self.mod.winn3_auto_provision = job
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertTrue(out["auto_reopen_pending"], out)
        self.assertEqual(len(seen), 1, seen)
        name, row = seen[0]
        self.assertEqual(name, slug)
        self.assertTrue(row[0], "the job reads the released row, so the trigger follows the commit")
        self.assertIsNone(row[1])

    def test_release_is_recorded_and_triggers_even_for_a_node_that_is_not_eligible(self):
        slug = "p11-plain"
        self.seed_placeholder(slug)
        self.register_rev(slug)
        withdrawn = self.withdraw(slug)
        self.register_rev(slug)
        self.provisioned.clear()
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertFalse(out["auto_reopen_pending"])
        self.assertTrue(self.node(slug)["deployment_released_at"])
        self.assertEqual(self.provisioned, [slug])

    def test_a_completion_that_does_not_match_releases_and_triggers_nothing(self):
        slug = "p11-mismatch"
        self.live_node(slug)
        self.withdraw(slug)
        self.provisioned.clear()
        with self.assertRaises(harness.HTTPException) as caught:
            self.complete(slug, "0" * 32)
        self.assertEqual(caught.exception.status_code, 409)
        self.assertEqual(self.provisioned, [])
        self.assertIsNone(self.node(slug)["deployment_released_at"])
        self.assertEqual(self.spool_names(), [])

    def test_a_failing_job_never_fails_or_delays_the_completion(self):
        slug = "p11-raises"
        self.live_node(slug)
        threads = []

        def start(target, name):
            thread = threading.Thread(target=target, args=(name,), daemon=True)
            threads.append(thread)
            thread.start()

        self.mod._winn3_provision_start_thread = start

        def job(name):
            raise RuntimeError("secret-looking detail that must not be logged")

        self.mod.winn3_auto_provision = job
        try:
            out = self.rerun(slug)
        except Exception as exc:
            self.fail("a failing job failed the completion: " + type(exc).__name__)
        self.assertTrue(out["ok"])
        self.assertTrue(self.node(slug)["deployment_released_at"])
        self.assertTrue(threads, "anti-vacuity: the release started a pass")
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(self.mod._WINN3_PROVISION_STATE, {}, "a failed pass leaves no stuck state")
        self.provisioned.clear()
        self.mod.winn3_auto_provision = self.provisioned.append
        self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, "deployment-released"), "started")
        threads[-1].join(10)
        self.assertEqual(self.provisioned, [slug], "the next trigger still runs")

    def test_triggers_coalesce_while_a_pass_runs(self):
        slug = "p11-coalesce"
        self.mod._winn3_provision_start_thread = lambda target, name: threading.Thread(
            target=target, args=(name,), daemon=True).start()
        entered, release, passes = threading.Event(), threading.Event(), []

        def job(name):
            passes.append(name)
            if len(passes) == 1:
                entered.set()
                self.assertTrue(release.wait(10))

        self.mod.winn3_auto_provision = job
        self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, "deployment-released"), "started")
        self.assertTrue(entered.wait(10))
        for reason in ("registration", "deployment-released", "registration", "registration", "registration"):
            self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, reason), "coalesced")
        release.set()
        deadline = time.time() + 10
        while self.mod._WINN3_PROVISION_STATE and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(passes, [slug, slug], "six triggers during one pass cost exactly one more pass")
        self.assertEqual(self.mod._WINN3_PROVISION_STATE, {})

    def test_the_trigger_refuses_a_bad_slug_or_reason(self):
        for bad in ("", "../x", "a", "x" * 41, "a b", "a\n", None, 7, b"abc", "-ab"):
            with self.subTest(slug=bad):
                self.assertEqual(self.mod.trigger_winn3_auto_provision(bad, "registration"), "ignored")
        for reason in ("", "sweep", None, "Registration", "identity-ready"):
            with self.subTest(reason=reason):
                self.assertEqual(self.mod.trigger_winn3_auto_provision("good-slug", reason), "ignored")
        self.assertEqual(self.provisioned, [])
        self.assertEqual(self.mod.trigger_winn3_auto_provision("good-slug", "registration"), "started",
                         "anti-vacuity")

    # ---- the integrated rule (P-11 beside H2's post-commit job) ------------
    def test_every_committed_registration_and_heartbeat_starts_a_pass_through_the_one_scheduler(self):
        slug = "p11-register"
        self.seed_placeholder(slug)
        self.register_rev(slug)
        self.assertEqual(self.provisioned, [slug], "the registration (H2's post-commit job)")
        self.mod.heartbeat(self.mod.NodeHeartbeat(slug=slug, secret_token=dark.NODE_TOKEN, status="online"),
                           harness.FakeRequest(path="/api/v1/nodes/heartbeat"))
        self.assertEqual(self.provisioned, [slug, slug], "the heartbeat route")
        with self.assertRaises(harness.HTTPException):
            self.register_rev(slug, secret_token="wrong-token")
        self.assertEqual(self.provisioned, [slug, slug], "a registration that fails starts nothing")

    def test_the_identity_ready_registration_needs_no_trigger_of_its_own(self):
        # S4's node reports winn3_identity_ready on every registration; H2's job
        # runs after every registration, so that report starts it, once.
        slug = "p11-ready"
        self.seed_placeholder(slug)
        self.register_rev(slug, winn3_identity_ready=True)
        self.assertEqual(self.provisioned, [slug], "one pass per registration, never two")
        self.register_rev(slug, winn3_identity_ready=False)
        self.assertEqual(self.provisioned, [slug, slug], "the same rule with or without the report")

    def test_both_completion_routes_trigger_and_the_release_is_the_earliest_trigger(self):
        # complete-fresh is the other completion route (design 3.17); it must
        # trigger after its commit like complete.
        tree = ast.parse(SOURCE if self.source is None else self.source)
        for name in ("complete_node_deployment", "complete_fresh_node_deployment"):
            with self.subTest(route=name):
                function = next(node for node in tree.body
                                if isinstance(node, ast.FunctionDef) and node.name == name)
                calls = [index for index, statement in enumerate(function.body)
                         if "trigger_winn3_golive_after_release(node_slug)" in ast.unparse(statement)
                         and not isinstance(statement, ast.With)]
                withs = [index for index, statement in enumerate(function.body) if isinstance(statement, ast.With)]
                self.assertEqual(len(calls), 1, f"{name}: one trigger, at the function's top level")
                self.assertGreater(calls[0], max(withs), f"{name}: after the release transaction commits")

    def test_a_trigger_during_a_pass_reaches_the_release(self):
        # The earliest correct trigger is never lost: a registration pass that
        # runs while the completion commits is followed by one that sees it.
        slug = "p11-race"
        self.live_node(slug)
        withdrawn = self.withdraw(slug)
        self.mod._winn3_provision_start_thread = lambda target, name: threading.Thread(
            target=target, args=(name,), daemon=True).start()
        entered, release, seen = threading.Event(), threading.Event(), []

        def job(name):
            conn = sqlite3.connect(self.mod._DB)
            try:
                seen.append(conn.execute("SELECT deployment_released_at FROM nodes WHERE slug=?",
                                         (name,)).fetchone()[0])
            finally:
                conn.close()
            if len(seen) == 1:
                entered.set()
                self.assertTrue(release.wait(10))

        self.mod.winn3_auto_provision = job
        self.register_rev(slug)
        self.assertTrue(entered.wait(10), "anti-vacuity: the registration pass is running")
        out = self.complete(slug, withdrawn["withdrawal_id"])
        self.assertTrue(out["ok"])
        release.set()
        deadline = time.time() + 10
        while self.mod._WINN3_PROVISION_STATE and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(seen), 2, seen)
        self.assertIsNone(seen[0], "the running pass read the row before the release")
        self.assertTrue(seen[1], "the release got a pass that sees it")

    def test_no_slug_ever_has_two_passes_at_once(self):
        slug = "p11-single"
        self.mod._winn3_provision_start_thread = lambda target, name: threading.Thread(
            target=target, args=(name,), daemon=True).start()
        active, peak, passes, lock = [0], [0], [], threading.Lock()

        def job(name):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            passes.append(name)
            time.sleep(0.05)
            with lock:
                active[0] -= 1

        self.mod.winn3_auto_provision = job
        triggers = [threading.Thread(target=self.mod.trigger_winn3_auto_provision,
                                     args=(slug, reason)) for reason in ("registration", "deployment-released") * 10]
        for thread in triggers:
            thread.start()
        for thread in triggers:
            thread.join(10)
        deadline = time.time() + 10
        while self.mod._WINN3_PROVISION_STATE and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(peak[0], 1, "never two passes of one slug at once")
        self.assertGreaterEqual(len(passes), 1)
        self.assertLessEqual(len(passes), 20)

    def test_the_switches_rule_of_h2_applies_to_every_trigger(self):
        slug = "p11-switches"
        with patch.dict(os.environ, {"WINN3_AUTO_SIGN": "0", "WINN3_AUTO_CARRIER": "0"}):
            self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, "deployment-released"), "disabled")
            self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, "registration"), "disabled")
        self.assertEqual(self.provisioned, [])
        for sign, carrier in (("1", "0"), ("0", "1")):
            with patch.dict(os.environ, {"WINN3_AUTO_SIGN": sign, "WINN3_AUTO_CARRIER": carrier}):
                self.assertEqual(self.mod.trigger_winn3_auto_provision(slug, "registration"), "started")
        self.assertEqual(self.provisioned, [slug, slug], "anti-vacuity: one switch on is enough")

    def test_the_sweep_and_the_audit_loop_stay_as_backstops(self):
        loop = block_of(SOURCE, "async def fleet_availability_sweep_loop():", "async def awg_canary_sync_loop():")
        self.assertIn("await asyncio.to_thread(auto_reopen_health_closed_nodes)", loop)
        self.assertIn("await asyncio.sleep(FLEET_AVAILABILITY_AUDIT_SECONDS)", loop)
        self.assertEqual(self.mod.FLEET_AVAILABILITY_AUDIT_SECONDS, 120)
        sweep = block_of(SOURCE, "async def winn3_auto_provision_sweep_loop()", "def winn3_schedule_auto_provision")
        self.assertIn("await asyncio.sleep(300)", sweep)


# =========================================================== P-12 ===========

class P12RequestSpoolTests(Hub):
    def request_path(self, slug):
        return self.spool / (slug + ".json")

    def test_a_known_slug_gets_h3s_request_file(self):
        slug = "p12-known"
        self.seed_placeholder(slug)
        self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
        self.assertEqual(self.spool_names(), [slug + ".json"])
        path = self.request_path(slug)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text()), {"slug": slug}, "H3's fixed body (P2-SEAM-H3)")

    def test_completion_writes_the_request_after_the_commit(self):
        slug = "p12-completion"
        self.live_node(slug)
        seen = []
        real = self.mod.winn3_request_canary

        def spy(name):
            conn = sqlite3.connect(self.mod._DB)
            try:
                seen.append(conn.execute("SELECT deployment_released_at FROM nodes WHERE slug=?",
                                         (name,)).fetchone()[0])
            finally:
                conn.close()
            return real(name)

        self.mod.winn3_request_canary = spy
        self.rerun(slug)
        self.assertEqual(self.spool_names(), [slug + ".json"])
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0], "written after the release committed")

    def test_unknown_retired_and_malformed_requests_write_nothing(self):
        self.seed_placeholder("p12-retired")
        self.set_row("p12-retired", retired_at=self.iso())
        self.seed_placeholder("p12-real")
        # Rows whose names are not in the fleet pattern: only the pattern keeps
        # them out of the spool, because the database knows them.
        odd = ["bad_slug", "a", "x" * 41, "has space", "dot.name", "-lead", "p12-real.json"]
        for name in odd:
            self.seed_placeholder(name)
        cases = ["p12-unknown", "p12-retired", "../p12-real", "p12-real/../x", "P12-REAL-X", "",
                 None, 5, ".p12", *odd, *[name.upper() for name in odd]]
        for slug in cases:
            with self.subTest(slug=slug):
                self.assertFalse(self.mod.request_winn3_canary_proof(slug, "completion"))
        for reason in ("", "sweep", None, "COMPLETION"):
            with self.subTest(reason=reason):
                self.assertFalse(self.mod.request_winn3_canary_proof("p12-real", reason))
        self.assertEqual(self.spool_names(), [])
        self.assertTrue(self.mod.request_winn3_canary_proof("p12-real", "carrier-flip"),
                        "anti-vacuity: the same slug is accepted for the other reason")

    def test_a_second_request_inside_sixty_seconds_is_not_written_inside_the_limit(self):
        slug = "p12-limit"
        self.seed_placeholder(slug)
        clock = [1000.0]
        with patch.object(time, "monotonic", lambda: clock[0]):
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
            os.unlink(self.request_path(slug))
            clock[0] += 59.0
            self.assertFalse(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
            self.assertEqual(self.spool_names(), [])
            clock[0] += 1.01
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
        self.assertEqual(self.spool_names(), [slug + ".json"])

    def test_a_pending_request_stays_one_file_with_the_fixed_body(self):
        # H3's writer replaces the file under a dot name; its body is fixed, so
        # a second write of a pending request changes nothing it carries.
        slug = "p12-pending"
        self.seed_placeholder(slug)
        clock = [1000.0]
        with patch.object(time, "monotonic", lambda: clock[0]):
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
            first = self.request_path(slug).read_bytes()
            clock[0] += 120.0
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
        self.assertEqual(self.spool_names(), [slug + ".json"])
        self.assertEqual(self.request_path(slug).read_bytes(), first)

    def test_a_request_inside_the_limit_is_deferred_not_dropped(self):
        slug = "p12-defer"
        self.seed_placeholder(slug)
        clock = [1000.0]
        with patch.object(time, "monotonic", lambda: clock[0]):
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
            os.unlink(self.request_path(slug))
            clock[0] += 40.0
            self.assertFalse(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
            asked = clock[0]
            clock[0] += 5.0
            self.assertFalse(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
            self.assertEqual(self.spool_names(), [], "nothing is written inside the limit")
            self.assertEqual(len(self.deferred), 1, "requests inside the limit coalesce into one deferral")
            delay, name, reason = self.deferred[0]
            self.assertEqual((name, reason), (slug, "carrier-flip"))
            self.assertGreaterEqual(delay, 20.0, "not before the limit ends")
            self.assertLess(delay, 21.0, "and not long after it")
            clock[0] = asked + delay
            self.mod._winn3_canary_deferred_fire(slug, reason)
        self.assertEqual(self.spool_names(), [slug + ".json"], "the after-flip request is written when the limit ends")
        self.assertEqual(self.mod._WINN3_CANARY_REQUEST_DEFERRED, {})

    def test_a_deferred_request_is_written_by_a_real_timer(self):
        # Claude P2-T3 note 1: a 3 s limit, so two hub calls cannot cross it
        # under load; the 10 s wait still covers it.
        slug = "p12-timer"
        self.seed_placeholder(slug)
        self.mod._winn3_canary_defer_start = self.real_defer_start
        self.mod.WINN3_CANARY_REQUEST_MIN_INTERVAL_SECONDS = 3.0
        self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
        os.unlink(self.request_path(slug))
        self.assertFalse(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
        self.assertEqual(self.spool_names(), [])
        deadline = time.time() + 10
        # H3's writer renames a dot temporary into place; wait for the name.
        while self.spool_names() != [slug + ".json"] and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.spool_names(), [slug + ".json"])

    def test_retirement_cancels_a_deferred_request(self):
        slug = "p12-defer-retire"
        self.seed_placeholder(slug)
        clock = [1000.0]
        with patch.object(time, "monotonic", lambda: clock[0]):
            self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
            clock[0] += 10.0
            self.assertFalse(self.mod.request_winn3_canary_proof(slug, "carrier-flip"))
        self.assertIn(slug, self.mod._WINN3_CANARY_REQUEST_DEFERRED)
        self.mod.remove_winn3_canary_request(slug)
        self.assertNotIn(slug, self.mod._WINN3_CANARY_REQUEST_DEFERRED)
        self.assertIn(("cancelled", slug, "carrier-flip"), self.deferred)

    def test_a_missing_spool_is_not_created_and_does_not_use_up_the_limit(self):
        slug = "p12-nodir"
        self.seed_placeholder(slug)
        shutil.rmtree(self.spool)
        self.assertFalse(self.mod.request_winn3_canary_proof(slug, "completion"))
        self.assertFalse(self.spool.exists(), "the app opens the installer's directory, it never creates one")
        os.mkdir(self.spool, 0o700)
        self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))

    def test_a_symlinked_spool_is_refused(self):
        slug = "p12-linkdir"
        self.seed_placeholder(slug)
        target = tempfile.mkdtemp(prefix="p2-elsewhere-")
        self.addCleanup(shutil.rmtree, target, True)
        shutil.rmtree(self.spool)
        os.symlink(target, self.spool)
        self.addCleanup(lambda: self.spool.unlink() if self.spool.is_symlink() else None)
        self.assertFalse(self.mod.request_winn3_canary_proof(slug, "completion"))
        self.assertEqual(os.listdir(target), [])

    def test_a_planted_symlink_is_never_written_through(self):
        slug = "p12-linkfile"
        self.seed_placeholder(slug)
        victim = Path(tempfile.mkdtemp(prefix="p2-victim-")) / "important"
        victim.write_text("original")
        self.addCleanup(shutil.rmtree, victim.parent, True)
        os.symlink(victim, self.request_path(slug))
        self.assertTrue(self.mod.request_winn3_canary_proof(slug, "completion"))
        self.assertEqual(victim.read_text(), "original")
        self.assertFalse(self.request_path(slug).is_symlink(), "the link itself was replaced")

    def test_retirement_removes_the_pending_request_and_the_limit_entry(self):
        keep, gone = "p12-keep", "p12-gone"
        for slug in (keep, gone):
            self.live_node(slug)
        self.assertTrue(self.mod.request_winn3_canary_proof(gone, "completion"))
        self.assertTrue(self.mod.request_winn3_canary_proof(keep, "completion"))
        self.assertEqual(self.spool_names(), [gone + ".json", keep + ".json"])
        # The retire route needs the node closed and a hub-verified gate.
        self.set_row(gone, operator_enabled=0)
        gate = self.offnode_gate(gone)
        out = self.mod.admin_retire_node(
            self.request, slug=gone, reason="p12", confirm_last_servable_node=gone,
            offnode_gate_sha256=gate, x_admin_token=dark.ADMIN_TOKEN)
        self.assertTrue(out["ok"])
        self.assertEqual(self.spool_names(), [keep + ".json"], "only the retired slug's request is removed")
        self.assertNotIn(gone, self.mod._WINN3_CANARY_REQUEST_LAST)
        self.assertFalse(self.mod.request_winn3_canary_proof(gone, "completion"), "a retired slug is refused")
        self.assertEqual(self.spool_names(), [keep + ".json"])

    def test_remove_refuses_a_name_that_could_leave_the_directory(self):
        outside = self.spool.parent / "p2-outside-target.json"
        outside.write_text("keep")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        self.mod.remove_winn3_canary_request("../p2-outside-target")
        self.mod.remove_winn3_canary_request(None)
        self.assertTrue(outside.exists(), "a name outside the directory was removed")
        self.assertEqual(outside.read_text(), "keep")

    # ---- design 10.3: the proof after the operator's carrier flip ----------
    def flip(self, slug, **overrides):
        kwargs = dict(request=harness.FakeRequest(path="/admin/nodes/winn3"), slug=slug, enabled=True,
                      protocol_params_json=json.dumps({"carrier": "winn3"}), path_mtu="1450",
                      carrier_classes="udp", x_admin_token=dark.ADMIN_TOKEN)
        kwargs.update(overrides)
        return self.mod.admin_set_node_winn3(**kwargs)

    def test_the_operator_carrier_flip_requests_the_post_flip_proof_after_its_commit(self):
        slug = "p12-flip"
        self.live_node(slug)
        seen = []
        real = self.mod.request_winn3_canary_proof

        def spy(name, reason):
            conn = sqlite3.connect(self.mod._DB)
            try:
                seen.append((name, reason, conn.execute(
                    "SELECT protocol_version FROM nodes WHERE slug=?", (name,)).fetchone()[0]))
            finally:
                conn.close()
            return real(name, reason)

        self.mod.request_winn3_canary_proof = spy
        out = self.flip(slug)
        self.assertEqual(out["protocol_version"], "winn/3")
        self.assertEqual(seen, [(slug, "carrier-flip", "winn/3")], "requested once, after the carrier commit")
        self.assertEqual(self.spool_names(), [slug + ".json"])
        seen.clear()
        self.flip(slug, enabled=False)
        self.assertEqual(seen, [], "anti-vacuity: the rollback to winn/1 requests nothing")

    def test_a_failing_request_never_fails_the_carrier_flip(self):
        slug = "p12-flip-raises"
        self.live_node(slug)

        def boom(name, reason):
            raise RuntimeError("secret-looking detail")

        self.mod.request_winn3_canary_proof = boom
        try:
            out = self.flip(slug)
        except Exception as exc:
            self.fail("a failing request failed the flip: " + type(exc).__name__)
        self.assertTrue(out["ok"])
        self.assertEqual(self.node(slug)["protocol_version"], "winn/3")

    def test_a_flip_inside_the_limit_of_the_completion_request_is_deferred(self):
        slug = "p12-flip-defer"
        self.live_node(slug)
        clock = [5000.0]
        with patch.object(time, "monotonic", lambda: clock[0]):
            self.rerun(slug)
            self.assertEqual(self.spool_names(), [slug + ".json"], "the completion request")
            os.unlink(self.request_path(slug))
            clock[0] += 30.0
            self.flip(slug)
        self.assertEqual(self.spool_names(), [])
        self.assertEqual([(name, reason) for _delay, name, reason in self.deferred], [(slug, "carrier-flip")],
                         "the after-flip request waits for the limit instead of the 15 minute timer")

    def test_every_app_write_of_a_request_goes_through_the_gate(self):
        # P2-SEAM-H3: P2's app-side gate stays in front of H3's writer, so H3's
        # writer has exactly one caller, and H2's automatic flip and both
        # completion paths reach it only through the gate.
        tree = ast.parse(SOURCE if self.source is None else self.source)
        callers = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                        callers.setdefault(call.func.id, set()).add(node.name)
        self.assertEqual(callers.get("winn3_request_canary"), {"request_winn3_canary_proof"})
        self.assertTrue({"winn3_auto_provision", "admin_set_node_winn3", "trigger_winn3_golive_after_release",
                         "_winn3_canary_deferred_fire"} <= callers.get("request_winn3_canary_proof", set()),
                        callers.get("request_winn3_canary_proof"))
        job = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "winn3_auto_provision")
        self.assertIn('request_winn3_canary_proof(slug, "carrier-flip")', ast.unparse(job).replace("'", '"'))

    def test_the_app_names_no_command_and_never_touches_the_service_manager(self):
        block = p2_block(self.source)
        for word in ("systemctl", "os.system", "subprocess", "Popen"):
            self.assertNotIn(word, block)
        writer = block_of(SOURCE if self.source is None else self.source,
                          "def winn3_request_canary(slug: str) -> bool:", "def winn3_pre_sign_canary")
        for word in ("systemctl", "subprocess", "Popen"):
            self.assertNotIn(word, writer)


# =========================================================== P-13 ===========

class P13LastProofTests(Hub):
    def closed_rerun(self, slug):
        self.live_node(slug)
        self.add_carry_columns()
        out = self.rerun(slug)
        self.assertTrue(out["auto_reopen_pending"], out)
        self.provisioned.clear()
        return self.node(slug)["deployment_completed_at"]

    def prove(self, slug, completed, *, udp="ok", seconds=5.0):
        stamp = (self.mod.utcnow() + timedelta(seconds=seconds)).isoformat() if seconds is not None else None
        self.set_row(slug, data_plane_udp_carry_status=udp, data_plane_udp_carry_ok_at=stamp)

    def spy(self):
        calls = []
        real = self.mod.auto_reopen_health_closed_nodes

        def wrapper(only_slug=None):
            calls.append(only_slug)
            return real(only_slug=only_slug)

        self.mod.auto_reopen_health_closed_nodes = wrapper
        return calls

    def open_conditions(self):
        return patch.object(self.mod, "node_auto_reopen_failures", return_value=[])

    def probe(self):
        return load_probe(DB_PATH=self.mod._DB)

    def test_a_missing_or_stale_or_failed_proof_is_not_the_last_proof(self):
        slug = "p13-notlast"
        completed = self.closed_rerun(slug)
        calls = self.spy()
        self.assertFalse(self.mod.reopen_last_proof_arrived(self.node(slug)), "no proof yet")
        self.mod.note_winn3_proof_ingested(slug)
        self.prove(slug, completed, seconds=-60.0)
        self.mod.note_winn3_proof_ingested(slug)
        self.assertFalse(self.mod.reopen_last_proof_arrived(self.node(slug)), "a proof older than the completion")
        self.prove(slug, completed, udp="failed")
        self.mod.note_winn3_proof_ingested(slug)
        self.assertFalse(self.mod.reopen_last_proof_arrived(self.node(slug)), "a failed proof")
        self.assertEqual(calls, [], "no evaluation until the last proof is in")
        self.assertEqual(self.node(slug)["operator_enabled"], 0)

    def test_every_proof_must_be_newer_than_the_completion_even_the_last_one(self):
        slug = "p13-stale"
        completed = self.closed_rerun(slug)
        self.set_row(slug, data_plane_udp_carry_status="ok", data_plane_udp_carry_ok_at=completed)
        self.assertFalse(self.mod.reopen_last_proof_arrived(self.node(slug)), "equal to the completion is not newer")
        self.assertIsNone(self.mod.evaluate_reopen_on_last_proof(slug))
        self.prove(slug, completed, seconds=1.0)
        self.assertTrue(self.mod.reopen_last_proof_arrived(self.node(slug)))

    def test_the_last_proof_evaluates_that_slug_at_once_and_reopens_it(self):
        slug = "p13-reopen"
        completed = self.closed_rerun(slug)
        gate = self.offnode_gate(slug)
        calls = self.spy()
        self.prove(slug, completed)
        with self.open_conditions():
            self.mod.note_winn3_proof_ingested(slug)
        self.assertEqual(calls, [slug])
        row = self.node(slug)
        self.assertEqual(row["operator_enabled"], 1)
        self.assertEqual(row["latch_cause"], "auto_reopen_installer_rerun")
        with self.db() as conn:
            self.assertEqual(conn.execute("SELECT used_for FROM node_offnode_gates WHERE gate_sha256=?",
                                          (gate,)).fetchone()[0], "auto_reopened")

    def test_the_evaluation_keeps_every_condition_of_the_fleet_pass(self):
        slug = "p13-held"
        completed = self.closed_rerun(slug)
        self.offnode_gate(slug)
        self.prove(slug, completed)
        out = self.mod.evaluate_reopen_on_last_proof(slug)
        self.assertIsNotNone(out)
        self.assertEqual(out["reopened"], [])
        self.assertIn(slug, out["held"], "the armed and green-streak conditions still hold it")
        self.assertEqual(self.node(slug)["operator_enabled"], 0)
        # The same gate-record rule: no usable off-node record, no reopen.
        slug = "p13-nogate"
        completed = self.closed_rerun(slug)
        self.prove(slug, completed)
        with self.open_conditions():
            out = self.mod.evaluate_reopen_on_last_proof(slug)
        self.assertEqual(out["reopened"], [])
        self.assertTrue(any(f.startswith("offnode gate") for f in out["held"][slug]), out["held"])

    def test_only_the_named_slug_is_evaluated(self):
        first, second = "p13-first", "p13-second"
        completed = {slug: self.closed_rerun(slug) for slug in (first, second)}
        for slug in (first, second):
            self.offnode_gate(slug)
            self.prove(slug, completed[slug])
        with self.open_conditions():
            out = self.mod.evaluate_reopen_on_last_proof(first)
            self.assertEqual(out["reopened"], [first])
            self.assertEqual(self.node(second)["operator_enabled"], 0, "the other node waits for its own proof or the loop")
            self.assertEqual(self.mod.auto_reopen_health_closed_nodes()["reopened"], [second], "the loop is the backstop")

    def test_only_a_closed_rerun_or_fresh_install_node_is_evaluated(self):
        slug = "p13-class"
        completed = self.closed_rerun(slug)
        self.prove(slug, completed)
        for column, value in (("health_closed_reason", "heartbeat_stale"), ("health_closed_reason", None),
                              ("retired_at", self.iso())):
            with self.subTest(column=column, value=value):
                row = dict(self.node(slug))
                row[column] = value
                self.assertFalse(self.mod.reopen_last_proof_arrived(row))
        self.assertTrue(self.mod.reopen_last_proof_arrived(self.node(slug)))
        live = dict(self.node(slug))
        live["operator_enabled"] = 1
        self.assertFalse(self.mod.reopen_last_proof_arrived(live))

    def test_a_fresh_install_goes_live_only_on_winn3_with_the_canary_as_a_proof(self):
        # Integration (P2 T3 FIXES, seams table): P-13 widened to H7's
        # fresh_install class, whose go-live needs winn/3 and the v3 canary.
        # Times are relative to now: H5 reads a carrying proof only while it
        # is younger than AWG_CARRY_PROOF_MAX_AGE_SECONDS.
        base = {"deployment_completed_at": self.iso(-120), "health_closed_reason": "fresh_install",
                "operator_enabled": 0, "direct_awg_enabled": 1, "endpoint": "198.51.100.7:9110",
                "public_key": "A" * 43 + "=", "ssh_host": "198.51.100.7", "stealth_endpoint": "",
                "protocol_version": "winn/3", "data_plane_udp_carry_status": "ok",
                "data_plane_udp_carry_ok_at": self.iso(-60),
                "winn3_canary_status": "ok", "winn3_canary_ok_at": self.iso(-90)}
        arrived = self.mod.reopen_last_proof_arrived
        self.assertTrue(arrived(base), "anti-vacuity: every proof is in")
        self.assertFalse(arrived({**base, "protocol_version": "winn/1"}), "no v3 profile is served yet")
        self.assertFalse(arrived({**base, "winn3_canary_ok_at": self.iso(-121)}), "a canary older than completion")
        self.assertFalse(arrived({**base, "data_plane_udp_carry_status": "failed"}))

    def test_the_canary_can_be_the_last_proof_for_a_v3_node(self):
        # Times relative to now: H5's carrying-proof freshness (900 s).
        base = {"deployment_completed_at": self.iso(-300), "health_closed_reason": "installer_rerun",
                "operator_enabled": 0, "direct_awg_enabled": 1, "endpoint": "198.51.100.7:9110",
                "public_key": "A" * 43 + "=", "ssh_host": "198.51.100.7", "stealth_endpoint": "",
                "protocol_version": "winn/3", "data_plane_udp_carry_status": "ok",
                "data_plane_udp_carry_ok_at": self.iso(-60)}
        arrived = self.mod.reopen_last_proof_arrived
        self.assertFalse(arrived(base), "the v3 canary is still missing")
        self.assertFalse(arrived({**base, "winn3_canary_status": "ok", "winn3_canary_ok_at": self.iso(-301)}))
        self.assertTrue(arrived({**base, "winn3_canary_status": "ok", "winn3_canary_ok_at": self.iso(-270)}))

    def test_the_watch_evaluates_a_changed_proof_set_once(self):
        slug = "p13-watch"
        completed = self.closed_rerun(slug)
        calls = self.spy()
        self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [], "nothing complete yet")
        self.prove(slug, completed)
        self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [slug], "the last proof changed the columns")
        self.assertEqual(calls, [slug])
        self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [], "unchanged columns are not re-evaluated")
        self.assertEqual(calls, [slug])
        self.prove(slug, completed, seconds=9.0)
        self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [slug], "a newer proof is evaluated again")
        self.assertEqual(len(calls), 2)

    def test_the_watch_covers_a_fresh_install_window_under_its_own_switch(self):
        slug = "p13-fresh"
        completed = self.closed_rerun(slug)
        self.set_row(slug, health_closed_reason="fresh_install", protocol_version="winn/3",
                     winn3_canary_status="ok", winn3_canary_ok_at=self.iso(4.0))
        calls = self.spy()
        self.prove(slug, completed)
        with patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", False):
            self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [])
        self.assertEqual(calls, [], "the class's switch is off")
        with patch.object(self.mod, "WINN3_FRESH_INSTALL_AUTO_GOLIVE", True), \
                patch.object(self.mod, "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", False):
            self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [slug])
        self.assertEqual(calls, [slug], "the fresh_install go-live is evaluated when its last proof is in")

    def test_the_watch_forgets_a_node_that_left_the_window(self):
        slug = "p13-forget"
        completed = self.closed_rerun(slug)
        self.prove(slug, completed)
        self.mod.evaluate_reopen_on_new_proofs()
        self.assertIn(slug, self.mod._WINN3_PROOF_SEEN)
        self.set_row(slug, health_closed_reason=None, health_closed_at=None)
        self.mod.evaluate_reopen_on_new_proofs()
        self.assertNotIn(slug, self.mod._WINN3_PROOF_SEEN)

    def test_the_watch_does_nothing_while_the_rerun_switch_is_off(self):
        slug = "p13-off"
        completed = self.closed_rerun(slug)
        self.prove(slug, completed)
        calls = self.spy()
        with patch.object(self.mod, "NODE_INSTALLER_RERUN_AUTO_REOPEN_ENABLED", False):
            self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [])
        self.assertEqual(calls, [])

    def test_the_audit_loop_is_unchanged_and_the_only_slug_pass_is_the_same_function(self):
        slug = "p13-same"
        completed = self.closed_rerun(slug)
        self.prove(slug, completed)
        self.offnode_gate(slug)
        with self.open_conditions():
            fleet = self.mod.auto_reopen_health_closed_nodes()
        self.assertEqual(fleet["reopened"], [slug])
        self.assertEqual(sorted(fleet), ["enabled", "fresh_install_enabled", "fresh_install_expired", "gate_notices",
                                         "held", "installer_rerun_enabled", "installer_rerun_expired", "reopened"])

    # ---- the carrying proof, written by H5's probe in its own unit -----------
    def write_carry(self, slug, verdict, *, observed=1.0, snapshot_row=None):
        """What H5's probe does with one verdict: written at the run's start
        time, bound to the row it read (CARRY_SNAPSHOT_COLUMNS)."""
        probe = self.probe()
        observed_iso = observed if isinstance(observed, str) else self.iso(observed)
        with closing(probe["connect_db"]()) as conn:
            probe["ensure_columns"](conn)
            row = snapshot_row if snapshot_row is not None else conn.execute(
                "SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
            return probe["apply_carry_verdict"](conn, slug, "udp", verdict, observed_iso,
                                                probe["carry_snapshot"](row))

    def test_a_carrying_proof_from_the_probe_is_noticed_and_reopens(self):
        slug = "p13-sink"
        self.closed_rerun(slug)
        self.offnode_gate(slug)
        self.mod.evaluate_reopen_on_new_proofs()
        calls = self.spy()
        self.assertTrue(self.write_carry(slug, "reachable"))
        with self.open_conditions():
            self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [slug])
        self.assertEqual(calls, [slug])
        self.assertEqual(self.node(slug)["operator_enabled"], 1)

    def test_a_failed_carrying_result_never_triggers_an_evaluation(self):
        slug = "p13-fail"
        self.closed_rerun(slug)
        self.mod.evaluate_reopen_on_new_proofs()
        calls = self.spy()
        self.assertTrue(self.write_carry(slug, "unreachable"))
        self.assertEqual(self.node(slug)["data_plane_udp_carry_status"], "failed")
        self.assertIsNone(self.node(slug)["data_plane_udp_carry_ok_at"])
        self.assertEqual(self.mod.evaluate_reopen_on_new_proofs(), [])
        self.assertEqual(calls, [], "a failure is not a proof, so it evaluates nothing")
        self.assertTrue(self.write_carry(slug, "reachable", observed=2.0))
        self.mod.evaluate_reopen_on_new_proofs()
        self.assertEqual(calls, [slug], "anti-vacuity: a good result does")

    def test_a_result_bound_to_a_state_that_moved_is_not_written(self):
        # P2-SEAM-H5: H5's binding (CARRY_SNAPSHOT_COLUMNS, observed_iso as the
        # start time) carries every case P2's sink refused.
        slug = "p13-bound"
        self.closed_rerun(slug)
        unwritten = self.node(slug)["data_plane_udp_carry_status"]
        self.assertNotEqual(unwritten, "ok")
        for column, value in (("retired_at", self.iso()), ("deployment_withdrawal_id", "w" * 32),
                              ("deployment_completed_at", "2000-01-01T00:00:00")):
            with self.subTest(column=column):
                seen = self.node(slug)
                before = seen[column]
                self.set_row(slug, **{column: value})
                try:
                    self.assertFalse(self.write_carry(slug, "reachable", snapshot_row=seen))
                    self.assertEqual(self.node(slug)["data_plane_udp_carry_status"], unwritten)
                    self.assertIsNone(self.node(slug)["data_plane_udp_carry_checked_at"])
                finally:
                    self.set_row(slug, **{column: before})
        started = self.iso(2.0)
        self.assertTrue(self.write_carry(slug, "reachable", observed=started), "anti-vacuity: a bound result")
        self.assertEqual(self.node(slug)["data_plane_udp_carry_ok_at"], started, "the time recorded is the run's start")
        self.assertTrue(self.mod.reopen_last_proof_arrived(self.node(slug)))


# =========================================================== P-16 ===========

FAKE_CLIENT = r'''#!@PYTHON@
import json, os, struct, subprocess, sys, time
CONTROL, RECORD, DIRECTORY = @CONTROL@, @RECORD@, @DIRECTORY@


def dns_answer(query):
    # A response to exactly this question carrying one address record.
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([192, 0, 2, 7])
    return header + query[12:] + record


for line in sys.stdin:
    try:
        modes = json.load(open(CONTROL))
    except Exception:
        modes = {"mode": "echo"}
    request = json.loads(line)
    mode = modes.get("slug:" + request["slug"], modes.get("mode", "echo"))
    with open(RECORD, "a") as handle:
        handle.write(json.dumps({"pid": os.getpid(), "argv": sys.argv[1:], "env": sorted(os.environ),
                                 "slug": request["slug"], "transport": request["transport"],
                                 "fields": sorted(request), "mode": mode}) + "\n")
    query = bytes.fromhex(request.get("dns_query_hex", ""))
    reply = {"id": request["id"], "slug": request["slug"], "transport": request["transport"],
             "dns_reply_hex": dns_answer(query).hex() if query else ""}
    if mode == "crash-once":
        marker = os.path.join(DIRECTORY, "crashed-once")
        if not os.path.exists(marker):
            open(marker, "w").close()
            os._exit(3)
    if mode in ("spawn", "orphan"):
        grandchild = subprocess.Popen(["/bin/sleep", "30"], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(os.path.join(DIRECTORY, "grandchild"), "w") as handle:
            handle.write(str(grandchild.pid))
    if mode == "orphan":
        print(json.dumps(reply), flush=True)
        os._exit(0)
    if mode == "crash":
        os._exit(3)
    if mode == "hang":
        time.sleep(60)
    if mode == "slow":
        time.sleep(1.5)
    if mode == "block":
        go = os.path.join(DIRECTORY, "go-" + request["slug"])
        deadline = time.time() + 30
        while not os.path.exists(go) and time.time() < deadline:
            time.sleep(0.02)
    if mode == "garbage":
        print("not json", flush=True)
        continue
    if mode == "wrongslug":
        reply["slug"] = "other-slug"
    if mode == "wrongtransport":
        reply["transport"] = "stealth_tls" if request["transport"] != "stealth_tls" else "udp"
    if mode == "wrongid":
        reply["id"] = request["id"] + 1
    if mode == "boolid":
        reply["id"] = True
    if mode == "noreply":
        del reply["dns_reply_hex"]
        reply["carried"] = True
    if mode == "nothex":
        reply["dns_reply_hex"] = "zz"
    if mode == "empty":
        reply["dns_reply_hex"] = ""
    print(json.dumps(reply), flush=True)
'''


class P16ClientTests(unittest.TestCase):
    """The long-lived client per transport inside H5's probe (P2-SEAM-H5)."""
    probe_text = None

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="p2-client-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.control = self.dir / "control.json"
        self.record = self.dir / "record.jsonl"
        self.control.write_text(json.dumps({"mode": "echo"}))
        self.script = self.dir / "fake-client"
        self.script.write_text(FAKE_CLIENT.replace("@PYTHON@", sys.executable)
                               .replace("@CONTROL@", repr(str(self.control)))
                               .replace("@RECORD@", repr(str(self.record)))
                               .replace("@DIRECTORY@", repr(str(self.dir))))
        self.script.chmod(0o755)
        self.p = load_probe(self.probe_text, CARRY_CLIENT_BIN=str(self.script), CARRY_CLIENT_TIMEOUT=5,
                            CARRY_DNS_NAME="hub.example.test",
                            # The fake lives in a temp dir; the D6 gate has its own tests.
                            carry_client_untrusted=lambda _path: "")

    def client(self, transport="udp"):
        proc = self.p["CarryClientProcess"](transport)
        self.addCleanup(proc.close)
        return proc

    def mode(self, value, **per_slug):
        modes = {"mode": value}
        modes.update({"slug:" + slug: mode for slug, mode in per_slug.items()})
        self.control.write_text(json.dumps(modes))

    def records(self):
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines() if line.strip()]

    def ask(self, proc, slug="node-one"):
        query, _ = self.p["build_dns_query"]("hub.example.test")
        return proc.exchange({"dns_query_hex": query.hex(), "private_key": CANARY_KEY}, slug)

    def wait_gone(self, pid, seconds=5.0):
        deadline = time.time() + seconds
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
            time.sleep(0.05)
        return False

    def grandchild(self):
        pid = int((self.dir / "grandchild").read_text())

        def reap():
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass

        self.addCleanup(reap)
        return pid

    # ---- one long-lived process per transport --------------------------------
    def test_one_process_serves_every_probe(self):
        proc = self.client()
        for index in range(6):
            status, detail, reply = self.ask(proc, f"node-{index}")
            self.assertEqual(status, "reply", detail)
            self.assertTrue(reply)
        pids = {record["pid"] for record in self.records()}
        self.assertEqual(len(pids), 1, "six probes, one process")
        self.assertEqual(proc.spawn_count, 1)
        self.assertEqual(proc.pid(), next(iter(pids)))
        MEASUREMENTS["probes_per_spawn"] = 6

    def test_the_client_gets_no_hub_secret_and_a_fixed_command_line(self):
        with patch.dict(os.environ, {"ADMIN_TOKEN": "t", "RATE_LIMIT_SECRET": "s", "SPA_HMAC": "h"}):
            status, detail, _ = self.ask(self.client("stealth"))
        self.assertEqual(status, "reply", detail)
        seen = self.records()[0]
        env = set(seen["env"]) - {"__CF_USER_TEXT_ENCODING", "LC_CTYPE"}
        self.assertLessEqual(env, {"PATH", "HOME", "LANG", "LC_ALL", "TZ"}, "H5's narrowed environment")
        self.assertFalse(env & SECRET_ENV)
        self.assertEqual(seen["argv"], ["--transport", "stealth"])
        self.assertNotIn(CANARY_KEY, json.dumps(seen["argv"]) + json.dumps(seen["env"]),
                         "the private key travels only in the request line")
        self.assertIn("private_key", seen["fields"])

    def test_a_crash_is_no_verdict_then_a_restart_after_the_backoff(self):
        proc = self.client()
        self.assertEqual(self.ask(proc)[0], "reply")
        first = proc.pid()
        self.mode("crash")
        status, detail, _ = self.ask(proc)
        self.assertEqual(status, "error")
        self.assertIn("AWG carry client exited", detail)
        self.assertEqual(proc.failures, 1)
        self.mode("echo")
        status, detail, _ = self.ask(proc)
        self.assertEqual((status, detail), ("unavailable", "AWG carry client is in restart backoff"))
        self.assertEqual(proc.spawn_count, 1, "no respawn inside the backoff")
        proc.not_before = 0.0
        status, detail, _ = self.ask(proc)
        self.assertEqual(status, "reply", detail)
        self.assertEqual(proc.spawn_count, 2)
        self.assertNotEqual(proc.pid(), first)
        self.assertEqual(proc.failures, 0, "a good reply resets the backoff")

    def test_kill_stops_the_clients_whole_process_group(self):
        proc = self.client()
        self.mode("spawn")
        self.assertEqual(self.ask(proc)[0], "reply")
        grandchild = self.grandchild()
        os.kill(grandchild, 0)
        proc.kill()
        self.assertTrue(self.wait_gone(grandchild), "a process the client started outlived the kill")

    def test_an_exited_client_is_signalled_by_group_before_it_is_reaped(self):
        if not hasattr(os, "waitid"):
            self.skipTest("this platform has no waitid")
        proc = self.client()
        self.mode("orphan")
        self.assertEqual(self.ask(proc)[0], "reply")
        grandchild = self.grandchild()
        deadline = time.time() + 5
        while proc.pid() is not None and time.time() < deadline:
            time.sleep(0.05)
        self.assertIsNone(proc.pid(), "the client exited")
        self.assertIsNone(proc.proc.returncode,
                          "an exited client is not reaped until its group is signalled, so its id cannot be reused")
        self.mode("echo")
        proc.not_before = 0.0
        self.assertEqual(self.ask(proc)[0], "reply")
        self.assertTrue(self.wait_gone(grandchild), "the exited client's own child was stopped with its group")

    def test_a_client_already_reaped_is_never_signalled_by_its_old_id(self):
        proc = self.client()
        done = subprocess.Popen(["/usr/bin/true"], start_new_session=True)
        done.wait()
        proc.proc = done
        signalled = []
        with patch.object(os, "killpg", lambda pid, sig: signalled.append(pid)):
            proc.kill()
        self.assertEqual(signalled, [])
        live = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
        self.addCleanup(lambda: live.poll() is None and (live.kill() or live.wait()))
        proc.proc = live
        proc.kill()
        self.assertIsNotNone(live.returncode, "anti-vacuity: an unreaped client is signalled and reaped")

    def test_the_backoff_grows_and_is_capped(self):
        proc = self.client()
        delays = []
        for _ in range(7):
            proc._failed(100.0)
            delays.append(proc.not_before - 100.0)
        self.assertEqual(delays, [1, 2, 5, 15, 60, 60, 60])

    def test_a_hung_client_times_out_is_killed_and_replaced(self):
        proc = self.client()
        self.assertEqual(self.ask(proc)[0], "reply")
        pid = proc.pid()
        self.mode("hang")
        self.p["CARRY_CLIENT_TIMEOUT"] = -9.5   # a 0.5 s reply wait
        started = time.time()
        status, detail, _ = self.ask(proc)
        self.assertEqual(status, "error")
        self.assertIn("timed out", detail)
        self.assertLess(time.time() - started, 10)
        self.assertTrue(self.wait_gone(pid))
        self.assertIsNone(proc.pid())
        self.mode("echo")
        proc.not_before = 0.0
        self.assertEqual(self.ask(proc)[0], "reply")

    def test_a_reply_that_is_not_for_this_request_is_no_verdict_and_a_kill(self):
        # Each on a fresh client's FIRST request, whose id is 1, so a boolean
        # True would equal it if the type were not checked.
        for mode in ("garbage", "wrongslug", "wrongtransport", "wrongid", "boolid", "noreply", "nothex"):
            with self.subTest(mode=mode):
                proc = self.client()
                self.mode(mode)
                status, detail, _ = self.ask(proc)
                self.assertEqual((status, detail.split(" (exit")[0]),
                                 ("error", "AWG carry client printed no readable result"))
                self.assertIsNone(proc.pid(), "the stream is out of step, so the client is killed")
                self.assertIsNone(proc.proc)
                self.assertEqual(proc.failures, 1)
        self.mode("echo")
        proc = self.client()
        self.assertEqual(self.ask(proc)[0], "reply", "anti-vacuity: the same path accepts a good reply")

    def test_an_empty_dns_reply_is_a_verdict_and_keeps_its_process(self):
        proc = self.client()
        self.mode("empty")
        query, _ = self.p["build_dns_query"]("hub.example.test")
        verdict, detail = self.p["run_carry_client"]({"dns_query_hex": query.hex()}, query, CANARY_KEY, proc, "node-one")
        self.assertEqual(verdict, "unreachable", detail)
        pid = proc.pid()
        self.assertEqual(proc.failures, 0, "an answer that nothing came back is not a process failure")
        self.mode("echo")
        verdict, _ = self.p["run_carry_client"]({"dns_query_hex": query.hex()}, query, CANARY_KEY, proc, "node-one")
        self.assertEqual(verdict, "reachable")
        self.assertEqual(proc.pid(), pid)

    def test_the_client_is_gated_before_it_is_run(self):
        marker = self.dir / "ran"
        risky = self.dir / "writable-client"
        risky.write_text(f"#!/bin/sh\ntouch {marker}\n")
        risky.chmod(0o775)
        gated = load_probe(self.probe_text, CARRY_CLIENT_BIN=str(risky), CARRY_CLIENT_TIMEOUT=5)
        for command, expected in ((str(risky), "H0 D6"), ("", "no AWG carry client installed"),
                                  (str(self.dir / "absent"), "no AWG carry client installed")):
            with self.subTest(command=command):
                gated["CARRY_CLIENT_BIN"] = command
                proc = gated["CarryClientProcess"]("udp")
                self.addCleanup(proc.close)
                status, detail, _ = proc.exchange({}, "node-one")
                self.assertEqual(status, "unavailable")
                self.assertIn(expected, detail)
                self.assertTrue(proc.unusable)
                self.assertEqual(proc.spawn_count, 0)
        self.assertFalse(marker.exists(), "an ungated client was run")


class P16LaneTests(Hub):
    """P-16's status rules in front of H5's apply_carry_verdict, through the
    real carry_main and the real probe, against the hub's database."""
    probe_text = None

    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp(prefix="p2-lane-"))
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.control = self.dir / "control.json"
        self.record = self.dir / "record.jsonl"
        self.control.write_text(json.dumps({"mode": "echo"}))
        self.script = self.dir / "fake-client"
        self.script.write_text(FAKE_CLIENT.replace("@PYTHON@", sys.executable)
                               .replace("@CONTROL@", repr(str(self.control)))
                               .replace("@RECORD@", repr(str(self.record)))
                               .replace("@DIRECTORY@", repr(str(self.dir))))
        self.script.chmod(0o755)
        self.key_file = self.dir / "canary.key"
        self.key_file.write_text(CANARY_KEY + "\n")
        self.key_file.chmod(0o600)
        self.logs = []

    def mode(self, value, **per_slug):
        modes = {"mode": value}
        modes.update({"slug:" + slug: mode for slug, mode in per_slug.items()})
        self.control.write_text(json.dumps(modes))

    def records(self, transport=None):
        if not self.record.exists():
            return []
        found = [json.loads(line) for line in self.record.read_text().splitlines() if line.strip()]
        return [r for r in found if transport is None or r["transport"] == transport]

    def run_carry(self, **overrides):
        values = dict(DB_PATH=self.mod._DB, CARRY_PUBLIC_KEY=CANARY_KEY, CARRY_KEY_FILE=str(self.key_file),
                      CARRY_CLIENT_BIN=str(self.script), CARRY_CLIENT_TIMEOUT=5,
                      CARRY_DNS_NAME="hub.example.test", carry_client_untrusted=lambda _path: "")
        values.update(overrides)
        probe = load_probe(self.probe_text, **values)
        probe["log"] = self.logs.append
        return probe["carry_main"](types.SimpleNamespace(slug="", dry_run=False))

    def udp(self, slug):
        row = self.node(slug)
        return row["data_plane_udp_carry_status"], row["data_plane_udp_carry_ok_at"], row["data_plane_udp_carry_checked_at"]

    def open_nodes(self, *slugs):
        for slug in slugs:
            self.live_node(slug)

    def test_a_run_uses_one_client_per_transport_and_records_the_verdicts(self):
        slugs = ("lane-a", "lane-b", "lane-c", "lane-d")
        self.open_nodes(*slugs)
        self.assertEqual(self.run_carry(), 0)
        for slug in slugs:
            status, ok_at, checked = self.udp(slug)
            self.assertEqual(status, "ok", slug)
            self.assertEqual(ok_at, checked, "a success is stamped with the run start")
        pids = {}
        for record in self.records():
            pids.setdefault(record["transport"], set()).add(record["pid"])
        self.assertEqual({len(v) for v in pids.values()}, {1}, f"one client per transport: {pids}")
        self.assertEqual(len({next(iter(v)) for v in pids.values()}), len(pids))
        self.assertEqual(len(self.records("udp")), len(slugs), "every node once, from one process")

    def test_no_usable_client_writes_nothing_and_ends_each_pass(self):
        slugs = ("lane-a", "lane-b", "lane-c")
        self.open_nodes(*slugs)
        before = {slug: dict(self.node(slug)) for slug in slugs}
        self.run_carry(CARRY_CLIENT_BIN=str(self.dir / "absent"))
        for slug in slugs:
            after = dict(self.node(slug))
            self.assertEqual({k: v for k, v in after.items() if "_carry_" in k},
                             {k: v for k, v in before[slug].items() if "_carry_" in k},
                             "a probe that never ran is not the node's carrying failure (not even probe_error)")
        skipped = [line for line in self.logs if "not taken (unavailable)" in line]
        self.assertEqual(len(skipped), 3, f"one per lane: the pass ends at once: {skipped}")
        self.assertEqual(self.records(), [])
        self.run_carry()
        for slug in slugs:
            self.assertEqual(self.udp(slug)[0], "ok", "anti-vacuity: every slug was still due")

    def test_a_client_in_backoff_ends_the_pass_and_every_slug_left_stays_due(self):
        slugs = ("lane-a", "lane-b", "lane-c")
        self.open_nodes(*slugs)
        before = {slug: self.udp(slug) for slug in slugs}
        self.mode("crash")
        self.run_carry(CARRY_CLIENT_RESTART_BACKOFF_SECONDS=(600,))
        udp = self.records("udp")
        self.assertEqual(len(udp), 1, "the first request crashed the client; nothing more reached one")
        first = udp[0]["slug"]
        for slug in slugs:
            status, ok_at, checked = self.udp(slug)
            self.assertEqual((status, ok_at), before[slug][:2], "no verdict is written for any slug")
            if slug == first:
                self.assertIsNotNone(checked, "the request that got no reply used up that slug's cadence (P2-T3)")
            else:
                self.assertIsNone(checked, "a slug no request reached stays due")
        self.assertTrue(any("not taken (error)" in line for line in self.logs))
        self.assertTrue(any("not taken (unavailable)" in line for line in self.logs))
        self.record.unlink()
        self.mode("crash-once")
        self.run_carry(CARRY_CLIENT_RESTART_BACKOFF_SECONDS=(0.3,))
        udp = self.records("udp")
        crashed = udp[0]["slug"]
        self.assertNotIn(first, [r["slug"] for r in udp], "the first run's no-verdict slug waits its cadence")
        self.assertEqual(self.udp(crashed)[:2], before[crashed][:2], "the slug whose request got no reply")
        left = set(slugs) - {crashed, first}
        self.assertTrue(left, "anti-vacuity: a slug was left after the crash")
        for slug in left:
            self.assertEqual(self.udp(slug)[0], "ok", "the pass resumed after the backoff, inside the run")

    def test_a_request_without_a_verdict_records_nothing_and_waits_its_cadence(self):
        slugs = ("lane-a", "lane-b", "lane-c")
        self.open_nodes(*slugs)
        # lane-a is in a pending reopen window, so H5's order probes it first
        # (pending first, then a random order): the slug that hangs the client
        # always comes before the others.
        self.assertTrue(self.rerun("lane-a")["auto_reopen_pending"])
        stamp = attempted = self.iso(-700)
        for slug in slugs:
            self.set_row(slug, data_plane_udp_carry_status="ok", data_plane_udp_carry_checked_at=attempted,
                         data_plane_udp_carry_ok_at=stamp)
        self.mode("echo", **{"lane-a": "hang"})
        self.run_carry(CARRY_CLIENT_TIMEOUT=-9.5, CARRY_CLIENT_RESTART_BACKOFF_SECONDS=(0.2,))
        status, ok_at, checked = self.udp("lane-a")
        self.assertEqual((status, ok_at), ("ok", stamp), "no verdict, no record: neither a status nor a success")
        self.assertTrue(self.mod._iso_after(checked, attempted),
                        "only the attempt time, so the slug waits its cadence (P2-T3)")
        for slug in ("lane-b", "lane-c"):
            self.assertEqual(self.udp(slug)[0], "ok", "a slug that hangs the client does not hold the rest")
        udp = [r["slug"] for r in self.records("udp")]
        self.assertEqual(udp[0], "lane-a", "anti-vacuity: the hanging slug went first")
        self.assertEqual(udp.count("lane-a"), 1, "the slug is not retried inside the run")

    def test_a_request_without_a_verdict_waits_its_cadence(self):
        # P2-T3: "On error it records nothing and advances only that slug's
        # cadence", rejecting "a shorter retry than the cadence after a
        # no-verdict error". In H5's stamped cadence that is the attempt time.
        slugs = ("cad-a", "cad-b")
        self.open_nodes(*slugs)
        old = self.iso(-700)
        for slug in slugs:
            self.set_row(slug, data_plane_udp_carry_status="ok", data_plane_udp_carry_ok_at=old,
                         data_plane_udp_carry_checked_at=old)
        self.mode("echo", **{"cad-a": "hang"})
        for _run in range(3):
            self.run_carry(CARRY_CLIENT_TIMEOUT=-9.5, CARRY_CLIENT_RESTART_BACKOFF_SECONDS=(0.2,))
        udp = [r["slug"] for r in self.records("udp")]
        self.assertEqual(udp.count("cad-b"), 1, "anti-vacuity: a verdict waits its cadence")
        self.assertEqual(udp.count("cad-a"), 1, "a slug that hangs the client is not retried on every run")
        self.assertEqual(self.udp("cad-a")[:2], ("ok", old), "and nothing about the node was recorded")

    def test_apply_writes_nothing_for_a_probe_that_gave_no_verdict(self):
        # Claude's P2-SEAM-H5 reading: H5's apply_carry_verdict never writes
        # probe_error or failed for a probe that did not reach a client.
        slug = "lane-apply"
        self.live_node(slug)
        probe = load_probe(self.probe_text, DB_PATH=self.mod._DB)
        unwritten = self.udp(slug)
        with closing(probe["connect_db"]()) as conn:
            probe["ensure_columns"](conn)
            row = conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
            for verdict in ("unavailable", "error"):
                with self.subTest(verdict=verdict):
                    self.assertFalse(probe["apply_carry_verdict"](conn, slug, "udp", verdict, self.iso(),
                                                                  probe["carry_snapshot"](row)))
                    self.assertEqual(self.udp(slug), unwritten)
            self.assertTrue(probe["apply_carry_verdict"](conn, slug, "udp", "unreachable", self.iso(),
                                                         probe["carry_snapshot"](row)), "anti-vacuity")
        self.assertEqual(self.udp(slug)[0], "failed")

    def crossing_run(self, slug, during):
        """Run carry_main while the client holds slug's udp request; `during`
        runs at that moment, then the client answers."""
        self.mode("echo", **{slug: "block"})
        done = []
        runner = threading.Thread(target=lambda: done.append(self.run_carry()), daemon=True)
        runner.start()
        deadline = time.time() + 20
        while not any(r["slug"] == slug and r["transport"] == "udp" for r in self.records()) \
                and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(any(r["slug"] == slug for r in self.records("udp")), "anti-vacuity: the probe ran")
        during()
        (self.dir / ("go-" + slug)).write_text("")
        runner.join(30)
        self.assertEqual(done, [0])

    def test_an_old_reply_never_becomes_a_proof_after_a_withdrawal_and_a_new_completion(self):
        slug = "lane-cross"
        self.live_node(slug)
        self.add_carry_columns()
        self.assertTrue(self.rerun(slug)["auto_reopen_pending"])
        crossed = []

        def cross():
            self.promote(slug)
            crossed.append(self.rerun(slug)["auto_reopen_pending"])

        unwritten = self.udp(slug)
        self.crossing_run(slug, cross)
        self.assertEqual(crossed, [True], "anti-vacuity: a new completion opened a new proof window")
        row = self.node(slug)
        self.assertEqual(self.udp(slug), unwritten, "the old answer was recorded")
        self.assertIsNone(row["data_plane_udp_carry_ok_at"])
        self.assertFalse(self.mod.reopen_last_proof_arrived(row))
        before = self.mod.utcnow().replace(tzinfo=None)
        self.mode("echo", **{slug: "slow"})
        self.run_carry()
        row = self.node(slug)
        self.assertEqual(row["data_plane_udp_carry_status"], "ok", "anti-vacuity: an answer in its own window")
        self.assertTrue(self.mod._iso_after(row["data_plane_udp_carry_ok_at"], row["deployment_completed_at"]))
        self.assertLess(datetime.fromisoformat(row["data_plane_udp_carry_ok_at"]), before + timedelta(seconds=1),
                        "the time recorded is when the run started, not when its answer (1.5 s later) was written")
        self.assertTrue(self.mod.reopen_last_proof_arrived(row))

    def test_a_withdrawal_while_the_probe_runs_records_nothing(self):
        slug = "lane-withdrawn"
        self.live_node(slug)
        self.add_carry_columns()
        unwritten = self.udp(slug)
        self.crossing_run(slug, lambda: self.withdraw(slug))
        row = self.node(slug)
        self.assertTrue(row["deployment_withdrawal_id"], "anti-vacuity: the node was withdrawn during the probe")
        self.assertEqual(self.udp(slug), unwritten)
        self.assertIsNone(row["data_plane_udp_carry_checked_at"])

    def test_a_retirement_while_the_probe_runs_records_nothing(self):
        slug = "lane-retired"
        self.live_node(slug)
        self.add_carry_columns()
        unwritten = self.udp(slug)
        self.crossing_run(slug, lambda: self.set_row(slug, retired_at=self.iso()))
        row = self.node(slug)
        self.assertTrue(row["retired_at"])
        self.assertEqual(self.udp(slug), unwritten)
        self.assertIsNone(row["data_plane_udp_carry_checked_at"])


class P16MeasurementTests(unittest.TestCase):
    def test_probe_rates_match_the_design_arithmetic_at_64_slugs(self):
        # H5's cadence (the A-2 intervals and its 30 s slack) driven by a 120 s
        # timer, three transports, 64 slugs, every probe a success.
        probe = load_probe()
        due = probe["carry_due"]
        start = datetime(2026, 10, 8)
        for klass, expected in (("open", 64 * 3 / 600), ("pending", 64 * 3 / 120)):
            stamps = {}
            probes, burst, runs = 0, 0, 0
            for run in range(0, 3000 // 120 + 1):
                now = start + timedelta(seconds=run * 120)
                this_run = 0
                for slug in range(64):
                    for transport in CARRY:
                        stamp = stamps.get((slug, transport))
                        if due("ok" if stamp else None, stamp, klass, now, stamp):
                            stamps[(slug, transport)] = now.isoformat()
                            this_run += 1
                runs += 1
                if run:
                    probes += this_run
                burst = max(burst, this_run)
            rate = probes / ((runs - 1) * 120)
            self.assertAlmostEqual(rate, expected, delta=expected * 0.15, msg=klass)
            MEASUREMENTS[f"probes_per_second_{klass}_64_slugs_3_transports"] = round(rate, 3)
            MEASUREMENTS[f"largest_run_{klass}_64_slugs_3_transports"] = burst
        MEASUREMENTS["client_spawns_per_run_at_most"] = len(CARRY)


# ======================================================== installer text =====

class InstallerWiringTests(unittest.TestCase):
    def test_the_hub_unit_may_write_the_request_spool_and_it_is_created_first(self):
        # P2's hub-unit property, on H3's (H0-hardened) unit.
        function = block_of(TEXT, "write_systemd() {", "\nsshd_effective_value_is() {")
        make = function.index("install -d -m 0700 -o root -g root /var/lib/wins-canary-requests")
        unit = function.index("cat > \"${SERVICE_FILE}\" <<EOF")
        self.assertLess(make, unit, "systemd validates ReadWritePaths before ExecStart")
        hub_unit = function[unit:function.index("\nEOF\n", unit)]
        self.assertIn("ReadWritePaths=/var/lib/wins-canary-requests", hub_unit)

    def test_the_long_lived_clients_run_inside_h5s_carry_unit_and_sandbox(self):
        unit = block_of(TEXT, "cat > /etc/systemd/system/wins-awg-carry-probe.service <<'EOF'", "\nEOF\n")
        for line in ("Type=oneshot", "ExecStart=/usr/bin/python3 -I /usr/local/lib/wins_node_dataplane_probe.py --carry",
                     "CapabilityBoundingSet=", "NoNewPrivileges=true", "ProtectSystem=strict",
                     "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK", "TemporaryFileSystem=/run:ro"):
            self.assertIn(line, unit)
        self.assertNotIn("WINS_AWG_CARRY_PROBE_COMMAND", SOURCE, "no probe process in the hub app")
        self.assertNotIn("subprocess.Popen(", p2_block())


class StartupWiringTests(unittest.TestCase):
    source = None

    def test_startup_runs_the_proof_watch_beside_the_backstop(self):
        text = self.source if self.source is not None else SOURCE
        startup = block_of(text, "async def startup_event():", "@app.exception_handler(Exception)")
        self.assertIn("asyncio.create_task(fleet_availability_sweep_loop())", startup, "the backstop loop stays")
        self.assertIn("asyncio.create_task(winn3_proof_reopen_watch_loop())", startup)
        self.assertIn("asyncio.create_task(winn3_auto_provision_sweep_loop())", startup, "H2's sweep stays")
        self.assertLess(startup.index("fleet_availability_sweep_loop"), startup.index("winn3_proof_reopen_watch_loop"))


# ============================================================ mutants ========

class MutantTests(unittest.TestCase):
    """One source change per guard; the named test must fail on it, and it must
    fail an assertion, not setup or syntax."""

    kills = []

    def run_case(self, name, case_class, method, attribute, mutated):
        case = case_class(method)
        setattr(case, attribute, mutated)
        result = unittest.TestResult()
        case.run(result)
        self.assertEqual(result.testsRun, 1, name)
        self.assertEqual(result.errors, [], f"{name}: mutant must fail an assertion, not setup or syntax: {result.errors}")
        self.assertGreaterEqual(len(result.failures), 1, f"mutant survived: {name}")
        MutantTests.kills.append(name)

    def kill(self, name, case_class, method, old, new, base_source=None):
        base_source = SOURCE if base_source is None else base_source
        self.assertEqual(base_source.count(old), 1, "mutant target absent or ambiguous: " + name)
        mutated = base_source.replace(old, new)
        self.assertNotEqual(mutated, base_source)
        self.run_case(name, case_class, method, "source", mutated)

    def kill_probe(self, name, case_class, method, old, new):
        base = probe_source()
        self.assertEqual(base.count(old), 1, "mutant target absent or ambiguous: " + name)
        self.run_case(name, case_class, method, "probe_text", base.replace(old, new))

    def test_p11_mutants(self):
        worker_catch = ("        except Exception as exc:\n            # The type only: the job's message can carry node material.\n"
                        "            logger.error(\"winn3 provisioning pass for %s failed: %s\", slug, type(exc).__name__)\n")
        release_update = ("        released = conn.execute(\n            \"UPDATE nodes SET deployment_withdrawal_id=NULL, "
                          "deployment_withdrawn_at=NULL, deployment_released_at=? \"\n")
        match_check = "            (utcnow().isoformat(), node_slug, withdrawal_id),\n        )\n        if released.rowcount != 1:\n"
        commit_test = "test_a_release_starts_provisioning_once_and_after_the_commit"
        for name, old, new, method in [
            ("p11-no-trigger-after-release",
             "    trigger_winn3_golive_after_release(node_slug)\n    if fresh_pending:", "    if fresh_pending:", commit_test),
            ("p11-trigger-before-the-release-update", release_update,
             "        trigger_winn3_golive_after_release(node_slug)\n" + release_update, commit_test),
            ("p11-trigger-before-the-match-check", match_check,
             match_check.replace("        if released", "        trigger_winn3_golive_after_release(node_slug)\n        if released"),
             "test_a_completion_that_does_not_match_releases_and_triggers_nothing"),
            ("p11-withdrawal-keeps-the-release",
             "            \"deployment_completed_at=NULL, deployment_released_at=NULL, \"\n",
             "            \"deployment_completed_at=NULL, \"\n",
             "test_released_at_column_is_set_on_release_and_cleared_by_the_withdrawal"),
            ("p11-release-is-not-recorded",
             "deployment_withdrawn_at=NULL, deployment_released_at=? \"\n"
             "            \"WHERE slug=? AND deployment_withdrawal_id=? AND COALESCE(operator_enabled, 0)=0\",\n"
             "            (utcnow().isoformat(), node_slug, withdrawal_id),",
             "deployment_withdrawn_at=NULL, deployment_released_at=deployment_released_at \"\n"
             "            \"WHERE slug=? AND deployment_withdrawal_id=? AND COALESCE(operator_enabled, 0)=0\",\n"
             "            (node_slug, withdrawal_id),",
             "test_released_at_column_is_set_on_release_and_cleared_by_the_withdrawal"),
            ("p11-no-coalescing",
             "        if clean in _WINN3_PROVISION_STATE:\n            _WINN3_PROVISION_STATE[clean] = \"again\"\n            return \"coalesced\"\n",
             "", "test_triggers_coalesce_while_a_pass_runs"),
            ("p11-a-trigger-during-a-pass-is-dropped",
             "            if _WINN3_PROVISION_STATE.get(slug) == \"again\":\n",
             "            if False:\n", "test_a_trigger_during_a_pass_reaches_the_release"),
            ("p11-a-second-pass-runs-beside-the-first",
             "        if clean in _WINN3_PROVISION_STATE:\n", "        if False:\n",
             "test_no_slug_ever_has_two_passes_at_once"),
            ("p11-a-failing-job-fails-the-completion", worker_catch, "        finally:\n            pass\n",
             "test_a_failing_job_never_fails_or_delays_the_completion"),
            ("p11-registration-does-not-trigger",
             "    trigger_winn3_auto_provision(slug, \"registration\")\n", "    return None\n",
             "test_every_committed_registration_and_heartbeat_starts_a_pass_through_the_one_scheduler"),
            ("p11-identity-ready-gets-a-second-trigger",
             "    winn3_schedule_auto_provision(payload.slug)\n    return {\"ok\": True}\n\n@app.post(\"/api/v1/nodes/{slug}/deployment/withdraw\")",
             "    winn3_schedule_auto_provision(payload.slug)\n    _winn3_provision_worker(payload.slug)\n    return {\"ok\": True}\n\n"
             "@app.post(\"/api/v1/nodes/{slug}/deployment/withdraw\")",
             "test_the_identity_ready_registration_needs_no_trigger_of_its_own"),
            ("p11-fresh-completion-does-not-trigger",
             "    # After its release has committed; neither can fail the completion.\n    trigger_winn3_golive_after_release(node_slug)\n",
             "    # After its release has committed; neither can fail the completion.\n",
             "test_both_completion_routes_trigger_and_the_release_is_the_earliest_trigger"),
            ("p11-switches-ignored", "    if not winn3_auto_provision_triggers_enabled():\n        return \"disabled\"\n", "",
             "test_the_switches_rule_of_h2_applies_to_every_trigger"),
            ("p11-one-switch-is-not-enough",
             "            or os.getenv(\"WINN3_AUTO_CARRIER\", \"1\").strip() == \"1\")\n",
             "            and os.getenv(\"WINN3_AUTO_CARRIER\", \"1\").strip() == \"1\")\n",
             "test_the_switches_rule_of_h2_applies_to_every_trigger"),
        ]:
            with self.subTest(mutant=name):
                cls = P11CompletionTriggerTests
                self.kill(name, cls, method, old, new)

    def test_p12_app_mutants(self):
        for name, old, new, method in [
            ("p12-no-retired-check", "    if row is None or node_is_retired(row):\n        return False\n    now = time.monotonic()",
             "    now = time.monotonic()", "test_unknown_retired_and_malformed_requests_write_nothing"),
            ("p12-no-slug-pattern",
             "    clean = winn3_node_slug_or_empty(slug)\n    if not clean or reason not in WINN3_CANARY_REQUEST_REASONS:\n        return False\n",
             "    clean = str(slug or \"\").strip().lower()\n    if not clean or reason not in WINN3_CANARY_REQUEST_REASONS:\n        return False\n",
             "test_unknown_retired_and_malformed_requests_write_nothing"),
            ("p12-no-sixty-second-limit", "        if last is not None and now - last < WINN3_CANARY_REQUEST_MIN_INTERVAL_SECONDS:\n",
             "        if False:\n", "test_a_second_request_inside_sixty_seconds_is_not_written_inside_the_limit"),
            # H3's writer now carries these three properties (P2-SEAM-H3).
            ("p12-follows-symlinks", "        os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)\n",
             "        with open(os.path.join(directory, name), \"wb\") as stream:\n            stream.write(value)\n",
             "test_a_planted_symlink_is_never_written_through"),
            ("p12-creates-the-directory",
             "def winn3_write_canary_file(directory: Path, name: str, value: bytes) -> None:\n    fd = os.open(",
             "def winn3_write_canary_file(directory: Path, name: str, value: bytes) -> None:\n"
             "    os.makedirs(directory, exist_ok=True)\n    fd = os.open(",
             "test_a_missing_spool_is_not_created_and_does_not_use_up_the_limit"),
            ("p12-follows-a-symlinked-directory",
             "def winn3_write_canary_file(directory: Path, name: str, value: bytes) -> None:\n"
             "    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n",
             "def winn3_write_canary_file(directory: Path, name: str, value: bytes) -> None:\n"
             "    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)\n",
             "test_a_symlinked_spool_is_refused"),
            ("p12-failed-write-uses-up-the-limit",
             "        # Nothing reached the spool, so the attempt uses up no limit.\n"
             "        if _WINN3_CANARY_REQUEST_LAST.get(clean) == now:\n            del _WINN3_CANARY_REQUEST_LAST[clean]\n",
             "        pass\n", "test_a_missing_spool_is_not_created_and_does_not_use_up_the_limit"),
            ("p12-retire-leaves-the-request", "    remove_winn3_canary_request(node_slug)\n", "",
             "test_retirement_removes_the_pending_request_and_the_limit_entry"),
            ("p12-remove-takes-any-path",
             "    if not re.fullmatch(r\"[a-z0-9][a-z0-9_-]{0,62}\", name):\n        return\n", "",
             "test_remove_refuses_a_name_that_could_leave_the_directory"),
            ("p12-suppressed-request-is-dropped",
             "            if clean not in _WINN3_CANARY_REQUEST_DEFERRED:\n"
             "                delay = WINN3_CANARY_REQUEST_MIN_INTERVAL_SECONDS - (now - last) + 0.05\n"
             "                try:\n"
             "                    _WINN3_CANARY_REQUEST_DEFERRED[clean] = _winn3_canary_defer_start(delay, clean, reason)\n"
             "                except Exception as exc:\n"
             "                    logger.warning(\"winn3 canary request could not be deferred: %s\", type(exc).__name__)\n",
             "", "test_a_request_inside_the_limit_is_deferred_not_dropped"),
            ("p12-deferrals-not-coalesced", "            if clean not in _WINN3_CANARY_REQUEST_DEFERRED:\n",
             "            if True:\n", "test_a_request_inside_the_limit_is_deferred_not_dropped"),
            ("p12-deferral-before-the-limit-ends",
             "                delay = WINN3_CANARY_REQUEST_MIN_INTERVAL_SECONDS - (now - last) + 0.05\n",
             "                delay = 0.05\n", "test_a_request_inside_the_limit_is_deferred_not_dropped"),
            ("p12-retire-keeps-the-deferral", "            deferred = _WINN3_CANARY_REQUEST_DEFERRED.pop(clean, None)\n",
             "            deferred = None\n", "test_retirement_cancels_a_deferred_request"),
            ("p12-no-request-after-the-flip",
             "    try:\n        request_winn3_canary_proof(node_slug, \"carrier-flip\")\n    except Exception as exc:\n"
             "        logger.error(\"winn3 post-flip canary request failed: %s\", type(exc).__name__)\n",
             "", "test_the_operator_carrier_flip_requests_the_post_flip_proof_after_its_commit"),
            ("p12-flip-request-before-the-commit",
             "        stored = json.dumps(params, sort_keys=True, separators=(\",\", \":\"))\n        conn.execute(\n"
             "            \"UPDATE nodes SET protocol_version = ?, protocol_params_json = ?,\"\n",
             "        request_winn3_canary_proof(node_slug, \"carrier-flip\")\n"
             "        stored = json.dumps(params, sort_keys=True, separators=(\",\", \":\"))\n        conn.execute(\n"
             "            \"UPDATE nodes SET protocol_version = ?, protocol_params_json = ?,\"\n",
             "test_the_operator_carrier_flip_requests_the_post_flip_proof_after_its_commit"),
            ("p12-flip-request-failure-fails-the-flip",
             "    try:\n        request_winn3_canary_proof(node_slug, \"carrier-flip\")\n    except Exception as exc:\n"
             "        logger.error(\"winn3 post-flip canary request failed: %s\", type(exc).__name__)\n",
             "    request_winn3_canary_proof(node_slug, \"carrier-flip\")\n",
             "test_a_failing_request_never_fails_the_carrier_flip"),
            ("p12-no-request-after-completion",
             "    try:\n        request_winn3_canary_proof(slug, \"completion\")\n    except Exception as exc:\n"
             "        logger.error(\"winn3 canary request failed: %s\", type(exc).__name__)\n",
             "    pass\n", "test_completion_writes_the_request_after_the_commit"),
            ("p12-h2-flip-bypasses-the-gate",
             "        try:\n            request_winn3_canary_proof(slug, \"carrier-flip\")\n        except Exception as exc:\n"
             "            logger.error(\"winn3 post-flip canary request failed: %s\", type(exc).__name__)\n",
             "        winn3_request_canary(slug)\n",
             "test_every_app_write_of_a_request_goes_through_the_gate"),
        ]:
            with self.subTest(mutant=name):
                self.kill(name, P12RequestSpoolTests, method, old, new)

    def test_p13_mutants(self):
        for name, old, new, method in [
            ("p13-every-proof-is-the-last", "    return not installer_rerun_carry_failures(data)\n\ndef evaluate_reopen_on_last_proof",
             "    return True\n\ndef evaluate_reopen_on_last_proof", "test_a_missing_or_stale_or_failed_proof_is_not_the_last_proof"),
            ("p13-accepts-a-proof-older-than-completion", "    return later is not None and earlier is not None and later > earlier",
             "    return later is not None and earlier is not None", "test_every_proof_must_be_newer_than_the_completion_even_the_last_one"),
            ("p13-fleet-pass-for-one-slug", "                \"AND (? IS NULL OR slug = ?) \"\n", "                \"AND (? IS NULL OR ? IS NOT NULL) \"\n",
             "test_only_the_named_slug_is_evaluated"),
            ("p13-evaluates-any-class", "    if reason not in WINN3_PROOF_REOPEN_CLASSES:\n        return False\n", "",
             "test_only_a_closed_rerun_or_fresh_install_node_is_evaluated"),
            ("p13-fresh-install-without-winn3",
             "    if reason == \"fresh_install\" and str(data.get(\"protocol_version\") or \"\").strip().lower() != \"winn/3\":\n        return False\n",
             "", "test_a_fresh_install_goes_live_only_on_winn3_with_the_canary_as_a_proof"),
            ("p13-watch-ignores-fresh-install", "WINN3_PROOF_REOPEN_CLASSES = (\"installer_rerun\", \"fresh_install\")\n",
             "WINN3_PROOF_REOPEN_CLASSES = (\"installer_rerun\",)\n",
             "test_the_watch_covers_a_fresh_install_window_under_its_own_switch"),
            ("p13-watch-ignores-the-class-switch",
             "    if reason == \"fresh_install\":\n        return bool(WINN3_FRESH_INSTALL_AUTO_GOLIVE)\n",
             "    if reason == \"fresh_install\":\n        return True\n",
             "test_the_watch_covers_a_fresh_install_window_under_its_own_switch"),
            ("p13-watch-re-evaluates-unchanged-proofs", "        if _WINN3_PROOF_SEEN.get(slug) != fingerprint:\n            changed.append(slug)",
             "        changed.append(slug)", "test_the_watch_evaluates_a_changed_proof_set_once"),
            ("p13-watch-never-forgets", "    _WINN3_PROOF_SEEN.clear()\n    _WINN3_PROOF_SEEN.update(seen)", "    _WINN3_PROOF_SEEN.update(seen)",
             "test_the_watch_forgets_a_node_that_left_the_window"),
            ("p13-watch-misses-the-carrying-proof",
             "    for _name, column in NODE_RERUN_AWG_CARRY_COLUMNS:\n        wanted += [f\"{column}_status\", f\"{column}_ok_at\"]\n", "",
             "test_a_carrying_proof_from_the_probe_is_noticed_and_reopens"),
            ("p13-evaluates-without-the-proof-set",
             "    if row is None or not reopen_last_proof_arrived(row):\n        return None\n    return auto_reopen_health_closed_nodes",
             "    if row is None:\n        return None\n    return auto_reopen_health_closed_nodes",
             "test_a_failed_carrying_result_never_triggers_an_evaluation"),
        ]:
            with self.subTest(mutant=name):
                self.kill(name, P13LastProofTests, method, old, new)

    def test_p16_client_mutants(self):
        for name, old, new, method in [
            ("p16-one-process-per-probe", "        self.failures = 0\n        self.not_before = 0.0\n        return \"reply\", \"\", data\n",
             "        self.failures = 0\n        self.not_before = 0.0\n        self.kill()\n        return \"reply\", \"\", data\n",
             "test_one_process_serves_every_probe"),
            ("p16-accepts-another-slugs-reply", "                and reply.get(\"slug\") == slug\n", "",
             "test_a_reply_that_is_not_for_this_request_is_no_verdict_and_a_kill"),
            ("p16-accepts-another-transports-reply", "                and reply.get(\"transport\") == self.transport\n", "",
             "test_a_reply_that_is_not_for_this_request_is_no_verdict_and_a_kill"),
            ("p16-accepts-a-boolean-id", "                and type(reply.get(\"id\")) is int\n", "",
             "test_a_reply_that_is_not_for_this_request_is_no_verdict_and_a_kill"),
            ("p16-a-reply-without-a-dns-reply-is-empty",
             "                and isinstance(reply_hex, str)\n            )\n            data = bytes.fromhex(reply_hex) if valid else b\"\"\n",
             "            )\n            data = bytes.fromhex(reply_hex) if valid and isinstance(reply_hex, str) else b\"\"\n",
             "test_a_reply_that_is_not_for_this_request_is_no_verdict_and_a_kill"),
            ("p16-no-backoff", "        self.not_before = now + delay", "        self.not_before = 0.0",
             "test_a_crash_is_no_verdict_then_a_restart_after_the_backoff"),
            ("p16-no-kill-on-timeout",
             "            return \"error\", self._gone(time.monotonic(), \"AWG carry client timed out\"), b\"\"\n",
             "            self._failed(time.monotonic())\n            return \"error\", \"AWG carry client timed out\", b\"\"\n",
             "test_a_hung_client_times_out_is_killed_and_replaced"),
            ("p16-passes-the-hub-environment", "                env=carry_client_env())\n", "                env=dict(os.environ))\n",
             "test_the_client_gets_no_hub_secret_and_a_fixed_command_line"),
            ("p16-runs-an-ungated-client",
             "        untrusted = carry_client_untrusted(CARRY_CLIENT_BIN)\n        if untrusted:\n"
             "            self.unusable = untrusted\n            return untrusted\n", "",
             "test_the_client_is_gated_before_it_is_run"),
            ("p16-kill-signals-the-leader-only", "                os.killpg(group, signal.SIGKILL)\n",
             "                os.kill(group, signal.SIGKILL)\n", "test_kill_stops_the_clients_whole_process_group"),
            ("p16-exited-client-is-reaped-before-the-kill", "        return info is not None and info.si_pid != 0\n",
             "        return proc.poll() is not None\n", "test_an_exited_client_is_signalled_by_group_before_it_is_reaped"),
            ("p16-reaped-client-is-signalled-by-its-old-id",
             "        if proc.returncode is None:\n            # Not reaped yet, so the group id is still this client's: signal\n",
             "        if True:\n            # Not reaped yet, so the group id is still this client's: signal\n",
             "test_a_client_already_reaped_is_never_signalled_by_its_old_id"),
            ("p16-an-empty-reply-is-a-process-failure",
             "        self.failures = 0\n        self.not_before = 0.0\n        return \"reply\", \"\", data\n",
             "        if not data:\n            return \"error\", self._gone(time.monotonic(), \"empty\"), b\"\"\n"
             "        self.failures = 0\n        self.not_before = 0.0\n        return \"reply\", \"\", data\n",
             "test_an_empty_dns_reply_is_a_verdict_and_keeps_its_process"),
        ]:
            with self.subTest(mutant=name):
                self.kill_probe(name, P16ClientTests, method, old, new)

    def test_p16_lane_mutants(self):
        for name, old, new, method in [
            ("p16-unavailable-recorded-as-failure",
             "                results.put((\"unavailable\", row, transport, verdict, detail))\n",
             "                results.put((\"verdict\", row, transport, \"probe_error\", detail))\n",
             "test_no_usable_client_writes_nothing_and_ends_each_pass"),
            ("p16-unavailable-moves-on-instead-of-ending-the-pass",
             "                if client.unusable or resume <= time.monotonic() or resume >= deadline:\n                    break\n",
             "                if client.unusable or resume <= time.monotonic() or resume >= deadline:\n"
             "                    index += 1\n                    continue\n",
             "test_no_usable_client_writes_nothing_and_ends_each_pass"),
            ("p16-backoff-never-resumes-inside-the-run",
             "                stop.wait(resume - time.monotonic())\n                continue\n",
             "                break\n", "test_a_client_in_backoff_ends_the_pass_and_every_slug_left_stays_due"),
            ("p16-no-verdict-recorded-as-failure",
             "            results.put((\"skipped\" if verdict == \"error\" else \"verdict\", row, transport, verdict, detail))\n",
             "            results.put((\"verdict\", row, transport, \"unreachable\" if verdict == \"error\" else verdict, detail))\n",
             "test_a_request_without_a_verdict_records_nothing_and_waits_its_cadence"),
            ("p16-no-verdict-holds-the-pass",
             "            index += 1\n            results.put((\"skipped\" if verdict == \"error\" else \"verdict\", row, transport, verdict, detail))\n",
             "            index += 1\n            if verdict == \"error\":\n                break\n"
             "            results.put((\"skipped\" if verdict == \"error\" else \"verdict\", row, transport, verdict, detail))\n",
             "test_a_request_without_a_verdict_records_nothing_and_waits_its_cadence"),
            ("p16-error-is-due-every-run",
             "                noted = kind == \"skipped\" and not args.dry_run and note_carry_attempt(\n",
             "                noted = False and note_carry_attempt(\n",
             "test_a_request_without_a_verdict_waits_its_cadence"),
            ("p16-ok-cadence-ignores-the-attempt",
             "        if attempt is not None and success is not None and attempt < success:\n",
             "        if False:\n",
             "test_a_request_without_a_verdict_waits_its_cadence"),
            ("p16-apply-writes-a-non-verdict",
             "    status = CARRY_STATUS_FOR_VERDICT.get(verdict)\n    if status is None:\n",
             "    status = CARRY_STATUS_FOR_VERDICT.get(verdict, \"probe_error\")\n    if status is None:\n",
             "test_apply_writes_nothing_for_a_probe_that_gave_no_verdict"),
            ("p16-old-reply-crosses-a-new-completion",
             "    if row is None or (snapshot is not None and carry_snapshot(row) != snapshot):\n",
             "    if row is None:\n",
             "test_an_old_reply_never_becomes_a_proof_after_a_withdrawal_and_a_new_completion"),
            ("p16-records-the-write-time-not-the-start",
             "apply_carry_verdict(conn, slug, transport, verdict, run_started, carry_snapshot(row))",
             "apply_carry_verdict(conn, slug, transport, verdict, utcnow_iso(), carry_snapshot(row))",
             "test_an_old_reply_never_becomes_a_proof_after_a_withdrawal_and_a_new_completion"),
            ("p16-binding-ignores-a-withdrawal",
             '    "deployment_completed_at", "deployment_withdrawal_id", "retired_at", "public_key",\n',
             '    "deployment_completed_at", "retired_at", "public_key",\n',
             "test_a_withdrawal_while_the_probe_runs_records_nothing"),
            ("p16-binding-ignores-a-retirement",
             '    "deployment_completed_at", "deployment_withdrawal_id", "retired_at", "public_key",\n',
             '    "deployment_completed_at", "deployment_withdrawal_id", "public_key",\n',
             "test_a_retirement_while_the_probe_runs_records_nothing"),
            ("p16-one-client-per-probe",
             "    client, temporary = carry_lane_client(transport)\n    relay = None\n",
             "    client, temporary = CarryClientProcess(transport), True\n    relay = None\n",
             "test_a_run_uses_one_client_per_transport_and_records_the_verdicts"),
        ]:
            with self.subTest(mutant=name):
                self.kill_probe(name, P16LaneTests, method, old, new)

    def test_startup_mutants(self):
        for name, old, new in [
            ("startup-no-proof-watch", "    asyncio.create_task(winn3_proof_reopen_watch_loop())\n", ""),
            ("startup-no-backstop-loop", "    asyncio.create_task(fleet_availability_sweep_loop())\n", ""),
        ]:
            with self.subTest(mutant=name):
                self.kill(name, StartupWiringTests, "test_startup_runs_the_proof_watch_beside_the_backstop", old, new)

    def test_zz_report(self):
        MEASUREMENTS["mutants_killed"] = sorted(MutantTests.kills)
        self.assertGreaterEqual(len(MutantTests.kills), 60, MutantTests.kills)


if __name__ == "__main__":
    program = unittest.main(exit=False, verbosity=2)
    print("P2_GOLIVE_MEASUREMENTS " + json.dumps(MEASUREMENTS, sort_keys=True))
    raise SystemExit(not program.result.wasSuccessful())
