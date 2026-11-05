#!/usr/bin/env python3
"""M-5 regression contracts: atomic/persistent hub rate limiter with
eviction, and a capped isolate-local Cloudflare Worker rate map.

`check_rate_limit()` used to SELECT the current count, decide locally
whether the caller was under the limit, and only then UPDATE -- two
statements with a race window in between. Any number of concurrent
requests on the same bucket could all read the pre-increment count and
all pass the limit check before any of their writes landed, so a
sufficiently parallel/distributed client could exceed the configured
quota by an arbitrary factor. It is now a single `INSERT .. ON CONFLICT
DO UPDATE .. RETURNING` statement, which SQLite executes indivisibly
against the already-committed row.

`site_rate_limited()` used to track counts in `SITE_AI_RATE_BUCKETS`, a
plain isolate-local dict with no eviction and no persistence across
worker processes/restarts; it now shares the same atomic, persistent,
evicted primitive as every other limiter.

`web/_worker.js`'s `rateBuckets` Map had no eviction and no size cap, so
a burst of distinct/spoofed source IPs grew it for the life of the
isolate; it now prunes expired entries on a cadence and hard-caps
worst-case size. (The near-identical Netlify Functions this file used to
also cover -- wins-ai-chat.js, translate-site.js -- served the same
public endpoints under Netlify hosting; both are gone now that the site
is fully served from this Worker instead, and the endpoints they used to
serve, /api/site/ai-chat and /api/site/translate, are implemented here.)

These tests exercise the real embedded/shipped functions -- not
reimplementations of their logic -- so a regression in the shipped code
fails here too, following the same harness style as
test_bootstrap_grant_auth.py (Python) and test_ollama_pin_hardening.py
(executing real non-Python source against a synthetic environment).
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional

ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE_PATH = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
WORKER_PATH = ROOT / "web" / "_worker.js"

CONTROL_PLANE_SOURCE = CONTROL_PLANE_PATH.read_text(encoding="utf-8")
WORKER_SOURCE = WORKER_PATH.read_text(encoding="utf-8")


def embedded_app_source(installer: str) -> str:
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


EMBEDDED_APP_SOURCE = embedded_app_source(CONTROL_PLANE_SOURCE)


class HTTPException(Exception):
    """Minimal stand-in so the embedded functions can be exec'd without a
    real fastapi install; behavior (raise on rate-limited) is what these
    tests actually assert, not the exception class's identity."""

    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        super().__init__(detail)


def load_functions_and_constants(
    source: str,
    function_names: set[str],
    constant_names: set[str],
    namespace: dict[str, Any],
) -> dict[str, Any]:
    tree = ast.parse(source)
    nodes = []
    found_functions: set[str] = set()
    found_constants: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in function_names:
            node.decorator_list = []
            nodes.append(node)
            found_functions.add(node.name)
        elif (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in constant_names
        ):
            nodes.append(node)
            found_constants.add(node.targets[0].id)
    if found_functions != function_names:
        raise AssertionError(f"missing embedded functions: {sorted(function_names - found_functions)}")
    if found_constants != constant_names:
        raise AssertionError(f"missing embedded constants: {sorted(constant_names - found_constants)}")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "embedded-rate-limit-functions", "exec"), namespace)
    return namespace


def extract_python_function_source(source: str, name: str) -> str:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            assert segment is not None, f"could not recover source for {name}"
            return segment
    raise AssertionError(f"function {name} not found")


RATE_LIMIT_FUNCTION_NAMES = {
    "rate_limit_bucket",
    "check_rate_limit",
    "site_rate_limited",
    "request_origin_ip",
    "_trusted_forwarded_client_ip",
    # C3: the split limiter -- read-only precheck, atomic consume-after-failure.
    "rate_limit_current_count",
    "precheck_rate_limit",
    "consume_auth_failure",
}
RATE_LIMIT_CONSTANT_NAMES = {"TRUSTED_PROXY_NETWORKS"}
RATE_LIMITS_DDL = "CREATE TABLE IF NOT EXISTS rate_limits (bucket TEXT PRIMARY KEY, count INTEGER DEFAULT 0, reset_at REAL)"


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    # Mirrors the retry in the shipped get_db(): switching a fresh file to
    # WAL needs a brief exclusive lock that busy_timeout doesn't reliably
    # cover, so many threads opening their first connection to the same
    # brand-new db_path at once (exactly what the concurrency test below
    # does) can otherwise race and raise "database is locked" here.
    for attempt in range(5):
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError:
            if attempt == 4:
                raise
            time.sleep(0.05 * (attempt + 1))
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _make_get_db(db_path: str):
    @contextmanager
    def _get_db():
        conn = _connect(db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    return _get_db


def load_rate_limit_gate(db_path: str) -> dict[str, Any]:
    namespace: dict[str, Any] = {
        "sqlite3": sqlite3,
        "hmac": hmac,
        "hashlib": hashlib,
        "secrets": secrets,
        "time": time,
        "ipaddress": ipaddress,
        "Any": Any,
        "Optional": Optional,
        "Request": object,
        "HTTPException": HTTPException,
        "RATE_LIMIT_SECRET": "test-only-rate-limit-hmac-secret",
        "get_db": _make_get_db(db_path),
        "ensure_schema": lambda conn: conn.execute(RATE_LIMITS_DDL),
    }
    load_functions_and_constants(EMBEDDED_APP_SOURCE, RATE_LIMIT_FUNCTION_NAMES, RATE_LIMIT_CONSTANT_NAMES, namespace)
    return namespace


def fake_request(ip: str) -> SimpleNamespace:
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={})


class SourceContractTests(unittest.TestCase):
    """Source-level assertions about the fix shape, independent of runtime behavior."""

    def test_check_rate_limit_is_a_single_atomic_upsert(self) -> None:
        body = extract_python_function_source(EMBEDDED_APP_SOURCE, "check_rate_limit")
        self.assertIn("ON CONFLICT(bucket) DO UPDATE SET", body)
        self.assertIn("RETURNING count", body)
        # The prior SELECT-then-conditionally-UPDATE shape must be gone, not
        # just supplemented -- a leftover copy would silently reintroduce
        # the race on any code path that still called it.
        self.assertNotIn("SELECT count, reset_at FROM rate_limits", body)
        self.assertNotIn("UPDATE rate_limits SET count = count + 1", body)

    def test_check_rate_limit_evicts_expired_buckets_on_every_call_path(self) -> None:
        body = extract_python_function_source(EMBEDDED_APP_SOURCE, "check_rate_limit")
        self.assertIn("secrets.randbelow(128)", body)
        self.assertIn("DELETE FROM rate_limits WHERE reset_at <", body)
        # Eviction must run before the limit-exceeded raise, or a client that
        # only ever gets rejected on this bucket would never trigger cleanup.
        self.assertLess(body.index("randbelow"), body.index("raise HTTPException"))

    def test_site_ai_limiter_no_longer_uses_an_unbounded_isolate_local_dict(self) -> None:
        self.assertNotIn("SITE_AI_RATE_BUCKETS", CONTROL_PLANE_SOURCE)

    def test_site_rate_limited_delegates_to_the_atomic_persistent_limiter(self) -> None:
        body = extract_python_function_source(EMBEDDED_APP_SOURCE, "site_rate_limited")
        self.assertIn("with get_db() as conn:", body)
        self.assertIn("check_rate_limit(", body)
        self.assertIn("rate_limit_bucket(", body)

    def test_enforce_wrappers_no_longer_run_a_redundant_unconditional_sweep(self) -> None:
        # check_rate_limit() now evicts on every call (including rejections),
        # so a separate unconditional DELETE at the end of these wrappers
        # would only add redundant full-table scans on the hot path.
        for name in ("enforce_verify_rate_limits", "enforce_free_verify_rate_limits"):
            body = extract_python_function_source(EMBEDDED_APP_SOURCE, name)
            self.assertNotIn("DELETE FROM rate_limits", body)

    def test_worker_js_caps_and_prunes_the_isolate_local_rate_map(self) -> None:
        self.assertIn("const RATE_BUCKET_CAP = 10_000;", WORKER_SOURCE)
        self.assertIn("function pruneRateBuckets(now) {", WORKER_SOURCE)
        limiter_fn = _extract_js_function(WORKER_SOURCE, "isolateLocalRateLimited")
        self.assertIn("pruneRateBuckets(now)", limiter_fn)


class CheckRateLimitAtomicityTests(unittest.TestCase):
    """Executes the real check_rate_limit() against a real SQLite file."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "ratelimit.db")
        conn = sqlite3.connect(self.db_path)
        conn.execute(RATE_LIMITS_DDL)
        conn.commit()
        conn.close()
        self.ns = load_rate_limit_gate(self.db_path)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_allows_exactly_limit_requests_then_rejects(self) -> None:
        conn = _connect(self.db_path)
        try:
            allowed = rejected = 0
            for _ in range(8):
                try:
                    self.ns["check_rate_limit"](conn, "b1", 5, 60)
                    allowed += 1
                except HTTPException as exc:
                    self.assertEqual(exc.status_code, 429)
                    rejected += 1
            self.assertEqual(allowed, 5)
            self.assertEqual(rejected, 3)
        finally:
            conn.close()

    def test_disabled_when_limit_is_non_positive(self) -> None:
        conn = _connect(self.db_path)
        try:
            for _ in range(50):
                self.ns["check_rate_limit"](conn, "b-unlimited", 0, 60)
        finally:
            conn.close()

    def test_window_expiry_resets_the_counter_instead_of_staying_blocked(self) -> None:
        conn = _connect(self.db_path)
        try:
            for _ in range(3):
                self.ns["check_rate_limit"](conn, "b2", 3, 60)
            with self.assertRaises(HTTPException):
                self.ns["check_rate_limit"](conn, "b2", 3, 60)
            conn.execute("UPDATE rate_limits SET reset_at = ? WHERE bucket = ?", (time.time() - 1, "b2"))
            conn.commit()
            self.ns["check_rate_limit"](conn, "b2", 3, 60)
            row = conn.execute("SELECT count FROM rate_limits WHERE bucket = ?", ("b2",)).fetchone()
            self.assertEqual(row["count"], 1)
        finally:
            conn.close()

    def test_concurrent_requests_on_the_same_bucket_never_exceed_the_limit(self) -> None:
        # Direct regression test for the fixed race: the prior
        # SELECT-then-UPDATE let many concurrent connections all read the
        # pre-increment count and pass the limit check before any write
        # landed. Every thread here opens its own connection (exactly like a
        # fresh get_db() call per request) and hammers the same bucket at
        # (as close as possible to) the same instant.
        limit = 10
        thread_count = 60
        results: list[bool] = []
        lock = threading.Lock()
        # A bounded wait so one connection failing before it ever reaches
        # the barrier (e.g. a resource limit in an unusual CI environment)
        # breaks every other thread out with BrokenBarrierError instead of
        # hanging the test suite forever. The barrier is constructed for
        # exactly thread_count parties; if any thread never arrives (the
        # except branch below), the remaining threads can only ever learn
        # that via the full 15s timeout, and -- without the fix below --
        # wait()'s BrokenBarrierError would propagate straight through each
        # of those threads uncaught, silently dropping their result instead
        # of recording a failure. Both halves of that (the needless 15s
        # stall, and the silently-lost results) are test-harness bugs, not
        # evidence of a real bug in check_rate_limit's atomicity.
        barrier = threading.Barrier(thread_count, timeout=15)

        def worker() -> None:
            try:
                conn = _connect(self.db_path)
            except Exception:
                with lock:
                    results.append(False)
                # Abort immediately: with one party permanently missing the
                # barrier can never fill, so every other thread waiting (or
                # about to wait) should be released now, not after riding
                # out the full 15s timeout to learn the same thing.
                barrier.abort()
                return
            try:
                try:
                    barrier.wait()
                except threading.BrokenBarrierError:
                    with lock:
                        results.append(False)
                    return
                try:
                    self.ns["check_rate_limit"](conn, "hot-bucket", limit, 60)
                    ok = True
                except HTTPException:
                    ok = False
                # get_db() commits on every request in production; without
                # this, a connection's own increment never becomes visible
                # to any other connection and every thread would see (and
                # pass) the same pre-increment count.
                conn.commit()
                with lock:
                    results.append(ok)
            finally:
                conn.close()

        threads = [threading.Thread(target=worker) for _ in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertEqual(
            len(results),
            thread_count,
            "not every thread recorded a result -- a real hang, not just a broken barrier "
            "(that path always appends a result now)",
        )
        self.assertEqual(sum(results), limit, f"expected exactly {limit} allowed requests, got {sum(results)}")

    def test_expired_buckets_are_eventually_evicted(self) -> None:
        conn = _connect(self.db_path)
        try:
            conn.execute(
                "INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, ?, ?)",
                ("long-expired", 99, time.time() - 7200),
            )
            conn.commit()
            # secrets.randbelow(128) == 0 fires with probability 1/128 per
            # call; 5000 calls make the odds of never firing astronomically
            # small (~1e-17) while still running in well under a second
            # against a local SQLite file.
            for _ in range(5000):
                self.ns["check_rate_limit"](conn, "eviction-driver", 1_000_000, 60)
            row = conn.execute("SELECT 1 FROM rate_limits WHERE bucket = ?", ("long-expired",)).fetchone()
            self.assertIsNone(row, "expired bucket was never evicted after 5000 probabilistic attempts")
        finally:
            conn.close()


class C3SplitLimiterTests(unittest.TestCase):
    """C3: edge load shedding counts requests; app backoff counts only FAILURES.

    Executes the real shipped rate_limit_current_count / precheck_rate_limit /
    consume_auth_failure against a real SQLite rate_limits table.

    The deviation these lock down: the application limiter used to consume a
    bucket at the TOP of /verify and /api/redeem, before any credential was
    examined -- so successful reconnects, idempotent recoveries and
    acknowledgements all burned the same budget a brute-force attempt does.
    Behind carrier-grade NAT, a university or a corporate network that is a
    self-inflicted outage for users who did nothing wrong.
    """

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "c3.db")
        self.ns = load_rate_limit_gate(self.db_path)
        self.conn = _connect(self.db_path)
        self.conn.execute(RATE_LIMITS_DDL)
        self.conn.commit()

    def tearDown(self) -> None:
        self.conn.close()
        self.tmpdir.cleanup()

    def test_precheck_is_read_only(self):
        """The load-bearing property: a precheck must have no side effect."""
        precheck = self.ns["precheck_rate_limit"]
        for _ in range(50):
            precheck(self.conn, "auth-failures", 5)
        rows = self.conn.execute("SELECT COUNT(*) AS n FROM rate_limits").fetchone()["n"]
        self.assertEqual(rows, 0, "the read-only precheck wrote to the rate_limits table")
        self.assertEqual(self.ns["rate_limit_current_count"](self.conn, "auth-failures"), 0)

    def test_precheck_rejects_an_already_exhausted_bucket(self):
        consume = self.ns["consume_auth_failure"]
        precheck = self.ns["precheck_rate_limit"]
        for _ in range(5):
            consume(self.conn, "auth-failures", 5, 3600)
        with self.assertRaises(HTTPException) as caught:
            precheck(self.conn, "auth-failures", 5)
        self.assertEqual(caught.exception.status_code, 429)

    def test_consume_only_counts_when_called(self):
        # 100 successful requests -> 0 consumption. This is the whole fix.
        precheck = self.ns["precheck_rate_limit"]
        for _ in range(100):
            precheck(self.conn, "verify-ip", 8)
        self.assertEqual(self.ns["rate_limit_current_count"](self.conn, "verify-ip"), 0)
        # One genuine failure -> exactly one unit consumed.
        self.ns["consume_auth_failure"](self.conn, "verify-ip", 8, 60)
        self.assertEqual(self.ns["rate_limit_current_count"](self.conn, "verify-ip"), 1)

    def test_expired_window_reads_as_zero_without_rewriting(self):
        self.conn.execute(
            "INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, ?, ?)",
            ("stale", 99, time.time() - 10),
        )
        self.conn.commit()
        self.assertEqual(self.ns["rate_limit_current_count"](self.conn, "stale"), 0)
        # Still the original row: reading must not reset it either.
        row = self.conn.execute("SELECT count FROM rate_limits WHERE bucket='stale'").fetchone()
        self.assertEqual(row["count"], 99)
        # And a precheck against it passes, because the window has closed.
        self.ns["precheck_rate_limit"](self.conn, "stale", 5)

    def test_corrupt_bucket_row_reads_as_zero(self):
        self.conn.execute(
            "INSERT INTO rate_limits (bucket, count, reset_at) VALUES (?, ?, ?)",
            ("corrupt", "not-a-number", "not-a-time"),
        )
        self.conn.commit()
        self.assertEqual(self.ns["rate_limit_current_count"](self.conn, "corrupt"), 0)

    def test_consume_is_atomic_under_concurrency(self):
        # Failures arriving in parallel on one bucket must not split the
        # increment from the limit check (the M-5 property, preserved).
        limit = 20
        errors: list[Exception] = []
        allowed: list[int] = []
        barrier = threading.Barrier(16)

        def worker():
            conn = _connect(self.db_path)
            try:
                barrier.wait(timeout=30)
                for _ in range(5):
                    try:
                        self.ns["consume_auth_failure"](conn, "concurrent", limit, 3600)
                        allowed.append(1)
                    except HTTPException:
                        pass
                    conn.commit()
            except Exception as exc:  # pragma: no cover - surfaced below
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertEqual(len(allowed), limit,
                         "concurrent failures over- or under-counted the failure budget")

    def test_precheck_and_consume_agree_on_the_boundary(self):
        consume = self.ns["consume_auth_failure"]
        precheck = self.ns["precheck_rate_limit"]
        for i in range(5):
            precheck(self.conn, "edge", 5)   # still allowed
            consume(self.conn, "edge", 5, 3600)
        # Exactly `limit` failures have been absorbed; the next request is shed
        # by the precheck without needing to consume anything further.
        with self.assertRaises(HTTPException):
            precheck(self.conn, "edge", 5)


class C3EndpointWiringTests(unittest.TestCase):
    """The split is only real if the shipped endpoints actually use it."""

    def setUp(self):
        self.source = CONTROL_PLANE_SOURCE

    def test_verify_prechecks_instead_of_consuming(self):
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "enforce_verify_rate_limits")
        self.assertIn("precheck_rate_limit", fn)
        # Word-boundary match: "precheck_rate_limit(" contains "check_rate_limit(".
        self.assertIsNone(
            re.search(r"(?<![_a-zA-Z])check_rate_limit\(", fn),
            "enforce_verify_rate_limits still consumes the bucket",
        )

    def test_verify_consumes_only_on_a_missing_account(self):
        wrapper = extract_python_function_source(EMBEDDED_APP_SOURCE, "verify_account")
        self.assertIn("await _verify_account_impl(", wrapper)
        impl = extract_python_function_source(EMBEDDED_APP_SOURCE, "_verify_account_impl")
        self.assertIn("asyncio.to_thread(", impl)
        self.assertIn("_verify_account_sync,", impl)
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "_verify_account_sync")
        self.assertIn("consume_verify_auth_failure", fn)
        # The consume must sit with account_not_found, not with the malformed
        # or business-state rejections.
        before_not_found = fn.split('"account_not_found"')[0]
        self.assertIn("consume_verify_auth_failure", before_not_found)
        for benign in ('"invalid_account_format"', '"account_inactive"', '"account_expired"'):
            segment = fn.split(benign)[0]
            # No consume introduced immediately before these rejections.
            tail = segment[segment.rfind("\n        if "):]
            self.assertNotIn("consume_verify_auth_failure", tail, benign)

    def test_redeem_prechecks_at_entry_and_consumes_only_on_decline(self):
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "redeem_prepaid_code")
        self.assertIn("precheck_redemption_rate_limits", fn)
        self.assertIn("consume_redemption_failure_budget", fn)
        # Consumption must be gated on the declined outcome.
        idx = fn.index("consume_redemption_failure_budget")
        preceding = fn[:idx]
        self.assertIn('outcome == "declined"', preceding)

    def test_malformed_redemption_code_consumes_nothing(self):
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "redeem_prepaid_code")
        malformed = fn.split("if not redemption_code_well_formed(normalized):")[1]
        malformed = malformed.split("outcome, result = redeem_code_transaction")[0]
        self.assertNotIn("consume_", malformed)

    def test_acknowledgement_consumes_nothing(self):
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "acknowledge_redemption")
        self.assertIn("precheck_redemption_rate_limits", fn)
        self.assertNotIn("consume_", fn)

    def test_successful_redemption_consumes_nothing(self):
        fn = extract_python_function_source(EMBEDDED_APP_SOURCE, "redeem_prepaid_code")
        # Everything after the declined branch is the grant/recovery path.
        granted = fn.split('if outcome == "declined":')[-1]
        self.assertNotIn("consume_", granted)

    def test_the_old_consuming_entry_point_is_gone(self):
        # If this name comes back, so does the deviation.
        self.assertNotIn("def enforce_redemption_rate_limits", EMBEDDED_APP_SOURCE)

    def test_edge_load_shedding_layer_exists_and_is_separate(self):
        self.assertIn("limit_req_zone $binary_remote_addr zone=wins_edge:10m", self.source)
        self.assertIn("limit_conn_zone $binary_remote_addr zone=wins_edge_conn:10m", self.source)
        # Applied to the authenticated and redemption surfaces.
        self.assertIn("limit_req zone=wins_edge burst=60 nodelay;", self.source)
        # Health must not be shed, or an outage hides behind its own limiter.
        healthz = self.source.split("location = /healthz {")[1].split("}")[0]
        self.assertNotIn("limit_req", healthz)


class SiteRateLimitedTests(unittest.TestCase):
    """Executes the real site_rate_limited() -- the migrated in-memory-dict caller."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "site_ratelimit.db")
        self.ns = load_rate_limit_gate(self.db_path)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_returns_false_while_under_the_limit_then_true(self) -> None:
        request = fake_request("203.0.113.9")
        outcomes = [self.ns["site_rate_limited"](request, limit=4, window_seconds=60) for _ in range(6)]
        self.assertEqual(outcomes, [False, False, False, False, True, True])

    def test_different_source_ips_get_independent_quotas(self) -> None:
        ip_a = fake_request("203.0.113.1")
        ip_b = fake_request("203.0.113.2")
        for _ in range(4):
            self.assertFalse(self.ns["site_rate_limited"](ip_a, limit=4, window_seconds=60))
        self.assertTrue(self.ns["site_rate_limited"](ip_a, limit=4, window_seconds=60))
        # ip_a being exhausted must not affect an unrelated source IP.
        self.assertFalse(self.ns["site_rate_limited"](ip_b, limit=4, window_seconds=60))

    def test_persists_across_independent_get_db_connections(self) -> None:
        # Each call opens (and closes) its own connection via get_db(),
        # exactly like separate requests in production; this is only
        # correctly enforced now that the counter lives in SQLite rather
        # than a never-shared, isolate-local Python dict.
        request = fake_request("203.0.113.42")
        for _ in range(3):
            self.assertFalse(self.ns["site_rate_limited"](request, limit=3, window_seconds=60))
        self.assertTrue(self.ns["site_rate_limited"](request, limit=3, window_seconds=60))


def _extract_js_function(source: str, name: str) -> str:
    pattern = r"^function " + re.escape(name) + r"\([^)]*\)\s*\{"
    marker = re.search(pattern, source, re.MULTILINE)
    assert marker, f"could not find function {name}"
    depth = 0
    start = marker.start()
    for index in range(marker.end() - 1, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated function {name}")


def _extract_js_const(source: str, name: str) -> str:
    pattern = r"^const " + re.escape(name) + r" = [^\n;]+;$"
    match = re.search(pattern, source, re.MULTILINE)
    assert match, f"could not find const {name}"
    return match.group(0)


def _run_node(script: str) -> subprocess.CompletedProcess:
    raw = os.environ.get("WINS_RELEASE_NODE", "")
    if not raw:
        which = shutil.which("node")
        if which:
            raw = str(Path(which).resolve())
    node = Path(raw)
    assert raw and node.is_absolute() and not node.is_symlink(), (
        "authenticated absolute WINS_RELEASE_NODE is required"
    )
    info = node.stat()
    assert node.is_file() and os.access(node, os.X_OK) and info.st_nlink == 1, (
        "WINS_RELEASE_NODE must be one executable regular file"
    )
    node_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
    for name in ("HOME", "TMPDIR"):
        value = os.environ.get(name)
        if value:
            node_env[name] = value
    with tempfile.TemporaryDirectory() as tmp:
        script_path = Path(tmp) / "check.mjs"
        script_path.write_text(script, encoding="utf-8")
        return subprocess.run(
            [str(node), str(script_path)], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, env=node_env
        )


def _worker_prelude() -> str:
    return "\n".join(
        [
            _extract_js_const(WORKER_SOURCE, "rateBuckets"),
            _extract_js_const(WORKER_SOURCE, "RATE_BUCKET_CAP"),
            _extract_js_function(WORKER_SOURCE, "pruneRateBuckets"),
            _extract_js_function(WORKER_SOURCE, "isolateLocalRateLimited"),
        ]
    )


class WorkerRateBucketCapTests(unittest.TestCase):
    """Executes the real _worker.js limiter functions under Node."""

    def test_cap_bounds_worst_case_map_size(self) -> None:
        # The size check only samples every 128th mutation (`size & 127`), so
        # the map can transiently overshoot RATE_BUCKET_CAP by up to 127
        # entries between samples; it must never approach the unbounded
        # 50,000-distinct-key growth this test drives it with.
        lines = [
            'import assert from "node:assert/strict";',
            "for (let i = 0; i < 50000; i++) {",
            '  isolateLocalRateLimited("probe", `ip-${i}`, 1000000, 60000);',
            "}",
            "assert.ok(",
            "  rateBuckets.size <= RATE_BUCKET_CAP + 127,",
            '  `size ${rateBuckets.size} exceeded the cap + sampling slack (${RATE_BUCKET_CAP + 127})`,',
            ");",
            'console.log("OK");',
        ]
        result = _run_node(_worker_prelude() + "\n" + "\n".join(lines))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_expired_buckets_are_pruned(self) -> None:
        lines = [
            'import assert from "node:assert/strict";',
            'isolateLocalRateLimited("probe", "1.2.3.4", 5, 1);',
            'const key = "probe:1.2.3.4";',
            "assert.ok(rateBuckets.has(key));",
            "rateBuckets.get(key).reset = Date.now() - 1000;",
            "pruneRateBuckets(Date.now());",
            'assert.ok(!rateBuckets.has(key), "expired bucket survived pruneRateBuckets");',
            'console.log("OK");',
        ]
        result = _run_node(_worker_prelude() + "\n" + "\n".join(lines))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)

    def test_allows_limit_requests_then_rejects(self) -> None:
        lines = [
            'import assert from "node:assert/strict";',
            "let rejected = 0;",
            "for (let i = 0; i < 7; i++) {",
            '  if (isolateLocalRateLimited("probe", "9.9.9.9", 5, 60000)) rejected++;',
            "}",
            'assert.equal(rejected, 2, `expected exactly 2 rejections, got ${rejected}`);',
            'console.log("OK");',
        ]
        result = _run_node(_worker_prelude() + "\n" + "\n".join(lines))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
