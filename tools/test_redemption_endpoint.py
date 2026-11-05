#!/usr/bin/env python3
"""Phase 3 regression tests for the prepaid-code redemption endpoint.

These exercise the REAL embedded control-plane code -- the redemption block is
sliced verbatim out of server/wins_control_plane_setup_ONETOUCH.sh and exec'd
against a real, file-backed SQLite database -- rather than re-implementing its
logic, so a regression in the shipped script fails here too.

What is real and what is a fake, stated plainly (HANDOFF 3b evidence category
B -- local/mock infrastructure only, no hub, no node, no Litestream):

  REAL: the whole redemption block (code minting, Crockford checksum,
        normalisation, keyed-HMAC lookup, the sealed fulfillment record, the
        BEGIN IMMEDIATE claim transaction, the outbox drain, the pinned
        Litestream parser), plus the borrowed hub primitives
        check_rate_limit, rate_limit_bucket, _trusted_forwarded_client_ip,
        request_origin_bucket_value, security_event_hash,
        issue_activation_secret, issue_activation_secrets, token_digest, new_account_number,
        new_referral_code, parse_duration, and real SQLite with WAL and
        BEGIN IMMEDIATE across real threads.

  FAKE: FastAPI/pydantic (not installed locally -- Request/HTTPException/
        JSONResponse/BaseModel are stubs), relativedelta (dateutil is not
        installed), send_account_email, security_alert, and -- most
        importantly -- the Litestream binary. Litestream is NOT installed in
        this environment, so the durability barrier is driven through the
        documented runner seam by a fake that reproduces every failure mode
        the pinned parser must reject. No test here has ever seen a real
        `litestream sync -wait`.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"
REDEMPTION_MARKER = "# --- Phase 3: prepaid redemption codes"

# Borrowed verbatim from the shipped module so the tests bind to the real
# helpers the endpoint depends on rather than to look-alikes.
BORROWED = {
    "utcnow",
    "now_utc",
    "token_digest",
    "security_event_hash",
    "normalize_account_number",
    "request_origin_bucket_value",
    "_trusted_forwarded_client_ip",
    "rate_limit_bucket",
    "check_rate_limit",
    # C3: the split limiter. The precheck is read-only and the consume is
    # atomic-after-failure; both are borrowed real so these tests bind to the
    # shipped behaviour rather than to a look-alike.
    "rate_limit_current_count",
    "precheck_rate_limit",
    "consume_auth_failure",
    "issue_activation_secret",
    # One setup key per device slot: the redemption block mints a key set.
    "issue_activation_secrets",
    "activation_key_count",
    "activation_key_list",
    "fetch_activation_extra_keys",
    "create_activation_extra_keys_table",
    # The welcome mail seals its own copy of the key set and checks it against
    # the stored keys before it sends.
    "activation_secret_matches",
    "activation_bundle_states",
    "account_may_receive_keys",
    "verify_and_consume_activation_secret",
    "_activation_outbox_keys",
    "_activation_outbox_stream",
    "_activation_outbox_aad",
    "seal_activation_delivery",
    "open_activation_delivery",
    "_hash_activation_secret",
    "new_account_number",
    "reclaim_expired_account_for_reuse",
    "parse_iso_datetime",
    "new_referral_code",
    "parse_duration",
    "mask_id",
    "admin_secret_matches",
    "require_admin_token",
    "create_rate_limits_table",
    "create_users_table",
    # R2: create_redemption_tables now adds its columns idempotently.
    "add_column_if_missing",
    "table_columns",
    "table_exists",
}

TEST_REDEMPTION_KEY_V1 = "a" * 64
TEST_REDEMPTION_KEY_V2 = "b" * 64
TEST_ADMIN_TOKEN = "test-only-admin-token"


def embedded_app_source() -> str:
    installer = INSTALLER.read_text(encoding="utf-8")
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def redemption_block_source(app_source: str) -> str:
    return app_source[app_source.index(REDEMPTION_MARKER):]


def _await_if_needed(result: Any) -> Any:
    # The hub handlers moved from async def to def (FastAPI runs a plain
    # def route in its threadpool). Await only what is still a coroutine.
    return asyncio.run(result) if asyncio.iscoroutine(result) else result


def function_source(app_source: str, name: str) -> str:
    tree = ast.parse(app_source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(app_source, node) or ""
    raise AssertionError(f"function not found: {name}")


# --------------------------------------------------------------------------
# Minimal stand-ins for the packages the production hub has and this machine
# does not. Behaviour under test is the redemption logic, never these.
# --------------------------------------------------------------------------
class HTTPException(Exception):
    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers or {}
        super().__init__(detail)


class JSONResponse:
    def __init__(self, status_code: int = 200, content: Any = None, headers: Any = None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {}


class FakeURL:
    def __init__(self, path: str):
        self.path = path


class FakeClient:
    def __init__(self, host: str):
        self.host = host


class FakeRequest:
    def __init__(self, headers: Optional[dict] = None, client_host: str = "127.0.0.1", path: str = "/api/redeem"):
        self.headers = headers or {}
        self.client = FakeClient(client_host)
        self.url = FakeURL(path)
        self.method = "POST"


class BaseModel:
    def __init__(self, **kwargs):
        for name, value in type(self).__dict__.items():
            if name.startswith("_") or callable(value) or name == "model_config":
                continue
            setattr(self, name, value)
        for name, value in kwargs.items():
            setattr(self, name, value)


def Field(default=None, **_kwargs):
    return default


def ConfigDict(**kwargs):
    return kwargs


def Header(default=None, **_kwargs):
    return default


def Form(default=None, **_kwargs):
    return default


class FakeApp:
    """Collects route registrations; the tests call the coroutines directly."""

    def __init__(self):
        self.routes = []

    def _register(self, method, path):
        def decorator(func):
            self.routes.append((method, path, func.__name__))
            return func
        return decorator

    def post(self, path, **_kw):
        return self._register("POST", path)

    def get(self, path, **_kw):
        return self._register("GET", path)


class relativedelta:  # noqa: N801 - mirrors the dateutil name the hub imports
    """timedelta-backed stand-in. Only used through the real parse_duration."""

    def __init__(self, years=0, months=0, days=0):
        self.days_total = years * 365 + months * 30 + days

    def __radd__(self, other):
        return other + timedelta(days=self.days_total)


def build_namespace(db_path: str, *, keys: str = None, active_version: str = "v1",
                    barrier_enabled: str = "1", extra_env: Optional[dict] = None) -> dict:
    """Exec the real redemption block against a real SQLite file."""
    env_backup = {}
    env = {
        "REDEMPTION_KEYS": keys if keys is not None else f"v1:{TEST_REDEMPTION_KEY_V1}",
        "REDEMPTION_KEY_ACTIVE_VERSION": active_version,
        "DURABILITY_BARRIER_ENABLED": barrier_enabled,
        "DURABILITY_BARRIER_REQUIRED": "1",
        "REDEMPTION_FULFILLMENT_TTL_SECONDS": "900",
        "REDEMPTION_IP_RATE_LIMIT_PER_MINUTE": "1000",
        "REDEMPTION_IP_RATE_LIMIT_PER_HOUR": "5000",
        "REDEMPTION_CODE_RATE_LIMIT_PER_HOUR": "1000",
    }
    env.update(extra_env or {})
    for key, value in env.items():
        env_backup[key] = os.environ.get(key)
        os.environ[key] = value

    try:
        app_source = embedded_app_source()
        namespace: dict = {
            "__name__": "wins_hub_redemption_under_test",
            "os": os, "re": re, "json": json, "hmac": hmac, "hashlib": hashlib,
            "base64": base64, "secrets": secrets, "sqlite3": sqlite3,
            "subprocess": subprocess, "asyncio": asyncio, "time": time,
            "threading": threading, "ipaddress": ipaddress,
            "datetime": datetime, "timedelta": timedelta, "timezone": timezone,
            "Optional": Optional, "Any": Any,
            "relativedelta": relativedelta,
            "logger": logging.getLogger("redemption-test"),
            "DB_PATH": db_path,
            "ADMIN_SECRET_TOKEN": TEST_ADMIN_TOKEN,
            # security_event_hash / rate_limit_bucket key off this. It is the
            # hub's EXISTING bucketing secret and is deliberately NOT the
            # redemption key -- the tests below assert the two never coincide.
            "RATE_LIMIT_SECRET": "test-only-rate-limit-secret",
            "_ACTIVATION_SECRET_PEPPER": b"test-only-activation-pepper",
            "DEVICE_LIMIT": 3,
            # _activation_mail_can_send reads these; without them the rotation
            # path raised NameError in this fixture (a gap since R23 A-1).
            "SMTP_USER": "relay-user",
            "SMTP_PASS": "relay-pass",
            "HTTPException": HTTPException,
            "Request": FakeRequest,
            "JSONResponse": JSONResponse,
            "BaseModel": BaseModel,
            "Field": Field,
            "ConfigDict": ConfigDict,
            "Header": Header,
            "Form": Form,
            "app": FakeApp(),
        }
        # Real hub helpers, lifted from the shipped module.
        tree = ast.parse(app_source)
        wanted = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in BORROWED]
        found = {n.name for n in wanted}
        missing = BORROWED - found
        if missing:
            raise AssertionError(f"missing embedded helper functions: {sorted(missing)}")
        exec(compile(ast.Module(body=wanted, type_ignores=[]), "embedded-hub-helpers", "exec"), namespace)
        # TRUSTED_PROXY_NETWORKS is a module constant the trusted-IP helper
        # reads; take the real one rather than inventing a wider set.
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in {
                    "TRUSTED_PROXY_NETWORKS", "ACTIVATION_KEY_SEPARATOR", "_ACTIVATION_DUMMY_HASH",
                    "ACTIVATION_DELIVERY_MAX_PLAINTEXT", "ACTIVATION_DELIVERY_MAX_SEALED",
                }
                for t in node.targets
            ):
                exec(compile(ast.Module(body=[node], type_ignores=[]), "embedded-hub-constants", "exec"), namespace)

        recorded = {"emails": [], "alerts": []}

        def fake_send_account_email(to_email, subscriber_name, account_number, plan_type="", activation_secret=""):
            recorded["emails"].append({
                "to": to_email, "account_number": account_number,
                "plan_type": plan_type, "activation_secret": activation_secret,
            })
            return True

        def fake_security_alert(priority, event_type, request=None, source_ip="", details=None):
            recorded["alerts"].append((priority, event_type, dict(details or {})))

        namespace["send_account_email"] = fake_send_account_email
        namespace["security_alert"] = fake_security_alert
        namespace["_recorded"] = recorded

        @contextlib.contextmanager
        def get_db():
            conn = sqlite3.connect(db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

        def ensure_schema(conn):
            namespace["create_users_table"](conn)
            namespace["create_activation_extra_keys_table"](conn)
            namespace["create_rate_limits_table"](conn)
            namespace["create_redemption_tables"](conn)

        namespace["get_db"] = get_db
        namespace["ensure_schema"] = ensure_schema

        exec(compile(redemption_block_source(app_source), "embedded-redemption-block", "exec"), namespace)
        return namespace
    finally:
        for key, value in env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# --------------------------------------------------------------------------
# Litestream fakes. Litestream is not installed here; every barrier outcome in
# these tests comes from one of these, injected at the documented runner seam.
# --------------------------------------------------------------------------
def ok_barrier(db_path: str, txid: int = 42):
    return (0, json.dumps({"db_path": db_path, "txid": txid, "replica_txid": txid}), "")


def make_runner(sequence):
    """Return a runner that yields each entry in turn, repeating the last."""
    calls = {"n": 0}

    def runner(db_path):
        index = min(calls["n"], len(sequence) - 1)
        calls["n"] += 1
        entry = sequence[index]
        if callable(entry):
            return entry(db_path)
        return entry

    runner.calls = calls
    return runner


class BaseRedemptionTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="wins-redeem-test-")
        self.db_path = os.path.join(self.tmpdir, "vpn_users.db")
        self.ns = build_namespace(self.db_path)
        self.set_barrier([ok_barrier])
        with self.ns["get_db"]() as conn:
            self.ns["ensure_schema"](conn)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------
    def set_barrier(self, sequence, ns=None):
        target = ns or self.ns
        runner = make_runner(sequence)
        target["_DURABILITY_BARRIER_RUNNER"] = runner
        return runner

    def issue_batch(self, batch_id="test-batch", count=4, canaries=0, duration="1m",
                    expires_in_days=0, ns=None):
        target = ns or self.ns
        result = _await_if_needed(target["admin_issue_redemption_batch"](
            request=FakeRequest(path="/admin/redemption/batch"),
            batch_id=batch_id, count=count, duration=duration, label="test",
            partner="", plan_key="", canaries=canaries,
            expires_in_days=expires_in_days, x_admin_token=TEST_ADMIN_TOKEN,
        ))
        return result

    def redeem(self, code, email="", ns=None, request=None):
        target = ns or self.ns
        payload = target["RedemptionRequest"](code=code, email=email)
        return _await_if_needed(target["redeem_prepaid_code"](
            request=request or FakeRequest(), payload=payload,
        ))

    def rows(self, sql, params=()):
        with self.ns["get_db"]() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.rows(sql, params)
        return rows[0] if rows else None


# ==========================================================================
# 1. Code format, entropy and checksum (acceptance criterion 1)
# ==========================================================================
class CodeFormatTests(BaseRedemptionTest):
    def test_alphabet_is_crockford_and_excludes_the_four_confusables(self):
        alphabet = self.ns["REDEMPTION_ALPHABET"]
        self.assertEqual(len(alphabet), 32)
        self.assertEqual(len(set(alphabet)), 32)
        for ch in "ILOU":
            self.assertNotIn(ch, alphabet)

    def test_minted_code_is_27_symbols_with_a_valid_check_symbol(self):
        for _ in range(200):
            code = self.ns["mint_redemption_code"]()
            self.assertEqual(len(code), 27)
            self.assertTrue(all(c in self.ns["REDEMPTION_ALPHABET"] for c in code))
            self.assertTrue(self.ns["redemption_code_well_formed"](code))

    def test_effective_entropy_after_checksum_removal_is_at_least_128_bits(self):
        # 26 payload symbols from a 32-symbol alphabet = 130 raw bits, minus
        # the payloads rejected at issuance because their Crockford check value
        # would land on one of *, ~, $, =, U (all destroyed by the client
        # normalisation). The check symbol itself contributes zero.
        import math
        payload_symbols = self.ns["REDEMPTION_PAYLOAD_SYMBOLS"]
        self.assertEqual(payload_symbols, 26)
        space = 32 ** payload_symbols
        quotient, remainder = divmod(space, 37)
        accepted = 32 * quotient + min(remainder, 32)
        effective = math.log2(accepted)
        self.assertGreaterEqual(effective, 128.0)
        self.assertAlmostEqual(effective, 129.7905466, places=5)

    def test_minted_check_symbol_never_lands_outside_the_client_alphabet(self):
        # If it did, the deployed website normaliser would mangle it: it strips
        # * ~ $ = as non-alphanumeric and folds U to V.
        for _ in range(500):
            code = self.ns["mint_redemption_code"]()
            self.assertIn(code[-1], self.ns["REDEMPTION_ALPHABET"])

    def test_single_symbol_error_is_always_detected(self):
        code = self.ns["mint_redemption_code"]()
        alphabet = self.ns["REDEMPTION_ALPHABET"]
        for position in range(len(code)):
            for replacement in alphabet:
                if replacement == code[position]:
                    continue
                corrupted = code[:position] + replacement + code[position + 1:]
                self.assertFalse(
                    self.ns["redemption_code_well_formed"](corrupted),
                    f"single-symbol error at {position} slipped through",
                )

    def test_adjacent_transposition_is_always_detected(self):
        for _ in range(25):
            code = self.ns["mint_redemption_code"]()
            for position in range(len(code) - 1):
                if code[position] == code[position + 1]:
                    continue
                swapped = list(code)
                swapped[position], swapped[position + 1] = swapped[position + 1], swapped[position]
                self.assertFalse(self.ns["redemption_code_well_formed"]("".join(swapped)))

    def test_server_normalisation_matches_the_deployed_website_folding(self):
        normalise = self.ns["normalize_redemption_code"]
        self.assertEqual(normalise("  abcd-efgh  "), "ABCDEFGH")
        self.assertEqual(normalise("IiLl"), "1111")
        self.assertEqual(normalise("Oo"), "00")
        self.assertEqual(normalise("Uu"), "VV")
        code = self.ns["mint_redemption_code"]()
        grouped = self.ns["format_redemption_code"](code)
        self.assertIn("-", grouped)
        self.assertEqual(normalise(grouped.lower()), code)


# ==========================================================================
# 2. Keyed lookup with a dedicated, versioned key (acceptance criterion 2)
# ==========================================================================
class KeyedLookupTests(BaseRedemptionTest):
    def test_lookup_hash_is_keyed_and_domain_separated_not_a_bare_sha256(self):
        code = self.ns["mint_redemption_code"]()
        digest = self.ns["redemption_code_hash"](code, "v1")
        self.assertNotEqual(digest, hashlib.sha256(code.encode()).hexdigest())
        self.assertNotEqual(digest, self.ns["token_digest"](code))

    def test_lookup_key_is_not_derived_from_rate_limit_secret_or_admin_token(self):
        code = self.ns["mint_redemption_code"]()
        digest = self.ns["redemption_code_hash"](code, "v1")
        for foreign in (TEST_ADMIN_TOKEN, "test-only-rate-limit-secret", "spa-hmac"):
            self.assertNotEqual(
                digest,
                hmac.new(foreign.encode(), code.encode(), hashlib.sha256).hexdigest(),
            )
        # Scope this assertion to the lookup primitive itself. The larger
        # redemption section also includes rate limiting and audit helpers that
        # correctly use RATE_LIMIT_SECRET for their separate domains.
        lookup = function_source(embedded_app_source(), "redemption_code_hash")
        self.assertIn("_redemption_key_material(version)", lookup)
        self.assertIn('b"wins-redeem-lookup-hmac/v1"', lookup)
        for line in lookup.splitlines():
            if line.strip().startswith("#"):
                continue
            for forbidden in ("RATE_LIMIT_SECRET", "ADMIN_SECRET_TOKEN", "SPA_HMAC", "LEGAL_ACCEPTANCE_HMAC_KEY"):
                self.assertNotIn(forbidden, line, f"redemption must not key off {forbidden}: {line.strip()}")

    def test_key_version_changes_the_digest(self):
        ns = build_namespace(
            self.db_path,
            keys=f"v1:{TEST_REDEMPTION_KEY_V1},v2:{TEST_REDEMPTION_KEY_V2}",
            active_version="v2",
        )
        code = ns["mint_redemption_code"]()
        self.assertNotEqual(ns["redemption_code_hash"](code, "v1"), ns["redemption_code_hash"](code, "v2"))

    def test_rotated_keyring_still_redeems_a_code_minted_under_the_old_version(self):
        # A one-shot code's HMAC cannot be recomputed under a new key, so the
        # old version must stay in the ring or every printed card dies.
        batch = self.issue_batch(batch_id="pre-rotation", count=1)
        code = batch["codes"][0]["code"]
        rotated = build_namespace(
            self.db_path,
            keys=f"v1:{TEST_REDEMPTION_KEY_V1},v2:{TEST_REDEMPTION_KEY_V2}",
            active_version="v2",
        )
        self.set_barrier([ok_barrier], ns=rotated)
        response = self.redeem(code, ns=rotated)
        self.assertTrue(response.content["ok"])

    def test_dropping_the_old_key_version_makes_its_codes_undecidable(self):
        batch = self.issue_batch(batch_id="orphaned", count=1)
        code = batch["codes"][0]["code"]
        rotated = build_namespace(self.db_path, keys=f"v2:{TEST_REDEMPTION_KEY_V2}", active_version="v2")
        self.set_barrier([ok_barrier], ns=rotated)
        response = self.redeem(code, ns=rotated)
        self.assertFalse(response.content["ok"])
        self.assertEqual(response.content["status"], "not_redeemable")

    def test_redemption_disabled_without_a_configured_keyring(self):
        unkeyed = build_namespace(self.db_path, keys="")
        self.assertFalse(unkeyed["redemption_enabled"]())
        with self.assertRaises(HTTPException) as ctx:
            self.redeem("A" * 27, ns=unkeyed)
        self.assertEqual(ctx.exception.status_code, 503)


# ==========================================================================
# 3. The claim transaction: exactly one winner, lost-response recovery,
#    idempotency (acceptance criteria 3, 4, 5)
# ==========================================================================
class ClaimTransactionTests(BaseRedemptionTest):
    def test_happy_path_grants_an_account_and_a_setup_key(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        response = self.redeem(code)
        self.assertTrue(response.content["ok"])
        self.assertRegex(response.content["account_number"], r"^\d{4}-\d{4}-\d{4}$")
        self.assertTrue(response.content["setup_key"])
        self.assertFalse(response.content["recovered"])
        user = self.one("SELECT * FROM users WHERE account_number = ?", (response.content["account_number"],))
        self.assertEqual(user["status"], "active")
        self.assertEqual(user["renewal_source"], "redemption")
        # Only the digest of the setup key is persisted.
        self.assertEqual(user["activation_secret_hash"], self.ns["_hash_activation_secret"](response.content["setup_key"]))
        self.assertNotEqual(user["activation_secret_hash"], response.content["setup_key"])

    def test_exactly_one_concurrent_claim_creates_an_account(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        normalized = self.ns["normalize_redemption_code"](code)
        outcomes = []
        lock = threading.Lock()
        barrier = threading.Barrier(8)

        def worker():
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            try:
                barrier.wait(timeout=10)
                outcome, result = self.ns["redeem_code_transaction"](
                    conn, normalized, FakeRequest(), ""
                )
                with lock:
                    outcomes.append((outcome, result.get("account_number")))
            finally:
                conn.close()

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(outcomes), 8, "every worker must have produced an outcome")
        granted = [o for o in outcomes if o[0] == "granted"]
        recovered = [o for o in outcomes if o[0] == "recovered"]
        self.assertEqual(len(granted), 1, f"exactly one claim must win, got {outcomes}")
        self.assertEqual(len(granted) + len(recovered), 8)
        # Every successful caller sees the SAME entitlement.
        accounts = {account for _outcome, account in outcomes}
        self.assertEqual(len(accounts), 1)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 1)
        code_row = self.one("SELECT * FROM redemption_codes")
        self.assertEqual(code_row["status"], "redeemed")
        self.assertEqual(code_row["account_number"], granted[0][1])
        events = self.rows("SELECT outcome FROM redemption_events WHERE outcome IN ('granted','recovered')")
        self.assertEqual(len([e for e in events if e["outcome"] == "granted"]), 1)

    def test_compare_and_set_guard_rejects_a_second_claim_on_a_spent_row(self):
        # Proves the WHERE status='unused' guard is what protects the row, not
        # merely the writer lock's ordering.
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        self.redeem(code)
        with self.ns["get_db"]() as conn:
            changed = conn.execute(
                "UPDATE redemption_codes SET status='redeemed', account_number='9999-9999-9999' "
                "WHERE status='unused'"
            ).rowcount
        self.assertEqual(changed, 0)

    def test_lost_response_after_commit_recovers_the_same_entitlement(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        first = self.redeem(code)
        # The customer never saw that response. They retype the same code.
        second = self.redeem(code)
        self.assertTrue(second.content["ok"])
        self.assertTrue(second.content["recovered"])
        self.assertEqual(second.content["account_number"], first.content["account_number"])
        self.assertEqual(second.content["setup_key"], first.content["setup_key"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 1)

    def test_duplicate_idempotency_keys_never_create_a_second_account(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        accounts = {self.redeem(code).content["account_number"] for _ in range(5)}
        self.assertEqual(len(accounts), 1)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 1)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 1)

    def test_idempotency_key_is_derived_only_from_the_code(self):
        # A client that invents a fresh key per attempt must not be able to
        # route around the fulfillment record, so the key takes no caller
        # input beyond the code itself.
        code = self.ns["mint_redemption_code"]()
        first = self.ns["redemption_idempotency_key"](code, "v1")
        second = self.ns["redemption_idempotency_key"](code, "v1")
        self.assertEqual(first, second)
        self.assertNotEqual(first, self.ns["redemption_idempotency_key"](self.ns["mint_redemption_code"](), "v1"))

        block = redemption_block_source(embedded_app_source())
        tree = ast.parse(block)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "redemption_idempotency_key"
        )
        self.assertEqual([a.arg for a in function.args.args], ["normalized", "version"])
        self.assertEqual(function.args.kwonlyargs, [])
        # And no request-supplied idempotency channel exists at all.
        for header in ("idempotency-key", "idempotency_key\":", "x-idempotency"):
            self.assertNotIn(header, block.lower().split("def redeem_code_transaction")[0])
        request_model = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "RedemptionRequest"
        )
        fields = [n.target.id for n in request_model.body if isinstance(n, ast.AnnAssign)]
        # R2: optional extension target, device id and referral/promo codes.
        # None is an idempotency channel; the key above is the code alone.
        self.assertEqual(fields, ["code", "email", "account_number", "device_id", "referral_code", "promo_code"])

    def test_no_network_call_happens_inside_the_claim_transaction(self):
        # The email send and the durability barrier are the two remote calls on
        # this path; neither may appear inside redeem_code_transaction.
        block = redemption_block_source(embedded_app_source())
        body = block.split("def redeem_code_transaction")[1].split("\nclass RedemptionRequest")[0]
        for forbidden in ("send_account_email", "run_durability_barrier", "urllib", "subprocess", "requests."):
            self.assertNotIn(forbidden, body, f"{forbidden} must not run inside the claim transaction")

    def test_every_durable_state_transition_lands_in_one_transaction(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        response = self.redeem(code)
        account = response.content["account_number"]
        self.assertEqual(self.one("SELECT status FROM redemption_codes")["status"], "redeemed")
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM users WHERE account_number = ?", (account,)))
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM redemption_fulfillments"))
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM redemption_outbox"))
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM redemption_events WHERE outcome='granted'"))

    def test_no_server_side_pin_is_introduced(self):
        # C1 / 3a: the four-digit PIN is local to the device. Redemption issues
        # the existing high-entropy setup key and creates no PIN of any kind.
        block = redemption_block_source(embedded_app_source())
        code_only = "\n".join(
            line for line in block.splitlines() if not line.strip().startswith("#")
        ).lower()
        for forbidden in ("pin_hash", "pin_digest", "verify_pin", "check_pin", '"pin"', "'pin'", "pin_code"):
            self.assertNotIn(forbidden, code_only, f"{forbidden} would be a server-side PIN")
        self.assertNotIn("pin", [c.lower() for c in self.rows("PRAGMA table_info(redemption_codes)")[0].keys()])

        batch = self.issue_batch(count=1)
        response = self.redeem(batch["codes"][0]["code"])
        # The credential issued is the existing ~256-bit setup key.
        self.assertGreaterEqual(len(response.content["setup_key"]), 40)
        self.assertNotIn("pin", json.dumps(response.content).lower())
        # And it really is issue_activation_secret's output, digest and all.
        user = self.one("SELECT activation_secret_hash FROM users")
        self.assertEqual(user["activation_secret_hash"], self.ns["_hash_activation_secret"](response.content["setup_key"]))


# ==========================================================================
# 4. The setup key at rest: sealed, never plaintext, never logged
#    (acceptance criteria 4, 6)
# ==========================================================================
class SetupKeyHandlingTests(BaseRedemptionTest):
    def test_setup_key_is_never_stored_in_plaintext_anywhere(self):
        batch = self.issue_batch(count=1)
        response = self.redeem(batch["codes"][0]["code"])
        setup_key = response.content["setup_key"]
        with open(self.db_path, "rb") as handle:
            raw = handle.read()
        wal = Path(self.db_path + "-wal")
        if wal.exists():
            raw += wal.read_bytes()
        self.assertNotIn(setup_key.encode(), raw, "the setup key must never appear in the database file")

    def test_sealed_record_is_authenticated_and_bound_to_its_row(self):
        sealed = self.ns["seal_fulfillment_secret"]("super-secret", "v1", "idem-1|1111-2222-3333")
        self.assertEqual(self.ns["open_fulfillment_secret"](sealed, "v1", "idem-1|1111-2222-3333"), "super-secret")
        with self.assertRaises(ValueError):
            self.ns["open_fulfillment_secret"](sealed, "v1", "idem-2|1111-2222-3333")
        with self.assertRaises(ValueError):
            self.ns["open_fulfillment_secret"](sealed, "v1", "idem-1|4444-5555-6666")
        tampered = sealed[:-4] + ("AAAA" if not sealed.endswith("AAAA") else "BBBB")
        with self.assertRaises(ValueError):
            self.ns["open_fulfillment_secret"](tampered, "v1", "idem-1|1111-2222-3333")

    def test_sealing_is_randomised_per_record(self):
        a = self.ns["seal_fulfillment_secret"]("same", "v1", "aad")
        b = self.ns["seal_fulfillment_secret"]("same", "v1", "aad")
        self.assertNotEqual(a, b)

    def test_success_response_is_marked_no_store(self):
        batch = self.issue_batch(count=1)
        response = self.redeem(batch["codes"][0]["code"])
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")

    def test_setup_key_never_reaches_a_url_or_a_log_line(self):
        block = redemption_block_source(embedded_app_source())
        for line in block.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "logger." in stripped:
                self.assertNotIn("setup_key", stripped, f"setup key must never be logged: {stripped}")
                self.assertNotIn("activation_secret", stripped)
        # And the endpoint returns it only in a POST response body.
        self.assertNotIn("setup_key=", block)

    def test_expired_fulfillment_record_is_hard_deleted_and_stops_recovery(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        first = self.redeem(code)
        with self.ns["get_db"]() as conn:
            conn.execute(
                "UPDATE redemption_fulfillments SET expires_at = ?",
                ((self.ns["utcnow"]() - timedelta(seconds=1)).isoformat(),),
            )
        # Recovery window closed: the response is now indistinguishable from an
        # unknown code, and the sealed key is swept away.
        second = self.redeem(code)
        self.assertFalse(second.content["ok"])
        self.assertEqual(second.content, dict(self.ns["REDEMPTION_DECLINED_RESPONSE"]))
        with self.ns["get_db"]() as conn:
            removed = self.ns["sweep_expired_redemption_fulfillments"](conn)
        self.assertEqual(removed, 1)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 0)
        # The entitlement itself survives -- only the recovery copy is gone.
        self.assertIsNotNone(
            self.one("SELECT 1 AS x FROM users WHERE account_number = ?", (first.content["account_number"],))
        )

    def test_explicit_acknowledgement_deletes_the_fulfillment_record(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        self.redeem(code)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 1)
        payload = self.ns["RedemptionRequest"](code=code)
        result = _await_if_needed(self.ns["acknowledge_redemption"](
            request=FakeRequest(path="/api/redeem/ack"), payload=payload
        ))
        self.assertTrue(result["ok"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 0)
        # Acknowledging something that never existed looks identical.
        unknown = self.ns["RedemptionRequest"](code=self.ns["mint_redemption_code"]())
        self.assertEqual(
            _await_if_needed(self.ns["acknowledge_redemption"](request=FakeRequest(), payload=unknown)),
            result,
        )

    def test_acknowledgement_preserves_mail_after_the_api_key_is_spent(self):
        # K3-04. The API shows only key 1. Acknowledging it must not destroy the
        # welcome mail that is the only way the buyer receives keys 2 and 3.
        code = self.issue_batch(count=1)["codes"][0]["code"]
        response = self.redeem(code, email="buyer@example.test")
        account = response.content["account_number"]
        with self.ns["get_db"]() as conn:
            self.assertTrue(self.ns["verify_and_consume_activation_secret"](
                conn, account, response.content["setup_key"]
            ))
        payload = self.ns["RedemptionRequest"](code=code)
        _await_if_needed(self.ns["acknowledge_redemption"](request=FakeRequest(), payload=payload))
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 0)
        self.assertEqual(self.one("SELECT status FROM redemption_outbox")["status"], "pending")
        self.set_barrier([ok_barrier] * 8)
        self.assertEqual(self.ns["drain_redemption_outbox"]()["confirmed"], 1)
        keys = self.ns["_recorded"]["emails"][0]["activation_secret"]
        self.assertEqual(len(keys), 2)  # the spent first key is not mailed again
        self.assertNotIn(response.content["setup_key"], keys)
        with self.ns["get_db"]() as conn:
            self.assertTrue(self.ns["verify_and_consume_activation_secret"](conn, account, keys[0]))
            self.assertTrue(self.ns["verify_and_consume_activation_secret"](conn, account, keys[1]))

    def test_acknowledgement_still_cancels_mail_when_there_is_no_email(self):
        code = self.issue_batch(count=1)["codes"][0]["code"]
        self.redeem(code)
        payload = self.ns["RedemptionRequest"](code=code)
        _await_if_needed(self.ns["acknowledge_redemption"](request=FakeRequest(), payload=payload))
        row = self.one("SELECT status, sealed_secret FROM redemption_outbox")
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))


# ==========================================================================
# 5. The pinned Litestream parser (HANDOFF 3j)
# ==========================================================================
class DurabilityBarrierParserTests(BaseRedemptionTest):
    def parse(self, exit_code, stdout, stderr="", db_path=None):
        return self.ns["parse_litestream_sync_result"](exit_code, stdout, stderr, db_path or self.db_path)

    def assert_fails(self, reason, exit_code, stdout, stderr="", db_path=None):
        with self.assertRaises(self.ns["DurabilityBarrierError"]) as ctx:
            self.parse(exit_code, stdout, stderr, db_path)
        self.assertEqual(ctx.exception.reason, reason)

    def test_accepts_only_the_fully_conforming_response(self):
        result = self.parse(0, json.dumps({"db_path": self.db_path, "txid": 7, "replica_txid": 7}))
        self.assertEqual(result["txid"], 7)
        self.assertEqual(result["replica_txid"], 7)

    def test_accepts_a_symlinked_path_that_resolves_to_the_expected_database(self):
        link = os.path.join(self.tmpdir, "linked.db")
        os.symlink(self.db_path, link)
        result = self.parse(0, json.dumps({"db_path": link, "txid": 3, "replica_txid": 3}))
        self.assertEqual(result["txid"], 3)

    def test_non_zero_exit_fails_closed(self):
        self.assert_fails("exit_status", 1, json.dumps({"db_path": self.db_path, "txid": 7, "replica_txid": 7}))

    def test_empty_output_fails_closed(self):
        self.assert_fails("empty_output", 0, "   ")

    def test_malformed_json_fails_closed(self):
        self.assert_fails("malformed_json", 0, '{"db_path": "x", "txid": 1,')

    def test_non_object_payload_fails_closed(self):
        self.assert_fails("unexpected_payload_shape", 0, "[1, 2, 3]")

    def test_wrong_db_path_fails_closed(self):
        self.assert_fails(
            "db_path_mismatch", 0,
            json.dumps({"db_path": "/var/lib/somewhere-else.db", "txid": 7, "replica_txid": 7}),
        )

    def test_missing_db_path_fails_closed(self):
        self.assert_fails("db_path_missing_or_wrong_type", 0, json.dumps({"txid": 7, "replica_txid": 7}))

    def test_null_db_path_fails_closed(self):
        self.assert_fails(
            "db_path_missing_or_wrong_type", 0,
            json.dumps({"db_path": None, "txid": 7, "replica_txid": 7}),
        )

    def test_wrong_type_db_path_fails_closed(self):
        self.assert_fails(
            "db_path_missing_or_wrong_type", 0,
            json.dumps({"db_path": 12, "txid": 7, "replica_txid": 7}),
        )

    def test_missing_replica_txid_fails_closed(self):
        self.assert_fails("replica_txid_missing", 0, json.dumps({"db_path": self.db_path, "txid": 7}))

    def test_ipc_field_name_is_rejected_as_an_unexpected_interface(self):
        # The IPC API calls it replicated_txid. An absent field must never
        # compare equal to anything, and reading the wrong interface's schema
        # is the silent false positive this pin exists to prevent.
        self.assert_fails(
            "unexpected_interface", 0,
            json.dumps({"db_path": self.db_path, "txid": 7, "replicated_txid": 7}),
        )

    def test_null_txid_fails_closed(self):
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": None, "replica_txid": 7}),
        )

    def test_missing_txid_fails_closed(self):
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "replica_txid": 7}),
        )

    def test_string_txid_fails_closed(self):
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": "7", "replica_txid": 7}),
        )

    def test_boolean_txid_fails_closed(self):
        # bool is a subclass of int in Python; True must never read as 1.
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": True, "replica_txid": True}),
        )

    def test_zero_and_negative_txids_fail_closed(self):
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": 0, "replica_txid": 0}),
        )
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": -1, "replica_txid": -1}),
        )

    def test_replica_behind_primary_fails_closed(self):
        self.assert_fails(
            "replica_behind_primary", 0,
            json.dumps({"db_path": self.db_path, "txid": 9, "replica_txid": 8}),
        )

    def test_replica_ahead_of_primary_also_fails_closed(self):
        # The contract is equality, not "at least".
        self.assert_fails(
            "replica_behind_primary", 0,
            json.dumps({"db_path": self.db_path, "txid": 8, "replica_txid": 9}),
        )

    def test_float_txid_fails_closed(self):
        self.assert_fails(
            "txid_missing_or_wrong_type", 0,
            json.dumps({"db_path": self.db_path, "txid": 7.0, "replica_txid": 7.0}),
        )

    def test_litestream_unavailable_fails_closed(self):
        self.ns["_DURABILITY_BARRIER_RUNNER"] = lambda p: (_ for _ in ()).throw(
            self.ns["DurabilityBarrierError"]("litestream_unavailable", "not installed")
        )
        with self.assertRaises(self.ns["DurabilityBarrierError"]) as ctx:
            self.ns["run_durability_barrier"]()
        self.assertEqual(ctx.exception.reason, "litestream_unavailable")

    def test_timeout_fails_closed(self):
        self.ns["_DURABILITY_BARRIER_RUNNER"] = lambda p: (_ for _ in ()).throw(
            self.ns["DurabilityBarrierError"]("timeout", "exceeded")
        )
        with self.assertRaises(self.ns["DurabilityBarrierError"]) as ctx:
            self.ns["run_durability_barrier"]()
        self.assertEqual(ctx.exception.reason, "timeout")

    def test_command_pins_the_cli_interface_flags(self):
        # -wait is what makes this a barrier rather than a nudge; -json is what
        # makes the response parseable; the timeout is bounded.
        block = redemption_block_source(embedded_app_source())
        body = block.split("def _run_litestream_sync")[1].split("\n_DURABILITY_BARRIER_RUNNER")[0]
        for flag in ('"sync"', '"-wait"', '"-timeout"', '"-json"'):
            self.assertIn(flag, body)

    def test_disabled_barrier_still_fails_closed_while_required(self):
        strict = build_namespace(self.db_path, barrier_enabled="0")
        with self.assertRaises(strict["DurabilityBarrierError"]) as ctx:
            strict["run_durability_barrier"]()
        self.assertEqual(ctx.exception.reason, "barrier_disabled")


# ==========================================================================
# 6. The barrier on the request path, and the HANDOFF 3j invariant
# ==========================================================================
class BarrierOnRequestPathTests(BaseRedemptionTest):
    def test_barrier_failure_withholds_the_setup_key_but_keeps_the_claim(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        self.set_barrier([(1, "", "replica unreachable")])
        with self.assertRaises(HTTPException) as ctx:
            self.redeem(code)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertNotIn("setup_key", json.dumps(ctx.exception.detail))
        # The claim is committed -- that is the whole point: the retry must be
        # able to recover it rather than the customer losing the code.
        self.assertEqual(self.one("SELECT status FROM redemption_codes")["status"], "redeemed")
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_fulfillments")["n"], 1)

    def test_retry_after_barrier_failure_crosses_the_barrier_itself(self):
        # THE INVARIANT. The retry finds an already-committed result. It must
        # NOT short-circuit to success on the strength of that row.
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        runner = self.set_barrier([(1, "", "replica unreachable")])
        with self.assertRaises(HTTPException):
            self.redeem(code)
        self.assertEqual(runner.calls["n"], 1)

        # Retry while the replica is STILL down: recovery must not succeed.
        with self.assertRaises(HTTPException) as ctx:
            self.redeem(code)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(runner.calls["n"], 2, "the retry must have invoked the barrier itself")

        # Replica returns; the same retry now succeeds and recovers.
        good = self.set_barrier([ok_barrier])
        response = self.redeem(code)
        self.assertTrue(response.content["ok"])
        self.assertTrue(response.content["recovered"])
        self.assertEqual(good.calls["n"], 1)

    def test_recovery_path_calls_the_barrier_exactly_once_per_acknowledgement(self):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        runner = self.set_barrier([ok_barrier])
        self.redeem(code)
        self.assertEqual(runner.calls["n"], 1)
        self.redeem(code)
        self.assertEqual(runner.calls["n"], 2)

    def test_barrier_ordering_holds_under_concurrent_redemptions(self):
        # HANDOFF 3j: "Test this ordering under concurrent writes." Distinct
        # codes redeemed in parallel; every acknowledgement must have crossed
        # its own barrier, and no claim may leak into another's account.
        batch = self.issue_batch(count=6)
        codes = [c["code"] for c in batch["codes"]]
        seen = []
        lock = threading.Lock()
        barrier_calls = {"n": 0}
        start = threading.Barrier(len(codes))

        def counting_runner(db_path):
            with lock:
                barrier_calls["n"] += 1
            return ok_barrier(db_path, txid=barrier_calls["n"])

        self.ns["_DURABILITY_BARRIER_RUNNER"] = counting_runner

        def worker(code):
            start.wait(timeout=10)
            response = self.redeem(code)
            with lock:
                seen.append(response.content)

        threads = [threading.Thread(target=worker, args=(code,)) for code in codes]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        self.assertEqual(len(seen), len(codes))
        self.assertTrue(all(r["ok"] for r in seen))
        self.assertEqual(len({r["account_number"] for r in seen}), len(codes))
        self.assertEqual(barrier_calls["n"], len(codes), "one barrier per acknowledgement")
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], len(codes))
        self.assertEqual(
            self.one("SELECT COUNT(*) AS n FROM redemption_codes WHERE status='redeemed'")["n"],
            len(codes),
        )

    def test_declined_responses_do_not_invoke_the_barrier(self):
        # Nothing durable changed that anyone is waiting on, and an attacker
        # must not be able to drive remote round-trips with junk input.
        runner = self.set_barrier([ok_barrier])
        self.redeem(self.ns["mint_redemption_code"]())
        self.assertEqual(runner.calls["n"], 0)


# ==========================================================================
# 7. Enumeration resistance (acceptance criterion 7)
# ==========================================================================
class EnumerationResistanceTests(BaseRedemptionTest):
    def declined_shapes(self):
        shapes = []
        batch = self.issue_batch(batch_id="enum", count=3, expires_in_days=0)
        codes = [c["code"] for c in batch["codes"]]

        # 1. unknown, well-formed code
        shapes.append(("unknown", self.redeem(self.ns["mint_redemption_code"]())))
        # 2. already redeemed, past the recovery window
        self.redeem(codes[0])
        with self.ns["get_db"]() as conn:
            conn.execute("UPDATE redemption_fulfillments SET expires_at = ?",
                         ((self.ns["utcnow"]() - timedelta(seconds=1)).isoformat(),))
        shapes.append(("already_redeemed", self.redeem(codes[0])))
        # 3. malformed code
        shapes.append(("malformed", self.redeem("ZZZZ-ZZZZ")))
        # 4. revoked batch
        _await_if_needed(self.ns["admin_revoke_redemption_batch"](
            request=FakeRequest(path="/admin/redemption/revoke"),
            batch_id="enum", reason="lost in transit", x_admin_token=TEST_ADMIN_TOKEN,
        ))
        shapes.append(("revoked", self.redeem(codes[1])))
        # 5. expired code
        batch2 = self.issue_batch(batch_id="enum-expired", count=1)
        with self.ns["get_db"]() as conn:
            conn.execute("UPDATE redemption_codes SET expires_at = ? WHERE batch_id = 'enum-expired'",
                         ((self.ns["utcnow"]() - timedelta(days=1)).isoformat(),))
        shapes.append(("expired", self.redeem(batch2["codes"][0]["code"])))
        # 6. canary
        batch3 = self.issue_batch(batch_id="enum-canary", count=1, canaries=1)
        shapes.append(("canary", self.redeem(batch3["codes"][0]["code"])))
        return shapes

    def test_every_declined_outcome_is_byte_identical(self):
        shapes = self.declined_shapes()
        statuses = {name: (response.status_code, json.dumps(response.content, sort_keys=True))
                    for name, response in shapes}
        distinct = set(statuses.values())
        self.assertEqual(
            len(distinct), 1,
            f"declined outcomes must be indistinguishable, got {statuses}",
        )
        status_code, body = distinct.pop()
        self.assertEqual(status_code, 200)
        self.assertEqual(json.loads(body), dict(self.ns["REDEMPTION_DECLINED_RESPONSE"]))
        self.assertFalse(json.loads(body)["ok"])

    def test_declined_response_carries_no_batch_or_code_metadata(self):
        response = self.redeem(self.ns["mint_redemption_code"]())
        serialised = json.dumps(response.content).lower()
        for leak in ("batch", "canary", "revoked", "expired", "unknown", "account"):
            self.assertNotIn(leak, serialised)


# ==========================================================================
# 8. Rate limiting on gateway-observed identity only (acceptance criterion 6)
# ==========================================================================
class RateLimitTests(BaseRedemptionTest):
    def setUp(self):
        super().setUp()
        self.ns = build_namespace(
            self.db_path,
            extra_env={
                "REDEMPTION_IP_RATE_LIMIT_PER_MINUTE": "3",
                "REDEMPTION_IP_RATE_LIMIT_PER_HOUR": "5",
                "REDEMPTION_CODE_RATE_LIMIT_PER_HOUR": "2",
            },
        )
        self.set_barrier([ok_barrier])
        with self.ns["get_db"]() as conn:
            self.ns["ensure_schema"](conn)

    def test_per_source_limit_trips_and_returns_a_retry_after(self):
        request = FakeRequest(client_host="127.0.0.1", headers={"x-real-ip": "203.0.113.9"})
        for _ in range(3):
            self.redeem(self.ns["mint_redemption_code"](), request=request)
        with self.assertRaises(HTTPException) as ctx:
            self.redeem(self.ns["mint_redemption_code"](), request=request)
        self.assertEqual(ctx.exception.status_code, 429)
        self.assertIn("Retry-After", ctx.exception.headers)
        self.assertTrue(int(ctx.exception.headers["Retry-After"]) <= 900)

    def test_per_code_limit_trips_independently_of_the_source(self):
        code = self.ns["mint_redemption_code"]()
        self.redeem(code, request=FakeRequest(headers={"x-real-ip": "203.0.113.1"}))
        self.redeem(code, request=FakeRequest(headers={"x-real-ip": "203.0.113.2"}))
        with self.assertRaises(HTTPException) as ctx:
            self.redeem(code, request=FakeRequest(headers={"x-real-ip": "203.0.113.3"}))
        self.assertEqual(ctx.exception.status_code, 429)

    def test_client_supplied_header_from_an_untrusted_peer_is_ignored(self):
        # A caller whose immediate TCP peer is not in TRUSTED_PROXY_NETWORKS
        # cannot pick its own rate-limit identity by setting a header, so
        # spoofing X-Real-IP does not buy a fresh bucket.
        buckets = set()
        for spoofed in ("198.51.100.1", "198.51.100.2", "198.51.100.3"):
            request = FakeRequest(client_host="203.0.113.77", headers={"x-real-ip": spoofed})
            buckets.add(self.ns["request_origin_bucket_value"](request))
        self.assertEqual(buckets, {"203.0.113.77"})

    def test_trusted_loopback_peer_may_supply_the_forwarded_identity(self):
        request = FakeRequest(client_host="127.0.0.1", headers={"x-real-ip": "198.51.100.4"})
        self.assertEqual(self.ns["request_origin_bucket_value"](request), "198.51.100.4")

    def test_rate_limit_bucket_never_stores_the_raw_identity(self):
        bucket = self.ns["rate_limit_bucket"]("redeem-ip-minute", "203.0.113.9")
        self.assertNotIn("203.0.113.9", bucket)
        self.assertTrue(bucket.startswith("redeem-ip-minute:"))

    def test_rate_limit_windows_are_rolling_not_lifetime(self):
        with self.ns["get_db"]() as conn:
            self.ns["ensure_schema"](conn)
            bucket = self.ns["rate_limit_bucket"]("redeem-ip-minute", "203.0.113.9")
            for _ in range(3):
                self.ns["check_rate_limit"](conn, bucket, 3, 60)
            with self.assertRaises(HTTPException):
                self.ns["check_rate_limit"](conn, bucket, 3, 60)
            # Expire the window; the bucket resets rather than banning forever.
            conn.execute("UPDATE rate_limits SET reset_at = ? WHERE bucket = ?", (time.time() - 1, bucket))
            self.ns["check_rate_limit"](conn, bucket, 3, 60)


# ==========================================================================
# 9. Batch lifecycle: issuance, revocation, expiry, canaries
#    (acceptance criteria 8, 11)
# ==========================================================================
class BatchLifecycleTests(BaseRedemptionTest):
    def test_issuance_returns_plaintext_once_and_stores_only_hmacs(self):
        batch = self.issue_batch(batch_id="unidays-2026-q3", count=5)
        self.assertEqual(len(batch["codes"]), 5)
        stored = self.rows("SELECT code_hash FROM redemption_codes")
        self.assertEqual(len(stored), 5)
        with open(self.db_path, "rb") as handle:
            raw = handle.read()
        for entry in batch["codes"]:
            normalized = self.ns["normalize_redemption_code"](entry["code"])
            self.assertNotIn(normalized.encode(), raw)
            self.assertIn(
                self.ns["redemption_code_hash"](normalized, "v1"),
                {row["code_hash"] for row in stored},
            )

    def test_batch_tagging_survives_to_the_redemption_event(self):
        batch = self.issue_batch(batch_id="unidays-2026-q3", count=1)
        self.redeem(batch["codes"][0]["code"])
        event = self.one("SELECT * FROM redemption_events WHERE outcome='granted'")
        self.assertEqual(event["batch_id"], "unidays-2026-q3")

    def test_batch_revocation_kills_every_unused_code_in_bulk(self):
        batch = self.issue_batch(batch_id="lost-run", count=6)
        codes = [c["code"] for c in batch["codes"]]
        self.redeem(codes[0])  # one already sold before the run went missing
        result = _await_if_needed(self.ns["admin_revoke_redemption_batch"](
            request=FakeRequest(path="/admin/redemption/revoke"),
            batch_id="lost-run", reason="lost in transit", x_admin_token=TEST_ADMIN_TOKEN,
        ))
        self.assertEqual(result["revoked_codes"], 5)
        for code in codes[1:]:
            self.assertFalse(self.redeem(code).content["ok"])
        # The already-redeemed one keeps its history.
        self.assertEqual(
            self.one("SELECT COUNT(*) AS n FROM redemption_codes WHERE status='redeemed'")["n"], 1
        )
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM redemption_events WHERE outcome='batch_revoked'"))

    def test_revoking_an_unknown_batch_is_a_404_for_the_admin(self):
        with self.assertRaises(HTTPException) as ctx:
            _await_if_needed(self.ns["admin_revoke_redemption_batch"](
                request=FakeRequest(), batch_id="never-existed", reason="",
                x_admin_token=TEST_ADMIN_TOKEN,
            ))
        self.assertEqual(ctx.exception.status_code, 404)

    def test_batch_level_expiry_declines_even_when_the_code_itself_has_none(self):
        expired = self.issue_batch(batch_id="short-lived", count=1, expires_in_days=1)
        live = self.issue_batch(batch_id="still-good", count=1, expires_in_days=1)
        with self.ns["get_db"]() as conn:
            # Age only the BATCH; clear the per-code expiry so the batch window
            # is provably the thing doing the work.
            conn.execute(
                "UPDATE redemption_batches SET expires_at = ? WHERE batch_id='short-lived'",
                ((self.ns["utcnow"]() - timedelta(days=1)).isoformat(),),
            )
            conn.execute("UPDATE redemption_codes SET expires_at = NULL WHERE batch_id='short-lived'")
        self.assertFalse(self.redeem(expired["codes"][0]["code"]).content["ok"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 0)
        self.assertEqual(self.one("SELECT status FROM redemption_codes WHERE batch_id='short-lived'")["status"], "unused")
        # A sibling batch inside its window is unaffected.
        self.assertTrue(self.redeem(live["codes"][0]["code"]).content["ok"])

    def test_code_level_expiry_declines(self):
        batch = self.issue_batch(batch_id="expiring", count=1, expires_in_days=30)
        with self.ns["get_db"]() as conn:
            conn.execute(
                "UPDATE redemption_codes SET expires_at = ? WHERE batch_id='expiring'",
                ((self.ns["utcnow"]() - timedelta(seconds=1)).isoformat(),),
            )
        self.assertFalse(self.redeem(batch["codes"][0]["code"]).content["ok"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 0)

    def test_canary_never_grants_and_raises_a_batch_scoped_alarm(self):
        batch = self.issue_batch(batch_id="unidays-2026-q3", count=4, canaries=4)
        response = self.redeem(batch["codes"][0]["code"])
        self.assertFalse(response.content["ok"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM users")["n"], 0)
        alerts = [a for a in self.ns["_recorded"]["alerts"] if "canary" in a[1]]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][0], 1, "a tripped canary is a P1")
        self.assertEqual(alerts[0][2]["batch_id"], "unidays-2026-q3")
        self.assertEqual(self.one("SELECT status FROM redemption_codes WHERE is_canary=1 AND redeemed_at IS NOT NULL")["status"], "canary_tripped")
        self.assertIsNotNone(self.one("SELECT 1 AS x FROM redemption_events WHERE outcome='canary'"))

    def test_canary_positions_are_not_a_fixed_prefix(self):
        seen = set()
        for index in range(6):
            batch = self.issue_batch(batch_id=f"canary-spread-{index}", count=20, canaries=3)
            positions = tuple(i for i, entry in enumerate(batch["codes"]) if entry["canary"])
            seen.add(positions)
        self.assertGreater(len(seen), 1, "canary placement must not be deterministic")

    def test_duplicate_batch_id_is_rejected(self):
        self.issue_batch(batch_id="dupe", count=1)
        with self.assertRaises(HTTPException) as ctx:
            self.issue_batch(batch_id="dupe", count=1)
        self.assertEqual(ctx.exception.status_code, 409)

    def test_admin_endpoints_require_the_admin_token(self):
        for coro, kwargs in (
            (self.ns["admin_issue_redemption_batch"], dict(
                batch_id="nope", count=1, duration="1m", label="", partner="",
                plan_key="", canaries=0, expires_in_days=0)),
            (self.ns["admin_revoke_redemption_batch"], dict(batch_id="nope", reason="")),
            (self.ns["admin_list_redemption_batches"], {}),
            (self.ns["admin_drain_redemption_outbox"], {}),
        ):
            with self.assertRaises(HTTPException) as ctx:
                _await_if_needed(coro(request=FakeRequest(), x_admin_token="wrong", **kwargs))
            self.assertEqual(ctx.exception.status_code, 401)


# ==========================================================================
# 10. Immutable audit events (acceptance criterion 8)
# ==========================================================================
class ImmutableAuditTests(BaseRedemptionTest):
    def test_grant_events_cannot_be_updated(self):
        batch = self.issue_batch(count=1)
        self.redeem(batch["codes"][0]["code"])
        with self.ns["get_db"]() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE redemption_events SET outcome='nothing-happened' WHERE outcome='granted'")

    def test_grant_events_cannot_be_deleted(self):
        batch = self.issue_batch(count=1)
        self.redeem(batch["codes"][0]["code"])
        with self.ns["get_db"]() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM redemption_events WHERE outcome='granted'")

    def test_canary_and_revocation_events_cannot_be_deleted(self):
        batch = self.issue_batch(batch_id="audit", count=2, canaries=2)
        self.redeem(batch["codes"][0]["code"])
        _await_if_needed(self.ns["admin_revoke_redemption_batch"](
            request=FakeRequest(), batch_id="audit", reason="", x_admin_token=TEST_ADMIN_TOKEN,
        ))
        with self.ns["get_db"]() as conn:
            for outcome in ("canary", "batch_revoked", "batch_issued"):
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("DELETE FROM redemption_events WHERE outcome = ?", (outcome,))

    def test_recent_declined_probe_events_cannot_be_deleted_either(self):
        self.redeem(self.ns["mint_redemption_code"]())
        with self.ns["get_db"]() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM redemption_events WHERE outcome='declined'")

    def test_only_aged_declined_probe_events_may_be_pruned(self):
        # The ONE permitted deletion: unbounded junk from a prober must not be
        # able to fill the disk. Nothing else is ever removable.
        batch = self.issue_batch(count=1)
        self.redeem(batch["codes"][0]["code"])          # a grant, must survive
        self.redeem(self.ns["mint_redemption_code"]())  # a probe, may be pruned
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_events WHERE outcome='declined'")["n"], 1)

        # Age BOTH rows past the retention window. UPDATE is blocked by design,
        # so the trigger has to come off to stage the fixture -- which is
        # itself evidence that the immutability control is real.
        old = (self.ns["utcnow"]() - timedelta(days=self.ns["REDEMPTION_DECLINED_EVENT_RETENTION_DAYS"] + 1)).isoformat()
        with self.ns["get_db"]() as conn:
            conn.execute("DROP TRIGGER redemption_events_append_only_update")
            conn.execute("UPDATE redemption_events SET occurred_at = ?", (old,))
            conn.execute("""
                CREATE TRIGGER redemption_events_append_only_update
                BEFORE UPDATE ON redemption_events
                BEGIN SELECT RAISE(ABORT, 'redemption_events is append-only'); END
            """)
            self.ns["sweep_expired_redemption_fulfillments"](conn)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_events WHERE outcome='declined'")["n"], 0)
        # The aged GRANT is still there: age is not a licence to delete.
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_events WHERE outcome='granted'")["n"], 1)
        with self.ns["get_db"]() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM redemption_events WHERE outcome='granted'")

    def test_audit_event_records_no_raw_source_address(self):
        request = FakeRequest(client_host="127.0.0.1", headers={"x-real-ip": "203.0.113.44",
                                                                "user-agent": "curl/8"})
        self.redeem(self.ns["mint_redemption_code"](), request=request)
        event = self.one("SELECT * FROM redemption_events ORDER BY id DESC")
        self.assertTrue(event["source_ip_bucket"])
        self.assertNotIn("203.0.113.44", json.dumps(dict(event)))
        self.assertNotIn("curl/8", json.dumps(dict(event)))


# ==========================================================================
# 11. Outbox: retries, ordering against the barrier, restart recovery
#     (acceptance criterion 3 "after commit only", HANDOFF 3j)
# ==========================================================================
class OutboxTests(BaseRedemptionTest):
    def redeem_with_email(self, email="buyer@example.org"):
        batch = self.issue_batch(count=1)
        code = batch["codes"][0]["code"]
        response = self.redeem(code, email=email)
        return code, response

    def test_outbox_row_is_written_inside_the_claim_transaction(self):
        self.redeem_with_email()
        item = self.one("SELECT * FROM redemption_outbox")
        self.assertEqual(item["status"], "pending")
        self.assertEqual(item["target_email"], "buyer@example.org")
        self.assertEqual(item["attempts"], 0)

    def test_drain_crosses_the_barrier_before_sending_and_after_completing(self):
        self.redeem_with_email()
        runner = self.set_barrier([ok_barrier])
        summary = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary["claimed"], 1)
        self.assertEqual(summary["delivered"], 1)
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(runner.calls["n"], 2, "one barrier before delivery, one before acknowledgement")
        self.assertEqual(len(self.ns["_recorded"]["emails"]), 1)
        item = self.one("SELECT * FROM redemption_outbox")
        self.assertEqual(item["status"], "completed")
        self.assertIsNotNone(item["barrier_confirmed_at"])

    def test_pre_delivery_barrier_failure_sends_nothing_and_leaves_the_row_pending(self):
        self.redeem_with_email()
        self.set_barrier([(1, "", "replica down")])
        summary = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary["deferred"], 1)
        self.assertEqual(summary["delivered"], 0)
        self.assertEqual(self.ns["_recorded"]["emails"], [])
        item = self.one("SELECT * FROM redemption_outbox")
        self.assertEqual(item["status"], "pending")
        self.assertIsNone(item["lease_until"])
        self.assertTrue(item["last_error"].startswith("pre_barrier:"))

    def test_post_delivery_barrier_failure_leaves_a_pending_record_another_worker_completes(self):
        # HANDOFF 3j test 7: the business row already reads delivered, and the
        # durability half must still be finished by someone -- without a second
        # email.
        self.redeem_with_email()
        self.set_barrier([ok_barrier, (1, "", "replica down")])
        summary = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary["delivered"], 1)
        self.assertEqual(summary["deferred"], 1)
        self.assertEqual(summary["confirmed"], 0)
        item = self.one("SELECT * FROM redemption_outbox")
        self.assertEqual(item["status"], "delivered")
        self.assertIsNone(item["barrier_confirmed_at"])
        self.assertEqual(len(self.ns["_recorded"]["emails"]), 1)

        # A second worker (or the next timer tick) picks it up.
        self.set_barrier([ok_barrier])
        summary2 = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary2["claimed"], 1)
        self.assertEqual(summary2["delivered"], 0, "must not re-send")
        self.assertEqual(summary2["confirmed"], 1)
        self.assertEqual(len(self.ns["_recorded"]["emails"]), 1, "exactly-once delivery")
        item = self.one("SELECT * FROM redemption_outbox")
        self.assertEqual(item["status"], "completed")
        self.assertIsNotNone(item["barrier_confirmed_at"])

    def test_delivery_failure_is_retried_on_the_next_drain(self):
        self.redeem_with_email()
        boom = {"n": 0}

        def flaky(*_args, **_kwargs):
            boom["n"] += 1
            if boom["n"] == 1:
                raise RuntimeError("smtp timeout")
            self.ns["_recorded"]["emails"].append({"account_number": "sent"})
            return True

        self.ns["send_account_email"] = flaky
        self.set_barrier([ok_barrier])
        first = self.ns["drain_redemption_outbox"]()
        self.assertEqual(first["failed"], 1)
        self.assertEqual(self.one("SELECT status FROM redemption_outbox")["status"], "pending")
        second = self.ns["drain_redemption_outbox"]()
        self.assertEqual(second["delivered"], 1)
        self.assertEqual(second["confirmed"], 1)
        self.assertEqual(boom["n"], 2)
        self.assertEqual(self.one("SELECT attempts FROM redemption_outbox")["attempts"], 2)

    def test_drain_is_idempotent_once_completed(self):
        self.redeem_with_email()
        self.set_barrier([ok_barrier])
        self.ns["drain_redemption_outbox"]()
        summary = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary["claimed"], 0)
        self.assertEqual(len(self.ns["_recorded"]["emails"]), 1)

    def test_drain_with_no_email_target_still_crosses_both_barriers(self):
        batch = self.issue_batch(count=1)
        self.redeem(batch["codes"][0]["code"])  # website path: no email supplied
        runner = self.set_barrier([ok_barrier])
        summary = self.ns["drain_redemption_outbox"]()
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(runner.calls["n"], 2)
        self.assertEqual(self.ns["_recorded"]["emails"], [])

    def test_expired_fulfillment_preserves_the_original_setup_keys_for_delivery(self):
        # K3-04: the mail has its own sealed copy, so the API record expiring
        # neither rotates nor loses the keys.
        code, response = self.redeem_with_email()
        original = response.content["setup_key"]
        with self.ns["get_db"]() as conn:
            conn.execute("UPDATE redemption_fulfillments SET expires_at = ?",
                         ((self.ns["utcnow"]() - timedelta(seconds=1)).isoformat(),))
        self.set_barrier([ok_barrier])
        self.ns["drain_redemption_outbox"]()
        sent = self.ns["_recorded"]["emails"]
        self.assertEqual(len(sent), 1)
        mailed = sent[0]["activation_secret"]  # the whole key set, a list
        self.assertEqual(len(mailed), 3)
        self.assertEqual(mailed[0], original)
        user = self.one("SELECT activation_secret_hash FROM users")
        self.assertEqual(user["activation_secret_hash"], self.ns["_hash_activation_secret"](mailed[0]))

    def test_a_row_from_before_the_sealed_column_rotates_once_and_retries_reuse_the_rotation(self):
        code, response = self.redeem_with_email()
        original = response.content["setup_key"]
        with self.ns["get_db"]() as conn:
            conn.execute("UPDATE redemption_outbox SET sealed_secret = NULL")
            conn.execute("DELETE FROM redemption_fulfillments")
        calls = []

        def flaky(to_email, subscriber_name, account_number, plan_type="", activation_secret=""):
            calls.append(list(activation_secret))
            return len(calls) > 1

        self.ns["send_account_email"] = flaky
        self.set_barrier([ok_barrier] * 8)
        self.assertEqual(self.ns["drain_redemption_outbox"]()["failed"], 1)
        self.assertEqual(self.ns["drain_redemption_outbox"]()["confirmed"], 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0], calls[1])
        self.assertNotIn(original, calls[0])
        self.assertEqual(len(calls[0]), 3)

    def test_recovery_after_process_restart(self):
        # Commit in one "process", then throw away all module state and drain
        # from a freshly exec'd module bound to the same database file.
        code, response = self.redeem_with_email()
        account = response.content["account_number"]
        restarted = build_namespace(self.db_path)
        self.set_barrier([ok_barrier], ns=restarted)
        summary = restarted["drain_redemption_outbox"]()
        self.assertEqual(summary["confirmed"], 1)
        self.assertEqual(len(restarted["_recorded"]["emails"]), 1)
        self.assertEqual(restarted["_recorded"]["emails"][0]["account_number"], account)
        # And a retry of the original request still recovers the same entitlement.
        recovered = self.redeem(code, ns=restarted)
        self.assertTrue(recovered.content["recovered"])
        self.assertEqual(recovered.content["account_number"], account)
        self.assertEqual(recovered.content["setup_key"], response.content["setup_key"])


# ==========================================================================
# 12. Shipped-script wiring: the block is actually in the installer, the key
#     is dedicated, and the Litestream install is pinned and fail-closed.
# ==========================================================================
class ShippedScriptWiringTests(unittest.TestCase):
    def setUp(self):
        self.installer = INSTALLER.read_text(encoding="utf-8")

    def test_routes_are_registered_in_the_shipped_module(self):
        for route in ('@app.post("/api/redeem")', '@app.post("/api/redeem/ack")',
                      '@app.post("/admin/redemption/batch")',
                      '@app.post("/admin/redemption/revoke")',
                      '@app.post("/admin/redemption/outbox/drain")'):
            self.assertIn(route, self.installer)

    def test_schema_is_created_from_ensure_schema(self):
        self.assertIn("create_redemption_tables(conn)", self.installer)

    def test_redemption_key_is_generated_independently_of_every_other_secret(self):
        self.assertIn("write_env_kv REDEMPTION_KEYS", self.installer)
        block = self.installer.split("redemption_keys=\"${REDEMPTION_KEYS:-}\"")[1].split("write_env_kv ADMIN_TOKEN")[0]
        for forbidden in ("${admin_token}", "${spa_hmac}", "${rate_limit_secret}"):
            self.assertNotIn(forbidden, block)

    def test_litestream_install_refuses_an_unverified_binary(self):
        function = self.installer.split("install_litestream() {")[1].split("\nwrite_redemption_outbox_timer()")[0]
        self.assertIn("sha256sum", function)
        self.assertIn("LITESTREAM_SHA256_", function)
        self.assertIn("Refusing to install", function)
        # A malformed or empty digest must still abort the install, so the
        # 64-hex guard is the control -- not the emptiness of the constant.
        self.assertIn('[[ ! "${expected}" =~ ^[0-9a-fA-F]{64}$ ]]', function)

    def test_pinned_digests_are_the_published_release_checksums(self):
        # These digests are the GitHub release asset digests published for
        # litestream-0.5.17-linux-x86_64.tar.gz and -linux-arm64.tar.gz.
        self.assertIn(
            'LITESTREAM_SHA256_AMD64_DEFAULT="${LITESTREAM_SHA256_AMD64:-'
            'cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d}"',
            self.installer,
        )
        self.assertIn(
            'LITESTREAM_SHA256_ARM64_DEFAULT="${LITESTREAM_SHA256_ARM64:-'
            'f8ca4a050095c1efbda2c4365172e61bf9d955ea0d9ac42f448b52e51819baa5}"',
            self.installer,
        )

    def test_litestream_version_is_pinned_and_verified_after_install(self):
        function = self.installer.split("install_litestream() {")[1].split("\nwrite_redemption_outbox_timer()")[0]
        self.assertIn('version 2>/dev/null | grep -F -- "${version}" >/dev/null', function)
        self.assertIn('LITESTREAM_VERSION_DEFAULT="${LITESTREAM_VERSION:-', self.installer)

    def test_pinned_version_can_actually_satisfy_the_barrier(self):
        # `sync -wait` needs 0.5.9+ and `-json` needs 0.5.12+. The previous pin
        # was 0.5.0, which supports NEITHER: the barrier could only ever have
        # failed closed. Both halves of the pin must be >= 0.5.12 and equal.
        match = re.search(
            r'LITESTREAM_VERSION_DEFAULT="\$\{LITESTREAM_VERSION:-([0-9]+\.[0-9]+\.[0-9]+)\}"',
            self.installer,
        )
        self.assertIsNotNone(match, "installer must pin an exact x.y.z Litestream version")
        shell_version = tuple(int(p) for p in match.group(1).split("."))
        self.assertGreaterEqual(shell_version, (0, 5, 12))

        runtime = re.search(
            r'LITESTREAM_PINNED_VERSION = os\.getenv\("LITESTREAM_PINNED_VERSION", "([0-9]+\.[0-9]+\.[0-9]+)"\)',
            self.installer,
        )
        self.assertIsNotNone(runtime, "runtime half of the pin must be an exact x.y.z version")
        self.assertEqual(match.group(1), runtime.group(1),
                         "installer and runtime Litestream pins must be identical")

    def test_install_rejects_a_version_that_predates_the_barrier_flags(self):
        function = self.installer.split("install_litestream() {")[1].split("\nwrite_redemption_outbox_timer()")[0]
        self.assertIn("litestream_version_supports_barrier", function)
        guard = self.installer.split("litestream_version_supports_barrier() {")[1].split("\n}")[0]
        # Numeric comparison, because "0.5.9" > "0.5.12" lexically.
        self.assertIn("BASH_REMATCH", guard)
        self.assertIn("patch >= 12", guard)

    def test_download_url_uses_the_published_asset_naming(self):
        function = self.installer.split("install_litestream() {")[1].split("\nwrite_redemption_outbox_timer()")[0]
        # Asset name has NO `v` before the version and uses `x86_64`, while the
        # release tag directory keeps its `v`. Both details were wrong before.
        self.assertIn('/v${version}/litestream-${version}-linux-${asset_arch}.tar.gz', function)
        self.assertNotIn("litestream-v${version}", function)
        self.assertIn('asset_arch="x86_64"', function)

    def test_archive_members_are_validated_before_extraction(self):
        function = self.installer.split("install_litestream() {")[1].split("\nwrite_redemption_outbox_timer()")[0]
        self.assertIn("litestream_archive_members_are_safe", function)
        # Validation must run before the extraction it protects.
        self.assertLess(function.index("litestream_archive_members_are_safe"),
                        function.index("tar -xzf"))
        self.assertIn("--no-same-owner", function)
        guard = self.installer.split("litestream_archive_members_are_safe() {")[1].split("\ninstall_litestream()")[0]
        for expected in ("traverses upward", "unexpected type", "expected release layout"):
            self.assertIn(expected, guard)

    def test_outbox_timer_is_installed_and_enabled(self):
        self.assertIn("write_redemption_outbox_timer", self.installer)
        self.assertIn("wins-redemption-outbox.timer", self.installer)
        # CP-14: enabled through the helper that also revives a timer an older
        # unit (Persistent=true) left elapsed with no next run.
        self.assertIn("wins_enable_monotonic_timer wins-redemption-outbox.timer", self.installer)

    def test_embedded_module_still_parses(self):
        ast.parse(embedded_app_source())

    def test_worker_route_exists_and_never_puts_the_code_in_a_url(self):
        worker = (ROOT / "web" / "_worker.js").read_text(encoding="utf-8")
        self.assertIn('url.pathname === "/api/redeem"', worker)
        self.assertIn("handleRedeem", worker)
        handler = worker.split("async function handleRedeem")[1].split("\nexport default")[0]
        self.assertNotIn("searchParams", handler)
        self.assertNotIn("console.log", handler)
        proxy = worker.split("async function proxyRedeemRequest")[1].split("async function handleRedeem")[0]
        self.assertIn('method: "POST"', proxy)
        self.assertNotIn("console.", proxy)


# ==========================================================================
# 13. Website credential delivery (fix for the prepaid-card black-hole)
#     The site previously checked payload.ok and discarded both values.
# ==========================================================================
class RedemptionCredentialDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.index = (ROOT / "web" / "index.html").read_text(encoding="utf-8")
        self.worker = (ROOT / "web" / "_worker.js").read_text(encoding="utf-8")

    def test_website_has_email_field_and_sends_it_in_post_body(self):
        self.assertIn('id="redemptionEmail"', self.index)
        self.assertIn('type="email"', self.index)
        # The fetch body must include email when present; the worker must forward it.
        self.assertIn("redemptionEmail", self.index)
        self.assertIn("email", self.index.split("fetch(\"/api/redeem\"")[1].split("});")[0] if "fetch(\"/api/redeem\"" in self.index else self.index)
        # Concrete: JSON.stringify spread with email
        self.assertIn("JSON.stringify({ code, ...(rawEmail", self.index)
        self.assertIn('code,', self.worker)
        # Worker forwards email: see source/wins_vpn/web/_worker.js:1195
        self.assertIn("...(email ? { email }", self.worker)

    def test_website_format_gate_requires_exactly_27_symbols(self):
        # Old gate was < 16; new gate must be !== 27 to match worker's 27.
        self.assertIn('length !== 27', self.index)
        self.assertNotIn('length < 16', self.index)
        # Worker pattern is exactly 27 alphanumerics.
        self.assertIn("REDEMPTION_CODE_PATTERN = /^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{27}$/", self.worker)

    def test_website_renders_account_number_and_setup_key_in_dom(self):
        for token in ('id="redemptionAccountNumber"', 'id="redemptionSetupKey"', 'id="redemptionCredentials"'):
            self.assertIn(token, self.index)
        # Handler must write payload.account_number and payload.setup_key into DOM textContent.
        self.assertIn("payload.account_number", self.index)
        self.assertIn("payload.setup_key", self.index)
        self.assertIn("redemptionAccountNumber.textContent", self.index)
        self.assertIn("redemptionSetupKey.textContent", self.index)
        # Must show the save-once warning and keep it visible.
        self.assertIn("Save these now", self.index)
        self.assertIn("shown once", self.index.lower())
        # Must not auto-dismiss: no setTimeout that clears credentials.
        handler = self.index.split("redemptionCodeSubmit")[1].split("const trackingConfig")[0]
        self.assertNotIn("setTimeout", handler.split("redemptionCredentials")[1] if "redemptionCredentials" in handler else handler)

    def test_website_has_copy_controls_and_confirmation(self):
        self.assertIn('id="redemptionCopyAccount"', self.index)
        self.assertIn('id="redemptionCopyKey"', self.index)
        self.assertIn("navigator.clipboard.writeText", self.index)
        self.assertIn('id="redemptionConfirmCheck"', self.index)
        self.assertIn('id="redemptionAckButton"', self.index)
        self.assertIn('Confirm I have saved these', self.index)
        # Confirmation must be required before ack is enabled.
        self.assertIn("updateAckButtonState", self.index)
        self.assertIn("redemptionConfirmCheck.checked", self.index)

    def test_website_calls_ack_after_confirmation(self):
        self.assertIn('"/api/redeem/ack"', self.index)
        self.assertIn('fetch("/api/redeem/ack"', self.index)
        self.assertIn("pendingAckCode", self.index)
        self.assertIn('JSON.stringify({ code: pendingAckCode', self.index)
        # Worker routes ack correctly.
        self.assertIn('url.pathname === "/api/redeem/ack"', self.worker)
        self.assertIn('handleRedeem(request, env, "/api/redeem/ack")', self.worker)

    def test_website_never_logs_secrets(self):
        handler = self.index.split("redemptionCodeSubmit")[1].split("const trackingConfig")[0]
        for forbidden in ("console.log", "console.error", "console.warn"):
            self.assertNotIn(forbidden, handler)
        # The setup key must not appear in a URL, query string, or log line.
        self.assertNotIn("setup_key", handler.split("redemptionSetupKey")[0] if "payload.setup_key" in handler else handler)
        # Overall index should never console.log the setup key.
        for line in handler.splitlines():
            if "setup_key" in line.lower() or "setupkey" in line.lower():
                self.assertNotIn("console.", line)
                self.assertNotIn("searchParams", line)

    def test_website_does_not_auto_dismiss_credentials(self):
        # "Do not auto-dismiss" invariant: credentials stay until user confirms.
        handler = self.index.split("redemptionCodeSubmit")[1].split("const trackingConfig")[0]
        # No hidden=true reset on a timer and no automatic removal of textContent.
        self.assertNotIn("redemptionCredentials.hidden = true", handler)
        # The only place hidden is set false on success and never true.
        self.assertIn("redemptionCredentials.hidden = false", self.index)


if __name__ == "__main__":
    result = unittest.main(module=__name__, argv=["redemption-endpoint"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Redemption endpoint tests passed")
