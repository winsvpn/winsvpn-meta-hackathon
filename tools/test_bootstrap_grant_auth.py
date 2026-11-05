#!/usr/bin/env python3
"""Fail-closed regression tests for the H-2 bootstrap-grant credential system.

The fleet-wide admin token must no longer be a routine node/core credential.
Instead, an admin mints a short-lived, single-use bootstrap grant
(mint_bootstrap_grant) that one target exchanges exactly once for its own
permanent, scoped token (bootstrap_core / bootstrap_node); every routine
node/core endpoint thereafter authenticates with that scoped token
(require_core_token / require_node_token) and never with the admin token.

These tests exercise the real embedded control-plane functions -- not
reimplementations of their logic -- so a regression in the shipped code
fails here too.
"""

from __future__ import annotations

import asyncio
import ast
import hashlib
import hmac
import inspect
import secrets
import sqlite3
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"

ADMIN_SECRET_TOKEN = "test-only-admin-secret-token-0123456789"


def embedded_app_source(installer: str) -> str:
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


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
            # Route handlers carry an @app.post(...) decorator; strip it so
            # exec'ing this isolated module never needs a real FastAPI app.
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
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "embedded-bootstrap-functions", "exec"), namespace)
    return namespace


class HTTPException(Exception):
    """Minimal stand-in so the embedded functions can be exec'd without a
    real fastapi install; behavior (raise on unauthorized/invalid) is what
    these tests actually assert, not the exception class's identity."""

    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        super().__init__(detail)


class FakeRequest:
    def __init__(self, headers: Optional[dict[str, str]] = None):
        self.headers = headers or {}


def build_namespace(alerts: list, conn: sqlite3.Connection) -> dict[str, Any]:
    @contextmanager
    def fake_get_db():
        yield conn

    return {
        "Optional": Optional,
        "sqlite3": sqlite3,
        "hmac": hmac,
        "hashlib": hashlib,
        "secrets": secrets,
        "re": re,
        "urllib": urllib,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "Request": object,
        "Header": lambda *args, **kwargs: None,
        "BootstrapGrantRequest": object,
        "CoreBootstrapRequest": object,
        "NodeBootstrapRequest": object,
        "CoreManagementVerifyRequest": object,
        "HTTPException": HTTPException,
        "ADMIN_SECRET_TOKEN": ADMIN_SECRET_TOKEN,
        "DOUBLE_VPN_CORE_ID": "north-america-core",
        "RATE_LIMIT_SECRET": "test-only-rate-limit-secret-for-hostname-hmac",
        # IA-SYNC SYNC-24: management hostnames are keyed by their own key,
        # which main.py defaults to RATE_LIMIT_SECRET when unset.
        "MANAGEMENT_NAME_HMAC_KEY": "test-only-rate-limit-secret-for-hostname-hmac",
        "NODE_MANAGEMENT_TUNNEL_ZONE_NAME": "mgmt.example.test",
        "get_db": fake_get_db,
        "ensure_schema": lambda _conn: None,
        "security_alert": lambda priority, event_type, request=None, source_ip="", details=None: alerts.append(
            (priority, event_type, details or {})
        ),
    }


FUNCTION_NAMES = {
    "utcnow",
    "admin_secret_matches",
    "require_admin_token",
    "token_digest",
    "node_token_matches",
    "fetch_node_token_hash",
    "require_node_token",
    "create_bootstrap_grant",
    "consume_bootstrap_grant",
    "core_token_matches",
    "fetch_core_token_hash",
    "require_core_token",
    "mint_bootstrap_grant",
    "bootstrap_core",
    "bootstrap_node",
    "node_is_retired",
    "normalize_hostname",
    "management_tunnel_hostname",
    "core_management_hostname",
    "verify_core_management_tunnel",
}
CONSTANT_NAMES = {"BOOTSTRAP_GRANT_TTL_SECONDS", "BOOTSTRAP_GRANT_ROLES"}


def load_gate(alerts: list, conn: sqlite3.Connection) -> dict[str, Any]:
    app = embedded_app_source(INSTALLER.read_text(encoding="utf-8"))
    namespace = build_namespace(alerts, conn)
    load_functions_and_constants(app, FUNCTION_NAMES, CONSTANT_NAMES, namespace)
    return namespace


def make_grant_payload(bootstrap_token: str, **kwargs) -> SimpleNamespace:
    return SimpleNamespace(bootstrap_token=bootstrap_token, **kwargs)


class BootstrapGrantPrimitiveTests(unittest.TestCase):
    """Tests against create_bootstrap_grant / consume_bootstrap_grant directly."""

    def setUp(self):
        self.alerts: list = []
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE bootstrap_grants (
                token_hash TEXT PRIMARY KEY, role TEXT NOT NULL,
                subject_id TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
            )
            """
        )
        self.conn.execute(
            "CREATE TABLE nodes (slug TEXT PRIMARY KEY, node_token_hash TEXT, retired_at TEXT, "
            "operator_enabled INTEGER NOT NULL DEFAULT 0)"
        )
        self.conn.execute("CREATE TABLE core_servers (core_id TEXT PRIMARY KEY, core_token_hash TEXT)")
        self.ns = load_gate(self.alerts, self.conn)

    def tearDown(self):
        self.conn.close()

    def create_grant(self, role: str, subject_id: str) -> str:
        return self.ns["create_bootstrap_grant"](self.conn, role, subject_id)

    def consume_grant(self, token: Optional[str], role: str, subject_id: str) -> bool:
        return self.ns["consume_bootstrap_grant"](self.conn, token, role, subject_id)

    def test_create_bootstrap_grant_stores_only_a_hash_never_the_plaintext(self):
        token = self.create_grant("node", "tokyo")
        row = self.conn.execute(
            "SELECT token_hash, role, subject_id, used_at FROM bootstrap_grants"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_hash"], token)
        self.assertEqual(row["token_hash"], self.ns["token_digest"](token))
        self.assertEqual(row["role"], "node")
        self.assertEqual(row["subject_id"], "tokyo")
        self.assertIsNone(row["used_at"])

    def test_consume_bootstrap_grant_succeeds_for_matching_role_and_subject(self):
        token = self.create_grant("node", "tokyo")
        self.assertTrue(self.consume_grant(token, "node", "tokyo"))
        row = self.conn.execute("SELECT used_at FROM bootstrap_grants").fetchone()
        self.assertIsNotNone(row["used_at"])

    def test_consume_bootstrap_grant_is_single_use(self):
        token = self.create_grant("core", "north-america-core")
        self.assertTrue(self.consume_grant(token, "core", "north-america-core"))
        # A second redemption of the exact same grant must never succeed,
        # even though the token, role, and subject are all still correct --
        # this is what makes a captured/leaked grant worthless after its
        # first use, unlike the fleet-wide admin token it replaces.
        self.assertFalse(self.consume_grant(token, "core", "north-america-core"))

    def test_consume_bootstrap_grant_rejects_wrong_role(self):
        token = self.create_grant("node", "tokyo")
        self.assertFalse(self.consume_grant(token, "core", "tokyo"))
        # The grant must still be unconsumed/available for its real role.
        self.assertTrue(self.consume_grant(token, "node", "tokyo"))

    def test_consume_bootstrap_grant_rejects_wrong_subject_id(self):
        token = self.create_grant("node", "tokyo")
        self.assertFalse(self.consume_grant(token, "node", "berlin"))
        self.assertTrue(self.consume_grant(token, "node", "tokyo"))

    def test_consume_bootstrap_grant_rejects_wrong_token(self):
        self.create_grant("node", "tokyo")
        self.assertFalse(self.consume_grant("a-completely-different-token", "node", "tokyo"))

    def test_consume_bootstrap_grant_rejects_empty_or_missing_token(self):
        self.create_grant("node", "tokyo")
        self.assertFalse(self.consume_grant("", "node", "tokyo"))
        self.assertFalse(self.consume_grant(None, "node", "tokyo"))

    def test_consume_bootstrap_grant_rejects_expired_grant(self):
        token = self.create_grant("node", "tokyo")
        expired = (self.ns["utcnow"]() - timedelta(seconds=1)).isoformat()
        self.conn.execute(
            "UPDATE bootstrap_grants SET expires_at = ? WHERE token_hash = ?",
            (expired, self.ns["token_digest"](token)),
        )
        self.assertFalse(self.consume_grant(token, "node", "tokyo"))

    def test_consume_bootstrap_grant_never_matches_across_unrelated_grants(self):
        # Two live grants for different targets must never cross-authorize.
        node_token = self.create_grant("node", "tokyo")
        core_token = self.create_grant("core", "north-america-core")
        self.assertFalse(self.consume_grant(node_token, "core", "north-america-core"))
        self.assertFalse(self.consume_grant(core_token, "node", "tokyo"))
        self.assertTrue(self.consume_grant(node_token, "node", "tokyo"))
        self.assertTrue(self.consume_grant(core_token, "core", "north-america-core"))


class ScopedTokenMatchingTests(unittest.TestCase):
    """Tests for core_token_matches / node_token_matches / require_*_token."""

    def setUp(self):
        self.alerts: list = []
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE nodes (slug TEXT PRIMARY KEY, node_token_hash TEXT, retired_at TEXT, "
            "operator_enabled INTEGER NOT NULL DEFAULT 0)"
        )
        self.conn.execute("CREATE TABLE core_servers (core_id TEXT PRIMARY KEY, core_token_hash TEXT)")
        self.ns = load_gate(self.alerts, self.conn)

    def tearDown(self):
        self.conn.close()

    def test_core_token_matches_only_the_real_token(self):
        matches = self.ns["core_token_matches"]
        digest = self.ns["token_digest"]
        stored = digest("real-core-token")
        self.assertTrue(matches(stored, "real-core-token"))
        self.assertFalse(matches(stored, "guessed-core-token"))
        self.assertFalse(matches(stored, ""))
        self.assertFalse(matches(stored, None))
        self.assertFalse(matches("", "anything"))
        self.assertFalse(matches(None, "anything"))

    def test_node_token_matches_only_the_real_token(self):
        matches = self.ns["node_token_matches"]
        digest = self.ns["token_digest"]
        stored = digest("real-node-token")
        self.assertTrue(matches(stored, "real-node-token"))
        self.assertFalse(matches(stored, "guessed-node-token"))
        self.assertFalse(matches(stored, ""))
        self.assertFalse(matches(stored, None))

    def test_require_core_token_passes_for_the_correct_core(self):
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
            ("north-america-core", digest("core-token-abc")),
        )
        # Must not raise.
        self.ns["require_core_token"](self.conn, "north-america-core", "core-token-abc", None, "test")
        self.assertEqual(self.alerts, [])

    def test_require_core_token_fails_closed_on_mismatch(self):
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
            ("north-america-core", digest("core-token-abc")),
        )
        with self.assertRaises(HTTPException) as ctx:
            self.ns["require_core_token"](self.conn, "north-america-core", "wrong-token", None, "test")
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(self.alerts[0][0], 2)

    def test_require_core_token_fails_closed_for_a_different_cores_token(self):
        # A leaked/guessed token for core A must never authorize as core B.
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
            ("core-a", digest("core-a-token")),
        )
        self.conn.execute(
            "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
            ("core-b", digest("core-b-token")),
        )
        with self.assertRaises(HTTPException):
            self.ns["require_core_token"](self.conn, "core-b", "core-a-token", None, "test")
        self.ns["require_core_token"](self.conn, "core-a", "core-a-token", None, "test")

    def test_require_core_token_fails_closed_when_core_never_bootstrapped(self):
        # No row at all (never exchanged a grant for a token yet).
        with self.assertRaises(HTTPException) as ctx:
            self.ns["require_core_token"](self.conn, "unknown-core", "anything", None, "test")
        self.assertEqual(ctx.exception.status_code, 401)

    def test_require_node_token_passes_for_the_correct_node(self):
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO nodes (slug, node_token_hash) VALUES (?, ?)",
            ("tokyo", digest("node-token-abc")),
        )
        self.ns["require_node_token"](self.conn, "tokyo", "node-token-abc", None, "test")
        self.assertEqual(self.alerts, [])

    def test_require_node_token_fails_closed_on_mismatch(self):
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO nodes (slug, node_token_hash) VALUES (?, ?)",
            ("tokyo", digest("node-token-abc")),
        )
        with self.assertRaises(HTTPException) as ctx:
            self.ns["require_node_token"](self.conn, "tokyo", "wrong-token", None, "test")
        self.assertEqual(ctx.exception.status_code, 401)


class BootstrapEndpointTests(unittest.TestCase):
    """End-to-end tests against the real mint_bootstrap_grant / bootstrap_core /
    bootstrap_node endpoint bodies (async def), proving the fleet-wide admin
    token can mint a grant but a routine node/core endpoint never accepts it,
    and that the grant<->token exchange is correctly scoped and single-use."""

    def setUp(self):
        self.alerts: list = []
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE bootstrap_grants (
                token_hash TEXT PRIMARY KEY, role TEXT NOT NULL,
                subject_id TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
            )
            """
        )
        self.conn.execute(
            "CREATE TABLE nodes (slug TEXT PRIMARY KEY, node_token_hash TEXT, retired_at TEXT, "
            "operator_enabled INTEGER NOT NULL DEFAULT 0)"
        )
        self.conn.execute("CREATE TABLE core_servers (core_id TEXT PRIMARY KEY, core_token_hash TEXT)")
        self.ns = load_gate(self.alerts, self.conn)

    def tearDown(self):
        self.conn.close()

    def run_async(self, coro):
        return asyncio.run(coro)

    def mint(self, role: str, subject_id: str, admin_token: str = ADMIN_SECRET_TOKEN) -> dict:
        payload = SimpleNamespace(role=role, subject_id=subject_id)
        return self.run_async(
            self.ns["mint_bootstrap_grant"](payload, FakeRequest(), admin_token)
        )

    # -- mint_bootstrap_grant: still admin-token-gated, by design ----------

    def test_mint_bootstrap_grant_rejects_wrong_admin_token(self):
        payload = SimpleNamespace(role="node", subject_id="tokyo")
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["mint_bootstrap_grant"](payload, FakeRequest(), "wrong-admin-token"))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_mint_bootstrap_grant_rejects_invalid_role(self):
        payload = SimpleNamespace(role="admin", subject_id="tokyo")
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["mint_bootstrap_grant"](payload, FakeRequest(), ADMIN_SECRET_TOKEN))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_mint_bootstrap_grant_rejects_invalid_subject_id(self):
        payload = SimpleNamespace(role="node", subject_id="../etc/passwd")
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["mint_bootstrap_grant"](payload, FakeRequest(), ADMIN_SECRET_TOKEN))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_mint_bootstrap_grant_returns_a_token_that_can_be_redeemed(self):
        result = self.mint("node", "tokyo")
        self.assertTrue(result["ok"])
        self.assertTrue(result["bootstrap_token"])
        self.assertTrue(
            self.ns["consume_bootstrap_grant"](self.conn, result["bootstrap_token"], "node", "tokyo")
        )

    # -- bootstrap_core: grant-gated, never admin-token-gated ---------------

    def test_bootstrap_core_never_accepts_the_admin_token_as_a_grant(self):
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_core"](
                    make_grant_payload(ADMIN_SECRET_TOKEN, core_id="north-america-core"),
                    FakeRequest(),
                )
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_core_exchanges_a_valid_grant_for_a_scoped_core_token(self):
        grant = self.mint("core", "north-america-core")["bootstrap_token"]
        result = self.run_async(
            self.ns["bootstrap_core"](
                make_grant_payload(grant, core_id="north-america-core"), FakeRequest()
            )
        )
        self.assertTrue(result["ok"])
        core_token = result["core_token"]
        self.assertTrue(core_token)
        row = self.conn.execute(
            "SELECT core_token_hash FROM core_servers WHERE core_id = ?", ("north-america-core",)
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertTrue(self.ns["core_token_matches"](row["core_token_hash"], core_token))

    def test_bootstrap_core_rejects_an_invalid_core_id(self):
        grant = self.mint("core", "north-america-core")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_core"](
                    make_grant_payload(grant, core_id="Not A Valid Id!"), FakeRequest()
                )
            )
        self.assertEqual(ctx.exception.status_code, 400)

    def test_bootstrap_core_grant_is_single_use(self):
        grant = self.mint("core", "north-america-core")["bootstrap_token"]
        self.run_async(
            self.ns["bootstrap_core"](
                make_grant_payload(grant, core_id="north-america-core"), FakeRequest()
            )
        )
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_core"](
                    make_grant_payload(grant, core_id="north-america-core"), FakeRequest()
                )
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_core_grant_cannot_be_redeemed_for_a_different_core(self):
        grant = self.mint("core", "core-a")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_core"](make_grant_payload(grant, core_id="core-b"), FakeRequest())
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_core_grant_minted_for_a_node_cannot_bootstrap_a_core(self):
        grant = self.mint("node", "north-america-core")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_core"](
                    make_grant_payload(grant, core_id="north-america-core"), FakeRequest()
                )
            )
        self.assertEqual(ctx.exception.status_code, 401)

    # -- bootstrap_node: grant-gated, never admin-token-gated ---------------

    def test_bootstrap_node_never_accepts_the_admin_token_as_a_grant(self):
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(
                self.ns["bootstrap_node"](make_grant_payload(ADMIN_SECRET_TOKEN, slug="tokyo"), FakeRequest())
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_node_exchanges_a_valid_grant_for_a_scoped_node_token(self):
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        result = self.run_async(
            self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest())
        )
        self.assertTrue(result["ok"])
        node_token = result["node_token"]
        self.assertTrue(node_token)
        row = self.conn.execute(
            "SELECT node_token_hash, operator_enabled FROM nodes WHERE slug = ?", ("tokyo",)
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertTrue(self.ns["node_token_matches"](row["node_token_hash"], node_token))
        self.assertEqual(row["operator_enabled"], 0)

    def test_bootstrap_node_token_rotation_preserves_manual_promotion(self):
        self.conn.execute(
            "INSERT INTO nodes (slug, node_token_hash, operator_enabled) VALUES (?, ?, 1)",
            ("tokyo", self.ns["token_digest"]("old-node-token")),
        )
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        result = self.run_async(
            self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest())
        )
        row = self.conn.execute(
            "SELECT node_token_hash, operator_enabled FROM nodes WHERE slug = ?", ("tokyo",)
        ).fetchone()
        self.assertTrue(self.ns["node_token_matches"](row["node_token_hash"], result["node_token"]))
        self.assertEqual(row["operator_enabled"], 1)

    def test_bootstrap_node_requires_a_nonempty_slug(self):
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["bootstrap_node"](make_grant_payload(grant, slug=""), FakeRequest()))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_bootstrap_node_grant_is_single_use(self):
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        self.run_async(self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest()))
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest()))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_node_grant_cannot_be_redeemed_for_a_different_node(self):
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["bootstrap_node"](make_grant_payload(grant, slug="berlin"), FakeRequest()))
        self.assertEqual(ctx.exception.status_code, 401)

    def test_bootstrap_node_grant_minted_for_a_core_cannot_bootstrap_a_node(self):
        grant = self.mint("core", "tokyo")["bootstrap_token"]
        with self.assertRaises(HTTPException) as ctx:
            self.run_async(self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest()))
        self.assertEqual(ctx.exception.status_code, 401)

    # -- full lifecycle: mint -> bootstrap -> routine auth accepts the new
    #    token and never the admin token that minted it -----------------

    def test_full_lifecycle_issues_a_working_scoped_token_the_admin_token_cannot_impersonate(self):
        grant = self.mint("node", "tokyo")["bootstrap_token"]
        node_token = self.run_async(
            self.ns["bootstrap_node"](make_grant_payload(grant, slug="tokyo"), FakeRequest())
        )["node_token"]
        # The freshly bootstrapped node token authenticates routine calls.
        self.ns["require_node_token"](self.conn, "tokyo", node_token, None, "routine")
        # The fleet-wide admin token itself must never pass as this node's
        # own scoped token on a routine node-facing endpoint.
        with self.assertRaises(HTTPException):
            self.ns["require_node_token"](self.conn, "tokyo", ADMIN_SECRET_TOKEN, None, "routine")


class VerifyCoreManagementTunnelTests(unittest.TestCase):
    """H-2 regression coverage for POST /admin/core/verify-management.

    This routine core-scoped endpoint must be core-token-only. It used to
    also accept the fleet-wide ADMIN_TOKEN as an alternative authorization
    path (guarded only by `if not admin_secret_matches(x_admin_token):`
    before falling back to require_core_token), which made that global
    secret a routine credential again on every re-deployment -- exactly
    what H-2 eliminated everywhere else. Both real callers
    (probe_hub_core_management's redeploy reuse-check in
    wins_core_server_setup_ONETOUCH.sh, and the deployed wins-core-sync
    timer agent's verify_management_runtime) already hold their own
    CORE_TOKEN before either can ever reach this endpoint, so there is no
    legitimate routine or documented manual workflow that needs
    ADMIN_TOKEN here; minting a *new* tunnel remains a separate,
    intentionally admin-token-only endpoint
    (POST /admin/core/bootstrap-management-tunnel), unaffected by this."""

    CORE_ID = "north-america-core"

    def setUp(self):
        self.alerts: list = []
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE core_servers (
                core_id TEXT PRIMARY KEY,
                core_token_hash TEXT,
                management_host TEXT,
                management_user TEXT
            )
            """
        )
        self.ns = load_gate(self.alerts, self.conn)

    def tearDown(self):
        self.conn.close()

    def register_core(self, core_token: str) -> None:
        digest = self.ns["token_digest"]
        self.conn.execute(
            "INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
            (self.CORE_ID, digest(core_token)),
        )

    def verify(self, x_core_token: Optional[str]):
        # Keyword, not positional: this must land on x_core_token by name
        # regardless of what other parameters the signature does or does
        # not have, so these tests stay meaningful even if the endpoint's
        # parameter list changes shape again later.
        payload = SimpleNamespace(core_id=self.CORE_ID)
        return self.ns["verify_core_management_tunnel"](payload, FakeRequest(), x_core_token=x_core_token)

    def test_endpoint_no_longer_declares_an_admin_token_parameter(self):
        # Structural proof, not just behavioral: there is no longer any
        # parameter this endpoint could even read a fleet-wide admin token
        # from, matching every sibling require_core_token-only endpoint.
        signature = inspect.signature(self.ns["verify_core_management_tunnel"])
        self.assertNotIn("x_admin_token", signature.parameters)
        self.assertIn("x_core_token", signature.parameters)

    def test_the_exact_former_exploit_call_shape_is_now_structurally_impossible(self):
        # This is exactly how the old vulnerable branch was reached: the
        # fleet-wide admin token supplied as x_admin_token, no core token
        # at all. That call shape must now fail before any request
        # handling logic runs at all, because the parameter is gone --
        # not merely because the value fails some check.
        payload = SimpleNamespace(core_id=self.CORE_ID)
        with self.assertRaises(TypeError):
            self.ns["verify_core_management_tunnel"](
                payload, FakeRequest(), x_admin_token=ADMIN_SECRET_TOKEN
            )

    def test_admin_token_presented_as_the_core_token_is_rejected(self):
        # Defense in depth: the admin secret must not be quietly special-
        # cased anywhere along the core-token comparison path either --
        # require_core_token must reject it exactly like any other wrong
        # value once it is the only token-shaped argument this endpoint
        # has left.
        self.register_core("the-real-core-token")
        with self.assertRaises(HTTPException) as ctx:
            self.verify(ADMIN_SECRET_TOKEN)
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(self.alerts[0][0], 2)

    def test_unregistered_core_is_rejected_even_with_the_admin_token(self):
        # This is the exact scenario the removed comment invoked to justify
        # the admin-token fallback -- "before this core has ever synced
        # (and so before it could hold a core token at all)". Even here,
        # with no core_servers row for this core_id at all, the admin
        # token must still not authorize the call.
        with self.assertRaises(HTTPException) as ctx:
            self.verify(ADMIN_SECRET_TOKEN)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_missing_core_token_is_rejected(self):
        self.register_core("the-real-core-token")
        with self.assertRaises(HTTPException) as ctx:
            self.verify(None)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_the_real_core_token_passes_the_auth_gate(self):
        # Positive control proving the 401s above are because of auth, not
        # because every call fails: with no management_host registered
        # yet, a correctly authenticated call proceeds past auth and fails
        # later on unrelated, unregistered-metadata grounds (409), never
        # on the 401 an authorization failure would raise.
        self.register_core("the-real-core-token")
        with self.assertRaises(HTTPException) as ctx:
            self.verify("the-real-core-token")
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertEqual(self.alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
