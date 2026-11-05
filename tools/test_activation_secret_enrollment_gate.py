#!/usr/bin/env python3
"""Fail-closed regression tests for the H-1 activation-secret enrollment gate.

account_number is a low-entropy identifier (12 digits, typed, emailed,
displayed, shared with support) and must never by itself authorize enrolling
a new device or rotating an existing device's WireGuard public key on
/verify. These tests exercise the real embedded control-plane functions --
require_verify_authorization, activation_secret_matches,
issue_activation_secret, device_auth_token_matches, and
require_device_auth_token -- rather than re-implementing their logic, so a
regression in the shipped code fails here too.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import secrets
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"


def embedded_app_source(installer: str) -> str:
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def load_functions(source: str, names: set[str], namespace: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    found = {node.name for node in functions}
    if found != names:
        raise AssertionError(f"missing embedded functions: {sorted(names - found)}")
    exec(compile(ast.Module(body=functions, type_ignores=[]), "embedded-activation-functions", "exec"), namespace)
    return namespace


def load_constants(source: str, names: set[str], namespace: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(source)
    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names
    ]
    found = {node.targets[0].id for node in assignments}
    if found != names:
        raise AssertionError(f"missing embedded constants: {sorted(names - found)}")
    exec(compile(ast.Module(body=assignments, type_ignores=[]), "embedded-activation-constants", "exec"), namespace)
    return namespace


class HTTPException(Exception):
    """Minimal stand-in so the embedded functions can be exec'd without a
    real fastapi install; behavior (raise on unauthorized) is what these
    tests actually assert, not the exception class's identity."""

    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        super().__init__(detail)


class FakeRequest:
    def __init__(self, headers: Optional[dict[str, str]] = None):
        self.headers = headers or {}


def build_namespace(alerts: list) -> dict[str, Any]:
    return {
        "Optional": Optional,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "_ACTIVATION_SECRET_PEPPER": b"audit-test-only-pepper",
        "sqlite3": sqlite3,
        "hmac": hmac,
        "hashlib": hashlib,
        "secrets": secrets,
        "Request": object,
        "HTTPException": HTTPException,
        "RATE_LIMIT_SECRET": "test-only-rate-limit-secret",
        # security_alert is exercised for its own behavior elsewhere; here we
        # only need to observe that the gate calls it (and with what
        # priority) on every unauthorized path.
        "security_alert": lambda priority, event_type, request=None, source_ip="", details=None: alerts.append(
            (priority, event_type, details or {})
        ),
    }


def load_gate(alerts: list) -> dict[str, Any]:
    app = embedded_app_source(INSTALLER.read_text(encoding="utf-8"))
    namespace = build_namespace(alerts)
    # The gate answers a refused key with the hub's one client-facing wording.
    load_constants(app, {"SETUP_KEY_REFUSED_DETAIL", "SETUP_KEY_REQUIRED_DETAIL"}, namespace)
    load_functions(
        app,
        {
            "security_event_hash",
            "now_utc",
            "_hash_activation_secret",
            "token_digest",
            "bearer_token_from_request",
            "device_auth_token_matches",
            "require_device_auth_token",
            "activation_secret_matches",
            "issue_activation_secret",
            "require_verify_authorization",
        },
        namespace,
    )
    return namespace


def make_device_row(
    conn: sqlite3.Connection,
    *,
    device_id: str,
    public_key: str,
    token_hash: str,
    account_number: str = "1111-2222-3333",
) -> sqlite3.Row:
    conn.execute(
        "INSERT INTO devices (device_id, account_number, client_public_key, device_auth_token_hash) VALUES (?, ?, ?, ?)",
        (device_id, account_number, public_key, token_hash),
    )
    return conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()


class ActivationSecretEnrollmentGateTests(unittest.TestCase):
    def setUp(self):
        self.alerts: list = []
        self.ns = load_gate(self.alerts)
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE devices (
              device_id TEXT PRIMARY KEY, account_number TEXT,
              client_public_key TEXT, device_auth_token_hash TEXT
            )
            """
        )

    def tearDown(self):
        self.conn.close()

    def token_digest(self, value: str) -> str:
        return self.ns["token_digest"](value)

    def require_verify_authorization(self, **kwargs):
        return self.ns["require_verify_authorization"](**kwargs)

    # -- activation_secret_matches / issue_activation_secret --------------

    def test_activation_secret_matches_only_the_real_secret(self):
        matches = self.ns["activation_secret_matches"]
        digest = self.ns["token_digest"]
        stored = digest("correct-secret")
        self.assertTrue(matches(stored, "correct-secret"))
        self.assertFalse(matches(stored, "wrong-secret"))
        self.assertFalse(matches(stored, ""))
        self.assertFalse(matches(stored, None))
        self.assertFalse(matches("", "anything"))
        self.assertFalse(matches(None, "anything"))

    def test_issue_activation_secret_returns_plaintext_and_stores_only_digest(self):
        self.conn.execute("CREATE TABLE users (account_number TEXT PRIMARY KEY, activation_secret_hash TEXT, activation_secret_expires_at TEXT, activation_secret_used_at TEXT)")
        self.conn.execute("INSERT INTO users (account_number) VALUES ('1111-2222-3333')")
        secret = self.ns["issue_activation_secret"](self.conn, "1111-2222-3333")
        row = self.conn.execute(
            "SELECT activation_secret_hash FROM users WHERE account_number = '1111-2222-3333'"
        ).fetchone()
        self.assertTrue(secret)
        self.assertNotEqual(secret, row["activation_secret_hash"])
        self.assertEqual(row["activation_secret_hash"], self.ns["_hash_activation_secret"](secret))
        self.assertTrue(self.ns["activation_secret_matches"](row["activation_secret_hash"], secret))
        self.assertNotEqual(row["activation_secret_hash"], self.token_digest(secret))

    # -- require_verify_authorization: brand-new device -------------------

    def test_new_device_without_activation_secret_is_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=None,
                requested_client_public_key="client-key-a",
                request=FakeRequest(),
                account_number="1111-2222-3333",
            )
        self.assertEqual(ctx.exception.status_code, 401)
        self.assertEqual(len(self.alerts), 1)
        self.assertEqual(self.alerts[0][0], 2)

    def test_new_device_with_correct_activation_secret_is_enrollment(self):
        mode = self.require_verify_authorization(
            activation_secret_hash=self.token_digest("real-secret"),
            device_row=None,
            requested_client_public_key="client-key-a",
            request=FakeRequest(headers={"x-wins-activation": "real-secret"}),
            account_number="1111-2222-3333",
        )
        self.assertEqual(mode, "enrollment")
        self.assertEqual(self.alerts, [])

    def test_new_device_with_wrong_activation_secret_is_rejected(self):
        with self.assertRaises(HTTPException) as ctx:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=None,
                requested_client_public_key="client-key-a",
                request=FakeRequest(headers={"x-wins-activation": "guessed-secret"}),
                account_number="1111-2222-3333",
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_a_refused_key_gets_the_plain_wording_and_a_missing_key_a_different_one(self):
        # One message for a wrong, used, replaced or revoked key; the 401 stays.
        with self.assertRaises(HTTPException) as wrong:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=None,
                requested_client_public_key="client-key-a",
                request=FakeRequest(headers={"x-wins-activation": "guessed-secret"}),
                account_number="1111-2222-3333",
            )
        self.assertEqual(wrong.exception.status_code, 401)
        self.assertEqual(wrong.exception.detail, self.ns["SETUP_KEY_REFUSED_DETAIL"])
        self.assertIn("That setup key is not valid or has already been used.", wrong.exception.detail)
        self.assertNotIn("smart routing", wrong.exception.detail.lower())
        with self.assertRaises(HTTPException) as missing:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=None,
                requested_client_public_key="client-key-a",
                request=FakeRequest(),
                account_number="1111-2222-3333",
            )
        self.assertEqual(missing.exception.status_code, 401)
        self.assertEqual(missing.exception.detail, self.ns["SETUP_KEY_REQUIRED_DETAIL"])
        self.assertNotEqual(missing.exception.detail, wrong.exception.detail)

    def test_account_with_no_activation_secret_issued_yet_cannot_be_enrolled(self):
        # A row created before an activation secret existed (or one that
        # never got a fresh secret) must never fall back to open enrollment.
        with self.assertRaises(HTTPException):
            self.require_verify_authorization(
                activation_secret_hash=None,
                device_row=None,
                requested_client_public_key="client-key-a",
                request=FakeRequest(headers={"x-wins-activation": ""}),
                account_number="1111-2222-3333",
            )

    # -- require_verify_authorization: existing device reconnect ----------

    def test_existing_device_unchanged_key_with_valid_bearer_token_is_device_mode(self):
        token = "device-bearer-token"
        row = make_device_row(
            self.conn, device_id="dev-1", public_key="client-key-a", token_hash=self.token_digest(token)
        )
        mode = self.require_verify_authorization(
            activation_secret_hash=self.token_digest("real-secret"),
            device_row=row,
            requested_client_public_key="client-key-a",
            request=FakeRequest(headers={"authorization": f"Bearer {token}"}),
            account_number="1111-2222-3333",
        )
        self.assertEqual(mode, "device")
        self.assertEqual(self.alerts, [])

    def test_existing_device_wrong_bearer_token_without_activation_secret_is_rejected(self):
        row = make_device_row(
            self.conn,
            device_id="dev-1",
            public_key="client-key-a",
            token_hash=self.token_digest("device-bearer-token"),
        )
        with self.assertRaises(HTTPException) as ctx:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=row,
                requested_client_public_key="client-key-a",
                request=FakeRequest(headers={"authorization": "Bearer stolen-or-guessed-token"}),
                account_number="1111-2222-3333",
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_existing_device_key_rotation_with_valid_bearer_token_alone_is_rejected(self):
        # This is the core H-1 regression: a caller must not be able to
        # replace an existing device's WireGuard public key just because it
        # happens to also hold that device's own bearer token, because a
        # bearer token can leak (logs, a compromised client) independently
        # of the account-level activation secret.
        token = "device-bearer-token"
        row = make_device_row(
            self.conn, device_id="dev-1", public_key="client-key-a", token_hash=self.token_digest(token)
        )
        with self.assertRaises(HTTPException) as ctx:
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=row,
                requested_client_public_key="attacker-supplied-key",
                request=FakeRequest(headers={"authorization": f"Bearer {token}"}),
                account_number="1111-2222-3333",
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_existing_device_key_rotation_with_activation_secret_is_enrollment(self):
        token = "device-bearer-token"
        row = make_device_row(
            self.conn, device_id="dev-1", public_key="client-key-a", token_hash=self.token_digest(token)
        )
        mode = self.require_verify_authorization(
            activation_secret_hash=self.token_digest("real-secret"),
            device_row=row,
            requested_client_public_key="new-legitimate-key",
            request=FakeRequest(headers={"x-wins-activation": "real-secret"}),
            account_number="1111-2222-3333",
        )
        self.assertEqual(mode, "enrollment")

    def test_different_device_row_hardware_hash_reuse_requires_activation_secret(self):
        # Simulates a hardware-hash-bucket match (reinstall) or a
        # device-limit eviction candidate: the resolved device_row belongs
        # to a different device_id than the caller's own bearer token, so
        # it must never satisfy "device" mode even with *some* bearer token
        # attached to the request.
        other_row = make_device_row(
            self.conn,
            device_id="dev-other",
            public_key="other-devices-key",
            token_hash=self.token_digest("other-devices-token"),
        )
        with self.assertRaises(HTTPException):
            self.require_verify_authorization(
                activation_secret_hash=self.token_digest("real-secret"),
                device_row=other_row,
                requested_client_public_key="new-device-key",
                request=FakeRequest(headers={"authorization": "Bearer some-unrelated-token"}),
                account_number="1111-2222-3333",
            )

    # -- require_device_auth_token: fails closed on legacy/missing rows ---

    def test_require_device_auth_token_fails_closed_when_no_hash_on_file(self):
        self.conn.execute(
            "INSERT INTO devices (device_id, account_number, client_public_key, device_auth_token_hash) "
            "VALUES ('dev-legacy', '1111-2222-3333', 'k', '')"
        )
        with self.assertRaises(HTTPException) as ctx:
            self.ns["require_device_auth_token"](
                self.conn, "1111-2222-3333", "dev-legacy", FakeRequest(headers={}), "logout"
            )
        self.assertEqual(ctx.exception.status_code, 401)

    def test_require_device_auth_token_accepts_matching_bearer_token(self):
        token = "device-bearer-token"
        self.conn.execute(
            "INSERT INTO devices (device_id, account_number, client_public_key, device_auth_token_hash) VALUES (?, ?, ?, ?)",
            ("dev-1", "1111-2222-3333", "k", self.token_digest(token)),
        )
        # Must not raise.
        self.ns["require_device_auth_token"](
            self.conn,
            "1111-2222-3333",
            "dev-1",
            FakeRequest(headers={"authorization": f"Bearer {token}"}),
            "logout",
        )


if __name__ == "__main__":
    result = unittest.main(module=__name__, argv=["activation-secret-enrollment-gate"], exit=False, verbosity=2)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("Activation secret enrollment gate tests passed")
