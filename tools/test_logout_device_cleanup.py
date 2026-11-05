#!/usr/bin/env python3
"""H-1 follow-up: proves the device_auth_token logout/cleanup mechanism end
to end, against the real embedded control-plane code.

Context: H-1 hardened _persistDeviceAuthTokenRequired (lib/main.dart) so a
freshly issued device_auth_token is durably persisted before login can
succeed. An on-device manual run then exercised
login -> connect -> disconnect -> reconnect -> "Deactivate Device" (logout)
successfully, but that run's *one* immediate /logout HTTP round-trip did not
get a 2xx that time, surfacing the app's own "Server cleanup will retry when
the hub is reachable" fallback message. The owner has said this is not a
regression and not something to re-diagnose by hand again; what is missing
is a controlled, automated, repeatable proof that the underlying mechanism
-- a real device_auth_token issued by /verify (or /free/verify) authorizing
a real /logout (or /free/logout) call that the hub actually processes and
that genuinely deletes the device row -- is sound.

Traced call shape (lib/main.dart / lib/gateway_failover.dart):
  _sendLogoutToHub(freeAccess, accountNumber, deviceId, deviceAuthToken)
    -> skips the call outright if deviceAuthToken is empty (M-5)
    -> headers: Authorization: Bearer <deviceAuthToken>
    -> body: {"account_number": accountNumber, "device_id": deviceId}
    -> POSTs to (freeAccess ? freeLogoutGateways : logoutGateways)(...),
       i.e. "<gateway>/free/logout" or "<gateway>/logout"
    -> returns true only on a 2xx response

Matching FastAPI routes (server/wins_control_plane_setup_ONETOUCH.sh, the
embedded main.py control-plane app):
  POST /logout      -> logout_device(...)      requires require_device_auth_token,
                       then DELETEs the devices row.
  POST /free/logout  -> free_logout_device(...) derives (account_number,
                       synthetic_device_id) from the device identifier via
                       free_identity_for_device(), then delegates to the
                       exact same logout_device().
  POST /verify        -> verify_account(...)    issues a fresh
                       device_auth_token (secrets.token_urlsafe(32), stored
                       only as its sha256 digest) the first time a device
                       row is created, gated by require_verify_authorization
                       (accepts the account's activation secret for a
                       brand-new device -- see issue_activation_secret).
  POST /free/verify   -> verify_free_access(...) upserts the shared
                       free-access user row, then builds a LoginRequest with
                       free_access=True and delegates to the same
                       verify_account().

Technique (mirrors tools/test_bootstrap_grant_auth.py and
tools/test_activation_secret_enrollment_gate.py -- same technique, reused
deliberately for consistency rather than inventing a new one): fastapi and
pydantic are NOT installed in this environment (`python3 -c "import
fastapi"` raises ModuleNotFoundError here), so a real TestClient is not an
option. Instead this AST-parses the embedded main.py source straight out of
the installer shell script and exec()s only the real, unmodified function
definitions it needs into an isolated namespace backed by a temporary
in-memory sqlite3 database -- the exact same functions FastAPI would call,
minus the ASGI/HTTP plumbing FastAPI itself provides (a minimal
HTTPException/Request/BackgroundTasks stand-in fills that gap, same as the
sibling test files). Everything that touches real infrastructure this test
cannot and should not touch (SSH/subprocess peer sync to a live VPN node,
the `wg` CLI, outbound email) is stubbed at that exact boundary; everything
that is the actual security mechanism under test -- rate limiting, the
activation-secret/device-token auth gates, WireGuard-material bookkeeping,
device row creation, token issuance and hashing, and the /logout delete --
runs as the real, unmodified shipped code, so a regression there fails here
too.

No device_auth_token value is ever printed, logged, or embedded in any
assertion message or diagnostic string anywhere in this file -- see
run_endpoint()'s (status, body) return shape and every assertion below: the
only token comparisons are either boolean/length checks, or comparisons
against its sha256 digest (token_digest), never the plaintext against
itself in a way unittest could echo into a failure message.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import unittest
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "server" / "wins_control_plane_setup_ONETOUCH.sh"

TEST_RATE_LIMIT_SECRET = "test-only-rate-limit-secret-for-logout-cleanup"

PAID_ACCOUNT_NUMBER = "1234-5678-9012"
PAID_DEVICE_ID = "paid-account-test-device-0001"
FREE_ACCESS_DEVICE_FINGERPRINT = "free-access-test-device-fingerprint-0001"
TEST_NODE_SLUG = "test-node-1"
TEST_NODE_OBFUSCATION = {
    "Jc": 2,
    "Jmin": 10,
    "Jmax": 30,
    "S1": 16,
    "S2": 80,
    "S3": 16,
    "S4": 0,
    "H1": 11,
    "H2": 22,
    "H3": 33,
    "H4": 44,
}


def embedded_app_source(installer: str) -> str:
    marker = 'cat > "${APP_DIR}/main.py" <<\'PYEOF\''
    start = installer.index(marker)
    start = installer.index("\n", start) + 1
    end = installer.index("\nPYEOF", start)
    return installer[start:end]


def fake_wg_public_key() -> str:
    """A well-formed (base64, 32 raw bytes) but not-a-real-keypair public
    key -- enough to satisfy validate_wireguard_public_key's real shape
    check without ever shelling out to `wg genkey`/`wg pubkey`, and matching
    how the real Dart client always supplies its own client_public_key on
    every /verify and /free/verify call (see _loadOrCreateClientKeyPair in
    lib/main.dart), so generate_wireguard_material (which does shell out) is
    never reached."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def load_functions(source: str, names: set[str], namespace: dict[str, Any]) -> dict[str, Any]:
    tree = ast.parse(source)
    nodes = []
    found: set[str] = set()
    for node in tree.body:
        # ClassDef is accepted alongside the two function kinds because some
        # extracted functions raise/catch an embedded exception type
        # (ObfuscationProfileError); pulling only the functions leaves a latent
        # NameError that surfaces on whichever branch happens to raise first.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in names:
            # Route handlers carry an @app.post(...) decorator; strip it so
            # exec'ing this isolated module never needs a real FastAPI app
            # (same as tools/test_bootstrap_grant_auth.py).
            node.decorator_list = []
            nodes.append(node)
            found.add(node.name)
    if found != names:
        raise AssertionError(f"missing embedded functions: {sorted(names - found)}")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "embedded-logout-cleanup-functions", "exec"), namespace)
    return namespace


class HTTPException(Exception):
    """Minimal stand-in so the embedded functions can be exec'd without a
    real fastapi install; behavior (raise with a status_code/detail) is
    what these tests actually assert, not the exception class's identity.
    Mirrors tools/test_bootstrap_grant_auth.py's HTTPException exactly."""

    def __init__(self, status_code: int = 500, detail: Any = None, headers: Any = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = headers
        super().__init__(detail)


class FakeRequest:
    """Minimal stand-in for a Starlette Request. Header keys must be
    supplied lowercase by the caller, exactly mirroring Starlette's own
    case-insensitive Headers -- see the FakeRequest already used the same
    way in tools/test_activation_secret_enrollment_gate.py."""

    def __init__(self, *, headers=None, client_host="203.0.113.10", path="/", json_body=None):
        self.headers = headers or {}
        self.client = SimpleNamespace(host=client_host)
        self.url = SimpleNamespace(path=path)
        self._json_body = json_body

    async def json(self):
        return self._json_body


class FakeBackgroundTasks:
    """Records scheduled tasks instead of running them -- exactly like real
    FastAPI's BackgroundTasks, which never invokes its callable until after
    the HTTP response is sent. Node/SSH cleanup (remove_peer_from_node) is
    only ever *scheduled* through this by the real code, never actually
    executed by it or by this test -- see fake_sync_peer_to_node below for
    why the one *synchronous* infrastructure call is stubbed instead."""

    def __init__(self):
        self.tasks: list[tuple] = []

    def add_task(self, func, *args, **kwargs):
        self.tasks.append((func, args, kwargs))


# Real, unmodified embedded functions this test exercises. Deliberately
# narrower than "everything verify_account/logout_device might ever touch":
# legal-acceptance bookkeeping, referral payloads, and payment-option
# listings are orthogonal to H-1's device-token issuance/logout mechanism
# (they neither gate it nor are gated by it), so those specific dependencies
# are stubbed in build_namespace below instead of loaded for real -- the
# same "stub infrastructure/peripheral concerns, keep the actual mechanism
# real" split tools/test_bootstrap_grant_auth.py already uses for
# get_db/security_alert/ensure_schema.
FUNCTION_NAMES = {
    "utcnow",
    "security_event_hash",
    "key_fingerprint",
    "alert_failed_login",
    "get_setting",
    "parse_iso_datetime",
    "normalize_account_number",
    "_trusted_forwarded_client_ip",
    "request_origin_bucket_value",
    "device_identity_bucket",
    "rate_limit_bucket",
    "check_rate_limit",
    # C3: /verify now prechecks (read-only) and consumes the failure budget
    # only on a genuine credential failure, so the enrolment path here needs
    # both halves of the split limiter.
    "rate_limit_current_count",
    "precheck_rate_limit",
    "consume_auth_failure",
    "enforce_verify_rate_limits",
    "consume_verify_auth_failure",
    "enforce_free_verify_rate_limits",
    "free_identity_for_device",
    "record_free_access_event",
    "normalized_node_max_peers",
    "node_capacity_snapshot",
    "node_accepts_new_peer",
    "node_is_operator_enabled",
    "platform_can_use_stealth",
    "_fresh_enough",
    "node_data_plane_is_available",
    "node_is_online_and_managed",
    "select_online_node",
    "select_free_node",
    "is_free_node",
    "ObfuscationProfileError",
    "coerce_obfuscation_value",
    "parse_obfuscation",
    "extract_node_host",
    "split_host_port",
    "normalize_private_tunnel_gateway_ipv4",
    "normalize_hostname",
    "parse_aliases",
    "parse_xray_transports",
    "generate_preshared_key",
    "maybe_generate_preshared_key",
    "validate_wireguard_public_key",
    "allocate_internal_ip",
    "token_digest",
    "bearer_token_from_request",
    "device_auth_token_matches",
    "require_device_auth_token",
    "activation_secret_matches",
    "issue_activation_secret",
    "require_verify_authorization",
    "mark_node_management_status",
    "normalize_client_platform",
    "request_client_capabilities",
    "platform_support_metadata",
    "Winn3ContractError",
    "verify_account",
    "verify_free_access",
    "logout_device",
    "free_logout_device",
    "perform_authenticated_device_logout",
    "parse_protocol_params",
}


# Hand-created schema for only the tables the functions above actually
# touch -- same approach as tools/test_bootstrap_grant_auth.py's fake_get_db
# tests, which create just the 2-3 tables each test needs rather than
# running the real (15-table, paypal/referral/legal-seeding) ensure_schema.
# Column lists are copied from create_users_table/create_devices_table/
# create_nodes_table/create_settings_table/create_rate_limits_table/
# create_double_vpn_assignments_table/create_free_access_events_table and the
# additive nodes/device migrations in server/wins_control_plane_setup_ONETOUCH.sh.
# Keep the policy and protocol columns even when a particular test branch only
# reads their defaults: this fixture must fail when the real enrollment query
# starts depending on current schema, rather than silently exercising a legacy
# selection shape that production no longer runs.
SCHEMA_SQL = """
CREATE TABLE users (
    account_number TEXT PRIMARY KEY,
    email TEXT,
    subscriber_name TEXT DEFAULT 'Wins VPN User',
    status TEXT DEFAULT 'active',
    expiration_date TEXT,
    hardware_hash TEXT,
    paypal_subscription_id TEXT,
    paypal_plan_id TEXT,
    paypal_payer_id TEXT,
    paypal_status TEXT,
    paypal_purchase_reference TEXT,
    last_paypal_sync TEXT,
    renewal_source TEXT,
    referral_code TEXT UNIQUE,
    referred_by_account_number TEXT,
    referral_bonus_days INTEGER DEFAULT 0,
    referral_bonus_applied_at TEXT,
    activation_secret_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE devices (
    device_id TEXT PRIMARY KEY,
    account_number TEXT,
    device_model TEXT DEFAULT 'Unknown Android',
    hardware_hash TEXT,
    source_ip_bucket TEXT,
    vpn_internal_ip TEXT UNIQUE,
    client_private_key TEXT,
    client_public_key TEXT,
    preshared_key TEXT,
    last_seen TEXT,
    location_slug TEXT,
    updated_at TEXT,
    device_auth_token_hash TEXT,
    winn3_inner_v4 TEXT,
    winn3_static_private TEXT,
    winn3_static_public TEXT,
    FOREIGN KEY(account_number) REFERENCES users(account_number)
);
CREATE TABLE nodes (
    slug TEXT PRIMARY KEY,
    name TEXT,
    flag TEXT,
    endpoint TEXT,
    tunnel_gateway_ipv4 TEXT,
    stealth_endpoint TEXT,
    public_key TEXT,
    preshared_key TEXT,
    status TEXT DEFAULT 'online',
    last_heartbeat TEXT,
    obfuscation_json TEXT,
    protocol_version TEXT DEFAULT 'winn/1',
    protocol_params_json TEXT,
    data_plane_code_revision TEXT,
    ssh_host TEXT,
    wg_port INTEGER DEFAULT 9110,
    xray_uuid TEXT,
    xray_path TEXT DEFAULT '/wins-stealth-tunnel',
    xray_security TEXT DEFAULT 'none',
    xray_sni TEXT,
    stealth_public_port INTEGER DEFAULT 80,
    xray_inbound_port INTEGER DEFAULT 10085,
    regional_aliases TEXT DEFAULT '[]',
    stealth_transports TEXT DEFAULT '[]',
    awg_rx_bytes INTEGER DEFAULT 0,
    awg_tx_bytes INTEGER DEFAULT 0,
    wan_rx_bytes INTEGER DEFAULT 0,
    wan_tx_bytes INTEGER DEFAULT 0,
    rx_mbps REAL DEFAULT 0,
    tx_mbps REAL DEFAULT 0,
    peer_count INTEGER DEFAULT 0,
    max_peers INTEGER DEFAULT 0,
    free_access_enabled INTEGER DEFAULT 0,
    direct_awg_enabled INTEGER DEFAULT 1,
    operator_enabled INTEGER NOT NULL DEFAULT 1,
    management_status TEXT DEFAULT 'unknown',
    management_checked_at TEXT,
    management_error TEXT,
    data_plane_status TEXT DEFAULT 'unknown',
    data_plane_checked_at TEXT,
    data_plane_ok_at TEXT,
    data_plane_fail_streak INTEGER DEFAULT 0,
    data_plane_error TEXT DEFAULT '',
    data_plane_udp_status TEXT DEFAULT 'unknown',
    data_plane_udp_ok_at TEXT,
    data_plane_udp_fail_streak INTEGER DEFAULT 0,
    data_plane_stealth_status TEXT DEFAULT 'unknown',
    data_plane_stealth_ok_at TEXT,
    data_plane_stealth_fail_streak INTEGER DEFAULT 0,
    data_plane_stealth_tls_status TEXT DEFAULT 'unknown',
    data_plane_stealth_tls_ok_at TEXT,
    data_plane_stealth_tls_fail_streak INTEGER DEFAULT 0,
    winn3_canary_status TEXT DEFAULT 'unknown',
    winn3_canary_checked_at TEXT,
    winn3_canary_ok_at TEXT,
    winn3_canary_error TEXT DEFAULT '',
    node_token_hash TEXT,
    retired_at TEXT,
    winn3_descriptor_json TEXT,
    winn3_admission_json TEXT,
    path_mtu INTEGER,
    carrier_classes TEXT
);
CREATE TABLE system_settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE rate_limits (
    bucket TEXT PRIMARY KEY,
    count INTEGER DEFAULT 0,
    reset_at REAL
);
CREATE TABLE double_vpn_assignments (
    device_id TEXT PRIMARY KEY,
    account_number TEXT,
    core_id TEXT,
    exit_slug TEXT,
    client_public_key TEXT,
    client_ip TEXT UNIQUE,
    preshared_key TEXT,
    status TEXT DEFAULT 'active',
    applied_revision TEXT,
    runtime_validated_at TEXT,
    assigned_at TEXT,
    updated_at TEXT
);
CREATE TABLE free_access_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT,
    account_number TEXT,
    device_id_bucket TEXT,
    source_ip_bucket TEXT,
    client_public_key_fingerprint TEXT,
    platform TEXT,
    device_model TEXT,
    node_slug TEXT,
    stealth_mode INTEGER DEFAULT 0,
    user_agent_hash TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


def build_namespace(conn: sqlite3.Connection, alerts: list) -> dict[str, Any]:
    @contextmanager
    def fake_get_db():
        # Mirrors tools/test_bootstrap_grant_auth.py's fake_get_db: yields
        # the single injected test connection with no separate commit/close.
        # A connection always sees its own writes whether or not they are
        # committed, so assertions after calling an endpoint function still
        # observe them; verify_account's own internal conn.commit() calls
        # (immediately before its "BEGIN IMMEDIATE") still run for real
        # regardless, so this test never depends on that omission to see
        # correct behavior -- it is only here for parity with the
        # established pattern.
        yield conn

    def fake_ensure_schema(_conn):
        # Real ensure_schema creates ~15 tables and seeds unrelated
        # paypal/referral/legal-document state. See SCHEMA_SQL above for
        # what this test creates instead -- exactly the tables the H-1
        # enroll -> logout path actually touches.
        return None

    def fake_security_alert(priority, event_type, request=None, source_ip="", details=None):
        alerts.append((priority, event_type, details or {}))

    def fake_ensure_legal_acceptance_for_activation(*_args, **_kwargs):
        # Legal-acceptance bookkeeping is orthogonal to H-1's device-token
        # issuance/logout mechanism -- see module docstring.
        return None

    def fake_cleanup_stale_devices(_conn, _background_tasks=None):
        return 0

    def fake_sync_peer_to_node(_node_ip, _cfg):
        # The real function shells out (SSH or a local subprocess) to
        # configure AmneziaWG on an actual VPN node -- genuine external
        # infrastructure with no place in an in-process unit test.
        # Returning True simulates the success path so verify_account's own
        # real bookkeeping around it (mark_node_management_status, the
        # device row commit, device_auth_token issuance and the response
        # payload) all still run for real.
        return True

    def fake_remove_peer_from_node(_node_ip, _client_public_key):
        return None

    def fake_generate_wireguard_material():
        # The real function shells out to the `wg` CLI. Every
        # LoginRequest/FreeAccessRequest this test builds supplies its own
        # client_public_key (exactly like the real Dart client always does),
        # so verify_account must never reach this branch; raising loudly
        # here turns any future test change that drops client_public_key
        # into an immediate, obvious failure instead of a silent shell-out.
        raise AssertionError(
            "generate_wireguard_material should not be called when a client_public_key is supplied"
        )

    def fake_account_referral_payload(_conn, _account_number):
        return {
            "referral_code": "",
            "referralcode": "",
            "referral_link": "",
            "referrallink": "",
            "referral_backup_link": "",
            "referralbackuplink": "",
        }

    def fake_payment_options(*_args, **_kwargs):
        return []

    def fake_announcement_fields(*_args, **_kwargs):
        # Site announcement presentation is independent of activation and
        # device cleanup. Returning no announcement preserves the response
        # merge shape without replacing any enrollment or auth operation.
        return {}

    def fake_double_vpn_free_access_enabled(_conn):
        # Every LoginRequest/FreeAccessRequest below sets double_vpn=False,
        # so double_vpn_requested is always False regardless of this value
        # (see verify_account: `login.double_vpn and (...)`) -- this exists
        # only so the name resolves.
        return True

    def fake_smart_router_trigger_for_existing_node(*_args, **_kwargs):
        # Smart Router advice is orthogonal to the enrollment-token and logout
        # contract exercised here. Keep the normal deterministic initiation
        # path so the real endpoint bookkeeping remains under test.
        return "connection_initiation"

    def fake_smart_router_recommend_node(*_args, **_kwargs):
        return None

    def fake_hoppy_effective_device_limit(*_args, **_kwargs):
        return 3

    def fake_data_plane_sql(*_args, **_kwargs):
        # Data-plane health selection is covered by its dedicated tests. This
        # fixture supplies one known-good node and isolates token/logout state.
        return ""

    def fake_resolve_served_winn_protocol(node, **_kwargs):
        # Winn v3 admission/descriptor behavior has its own conformance suite.
        # This fixture registers an explicit Winn v1 node, for which the real
        # resolver's exact result is the fixed tuple below. Assert that
        # precondition so this stub cannot hide a future fixture switch to v3.
        assert str(node["protocol_version"] or "").strip().lower() == "winn/1"
        return "winn/1", {}, "node-not-winn3"

    def fake_resolve_served_winn3_descriptor(node, **kwargs):
        assert str(node["protocol_version"] or "").strip().lower() == "winn/1"
        assert kwargs.get("served_protocol_version") == "winn/1"
        return {}, "protocol-not-winn3"

    def fake_resolve_served_winn3_device_config(_conn, _device_cfg, *, descriptor_envelope):
        assert descriptor_envelope == {}
        return {}, "no-descriptor"

    return {
        "Any": Any,
        "Optional": Optional,
        "sqlite3": sqlite3,
        "hmac": hmac,
        "hashlib": hashlib,
        "secrets": secrets,
        "re": re,
        "json": json,
        "time": time,
        "os": os,
        "base64": base64,
        "ipaddress": ipaddress,
        "datetime": datetime,
        "timedelta": timedelta,
        "timezone": timezone,
        "urllib": urllib,
        "logger": logging.getLogger("test_logout_device_cleanup"),
        "Request": object,
        "BackgroundTasks": object,
        "LoginRequest": SimpleNamespace,
        "FreeAccessRequest": object,
        "HTTPException": HTTPException,
        "get_db": fake_get_db,
        "ensure_schema": fake_ensure_schema,
        "security_alert": fake_security_alert,
        "ensure_legal_acceptance_for_activation": fake_ensure_legal_acceptance_for_activation,
        "cleanup_stale_devices": fake_cleanup_stale_devices,
        "sync_peer_to_node": fake_sync_peer_to_node,
        "remove_peer_from_node": fake_remove_peer_from_node,
        "generate_wireguard_material": fake_generate_wireguard_material,
        "account_referral_payload": fake_account_referral_payload,
        "payment_options": fake_payment_options,
        "announcement_fields": fake_announcement_fields,
        "double_vpn_free_access_enabled": fake_double_vpn_free_access_enabled,
        "smart_router_trigger_for_existing_node": fake_smart_router_trigger_for_existing_node,
        "smart_router_recommend_node": fake_smart_router_recommend_node,
        "_hoppy_effective_device_limit": fake_hoppy_effective_device_limit,
        "data_plane_sql": fake_data_plane_sql,
        "resolve_served_winn_protocol": fake_resolve_served_winn_protocol,
        "resolve_served_winn3_descriptor": fake_resolve_served_winn3_descriptor,
        "resolve_served_winn3_device_config": fake_resolve_served_winn3_device_config,
        # -- test-only constant values, supplied directly rather than
        # extracted from source, exactly like tools/test_bootstrap_grant_auth.py's
        # ADMIN_SECRET_TOKEN/RATE_LIMIT_SECRET/DOUBLE_VPN_CORE_ID --
        "RATE_LIMIT_SECRET": TEST_RATE_LIMIT_SECRET,
        "TRUSTED_PROXY_NETWORKS": (
            ipaddress.ip_network("127.0.0.1/32"),
            ipaddress.ip_network("::1/128"),
        ),
        "VERIFY_IP_RATE_LIMIT_PER_MINUTE": 100000,
        "VERIFY_ACCOUNT_RATE_LIMIT_PER_HOUR": 100000,
        "FREE_VERIFY_IP_RATE_LIMIT_PER_MINUTE": 100000,
        "FREE_VERIFY_DEVICE_RATE_LIMIT_PER_HOUR": 100000,
        "FREE_NEW_DEVICE_RATE_LIMIT_PER_HOUR": 100000,
        "FREE_ACCESS_ACCOUNT_NUMBER": "9999-9999-9999",
        "FREE_ACCESS_LABEL": "Free Server (Limited Speed)",
        "DEFAULT_NODE_MAX_PEERS": 4096,
        "MAX_NODE_MAX_PEERS": 60000,
        "NODE_RUNTIME_PEER_RESERVE": 16,
        "STEALTH_INCAPABLE_PLATFORMS": {"linux"},
        "DATA_PLANE_HARD_STALE_MINUTES": 30,
        "DEFAULT_OBFUSCATION": TEST_NODE_OBFUSCATION,
        "AWG_OBFUSCATION_MAX": 0xFFFFFFFF,
        "AWG_OBFUSCATION_RANGE_KEYS": frozenset({"H1", "H2", "H3", "H4"}),
        "WINN_PROTOCOL_V1": "winn/1",
        "WINN_PROTOCOL_V3": "winn/3",
        "WINN3_CARRIER_DIRECT_AWG": "direct-awg",
        "WINN3_CARRIER_WINN3": "winn3",
        "AWG_PRESHARED_KEYS_ENABLED": False,
        "VPN_CLIENT_POOL_THIRD_OCTET_MAX": 8,
        "APPLE_RELEASE_BLOCKERS": [],
        "DOUBLE_VPN_ENABLED": False,
        "FREE_ACCESS_ENABLED": True,
        "DEVICE_LIMIT": 3,
        "LEGAL_DOCUMENT_VERSION": "test-legal-version",
        "LEGAL_DOCUMENT_HASH": "test-legal-hash",
        "LEGAL_TERMS_URL": "https://example.test/terms",
        "LEGAL_PRIVACY_URL": "https://example.test/privacy",
        "LEGAL_HOLD_HARMLESS_URL": "https://example.test/hold-harmless",
        "LEGAL_LIMITATION_URL": "https://example.test/limitation",
        "WELCOME_MESSAGE_DEFAULT": "Welcome",
    }


def load_gate(conn: sqlite3.Connection, alerts: list) -> dict[str, Any]:
    app = embedded_app_source(INSTALLER.read_text(encoding="utf-8"))
    namespace = build_namespace(conn, alerts)
    load_functions(app, FUNCTION_NAMES, namespace)
    return namespace


class LogoutDeviceCleanupTestCase(unittest.TestCase):
    """Shared fixture: a fresh in-memory DB, one online+free-access-enabled
    test node, and the real embedded functions loaded on top of it."""

    def setUp(self):
        self.alerts: list = []
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)
        self._insert_online_node(TEST_NODE_SLUG)
        self.ns = load_gate(self.conn, self.alerts)

    def tearDown(self):
        self.conn.close()

    def _insert_online_node(self, slug: str) -> None:
        self.conn.execute(
            """
            INSERT INTO nodes (
                slug, name, flag, endpoint, tunnel_gateway_ipv4, public_key,
                obfuscation_json, status, management_status, ssh_host, wg_port,
                max_peers, free_access_enabled, operator_enabled
            ) VALUES (?, ?, '\U0001F310', '198.51.100.10:9110', '10.8.0.1', ?, ?,
                      'online', 'ok', '198.51.100.10', 9110, 10, 1, 1)
            """,
            (
                slug,
                slug.title(),
                fake_wg_public_key(),
                # Regression guard: enrollment now parses the node's complete
                # registered AWG profile atomically and fails closed on a
                # missing profile. Supplying the production default shape
                # keeps that real parser in the path instead of stubbing it.
                json.dumps(TEST_NODE_OBFUSCATION, sort_keys=True),
            ),
        )

    def run_endpoint(self, coro):
        """Runs an embedded async endpoint function and returns
        (status_code, body) -- the literal, correct translation of "HTTP
        response status" at this level: a real FastAPI app turns a normal
        return into an implicit 200 and an HTTPException into its own
        status_code, with no other mechanism in between (there is no real
        ASGI/HTTP stack here -- see module docstring)."""
        try:
            result = asyncio.run(coro)
            return 200, result
        except HTTPException as exc:
            return exc.status_code, exc.detail

    def device_row(self, account_number: str, device_id: str):
        return self.conn.execute(
            "SELECT * FROM devices WHERE account_number = ? AND device_id = ?",
            (account_number, device_id),
        ).fetchone()

    def create_paid_user(self, account_number: str) -> None:
        self.conn.execute(
            "INSERT INTO users (account_number, email, subscriber_name, status, expiration_date, renewal_source) "
            "VALUES (?, 'owner@example.test', 'Test Subscriber', 'active', 'Lifetime Access', 'paypal')",
            (account_number,),
        )


class PaidAccountLogoutReachesHubAndCleansUpDeviceTests(LogoutDeviceCleanupTestCase):
    """Paid-account path: freeLogoutGateways is not involved;
    _sendLogoutToHub(freeAccess: false) posts to logoutGateways, i.e.
    POST <gateway>/logout, handled by logout_device()."""

    def enroll(self, *, activation_secret: str, account_number=PAID_ACCOUNT_NUMBER, device_id=PAID_DEVICE_ID):
        login = SimpleNamespace(
            account_number=account_number,
            device_id=device_id,
            device_fingerprint=device_id,
            device_model="Test Device",
            platform="android",
            app_version="test",
            locale="en_US",
            location="auto",
            stealth_mode=False,
            double_vpn=False,
            client_public_key=fake_wg_public_key(),
            supports_awg=True,
            supports_xray=True,
            supports_split_tunnel=True,
            supports_per_app_split_tunnel=False,
            supports_double_vpn=False,
            free_access=False,
            legal_version="",
            legal_hash="",
            accepted_terms=True,
            accepted_hold_harmless=True,
            accepted_limitation_liability=True,
            accepted_electronic_records=True,
            acceptance_method="test",
        )
        request = FakeRequest(
            headers={"x-wins-activation": activation_secret},
            path="/verify",
        )
        return self.run_endpoint(self.ns["verify_account"](request, login, FakeBackgroundTasks()))

    def logout(self, *, token: str, account_number=PAID_ACCOUNT_NUMBER, device_id=PAID_DEVICE_ID):
        # Exactly mirrors _sendLogoutToHub's real request shape for the paid
        # path: Authorization: Bearer <token>, JSON body
        # {"account_number":..., "device_id":...}, no query params.
        request = FakeRequest(
            headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
            json_body={"account_number": account_number, "device_id": device_id},
        )
        return self.run_endpoint(self.ns["logout_device"](FakeBackgroundTasks(), request))

    def test_verify_issues_a_genuine_device_auth_token_via_the_real_pipeline(self):
        self.create_paid_user(PAID_ACCOUNT_NUMBER)
        activation_secret = self.ns["issue_activation_secret"](self.conn, PAID_ACCOUNT_NUMBER)

        status, body = self.enroll(activation_secret=activation_secret)

        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "authenticated")
        token = body.get("device_auth_token")
        self.assertTrue(token, "verify_account did not issue a device_auth_token")
        self.assertGreaterEqual(len(token), 16)
        self.assertTrue(
            body.get("deviceauthtoken") == token,
            "device_auth_token and deviceauthtoken fields disagree",
        )
        row = self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID)
        self.assertIsNotNone(row, "verify_account did not create the device row")
        # The DB only ever stores a digest, never the plaintext -- and it is
        # the real token_digest function (the same one require_device_auth_token
        # checks against) that must agree, proving this is the actual issued
        # credential rather than test-fixture data dressed up to look right.
        self.assertEqual(row["device_auth_token_hash"], self.ns["token_digest"](token))
        self.assertFalse(
            row["device_auth_token_hash"] == token,
            "device_auth_token_hash must never equal the plaintext token",
        )

    def test_authenticated_logout_reaches_hub_gets_2xx_and_deletes_the_device_row(self):
        self.create_paid_user(PAID_ACCOUNT_NUMBER)
        activation_secret = self.ns["issue_activation_secret"](self.conn, PAID_ACCOUNT_NUMBER)
        _enroll_status, enroll_body = self.enroll(activation_secret=activation_secret)
        token = enroll_body["device_auth_token"]
        # Positive control: the row genuinely exists before logout.
        self.assertIsNotNone(self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID))

        status, body = self.logout(token=token)

        self.assertTrue(200 <= status < 300, f"logout did not return a 2xx status (got {status!r})")
        self.assertEqual(body, {"ok": True})
        # Server-side state genuinely changed: the row is gone, not just a
        # 200 with no real effect.
        self.assertIsNone(
            self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID),
            "device row must actually be deleted by a successful /logout",
        )

    def test_logout_with_a_wrong_token_is_rejected_and_leaves_the_device_row_intact(self):
        self.create_paid_user(PAID_ACCOUNT_NUMBER)
        activation_secret = self.ns["issue_activation_secret"](self.conn, PAID_ACCOUNT_NUMBER)
        self.enroll(activation_secret=activation_secret)
        self.assertIsNotNone(self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID))

        status, _body = self.logout(token="a-completely-wrong-token-0000000000000000")

        self.assertEqual(status, 401)
        # A rejected logout must never delete the device row -- otherwise
        # the 2xx-and-delete assertion above would be meaningless (anyone
        # could delete any device's row with no valid credential at all).
        self.assertIsNotNone(self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID))

    def test_verify_with_a_wrong_activation_secret_is_rejected_and_issues_no_token(self):
        # Confirms the *enrollment* step itself is genuinely gated, not just
        # the logout step -- the whole point of proving "a device_auth_token
        # issued through the REAL enrollment/activation code path" is that
        # the issuance is itself authorized, not incidental.
        self.create_paid_user(PAID_ACCOUNT_NUMBER)
        self.ns["issue_activation_secret"](self.conn, PAID_ACCOUNT_NUMBER)

        status, _body = self.enroll(activation_secret="a-completely-wrong-activation-secret")

        self.assertEqual(status, 401)
        self.assertIsNone(self.device_row(PAID_ACCOUNT_NUMBER, PAID_DEVICE_ID))


class FreeAccessLogoutReachesHubAndCleansUpDeviceTests(LogoutDeviceCleanupTestCase):
    """Free-access path: this is the specific variant the on-device manual
    test that surfaced the "will retry" message actually used.
    _sendLogoutToHub(freeAccess: true) posts to freeLogoutGateways, i.e.
    POST <gateway>/free/logout, handled by free_logout_device() ->
    logout_device() -- a genuinely different gateway/endpoint from the paid
    path above, not just a flag on the same call."""

    def enroll(self, *, device_identifier=FREE_ACCESS_DEVICE_FINGERPRINT):
        free_request = SimpleNamespace(
            device_id=device_identifier,
            device_fingerprint=device_identifier,
            device_model="Test Device",
            platform="android",
            app_version="test",
            locale="en_US",
            location="auto",
            stealth_mode=False,
            double_vpn=False,
            client_public_key=fake_wg_public_key(),
            supports_awg=True,
            supports_xray=True,
            supports_split_tunnel=True,
            supports_per_app_split_tunnel=False,
            supports_double_vpn=False,
            # Keep this fixture synchronized with FreeAccessRequest's current
            # capability surface. False is the explicit Winn v1 client case;
            # verify_free_access still copies all three fields through the real
            # LoginRequest construction before invoking real verify_account.
            supports_winn3=False,
            supports_winn3_spa=False,
            supports_winn3_descriptor=False,
            legal_version="",
            legal_hash="",
            accepted_terms=True,
            accepted_hold_harmless=True,
            accepted_limitation_liability=True,
            accepted_electronic_records=True,
            acceptance_method="test",
        )
        request = FakeRequest(path="/free/verify")
        return self.run_endpoint(self.ns["verify_free_access"](request, free_request, FakeBackgroundTasks()))

    def logout(self, *, token: str, device_identifier=FREE_ACCESS_DEVICE_FINGERPRINT):
        # Exactly mirrors _sendLogoutToHub's real request shape for the free
        # path. The client still sends an "account_number" field (its own
        # _freeAccessAccountNumber constant), but the real /free/logout
        # handler ignores it and derives its own account_number from the
        # device identifier via free_identity_for_device -- deliberately
        # using an obviously-not-that value here to prove the assertions
        # below hold against the *server-derived* identity, not whatever a
        # caller happens to put in the body.
        request = FakeRequest(
            headers={"authorization": f"Bearer {token}", "content-type": "application/json"},
            json_body={"account_number": "client-supplied-value-is-ignored", "device_id": device_identifier},
        )
        return self.run_endpoint(self.ns["free_logout_device"](FakeBackgroundTasks(), request))

    def _free_identity(self, device_identifier=FREE_ACCESS_DEVICE_FINGERPRINT):
        return self.ns["free_identity_for_device"](device_identifier)

    def test_free_verify_issues_a_genuine_device_auth_token_via_the_real_pipeline(self):
        status, body = self.enroll()

        self.assertEqual(status, 200)
        self.assertEqual(body.get("status"), "authenticated")
        self.assertTrue(body.get("free_access"))
        token = body.get("device_auth_token")
        self.assertTrue(token, "verify_free_access did not issue a device_auth_token")
        self.assertGreaterEqual(len(token), 16)
        account_number, synthetic_device_id, _fingerprint = self._free_identity()
        row = self.device_row(account_number, synthetic_device_id)
        self.assertIsNotNone(row, "verify_free_access did not create the device row")
        self.assertEqual(row["device_auth_token_hash"], self.ns["token_digest"](token))
        self.assertFalse(
            row["device_auth_token_hash"] == token,
            "device_auth_token_hash must never equal the plaintext token",
        )

    def test_authenticated_free_logout_reaches_hub_gets_2xx_and_deletes_the_device_row(self):
        _enroll_status, enroll_body = self.enroll()
        token = enroll_body["device_auth_token"]
        account_number, synthetic_device_id, _fingerprint = self._free_identity()
        self.assertIsNotNone(self.device_row(account_number, synthetic_device_id))

        status, body = self.logout(token=token)

        self.assertTrue(200 <= status < 300, f"free logout did not return a 2xx status (got {status!r})")
        self.assertEqual(body, {"ok": True})
        self.assertIsNone(
            self.device_row(account_number, synthetic_device_id),
            "device row must actually be deleted by a successful /free/logout",
        )

    def test_free_logout_with_a_wrong_token_is_rejected_and_leaves_the_device_row_intact(self):
        self.enroll()
        account_number, synthetic_device_id, _fingerprint = self._free_identity()
        self.assertIsNotNone(self.device_row(account_number, synthetic_device_id))

        status, _body = self.logout(token="a-completely-wrong-token-0000000000000000")

        self.assertEqual(status, 401)
        self.assertIsNotNone(self.device_row(account_number, synthetic_device_id))


if __name__ == "__main__":
    unittest.main(verbosity=2)
