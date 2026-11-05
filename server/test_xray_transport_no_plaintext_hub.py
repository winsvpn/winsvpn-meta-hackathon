#!/usr/bin/env python3
"""Offline hub tests: no plaintext Xray route is served when a TLS route exists.

Nodes register "80:none,443:tls" by default, and the old served order put port
80 first, so the WebSocket path, the Host header and the VLESS header (node
UUID) crossed the client's access network in the clear. The hub now serves only
the TLS routes to clients, keeps the registered list in storage and for the
core-to-exit link, and refuses a TLS registration that no client could attempt
(no DNS-named host candidate). Runs the installer's own hub code through the
account-deletion harness. Network calls to nodes and cores are stubbed; no
network.
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import json
import logging
import os
import sqlite3
import sys
import traceback
from contextlib import closing
from unittest.mock import patch

import test_account_deletion_hub as harness  # noqa: E402
import test_core_dark_start_latch as core_latch  # noqa: E402
import test_data_plane_dark_start_latch as node_latch  # noqa: E402
import test_winn3_serving_hub as serving  # noqa: E402

FAILURES = []
PASSED = [0]
PLAIN = {"port": 80, "security": "none"}
TLS = {"port": 443, "security": "tls"}
DEFAULT = [PLAIN, TLS]
CORE_ENV = {
    "DOUBLE_VPN_ENABLED": "1",
    "DOUBLE_VPN_CORE_INGRESS_ENDPOINT": "192.0.2.50:9210",
    "DOUBLE_VPN_CORE_INGRESS_PUBLIC_KEY": "D" * 43 + "=",
    "DOUBLE_VPN_CORE_EXIT_PUBLIC_KEY": "E" * 43 + "=",
    "DOUBLE_VPN_CORE_STEALTH_ENDPOINT": "core-edge.example.test:80",
    "DOUBLE_VPN_CORE_XRAY_UUID": "11111111-2222-4333-8444-666666666666",
    "DOUBLE_VPN_CORE_STEALTH_TRANSPORTS": json.dumps(DEFAULT),
}


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def quiet(mod):
    for handler in list(mod.logger.handlers):
        handler.close()
        mod.logger.removeHandler(handler)
    mod.logger.addHandler(logging.NullHandler())
    mod.logger.propagate = False
    return mod


def load(**env):
    """load_hub() copies its env into os.environ; drop it again so no test leaks a core config."""
    try:
        return quiet(harness.load_hub(**env))
    finally:
        for key in env:
            os.environ.pop(key, None)


def expect_http_400(fn):
    try:
        fn()
    except harness.HTTPException as exc:
        assert exc.status_code == 400, f"expected 400, got {exc.status_code}: {exc.detail}"
        return exc
    raise AssertionError("expected HTTP 400, the registration was accepted")


def served(mod, **login):
    body = serving.served_config(mod, **login)
    return body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]


def served_xray(mod, transports):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    serving.arm_activation(mod)
    serving.seed_node(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE nodes SET stealth_transports=? WHERE slug='lab-alpha'",
                     (json.dumps(transports),))
    return served(mod, stealth_mode=True)["xray"]


def double_vpn_session(mod):
    """Serve one stealth Double VPN session through the env-configured default core."""
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    serving.arm_activation(mod)
    serving.seed_node(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)  # the default-core upsert under test
        stored = json.loads(conn.execute(
            "SELECT stealth_transports FROM core_servers WHERE core_id=?",
            (mod.DOUBLE_VPN_CORE_ID,)).fetchone()[0])
        # The core has reported its core0 obfuscation profile (SYNC-02 round
        # 2 withholds Double VPN through a core that has not).
        conn.execute(
            "UPDATE core_servers SET status='online', runtime_ready=1, tunnel_gateway_ipv4='10.9.0.1',"
            " obfuscation_json=? WHERE core_id=?",
            (json.dumps(serving.GOOD_OBFUSCATION), mod.DOUBLE_VPN_CORE_ID))
        conn.execute("UPDATE nodes SET stealth_transports=? WHERE slug='lab-alpha'", (json.dumps(DEFAULT),))
        core = dict(conn.execute("SELECT * FROM core_servers WHERE core_id=?",
                                 (mod.DOUBLE_VPN_CORE_ID,)).fetchone())
    mod.select_double_vpn_core = lambda conn: core
    mod.DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = 0
    with patch.object(mod, "_wait_for_core_assignment_ready_sync", return_value=True), \
            patch.object(mod, "sync_winn3_registry_to_node", return_value=True):
        cfg = served(mod, stealth_mode=True, double_vpn=True)
    return stored, cfg


# ---------------------------------------------------------------- serving


def test_default_registration_is_served_tls_only(mod):
    x = served_xray(mod, DEFAULT)
    assert x["transports"] == [TLS], x["transports"]
    # The primary pair is left alone; clients order candidates by the list.
    assert (x["port"], x["security"]) == (80, "none"), (x["port"], x["security"])


def test_plaintext_only_node_is_unchanged(mod):
    x = served_xray(mod, [PLAIN])
    assert x["transports"] == [PLAIN], x["transports"]


def test_strict_registration_keeps_order_and_primary_check(mod):
    assert mod.parse_xray_transports(DEFAULT, 80, "none", strict=True) == DEFAULT
    try:
        mod.parse_xray_transports([TLS, PLAIN], 80, "none", strict=True)
    except ValueError:
        return
    raise AssertionError("strict parsing must still require first == primary")


def test_serving_filter_is_stable_and_idempotent(mod):
    items = [PLAIN, {"port": 8443, "security": "tls"}, {"port": 8080, "security": "none"}, TLS]
    out = mod.parse_xray_transports(items, 80, "none")
    assert out == [items[1], items[3]], out
    assert mod.parse_xray_transports(out, 80, "none") == out
    assert mod.parse_xray_transports(json.dumps(items), 80, "none") == out


# ------------------------------------------------ storage and core-to-exit


def test_default_core_storage_keeps_plaintext_while_serving_tls_only(_unused):
    mod = load(**CORE_ENV)
    stored, cfg = double_vpn_session(mod)
    assert stored == DEFAULT, f"ensure_schema rewrote core_servers.stealth_transports to {stored!r}"
    assert cfg["xray"]["host"] == "core-edge.example.test", cfg["xray"]["host"]
    assert cfg["xray"]["transports"] == [TLS], cfg["xray"]["transports"]


def test_core_exit_assignment_payloads_keep_registered_routes(_unused):
    # Caller-level: the core-to-exit link is server to server and keeps every
    # registered route, in registered order (an accepted, recorded residual).
    mod = load(**CORE_ENV)
    double_vpn_session(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        payloads = mod.active_core_assignment_payloads(conn, mod.DOUBLE_VPN_CORE_ID)
    assert len(payloads) == 1, payloads
    assert payloads[0]["exit_xray_transports"] == DEFAULT, payloads[0]["exit_xray_transports"]


# ------------------------------------------- registration hostname invariant


NODE_IDENTITIES = {}


def register_node(mod, slug, **fields):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute("INSERT OR IGNORE INTO nodes (slug, node_token_hash, operator_enabled) VALUES (?, ?, 0)",
                     (slug, mod.token_digest(node_latch.NODE_TOKEN)))
    payload = node_latch.registration_payload(slug)
    n = NODE_IDENTITIES.setdefault(slug, len(NODE_IDENTITIES) + 20)
    payload.endpoint = f"198.51.100.{n}:9110"
    payload.ssh_host = f"198.51.100.{n}"
    payload.public_key = chr(ord("F") + n % 20) * 43 + "="
    payload.xray_uuid = "11111111-2222-4333-8444-555555555555"
    payload.stealth_transports = DEFAULT
    payload.stealth_public_port = 80
    for key, value in fields.items():
        setattr(payload, key, value)
    return mod.register_node(payload, harness.FakeRequest(path="/api/v1/nodes/register"))


def stored_node_transports(mod, slug):
    with closing(sqlite3.connect(mod._DB)) as conn:
        row = conn.execute("SELECT stealth_transports FROM nodes WHERE slug=?", (slug,)).fetchone()
    return json.loads(row[0]) if row and row[0] else None


def test_node_tls_registration_requires_dns_candidate(_unused):
    mod = load(HIDE_CONTROL_ORIGIN="0")
    exc = expect_http_400(lambda: register_node(mod, "ip-only", stealth_endpoint="203.0.113.7:80", regional_aliases=[]))
    assert "DNS-named" in exc.detail, exc.detail
    assert stored_node_transports(mod, "ip-only") in (None, []), "a refused registration must not be stored"
    register_node(mod, "dns-host", stealth_endpoint="edge.example.test:80", regional_aliases=[])
    assert stored_node_transports(mod, "dns-host") == DEFAULT
    register_node(mod, "ip-host-dns-alias", stealth_endpoint="203.0.113.8:80", regional_aliases=["alias.example.test"])
    assert stored_node_transports(mod, "ip-host-dns-alias") == DEFAULT
    register_node(mod, "ip-plaintext-only", stealth_endpoint="203.0.113.9:80", regional_aliases=[],
                  stealth_transports=[PLAIN])
    assert stored_node_transports(mod, "ip-plaintext-only") == [PLAIN]


def register_core(mod, **fields):
    payload = core_latch.core_registration(mod, runtime_ready=False)
    payload.stealth_transports = DEFAULT
    for key, value in fields.items():
        setattr(payload, key, value)
    return mod.register_core(payload, harness.FakeRequest(path="/api/v1/core/register"),
                             x_core_token=core_latch.CORE_TOKEN)


def test_core_tls_registration_requires_dns_candidate(_unused):
    mod = load(HIDE_CONTROL_ORIGIN="0", DOUBLE_VPN_ENABLED="1")
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute("INSERT INTO core_servers (core_id, core_token_hash) VALUES (?, ?)",
                     (mod.DOUBLE_VPN_CORE_ID, mod.token_digest(core_latch.CORE_TOKEN)))
    exc = expect_http_400(lambda: register_core(mod, stealth_endpoint="203.0.113.7:80", regional_aliases=[]))
    assert "DNS-named" in exc.detail, exc.detail
    register_core(mod, stealth_endpoint="core.example.test:80", regional_aliases=[])
    with closing(sqlite3.connect(mod._DB)) as conn:
        stored = json.loads(conn.execute("SELECT stealth_transports FROM core_servers WHERE core_id=?",
                                         (mod.DOUBLE_VPN_CORE_ID,)).fetchone()[0])
    assert stored == DEFAULT, stored


TESTS = [
    test_default_registration_is_served_tls_only,
    test_plaintext_only_node_is_unchanged,
    test_strict_registration_keeps_order_and_primary_check,
    test_serving_filter_is_stable_and_idempotent,
    test_default_core_storage_keeps_plaintext_while_serving_tls_only,
    test_core_exit_assignment_payloads_keep_registered_routes,
    test_node_tls_registration_requires_dns_candidate,
    test_core_tls_registration_requires_dns_candidate,
]


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    print("Xray served transports without plaintext")
    for fn in TESTS:
        mod = load()
        check(fn.__name__, lambda f=fn, m=mod: f(m))
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
