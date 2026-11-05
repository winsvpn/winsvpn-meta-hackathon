#!/usr/bin/env python3
"""Hub tests for the 2026-09-29 Fable 5.1 key-custody ruling.

Question 1 (IA-CP-05): devices own their winn/3 static keypair. The hub stores
only winn3_static_public + winn3_inner_v4, mints only on the legacy path behind
WINN3_HUB_MINTED_KEYS_ALLOWED, migrates hub-minted rows by REPLACING the public
key (inner address kept, private NULLed), and never serves a stored private key
to a client that supplied its own. The legacy AWG mint sits behind the same
lever.

Question 2 (IA-CP-06): announcements are signed OFFLINE. The hub verifies an
uploaded envelope against ANNOUNCE_PUBKEY_A1..A3 with a strictly increasing
sequence floor, stores it verbatim, and holds no signer, no key home, no
LoadCredential drop-in and no sweep entry for one.

Like the other *_hub.py suites this exercises the REAL main.py heredoc from the
installer (via test_account_deletion_hub.load_hub). Signatures are produced by
real openssl(1). No test contacts a node, a live hub, or the network.

Run:  python3 server/test_winn3_client_keys_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import base64
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402
import test_winn3_descriptor_hub as dh  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(REPO_ROOT, "server", "wins_control_plane_setup_ONETOUCH.sh")
ADMIN = "test-admin-token"
DEVICE_ID = "device-abcdef0123456789"
ANNOUNCE_DOMAIN = b"winsvpn-announcement/v1"

FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def expect_http(status, fn):
    try:
        fn()
    except HTTPException as exc:
        assert exc.status_code == status, (
            f"expected HTTP {status}, got {exc.status_code}: {exc.detail}")
        return exc
    raise AssertionError(f"expected HTTPException {status}, nothing was raised")


class HeaderedHTTPException(HTTPException):
    """The harness HTTPException drops `headers`; this keeps them."""

    def __init__(self, status_code, detail="", headers=None, **kw):
        super().__init__(status_code, detail)
        self.headers = headers


def pub(seed):
    """A canonical base64 32-byte public key that is not all zero."""
    return base64.b64encode(bytes([seed]) * 31 + b"\x01").decode()


def installer_source():
    with open(INSTALLER, "r", encoding="utf-8") as handle:
        return handle.read()


def main_source():
    return harness._extract_main_block()


# ------------------------------------------------------------------ hubs ---

_KEY_ENV = (
    "WINN3_HUB_MINTED_KEYS_ALLOWED", "ANNOUNCE_REQUIRE_SIGNED",
    "ANNOUNCE_PUBKEY_A1", "ANNOUNCE_PUBKEY_A2", "ANNOUNCE_PUBKEY_A3",
    "WINN3_CANARY_STATIC_PUBLIC", "WINN3_CANARY_NODE_SLUG",
)


def load(**env):
    """A fresh hub + database. Every key-custody variable is cleared first:
    load_hub writes os.environ, so a value from an earlier test would leak."""
    for name in _KEY_ENV:
        os.environ.pop(name, None)
    return dh.load_hub_with_ring(**env)


def v3_node(mod):
    payload_b64, sig_b64 = dh.envelope_for(dh.descriptor_payload())
    dh.seed_node(mod, protocol_version="winn/3", protocol_params_json="{}",
                 descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}))


def config_of(body):
    return body["vpn_config"] if "vpn_config" in body else body["vpnconfig"]


def compat_of(body):
    return body.get("vpnconfig") or {}


def v3(mod, headers=None, **overrides):
    return dh.served_config(mod, request_headers=headers, supports_winn3=True,
                            supports_winn3_descriptor=True, **overrides)


def bearer(body):
    return {"authorization": f"Bearer {body['device_auth_token']}"}


def row(mod, device_id=DEVICE_ID):
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()


def registry(mod, slug="lab-alpha"):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        return mod.winn3_peer_registry_document(conn, slug)


def enrolled(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    dh.arm_activation(mod)
    v3_node(mod)


# ========================= Q1: request validation ==========================


def test_validator_accepts_only_canonical_nonzero_32_bytes(mod):
    good = pub(7)
    assert mod.validate_winn3_static_public(good) == good
    assert mod.validate_winn3_static_public("") == ""
    assert mod.validate_winn3_static_public(None) == ""
    raw = bytes([7]) * 31 + b"\x01"
    noncanonical = base64.b64encode(raw).decode()[:-2] + "F="
    assert base64.b64decode(noncanonical) == raw, "fixture must decode to the same bytes"
    for bad in ("not base64!!", base64.b64encode(b"x" * 31).decode(),
                base64.b64encode(b"x" * 33).decode(),
                base64.b64encode(bytes(32)).decode(), noncanonical):
        exc = expect_http(400, lambda b=bad: mod.validate_winn3_static_public(b))
        assert "Invalid winn3 static public key" in exc.detail
        assert bad not in exc.detail


def _real_pydantic_models():
    """LoginRequest and FreeAccessRequest built with REAL pydantic (the lock
    pins 2.13.5). The harness stubs pydantic, which ignores aliases, so the
    wire spellings can only be proven against the real library. The real
    package is installed in sys.modules only for the duration of this call."""
    import importlib
    from typing import Any, Optional
    saved = {name: mod for name, mod in sys.modules.items()
             if name == "pydantic" or name.startswith("pydantic.")}
    for name in saved:
        del sys.modules[name]
    try:
        pydantic = importlib.import_module("pydantic")
        src = main_source()
        start = src.index("class LoginRequest(BaseModel):")
        end = src.index("\n\n", src.index("class FreeAccessRequest(BaseModel):"))
        namespace = {
            "BaseModel": pydantic.BaseModel, "Field": pydantic.Field,
            "AliasChoices": pydantic.AliasChoices, "ConfigDict": pydantic.ConfigDict,
            "Optional": Optional, "Any": Any,
            "LEGAL_ACCEPTANCE_METHOD_DEFAULT": "test",
        }
        exec(compile(src[start:end], "request_models", "exec"), namespace)
        login_model = namespace["LoginRequest"]
        free_model = namespace["FreeAccessRequest"]
        results = {}
        for label, model, extra in (("login", login_model, {"account_number": "1"}),
                                    ("free", free_model, {})):
            for spelling in ("winn3_static_public", "winn3staticpublic",
                             "supports_winn3_client_key", "supportswinn3clientkey"):
                value = pub(3) if "public" in spelling else True
                req = model.model_validate({"device_id": "d", **extra, spelling: value})
                results[(label, spelling)] = (req.winn3_static_public,
                                              req.supports_winn3_client_key)
            req = model.model_validate({"device_id": "d", **extra,
                                        "supports_winn3_client_key": "true"})
            results[(label, "string")] = req.supports_winn3_client_key
            req = model.model_validate({"device_id": "d", **extra})
            results[(label, "absent")] = (req.winn3_static_public,
                                          req.supports_winn3_client_key)
        return results
    finally:
        for name in [n for n in sys.modules if n == "pydantic" or n.startswith("pydantic.")]:
            del sys.modules[name]
        sys.modules.update(saved)


def test_both_wire_spellings_reach_both_request_models(mod):
    results = _real_pydantic_models()
    for label in ("login", "free"):
        for spelling in ("winn3_static_public", "winn3staticpublic"):
            assert results[(label, spelling)] == (pub(3), None), (label, spelling)
        for spelling in ("supports_winn3_client_key", "supportswinn3clientkey"):
            assert results[(label, spelling)] == (None, True), (label, spelling)
        # Strictness lives in winn3_capability_bool; the model must not coerce.
        assert results[(label, "string")] == "true"
        assert results[(label, "absent")] == (None, None)


def test_malformed_capability_is_refused_not_coerced(mod):
    enrolled(mod)
    exc = expect_http(400, lambda: v3(mod, winn3_static_public=pub(1),
                                      supports_winn3_client_key="true"))
    assert "capability" in exc.detail.lower()
    assert row(mod) is None, "a refused request must not create the device"


def test_winn3_key_must_not_reuse_the_awg_key(mod):
    enrolled(mod)
    awg = "C" * 43 + "="
    expect_http(400, lambda: v3(mod, winn3_static_public=awg))
    assert row(mod) is None


def test_free_path_validates_and_forwards_the_key(mod):
    bad = mod.FreeAccessRequest(device_id="free-device-1",
                                client_public_key=pub(9),
                                winn3_static_public="not base64!!")
    expect_http(400, lambda: mod._prepare_free_login_sync(
        FakeRequest(path="/free/verify"), bad, None))
    src = main_source()
    body = src[src.index("def _prepare_free_login_sync"):src.index("def perform_authenticated_device_logout")]
    assert "winn3_static_public=requested_winn3_static_public or None" in body
    assert "supports_winn3_client_key=free_request.supports_winn3_client_key" in body


# ===================== Q1: client-owned key, end to end =====================


def test_client_key_is_stored_echoed_and_never_answered_with_a_private(mod):
    enrolled(mod)
    mine = pub(21)
    body = v3(mod, winn3_static_public=mine, supports_winn3_client_key=True)
    config = config_of(body)
    assert config["winn3_static_private"] == ""
    assert config["winn3_static_public"] == mine
    assert mod.winn3_inner_router_in_pool(config["winn3_inner_v4"])
    compat = compat_of(body)
    if compat:
        assert compat["winn3staticpublic"] == mine
        assert compat["winn3_static_public"] == mine
        assert compat["winn3staticprivate"] == ""
    stored = row(mod)
    assert stored["winn3_static_public"] == mine
    assert stored["winn3_static_private"] is None
    assert stored["winn3_inner_v4"] == config["winn3_inner_v4"]
    doc = registry(mod)
    assert [p["static_public"] for p in doc["peers"]] == [mine]
    assert doc["peers"][0]["inner_v4"] == config["winn3_inner_v4"]
    # Reconnect with the same key: same address, still no private.
    again = config_of(v3(mod, headers=bearer(body), winn3_static_public=mine,
                         supports_winn3_client_key=True))
    assert again["winn3_inner_v4"] == config["winn3_inner_v4"]
    assert again["winn3_static_private"] == ""
    assert again["winn3_static_public"] == mine


def test_legacy_client_still_gets_a_hub_minted_pair_by_default(mod):
    enrolled(mod)
    config = config_of(v3(mod))
    private_key = config["winn3_static_private"]
    assert len(base64.b64decode(private_key, validate=True)) == 32
    stored = row(mod)
    assert stored["winn3_static_private"] == private_key
    assert config["winn3_static_public"] == stored["winn3_static_public"]


def test_migration_replaces_the_hub_minted_key_and_keeps_the_address(mod):
    """The 13 hub-minted rows on Kansas: next /verify from a client-key build."""
    enrolled(mod)
    first = v3(mod)
    old = config_of(first)
    old_public = row(mod)["winn3_static_public"]
    assert old["winn3_static_private"], "fixture: the row starts hub-minted"
    mine = pub(33)
    body = v3(mod, headers=bearer(first), winn3_static_public=mine,
              supports_winn3_client_key=True)
    config = config_of(body)
    assert config["winn3_inner_v4"] == old["winn3_inner_v4"], "address must be kept"
    assert config["winn3_static_private"] == "", "stored private must never be served"
    assert config["winn3_static_public"] == mine
    stored = row(mod)
    assert stored["winn3_static_private"] is None, "hub copy must be NULLed"
    assert stored["winn3_static_public"] == mine
    keys = [p["static_public"] for p in registry(mod)["peers"]]
    assert mine in keys and old_public not in keys, "old key must stop being admitted"
    serialized = json.dumps(body)
    assert old["winn3_static_private"] not in serialized


def test_migration_happens_even_when_the_request_is_not_served_v3(mod):
    """Adoption is not lazy: a winn/1 request still retires the hub copy."""
    enrolled(mod)
    first = v3(mod)
    inner = config_of(first)["winn3_inner_v4"]
    mine = pub(44)
    # Plain winn/1 capability set against a winn/1 node.
    dh.seed_node(mod, slug="lab-beta", protocol_version="winn/1")
    body = dh.served_config(mod, request_headers=bearer(first), location="lab-beta",
                            winn3_static_public=mine, supports_winn3_client_key=True)
    assert config_of(body)["protocol_version"] == "winn/1"
    assert config_of(body)["winn3_static_private"] == ""
    stored = row(mod)
    assert stored["winn3_static_private"] is None
    assert stored["winn3_static_public"] == mine
    assert stored["winn3_inner_v4"] == inner
    with closing(sqlite3.connect(mod._DB)) as conn:
        queued = {r[0] for r in conn.execute("SELECT node_slug FROM winn3_registry_refreshes")}
    assert "lab-alpha" in queued, "the old node must be republished without the old key"


def test_same_key_resent_after_adoption_blanks_any_private_copy(mod):
    enrolled(mod)
    first = v3(mod)
    stored_public = row(mod)["winn3_static_public"]
    # An older client-key build that adopted the hub pair now sends its public.
    body = v3(mod, headers=bearer(first), winn3_static_public=stored_public,
              supports_winn3_client_key=True)
    assert config_of(body)["winn3_static_private"] == ""
    assert config_of(body)["winn3_static_public"] == stored_public
    assert row(mod)["winn3_static_private"] is None


def test_client_key_build_without_a_public_is_never_minted_for(mod):
    enrolled(mod)
    expect_http(503, lambda: v3(mod, supports_winn3_client_key=True))
    stored = row(mod)
    assert stored is None or not (stored["winn3_static_private"] or "")


def test_flag_off_refuses_the_legacy_winn3_mint(mod):
    mod.WINN3_HUB_MINTED_KEYS_ALLOWED = False
    enrolled(mod)
    expect_http(503, lambda: v3(mod))
    stored = row(mod)
    assert stored is None or not (stored["winn3_static_private"] or "")
    # A client-key build is unaffected by the flag.
    config = config_of(v3(mod, winn3_static_public=pub(55)))
    assert config["winn3_static_private"] == ""
    assert config["winn3_static_public"] == pub(55)


def test_flag_off_refuses_the_legacy_awg_mint(mod):
    mod.WINN3_HUB_MINTED_KEYS_ALLOWED = False
    enrolled(mod)
    exc = expect_http(400, lambda: dh.served_config(mod, client_public_key=None))
    assert exc.detail == "Client public key is required."
    assert row(mod) is None


def test_flag_default_is_on_and_read_from_the_environment(mod):
    assert mod.WINN3_HUB_MINTED_KEYS_ALLOWED is True
    off = load(WINN3_HUB_MINTED_KEYS_ALLOWED="0")
    assert off.WINN3_HUB_MINTED_KEYS_ALLOWED is False
    shutil.rmtree(off._TMPDIR, ignore_errors=True)


def test_awg_stored_private_is_blanked_when_the_client_sends_its_key(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=0)
    dh.arm_activation(mod)
    dh.seed_node(mod)  # winn/1
    first = dh.served_config(mod)
    awg = "C" * 43 + "="
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE devices SET client_private_key = ? WHERE device_id = ?",
                     ("HUB-MINTED-AWG-PRIVATE", DEVICE_ID))
    body = dh.served_config(mod, request_headers=bearer(first), client_public_key=awg)
    assert config_of(body)["client_private_key"] == ""
    assert "HUB-MINTED-AWG-PRIVATE" not in json.dumps(body)
    assert (row(mod)["client_private_key"] or "") == ""


def test_duplicate_key_is_refused_before_anything_is_written(mod):
    """The gateway refuses a whole snapshot holding a duplicate static_public."""
    mod.HTTPException = HeaderedHTTPException
    enrolled(mod)
    taken = pub(66)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip,"
            " client_public_key, last_seen, location_slug, winn3_static_public, winn3_inner_v4)"
            " VALUES ('other-device', '1111-2222-3333', 'Other', '10.8.9.9', ?, ?, 'lab-alpha', ?, '10.10.0.77')",
            (pub(67), mod.utcnow().isoformat(), taken))
    exc = expect_http(409, lambda: v3(mod, winn3_static_public=taken))
    assert exc.headers == {"X-Wins-Error-Code": "winn3_static_public_in_use"}
    assert row(mod) is None
    with closing(sqlite3.connect(mod._DB)) as conn:
        used = conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]
    assert used is None, "the refusal must roll back the activation-key consumption"
    # The admission check is the PRIMARY guard, not the index: it also refuses
    # a request that would never write the key (a new device on a winn/1
    # node), where the UNIQUE backstop has nothing to catch.
    dh.seed_node(mod, slug="lab-beta", protocol_version="winn/1")
    exc = expect_http(409, lambda: dh.served_config(
        mod, location="lab-beta", winn3_static_public=taken))
    assert exc.headers == {"X-Wins-Error-Code": "winn3_static_public_in_use"}
    assert row(mod) is None
    # The canary key is reserved too.
    os.environ["WINN3_CANARY_STATIC_PUBLIC"] = pub(68)
    try:
        expect_http(409, lambda: v3(mod, winn3_static_public=pub(68)))
    finally:
        os.environ.pop("WINN3_CANARY_STATIC_PUBLIC", None)


def test_key_change_on_a_moving_device_earns_no_departure_grace(mod):
    enrolled(mod)
    first = v3(mod)
    old_public = row(mod)["winn3_static_public"]
    payload_b64, sig_b64 = dh.envelope_for(dh.descriptor_payload(node="lab-beta"))
    dh.seed_node(mod, slug="lab-beta", protocol_version="winn/3", protocol_params_json="{}",
                 descriptor_json=json.dumps({"payload": payload_b64, "sig": sig_b64}))
    mine = pub(77)
    v3(mod, headers=bearer(first), location="lab-beta", winn3_static_public=mine,
       supports_winn3_client_key=True)
    with closing(sqlite3.connect(mod._DB)) as conn:
        grants = conn.execute(
            "SELECT static_public FROM winn3_departure_grants WHERE expires_at > 0").fetchall()
    assert all(g[0] != old_public for g in grants), "a replaced key is retired, not graced"
    assert old_public not in json.dumps(registry(mod, "lab-alpha"))


def test_ensure_material_unit_semantics(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=1)
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        device_id = "dev-1111-2222-3333-0"
        cfg = dict(conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone())
        assert mod.ensure_winn3_device_material(conn, dict(cfg), client_owns_key=True) == (
            "", "", "winn3-client-key-required")
        mod.WINN3_HUB_MINTED_KEYS_ALLOWED = False
        assert mod.ensure_winn3_device_material(conn, dict(cfg)) == (
            "", "", "winn3-client-key-required")
        mod.WINN3_HUB_MINTED_KEYS_ALLOWED = True
        inner, private_key, reason = mod.ensure_winn3_device_material(
            conn, cfg, requested_static_public=pub(88))
        assert (private_key, reason) == ("", "winn3-client-key-adopted") and inner
        stored = conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        assert stored["winn3_static_private"] is None
        assert stored["winn3_static_public"] == pub(88)
        again = mod.ensure_winn3_device_material(conn, cfg, requested_static_public=pub(88))
        assert again == (inner, "", "winn3-client-key-on-file")
        moved = mod.ensure_winn3_device_material(conn, cfg, requested_static_public=pub(89))
        assert moved == (inner, "", "winn3-client-key-adopted")
        # A hub copy still on a row whose public the client now sends is
        # dropped by ensure itself, not only by the /verify pre-pass.
        conn.execute("UPDATE devices SET winn3_static_private='HUB-COPY' WHERE device_id=?",
                     (device_id,))
        cfg["winn3_static_private"] = "HUB-COPY"
        assert mod.ensure_winn3_device_material(
            conn, cfg, requested_static_public=pub(89)) == (inner, "", "winn3-client-key-on-file")
        assert conn.execute("SELECT winn3_static_private FROM devices WHERE device_id=?",
                            (device_id,)).fetchone()[0] is None
        # A legacy build on a client-key row: a replacement pair at the SAME
        # address while the flag is on.
        legacy = mod.ensure_winn3_device_material(conn, cfg)
        assert legacy[0] == inner and legacy[2] == "winn3-material-issued"
        assert len(base64.b64decode(legacy[1], validate=True)) == 32
        conn.rollback()


def _index_exists(conn):
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='index' AND name=?",
        (mod_index_name,)).fetchone() is not None


mod_index_name = "idx_devices_winn3_static_public_unique"


def test_unique_index_backstop_is_created_and_enforced(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=2)
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        assert _index_exists(conn)
        conn.execute("UPDATE devices SET winn3_static_public=? WHERE device_id=?",
                     (pub(90), "dev-1111-2222-3333-0"))
        try:
            conn.execute("UPDATE devices SET winn3_static_public=? WHERE device_id=?",
                         (pub(90), "dev-1111-2222-3333-1"))
        except sqlite3.IntegrityError as exc:
            assert mod.winn3_static_public_conflict(exc)
        else:
            raise AssertionError("the UNIQUE backstop let a duplicate through")
        # Empty and NULL are not identities and never collide.
        conn.execute("UPDATE devices SET winn3_static_public='' WHERE device_id=?",
                     ("dev-1111-2222-3333-1",))
        conn.execute("UPDATE devices SET winn3_static_public='' WHERE device_id=?",
                     ("dev-1111-2222-3333-0",))
        conn.rollback()


def test_unique_index_is_skipped_not_crashed_on_existing_duplicates(mod):
    harness.seed_account(mod, account="1111-2222-3333", devices=3)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(f"DROP INDEX {mod_index_name}")
        conn.execute("UPDATE devices SET winn3_static_public=?", (pub(91),))
    records = []
    handler = type("H", (mod.logging.Handler,), {"emit": lambda self, r: records.append(r)})()
    mod.logger.addHandler(handler)
    try:
        with closing(sqlite3.connect(mod._DB)) as conn:
            conn.row_factory = sqlite3.Row
            mod.ensure_schema(conn)  # must not raise
            conn.commit()
            assert not _index_exists(conn)
            assert mod.ensure_unique_winn3_static_publics(conn) is False
    finally:
        mod.logger.removeHandler(handler)
    text = " ".join(r.getMessage() for r in records)
    assert "NOT creating idx_devices_winn3_static_public_unique" in text
    assert "1 winn/3 static public key(s) are stored on 3 device rows" in text
    assert pub(91) not in text, "key values must not be logged"
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        stored = conn.execute("SELECT COUNT(*) FROM devices WHERE winn3_static_public=?",
                              (pub(91),)).fetchone()[0]
        assert stored == 3, "nothing is cleared automatically"
        conn.execute("UPDATE devices SET winn3_static_public=NULL WHERE device_id != ?",
                     ("dev-1111-2222-3333-0",))
        assert mod.ensure_unique_winn3_static_publics(conn) is True
        assert _index_exists(conn)
        conn.commit()


def test_backstop_integrity_error_becomes_409_on_verify(mod):
    """The admission check is bypassed; the index alone must answer 409."""
    mod.HTTPException = HeaderedHTTPException
    enrolled(mod)
    first = v3(mod)
    taken = pub(92)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip,"
            " client_public_key, last_seen, location_slug, winn3_static_public)"
            " VALUES ('other-device', '1111-2222-3333', 'Other', '10.8.9.9', ?, ?, 'lab-alpha', ?)",
            (pub(93), mod.utcnow().isoformat(), taken))
    before = dict(row(mod))
    mod.winn3_static_public_in_use = lambda *a, **k: False
    exc = expect_http(409, lambda: v3(mod, headers=bearer(first), winn3_static_public=taken,
                                      supports_winn3_client_key=True))
    assert exc.headers == {"X-Wins-Error-Code": "winn3_static_public_in_use"}
    after = dict(row(mod))
    assert after["winn3_static_public"] == before["winn3_static_public"]
    assert after["winn3_static_private"] == before["winn3_static_private"]
    # ensure() maps the same conflict to a named reason instead of raising.
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        cfg = dict(conn.execute("SELECT * FROM devices WHERE device_id=?", (DEVICE_ID,)).fetchone())
        assert mod.ensure_winn3_device_material(conn, cfg, requested_static_public=taken) == (
            "", "", "winn3-static-public-in-use")
        # And on the allocation path (no inner address yet).
        conn.execute("UPDATE devices SET winn3_inner_v4=NULL WHERE device_id=?", (DEVICE_ID,))
        cfg["winn3_inner_v4"] = ""
        assert mod.ensure_winn3_device_material(conn, cfg, requested_static_public=taken) == (
            "", "", "winn3-static-public-in-use")
        conn.rollback()


def test_backstop_on_the_allocation_path_answers_409_with_the_code(mod):
    """OI-KEYSAPP-14: a collision the UNIQUE index catches while the hub
    assigns a NEW device its address and key must carry the same 409 +
    X-Wins-Error-Code the app rotates on, not a bare 503."""
    mod.HTTPException = HeaderedHTTPException
    enrolled(mod)
    taken = pub(94)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip,"
            " client_public_key, last_seen, location_slug, winn3_static_public)"
            " VALUES ('other-device', '1111-2222-3333', 'Other', '10.8.9.9', ?, ?, 'lab-alpha', ?)",
            (pub(95), mod.utcnow().isoformat(), taken))
    mod.winn3_static_public_in_use = lambda *a, **k: False
    exc = expect_http(409, lambda: v3(mod, winn3_static_public=taken,
                                      supports_winn3_client_key=True))
    assert exc.headers == {"X-Wins-Error-Code": "winn3_static_public_in_use"}
    assert row(mod) is None, "the refused admission must not persist the device"
    with closing(sqlite3.connect(mod._DB)) as conn:
        used = conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]
    assert used is None, "the refusal must roll back the activation-key consumption"


def test_resolver_refuses_a_private_for_a_client_key(mod):
    src = main_source()
    fn = src[src.index("def resolve_served_winn3_device_config"):src.index("def allocate_core_client_ip")]
    assert '"winn3_static_public": public_key' in fn
    assert "winn3-private-for-client-key" in fn


# ============================ Q2: announcements ============================

_ANN_KEYDIR = tempfile.mkdtemp(prefix="announce-keys-")
ANN_KEYS = {}
ANN_PUBS = {}
for _slot in ("a1", "a2", "a3"):
    _path = os.path.join(_ANN_KEYDIR, f"{_slot}.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", _path],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _der = subprocess.run(["openssl", "pkey", "-in", _path, "-pubout", "-outform", "DER"],
                          check=True, stdout=subprocess.PIPE).stdout
    ANN_KEYS[_slot] = _path
    ANN_PUBS[_slot] = base64.b64encode(_der[-32:]).decode()


def ann_hub(slots=("a1",), **env):
    settings = {f"ANNOUNCE_PUBKEY_{s.upper()}": ANN_PUBS[s] for s in slots}
    settings.update(env)
    return load(**settings)


def ann_sign(payload_bytes, slot="a1", domain=ANNOUNCE_DOMAIN):
    with tempfile.TemporaryDirectory() as work:
        path = os.path.join(work, "m.bin")
        with open(path, "wb") as handle:
            handle.write(domain + b"\x00" + payload_bytes)
        return subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", ANN_KEYS[slot], "-in", path],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout


def ann_payload(text="Hello", seq=1, kid="a1", iat=1700000000, **extra):
    body = {"kid": kid, "seq": seq, "iat": iat, "text": text}
    body.update(extra)
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def ann_envelope(payload_bytes, slot="a1", **kw):
    return (base64.b64encode(payload_bytes).decode(),
            base64.b64encode(ann_sign(payload_bytes, slot, **kw)).decode())


def post(mod, **form):
    form.setdefault("x_admin_token", ADMIN)
    form.setdefault("request", FakeRequest(path="/admin/announce"))
    return mod.set_announcement(**form)


def post_env(mod, payload_bytes, slot="a1", **kw):
    p, s = ann_envelope(payload_bytes, slot, **kw)
    return post(mod, announcement_payload_b64=p, announcement_sig_b64=s)


def fields(mod):
    with closing(sqlite3.connect(mod._DB)) as conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        return mod.announcement_fields(conn)


def test_signed_envelope_is_verified_and_stored_verbatim():
    mod = ann_hub()
    raw = ann_payload("Service notice: all good", seq=5)
    p, s = ann_envelope(raw)
    result = post(mod, announcement_payload_b64=p, announcement_sig_b64=s)
    assert result == {"ok": True, "signed": True, "seq": 5, "kid": "a1"}
    served = fields(mod)
    assert served["announcement"] == "Service notice: all good"
    assert served["announcement_signed"] == {"payload": p, "sig": s}
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def _unchanged_after(mod, fn, status=400):
    before = fields(mod)
    exc = expect_http(status, fn)
    assert fields(mod) == before, "a refusal must write nothing"
    return exc


def test_sequence_must_strictly_increase_and_survives_a_plaintext_clear():
    mod = ann_hub()
    post_env(mod, ann_payload(seq=7))
    for seq in (7, 6, 1):
        exc = _unchanged_after(mod, lambda q=seq: post_env(mod, ann_payload("replay", seq=q)))
        assert "announcement-seq-not-increasing" in exc.detail
    post(mod, msg="plain words")  # ANNOUNCE_REQUIRE_SIGNED=0
    served = fields(mod)
    assert served["announcement"] == "plain words"
    assert "announcement_signed" not in served, "plaintext post clears the envelope"
    _unchanged_after(mod, lambda: post_env(mod, ann_payload("old", seq=7)))
    assert post_env(mod, ann_payload("new", seq=8))["seq"] == 8
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_unprovisioned_slot_and_forgeries_are_refused():
    mod = ann_hub(slots=("a1",))
    exc = _unchanged_after(mod, lambda: post_env(mod, ann_payload(kid="a2"), slot="a2"))
    assert "announcement-key-slot-not-provisioned" in exc.detail
    # Signed by a2's key but labelled a1.
    exc = _unchanged_after(mod, lambda: post_env(mod, ann_payload(kid="a1"), slot="a2"))
    assert "announcement-signature-invalid" in exc.detail
    # Right key, wrong domain (a descriptor-domain signature).
    exc = _unchanged_after(mod, lambda: post_env(
        mod, ann_payload(), domain=b"winsvpn-winn3-descriptor/v1"))
    assert "announcement-signature-invalid" in exc.detail
    # Tampered payload under a genuine signature.
    good_p, good_s = ann_envelope(ann_payload("genuine", seq=3))
    forged = base64.b64encode(ann_payload("forged!", seq=3)).decode()
    exc = _unchanged_after(mod, lambda: post(mod, announcement_payload_b64=forged,
                                             announcement_sig_b64=good_s))
    assert "announcement-signature-invalid" in exc.detail
    # No ring at all.
    bare = load()
    exc = expect_http(400, lambda: post_env(bare, ann_payload()))
    assert "announcement-no-verification-keys-configured" in exc.detail
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)
    shutil.rmtree(bare._TMPDIR, ignore_errors=True)


def test_payload_shape_is_held_to_what_the_client_accepts():
    mod = ann_hub()
    cases = (
        (ann_payload(extra_field=1), "announcement-payload-fields"),
        (ann_payload(seq=True), "announcement-seq-invalid"),
        (ann_payload(seq=0), "announcement-seq-invalid"),
        (ann_payload(iat="now"), "announcement-iat-invalid"),
        (ann_payload(text="   "), "announcement-text-empty"),
        (ann_payload(text="x" * 901), "announcement-text-too-long"),
        (b"[1,2]", "announcement-payload-fields"),
        (b"\xff\xfe", "announcement-payload-not-json"),
    )
    for raw, reason in cases:
        exc = _unchanged_after(mod, lambda r=raw: post_env(mod, r))
        assert reason in exc.detail, (reason, exc.detail)
    assert post_env(mod, ann_payload(text="x" * 900))["signed"] is True
    exc = _unchanged_after(mod, lambda: post(mod, announcement_payload_b64="only-half"))
    assert "announcement-envelope-incomplete" in exc.detail
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_require_signed_refuses_plaintext():
    mod = ann_hub(ANNOUNCE_REQUIRE_SIGNED="1")
    assert mod.ANNOUNCE_REQUIRE_SIGNED is True
    _unchanged_after(mod, lambda: post(mod, msg="unsigned"))
    assert post_env(mod, ann_payload(seq=1))["signed"] is True
    default = ann_hub()
    assert default.ANNOUNCE_REQUIRE_SIGNED is False
    assert post(default, msg="unsigned") == {"ok": True, "signed": False, "seq": None}
    expect_http(400, lambda: post(default))
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)
    shutil.rmtree(default._TMPDIR, ignore_errors=True)


def test_the_hub_holds_no_announcement_signer():
    src = main_source()
    for gone in ("sign_announcement_payload", "announce_signing_key_path",
                 "ANNOUNCE_SIGNING_KEY_ID", "announcement_signing_available",
                 "store_signed_announcement", "announce-sign.key",
                 "CREDENTIALS_DIRECTORY"):
        assert gone not in src, gone
    assert '"-sign"' not in src, "main.py must not sign anything with openssl"
    assert "necessarily warm" not in src
    mod = ann_hub()
    for name in ("sign_announcement_payload", "announce_signing_key_path",
                 "build_announcement_payload"):
        assert not hasattr(mod, name), name
    shutil.rmtree(mod._TMPDIR, ignore_errors=True)


def test_installer_has_no_key_home_dropin_or_sweep_entry():
    src = installer_source()
    for gone in ("install -d -m 700 /etc/winn/announce",
                 "LoadCredential=announce-sign.key",
                 "announcement signing private key (provisioned out of band)",
                 "announcement key directory",
                 "CONTROL_ANNOUNCE_SIGN_KEY"):
        assert gone not in src, gone
    specs = src[src.index("control_secret_path_specs() {"):]
    specs = specs[:specs.index("\n}\n")]
    assert "announce" not in specs
    ws = src[src.index("write_systemd() {"):]
    ws = ws[:ws.index('cat > "${SERVICE_FILE}" <<EOF')]
    assert "retire_hub_announce_signing_home || return 1" in ws


def _bash_fn(src, signature):
    start = src.index(signature)
    depth = 0
    for idx in range(src.index("{", start), len(src)):
        if src[idx] == "{":
            depth += 1
        elif src[idx] == "}":
            depth -= 1
            if depth == 0:
                return src[start:idx + 1]
    raise AssertionError(signature)


_FAKE_SHRED_DIR = tempfile.mkdtemp(prefix="fake-shred-")
with open(os.path.join(_FAKE_SHRED_DIR, "shred"), "w") as _handle:
    # Behaves like shred -u -z for this test: OVERWRITES the inode, then
    # unlinks. Real shred(1) is absent on macOS, so without this stub a test of
    # the hard-link rule could not see an overwrite at all.
    _handle.write('#!/bin/sh\nfor f; do :; done\nprintf SHREDDED > "$f" && rm -f -- "$f"\n')
os.chmod(os.path.join(_FAKE_SHRED_DIR, "shred"), 0o755)
_FAILING_SHRED_DIR = tempfile.mkdtemp(prefix="failing-shred-")
with open(os.path.join(_FAILING_SHRED_DIR, "shred"), "w") as _handle:
    _handle.write("#!/bin/sh\nexit 1\n")
os.chmod(os.path.join(_FAILING_SHRED_DIR, "shred"), 0o755)


def _run_retire(announce_dir, dropin, shred_dir=None, extra_path=None, prelude="set -Eeuo pipefail\n"):
    src = installer_source()
    script = (
        prelude
        + 'SERVICE_FILE="/etc/systemd/system/wins-hub.service"\n'
        "log() { printf '[INFO] %s\\n' \"$*\"; }\n"
        "warn() { printf '[WARN] %s\\n' \"$*\"; }\n"
        "err() { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
        + _bash_fn(src, "retire_hub_announce_signing_home() {") + "\n"
        "retire_hub_announce_signing_home\n")
    env = {"PATH": ((extra_path + ":") if extra_path else "") + (shred_dir or _FAKE_SHRED_DIR) + ":"
           + os.environ.get("PATH", "/usr/bin:/bin"),
           "CONTROL_ANNOUNCE_DIR": announce_dir, "CONTROL_ANNOUNCE_DROPIN": dropin}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_retire_removes_the_old_home_and_dropin_and_flags_a_found_key():
    with tempfile.TemporaryDirectory() as raw_work:
        # realpath: on macOS the temp root sits under the /var -> /private/var
        # symlink, which the cleanup now (correctly) refuses as a parent.
        work = os.path.realpath(raw_work)
        home = os.path.join(work, "announce")
        dropin_dir = os.path.join(work, "wins-hub.service.d")
        dropin = os.path.join(dropin_dir, "announce-signing.conf")
        os.makedirs(home)
        os.makedirs(dropin_dir)
        with open(os.path.join(home, "announce-sign.key"), "w") as handle:
            handle.write("KEYBYTES")
        with open(dropin, "w") as handle:
            handle.write("[Service]\nLoadCredential=announce-sign.key:/x\n")
        other = os.path.join(dropin_dir, "other.conf")
        with open(other, "w") as handle:
            handle.write("[Service]\n")
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0, proc.stderr
        assert not os.path.exists(home) and not os.path.exists(dropin)
        assert os.path.exists(other), "only the announcement drop-in is removed"
        assert "SECURITY" in proc.stdout and "EXPOSED" in proc.stdout
        # Honest accounting: either shredded, or reported as removed WITHOUT
        # shredding (macOS has no shred(1)); never a false "shredded".
        assert "SECURITY: 1 file(s) shredded, 0 removed WITHOUT shredding" in proc.stdout, proc.stdout
        assert "0 hard-linked file(s)" in proc.stdout, proc.stdout
        assert "KEYBYTES" not in proc.stdout + proc.stderr
        # Kansas today: the home exists and is empty.
        os.makedirs(home)
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0 and not os.path.exists(home)
        assert "SECURITY" not in proc.stdout
        # Fresh install: nothing there at all.
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0 and proc.stdout == ""
        # OI-KEYSHUB-7, Sol's exact case: a LoadCredential for the announce key
        # in a drop-in OTHER than announce-signing.conf. Refuse, change nothing.
        os.makedirs(home)
        with open(os.path.join(home, "announce-sign.key"), "w") as handle:
            handle.write("KEYBYTES")
        with open(dropin, "w") as handle:
            handle.write("[Service]\n")
        stray = os.path.join(dropin_dir, "zz-credentials.conf")
        with open(stray, "w") as handle:
            handle.write("[Service]\nLoadCredential=announce-sign.key:/etc/winn/announce/announce-sign.key\n")
        proc = _run_retire(home, dropin)
        assert proc.returncode == 1, proc.stdout
        assert "zz-credentials.conf" in proc.stderr
        assert os.path.exists(os.path.join(home, "announce-sign.key")), "nothing may change"
        assert os.path.exists(dropin) and os.path.exists(stray)
        os.remove(stray)
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0 and not os.path.exists(home)
        # A failed shred is reported as removed WITHOUT shredding, never as
        # shredded.
        os.makedirs(home)
        with open(os.path.join(home, "announce-sign.key"), "w") as handle:
            handle.write("KEYBYTES")
        proc = _run_retire(home, dropin, shred_dir=_FAILING_SHRED_DIR)
        assert proc.returncode == 0 and not os.path.exists(home), proc.stderr
        assert "SECURITY: 0 file(s) shredded, 1 removed WITHOUT shredding" in proc.stdout, proc.stdout
        # OI-KEYSHUB-6: a hard link inside the key home is unlinked, NEVER
        # shredded, so the inode reachable from outside keeps its bytes.
        outside = os.path.join(work, "outside-copy.key")
        with open(outside, "w") as handle:
            handle.write("OUTSIDE-BYTES")
        os.makedirs(home)
        os.link(outside, os.path.join(home, "announce-sign.key"))
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0, proc.stderr
        assert not os.path.exists(home)
        with open(outside) as handle:
            assert handle.read() == "OUTSIDE-BYTES", "shred reached an inode outside the key home"
        assert "1 hard-linked file(s) unlinked but NOT shredded" in proc.stdout
        # A key home under a symlinked PARENT is refused before anything changes.
        real_parent = os.path.join(work, "real-parent")
        os.makedirs(os.path.join(real_parent, "announce"))
        with open(os.path.join(real_parent, "announce", "k"), "w") as handle:
            handle.write("x")
        linked_parent = os.path.join(work, "linked-parent")
        os.symlink(real_parent, linked_parent)
        with open(dropin, "w") as handle:
            handle.write("[Service]\n")
        proc = _run_retire(os.path.join(linked_parent, "announce"), dropin)
        assert proc.returncode == 1 and "symlinked parent" in proc.stderr
        assert os.path.exists(os.path.join(real_parent, "announce", "k"))
        assert os.path.exists(dropin), "the refusal must come before the drop-in is removed"
        os.remove(dropin)
        # An unreadable other drop-in fails closed too.
        unreadable = os.path.join(dropin_dir, "unreadable.conf")
        with open(unreadable, "w") as handle:
            handle.write("[Service]\n")
        os.chmod(unreadable, 0)
        try:
            if os.geteuid() != 0:
                proc = _run_retire(home, dropin)
                assert proc.returncode == 1 and "unreadable.conf" in proc.stderr
        finally:
            os.chmod(unreadable, 0o644)
            os.remove(unreadable)
        # N-1 (seat C, Turn 2): a subdirectory, or any other non-regular
        # entry, is refused BEFORE anything changes; a key nested inside it
        # would otherwise survive unshredded after the drop-in and the
        # top-level key were already gone.
        os.makedirs(os.path.join(home, "old"))
        with open(os.path.join(home, "announce-sign.key"), "w") as handle:
            handle.write("KEYBYTES")
        with open(os.path.join(home, "old", "announce-sign.key"), "w") as handle:
            handle.write("NESTED")
        with open(dropin, "w") as handle:
            handle.write("[Service]\n")
        proc = _run_retire(home, dropin)
        assert proc.returncode == 1, proc.stdout
        assert os.path.join(home, "old") in proc.stderr and "nothing was changed" in proc.stderr
        assert os.path.exists(os.path.join(home, "announce-sign.key")), "top-level key touched"
        assert os.path.exists(os.path.join(home, "old", "announce-sign.key"))
        assert os.path.exists(dropin), "the drop-in must not be removed before the refusal"
        assert "SECURITY" not in proc.stdout
        shutil.rmtree(os.path.join(home, "old"))
        # A symlink INSIDE the home is refused the same way (it may point at
        # key material elsewhere); its target is untouched.
        target_key = os.path.join(work, "target.key")
        with open(target_key, "w") as handle:
            handle.write("TARGET")
        os.symlink(target_key, os.path.join(home, "pointer.key"))
        proc = _run_retire(home, dropin)
        assert proc.returncode == 1 and "pointer.key" in proc.stderr
        with open(target_key) as handle:
            assert handle.read() == "TARGET"
        os.remove(os.path.join(home, "pointer.key"))
        # A FIFO is a non-regular entry too.
        os.mkfifo(os.path.join(home, "pipe"))
        proc = _run_retire(home, dropin)
        assert proc.returncode == 1 and "pipe" in proc.stderr
        os.remove(os.path.join(home, "pipe"))
        # With only regular files left, the same home is retired normally.
        proc = _run_retire(home, dropin)
        assert proc.returncode == 0 and not os.path.exists(home), proc.stderr
        assert not os.path.exists(dropin)
        # A symlinked home is refused, never followed.
        target = os.path.join(work, "elsewhere")
        os.makedirs(target)
        with open(os.path.join(target, "keep"), "w") as handle:
            handle.write("x")
        os.symlink(target, home)
        proc = _run_retire(home, dropin)
        assert proc.returncode == 1
        assert os.path.exists(os.path.join(target, "keep"))


def _stub_dir(work, name, script):
    path = os.path.join(work, name)
    os.makedirs(path)
    with open(os.path.join(path, script[0]), "w") as handle:
        handle.write(script[1])
    os.chmod(os.path.join(path, script[0]), 0o755)
    return path


class _RetireBox:
    """A key home, a drop-in and a scratch dir for the follow-up cases."""

    def __init__(self, work):
        self.work = work
        self.home = os.path.join(work, "announce")
        self.dropin_dir = os.path.join(work, "wins-hub.service.d")
        self.dropin = os.path.join(self.dropin_dir, "announce-signing.conf")
        os.makedirs(self.dropin_dir)

    def arm(self):
        os.makedirs(self.home, exist_ok=True)
        with open(os.path.join(self.home, "announce-sign.key"), "w") as handle:
            handle.write("KEYBYTES")
        with open(self.dropin, "w") as handle:
            handle.write("[Service]\nLoadCredential=announce-sign.key:/x\n")


def test_retire_refuses_a_failed_listing_before_any_change():
    """Sol N-3 (F-KEYS-2): a failed listing (an I/O error, or find missing)
    never reads as an empty home. Three shapes: no output and status 1, a
    partial listing and status 1, and command-not-found (127)."""
    real_find = shutil.which("find") or "/usr/bin/find"
    stubs = {
        "find-empty-fail": "#!/bin/sh\nexit 1\n",
        "find-partial-fail": "#!/bin/sh\ncase \"$*\" in *'-mindepth 1'*) printf '%s/announce-sign.key\\0' \"$1\"; exit 1 ;; esac\n"
                             f"exec {real_find} \"$@\"\n",
        "find-missing": "#!/bin/sh\necho 'find: command not found' >&2\nexit 127\n",
    }
    with tempfile.TemporaryDirectory() as raw_work:
        box = _RetireBox(os.path.realpath(raw_work))
        for name, body in stubs.items():
            box.arm()
            proc = _run_retire(box.home, box.dropin, extra_path=_stub_dir(box.work, name, ("find", body)))
            assert proc.returncode == 1, (name, proc.stdout, proc.stderr)
            assert "Could not list the retired announcement key home" in proc.stderr, (name, proc.stderr)
            assert "find failed or is not installed" in proc.stderr, (name, proc.stderr)
            assert os.path.exists(box.dropin), f"{name}: the drop-in was removed after a failed listing"
            with open(os.path.join(box.home, "announce-sign.key")) as handle:
                assert handle.read() == "KEYBYTES", name
            assert "SECURITY" not in proc.stdout, name
        # The listing checks its own status: it does not rely on the caller
        # having set pipefail.
        box.arm()
        proc = _run_retire(box.home, box.dropin, prelude="set -Eeu\n",
                           extra_path=os.path.join(box.work, "find-empty-fail"))
        assert proc.returncode == 1 and "find failed or is not installed" in proc.stderr, (proc.stdout, proc.stderr)
        assert os.path.exists(box.dropin), "without caller pipefail the failed listing reached the drop-in removal"


def test_retire_refuses_a_regular_file_at_the_key_home_path():
    """Seat C low note (F-KEYS-2): a regular FILE at the key home path may
    itself be the key. Refused before the drop-in is touched; kept as is."""
    with tempfile.TemporaryDirectory() as raw_work:
        box = _RetireBox(os.path.realpath(raw_work))
        with open(box.home, "w") as handle:
            handle.write("KEYBYTES-AT-HOME-PATH")
        with open(box.dropin, "w") as handle:
            handle.write("[Service]\n")
        proc = _run_retire(box.home, box.dropin)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        assert "exists but is not a directory" in proc.stderr, proc.stderr
        assert os.path.exists(box.dropin), "the drop-in must not be removed before the refusal"
        with open(box.home) as handle:
            assert handle.read() == "KEYBYTES-AT-HOME-PATH"
        # A name with a newline cannot split into another path: refused whole.
        os.remove(box.home)
        box.arm()
        odd = os.path.join(box.home, "a\nb")
        with open(odd, "w") as handle:
            handle.write("x")
        proc = _run_retire(box.home, box.dropin)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        assert "control character in its name" in proc.stderr, proc.stderr
        assert os.path.exists(box.dropin) and os.path.exists(odd)
        assert os.path.exists(os.path.join(box.home, "announce-sign.key"))


def test_retire_refuses_an_entry_that_changed_type_after_the_pre_scan():
    """Seat C low note (F-KEYS-2): the removal loop has no tolerant rm. An
    entry that stops being a regular file between the pre-scan and the
    removal (a concurrent change) is refused loudly. The shred stub turns
    every other regular file in the home into a symlink to an outside file."""
    with tempfile.TemporaryDirectory() as raw_work:
        box = _RetireBox(os.path.realpath(raw_work))
        outside = os.path.join(box.work, "outside.key")
        with open(outside, "w") as handle:
            handle.write("OUTSIDE")
        race_shred = _stub_dir(box.work, "race-shred", ("shred", (
            "#!/bin/sh\nfor f; do :; done\nd=$(dirname \"$f\")\n"
            "printf SHREDDED > \"$f\" && rm -f -- \"$f\"\n"
            "for o in \"$d\"/*; do\n"
            f"  if [ -f \"$o\" ] && [ ! -L \"$o\" ]; then rm -f -- \"$o\"; ln -s {outside} \"$o\"; fi\n"
            "done\n")))
        box.arm()
        with open(os.path.join(box.home, "second.key"), "w") as handle:
            handle.write("SECOND")
        proc = _run_retire(box.home, box.dropin, shred_dir=race_shred)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        assert "stopped being a regular file after the pre-scan" in proc.stderr, proc.stderr
        assert os.path.isdir(box.home), "the home must not be reported removed"
        with open(outside) as handle:
            assert handle.read() == "OUTSIDE", "the symlink target was touched"
        assert "Removed the retired announcement key home" not in proc.stdout
        # Round 2 (seat C N-2): the file already shredded in this run is still
        # reported, and the key still declared EXPOSED, on the refusal path.
        assert "SECURITY: 1 file(s) shredded" in proc.stdout and "EXPOSED" in proc.stdout, proc.stdout


def test_retire_never_shreds_on_an_unconfirmed_link_count():
    """Round 2 (Sol N-2): shred runs only on a link count of exactly 1 that
    find positively reported. A failed, empty or contradictory link-count
    query refuses the file, so an inode also linked outside the key home is
    never overwritten."""
    real_find = shutil.which("find") or "/usr/bin/find"
    shapes = {
        # Round 3 (Sol N-2): both queries succeed and both name the file.
        "links-both-name-it": "*'-maxdepth 0'*) printf '%s\\n' \"$1\"; exit 0 ;;",
        # Round 3 (seat C E3): the exact-1 query names the file but fails.
        "links-one-prints-then-fails": "*'-links +1'*) exit 0 ;; *'-links 1'*) printf '%s\\n' \"$1\"; exit 1 ;;",
        "links-fail": "*'-maxdepth 0'*) exit 1 ;;",
        "links-empty": "*'-maxdepth 0'*) exit 0 ;;",
        "links-many-fail-one-lies": "*'-links +1'*) exit 1 ;; *'-links 1'*) printf '%s\\n' \"$1\"; exit 0 ;;",
    }
    with tempfile.TemporaryDirectory() as raw_work:
        box = _RetireBox(os.path.realpath(raw_work))
        outside = os.path.join(box.work, "outside-link.key")
        for name, case in shapes.items():
            with open(outside, "w") as handle:
                handle.write("OUTSIDE-BYTES")
            box.arm()
            key = os.path.join(box.home, "announce-sign.key")
            os.remove(key)
            os.link(outside, key)
            stub = _stub_dir(box.work, name, ("find", f"#!/bin/sh\ncase \"$*\" in {case} esac\nexec {real_find} \"$@\"\n"))
            proc = _run_retire(box.home, box.dropin, extra_path=stub)
            assert proc.returncode == 1, (name, proc.stdout, proc.stderr)
            assert "Could not confirm the hard-link count" in proc.stderr, (name, proc.stderr)
            assert "neither shredded nor unlinked" in proc.stderr, (name, proc.stderr)
            assert "hard-linked file(s) unlinked" not in proc.stdout, (name, proc.stdout)
            with open(outside) as handle:
                assert handle.read() == "OUTSIDE-BYTES", f"{name}: shred reached an inode linked outside the key home"
            assert os.path.exists(key), name
            os.remove(key)


def _run_custody_writer(extra_env):
    src = installer_source()
    begin = src.index("# --- begin winn3 hub EnvironmentFile writers ---")
    end = src.index("# --- end winn3 hub EnvironmentFile writers ---")
    script = (
        "set -Eeuo pipefail\n"
        'ENV_FILE="/root/vpn_auth.env"\n'
        "err() { printf '[ERR] %s\\n' \"$*\" >&2; }\n"
        "warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
        'env_kv_buffer=""\n'
        "write_env_kv() { env_kv_buffer+=\"$1=$2\"$'\\n'; }\n"
        + src[begin:end] + "\n"
        "write_hub_key_custody_env\n"
        "printf '%s' \"${env_kv_buffer}\"\n")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    env.update(extra_env)
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def dart_reviewed_announce_pubkeys():
    dart = os.path.join(REPO_ROOT, "lib", "announcement_signature.dart")
    if not os.path.exists(dart):
        raise AssertionError(f"lib/ not present at {dart}; copy it in to run this check")
    src = open(dart, encoding="utf-8").read()
    found = dict(re.findall(
        r"const String kReviewedAnnouncementPubkey(A[123]) =\s*'([A-Za-z0-9+/=]+)';", src))
    assert set(found) == {"A1", "A2", "A3"}, found
    return found


def test_installer_writes_the_custody_flags_with_the_ruled_defaults():
    proc = _run_custody_writer({})
    assert proc.returncode == 0, proc.stderr
    assert "WINN3_HUB_MINTED_KEYS_ALLOWED=1\n" in proc.stdout
    assert "ANNOUNCE_REQUIRE_SIGNED=0\n" in proc.stdout
    # Default ring = the reviewed public keys the app compiles in, read from
    # the Dart source itself so the two cannot drift.
    reviewed = dart_reviewed_announce_pubkeys()
    for slot in ("A1", "A2", "A3"):
        assert f"ANNOUNCE_PUBKEY_{slot}={reviewed[slot]}\n" in proc.stdout, slot
    proc = _run_custody_writer({
        "WINN3_HUB_MINTED_KEYS_ALLOWED": "0", "ANNOUNCE_REQUIRE_SIGNED": "1",
        "ANNOUNCE_PUBKEY_A1": ANN_PUBS["a1"], "ANNOUNCE_PUBKEY_A3": ANN_PUBS["a3"]})
    assert proc.returncode == 0, proc.stderr
    assert "WINN3_HUB_MINTED_KEYS_ALLOWED=0\n" in proc.stdout
    assert f"ANNOUNCE_PUBKEY_A1={ANN_PUBS['a1']}\n" in proc.stdout
    assert f"ANNOUNCE_PUBKEY_A3={ANN_PUBS['a3']}\n" in proc.stdout
    for bad in ({"WINN3_HUB_MINTED_KEYS_ALLOWED": "yes"},
                {"ANNOUNCE_REQUIRE_SIGNED": "2"},
                {"ANNOUNCE_PUBKEY_A2": base64.b64encode(b"x" * 31).decode()},
                {"ANNOUNCE_PUBKEY_A1": "--dart-define=WINS_ANNOUNCE_PUBKEY_A1=" + ANN_PUBS["a1"]},
                {"ANNOUNCE_PUBKEY_A1": "-----BEGIN PRIVATE KEY-----"}):
        proc = _run_custody_writer(bad)
        assert proc.returncode != 0, bad
        assert proc.stdout == "", ("nothing may be written on a refusal", bad)


def test_wins_admin_posts_the_envelope_fields():
    src = installer_source()
    admin = src[src.index("cat > /usr/local/bin/wins-admin <<'PYEOF'"):]
    fn = admin[admin.index("def announce():"):admin.index("def maintenance():")]
    assert "'announcement_payload_b64': payload" in fn
    assert "'announcement_sig_b64': sig" in fn
    assert "ANNOUNCE_REQUIRE_SIGNED" in fn


UNIT_TESTS = [
    test_validator_accepts_only_canonical_nonzero_32_bytes,
    test_both_wire_spellings_reach_both_request_models,
    test_malformed_capability_is_refused_not_coerced,
    test_winn3_key_must_not_reuse_the_awg_key,
    test_free_path_validates_and_forwards_the_key,
    test_client_key_is_stored_echoed_and_never_answered_with_a_private,
    test_legacy_client_still_gets_a_hub_minted_pair_by_default,
    test_migration_replaces_the_hub_minted_key_and_keeps_the_address,
    test_migration_happens_even_when_the_request_is_not_served_v3,
    test_same_key_resent_after_adoption_blanks_any_private_copy,
    test_client_key_build_without_a_public_is_never_minted_for,
    test_flag_off_refuses_the_legacy_winn3_mint,
    test_flag_off_refuses_the_legacy_awg_mint,
    test_flag_default_is_on_and_read_from_the_environment,
    test_awg_stored_private_is_blanked_when_the_client_sends_its_key,
    test_duplicate_key_is_refused_before_anything_is_written,
    test_key_change_on_a_moving_device_earns_no_departure_grace,
    test_ensure_material_unit_semantics,
    test_unique_index_backstop_is_created_and_enforced,
    test_unique_index_is_skipped_not_crashed_on_existing_duplicates,
    test_backstop_integrity_error_becomes_409_on_verify,
    test_backstop_on_the_allocation_path_answers_409_with_the_code,
    test_resolver_refuses_a_private_for_a_client_key,
]
PLAIN_TESTS = [
    test_signed_envelope_is_verified_and_stored_verbatim,
    test_sequence_must_strictly_increase_and_survives_a_plaintext_clear,
    test_unprovisioned_slot_and_forgeries_are_refused,
    test_payload_shape_is_held_to_what_the_client_accepts,
    test_require_signed_refuses_plaintext,
    test_the_hub_holds_no_announcement_signer,
    test_installer_has_no_key_home_dropin_or_sweep_entry,
    test_retire_removes_the_old_home_and_dropin_and_flags_a_found_key,
    test_retire_refuses_a_failed_listing_before_any_change,
    test_retire_refuses_a_regular_file_at_the_key_home_path,
    test_retire_refuses_an_entry_that_changed_type_after_the_pre_scan,
    test_retire_never_shreds_on_an_unconfirmed_link_count,
    test_installer_writes_the_custody_flags_with_the_ruled_defaults,
    test_wins_admin_posts_the_envelope_fields,
]


def main():
    asyncio.set_event_loop(asyncio.new_event_loop())
    only = set(sys.argv[1:])
    print("client-owned winn/3 keys and offline-signed announcements")
    try:
        for fn in UNIT_TESTS:
            if only and fn.__name__ not in only:
                continue
            mod = load()
            check(fn.__name__, lambda f=fn, m=mod: f(m))
            shutil.rmtree(mod._TMPDIR, ignore_errors=True)
        for fn in PLAIN_TESTS:
            if only and fn.__name__ not in only:
                continue
            check(fn.__name__, fn)
    finally:
        shutil.rmtree(_ANN_KEYDIR, ignore_errors=True)
        shutil.rmtree(_FAKE_SHRED_DIR, ignore_errors=True)
        shutil.rmtree(_FAILING_SHRED_DIR, ignore_errors=True)
        shutil.rmtree(dh._KEYDIR, ignore_errors=True)
        for name in _KEY_ENV:
            os.environ.pop(name, None)
    total = len(UNIT_TESTS) + len(PLAIN_TESTS)
    ran = PASSED[0] + len(FAILURES)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed, {ran} run, {total} in suite")
    for name, tb in FAILURES:
        print()
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
