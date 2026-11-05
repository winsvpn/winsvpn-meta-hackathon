#!/usr/bin/env python3
"""Hub tests for the Hoppy agent Tier 1 control-plane endpoints.

Like test_account_deletion_hub.py this exercises the REAL control-plane source:
the module is extracted from the `cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc
inside wins_control_plane_setup_ONETOUCH.sh and exec'd with the shared harness
stubs. Nothing here is a reimplementation, so a regression in the shipped
installer fails these tests.

What is under test, and why each is a safety property of the design
(docs/design/HOPPY_AGENT_V1_20260811.md):

  * AUTHORISATION -- identity comes from the signed, account-scoped agent
    token, never from the body. A token minted for account A cannot act on
    account B, and no body field can change the target account or action.
  * IDEMPOTENCY -- the endpoints are idempotent on the request id, so a policy
    engine retrying after a lost response cannot double-execute.
  * ACCOUNT-SCOPED DESTINATION -- resend-credentials and reissue-receipt send
    ONLY to the email ALREADY ON FILE. An email/address supplied in the request
    body is ignored. Accepting a body-supplied address would be an account
    take-over, so this is enforced, not assumed.
  * AUDIT -- every mutation writes an append-only audit row with actor
    'hoppy-agent'.
  * PAYLOAD VALIDATION -- device-revoke requires a device_id belonging to the
    account; preferred-server refuses an unknown server/region.

Run:  python3 server/test_hoppy_agent_tier1_hub.py  (from source/wins_vpn)
      python3 test_hoppy_agent_tier1_hub.py        (from source/wins_vpn/server)
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import ast
import asyncio
import inspect
import json
import os
import sqlite3
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest  # noqa: E402

ACCOUNT = "1111-2222-3333"
OTHER = "9999-8888-7777"
HMAC = "16-byte-test-hoppy-hmac-secret"


def _env(**extra):
    env = {
        "HOPPY_AGENT_HMAC": HMAC,
        "DURABILITY_BARRIER_ENABLED": "0",
        "DURABILITY_BARRIER_REQUIRED": "0",
        "HOPPY_AGENT_IP_RATE_LIMIT_PER_MINUTE": "1000",
        "HOPPY_AGENT_ACCOUNT_RATE_LIMIT_PER_HOUR": "1000",
    }
    env.update({k: str(v) for k, v in extra.items()})
    return env


def seed_account(mod, account=ACCOUNT, email=None, devices=2, with_override=False):
    """Create a paid account with active device rows. Returns device ids."""
    if email is None:
        email = f"onfile-{account}@example.test"
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO users (account_number, email, status, expiration_date, referral_code, device_limit_override, preferred_region) "
            "VALUES (?, ?, 'active', ?, ?, ?, ?)",
            (account, email, "2030-01-01T00:00:00",
             f"CODE{account.replace('-', '')}",
             1 if with_override else None,
             None),
        )
        now = mod.utcnow().isoformat()
        ids = []
        for n in range(devices):
            device_id = f"dev-{account}-{n}"
            ids.append(device_id)
            conn.execute(
                "INSERT OR REPLACE INTO devices (device_id, account_number, device_model, client_public_key, last_seen, location_slug, device_auth_token_hash) "
                "VALUES (?, ?, 'Android Test', ?, ?, 'tokyo-a', ?)",
                (device_id, account, f"pubkey-{n}", now, "devhash"),
            )
        if with_override:
            conn.execute("UPDATE users SET device_limit_override = 5 WHERE account_number = ?", (account,))
    return ids


def token(mod, account=ACCOUNT, action=""):
    value, _exp = mod.mint_hoppy_agent_token(account, action)
    return value


def call(mod, path, body, x_token=None, extra_headers=None, client="203.0.113.9"):
    headers = {}
    if x_token:
        headers["x-hoppy-agent-token"] = x_token
    if extra_headers:
        headers.update(extra_headers)
    request = FakeRequest(headers=headers, body=body, client_host=client)
    handler = mod.app.routes[("POST", path)]
    model = _make_model(mod, path, body)
    # The outbox-based endpoints (credentials-resend, receipt-reissue,
    # preferred-server) never schedule background tasks, so their handlers are
    # correctly declared without a BackgroundTasks parameter. Pass it only where
    # the handler is declared to accept it, mirroring FastAPI's injection, so
    # the same call helper works for every Tier 1 route.
    try:
        params = list(inspect.signature(handler).parameters)
    except (TypeError, ValueError):
        params = list(handler.__code__.co_varnames[:handler.__code__.co_argcount])
    if "background_tasks" in params:
        result = handler(request, harness.BackgroundTasks(), model)
        return result, request
    return handler(request, model), request


def _make_model(mod, path, body):
    """Construct the pydantic request object for the given route from a dict."""
    route_models = {
        "/api/agent/v1/device-limit-reset": "HoppyAccountRequest",
        "/api/agent/v1/device-revoke": "HoppyDeviceRevokeRequest",
        "/api/agent/v1/credentials-resend": "HoppyAccountRequest",
        "/api/agent/v1/receipt-reissue": "HoppyAccountRequest",
        "/api/agent/v1/preferred-server": "HoppyPreferredServerRequest",
    }
    name = route_models[path]
    # Extra/unknown fields are intentionally passed (a body-supplied address is
    # ignored, never honoured) so the test that asserts body addresses are
    # ignored carries real teeth.
    return mod.__dict__[name](**body)


def audit_rows(mod, account):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT action, actor, outcome, detail FROM hoppy_agent_audit WHERE account_ref = ?",
            (mod._hoppy_account_ref(account),),
        ).fetchall()
        return [dict(r) for r in rows]


def outbox_targets(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT kind, target_email, status FROM hoppy_agent_mail_outbox ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]


def devices_for(mod, account):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT device_id FROM devices WHERE account_number = ?", (account,)
        ).fetchall()
        return [r["device_id"] for r in rows]


def user_prefs(mod, account):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT preferred_region, preferred_server, device_limit_override FROM users WHERE account_number = ?",
            (account,),
        ).fetchone()
        return dict(row)


def hub_function_ast(name):
    """Return one top-level function from the shipped main.py heredoc."""
    tree = ast.parse(harness._extract_main_block())
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    assert len(matches) == 1, f"expected exactly one shipped {name} function"
    return matches[0]


# ============================== authorisation ==============================


def test_all_five_routes_are_registered():
    mod = harness.load_hub(**_env())
    for path in [
        "/api/agent/v1/device-limit-reset",
        "/api/agent/v1/device-revoke",
        "/api/agent/v1/credentials-resend",
        "/api/agent/v1/receipt-reissue",
        "/api/agent/v1/preferred-server",
    ]:
        assert ("POST", path) in mod.app.routes, path


def test_no_tier2_action_has_an_endpoint():
    # The design draws the line at money, identity and infrastructure. None of
    # these may ever be reachable through the agent surface.
    mod = harness.load_hub(**_env())
    for tier2 in ["refund", "payment", "delete", "email", "prepaid", "server-keys",
                  "node", "key", "credential-admin"]:
        for (method, path) in mod.app.routes:
            if path.startswith("/api/agent/v1/") and tier2.lower() in path.lower():
                raise AssertionError(f"Tier 2 surface leaked: {method} {path}")


def test_configured_requires_hmac():
    mod = harness.load_hub(**_env(HOPPY_AGENT_HMAC=""))
    assert mod.hoppy_agent_enabled() is False
    body = {"account_number": ACCOUNT, "request_id": "r1"}
    try:
        call(mod, "/api/agent/v1/device-limit-reset", body, x_token="whatever")
        raise AssertionError("expected failure when HMAC not configured")
    except harness.HTTPException as exc:
        assert exc.status_code == 503


def test_missing_token_is_rejected():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "r1"}
    try:
        call(mod, "/api/agent/v1/device-limit-reset", body)
        raise AssertionError("expected 401")
    except harness.HTTPException as exc:
        assert exc.status_code == 401


def test_token_for_account_a_cannot_act_on_account_b():
    mod = harness.load_hub(**_env())
    seed_account(mod, ACCOUNT)
    seed_account(mod, OTHER)
    body = {"account_number": OTHER, "request_id": "r1"}
    try:
        call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod, ACCOUNT))
        raise AssertionError("expected 403 account mismatch")
    except harness.HTTPException as exc:
        assert exc.status_code == 403
    # account B's devices untouched
    assert len(devices_for(mod, OTHER)) == 2


def test_token_bound_to_a_different_action_is_rejected():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "r1"}
    try:
        # token minted for device-revoke cannot run device-limit-reset
        call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod, ACCOUNT, "device-revoke"))
        raise AssertionError("expected 403 action mismatch")
    except harness.HTTPException as exc:
        assert exc.status_code == 403


# ============================== device limit reset =========================


def test_device_limit_reset_clears_devices_and_resets_override():
    mod = harness.load_hub(**_env())
    dev = seed_account(mod, with_override=True)
    assert len(devices_for(mod, ACCOUNT)) == 2
    assert user_prefs(mod, ACCOUNT)["device_limit_override"] == 5
    body = {"account_number": ACCOUNT, "request_id": "r1"}
    call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod))
    assert devices_for(mod, ACCOUNT) == []
    assert user_prefs(mod, ACCOUNT)["device_limit_override"] is None
    aud = audit_rows(mod, ACCOUNT)
    assert any(a["action"] == "device-limit-reset" and a["outcome"] == "completed" for a in aud)
    assert all(a["actor"] == "hoppy-agent" for a in aud)


def test_device_limit_reset_is_idempotent_on_request_id():
    mod = harness.load_hub(**_env())
    dev = seed_account(mod, with_override=True)
    body = {"account_number": ACCOUNT, "request_id": "same-req"}
    call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod))
    call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        n = conn.execute("SELECT COUNT(*) AS n FROM hoppy_agent_actions WHERE action='device-limit-reset'").fetchone()["n"]
    assert n == 1
    # exactly one audit row for the mutation (replays do not add another)
    assert len(audit_rows(mod, ACCOUNT)) == 1


# ============================== device revoke ==============================


def test_device_revoke_removes_one_named_device():
    mod = harness.load_hub(**_env())
    dev = seed_account(mod, devices=2)
    target = dev[0]
    body = {"account_number": ACCOUNT, "device_id": target, "request_id": "r2"}
    call(mod, "/api/agent/v1/device-revoke", body, x_token=token(mod))
    remaining = devices_for(mod, ACCOUNT)
    assert target not in remaining
    assert len(remaining) == 1
    assert any(a["action"] == "device-revoke" and a["actor"] == "hoppy-agent" for a in audit_rows(mod, ACCOUNT))


def test_device_revoke_unknown_or_foreign_device_is_404():
    mod = harness.load_hub(**_env())
    seed_account(mod, devices=2)
    for bad in ["no-such-device", "dev-" + OTHER + "-0"]:
        body = {"account_number": ACCOUNT, "device_id": bad, "request_id": f"r-{bad}"}
        try:
            call(mod, "/api/agent/v1/device-revoke", body, x_token=token(mod))
            raise AssertionError(f"expected 404 for {bad}")
        except harness.HTTPException as exc:
            assert exc.status_code == 404
    assert len(devices_for(mod, ACCOUNT)) == 2


def test_device_revoke_requires_device_id():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "r3"}
    try:
        call(mod, "/api/agent/v1/device-revoke", body, x_token=token(mod))
        raise AssertionError("expected 400")
    except harness.HTTPException as exc:
        assert exc.status_code == 400


def test_device_revoke_idempotency_is_bound_to_the_target_device():
    """One request id must not replay a success for a different device."""
    mod = harness.load_hub(**_env())
    first, second = seed_account(mod, devices=2)
    request_id = "same-request-different-device"

    call(
        mod,
        "/api/agent/v1/device-revoke",
        {"account_number": ACCOUNT, "device_id": first, "request_id": request_id},
        x_token=token(mod),
    )
    call(
        mod,
        "/api/agent/v1/device-revoke",
        {"account_number": ACCOUNT, "device_id": second, "request_id": request_id},
        x_token=token(mod),
    )

    assert devices_for(mod, ACCOUNT) == [], (
        "reusing a request_id for a different device replayed the first result "
        "instead of binding idempotency to device_id"
    )
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        action_count = conn.execute(
            "SELECT COUNT(*) FROM hoppy_agent_actions WHERE action = 'device-revoke'"
        ).fetchone()[0]
    assert action_count == 2, "each distinct target device must have its own action claim"


def test_device_revoke_rechecks_replay_inside_the_write_transaction():
    """The lock-closing replay check must precede mutation in the same txn."""
    function = hub_function_ast("hoppy_agent_device_revoke")
    begin_lines = []
    replay_lines = []
    mutation_lines = []
    transaction_end_lines = []

    for node in ast.walk(function):
        if not isinstance(node, ast.Call):
            continue
        called = node.func
        if isinstance(called, ast.Name) and called.id == "_hoppy_try_replay":
            replay_lines.append(node.lineno)
        # Owner ruling 2026-10-25: the device row is deleted (and its setup
        # key returned) by this helper, in the caller's transaction.
        if isinstance(called, ast.Name) and called.id == "deactivate_device_returning_key":
            mutation_lines.append(node.lineno)
        if not isinstance(called, ast.Attribute):
            continue
        if called.attr == "execute" and node.args:
            sql = node.args[0]
            if isinstance(sql, ast.Constant) and isinstance(sql.value, str):
                normalized = " ".join(sql.value.upper().split())
                if normalized == "BEGIN IMMEDIATE":
                    begin_lines.append(node.lineno)
                if normalized.startswith("DELETE FROM DEVICES"):
                    mutation_lines.append(node.lineno)
        if called.attr in {"commit", "rollback"}:
            transaction_end_lines.append(node.lineno)

    assert len(begin_lines) == 1, "device-revoke must acquire exactly one write lock"
    assert len(replay_lines) >= 2, (
        "device-revoke needs a second replay lookup after acquiring BEGIN IMMEDIATE"
    )
    assert len(mutation_lines) == 1, "expected exactly one device deletion mutation"
    begin_line = begin_lines[0]
    mutation_line = mutation_lines[0]
    locked_replays = [line for line in replay_lines if begin_line < line < mutation_line]
    assert locked_replays, (
        "replay lookup must be repeated after BEGIN IMMEDIATE and before device deletion"
    )
    assert not any(begin_line < line < mutation_line for line in transaction_end_lines), (
        "the locked replay lookup and mutation must remain in one transaction"
    )


def test_hoppy_idempotency_storage_is_insert_once_and_fail_closed():
    """A duplicate action claim must fail and must never replace its result."""
    mod = harness.load_hub(**_env())
    first_result = json.dumps({"ok": True, "marker": "first"})
    replacement = json.dumps({"ok": True, "marker": "replacement"})
    idem = mod.hoppy_agent_idempotency_key(ACCOUNT, "device-revoke", "duplicate")

    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        mod._hoppy_store_idempotency(
            conn, idem, ACCOUNT, "device-revoke", "duplicate", first_result
        )
        conn.commit()

        try:
            mod._hoppy_store_idempotency(
                conn, idem, ACCOUNT, "device-revoke", "duplicate", replacement
            )
            conn.commit()
            raise AssertionError(
                "duplicate idempotency storage must fail closed, not overwrite or ignore"
            )
        except sqlite3.IntegrityError:
            conn.rollback()

        stored = conn.execute(
            "SELECT result_json FROM hoppy_agent_actions WHERE idempotency_key = ?",
            (idem,),
        ).fetchone()["result_json"]

    assert stored == first_result, "the first immutable idempotency result was replaced"


# ========================= credentials resend ==============================
# THE mandatory test: an address supplied in the request body must be ignored.
# The target is read ONLY from the account record. Accepting a body address
# would be an account take-over.


def test_credentials_resend_uses_only_the_on_file_email():
    mod = harness.load_hub(**_env())
    seed_account(mod, email="real-on-file@example.test")
    # The body smuggles a different address. It MUST be ignored.
    body = {
        "account_number": ACCOUNT,
        "request_id": "r4",
        "email": "attacker-controlled@example.net",
    }
    call(mod, "/api/agent/v1/credentials-resend", body, x_token=token(mod))
    targets = outbox_targets(mod)
    assert len(targets) == 1
    assert targets[0]["kind"] == "credentials_resend"
    assert targets[0]["target_email"] == "real-on-file@example.test"
    assert targets[0]["target_email"] != "attacker-controlled@example.net"
    assert any(a["action"] == "credentials-resend" and a["actor"] == "hoppy-agent" for a in audit_rows(mod, ACCOUNT))


def test_credentials_resend_is_idempotent_on_request_id():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "same-rid"}
    call(mod, "/api/agent/v1/credentials-resend", body, x_token=token(mod))
    call(mod, "/api/agent/v1/credentials-resend", body, x_token=token(mod))
    assert len(outbox_targets(mod)) == 1


def test_credentials_resend_with_no_email_on_file_is_refused():
    mod = harness.load_hub(**_env())
    seed_account(mod, email="")
    body = {"account_number": ACCOUNT, "request_id": "r5"}
    try:
        call(mod, "/api/agent/v1/credentials-resend", body, x_token=token(mod))
        raise AssertionError("expected 409 when no email on file")
    except harness.HTTPException as exc:
        assert exc.status_code == 409


# ============================== receipt reissue =============================


def test_receipt_reissue_uses_only_the_on_file_email():
    mod = harness.load_hub(**_env())
    seed_account(mod, email="receipt-on-file@example.test")
    body = {
        "account_number": ACCOUNT,
        "request_id": "r6",
        "email": "steal-my-receipt@example.net",
    }
    call(mod, "/api/agent/v1/receipt-reissue", body, x_token=token(mod))
    targets = outbox_targets(mod)
    assert len(targets) == 1
    assert targets[0]["kind"] == "receipt_reissue"
    assert targets[0]["target_email"] == "receipt-on-file@example.test"
    assert targets[0]["target_email"] != "steal-my-receipt@example.net"
    assert any(a["action"] == "receipt-reissue" and a["actor"] == "hoppy-agent" for a in audit_rows(mod, ACCOUNT))


def test_receipt_reissue_is_idempotent_on_request_id():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "same-rid-receipt"}
    call(mod, "/api/agent/v1/receipt-reissue", body, x_token=token(mod))
    call(mod, "/api/agent/v1/receipt-reissue", body, x_token=token(mod))
    assert len(outbox_targets(mod)) == 1


# ============================== preferred server ============================


def test_preferred_server_is_stored():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    # create a node so the region validates
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO nodes (slug, name, flag, endpoint, public_key, status, last_heartbeat) "
            "VALUES ('singapore-b', 'Singapore B', 'SG', '1.2.3.4:51820', 'gkp', 'online', ?)",
            (mod.utcnow().isoformat(),),
        )
    body = {"account_number": ACCOUNT, "region": "singapore-b", "request_id": "r7"}
    call(mod, "/api/agent/v1/preferred-server", body, x_token=token(mod))
    prefs = user_prefs(mod, ACCOUNT)
    assert prefs["preferred_region"] == "singapore-b"
    assert prefs["preferred_server"] == "singapore-b"
    assert any(a["action"] == "preferred-server" and a["actor"] == "hoppy-agent" for a in audit_rows(mod, ACCOUNT))


def test_preferred_server_unknown_region_is_404():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "region": "no-such-region", "request_id": "r8"}
    try:
        call(mod, "/api/agent/v1/preferred-server", body, x_token=token(mod))
        raise AssertionError("expected 404")
    except harness.HTTPException as exc:
        assert exc.status_code == 404


def test_preferred_server_auto_clears():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO nodes (slug, name, flag, endpoint, public_key, status, last_heartbeat) "
            "VALUES ('singapore-b', 'Singapore B', 'SG', '1.2.3.4:51820', 'gkp', 'online', ?)",
            (mod.utcnow().isoformat(),),
        )
    body = {"account_number": ACCOUNT, "region": "singapore-b", "request_id": "r7"}
    call(mod, "/api/agent/v1/preferred-server", body, x_token=token(mod))
    assert user_prefs(mod, ACCOUNT)["preferred_region"] == "singapore-b"
    clear = {"account_number": ACCOUNT, "region": "auto", "request_id": "r7b"}
    call(mod, "/api/agent/v1/preferred-server", clear, x_token=token(mod))
    assert user_prefs(mod, ACCOUNT)["preferred_region"] == ""


# ============================== audit immutability =========================


def test_audit_table_is_append_only():
    mod = harness.load_hub(**_env())
    seed_account(mod)
    body = {"account_number": ACCOUNT, "request_id": "r1"}
    call(mod, "/api/agent/v1/device-limit-reset", body, x_token=token(mod))
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT event_id FROM hoppy_agent_audit LIMIT 1").fetchone()
        try:
            conn.execute("UPDATE hoppy_agent_audit SET outcome='tampered' WHERE event_id=?", (row["event_id"],))
            raise AssertionError("audit UPDATE must be rejected")
        except sqlite3.IntegrityError:
            pass


def test_pre_delivery_barrier_failure_does_not_exhaust_mail_attempts():
    mod = harness.load_hub(**_env(HOPPY_AGENT_OUTBOX_MAX_ATTEMPTS=1))
    seed_account(mod)
    call(mod, "/api/agent/v1/receipt-reissue",
         {"account_number": ACCOUNT, "request_id": "barrier-pre"}, x_token=token(mod))

    def unavailable():
        raise mod.DurabilityBarrierError("replica_unavailable")

    mod.run_durability_barrier = unavailable
    assert mod.drain_hoppy_agent_mail_outbox()["deferred"] == 1
    with closing(sqlite3.connect(mod._DB)) as conn:
        status, attempts = conn.execute(
            "SELECT status, attempts FROM hoppy_agent_mail_outbox"
        ).fetchone()
    assert (status, attempts) == ("pending", 0)

    mod.run_durability_barrier = lambda: {}
    mod.send_hoppy_receipt_email = lambda record: True
    assert mod.drain_hoppy_agent_mail_outbox()["confirmed"] == 1


def test_post_delivery_barrier_retries_after_send_attempt_cap():
    mod = harness.load_hub(**_env(HOPPY_AGENT_OUTBOX_MAX_ATTEMPTS=1))
    seed_account(mod)
    call(mod, "/api/agent/v1/receipt-reissue",
         {"account_number": ACCOUNT, "request_id": "barrier-post"}, x_token=token(mod))
    sent = []
    mod.send_hoppy_receipt_email = lambda record: sent.append(True) or True
    barrier_calls = []

    def fail_once_after_send():
        barrier_calls.append(True)
        if len(barrier_calls) == 2:
            raise mod.DurabilityBarrierError("replica_unavailable")
        return {}

    mod.run_durability_barrier = fail_once_after_send
    result = mod.drain_hoppy_agent_mail_outbox()
    assert result["delivered"] == 1 and result["deferred"] == 1
    assert len(sent) == 1
    mod.run_durability_barrier = lambda: {}
    assert mod.drain_hoppy_agent_mail_outbox()["confirmed"] == 1
    assert len(sent) == 1


def test_credentials_resend_replicates_the_rotated_key_before_mailing_it():
    # R24 Argon 1: the resend rotates the setup key after the pre-send
    # barrier; that new hash must replicate before the key is mailed, and a
    # replica outage at that point defers without spending an attempt.
    mod = harness.load_hub(**_env(HOPPY_AGENT_OUTBOX_MAX_ATTEMPTS=1))
    seed_account(mod, email="real-on-file@example.test")
    call(mod, "/api/agent/v1/credentials-resend",
         {"account_number": ACCOUNT, "request_id": "barrier-rotate"}, x_token=token(mod))
    mod.SMTP_USER, mod.SMTP_PASS = "relay-user", "relay-pass"
    events = []
    mod.send_account_email = lambda *args: events.append("send") or True

    def fail_after_rotation():
        events.append("barrier")
        if events.count("barrier") == 2:
            raise mod.DurabilityBarrierError("replica_unavailable")
        return {}

    mod.run_durability_barrier = fail_after_rotation
    result = mod.drain_hoppy_agent_mail_outbox()
    assert result["deferred"] == 1 and result["delivered"] == 0
    assert "send" not in events
    with closing(sqlite3.connect(mod._DB)) as conn:
        status, attempts = conn.execute(
            "SELECT status, attempts FROM hoppy_agent_mail_outbox"
        ).fetchone()
    assert (status, attempts) == ("pending", 0)

    events.clear()
    mod.run_durability_barrier = lambda: events.append("barrier") or {}
    assert mod.drain_hoppy_agent_mail_outbox()["confirmed"] == 1
    assert events[:3] == ["barrier", "barrier", "send"]

if __name__ == "__main__":
    tests = [(k, v) for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            import traceback
            print(f"FAIL {name}: {exc}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
