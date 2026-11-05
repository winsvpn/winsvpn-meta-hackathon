#!/usr/bin/env python3
"""Hub tests for authenticated, quorum-based account deletion.

These exercise the REAL control-plane source: the module is extracted from the
`cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc inside
wins_control_plane_setup_ONETOUCH.sh and exec'd with minimal stubs for its only
three third-party imports (fastapi, pydantic, dateutil). Nothing here is a
reimplementation, so a regression in the shipped script fails these tests.

Run:  python3 server/test_account_deletion_hub.py

Scope note: this cannot prove the deployed control plane behaves correctly --
there is no HTTP server, no uvicorn, no real gateway. It proves the handler
functions, SQL, and policy logic behave correctly against a real SQLite file.
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import os
import re
import sqlite3
import sys
import tempfile
import traceback
import types
from datetime import timedelta

HUB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "wins_control_plane_setup_ONETOUCH.sh")


# =========================== third-party stubs ============================

class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = "", **kw):
        super().__init__(f"{status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class _App:
    def __init__(self, *a, **kw):
        self.routes = {}

    def _reg(self, method, path):
        def deco(fn):
            self.routes[(method, path)] = fn
            return fn
        return deco

    def get(self, path, **kw):
        return self._reg("GET", path)

    def post(self, path, **kw):
        return self._reg("POST", path)

    def put(self, path, **kw):
        return self._reg("PUT", path)

    def delete(self, path, **kw):
        return self._reg("DELETE", path)

    def on_event(self, name):
        return lambda fn: fn

    def exception_handler(self, exc):
        return lambda fn: fn

    def add_middleware(self, *a, **k):
        pass

    def mount(self, *a, **k):
        pass


class FakeRequest:
    def __init__(self, headers=None, body=None, client_host="203.0.113.9", path="/",
                 method="POST"):
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._body = body if body is not None else {}
        self.client = types.SimpleNamespace(host=client_host)
        self.url = types.SimpleNamespace(path=path)
        self.method = method
        self.query_params = {}
        self.cookies = {}

    async def json(self):
        return self._body

    async def form(self):
        return self._body


class BackgroundTasks:
    def __init__(self):
        self.tasks = []

    def add_task(self, fn, *a, **k):
        self.tasks.append((fn, a, k))


def _install_stubs():
    fastapi = types.ModuleType("fastapi")
    fastapi.FastAPI = _App
    fastapi.HTTPException = HTTPException
    fastapi.Request = FakeRequest
    fastapi.BackgroundTasks = BackgroundTasks
    fastapi.Header = lambda *a, **k: None
    fastapi.Form = lambda *a, **k: None
    fastapi.Depends = lambda *a, **k: None
    responses = types.ModuleType("fastapi.responses")
    for name in ("JSONResponse", "RedirectResponse", "HTMLResponse",
                 "PlainTextResponse", "Response"):
        setattr(responses, name,
                type(name, (), {"__init__": lambda self, *a, **k: None}))
    fastapi.responses = responses
    sys.modules["fastapi"] = fastapi
    sys.modules["fastapi.responses"] = responses

    pydantic = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kw):
            for k, v in kw.items():
                setattr(self, k, v)

        def __getattr__(self, item):
            return None

    pydantic.BaseModel = BaseModel
    pydantic.Field = lambda *a, **k: None
    pydantic.AliasChoices = lambda *a, **k: None
    pydantic.ConfigDict = lambda *a, **k: dict()
    pydantic.validator = lambda *a, **k: (lambda fn: fn)
    sys.modules["pydantic"] = pydantic

    dateutil = types.ModuleType("dateutil")
    rd = types.ModuleType("dateutil.relativedelta")

    class relativedelta:
        def __init__(self, **kw):
            self.kw = kw

        def __radd__(self, other):
            months = self.kw.get("months", 0) + 12 * self.kw.get("years", 0)
            year = other.year + (other.month - 1 + months) // 12
            month = (other.month - 1 + months) % 12 + 1
            last = [31, 29 if year % 4 == 0 else 28, 31, 30, 31, 30,
                    31, 31, 30, 31, 30, 31][month - 1]
            return other.replace(year=year, month=month, day=min(other.day, last))

    rd.relativedelta = relativedelta
    dateutil.relativedelta = rd
    sys.modules["dateutil"] = dateutil
    sys.modules["dateutil.relativedelta"] = rd


def _extract_main_block() -> str:
    with open(HUB, encoding="utf-8") as fh:
        lines = fh.readlines()
    for i, line in enumerate(lines):
        if re.search(r"<<'PYEOF'", line) and "main.py" in line:
            j = i + 1
            while j < len(lines) and lines[j].rstrip("\n") != "PYEOF":
                j += 1
            return "".join(lines[i + 1:j])
    raise RuntimeError("main.py heredoc not found in the installer")


def load_hub(**env):
    _install_stubs()
    tmpdir = tempfile.mkdtemp(prefix="winshub-test-")
    logdir = os.path.join(tmpdir, "log")
    os.makedirs(logdir, exist_ok=True)
    settings = {
        "DATABASE_PATH": os.path.join(tmpdir, "vpn_users.db"),
        "RATE_LIMIT_SECRET": "test-rate-limit-secret",
        "ADMIN_TOKEN": "test-admin-token",
        "SPA_HMAC": "test-spa-hmac",
        "SECURITY_EVENTS_DB": os.path.join(tmpdir, "security_events.db"),
        "SMTP_PASS": "",
        "DEVICE_LIMIT": "3",
        # Functional tests make more calls than a real client would; the
        # dedicated rate-limit test overrides these back down.
        "ACCOUNT_DELETION_IP_RATE_LIMIT_PER_MINUTE": "1000",
        "ACCOUNT_DELETION_ACCOUNT_RATE_LIMIT_PER_HOUR": "1000",
    }
    settings.update({k: str(v) for k, v in env.items()})
    os.environ.update(settings)

    src = _extract_main_block()
    # Harness-only redirection of root-owned literal paths written at import.
    src = src.replace('"/var/log/winsvpn"', repr(logdir))
    src = src.replace('"/var/log/winsvpn/master.log"',
                      repr(os.path.join(logdir, "master.log")))
    src = src.replace('"/var/lib/wins-security-alerts"', repr(tmpdir))

    mod = types.ModuleType("wins_hub")
    mod.__dict__["__file__"] = os.path.join(tmpdir, "main.py")
    exec(compile(src, "wins_hub_main.py", "exec"), mod.__dict__)
    mod._TMPDIR = tmpdir
    mod._DB = settings["DATABASE_PATH"]
    return mod


# ============================= test fixtures ==============================

ACCOUNT = "1111-2222-3333"

# users.referral_code and devices.vpn_internal_ip are both UNIQUE. Seeding two
# accounts in one test must not collide on either, or INSERT OR REPLACE will
# silently evict the first account's rows.
_IP_SEQ = [0]


def seed_account(mod, account=ACCOUNT, devices=3, expiration="2030-01-01T00:00:00"):
    """Create a paid account with `devices` active devices. Returns
    {device_id: plaintext device auth token}."""
    tokens = {}
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO users (account_number, email, status, expiration_date, referral_code) "
            "VALUES (?, ?, 'active', ?, ?)",
            (account, f"user-{account}@example.test", expiration,
             f"CODE{account.replace('-', '')}"),
        )
        now = mod.utcnow().isoformat()
        for n in range(devices):
            # Full account number in the id: two accounts in one test must never
            # collide on device_id (devices.device_id is the PRIMARY KEY).
            device_id = f"dev-{account}-{n}"
            token = f"token-{device_id}-secret"
            tokens[device_id] = token
            _IP_SEQ[0] += 1
            conn.execute(
                """
                INSERT OR REPLACE INTO devices (
                    device_id, account_number, device_model, vpn_internal_ip,
                    client_private_key, client_public_key, last_seen, location_slug,
                    updated_at, device_auth_token_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (device_id, account, f"Model {n}",
                 f"10.8.{_IP_SEQ[0] // 250}.{_IP_SEQ[0] % 250 + 2}",
                 f"PRIVATE-KEY-{device_id}", f"PUBLIC-KEY-{device_id}",
                 now, "test-node", now, mod.token_digest(token)),
            )
        conn.execute(
            """
            INSERT OR REPLACE INTO legal_acceptances (
                acceptance_id, account_number, email, document_version, document_hash, accepted_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (f"acc-{account}", account, f"user-{account}@example.test",
             mod.LEGAL_DOCUMENT_VERSION, mod.LEGAL_DOCUMENT_HASH, now),
        )
        conn.commit()
    return tokens


def call(mod, path, account, device_id, token, extra=None, ip="203.0.113.9"):
    """Invoke a registered deletion route the way FastAPI would."""
    body = {"account_number": account, "device_id": device_id}
    body.update(extra or {})
    headers = {"content-type": "application/json"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    request = FakeRequest(headers=headers, body=body, client_host=ip, path=path)
    handler = mod.app.routes[("POST", path)]
    return asyncio.run(handler(request, BackgroundTasks()))


def table_count(mod, table, where="", args=()):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        sql = f"SELECT COUNT(*) FROM {table}"
        if where:
            sql += f" WHERE {where}"
        return conn.execute(sql, args).fetchone()[0]


# ================================= tests ==================================

RESULTS = []


def test(fn):
    RESULTS.append(fn)
    return fn
test.__test__ = False


def expect_http(status, fn, *a, **k):
    try:
        fn(*a, **k)
    except HTTPException as exc:
        assert exc.status_code == status, f"expected HTTP {status}, got {exc.status_code}: {exc.detail}"
        return exc
    raise AssertionError(f"expected HTTP {status}, call succeeded")


@test
def test_auth_missing_token_is_rejected():
    mod = load_hub()
    seed_account(mod, devices=3)
    expect_http(401, call, mod, "/account/deletion/request", ACCOUNT, f"dev-{ACCOUNT}-0", None)
    assert table_count(mod, "account_deletion_requests") == 0
    assert table_count(mod, "users") == 1, "no account may be touched by an unauthenticated call"


@test
def test_auth_wrong_token_is_rejected():
    mod = load_hub()
    seed_account(mod, devices=3)
    expect_http(401, call, mod, "/account/deletion/request", ACCOUNT, f"dev-{ACCOUNT}-0", "not-the-token")
    assert table_count(mod, "account_deletion_requests") == 0


@test
def test_cross_device_replay_is_rejected():
    """Device A's bearer token must not authenticate a call claiming to be B."""
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    # A holds A's token and tries to submit B's confirmation.
    expect_http(401, call, mod, "/account/deletion/confirm", ACCOUNT, b, tokens[a])
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        confirmed = conn.execute(
            "SELECT device_id FROM account_deletion_confirmations").fetchall()
    assert [r[0] for r in confirmed] == [a], f"only A should be confirmed, got {confirmed}"
    assert table_count(mod, "users") == 1, "account must survive a failed replay"


@test
def test_same_device_cannot_reach_quorum_alone():
    """The anti-theft property: one device confirming repeatedly never deletes."""
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a = f"dev-{ACCOUNT}-0"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    for _ in range(5):
        out = call(mod, "/account/deletion/confirm", ACCOUNT, a, tokens[a])
    assert out["stage"] == "awaiting_confirmations", out
    assert out["confirmed_device_count"] == 1, out
    assert table_count(mod, "users") == 1, "one device must never delete a 3-device account"


@test
def test_three_devices_need_two_not_three():
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    out = call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert out["required_confirmations"] == 2, out
    assert out["active_device_count"] == 3, out
    assert out["stage"] == "awaiting_confirmations", out
    assert out["confirmed_device_count"] == 1, out
    assert table_count(mod, "users") == 1

    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out
    # The third device never confirmed and deletion still completed.
    assert table_count(mod, "users") == 0


@test
def test_two_devices_need_both():
    mod = load_hub()
    tokens = seed_account(mod, devices=2)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    out = call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert out["required_confirmations"] == 2, out
    assert out["stage"] == "awaiting_confirmations", out
    assert table_count(mod, "users") == 1
    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out
    assert table_count(mod, "users") == 0


@test
def test_one_device_uses_waiting_period_then_completes():
    mod = load_hub()
    tokens = seed_account(mod, devices=1)
    a = f"dev-{ACCOUNT}-0"
    out = call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert out["required_confirmations"] == 1, out
    assert out["stage"] == "awaiting_delay", out
    assert out["execute_after"], "a single-device request must schedule an execution time"
    assert table_count(mod, "users") == 1, "must NOT delete immediately"

    # Not yet due: a sweep must leave it alone.
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        assert mod.resolve_due_account_deletions(conn, None) == 0
        conn.commit()
    assert table_count(mod, "users") == 1

    # Wind the clock back past the delay, then sweep.
    due = (mod.utcnow() - timedelta(days=1)).isoformat()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE account_deletion_requests SET execute_after = ?", (due,))
        conn.commit()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        assert mod.resolve_due_account_deletions(conn, None) == 1
        conn.commit()
    assert table_count(mod, "users") == 0
    assert table_count(mod, "devices") == 0


@test
def test_cancel_from_any_device_while_pending():
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, c = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-2"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    # A device that never confirmed cancels.
    out = call(mod, "/account/deletion/cancel", ACCOUNT, c, tokens[c])
    assert out["stage"] == "cancelled", out
    assert table_count(mod, "users") == 1
    assert table_count(mod, "account_deletion_confirmations") == 0
    status = call(mod, "/account/deletion/status", ACCOUNT, a, tokens[a])
    assert status["stage"] == "none", status


@test
def test_confirmation_does_not_survive_cancellation():
    """A confirmation captured under a cancelled request cannot be replayed
    into the next one."""
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    call(mod, "/account/deletion/cancel", ACCOUNT, a, tokens[a])
    out = call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert out["confirmed_device_count"] == 1, out
    assert out["stage"] == "awaiting_confirmations", out
    assert table_count(mod, "users") == 1
    # And a confirm carrying the OLD request id is refused outright.
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        current = conn.execute(
            "SELECT request_id FROM account_deletion_requests WHERE status='pending'").fetchone()[0]
    expect_http(409, call, mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b],
                {"request_id": current + "-stale"})
    assert table_count(mod, "users") == 1


@test
def test_reenrolled_device_counts_once_not_twice():
    """A thief must not be able to cycle ONE physical device through
    re-enrolment to manufacture a two-device quorum -- while a legitimate
    re-enrolment must not permanently lose that device's vote either."""
    mod = load_hub()
    tokens = seed_account(mod, devices=2)
    a = f"dev-{ACCOUNT}-0"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert table_count(mod, "account_deletion_confirmations") == 1

    # Simulate logout + re-enrol: /verify mints a NEW device_auth_token.
    new_token = "token-after-reenrolment"
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE devices SET device_auth_token_hash = ? WHERE device_id = ?",
                     (mod.token_digest(new_token), a))
        conn.commit()

    out = call(mod, "/account/deletion/confirm", ACCOUNT, a, new_token)
    assert out["confirmed_device_count"] == 1, \
        f"re-enrolled device must count once, not twice: {out}"
    assert out["stage"] == "awaiting_confirmations", out
    assert table_count(mod, "users") == 1


@test
def test_stale_device_is_not_counted_toward_quorum():
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    # Age the third device out past STALE_DEVICE_RETENTION_DAYS.
    old = (mod.utcnow() - timedelta(days=mod.STALE_DEVICE_RETENTION_DAYS + 5)).isoformat()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?", (old, f"dev-{ACCOUNT}-2"))
        conn.commit()
    out = call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    assert out["active_device_count"] == 2, out
    assert out["required_confirmations"] == 2, out
    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out


@test
def test_deletion_removes_rows_and_destroys_private_keys():
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "INSERT INTO double_vpn_assignments (account_number, device_id, status) VALUES (?, ?, 'active')",
            (ACCOUNT, a))
        conn.commit()
    assert table_count(mod, "devices", "client_private_key != ''") == 3

    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out

    for table in ("users", "devices", "legal_acceptances", "double_vpn_assignments",
                  "account_deletion_requests", "account_deletion_confirmations"):
        assert table_count(mod, table) == 0, f"{table} still has rows after deletion"
    # The server-stored WireGuard private keys are gone, not blanked-in-place.
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        leftover = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE client_private_key LIKE 'PRIVATE-KEY-%'").fetchone()[0]
    assert leftover == 0


@test
def test_audit_record_contains_no_pii():
    mod = load_hub()
    tokens = seed_account(mod, devices=2)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])

    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM account_deletion_audit").fetchall()
    assert len(rows) == 1, rows
    blob = " ".join(str(v) for v in dict(rows[0]).values())
    for secret in (ACCOUNT, "1111", "2222", "3333", a, b,
                   f"user-{ACCOUNT}@example.test", "PRIVATE-KEY", "203.0.113.9"):
        assert secret not in blob, f"audit record leaked {secret!r}: {blob}"
    assert dict(rows[0])["outcome"] == "completed"
    assert dict(rows[0])["devices_deleted"] == 2
    assert dict(rows[0])["confirmations_received"] == 2


@test
def test_referrer_record_survives_and_clawback_still_works():
    """Deleting a referred account must not corrupt or orphan the referrer's
    row, must not take back the referrer's already-granted days, and must not
    make a later refund unclawable."""
    mod = load_hub()
    referrer = "9999-8888-7777"
    seed_account(mod, account=referrer, devices=1)
    tokens = seed_account(mod, account=ACCOUNT, devices=2)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"

    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute(
            "UPDATE users SET expiration_date = ?, referral_bonus_days = 30 WHERE account_number = ?",
            ("2030-02-01T00:00:00", referrer))
        conn.execute("UPDATE users SET referred_by_account_number = ? WHERE account_number = ?",
                     (referrer, ACCOUNT))
        conn.execute(
            """INSERT INTO referral_rewards (referral_code, referrer_account_number,
               referred_account_number, purchase_reference, base_days, bonus_days)
               VALUES (?, ?, ?, ?, ?, ?)""",
            ("CODE7777", referrer, ACCOUNT, "PAY-1", 150, 30))
        conn.commit()

    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out

    tombstone = mod.deleted_account_tombstone(ACCOUNT)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        reward = conn.execute("SELECT * FROM referral_rewards").fetchall()
        assert len(reward) == 1, "the referrer's reward row must survive, not be deleted"
        reward = dict(reward[0])
        assert reward["referred_account_number"] == tombstone, reward
        assert ACCOUNT not in str(reward), "deleted account number must not remain on the row"
        assert reward["referrer_account_number"] == referrer, "referrer link must stay intact"
        assert reward["bonus_days"] == 30
        ref = dict(conn.execute("SELECT * FROM users WHERE account_number = ?",
                                (referrer,)).fetchone())
        assert ref["referral_bonus_days"] == 30, "already-granted bonus must NOT be clawed back"
        assert ref["expiration_date"] == "2030-02-01T00:00:00"

    # A refund arriving AFTER deletion must still reverse the referrer's bonus.
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.claw_back_referral_bonus(conn, ACCOUNT)
        conn.commit()
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        ref = dict(conn.execute("SELECT * FROM users WHERE account_number = ?",
                                (referrer,)).fetchone())
        row = dict(conn.execute("SELECT * FROM referral_rewards").fetchone())
    assert ref["referral_bonus_days"] == 0, "post-deletion refund must still claw back"
    assert row["clawed_back_at"], "clawback must be recorded"


@test
def test_deleting_a_referrer_does_not_orphan_the_referred_account():
    mod = load_hub()
    referred = "5555-4444-3333"
    tokens = seed_account(mod, account=ACCOUNT, devices=2)
    seed_account(mod, account=referred, devices=1)
    a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE users SET referred_by_account_number = ? WHERE account_number = ?",
                     (ACCOUNT, referred))
        conn.execute(
            """INSERT INTO referral_rewards (referral_code, referrer_account_number,
               referred_account_number, bonus_days) VALUES (?, ?, ?, ?)""",
            ("CODE3333", ACCOUNT, referred, 15))
        conn.commit()

    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    out = call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
    assert out["stage"] == "completed", out

    tombstone = mod.deleted_account_tombstone(ACCOUNT)
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        survivor = dict(conn.execute("SELECT * FROM users WHERE account_number = ?",
                                     (referred,)).fetchone())
        reward = dict(conn.execute("SELECT * FROM referral_rewards").fetchone())
    assert survivor["referred_by_account_number"] == tombstone, \
        "the surviving account must point at a tombstone, not a dangling account number"
    assert reward["referrer_account_number"] == tombstone
    assert reward["referred_account_number"] == referred, "surviving party's id is untouched"


@test
def test_rate_limit_enforced_on_deletion_routes():
    mod = load_hub(ACCOUNT_DELETION_IP_RATE_LIMIT_PER_MINUTE=3,
                   ACCOUNT_DELETION_ACCOUNT_RATE_LIMIT_PER_HOUR=1000)
    seed_account(mod, devices=3)
    # Unauthenticated attempts still consume quota (rate limit precedes auth).
    for _ in range(3):
        expect_http(401, call, mod, "/account/deletion/request", ACCOUNT, f"dev-{ACCOUNT}-0", None)
    exc = expect_http(429, call, mod, "/account/deletion/request", ACCOUNT, f"dev-{ACCOUNT}-0", None)
    assert exc.status_code == 429


@test
def test_status_reports_policy_and_progress():
    mod = load_hub()
    tokens = seed_account(mod, devices=3)
    a = f"dev-{ACCOUNT}-0"
    out = call(mod, "/account/deletion/status", ACCOUNT, a, tokens[a])
    assert out["stage"] == "none", out
    assert out["active_device_count"] == 3
    assert out["required_confirmations"] == 2
    assert "2 different devices" in out["policy"], out["policy"]
    assert out["this_device_confirmed"] is False

    call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
    out = call(mod, "/account/deletion/status", ACCOUNT, a, tokens[a])
    assert out["stage"] == "awaiting_confirmations", out
    assert out["confirmed_device_count"] == 1
    assert out["this_device_confirmed"] is True
    # A device that has not confirmed sees this_device_confirmed False.
    other = call(mod, "/account/deletion/status", ACCOUNT, f"dev-{ACCOUNT}-2", tokens[f"dev-{ACCOUNT}-2"])
    assert other["this_device_confirmed"] is False, other


@test
def test_single_device_policy_copy_states_the_waiting_period():
    mod = load_hub()
    text = mod.account_deletion_policy_text(1)
    assert "7-day waiting period" in text, text
    assert "cancel" in text
    assert mod.account_deletion_policy_text(0).startswith("This account has no active devices")


@test
def test_legal_hash_contract_is_unbroken():
    """Guard rail: deletion work must not disturb legal_payload_is_current or
    the accepted-hash tuple."""
    mod = load_hub()
    assert len(mod.LEGAL_DOCUMENT_ACCEPTED_HASHES) == 3
    assert mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION, mod.LEGAL_DOCUMENT_HASH)
    assert mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION,
                                        mod.LEGAL_DOCUMENT_HASH_SUPERSEDED_20260721)
    assert not mod.legal_payload_is_current(mod.LEGAL_DOCUMENT_VERSION, "0" * 64)
    assert not mod.legal_payload_is_current("1999-01-01.v1", mod.LEGAL_DOCUMENT_HASH)


@test
def test_required_confirmations_derives_from_live_count():
    mod = load_hub()
    assert [mod.required_deletion_confirmations(n) for n in range(6)] == [0, 1, 2, 2, 2, 2]
    # Raising the device limit must not change the quorum.
    higher = load_hub(DEVICE_LIMIT=10)
    assert higher.required_deletion_confirmations(10) == higher.ACCOUNT_DELETION_QUORUM


def main():
    passed = failed = 0
    for fn in RESULTS:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"ok    {fn.__name__}")
    print(f"\n{passed} passed, {failed} failed, {len(RESULTS)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
