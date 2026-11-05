#!/usr/bin/env python3
"""Hub tests for the duress emergency relay -- POST /emergency/dispatch.

Like test_account_deletion_hub.py and test_donor_acknowledgment_hub.py these
exercise the REAL control-plane source: the module is extracted from the
`cat > "${APP_DIR}/main.py" <<'PYEOF'` heredoc inside
wins_control_plane_setup_ONETOUCH.sh and exec'd with stubs for its three
third-party imports. Nothing here is a reimplementation, so a regression in the
shipped installer fails these tests.

SMTP is monkeypatched in every test. No mail leaves this process; no test needs
the network, a live hub, or a real contact.

What is under test, and why each one is a safety property rather than a nicety:

  * PAYLOAD VALIDATION -- the client's contract (lib/duress_dispatch.dart,
    DuressDispatch.toWirePayload) is fixed; the hub must accept exactly it, must
    never reject an alert over a degraded field, and must never let a contact
    string smuggle headers into a composed message.
  * IDEMPOTENCY -- the handset retries from an offline queue, so one alert
    arrives many times and must be relayed once; a user triggering duress AGAIN
    must be relayed again.
  * RATE LIMITING -- must pace, never refuse. A refused duress alert is a
    person who does not get help.
  * NO PII IN LOGS -- hub logs may be seized. Nothing in them may identify the
    user, the contact, the location, or reveal what this service is.
  * DURABILITY -- the client destroys its only copy of the alert on 2xx, so a
    2xx that was not committed loses a life-safety message permanently.

Run:  python3 server/test_emergency_dispatch_hub.py
"""
from contextlib import closing
import _toolchain  # noqa: F401  (V-01 preflight)
import asyncio
import json
import logging
import os
import sqlite3
import sys
import time
import traceback
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reuse the deletion suite's extraction harness so every suite is provably
# reading the same heredoc out of the same installer.
import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import BackgroundTasks, FakeRequest, HTTPException  # noqa: E402


# ============================== fixtures ==================================

CONTACT = "amara.hla@example.org"
LAT = 16.871311
LNG = 96.199379
CAPTURED = "2026-08-06T01:23:45.000Z"
ACCOUNT = "4444-5555-6666"
DEVICE = "device-abcdef0123456789"
TOKEN = "bearer-token-should-never-be-logged"

# Every EMERGENCY_* knob is passed explicitly on every load: harness.load_hub()
# mutates os.environ and never unsets it, so a value set by one test would
# otherwise leak into the next.
BASE_ENV = {
    "EMERGENCY_DISPATCH_ENABLED": "true",
    "EMERGENCY_FROM_EMAIL": "alerts@notify.example",
    "EMERGENCY_FROM_NAME": "Safety Notification",
    "EMERGENCY_ALLOW_BRANDED_SENDER": "false",
    "EMERGENCY_DISPATCH_CHANNEL": "auto",
    "EMERGENCY_IP_BURST_PER_MINUTE": "1000",
    "EMERGENCY_CONTACT_BURST_PER_HOUR": "1000",
    "EMERGENCY_GLOBAL_NEW_PER_HOUR": "1000",
    "EMERGENCY_DEFER_SECONDS": "120",
    "EMERGENCY_MAX_DEFER_SECONDS": "900",
    "EMERGENCY_OUTBOX_BATCH_LIMIT": "200",
    "EMERGENCY_SWEEP_INTERVAL_SECONDS": "5",
    "EMERGENCY_LEASE_SECONDS": "120",
    "EMERGENCY_BACKLOG_NOTICE_SECONDS": "3600",
    "EMERGENCY_DEDUPE_RETENTION_DAYS": "30",
    "SMTP_USER": "smtp-user",
    "SMTP_PASS": "smtp-pass",
    "SECURITY_ALERT_EMAIL": "",
}

SENT = []           # [(from, [to], raw_message)]
SMTP_FAILURE = [None]


class FakeSMTP:
    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def sendmail(self, sender, recipients, message):
        if SMTP_FAILURE[0] is not None:
            raise SMTP_FAILURE[0]
        SENT.append((sender, list(recipients), message))


def load(**env):
    """Load the hub with a clean emergency configuration and a captured log."""
    SENT.clear()
    SMTP_FAILURE[0] = None
    settings = dict(BASE_ENV)
    settings.update({k: str(v) for k, v in env.items()})
    mod = harness.load_hub(**settings)
    mod.smtplib = types.SimpleNamespace(SMTP=FakeSMTP)

    # Capture EVERYTHING the hub logs during this test to a file we can grep.
    # logging.basicConfig() inside the module is a no-op after the first load
    # (the root logger already has handlers), so the assertion is made against
    # a handler this harness owns.
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, "_wins_capture", False):
            root.removeHandler(handler)
            handler.close()
    logpath = os.path.join(mod._TMPDIR, "captured.log")
    capture = logging.FileHandler(logpath, encoding="utf-8")
    capture.setLevel(logging.DEBUG)
    capture.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))
    capture._wins_capture = True
    root.addHandler(capture)
    root.setLevel(logging.DEBUG)
    mod._LOGPATH = logpath
    return mod


def payload(contact=CONTACT, lat=LAT, lng=LNG, captured_at=CAPTURED,
            account_number=None, device_id=None, app_version=None, message=None):
    """The exact wire shape DuressDispatch.toWirePayload() produces."""
    body = {"kind": "emergency", "contact": contact, "captured_at": captured_at}
    if lat is not None:
        body["lat"] = lat
    if lng is not None:
        body["lng"] = lng
    body["message"] = message if message is not None else (
        "Automated safety alert: your contact may need help and asked you to be "
        "notified. Last known location: %s, %s." % (lat, lng)
    )
    if account_number:
        body["account_number"] = account_number
    if device_id:
        body["device_id"] = device_id
    if app_version:
        body["app_version"] = app_version
    return body


def post(mod, body=None, ip="203.0.113.44", token=None, background=None):
    headers = {"content-type": "application/json", "user-agent": "WinsVPN-App/1.0"}
    if token:
        headers["authorization"] = "Bearer %s" % token
    request = FakeRequest(headers=headers, body=body if body is not None else payload(),
                          client_host=ip, path="/emergency/dispatch")
    bg = background if background is not None else BackgroundTasks()
    handler = mod.app.routes[("POST", "/emergency/dispatch")]
    return asyncio.run(handler(request, bg)), bg


def sent_text(index=0):
    """Headers plus the DECODED body of a captured message.

    The relay sends utf-8 (so a localised body stays possible), which means the
    payload is base64 on the wire. Asserting "secret not in raw" would then pass
    for any secret, which is worse than no assertion at all -- so every content
    assertion in this file goes through here.
    """
    import email as _email
    sender, recipients, raw = SENT[index]
    msg = _email.message_from_string(raw)
    body = msg.get_payload(decode=True)
    body = body.decode("utf-8", "replace") if body else ""
    headers = "\n".join("%s: %s" % (k, v) for k, v in msg.items())
    return sender, recipients, headers + "\n\n" + body


def outbox(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM emergency_outbox ORDER BY id").fetchall()]
        except sqlite3.OperationalError:
            return []


def release(mod):
    """Make every queued alert due immediately (stands in for elapsed time)."""
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.execute("UPDATE emergency_outbox SET not_before = 0, lease_until = NULL")
        conn.commit()


def seed_device(mod):
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        mod.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO users (account_number, email, status, expiration_date, referral_code) "
            "VALUES (?, ?, 'active', '2030-01-01T00:00:00', ?)",
            (ACCOUNT, "seed@example.test", "REF" + ACCOUNT.replace("-", "")),
        )
        now = mod.utcnow().isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO devices (device_id, account_number, device_model, "
            "vpn_internal_ip, client_private_key, client_public_key, last_seen, "
            "location_slug, updated_at, device_auth_token_hash) "
            "VALUES (?, ?, 'Model', '10.9.0.2', 'PRIV', 'PUB', ?, 'slug', ?, ?)",
            (DEVICE, ACCOUNT, now, now, mod.token_digest(TOKEN)),
        )
        conn.commit()


def logtext(mod):
    for handler in logging.getLogger().handlers:
        if getattr(handler, "_wins_capture", False):
            handler.flush()
    if not os.path.exists(mod._LOGPATH):
        return ""
    with open(mod._LOGPATH, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def dbtext(mod):
    """Every text value in the whole database, for leak assertions."""
    chunks = []
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        conn.row_factory = sqlite3.Row
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for table in tables:
            for row in conn.execute("SELECT * FROM %s" % table).fetchall():
                chunks.append(" ".join(str(v) for v in tuple(row)))
    return "\n".join(chunks)


RESULTS = []


def test(fn):
    RESULTS.append(fn)
    return fn
test.__test__ = False


def expect_http(status, fn, *a, **k):
    try:
        fn(*a, **k)
    except HTTPException as exc:
        assert exc.status_code == status, \
            "expected HTTP %s, got %s: %s" % (status, exc.status_code, exc.detail)
        return exc
    raise AssertionError("expected HTTP %s, call succeeded" % status)


# =========================== contract / routing ===========================

@test
def test_route_matches_the_client_contract():
    """The app POSTs this exact path (lib/gateway_failover.dart,
    emergencyDispatchGateways). If this key changes, every duress alert in the
    field falls into the on-device queue and stays there."""
    mod = load()
    assert ("POST", "/emergency/dispatch") in mod.app.routes


@test
def test_full_wire_payload_is_accepted():
    mod = load()
    result, bg = post(mod, payload(account_number=ACCOUNT, device_id=DEVICE,
                                   app_version="1.0.14+29"))
    assert result["status"] == "ok", result
    assert result["state"] == "queued", result
    assert len(outbox(mod)) == 1
    # A due alert is attempted immediately rather than waiting for the sweep.
    assert len(bg.tasks) == 1


# ============================ payload validation ==========================

@test
def test_missing_contact_is_rejected_and_stores_nothing():
    mod = load()
    expect_http(400, post, mod, {"kind": "emergency", "captured_at": CAPTURED})
    assert outbox(mod) == []


@test
def test_control_only_contact_is_rejected():
    mod = load()
    expect_http(400, post, mod, payload(contact="\x00\x01\x1f  \x7f"))
    assert outbox(mod) == []


@test
def test_header_injection_via_contact_cannot_reach_a_recipient():
    """A contact carrying CRLF must not be able to add headers to the composed
    message. The control characters are stripped (as the client also strips
    them); what remains is not a valid address, so the alert is HELD for the
    operator rather than sent to an attacker-chosen Bcc."""
    mod = load()
    result, _ = post(mod, payload(contact="a@b.co\r\nBcc: attacker@evil.test"))
    assert result["status"] == "ok"
    rows = outbox(mod)
    assert len(rows) == 1
    assert "\r" not in rows[0]["destination"] and "\n" not in rows[0]["destination"]
    mod.drain_emergency_outbox()
    assert SENT == [], "nothing may be sent for an unroutable contact"
    rows = outbox(mod)
    assert rows[0]["status"] == "held"
    assert rows[0]["last_failure_kind"] == "contact_shape_unrecognised"


@test
def test_degraded_coordinates_never_reject_the_alert():
    """A bad coordinate degrades the alert; it must never lose it. The contact
    still needs to know help was asked for."""
    mod = load()
    for lat, lng in [("abc", "def"), (999.0, 999.0), (None, None), (LAT, None)]:
        SENT.clear()
        sub = load()
        result, _ = post(sub, payload(lat=lat, lng=lng))
        assert result["status"] == "ok", (lat, lng, result)
        rows = outbox(sub)
        assert len(rows) == 1
        assert rows[0]["lat"] is None and rows[0]["lng"] is None, (lat, lng)
        sub.drain_emergency_outbox()
        assert len(SENT) == 1
        assert "No location was available." in sent_text()[2]
    assert mod is not None


@test
def test_oversized_contact_is_truncated_not_rejected():
    mod = load()
    long_contact = ("x" * 300) + "@example.org"
    result, _ = post(mod, payload(contact=long_contact))
    assert result["status"] == "ok"
    rows = outbox(mod)
    assert len(rows[0]["destination"]) == 254  # kMaxTrustedContactLength


@test
def test_identity_fields_are_dropped_not_stored_or_relayed():
    """The client may attach account_number / device_id / app_version and a
    bearer token. None of them may reach storage, the outgoing message, or a
    log. This is the point where the client's minimisation would be undone."""
    mod = load()
    seed_device(mod)
    post(mod, payload(account_number=ACCOUNT, device_id=DEVICE,
                      app_version="1.0.14+29"), token=TOKEN)
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    blob = sent_text()[2] + "\n" + logtext(mod)
    for secret in (ACCOUNT, DEVICE, TOKEN, "1.0.14+29"):
        assert secret not in blob, "leaked %r" % secret
    rows = outbox(mod)
    assert len(rows) == 1
    row_blob = " ".join(str(v) for v in rows[0].values())
    for secret in (ACCOUNT, DEVICE, TOKEN, "1.0.14+29"):
        assert secret not in row_blob, "stored %r" % secret


@test
def test_client_supplied_message_text_is_never_relayed():
    """The message is composed server-side from the structured fields. That is
    what stops this unauthenticated route being an open relay for
    attacker-chosen text."""
    mod = load()
    post(mod, payload(message="CLICK http://evil.test FOR FREE MONEY"))
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    body = sent_text()[2]
    assert "evil.test" not in body
    assert "FREE MONEY" not in body


# =============================== idempotency ==============================

@test
def test_offline_retries_of_one_alert_relay_exactly_once():
    """The handset retries from its durable queue with the SAME captured_at."""
    mod = load()
    for _ in range(5):
        post(mod, payload())
        mod.drain_emergency_outbox()
    assert len(SENT) == 1, "one alert must produce one relay, got %d" % len(SENT)
    rows = outbox(mod)
    assert len(rows) == 1
    assert rows[0]["repeat_count"] == 4
    assert rows[0]["status"] == "delivered"


@test
def test_a_second_duress_entry_is_relayed_again():
    """A user still in danger triggering the code AGAIN produces a new
    captured_at, and must NOT be deduplicated away."""
    mod = load()
    post(mod, payload(captured_at="2026-08-06T01:23:45.000Z"))
    post(mod, payload(captured_at="2026-08-06T02:00:00.000Z"))
    mod.drain_emergency_outbox()
    assert len(outbox(mod)) == 2
    assert len(SENT) == 2, "an ongoing-danger repeat must be relayed"


@test
def test_retry_after_delivery_reports_already_relayed():
    mod = load()
    post(mod, payload())
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    result, bg = post(mod, payload())
    assert result["state"] == "already_relayed", result
    assert bg.tasks == [], "a delivered alert must not trigger another attempt"
    mod.drain_emergency_outbox()
    assert len(SENT) == 1


@test
def test_unusable_captured_at_still_delivers_and_collapses_retries():
    """DuressDispatch.fromQueueJson() substitutes the epoch for a corrupt queue
    record. Treating that as a real timestamp would let two different alerts
    collide, so it falls back to an hour bucket: retries inside the hour still
    collapse, and the suppression can never outlive it."""
    mod = load()
    for captured in ("1970-01-01T00:00:00.000Z", "not-a-timestamp", ""):
        sub = load()
        SENT.clear()
        result, _ = post(sub, payload(captured_at=captured))
        assert result["status"] == "ok", captured
        post(sub, payload(captured_at=captured))
        sub.drain_emergency_outbox()
        assert len(SENT) == 1, "%r: expected 1 relay, got %d" % (captured, len(SENT))
        rows = outbox(sub)
        assert len(rows) == 1 and rows[0]["captured_at"] is None
    assert mod is not None


@test
def test_different_contacts_are_never_deduplicated_together():
    mod = load()
    post(mod, payload(contact="one@example.org"))
    post(mod, payload(contact="two@example.org"))
    mod.drain_emergency_outbox()
    assert len(SENT) == 2


# ============================== rate limiting =============================

@test
def test_a_burst_is_paced_but_never_refused():
    """The whole rate-limit design in one test: over-limit traffic is delayed,
    never rejected, and nothing is discarded. No call may raise 429."""
    mod = load(EMERGENCY_IP_BURST_PER_MINUTE=2, EMERGENCY_CONTACT_BURST_PER_HOUR=2)
    for n in range(30):
        result, _ = post(mod, payload(captured_at="2026-08-06T01:%02d:00.000Z" % n))
        assert result["status"] == "ok", "call %d was refused: %r" % (n, result)
    rows = outbox(mod)
    assert len(rows) == 30, "every alert must be stored, got %d" % len(rows)
    now = time.time()
    deferred = [r for r in rows if r["not_before"] > now + 1]
    assert deferred, "over-limit traffic must actually be paced"
    assert len(deferred) < 30, "the first calls must not be paced"
    # And the paced ones are delivered once their delay elapses -- not dropped.
    release(mod)
    mod.drain_emergency_outbox()
    assert len(SENT) == 30, "paced alerts must still be relayed, got %d" % len(SENT)
    assert all(r["status"] == "delivered" for r in outbox(mod))


@test
def test_rate_limiting_never_returns_429():
    mod = load(EMERGENCY_IP_BURST_PER_MINUTE=1, EMERGENCY_CONTACT_BURST_PER_HOUR=1,
               EMERGENCY_GLOBAL_NEW_PER_HOUR=1)
    for n in range(12):
        try:
            post(mod, payload(captured_at="2026-08-06T03:%02d:00.000Z" % n))
        except HTTPException as exc:
            raise AssertionError("call %d refused with HTTP %s" % (n, exc.status_code))
    assert len(outbox(mod)) == 12


@test
def test_global_ceiling_paces_new_contacts_without_dropping_them():
    mod = load(EMERGENCY_GLOBAL_NEW_PER_HOUR=2)
    for n in range(8):
        post(mod, payload(contact="c%d@example.org" % n))
    rows = outbox(mod)
    assert len(rows) == 8
    assert [r for r in rows if r["not_before"] > time.time() + 1], \
        "a spray of new contacts must be paced"
    release(mod)
    mod.drain_emergency_outbox()
    assert len(SENT) == 8


@test
def test_a_proven_device_is_not_paced():
    """A caller holding a valid device token has proved the one thing an abuser
    cannot manufacture in bulk, so it gets a pacing-free lane."""
    mod = load(EMERGENCY_IP_BURST_PER_MINUTE=1, EMERGENCY_CONTACT_BURST_PER_HOUR=1)
    seed_device(mod)
    now = time.time()
    for n in range(10):
        post(mod, payload(captured_at="2026-08-06T04:%02d:00.000Z" % n), token=TOKEN)
    rows = outbox(mod)
    assert len(rows) == 10
    assert all(r["not_before"] <= now + 1 for r in rows), \
        "an authenticated duress alert must not be delayed"


@test
def test_an_invalid_token_costs_nothing_but_pacing():
    """A wrong/absent token must never turn into a rejection -- the realistic
    case is a handset whose credentials were wiped in the same moment."""
    mod = load()
    result, _ = post(mod, payload(), token="not-a-real-token")
    assert result["status"] == "ok"
    result, _ = post(mod, payload(captured_at="2026-08-06T05:00:00.000Z"))
    assert result["status"] == "ok"
    assert len(outbox(mod)) == 2


# ============================== no PII in logs ============================

@test
def test_logs_never_carry_the_contact_location_or_service_name():
    """Hub logs may be seized. Exercise every logging path this feature has --
    accept, immediate attempt, SMTP failure (whose exception text quotes the
    recipient), hold, drain, backlog notice -- and prove none of it lands."""
    mod = load(EMERGENCY_BACKLOG_NOTICE_SECONDS=1)
    seed_device(mod)
    post(mod, payload(account_number=ACCOUNT, device_id=DEVICE), token=TOKEN)
    # An SMTP rejection string routinely quotes the recipient address.
    SMTP_FAILURE[0] = RuntimeError("550 5.1.1 <%s>: recipient rejected" % CONTACT)
    mod.drain_emergency_outbox()
    SMTP_FAILURE[0] = None
    # A phone contact exercises the not-yet-configured channel path.
    post(mod, payload(contact="+95 9 123 456 789",
                      captured_at="2026-08-06T06:00:00.000Z"))
    release(mod)
    mod.drain_emergency_outbox()
    mod.emergency_backlog_notice(2)

    text = logtext(mod)
    assert text.strip(), "the test captured no log output at all"
    forbidden = [
        CONTACT, "amara", "example.org", "95 9 123", "95912345",
        ACCOUNT, DEVICE, TOKEN,
        "16.87", "96.19", "16.871311", "96.199379",
        "203.0.113.44",              # the client IP
        "/emergency/dispatch",       # the route path
        "duress", "panic", "emergency contact", "trusted contact",
        "550 5.1.1",                 # the SMTP rejection text
    ]
    lowered = text.lower()
    for needle in forbidden:
        assert needle.lower() not in lowered, \
            "log leaked %r\n---\n%s\n---" % (needle, text)
    # Nothing may reveal what this service is.
    assert "vpn" not in lowered, "log names a VPN:\n%s" % text
    assert "winsvpn" not in lowered


@test
def test_stored_failure_reasons_are_static_tokens_only():
    """last_failure_kind must be an exception TYPE or a fixed reason token --
    never a message, which can quote the recipient."""
    mod = load()
    post(mod, payload())
    SMTP_FAILURE[0] = RuntimeError("550 5.1.1 <%s>: recipient rejected" % CONTACT)
    mod.drain_emergency_outbox()
    SMTP_FAILURE[0] = None
    rows = outbox(mod)
    assert rows[0]["last_failure_kind"] == "RuntimeError", rows[0]["last_failure_kind"]
    assert CONTACT not in dbtext(mod).replace(rows[0]["destination"], "")


@test
def test_the_outgoing_message_names_no_service_and_no_account():
    mod = load()
    post(mod, payload(account_number=ACCOUNT, device_id=DEVICE))
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    sender, recipients, raw = sent_text()
    lowered = raw.lower()
    for needle in ("vpn", "winsvpn", "wins", "duress", "panic", "censor",
                   "circumvent", ACCOUNT.lower(), DEVICE.lower()):
        assert needle not in lowered, "outgoing message leaked %r:\n%s" % (needle, raw)
    assert sender == "alerts@notify.example"
    assert recipients == [CONTACT]
    # It still has to be useful to whoever receives it.
    assert "16.871311" in raw and "96.199379" in raw
    assert "maps" in lowered
    assert "may need help" in lowered


# ================================ channels ================================

@test
def test_email_channel_is_the_one_wired_channel():
    mod = load()
    assert set(mod.EMERGENCY_CHANNELS) == {"email", "sms", "messenger", "unroutable"}
    for name in ("sms", "messenger"):
        try:
            mod.EMERGENCY_CHANNELS[name]("x", "s", "b")
        except mod.EmergencyChannelUnavailable as exc:
            assert exc.reason.endswith("_not_implemented"), exc.reason
        else:
            raise AssertionError("%s must be an explicit owner decision" % name)


@test
def test_a_phone_contact_is_held_for_the_owner_not_dropped():
    mod = load()
    post(mod, payload(contact="+959123456789"))
    mod.drain_emergency_outbox()
    rows = outbox(mod)
    assert len(rows) == 1, "the alert must survive an unconfigured channel"
    assert rows[0]["channel"] == "sms"
    assert rows[0]["status"] == "held"
    assert rows[0]["last_failure_kind"] == "sms_channel_not_implemented"
    assert rows[0]["destination"] == "+959123456789", \
        "a held alert must keep its destination so it can still be delivered"


@test
def test_without_a_neutral_sender_the_alert_is_held_not_sent_branded():
    """Relaying from the branded address would put the service domain on the
    recipient's device -- exactly what the client design avoids. Default is to
    hold; the owner can opt in explicitly."""
    mod = load(EMERGENCY_FROM_EMAIL="")
    post(mod, payload())
    mod.drain_emergency_outbox()
    assert SENT == []
    rows = outbox(mod)
    assert rows[0]["status"] == "held"
    assert rows[0]["last_failure_kind"] == "neutral_sender_not_configured"

    mod2 = load(EMERGENCY_FROM_EMAIL="", EMERGENCY_ALLOW_BRANDED_SENDER="true")
    post(mod2, payload())
    mod2.drain_emergency_outbox()
    assert len(SENT) == 1, "the explicit opt-in must deliver"


@test
def test_a_held_alert_is_delivered_once_the_channel_appears():
    mod = load(EMERGENCY_FROM_EMAIL="")
    post(mod, payload())
    mod.drain_emergency_outbox()
    assert outbox(mod)[0]["status"] == "held"
    # Owner configures the sender; the same process picks the alert back up.
    mod.EMERGENCY_FROM_EMAIL = "alerts@notify.example"
    release(mod)
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    assert outbox(mod)[0]["status"] == "delivered"


@test
def test_delivery_scrubs_the_destination_and_the_location():
    """Once relayed there is no reason to keep who or where. What remains is an
    irreversible HMAC that keeps a later retry idempotent."""
    mod = load()
    post(mod, payload())
    mod.drain_emergency_outbox()
    row = outbox(mod)[0]
    assert row["status"] == "delivered"
    assert row["destination"] == ""
    assert row["lat"] is None and row["lng"] is None and row["captured_at"] is None
    assert row["dedupe_key"] and CONTACT not in row["dedupe_key"]
    assert CONTACT not in dbtext(mod)
    assert "16.871311" not in dbtext(mod)


@test
def test_transient_failures_retry_with_backoff_and_never_discard():
    mod = load()
    post(mod, payload())
    SMTP_FAILURE[0] = RuntimeError("temporary")
    for _ in range(3):
        release(mod)
        mod.drain_emergency_outbox()
    rows = outbox(mod)
    assert len(rows) == 1, "a failing alert must never be discarded"
    assert rows[0]["attempts"] >= 3
    assert rows[0]["status"] == "pending"
    SMTP_FAILURE[0] = None
    release(mod)
    mod.drain_emergency_outbox()
    assert len(SENT) == 1
    assert outbox(mod)[0]["status"] == "delivered"


# =============================== durability ===============================

@test
def test_a_storage_failure_returns_5xx_so_the_handset_keeps_its_copy():
    """The client wipes its only copy on 2xx. A 2xx the hub did not commit is a
    permanently lost life-safety message."""
    mod = load()

    def exploding_db():
        raise sqlite3.OperationalError("disk I/O error")

    original = mod.get_db
    mod.get_db = exploding_db
    try:
        exc = expect_http(503, post, mod, payload())
        assert "disk" not in str(exc.detail).lower()
    finally:
        mod.get_db = original
    assert outbox(mod) == []


@test
def test_the_disabled_switch_returns_503_never_200():
    mod = load(EMERGENCY_DISPATCH_ENABLED="false")
    expect_http(503, post, mod, payload())
    assert outbox(mod) == []


@test
def test_acceptance_is_committed_before_the_response():
    """Read the row back on a SEPARATE connection: if it is visible there, it
    survived the response and any crash after it."""
    mod = load()
    result, _ = post(mod, payload())
    assert result["state"] == "queued"
    with closing(sqlite3.connect(mod._DB)) as conn, conn:
        count = conn.execute("SELECT COUNT(*) FROM emergency_outbox").fetchone()[0]
    assert count == 1, "the alert was not committed before the 2xx"


# ================================= admin ==================================

@test
def test_admin_view_reports_counts_only():
    mod = load()
    post(mod, payload())
    post(mod, payload(contact="+959123456789",
                      captured_at="2026-08-06T07:00:00.000Z"))
    mod.drain_emergency_outbox()
    handler = mod.app.routes[("GET", "/admin/emergency/outbox")]
    request = FakeRequest(headers={}, body={}, path="/admin/emergency/outbox",
                          method="GET")
    result = handler(request, os.environ["ADMIN_TOKEN"])
    blob = json.dumps(result)
    assert CONTACT not in blob and "959123456789" not in blob
    assert "16.871311" not in blob
    assert result["counts"].get("delivered") == 1
    assert result["held_reasons"].get("sms_channel_not_implemented") == 1
    assert result["email_sender_configured"] is True


@test
def test_admin_view_requires_the_admin_token():
    mod = load()
    handler = mod.app.routes[("GET", "/admin/emergency/outbox")]
    request = FakeRequest(headers={}, body={}, path="/admin/emergency/outbox",
                          method="GET")
    expect_http(401, lambda: handler(request, "wrong-token"))


# ================================= runner =================================

def main():
    passed = failed = 0
    failures = []
    for fn in RESULTS:
        try:
            fn()
        except Exception:
            failed += 1
            failures.append((fn.__name__, traceback.format_exc()))
            print("FAIL  %s" % fn.__name__)
        else:
            passed += 1
            print("ok    %s" % fn.__name__)
    print("\n%d passed, %d failed, %d total" % (passed, failed, passed + failed))
    for name, tb in failures:
        print("\n===== %s =====\n%s" % (name, tb))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
