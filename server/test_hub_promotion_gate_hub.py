#!/usr/bin/env python3
"""Hub promotion gate and /logout rate limit (lane L77) against a given hub main.py, with REAL FastAPI/pydantic/
starlette and an in-process TestClient (the L65 loader).

Usage:  TZ=UTC python3 server/test_hub_promotion_gate_hub.py   (the installer beside it)
        TZ=UTC python3 test_hub_promotion_gate_hub.py <main.py> | --repo-installer <ONETOUCH.sh> [unittest args]

Item 1: POST /admin/nodes/tier promotes an off node only when EVERY transport
the row is configured for is ok and fresh. The node-side off-node gate record
(verify_offnode_gate_for_use / consume_offnode_gate) is stubbed to pass, and
the closure cleanup row is seeded confirmed, so the data-plane gate is the
only gate under test. Everything else in the route runs for real.
Item 2: POST /logout is rate-limited per request origin (20/60 s), the
increment is committed before the device lookup, and an exhausted source never
reaches require_device_auth_token.

Anti-vacuity: on the unpatched live file the item-1 refusal tests and the
item-2 limit tests FAIL (the aggregate-only gate promotes; /logout has no
limit). The allowed-case tests pass on both, by design.
"""
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
import types
import unittest
from contextlib import closing
from datetime import timedelta

sys.dont_write_bytecode = True
if os.environ.get("TZ") != "UTC":
    raise SystemExit("run with TZ=UTC (the hub's timezone)")
if len(sys.argv) < 2 or sys.argv[1].startswith("-") and sys.argv[1] != "--repo-installer":
    # Repository default: the control-plane installer next to this file.
    sys.argv[1:1] = ["--repo-installer",
                     os.path.join(os.path.dirname(os.path.abspath(__file__)), "wins_control_plane_setup_ONETOUCH.sh")]
if sys.argv[1] == "--repo-installer":
    INSTALLER = os.path.abspath(sys.argv[2])
    lines = open(INSTALLER, encoding="utf-8").read().splitlines(keepends=True)
    start = next(i for i, l in enumerate(lines) if "<<'PYEOF'" in l and "main.py" in l)
    end = next(j for j in range(start + 1, len(lines)) if lines[j].rstrip("\n") == "PYEOF")
    SOURCE = "".join(lines[start + 1:end])
    LABEL = f"{INSTALLER} (main.py heredoc)"
    ARGV_REST = sys.argv[3:]
else:
    TARGET = os.path.abspath(sys.argv[1])
    SOURCE = open(TARGET, encoding="utf-8").read()
    LABEL = TARGET
    ARGV_REST = sys.argv[2:]

import fastapi  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TMP = tempfile.mkdtemp(prefix="l77-routes-")
ADMIN = "test-admin-token"
ACCOUNT = "1111-2222-3333"
DEVICE = "l77-device-0"
TOKEN = "l77-device-token-not-a-secret"
SLUG = "lab-node"  # replaced per seed_node() call: promotion events are immutable
_SEQ = [0]
EVIDENCE = "e" * 64


def load():
    logdir = os.path.join(TMP, "log")
    os.makedirs(logdir, exist_ok=True)
    os.environ.update({
        "DATABASE_PATH": os.path.join(TMP, "vpn_users.db"),
        "RATE_LIMIT_SECRET": "test-rate-limit-secret",
        "ADMIN_TOKEN": ADMIN,
        "SPA_HMAC": "test-spa-hmac",
        "SECURITY_EVENTS_DB": os.path.join(TMP, "security_events.db"),
        "SMTP_PASS": "",
        "DEVICE_LIMIT": "3",
    })
    src = SOURCE
    src = src.replace('"/var/log/winsvpn"', repr(logdir))
    src = src.replace('"/var/log/winsvpn/master.log"', repr(os.path.join(logdir, "master.log")))
    src = src.replace('"/var/lib/wins-security-alerts"', repr(TMP))
    mod = types.ModuleType("wins_hub_l77")
    mod.__dict__["__file__"] = os.path.join(TMP, "main.py")
    sys.modules["wins_hub_l77"] = mod
    exec(compile(src, "wins_hub_main.py", "exec"), mod.__dict__)
    return mod


print(f"hub source: {LABEL} sha256={hashlib.sha256(SOURCE.encode()).hexdigest()} "
      f"fastapi={fastapi.__version__}", flush=True)
HUB = load()
# The off-node gate record is out of scope here (see the module docstring).
HUB.verify_offnode_gate_for_use = lambda conn, slug, digest, **_kw: []  # IA-SYNC SYNC-08: allow_hub_source
HUB.consume_offnode_gate = lambda conn, slug, digest, purpose: True
HUB.security_alert = lambda *args, **kwargs: None
CLIENT = TestClient(HUB.app, raise_server_exceptions=False)
# Lineage difference, read from the hub's own client-config parser: the repo
# lineage serves clients no plaintext stealth route when a TLS route exists
# (parse_xray_transports keep_plaintext=False), the live lineage serves both.
# Expectations about the plaintext transport of a fleet-shaped row follow it.
PLAINTEXT_OFFERED_WITH_TLS = any(
    t["security"] == "none" for t in HUB.parse_xray_transports(
        '[{"port":80,"security":"none"},{"port":443,"security":"tls"}]', 80, "none"))


def db():
    conn = sqlite3.connect(HUB.DB_PATH)
    conn.row_factory = sqlite3.Row
    return closing(conn)


def fresh():
    return HUB.utcnow().isoformat()


def stale():
    return (HUB.utcnow() - timedelta(minutes=HUB.DATA_PLANE_HARD_STALE_MINUTES + 15)).isoformat()


# The live fleet shape (every row on 2026-09-26): winn/3, direct AWG on,
# plaintext stealth on 80 and TLS stealth on 443.
FLEET_ROW = {
    "protocol_version": "winn/3", "direct_awg_enabled": 1,
    "endpoint": "192.0.2.10:9110", "wg_port": 9110,
    "stealth_endpoint": "stealth.example.test:80", "xray_security": "none",
    "stealth_transports": '[{"port":80,"security":"none"},{"port":443,"security":"tls"}]',
    "xray_path": "/stealth", "xray_uuid": "00000000-0000-4000-8000-000000000000",
    "public_key": "A" * 43 + "=", "stealth_public_port": 80, "regional_aliases": "[]",
}


def seed_node(**overrides):
    global SLUG
    _SEQ[0] += 1
    SLUG = f"lab-node-{_SEQ[0]}"
    row = dict(FLEET_ROW)
    now = fresh()
    row.update({
        "slug": SLUG, "name": "Lab", "status": "online", "management_status": "ok",
        "management_checked_at": now, "operator_enabled": 0, "ssh_host": "192.0.2.10",
        "data_plane_status": "ok", "data_plane_ok_at": now,
        "data_plane_udp_status": "ok", "data_plane_udp_ok_at": now,
        "data_plane_stealth_status": "ok", "data_plane_stealth_ok_at": now,
        "data_plane_stealth_tls_status": "ok", "data_plane_stealth_tls_ok_at": now,
    })
    row.update(overrides)
    with db() as conn, conn:
        HUB.ensure_schema(conn)
        cols = ", ".join(row)
        conn.execute(f"INSERT INTO nodes ({cols}) VALUES ({', '.join('?' * len(row))})", tuple(row.values()))
        conn.execute(
            "INSERT INTO node_closure_cleanup (slug, state, updated_at, confirmed_at) VALUES (?, 'confirmed', ?, ?)",
            (SLUG, now, now))


def promote():
    return CLIENT.post(
        "/admin/nodes/tier",
        data={"slug": SLUG, "tier": "premium", "evidence_sha256": EVIDENCE, "confirm_slug": SLUG},
        headers={"x-admin-token": ADMIN},
    )


def operator_enabled():
    with db() as conn:
        return conn.execute("SELECT operator_enabled FROM nodes WHERE slug=?", (SLUG,)).fetchone()[0]


class PromotionGate(unittest.TestCase):
    def assert_refused(self, response, *reasons):
        self.assertEqual(response.status_code, 409, response.text)
        detail = response.json()["detail"]
        self.assertIn("positive external data-plane proof is absent or stale", detail)
        for reason in reasons:
            self.assertIn(reason, detail)
        self.assertEqual(operator_enabled(), 0, "a refused promotion changed the latch")

    def assert_promoted(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["operator_enabled"])
        self.assertEqual(operator_enabled(), 1)

    def test_1_aggregate_ok_with_udp_probe_error_is_refused(self):
        # France on 2026-09-26 19:13 (L75 hub_gates_baseline.out): the
        # aggregate reads ok on stealth TLS alone.
        seed_node(data_plane_udp_status="probe_error", data_plane_udp_ok_at=stale(),
                  data_plane_stealth_status="unreachable", data_plane_stealth_ok_at=None)
        self.assert_refused(promote(), "udp is probe_error",
                            *(["stealth is unreachable"] if PLAINTEXT_OFFERED_WITH_TLS else []))

    def test_2_all_configured_transports_ok_and_fresh_is_allowed(self):
        seed_node()
        self.assert_promoted(promote())

    def test_3_a_stale_transport_is_refused(self):
        # Aggregate ok_at is the newest of the three, so it stays fresh.
        seed_node(data_plane_stealth_tls_ok_at=stale())
        self.assert_refused(promote(), "stealth_tls proof is stale")

    def test_4_node_without_a_port_80_transport_does_not_need_stealth(self):
        seed_node(stealth_endpoint="stealth.example.test:443", xray_security="tls",
                  stealth_transports='[{"port":443,"security":"tls"}]',
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None)
        self.assert_promoted(promote())

    def test_5_leftover_failure_on_an_unconfigured_transport_is_ignored(self):
        # The row no longer advertises plaintext stealth; an older probe verdict
        # for it must not block promotion.
        seed_node(stealth_endpoint="stealth.example.test:443", xray_security="tls",
                  stealth_transports='[{"port":443,"security":"tls"}]',
                  data_plane_stealth_status="unreachable", data_plane_stealth_ok_at=None)
        self.assert_promoted(promote())

    def test_6_configured_transport_reported_unconfigured_is_refused(self):
        name = "stealth" if PLAINTEXT_OFFERED_WITH_TLS else "stealth_tls"
        seed_node(**{f"data_plane_{name}_status": "unconfigured", f"data_plane_{name}_ok_at": None})
        self.assert_refused(promote(), f"{name} is unconfigured")

    def test_7_never_probed_udp_is_refused(self):
        seed_node(data_plane_udp_status="unknown", data_plane_udp_ok_at=None)
        self.assert_refused(promote(), "udp is unknown")

    def test_8_winn1_node_with_direct_awg_off_does_not_need_udp(self):
        seed_node(protocol_version="winn/1", direct_awg_enabled=0,
                  data_plane_udp_status="probe_error", data_plane_udp_ok_at=None)
        self.assert_promoted(promote())

    def test_9_winn3_node_needs_udp_even_with_direct_awg_off(self):
        seed_node(direct_awg_enabled=0, data_plane_udp_status="probe_error", data_plane_udp_ok_at=None)
        self.assert_refused(promote(), "udp is probe_error")

    def test_10_stale_aggregate_is_still_refused(self):
        seed_node(data_plane_ok_at=stale())
        self.assert_refused(promote())

    def test_12_advertised_tls_with_blank_xray_path_is_refused_and_named(self):
        # Sol OI-PG-1: the row advertises 443/tls but the probe cannot test it
        # (blank xray_path), so its verdict is 'unconfigured'. Advertised means
        # required: refuse and name the missing field, never skip it.
        seed_node(xray_path="", stealth_endpoint="stealth.example.test:443", xray_security="tls",
                  stealth_transports='[{"port":443,"security":"tls"}]',
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None,
                  data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth_tls is advertised but cannot be probed (missing xray_path)")

    def test_13_advertised_plaintext_without_xray_uuid_is_refused_and_named(self):
        seed_node(xray_uuid="", data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None,
                  data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth_tls is advertised but cannot be probed (missing xray_uuid)",
                            *(["stealth is advertised but cannot be probed (missing xray_uuid)"]
                              if PLAINTEXT_OFFERED_WITH_TLS else []))

    def test_14_node_without_ssh_host_is_refused_and_named(self):
        # The probe skips a node with no management host entirely.
        seed_node(ssh_host="")
        self.assert_refused(promote(), "udp is advertised but cannot be probed (missing ssh_host)")

    def test_15_registration_fallback_list_without_a_stealth_host_needs_no_stealth(self):
        # Registration always stores a stealth_transports entry (the
        # parse_xray_transports fallback, 80/none); with no stealth host no
        # client is handed stealth, so only UDP must be proven.
        seed_node(stealth_endpoint="", xray_uuid="", stealth_transports='[{"port":80,"security":"none"}]',
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None,
                  data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_promoted(promote())

    # ---- Sol PG Turn 2: every row shape a client is offered stealth for.
    # The current probe parses stealth_endpoint with rpartition(":"), so for a
    # portless endpoint it reports 'unconfigured': that is the verdict these
    # rows actually get, and the gate must refuse on it.

    def test_16_portless_endpoint_with_a_transport_list_requires_both(self):
        seed_node(stealth_endpoint="stealth.example.test", data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None, data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth_tls is unconfigured",
                            *(["stealth is unconfigured"] if PLAINTEXT_OFFERED_WITH_TLS else []))

    def test_17_portless_endpoint_with_a_transport_list_allowed_when_proven(self):
        seed_node(stealth_endpoint="stealth.example.test")
        self.assert_promoted(promote())

    def test_18_portless_endpoint_with_the_registration_default_list(self):
        seed_node(stealth_endpoint="stealth.example.test", stealth_transports='[{"port":80,"security":"none"}]',
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None, data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        r = promote()
        self.assert_refused(r, "stealth is unconfigured")
        self.assertNotIn("stealth_tls", r.json()["detail"], "the default list offers no TLS transport")

    def test_19_portless_default_list_allowed_when_plaintext_proven(self):
        seed_node(stealth_endpoint="stealth.example.test", stealth_transports='[{"port":80,"security":"none"}]',
                  data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_promoted(promote())

    def test_20_bracketed_ipv6_endpoint_requires_its_transport(self):
        seed_node(stealth_endpoint="[2001:db8::1]:443", xray_security="tls",
                  stealth_transports='[{"port":443,"security":"tls"}]',
                  data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth_tls is unconfigured")

    def test_21_uppercase_and_whitespace_still_offer_tls(self):
        seed_node(stealth_endpoint="  STEALTH.example.test:443  ", xray_security=" TLS ",
                  stealth_transports='[{"port":"443","security":" TLS "}]',
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None,
                  data_plane_stealth_tls_status="probe_error")
        self.assert_refused(promote(), "stealth_tls is probe_error")

    def test_22_unknown_xray_security_falls_back_to_plaintext_on_the_endpoint_port(self):
        seed_node(stealth_endpoint="stealth.example.test:8080", xray_security="quic", stealth_transports="[]",
                  data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None, data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth is unconfigured")

    def test_23_whitespace_only_endpoint_without_aliases_is_refused_and_named(self):
        seed_node(stealth_endpoint="   ", data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None, data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "missing a stealth host (stealth_endpoint host or regional_aliases)")

    def test_24_whitespace_only_endpoint_with_regional_aliases_needs_proof(self):
        seed_node(stealth_endpoint="   ", regional_aliases='["alias.example.test"]', data_plane_stealth_status="unconfigured", data_plane_stealth_ok_at=None, data_plane_stealth_tls_status="unconfigured", data_plane_stealth_tls_ok_at=None)
        self.assert_refused(promote(), "stealth_tls is unconfigured",
                            *(["stealth is unconfigured"] if PLAINTEXT_OFFERED_WITH_TLS else []))

    def test_25_unparsable_stealth_public_port_is_refused_and_named(self):
        seed_node(stealth_endpoint="stealth.example.test", stealth_public_port="eighty")
        self.assert_refused(promote(), "missing a parsable stealth_endpoint/stealth_public_port")

    def test_26_plaintext_requirement_follows_what_this_lineage_serves(self):
        # Fleet row, plaintext verdict failing, TLS proven: required (refused)
        # exactly when this lineage's client config offers plaintext.
        seed_node(data_plane_stealth_status="unreachable", data_plane_stealth_ok_at=None)
        if PLAINTEXT_OFFERED_WITH_TLS:
            self.assert_refused(promote(), "stealth is unreachable")
        else:
            self.assert_promoted(promote())

    def test_11_withdrawal_needs_no_proof(self):
        seed_node(operator_enabled=1, data_plane_udp_status="probe_error")
        r = CLIENT.post("/admin/nodes/tier", data={"slug": SLUG, "tier": "off"},
                        headers={"x-admin-token": ADMIN})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(operator_enabled(), 0)


def seed_device():
    with db() as conn, conn:
        HUB.ensure_schema(conn)
        conn.execute(
            "INSERT OR REPLACE INTO users (account_number, email, status, expiration_date, referral_code) "
            "VALUES (?, 'l77@example.test', 'active', '2030-01-01T00:00:00', 'L77CODE')", (ACCOUNT,))
        now = fresh()
        conn.execute(
            "INSERT OR REPLACE INTO devices (device_id, account_number, device_model, vpn_internal_ip, "
            "client_private_key, client_public_key, last_seen, location_slug, updated_at, device_auth_token_hash) "
            "VALUES (?, ?, 'Model', '10.8.0.2', 'PRIV', 'PUB', ?, 'no-such-node', ?, ?)",
            (DEVICE, ACCOUNT, now, now, HUB.token_digest(TOKEN)))


def device_rows():
    with db() as conn:
        return conn.execute("SELECT COUNT(*) FROM devices WHERE device_id=?", (DEVICE,)).fetchone()[0]


def logout(token="l77-invalid-token", body=None):
    return CLIENT.post("/logout", json=body if body is not None else
                       {"account_number": "l77-route-check", "device_id": "l77-route-check"},
                       headers={"authorization": f"Bearer {token}"})


def bucket_count():
    bucket = HUB.rate_limit_bucket("logout-ip", "testclient")
    with db() as conn:
        row = conn.execute("SELECT count FROM rate_limits WHERE bucket=?", (bucket,)).fetchone()
        return row[0] if row else 0


class LogoutRateLimit(unittest.TestCase):
    def setUp(self):
        with db() as conn, conn:
            HUB.ensure_schema(conn)
            conn.execute("DELETE FROM rate_limits")
        self.lookups = 0
        real = HUB.require_device_auth_token

        def counting(*args, **kwargs):
            self.lookups += 1
            return real(*args, **kwargs)

        HUB.require_device_auth_token = counting
        self.addCleanup(setattr, HUB, "require_device_auth_token", real)

    def test_1_twenty_first_request_in_a_minute_is_429(self):
        codes = [logout().status_code for _ in range(21)]
        self.assertEqual(codes[:20], [401] * 20)
        self.assertEqual(codes[20], 429)

    def test_2_exhausted_source_never_reaches_the_device_lookup(self):
        for _ in range(20):
            logout()
        self.assertEqual(self.lookups, 20)
        self.assertEqual(logout().status_code, 429)
        self.assertEqual(self.lookups, 20, "a rate-limited request reached require_device_auth_token")

    def test_3_increment_is_committed_although_authentication_fails(self):
        for _ in range(5):
            self.assertEqual(logout().status_code, 401)
        self.assertEqual(bucket_count(), 5)

    def test_4_authenticated_logout_still_deletes_the_device(self):
        seed_device()
        r = logout(token=TOKEN, body={"account_number": ACCOUNT, "device_id": DEVICE})
        self.assertEqual((r.status_code, r.json()), (200, {"ok": True}))
        self.assertEqual(device_rows(), 0)
        self.assertEqual(bucket_count(), 1)

    def test_5_missing_ids_answer_400_and_consume_nothing(self):
        # The deploy package's route proof sends exactly this body.
        r = CLIENT.post("/logout", json={})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(bucket_count(), 0)

    def test_6_free_logout_bucket_is_separate(self):
        for _ in range(20):
            logout()
        self.assertEqual(logout().status_code, 429)
        r = CLIENT.post("/free/logout", json={"device_id": "l77-free-route-check"},
                        headers={"authorization": "Bearer l77-invalid-token"})
        self.assertNotEqual(r.status_code, 429)


class _Verdicts(unittest.TextTestResult):
    """Also prints one 'VERDICT <class>.<test> PASS|FAIL' line per test."""

    def _emit(self, test, verdict):
        print(f"VERDICT {type(test).__name__}.{test._testMethodName} {verdict}", file=sys.stderr, flush=True)

    def addSuccess(self, test):
        super().addSuccess(test)
        self._emit(test, "PASS")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._emit(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._emit(test, "ERROR")


if __name__ == "__main__":
    import logging
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        prog = unittest.main(argv=[sys.argv[0]] + ARGV_REST, exit=False,
                             testRunner=unittest.TextTestRunner(resultclass=_Verdicts))
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    sys.exit(0 if prog.result.wasSuccessful() else 1)
