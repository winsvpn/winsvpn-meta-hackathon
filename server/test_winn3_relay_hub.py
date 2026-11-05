#!/usr/bin/env python3
"""Hub tests for w3r/1: the ciphertext relay Double VPN.

Like test_winn3_double_hub.py (packet A) these exercise the REAL control-plane
source, extracted from the heredoc in wins_control_plane_setup_ONETOUCH.sh,
against real SQLite. Exit descriptors are signed with real openssl keys
(test_winn3_descriptor_hub fixtures), so the signature path under test is the
shipping one. No test contacts a node, a Core, a live hub or the network; every
remote write is a fake.

What is under test, and why each is a safety property:

  * THE NO-OP DEFAULT. With WINN3_RELAY_ENABLED off, or for any client that does
    not send supports_winn3_relay, a Double VPN request is served exactly what it
    is served today (winn/1 over the Core's AmneziaWG ingress with a Core
    assignment), the Core payload carries no new key.
  * THE GATE OPENS ON EVERY CONDITION. A missing capability, switch, row, fresh
    report, listen entry, global IPv4 ingress host or servable exit each fall
    back to today's behaviour, never to a Double label without a relay.
  * THE RELAY PATH IS A SINGLE HOP FOR ASSIGNMENT PURPOSES. No Core assignment,
    no Core wait, no enrollment lease, the exit registry is published exactly as
    for single hop, the activation key is single use exactly as for single hop.
  * THE CORE LIST IS STATIC AND SIGNED. No device data, only exits with a valid
    stored signed descriptor, byte identical response when nothing is enabled.
  * ROLLBACK NEVER FAILS. Every switch removes the new fields at once.

No project address appears here: public hosts are built at run time from an
integer so that no routable literal sits in the file.

Run:  python3 server/test_winn3_relay_hub.py
"""
import _toolchain  # noqa: F401
import asyncio
import base64
from contextlib import closing
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import unittest
from datetime import timedelta
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_account_deletion_hub as harness  # noqa: E402
import test_winn3_descriptor_hub as desc  # noqa: E402
import test_winn3_serving_hub as serving  # noqa: E402

ADMIN = "test-admin-token"
CORE_TOKEN = "test-core-token-with-enough-entropy"
EXIT_SLUG = "test-node"
OTHER_EXIT_SLUG = "second-node"
CLIENT_KEY = base64.b64encode(b"K" * 32).decode()
SECOND_KEY = base64.b64encode(b"L" * 32).decode()
THIRD_KEY = base64.b64encode(b"M" * 32).decode()


def public_host(n: int) -> str:
    """A global unicast IPv4 built from an integer (no routable literal here)."""
    return str(ipaddress.IPv4Address((45 << 24) + n))


CORE_HOST = public_host(50)
CORE_AWG_ENDPOINT = CORE_HOST + ":9210"
# Exit addresses in documentation space: the hub does not require them global
# (the Core does, and its helper is another lane's).
EXIT_GATEWAY_ENDPOINT = "198.51.100.7:9111"


def envelope_json(payload, slot="g1"):
    payload_b64, sig_b64 = desc.envelope_for(payload, slot=slot)
    return json.dumps({"payload": payload_b64, "sig": sig_b64})


def good_report(*listens, state="active", **overrides):
    if not listens:
        listens = ({"exit_slug": EXIT_SLUG, "port": 9211, "state": "up", "packets": 12},)
    report = {
        "v": 1, "state": state, "port_range": "9211-9218", "wan_iface": "enp5s0",
        "applied_at": 1766000000,
        "rules_sha256": "a" * 64, "listens": [dict(item) for item in listens],
    }
    report.update(overrides)
    return report


class RelayCase(unittest.TestCase):
    """One hub per test. Subclasses pick the env."""

    relay_enabled = "1"
    env: dict = {}

    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        # os.environ is process wide: name every relay variable on every load.
        for name in ("WINN3_RELAY_PORT_RANGE", "WINN3_RELAY_REPORT_MAX_AGE_SECONDS"):
            os.environ.pop(name, None)
        settings = {"HIDE_CONTROL_ORIGIN": "0", "DOUBLE_VPN_ENABLED": "1",
                    "WINN3_RELAY_ENABLED": self.relay_enabled}
        settings.update(self.env)
        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = desc.load_hub_with_ring(**settings)
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        self.mod.logger.propagate = False
        self.log_records = []

        class Capture(logging.Handler):
            def emit(handler, record):  # noqa: N805
                self.log_records.append(record.getMessage())

        self.mod.logger.addHandler(Capture())
        self.mod.logger.setLevel(logging.INFO)
        self.mod.security_alert = lambda *args, **kwargs: None
        self.mod.sync_peer_to_node = lambda *args, **kwargs: True
        self.published = []
        self.used_at_publish = []
        self.bearers = {}
        self.publish_ok = True

        def fake_publish(conn, ip, slug, *args, **kwargs):
            # What the activation key looks like, in the publishing transaction,
            # at the moment the exit registry is written.
            row = conn.execute("SELECT activation_secret_used_at FROM users WHERE account_number = ?",
                               (harness.ACCOUNT,)).fetchone()
            self.used_at_publish.append(row["activation_secret_used_at"] if row else None)
            self.published.append(slug)
            return self.publish_ok

        self.mod.sync_winn3_registry_to_node = fake_publish
        self.tokens = harness.seed_account(self.mod, devices=1)
        self.seed_exit()
        self.seed_core()
        self.seed_relay()
        self.seed_report()

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR, ignore_errors=True)
        os.environ.pop("WINN3_RELAY_ENABLED", None)

    # ----------------------------- fixtures ---------------------------------

    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def seed_exit(self, slug=EXIT_SLUG, endpoint=EXIT_GATEWAY_ENDPOINT, seq=1):
        """A registered standalone winn/3 exit with a valid signed descriptor."""
        serving.seed_node(self.mod, slug=slug, obfuscation=serving.GOOD_OBFUSCATION)
        payload = desc.descriptor_payload(node=slug, endpoint=endpoint, seq=seq)
        now = self.mod.utcnow()
        before = (now - timedelta(hours=1)).isoformat()
        with self.db() as conn, conn:
            conn.execute(
                "UPDATE nodes SET protocol_version = 'winn/3', protocol_params_json = ?,"
                " winn3_descriptor_json = ?, carrier_classes = 'udp', path_mtu = 1450,"
                " winn3_canary_status = 'ok', winn3_canary_ok_at = ?,"
                " winn3_identity_sha256 = ?, deployment_released_at = ?,"
                " winn3_carrier_flipped_at = ? WHERE slug = ?",
                (json.dumps({"carrier": "winn3"}), envelope_json(payload),
                 now.isoformat(), "a" * 64, before, before, slug),
            )
            # A fresh canary is one bound to the row's identity, sequence and
            # generation (the same fixture the path MTU suite uses).
            row = conn.execute("SELECT * FROM nodes WHERE slug = ?", (slug,)).fetchone()
            bound = self.mod.winn3_result_binding(row)
            conn.execute(
                "UPDATE nodes SET winn3_canary_identity_sha256 = ?, winn3_canary_seq = ?,"
                " winn3_canary_generation = ? WHERE slug = ?",
                (bound["identity_sha256"], bound["seq"], bound["generation"], slug),
            )

    def seed_core(self, *, host=CORE_HOST, heartbeat_age=0):
        now = self.mod.utcnow()
        beat = (now - timedelta(seconds=heartbeat_age)).isoformat()
        with self.db() as conn, conn:
            self.mod.ensure_schema(conn)
            conn.execute(
                "INSERT OR REPLACE INTO core_servers (core_id, name, region, ingress_endpoint,"
                " tunnel_gateway_ipv4, stealth_endpoint, ingress_public_key, exit_public_key,"
                " xray_uuid, status, runtime_ready, promoted, active_promotion_id,"
                " obfuscation_json, management_status, management_checked_at,"
                " last_heartbeat, runtime_checked_at, regional_aliases, direct_awg_enabled)"
                " VALUES (?, 'Core', 'Test', ?, '10.9.1.1', 'core.example.test:80', ?, ?,"
                " '11111111-2222-4333-8444-666666666666', 'online', 1, 1, 'p1', ?,"
                " 'ok', ?, ?, ?, '[]', 1)",
                (self.mod.DOUBLE_VPN_CORE_ID, host + ":9210", "I" * 43 + "=", "D" * 43 + "=",
                 json.dumps(serving.GOOD_OBFUSCATION), beat, beat, beat),
            )

    def seed_relay(self, *, exit_slug=EXIT_SLUG, port=9211, enabled=1,
                   core_id=None):
        now = self.mod.utcnow().isoformat()
        with self.db() as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO core_relay_exits (core_id, exit_slug, relay_port,"
                " enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (core_id or self.mod.DOUBLE_VPN_CORE_ID, exit_slug, port, enabled, now, now),
            )

    def seed_report(self, report="good", *, age=0, core_id=None):
        if report == "good":
            report = good_report()
        reported = (self.mod.utcnow() - timedelta(seconds=age)).isoformat()
        with self.db() as conn, conn:
            if report is None:
                conn.execute("DELETE FROM core_relay_reports")
                return
            conn.execute(
                "INSERT OR REPLACE INTO core_relay_reports (core_id, report_json, reported_at)"
                " VALUES (?, ?, ?)",
                (core_id or self.mod.DOUBLE_VPN_CORE_ID, json.dumps(report), reported),
            )

    def core_row(self):
        with self.db() as conn:
            return conn.execute("SELECT * FROM core_servers WHERE core_id = ?",
                                (self.mod.DOUBLE_VPN_CORE_ID,)).fetchone()

    def verify_raw(self, *, device_id="relay-device", key=CLIENT_KEY, capable=True,
                   relay=True, double=True, location=EXIT_SLUG, secret=None, **overrides):
        # A first login of a device enrolls with the account's setup key (one
        # use); every later login of that device presents the bearer it was
        # issued, with an unchanged AmneziaWG key.
        if device_id in self.bearers:
            headers = {"content-type": "application/json",
                       "authorization": "Bearer " + self.bearers[device_id]}
        else:
            if secret is None:
                with self.mod.get_db() as conn:
                    secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
            headers = {"content-type": "application/json", "x-wins-activation": secret}
        request = harness.FakeRequest(path="/verify", headers=headers)
        extra = {}
        if capable:
            extra.update(supports_winn3=True, supports_winn3_descriptor=True)
        if capable and relay:
            extra.update(supports_winn3_relay=True)
        if key:
            extra["winn3_static_public"] = key
        extra.update(overrides)
        login = serving.build_login(
            self.mod, device_id=device_id, device_fingerprint="fp-" + device_id,
            device_model="audit-harness", location=location, double_vpn=double,
            selection_generation="a" * 32, ordinary_v3_failure_generation="a" * 32, **extra)
        # The Core wait is patched only so the AmneziaWG fallback can complete;
        # tests of the relay path assert it is never reached.
        with patch.object(self.mod, "_wait_for_core_assignment_ready_sync", return_value=True):
            return asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks())), device_id

    def verify(self, **kwargs):
        result, device_id = self.verify_raw(**kwargs)
        body = result if isinstance(result, dict) else json.loads(result.body)
        if body.get("device_auth_token"):
            self.bearers[device_id] = body["device_auth_token"]
        return body

    def config(self, **kwargs):
        return self.verify(**kwargs)["vpn_config"]

    def refused(self, status, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except harness.HTTPException as exc:
            self.assertEqual(status, exc.status_code, exc.detail)
            return exc
        self.fail(f"expected HTTP {status}, the call succeeded")

    def assignment(self, device_id="relay-device"):
        with self.db() as conn:
            return conn.execute("SELECT * FROM double_vpn_assignments WHERE device_id = ?",
                                (device_id,)).fetchone()

    def assert_relay_absent(self, body):
        config = body["vpn_config"]
        compat = body["vpnconfig"]
        for name in ("winn3_relay", "winn3relay"):
            self.assertNotIn(name, config)
            self.assertNotIn(name, compat)

    def assert_awg_double(self, body, device_id="relay-device", endpoint=None):
        config = body["vpn_config"]
        self.assertEqual("winn/1", config["protocol_version"])
        self.assertEqual({}, config["protocol_params"])
        self.assertEqual({}, config["winn3_descriptor"])
        self.assertTrue(config["double_vpn_active"])
        self.assertEqual(self.mod.DOUBLE_VPN_CORE_ID, config["double_vpn_core_id"])
        self.assertEqual(EXIT_SLUG, config["double_vpn_exit_slug"])
        self.assertEqual(endpoint or CORE_AWG_ENDPOINT, config["server_endpoint"])
        self.assert_relay_absent(body)
        row = self.assignment(device_id)
        self.assertIsNotNone(row, "the AmneziaWG Double must write its Core assignment")
        self.assertEqual("active", row["status"])

    def core_assignments(self):
        request = harness.FakeRequest(path="/api/v1/core/assignments", method="GET")
        with patch.object(self.mod, "require_core_token", lambda *a, **k: None):
            return self.mod.core_assignments(
                request, core_id=self.mod.DOUBLE_VPN_CORE_ID, x_core_token=CORE_TOKEN)

    def register(self, relay="__omit__", runtime_ready=True, ingress_endpoint=None):
        fields = dict(
            core_id=self.mod.DOUBLE_VPN_CORE_ID, name="Core", region="Test",
            management_host="core-management.test", management_user="ubuntu",
            ingress_endpoint=ingress_endpoint or CORE_AWG_ENDPOINT,
            tunnel_gateway_ipv4="10.9.1.1", ingress_public_key="I" * 43 + "=",
            exit_public_key="D" * 43 + "=", stealth_endpoint="core.example.test:80",
            xray_uuid="11111111-2222-4333-8444-666666666666", xray_path="/wins-core-tunnel",
            xray_security="none", stealth_transports=[], regional_aliases=["core.example.test"],
            direct_awg_enabled=True, status="online", runtime_ready=runtime_ready,
            applied_assignment_revisions=[],
            obfuscation_json=json.dumps(serving.GOOD_OBFUSCATION),
        )
        if relay != "__omit__":
            fields["relay"] = relay
        payload = self.mod.CoreRegistration(**fields)
        request = harness.FakeRequest(path="/api/v1/core/register")
        with patch.object(self.mod, "require_core_token", lambda *a, **k: None):
            return self.mod.register_core(payload, request, x_core_token=CORE_TOKEN)

    def stored_report(self):
        with self.db() as conn:
            row = conn.execute("SELECT * FROM core_relay_reports WHERE core_id = ?",
                               (self.mod.DOUBLE_VPN_CORE_ID,)).fetchone()
        return None if row is None else (json.loads(row["report_json"]), row["reported_at"])


# ======================= 1. the no-op default ===============================


class NoOpDefaultTests(RelayCase):
    relay_enabled = "0"

    def test_flag_off_serves_awg_double_for_a_relay_capable_client(self):
        body = self.verify()
        self.assert_awg_double(body)
        # The echo reports what the client sent; it is not a decision.
        self.assertTrue(body["vpn_config"]["client_capabilities"]["supports_winn3_relay"])

    def test_flag_off_response_equals_the_response_of_a_client_without_the_capability(self):
        with_cap = self.verify(relay=True)
        without = self.verify(relay=False)
        for body in (with_cap, without):
            body["vpn_config"].pop("client_capabilities")
            body["vpn_config"].pop("clientcapabilities", None)
            body["vpnconfig"].pop("clientcapabilities", None)
        self.assertEqual(with_cap["vpn_config"], without["vpn_config"])
        self.assertEqual(with_cap["vpnconfig"], without["vpnconfig"])

    def test_capability_echo_is_absent_for_every_other_client(self):
        for relay in (False,):
            config = self.config(relay=relay)
            self.assertNotIn("supports_winn3_relay", config["client_capabilities"])
            self.assertNotIn("supportswinn3relay", config["client_capabilities"])

    def test_malformed_capability_is_refused_not_coerced(self):
        for bad in ("true", 1, "false", [True]):
            with self.subTest(value=bad):
                with self.assertRaises(self.mod.Winn3ContractError):
                    self.mod.request_client_capabilities(
                        type("L", (), {"supports_winn3_relay": bad})())
        # Absent and an explicit false are both False and neither is echoed.
        for payload in (type("L", (), {})(), type("L", (), {"supports_winn3_relay": False})(),
                        type("L", (), {"supports_winn3_relay": None})()):
            self.assertNotIn("supports_winn3_relay", self.mod.request_client_capabilities(payload))
        echoed = self.mod.request_client_capabilities(type("L", (), {"supports_winn3_relay": True})())
        self.assertIs(True, echoed["supports_winn3_relay"])

    def test_core_assignments_response_is_byte_identical_when_the_flag_is_off(self):
        self.verify()
        # Rows exist and are enabled, the flag is off: the key must not appear.
        response = self.core_assignments()
        self.assertEqual({"ok", "core_id", "assignments"}, set(response))

    def test_registration_still_ignores_nothing_it_did_before(self):
        # The flag is off and a Core still reports: the report is stored (it is
        # data), but nothing is served from it.
        self.register(relay=good_report())
        self.assertIsNotNone(self.stored_report())
        self.assert_awg_double(self.verify())


# ======================= 2. the serving gate ================================


class ServedTests(RelayCase):
    def test_a_relay_double_is_served_with_every_field_of_the_contract(self):
        body = self.verify()
        config = body["vpn_config"]
        compat = body["vpnconfig"]
        self.assertEqual("winn/3", config["protocol_version"])
        self.assertEqual({"carrier": "winn3"}, config["protocol_params"])
        self.assertTrue(config["winn3_descriptor"].get("payload"))
        self.assertTrue(config["winn3_descriptor"].get("sig"))
        # The descriptor is the EXIT's own (the ruled selectedNode == descriptor.node).
        payload = json.loads(base64.b64decode(config["winn3_descriptor"]["payload"]))
        self.assertEqual(EXIT_SLUG, payload["node"])
        self.assertEqual(EXIT_SLUG, config["node_slug"])
        self.assertEqual(self.mod.DOUBLE_VPN_CORE_ID, config["double_vpn_core_id"])
        self.assertEqual(EXIT_SLUG, config["double_vpn_exit_slug"])
        self.assertIs(True, config["double_vpn_active"])
        self.assertIs(True, compat["doublevpnactive"])
        self.assertEqual(self.mod.DOUBLE_VPN_CORE_ID, compat["doublevpncoreid"])
        self.assertEqual(EXIT_SLUG, compat["doublevpnexitslug"])
        self.assertEqual({"v": 1, "endpoint": CORE_HOST + ":9211"}, config["winn3_relay"])
        self.assertEqual(config["winn3_relay"], compat["winn3_relay"])
        self.assertEqual(config["winn3_relay"], compat["winn3relay"])
        self.assertEqual(["endpoint", "v"], sorted(config["winn3_relay"]))
        self.assertIsInstance(config["winn3_relay"]["v"], int)
        self.assertNotIsInstance(config["winn3_relay"]["v"], bool)
        self.assertEqual(CLIENT_KEY, config["winn3_static_public"])
        self.assertEqual("", config["winn3_static_private"])
        self.assertTrue(config["winn3_inner_v4"].startswith("10.10."))
        self.assertEqual("1450", config["winn3_path_mtu"])
        self.assertEqual("udp", config["winn3_carrier_classes"])
        self.assertTrue(config["client_capabilities"]["supports_winn3_relay"])
        # The relay endpoint is the Core's ingress host with the relay port and
        # never the exit's address: the phone must not learn the exit's address
        # from this field and the exit descriptor still names the exit.
        self.assertNotIn("198.51.100.7", config["winn3_relay"]["endpoint"])

    def test_no_core_assignment_is_written_and_the_core_wait_is_never_made(self):
        def boom(name):
            def raiser(*args, **kwargs):
                raise AssertionError(name + " must not run for a relay Double")
            return raiser

        with patch.object(self.mod, "ensure_core_exit_peer", boom("ensure_core_exit_peer")), \
                patch.object(self.mod, "acquire_double_vpn_enrollment_lease",
                             boom("acquire_double_vpn_enrollment_lease")), \
                patch.object(self.mod, "_wait_for_core_assignment_ready_sync",
                             boom("_wait_for_core_assignment_ready_sync")):
            request = harness.FakeRequest(path="/verify", headers={
                "content-type": "application/json",
                "x-wins-activation": self.activation_secret()})
            login = serving.build_login(
                self.mod, device_id="relay-device", device_fingerprint="fp-relay",
                device_model="audit-harness", location=EXIT_SLUG, double_vpn=True,
                selection_generation="a" * 32, ordinary_v3_failure_generation="a" * 32,
                supports_winn3=True, supports_winn3_descriptor=True,
                supports_winn3_relay=True, winn3_static_public=CLIENT_KEY)
            result = asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
        body = result if isinstance(result, dict) else json.loads(result.body)
        self.assertIn("winn3_relay", body["vpn_config"])
        self.assertIsNone(self.assignment())
        with self.db() as conn:
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM double_vpn_assignments").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM core_exit_peers").fetchone()[0])
            self.assertEqual(0, conn.execute("SELECT COUNT(*) FROM double_vpn_enrollment_leases").fetchone()[0])

    def activation_secret(self):
        with self.mod.get_db() as conn:
            return self.mod.issue_activation_secret(conn, harness.ACCOUNT)

    def test_an_existing_awg_double_assignment_is_set_inactive_by_the_switch(self):
        self.seed_relay(enabled=0)
        self.assert_awg_double(self.verify())
        self.seed_relay(enabled=1)
        body = self.verify()
        self.assertIn("winn3_relay", body["vpn_config"])
        row = self.assignment()
        self.assertEqual("inactive", row["status"])
        self.assertIsNone(row["applied_revision"])

    def test_the_exit_registry_is_published_exactly_as_for_single_hop(self):
        relay_body = self.verify(device_id="relay-device", key=CLIENT_KEY)
        self.assertIn("winn3_relay", relay_body["vpn_config"])
        single_body = self.verify(device_id="single-device", key=SECOND_KEY, double=False)
        self.assertNotIn("winn3_relay", single_body["vpn_config"])
        self.assertEqual([EXIT_SLUG, EXIT_SLUG], self.published[:2])
        with self.db() as conn:
            document, _meta = self.mod.winn3_peer_registry_publication(conn, EXIT_SLUG)
        peers = {peer["static_public"]: peer for peer in document["peers"]}
        self.assertEqual({CLIENT_KEY, SECOND_KEY}, set(peers))
        self.assertEqual(set(peers[CLIENT_KEY]), set(peers[SECOND_KEY]))
        self.assertEqual(peers[CLIENT_KEY]["not_after"], peers[SECOND_KEY]["not_after"])
        # The device is a normal device row bound to the exit.
        with self.db() as conn:
            row = conn.execute("SELECT location_slug, winn3_static_public FROM devices"
                               " WHERE device_id = 'relay-device'").fetchone()
        self.assertEqual((EXIT_SLUG, CLIENT_KEY), (row["location_slug"], row["winn3_static_public"]))

    def test_a_publication_failure_refuses_and_leaves_the_activation_key_reusable(self):
        self.publish_ok = False
        error = self.refused(503, self.verify_raw)
        self.assertIn("synchronizing", error.detail)
        self.assertIsNone(self.assignment())
        self.publish_ok = True
        # The same setup key still enrolls: the rollback undid the early consume.
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT activation_secret_used_at FROM users WHERE account_number = ?",
                               (harness.ACCOUNT,)).fetchone()
        self.assertFalse(row["activation_secret_used_at"])

    def test_the_activation_key_is_single_use_exactly_as_for_single_hop(self):
        secret = self.activation_secret()
        first = self.verify(device_id="first-device", key=CLIENT_KEY, secret=secret)
        self.assertIn("winn3_relay", first["vpn_config"])
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT activation_secret_used_at FROM users WHERE account_number = ?",
                               (harness.ACCOUNT,)).fetchone()
        self.assertTrue(row["activation_secret_used_at"])
        error = self.refused(401, self.verify_raw, device_id="second-device",
                             key=SECOND_KEY, secret=secret)
        self.assertEqual(self.mod.SETUP_KEY_REFUSED_DETAIL, error.detail)
        # And the first device reconnects with its bearer, not the key.
        again = self.verify(device_id="first-device", key=CLIENT_KEY)
        self.assertIn("winn3_relay", again["vpn_config"])

    def test_the_activation_key_is_consumed_before_the_publication_as_for_single_hop(self):
        # A single hop enrollment consumes the key at authorization, inside the
        # transaction that later publishes. The relay path must not defer it to
        # the end (the deferral exists for the Core wait it never makes), or two
        # concurrent enrollments with one key would both reach the exit.
        self.verify(device_id="relay-device", key=CLIENT_KEY)
        self.assertTrue(self.used_at_publish[-1])
        single_secret = self.activation_secret()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_used_at = NULL WHERE account_number = ?",
                         (harness.ACCOUNT,))
        self.verify(device_id="single-device", key=SECOND_KEY, double=False, secret=single_secret)
        self.assertTrue(self.used_at_publish[-1])

    def test_both_double_paths_record_the_key_and_logout_returns_it(self):
        # Owner ruling 2026-10-25 ("Key returns"). The relay path spends the
        # key at the relay gate and the AmneziaWG Core path spends it after the
        # Core wait; either way the device row records the key that enrolled
        # it and the owner's logout makes that key valid again.
        for relay_enabled in (1, 0):
            self.seed_relay(enabled=relay_enabled)
            secret = self.activation_secret()
            body = self.verify(device_id="relay-device", key=CLIENT_KEY, secret=secret)
            if relay_enabled:
                self.assertIn("winn3_relay", body["vpn_config"])
            else:
                self.assert_awg_double(body)
            with self.db() as conn:
                device = conn.execute(
                    "SELECT activation_key_slot, activation_key_hash FROM devices"
                    " WHERE device_id = 'relay-device'").fetchone()
                user = conn.execute(
                    "SELECT activation_secret_hash, activation_secret_used_at FROM users"
                    " WHERE account_number = ?", (harness.ACCOUNT,)).fetchone()
            self.assertTrue(user["activation_secret_used_at"], relay_enabled)
            self.assertEqual((1, user["activation_secret_hash"]),
                             (device["activation_key_slot"], device["activation_key_hash"]))
            request = harness.FakeRequest(headers={
                "authorization": "Bearer " + self.bearers.pop("relay-device")})
            self.mod.logout_device_sync(harness.BackgroundTasks(), request,
                                        harness.ACCOUNT, "relay-device")
            with self.db() as conn:
                user = conn.execute(
                    "SELECT activation_secret_used_at FROM users WHERE account_number = ?",
                    (harness.ACCOUNT,)).fetchone()
            self.assertIsNone(user["activation_secret_used_at"], relay_enabled)

    def test_the_relay_endpoint_follows_the_core_ingress_host_with_no_re_sign(self):
        before = self.config()["winn3_relay"]["endpoint"]
        self.assertEqual(CORE_HOST + ":9211", before)
        moved = public_host(77)
        self.register(relay=good_report(), ingress_endpoint=moved + ":9210")
        # The registration refreshed the report; the descriptor row is untouched.
        with self.db() as conn:
            envelope = conn.execute("SELECT winn3_descriptor_json FROM nodes WHERE slug = ?",
                                    (EXIT_SLUG,)).fetchone()[0]
        config = self.config()
        self.assertEqual(moved + ":9211", config["winn3_relay"]["endpoint"])
        with self.db() as conn:
            self.assertEqual(envelope, conn.execute(
                "SELECT winn3_descriptor_json FROM nodes WHERE slug = ?", (EXIT_SLUG,)).fetchone()[0])

    def test_the_serve_path_logs_names_and_never_an_address(self):
        self.config()
        joined = "\n".join(self.log_records)
        self.assertIn("serving winn3 relay", joined)
        self.assertNotIn(CORE_HOST, joined)
        self.assertNotIn("198.51.100.7", joined)

    def test_the_final_resolution_guard_never_serves_a_double_label_without_the_relay(self):
        real = self.mod.resolve_served_winn3_descriptor
        calls = []

        def flaky(node, **kwargs):
            # The early gate sees a descriptor; the final resolution does not.
            calls.append(1)
            if len(calls) == 1:
                return real(node, **kwargs)
            return {}, "no-descriptor-registered"

        seen = {}
        original_init = harness.HTTPException.__init__

        def keep_headers(exc, status_code, detail="", **kw):
            original_init(exc, status_code, detail, **kw)
            seen["headers"] = kw.get("headers") or {}

        with patch.object(self.mod, "resolve_served_winn3_descriptor", flaky), \
                patch.object(harness.HTTPException, "__init__", keep_headers):
            error = self.refused(503, self.verify_raw)
        self.assertEqual("double_vpn_relay_changed", seen["headers"]["X-Wins-Error-Code"])
        self.assertEqual("1", seen["headers"]["Retry-After"])
        self.assertIn("relay changed", error.detail)
        self.assertIsNone(self.assignment())
        # Nothing was committed: the device row of this request does not exist.
        with self.db() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM devices WHERE device_id = 'relay-device'").fetchone())

    def test_the_paid_gate_is_unchanged_a_non_double_request_never_gets_the_relay(self):
        body = self.verify(double=False)
        self.assertNotIn("winn3_relay", body["vpn_config"])
        self.assertFalse(body["vpn_config"]["double_vpn_active"])
        self.assertEqual("", body["vpn_config"]["double_vpn_core_id"])
        self.assertEqual("", body["vpn_config"]["double_vpn_exit_slug"])
        self.assertEqual("winn/3", body["vpn_config"]["protocol_version"])

    def seed_free_account(self):
        with self.db() as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO users (account_number, email, status, expiration_date,"
                " referral_code, subscriber_name, renewal_source) VALUES (?, ?, 'active', ?, ?,"
                " 'Free VPN User', 'free_access')",
                (self.mod.FREE_ACCESS_ACCOUNT_NUMBER, "free@example.test",
                 self.mod.lifetime_expiry(), "FREECODE9999"))

    def free_double_login(self, **overrides):
        return serving.build_login(
            self.mod, account_number=self.mod.FREE_ACCESS_ACCOUNT_NUMBER,
            device_id="free-device", device_fingerprint="fp-free",
            free_access=True, double_vpn=True, location=EXIT_SLUG,
            supports_winn3=True, supports_winn3_descriptor=True,
            supports_winn3_relay=True, winn3_static_public=CLIENT_KEY,
            selection_generation="a" * 32, ordinary_v3_failure_generation="a" * 32, **overrides)

    def test_free_access_double_is_refused_even_when_the_legacy_free_flag_is_on(self):
        """H1, owner ruling 2026-10-13: Double VPN is paid only. The legacy flag is
        inert; with it patched on, with the STORED setting on, and with the env
        seed on, a free account is refused 403 and nothing Double is served."""
        self.seed_free_account()

        def attempt():
            return self.refused(
                403, lambda: asyncio.run(self.mod.verify_account(
                    harness.FakeRequest(path="/free/verify"), self.free_double_login(),
                    harness.BackgroundTasks())))

        with patch.object(self.mod, "double_vpn_free_access_enabled", return_value=True):
            self.assertIn("Double VPN is not available for free access", attempt().detail)
        # The real function with the stored setting really on.
        with self.db() as conn, conn:
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value)"
                         " VALUES ('double_vpn_free_access_enabled', 'true')")
        with self.db() as conn:
            self.assertTrue(self.mod.setting_bool(conn, "double_vpn_free_access_enabled", False))
            self.assertFalse(self.mod.double_vpn_free_access_enabled(conn))
        self.assertIn("Double VPN is not available for free access", attempt().detail)
        with patch.object(self.mod, "DOUBLE_VPN_FREE_ACCESS_ENABLED", True):
            self.assertIn("Double VPN is not available for free access", attempt().detail)
        with self.db() as conn:
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM double_vpn_assignments WHERE device_id = 'free-device'").fetchone())

    def test_the_status_surfaces_report_free_double_as_off_even_when_the_setting_is_on(self):
        with self.db() as conn, conn:
            conn.execute("INSERT OR REPLACE INTO system_settings (key, value)"
                         " VALUES ('double_vpn_free_access_enabled', 'true')")
        status = self.mod._free_status_sync("android")
        self.assertIs(False, status["double_vpn_free_access_enabled"])
        self.assertIs(False, status["doublevpnfreeaccessenabled"])
        # Every other surface that reports the flag reads it through the one
        # function, and that function never reads the stored value.
        with open(harness.HUB, encoding="utf-8") as handle:
            source = handle.read()
        self.assertEqual(
            source.count("double_vpn_free_access_enabled(conn)"),
            source.count("= double_vpn_free_access_enabled(conn)"),
            "a surface reads the free Double flag some other way than assigning the function result")
        self.assertNotIn('"double_vpn_free_access_enabled": setting_bool', source)

    def test_a_paid_double_request_is_unchanged_by_the_ruling(self):
        self.assertIn("winn3_relay", self.config())

    def test_the_free_request_forwards_the_capability_and_both_models_declare_both_spellings(self):
        """A SOURCE assertion, and it says so: the harness stubs pydantic, so
        field metadata does not survive into the loaded module. What can be
        checked is that the installer declares the field on both request models
        with default False and both wire spellings (what a real pydantic reads)
        and that the free path forwards it into the LoginRequest it builds."""
        src = harness._extract_main_block()
        verify_free = src[src.index("async def verify_free_access"):src.index("def perform_authenticated_device_logout")]
        self.assertIn("supports_winn3_relay=free_request.supports_winn3_relay,", verify_free)
        for model in ("class LoginRequest", "class FreeAccessRequest"):
            start = src.index(model)
            block = src[start:src.index("\nclass ", start + 1)]
            lines = [ln for ln in block.splitlines() if ln.strip().startswith("supports_winn3_relay:")]
            self.assertEqual(1, len(lines), model)
            self.assertIn("default=False", lines[0])
            self.assertIn('"supports_winn3_relay"', lines[0])
            self.assertIn('"supportswinn3relay"', lines[0])
        block = src[src.index("class CoreRegistration"):src.index("\nclass ", src.index("class CoreRegistration") + 1)]
        self.assertEqual(1, len([ln for ln in block.splitlines() if ln.strip().startswith("relay:")]))


# ======================= 3. every gate falls back ===========================


class GateTests(RelayCase):
    """Each gate, alone, falls back to today's behaviour."""

    def test_the_baseline_is_served(self):
        self.assertIn("winn3_relay", self.config())

    def fallback(self, mutate, *, label, endpoint=None, **verify_kwargs):
        """Mutate one condition, expect AmneziaWG Double, restore."""
        with self.subTest(gate=label):
            mutate()
            body = self.verify(**verify_kwargs)
            self.assert_awg_double(body, endpoint=endpoint)
            self.assertNotIn("winn3_relay", body["vpn_config"])

    def restore(self):
        self.seed_exit()
        self.seed_core()
        self.seed_relay()
        self.seed_report()

    def test_request_side_gates(self):
        for label, kwargs in (
            ("capability absent", dict(relay=False)),
            ("capability explicit false", dict(supports_winn3_relay=False)),
            ("supports_winn3 missing", dict(supports_winn3=False)),
            ("descriptor capability missing", dict(supports_winn3_descriptor=False)),
        ):
            self.fallback(lambda: None, label=label, **kwargs)

    def test_switch_and_row_gates(self):
        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
            self.fallback(lambda: None, label="env flag off")
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", None):
            self.fallback(lambda: None, label="range invalid")
        with self.db() as conn, conn:
            conn.execute("DELETE FROM core_relay_exits")
        self.fallback(lambda: None, label="no relay row")
        self.restore()
        self.fallback(lambda: self.seed_relay(enabled=0), label="row disabled")
        self.restore()
        self.fallback(lambda: self.seed_relay(port=9100), label="port below the range")
        self.fallback(lambda: self.seed_relay(port=9219), label="port above the range")
        self.fallback(lambda: self.seed_relay(port=9210), label="port is the AWG ingress")
        self.restore()
        # The same ports, with a Core report that LISTENS on them (a report row
        # written past the sanitizer), so the range check is the only gate left.
        for port in (9100, 9210, 9219):
            self.seed_relay(port=port)
            self.seed_report(good_report({"exit_slug": EXIT_SLUG, "port": port, "state": "up", "packets": 0}))
            self.fallback(lambda: None, label=f"port {port} with a matching report")
            self.restore()
        with self.db() as conn, conn:
            conn.execute("DELETE FROM core_relay_exits")
        self.seed_relay(core_id="other-core")
        self.fallback(lambda: None, label="row of another core only")

    def test_a_malformed_relay_capability_is_refused_with_400_and_writes_nothing(self):
        """H3: the wire field is Any, so "true" and 1 reach the strict check and are
        refused as a malformed advertisement instead of being coerced into a
        capability the client never advertised."""
        for raw in ("true", 1, [], "false"):
            with self.subTest(raw=raw):
                error = self.refused(400, lambda r=raw: self.verify_raw(
                    device_id="malformed-" + str(abs(hash(str(r))) % 1000), supports_winn3_relay=r))
                self.assertIn("malformed", error.detail)
        with self.db() as conn:
            self.assertEqual(0, conn.execute(
                "SELECT COUNT(*) FROM double_vpn_assignments WHERE device_id LIKE 'malformed-%'").fetchone()[0])

    def test_a_core_reporting_another_range_keeps_the_relay_off(self):
        """H4: one range value, checked from both ends. A Core that runs with a
        different range (or reports none) is stored but never served, and the
        request is the AmneziaWG Double."""
        for label, report_range in (("wider range", "9211-9230"), ("shifted range", "9212-9219"),
                                    ("narrower range", "9211-9217")):
            self.fallback(lambda r=report_range: self.seed_report(good_report(port_range=r)), label=label)
            self.restore()
        # A report row written without the key (an old Core) is never served either.
        stale = good_report()
        del stale["port_range"]
        self.fallback(lambda: self.seed_report(stale), label="report without port_range")
        self.restore()
        self.assertIn("winn3_relay", self.config())

    def full_pool(self):
        pool = self.mod.winn3_inner_pool()
        return patch.object(self.mod, "winn3_inner_addresses_in_use",
                            return_value={str(host) for host in pool.hosts()})

    def test_a_full_inner_pool_falls_back_to_awg_double_not_a_503(self):
        """F-02: a new device cannot be issued an inner address when the pool is
        full. The request is served the AmneziaWG Double (assignment row written,
        Core wait made), never a 503, and nothing is deactivated first."""
        with self.full_pool():
            body = self.verify(device_id="pool-full-new-device")
            self.assert_awg_double(body, device_id="pool-full-new-device")
        # and the real allocator agrees: the pool really is full under the patch
        with self.full_pool(), self.db() as conn:
            self.assertEqual("", self.mod.allocate_winn3_inner_ip(conn))

    def test_a_device_that_already_holds_an_inner_address_is_still_served_the_relay_when_the_pool_is_full(self):
        first = self.config()
        self.assertIn("winn3_relay", first)
        inner = first["winn3_inner_v4"]
        self.assertTrue(inner)
        with self.full_pool():
            again = self.config()
        self.assertIn("winn3_relay", again)
        self.assertEqual(inner, again["winn3_inner_v4"])
        self.assertIsNone(self.assignment())

    def test_a_reenrollment_rotates_the_address_so_a_full_pool_falls_back(self):
        """The prediction mirrors rotate_winn3_identity: a request that will null
        the device's address needs a FREE address even though it holds one."""
        first = self.config()
        self.assertIn("winn3_relay", first)
        self.bearers.pop("relay-device")  # the next login enrolls again with the setup key
        with self.full_pool():
            body = self.verify()
        self.assert_awg_double(body)

    def test_the_pool_gate_unit_cases(self):
        row = {"winn3_inner_v4": "10.10.0.50"}
        with self.db() as conn:
            with self.full_pool():
                self.assertTrue(self.mod.winn3_relay_inner_pool_available(conn, row))
                self.assertFalse(self.mod.winn3_relay_inner_pool_available(conn, row, rotates_identity=True))
                self.assertFalse(self.mod.winn3_relay_inner_pool_available(conn, None))
                self.assertFalse(self.mod.winn3_relay_inner_pool_available(conn, {"winn3_inner_v4": ""}))
                # an address outside the pool is not "held"
                self.assertFalse(self.mod.winn3_relay_inner_pool_available(
                    conn, {"winn3_inner_v4": "192.0.2.5"}))
            self.assertTrue(self.mod.winn3_relay_inner_pool_available(conn, None))
            self.assertTrue(self.mod.winn3_relay_inner_pool_available(conn, row, rotates_identity=True))

    def test_the_gate_names_the_pool_blocker_and_the_readiness_does_not_evaluate_it(self):
        with self.db() as conn:
            node = dict(conn.execute("SELECT * FROM nodes WHERE slug = ?", (EXIT_SLUG,)).fetchone())
            relay_row = conn.execute("SELECT * FROM core_relay_exits").fetchone()
            core = conn.execute("SELECT * FROM core_servers").fetchone()
            caps = {"supports_winn3": True, "supports_winn3_spa": True,
                    "supports_winn3_descriptor": True, "supports_winn3_relay": True}
            with self.full_pool():
                blocked = self.mod.core_relay_blockers(
                    conn, core_id=self.mod.DOUBLE_VPN_CORE_ID, relay_row=relay_row, node=node,
                    capabilities=caps, core=core, device_row=None, check_inner_pool=True)
                self.assertEqual(["winn3_inner_pool_exhausted"], blocked)
                readiness_view = self.mod.core_relay_blockers(
                    conn, core_id=self.mod.DOUBLE_VPN_CORE_ID, relay_row=relay_row, node=node,
                    capabilities=caps, core=core)
                self.assertEqual([], readiness_view)

    def test_the_residual_503_after_a_planned_relay_rolls_back_first(self):
        """The pool gate passed and the allocator still failed (a concurrent request
        took the last address). The refusal is the existing 503; nothing of the
        failed request survives (get_db closes an uncommitted connection, which
        discards it, and the code also rolls back explicitly first: the guard text
        is pinned below because the two are indistinguishable from outside)."""
        real = self.mod.allocate_winn3_inner_ip
        calls = {"n": 0}

        def first_call_sees_a_free_address(conn):
            calls["n"] += 1
            return real(conn) if calls["n"] == 1 else ""

        with patch.object(self.mod, "allocate_winn3_inner_ip", first_call_sees_a_free_address):
            self.refused(503, lambda: self.verify_raw())
        self.assertEqual(2, calls["n"])
        self.assertIsNone(self.assignment())
        with self.db() as conn:
            self.assertIsNone(conn.execute(
                "SELECT winn3_inner_v4 FROM devices WHERE device_id = 'relay-device'").fetchone())
        with open(harness.HUB, encoding="utf-8") as handle:
            source = handle.read()
        self.assertRegex(
            source,
            r"            if double_relay:\n(?:                #[^\n]*\n)+                conn\.rollback\(\)\n"
            r"            raise HTTPException\(\n                status_code=503,\n"
            r"                detail=\"Selected Winn Protocol v3 node cannot be served for this request\.\",")

    def test_report_gates(self):
        self.fallback(lambda: self.seed_report(None), label="report missing")
        self.restore()
        self.fallback(lambda: self.seed_report(age=31), label="report stale")
        self.restore()
        self.fallback(lambda: self.seed_report(good_report(state="inactive")), label="report inactive")
        self.restore()
        self.fallback(lambda: self.seed_report(good_report({"exit_slug": OTHER_EXIT_SLUG, "port": 9211,
                                                            "state": "up", "packets": 0})),
                      label="listen for another exit")
        self.restore()
        self.fallback(lambda: self.seed_report(good_report({"exit_slug": EXIT_SLUG, "port": 9212,
                                                            "state": "up", "packets": 0})),
                      label="listen on another port")
        self.restore()
        self.fallback(lambda: self.seed_report(good_report({"exit_slug": EXIT_SLUG, "port": 9211,
                                                            "state": "down", "reason": "ring_not_pinned",
                                                            "packets": 0})),
                      label="listen down")
        self.restore()
        self.fallback(lambda: self.seed_report(good_report(), core_id="other-core") or self.seed_report(None) or
                      self.seed_report(good_report(), core_id="other-core"),
                      label="report of another core only")
        self.restore()
        with self.db() as conn, conn:
            conn.execute("UPDATE core_relay_reports SET report_json = 'not json'")
        self.fallback(lambda: None, label="report unreadable")

    def test_ingress_host_gate(self):
        for label, host in (
            ("hostname", "core.example.test"),
            ("private", "192.168.4.36"),
            ("loopback", "127.0.0.1"),
            ("cgnat", "100.64.1.1"),
            ("link local", "169.254.1.1"),
            ("documentation", "203.0.113.5"),
            ("multicast", "224.0.0.9"),
            ("ipv6", "2001:db8::1"),
            ("leading zero form", "0" + CORE_HOST),
        ):
            self.fallback(lambda host=host: self.seed_core(host=host), label="ingress " + label,
                          endpoint=host + ":9210")
            self.restore()

    def test_exit_gates(self):
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET protocol_version = 'winn/1' WHERE slug = ?", (EXIT_SLUG,))
        self.fallback(lambda: None, label="exit explicit winn/1")
        self.restore()
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json = NULL WHERE slug = ?", (EXIT_SLUG,))
        # A registered standalone exit without a descriptor refuses winn/3
        # (a Winn3ContractError): the relay gate fails closed and the AWG
        # Double (which ignores the exit's winn/3 registration) is served.
        self.fallback(lambda: None, label="exit descriptor missing")
        self.restore()
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET winn3_canary_status = 'failed' WHERE slug = ?", (EXIT_SLUG,))
        self.fallback(lambda: None, label="exit canary not fresh")
        self.restore()
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET protocol_params_json = ? WHERE slug = ?",
                         (json.dumps({"carrier": "direct-awg"}), EXIT_SLUG))
        self.fallback(lambda: None, label="exit carrier is not standalone")

    def test_core_gates_keep_todays_behaviour(self):
        # No Core, or a stale one: the request fails exactly as it does today,
        # a 503 from select_double_vpn_core's gate, and never a relay label.
        self.seed_core(heartbeat_age=10_000)
        error = self.refused(503, self.verify_raw)
        self.assertIn("Double VPN core is not available", error.detail)
        self.restore()
        with self.db() as conn, conn:
            conn.execute("UPDATE core_servers SET runtime_ready = 0")
        self.refused(503, self.verify_raw)

    def test_stealth_never_gets_the_relay(self):
        core = self.core_row()
        with self.db() as conn:
            node = dict(conn.execute("SELECT * FROM nodes WHERE slug = ?", (EXIT_SLUG,)).fetchone())
        login = serving.build_login(
            self.mod, device_id="relay-device", location=EXIT_SLUG, double_vpn=True, stealth_mode=True,
            supports_winn3=True, supports_winn3_descriptor=True, supports_winn3_relay=True)
        with self.db() as conn:
            self.assertIsNone(self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core))
            login = serving.build_login(
                self.mod, device_id="relay-device", location=EXIT_SLUG, double_vpn=True,
                supports_winn3=True, supports_winn3_descriptor=True, supports_winn3_relay=True)
            plan = self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core)
        self.assertEqual({"core_id": self.mod.DOUBLE_VPN_CORE_ID, "host": CORE_HOST, "port": 9211,
                          "endpoint": CORE_HOST + ":9211"}, plan)

    def test_the_gate_never_raises_and_a_failure_is_logged_by_name(self):
        core = self.core_row()
        with self.db() as conn:
            node = dict(conn.execute("SELECT * FROM nodes WHERE slug = ?", (EXIT_SLUG,)).fetchone())
        login = serving.build_login(self.mod, device_id="relay-device", location=EXIT_SLUG,
                                    double_vpn=True)
        with self.db() as conn:
            self.assertIsNone(self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core))
            # A broken dependency is a fallback, never a 500.
            login = serving.build_login(
                self.mod, device_id="relay-device", location=EXIT_SLUG, double_vpn=True,
                supports_winn3=True, supports_winn3_descriptor=True, supports_winn3_relay=True)
            with patch.object(self.mod, "core_relay_blockers", side_effect=RuntimeError("boom")):
                self.assertIsNone(self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core))
        joined = "\n".join(self.log_records)
        self.assertIn("winn3 relay not served (reason=capability)", joined)
        self.assertIn("winn3 relay not served (reason=gate_error)", joined)
        self.assertNotIn(CORE_HOST, joined)

    def test_flag_off_never_reaches_the_gate_and_the_gate_itself_refuses(self):
        def boom(*args, **kwargs):
            raise AssertionError("the relay gate must not run with the flag off")

        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False), \
                patch.object(self.mod, "resolve_served_double_relay", boom):
            self.assert_awg_double(self.verify())
        # And the gate, called directly with the flag off, answers None even
        # when every other condition holds.
        core = self.core_row()
        with self.db() as conn:
            node = dict(conn.execute("SELECT * FROM nodes WHERE slug = ?", (EXIT_SLUG,)).fetchone())
            login = serving.build_login(
                self.mod, device_id="relay-device", location=EXIT_SLUG, double_vpn=True,
                supports_winn3=True, supports_winn3_descriptor=True, supports_winn3_relay=True)
            self.assertIsNotNone(self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core))
            with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
                self.assertIsNone(self.mod.resolve_served_double_relay(conn, login=login, node=node, core=core))

    def test_rollback_flag_off_serves_awg_double_again_for_the_same_request(self):
        self.assertIn("winn3_relay", self.config())
        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
            body = self.verify()
        self.assert_awg_double(body)
        # and back on: the relay is served again, the assignment goes inactive
        body = self.verify()
        self.assertIn("winn3_relay", body["vpn_config"])
        self.assertEqual("inactive", self.assignment()["status"])


# ======================= 4. the Core's list ==================================


class CoreListTests(RelayCase):
    def relay(self, response=None):
        response = response or self.core_assignments()
        return response.get("relay")

    def test_the_exact_relay_shape(self):
        self.seed_exit(slug=OTHER_EXIT_SLUG, endpoint="198.51.100.9:9111")
        self.seed_relay(exit_slug=OTHER_EXIT_SLUG, port=9213)
        response = self.core_assignments()
        self.assertEqual({"ok", "core_id", "assignments", "relay"}, set(response))
        relay = response["relay"]
        self.assertEqual({"v", "port_range", "relays"}, set(relay))
        self.assertEqual(1, relay["v"])
        self.assertEqual("9211-9218", relay["port_range"])
        self.assertEqual([(EXIT_SLUG, 9211), (OTHER_EXIT_SLUG, 9213)],
                         [(item["exit_slug"], item["port"]) for item in relay["relays"]])
        for item in relay["relays"]:
            self.assertEqual({"exit_slug", "port", "descriptor"}, set(item))
            self.assertEqual({"payload", "sig"}, set(item["descriptor"]))
            payload = json.loads(base64.b64decode(item["descriptor"]["payload"]))
            self.assertEqual(item["exit_slug"], payload["node"])
        # The envelope is the stored one, verbatim.
        with self.db() as conn:
            stored = json.loads(conn.execute("SELECT winn3_descriptor_json FROM nodes WHERE slug = ?",
                                             (EXIT_SLUG,)).fetchone()[0])
        self.assertEqual(stored, relay["relays"][0]["descriptor"])

    def test_sorted_by_port_not_by_insertion(self):
        self.seed_exit(slug=OTHER_EXIT_SLUG, endpoint="198.51.100.9:9111")
        self.seed_relay(exit_slug=OTHER_EXIT_SLUG, port=9212)
        self.seed_relay(exit_slug=EXIT_SLUG, port=9218)
        ports = [item["port"] for item in self.relay()["relays"]]
        self.assertEqual([9212, 9218], ports)

    def test_no_device_account_or_key_data_is_in_the_list(self):
        self.verify()
        text = json.dumps(self.core_assignments())
        for needle in (CLIENT_KEY, "relay-device", harness.ACCOUNT, "client_public_key",
                       "winn3_static", "preshared", "assignment_revision"):
            self.assertNotIn(needle, text)

    def test_excluded_rows(self):
        def keys_after(sql, args=()):
            with self.db() as conn, conn:
                conn.execute(sql, args)
            relay = self.relay()
            self.seed_exit()
            return None if relay is None else [i["exit_slug"] for i in relay["relays"]]

        self.assertIsNone(keys_after("UPDATE core_relay_exits SET enabled = 0"))
        self.seed_relay()
        self.assertIsNone(keys_after("UPDATE nodes SET retired_at = ? WHERE slug = ?",
                                     (self.mod.utcnow().isoformat(), EXIT_SLUG)))
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET retired_at = NULL WHERE slug = ?", (EXIT_SLUG,))
        self.assertIsNone(keys_after("UPDATE nodes SET status = 'offline' WHERE slug = ?", (EXIT_SLUG,)))
        self.assertIsNone(keys_after("UPDATE nodes SET status = 'maintenance' WHERE slug = ?", (EXIT_SLUG,)))
        self.assertIsNone(keys_after("UPDATE nodes SET operator_enabled = 0 WHERE slug = ?", (EXIT_SLUG,)))
        self.assertIsNone(keys_after("UPDATE nodes SET winn3_descriptor_json = NULL WHERE slug = ?", (EXIT_SLUG,)))
        # A congested exit keeps its relay: existing sessions must not be torn
        # down by a capacity state (the serve gate refuses NEW logins itself).
        self.assertEqual([EXIT_SLUG], keys_after("UPDATE nodes SET status = 'congested' WHERE slug = ?",
                                                 (EXIT_SLUG,)))
        # A forged envelope (signature over other bytes) is not listed.
        forged = json.loads(envelope_json(desc.descriptor_payload(node=EXIT_SLUG, endpoint="198.51.100.7:9111")))
        forged["sig"] = base64.b64encode(b"\0" * 64).decode()
        self.assertIsNone(keys_after("UPDATE nodes SET winn3_descriptor_json = ? WHERE slug = ?",
                                     (json.dumps(forged), EXIT_SLUG)))
        # An expired descriptor is not listed either (serving control).
        expired = desc.descriptor_payload(node=EXIT_SLUG, endpoint="198.51.100.7:9111",
                                          iat=1_600_000_000, ttl=3600)
        self.assertIsNone(keys_after("UPDATE nodes SET winn3_descriptor_json = ? WHERE slug = ?",
                                     (envelope_json(expired), EXIT_SLUG)))

    def test_a_row_outside_the_range_is_not_listed(self):
        with self.db() as conn, conn:
            conn.execute("UPDATE core_relay_exits SET relay_port = 9400")
        self.assertIsNone(self.relay())

    def test_only_the_asking_cores_rows(self):
        self.seed_relay(core_id="other-core", exit_slug=EXIT_SLUG, port=9215)
        self.assertEqual([(EXIT_SLUG, 9211)],
                         [(i["exit_slug"], i["port"]) for i in self.relay()["relays"]])

    def test_flag_off_or_no_rows_leaves_the_response_byte_identical(self):
        baseline = {"ok": True, "core_id": self.mod.DOUBLE_VPN_CORE_ID, "assignments": []}
        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
            self.assertEqual(baseline, self.core_assignments())
        with self.db() as conn, conn:
            conn.execute("DELETE FROM core_relay_exits")
        self.assertEqual(baseline, self.core_assignments())
        self.assertEqual(json.dumps(baseline, sort_keys=True), json.dumps(self.core_assignments(), sort_keys=True))

    def test_assignment_revision_formula_is_unchanged(self):
        base = {field: "x" for field in self.mod.CORE_ASSIGNMENT_REVISION_FIELDS}
        # The formula as it stood before w3r/1, restated on purpose.
        canonical = {field: base.get(field) for field in self.mod.CORE_ASSIGNMENT_REVISION_FIELDS}
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        secret = (self.mod.MANAGEMENT_NAME_HMAC_KEY or self.mod.ADMIN_SECRET_TOKEN).encode()
        legacy = hmac.new(secret, b"core-assignment-v1\0" + encoded, hashlib.sha256).hexdigest()
        self.assertEqual(legacy, self.mod.core_assignment_revision(base))


# ======================= 5. the report =======================================


class ReportTests(RelayCase):
    def sanitize(self, raw):
        return self.mod.sanitize_core_relay_report(raw)

    def test_a_good_report_round_trips_and_unknown_keys_are_dropped(self):
        raw = good_report()
        raw["extra"] = "x"
        raw["listens"][0]["extra"] = "y"
        clean, reason = self.sanitize(raw)
        self.assertEqual("", reason)
        self.assertEqual(good_report(), clean)
        self.assertEqual({"v", "state", "port_range", "wan_iface", "applied_at", "rules_sha256", "listens"},
                         set(clean))

    def test_reason_is_kept_only_on_down(self):
        down = good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "down",
                            "reason": "descriptor_expired", "packets": 0})
        self.assertEqual("descriptor_expired", self.sanitize(down)[0]["listens"][0]["reason"])
        up = good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "up", "reason": "x_y",
                          "packets": 0})
        self.assertNotIn("reason", self.sanitize(up)[0]["listens"][0])
        nodown_reason = good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "down", "packets": 0})
        self.assertNotIn("reason", self.sanitize(nodown_reason)[0]["listens"][0])

    def test_malformed_reports_are_dropped_whole(self):
        def mutate(fn):
            report = good_report()
            fn(report)
            return report

        cases = {
            "not an object": "string",
            "list": [],
            "version string": mutate(lambda r: r.update(v="1")),
            "version bool": mutate(lambda r: r.update(v=True)),
            "version 2": mutate(lambda r: r.update(v=2)),
            "version float": mutate(lambda r: r.update(v=1.0)),
            "state word": mutate(lambda r: r.update(state="running")),
            "state missing": mutate(lambda r: r.pop("state")),
            "iface empty": mutate(lambda r: r.update(wan_iface="")),
            "iface long": mutate(lambda r: r.update(wan_iface="x" * 16)),
            "iface space": mutate(lambda r: r.update(wan_iface="en p")),
            "applied_at string": mutate(lambda r: r.update(applied_at="1")),
            "applied_at negative": mutate(lambda r: r.update(applied_at=-1)),
            "applied_at bool": mutate(lambda r: r.update(applied_at=True)),
            "applied_at huge": mutate(lambda r: r.update(applied_at=2 ** 54)),
            "sha short": mutate(lambda r: r.update(rules_sha256="a" * 63)),
            "sha upper": mutate(lambda r: r.update(rules_sha256="A" * 64)),
            "listens not a list": mutate(lambda r: r.update(listens={})),
            "listens too many": mutate(lambda r: r.update(listens=[
                {"exit_slug": f"node-{i:02d}", "port": 9211 + (i % 20), "state": "up", "packets": 0}
                for i in range(33)])),
            "listen not an object": mutate(lambda r: r.update(listens=["x"])),
            "slug bad": mutate(lambda r: r["listens"][0].update(exit_slug="Bad Slug")),
            "slug missing": mutate(lambda r: r["listens"][0].pop("exit_slug")),
            "port string": mutate(lambda r: r["listens"][0].update(port="9211")),
            "port bool": mutate(lambda r: r["listens"][0].update(port=True)),
            "port below": mutate(lambda r: r["listens"][0].update(port=9100)),
            "port above": mutate(lambda r: r["listens"][0].update(port=9231)),
            "port awg": mutate(lambda r: r["listens"][0].update(port=9210)),
            "listen state": mutate(lambda r: r["listens"][0].update(state="active")),
            "packets negative": mutate(lambda r: r["listens"][0].update(packets=-1)),
            "packets string": mutate(lambda r: r["listens"][0].update(packets="1")),
            "packets missing": mutate(lambda r: r["listens"][0].pop("packets")),
            "reason bad": mutate(lambda r: r["listens"][0].update(state="down", reason="Bad Reason")),
            "reason number": mutate(lambda r: r["listens"][0].update(state="down", reason=5)),
            "duplicate slug": good_report(
                {"exit_slug": EXIT_SLUG, "port": 9211, "state": "up", "packets": 0},
                {"exit_slug": EXIT_SLUG, "port": 9212, "state": "up", "packets": 0}),
            "duplicate port": good_report(
                {"exit_slug": EXIT_SLUG, "port": 9211, "state": "up", "packets": 0},
                {"exit_slug": OTHER_EXIT_SLUG, "port": 9211, "state": "up", "packets": 0}),
        }
        for label, raw in cases.items():
            with self.subTest(case=label):
                clean, reason = self.sanitize(raw)
                self.assertIsNone(clean)
                self.assertTrue(re.fullmatch(r"relay-report-[a-z0-9-]+", reason), reason)

    def test_the_report_carries_its_own_range_and_the_gate_compares_it(self):
        """The sanitizer judges listen ports against the range the Core REPORTS
        (so a mismatching Core is stored and named port_range_mismatch by the
        gate, not silently dropped as a bad port); a missing or malformed
        port_range drops the report whole."""
        wide = good_report({"exit_slug": EXIT_SLUG, "port": 9305, "state": "up", "packets": 0},
                           port_range="9300-9310")
        clean, _ = self.sanitize(wide)
        self.assertIsNotNone(clean)
        self.assertEqual("9300-9310", clean["port_range"])
        outside = good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "up", "packets": 0},
                              port_range="9300-9310")
        self.assertEqual("relay-report-listen-port", self.sanitize(outside)[1])
        for label, value in (("missing", "__omit__"), ("empty", ""), ("not text", 9211),
                             ("one number", "9211"), ("reversed", "9218-9211"),
                             ("below 1024", "80-90"), ("too wide", "9211-9300"),
                             ("contains the AWG ingress", "9200-9215"),
                             ("contains the data plane", "9100-9120"), ("letters", "a-b"),
                             ("spaces", " 9211-9218 x")):
            with self.subTest(port_range=label):
                report = good_report()
                if value == "__omit__":
                    del report["port_range"]
                else:
                    report["port_range"] = value
                clean, reason = self.sanitize(report)
                self.assertIsNone(clean)
                self.assertEqual("relay-report-port-range", reason)
        # Leading zeros normalise to the canonical text the gate compares.
        padded = good_report(port_range="09211-9218")
        self.assertEqual("9211-9218", self.sanitize(padded)[0]["port_range"])

    def test_oversize_is_dropped(self):
        listens = [{"exit_slug": "n" + "a" * 37 + f"{i:02d}", "port": 9211 + i, "state": "down",
                    "reason": "r" * 40, "packets": 2 ** 53} for i in range(32)]
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", (9211, 9260)):
            clean, reason = self.sanitize(good_report(*listens, port_range="9211-9260"))
            self.assertIsNone(clean)
            self.assertEqual("relay-report-oversize", reason)
            # The same shape with short values fits.
            small = [{"exit_slug": f"node-{i:02d}", "port": 9211 + i, "state": "up", "packets": 1}
                     for i in range(32)]
            self.assertIsNotNone(self.sanitize(good_report(*small, port_range="9211-9260"))[0])

    def test_registration_stores_replaces_and_deletes(self):
        self.seed_report(None)
        self.register(relay=good_report())
        report, reported_at = self.stored_report()
        self.assertEqual(good_report(), report)
        self.assertIsNotNone(self.mod.parse_iso_datetime(reported_at))
        newer = good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "down",
                             "reason": "ring_not_pinned", "packets": 3}, state="inactive")
        self.register(relay=newer)
        self.assertEqual(newer, self.stored_report()[0])
        # absent deletes (an older agent or a Core with the relay off)
        self.register()
        self.assertIsNone(self.stored_report())

    def test_a_malformed_report_never_fails_the_registration_and_clears_the_report(self):
        self.register(relay=good_report())
        self.assertIsNotNone(self.stored_report())
        for bad in ({"v": 9}, "junk", {"v": 1, "state": "active"}, {}, [], [{"v": 1}], 42, 3.5, True,
                    {"v": 1, "state": "active", "port_range": "bad", "wan_iface": "e", "applied_at": 1,
                     "rules_sha256": "a" * 64, "listens": []}):
            with self.subTest(bad=bad):
                self.register(relay=good_report())
                response = self.register(relay=bad, runtime_ready=True)
                self.assertTrue(response["ok"])
                self.assertTrue(response["runtime_ready"])
                self.assertIsNone(self.stored_report())
        self.assertTrue(any("dropped the winn3 relay report" in line for line in self.log_records))
        joined = "\n".join(self.log_records)
        self.assertNotIn("junk", joined)

    def test_a_registration_keeps_the_awg_double_heartbeat_even_with_a_bad_report(self):
        self.register(relay="not an object")
        row = self.core_row()
        self.assertEqual(1, row["runtime_ready"])

    def test_the_relay_is_served_from_a_registration_and_stops_when_it_goes_away(self):
        self.seed_report(None)
        self.assert_awg_double(self.verify())
        self.register(relay=good_report())
        self.assertIn("winn3_relay", self.verify()["vpn_config"])
        self.register()  # an agent that stops reporting
        self.assert_awg_double(self.verify())

    def test_the_report_expires_by_age_without_any_new_registration(self):
        self.register(relay=good_report())
        self.assertIn("winn3_relay", self.config())
        with self.db() as conn, conn:
            old = (self.mod.utcnow() - timedelta(seconds=self.mod.WINN3_RELAY_REPORT_MAX_AGE_SECONDS + 5)).isoformat()
            conn.execute("UPDATE core_relay_reports SET reported_at = ?", (old,))
        self.assert_awg_double(self.verify())


class EnvTests(unittest.TestCase):
    """The import time environment parsing, one hub per case."""

    def load(self, **env):
        for name in ("WINN3_RELAY_PORT_RANGE", "WINN3_RELAY_REPORT_MAX_AGE_SECONDS"):
            os.environ.pop(name, None)

        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        settings = {"HIDE_CONTROL_ORIGIN": "0", "DOUBLE_VPN_ENABLED": "1", "WINN3_RELAY_ENABLED": "1"}
        settings.update(env)
        with patch("logging.basicConfig", side_effect=close_handlers):
            mod = desc.load_hub_with_ring(**settings)
        self.addCleanup(shutil.rmtree, mod._TMPDIR, ignore_errors=True)
        self.addCleanup(lambda: os.environ.pop("WINN3_RELAY_ENABLED", None))
        for name in ("WINN3_RELAY_PORT_RANGE", "WINN3_RELAY_REPORT_MAX_AGE_SECONDS"):
            self.addCleanup(os.environ.pop, name, None)
        for handler in list(mod.logger.handlers):
            handler.close()
            mod.logger.removeHandler(handler)
        return mod

    def test_defaults(self):
        mod = self.load()
        self.assertEqual((9211, 9218), mod.WINN3_RELAY_PORT_RANGE)
        self.assertEqual("9211-9218", mod.WINN3_RELAY_PORT_RANGE_TEXT)
        self.assertEqual(30, mod.WINN3_RELAY_REPORT_MAX_AGE_SECONDS)
        self.assertTrue(mod.winn3_relay_enabled())

    def test_default_is_off(self):
        mod = self.load(WINN3_RELAY_ENABLED="")
        self.assertFalse(mod.winn3_relay_enabled())
        for value in ("0", "true", "yes", "2", " 0 "):
            self.assertFalse(self.load(WINN3_RELAY_ENABLED=value).winn3_relay_enabled(), value)
        self.assertTrue(self.load(WINN3_RELAY_ENABLED=" 1 ").winn3_relay_enabled())

    def test_a_custom_range_is_accepted(self):
        mod = self.load(WINN3_RELAY_PORT_RANGE="9300-9303")
        self.assertEqual((9300, 9303), mod.WINN3_RELAY_PORT_RANGE)
        self.assertEqual("9300-9303", mod.WINN3_RELAY_PORT_RANGE_TEXT)

    def test_bad_ranges_turn_the_relay_off(self):
        for value in ("9218-9211", "80-90", "9211-70000", "abc", "9211", "9211-", "-9218", "9211:9218",
                      "9200-9215", "9100-9120", "9211-9300", "9211-9218-9220", " 9211 - 9218 "):
            with self.subTest(value=value):
                mod = self.load(WINN3_RELAY_PORT_RANGE=value)
                self.assertIsNone(mod.WINN3_RELAY_PORT_RANGE)
                self.assertEqual("", mod.WINN3_RELAY_PORT_RANGE_TEXT)
                self.assertFalse(mod.winn3_relay_enabled())
        # An empty value is the default, which is valid; surrounding spaces are stripped.
        self.assertTrue(self.load(WINN3_RELAY_PORT_RANGE="").winn3_relay_enabled())
        self.assertEqual((9211, 9218), self.load(WINN3_RELAY_PORT_RANGE="  9211-9218 ").WINN3_RELAY_PORT_RANGE)

    def test_the_old_min_and_max_variables_are_no_longer_read(self):
        os.environ["WINN3_RELAY_PORT_MIN"] = "9300"
        os.environ["WINN3_RELAY_PORT_MAX"] = "9303"
        self.addCleanup(os.environ.pop, "WINN3_RELAY_PORT_MIN", None)
        self.addCleanup(os.environ.pop, "WINN3_RELAY_PORT_MAX", None)
        mod = self.load()
        self.assertEqual((9211, 9218), mod.WINN3_RELAY_PORT_RANGE)

    def test_report_age_is_clamped(self):
        self.assertEqual(5, self.load(WINN3_RELAY_REPORT_MAX_AGE_SECONDS="1").WINN3_RELAY_REPORT_MAX_AGE_SECONDS)
        self.assertEqual(300, self.load(WINN3_RELAY_REPORT_MAX_AGE_SECONDS="9999").WINN3_RELAY_REPORT_MAX_AGE_SECONDS)
        self.assertEqual(30, self.load(WINN3_RELAY_REPORT_MAX_AGE_SECONDS="x").WINN3_RELAY_REPORT_MAX_AGE_SECONDS)

    def test_the_schema_adds_two_tables_and_alters_nothing(self):
        mod = self.load()
        with closing(sqlite3.connect(mod._DB)) as conn:
            conn.row_factory = sqlite3.Row
            mod.ensure_schema(conn)
            mod.ensure_schema(conn)  # idempotent
            columns = {row["name"]: row["type"] for row in conn.execute("PRAGMA table_info(core_relay_exits)")}
            self.assertEqual({"core_id": "TEXT", "exit_slug": "TEXT", "relay_port": "INTEGER",
                              "enabled": "INTEGER", "created_at": "TEXT", "updated_at": "TEXT"}, columns)
            reports = {row["name"] for row in conn.execute("PRAGMA table_info(core_relay_reports)")}
            self.assertEqual({"core_id", "report_json", "reported_at"}, reports)
            for table, forbidden in (("core_servers", "relay"), ("core_exit_peers", "relay"),
                                     ("double_vpn_assignments", "relay"), ("devices", "relay")):
                names = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
                self.assertFalse([n for n in names if forbidden in n], (table, names))


# ======================= 6. admin routes =====================================


class AdminTests(RelayCase):
    def setUp(self):
        super().setUp()
        with self.db() as conn, conn:
            conn.execute("DELETE FROM core_relay_exits")
            conn.execute("DELETE FROM core_relay_reports")

    def set_exit(self, exit_slug=EXIT_SLUG, enabled=True, core_id=None, token=ADMIN):
        return self.mod.admin_set_core_relay_exit(
            request=harness.FakeRequest(path="/admin/cores/relay/exit"),
            core_id=core_id or self.mod.DOUBLE_VPN_CORE_ID, exit_slug=exit_slug,
            enabled=enabled, x_admin_token=token)

    def readiness(self, core_id="", token=ADMIN):
        return self.mod.admin_core_relay_readiness(
            request=harness.FakeRequest(path="/admin/cores/relay", method="GET"),
            core_id=core_id, x_admin_token=token)

    def rows(self):
        with self.db() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT core_id, exit_slug, relay_port, enabled FROM core_relay_exits ORDER BY relay_port")]

    def test_admin_token_is_required_on_both_routes(self):
        self.refused(401, self.set_exit, token="wrong")
        self.refused(401, self.readiness, token="wrong")
        self.refused(401, self.set_exit, token="")
        self.assertEqual([], self.rows())

    def test_the_lowest_free_port_is_allocated_and_kept_across_disable_and_enable(self):
        self.seed_exit(slug=OTHER_EXIT_SLUG, endpoint="198.51.100.9:9111")
        first = self.set_exit(EXIT_SLUG)
        self.assertEqual({"ok": True, "core_id": self.mod.DOUBLE_VPN_CORE_ID, "exit_slug": EXIT_SLUG,
                          "enabled": True, "port": 9211}, first)
        second = self.set_exit(OTHER_EXIT_SLUG)
        self.assertEqual(9212, second["port"])
        off = self.set_exit(EXIT_SLUG, enabled=False)
        self.assertEqual({"ok": True, "core_id": self.mod.DOUBLE_VPN_CORE_ID, "exit_slug": EXIT_SLUG,
                          "enabled": False, "port": 9211}, off)
        # the freed row keeps its port: a third exit does not take 9211
        self.seed_exit(slug="third-node", endpoint="198.51.100.11:9111")
        self.assertEqual(9213, self.set_exit("third-node")["port"])
        back = self.set_exit(EXIT_SLUG)
        self.assertEqual(9211, back["port"])
        self.assertEqual([(9211, 1), (9212, 1), (9213, 1)], [(r["relay_port"], r["enabled"]) for r in self.rows()])

    def test_ports_are_unique_per_core_and_a_second_core_may_reuse_a_port(self):
        self.set_exit(EXIT_SLUG)
        with self.db() as conn, conn:
            conn.execute("INSERT INTO core_servers (core_id, name, region, ingress_endpoint,"
                         " ingress_public_key, exit_public_key) VALUES ('other-core', 'o', 'o', 'x', 'k', 'k')")
        self.assertEqual(9211, self.set_exit(EXIT_SLUG, core_id="other-core")["port"])
        with self.db() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                with conn:
                    conn.execute("INSERT INTO core_relay_exits (core_id, exit_slug, relay_port, enabled,"
                                 " created_at, updated_at) VALUES (?, 'x-node', 9211, 1, 'a', 'a')",
                                 (self.mod.DOUBLE_VPN_CORE_ID,))

    def test_the_pool_runs_out_with_a_409_and_changes_nothing(self):
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", (9211, 9212)):
            self.seed_exit(slug="node-a", endpoint="198.51.100.21:9111")
            self.seed_exit(slug="node-b", endpoint="198.51.100.22:9111")
            self.set_exit("node-a")
            self.set_exit("node-b")
            error = self.refused(409, self.set_exit, EXIT_SLUG)
            self.assertIn("No free relay port", error.detail)
        self.assertEqual(2, len(self.rows()))

    def test_range_changes_reallocate_an_out_of_range_port(self):
        self.set_exit(EXIT_SLUG)
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", (9300, 9305)):
            self.assertEqual(9300, self.set_exit(EXIT_SLUG)["port"])
        self.assertEqual(9300, self.rows()[0]["relay_port"])

    # The owner's eero forwards today, one port per exit (the fleet has seven live
    # exits and Australia is being deployed): the recommended admin pins.
    FLEET = (("canada-ca1", 9211), ("germany-de1", 9212), ("uk-gb1", 9213), ("us-oregon1", 9214),
             ("malaysia-my1", 9215), ("singapore-sg1", 9216), ("australia-au1", 9217), ("brazil-br1", 9218))

    def seed_fleet(self, count=8):
        for index, (slug, _port) in enumerate(self.FLEET[:count]):
            self.seed_exit(slug=slug, endpoint="198.51.100.%d:9111" % (30 + index))

    def set_exit_pinned(self, slug, port, enabled=True):
        return self.mod.admin_set_core_relay_exit(
            request=harness.FakeRequest(path="/admin/cores/relay/exit"),
            core_id=self.mod.DOUBLE_VPN_CORE_ID, exit_slug=slug, enabled=enabled,
            port=port, x_admin_token=ADMIN)

    def assert_every_port_in_range(self):
        for row in self.rows():
            self.assertTrue(9211 <= row["relay_port"] <= 9218, row)

    def test_eight_exits_take_all_eight_ports_in_order_and_never_leave_the_range(self):
        self.seed_fleet()
        ports = [self.set_exit(slug)["port"] for slug, _ in self.FLEET]
        self.assertEqual(list(range(9211, 9219)), ports)
        self.assert_every_port_in_range()
        self.assertEqual(8, len(self.rows()))

    def test_the_owner_mapping_can_be_pinned_whatever_the_enabling_order(self):
        self.seed_fleet()
        for slug, port in reversed(self.FLEET):
            self.assertEqual(port, self.set_exit_pinned(slug, port)["port"])
        self.assertEqual([port for _, port in self.FLEET], [r["relay_port"] for r in self.rows()])
        by_port = {r["relay_port"]: r["exit_slug"] for r in self.rows()}
        self.assertEqual({port: slug for slug, port in self.FLEET}, by_port)

    def test_a_ninth_exit_gets_409_until_one_is_disabled_and_then_reclaims_its_port(self):
        self.seed_fleet()
        for slug, _ in self.FLEET:
            self.set_exit(slug)
        self.seed_exit(slug="ninth-node", endpoint="198.51.100.99:9111")
        error = self.refused(409, self.set_exit, "ninth-node")
        self.assertIn("No free relay port", error.detail)
        self.assertEqual(8, len(self.rows()))
        # Disabling frees nothing by itself (the row keeps its port) ...
        self.assertEqual(9213, self.set_exit("uk-gb1", enabled=False)["port"])
        self.assertEqual(9213, self.rows()[2]["relay_port"])
        # ... but the next allocation reclaims it and the disabled row goes away.
        self.assertEqual(9213, self.set_exit("ninth-node")["port"])
        slugs = {r["exit_slug"] for r in self.rows()}
        self.assertNotIn("uk-gb1", slugs)
        self.assertIn("ninth-node", slugs)
        self.assertEqual(8, len(self.rows()))
        self.assert_every_port_in_range()
        # The reclaimed exit cannot come back while every port is held by an active row.
        self.refused(409, self.set_exit, "uk-gb1")

    def test_a_retired_exit_gives_its_port_up_even_while_its_row_is_still_enabled(self):
        self.seed_fleet()
        for slug, _ in self.FLEET:
            self.set_exit(slug)
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET retired_at = ? WHERE slug = 'germany-de1'",
                         (self.mod.utcnow().isoformat(),))
        self.seed_exit(slug="ninth-node", endpoint="198.51.100.99:9111")
        self.assertEqual(9212, self.set_exit("ninth-node")["port"])
        self.assertNotIn("germany-de1", {r["exit_slug"] for r in self.rows()})
        # A row whose exit no longer exists at all is reclaimable too.
        with self.db() as conn, conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("DELETE FROM nodes WHERE slug = 'us-oregon1'")
        self.seed_exit(slug="tenth-node", endpoint="198.51.100.98:9111")
        self.assertEqual(9214, self.set_exit("tenth-node")["port"])

    def test_reclaim_takes_the_oldest_unused_port_first_and_prefers_a_never_used_one(self):
        self.seed_fleet(4)
        for slug, _ in self.FLEET[:4]:
            self.set_exit(slug)
        with self.db() as conn, conn:
            conn.execute("UPDATE core_relay_exits SET enabled = 0, updated_at = '2026-01-01T00:00:00'"
                         " WHERE exit_slug = 'uk-gb1'")
            conn.execute("UPDATE core_relay_exits SET enabled = 0, updated_at = '2025-01-01T00:00:00'"
                         " WHERE exit_slug = 'germany-de1'")
        self.seed_exit(slug="fifth-node", endpoint="198.51.100.99:9111")
        # Four ports (9215..9218) were never used: they come first, nothing is reclaimed.
        self.assertEqual(9215, self.set_exit("fifth-node")["port"])
        self.assertEqual(4 + 1, len(self.rows()))
        for slug in ("sixth-node", "seventh-node", "eighth-node"):
            self.seed_exit(slug=slug, endpoint="198.51.100.9%d:9111" % len(slug))
            self.set_exit(slug)
        self.assertEqual(8, len(self.rows()))
        self.seed_exit(slug="ninth-node", endpoint="198.51.100.77:9111")
        # Now only reclaim is left and the OLDEST disabled row (germany, 2025) goes first.
        self.assertEqual(9212, self.set_exit("ninth-node")["port"])
        self.assertEqual({"germany-de1"}, {"germany-de1", "uk-gb1"} - {r["exit_slug"] for r in self.rows()})

    def test_a_pin_outside_the_range_is_refused_and_changes_nothing(self):
        self.seed_fleet(2)
        for port in (9210, 9219, 9111, 1, 0, -5, 70000):
            with self.subTest(port=port):
                error = self.refused(400, self.set_exit_pinned, "canada-ca1", port)
                self.assertIn("outside the configured range", error.detail)
        self.assertEqual([], self.rows())

    def test_a_pin_onto_an_active_rows_port_is_refused_and_a_disabled_rows_port_is_reclaimed(self):
        self.seed_fleet(3)
        self.set_exit_pinned("canada-ca1", 9211)
        error = self.refused(409, self.set_exit_pinned, "germany-de1", 9211)
        self.assertIn("belongs to another enabled exit", error.detail)
        self.assertEqual([("canada-ca1", 9211)], [(r["exit_slug"], r["relay_port"]) for r in self.rows()])
        # a retired exit holding the port is not active
        self.set_exit("canada-ca1", enabled=False)
        self.assertEqual(9211, self.set_exit_pinned("germany-de1", 9211)["port"])
        self.assertEqual([("germany-de1", 9211)], [(r["exit_slug"], r["relay_port"]) for r in self.rows()])

    def test_a_pin_moves_an_existing_row_and_pinning_its_own_port_is_a_no_op(self):
        self.seed_fleet(2)
        self.set_exit("canada-ca1")
        self.assertEqual(9211, self.set_exit_pinned("canada-ca1", 9211)["port"])
        self.assertEqual(9216, self.set_exit_pinned("canada-ca1", 9216)["port"])
        self.assertEqual([("canada-ca1", 9216)], [(r["exit_slug"], r["relay_port"]) for r in self.rows()])
        # an unpinned re-enable keeps the in-range port it has
        self.set_exit("canada-ca1", enabled=False)
        self.assertEqual(9216, self.set_exit("canada-ca1")["port"])

    def test_a_pin_is_ignored_when_disabling(self):
        self.seed_fleet(1)
        self.set_exit("canada-ca1")
        self.assertEqual(9211, self.set_exit_pinned("canada-ca1", 9218, enabled=False)["port"])

    def test_refusals(self):
        error = self.refused(404, self.set_exit, "no-such-node")
        self.assertIn("Exit node not found", error.detail)
        self.refused(404, self.set_exit, EXIT_SLUG, core_id="no-such-core")
        self.refused(400, self.set_exit, "core-na")
        self.refused(400, self.set_exit, "Bad Slug")
        self.refused(400, self.set_exit, "x")
        self.refused(400, self.set_exit, EXIT_SLUG, core_id="Bad Core")
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET retired_at = ? WHERE slug = ?",
                         (self.mod.utcnow().isoformat(), EXIT_SLUG))
        self.refused(409, self.set_exit, EXIT_SLUG)
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", None):
            self.seed_exit()
            self.refused(409, self.set_exit, EXIT_SLUG)
        self.assertEqual([], self.rows())

    def test_staging_is_allowed_while_the_env_flag_is_off(self):
        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
            self.assertEqual(9211, self.set_exit(EXIT_SLUG)["port"])

    def test_disable_never_fails(self):
        self.set_exit(EXIT_SLUG)
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET retired_at = ? WHERE slug = ?",
                         (self.mod.utcnow().isoformat(), EXIT_SLUG))
        self.assertFalse(self.set_exit(EXIT_SLUG, enabled=False)["enabled"])
        with patch.object(self.mod, "WINN3_RELAY_PORT_RANGE", None):
            self.assertFalse(self.set_exit(EXIT_SLUG, enabled=False)["enabled"])
        # disabling something never configured is not an error and invents no row
        out = self.set_exit("never-seen", enabled=False)
        self.assertEqual((False, None), (out["enabled"], out["port"]))
        self.assertEqual(1, len(self.rows()))
        self.assertEqual(0, self.rows()[0]["enabled"])

    def test_readiness_names_every_blocker_and_reports_no_secret_or_address(self):
        self.set_exit(EXIT_SLUG)
        ready = self.readiness()
        self.assertEqual(["report_missing"], ready["exits"][0]["blockers"])
        self.register(relay=good_report())
        ready = self.readiness()
        self.assertEqual([], ready["exits"][0]["blockers"])
        self.assertEqual("9211-9218", ready["port_range"])
        self.assertTrue(ready["relay_enabled"])
        text = json.dumps(ready)
        for needle in (CORE_HOST, "198.51.100.7", "payload", "sig", "admission", ADMIN, CORE_TOKEN):
            self.assertNotIn(needle, text)
        self.assertEqual(sorted(self.mod.WINN3_RELAY_BLOCKERS), sorted(ready["known_blockers"]))

    def test_each_blocker_name_is_reported(self):
        self.set_exit(EXIT_SLUG)
        self.register(relay=good_report())

        def blockers():
            return self.readiness()["exits"][0]["blockers"]

        with patch.object(self.mod, "WINN3_RELAY_ENABLED", False):
            self.assertIn("relay_flag_off", blockers())
        self.seed_core(heartbeat_age=10_000)
        self.assertIn("core_not_ready", blockers())
        self.seed_core()
        self.seed_report(age=100)
        self.assertIn("report_stale", blockers())
        self.seed_report(good_report(state="inactive"))
        self.assertIn("report_inactive", blockers())
        self.seed_report(good_report(port_range="9211-9230"))
        found = blockers()
        self.assertIn("port_range_mismatch", found)
        self.assertNotIn("listen_missing", found)
        self.seed_report(good_report({"exit_slug": EXIT_SLUG, "port": 9211, "state": "down", "packets": 0}))
        self.assertIn("listen_down", blockers())
        self.seed_report(good_report({"exit_slug": OTHER_EXIT_SLUG, "port": 9211, "state": "up", "packets": 0}))
        self.assertIn("listen_missing", blockers())
        self.seed_report()
        self.seed_core(host="core.example.test")
        self.assertIn("ingress_host_not_ipv4_literal", blockers())
        self.seed_core()
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET protocol_version = 'winn/1' WHERE slug = ?", (EXIT_SLUG,))
        self.assertIn("exit_not_winn3", blockers())
        self.seed_exit()
        with self.db() as conn, conn:
            conn.execute("UPDATE nodes SET winn3_descriptor_json = NULL WHERE slug = ?", (EXIT_SLUG,))
        found = blockers()
        self.assertTrue({"exit_not_winn3", "exit_descriptor_missing"} & set(found), found)
        for name in found:
            self.assertIn(name, self.mod.WINN3_RELAY_BLOCKERS)

    def test_readiness_for_an_unknown_core_and_a_bad_core_id(self):
        self.assertEqual([], self.readiness(core_id="never-registered")["exits"])
        self.refused(400, self.readiness, core_id="Bad Core")


# ======================= 7. rollback ==========================================


class RollbackTests(RelayCase):
    def test_every_switch_removes_the_relay_at_once(self):
        self.assertIn("winn3_relay", self.config())
        steps = (
            ("admin row off", lambda: self.mod.admin_set_core_relay_exit(
                request=harness.FakeRequest(path="/x"), core_id=self.mod.DOUBLE_VPN_CORE_ID,
                exit_slug=EXIT_SLUG, enabled=False, x_admin_token=ADMIN),
             lambda: self.mod.admin_set_core_relay_exit(
                 request=harness.FakeRequest(path="/x"), core_id=self.mod.DOUBLE_VPN_CORE_ID,
                 exit_slug=EXIT_SLUG, enabled=True, x_admin_token=ADMIN)),
            ("report removed", lambda: self.seed_report(None), lambda: self.seed_report()),
            ("core agent stops reporting", lambda: self.register(), lambda: self.register(relay=good_report())),
        )
        for label, off, on in steps:
            with self.subTest(switch=label):
                off()
                body = self.verify()
                self.assert_awg_double(body)
                if label == "admin row off":
                    self.assertNotIn("relay", self.core_assignments())
                on()
                self.assertIn("winn3_relay", self.verify()["vpn_config"])

    def test_dropping_the_two_tables_restores_the_old_schema_behaviour(self):
        self.assertIn("winn3_relay", self.config())
        with self.db() as conn, conn:
            conn.execute("DROP TABLE core_relay_exits")
            conn.execute("DROP TABLE core_relay_reports")
        # ensure_schema recreates empty tables; the relay is then simply unconfigured
        self.assert_awg_double(self.verify())


# ======================= 8. installer shell: env persistence ===================


class InstallerEnvTests(unittest.TestCase):
    """The hub installer rebuilds the hub env file from a fixed write_env_kv list, so a
    relay switch that is not listed there is deleted by the next installer run. These
    tests read the real installer text and run its validator under bash."""

    @classmethod
    def setUpClass(cls):
        with open(harness.HUB, encoding="utf-8") as handle:
            cls.text = handle.read()
        match = re.search(r"^validate_winn3_relay_settings\(\) \{\n.*?^\}\n", cls.text, re.S | re.M)
        assert match, "validate_winn3_relay_settings is missing from the installer"
        cls.function = match.group(0)

    def run_validator(self, **env):
        values = {"WINN3_RELAY_ENABLED_DEFAULT": "0", "WINN3_RELAY_PORT_RANGE_DEFAULT": "9211-9218",
                  "WINN3_RELAY_REPORT_MAX_AGE_SECONDS_DEFAULT": "30"}
        values.update(env)
        script = "err() { printf '%s\\n' \"$*\" >&2; }\n" + self.function + "\nvalidate_winn3_relay_settings\n"
        import subprocess
        return subprocess.run(["bash", "-c", script], env={"PATH": os.environ.get("PATH", ""), **values},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_defaults_validate(self):
        self.assertEqual(0, self.run_validator().returncode)
        self.assertEqual(0, self.run_validator(WINN3_RELAY_ENABLED_DEFAULT="1").returncode)
        self.assertEqual(0, self.run_validator(WINN3_RELAY_PORT_RANGE_DEFAULT="9300-9363").returncode)

    def test_bad_values_are_refused(self):
        cases = (
            {"WINN3_RELAY_ENABLED_DEFAULT": "2"}, {"WINN3_RELAY_ENABLED_DEFAULT": "true"},
            {"WINN3_RELAY_ENABLED_DEFAULT": ""},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "80-90"}, {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9211-70000"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9218-9211"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9200-9215"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9100-9120"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9211-9300"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": "abc"}, {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9211"},
            {"WINN3_RELAY_PORT_RANGE_DEFAULT": ""}, {"WINN3_RELAY_PORT_RANGE_DEFAULT": "9211 - 9218"},
            {"WINN3_RELAY_REPORT_MAX_AGE_SECONDS_DEFAULT": "4"},
            {"WINN3_RELAY_REPORT_MAX_AGE_SECONDS_DEFAULT": "301"},
            {"WINN3_RELAY_REPORT_MAX_AGE_SECONDS_DEFAULT": "x"},
        )
        for env in cases:
            with self.subTest(env=env):
                result = self.run_validator(**env)
                self.assertNotEqual(0, result.returncode, env)
                self.assertTrue(result.stderr.strip(), env)

    def test_the_three_values_are_persisted_and_validated_at_preflight(self):
        for key in ("WINN3_RELAY_ENABLED", "WINN3_RELAY_PORT_RANGE",
                    "WINN3_RELAY_REPORT_MAX_AGE_SECONDS"):
            with self.subTest(key=key):
                self.assertEqual(1, len(re.findall(r"^  write_env_kv %s \"" % key, self.text, re.M)))
                self.assertIn('%s_DEFAULT="${%s:-' % (key, key), self.text)
        self.assertEqual(1, self.text.count("  validate_winn3_relay_settings || exit 1\n"))
        # The off default is the one a fresh installer writes, and the range default is
        # the ports the owner's router forwards.
        self.assertIn('WINN3_RELAY_ENABLED_DEFAULT="${WINN3_RELAY_ENABLED:-0}"', self.text)
        self.assertIn('WINN3_RELAY_PORT_RANGE_DEFAULT="${WINN3_RELAY_PORT_RANGE:-9211-9218}"', self.text)
        # One value: the old MIN and MAX variables are gone from the installer.
        self.assertNotIn("WINN3_RELAY_PORT_MIN", self.text)
        self.assertNotIn("WINN3_RELAY_PORT_MAX", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
