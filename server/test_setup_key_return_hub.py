#!/usr/bin/env python3
"""Setup keys return when their device is deactivated (owner ruling 2026-10-25,
"Key returns").

Exercises the REAL embedded hub (the main.py heredoc) against real SQLite, on
top of the three key harness in test_activation_keys3_hub.py. Nothing is sent
and no node is contacted.

What is pinned:

1. Activation records on the device row which key it spent: the slot and the
   stored secret_hash, in the transaction that consumed the key.
2. The owner's /logout, an admin removal (/admin/device/remove) and a support
   removal (Hoppy device-revoke, device-limit-reset) clear the used mark of
   exactly that key, in the transaction that deletes the device. The key then
   enrols any device, once.
3. A rotated key set (hash differs) and a device enrolled before the ruling
   (nothing recorded) return nothing.
4. Removals that are not a deactivation return nothing: expiry and PayPal
   revocation (revoke_account_runtime), the stale-device sweep, the duplicate
   cleanup of a re-enrolling device, and the slot replacement at the cap.
5. The device cap still holds with a returned key.
6. Two concurrent deactivations of one device return its key once, and a late
   one never undoes a later enrolment.
7. The account email says a key is used up when it activates a device and
   becomes valid again when that device is deactivated.
8. Review round 1: no key returns on an inactive or expired account; a record
   left by an older hub's re-enrolment (bearer rotated) returns nothing; a
   Double VPN Core enrolment that commits its row before spending the key
   leaves a row that returns nothing and is reused first at the cap; every
   devices schema carries the key columns.

Run: python3 -m pytest -q server/test_setup_key_return_hub.py
"""
import _toolchain  # noqa: F401
import json
import sqlite3
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_activation_keys3_hub as keys3
import test_winn3_descriptor_hub as dh

ACCOUNT = keys3.ACCOUNT
ADMIN = keys3.ADMIN
HOPPY_HMAC = "16-byte-test-hoppy-hmac-secret"


class KeyReturnBase(keys3.EnrolBase):
    def setUp(self):
        self.mod = self.load(
            HOPPY_AGENT_HMAC=HOPPY_HMAC,
            HOPPY_AGENT_IP_RATE_LIMIT_PER_MINUTE=1000,
            HOPPY_AGENT_ACCOUNT_RATE_LIMIT_PER_HOUR=1000,
        )
        harness.seed_account(self.mod, devices=0)
        dh.seed_node(self.mod)
        with self.mod.get_db() as conn:
            self.keys = self.mod.issue_activation_secrets(conn, ACCOUNT)
        self.bearers = {}

    # ---- helpers -----------------------------------------------------------
    def activate(self, key, n, **overrides):
        body = self.enrol(key, n) if not overrides else dh.served_config(
            self.mod, request_headers={"x-wins-activation": key}, location="lab-alpha",
            device_id=f"keys3-device-{n}", device_model="audit-harness",
            client_public_key=keys3.pub(40 + n % 20), **overrides,
        )
        self.assertEqual(body.get("status"), "authenticated", body)
        self.bearers[f"keys3-device-{n}"] = body["device_auth_token"]
        return f"keys3-device-{n}"

    def refused(self, key, n):
        with self.assertRaises(self.mod.HTTPException) as caught:
            self.enrol(key, n)
        self.assertEqual(caught.exception.status_code, 401)
        self.assertEqual(caught.exception.detail, self.mod.SETUP_KEY_REFUSED_DETAIL)

    def logout(self, device_id):
        request = harness.FakeRequest(headers={"authorization": "Bearer " + self.bearers[device_id]})
        return self.mod.logout_device_sync(harness.BackgroundTasks(), request, ACCOUNT, device_id)

    def admin_remove(self, device_id):
        return self.mod.admin_remove_device(
            harness.FakeRequest(), harness.BackgroundTasks(),
            account_number=ACCOUNT, device_id=device_id, device_model=None, x_admin_token=ADMIN,
        )

    def hoppy(self, handler, model, action, **body):
        token, _exp = self.mod.mint_hoppy_agent_token(ACCOUNT, action)
        request = harness.FakeRequest(headers={"x-hoppy-agent-token": token})
        payload = getattr(self.mod, model)(account_number=ACCOUNT, **body)
        return getattr(self.mod, handler)(request, harness.BackgroundTasks(), payload)

    def recorded(self, device_id):
        with self.db(self.mod) as conn:
            row = conn.execute(
                "SELECT activation_key_slot, activation_key_hash FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        return None if row is None else (row[0], row[1])

    def stored(self, index):
        # (slot, stored hash) of key `index` of the current set.
        slot, stored_hash, _expires, _used = self.key_rows(self.mod)[index]
        return (slot, stored_hash)


# ===================== 1. activation records the key ========================

class Recording(KeyReturnBase):
    def test_activation_records_the_slot_and_stored_hash_of_the_key_it_spent(self):
        for n, index in enumerate((2, 0, 1)):
            device = self.activate(self.keys[index], n)
            self.assertEqual(self.recorded(device), self.stored(index))
        # Never the plaintext.
        with self.db(self.mod) as conn:
            dump = "\n".join(conn.iterdump())
        for key in self.keys:
            self.assertNotIn(key, dump)

    def test_a_reconnect_with_the_bearer_keeps_the_record(self):
        device = self.activate(self.keys[1], 0)
        before = self.recorded(device)
        body = dh.served_config(
            self.mod, request_headers={"authorization": "Bearer " + self.bearers[device]},
            location="lab-alpha", device_id=device, device_model="audit-harness",
            client_public_key=keys3.pub(40), device_fingerprint="fp-keys3-0-0123456789",
        )
        self.assertEqual(body.get("status"), "authenticated", body)
        self.assertEqual(self.recorded(device), before)


# ============== 2. deactivation by the owner or support returns ==============

class Returning(KeyReturnBase):
    def test_owner_logout_returns_the_key_for_any_other_device(self):
        # Slot 1 (users row) and slot 3 (activation_extra_keys) alike.
        for index, (first, second, third) in ((0, (0, 1, 2)), (2, (3, 4, 5))):
            device = self.activate(self.keys[index], first)
            self.assertFalse(self.accepts(self.mod, self.keys[index]))
            self.assertEqual(self.logout(device), {"ok": True})
            self.assertNotIn(device, self.device_ids())
            self.assertTrue(self.accepts(self.mod, self.keys[index]))
            other = self.activate(self.keys[index], second)
            self.assertEqual(self.recorded(other), self.stored(index))
            # A returned key is single-use again.
            self.assertFalse(self.accepts(self.mod, self.keys[index]))
            self.refused(self.keys[index], third)
        # The untouched key was never spent or returned.
        self.assertTrue(self.accepts(self.mod, self.keys[1]))

    def test_only_the_deactivated_devices_key_returns(self):
        devices = [self.activate(key, n) for n, key in enumerate(self.keys)]
        self.logout(devices[1])
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [2])
        self.assertFalse(self.accepts(self.mod, self.keys[0]))
        self.assertFalse(self.accepts(self.mod, self.keys[2]))

    def test_admin_removal_returns_the_key(self):
        device = self.activate(self.keys[1], 0)
        result = self.admin_remove(device)
        self.assertEqual(result["remaining_devices_count"], 0)
        self.assertTrue(self.accepts(self.mod, self.keys[1]))
        self.activate(self.keys[1], 1)
        self.assertFalse(self.accepts(self.mod, self.keys[1]))

    def test_support_revoke_and_reset_return_the_keys(self):
        devices = [self.activate(key, n) for n, key in enumerate(self.keys)]
        self.hoppy("hoppy_agent_device_revoke", "HoppyDeviceRevokeRequest", "device-revoke",
                   device_id=devices[0], request_id="revoke-1")
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [1])
        self.hoppy("hoppy_agent_device_limit_reset", "HoppyAccountRequest", "device-limit-reset",
                   request_id="reset-1")
        self.assertEqual(self.device_ids(), [])
        self.assertEqual(len(self.live_keys(self.mod)), 3)
        for n, key in enumerate(self.keys, 10):
            self.activate(key, n)
        self.assertEqual(self.live_keys(self.mod), [])

    def test_a_returned_key_keeps_its_stored_expiry(self):
        # Returning a key clears its used mark only. A key row an older build
        # wrote with an expiry that has since passed stays refused.
        device = self.activate(self.keys[2], 0)
        past = (self.mod.utcnow() - timedelta(minutes=1)).isoformat(timespec="seconds")
        with self.mod.get_db() as conn:
            conn.execute("UPDATE activation_extra_keys SET expires_at = ? WHERE slot = 3", (past,))
        self.logout(device)
        self.assertEqual([row[0] for row in self.live_keys(self.mod) if row[0] == 3], [3])
        self.assertEqual(self.key_rows(self.mod)[2][2], past)
        self.assertFalse(self.accepts(self.mod, self.keys[2]))


# ======================= 3. nothing to return ================================

class NothingToReturn(KeyReturnBase):
    def test_a_rotated_key_set_does_not_revive_the_old_key(self):
        old_device = self.activate(self.keys[0], 0)
        old_record = self.recorded(old_device)
        old_keys = list(self.keys)
        with self.mod.get_db() as conn:
            self.keys = self.mod.issue_activation_secrets(conn, ACCOUNT)
        new_device = self.activate(self.keys[0], 1)  # the same slot, a new hash
        self.assertEqual(self.recorded(new_device), self.stored(0))
        self.assertNotEqual(self.recorded(new_device), old_record)
        rows_before = self.key_rows(self.mod)
        self.logout(old_device)
        self.assertEqual(self.key_rows(self.mod), rows_before)
        self.assertFalse(self.accepts(self.mod, old_keys[0]))
        self.assertFalse(self.accepts(self.mod, self.keys[0]))
        # The new set's own device still returns its key.
        self.logout(new_device)
        self.assertTrue(self.accepts(self.mod, self.keys[0]))
        self.assertFalse(self.accepts(self.mod, old_keys[0]))

    def test_a_device_enrolled_before_the_ruling_returns_nothing(self):
        legacy = self.activate(self.keys[1], 0)
        current = self.activate(self.keys[2], 1)
        with self.mod.get_db() as conn:
            conn.execute(
                "UPDATE devices SET activation_key_slot = NULL, activation_key_hash = NULL "
                "WHERE device_id = ?", (legacy,),
            )
        rows_before = self.key_rows(self.mod)
        self.logout(legacy)
        self.assertEqual(self.key_rows(self.mod), rows_before)
        self.assertFalse(self.accepts(self.mod, self.keys[1]))
        # A recorded device on the same account still returns its own key.
        self.admin_remove(current)
        self.assertTrue(self.accepts(self.mod, self.keys[2]))
        self.assertFalse(self.accepts(self.mod, self.keys[1]))

    def test_removals_that_are_not_a_deactivation_return_nothing(self):
        devices = [self.activate(key, n) for n, key in enumerate(self.keys)]
        for index, device in enumerate(devices):
            self.assertEqual(self.recorded(device), self.stored(index))
        # Stale-device sweep.
        old = (self.mod.utcnow() - timedelta(days=self.mod.STALE_DEVICE_RETENTION_DAYS + 5)).isoformat()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?", (old, devices[0]))
            self.mod.cleanup_stale_devices(conn)
        self.assertNotIn(devices[0], self.device_ids())
        self.assertEqual(self.live_keys(self.mod), [])
        # Expiry, PayPal cancel/suspend, refund and reversal all end in
        # revoke_account_runtime; so does an account number being recycled.
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date = ? WHERE account_number = ?",
                         ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(), ACCOUNT))
            self.assertTrue(self.mod.expire_account_runtime_if_due(conn, ACCOUNT))
        self.assertEqual(self.device_ids(), [])
        self.assertEqual(self.live_keys(self.mod), [])

    def test_a_device_replaced_by_its_own_re_enrolment_returns_nothing(self):
        # The same physical device (same fingerprint) enrols again with another
        # key under a new install id: the earlier row is cleaned up as a
        # duplicate, which is not a deactivation.
        first = self.activate(self.keys[0], 0, device_fingerprint="fp-same-phone-0123456789")
        second = self.activate(self.keys[1], 1, device_fingerprint="fp-same-phone-0123456789")
        self.assertEqual(self.device_ids(), [second])
        self.assertNotEqual(first, second)
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [3])
        self.assertEqual(self.recorded(second), self.stored(1))


# ============================ 4. the device cap ==============================

class Cap(KeyReturnBase):
    def test_the_device_cap_still_holds_with_a_returned_key(self):
        a, b, c = (self.activate(key, n) for n, key in enumerate(self.keys))
        self.logout(a)
        self.assertEqual(len(self.device_ids()), 2)
        d = self.activate(self.keys[0], 3)
        self.assertEqual(sorted(self.device_ids()), sorted([b, c, d]))
        # Every key is spent again: a fourth device is refused with any of them.
        for n, key in enumerate(self.keys, 4):
            self.refused(key, n)
        self.assertEqual(len(self.device_ids()), 3)

        # Three devices AND a live returned key: d is deactivated and a device
        # with no recorded key (enrolled before the ruling) fills the slot.
        self.logout(d)
        now = self.mod.utcnow()
        with self.mod.get_db() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, account_number, device_model, vpn_internal_ip, "
                "client_public_key, last_seen, location_slug, updated_at, device_auth_token_hash) "
                "VALUES ('legacy-device', ?, 'Legacy', '10.8.250.250', ?, ?, 'lab-alpha', ?, 'x')",
                (ACCOUNT, keys3.pub(99), now.isoformat(), now.isoformat()),
            )
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                         ((now - timedelta(days=1)).isoformat(), b))
        self.assertEqual(len(self.device_ids()), 3)
        self.assertTrue(self.accepts(self.mod, self.keys[0]))
        e = self.activate(self.keys[0], 9)
        devices = self.device_ids()
        self.assertEqual(len(devices), 3)  # never a fourth device row
        self.assertNotIn(b, devices)  # the existing slot replacement, unchanged
        self.assertIn(e, devices)
        # The replaced device's key is not returned, and the reused row now
        # records the key that enrolled it.
        self.assertEqual(self.live_keys(self.mod), [])
        self.assertEqual(self.recorded(e), self.stored(0))
        self.logout(e)
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [1])


# ========================= 5. concurrency and replay =========================

class Concurrency(KeyReturnBase):
    def test_concurrent_double_deactivation_returns_the_key_once(self):
        device = self.activate(self.keys[0], 0)
        returned = []
        real = self.mod.return_device_activation_key

        def counting(*args, **kwargs):
            result = real(*args, **kwargs)
            returned.append(result)
            return result

        self.mod.return_device_activation_key = counting
        barrier = threading.Barrier(2)
        outcomes = []

        def worker():
            barrier.wait()
            try:
                outcomes.append(self.logout(device))
            except self.mod.HTTPException as exc:
                outcomes.append(exc.status_code)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        self.assertEqual(sorted(map(str, outcomes)), sorted(["401", str({"ok": True})]))
        self.assertEqual(returned, [True])
        self.assertTrue(self.accepts(self.mod, self.keys[0]))

        # The key enrols another device; a late replay of the first logout
        # must not hand it back a second time.
        self.activate(self.keys[0], 1)
        with self.assertRaises(self.mod.HTTPException) as late:
            self.logout(device)
        self.assertEqual(late.exception.status_code, 401)
        self.assertFalse(self.accepts(self.mod, self.keys[0]))
        self.refused(self.keys[0], 2)

    def test_two_admin_removals_of_one_device_return_the_key_once(self):
        device = self.activate(self.keys[1], 0)
        self.admin_remove(device)
        self.activate(self.keys[1], 1)
        with self.assertRaises(self.mod.HTTPException) as again:
            self.admin_remove(device)
        self.assertEqual(again.exception.status_code, 404)
        self.assertFalse(self.accepts(self.mod, self.keys[1]))

    def test_every_removal_path_deletes_and_returns_in_one_writer_transaction(self):
        source = harness._extract_main_block()
        for name in ("logout_device_sync", "admin_remove_device",
                     "hoppy_agent_device_revoke", "hoppy_agent_device_limit_reset"):
            start = source.index(f"def {name}(")
            body = source[start:source.index("\ndef ", start + 1)]
            self.assertIn('conn.execute("BEGIN IMMEDIATE")', body, name)


# ============================ 6. the email wording ===========================

class Wording(keys3.KeysBase):
    def render(self, mod, keys):
        captured = []
        mod.SMTP_USER, mod.SMTP_PASS = "user", "pass"
        mod.smtp_dispatch_message = lambda msg, to: captured.append((msg, to)) or True
        self.assertTrue(mod.send_account_email(keys3.BUYER, "Buyer", ACCOUNT, "Monthly", keys))
        ((msg, _to),) = captured
        return {part.get_content_type(): part.get_payload(decode=True).decode("utf-8")
                for part in msg.get_payload()}

    def test_the_email_says_a_key_returns_when_its_device_is_deactivated(self):
        mod = self.load()
        many = self.render(mod, ["key-one", "key-two", "key-three"])
        one = self.render(mod, ["only-key"])
        for parts, sentence in ((many, "A key is used up when it activates a device and becomes "
                                       "valid again when that device is deactivated."),
                                (one, "It is used up when it activates a device and becomes "
                                      "valid again when that device is deactivated.")):
            for body in parts.values():
                self.assertIn(sentence, body)
                self.assertNotIn("can be used once", body)
                self.assertNotIn("it works until it has activated a device", body)
                self.assertNotIn("\u2014", body)
                self.assertNotIn("\u2013", body)


# ================== 7. review round 1 (KR findings) ===========================

class AccountState(KeyReturnBase):
    # Sol KR-01, Argon KR-03: a key returns only while the account is active
    # and unexpired, read in the removal transaction.
    def test_logout_after_account_expiry_does_not_return_a_key_for_later_renewal(self):
        device = self.activate(self.keys[0], 0)
        with self.mod.get_db() as conn:
            conn.execute(
                "UPDATE users SET expiration_date = ? WHERE account_number = ?",
                ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(), ACCOUNT),
            )
        self.assertEqual(self.logout(device), {"ok": True})
        self.assertIsNotNone(self.key_rows(self.mod)[0][3])
        with self.mod.get_db() as conn:
            conn.execute(
                "UPDATE users SET status = 'active', expiration_date = ? WHERE account_number = ?",
                ((self.mod.utcnow() + timedelta(days=30)).isoformat(), ACCOUNT),
            )
        self.assertFalse(self.accepts(self.mod, self.keys[0]))

    def test_support_reset_of_an_inactive_account_does_not_return_keys(self):
        self.activate(self.keys[0], 0)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET status = 'expired' WHERE account_number = ?", (ACCOUNT,))
        self.hoppy("hoppy_agent_device_limit_reset", "HoppyAccountRequest", "device-limit-reset",
                   request_id="inactive-reset")
        self.assertEqual(self.device_ids(), [])
        self.assertIsNotNone(self.key_rows(self.mod)[0][3])

    def test_inactive_or_expired_account_never_regains_a_key_on_any_removal(self):
        first = self.activate(self.keys[0], 0)
        second = self.activate(self.keys[1], 1)
        self.activate(self.keys[2], 2)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date = ? WHERE account_number = ?",
                         ((self.mod.utcnow() - timedelta(minutes=5)).isoformat(), ACCOUNT))
        self.logout(first)
        self.assertEqual(self.live_keys(self.mod), [])
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET status = 'revoked', expiration_date = ? WHERE account_number = ?",
                         ((self.mod.utcnow() + timedelta(days=5)).isoformat(), ACCOUNT))
        self.admin_remove(second)
        self.hoppy("hoppy_agent_device_limit_reset", "HoppyAccountRequest", "device-limit-reset",
                   request_id="reset-revoked-1")
        self.assertEqual(self.device_ids(), [])
        self.assertEqual(self.live_keys(self.mod), [])


class StaleRecord(KeyReturnBase):
    # Sol KR-02: an older hub build re-enrols the row with key B (new bearer)
    # and leaves this build's key A record behind. Removing the row must not
    # return A.
    def test_an_older_hub_re_enrolment_does_not_return_the_previous_key(self):
        device = self.activate(self.keys[0], 0)
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(conn, ACCOUNT, self.keys[1]))
            conn.execute("UPDATE devices SET device_auth_token_hash = ? WHERE device_id = ?",
                         (self.mod.token_digest("legacy-reenrollment-token"), device))
        self.assertEqual(self.recorded(device), self.stored(0))  # the stale record is still there
        self.bearers[device] = "legacy-reenrollment-token"
        self.assertEqual(self.logout(device), {"ok": True})
        self.assertIsNotNone(self.key_rows(self.mod)[0][3])
        self.assertIsNotNone(self.key_rows(self.mod)[1][3])
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [3])


class DoubleCore(KeyReturnBase):
    # Argon KR-01 and KR-02: the Double VPN Core path commits the device row
    # before it spends the key. A failure after that commit must leave a row
    # that returns nothing and is the first one reused at the cap.
    def arm_core(self):
        with self.mod.get_db() as conn:
            conn.execute(
                "INSERT INTO core_servers (core_id, exit_public_key, ingress_public_key, "
                "ingress_endpoint, tunnel_gateway_ipv4, status, runtime_ready, obfuscation_json) "
                "VALUES ('fixture-core', ?, ?, '192.0.2.50:9210', '10.9.0.1', 'online', 1, ?)",
                ("D" * 43 + "=", "E" * 43 + "=", json.dumps(self.mod.DEFAULT_OBFUSCATION)),
            )
            core = dict(conn.execute("SELECT * FROM core_servers").fetchone())
        self.mod.select_double_vpn_core = lambda _conn: core

    def failed_core_enrolment(self, key, device_id, fingerprint):
        with patch.object(self.mod, "_wait_for_core_assignment_ready_sync", return_value=False), \
                patch.object(self.mod, "sync_peer_to_node", return_value=True), \
                patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True):
            request = harness.FakeRequest(path="/verify", headers={"x-wins-activation": key})
            login = dh.build_login(
                self.mod, supports_winn3=True, supports_winn3_descriptor=True, double_vpn=True,
                device_id=device_id, device_model="audit-harness", device_fingerprint=fingerprint,
            )
            with self.assertRaises(self.mod.HTTPException) as caught:
                self.mod._verify_account_sync(request, login, harness.BackgroundTasks())
        self.assertEqual(caught.exception.status_code, 503)

    def test_an_unspent_core_re_enrolment_clears_the_earlier_key_and_returns_nothing(self):
        self.arm_core()
        first = self.activate(self.keys[0], 0, device_fingerprint="fp-same-phone-0123456789")
        self.assertEqual(self.recorded(first), self.stored(0))
        self.failed_core_enrolment(self.keys[1], "re-enrolled-double-core", "fp-same-phone-0123456789")
        self.assertEqual(self.recorded("re-enrolled-double-core"), (0, None))
        self.admin_remove("re-enrolled-double-core")
        self.assertEqual([row[0] for row in self.live_keys(self.mod)], [2, 3])
        self.assertFalse(self.accepts(self.mod, self.keys[0]))

    def test_unspent_core_rows_are_reused_first_at_the_cap(self):
        self.arm_core()
        a = self.activate(self.keys[0], 0)
        b = self.activate(self.keys[1], 1)
        now = self.mod.utcnow()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                         ((now - timedelta(hours=2)).isoformat(), a))
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                         ((now - timedelta(hours=1)).isoformat(), b))
        for idx in range(1, 4):
            self.failed_core_enrolment(self.keys[2], f"ghost-device-{idx}", f"fp-ghost-{idx}-0123456789")
        c = self.activate(self.keys[2], 9)
        self.assertEqual(sorted(self.device_ids()), sorted([a, b, c]))
        self.assertEqual(self.live_keys(self.mod), [])
        # The returned key again lands in the free slot, never on a or b.
        self.logout(c)
        d = self.activate(self.keys[2], 10)
        self.assertEqual(sorted(self.device_ids()), sorted([a, b, d]))


class Schema(KeyReturnBase):
    # Argon KR-04: every place that creates the devices table carries the columns.
    def test_create_devices_table_and_the_shell_bootstrap_include_the_key_columns(self):
        columns = ("activation_key_slot", "activation_key_hash", "activation_key_bearer_hash")
        with closing_memory() as mem:
            self.mod.create_users_table(mem)
            self.mod.create_devices_table(mem)
            present = {row[1] for row in mem.execute("PRAGMA table_info(devices)")}
        for column in columns:
            self.assertIn(column, present)
        installer = (Path(__file__).resolve().parent / "wins_control_plane_setup_ONETOUCH.sh").read_text(encoding="utf-8")
        for column in columns:
            self.assertIn(f"sqlite_add_column_if_missing devices {column} ", installer)


def closing_memory():
    from contextlib import closing
    return closing(sqlite3.connect(":memory:"))


if __name__ == "__main__":
    unittest.main()
