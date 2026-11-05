#!/usr/bin/env python3
"""Three setup keys per new account, all in one email (owner request 2026-10-22).

Exercises the REAL embedded hub (the main.py heredoc) against real SQLite. SMTP,
payment providers and node transport are test doubles; nothing is sent.

What is pinned:

1. A new account gets DEVICE_LIMIT independent setup keys: distinct, 32 bytes of
   entropy each, HMAC hashed at rest, no expiry (owner ruling: valid until
   used), and the plaintext is nowhere in the database or the logs.
2. The email carries all of them, once each, in both the HTML and the text part,
   with wording that says each key activates one device.
3. Each key enrols exactly one device through the real /verify and is then
   spent, independently of the others. Expired or spent keys never affect the
   rest of the set.
4. Retries and resends never mint extra keys. A retried delivery re-sends the
   SAME sealed keys; a resend or a hoppy rotation REPLACES the whole set, so the
   account never holds more than DEVICE_LIMIT live keys.
5. Minting is atomic: a failure between two keys leaves the account's keys as
   they were, and a failed grant leaves no key and no outbox row.
6. A per-account device_limit_override never raises the number of keys, and
   DEVICE_LIMIT is the only constant that sets it.
7. Renewals of an active account still send no key.
8. The same rate limits apply: a three key account gets no extra guesses.
9. Keys never expire. Keys already in a database keep the expiry they were
   given and an expired one is never revived.
10. A wrong, used, replaced or revoked key is refused with one plain message
    (not the smart-routing wording) and the same 401 and rate limits.

Run: python3 server/test_activation_keys3_hub.py
"""
import _toolchain  # noqa: F401
import ast
import asyncio
import base64
import json
import logging
import re
import secrets
import shutil
import sqlite3
import types
import unittest
from pathlib import Path
from contextlib import closing
from datetime import timedelta
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_hoppy_agent_tier1_hub as hoppy
import test_winn3_descriptor_hub as dh

ADMIN = "test-admin-token"
ACCOUNT = harness.ACCOUNT
BUYER = "buyer@example.test"
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


def pub(seed):
    return base64.b64encode(bytes([seed]) * 31 + b"\x01").decode()


class WebhookRequest(harness.FakeRequest):
    async def body(self):
        return json.dumps(self._body).encode()


class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


class KeysBase(unittest.TestCase):
    def load(self, **env):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        settings = dict(
            DURABILITY_BARRIER_ENABLED=0,
            DURABILITY_BARRIER_REQUIRED=0,
            WINN3_INNER_POOL_CIDR="10.10.0.0/24",
            WINN3_CANARY_NODE_SLUG="",
            VERIFY_IP_RATE_LIMIT_PER_MINUTE=1000,
            VERIFY_ACCOUNT_RATE_LIMIT_PER_HOUR=1000,
            REDEMPTION_KEYS="v1:" + "cd" * 32,
            REDEMPTION_KEY_ACTIVE_VERSION="v1",
            REDEMPTION_IP_RATE_LIMIT_PER_MINUTE=1000,
            REDEMPTION_IP_RATE_LIMIT_PER_HOUR=1000,
            REDEMPTION_CODE_RATE_LIMIT_PER_HOUR=1000,
        )
        settings.update(env)
        with patch("logging.basicConfig", side_effect=close_handlers):
            mod = dh.load_hub_with_ring(**settings)
        mod.logger.propagate = False
        mod.logger.addHandler(logging.NullHandler())
        mod.security_alert = lambda *args, **kwargs: None
        mod.run_durability_barrier = lambda: {}
        self.addCleanup(shutil.rmtree, mod._TMPDIR, True)
        return mod

    # ---- helpers -----------------------------------------------------------
    def db(self, mod):
        conn = sqlite3.connect(mod._DB)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def key_rows(self, mod, account=ACCOUNT):
        """Every stored key slot as (slot, hash, expires_at, used_at), slot 1 first."""
        with self.db(mod) as conn:
            user = conn.execute(
                "SELECT activation_secret_hash AS h, activation_secret_expires_at AS e, "
                "activation_secret_used_at AS u FROM users WHERE account_number=?", (account,),
            ).fetchone()
            rows = [(1, user["h"], user["e"], user["u"])] if user is not None and user["h"] else []
            rows += [
                (r["slot"], r["secret_hash"], r["expires_at"], r["used_at"])
                for r in conn.execute(
                    "SELECT slot, secret_hash, expires_at, used_at FROM activation_extra_keys "
                    "WHERE account_number=? ORDER BY slot", (account,))
            ]
        return rows

    def live_keys(self, mod, account=ACCOUNT):
        return [row for row in self.key_rows(mod, account) if row[3] is None]

    def accepts(self, mod, key, account=ACCOUNT):
        """True when `key` would enrol a device now. Checks, never consumes."""
        with mod.get_db() as conn:
            return mod.verify_and_consume_activation_secret(conn, account, key, consume=False)

    def mint(self, mod, account=ACCOUNT, **seed):
        harness.seed_account(mod, account=account, devices=seed.pop("devices", 0), **seed)
        with mod.get_db() as conn:
            return mod.issue_activation_secrets(conn, account)

    def capture_mail(self, mod, results=None):
        """Replace send_account_email; each call is recorded and gets the next
        scripted outcome (True, False, or an exception to raise)."""
        sent = []
        outcomes = list(results or [])

        def fake(*args):
            sent.append(args)
            outcome = outcomes.pop(0) if outcomes else True
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        mod.send_account_email = fake
        return sent

    def provision(self, mod, email=BUYER, duration="1m"):
        return mod.provision_account(
            harness.FakeRequest(), harness.BackgroundTasks(),
            name="Buyer", email=email, duration=duration, x_admin_token=ADMIN,
        )


# ============================ 1. mint and storage ===========================

class MintAndStorage(KeysBase):
    def test_new_account_gets_three_distinct_keys_stored_hashed(self):
        mod = self.load()
        sent = self.capture_mail(mod)
        result = self.provision(mod)
        self.assertTrue(result["email_sent"])
        ((to_email, _name, account, _plan, keys),) = sent
        self.assertEqual(to_email, BUYER)
        self.assertEqual(len(keys), 3)
        self.assertEqual(len(set(keys)), 3)
        rows = self.key_rows(mod, account)
        self.assertEqual([row[0] for row in rows], [1, 2, 3])
        for key, (_slot, stored_hash, _expires, used_at) in zip(keys, rows):
            self.assertRegex(key, KEY_PATTERN)  # token_urlsafe(32): 256 bits, 43 characters
            self.assertEqual(stored_hash, mod._hash_activation_secret(key))
            self.assertNotEqual(stored_hash, key)
            self.assertIsNone(used_at)
        # Plaintext exists only in the email: not in any table, row or index.
        with self.db(mod) as conn:
            dump = "\n".join(conn.iterdump())
        for key in keys:
            self.assertNotIn(key, dump)

    def test_new_keys_carry_no_expiry(self):
        mod = self.load()
        keys = self.mint(mod)
        rows = self.key_rows(mod)
        self.assertEqual(len(keys), 3)
        self.assertEqual([row[2] for row in rows], [None, None, None])

    def test_the_single_key_primitive_also_issues_without_an_expiry(self):
        mod = self.load()
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            key = mod.issue_activation_secret(conn, ACCOUNT)
        self.assertRegex(key, KEY_PATTERN)
        self.assertEqual(self.key_rows(mod)[0][2], None)
        # A caller that asks for a lifetime still gets one.
        with mod.get_db() as conn:
            mod.issue_activation_secret(conn, ACCOUNT, timedelta(minutes=5))
        self.assertIsNotNone(self.key_rows(mod)[0][2])

    def test_count_comes_from_device_limit_alone(self):
        mod = self.load()
        for limit, expected in ((1, 1), (3, 3), (5, 5), (0, 1)):
            with patch.object(mod, "DEVICE_LIMIT", limit):
                keys = self.mint(mod)
            self.assertEqual(len(keys), expected, f"DEVICE_LIMIT={limit}")
            self.assertEqual(len(self.key_rows(mod)), expected, f"DEVICE_LIMIT={limit}")

    def test_count_can_only_be_lowered_never_raised(self):
        mod = self.load()
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            self.assertEqual(len(mod.issue_activation_secrets(conn, ACCOUNT, count=1)), 1)
            self.assertEqual(len(mod.issue_activation_secrets(conn, ACCOUNT, count=99)), 3)

    def test_issuing_replaces_every_earlier_key_used_or_not(self):
        mod = self.load()
        first = self.mint(mod)
        with mod.get_db() as conn:
            self.assertTrue(mod.verify_and_consume_activation_secret(conn, ACCOUNT, first[1]))
        with mod.get_db() as conn:
            second = mod.issue_activation_secrets(conn, ACCOUNT)
        self.assertEqual(len(self.key_rows(mod)), 3)
        self.assertEqual(len(self.live_keys(mod)), 3)
        for key in first:
            self.assertFalse(self.accepts(mod, key))
        for key in second:
            self.assertTrue(self.accepts(mod, key))

    def test_unknown_account_is_refused_and_nothing_is_written(self):
        mod = self.load()
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            with self.assertRaises(LookupError):
                mod.issue_activation_secrets(conn, "9999-0000-1111")
        self.assertEqual(self.key_rows(mod, "9999-0000-1111"), [])

    def test_no_path_mints_a_lone_key(self):
        # Every mint goes through issue_activation_secrets; the single key
        # primitive is only ever called from inside it.
        tree = ast.parse(harness._extract_main_block())
        callers = set()
        for function in ast.walk(tree):
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for node in ast.walk(function):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                            and node.func.id == "issue_activation_secret"):
                        callers.add(function.name)
        self.assertEqual(callers, {"issue_activation_secrets"})


# ================================ 2. the email ==============================

class EmailContent(KeysBase):
    @staticmethod
    def random_keys(count):
        return [secrets.token_urlsafe(32) for _ in range(count)]

    def render(self, mod, keys):
        mod.SMTP_USER, mod.SMTP_PASS = "relay-user", "relay-pass"
        captured = []
        mod.smtp_dispatch_message = lambda msg, to: captured.append((msg, to)) or True
        self.assertTrue(mod.send_account_email(BUYER, "Buyer", ACCOUNT, "Monthly", keys))
        ((msg, _to),) = captured
        parts = {part.get_content_type(): part.get_payload(decode=True).decode("utf-8")
                 for part in msg.get_payload()}
        return parts["text/plain"], parts["text/html"]

    def test_all_three_keys_appear_once_in_both_parts(self):
        mod = self.load()
        keys = self.random_keys(3)
        text, html_part = self.render(mod, keys)
        for body in (text, html_part):
            for key in keys:
                self.assertEqual(body.count(key), 1, key)
        self.assertIn(ACCOUNT, text)
        self.assertIn(ACCOUNT, html_part)

    def test_wording_says_each_key_activates_one_device(self):
        mod = self.load()
        keys = self.random_keys(3)
        text, html_part = self.render(mod, keys)
        self.assertIn("Each setup key activates one device.", text)
        self.assertIn("A key is used up when it activates a device and becomes valid again when that device is deactivated.", text)
        self.assertIn("A setup key does not expire.", text)
        self.assertIn("The account supports up to 3 devices.", text)
        self.assertIn("To add another device or replace an expired or used key, contact support.", text)
        self.assertIn("Setup key 1 of 3: " + keys[0], text)
        self.assertIn("Setup key 3 of 3: " + keys[2], text)
        self.assertIn("Each setup key activates one device.", html_part)
        self.assertIn("A key is used up when it activates a device and becomes valid again when that device is deactivated.", html_part)
        self.assertIn("A setup key does not expire.", html_part)
        self.assertIn("The account supports up to 3 devices.", html_part)
        self.assertIn("To add another device or replace an expired or used key, contact support.", html_part)
        self.assertIn("Setup key 2 of 3", html_part)
        self.assertIn("Each account is limited to 3 devices.", html_part)
        # The one-key sentence is gone from a three key email.
        for body in (text, html_part):
            self.assertNotIn("This setup key activates one device", body)
            self.assertNotIn("This <strong>setup key</strong> activates one device", body)

    def test_wording_follows_device_limit(self):
        mod = self.load(DEVICE_LIMIT=5)
        keys = self.random_keys(5)
        text, html_part = self.render(mod, keys)
        for body in (text, html_part):
            self.assertIn("up to 5 devices", body)
            for key in keys:
                self.assertEqual(body.count(key), 1)

    def test_one_key_keeps_the_single_key_wording(self):
        mod = self.load()
        text, html_part = self.render(mod, ["only-one-key"])
        self.assertIn("This setup key activates one device.", text)
        self.assertIn("This <strong>setup key</strong> activates one device.", html_part)
        self.assertEqual(text.count("only-one-key"), 1)
        # A plain string still means one key.
        text, html_part = self.render(mod, "only-one-key")
        self.assertEqual(html_part.count("only-one-key"), 1)

    def test_no_keys_means_no_setup_key_text(self):
        mod = self.load()
        for empty in ("", [], None):
            text, html_part = self.render(mod, empty)
            for body in (text, html_part):
                self.assertNotIn("setup key", body.lower())

    def test_keys_are_escaped_in_html_and_literal_in_text(self):
        mod = self.load()
        text, html_part = self.render(mod, ["a<b>&c", "d-e_f"])
        self.assertIn("a&lt;b&gt;&amp;c", html_part)
        self.assertIn("Setup key 1 of 2: a<b>&c", text)


# =========================== 3. enrolment through /verify ===================

class EnrolBase(KeysBase):
    def setUp(self):
        self.mod = self.load()
        harness.seed_account(self.mod, devices=0)
        dh.seed_node(self.mod)
        with self.mod.get_db() as conn:
            self.keys = self.mod.issue_activation_secrets(conn, ACCOUNT)

    def enrol(self, key, n, location="lab-alpha"):
        # key=None sends a request with no setup key at all.
        headers = {"x-wins-activation": key} if key is not None else {"x-unrelated": "1"}
        return dh.served_config(
            self.mod, request_headers=headers, location=location,
            device_id=f"keys3-device-{n}", device_model="audit-harness",
            client_public_key=pub(40 + n % 20), device_fingerprint=f"fp-keys3-{n}-0123456789",
        )

    def device_ids(self):
        with self.db(self.mod) as conn:
            return [r[0] for r in conn.execute("SELECT device_id FROM devices ORDER BY device_id")]


class Enrolment(EnrolBase):
    def test_each_key_enrols_exactly_one_device_then_is_spent(self):
        for n, index in enumerate((2, 0, 1)):  # any order
            body = self.enrol(self.keys[index], n)
            self.assertEqual(body.get("status"), "authenticated", body)
            self.assertEqual(len(self.device_ids()), n + 1)
            used = [row[3] is not None for row in self.key_rows(self.mod)]
            self.assertEqual(sum(used), n + 1)
            self.assertTrue(used[index])
            self.assertFalse(self.accepts(self.mod, self.keys[index]))  # spent for every reader
            # The same key cannot enrol a second device.
            with self.assertRaises(self.mod.HTTPException) as refused:
                self.enrol(self.keys[index], 10 + n)
            self.assertEqual(refused.exception.status_code, 401)
            self.assertEqual(len(self.device_ids()), n + 1)
        self.assertEqual(self.live_keys(self.mod), [])
        with self.assertRaises(self.mod.HTTPException) as refused:
            self.enrol("a-key-that-was-never-issued", 20)
        self.assertEqual(refused.exception.status_code, 401)

    def test_a_spent_key_does_not_affect_the_others(self):
        self.assertEqual(self.enrol(self.keys[0], 0).get("status"), "authenticated")
        self.assertFalse(self.accepts(self.mod, self.keys[0]))
        self.assertTrue(self.accepts(self.mod, self.keys[1]))
        self.assertTrue(self.accepts(self.mod, self.keys[2]))

    def test_an_expired_slot_does_not_affect_the_others(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=2",
                         ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(),))
        self.assertFalse(self.accepts(self.mod, self.keys[1]))
        self.assertTrue(self.accepts(self.mod, self.keys[0]))
        self.assertTrue(self.accepts(self.mod, self.keys[2]))
        self.assertEqual(self.enrol(self.keys[2], 0).get("status"), "authenticated")

    def test_consume_is_compare_and_set_per_slot(self):
        # A reader holding a stale snapshot (slot still unused) cannot spend a
        # key twice: the UPDATE itself refuses.
        with self.mod.get_db() as conn:
            stale = self.mod.fetch_activation_extra_keys(conn, ACCOUNT)
            self.assertTrue(self.mod.verify_and_consume_activation_secret(conn, ACCOUNT, self.keys[1]))
        with self.mod.get_db() as conn, patch.object(self.mod, "fetch_activation_extra_keys", lambda *_: stale):
            self.assertFalse(self.mod.verify_and_consume_activation_secret(conn, ACCOUNT, self.keys[1]))

    def test_advisory_check_accepts_any_key_and_consumes_none(self):
        for key in self.keys:
            request = harness.FakeRequest(headers={"x-wins-activation": key})
            for _ in range(2):
                with self.mod.get_db() as conn:
                    self.assertTrue(self.mod.verify_advisory_request_authorized(
                        conn, account_number=ACCOUNT, requested_client_public_key=pub(1), request=request))
        self.assertEqual(len(self.live_keys(self.mod)), 3)

    def test_gate_treats_the_account_as_expired_only_when_every_key_is(self):
        past = (self.mod.utcnow() - timedelta(minutes=5)).isoformat()
        future = (self.mod.utcnow() + timedelta(minutes=5)).isoformat()
        gate = self.mod.require_verify_authorization

        def call(primary_expiry, extra_expiries, header):
            return gate(
                activation_secret_hash=self.mod._hash_activation_secret(self.keys[0]),
                device_row=None, requested_client_public_key=pub(1),
                request=harness.FakeRequest(headers={"x-wins-activation": header}),
                account_number=ACCOUNT, activation_secret_expires_at=primary_expiry,
                additional_activation_secrets=tuple(
                    (self.mod._hash_activation_secret(key), expiry)
                    for key, expiry in zip(self.keys[1:], extra_expiries)),
            )

        self.assertEqual(call(future, (future, future), self.keys[2]), "enrollment")
        self.assertEqual(call(past, (future, past), self.keys[1]), "enrollment")
        with self.assertRaises(self.mod.HTTPException) as expired:
            call(past, (past, past), self.keys[1])
        self.assertEqual(expired.exception.status_code, 401)
        self.assertEqual(expired.exception.detail, self.mod.SETUP_KEY_REFUSED_DETAIL)
        with self.assertRaises(self.mod.HTTPException) as wrong:
            call(future, (future, future), "not-a-key")
        self.assertEqual(wrong.exception.status_code, 401)
        # With no extra keys the gate behaves exactly as it always did.
        with self.assertRaises(self.mod.HTTPException):
            gate(activation_secret_hash=self.mod._hash_activation_secret(self.keys[0]), device_row=None,
                 requested_client_public_key=pub(1),
                 request=harness.FakeRequest(headers={"x-wins-activation": self.keys[0]}),
                 account_number=ACCOUNT, activation_secret_expires_at=past)


# ===================== 4. retries and resends mint nothing extra ============

class RetriesAndResends(KeysBase):
    def purchase(self, mod, email=BUYER, delivery_id="paypal:evt-keys3"):
        with mod.get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            account, created, _expiry, keys = mod.upsert_paypal_account(
                conn, email=email, subscriber_name="Buyer", subscription_id="",
                plan_id="lifetime_support", payer_id="", paypal_status="ACTIVE",
                next_billing_time=None, duration_text="10y",
                purchase_reference="CAPTURE-K3", paypal_purchase_reference="CAPTURE-K3",
            )
            if keys:
                mod.enqueue_activation_delivery(conn, delivery_id, email, "Buyer", account, "PayPal test", keys)
        return account, created, keys

    def make_due(self, mod):
        with mod.get_db() as conn:
            conn.execute("UPDATE activation_delivery_outbox SET next_attempt_at=?",
                         ((mod.utcnow() - timedelta(seconds=1)).isoformat(),))

    def test_outbox_carries_all_three_keys_in_one_sealed_row(self):
        mod = self.load()
        account, created, keys = self.purchase(mod)
        self.assertTrue(created)
        self.assertEqual(len(keys), 3)
        with self.db(mod) as conn:
            rows = [dict(r) for r in conn.execute("SELECT * FROM activation_delivery_outbox")]
        self.assertEqual(len(rows), 1)
        sealed = rows[0]["sealed_secret"]
        for key in keys:
            self.assertNotIn(key, sealed)
        opened = mod.open_activation_delivery(sealed, "paypal:evt-keys3", account)
        self.assertEqual(mod.activation_key_list(opened), keys)

    def test_smtp_retries_resend_the_same_keys_and_mint_nothing(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)

        def identity():
            # Hash and used mark per slot. Expiry is excluded on purpose: each
            # delivery attempt refreshes it, for every key together.
            return [(slot, stored_hash, used) for slot, stored_hash, _e, used in self.key_rows(mod, account)]

        before = identity()
        sent = self.capture_mail(mod, results=[False, RuntimeError("smtp down"), True])
        for _attempt in range(3):
            self.make_due(mod)
            mod.drain_activation_delivery_outbox_once()
            self.assertEqual(identity(), before)  # no new key, nothing replaced
            self.assertEqual(len({row[2] for row in self.key_rows(mod, account)}), 1)
        self.assertEqual(len(sent), 3)
        for args in sent:
            self.assertEqual(list(args[4]), keys)
        with self.db(mod) as conn:
            row = dict(conn.execute("SELECT * FROM activation_delivery_outbox").fetchone())
        self.assertEqual((row["status"], row["sealed_secret"]), ("sent", ""))
        self.assertEqual(len(self.key_rows(mod, account)), 3)

    def test_a_replayed_grant_cannot_mint_more_keys(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        before = self.key_rows(mod, account)
        # The replay mints inside its transaction, then the duplicate delivery id
        # is refused; the whole transaction, mint included, is discarded.
        with self.assertRaises(sqlite3.IntegrityError):
            with mod.get_db() as conn:
                mod.issue_activation_secrets(conn, account)
                mod.enqueue_activation_delivery(conn, "paypal:evt-keys3", BUYER, "Buyer", account, "PayPal test", keys)
        self.assertEqual(self.key_rows(mod, account), before)

    def test_consumed_key_cancels_the_whole_delivery(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        with mod.get_db() as conn:
            self.assertTrue(mod.verify_and_consume_activation_secret(conn, account, keys[2]))
        sent = self.capture_mail(mod)
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 0)
        self.assertEqual(sent, [])
        with self.db(mod) as conn:
            row = dict(conn.execute("SELECT * FROM activation_delivery_outbox").fetchone())
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", ""))

    def test_a_resend_before_delivery_cancels_the_old_delivery(self):
        mod = self.load()
        account, _created, _keys = self.purchase(mod)
        with mod.get_db() as conn:
            mod.issue_activation_secrets(conn, account)
        sent = self.capture_mail(mod)
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 0)
        self.assertEqual(sent, [])

    def test_a_pending_delivery_never_revives_expired_keys(self):
        # K3-01. A queued or failed delivery does not prove its plaintext never
        # reached anyone, so an expiry already on a key stands. Mail for a set
        # with any expired key is cancelled and nothing is sent or rewritten.
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        past = (mod.utcnow() - timedelta(hours=1)).isoformat()
        soon = (mod.utcnow() + timedelta(minutes=5)).isoformat()
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_expires_at=? WHERE account_number=?", (past, account))
            conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=2", (soon,))
            conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=3", (past,))
        sent = self.capture_mail(mod)
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 0)
        self.assertEqual(sent, [])
        self.assertEqual([row[2] for row in self.key_rows(mod, account)], [past, soon, past])
        self.assertEqual([self.accepts(mod, key, account) for key in keys], [False, True, False])
        with self.db(mod) as conn:
            row = dict(conn.execute("SELECT * FROM activation_delivery_outbox").fetchone())
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", ""))

    def test_a_key_that_expires_between_two_attempts_stays_expired(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        sent = self.capture_mail(mod, results=[False, True])
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 0)  # SMTP refused, maybe after delivery
        self.assertEqual(len(sent), 1)
        past = (mod.utcnow() - timedelta(minutes=1)).isoformat()
        with mod.get_db() as conn:
            conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=2", (past,))
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 0)
        self.assertEqual(len(sent), 1)
        self.assertFalse(self.accepts(mod, keys[1], account))
        self.assertEqual(self.key_rows(mod, account)[1][2], past)

    def test_a_still_valid_legacy_expiry_is_kept_not_cleared_by_delivery(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        soon = (mod.utcnow() + timedelta(minutes=10)).isoformat()
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_expires_at=? WHERE account_number=?", (soon, account))
        sent = self.capture_mail(mod)
        self.make_due(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 1)
        self.assertEqual(list(sent[0][4]), keys)
        self.assertEqual([row[2] for row in self.key_rows(mod, account)], [soon, None, None])

    def test_delivery_leaves_keys_without_an_expiry_alone(self):
        mod = self.load()
        account, _created, keys = self.purchase(mod)
        sent = self.capture_mail(mod, results=[False, True])
        for _attempt in range(2):
            self.make_due(mod)
            mod.drain_activation_delivery_outbox_once()
            self.assertEqual([row[2] for row in self.key_rows(mod, account)], [None, None, None])
        self.assertEqual(len(sent), 2)

    def test_admin_resend_replaces_the_set_and_never_adds_to_it(self):
        mod = self.load()
        sent = self.capture_mail(mod)
        self.provision(mod)
        generations = [list(sent[0][4])]
        for _ in range(2):
            result = mod.resend_email(harness.FakeRequest(), harness.BackgroundTasks(), email=BUYER, x_admin_token=ADMIN)
            self.assertTrue(result["email_sent"])
            generations.append(list(sent[-1][4]))
            account = result["account_number"]
            self.assertEqual(len(generations[-1]), 3)
            self.assertEqual(len(self.key_rows(mod, account)), 3)
            self.assertEqual(len(self.live_keys(mod, account)), 3)
        flat = [key for generation in generations for key in generation]
        self.assertEqual(len(set(flat)), 9)
        for key in generations[0] + generations[1]:
            self.assertFalse(self.accepts(mod, key, account))
        for key in generations[2]:
            self.assertTrue(self.accepts(mod, key, account))

    def hoppy_resend_setup(self, **env):
        mod = harness.load_hub(**hoppy._env(**env))
        self.addCleanup(shutil.rmtree, mod._TMPDIR, True)
        hoppy.seed_account(mod, email="onfile@example.test", with_override=True)  # override 5
        hoppy.call(mod, "/api/agent/v1/credentials-resend",
                   {"account_number": ACCOUNT, "request_id": "keys3"}, x_token=hoppy.token(mod))
        mod.SMTP_USER, mod.SMTP_PASS = "relay-user", "relay-pass"
        mod.run_durability_barrier = lambda: {}
        return mod

    def hoppy_outbox(self, mod):
        with self.db(mod) as conn:
            return dict(conn.execute("SELECT * FROM hoppy_agent_mail_outbox").fetchone())

    def test_hoppy_resend_reuses_the_same_set_on_every_attempt(self):
        # K3-03. An ambiguous SMTP failure followed by a retry must not rotate
        # keys the first attempt may already have delivered.
        mod = self.hoppy_resend_setup()
        sent = self.capture_mail(mod, results=[False, RuntimeError("relay reset after DATA"), True])
        self.assertEqual(mod.drain_hoppy_agent_mail_outbox()["failed"], 1)
        first = self.key_rows(mod)
        self.assertEqual(len(first), 3)
        self.assertEqual(mod.drain_hoppy_agent_mail_outbox()["failed"], 1)
        self.assertEqual(mod.drain_hoppy_agent_mail_outbox()["confirmed"], 1)
        self.assertEqual(len(sent), 3)
        # An override of 5 does not raise the count: exactly DEVICE_LIMIT keys.
        self.assertEqual([len(args[4]) for args in sent], [3, 3, 3])
        self.assertEqual(list(sent[0][4]), list(sent[1][4]))
        self.assertEqual(list(sent[0][4]), list(sent[2][4]))
        self.assertEqual(self.key_rows(mod), first)  # nothing re-minted, nothing re-expired
        for key in sent[0][4]:
            self.assertTrue(self.accepts(mod, key))
        row = self.hoppy_outbox(mod)
        self.assertEqual((row["status"], row["sealed_secret"]), ("completed", None))

    def test_hoppy_sealed_set_is_encrypted_at_rest_and_gone_after_delivery(self):
        mod = self.hoppy_resend_setup()
        sent = self.capture_mail(mod, results=[False, True])
        mod.drain_hoppy_agent_mail_outbox()
        sealed = self.hoppy_outbox(mod)["sealed_secret"]
        self.assertTrue(sealed.startswith("wao1|"))
        for key in sent[0][4]:
            self.assertNotIn(key, sealed)
        mod.drain_hoppy_agent_mail_outbox()
        self.assertIsNone(self.hoppy_outbox(mod)["sealed_secret"])

    def test_hoppy_barrier_outage_after_the_mint_keeps_the_minted_set_for_the_retry(self):
        mod = self.hoppy_resend_setup()
        sent = self.capture_mail(mod)
        calls = []

        def barrier():
            calls.append(1)
            if len(calls) == 2:
                raise mod.DurabilityBarrierError("replica_unavailable")
            return {}

        mod.run_durability_barrier = barrier
        self.assertEqual(mod.drain_hoppy_agent_mail_outbox()["deferred"], 1)
        self.assertEqual(sent, [])
        minted = self.key_rows(mod)
        mod.run_durability_barrier = lambda: {}
        self.assertEqual(mod.drain_hoppy_agent_mail_outbox()["confirmed"], 1)
        self.assertEqual(self.key_rows(mod), minted)
        self.assertEqual(len(sent[0][4]), 3)
        for key, (_slot, stored_hash, _e, _u) in zip(sent[0][4], minted):
            self.assertEqual(stored_hash, mod._hash_activation_secret(key))

    def test_hoppy_mail_is_cancelled_when_the_account_changed_after_queueing(self):
        # K3-05, on the first attempt (nothing minted yet) and on a sealed retry.
        past = lambda mod: (mod.utcnow() - timedelta(minutes=1)).isoformat()  # noqa: E731
        changes = {
            "email": lambda mod: ("UPDATE users SET email='changed@example.test' WHERE account_number=?", ()),
            "status": lambda mod: ("UPDATE users SET status='expired' WHERE account_number=?", ()),
            "expired": lambda mod: ("UPDATE users SET expiration_date=? WHERE account_number=?", (past(mod),)),
        }
        for change, make in changes.items():
            for sealed_first in (False, True):
                mod = self.hoppy_resend_setup()
                sent = self.capture_mail(mod, results=[False] if sealed_first else [])
                if sealed_first:
                    mod.drain_hoppy_agent_mail_outbox()
                    self.assertIsNotNone(self.hoppy_outbox(mod)["sealed_secret"])
                before = self.key_rows(mod)
                statement, params = make(mod)
                with mod.get_db() as conn:
                    conn.execute(statement, (*params, ACCOUNT))
                sent.clear()
                mod.drain_hoppy_agent_mail_outbox()
                self.assertEqual(sent, [], (change, sealed_first))
                row = self.hoppy_outbox(mod)
                self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None), (change, sealed_first))
                self.assertEqual(self.key_rows(mod), before, (change, sealed_first))

    def test_hoppy_mail_for_a_vanished_account_is_cancelled_and_purged(self):
        mod = self.hoppy_resend_setup()
        sent = self.capture_mail(mod, results=[False])
        mod.drain_hoppy_agent_mail_outbox()
        with self.db(mod) as conn, conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("DELETE FROM devices WHERE account_number=?", (ACCOUNT,))
            conn.execute("DELETE FROM users WHERE account_number=?", (ACCOUNT,))
        sent.clear()
        mod.drain_hoppy_agent_mail_outbox()
        self.assertEqual(sent, [])
        row = self.hoppy_outbox(mod)
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_a_hoppy_row_that_runs_out_of_attempts_is_cancelled_and_purged(self):
        mod = self.hoppy_resend_setup()
        mod.HOPPY_AGENT_OUTBOX_MAX_ATTEMPTS = 2
        sent = self.capture_mail(mod, results=[False, False, True])
        mod.drain_hoppy_agent_mail_outbox()
        self.assertEqual(self.hoppy_outbox(mod)["status"], "pending")
        mod.drain_hoppy_agent_mail_outbox()
        row = self.hoppy_outbox(mod)
        self.assertEqual((row["status"], row["sealed_secret"], row["attempts"]), ("cancelled", None, 2))
        mod.drain_hoppy_agent_mail_outbox()
        self.assertEqual(len(sent), 2)

    def test_hoppy_rows_already_stuck_at_the_attempt_cap_are_purged_on_the_next_claim(self):
        mod = self.hoppy_resend_setup()
        sent = self.capture_mail(mod, results=[False])
        mod.drain_hoppy_agent_mail_outbox()
        with mod.get_db() as conn:
            conn.execute("UPDATE hoppy_agent_mail_outbox SET attempts=?", (mod.HOPPY_AGENT_OUTBOX_MAX_ATTEMPTS,))
        sent.clear()
        mod.drain_hoppy_agent_mail_outbox()
        self.assertEqual(sent, [])
        row = self.hoppy_outbox(mod)
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_hoppy_retry_is_cancelled_when_the_set_was_replaced_or_a_key_was_used(self):
        for change in ("replaced", "used", "expired"):
            mod = self.hoppy_resend_setup()
            sent = self.capture_mail(mod, results=[False])
            mod.drain_hoppy_agent_mail_outbox()
            with mod.get_db() as conn:
                if change == "replaced":
                    mod.issue_activation_secrets(conn, ACCOUNT)
                elif change == "used":
                    first = mod.open_activation_delivery(
                        conn.execute("SELECT sealed_secret FROM hoppy_agent_mail_outbox").fetchone()[0],
                        f"hoppy:{self.hoppy_outbox(mod)['idempotency_key']}", ACCOUNT)
                    self.assertTrue(mod.verify_and_consume_activation_secret(
                        conn, ACCOUNT, mod.activation_key_list(first)[1]))
                else:
                    conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=3",
                                 ((mod.utcnow() - timedelta(minutes=1)).isoformat(),))
            sent.clear()
            mod.drain_hoppy_agent_mail_outbox()
            self.assertEqual(sent, [], change)
            row = self.hoppy_outbox(mod)
            self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None), change)


# ================================ 5. atomicity ==============================

class Atomicity(KeysBase):
    def fail_on_third_key(self, mod):
        calls = []
        real = mod.secrets.token_urlsafe

        def flaky(nbytes=None):
            calls.append(nbytes)
            if len(calls) == 3:
                raise RuntimeError("injected failure between the second and third key")
            return real(nbytes)

        return patch.object(mod.secrets, "token_urlsafe", flaky)

    def test_failure_between_mints_leaves_the_earlier_set_intact(self):
        mod = self.load()
        old = self.mint(mod)
        before = self.key_rows(mod)
        with self.fail_on_third_key(mod):
            with self.assertRaises(RuntimeError):
                with mod.get_db() as conn:
                    mod.issue_activation_secrets(conn, ACCOUNT)
                    conn.commit()
        self.assertEqual(self.key_rows(mod), before)
        for key in old:
            self.assertTrue(self.accepts(mod, key))

    def test_savepoint_undoes_partial_mints_even_when_the_caller_swallows_the_error(self):
        mod = self.load()
        old = self.mint(mod)
        before = self.key_rows(mod)
        with mod.get_db() as conn:
            with self.fail_on_third_key(mod):
                with self.assertRaises(RuntimeError):
                    mod.issue_activation_secrets(conn, ACCOUNT)
            conn.commit()  # a careless caller commits anyway
        self.assertEqual(self.key_rows(mod), before)
        self.assertTrue(self.accepts(mod, old[0]))

    def test_failure_on_a_fresh_account_leaves_no_key_at_all(self):
        mod = self.load()
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            with self.fail_on_third_key(mod):
                with self.assertRaises(RuntimeError):
                    mod.issue_activation_secrets(conn, ACCOUNT)
            conn.commit()
        self.assertEqual(self.key_rows(mod), [])

    def test_failed_outbox_insert_rolls_back_the_grant_and_every_key(self):
        mod = self.load()
        mod.paypal_enabled = lambda: True
        mod.PAYPAL_WEBHOOK_ID = "test-webhook"
        mod.PAYPAL_PLAN_1M = "test-plan"
        mod.verify_paypal_webhook_signature = lambda *args: True
        mod.fetch_paypal_subscription = lambda sub_id: {
            "id": sub_id, "plan_id": "test-plan", "status": "ACTIVE",
            "subscriber": {"email_address": BUYER, "name": {"given_name": "Test", "surname": "Buyer"}},
            "billing_info": {"next_billing_time": (mod.utcnow() + timedelta(days=30)).isoformat()},
        }
        mod.sync_peer_to_node = lambda *args, **kwargs: True

        def webhook():
            request = WebhookRequest(path="/webhook/paypal", body={
                "id": "evt-keys3", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
                "resource": {"id": "I-KEYS3"},
            })
            return asyncio.run(mod.paypal_webhook(request, harness.BackgroundTasks()))

        with patch.object(mod, "enqueue_activation_delivery", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                webhook()
        with self.db(mod) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM activation_extra_keys").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM activation_delivery_outbox").fetchone()[0], 0)
        # The retry grants once: one account, three keys, one outbox row.
        self.assertTrue(webhook()["created"])
        with self.db(mod) as conn:
            account = conn.execute("SELECT account_number FROM users").fetchone()[0]
            outbox = [dict(r) for r in conn.execute("SELECT * FROM activation_delivery_outbox")]
        self.assertEqual(len(self.key_rows(mod, account)), 3)
        self.assertEqual(len(outbox), 1)
        # A duplicate delivery of the same event neither grants nor mints again.
        before = self.key_rows(mod, account)
        self.assertEqual(webhook()["status"], "duplicate")
        self.assertEqual(self.key_rows(mod, account), before)
        sent = self.capture_mail(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 1)
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(sent[0][4]), 3)
        for key, (_slot, stored_hash, _e, _u) in zip(sent[0][4], before):
            self.assertEqual(stored_hash, mod._hash_activation_secret(key))


# =========================== 6. override, renewals, reopen ==================

class OverridesAndRenewals(KeysBase):
    def test_resend_to_an_override_account_sends_device_limit_keys_not_more(self):
        mod = self.load()
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET device_limit_override=10, email=? WHERE account_number=?", (BUYER, ACCOUNT))
        sent = self.capture_mail(mod)
        mod.resend_email(harness.FakeRequest(), harness.BackgroundTasks(), email=BUYER, x_admin_token=ADMIN)
        self.assertEqual(len(sent[0][4]), 3)
        self.assertEqual(len(self.key_rows(mod)), 3)

    def test_provision_of_an_existing_email_renews_and_sends_no_key(self):
        mod = self.load()
        real_send = mod.send_account_email
        sent = self.capture_mail(mod)
        self.provision(mod)
        before = self.key_rows(mod, sent[0][2])
        self.provision(mod, duration="3m")
        self.assertEqual(len(sent), 2)
        self.assertFalse(sent[1][4])
        self.assertEqual(self.key_rows(mod, sent[0][2]), before)
        mod.SMTP_USER, mod.SMTP_PASS = "relay-user", "relay-pass"
        captured = []
        mod.smtp_dispatch_message = lambda msg, to: captured.append(msg) or True
        self.assertTrue(real_send(*sent[1]))
        for part in captured[0].get_payload():
            self.assertNotIn("setup key", part.get_payload(decode=True).decode().lower())

    def purchase(self, mod):
        with mod.get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return mod.upsert_paypal_account(
                conn, email=f"user-{ACCOUNT}@example.test", subscriber_name="Buyer", subscription_id="",
                plan_id="lifetime_support", payer_id="", paypal_status="ACTIVE",
                next_billing_time=None, duration_text="10y",
                purchase_reference="CAPTURE-R", paypal_purchase_reference="CAPTURE-R",
            )

    def test_renewal_of_an_active_account_returns_no_keys_and_keeps_the_set(self):
        mod = self.load()
        self.mint(mod, expiration="2030-01-01T00:00:00")
        before = self.key_rows(mod)
        _account, created, _expiry, keys = self.purchase(mod)
        self.assertFalse(created)
        self.assertEqual(keys, [])
        self.assertEqual(self.key_rows(mod), before)

    def test_reopening_a_lapsed_account_replaces_the_whole_set(self):
        # Keys do not expire, so an unused key from before the lapse can still be
        # alive. Reopening replaces the set rather than trusting it.
        mod = self.load()
        old = self.mint(mod, devices=2, expiration="2026-01-01T00:00:00")
        with mod.get_db() as conn:
            self.assertTrue(mod.expire_account_runtime_if_due(conn, ACCOUNT))
        _account, created, _expiry, keys = self.purchase(mod)
        self.assertFalse(created)
        self.assertEqual(len(keys), 3)
        self.assertEqual(len(self.key_rows(mod)), 3)
        for key in old:
            self.assertFalse(self.accepts(mod, key))
        for key in keys:
            self.assertTrue(self.accepts(mod, key))

    def elapsed_but_unswept(self, mod, hours=1):
        """An account whose entitlement ended but whose status the expiry sweep
        has not yet changed: status 'active', expiration_date in the past."""
        keys = self.mint(mod, devices=2, expiration=(mod.utcnow() - timedelta(hours=hours)).isoformat())
        with mod.get_db() as conn:
            self.assertEqual(
                conn.execute("SELECT status FROM users WHERE account_number=?", (ACCOUNT,)).fetchone()[0], "active")
        return keys

    def test_a_purchase_after_expiry_but_before_the_sweep_gets_a_fresh_set(self):
        # K3-02. The status sweep runs on a timer, so entitlement can be over
        # while the row still says active. That is a lapse, not a renewal.
        mod = self.load()
        old = self.elapsed_but_unswept(mod)
        _account, created, expiry, keys = self.purchase(mod)
        self.assertFalse(created)
        self.assertEqual(len(keys), 3)
        self.assertGreater(mod.parse_iso_datetime(expiry), mod.utcnow())
        self.assertEqual(len(self.key_rows(mod)), 3)
        for key in old:
            self.assertFalse(self.accepts(mod, key))
        for key in keys:
            self.assertTrue(self.accepts(mod, key))

    def test_the_same_lapse_rule_holds_for_a_subscription_and_a_duration_grant(self):
        mod = self.load()
        mod.PAYPAL_PLAN_1M = "test-plan"
        for kind in ("subscription", "duration"):
            old = self.elapsed_but_unswept(mod)
            with mod.get_db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if kind == "subscription":
                    result = mod.upsert_paypal_account(
                        conn, email=f"user-{ACCOUNT}@example.test", subscriber_name="Buyer", subscription_id="I-ELAPSED",
                        plan_id="test-plan", payer_id="", paypal_status="ACTIVE",
                        next_billing_time=(mod.utcnow() + timedelta(days=30)).isoformat())
                else:
                    result = mod.upsert_paypal_account(
                        conn, email=f"user-{ACCOUNT}@example.test", subscriber_name="Buyer", subscription_id="",
                        plan_id="one_month", payer_id="", paypal_status="ACTIVE",
                        next_billing_time=None, duration_text="1m", purchase_reference="BTCPAY-K3")
            self.assertEqual(len(result[3]), 3, kind)
            for key in old:
                self.assertFalse(self.accepts(mod, key), kind)

    def test_a_pre_sweep_purchase_is_delivered_through_the_outbox(self):
        mod = self.load()
        mod.paypal_enabled = lambda: True
        mod.PAYPAL_WEBHOOK_ID = "test-webhook"
        mod.PAYPAL_PLAN_1M = "test-plan"
        mod.verify_paypal_webhook_signature = lambda *args: True
        mod.sync_peer_to_node = lambda *args, **kwargs: True
        old = self.elapsed_but_unswept(mod)
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET paypal_subscription_id='I-PRESWEEP' WHERE account_number=?", (ACCOUNT,))
        mod.fetch_paypal_subscription = lambda sub_id: {
            "id": sub_id, "plan_id": "test-plan", "status": "ACTIVE",
            "subscriber": {"email_address": f"user-{ACCOUNT}@example.test",
                           "name": {"given_name": "Test", "surname": "Buyer"}},
            "billing_info": {"next_billing_time": (mod.utcnow() + timedelta(days=30)).isoformat()},
        }
        request = WebhookRequest(path="/webhook/paypal", body={
            "id": "evt-presweep", "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
            "resource": {"id": "I-PRESWEEP"},
        })
        asyncio.run(mod.paypal_webhook(request, harness.BackgroundTasks()))
        sent = self.capture_mail(mod)
        self.assertEqual(mod.drain_activation_delivery_outbox_once(), 1)
        keys = list(sent[0][4])
        self.assertEqual(len(keys), 3)
        for key in old:
            self.assertFalse(self.accepts(mod, key))
        for key in keys:
            self.assertTrue(self.accepts(mod, key))

    def test_a_renewal_before_expiry_still_keeps_the_set(self):
        mod = self.load()
        self.mint(mod, expiration=(mod.utcnow() + timedelta(minutes=5)).isoformat())
        before = self.key_rows(mod)
        _account, _created, _expiry, keys = self.purchase(mod)
        self.assertEqual(keys, [])
        self.assertEqual(self.key_rows(mod), before)

    def test_a_large_device_limit_still_fits_the_sealed_delivery(self):
        mod = self.load(DEVICE_LIMIT=10)
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            keys = mod.issue_activation_secrets(conn, ACCOUNT)
            mod.enqueue_activation_delivery(
                conn, "paypal:big", f"user-{ACCOUNT}@example.test", "Buyer", ACCOUNT, "Plan", keys)
        self.assertEqual(len(keys), 10)
        with self.db(mod) as conn:
            sealed = conn.execute("SELECT sealed_secret FROM activation_delivery_outbox").fetchone()[0]
        self.assertEqual(mod.activation_key_list(mod.open_activation_delivery(sealed, "paypal:big", ACCOUNT)), keys)


# ============= 12. the admin routes obey the same account guard (K3-07) =====

class AdminRoutes(KeysBase):
    def setUp(self):
        self.mod = self.load()
        self.mint(self.mod, devices=0)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET email=?, subscriber_name='Buyer' WHERE account_number=?", (BUYER, ACCOUNT))
        self.sent = self.capture_mail(self.mod)

    def resend(self, email=BUYER):
        return self.mod.resend_email(harness.FakeRequest(), harness.BackgroundTasks(), email=email, x_admin_token=ADMIN)

    def current_email(self):
        with self.db(self.mod) as conn:
            return conn.execute("SELECT email FROM users WHERE account_number=?", (ACCOUNT,)).fetchone()[0]

    def probe_from_another_connection(self, hook_name, action):
        """Wrap a hub function so that, just before it runs, a second connection
        tries `action` (a SQL statement). Records whether the hub's writer lock
        kept that second connection out."""
        probe = {"blocked": None}
        real = getattr(self.mod, hook_name)

        def hooked(*args, **kwargs):
            other = sqlite3.connect(self.mod._DB, timeout=0.05)
            try:
                other.execute(action)
                other.commit()
                probe["blocked"] = False
            except sqlite3.OperationalError:
                probe["blocked"] = True
            finally:
                other.close()
            return real(*args, **kwargs)

        setattr(self.mod, hook_name, hooked)
        return probe

    # ---- /admin/resend -----------------------------------------------------
    def test_resend_looks_up_validates_and_mints_under_the_writer_lock(self):
        # K3-07: a concurrent change of the account address, between the lookup
        # and the mint, must not let keys go to the superseded address.
        probe = self.probe_from_another_connection(
            "issue_activation_secrets", f"UPDATE users SET email='moved@example.test' WHERE account_number='{ACCOUNT}'")
        result = self.resend()
        self.assertTrue(probe["blocked"], "the second writer got in before the keys were minted")
        self.assertEqual(self.current_email(), BUYER)
        self.assertEqual([args[0] for args in self.sent], [BUYER])
        self.assertEqual(len(self.sent[0][4]), 3)
        self.assertEqual(result["account_number"], ACCOUNT)

    def test_resend_never_mails_keys_to_an_address_that_is_no_longer_the_accounts(self):
        # The same reproduction, judged by its outcome: whatever address the mail
        # went to is the address the account carries once the route returns.
        self.probe_from_another_connection(
            "issue_activation_secrets", f"UPDATE users SET email='moved@example.test' WHERE account_number='{ACCOUNT}'")
        self.resend()
        self.assertEqual(self.sent[0][0], self.current_email())

    def test_resend_to_an_inactive_or_expired_account_rotates_and_mails_nothing(self):
        past = (self.mod.utcnow() - timedelta(minutes=1)).isoformat()
        for label, statement in (
            ("status", "UPDATE users SET status='expired' WHERE account_number=?"),
            ("elapsed", f"UPDATE users SET expiration_date='{past}' WHERE account_number=?"),
        ):
            with self.mod.get_db() as conn:
                conn.execute("UPDATE users SET status='active', expiration_date='2030-01-01T00:00:00' WHERE account_number=?", (ACCOUNT,))
                conn.execute(statement, (ACCOUNT,))
            before = self.key_rows(self.mod)
            with self.assertRaises(self.mod.HTTPException) as refused:
                self.resend()
            self.assertEqual(refused.exception.status_code, 409, label)
            self.assertEqual(self.key_rows(self.mod), before, label)
            self.assertEqual(self.sent, [], label)

    def test_resend_for_an_unknown_address_is_still_a_404_with_no_mail(self):
        with self.assertRaises(self.mod.HTTPException) as refused:
            self.resend("nobody@example.test")
        self.assertEqual(refused.exception.status_code, 404)
        self.assertEqual(self.sent, [])

    def test_resend_to_a_valid_account_still_replaces_the_set_once(self):
        before = self.key_rows(self.mod)
        self.resend()
        self.assertEqual(len(self.sent), 1)
        after = self.key_rows(self.mod)
        self.assertEqual(len(after), 3)
        self.assertNotEqual([row[1] for row in after], [row[1] for row in before])
        for key in self.sent[0][4]:
            self.assertTrue(self.accepts(self.mod, key))

    # ---- /admin/provision --------------------------------------------------
    def test_provision_checks_for_an_existing_account_under_the_writer_lock(self):
        # K3-07: the "does this address already have an account" lookup and the
        # insert are one atomic step, so two provisions cannot both create one.
        probe = self.probe_from_another_connection(
            "new_account_number",
            "INSERT INTO users (account_number, email, status, expiration_date, referral_code) "
            "VALUES ('7777-7777-7777', 'fresh@example.test', 'active', '2030-01-01T00:00:00', 'RACE7777')")
        result = self.provision(self.mod, email="fresh@example.test")
        self.assertTrue(probe["blocked"], "a second provision could slip in between the lookup and the insert")
        with self.db(self.mod) as conn:
            count = conn.execute("SELECT COUNT(*) FROM users WHERE email='fresh@example.test'").fetchone()[0]
        self.assertEqual(count, 1)
        self.assertTrue(result["email_sent"])

    def test_provision_passes_a_new_account_through_the_common_key_guard(self):
        # A fresh insert is active, unexpired (every duration is positive) and
        # carries the address it was created for, so the guard always passes it;
        # it is still the same guard, and a refusal leaves no account and no mail.
        seen = []
        real = self.mod.account_may_receive_keys

        def watching(user, target_email):
            seen.append((user["status"], user["email"], target_email))
            return real(user, target_email)

        self.mod.account_may_receive_keys = watching
        self.provision(self.mod, email="guarded@example.test")
        self.assertEqual(seen, [("active", "guarded@example.test", "guarded@example.test")])
        self.sent.clear()
        self.mod.account_may_receive_keys = lambda user, target_email: False
        with self.assertRaises(self.mod.HTTPException) as refused:
            self.provision(self.mod, email="refused@example.test")
        self.assertEqual(refused.exception.status_code, 409)
        with self.db(self.mod) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE email='refused@example.test'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM activation_extra_keys WHERE account_number NOT IN (SELECT account_number FROM users)").fetchone()[0], 0)
        self.assertEqual(self.sent, [])

    def test_provision_of_an_existing_address_still_sends_the_keyless_renewal_mail(self):
        before = self.key_rows(self.mod)
        self.provision(self.mod, email=BUYER, duration="3m")
        self.assertEqual(len(self.sent), 1)
        self.assertFalse(self.sent[0][4])
        self.assertEqual(self.key_rows(self.mod), before)


# ================================ redemption ================================

class Redemption(KeysBase):
    def setUp(self):
        self.mod = self.load()
        self.mod.JSONResponse = lambda *a, **k: types.SimpleNamespace(
            status_code=k.get("status_code", 200), content=k.get("content", a[0] if a else {}),
            headers=k.get("headers", {}))
        batch = self.mod.admin_issue_redemption_batch(
            harness.FakeRequest(), batch_id="keys3", count=8, duration="1m", label="keys3",
            partner="", plan_key="", canaries=0, expires_in_days=0, x_admin_token=ADMIN)
        self.mod_batch = batch
        self.codes = [entry["code"] for entry in batch["codes"]]
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "relay-user", "relay-pass"

    def redeem(self, code, **fields):
        payload = self.mod.RedemptionRequest(code=code, **fields)
        return self.mod.redeem_prepaid_code(harness.FakeRequest(client_host="198.51.100.10"), payload).content

    def test_redemption_with_an_email_gets_three_keys_and_mails_all_three(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.assertTrue(body["ok"], body)
        self.assertEqual(len(self.key_rows(self.mod, account)), 3)
        self.assertEqual(self.key_rows(self.mod, account)[0][1], self.mod._hash_activation_secret(body["setup_key"]))
        sent = self.capture_mail(self.mod)
        self.assertEqual(self.mod.drain_redemption_outbox()["delivered"], 1)
        ((_to, _name, mailed_account, _plan, keys),) = sent
        self.assertEqual(mailed_account, account)
        self.assertEqual(len(keys), 3)
        self.assertEqual(keys[0], body["setup_key"])
        for key, (_slot, stored_hash, _e, _u) in zip(keys, self.key_rows(self.mod, account)):
            self.assertEqual(stored_hash, self.mod._hash_activation_secret(key))

    def test_a_lost_response_retry_returns_the_first_key_and_mints_nothing(self):
        first = self.redeem(self.codes[0], email=BUYER)
        before = self.key_rows(self.mod, first["account_number"])
        again = self.redeem(self.codes[0], email=BUYER)
        self.assertTrue(again["recovered"])
        self.assertEqual(again["setup_key"], first["setup_key"])
        self.assertEqual(self.key_rows(self.mod, first["account_number"]), before)

    def test_redemption_without_an_email_keeps_its_single_key(self):
        body = self.redeem(self.codes[1])
        self.assertEqual(len(self.key_rows(self.mod, body["account_number"])), 1)
        self.assertTrue(self.accepts(self.mod, body["setup_key"], body["account_number"]))
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])

    # ---- K3-04: the welcome mail has its own sealed custody ---------------
    def outbox(self, account):
        with self.db(self.mod) as conn:
            return dict(conn.execute("SELECT * FROM redemption_outbox WHERE account_number=?", (account,)).fetchone())

    def acknowledge(self, code):
        payload = self.mod.RedemptionRequest(code=code)
        return self.mod.acknowledge_redemption(harness.FakeRequest(client_host="198.51.100.10"), payload)

    def spend(self, account, key):
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(conn, account, key))

    def make_pre_upgrade(self, account):
        """The state a row had before this build: no sealed mail bundle, and
        only the API fulfillment record behind it."""
        with self.mod.get_db() as conn:
            conn.execute("UPDATE redemption_outbox SET sealed_secret=NULL WHERE account_number=?", (account,))

    def test_an_expired_api_record_keeps_the_original_mail_set(self):
        body = self.redeem(self.codes[2], email=BUYER)
        account = body["account_number"]
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM redemption_fulfillments")
        sent = self.capture_mail(self.mod)
        self.assertEqual(self.mod.drain_redemption_outbox()["delivered"], 1)
        keys = list(sent[0][4])
        self.assertEqual(len(keys), 3)
        self.assertEqual(len(self.key_rows(self.mod, account)), 3)
        self.assertEqual(keys[0], body["setup_key"])
        for key in keys:
            self.assertTrue(self.accepts(self.mod, key, account))

    def test_acknowledging_the_api_key_keeps_the_mail_that_carries_keys_two_and_three(self):
        # K3-04. The API shows one key. Acknowledging it must not destroy the
        # only copy of the other two, which exist only in the welcome mail.
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.spend(account, body["setup_key"])  # the customer enrolled a device with it
        self.acknowledge(self.codes[0])
        self.assertEqual(harness.table_count(self.mod, "redemption_fulfillments"), 0)
        self.assertEqual(self.outbox(account)["status"], "pending")
        sent = self.capture_mail(self.mod)
        self.assertEqual(self.mod.drain_redemption_outbox()["confirmed"], 1)
        ((_to, _name, mailed_account, _plan, keys),) = sent
        self.assertEqual(mailed_account, account)
        # The spent first key is not mailed again; both unseen keys are.
        self.assertEqual(len(keys), 2)
        self.assertNotIn(body["setup_key"], keys)
        rows = self.key_rows(self.mod, account)
        for key, (_slot, stored_hash, _e, used_at) in zip(keys, rows[1:]):
            self.assertEqual(stored_hash, self.mod._hash_activation_secret(key))
            self.assertIsNone(used_at)
            self.assertTrue(self.accepts(self.mod, key, account))
        self.assertIsNone(self.outbox(account)["sealed_secret"])

    def test_acknowledging_before_any_key_is_used_mails_all_three(self):
        body = self.redeem(self.codes[0], email=BUYER)
        self.acknowledge(self.codes[0])
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(len(sent[0][4]), 3)
        self.assertEqual(sent[0][4][0], body["setup_key"])

    def test_acknowledgement_still_cancels_mail_that_has_nothing_extra_to_deliver(self):
        # No email: nothing to mail. One key (DEVICE_LIMIT 1): the API showed it.
        plain = self.redeem(self.codes[0])
        self.acknowledge(self.codes[0])
        self.assertEqual(self.outbox(plain["account_number"])["status"], "cancelled")
        self.assertIsNone(self.outbox(plain["account_number"])["sealed_secret"])
        single = self.load(DEVICE_LIMIT=1)
        single.SMTP_USER, single.SMTP_PASS = "relay-user", "relay-pass"
        single.JSONResponse = self.mod.JSONResponse
        batch = single.admin_issue_redemption_batch(
            harness.FakeRequest(), batch_id="keys3-one", count=1, duration="1m", label="keys3",
            partner="", plan_key="", canaries=0, expires_in_days=0, x_admin_token=ADMIN)
        code = batch["codes"][0]["code"]
        body = single.redeem_prepaid_code(
            harness.FakeRequest(client_host="198.51.100.10"),
            single.RedemptionRequest(code=code, email=BUYER)).content
        single.acknowledge_redemption(harness.FakeRequest(client_host="198.51.100.10"),
                                      single.RedemptionRequest(code=code))
        with self.db(single) as conn:
            row = dict(conn.execute("SELECT * FROM redemption_outbox WHERE account_number=?",
                                    (body["account_number"],)).fetchone())
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_mail_retries_after_the_api_record_is_gone_reuse_the_same_keys(self):
        # K3-04, second half: failed attempts must not mint different sets.
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM redemption_fulfillments")
        before = self.key_rows(self.mod, account)
        sent = self.capture_mail(self.mod, results=[False, RuntimeError("relay reset"), True])
        self.assertEqual(self.mod.drain_redemption_outbox()["failed"], 1)
        self.assertEqual(self.mod.drain_redemption_outbox()["failed"], 1)
        self.assertEqual(self.mod.drain_redemption_outbox()["confirmed"], 1)
        self.assertEqual(len(sent), 3)
        self.assertEqual(list(sent[0][4]), list(sent[1][4]))
        self.assertEqual(list(sent[0][4]), list(sent[2][4]))
        self.assertEqual(self.key_rows(self.mod, account), before)
        for key in sent[0][4]:
            self.assertTrue(self.accepts(self.mod, key, account))

    def test_a_pre_upgrade_row_rotates_once_and_its_retries_reuse_that_set(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.make_pre_upgrade(account)
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM redemption_fulfillments")
        sent = self.capture_mail(self.mod, results=[False, True])
        self.assertEqual(self.mod.drain_redemption_outbox()["failed"], 1)
        rotated = self.key_rows(self.mod, account)
        self.assertEqual(self.mod.drain_redemption_outbox()["confirmed"], 1)
        self.assertEqual(self.key_rows(self.mod, account), rotated)
        self.assertEqual(list(sent[0][4]), list(sent[1][4]))
        self.assertNotIn(body["setup_key"], sent[0][4])
        self.assertEqual(len(sent[0][4]), 3)

    def test_a_pre_upgrade_row_whose_key_was_used_is_cancelled_not_rotated(self):
        body = self.redeem(self.codes[2], email=BUYER)
        account = body["account_number"]
        self.make_pre_upgrade(account)
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM redemption_fulfillments")
        self.spend(account, body["setup_key"])
        before = self.key_rows(self.mod, account)
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        self.assertEqual(self.key_rows(self.mod, account), before)
        self.assertEqual(self.outbox(account)["status"], "cancelled")

    def test_an_extra_key_that_was_used_cancels_the_mail_but_a_used_first_key_does_not(self):
        spent_first = self.redeem(self.codes[2], email=BUYER)
        spent_extra = self.redeem(self.codes[3], email="second@example.test")
        self.spend(spent_first["account_number"], spent_first["setup_key"])
        with self.mod.get_db() as conn:
            conn.execute("UPDATE activation_extra_keys SET used_at=? WHERE account_number=? AND slot=3",
                         ("2026-10-22T00:00:00", spent_extra["account_number"]))
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual([args[0] for args in sent], [BUYER])
        self.assertEqual(len(sent[0][4]), 2)
        self.assertEqual(self.outbox(spent_extra["account_number"])["status"], "cancelled")

    def test_a_replaced_key_set_cancels_the_pending_welcome_mail(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        with self.mod.get_db() as conn:
            self.mod.issue_activation_secrets(conn, account)
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        row = self.outbox(account)
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_a_changed_account_email_cancels_the_pending_welcome_mail(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET email=? WHERE account_number=?", ("someone-else@example.test", account))
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        row = self.outbox(account)
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def account_changes(self):
        past = (self.mod.utcnow() - timedelta(minutes=1)).isoformat()
        return {
            "email": "UPDATE users SET email='changed@example.test' WHERE account_number=?",
            "status": "UPDATE users SET status='expired' WHERE account_number=?",
            "expired": f"UPDATE users SET expiration_date='{past}' WHERE account_number=?",
        }

    def test_recovery_revalidates_the_account_before_it_mints_or_mails(self):
        # K3-05. Both the sealed path and the legacy path (no sealed copy and no
        # API record, so a rotation) must re-check, under the writer lock, that
        # the account is still active, unexpired and on the queued address.
        for index, (change, statement) in enumerate(self.account_changes().items()):
            for legacy in (False, True):
                body = self.redeem(self.codes[2 * index + int(legacy)],
                                   email=f"k{index}{int(legacy)}@example.test")
                self.assertTrue(body["ok"], body)
                account = body["account_number"]
                if legacy:
                    self.make_pre_upgrade(account)
                    with self.mod.get_db() as conn:
                        conn.execute("DELETE FROM redemption_fulfillments WHERE account_number=?", (account,))
                with self.mod.get_db() as conn:
                    conn.execute(statement, (account,))
                before = self.key_rows(self.mod, account)
                sent = self.capture_mail(self.mod)
                self.mod.drain_redemption_outbox()
                self.assertEqual(sent, [], (change, legacy))
                self.assertEqual(self.key_rows(self.mod, account), before, (change, legacy))
                row = self.outbox(account)
                self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None), (change, legacy))

    def test_a_pre_upgrade_row_with_a_changed_email_is_not_rotated_or_mailed(self):
        # The exact reproduction: legacy recovery, both bundles absent, email changed.
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.make_pre_upgrade(account)
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM redemption_fulfillments")
            conn.execute("UPDATE users SET email='moved@example.test' WHERE account_number=?", (account,))
        before = self.key_rows(self.mod, account)
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        self.assertEqual(self.key_rows(self.mod, account), before)

    # ---- K3-06: terminal rows hold no sealed copy -------------------------
    def test_a_redemption_row_that_runs_out_of_attempts_is_cancelled_and_purged(self):
        self.mod.REDEMPTION_OUTBOX_MAX_ATTEMPTS = 2
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        sent = self.capture_mail(self.mod, results=[False, False, True])
        self.assertEqual(self.mod.drain_redemption_outbox()["failed"], 1)
        self.assertEqual(self.outbox(account)["status"], "pending")
        self.assertIsNotNone(self.outbox(account)["sealed_secret"])
        self.assertEqual(self.mod.drain_redemption_outbox()["failed"], 1)
        row = self.outbox(account)
        self.assertEqual((row["status"], row["sealed_secret"], row["attempts"]), ("cancelled", None, 2))
        self.mod.drain_redemption_outbox()
        self.assertEqual(len(sent), 2)

    def test_a_deferral_does_not_spend_an_attempt_or_purge_the_bundle(self):
        self.mod.REDEMPTION_OUTBOX_MAX_ATTEMPTS = 1
        body = self.redeem(self.codes[0], email=BUYER)
        calls = []

        def barrier():
            calls.append(1)
            raise self.mod.DurabilityBarrierError("replica_unavailable")

        self.mod.run_durability_barrier = barrier
        self.assertEqual(self.mod.drain_redemption_outbox()["deferred"], 1)
        row = self.outbox(body["account_number"])
        self.assertEqual((row["status"], row["attempts"]), ("pending", 0))
        self.assertIsNotNone(row["sealed_secret"])

    def test_rows_already_stuck_at_the_attempt_cap_are_purged_on_the_next_claim(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        with self.mod.get_db() as conn:
            conn.execute("UPDATE redemption_outbox SET attempts=? WHERE account_number=?",
                         (self.mod.REDEMPTION_OUTBOX_MAX_ATTEMPTS, account))
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        row = self.outbox(account)
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_the_mail_bundle_is_sealed_only_when_there_is_mail_to_send(self):
        withmail = self.redeem(self.codes[0], email=BUYER)
        nomail = self.redeem(self.codes[1])
        sealed = self.outbox(withmail["account_number"])["sealed_secret"]
        self.assertTrue(sealed.startswith("wao1|"))
        self.assertNotIn(withmail["setup_key"], sealed)
        self.assertIsNone(self.outbox(nomail["account_number"])["sealed_secret"])
        self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertIsNone(self.outbox(withmail["account_number"])["sealed_secret"])

    def test_a_refund_withdraws_the_sealed_mail_bundle(self):
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.assertIsNotNone(self.outbox(account)["sealed_secret"])
        entry = next(c for c in self.mod_batch["codes"] if c["code"] == self.codes[0])
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=entry["serial"], reason="refund", reference="order-k3", x_admin_token=ADMIN)
        row = self.outbox(account)
        self.assertEqual((row["status"], row["sealed_secret"]), ("completed", None))

    def test_a_pre_upgrade_acknowledged_row_is_still_cancelled_without_rotation(self):
        # S-HUB-01: a restored database can hold mail an old acknowledgement left pending.
        body = self.redeem(self.codes[0], email=BUYER)
        account = body["account_number"]
        self.acknowledge(self.codes[0])
        self.make_pre_upgrade(account)
        before = self.key_rows(self.mod, account)
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        self.assertEqual(self.key_rows(self.mod, account), before)
        self.assertEqual(self.outbox(account)["status"], "cancelled")

    def test_extending_an_account_issues_and_changes_no_key(self):
        keys = self.mint(self.mod, expiration=(self.mod.utcnow() + timedelta(days=30)).isoformat())
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET renewal_source='redemption', email=? WHERE account_number=?",
                         (BUYER, ACCOUNT))
        before = self.key_rows(self.mod)
        body = self.redeem(self.codes[0], account_number=ACCOUNT, email="attacker@example.test")
        self.assertEqual((body["mode"], body["setup_key"]), ("extend", ""))
        self.assertEqual(self.key_rows(self.mod), before)
        for key in keys:
            self.assertTrue(self.accepts(self.mod, key))
        sent = self.capture_mail(self.mod)
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])


# ====================== account removal, logs, rate limits ==================

class RemovalLogsAndLimits(KeysBase):
    def test_deleting_an_account_deletes_its_extra_keys(self):
        mod = self.load()
        tokens = harness.seed_account(mod, devices=3)
        with mod.get_db() as conn:
            mod.issue_activation_secrets(conn, ACCOUNT)
        a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
        harness.call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
        out = harness.call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
        self.assertEqual(out["stage"], "completed", out)
        self.assertEqual(harness.table_count(mod, "users"), 0)
        self.assertEqual(harness.table_count(mod, "activation_extra_keys"), 0)

    def queue_hoppy_mail(self, mod, account):
        with mod.get_db() as conn:
            conn.execute(
                "INSERT INTO hoppy_agent_mail_outbox (idempotency_key, kind, account_ref, target_email, status, "
                "created_at, sealed_secret) VALUES (?, 'credentials_resend', ?, ?, 'pending', ?, ?)",
                (f"k3-{account}", mod._hoppy_account_ref(account), f"user-{account}@example.test",
                 mod.utcnow().isoformat(),
                 mod.seal_activation_delivery("k1\nk2\nk3", f"hoppy:k3-{account}", account)))

    def test_deleting_an_account_purges_its_hoppy_mail_and_sealed_keys(self):
        mod = self.load()
        tokens = harness.seed_account(mod, devices=3)
        harness.seed_account(mod, account="4444-5555-6666", devices=0)
        self.queue_hoppy_mail(mod, ACCOUNT)
        self.queue_hoppy_mail(mod, "4444-5555-6666")
        a, b = f"dev-{ACCOUNT}-0", f"dev-{ACCOUNT}-1"
        harness.call(mod, "/account/deletion/request", ACCOUNT, a, tokens[a])
        out = harness.call(mod, "/account/deletion/confirm", ACCOUNT, b, tokens[b])
        self.assertEqual(out["stage"], "completed", out)
        with self.db(mod) as conn:
            refs = [r[0] for r in conn.execute("SELECT account_ref FROM hoppy_agent_mail_outbox")]
        self.assertEqual(refs, [mod._hoppy_account_ref("4444-5555-6666")])

    def test_recycling_an_account_number_purges_its_hoppy_mail_and_sealed_keys(self):
        mod = self.load()
        self.mint(mod, expiration=(mod.utcnow() - timedelta(days=60)).isoformat())
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET status='expired' WHERE account_number=?", (ACCOUNT,))
        self.queue_hoppy_mail(mod, ACCOUNT)
        conn = sqlite3.connect(mod._DB)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            self.assertEqual(mod.reclaim_expired_account_for_reuse(conn), ACCOUNT)
            conn.commit()
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM hoppy_agent_mail_outbox").fetchone()[0], 0)
        finally:
            conn.close()

    def test_recycling_an_account_number_never_inherits_old_keys(self):
        mod = self.load()
        self.mint(mod, expiration=(mod.utcnow() - timedelta(days=60)).isoformat())
        with mod.get_db() as conn:
            conn.execute("UPDATE users SET status='expired' WHERE account_number=?", (ACCOUNT,))
        # Foreign keys OFF: the explicit DELETE must do the work, not the cascade.
        conn = sqlite3.connect(mod._DB)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=OFF")
            self.assertEqual(mod.reclaim_expired_account_for_reuse(conn), ACCOUNT)
            conn.commit()
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM activation_extra_keys").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        finally:
            conn.close()

    def test_key_values_are_never_logged(self):
        mod = self.load()
        capture = LogCapture()
        mod.logger.addHandler(capture)
        mod.SMTP_USER, mod.SMTP_PASS = "relay-user", "relay-pass"
        relayed = []
        refuse = []

        class FakeSMTP:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def ehlo(self):
                pass

            def starttls(self, **kwargs):
                pass

            def login(self, *args):
                pass

            def sendmail(self, sender, to, raw):
                if refuse:
                    raise RuntimeError("relay refused the message")
                relayed.append(raw)

        with patch.object(mod.smtplib, "SMTP", FakeSMTP):
            self.assertTrue(self.provision(mod)["email_sent"])
            mod.resend_email(harness.FakeRequest(), harness.BackgroundTasks(), email=BUYER, x_admin_token=ADMIN)
            refuse.append(True)
            mod.resend_email(harness.FakeRequest(), harness.BackgroundTasks(), email=BUYER, x_admin_token=ADMIN)
        keys = [key for raw in relayed for key in re.findall(r"Setup key \d of \d: (\S+)", raw)]
        self.assertEqual(len(keys), 6)  # two delivered emails, three keys each
        self.assertTrue(capture.lines)
        self.assertTrue(any("SMTP dispatch failed" in line for line in capture.lines))
        for line in capture.lines:
            for key in keys:
                self.assertNotIn(key, line)

    def test_a_three_key_account_gets_no_extra_guesses(self):
        mod = self.load(VERIFY_IP_RATE_LIMIT_PER_MINUTE=4)
        dh.seed_node(mod)
        harness.seed_account(mod, account="1111-2222-3333", devices=0)
        harness.seed_account(mod, account="4444-5555-6666", devices=0)
        with mod.get_db() as conn:
            mod.issue_activation_secrets(conn, "1111-2222-3333")
            mod.issue_activation_secrets(conn, "4444-5555-6666", count=1)

        def statuses(account):
            with mod.get_db() as conn:
                conn.execute("DELETE FROM rate_limits")
            codes = []
            for n in range(8):
                try:
                    dh.served_config(
                        mod, request_headers={"x-wins-activation": f"guess-{n}"}, account_number=account,
                        device_id=f"rate-device-{n}", device_model="audit-harness",
                        client_public_key=pub(60 + n), device_fingerprint=f"fp-rate-{n}-0123456789")
                    codes.append(200)
                except mod.HTTPException as exc:
                    codes.append(exc.status_code)
            return codes

        three = statuses("1111-2222-3333")
        one = statuses("4444-5555-6666")
        self.assertIn(429, three)
        self.assertEqual(three, one)


# ===================== 11. restore reconciliation of acknowledged mail ======

class RestoreReconciliation(KeysBase):
    ROOT = Path(__file__).resolve().parents[1]
    SQL = ROOT / "server" / "db" / "reconcile_redemption_ack_outbox.sql"
    DOC = ROOT / "docs" / "HUB_BACKUP_RECOVERY_CONTRACT.md"

    def runbook_step(self):
        return self.DOC.read_text(encoding="utf-8").split("\n6. ", 1)[1].split("\n7. ", 1)[0]

    def runbook_line(self, startswith):
        for line in self.runbook_step().splitlines():
            if line.strip().startswith(startswith):
                return line.strip()
        raise AssertionError(f"runbook line not found: {startswith}")

    def seed_rows(self, mod):
        """Four pending/delivered rows, each with a fulfillment_acknowledged
        event except the last. Returns {name: idempotency_key}."""
        harness.seed_account(mod, devices=0)
        now = mod.utcnow().isoformat()
        rows = {
            "legacy_acked": ("pending", None, True),
            "sealed_acked": ("pending", mod.seal_activation_delivery("k1\nk2\nk3", "redemption:sealed_acked", ACCOUNT), True),
            "delivered_acked": ("delivered", None, True),
            "legacy_unacked": ("pending", None, False),
        }
        with mod.get_db() as conn:
            for name, (status, sealed, acked) in rows.items():
                conn.execute(
                    "INSERT INTO redemption_outbox (idempotency_key, kind, account_number, target_email, status, "
                    "created_at, sealed_secret) VALUES (?, 'redemption_welcome_email', ?, 'x@example.test', ?, ?, ?)",
                    (name, ACCOUNT, status, now, sealed))
                if acked:
                    conn.execute(
                        "INSERT INTO redemption_events (event_id, occurred_at, outcome, idempotency_key) "
                        "VALUES (?, ?, 'fulfillment_acknowledged', ?)", (f"ev-{name}", now, name))
        return {name: name for name in rows}

    def statuses(self, mod):
        with self.db(mod) as conn:
            return {r["idempotency_key"]: (r["status"], r["sealed_secret"] is not None)
                    for r in conn.execute("SELECT idempotency_key, status, sealed_secret FROM redemption_outbox")}

    def count_check_sql(self):
        line = next(l for l in self.runbook_step().splitlines() if l.strip().startswith('test "$(sqlite3 -readonly'))
        return re.search(r'"(SELECT COUNT\(\*\).*?;)"\)" = 0', line).group(1)

    def test_the_reconciliation_keeps_sealed_mail_and_still_repairs_old_rows(self):
        # Sol round 2. An acknowledged row that holds its own sealed mail bundle
        # is legitimate multi-key mail. Only rows with no sealed copy (what an
        # acknowledgement before this build left behind) are cancelled.
        mod = self.load()
        self.seed_rows(mod)
        sql = self.SQL.read_text(encoding="utf-8")
        for _ in range(2):  # and it is safe to run twice
            with self.db(mod) as conn:
                conn.executescript(sql)
            self.assertEqual(self.statuses(mod), {
                "legacy_acked": ("cancelled", False),
                "sealed_acked": ("pending", True),
                "delivered_acked": ("delivered", False),
                "legacy_unacked": ("pending", False),
            })
        with self.db(mod) as conn:
            completed = conn.execute(
                "SELECT completed_at FROM redemption_outbox WHERE idempotency_key='legacy_acked'").fetchone()[0]
            self.assertIsNotNone(completed)
            # The runbook's own "nothing left to reconcile" check passes.
            self.assertEqual(conn.execute(self.count_check_sql()).fetchone()[0], 0)

    def test_the_runbook_check_does_not_count_sealed_mail_as_unreconciled(self):
        mod = self.load()
        self.seed_rows(mod)
        with self.db(mod) as conn:
            # Before the repair only the legacy acknowledged row is unreconciled.
            self.assertEqual(conn.execute(self.count_check_sql()).fetchone()[0], 1)

    @unittest.skipUnless(shutil.which("sqlite3"), "needs the sqlite3 command line shell")
    def test_the_runbook_commands_repair_a_database_from_before_the_sealed_column(self):
        # A restore normally comes from an older build, so the reconciliation
        # runs BEFORE the schema migration. Rehearse the runbook's own commands
        # against a database that has no sealed_secret column.
        import subprocess
        import tempfile
        mod = self.load()
        self.seed_rows(mod)
        with self.db(mod) as conn, conn:
            conn.execute("UPDATE redemption_outbox SET sealed_secret=NULL")
            conn.execute("ALTER TABLE redemption_outbox DROP COLUMN sealed_secret")
        db = tempfile.mkdtemp(prefix="k3-restore-") + "/vpn_users.db"
        self.addCleanup(shutil.rmtree, str(Path(db).parent), True)
        source, target = sqlite3.connect(mod._DB), sqlite3.connect(db)
        source.backup(target)
        source.close()
        target.close()
        steps = [
            self.runbook_line("sqlite3 -readonly"),
            self.runbook_line("sqlite3 -bail -cmd '.timeout 30000' /root/vpn_auth/vpn_users.db <"),
            self.runbook_line('test "$(sqlite3 -readonly'),
        ]
        for step in steps:
            command = step.replace("/root/vpn_auth/vpn_users.db", db).replace(
                "server/db/reconcile_redemption_ack_outbox.sql", str(self.SQL))
            result = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, (command, result.stderr))
        conn = sqlite3.connect(db)
        try:
            columns = [r[1] for r in conn.execute("PRAGMA table_info(redemption_outbox)")]
            self.assertIn("sealed_secret", columns)
            states = dict(conn.execute("SELECT idempotency_key, status FROM redemption_outbox"))
        finally:
            conn.close()
        self.assertEqual(states["legacy_acked"], "cancelled")
        self.assertEqual(states["legacy_unacked"], "pending")
        # Running the same commands again changes nothing and still passes.
        for step in steps:
            command = step.replace("/root/vpn_auth/vpn_users.db", db).replace(
                "server/db/reconcile_redemption_ack_outbox.sql", str(self.SQL))
            self.assertEqual(subprocess.run(["bash", "-c", command], capture_output=True, text=True).returncode, 0)

    def test_the_runbook_names_why_sealed_rows_are_skipped_and_orders_the_steps(self):
        step = self.runbook_step()
        ensure = step.index("ADD COLUMN sealed_secret TEXT")
        reconcile = step.index("< server/db/reconcile_redemption_ack_outbox.sql")
        self.assertLess(ensure, reconcile)
        self.assertIn("sealed_secret", step[reconcile:])
        self.assertIn("COALESCE(o.sealed_secret, '') = ''", step)


# ======================= 9. keys do not expire (owner ruling) ===============

class KeyLifetime(EnrolBase):
    def renewal(self):
        with self.mod.get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self.mod.upsert_paypal_account(
                conn, email=f"user-{ACCOUNT}@example.test", subscriber_name="Buyer", subscription_id="",
                plan_id="lifetime_support", payer_id="", paypal_status="ACTIVE",
                next_billing_time=None, duration_text="10y",
                purchase_reference="CAPTURE-L", paypal_purchase_reference="CAPTURE-L",
            )

    def test_every_key_still_enrols_a_device_more_than_a_year_later(self):
        real_now = self.mod.now_utc
        later = lambda: real_now() + timedelta(days=400)  # noqa: E731
        with patch.object(self.mod, "now_utc", later):
            with self.mod.get_db() as conn:
                conn.execute("UPDATE nodes SET last_heartbeat=?", (later().isoformat(),))
            for n, key in enumerate(self.keys):
                self.assertTrue(self.accepts(self.mod, key))
                self.assertEqual(self.enrol(key, n).get("status"), "authenticated")
        self.assertEqual(len(self.device_ids()), 3)
        self.assertEqual(self.live_keys(self.mod), [])

    def test_a_key_is_still_single_use_when_it_never_expires(self):
        self.assertEqual(self.enrol(self.keys[1], 0).get("status"), "authenticated")
        with self.assertRaises(self.mod.HTTPException) as refused:
            self.enrol(self.keys[1], 1)
        self.assertEqual(refused.exception.status_code, 401)
        self.assertEqual(len(self.device_ids()), 1)

    def test_a_revoked_account_refuses_every_key_and_spends_none(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET status='expired', paypal_status='REFUNDED' WHERE account_number=?", (ACCOUNT,))
        for n, key in enumerate(self.keys):
            with self.assertRaises(self.mod.HTTPException) as refused:
                self.enrol(key, n)
            self.assertEqual(refused.exception.status_code, 401)
        self.assertEqual(self.device_ids(), [])
        self.assertEqual(len(self.live_keys(self.mod)), 3)

    def test_expired_legacy_keys_stay_expired_and_unexpired_ones_keep_their_expiry(self):
        # Rows written by the earlier build. Nothing here may revive or change them.
        past = (self.mod.utcnow() - timedelta(minutes=5)).isoformat(timespec="seconds")
        soon = (self.mod.utcnow() + timedelta(minutes=20)).isoformat(timespec="seconds")
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_expires_at=? WHERE account_number=?", (past, ACCOUNT))
            conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=2", (soon,))
        before = self.key_rows(self.mod)
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            self.mod._ensure_schema_full(conn)
        _account, created, _expiry, issued = self.renewal()
        self.assertFalse(created)
        self.assertEqual(issued, [])
        self.assertEqual(self.key_rows(self.mod), before)
        self.assertFalse(self.accepts(self.mod, self.keys[0]))
        self.assertTrue(self.accepts(self.mod, self.keys[1]))
        self.assertTrue(self.accepts(self.mod, self.keys[2]))
        with self.assertRaises(self.mod.HTTPException) as refused:
            self.enrol(self.keys[0], 0)
        self.assertEqual(refused.exception.status_code, 401)
        self.assertEqual(self.device_ids(), [])


# ================= 10. the wording of a refused setup key ===================

class RefusalWording(EnrolBase):
    PLAIN = "That setup key is not valid or has already been used."

    def refusal(self, key, n, location):
        with self.assertRaises(self.mod.HTTPException) as caught:
            self.enrol(key, n, location=location)
        self.assertEqual(caught.exception.status_code, 401)
        return caught.exception.detail

    def test_wrong_used_replaced_and_expired_keys_get_one_plain_message(self):
        for round_number, location in enumerate(("lab-alpha", "auto")):
            with self.mod.get_db() as conn:
                keys = self.mod.issue_activation_secrets(conn, ACCOUNT)
            base = 100 * (round_number + 1)
            # used: spend key 1 on a device, then present it again
            self.assertEqual(self.enrol(keys[0], base).get("status"), "authenticated")
            used = self.refusal(keys[0], base + 1, location)
            # replaced: a newer set voids this one
            old = list(keys)
            with self.mod.get_db() as conn:
                keys = self.mod.issue_activation_secrets(conn, ACCOUNT)
            replaced = self.refusal(old[1], base + 2, location)
            # wrong: never issued
            wrong = self.refusal("a-key-that-was-never-issued", base + 3, location)
            # expired: a key row still carrying an old build's lapsed expiry
            with self.mod.get_db() as conn:
                conn.execute("UPDATE activation_extra_keys SET expires_at=? WHERE slot=3",
                             ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(),))
            expired = self.refusal(keys[2], base + 4, location)
            details = {used, replaced, wrong, expired}
            self.assertEqual(details, {self.mod.SETUP_KEY_REFUSED_DETAIL}, location)
            self.assertIn(self.PLAIN, used)
            self.assertNotIn("smart routing", used.lower())
            self.assertNotIn("device token", used.lower())

    def test_a_request_with_no_key_is_told_a_key_is_required(self):
        for location in ("lab-alpha", "auto"):
            detail = self.refusal(None, 7, location)
            self.assertEqual(detail, self.mod.SETUP_KEY_REQUIRED_DETAIL)
            self.assertNotIn("smart routing", detail.lower())
            self.assertNotEqual(detail, self.mod.SETUP_KEY_REFUSED_DETAIL)

    def test_the_old_wordings_are_gone_from_the_hub(self):
        source = harness._extract_main_block()
        for old in ("before smart routing", "Activation key is invalid, expired, or already used.",
                    "Activation key expired. Contact support to request a new key."):
            self.assertNotIn(old, source)

    def test_refusals_still_spend_the_failure_budget_on_both_paths(self):
        mod = self.load(VERIFY_IP_RATE_LIMIT_PER_MINUTE=3)
        dh.seed_node(mod)
        harness.seed_account(mod, devices=0)
        with mod.get_db() as conn:
            mod.issue_activation_secrets(conn, ACCOUNT)
        for location in ("lab-alpha", "auto"):
            with mod.get_db() as conn:
                conn.execute("DELETE FROM rate_limits")
            codes = []
            for n in range(6):
                try:
                    dh.served_config(
                        mod, request_headers={"x-wins-activation": f"guess-{n}"}, location=location,
                        device_id=f"budget-{n}", device_model="audit-harness",
                        client_public_key=pub(80 + n), device_fingerprint=f"fp-budget-{n}-0123456789")
                    codes.append(200)
                except mod.HTTPException as exc:
                    codes.append(exc.status_code)
            self.assertEqual(codes[:3], [401, 401, 401], location)
            self.assertIn(429, codes[3:], location)
            self.assertNotIn(200, codes, location)


if __name__ == "__main__":
    unittest.main()
