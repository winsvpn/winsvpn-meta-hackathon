#!/usr/bin/env python3
"""Round R2: prepaid extension, referral and promo codes, serials, refunds.

Exercises the REAL embedded hub (the main.py heredoc) against real SQLite:

1. Extension by account number alone only ADDS time to an active account:
   no setup key is issued, returned or emailed, and the email never changes.
2. A lapsed account needs a credential (device bearer or unused setup key);
   without one the request is refused, the code stays unused and the
   failure budget is spent.
3. Accounts that renew through a PayPal subscription are refused.
4. Referral codes entered at redemption pay the existing 20 percent bonus to
   both sides; self-referral and giveaway batches are refused.
5. Promo campaigns grant bonus days once per account, respect quota, expiry,
   revocation and the no-stacking rule.
6. Mint assigns printable serials and records the channel; retail channels
   may not expire before redemption.
7. /admin/redemption/revoke-code revokes an unused card and withdraws exactly
   the span a redeemed card granted, clawing back only its own referral.
8. /api/redeem/ack crosses the durability barrier on every call.
9. Hub-priced checkout validates a typed promo and settlement honours it.

Run: python3 server/test_r2_prepaid_promo_referral_hub.py
"""
import _toolchain  # noqa: F401
from contextlib import closing
from datetime import timedelta
import importlib.util
import logging
from pathlib import Path
import shutil
import sqlite3
import types
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness

ADMIN = "test-admin-token"
REFERRER = "4444-5555-6666"
TARGET = "1111-2222-3333"


class R2PrepaidPromoReferral(unittest.TestCase):
    def setUp(self):
        self.mod = self.load()

    def load(self, **env):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        settings = dict(
            DURABILITY_BARRIER_ENABLED=0,
            DURABILITY_BARRIER_REQUIRED=0,
            REDEMPTION_KEYS="v1:" + "cd" * 32,
            REDEMPTION_KEY_ACTIVE_VERSION="v1",
            REDEMPTION_IP_RATE_LIMIT_PER_MINUTE=1000,
            REDEMPTION_IP_RATE_LIMIT_PER_HOUR=1000,
            REDEMPTION_CODE_RATE_LIMIT_PER_HOUR=1000,
        )
        settings.update(env)
        with patch("logging.basicConfig", side_effect=close_handlers):
            mod = harness.load_hub(**settings)
        mod.logger.propagate = False
        mod.logger.addHandler(logging.NullHandler())
        mod.security_alert = lambda *args, **kwargs: None
        mod.JSONResponse = lambda *a, **k: types.SimpleNamespace(
            status_code=k.get("status_code", 200),
            content=k.get("content", a[0] if a else {}),
            headers=k.get("headers", {}),
        )
        self.addCleanup(shutil.rmtree, mod._TMPDIR, True)
        return mod

    # ---- helpers -----------------------------------------------------------
    def db(self):
        conn = sqlite3.connect(self.mod._DB)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def one(self, sql, args=()):
        with self.db() as conn:
            return conn.execute(sql, args).fetchone()

    def execute(self, sql, args=()):
        with self.db() as conn, conn:
            conn.execute(sql, args)

    def mint(self, batch_id="r2-batch", count=2, duration="1m", channel="direct", expires_in_days=0, canaries=0):
        # channel is omitted for the default so the same helper also mints on a
        # pre-R2 hub, where these tests must fail on the missing behaviour.
        extra = {} if channel == "direct" else {"channel": channel, "distribution_reference": ""}
        return self.mod.admin_issue_redemption_batch(
            harness.FakeRequest(), batch_id=batch_id, count=count, duration=duration, label="r2",
            partner="", plan_key="", canaries=canaries, expires_in_days=expires_in_days,
            x_admin_token=ADMIN, **extra,
        )

    def redeem(self, code, headers=None, ip="198.51.100.10", **fields):
        payload = self.mod.RedemptionRequest(code=code, **fields)
        response = self.mod.redeem_prepaid_code(harness.FakeRequest(headers=headers, client_host=ip), payload)
        return response.content

    def promo(self, code, bonus_days=7, max_uses=10, stack="false", plans="", days=30):
        return self.mod.admin_create_promo(
            harness.FakeRequest(), bonus_days=bonus_days, max_uses=max_uses, expires_at="",
            expires_in_days=days, code=code, plan_keys=plans, stack_referral=stack, note="",
            x_admin_token=ADMIN,
        )

    def seed(self, account, expiry_delta_days=30, status="active", devices=1, email=None):
        tokens = harness.seed_account(
            self.mod, account=account, devices=devices,
            expiration=(self.mod.utcnow() + timedelta(days=expiry_delta_days)).isoformat(),
        )
        self.execute("UPDATE users SET status=?, renewal_source='redemption' WHERE account_number=?", (status, account))
        if email is not None:
            self.execute("UPDATE users SET email=? WHERE account_number=?", (email, account))
        return tokens

    def code_status(self, code):
        normalized = self.mod.normalize_redemption_code(code)
        digest = self.mod.redemption_code_hash(normalized, "v1")
        return self.one("SELECT * FROM redemption_codes WHERE code_hash=?", (digest,))

    # ---- 1 -----------------------------------------------------------------
    def test_extension_by_number_alone_only_adds_time(self):
        self.seed(TARGET, expiry_delta_days=30, email="owner@example.test")
        before = self.one("SELECT * FROM users WHERE account_number=?", (TARGET,))
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, account_number=TARGET, email="attacker@example.test")
        self.assertTrue(body["ok"], body)
        self.assertEqual((body["mode"], body["status"], body["setup_key"]), ("extend", "extended", ""))
        after = self.one("SELECT * FROM users WHERE account_number=?", (TARGET,))
        expected = self.mod.parse_iso_datetime(before["expiration_date"]) + self.mod.parse_duration("1m")
        self.assertEqual(self.mod.parse_iso_datetime(after["expiration_date"]), expected)
        self.assertEqual(after["email"], "owner@example.test")
        self.assertEqual(after["activation_secret_hash"], before["activation_secret_hash"])
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM devices WHERE account_number=?", (TARGET,))["n"], 1)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM redemption_outbox")["n"], 0)
        # A retry of the same code recovers the extension and still discloses no key.
        again = self.redeem(code, account_number=TARGET)
        self.assertTrue(again["recovered"])
        self.assertEqual((again["mode"], again["setup_key"]), ("extend", ""))

    # ---- 2 -----------------------------------------------------------------
    def test_lapsed_account_needs_a_credential(self):
        self.seed(TARGET, expiry_delta_days=-20, status="expired", devices=0, email="owner@example.test")
        code = self.mint()["codes"][0]["code"]
        refused = self.redeem(code, account_number=TARGET, email="attacker@example.test")
        self.assertEqual((refused["ok"], refused["status"]), (False, "account_inactive"))
        self.assertNotIn("setup_key", refused)
        self.assertEqual(self.code_status(code)["status"], "unused")
        self.assertEqual(self.one("SELECT email FROM users WHERE account_number=?", (TARGET,))["email"], "owner@example.test")
        # Support re-issued a setup key: presenting it (unconsumed) unlocks extension.
        with self.mod.get_db() as conn:
            setup_key = self.mod.issue_activation_secret(conn, TARGET)
        body = self.redeem(code, headers={"X-Wins-Activation": setup_key}, account_number=TARGET)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["setup_key"], "")
        row = self.one("SELECT * FROM users WHERE account_number=?", (TARGET,))
        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["activation_secret_used_at"], "the setup key must stay usable for enrolment")
        self.assertGreater(self.mod.parse_iso_datetime(row["expiration_date"]), self.mod.utcnow() + timedelta(days=27))

    def test_lazily_unflipped_account_extends_with_its_device_token(self):
        tokens = self.seed(TARGET, expiry_delta_days=-2, status="active", devices=1)
        device_id, token = next(iter(tokens.items()))
        code = self.mint()["codes"][0]["code"]
        self.assertEqual(self.redeem(code, account_number=TARGET)["status"], "account_inactive")
        body = self.redeem(code, headers={"Authorization": f"Bearer {token}"},
                           account_number=TARGET, device_id=device_id)
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["mode"], "extend")

    # ---- 3 -----------------------------------------------------------------
    def test_recurring_paypal_account_is_refused(self):
        self.seed(TARGET)
        self.execute("UPDATE users SET paypal_subscription_id='I-R2SUB' WHERE account_number=?", (TARGET,))
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, account_number=TARGET)
        self.assertEqual((body["ok"], body["status"]), (False, "account_recurring"))
        self.assertEqual(self.code_status(code)["status"], "unused")

    def test_unknown_account_refusals_spend_the_failure_budget(self):
        self.mod = self.load(REDEMPTION_CODE_RATE_LIMIT_PER_HOUR=2)
        code = self.mint()["codes"][0]["code"]
        for _ in range(2):
            self.assertEqual(self.redeem(code, account_number="9876-5432-1098")["status"], "account_not_found")
        with self.assertRaises(harness.HTTPException) as caught:
            self.redeem(code, account_number="9876-5432-1098")
        self.assertEqual(caught.exception.status_code, 429)
        self.assertEqual(self.code_status(code)["status"], "unused")

    # ---- 4 -----------------------------------------------------------------
    def test_referral_at_redemption_pays_both_sides(self):
        self.seed(REFERRER, expiry_delta_days=10)
        ref_code = self.one("SELECT referral_code FROM users WHERE account_number=?", (REFERRER,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (ref_code, REFERRER))
        referrer_before = self.mod.parse_iso_datetime(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"])
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, referral_code=ref_code.upper())
        self.assertTrue(body["ok"], body)
        self.assertEqual(body["mode"], "new")
        self.assertTrue(body["setup_key"])
        self.assertGreater(body["referral_bonus_days"], 0)
        reward = self.one("SELECT * FROM referral_rewards WHERE referred_account_number=?", (body["account_number"],))
        self.assertEqual(reward["referrer_account_number"], REFERRER)
        self.assertTrue(reward["purchase_reference"].startswith("redemption:v1:"))
        referrer_after = self.mod.parse_iso_datetime(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"])
        self.assertEqual(referrer_after - referrer_before, timedelta(days=body["referral_bonus_days"]))
        new_user = self.one("SELECT * FROM users WHERE account_number=?", (body["account_number"],))
        self.assertEqual(new_user["referred_by_account_number"], REFERRER)

    def test_self_referral_and_giveaway_referral_are_refused(self):
        self.seed(TARGET)
        own = self.one("SELECT referral_code FROM users WHERE account_number=?", (TARGET,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (own, TARGET))
        code = self.mint()["codes"][0]["code"]
        self.assertEqual(self.redeem(code, account_number=TARGET, referral_code=own)["status"], "referral_invalid")
        self.seed(REFERRER)
        ref = self.one("SELECT referral_code FROM users WHERE account_number=?", (REFERRER,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (ref, REFERRER))
        gift = self.mint(batch_id="r2-gift", channel="giveaway", expires_in_days=30)["codes"][0]["code"]
        self.assertEqual(self.redeem(gift, referral_code=ref)["status"], "referral_not_allowed")
        self.assertEqual(self.code_status(gift)["status"], "unused")

    # ---- 5 -----------------------------------------------------------------
    def test_promo_bonus_days_once_per_account_with_quota_and_revocation(self):
        self.promo("WELCOME7", bonus_days=7, max_uses=2)
        codes = [c["code"] for c in self.mint(count=4)["codes"]]
        first = self.redeem(codes[0], promo_code="welcome7")
        self.assertTrue(first["ok"], first)
        self.assertEqual(first["promo_bonus_days"], 7)
        granted = self.mod.parse_iso_datetime(first["expiration_date"])
        self.assertGreaterEqual(granted - self.mod.utcnow(), timedelta(days=7 + 27))
        account = first["account_number"]
        self.assertEqual(self.redeem(codes[1], account_number=account, promo_code="WELCOME7")["status"], "promo_used")
        self.assertTrue(self.redeem(codes[1], promo_code="WELCOME7")["ok"])  # second account, use 2 of 2
        self.assertEqual(self.redeem(codes[2], promo_code="WELCOME7")["status"], "promo_invalid")  # quota spent
        self.promo("SPRING", bonus_days=3, max_uses=5)
        self.mod.admin_revoke_promo(harness.FakeRequest(), code="spring", reason="ended", x_admin_token=ADMIN)
        self.assertEqual(self.redeem(codes[2], promo_code="SPRING")["status"], "promo_invalid")
        self.assertEqual(self.redeem(codes[3], promo_code="NOPE-NOT-REAL")["status"], "promo_invalid")
        listed = {p["code"]: p for p in self.mod.admin_list_promos(harness.FakeRequest(), x_admin_token=ADMIN)["promos"]}
        self.assertEqual(listed["WELCOME7"]["uses"], 2)
        self.assertTrue(listed["SPRING"]["revoked_at"])

    def test_promo_and_referral_stack_only_when_the_campaign_allows(self):
        self.seed(REFERRER)
        ref = self.one("SELECT referral_code FROM users WHERE account_number=?", (REFERRER,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (ref, REFERRER))
        self.promo("SOLO", stack="false")
        self.promo("DUO2", stack="true")
        codes = [c["code"] for c in self.mint(count=2)["codes"]]
        self.assertEqual(self.redeem(codes[0], referral_code=ref, promo_code="SOLO")["status"], "promo_no_stack")
        both = self.redeem(codes[0], referral_code=ref, promo_code="DUO2")
        self.assertTrue(both["ok"], both)
        self.assertGreater(both["referral_bonus_days"], 0)
        self.assertEqual(both["promo_bonus_days"], 7)

    def test_promo_admin_validation(self):
        with self.assertRaises(harness.HTTPException):
            self.promo("BAD CODE")
        with self.assertRaises(harness.HTTPException):
            self.promo("ZERO", bonus_days=0)
        with self.assertRaises(harness.HTTPException):
            self.promo("PLANS", plans="one_week")
        generated = self.mod.admin_create_promo(
            harness.FakeRequest(), bonus_days=5, max_uses=3, expires_at="", expires_in_days=10, code="",
            plan_keys="prepaid,one_year", stack_referral="true", note="", x_admin_token=ADMIN)
        self.assertEqual(len(generated["code"]), 10)
        with self.assertRaises(harness.HTTPException) as dup:
            self.promo(generated["code"])
        self.assertEqual(dup.exception.status_code, 409)

    # ---- 6 -----------------------------------------------------------------
    def test_mint_assigns_serials_and_channel_and_retail_codes_never_expire(self):
        batch = self.mint(batch_id="amz-1m-001", count=3, channel="amazon")
        self.assertEqual(batch["channel"], "amazon")
        self.assertEqual([c["serial"] for c in batch["codes"]],
                         ["AMZ-1M-001-00001", "AMZ-1M-001-00002", "AMZ-1M-001-00003"])
        listed = {b["batch_id"]: b for b in self.mod.admin_list_redemption_batches(
            harness.FakeRequest(), x_admin_token=ADMIN)["batches"]}
        self.assertEqual(listed["amz-1m-001"]["channel"], "amazon")
        for channel, days, status in (("printer", 30, 400), ("pigeon", 0, 400)):
            with self.assertRaises(harness.HTTPException) as caught:
                self.mint(batch_id=f"bad-{channel}", channel=channel, expires_in_days=days)
            self.assertEqual(caught.exception.status_code, status)
        self.assertEqual(self.mint(batch_id="gift-ok", channel="giveaway", expires_in_days=30)["channel"], "giveaway")
        # The hub's one-time mint response is exactly what the export tool takes.
        spec = importlib.util.spec_from_file_location(
            "redemption_export", Path(__file__).resolve().parents[1] / "tools" / "redemption_export.py")
        exporter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(exporter)
        printed = self.mint(batch_id="print-1y-001", count=5, duration="1y", channel="printer", canaries=2)
        batch_id, channel, duration, rows, serials, pulls = exporter.build_rows(
            printed, exporter.DEFAULT_REDEEM_URL, False)
        self.assertEqual((batch_id, channel, duration, len(rows), pulls), ("print-1y-001", "printer", "1y", 3, []))
        *_unused, pulls = exporter.build_rows(printed, exporter.DEFAULT_REDEEM_URL, True)
        self.assertEqual(len(pulls), 2)

    # ---- 7 -----------------------------------------------------------------
    def test_revoke_code_unused_then_refund_withdraws_exact_span(self):
        self.seed(REFERRER, expiry_delta_days=10)
        ref = self.one("SELECT referral_code FROM users WHERE account_number=?", (REFERRER,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (ref, REFERRER))
        referrer_before = self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"]
        batch = self.mint(batch_id="ref-1", count=2, channel="printer")
        lost, sold = batch["codes"]
        revoked = self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=lost["serial"], reason="lost", reference="case-1", x_admin_token=ADMIN)
        self.assertEqual(revoked["result"], "revoked_unused")
        self.assertFalse(self.redeem(lost["code"])["ok"])
        body = self.redeem(sold["code"], referral_code=ref)
        self.assertTrue(body["ok"], body)
        account = body["account_number"]
        refund = self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=sold["serial"], reason="amazon refund", reference="order-1",
            x_admin_token=ADMIN)
        self.assertEqual(refund["result"], "withdrawn")
        user = self.one("SELECT * FROM users WHERE account_number=?", (account,))
        self.assertEqual(user["status"], "expired")
        self.assertLessEqual(self.mod.parse_iso_datetime(user["expiration_date"]), self.mod.utcnow())
        self.assertEqual(self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"],
                         referrer_before, "the referrer's bonus from this card is clawed back")
        self.assertEqual(self.code_status(sold["code"])["status"], "refunded")
        again = self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=sold["serial"], reason="", reference="", x_admin_token=ADMIN)
        self.assertEqual(again["result"], "already_refunded")

    def test_refund_of_an_extension_keeps_the_rest_of_the_term(self):
        self.seed(TARGET, expiry_delta_days=60)
        original = self.mod.parse_iso_datetime(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (TARGET,))["expiration_date"])
        self.promo("EXTRA3", bonus_days=3)
        sold = self.mint(batch_id="ext-1", count=1)["codes"][0]
        body = self.redeem(sold["code"], account_number=TARGET, promo_code="EXTRA3")
        self.assertTrue(body["ok"], body)
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=sold["serial"], reason="chargeback", reference="cb-1", x_admin_token=ADMIN)
        after = self.mod.parse_iso_datetime(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (TARGET,))["expiration_date"])
        self.assertEqual(after, original)
        self.assertTrue(self.one("SELECT reversed_at FROM promo_redemptions WHERE account_number=?", (TARGET,))["reversed_at"])
        self.assertEqual(self.one("SELECT status FROM users WHERE account_number=?", (TARGET,))["status"], "active")

    # ---- 8 -----------------------------------------------------------------
    def test_ack_crosses_the_barrier_on_every_call(self):
        calls = []
        self.mod.run_durability_barrier = lambda *a, **k: calls.append(1) or {"skipped": True}
        code = self.mint()["codes"][0]["code"]
        self.assertTrue(self.redeem(code)["ok"])
        calls.clear()
        for _ in range(2):
            self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))
        self.assertEqual(len(calls), 2, "a retried ack must still confirm replication")

    def test_ack_spends_the_barrier_only_for_a_code_that_could_have_a_fulfillment(self):
        # R22 Y1 F1: ack never consumes the failure budget, so a barrier (a
        # litestream sync subprocess) run for every garbage code is free
        # amplification for any caller. Garbage, empty, unused, revoked and
        # tripped-canary codes never had a fulfillment and skip it.
        calls = []

        def barrier(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise self.mod.DurabilityBarrierError("timeout", "first ack is not replicated")
            return {"skipped": True}

        minted = self.mint(count=5, canaries=1)["codes"]
        canary = next(c for c in minted if c["canary"])
        unused, revoked, refunded, redeemed = [c for c in minted if not c["canary"]]
        self.assertEqual(self.redeem(canary["code"])["ok"], False)
        self.assertEqual(self.code_status(canary["code"])["status"], "canary_tripped")
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=revoked["serial"], reason="lost", reference="", x_admin_token=ADMIN)
        self.assertTrue(self.redeem(refunded["code"])["ok"])
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=refunded["serial"], reason="refund", reference="r-1", x_admin_token=ADMIN)
        self.assertEqual(self.code_status(refunded["code"])["status"], "refunded")
        self.assertTrue(self.redeem(redeemed["code"])["ok"])
        self.mod.run_durability_barrier = barrier

        def ack(code):
            return self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))

        for code in (self.mod.mint_redemption_code(), "", "0" * 27, unused["code"], revoked["code"], canary["code"]):
            self.assertEqual(ack(code), {"ok": True})
        self.assertEqual(calls, [], "an ack with nothing to replicate must not run a litestream sync")
        # The real ack still crosses the barrier, and its retry after the 503
        # finds the row already deleted yet crosses it again.
        with self.assertRaises(self.mod.HTTPException) as failed:
            ack(redeemed["code"])
        self.assertEqual(failed.exception.status_code, 503)
        self.assertEqual(ack(redeemed["code"]), {"ok": True})
        self.assertEqual(len(calls), 2)
        # A refunded card once had a fulfillment, so its ack is still confirmed.
        self.assertEqual(ack(refunded["code"]), {"ok": True})
        self.assertEqual(len(calls), 3)

    def test_ack_before_email_drain_keeps_the_saved_setup_key_valid(self):
        # The saved key must never be rotated by the welcome mail. The ack no
        # longer cancels that mail (K3-04): it is the only way keys 2 and up
        # reach the buyer, and it carries the original, unchanged first key.
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="buyer@example.test")
        self.assertTrue(body["ok"], body)
        with self.mod.get_db() as conn:
            claimed = self.mod.claim_redemption_outbox_batch(
                conn, 1, (self.mod.utcnow() + timedelta(minutes=2)).isoformat(),
            )
        self.assertEqual(len(claimed), 1)
        self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod._redemption_outbox_setup_key(conn, claimed[0])[0], body["setup_key"])
        self.execute("UPDATE redemption_outbox SET lease_until=NULL")
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        self.mod.drain_redemption_outbox()
        self.assertEqual(len(sent), 1)
        self.assertEqual(list(sent[0][4])[0], body["setup_key"], "the mail repeats the saved key, never a new one")
        self.assertEqual(len(sent[0][4]), self.mod.DEVICE_LIMIT)
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(
                conn, body["account_number"], body["setup_key"], consume=False,
            ), "draining an acknowledged outbox must not rotate the saved key")
        self.assertEqual(self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (body["account_number"],))["status"], "completed")

    def test_ack_before_email_drain_cancels_the_mail_of_a_single_key_hub(self):
        # With one key per account the API already showed everything the mail
        # would carry, so the acknowledgement still cancels it (S-HUB-01).
        self.mod = self.load(DEVICE_LIMIT=1)
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="buyer@example.test")
        self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [], "the acknowledged key needs no backup email")
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(
                conn, body["account_number"], body["setup_key"], consume=False,
            ))
        row = self.one("SELECT status, sealed_secret FROM redemption_outbox WHERE account_number=?", (body["account_number"],))
        self.assertEqual((row["status"], row["sealed_secret"]), ("cancelled", None))

    def test_drain_cancels_mail_acknowledged_before_the_fix_without_rotating(self):
        # A restored database can carry a pre-S-HUB-01 row: the acknowledgement
        # deleted the sealed key and recorded its event, but the mail stayed
        # pending. Even if the runbook's reconciliation never ran, the drain
        # must cancel that mail and leave the saved key valid, while mail that
        # was never acknowledged still gets a rotated key once its seal is gone.
        codes = self.mint(count=2)["codes"]
        saved = self.redeem(codes[0]["code"], email="restored@example.test")
        waiting = self.redeem(codes[1]["code"], email="waiting@example.test")
        self.mod.acknowledge_redemption(
            harness.FakeRequest(), self.mod.RedemptionRequest(code=codes[0]["code"]),
        )
        self.execute(
            "UPDATE redemption_outbox SET status='pending', completed_at=NULL "
            "WHERE account_number=?", (saved["account_number"],),
        )
        # Both rows predate sealed mail custody, as a pre-S-HUB-01 row does.
        self.execute("UPDATE redemption_outbox SET sealed_secret=NULL")
        self.execute(
            "UPDATE redemption_fulfillments SET expires_at=? WHERE account_number=?",
            ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(), waiting["account_number"]),
        )
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "smtp-user", "smtp-pass"
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        self.mod.drain_redemption_outbox()
        self.assertEqual([args[0] for args in sent], ["waiting@example.test"])
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(
                conn, saved["account_number"], saved["setup_key"], consume=False,
            ), "the drain must not rotate a key acknowledged before the fix")
            self.assertFalse(self.mod.verify_and_consume_activation_secret(
                conn, waiting["account_number"], waiting["setup_key"], consume=False,
            ), "unacknowledged mail past its seal still gets a fresh key")
            self.assertEqual(len(sent[0][4]), self.mod.DEVICE_LIMIT)
            for rotated_key in sent[0][4]:
                self.assertTrue(self.mod.verify_and_consume_activation_secret(
                    conn, waiting["account_number"], rotated_key, consume=False,
                ))
        row = self.one(
            "SELECT status, completed_at FROM redemption_outbox WHERE account_number=?",
            (saved["account_number"],),
        )
        acknowledged = self.one(
            "SELECT MAX(occurred_at) AS at FROM redemption_events "
            "WHERE outcome='fulfillment_acknowledged'",
        )
        self.assertEqual((row["status"], row["completed_at"]), ("cancelled", acknowledged["at"]))

    def test_late_mail_for_a_used_setup_key_is_cancelled_not_rotated(self):
        # R22 F2b (arbiter): past the seal, the buyer already activated with
        # the key shown at redemption. Rotating would mail a live key and
        # re-open activation, so that mail is cancelled. The rule is for rows
        # written before mail custody was sealed on the row; a row with its own
        # sealed copy has nothing to rotate and keeps its unseen keys (below).
        codes = self.mint(count=2)["codes"]
        late = self.redeem(codes[0]["code"], email="late@example.test")
        sealed = self.redeem(codes[1]["code"], email="sealed@example.test")
        with self.mod.get_db() as conn:
            for body in (late, sealed):
                self.assertTrue(self.mod.verify_and_consume_activation_secret(
                    conn, body["account_number"], body["setup_key"],
                ))
            conn.commit()
        self.expire_seal(late["account_number"])
        credentials = "SELECT activation_secret_hash, activation_secret_used_at FROM users WHERE account_number=?"
        before = tuple(self.one(credentials, (late["account_number"],)))
        self.assertIsNotNone(before[1])
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        self.mod.drain_redemption_outbox()
        # Key 1 was spent, so only the two keys the API never showed are mailed.
        self.assertEqual(
            [(args[0], len(args[4]), sealed["setup_key"] in args[4]) for args in sent],
            [("sealed@example.test", self.mod.DEVICE_LIMIT - 1, False)],
            "the sealed copy carries the whole key set; the spent first key is not mailed again",
        )
        self.assertEqual(tuple(self.one(credentials, (late["account_number"],))), before,
                         "a used setup key must not be rotated or re-opened by a late mail")
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (late["account_number"],))["status"],
            "cancelled",
        )
        # Idempotent: another drain over the same state sends and changes nothing.
        self.mod.drain_redemption_outbox()
        self.assertEqual(len(sent), 1)
        self.assertEqual(tuple(self.one(credentials, (late["account_number"],))), before)

    def expire_seal(self, account_number):
        # The API record's seal runs out on a row written before mail custody
        # was sealed on the outbox row itself (redemption_outbox.sealed_secret,
        # K3-04), so only the old rotation fallback is left to deliver the mail.
        self.execute(
            "UPDATE redemption_fulfillments SET expires_at=? WHERE account_number=?",
            ((self.mod.utcnow() - timedelta(minutes=1)).isoformat(), account_number),
        )
        self.execute("UPDATE redemption_outbox SET sealed_secret=NULL WHERE account_number=?", (account_number,))

    def test_late_mail_that_cannot_be_sent_keeps_the_buyers_key(self):
        # R23 A-1: past the seal the drain rotated first and only then learned
        # that send_account_email refuses without trying (no SMTP credentials,
        # a supported hub state, or an unusable optional address). The key the
        # buyer was shown, valid for 30 minutes, died and nothing was mailed;
        # every retry rotated again.
        codes = self.mint(count=2)["codes"]
        typo = self.redeem(codes[0]["code"], email="buyer@typo")
        valid = self.redeem(codes[1]["code"], email="buyer@example.test")
        for body in (typo, valid):
            self.assertTrue(body["ok"], body)
            self.expire_seal(body["account_number"])
        credentials = "SELECT activation_secret_hash FROM users WHERE account_number=?"
        before = {b["account_number"]: self.one(credentials, (b["account_number"],))[0] for b in (typo, valid)}

        def assert_key_kept(body):
            with self.mod.get_db() as conn:
                self.assertTrue(self.mod.verify_and_consume_activation_secret(
                    conn, body["account_number"], body["setup_key"], consume=False,
                ), "an undeliverable late mail must not rotate the key the buyer holds")
            self.assertEqual(self.one(credentials, (body["account_number"],))[0], before[body["account_number"]])
            row = self.one("SELECT status, last_error FROM redemption_outbox WHERE account_number=?", (body["account_number"],))
            self.assertEqual(row["status"], "pending")
            self.assertIn("cannot be sent", row["last_error"])

        # No SMTP credentials: neither row may rotate. The real sender refuses
        # before any network use; it must not even be reached.
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "", ""
        real_send = self.mod.send_account_email
        attempted = []
        self.mod.send_account_email = lambda *args: attempted.append(args) or real_send(*args)
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual((summary["delivered"], summary["failed"]), (0, 2), summary)
        assert_key_kept(typo)
        assert_key_kept(valid)
        self.assertEqual(attempted, [])
        # SMTP configured: the unusable address still keeps its key, while the
        # valid address gets its rotated key.
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "smtp-user", "smtp-pass"
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual((summary["delivered"], summary["failed"]), (1, 1), summary)
        self.assertEqual([args[0] for args in sent], ["buyer@example.test"])
        assert_key_kept(typo)
        with self.mod.get_db() as conn:
            self.assertEqual(len(sent[0][4]), self.mod.DEVICE_LIMIT)
            for rotated_key in sent[0][4]:
                self.assertTrue(self.mod.verify_and_consume_activation_secret(
                    conn, valid["account_number"], rotated_key, consume=False,
                ))
            self.assertFalse(self.mod.verify_and_consume_activation_secret(
                conn, valid["account_number"], valid["setup_key"], consume=False,
            ))

    def test_rotated_key_is_replicated_before_it_is_mailed(self):
        # R23 A-1: the rotation commits after the pre-send barrier, so the key
        # must cross a barrier of its own before it leaves in an email
        # (state commit -> barrier -> external side effect).
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="buyer@example.test")
        self.expire_seal(body["account_number"])
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "smtp-user", "smtp-pass"
        events = []
        real_issue = self.mod.issue_activation_secret

        def issue(conn, account_number, *args, **kwargs):
            events.append("rotate")
            return real_issue(conn, account_number, *args, **kwargs)

        def barrier(*args, **kwargs):
            events.append("barrier")
            return {"skipped": True}

        self.mod.issue_activation_secret = issue
        self.mod.run_durability_barrier = barrier
        self.mod.send_account_email = lambda *args: events.append("send") or True
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual(summary["confirmed"], 1, summary)
        self.assertEqual(events, ["barrier", "rotate", "barrier", "send", "barrier"])

    def test_a_replica_outage_after_rotation_defers_without_mail_or_spent_attempt(self):
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="buyer@example.test")
        self.expire_seal(body["account_number"])
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "smtp-user", "smtp-pass"
        calls = []

        def barrier(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise self.mod.DurabilityBarrierError("replica_unavailable", "after rotation")
            return {"skipped": True}

        sent = []
        self.mod.run_durability_barrier = barrier
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual((summary["deferred"], summary["delivered"], summary["failed"]), (1, 0, 0), summary)
        self.assertEqual(sent, [])
        row = self.one("SELECT status, attempts, lease_until, last_error FROM redemption_outbox WHERE account_number=?", (body["account_number"],))
        self.assertEqual((row["status"], row["attempts"], row["lease_until"]), ("pending", 0, None))
        self.assertTrue(row["last_error"].startswith("pre_send_barrier:"), row["last_error"])
        self.mod.drain_redemption_outbox()
        self.assertEqual(len(sent), 1)
        with self.mod.get_db() as conn:
            self.assertEqual(len(sent[0][4]), self.mod.DEVICE_LIMIT)
            for rotated_key in sent[0][4]:
                self.assertTrue(self.mod.verify_and_consume_activation_secret(
                    conn, body["account_number"], rotated_key, consume=False,
                ))

    def test_late_mail_for_a_vanished_account_is_cancelled(self):
        # A pending welcome mail whose account row is gone (account deletion
        # removes both, so only an inconsistent restore leaves this) must not
        # mail a key that no account row backs.
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="buyer@example.test")
        self.expire_seal(body["account_number"])
        self.mod.SMTP_USER, self.mod.SMTP_PASS = "smtp-user", "smtp-pass"
        with self.db() as conn, conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("DELETE FROM devices WHERE account_number=?", (body["account_number"],))
            conn.execute("DELETE FROM users WHERE account_number=?", (body["account_number"],))
        sent = []
        self.mod.send_account_email = lambda *args: sent.append(args) or True
        self.mod.drain_redemption_outbox()
        self.assertEqual(sent, [])
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (body["account_number"],))["status"],
            "cancelled",
        )

    def test_ack_during_send_is_not_reported_as_a_confirmed_delivery(self):
        # R22 Muse X5-F2: the buyer acknowledges while the welcome mail (the
        # sealed, unchanged key) is in flight. On a single-key hub the ack
        # closes the row, so the drain must not report a delivery it never
        # marked or confirmed.
        self.mod = self.load(DEVICE_LIMIT=1)
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="race@example.test")
        self.assertTrue(body["ok"], body)

        def ack_then_send(*args):
            self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))
            return True

        outbox_id = self.one(
            "SELECT id FROM redemption_outbox WHERE account_number=?", (body["account_number"],),
        )["id"]
        self.mod.send_account_email = ack_then_send
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual((summary["delivered"], summary["confirmed"], summary["failed"]), (0, 0, 0), summary)
        self.assertEqual(summary["errors"], [{"id": outbox_id, "error": "closed_during_send"}])
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (body["account_number"],))["status"],
            "cancelled",
        )
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(
                conn, body["account_number"], body["setup_key"], consume=False,
            ))

    def test_ack_during_send_of_a_multi_key_mail_still_delivers_and_confirms(self):
        # K3-04: the mail carries keys the API never showed, so the ack no
        # longer closes it and the delivery is real.
        code = self.mint()["codes"][0]["code"]
        body = self.redeem(code, email="race@example.test")

        def ack_then_send(*args):
            self.mod.acknowledge_redemption(harness.FakeRequest(), self.mod.RedemptionRequest(code=code))
            return True

        self.mod.send_account_email = ack_then_send
        summary = self.mod.drain_redemption_outbox()
        self.assertEqual((summary["delivered"], summary["confirmed"], summary["failed"]), (1, 1, 0), summary)
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (body["account_number"],))["status"],
            "completed",
        )

    def test_reconcile_old_acknowledged_mail_keeps_unacknowledged_mail(self):
        codes = self.mint(count=2)["codes"]
        acknowledged = self.redeem(codes[0]["code"], email="saved@example.test")
        waiting = self.redeem(codes[1]["code"], email="waiting@example.test")
        self.mod.acknowledge_redemption(
            harness.FakeRequest(), self.mod.RedemptionRequest(code=codes[0]["code"]),
        )
        self.execute(
            "UPDATE redemption_outbox SET status='pending', completed_at=NULL "
            "WHERE account_number=?", (acknowledged["account_number"],),
        )
        # The row is the pre-S-HUB-01 kind the reconciliation exists for: an
        # acknowledgement deleted its API record and left no sealed mail copy.
        # (A row that holds one is legitimate multi-key mail and is skipped; see
        # server/test_activation_keys3_hub.py::RestoreReconciliation.)
        self.execute("UPDATE redemption_outbox SET sealed_secret=NULL WHERE account_number=?",
                     (acknowledged["account_number"],))
        migration = (Path(__file__).parent / "db/reconcile_redemption_ack_outbox.sql").read_text()
        with self.db() as conn:
            conn.executescript(migration)
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (acknowledged["account_number"],))["status"],
            "cancelled",
        )
        self.assertEqual(
            self.one("SELECT status FROM redemption_outbox WHERE account_number=?", (waiting["account_number"],))["status"],
            "pending",
        )

    # ---- 9 -----------------------------------------------------------------
    def test_checkout_promo_is_validated_and_settlement_honours_it(self):
        mod = self.mod
        mod.BTCPAY_URL, mod.BTCPAY_STORE_ID = "https://btcpay.winsvpn.org", "store-1"
        mod.BTCPAY_API_KEY, mod.BTCPAY_WEBHOOK_SECRET, mod.BTCPAY_CHECKOUT_CHAINS = "k", "w", "BTC"
        mod.crypto_price_usd = lambda conn, plan: "9.99"
        mod.btcpay_create_invoice = lambda amount, metadata: {
            "id": "inv-r2-000001", "checkoutLink": "https://btcpay.winsvpn.org/i/inv-r2-000001"}
        self.promo("CRYPTO5", bonus_days=5, plans="one_month")
        with self.assertRaises(harness.HTTPException) as caught:
            mod._crypto_create_invoice_sync(
                mod.CryptoInvoiceRequest(plan_key="one_year", promo_code="CRYPTO5"), harness.FakeRequest())
        self.assertEqual(caught.exception.status_code, 400)
        mod._crypto_create_invoice_sync(
            mod.CryptoInvoiceRequest(plan_key="one_month", promo_code="crypto5", email="buyer@example.test"),
            harness.FakeRequest())
        order = self.one("SELECT * FROM payment_orders WHERE provider='btcpay'")
        self.assertEqual(order["promo_code"], "CRYPTO5")
        # Settlement grants through upsert_paypal_account with the stored promo.
        with mod.get_db() as conn:
            account, created, expiry, _secret = mod.upsert_paypal_account(
                conn, email="buyer@example.test", subscriber_name="B", subscription_id="", plan_id="",
                payer_id="", paypal_status="ACTIVE", next_billing_time=None, duration_text="1m",
                purchase_reference="inv-r2-000001", promo_code=order["promo_code"])
        self.assertTrue(created)
        granted = mod.parse_iso_datetime(expiry) - mod.utcnow()
        self.assertGreaterEqual(granted, timedelta(days=27 + 5) - timedelta(minutes=1))
        # A subscription never takes promo days (PayPal's billing time is authoritative).
        with mod.get_db() as conn:
            _a, _c, sub_expiry, _s = mod.upsert_paypal_account(
                conn, email="sub@example.test", subscriber_name="S", subscription_id="I-SUB", plan_id="",
                payer_id="", paypal_status="ACTIVE", next_billing_time=None, duration_text="1m",
                purchase_reference="I-SUB", promo_code="CRYPTO5")
        self.assertLess(mod.parse_iso_datetime(sub_expiry) - mod.utcnow(), timedelta(days=32))
        self.assertEqual(self.one("SELECT uses FROM promo_campaigns WHERE code='CRYPTO5'")["uses"], 1)


    # ---- Argon A3 audit (R2-AUDIT-01..08) -----------------------------------
    def _referrer(self, account=REFERRER, expiry_delta_days=10, status="active", devices=1):
        self.seed(account, expiry_delta_days=expiry_delta_days, status=status, devices=devices)
        code = self.one("SELECT referral_code FROM users WHERE account_number=?", (account,))["referral_code"].lower()
        self.execute("UPDATE users SET referral_code=? WHERE account_number=?", (code, account))
        return code

    def test_audit01_refund_after_redeemer_deleted_or_recycled_still_claws_back(self):
        ref = self._referrer()
        referrer_before = self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"]
        self.promo("STACK5", bonus_days=5, stack="true")
        deleted_card, recycled_card = self.mint(batch_id="a01", count=2, duration="1y")["codes"]
        # (a) the redeemer deletes the account before the chargeback arrives
        body = self.redeem(deleted_card["code"], referral_code=ref, promo_code="STACK5")
        self.assertGreater(body["referral_bonus_days"], 0)
        with self.mod.get_db() as conn:
            self.mod.execute_account_deletion(conn, None, body["account_number"], {
                "request_id": "req-a01", "active_device_count": 0, "required_confirmations": 0,
                "single_device_path": 1}, 0)
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=deleted_card["serial"], reason="chargeback", reference="cb-a01",
            x_admin_token=ADMIN)
        self.assertIsNotNone(self.one("SELECT clawed_back_at FROM referral_rewards")["clawed_back_at"])
        self.assertIsNotNone(self.one("SELECT reversed_at FROM promo_redemptions")["reversed_at"])
        self.assertEqual(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"],
            referrer_before)
        # (b) the redeemed account lapses and its number is recycled
        other_ref = self._referrer(account="5555-6666-7777", expiry_delta_days=10)
        body = self.redeem(recycled_card["code"], referral_code=other_ref, promo_code="STACK5")
        self.assertGreater(body["referral_bonus_days"], 0)
        self.execute("UPDATE users SET status='expired', expiration_date=? WHERE account_number=?",
                     ((self.mod.utcnow() - timedelta(days=30)).isoformat(), body["account_number"]))
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod.reclaim_expired_account_for_reuse(conn), body["account_number"])
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=recycled_card["serial"], reason="chargeback", reference="cb-a01b",
            x_admin_token=ADMIN)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM referral_rewards WHERE clawed_back_at IS NULL")["n"], 0)
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM promo_redemptions WHERE reversed_at IS NULL")["n"], 0)

    def test_audit01_referrer_clamped_to_now_is_expired_by_the_existing_sweep(self):
        ref = self._referrer(expiry_delta_days=1, devices=1)
        card = self.mint(batch_id="a01c", count=1, duration="1y")["codes"][0]
        self.assertTrue(self.redeem(card["code"], referral_code=ref)["ok"])
        self.execute("UPDATE users SET expiration_date=? WHERE account_number=?",
                     ((self.mod.utcnow() + timedelta(days=10)).isoformat(), REFERRER))
        self.mod.admin_revoke_redemption_code(
            harness.FakeRequest(), serial=card["serial"], reason="chargeback", reference="cb-a01c", x_admin_token=ADMIN)
        self.assertLessEqual(self.mod.parse_iso_datetime(
            self.one("SELECT expiration_date FROM users WHERE account_number=?", (REFERRER,))["expiration_date"]),
            self.mod.utcnow())
        # The 60-second account_expiry_revocation_sweep_loop owns this transition for
        # every clawback path; run one sweep the way the loop does.
        self.mod.sweep_expired_account_runtime()
        self.assertEqual(self.one("SELECT status FROM users WHERE account_number=?", (REFERRER,))["status"], "expired")
        self.assertEqual(self.one("SELECT COUNT(*) AS n FROM devices WHERE account_number=?", (REFERRER,))["n"], 0)

    def test_audit02_invalid_codes_are_refused_before_any_account_check(self):
        own = self._referrer(account=TARGET, expiry_delta_days=30)
        self.seed("3333-4444-5555", expiry_delta_days=-5, status="expired", devices=0)
        code = self.mint(batch_id="a02", count=1)["codes"][0]["code"]
        for account in ("9876-5432-1098", "3333-4444-5555", TARGET):
            self.assertEqual(self.redeem(code, account_number=account, promo_code="BOGUS999")["status"], "promo_invalid")
            self.assertEqual(self.redeem(code, account_number=account, referral_code="nosuchcode1")["status"],
                             "referral_invalid")
        self.assertEqual(self.redeem(code, account_number=TARGET, referral_code=own, promo_code="BOGUS999")["status"],
                         "promo_invalid")
        self.assertEqual(self.code_status(code)["status"], "unused")

    def test_audit03_expired_but_unflipped_referrer_is_refused(self):
        stale = self._referrer(account="7777-8888-9999", expiry_delta_days=-20, status="active", devices=0)
        recent = self._referrer(account="6666-7777-8888", expiry_delta_days=-1, status="active", devices=0)
        code = self.mint(batch_id="a03", count=1)["codes"][0]["code"]
        for ref, account in ((stale, "7777-8888-9999"), (recent, "6666-7777-8888")):
            before = self.one("SELECT * FROM users WHERE account_number=?", (account,))
            self.assertEqual(self.redeem(code, referral_code=ref)["status"], "referral_invalid")
            after = self.one("SELECT * FROM users WHERE account_number=?", (account,))
            self.assertEqual(after["expiration_date"], before["expiration_date"])
        self.assertEqual(self.code_status(code)["status"], "unused")

    def test_audit04_extension_recovery_needs_the_same_account(self):
        self.seed(TARGET, expiry_delta_days=30)
        code = self.mint(batch_id="a04", count=1)["codes"][0]["code"]
        self.assertTrue(self.redeem(code, account_number=TARGET)["ok"])
        for probe in (self.redeem(code), self.redeem(code, account_number="9876-5432-1098")):
            self.assertEqual((probe["ok"], probe["status"]), (False, "not_redeemable"))
            self.assertNotIn("account_number", probe)
            self.assertNotIn("expiration_date", probe)
        self.assertTrue(self.redeem(code, account_number=TARGET)["recovered"])

    def test_audit06_already_referred_account_refuses_a_second_referral(self):
        ref = self._referrer()
        first, second = [c["code"] for c in self.mint(batch_id="a06", count=2)["codes"]]
        body = self.redeem(first, referral_code=ref)
        self.assertGreater(body["referral_bonus_days"], 0)
        refused = self.redeem(second, account_number=body["account_number"], referral_code=ref)
        self.assertEqual((refused["ok"], refused["status"]), (False, "referral_used"))
        self.assertEqual(self.code_status(second)["status"], "unused")
        self.assertTrue(self.redeem(second, account_number=body["account_number"])["ok"])

    def test_audit08_archive_keeps_the_promo_code(self):
        self.promo("ARCH5", bonus_days=5)
        old = (self.mod.utcnow() - timedelta(days=self.mod.PAYMENT_ORDER_RETENTION_DAYS + 1)).isoformat()
        with self.mod.get_db() as conn:
            conn.execute(
                "INSERT INTO payment_orders (hub_order_id, provider, plan_key, expected_amount, expected_currency, "
                "buyer_email, referral_code, status, created_at, promo_code) "
                "VALUES ('o-a08', 'btcpay', 'one_month', '1.00', 'USD', '', '', 'settled', ?, 'ARCH5')", (old,))
            self.mod.archive_terminal_payment_orders(conn)
        self.assertEqual(self.one("SELECT promo_code FROM payment_order_archive WHERE hub_order_id='o-a08'")["promo_code"],
                         "ARCH5")


if __name__ == "__main__":
    unittest.main()
