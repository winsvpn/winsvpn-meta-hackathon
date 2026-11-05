#!/usr/bin/env python3
"""Regressions for the verified true positives of the Gemini L02 hub audit.

1. /account/status: a failing bearer must still consume the rate-limit
   buckets (the 401 used to roll the increments back).
2. Hoppy credentials resend: with no SMTP credentials the drain must not
   rotate (and so invalidate) the setup key on file.
3. PayPal sync stop paths claw back the referrer's bonus like the stop
   webhook does.
4. /admin/paypal/retry rolls the failed resync back before recording failure.
5. A second secret-bearing PayPal sync for one subscription gets its own
   activation delivery (the fixed outbox id used to raise IntegrityError).

Run: python3 server/test_hub_gemini_l02_fixes.py
"""
import _toolchain  # noqa: F401
from contextlib import closing
import logging
import shutil
import sqlite3
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness

REFERRER = "9999-8888-7777"
SUBSCRIPTION = "I-GEMINIL02SUB"


class GeminiL02Fixes(unittest.TestCase):
    def load(self, **env):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            mod = harness.load_hub(**env)
        mod.logger.propagate = False
        mod.logger.addHandler(logging.NullHandler())
        mod.security_alert = lambda *args, **kwargs: None
        self.addCleanup(shutil.rmtree, mod._TMPDIR, True)
        return mod

    # ---- 1 ---------------------------------------------------------------
    def test_account_status_bad_bearer_attempts_reach_the_limit(self):
        mod = self.load(VERIFY_IP_RATE_LIMIT_PER_MINUTE=3,
                        VERIFY_ACCOUNT_RATE_LIMIT_PER_HOUR=1000)
        device = next(iter(harness.seed_account(mod, devices=1)))
        statuses = []
        for _ in range(6):
            request = harness.FakeRequest(
                path="/account/status",
                headers={"authorization": "Bearer not-the-token"},
            )
            with self.assertRaises(Exception) as caught:
                mod._account_status_sync(
                    mod.AccountStatusRequest(account_number=harness.ACCOUNT, device_id=device),
                    request, harness.BackgroundTasks(),
                )
            statuses.append(getattr(caught.exception, "status_code", None))
        self.assertEqual(statuses[:3], [401, 401, 401])
        self.assertEqual(statuses[3:], [429, 429, 429])

    # ---- 2 ---------------------------------------------------------------
    def test_resend_without_smtp_keeps_the_setup_key_on_file(self):
        mod = self.load(HOPPY_AGENT_HMAC="16-byte-test-hoppy-hmac-secret",
                        DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0)
        self.assertFalse(mod.SMTP_PASS)
        harness.seed_account(mod, devices=1)
        with mod.get_db() as conn:
            original = mod.issue_activation_secret(conn, harness.ACCOUNT)
        token, _expiry = mod.mint_hoppy_agent_token(harness.ACCOUNT, "credentials-resend")
        request = harness.FakeRequest(headers={"x-hoppy-agent-token": token})
        mod.hoppy_agent_credentials_resend(
            request, mod.HoppyAccountRequest(account_number=harness.ACCOUNT, request_id="r1"))
        summary = mod.drain_hoppy_agent_mail_outbox()
        self.assertEqual((summary["claimed"], summary["failed"]), (1, 1))
        with mod.get_db() as conn:
            row = conn.execute(
                "SELECT activation_secret_hash FROM users WHERE account_number=?",
                (harness.ACCOUNT,),
            ).fetchone()
        self.assertTrue(mod.activation_secret_matches(row["activation_secret_hash"], original))

    # ---- 3 and 4 ---------------------------------------------------------
    def paypal_hub(self):
        mod = self.load(DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0)
        harness.seed_account(mod, devices=1)
        harness.seed_account(mod, account=REFERRER, devices=0)
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.execute(
                "UPDATE users SET paypal_subscription_id=?, paypal_status='ACTIVE' WHERE account_number=?",
                (SUBSCRIPTION, harness.ACCOUNT),
            )
            conn.execute(
                "UPDATE users SET referral_bonus_days=30, expiration_date='2030-01-31T00:00:00' "
                "WHERE account_number=?",
                (REFERRER,),
            )
            conn.execute(
                "INSERT INTO referral_rewards (referral_code, referrer_account_number, "
                "referred_account_number, purchase_reference, base_days, bonus_days) "
                "VALUES ('CODE', ?, ?, 'ref-1', 30, 30)",
                (REFERRER, harness.ACCOUNT),
            )
        mod.paypal_enabled = lambda: True
        mod.fetch_paypal_subscription = lambda sid: {"id": sid, "status": "CANCELLED"}
        return mod

    def clawed_back(self, mod):
        with closing(sqlite3.connect(mod._DB)) as conn:
            return conn.execute(
                "SELECT clawed_back_at FROM referral_rewards WHERE referred_account_number=?",
                (harness.ACCOUNT,),
            ).fetchone()[0]

    def test_sync_one_cancel_claws_back_the_referral_bonus(self):
        mod = self.paypal_hub()
        with mod.get_db() as conn:
            result = mod.sync_one_paypal_subscription(conn, SUBSCRIPTION)
        self.assertEqual(result["revoked"], 1)
        self.assertTrue(self.clawed_back(mod))

    def test_scheduled_sync_cancel_claws_back_the_referral_bonus(self):
        mod = self.paypal_hub()
        result = mod.sync_due_paypal_subscriptions()
        self.assertEqual((result["checked"], result["updated"]), (1, 1), result)
        self.assertTrue(self.clawed_back(mod))

    def test_admin_retry_failure_discards_the_partial_resync(self):
        mod = self.paypal_hub()
        with closing(sqlite3.connect(mod._DB)) as conn, conn:
            conn.execute(
                "INSERT INTO paypal_events (event_id, event_type, paypal_subscription_id, status, attempts) "
                "VALUES ('WH-1', 'BILLING.SUBSCRIPTION.UPDATED', ?, 'failed', 1)",
                (SUBSCRIPTION,),
            )

        def half_applied(conn, subscription_id, background_tasks=None):
            # The real sync commits the caller's processing marker, then
            # writes inside its own BEGIN IMMEDIATE.
            conn.commit()
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE users SET status='expired' WHERE paypal_subscription_id=?",
                (subscription_id,),
            )
            raise RuntimeError("boom after the first write")

        mod.sync_one_paypal_subscription = half_applied
        with self.assertRaises(Exception) as caught:
            mod.admin_paypal_retry(
                harness.FakeRequest(), harness.BackgroundTasks(),
                event_id="WH-1", x_admin_token="test-admin-token",
            )
        self.assertEqual(getattr(caught.exception, "status_code", None), 502)
        with closing(sqlite3.connect(mod._DB)) as conn:
            status = conn.execute(
                "SELECT status FROM users WHERE account_number=?", (harness.ACCOUNT,)
            ).fetchone()[0]
            event = conn.execute(
                "SELECT status FROM paypal_events WHERE event_id='WH-1'"
            ).fetchone()[0]
        self.assertEqual(status, "active")
        self.assertEqual(event, "failed")

    # ---- 5 ---------------------------------------------------------------
    def test_second_secret_bearing_sync_gets_its_own_delivery(self):
        mod = self.paypal_hub()
        mod.PAYPAL_PLAN_1M = "P-GEMINIL02"
        mod.fetch_paypal_subscription = lambda sid: {
            "id": sid, "status": "ACTIVE", "plan_id": "P-GEMINIL02"}
        mod.upsert_paypal_account = lambda conn, **kwargs: (
            harness.ACCOUNT, False, "2030-01-31T00:00:00", "fresh-setup-key")
        for _ in range(2):
            with mod.get_db() as conn:
                mod.sync_one_paypal_subscription(conn, SUBSCRIPTION)
        with closing(sqlite3.connect(mod._DB)) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM activation_delivery_outbox WHERE account_number=?",
                (harness.ACCOUNT,),
            ).fetchone()[0]
        self.assertEqual(count, 2)


if __name__ == "__main__":
    unittest.main()
