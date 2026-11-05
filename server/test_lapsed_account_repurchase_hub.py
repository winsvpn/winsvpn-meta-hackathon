#!/usr/bin/env python3
"""A purchase that reopens a lapsed account must hand the buyer setup keys.

Expiry deletes every device (revoke_account_runtime) and each stored setup key
is single-use. Before the fix upsert_paypal_account returned no secret for an
existing row, every provider path enqueued delivery only when `created`, and
the reopened account had no way to enrol a device. It now returns the whole key
set (DEVICE_LIMIT keys, a list) and replaces whatever keys the account held.
A renewal of a still-active account keeps its key untouched (pinned by
tools/test_paypal_entitlement_contract.py). Run:
python3 server/test_lapsed_account_repurchase_hub.py
"""
import _toolchain  # noqa: F401
import logging
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class LapsedAccountRepurchaseTests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = harness.load_hub(
                DURABILITY_BARRIER_ENABLED=0, DURABILITY_BARRIER_REQUIRED=0,
                WINN3_INNER_POOL_CIDR="10.10.0.0/24", WINN3_CANARY_NODE_SLUG="",
            )
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.email = f"user-{harness.ACCOUNT}@example.test"

    def purchase(self):
        with self.mod.get_db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            return self.mod.upsert_paypal_account(
                conn, email=self.email, subscriber_name="Buyer", subscription_id="",
                plan_id="lifetime_support", payer_id="", paypal_status="ACTIVE",
                next_billing_time=None, duration_text="10y",
                purchase_reference="CAPTURE-1", paypal_purchase_reference="CAPTURE-1",
            )

    def test_reopening_a_lapsed_account_issues_a_fresh_setup_key_set(self):
        harness.seed_account(self.mod, devices=2, expiration="2026-01-01T00:00:00")
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.expire_account_runtime_if_due(conn, harness.ACCOUNT))
            conn.execute(
                "UPDATE users SET activation_secret_used_at='2025-12-01T00:00:00' WHERE account_number=?",
                (harness.ACCOUNT,),
            )
        account, created, _expiry, secrets = self.purchase()
        self.assertEqual(account, harness.ACCOUNT)
        self.assertFalse(created)
        self.assertEqual(len(secrets), self.mod.DEVICE_LIMIT)
        with self.mod.get_db() as conn:
            row = conn.execute(
                "SELECT status, activation_secret_hash, activation_secret_used_at FROM users WHERE account_number=?",
                (harness.ACCOUNT,),
            ).fetchone()
            extras = self.mod.fetch_activation_extra_keys(conn, harness.ACCOUNT)
        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["activation_secret_used_at"])
        self.assertTrue(self.mod.activation_secret_matches(row["activation_secret_hash"], secrets[0]))
        self.assertEqual(len(extras), len(secrets) - 1)
        for extra, secret in zip(extras, secrets[1:]):
            self.assertTrue(self.mod.activation_secret_matches(extra["secret_hash"], secret))

    def test_renewal_of_an_active_account_keeps_its_key(self):
        harness.seed_account(self.mod, devices=2, expiration="2030-01-01T00:00:00")
        with self.mod.get_db() as conn:
            original = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
        _account, created, _expiry, secrets = self.purchase()
        self.assertFalse(created)
        self.assertEqual(secrets, [])
        with self.mod.get_db() as conn:
            row = conn.execute(
                "SELECT activation_secret_hash FROM users WHERE account_number=?", (harness.ACCOUNT,),
            ).fetchone()
        self.assertTrue(self.mod.activation_secret_matches(row["activation_secret_hash"], original))


if __name__ == "__main__":
    unittest.main()
