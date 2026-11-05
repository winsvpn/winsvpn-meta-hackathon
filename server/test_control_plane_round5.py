#!/usr/bin/env python3
"""Round 5 payment delivery and scheduling regressions on real isolated SQLite.

The installer is extracted by the existing hub harness. Provider calls and
SMTP are test doubles; no external messages or payments are made.
"""
from contextlib import closing
import _toolchain  # noqa: F401
import asyncio
import contextlib
import json
import logging
import shutil
import sqlite3
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving


class WebhookRequest(harness.FakeRequest):
    async def body(self):
        return json.dumps(self._body).encode()


class Round5Tests(unittest.TestCase):
    def setUp(self):
        def discard_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()
        with patch("logging.basicConfig", side_effect=discard_handlers):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.mod.sync_peer_to_node = lambda *args, **kwargs: True
        self.mod.paypal_enabled = lambda: True
        self.mod.PAYPAL_WEBHOOK_ID = "test-webhook"
        self.mod.PAYPAL_PLAN_1M = "test-plan"
        self.mod.verify_paypal_webhook_signature = lambda *args: True
        self.mod.fetch_paypal_subscription = self.subscription
        self.mod.send_account_email = lambda *args: True

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def subscription(self, sub_id):
        return {
            "id": sub_id, "plan_id": "test-plan", "status": "ACTIVE",
            "subscriber": {"email_address": "buyer@example.test",
                           "name": {"given_name": "Test", "surname": "Buyer"}},
            "billing_info": {"next_billing_time": (self.mod.utcnow() + timedelta(days=30)).isoformat()},
        }

    def paypal(self, event="evt-subscription"):
        tasks = harness.BackgroundTasks()
        request = WebhookRequest(path="/webhook/paypal", body={
            "id": event, "event_type": "BILLING.SUBSCRIPTION.ACTIVATED",
            "resource": {"id": "I-TEST"},
        })
        return self.mod.paypal_webhook(request, tasks), tasks

    def deliveries(self):
        with self.mod.get_db() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM activation_delivery_outbox")]

    def seed_delivery(self):
        harness.seed_account(self.mod, devices=0)
        with self.mod.get_db() as conn:
            secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
            self.mod.enqueue_activation_delivery(
                conn, "test-delivery", f"user-{harness.ACCOUNT}@example.test", "Test",
                harness.ACCOUNT, "Monthly", secret,
            )
        return secret

    def make_due(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE activation_delivery_outbox SET next_attempt_at=?",
                         ((self.mod.utcnow() - timedelta(seconds=1)).isoformat(),))

    def test_sealed_secret_authenticates_ciphertext_and_identity(self):
        secret = self.seed_delivery()
        item = self.deliveries()[0]
        sealed = item["sealed_secret"]
        self.assertNotIn(secret, sealed)
        self.assertEqual(self.mod.open_activation_delivery(sealed, "test-delivery", harness.ACCOUNT), secret)
        self.assertNotEqual(sealed, self.mod.seal_activation_delivery(secret, "test-delivery", harness.ACCOUNT))
        for candidate, delivery_id, account in (
            (sealed, "other-delivery", harness.ACCOUNT),
            (sealed, "test-delivery", "other-account"),
            (sealed[:-3] + "AAAA", "test-delivery", harness.ACCOUNT),
            ("wao1|AA==|AA==|AA==", "test-delivery", harness.ACCOUNT),
        ):
            with self.subTest(delivery_id=delivery_id, account=account):
                with self.assertRaises(ValueError):
                    self.mod.open_activation_delivery(candidate, delivery_id, account)

    def test_smtp_failure_retries_same_key_and_scrubs_after_success(self):
        secret = self.seed_delivery()
        for failure in (False, RuntimeError("do-not-store-this-secret")):
            self.make_due()
            with patch.object(self.mod, "send_account_email") as send:
                if isinstance(failure, Exception):
                    send.side_effect = failure
                else:
                    send.return_value = failure
                self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 0)
            item = self.deliveries()[0]
            self.assertEqual(item["status"], "failed")
            self.assertGreater(self.mod.parse_iso_datetime(item["next_attempt_at"]), self.mod.utcnow())
            self.assertNotIn("do-not-store", item["last_error"])
            self.assertEqual(self.mod.claim_activation_delivery_batch(), [])
        self.make_due()
        with patch.object(self.mod, "send_account_email", return_value=True) as send:
            self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 1)
            self.assertEqual(send.call_args.args[-1], [secret])
        item = self.deliveries()[0]
        self.assertEqual((item["status"], item["sealed_secret"], item["attempts"]), ("sent", "", 3))

    def test_restart_expired_lease_reclaims_and_fences_stale_completion(self):
        self.seed_delivery()
        stale = self.mod.claim_activation_delivery_batch()[0]
        self.assertEqual(self.mod.claim_activation_delivery_batch(), [])
        with self.mod.get_db() as conn:
            conn.execute("UPDATE activation_delivery_outbox SET lease_until=?",
                         ((self.mod.utcnow() - timedelta(seconds=1)).isoformat(),))
        current = self.mod.claim_activation_delivery_batch()[0]
        self.assertNotEqual(stale["lease_token"], current["lease_token"])
        self.mod.finish_activation_delivery(stale, True)
        self.assertEqual(self.deliveries()[0]["status"], "sending")
        self.assertIsNone(self.mod._prepare_activation_delivery(stale))
        self.mod.finish_activation_delivery(current, True)
        self.assertEqual(self.deliveries()[0]["status"], "sent")

    def test_concurrent_workers_claim_exactly_once(self):
        self.seed_delivery()
        barrier = threading.Barrier(4)
        def claim(_):
            barrier.wait(timeout=5)
            return self.mod.claim_activation_delivery_batch()
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(len(rows) for rows in pool.map(claim, range(4))), 1)

    def test_smtp_runs_after_connection_close_and_a_valid_expiry_is_left_alone(self):
        secret = self.seed_delivery()
        soon = (self.mod.utcnow() + timedelta(minutes=10)).isoformat()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_expires_at=? WHERE account_number=?",
                         (soon, harness.ACCOUNT))
        def send(*args):
            with closing(sqlite3.connect(self.mod._DB, timeout=0.1)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            self.assertEqual(args[-1], [secret])
            return True
        self.mod.send_account_email = send
        self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 1)
        with self.mod.get_db() as conn:
            # Delivery never rewrites an expiry (K3-01): a legacy key keeps its own.
            self.assertEqual(conn.execute(
                "SELECT activation_secret_expires_at FROM users WHERE account_number=?", (harness.ACCOUNT,)
            ).fetchone()[0], soon)
            self.assertTrue(self.mod.verify_and_consume_activation_secret(conn, harness.ACCOUNT, secret))

    def test_a_lapsed_expiry_cancels_the_delivery_instead_of_reviving_the_key(self):
        secret = self.seed_delivery()
        past = (self.mod.utcnow() - timedelta(hours=1)).isoformat()
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET activation_secret_expires_at=? WHERE account_number=?",
                         (past, harness.ACCOUNT))
        with patch.object(self.mod, "send_account_email") as send:
            self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 0)
            send.assert_not_called()
        self.assertEqual(self.deliveries()[0]["status"], "cancelled")
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute(
                "SELECT activation_secret_expires_at FROM users WHERE account_number=?", (harness.ACCOUNT,)
            ).fetchone()[0], past)
            self.assertFalse(self.mod.verify_and_consume_activation_secret(conn, harness.ACCOUNT, secret))

    def test_consumed_key_cancels_delivery_and_delete_cascades(self):
        secret = self.seed_delivery()
        with self.mod.get_db() as conn:
            self.mod.verify_and_consume_activation_secret(conn, harness.ACCOUNT, secret)
        with patch.object(self.mod, "send_account_email") as send:
            self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 0)
            send.assert_not_called()
        self.assertEqual(self.deliveries()[0]["status"], "cancelled")
        self.assertEqual(self.deliveries()[0]["sealed_secret"], "")
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM users WHERE account_number=?", (harness.ACCOUNT,))
        self.assertEqual(self.deliveries(), [])

    def test_changed_recipient_or_reissued_key_never_receives_old_delivery(self):
        for change in ("recipient", "secret", "refund"):
            with self.subTest(change=change):
                with self.mod.get_db() as conn:
                    self.mod.ensure_schema(conn)
                    conn.execute("DELETE FROM activation_delivery_outbox")
                self.seed_delivery()
                with self.mod.get_db() as conn:
                    if change == "recipient":
                        conn.execute("UPDATE users SET email='new@example.test' WHERE account_number=?", (harness.ACCOUNT,))
                    elif change == "secret":
                        self.mod.issue_activation_secret(conn, harness.ACCOUNT)
                    else:
                        conn.execute("UPDATE users SET status='expired', paypal_status='REFUNDED' WHERE account_number=?", (harness.ACCOUNT,))
                with patch.object(self.mod, "send_account_email") as send:
                    self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 0)
                    send.assert_not_called()
                self.assertEqual(self.deliveries()[0]["status"], "cancelled")

    def test_startup_runs_delivery_worker_and_shutdown_cancels_it(self):
        self.mod.HIDE_CONTROL_ORIGIN = True
        self.mod.MONERO_WALLET_RPC_URL = ""
        self.mod.EMERGENCY_DISPATCH_ENABLED = False
        called = threading.Event()
        self.mod.drain_activation_delivery_outbox_once = lambda: called.set() or 0
        async def idle():
            await asyncio.Event().wait()
        for name in ("account_deletion_sweep_loop", "account_expiry_revocation_sweep_loop", "fleet_availability_sweep_loop"):
            setattr(self.mod, name, idle)
        async def exercise():
            before = asyncio.all_tasks()
            try:
                await self.mod.startup_event()
                self.assertTrue(await asyncio.to_thread(called.wait, 2))
                worker = self.mod._activation_delivery_task
                self.assertIsNotNone(worker)
                await self.mod.stop_activation_delivery_worker()
                self.assertTrue(worker.cancelled())
                self.assertIsNone(self.mod._activation_delivery_task)
            finally:
                created = asyncio.all_tasks() - before
                for task in created:
                    task.cancel()
                await asyncio.gather(*created, return_exceptions=True)
        asyncio.run(exercise())

    def test_paid_subscription_commits_queue_and_duplicate_does_not_regrant(self):
        work, tasks = self.paypal()
        self.assertTrue(asyncio.run(work)["created"])
        self.assertFalse(any(fn == self.mod.send_account_email for fn, _, _ in tasks.tasks))
        item = self.deliveries()[0]
        self.assertEqual((item["delivery_id"], item["status"]), ("paypal:evt-subscription", "pending"))
        self.assertEqual(asyncio.run(self.paypal()[0])["status"], "duplicate")
        self.assertEqual(len(self.deliveries()), 1)
        self.assertEqual(self.mod.drain_activation_delivery_outbox_once(), 1)

    def test_outbox_insert_failure_rolls_back_paid_grant_and_event_completion(self):
        with patch.object(self.mod, "enqueue_activation_delivery", side_effect=sqlite3.OperationalError("injected")):
            with self.assertRaises(sqlite3.OperationalError):
                asyncio.run(self.paypal()[0])
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE paypal_subscription_id='I-TEST'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT status FROM paypal_events WHERE event_id='evt-subscription'").fetchone()[0], "failed")
        self.assertEqual(self.deliveries(), [])
        self.assertTrue(asyncio.run(self.paypal()[0])["created"])

    def provider_grant(self, provider):
        tasks = harness.BackgroundTasks()
        if provider == "lifetime":
            self.mod.PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT = "99.00"
            self.mod.PAYPAL_LIFETIME_CURRENCY = "USD"
            capture = {
                "id": "CAPTURE-TEST", "status": "COMPLETED", "custom_id": "lifetime_no_support",
                "amount": {"value": "99.00", "currency_code": "USD"},
                "payer": {"email_address": "lifetime@example.test"},
                "supplementary_data": {"related_ids": {"order_id": "ORDER-TEST"}},
            }
            parent = {
                "id": "ORDER-TEST", "status": "COMPLETED", "payer": capture["payer"],
                "purchase_units": [{"payments": {"captures": [capture]}}],
            }
            with patch.object(self.mod, "paypal_json_request", return_value=parent):
                return asyncio.run(self.mod.paypal_webhook(WebhookRequest(body={
                    "id": "evt-lifetime", "event_type": "PAYMENT.CAPTURE.COMPLETED",
                    "resource": capture,
                }), tasks))
        if provider == "btcpay":
            self.mod.btcpay_enabled = lambda: True
            self.mod.verify_btcpay_webhook_signature = lambda *args: True
            self.mod.btcpay_fetch_invoice = lambda invoice_id: {
                "id": invoice_id, "status": "Settled", "amount": "0.99", "currency": "USD",
                "metadata": {"hub_order_id": "hub-btcpay", "plan_key": "one_month",
                             "buyerEmail": "btcpay@example.test"},
            }
            return asyncio.run(self.mod.btcpay_webhook(WebhookRequest(body={
                "type": "InvoiceSettled", "invoiceId": "invoice-test",
            }), tasks))
        with self.mod.get_db() as conn:
            return self.mod.settle_one_monero_order(conn, "hub-monero", 1000, 1000,
                                                   "test-tx", self.mod.utcnow(), "test-lease")

    def test_all_other_payment_providers_roll_back_then_queue_once(self):
        for provider in ("lifetime", "btcpay", "monero"):
            with self.subTest(provider=provider):
                if provider != "lifetime":
                    with self.mod.get_db() as conn:
                        conn.execute("""
                            INSERT INTO payment_orders(hub_order_id, provider, provider_order_id,
                                plan_key, expected_amount, expected_currency, buyer_email, status, created_at)
                            VALUES (?, ?, ?, 'one_month', '0.99', 'USD', ?, 'pending', ?)
                        """, (f"hub-{provider}", provider, "invoice-test" if provider == "btcpay" else "test-subaddress",
                              f"{provider}@example.test", self.mod.utcnow().isoformat()))
                        if provider == "monero":
                            conn.execute("""
                                INSERT INTO monero_orders(hub_order_id, subaddress, subaddress_index,
                                    plan_key, amount_atomic, buyer_email, expires_at, lease_until)
                                VALUES ('hub-monero', 'test-subaddress', 1, 'one_month', 1000,
                                        'monero@example.test', ?, 'test-lease')
                            """, ((self.mod.utcnow() + timedelta(hours=1)).isoformat(),))
                with patch.object(self.mod, "enqueue_activation_delivery", side_effect=sqlite3.OperationalError("queue unavailable")):
                    with self.assertRaises(sqlite3.OperationalError):
                        self.provider_grant(provider)
                with self.mod.get_db() as conn:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM users WHERE email=?", (f"{provider}@example.test",)).fetchone()[0], 0)
                    if provider != "lifetime":
                        self.assertEqual(conn.execute("SELECT status FROM payment_orders WHERE provider=?", (provider,)).fetchone()[0], "pending")
                result = self.provider_grant(provider)
                self.assertIn(result["status"], ("ok", "settled"))
                item = next(row for row in self.deliveries() if row["target_email"] == f"{provider}@example.test")
                self.assertEqual(item["status"], "pending")
                self.assertNotIn("delivery", result)
                self.assertNotIn("activation_secret", result)
                self.assertIn(self.provider_grant(provider)["status"], ("duplicate", "skipped"))
                self.assertEqual(sum(row["target_email"] == f"{provider}@example.test" for row in self.deliveries()), 1)

    def test_admin_sync_runs_in_worker_and_successful_sync_commits(self):
        asyncio.run(self.paypal()[0])
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET last_paypal_sync=NULL WHERE paypal_subscription_id='I-TEST'")
        self.mod.require_admin_token = lambda *args: None
        owner = threading.get_ident()
        def fetch(sub_id):
            self.assertNotEqual(threading.get_ident(), owner)
            with closing(sqlite3.connect(self.mod._DB, timeout=0.1)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            return self.subscription(sub_id)
        self.mod.fetch_paypal_subscription = fetch
        result = asyncio.run(self.mod.admin_paypal_sync(harness.FakeRequest(), 48, "test"))
        self.assertEqual((result["checked"], result["updated"], result["errors"]), (1, 1, []))

    def test_advisory_accepts_only_valid_bearer_or_unconsumed_activation(self):
        tokens = harness.seed_account(self.mod, devices=1)
        with self.mod.get_db() as conn:
            secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
            key = conn.execute("SELECT client_public_key FROM devices WHERE account_number=?", (harness.ACCOUNT,)).fetchone()[0]
            for headers in ({"authorization": f"Bearer {next(iter(tokens.values()))}"}, {"x-wins-activation": secret}):
                self.assertTrue(self.mod.verify_advisory_request_authorized(conn, account_number=harness.ACCOUNT,
                                requested_client_public_key=key, request=harness.FakeRequest(headers=headers)))
            self.assertFalse(self.mod.verify_advisory_request_authorized(conn, account_number=harness.ACCOUNT,
                             requested_client_public_key="other-key", request=harness.FakeRequest(headers={"authorization": f"Bearer {next(iter(tokens.values()))}"})))

    def test_paypal_remote_calls_are_off_event_loop_without_database_connections(self):
        original_get_db = self.mod.get_db
        active = []
        @contextlib.contextmanager
        def tracked_db():
            with original_get_db() as conn:
                active.append(conn)
                try:
                    yield conn
                finally:
                    active.remove(conn)
        calls = []
        owner = threading.get_ident()
        def offloop(name, result):
            def call(*args):
                self.assertNotEqual(threading.get_ident(), owner)
                self.assertEqual(active, [])
                time.sleep(0.04)
                calls.append(name)
                return result(*args) if callable(result) else result
            return call
        self.mod.get_db = tracked_db
        self.mod.verify_paypal_webhook_signature = offloop("signature", True)
        self.mod.fetch_paypal_subscription = offloop("subscription", self.subscription)
        asyncio.run(self.paypal()[0])
        self.mod.paypal_refund_is_terminal = offloop("refund", (False, [], ""))
        asyncio.run(self.mod.paypal_webhook(WebhookRequest(body={
            "id": "evt-refund", "event_type": "PAYMENT.CAPTURE.REFUNDED", "resource": {},
        }), harness.BackgroundTasks()))
        self.assertEqual(calls, ["signature", "subscription", "signature", "refund"])

    def test_paypal_sync_closes_candidates_and_concurrent_refund_wins(self):
        asyncio.run(self.paypal()[0])
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET last_paypal_sync=NULL WHERE paypal_subscription_id='I-TEST'")
        original_get_db = self.mod.get_db
        active = []
        @contextlib.contextmanager
        def tracked_db():
            with original_get_db() as conn:
                active.append(conn)
                try:
                    yield conn
                finally:
                    active.remove(conn)
        def fetch(sub_id):
            self.assertEqual(active, [])
            with original_get_db() as conn:
                conn.execute("UPDATE users SET status='expired', paypal_status='REFUNDED' WHERE paypal_subscription_id=?", (sub_id,))
            return self.subscription(sub_id)
        self.mod.get_db = tracked_db
        self.mod.fetch_paypal_subscription = fetch
        self.assertEqual(self.mod.sync_due_paypal_subscriptions()["updated"], 0)
        with original_get_db() as conn:
            self.assertEqual(conn.execute("SELECT paypal_status FROM users WHERE paypal_subscription_id='I-TEST'").fetchone()[0], "REFUNDED")

    def test_unauthorized_paid_verify_cannot_trigger_smart_router(self):
        harness.seed_account(self.mod, devices=0)
        serving.seed_node(self.mod)
        with self.mod.get_db() as conn:
            secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
        login = serving.build_login(self.mod, location="auto")
        for marker, expiry, presented in ((None, None, "wrong"), ("used", None, secret), (None, "malformed", secret)):
            with self.subTest(marker=marker, expiry=expiry):
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE users SET activation_secret_used_at=?, activation_secret_expires_at=? WHERE account_number=?",
                                 (marker, expiry, harness.ACCOUNT))
                with patch.object(self.mod, "smart_router_trigger_for_existing_node") as trigger, patch.object(self.mod, "smart_router_recommend_node") as recommend:
                    with self.assertRaises(harness.HTTPException) as error:
                        asyncio.run(self.mod.verify_account(harness.FakeRequest(path="/verify", headers={"x-wins-activation": presented}), login, harness.BackgroundTasks()))
                    self.assertEqual(error.exception.status_code, 401)
                    trigger.assert_not_called()
                    recommend.assert_not_called()


if __name__ == "__main__":
    unittest.main()
