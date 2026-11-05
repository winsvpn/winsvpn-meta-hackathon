"""Offline adversarial tests of exact generated hub code. No provider calls."""
from pathlib import Path
import asyncio
import copy
import os
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
import test_control_plane_round5 as base

if os.getenv("AUDIT_CANDIDATE") == "1":
    base.harness.HUB = str(ROOT / "docs/evidence/astra_round15/candidate/server/wins_control_plane_setup_ONETOUCH.sh")


class PaymentAuthority(unittest.TestCase):
    setUp = base.Round5Tests.setUp
    tearDown = base.Round5Tests.tearDown
    subscription = base.Round5Tests.subscription

    def capture_event(self, event_id="audit-capture-event"):
        self.mod.PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT = "10.00"
        self.mod.PAYPAL_LIFETIME_CURRENCY = "USD"
        return {"id": event_id, "event_type": "PAYMENT.CAPTURE.COMPLETED", "resource": {
            "id": "AUDIT-CAPTURE-001", "status": "COMPLETED", "custom_id": "lifetime_no_support",
            "payer": {"email_address": "buyer@example.test"},
            "amount": {"value": "10.00", "currency_code": "USD"},
            "supplementary_data": {"related_ids": {"order_id": "AUDIT-ORDER-001"}},
        }}

    def parent(self, status="COMPLETED"):
        capture = copy.deepcopy(self.capture_event()["resource"])
        capture["status"] = status
        return {"id": "AUDIT-ORDER-001", "status": "COMPLETED",
                "payer": {"email_address": "buyer@example.test"},
                "purchase_units": [{"payments": {"captures": [capture]}}]}

    def deliver(self, payload):
        return asyncio.run(self.mod.paypal_webhook(
            base.WebhookRequest(path="/webhook/paypal", body=payload), base.harness.BackgroundTasks()))

    def counts(self):
        with self.mod.get_db() as conn:
            return tuple(conn.execute("SELECT (SELECT count(*) FROM users WHERE status='active'), "
                                      "(SELECT count(*) FROM activation_delivery_outbox)").fetchone())

    def test_unbound_wallet_order_never_reaches_provider(self):
        calls = []
        def provider(method, path, *args):
            calls.append((method, path))
            return {"id": "AUDIT-ORDER-UNKNOWN", "status": "COMPLETED"}
        try:
            with patch.object(self.mod, "paypal_json_request", side_effect=provider):
                self.mod._wallet_capture_sync(self.mod.WalletCaptureRequest(order_id="AUDIT-ORDER-UNKNOWN"),
                                               base.harness.FakeRequest(path="/pay/wallet/capture"))
        except base.harness.HTTPException as error:
            self.assertEqual(error.status_code, 404)
        self.assertEqual(calls, [], "An unbound order reached the merchant capture API")

    def test_buyer_field_does_not_skip_current_payment_state(self):
        with patch.object(self.mod, "paypal_json_request", return_value=self.parent("REFUNDED")):
            try:
                self.deliver(self.capture_event())
            except RuntimeError:
                pass
        self.assertEqual(self.counts(), (0, 0), "A stale completion granted a fully refunded payment")

    def test_refund_before_delayed_completion_never_grants(self):
        refund = {"id": "audit-refund-event", "event_type": "PAYMENT.CAPTURE.REFUNDED", "resource": {
            "id": "AUDIT-REFUND-001", "status": "COMPLETED",
            "supplementary_data": {"related_ids": {"capture_id": "AUDIT-CAPTURE-001"}},
        }}
        def provider(method, path, *args):
            self.assertEqual(method, "GET")
            if path == "/v2/payments/captures/AUDIT-CAPTURE-001":
                return {"id": "AUDIT-CAPTURE-001", "status": "REFUNDED"}
            self.assertEqual(path, "/v2/checkout/orders/AUDIT-ORDER-001")
            # A stale provider snapshot is insufficient to erase a durable refund.
            return self.parent()
        with patch.object(self.mod, "paypal_json_request", side_effect=provider):
            result = self.deliver(refund)
            self.assertEqual(result["revoked"], 0)
            self.deliver(self.capture_event())
        self.assertEqual(self.counts(), (0, 0), "The refund was acknowledged without a durable anti-grant record")

    def test_valid_current_capture_grants_once(self):
        with patch.object(self.mod, "paypal_json_request", return_value=self.parent()):
            self.assertEqual(self.deliver(self.capture_event())["status"], "ok")
            self.assertEqual(self.deliver(self.capture_event())["status"], "duplicate")
        self.assertEqual(self.counts(), (1, 1))

    def test_refund_committed_during_provider_read_fences_grant(self):
        refund = {"id": "audit-concurrent-refund", "event_type": "PAYMENT.CAPTURE.REFUNDED", "resource": {
            "id": "AUDIT-REFUND-002", "status": "COMPLETED",
            "supplementary_data": {"related_ids": {"capture_id": "AUDIT-CAPTURE-001"}},
        }}
        def provider(method, path, *args):
            self.assertEqual(method, "GET")
            if path == "/v2/payments/captures/AUDIT-CAPTURE-001":
                return {"id": "AUDIT-CAPTURE-001", "status": "REFUNDED"}
            self.assertEqual(path, "/v2/checkout/orders/AUDIT-ORDER-001")
            self.deliver(refund)
            return self.parent()
        with patch.object(self.mod, "paypal_json_request", side_effect=provider):
            self.deliver(self.capture_event())
        self.assertEqual(self.counts(), (0, 0))

    def test_partial_refund_preserves_existing_nonterminal_policy(self):
        with patch.object(self.mod, "paypal_json_request", return_value=self.parent("PARTIALLY_REFUNDED")):
            self.assertEqual(self.deliver(self.capture_event())["status"], "ok")
        self.assertEqual(self.counts(), (1, 1))

    def test_known_wallet_order_captures_and_rechecks_duplicate(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute("INSERT INTO payment_orders "
                         "(hub_order_id,provider,provider_order_id,plan_key,expected_amount,expected_currency,status,created_at) "
                         "VALUES (?,?,?,?,?,?,?,?)", ("audit-hub", "paypal_wallet", "AUDIT-ORDER-001",
                         "lifetime_no_support", "10.00", "USD", "pending", self.mod.utcnow().isoformat()))
        calls = []
        def provider(method, path, *args):
            calls.append(method)
            return {"id": "AUDIT-ORDER-001", "status": "COMPLETED"}
        with patch.object(self.mod, "paypal_json_request", side_effect=provider):
            request = self.mod.WalletCaptureRequest(order_id="AUDIT-ORDER-001")
            self.assertEqual(self.mod._wallet_capture_sync(request, base.harness.FakeRequest())["status"], "COMPLETED")
            self.assertEqual(self.mod._wallet_capture_sync(request, base.harness.FakeRequest())["status"], "already_captured")
        self.assertEqual(calls, ["POST", "GET"])

    def test_known_manual_review_order_does_not_capture(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute("INSERT INTO payment_orders "
                         "(hub_order_id,provider,provider_order_id,plan_key,expected_amount,expected_currency,status,created_at) "
                         "VALUES (?,?,?,?,?,?,?,?)", ("audit-review", "paypal_wallet", "AUDIT-ORDER-REVIEW",
                         "lifetime_no_support", "10.00", "USD", "manual_review", self.mod.utcnow().isoformat()))
        with patch.object(self.mod, "paypal_json_request", return_value={"status": "COMPLETED"}) as provider:
            try:
                self.mod._wallet_capture_sync(self.mod.WalletCaptureRequest(order_id="AUDIT-ORDER-REVIEW"),
                                               base.harness.FakeRequest())
            except base.harness.HTTPException as error:
                self.assertEqual(error.status_code, 409)
            self.assertEqual(provider.call_count, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
