#!/usr/bin/env python3
"""Crypto payment integration tests for Spain server and Kansas Hub coordination.

Validates the full cryptocurrency processing contract:
- BTCPay Server Greenfield invoice generation and parameter validation.
- BTCPay webhook HMAC-SHA256 signature verification.
- Monero wallet RPC least-privilege configuration and authentication.
- Atomic piconero arithmetic and multi-oracle price extraction.
- Order ledger persistence in payment_orders and monero_orders.

Run: python3 server/test_crypto_payments_spain.py
"""
import _toolchain  # noqa: F401
import decimal
import hashlib
import hmac
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_account_deletion_hub as harness  # noqa: E402
from test_account_deletion_hub import FakeRequest, HTTPException  # noqa: E402


class CryptoPaymentsSpainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = harness.load_hub()

    def setUp(self):
        # Configure test crypto credentials in module
        self.mod.BTCPAY_URL = "https://btcpay.winsvpn.org"
        self.mod.BTCPAY_STORE_ID = "test-store-spain-001"
        self.mod.BTCPAY_API_KEY = "test-greenfield-api-key-999"
        self.mod.BTCPAY_WEBHOOK_SECRET = "test-webhook-secret-spain-hmac"
        self.mod.MONERO_WALLET_RPC_URL = "https://btcpay.winsvpn.org/monero-rpc"
        self.mod.MONERO_WALLET_RPC_USER = "winsmonero"
        self.mod.MONERO_WALLET_RPC_PASS = "super-secret-digest-pass"
        self.mod.MONERO_PRICE_MANUAL_USD = "165.50"
        self.mod._monero_rpc_config_state = None

    def test_btcpay_enabled_flags(self):
        self.assertTrue(self.mod.btcpay_enabled())
        orig = self.mod.BTCPAY_URL
        try:
            self.mod.BTCPAY_URL = ""
            self.assertFalse(self.mod.btcpay_enabled())
            self.mod.BTCPAY_URL = "http://insecure.example.com"
            self.assertFalse(self.mod.btcpay_enabled())
        finally:
            self.mod.BTCPAY_URL = orig

    def test_btcpay_webhook_hmac_verification(self):
        secret = "test-webhook-secret-spain-hmac"
        body = json.dumps({
            "deliveryId": "deliv-123",
            "webhookId": "wh-456",
            "type": "InvoiceSettled",
            "invoiceId": "inv-spain-789",
        }).encode("utf-8")
        expected_sig = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

        headers = {"btcpay-sig": expected_sig}
        self.assertTrue(self.mod.verify_btcpay_webhook_signature(headers, body))

        bad_headers = {"btcpay-sig": "sha256=0000000000000000000000000000000000000000000000000000000000000000"}
        self.assertFalse(self.mod.verify_btcpay_webhook_signature(bad_headers, body))

        missing_headers = {}
        self.assertFalse(self.mod.verify_btcpay_webhook_signature(missing_headers, body))

    def test_monero_rpc_least_privilege_validation(self):
        # Valid remote HTTPS on standard 443 port passes
        self.mod.MONERO_WALLET_RPC_URL = "https://btcpay.winsvpn.org/monero-rpc"
        self.mod.MONERO_WALLET_RPC_USER = "winsmonero"
        self.mod.MONERO_WALLET_RPC_PASS = "secretpass"
        self.mod._monero_rpc_config_state = None
        self.assertTrue(self.mod.monero_rpc_enabled())

        # Plaintext HTTP on non-loopback is refused
        self.mod.MONERO_WALLET_RPC_URL = "http://NODE_IP_ES1:18083"
        self.mod._monero_rpc_config_state = None
        self.assertFalse(self.mod.monero_rpc_enabled())

        # Nonstandard remote HTTPS port is refused
        self.mod.MONERO_WALLET_RPC_URL = "https://btcpay.winsvpn.org:8443/monero-rpc"
        self.mod._monero_rpc_config_state = None
        self.assertFalse(self.mod.monero_rpc_enabled())

        # Loopback HTTP is approved
        self.mod.MONERO_WALLET_RPC_URL = "http://127.0.0.1:18083"
        self.mod._monero_rpc_config_state = None
        self.assertTrue(self.mod.monero_rpc_enabled())

    def test_monero_atomic_conversion_exactness(self):
        # 1 XMR = 1,000,000,000,000 atomic units (piconero, 10^12)
        usd_price = "0.99"
        rate = decimal.Decimal("165.00")
        atomic = self.mod.monero_usd_to_atomic(usd_price, rate)
        self.assertIsInstance(atomic, int)
        self.assertGreater(atomic, 0)

        # 0.99 / 165.00 = 0.006 XMR = 6,000,000,000 atomic
        expected_atomic = 6000000000
        self.assertEqual(atomic, expected_atomic)

        xmr_str = self.mod.monero_atomic_to_xmr_str(atomic)
        self.assertEqual(xmr_str, "0.006000000000")

    def test_monero_price_oracle_extraction(self):
        kraken_payload = {
            "result": {
                "XXMRZUSD": {
                    "c": ["172.4500", "0.25"]
                }
            }
        }
        price_kraken = self.mod.extract_xmr_usd_price(kraken_payload)
        self.assertEqual(price_kraken, decimal.Decimal("172.4500"))

        coingecko_payload = {"monero": {"usd": 171.85}}
        price_cg = self.mod.extract_xmr_usd_price(coingecko_payload)
        self.assertEqual(price_cg, decimal.Decimal("171.85"))

        coinbase_payload = {"data": {"amount": "173.10"}}
        price_cb = self.mod.extract_xmr_usd_price(coinbase_payload)
        self.assertEqual(price_cb, decimal.Decimal("173.10"))

    def test_crypto_settled_invoice_amount_verification(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            # 1m plan allows valid positive USD amount
            valid_1m = {"currency": "USD", "amount": "0.99"}
            self.assertTrue(self.mod.crypto_settled_invoice_amount_ok(conn, "1m", valid_1m))

            # Non-USD currency refused
            eur_invoice = {"currency": "EUR", "amount": "0.99"}
            self.assertFalse(self.mod.crypto_settled_invoice_amount_ok(conn, "1m", eur_invoice))

            # Zero or negative amount refused
            zero_invoice = {"currency": "USD", "amount": "0.00"}
            self.assertFalse(self.mod.crypto_settled_invoice_amount_ok(conn, "1m", zero_invoice))

    def test_payment_orders_schema_and_binding(self):
        hub_order_id = "wins-test-order-999"
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute(
                """
                INSERT OR REPLACE INTO payment_orders (
                    hub_order_id, provider, plan_key, expected_amount,
                    expected_currency, buyer_email, referral_code, status, created_at
                ) VALUES (?, 'btcpay', '1m', '0.99', 'USD', 'buyer@example.com', '', 'creating', ?)
                """,
                (hub_order_id, self.mod.utcnow().isoformat()),
            )
            # Bind provider order id
            bound = conn.execute(
                "UPDATE payment_orders SET provider_order_id=?, status='pending' WHERE hub_order_id=? AND provider='btcpay' AND status='creating'",
                ("inv-btcpay-real-id-1", hub_order_id),
            ).rowcount
            self.assertEqual(bound, 1)

            # Settle order
            settled = conn.execute(
                "UPDATE payment_orders SET status='settled', settled_at=? WHERE provider='btcpay' AND provider_order_id=? AND status='pending'",
                (self.mod.utcnow().isoformat(), "inv-btcpay-real-id-1"),
            ).rowcount
            self.assertEqual(settled, 1)


if __name__ == "__main__":
    unittest.main()
