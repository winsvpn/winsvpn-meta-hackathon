#!/usr/bin/env python3
"""Fleet reset plan 2026-10-08 (FLEET1): hub runtime (main.py) changes.

The REAL hub module is extracted from the control-plane installer by the
account-deletion harness and exec'd with its usual third-party stubs.

  D7     MONERO_WALLET_RPC_CF_ACCESS=1 presents the wallet hostname's OWN
         Access service token (never the management token) on every wallet
         RPC request, only over https and only with a well-formed token; off,
         nothing is added.
  TP-P9  BTCPay checkout is offered and minted only for chains the owner named
         in BTCPAY_CHECKOUT_CHAINS (fail closed on empty, "none" or an unknown
         chain); webhooks for invoices already issued are still verified; GET
         /nodes names the offered chains (FLEET1 Turn 2) for the website.

Run: python3 -B -m pytest -q -p no:cacheprovider server/test_fleet_reset_hub_runtime.py
     WINS_FLEET_CP=/path/to/installer ... (mutant runs)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_account_deletion_hub as harness  # noqa: E402

if os.environ.get("WINS_FLEET_CP"):
    harness.HUB = os.environ["WINS_FLEET_CP"]

TOKEN_ID = "0123456789abcdef0123456789abcdef.access"
TOKEN_SECRET = "s" * 64
MGMT_ID = "fedcba9876543210fedcba9876543210.access"
MGMT_SECRET = "m" * 64


class _Response:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        data, self._body = self._body, b""
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _CapturingOpener:
    def __init__(self):
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        return _Response(json.dumps({"result": {"address": "8xyz", "address_index": 7}}).encode())


class MoneroAccessHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = harness.load_hub()

    def setUp(self):
        m = self.mod
        self.saved = {k: getattr(m, k, None) for k in (
            "MONERO_WALLET_RPC_URL", "MONERO_WALLET_RPC_USER", "MONERO_WALLET_RPC_PASS",
            "MONERO_WALLET_RPC_CF_ACCESS", "TUNNEL_SERVICE_TOKEN_ID", "TUNNEL_SERVICE_TOKEN_SECRET",
            "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID", "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET", "monero_opener")}
        m.MONERO_WALLET_RPC_URL = "https://monero-rpc.winsvpn.org"
        m.MONERO_WALLET_RPC_USER = "winsmonero"
        m.MONERO_WALLET_RPC_PASS = "digest-pass"
        m.TUNNEL_SERVICE_TOKEN_ID = MGMT_ID
        m.TUNNEL_SERVICE_TOKEN_SECRET = MGMT_SECRET
        m.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID = TOKEN_ID
        m.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET = TOKEN_SECRET
        m._monero_rpc_config_state = None
        self.opener = _CapturingOpener()
        m.monero_opener = lambda: self.opener

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(self.mod, k, v)
        self.mod._monero_rpc_config_state = None

    def test_the_flag_is_read_from_the_environment(self):
        self.assertIn('MONERO_WALLET_RPC_CF_ACCESS = os.getenv("MONERO_WALLET_RPC_CF_ACCESS", "0").strip() == "1"',
                      harness._extract_main_block())

    def test_with_the_flag_every_wallet_rpc_request_carries_both_access_headers(self):
        self.mod.MONERO_WALLET_RPC_CF_ACCESS = True
        self.assertTrue(self.mod.monero_rpc_enabled())
        result = self.mod.monero_rpc("create_address", {"account_index": 0})
        self.assertEqual(result["address_index"], 7)
        (req,) = self.opener.requests
        self.assertEqual(req.get_header("Cf-access-client-id"), TOKEN_ID)
        self.assertEqual(req.get_header("Cf-access-client-secret"), TOKEN_SECRET)
        self.assertEqual(req.full_url, "https://monero-rpc.winsvpn.org/json_rpc")

    def test_without_the_flag_no_access_header_is_sent(self):
        self.mod.MONERO_WALLET_RPC_CF_ACCESS = False
        self.assertEqual(self.mod.monero_cf_access_headers(), {})
        self.mod.monero_rpc("create_address", {"account_index": 0})
        (req,) = self.opener.requests
        self.assertIsNone(req.get_header("Cf-access-client-id"))
        self.assertIsNone(req.get_header("Cf-access-client-secret"))

    def test_the_flag_over_plaintext_loopback_disables_monero(self):
        self.mod.MONERO_WALLET_RPC_CF_ACCESS = True
        self.mod.MONERO_WALLET_RPC_URL = "http://127.0.0.1:18083"
        with self.assertRaisesRegex(RuntimeError, "requires an https wallet RPC URL"):
            self.mod.validate_monero_rpc_configuration()
        self.assertFalse(self.mod.monero_rpc_enabled())
        with self.assertRaises(RuntimeError):
            self.mod.monero_rpc("create_address", {})
        self.assertEqual(self.opener.requests, [], "nothing reached the wallet")

    def test_the_flag_without_a_well_formed_token_disables_monero(self):
        self.mod.MONERO_WALLET_RPC_CF_ACCESS = True
        for token_id, secret in (("", TOKEN_SECRET), ("not-an-access-id", TOKEN_SECRET), (TOKEN_ID, "short"),
                                 ("x y.access", TOKEN_SECRET), ("../x.access", TOKEN_SECRET),
                                 (TOKEN_ID, "s" * 20 + " " + "s" * 20), (TOKEN_ID, "s" * 20 + "\r\n" + "s" * 20)):
            with self.subTest(token_id=token_id, secret=len(secret)):
                self.mod.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID = token_id
                self.mod.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET = secret
                self.mod._monero_rpc_config_state = None
                self.assertFalse(self.mod.monero_rpc_enabled())

    def test_the_management_token_is_never_sent_to_the_wallet_host(self):
        # D7 ruling: a dedicated token. The management token opens every node.
        self.mod.MONERO_WALLET_RPC_CF_ACCESS = True
        self.mod.monero_rpc("create_address", {"account_index": 0})
        (req,) = self.opener.requests
        self.assertNotIn(MGMT_SECRET, [v for _, v in req.header_items()])
        for token_id, secret in ((MGMT_ID, MGMT_SECRET), (MGMT_ID, TOKEN_SECRET), (TOKEN_ID, MGMT_SECRET)):
            with self.subTest(token_id=token_id):
                self.mod.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID = token_id
                self.mod.MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET = secret
                self.mod._monero_rpc_config_state = None
                with self.assertRaisesRegex(RuntimeError, "dedicated Access service token"):
                    self.mod.validate_monero_rpc_configuration()
                self.assertFalse(self.mod.monero_rpc_enabled())

    def test_the_wallet_token_never_joins_the_ssh_env_allowlists(self):
        # FLEET1 Turn 2 (Astra): MANAGEMENT_SSH_ENV_KEYS and PROBE_SSH_ENV_KEYS
        # are the environment ssh children inherit, not a redaction list. The
        # management token belongs there; the wallet token never does.
        for name in ("MANAGEMENT_SSH_ENV_KEYS", "PROBE_SSH_ENV_KEYS"):
            keys = getattr(self.mod, name, None)
            if keys is None:
                continue
            with self.subTest(allowlist=name):
                self.assertIn("TUNNEL_SERVICE_TOKEN_SECRET", keys)
                self.assertNotIn("MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID", keys)
                self.assertNotIn("MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET", keys)
        self.assertIn("TUNNEL_SERVICE_TOKEN_SECRET", self.mod.MANAGEMENT_SSH_ENV_KEYS)
        env = {"TUNNEL_SERVICE_TOKEN_ID": MGMT_ID, "TUNNEL_SERVICE_TOKEN_SECRET": MGMT_SECRET,
               "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_ID": TOKEN_ID, "MONERO_WALLET_RPC_CF_ACCESS_CLIENT_SECRET": TOKEN_SECRET}
        saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            child = self.mod.management_ssh_env()
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.assertEqual(child.get("TUNNEL_SERVICE_TOKEN_SECRET"), MGMT_SECRET)
        self.assertNotIn(TOKEN_SECRET, child.values())


class BtcpayCheckoutChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = harness.load_hub()

    def setUp(self):
        m = self.mod
        self.saved = {k: getattr(m, k, None) for k in (
            "BTCPAY_URL", "BTCPAY_STORE_ID", "BTCPAY_API_KEY", "BTCPAY_WEBHOOK_SECRET", "BTCPAY_CHECKOUT_CHAINS")}
        m.BTCPAY_URL = "https://btcpay.winsvpn.org"
        m.BTCPAY_STORE_ID = "store-1"
        m.BTCPAY_API_KEY = "greenfield-key"
        m.BTCPAY_WEBHOOK_SECRET = "webhook-secret"

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(self.mod, k, v)

    def config(self, chains):
        self.mod.BTCPAY_CHECKOUT_CHAINS = chains
        return self.mod.site_crypto_config(harness.FakeRequest(method="GET"))

    def test_the_setting_defaults_to_no_checkout(self):
        self.assertIn('BTCPAY_CHECKOUT_CHAINS = os.getenv("BTCPAY_CHECKOUT_CHAINS", "")', harness._extract_main_block())

    def test_no_named_chain_offers_no_btcpay_checkout(self):
        for chains in ("", "none", "NONE", "  "):
            with self.subTest(chains=chains):
                body = self.config(chains)
                self.assertFalse(body["crypto_enabled"])
                self.assertEqual(body["btcpay_chains"], [])

    def test_named_chains_are_offered(self):
        body = self.config("BTC")
        self.assertTrue(body["crypto_enabled"])
        self.assertEqual(body["btcpay_chains"], ["BTC"])
        body = self.config("btc, DASH,BTC")
        self.assertEqual(body["btcpay_chains"], ["BTC", "DASH"])

    def test_an_unknown_chain_fails_closed(self):
        for chains in ("LTC", "BTC,LTC", "BTC,"):
            with self.subTest(chains=chains):
                body = self.config(chains)
                self.assertFalse(body["crypto_enabled"])
                self.assertEqual(body["btcpay_chains"], [])

    def test_an_unconfigured_store_offers_nothing_whatever_the_setting(self):
        self.mod.BTCPAY_API_KEY = ""
        self.assertFalse(self.config("BTC,DASH")["crypto_enabled"])

    def test_create_invoice_refuses_when_no_chain_is_named(self):
        self.mod.BTCPAY_CHECKOUT_CHAINS = "none"
        req = self.mod.CryptoInvoiceRequest(plan_key="one_month")
        with self.assertRaises(harness.HTTPException) as cm:
            self.mod._crypto_create_invoice_sync(req, harness.FakeRequest())
        self.assertEqual((cm.exception.status_code, cm.exception.detail), (503, "Crypto payments are not configured"))
        # With a named chain the request passes the gate (and stops later, at pricing).
        self.mod.BTCPAY_CHECKOUT_CHAINS = "BTC"
        saved = self.mod.crypto_price_usd
        self.mod.crypto_price_usd = lambda conn, plan: ""
        try:
            with self.assertRaises(harness.HTTPException) as cm:
                self.mod._crypto_create_invoice_sync(req, harness.FakeRequest())
        finally:
            self.mod.crypto_price_usd = saved
        self.assertEqual(cm.exception.detail, "Crypto pricing is not configured")

    def test_webhooks_for_issued_invoices_still_verify_with_checkout_off(self):
        self.mod.BTCPAY_CHECKOUT_CHAINS = "none"
        body = b'{"type":"InvoiceSettled","invoiceId":"inv-1"}'
        sig = "sha256=" + hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
        self.assertTrue(self.mod.verify_btcpay_webhook_signature({"btcpay-sig": sig}, body))
        self.assertTrue(self.mod.btcpay_enabled())

    def test_the_public_nodes_payload_names_the_offered_chains(self):
        # FLEET1 Turn 2 (Astra): the website's crypto-config proxy reads GET
        # /nodes, so the per-chain offer must be there too.
        for chains, enabled, offered in (("BTC", True, ["BTC"]), ("BTC,DASH", True, ["BTC", "DASH"]),
                                         ("none", False, []), ("LTC", False, [])):
            with self.subTest(chains=chains):
                self.mod.BTCPAY_CHECKOUT_CHAINS = chains
                body = self.mod._list_public_nodes_sync()
                self.assertIs(body["crypto_enabled"], enabled)
                self.assertEqual(body["btcpay_chains"], offered)
        self.mod.BTCPAY_API_KEY = ""
        self.mod.BTCPAY_CHECKOUT_CHAINS = "BTC"
        self.assertEqual(self.mod._list_public_nodes_sync()["btcpay_chains"], [])

    def test_every_offer_surface_uses_the_checkout_gate(self):
        src = harness._extract_main_block()
        self.assertEqual(src.count('"crypto_enabled": btcpay_checkout_enabled(),'), 1)
        self.assertEqual(src.count('"cryptoenabled": btcpay_checkout_enabled(),'), 1)
        self.assertNotIn('"crypto_enabled": btcpay_enabled()', src)
        start = src.index("def _crypto_create_invoice_sync(")
        self.assertIn("if not btcpay_checkout_enabled():", src[start:src.index("\ndef ", start + 10)])


if __name__ == "__main__":
    unittest.main()
