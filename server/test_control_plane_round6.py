#!/usr/bin/env python3
"""Round 6 regressions using the generated hub and isolated SQLite files."""
import _toolchain  # noqa: F401
import asyncio
from contextlib import closing
import logging
import shutil
import sqlite3
import threading
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class Round6Tests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.mod.BTCPAY_URL = "https://pay.example.test"
        self.mod.btcpay_enabled = lambda: True
        self.mod.CRYPTO_PRICE_1M = "1.00"
        self.tokens = harness.seed_account(self.mod, devices=1)
        with self.mod.get_db() as conn:
            conn.execute("SELECT 1")

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def test_checkout_normalizes_only_the_same_origin(self):
        for base, raw, expected in (
            ("https://pay.example.test/base", "HTTPS://PAY.EXAMPLE.TEST:443/i/123?q=1#pay",
             "https://pay.example.test/i/123?q=1#pay"),
            ("https://pay.example.test", "https://pay.example.test./i/123",
             "https://pay.example.test/i/123"),
            ("https://pay.example.test:8443", "https://pay.example.test:8443/i/123",
             "https://pay.example.test:8443/i/123"),
            ("https://xn--bcher-kva.example", "https://b\u00fccher.example/i/123",
             "https://xn--bcher-kva.example/i/123"),
            ("https://[2001:db8::1]", "https://[2001:0db8::1]:443/i/123",
             "https://[2001:db8::1]/i/123"),
        ):
            with self.subTest(raw=raw):
                self.mod.BTCPAY_URL = base
                self.assertEqual(self.mod.validated_btcpay_checkout_url(raw), expected)

    def test_checkout_rejects_unsafe_urls_and_invalid_configuration(self):
        invalid = (
            "", None, 123, "http://pay.example.test/i", "//pay.example.test/i",
            "https://evil.example/i", "https://pay.example.test.evil.example/i",
            "https://pay.example.test:8443/i", "https://pay.example.test:0/i",
            "https://pay.example.test:65536/i", "https://pay.example.test:bad/i",
            "https://pay.example.test:/i", "https://user@pay.example.test/i",
            "https://user:secret@pay.example.test/i", "https://@pay.example.test/i",
            "https://pay.example.test\\@evil.example/i", "https://pay.example.test\n/i",
            " https://pay.example.test/i", "https://pay.example.test/%00\t",
            "https://pay.example.test%2f.evil.example/i", "https://[::1]suffix/i",
            "https://[::1/i", "https://pay..example.test/i", "https://-bad.example/i",
            "https://bad_.example/i", "https:///i", "javascript:alert(1)",
        )
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    self.mod.validated_btcpay_checkout_url(raw)
        for base in ("http://pay.example.test", "https://user@pay.example.test",
                     "https://pay.example.test\n", "https://bad_.example"):
            with self.subTest(base=base):
                self.mod.BTCPAY_URL = base
                with self.assertRaises(ValueError):
                    self.mod.validated_btcpay_checkout_url("https://pay.example.test/i")

    def test_rejected_checkout_order_cannot_become_pending(self):
        self.mod.btcpay_create_invoice = lambda *args: {
            "id": "invoice_12345", "checkoutLink": "https://evil.example/i/12345",
        }
        request = harness.FakeRequest(path="/pay/crypto/create-invoice")
        invoice = self.mod.CryptoInvoiceRequest(plan_key="one_month")
        with self.assertLogs(self.mod.logger, level="WARNING") as logs:
            with self.assertRaises(harness.HTTPException) as error:
                self.mod._crypto_create_invoice_sync(invoice, request)
        self.assertEqual(error.exception.status_code, 502)
        self.assertTrue(any("invalid checkout origin" in line for line in logs.output))
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT status, provider_order_id FROM payment_orders").fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertFalse(row["provider_order_id"])

    def test_valid_checkout_is_bound_before_response(self):
        self.mod.btcpay_create_invoice = lambda *args: {
            "id": "invoice_12345", "checkoutLink": "https://pay.example.test/i/12345",
        }
        result = self.mod._crypto_create_invoice_sync(
            self.mod.CryptoInvoiceRequest(plan_key="one_month"),
            harness.FakeRequest(path="/pay/crypto/create-invoice"),
        )
        self.assertEqual(result["checkout_url"], "https://pay.example.test/i/12345")
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT status, provider_order_id FROM payment_orders").fetchone()
        self.assertEqual(tuple(row), ("pending", "invoice_12345"))

    def test_logout_endpoints_keep_event_loop_responsive_under_writer_lock(self):
        for route in ("/logout", "/free/logout"):
            with self.subTest(route=route):
                locked = threading.Event()
                release = threading.Event()

                def hold_writer():
                    with closing(sqlite3.connect(self.mod._DB)) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        locked.set()
                        release.wait(timeout=0.6)
                        conn.rollback()

                writer = threading.Thread(target=hold_writer)
                writer.start()
                self.assertTrue(locked.wait(timeout=5))
                request = harness.FakeRequest(
                    path=route, headers={"content-type": "application/json"},
                    body={"account_number": harness.ACCOUNT, "device_id": "round6-device"},
                )

                async def exercise():
                    task = asyncio.create_task(self.mod.app.routes[("POST", route)](
                        harness.BackgroundTasks(), request,
                    ))
                    ticks = 0
                    while not task.done():
                        await asyncio.sleep(0.02)
                        if not task.done():
                            ticks += 1
                    try:
                        await task
                    except harness.HTTPException as exc:
                        self.assertIn(exc.status_code, (400, 401, 403, 404))
                    return ticks

                try:
                    self.assertGreaterEqual(asyncio.run(exercise()), 3)
                finally:
                    release.set()
                    writer.join(timeout=5)
                self.assertFalse(writer.is_alive())

    def test_logout_preserves_authentication_and_deletes_only_authenticated_device(self):
        device, token = next(iter(self.tokens.items()))
        for supplied, status in (("wrong-token", 401), (token, 200)):
            request = harness.FakeRequest(
                path="/logout", headers={"content-type": "application/json",
                                          "authorization": f"Bearer {supplied}"},
                body={"account_number": harness.ACCOUNT, "device_id": device},
            )
            operation = self.mod.logout_device(harness.BackgroundTasks(), request)
            if status == 401:
                with self.assertRaises(harness.HTTPException) as error:
                    asyncio.run(operation)
                self.assertEqual(error.exception.status_code, status)
            else:
                self.assertEqual(asyncio.run(operation), {"ok": True})
            with self.mod.get_db() as conn:
                count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            self.assertEqual(count, int(status == 401))

    def test_security_event_connections_commit_and_close_on_success_and_failure(self):
        connections = []
        real_connect = sqlite3.connect

        def connect(*args, **kwargs):
            conn = real_connect(*args, **kwargs)
            connections.append(conn)
            return conn

        with patch.object(self.mod.sqlite3, "connect", side_effect=connect):
            event_id = self.mod.record_security_event(2, "test", "192.0.2.1", "/test", {}, "queued")
            self.mod.update_security_event_email_status(event_id, "sent")
            with patch.object(self.mod, "ensure_security_events_db", side_effect=RuntimeError("test failure")):
                self.mod.record_security_event(2, "test", "192.0.2.1", "/test", {}, "queued")
            with closing(real_connect(self.mod.SECURITY_EVENTS_DB)) as conn:
                self.assertEqual(conn.execute("SELECT email_status FROM security_events WHERE event_id=?",
                                              (event_id,)).fetchone()[0], "sent")
                conn.execute("DROP TABLE security_events")
                conn.commit()
            self.mod.update_security_event_email_status(event_id, "failed")
        self.assertEqual(len(connections), 4)
        for conn in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
