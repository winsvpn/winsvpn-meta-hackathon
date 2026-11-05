#!/usr/bin/env python3
"""Round 7 security regressions against the generated hub and real SQLite.

The shared harness stubs FastAPI/Pydantic and calendar arithmetic. Node I/O
and price feeds are deterministic fakes; no production service is contacted.
"""
import _toolchain  # noqa: F401
import asyncio
from contextlib import closing
from datetime import timedelta
from decimal import Decimal
import logging
import shutil
import sqlite3
import threading
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving


class Round7Tests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.mod.sync_peer_to_node = lambda *args, **kwargs: True
        self.tokens = harness.seed_account(self.mod, devices=1)
        self.device, self.token = next(iter(self.tokens.items()))
        serving.seed_node(self.mod, slug="test-node")
        self.mod.MONERO_PRICE_MANUAL_USD = ""
        self.mod.MONERO_PRICE_MAX_DEVIATION = Decimal("0.20")
        with self.mod.get_db() as conn:
            self.secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def request(self, token=None, path="/account/status", body=None):
        headers = {"content-type": "application/json"}
        if token is not None:
            headers["authorization"] = f"Bearer {token}"
        return harness.FakeRequest(path=path, headers=headers, body=body)

    def status(self, token=None, device=None, account=harness.ACCOUNT):
        return self.mod._account_status_sync(
            self.mod.AccountStatusRequest(account_number=account, device_id=device),
            self.request(token), harness.BackgroundTasks(),
        )

    def login(self, **overrides):
        fields = dict(device_id="round7-device", device_fingerprint="round7-fingerprint",
                      device_model="audit-harness", location="test-node",
                      selection_generation="a" * 32,
                      ordinary_v3_failure_generation="a" * 32)
        fields.update(overrides)
        return serving.build_login(self.mod, **fields)

    def admission(self, token=None, **overrides):
        request = self.request(token, path="/verify")
        if token is None:
            request.headers["x-wins-activation"] = self.secret
        return asyncio.run(self.mod.verify_account(
            request, self.login(**overrides), harness.BackgroundTasks(),
        ))

    def quote(self, values, baseline=Decimal(0), urls=None):
        self.mod.MONERO_PRICE_SOURCE_URLS = urls or [
            f"https://feed{i}.example.test/price" for i in range(len(values))
        ]
        with patch.object(self.mod, "fetch_bounded_monero_price", side_effect=values):
            return self.mod.resolve_monero_usd_per_xmr(last_quote=baseline)

    def test_quote_consensus_requires_all_independent_sources_to_agree(self):
        for values in ([Decimal(100), Decimal(1000)],
                       [Decimal(100), Decimal(101), Decimal(1000)]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.quote(values)
        self.assertEqual(self.quote([Decimal(100), Decimal(120)])[0], Decimal(110))
        with self.assertRaises(RuntimeError):
            self.quote([Decimal(100), Decimal("120.0001")])

    def test_quote_medians_average_even_counts_and_keep_odd_middle(self):
        for values, expected in (([100, 110], 105), ([100, 110, 120], 110),
                                 ([120, 100, 110, 106], 108)):
            with self.subTest(values=values):
                price, source = self.quote(list(map(Decimal, values)))
                self.assertEqual(price, expected)
                self.assertTrue(source.startswith("median:"))

    def test_duplicate_hostname_paths_ports_and_case_cannot_create_quorum(self):
        urls = ["https://FEED.example.test/one", "https://feed.example.test:443/two",
                "https://feed.example.test./three"]
        with self.assertRaises(RuntimeError):
            self.quote([Decimal(100)], urls=urls)
        price, source = self.quote([Decimal(100)], baseline=Decimal(100), urls=urls)
        self.assertEqual((price, source), (Decimal(100), "feed.example.test"))

    def test_nonfinite_quotes_manual_prices_and_baselines_are_not_trusted(self):
        for raw in ("NaN", "sNaN", "Infinity", "-Infinity", "0", "-1"):
            with self.subTest(raw=raw):
                self.assertIsNone(self.mod._to_positive_decimal(raw))
                with self.assertRaises(RuntimeError):
                    self.mod.resolve_monero_usd_per_xmr(manual_hint=raw)
                with self.assertRaises(RuntimeError):
                    self.quote([Decimal(raw), Decimal(100)])
                with self.assertRaises(RuntimeError):
                    self.quote([Decimal(100)], baseline=Decimal(raw))

    def test_single_source_and_consensus_obey_persisted_baseline(self):
        self.assertEqual(self.quote([Decimal(120)], Decimal(100))[0], 120)
        for values in ([Decimal(121)], [Decimal(121), Decimal(122)]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                self.quote(values, Decimal(100))
        with self.assertRaises(RuntimeError):
            self.quote([Decimal(100)])

    def test_decimal_overflow_is_a_controlled_quote_failure(self):
        with self.assertRaises(RuntimeError):
            self.quote([Decimal("1e9999999"), Decimal("1e-9999999")])

    def test_stale_removal_and_outbox_commit_together_without_background_runner(self):
        self.mod.STALE_DEVICE_RETENTION_DAYS = 1
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET last_seen=?", (
                (self.mod.utcnow() - timedelta(days=2)).isoformat(),))
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod.cleanup_stale_devices(conn), 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 1)
            conn.rollback()
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 0)
            tasks = harness.BackgroundTasks()
            self.mod.cleanup_stale_devices(conn, tasks)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 1)
        self.assertEqual(tasks.tasks[0][0], self.mod.drain_peer_revocation_outbox)
        with patch.object(self.mod, "remove_peer_from_node", return_value=True) as remove:
            self.mod.drain_peer_revocation_outbox()
            remove.assert_called_once()
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 0)

    def test_slot_replacement_returns_fresh_bearer_and_rejects_the_old_one(self):
        self.mod.DEVICE_LIMIT = 1
        response = self.admission()
        fresh = response["device_auth_token"]
        self.assertNotEqual(fresh, self.token)
        with self.mod.get_db() as conn:
            rows = conn.execute("SELECT device_id, device_auth_token_hash FROM devices").fetchall()
            self.assertEqual(len(rows), 1)
            self.assertEqual(tuple(rows[0]), ("round7-device", self.mod.token_digest(fresh)))
        with self.assertRaises(harness.HTTPException) as error:
            self.status(self.token, "round7-device")
        self.assertEqual(error.exception.status_code, 401)
        self.assertEqual(self.status(fresh, "round7-device")["status"], "ok")
        self.assertNotIn("device_auth_token", self.admission(token=fresh))

    def test_failed_direct_sync_preserves_existing_device_and_activation_for_retry(self):
        self.mod.DEVICE_LIMIT = 1
        with self.mod.get_db() as conn:
            before = dict(conn.execute("SELECT * FROM devices").fetchone())
        with patch.object(self.mod, "sync_peer_to_node", return_value=False):
            with self.assertRaises(harness.HTTPException) as error:
                self.admission()
        self.assertEqual(error.exception.status_code, 503)
        with self.mod.get_db() as conn:
            self.assertEqual(dict(conn.execute("SELECT * FROM devices").fetchone()), before)
            self.assertIsNone(conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0])
            self.assertEqual(conn.execute("SELECT management_status FROM nodes").fetchone()[0], "failed")
        serving.seed_node(self.mod, slug="test-node")
        self.assertTrue(self.admission()["device_auth_token"])

    def test_failed_double_exit_sync_rolls_back_assignments_and_activation(self):
        core = {"core_id": "test-core", "exit_public_key": "D" * 43 + "="}
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO core_servers (core_id) VALUES (?)", (core["core_id"],))
            before = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        with patch.object(self.mod, "select_double_vpn_core", return_value=core), \
                patch.object(self.mod, "sync_peer_to_node", return_value=False) as sync:
            with self.assertRaises(harness.HTTPException) as error:
                self.admission(double_vpn=True)
        self.assertEqual(error.exception.status_code, 503)
        self.assertEqual(sync.call_args.args[1]["client_public_key"], core["exit_public_key"])
        with self.mod.get_db() as conn:
            self.assertIsNone(conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], before)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM double_vpn_assignments").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM core_exit_peers").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT management_status FROM nodes").fetchone()[0], "failed")

    def test_status_requires_matching_account_device_and_bearer(self):
        other = harness.seed_account(self.mod, account="4444-5555-6666", devices=1)
        for token, device, account in (
            (None, self.device, harness.ACCOUNT), ("wrong", self.device, harness.ACCOUNT),
            (next(iter(other.values())), self.device, harness.ACCOUNT),
            (self.token, None, harness.ACCOUNT), (self.token, "missing", harness.ACCOUNT),
            (self.token, self.device, "0000-1111-2222"),
        ):
            with self.subTest(device=device, account=account), \
                    self.assertRaises(harness.HTTPException) as error:
                self.status(token, device, account)
            self.assertEqual((error.exception.status_code, error.exception.detail), (401, "Unauthorized"))
        self.assertEqual(self.status(self.token, self.device)["status"], "ok")

    def test_invalid_expirations_revoke_on_status_and_cannot_be_migrated_to_active(self):
        for raw in (None, "", " ", "not-a-date", "2026-99-99", "99999-01-01", "Lifetime Access"):
            with self.subTest(raw=raw):
                tokens = harness.seed_account(self.mod, devices=1)
                device, token = next(iter(tokens.items()))
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE users SET expiration_date=?", (raw,))
                self.assertEqual(self.status(token, device)["status"], "expired")
                with self.mod.get_db() as conn:
                    self.assertEqual(conn.execute("SELECT status FROM users").fetchone()[0], "expired")
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
                    self.assertGreater(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], 0)

    def test_invalid_expiration_rejected_before_admission_and_after_writer_recheck(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date='not-a-date'")
        with self.assertRaises(harness.HTTPException) as error:
            self.admission()
        self.assertEqual(error.exception.status_code, 401)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT status FROM users").fetchone()[0], "expired")
            conn.execute("UPDATE users SET status='active', expiration_date='2030-01-01'")
        original = self.mod.expire_account_runtime_if_due
        calls = []

        def change_before_recheck(conn, *args):
            calls.append(1)
            if len(calls) == 2:
                conn.execute("UPDATE users SET expiration_date='not-a-date'")
            return original(conn, *args)

        with patch.object(self.mod, "expire_account_runtime_if_due", side_effect=change_before_recheck):
            with self.assertRaises(harness.HTTPException):
                self.admission()
        self.assertEqual(len(calls), 2)
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT status FROM users").fetchone()[0], "expired")

    def test_free_access_stores_parseable_expiry_and_preserves_display_label(self):
        self.mod.FREE_ACCESS_ENABLED = True
        request = harness.FakeRequest(path="/free/verify")
        free = self.mod.FreeAccessRequest(**vars(self.login()))
        response = asyncio.run(self.mod.verify_free_access(request, free, harness.BackgroundTasks()))
        self.assertEqual(response["expiration_date"], self.mod.FREE_ACCESS_LABEL)
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT expiration_date FROM users WHERE renewal_source='free_access'").fetchone()
            self.assertGreater(self.mod.parse_iso_datetime(row[0]), self.mod.utcnow())

    def test_duration_accepts_only_bounded_terms(self):
        for raw, expected in (("1d", {"days": 1}), ("3650d", {"days": 3650}),
                              ("1m", {"months": 1}), ("120m", {"months": 120}),
                              ("1y", {"years": 1}), ("10y", {"years": 10}),
                              ("life", {"years": 10}), (" LIFETIME ", {"years": 10})):
            with self.subTest(raw=raw):
                self.assertEqual(self.mod.parse_duration(raw).kw, expected)
        for raw in (None, "", "typo", "0d", "-1m", "01y", "11y", "121m", "3651d",
                    "99999d", "1.5m", "1w", "1m garbage", "1\nd", 12, "1" * 10000 + "y"):
            with self.subTest(raw=str(raw)[:30]), self.assertRaises(self.mod.DurationParseError):
                self.mod.parse_duration(raw)

    def test_invalid_admin_durations_return_400_before_database_changes(self):
        for route in ("provision", "renew", "redemption/batch"):
            for duration in ("", "mistyped", "0d", "3651d", "121m", "11y"):
                with self.subTest(route=route, duration=duration):
                    request = harness.FakeRequest(path=f"/admin/{route}")
                    kwargs = dict(request=request, duration=duration, x_admin_token="test-admin-token")
                    with patch.object(self.mod, "get_db", side_effect=AssertionError("invalid term reached database")):
                        with self.assertRaises(harness.HTTPException) as error:
                            if route == "provision":
                                self.mod.provision_account(
                                    background_tasks=harness.BackgroundTasks(),
                                    name="Test", email="new@example.test", **kwargs)
                            elif route == "renew":
                                self.mod.renew_account(account_number=harness.ACCOUNT, **kwargs)
                            else:
                                self.mod.admin_issue_redemption_batch(
                                    batch_id="test-batch", count=1, **kwargs)
                    self.assertEqual(error.exception.status_code, 400)

    def test_deletion_routes_parse_on_loop_and_keep_it_responsive_under_writer_lock(self):
        for action in ("status", "request", "confirm", "cancel"):
            with self.subTest(action=action):
                locked = threading.Event()
                release = threading.Event()
                main_thread = threading.get_ident()
                body_threads = []

                class Request(harness.FakeRequest):
                    async def json(self):
                        body_threads.append(threading.get_ident())
                        return await super().json()

                def hold_writer():
                    with closing(sqlite3.connect(self.mod._DB)) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        locked.set()
                        release.wait(timeout=0.6)
                        conn.rollback()

                writer = threading.Thread(target=hold_writer)
                writer.start()
                self.assertTrue(locked.wait(timeout=5))
                path = f"/account/deletion/{action}"
                request = Request(path=path, headers={"content-type": "application/json"},
                                  body={"account_number": harness.ACCOUNT, "device_id": self.device})

                async def exercise():
                    task = asyncio.create_task(self.mod.app.routes[("POST", path)](
                        request, harness.BackgroundTasks()))
                    ticks = 0
                    while not task.done():
                        await asyncio.sleep(0.02)
                        if not task.done():
                            ticks += 1
                    with self.assertRaises(harness.HTTPException) as error:
                        await task
                    self.assertEqual(error.exception.status_code, 401)
                    return ticks

                try:
                    self.assertGreaterEqual(asyncio.run(exercise()), 3)
                    self.assertEqual(body_threads, [main_thread])
                finally:
                    release.set()
                    writer.join(timeout=5)
                self.assertFalse(writer.is_alive())


if __name__ == "__main__":
    unittest.main()
