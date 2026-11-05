#!/usr/bin/env python3
"""Round 4 regressions against the installer's real hub and isolated SQLite.

Only external peer provisioning is stubbed. No production service is used.
"""
import _toolchain  # noqa: F401
import asyncio
import contextlib
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


class ControlPlaneRound4Tests(unittest.TestCase):
    def setUp(self):
        def discard_file_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=discard_file_handlers):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        harness.seed_account(self.mod, devices=0)
        serving.seed_node(self.mod)
        self.mod.sync_peer_to_node = lambda *args, **kwargs: True
        self.mod.paypal_enabled = lambda: False
        self.mod.security_alert = lambda *args, **kwargs: None
        with self.mod.get_db() as conn:
            self.secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def login(self, number=1, **overrides):
        fields = dict(
            device_id=f"round4-device-{number:016d}",
            device_fingerprint=f"round4-fp-{number:016d}",
            device_model="audit-harness",
            selection_generation="a" * 32,
            ordinary_v3_failure_generation="a" * 32,
        )
        fields.update(overrides)
        return serving.build_login(self.mod, **fields)

    def admission(self, number=1, headers=None):
        return self.mod.verify_account(
            harness.FakeRequest(
                path="/verify",
                headers=headers or {"x-wins-activation": self.secret},
            ),
            self.login(number),
            harness.BackgroundTasks(),
        )

    def used_and_count(self):
        with self.mod.get_db() as conn:
            used = conn.execute(
                "SELECT activation_secret_used_at FROM users WHERE account_number=?",
                (harness.ACCOUNT,),
            ).fetchone()[0]
            count = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        return used, count

    def test_sequential_replay_is_rejected(self):
        self.assertTrue(asyncio.run(self.admission())["device_auth_token"])
        with self.assertRaises(harness.HTTPException) as error:
            asyncio.run(self.admission(2))
        self.assertEqual(error.exception.status_code, 401)
        used, count = self.used_and_count()
        self.assertIsNotNone(used)
        self.assertEqual(count, 1)

    def test_four_concurrent_devices_have_exactly_one_consumer(self):
        barrier = threading.Barrier(4)

        def activate(number):
            barrier.wait(timeout=10)
            try:
                asyncio.run(self.admission(number))
                return 200
            except harness.HTTPException as error:
                return error.status_code

        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(activate, range(1, 5)))
        self.assertEqual(sorted(statuses), [200, 401, 401, 401])
        self.assertEqual(self.used_and_count()[1], 1)

    def test_used_expired_and_malformed_keys_reject_without_admission(self):
        for used, expiry in (
            ("already-used", (self.mod.now_utc() + timedelta(hours=1)).isoformat()),
            (None, (self.mod.now_utc() - timedelta(seconds=1)).isoformat()),
            (None, "not-a-timestamp"),
        ):
            with self.subTest(used=used, expiry=expiry):
                with self.mod.get_db() as conn:
                    conn.execute(
                        "UPDATE users SET activation_secret_used_at=?, "
                        "activation_secret_expires_at=? WHERE account_number=?",
                        (used, expiry, harness.ACCOUNT),
                    )
                with self.assertRaises(harness.HTTPException) as error:
                    asyncio.run(self.admission())
                self.assertEqual(error.exception.status_code, 401)
                self.assertEqual(self.used_and_count()[1], 0)

    def test_bearer_reconnect_does_not_consume_a_new_activation_key(self):
        response = asyncio.run(self.admission())
        bearer = response["device_auth_token"]
        with self.mod.get_db() as conn:
            self.mod.issue_activation_secret(conn, harness.ACCOUNT)
        for _ in range(4):
            asyncio.run(self.admission(headers={"authorization": f"Bearer {bearer}"}))
        self.assertEqual(self.used_and_count(), (None, 1))

    def test_failed_admission_rolls_back_consumption_and_can_retry(self):
        with patch.object(
            self.mod,
            "ensure_legal_acceptance_for_activation",
            side_effect=harness.HTTPException(409, "injected legal failure"),
        ):
            with self.assertRaises(harness.HTTPException) as error:
                asyncio.run(self.admission())
        self.assertEqual(error.exception.status_code, 409)
        self.assertEqual(self.used_and_count(), (None, 0))
        self.assertTrue(asyncio.run(self.admission())["device_auth_token"])

    def test_unauthorized_account_cannot_inject_verify_log_lines(self):
        raw_account = "1111-2222-3333\nROUND4_FORGED_LOG"
        with self.assertLogs(self.mod.logger, level=logging.INFO) as captured:
            with self.assertRaises(harness.HTTPException):
                asyncio.run(self.mod.verify_account(
                    harness.FakeRequest(path="/verify"),
                    self.login(account_number=raw_account),
                    harness.BackgroundTasks(),
                ))
        verify_logs = [line for line in captured.output if "Verify request received:" in line]
        self.assertEqual(len(verify_logs), 1)
        self.assertNotIn(raw_account, verify_logs[0])
        self.assertNotIn("ROUND4_FORGED_LOG", verify_logs[0])
        self.assertNotIn("\n", verify_logs[0])
        self.assertIn("account_hash=" + self.mod.security_event_hash(
            self.mod.normalize_account_number(raw_account)), verify_logs[0])

    def test_sqlite_writer_lock_does_not_stall_unrelated_async_requests(self):
        async def exercise(name):
            blocker = sqlite3.connect(self.mod._DB, check_same_thread=False)
            blocker.execute("BEGIN IMMEDIATE")

            def release():
                blocker.rollback()
                blocker.close()

            timer = threading.Timer(0.35, release)
            timer.start()

            async def tick():
                start = time.monotonic()
                await asyncio.sleep(0.01)
                return time.monotonic() - start

            ticker = asyncio.create_task(tick())
            await asyncio.sleep(0)
            try:
                start = time.monotonic()
                if name == "verify":
                    await self.admission()
                elif name == "free_status":
                    await self.mod.free_status()
                else:
                    await self.mod.payment_redirect(
                        "one_month", harness.FakeRequest(path="/pay/one_month")
                    )
                elapsed = time.monotonic() - start
                if name == "free_status":
                    # A public read on a settled hub is a WAL reader
                    # (ensure_schema and mark_stale_nodes_offline take no
                    # write lock when nothing changed), so it returns before
                    # the blocker releases its lock instead of waiting on it.
                    self.assertLess(elapsed, 0.25)
                else:
                    self.assertGreater(elapsed, 0.25)
                self.assertLess(await ticker, 0.15)
            finally:
                timer.join()

        for name in ("verify", "free_status", "payment"):
            with self.subTest(handler=name):
                asyncio.run(exercise(name))

    def test_remaining_public_handlers_open_sqlite_on_a_worker(self):
        main_thread = threading.get_ident()
        original_db = self.mod.get_db
        visited = []

        @contextlib.contextmanager
        def observed_db():
            visited.append(threading.get_ident())
            with original_db() as conn:
                yield conn

        free_request = self.mod.FreeAccessRequest(**vars(self.login()))
        free_request.hardware_fingerprint = "round4-free-fingerprint"
        self.mod.FREE_ACCESS_ENABLED = True
        self.mod.DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = 0
        calls = (
            lambda: self.mod.wait_for_core_assignment_ready("core", "device", "a" * 64),
            lambda: self.mod.render_referral_landing("ABC123", harness.FakeRequest(path="/r/ABC123")),
            lambda: self.mod.verify_free_access(
                harness.FakeRequest(path="/free/verify"), free_request, harness.BackgroundTasks()
            ),
        )
        with patch.object(self.mod, "get_db", observed_db):
            for call in calls:
                visited.clear()
                with self.subTest(handler=call):
                    try:
                        asyncio.run(call())
                    except harness.HTTPException as error:
                        self.assertIn(error.status_code, (404, 503))
                    self.assertTrue(visited, "handler never reached SQLite")
                    self.assertNotIn(main_thread, visited)


if __name__ == "__main__":
    unittest.main()
