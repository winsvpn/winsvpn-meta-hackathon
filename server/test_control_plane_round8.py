#!/usr/bin/env python3
"""Round 8 regressions against generated hub code and real SQLite.

The shared harness supplies framework stubs. All gateway and provider I/O is
mocked. Transactions, persisted queues, races and retry behavior are real.
"""
import _toolchain  # noqa: F401
import ast
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import inspect
import logging
import shutil
import threading
import time
import types
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_hoppy_agent_tier1_hub as hoppy
import test_winn3_serving_hub as serving


class Round8Tests(unittest.TestCase):
    def setUp(self):
        def close_handlers(**kwargs):
            for handler in kwargs.get("handlers", []):
                handler.close()

        with patch("logging.basicConfig", side_effect=close_handlers):
            self.mod = harness.load_hub(
                HOPPY_AGENT_HMAC=hoppy.HMAC, DURABILITY_BARRIER_ENABLED=0,
                DURABILITY_BARRIER_REQUIRED=0, WINN3_INNER_POOL_CIDR="10.10.0.0/24",
                WINN3_CANARY_NODE_SLUG="",
            )
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.tokens = harness.seed_account(self.mod, devices=1)
        self.device, self.token = next(iter(self.tokens.items()))
        serving.seed_node(self.mod, slug="test-node")
        self.remote = patch.object(self.mod.subprocess, "run", side_effect=AssertionError("unexpected node I/O"))
        self.remote.start()
        self.provider = patch.object(self.mod, "paypal_json_request", side_effect=AssertionError("unexpected provider I/O"))
        self.provider.start()
        self.addCleanup(self.remote.stop)
        self.addCleanup(self.provider.stop)
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute(
                "INSERT INTO payment_orders "
                "(hub_order_id,provider,provider_order_id,plan_key,expected_amount,expected_currency,status,created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                ("round8-hub", "paypal_wallet", "ROUND8-ORDER", "lifetime_no_support",
                 "99.00", "USD", "pending", self.mod.utcnow().isoformat()),
            )

    def tearDown(self):
        for handler in list(self.mod.logger.handlers):
            handler.close()
            self.mod.logger.removeHandler(handler)
        shutil.rmtree(self.mod._TMPDIR)

    def bind_v3(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/3' WHERE slug='test-node'")
            conn.execute("UPDATE devices SET winn3_static_public=?, winn3_inner_v4=?",
                         (base64.b64encode(bytes(range(32))).decode(), "10.10.0.2"))

    def pending(self):
        with self.mod.get_db() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM winn3_registry_refreshes ORDER BY node_slug")]

    def clear_refreshes(self):
        with self.mod.get_db() as conn:
            conn.execute("DELETE FROM winn3_registry_refreshes")

    def capture(self):
        return self.mod._wallet_capture_sync(
            self.mod.WalletCaptureRequest(order_id="ROUND8-ORDER"),
            harness.FakeRequest(path="/pay/wallet/capture"))

    def event_status(self):
        with self.mod.get_db() as conn:
            return conn.execute("SELECT status FROM paypal_events WHERE event_id=?",
                                ("wallet-capture:ROUND8-ORDER",)).fetchone()[0]

    def test_customer_exports_reject_invalid_past_and_exact_expiry(self):
        self.bind_v3()
        now = self.mod.utcnow()
        for expiry in (None, "", "invalid", "LIFETIME ACCESS", (now - timedelta(seconds=1)).isoformat(), now.isoformat()):
            with self.subTest(expiry=expiry), patch.object(self.mod, "utcnow", return_value=now):
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE users SET expiration_date=?", (expiry,))
                    self.assertEqual(self.mod.winn3_peer_registry_document(conn, "test-node")["peers"], [])
                with patch.object(self.mod, "sync_peer_to_node", return_value=True) as sync, patch.object(
                    self.mod, "sync_winn3_registry_to_node", return_value=True
                ):
                    self.mod.resync_active_peers_to_node("test-node")
                    sync.assert_not_called()
        future = now + timedelta(days=1)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE users SET expiration_date=?", (future.isoformat(),))
            peers = self.mod.winn3_peer_registry_document(conn, "test-node")["peers"]
            self.assertEqual(len(peers), 1)
            self.assertEqual(peers[0]["not_after"], int(future.timestamp()))

    def test_registry_queue_is_seeded_once_and_survives_reinitialization(self):
        self.bind_v3()
        with self.mod.get_db() as conn:
            conn.execute("DROP TABLE winn3_registry_refreshes")
            self.mod.create_winn3_registry_refresh_table(conn)
            self.assertEqual(conn.execute("SELECT node_slug FROM winn3_registry_refreshes").fetchone()[0], "test-node")
            conn.execute("UPDATE winn3_registry_refreshes SET attempts=3, next_attempt_at=12345")
            self.mod.create_winn3_registry_refresh_table(conn)
        self.assertEqual(self.pending()[0]["attempts"], 3)

    def test_core_exports_require_future_expiration(self):
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO core_servers(core_id, exit_public_key) VALUES('test-core', 'core-key')")
            conn.execute("INSERT INTO core_exit_peers(core_id, exit_slug, core_exit_ip, table_id, iface) VALUES('test-core', 'test-node', '10.8.1.3', 100, 'exit0')")
            conn.execute("INSERT INTO double_vpn_assignments(device_id, account_number, core_id, exit_slug, client_public_key, client_ip) VALUES(?, ?, 'test-core', 'test-node', 'client-key', '10.9.0.2')",
                         (self.device, harness.ACCOUNT))
        now = self.mod.utcnow()
        for expiry in (None, "", "invalid", "LIFETIME ACCESS", now.isoformat(), (now + timedelta(days=1)).isoformat()):
            valid = expiry == (now + timedelta(days=1)).isoformat()
            with self.subTest(expiry=expiry), patch.object(self.mod, "utcnow", return_value=now):
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE users SET expiration_date=?", (expiry,))
                    self.assertEqual(len(self.mod.active_core_assignment_payloads(conn, "test-core")), int(valid))
                with patch.object(self.mod, "sync_peer_to_node", return_value=True) as sync:
                    self.mod.resync_active_peers_to_node("test-node")
                    if not valid:
                        sync.assert_not_called()

    def test_reconnect_and_duplicate_deletions_queue_each_removed_peer(self):
        for kind in ("hardware", "model", "key_rotation"):
            with self.subTest(kind=kind):
                tokens = harness.seed_account(self.mod, devices=2)
                device = next(iter(tokens))
                fingerprint = "round8-same-hardware"
                with self.mod.get_db() as conn:
                    conn.execute("DELETE FROM peer_revocations")
                    if kind == "hardware":
                        conn.execute("UPDATE devices SET hardware_hash=?",
                                     (self.mod.device_identity_bucket(fingerprint),))
                    if kind == "model":
                        conn.execute("UPDATE devices SET device_model='Round8 Phone'")
                    old_keys = {row[0] for row in conn.execute("SELECT client_public_key FROM devices")}
                    activation = self.mod.issue_activation_secret(conn, harness.ACCOUNT)
                login = serving.build_login(
                    self.mod, device_id=device, device_fingerprint=fingerprint,
                    device_model="Round8 Phone" if kind == "model" else "audit-harness",
                    location="test-node", selection_generation="a" * 32,
                    ordinary_v3_failure_generation="a" * 32,
                    client_public_key=base64.b64encode(b"k" * 32).decode(),
                )
                request = harness.FakeRequest(path="/verify", headers={"x-wins-activation": activation})
                with patch.object(self.mod, "sync_peer_to_node", return_value=True):
                    asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
                with self.mod.get_db() as conn:
                    queued = {row[0] for row in conn.execute("SELECT client_public_key FROM peer_revocations")}
                    expected = old_keys if kind != "key_rotation" else {"PUBLIC-KEY-" + device}
                    self.assertEqual(queued, expected)

    def test_triggered_device_move_key_rotation_and_account_updates(self):
        self.bind_v3()
        for statement, params, expected in (
            ("UPDATE devices SET location_slug=?", ("other-node",), ["other-node", "test-node"]),
            ("UPDATE devices SET winn3_static_public=''", (), ["other-node"]),
            ("UPDATE devices SET winn3_static_public=?", (base64.b64encode(b"x" * 32).decode(),), ["other-node"]),
            ("UPDATE devices SET winn3_inner_v4=?", ("10.10.0.3",), ["other-node"]),
            ("UPDATE users SET status='inactive'", (), ["other-node"]),
            ("UPDATE users SET expiration_date=?", ("2020-01-01T00:00:00Z",), ["other-node"]),
            ("DELETE FROM devices", (), ["other-node"]),
        ):
            self.clear_refreshes()
            with self.subTest(statement=statement), self.mod.get_db() as conn:
                conn.execute(statement, params)
            self.assertEqual([row["node_slug"] for row in self.pending()], expected)
        self.clear_refreshes()
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO devices(device_id, account_number, location_slug, winn3_static_public, winn3_inner_v4) VALUES(?, ?, ?, ?, ?)",
                         ("inserted-device", harness.ACCOUNT, "test-node", base64.b64encode(b"y" * 32).decode(), "10.10.0.4"))
        self.assertEqual([row["node_slug"] for row in self.pending()], ["test-node"])

    def test_rollback_reverts_device_and_refresh_queue_together(self):
        self.bind_v3()
        self.clear_refreshes()
        with self.assertRaisesRegex(RuntimeError, "rollback"), self.mod.get_db() as conn:
            conn.execute("DELETE FROM devices")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM winn3_registry_refreshes").fetchone()[0], 1)
            raise RuntimeError("rollback")
        self.assertEqual(self.pending(), [])
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)

    def test_logout_refresh_survives_failure_and_drains_empty_snapshot(self):
        self.bind_v3()
        self.clear_refreshes()
        request = harness.FakeRequest(path="/logout", headers={"authorization": "Bearer " + self.token})
        asyncio.run(self.mod.logout_device(
            harness.BackgroundTasks(), request,
            account_number=harness.ACCOUNT, device_id=self.device))
        self.assertEqual(len(self.pending()), 1)
        with patch.object(self.mod, "sync_winn3_registry_to_node", return_value=False) as publish:
            self.assertEqual(self.mod.drain_winn3_registry_refreshes(), {"published": 0, "retry": 1})
            self.assertGreater(self.pending()[0]["next_attempt_at"], time.time())
            self.assertEqual(self.mod.drain_winn3_registry_refreshes(), {"published": 0, "retry": 0})
            self.assertEqual(publish.call_count, 1)
        with self.mod.get_db() as conn:
            conn.execute("UPDATE winn3_registry_refreshes SET next_attempt_at=0")

        def publish(conn, node_ip, slug):
            self.assertTrue(conn.in_transaction)
            self.assertEqual(self.mod.winn3_peer_registry_document(conn, slug)["peers"], [])
            return True

        with patch.object(self.mod, "sync_winn3_registry_to_node", side_effect=publish):
            self.assertEqual(self.mod.drain_winn3_registry_refreshes(), {"published": 1, "retry": 0})
        self.assertEqual(self.pending(), [])

    def test_missing_node_is_retained_with_backoff(self):
        with self.mod.get_db() as conn:
            conn.execute("INSERT INTO winn3_registry_refreshes(node_slug) VALUES('absent-node')")
        self.assertEqual(self.mod.drain_winn3_registry_refreshes(), {"published": 0, "retry": 1})
        self.assertEqual(self.pending()[0]["attempts"], 1)

    def test_publication_serializes_with_device_mutation(self):
        self.bind_v3()
        for deferred in (False, True):
            with self.subTest(deferred=deferred):
                publishing = threading.Event()
                release = threading.Event()
                mutating = threading.Event()
                mutated = threading.Event()

                def run_remote(*args, **kwargs):
                    publishing.set()
                    self.assertTrue(release.wait(5))
                    return types.SimpleNamespace(returncode=0, stdout="", stderr="")

                def publish():
                    with self.mod.get_db() as conn:
                        if deferred:
                            conn.execute("BEGIN")
                        return self.mod.sync_winn3_registry_to_node(conn, "127.0.0.1", "test-node")

                def mutate():
                    with self.mod.get_db() as conn:
                        mutating.set()
                        conn.execute("UPDATE devices SET winn3_inner_v4='10.10.0.5'")
                    mutated.set()

                # H0 (D3): a loopback host is refused by name, so the SSH
                # transport itself is stubbed for this serialization test.
                with patch.object(self.mod.subprocess, "run", side_effect=run_remote), patch.object(
                        self.mod, "node_ssh_command", side_effect=lambda host, command, **kw: ["ssh", host, command]), \
                        ThreadPoolExecutor(max_workers=2) as pool:
                    first = pool.submit(publish)
                    try:
                        self.assertTrue(publishing.wait(5))
                        second = pool.submit(mutate)
                        self.assertTrue(mutating.wait(5))
                        self.assertFalse(mutated.wait(0.1))
                    finally:
                        release.set()
                    self.assertTrue(first.result(5))
                    second.result(5)
                self.assertTrue(mutated.is_set())
                self.assertEqual(len(self.pending()), 1)

    def test_hoppy_deletions_commit_revocations_without_background_execution(self):
        for action in ("device-revoke", "device-limit-reset"):
            with self.subTest(action=action):
                tokens = harness.seed_account(self.mod, devices=2)
                with self.mod.get_db() as conn:
                    conn.execute("DELETE FROM peer_revocations")
                bearer, _ = self.mod.mint_hoppy_agent_token(harness.ACCOUNT, action)
                body = {"account_number": harness.ACCOUNT, "request_id": "round8-" + action}
                if action == "device-revoke":
                    body["device_id"] = next(iter(tokens))
                hoppy.call(self.mod, "/api/agent/v1/" + action, body, x_token=bearer)
                expected = 1 if action == "device-revoke" else 2
                with self.mod.get_db() as conn:
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2 - expected)
                    self.assertEqual(conn.execute("SELECT COUNT(*) FROM peer_revocations").fetchone()[0], expected)
                with patch.object(self.mod, "remove_peer_from_node", return_value=False):
                    self.assertEqual(self.mod.drain_peer_revocation_outbox()["retry"], expected)
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE peer_revocations SET next_attempt_at=0, lease_until=NULL")
                with patch.object(self.mod, "remove_peer_from_node", return_value=True):
                    self.assertEqual(self.mod.drain_peer_revocation_outbox()["removed"], expected)

    def test_capture_requires_explicit_completed_result(self):
        with patch.object(self.mod, "paypal_enabled", return_value=True):
            for result, status in (({}, 502), (None, 502), ({"status": "APPROVED"}, 409), ({"status": "PENDING"}, 409)):
                with self.subTest(result=result):
                    with self.mod.get_db() as conn:
                        conn.execute("DELETE FROM paypal_events")
                    with patch.object(self.mod, "paypal_json_request", return_value=result), self.assertRaises(harness.HTTPException) as error:
                        self.capture()
                    self.assertEqual(error.exception.status_code, status)
                    self.assertEqual(self.event_status(), "failed")
            with patch.object(self.mod, "paypal_json_request", return_value={"status": "COMPLETED"}):
                self.assertEqual(self.capture()["status"], "COMPLETED")
            self.assertEqual(self.event_status(), "processed")

    def test_duplicate_capture_requires_processed_and_provider_confirmation(self):
        with self.mod.get_db() as conn:
            self.mod.reserve_paypal_event(conn, "wallet-capture:ROUND8-ORDER", "WALLET.CAPTURE", "")
        with patch.object(self.mod, "paypal_enabled", return_value=True):
            with self.assertRaises(harness.HTTPException) as error:
                self.capture()
            self.assertEqual(error.exception.status_code, 409)
            with self.mod.get_db() as conn:
                self.mod.finish_paypal_event(conn, "wallet-capture:ROUND8-ORDER", "processed")
            with patch.object(self.mod, "paypal_json_request", return_value={"status": "APPROVED"}) as provider, self.assertRaises(harness.HTTPException) as error:
                self.capture()
            provider.assert_called_once_with("GET", "/v2/checkout/orders/ROUND8-ORDER")
            self.assertEqual(error.exception.status_code, 409)
            self.assertEqual(self.event_status(), "failed")
            with self.mod.get_db() as conn:
                self.mod.finish_paypal_event(conn, "wallet-capture:ROUND8-ORDER", "processed")
            with patch.object(self.mod, "paypal_json_request", return_value={"status": "COMPLETED"}) as provider:
                self.assertEqual(self.capture()["status"], "already_captured")
            provider.assert_called_once_with("GET", "/v2/checkout/orders/ROUND8-ORDER")

    def test_all_async_routes_have_real_async_work(self):
        for function in ast.parse(harness._extract_main_block()).body:
            if not isinstance(function, ast.AsyncFunctionDef):
                continue
            if not any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in
                       {"get", "post", "put", "patch", "delete", "head", "options"} for d in function.decorator_list):
                continue
            with self.subTest(route=function.name):
                self.assertTrue(any(isinstance(n, (ast.Await, ast.AsyncFor, ast.AsyncWith)) for n in ast.walk(function)))
        self.assertFalse(inspect.iscoroutinefunction(self.mod.heartbeat))
        thread_ids = []

        def heartbeat(payload, request):
            thread_ids.append(threading.get_ident())
            return {"ok": True}

        with patch.object(self.mod, "heartbeat", side_effect=heartbeat):
            self.assertEqual(asyncio.run(self.mod.heartbeat_path(
                "test-node", types.SimpleNamespace(slug=""), harness.FakeRequest())), {"ok": True})
        self.assertNotEqual(thread_ids, [threading.get_ident()])


if __name__ == "__main__":
    unittest.main()
