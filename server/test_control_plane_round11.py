#!/usr/bin/env python3
"""Round 11 admission regressions against generated hub code and real SQLite.

Remote peer operations and the Core acknowledgment boundary are controlled
locally. No live account, node, service, or provider is contacted.
"""
import _toolchain  # noqa: F401
import asyncio
from datetime import timedelta
import json
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_control_plane_round10 as round10
import test_winn3_descriptor_hub as descriptor


class Round11Tests(unittest.TestCase):
    setUp = round10.Round10Tests.setUp
    cleanup = round10.Round10Tests.cleanup
    device = round10.Round10Tests.device

    def activate(self):
        with self.mod.get_db() as conn:
            self.secret = self.mod.issue_activation_secret(conn, harness.ACCOUNT)

    def seed_core(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE nodes SET protocol_version='winn/1', protocol_params_json='{}'")
            # The core has reported its core0 obfuscation profile (SYNC-02 round
            # 2 withholds Double VPN through a core that has not).
            conn.execute(
                "INSERT INTO core_servers (core_id, exit_public_key, ingress_public_key, "
                "ingress_endpoint, tunnel_gateway_ipv4, status, runtime_ready, obfuscation_json) "
                "VALUES ('fixture-core', ?, ?, '192.0.2.50:9210', '10.9.0.1', 'online', 1, ?)",
                ("D" * 43 + "=", "E" * 43 + "=", json.dumps(self.mod.DEFAULT_OBFUSCATION)),
            )
            core = dict(conn.execute("SELECT * FROM core_servers").fetchone())
        self.mod.select_double_vpn_core = lambda conn: core
        self.mod.DOUBLE_VPN_ASSIGNMENT_READY_TIMEOUT_SECONDS = 0
        self.activate()

    def verify(self, *, double=True, ready=None, sync=None):
        request = harness.FakeRequest(path="/verify", headers={"x-wins-activation": self.secret})
        login = descriptor.build_login(
            self.mod, supports_winn3=True, supports_winn3_descriptor=True, double_vpn=double)
        with patch.object(self.mod, "sync_peer_to_node", side_effect=sync or (lambda *args: True)), patch.object(
            self.mod, "sync_winn3_registry_to_node", return_value=True
        ):
            if ready is None:
                result = asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
            else:
                with patch.object(self.mod, "_wait_for_core_assignment_ready_sync", side_effect=ready):
                    result = asyncio.run(self.mod.verify_account(request, login, harness.BackgroundTasks()))
        return json.loads(result.body) if hasattr(result, "body") else result

    def used(self):
        with self.mod.get_db() as conn:
            return conn.execute("SELECT activation_secret_used_at FROM users").fetchone()[0]

    def test_activation_check_does_not_consume_and_terminal_check_remains_single_use(self):
        self.activate()
        with self.mod.get_db() as conn:
            self.assertFalse(self.mod.verify_and_consume_activation_secret(
                conn, harness.ACCOUNT, "wrong", consume=False))
            self.assertTrue(self.mod.verify_and_consume_activation_secret(
                conn, harness.ACCOUNT, self.secret, consume=False))
        self.assertIsNone(self.used())
        with self.mod.get_db() as conn:
            self.assertTrue(self.mod.verify_and_consume_activation_secret(conn, harness.ACCOUNT, self.secret))
            self.assertFalse(self.mod.verify_and_consume_activation_secret(
                conn, harness.ACCOUNT, self.secret, consume=False))
        self.assertIsNotNone(self.used())

    def test_uncertain_awg_install_is_rolled_back_and_durably_removed(self):
        self.activate()
        installed = set()

        def uncertain(host, device):
            installed.add((host, device["client_public_key"]))
            return False

        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(double=False, sync=uncertain)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertIsNone(self.used())
        with self.mod.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 0)
            self.assertEqual({tuple(row) for row in conn.execute(
                "SELECT node_ip, client_public_key FROM peer_revocations")}, installed)
            self.assertEqual(conn.execute(
                "SELECT management_status FROM nodes WHERE slug='lab-alpha'").fetchone()[0], "failed")

        def remove(host, key):
            installed.discard((host, key))
            return True

        with patch.object(self.mod, "remove_peer_from_node", side_effect=remove):
            self.assertEqual(self.mod.drain_peer_revocation_outbox(), {"removed": 1, "retry": 0})
        self.assertFalse(installed)

    def test_core_timeout_can_retry_same_secret_then_complete_once(self):
        self.seed_core()
        for _ in range(2):
            with self.assertRaises(harness.HTTPException) as caught:
                self.verify()
            self.assertEqual(caught.exception.status_code, 503)
            self.assertIn("still being prepared", caught.exception.detail)
            self.assertIsNone(self.used())
            with self.mod.get_db() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM double_vpn_assignments").fetchone()[0], 1)
        response = self.verify(ready=lambda *args: True)
        self.assertEqual(self.mod.token_digest(response["device_auth_token"]),
                         self.device()["device_auth_token_hash"])
        self.assertIsNotNone(self.used())
        with self.assertRaises(harness.HTTPException) as caught:
            self.verify(ready=lambda *args: True)
        self.assertEqual(caught.exception.status_code, 401)

    def test_authority_changes_during_core_wait_reject_stale_success(self):
        self.seed_core()
        with self.mod.get_db() as conn:
            expiry = conn.execute("SELECT expiration_date FROM users").fetchone()[0]
        changes = [
            ("UPDATE devices SET device_auth_token_hash='replacement'", ()),
            ("UPDATE users SET status='expired'", ()),
            ("UPDATE users SET expiration_date=?", ((self.mod.utcnow() - timedelta(seconds=1)).isoformat(),)),
            ("UPDATE users SET expiration_date=?", ((self.mod.utcnow() + timedelta(days=999)).isoformat(),)),
            ("UPDATE users SET expiration_date='invalid'", ()),
            ("UPDATE double_vpn_assignments SET client_ip='10.9.0.123'", ()),
            ("DELETE FROM devices", ()),
        ]
        for sql, params in changes:
            with self.subTest(change=sql, params=params):
                with self.mod.get_db() as conn:
                    conn.execute("UPDATE users SET status='active', expiration_date=?", (expiry,))
                self.activate()

                def mutate(*args):
                    with self.mod.get_db() as conn:
                        conn.execute(sql, params)
                    return True

                with self.assertRaises(harness.HTTPException) as caught:
                    self.verify(ready=mutate)
                self.assertEqual(caught.exception.status_code, 409)
                self.assertEqual(caught.exception.detail,
                                 "Double VPN enrollment changed while preparing. Please retry.")
                self.assertIsNone(self.used())

    def test_activation_invalidated_during_wait_cannot_complete(self):
        self.seed_core()
        for sql in [
            "UPDATE users SET activation_secret_hash='replacement'",
            "UPDATE users SET activation_secret_used_at='already-used'",
            "UPDATE users SET activation_secret_expires_at='2000-01-01T00:00:00+00:00'",
        ]:
            with self.subTest(change=sql):
                self.activate()

                def mutate(*args):
                    with self.mod.get_db() as conn:
                        conn.execute(sql)
                    return True

                with self.assertRaises(harness.HTTPException) as caught:
                    self.verify(ready=mutate)
                self.assertEqual(caught.exception.status_code, 401)

    def test_final_consumption_holds_writer_lock(self):
        self.seed_core()
        original = self.mod.verify_and_consume_activation_secret
        final_calls = []

        def consume(conn, *args, **kwargs):
            if kwargs.get("consume", True):
                self.assertTrue(conn.in_transaction)
                with self.mod.get_db() as other:
                    other.execute("PRAGMA busy_timeout=0")
                    with self.assertRaises(self.mod.sqlite3.OperationalError):
                        other.execute("BEGIN IMMEDIATE")
                final_calls.append(True)
            return original(conn, *args, **kwargs)

        with patch.object(self.mod, "verify_and_consume_activation_secret", side_effect=consume):
            self.verify(ready=lambda *args: True)
        self.assertEqual(final_calls, [True])


if __name__ == "__main__":
    unittest.main()
