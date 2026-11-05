#!/usr/bin/env python3
"""Public reads must not take the SQLite write lock on a settled hub.

ensure_schema() ran ten write statements per call on a settled schema and
mark_stale_nodes_offline() ran five UPDATEs even when nothing was stale, so
every request, GET /nodes included, queued behind whichever /verify was holding
the writer lock through its node pushes. These tests pin: a settled schema is
not rewritten per call; a recreated database file still gets a full pass; the
stale sweep takes no write lock when nothing is stale and still acts on every
stale condition it closes. Run:  python3 server/test_public_reads_take_no_write_lock.py
"""
import _toolchain  # noqa: F401
import logging
import os
import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta
from unittest.mock import patch

import test_account_deletion_hub as harness
import test_winn3_serving_hub as serving


class PublicReadWriteLockTests(unittest.TestCase):
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
        self.mod.security_alert = lambda *args, **kwargs: None
        harness.seed_account(self.mod, devices=1)
        serving.seed_node(self.mod, slug="test-node")

    def autocommit_conn(self):
        conn = sqlite3.connect(self.mod._DB, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    def test_settled_schema_is_not_rewritten_on_every_call(self):
        with closing(self.autocommit_conn()) as conn:
            self.mod.ensure_schema(conn)
            conn.commit()
            self.mod.ensure_schema(conn)
            self.assertFalse(conn.in_transaction, "a second ensure_schema call took the write lock")

    def test_recreated_database_file_gets_a_full_pass(self):
        with closing(self.autocommit_conn()) as conn:
            self.mod.ensure_schema(conn)
            conn.commit()
        os.remove(self.mod._DB)
        for suffix in ("-wal", "-shm"):
            try:
                os.remove(self.mod._DB + suffix)
            except FileNotFoundError:
                pass
        with closing(self.autocommit_conn()) as conn:
            self.mod.ensure_schema(conn)
            conn.commit()
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0], 0)

    def test_public_listing_is_a_pure_reader_on_a_fresh_fleet(self):
        payload = self.mod._list_public_nodes_sync("android")
        self.assertEqual(len(payload["nodes"]), 1)
        with closing(self.autocommit_conn()) as conn:
            self.mod.ensure_schema(conn)
            self.mod.mark_stale_nodes_offline(conn)
            self.assertFalse(conn.in_transaction, "the stale sweep took the write lock with nothing stale")

    def stale_iso(self, seconds):
        return (self.mod.utcnow() - timedelta(seconds=seconds)).isoformat()

    def test_stale_sweep_still_closes_every_stale_condition(self):
        cases = {
            "heartbeat": ("UPDATE nodes SET last_heartbeat=? WHERE slug='test-node'",
                          (self.stale_iso(self.mod.NODE_HEARTBEAT_STALE_SECONDS + 60),),
                          "SELECT status FROM nodes WHERE slug='test-node'", "offline"),
            "data_plane_unreachable": ("UPDATE nodes SET data_plane_status='unreachable' WHERE slug='test-node'", (),
                                       "SELECT operator_enabled FROM nodes WHERE slug='test-node'", 0),
            "data_plane_proof_stale": ("UPDATE nodes SET data_plane_ok_at=? WHERE slug='test-node'",
                                       (self.stale_iso(self.mod.DATA_PLANE_HARD_STALE_MINUTES * 60 + 60),),
                                       "SELECT operator_enabled FROM nodes WHERE slug='test-node'", 0),
        }
        for name, (statement, params, probe, expected) in cases.items():
            with self.subTest(case=name):
                serving.seed_node(self.mod, slug="test-node")
                with closing(self.autocommit_conn()) as conn:
                    conn.execute(statement, params)
                    conn.commit()
                    self.mod.mark_stale_nodes_offline(conn)
                    self.assertTrue(conn.in_transaction, "a stale fleet must be swept")
                    conn.commit()
                    self.assertEqual(conn.execute(probe).fetchone()[0], expected)

    def test_stale_sweep_closes_assignments_on_an_already_offline_node(self):
        with closing(self.autocommit_conn()) as conn:
            conn.execute("INSERT OR REPLACE INTO core_servers(core_id, exit_public_key, status) VALUES('test-core', 'core-key', 'online')")
            conn.execute("INSERT INTO double_vpn_assignments(device_id, account_number, core_id, exit_slug, client_public_key, client_ip, status) "
                         "VALUES(?, ?, 'test-core', 'test-node', 'client-key', '10.9.0.2', 'active')",
                         (f"dev-{harness.ACCOUNT}-0", harness.ACCOUNT))
            conn.execute("UPDATE nodes SET status='offline', operator_enabled=0, last_heartbeat=? WHERE slug='test-node'",
                         (self.stale_iso(self.mod.NODE_HEARTBEAT_STALE_SECONDS + 60),))
            conn.commit()
            self.mod.mark_stale_nodes_offline(conn)
            conn.commit()
            self.assertEqual(conn.execute("SELECT status FROM double_vpn_assignments").fetchone()[0], "inactive")

    def test_stale_sweep_closes_a_stale_promoted_core(self):
        with closing(self.autocommit_conn()) as conn:
            conn.execute("INSERT OR REPLACE INTO core_servers(core_id, exit_public_key, status, promoted, last_heartbeat) "
                         "VALUES('test-core', 'core-key', 'online', 1, ?)",
                         (self.stale_iso(self.mod.DOUBLE_VPN_CORE_STALE_SECONDS + 60),))
            conn.commit()
            self.mod.mark_stale_nodes_offline(conn)
            conn.commit()
            row = conn.execute("SELECT status, promoted FROM core_servers WHERE core_id='test-core'").fetchone()
            self.assertEqual((row[0], row[1]), ("offline", 0))


if __name__ == "__main__":
    unittest.main()
