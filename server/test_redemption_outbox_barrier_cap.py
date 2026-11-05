#!/usr/bin/env python3
"""A replica outage must not use up mail outbox barrier retries."""

import shutil
import sqlite3
import unittest

import test_account_deletion_hub as harness


class RedemptionOutboxBarrierCapTest(unittest.TestCase):
    def setUp(self):
        self.hub = harness.load_hub(
            DURABILITY_BARRIER_ENABLED="0", DURABILITY_BARRIER_REQUIRED="0"
        )
        self.hub.REDEMPTION_OUTBOX_MAX_ATTEMPTS = 1
        with sqlite3.connect(self.hub._DB) as conn:
            conn.row_factory = sqlite3.Row
            self.hub.ensure_schema(conn)
            conn.execute(
                "INSERT INTO redemption_outbox "
                "(idempotency_key, kind, status, attempts, created_at) "
                "VALUES ('pending-test', 'redemption_welcome_email', "
                "'pending', 0, '2026-10-13T00:00:00')"
            )
            conn.execute(
                "INSERT INTO redemption_outbox "
                "(idempotency_key, kind, status, attempts, created_at) "
                "VALUES ('delivered-test', 'redemption_welcome_email', "
                "'delivered', 1, '2026-10-13T00:00:00')"
            )

    def tearDown(self):
        shutil.rmtree(self.hub._TMPDIR)

    def test_barrier_recovery_claims_both_rows(self):
        def unavailable():
            raise self.hub.DurabilityBarrierError("replica_unavailable")

        self.hub.run_durability_barrier = unavailable
        first = self.hub.drain_redemption_outbox()
        self.assertEqual(first["claimed"], 2)
        with sqlite3.connect(self.hub._DB) as conn:
            pending_attempts = conn.execute(
                "SELECT attempts FROM redemption_outbox "
                "WHERE idempotency_key='pending-test'"
            ).fetchone()[0]
        self.assertEqual(pending_attempts, 0)

        self.hub.run_durability_barrier = lambda: {}
        second = self.hub.drain_redemption_outbox()
        self.assertEqual(second["claimed"], 2)
        self.assertEqual(second["confirmed"], 2)
        with sqlite3.connect(self.hub._DB) as conn:
            states = conn.execute(
                "SELECT status FROM redemption_outbox ORDER BY idempotency_key"
            ).fetchall()
        self.assertEqual(states, [("completed",), ("completed",)])


if __name__ == "__main__":
    unittest.main()
