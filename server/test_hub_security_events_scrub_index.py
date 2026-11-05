"""The legacy plaintext source_ip scrub in ensure_security_events_db must
stay a lookup (partial index), not a full table scan on every event."""
import logging
import os
import sqlite3
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class SecurityEventsScrubIndexTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False

    def test_scrub_uses_partial_index_and_still_cleans(self):
        db = self.mod.SECURITY_EVENTS_DB
        with sqlite3.connect(db) as conn:
            self.mod.configure_security_events_connection(conn)
            with conn:
                self.mod.ensure_security_events_db(conn)
            plan = " ".join(
                str(row[-1]) for row in conn.execute(
                    "EXPLAIN QUERY PLAN UPDATE security_events SET source_ip = NULL "
                    "WHERE source_ip IS NOT NULL AND source_ip != ''")
            )
            self.assertIn("idx_security_events_source_plaintext", plan)
            with conn:
                conn.execute(
                    "INSERT INTO security_events(event_id, observed_at_utc, "
                    "observed_at_eastern, priority, event_type, source_ip) "
                    "VALUES ('legacy-1', '2999-01-01T00:00:00+00:00', 't', 2, 'x', '192.0.2.9')")
                self.mod.ensure_security_events_db(conn)
            row = conn.execute(
                "SELECT source_ip FROM security_events WHERE event_id='legacy-1'"
            ).fetchone()
            self.assertIsNone(row[0])


if __name__ == "__main__":
    unittest.main()
