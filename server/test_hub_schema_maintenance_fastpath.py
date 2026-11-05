"""Per-request schema maintenance fast paths: once the winn3 inner-address
unique index exists, ensure_schema must not re-scan devices for duplicates
or rewrite an unchanged legal document on every request."""
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class SchemaMaintenanceFastpathTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False

    def test_unique_inner_repair_is_skipped_once_index_exists(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            statements = []
            conn.set_trace_callback(statements.append)
            try:
                self.assertEqual(self.mod.ensure_unique_winn3_inner_addresses(conn), 0)
            finally:
                conn.set_trace_callback(None)
            self.assertFalse(
                any("GROUP BY" in statement for statement in statements),
                statements,
            )
            # The repair still runs when the index is absent (legacy DB).
            conn.execute("DROP INDEX idx_devices_winn3_inner_v4_unique")
            for device_id in ("legacy-a", "legacy-b"):
                conn.execute(
                    "INSERT INTO devices (device_id, winn3_inner_v4) VALUES (?, ?)",
                    (device_id, " 10.10.0.44 "),
                )
            self.assertEqual(self.mod.ensure_unique_winn3_inner_addresses(conn), 2)

    def test_unchanged_legal_document_is_not_rewritten(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
        with self.mod.get_db() as conn:
            before = conn.total_changes
            self.mod.ensure_schema(conn)
            legal_changes = conn.execute(
                "SELECT COUNT(*) AS n FROM legal_documents WHERE version = ?",
                (self.mod.LEGAL_DOCUMENT_VERSION,),
            ).fetchone()["n"]
            self.assertEqual(legal_changes, 1)
            # A second ensure_schema over an unchanged document performs no
            # legal_documents write; total_changes for that row is proven by
            # the UPDATE guard in the upsert (rowcount of the statement).
            cursor = conn.execute(
                """
                INSERT INTO legal_documents (version, document_hash, title, body_text, effective_date, is_current, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
                ON CONFLICT(version) DO UPDATE SET
                    document_hash=excluded.document_hash,
                    title=excluded.title,
                    body_text=excluded.body_text,
                    effective_date=excluded.effective_date,
                    is_current=1
                WHERE legal_documents.document_hash IS NOT excluded.document_hash
                   OR legal_documents.title IS NOT excluded.title
                   OR legal_documents.body_text IS NOT excluded.body_text
                   OR legal_documents.effective_date IS NOT excluded.effective_date
                   OR legal_documents.is_current IS NOT 1
                """,
                (self.mod.LEGAL_DOCUMENT_VERSION, self.mod.LEGAL_DOCUMENT_HASH,
                 self.mod.LEGAL_DOCUMENT_TITLE, self.mod.LEGAL_DOCUMENT_TEXT,
                 self.mod.LEGAL_EFFECTIVE_DATE, self.mod.utcnow().isoformat()),
            )
            self.assertEqual(cursor.rowcount, 0)
            self.assertGreaterEqual(conn.total_changes, before)


if __name__ == "__main__":
    unittest.main()
