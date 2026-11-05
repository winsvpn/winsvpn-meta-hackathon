"""Schema maintenance must preserve settings changed after legacy import."""
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class LegacySettingsMigrationTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False

    def test_legacy_import_does_not_undo_later_maintenance_change(self):
        with self.mod.get_db() as conn:
            conn.execute("CREATE TABLE systemsettings(key TEXT PRIMARY KEY,value TEXT)")
            conn.execute("INSERT INTO systemsettings VALUES ('maintenancemode','false')")
            self.mod.ensure_schema(conn)
            self.assertEqual(self.mod.get_setting(conn, "maintenance_mode", "missing"), "false")
            self.mod.set_setting(conn, "maintenance_mode", "true")
        self.mod._legal_current_sync("en", True)
        with self.mod.get_db() as conn:
            self.assertEqual(self.mod.get_setting(conn, "maintenance_mode", "missing"), "true")

    def test_existing_canonical_announcement_wins_over_legacy_text(self):
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            self.mod.set_setting(conn, "global_announcement", "current message")
            conn.execute("CREATE TABLE systemsettings(key TEXT PRIMARY KEY,value TEXT)")
            conn.execute("INSERT INTO systemsettings VALUES ('globalannouncement','obsolete message')")
            self.mod.ensure_schema(conn)
            self.assertEqual(self.mod.get_setting(conn, "global_announcement", "missing"), "current message")


if __name__ == "__main__":
    unittest.main()
