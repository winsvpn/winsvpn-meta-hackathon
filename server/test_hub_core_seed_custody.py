"""An authenticated Core registration must survive later schema checks."""
import base64
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class CoreSeedCustodyTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.seed_key = base64.b64encode(bytes([31]) * 32).decode()
        self.current_key = base64.b64encode(bytes([32]) * 32).decode()
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub(
                HIDE_CONTROL_ORIGIN=0, DOUBLE_VPN_CORE_ID="test-core",
                DOUBLE_VPN_CORE_INGRESS_ENDPOINT="192.0.2.20:9210",
                DOUBLE_VPN_CORE_INGRESS_PUBLIC_KEY=self.seed_key,
                DOUBLE_VPN_CORE_EXIT_PUBLIC_KEY=self.seed_key,
            )
        self.mod.logger.propagate = False
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)

    def test_seed_creates_a_dark_core(self):
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT * FROM core_servers WHERE core_id='test-core'").fetchone()
            self.assertTrue(row["ingress_public_key"] == self.seed_key)
            self.assertEqual(row["status"], "maintenance")
            self.assertEqual(row["runtime_ready"], 0)
            self.assertEqual(row["promoted"], 0)

    def test_registration_survives_public_read_handler(self):
        token = "synthetic-core-credential"
        with self.mod.get_db() as conn:
            conn.execute("UPDATE core_servers SET core_token_hash=? WHERE core_id='test-core'",
                         (self.mod.token_digest(token),))
        payload = self.mod.CoreRegistration(
            core_id="test-core", name="Registered Core", region="test",
            management_host="", management_user="ubuntu",
            ingress_endpoint="192.0.2.21:9210", tunnel_gateway_ipv4="10.9.0.1",
            ingress_public_key=self.current_key, exit_public_key=self.current_key,
            stealth_endpoint="", xray_uuid="", xray_path="/current-route", xray_security="none",
            stealth_transports=[], regional_aliases=[], direct_awg_enabled=True,
            status="maintenance", runtime_ready=False, applied_assignment_revisions=[], obfuscation_json=None,
        )
        result = self.mod.register_core(payload, harness.FakeRequest(), token)
        self.assertTrue(result["ok"])
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT * FROM core_servers WHERE core_id='test-core'").fetchone()
            self.assertTrue(row["ingress_public_key"] == self.current_key)
        self.mod._legal_current_sync("en", True)
        with self.mod.get_db() as conn:
            row = conn.execute("SELECT * FROM core_servers WHERE core_id='test-core'").fetchone()
            self.assertTrue(row["ingress_public_key"] == self.current_key, "registered key overwritten by seed")
            self.assertEqual(row["ingress_endpoint"], "192.0.2.21:9210")
            self.assertEqual(row["xray_path"], "/current-route")


if __name__ == "__main__":
    unittest.main()
