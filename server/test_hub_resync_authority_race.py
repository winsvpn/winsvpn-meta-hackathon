"""Offline regression: a stale AWG resync must not restore a rotated key."""
import base64
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class ResyncAuthorityRaceTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub(WINN3_INNER_POOL_CIDR="10.10.0.0/24")
        self.mod.logger.propagate = False
        self.mod.logger.addHandler(logging.NullHandler())
        self.mod.security_alert = lambda *args, **kwargs: None
        self.old = base64.b64encode(bytes([17]) * 32).decode()
        self.new = base64.b64encode(bytes([18]) * 32).decode()
        self.runtime = {self.old}
        with self.mod.get_db() as conn:
            self.mod.ensure_schema(conn)
            conn.execute("INSERT INTO users(account_number,status,expiration_date) "
                         "VALUES ('1111-2222-3333','active','2099-01-01T00:00:00+00:00')")
            conn.execute("INSERT INTO nodes(slug,endpoint,ssh_host,status,operator_enabled,protocol_version) "
                         "VALUES ('test-node','192.0.2.10:9110','192.0.2.10','online',1,'winn/1')")
            conn.execute("INSERT INTO devices(device_id,account_number,client_public_key,vpn_internal_ip,location_slug) "
                         "VALUES ('device-1','1111-2222-3333',?,'10.8.1.3','test-node')", (self.old,))

    def rotate_and_drain(self):
        with self.mod.get_db() as conn:
            conn.execute("UPDATE devices SET client_public_key=? WHERE device_id='device-1'", (self.new,))
            self.mod.queue_peer_revocation(conn, "192.0.2.10", self.old)
        self.runtime.add(self.new)
        result = self.mod.drain_peer_revocation_outbox()
        self.assertEqual(result["removed"], 1)
        self.assertNotIn(self.old, self.runtime)

    def run_race(self, acknowledged):
        def remove(host, key):
            self.runtime.discard(key)
            return True

        def delayed_push(host, cfg):
            self.assertTrue(cfg["client_public_key"] == self.old)
            self.rotate_and_drain()
            self.runtime.add(self.old)
            return acknowledged

        with patch.object(self.mod, "sync_peer_to_node", side_effect=delayed_push), \
                patch.object(self.mod, "remove_peer_from_node", side_effect=remove), \
                patch.object(self.mod, "sync_winn3_registry_to_node", return_value=True), \
                patch.object(self.mod, "verify_node_management_access", return_value=True):
            self.mod.resync_active_peers_to_node("test-node")
            self.mod.drain_peer_revocation_outbox()
        self.assertFalse(self.old in self.runtime, "revoked key restored after completed revocation")
        self.assertTrue(self.new in self.runtime, "replacement peer must remain")

    def test_rotation_during_acknowledged_resync(self):
        self.run_race(True)

    def test_rotation_during_unacknowledged_resync(self):
        self.run_race(False)


if __name__ == "__main__":
    unittest.main()
