"""Free-verify rate-limit increments must survive a request that fails
after the check (an unknown location answers 503 inside the same get_db
block, which otherwise rolls the increment back and refunds the attempt)."""
import base64
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class FreeVerifyRatelimitPersistTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False

    def failing_attempt(self):
        request = harness.FakeRequest(client_host="203.0.113.9")
        free_request = self.mod.FreeAccessRequest(
            device_id="attacker-device",
            device_fingerprint="",
            client_public_key=base64.b64encode(b"K" * 32).decode(),
            winn3_static_public=None,
            location="nonexistent-node",
            platform="android",
            device_model="Model",
            stealth_mode=False,
        )
        with self.assertRaises(Exception) as caught:
            self.mod._prepare_free_login_sync(
                request, free_request, harness.BackgroundTasks())
        return getattr(caught.exception, "status_code", None)

    def test_failing_attempts_eventually_trip_the_ip_limit(self):
        statuses = [self.failing_attempt() for _ in range(35)]
        # Every attempt fails (no such node), but the bucket still fills:
        # first at the per-IP ceiling the answer becomes 429, not 503.
        self.assertIn(429, statuses)
        self.assertEqual(statuses[-1], 429)
        with self.mod.get_db() as conn:
            row = conn.execute(
                "SELECT count FROM rate_limits WHERE bucket LIKE 'free-verify-ip:%'"
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertGreaterEqual(
            row["count"], self.mod.FREE_VERIFY_IP_RATE_LIMIT_PER_MINUTE)


if __name__ == "__main__":
    unittest.main()
