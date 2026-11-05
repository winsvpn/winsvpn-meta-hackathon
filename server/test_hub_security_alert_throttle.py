"""Security-alert email throttle: varying an attacker-chosen detail (the
node slug in an invalid-token alert) must not mint one email -- and one
throttle state file -- per attempt."""
import logging
import os
import unittest
from unittest.mock import patch

import test_account_deletion_hub as harness


class SecurityAlertThrottleTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TMPDIR": os.environ.get("TMPDIR", "")}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        with patch("logging.basicConfig", side_effect=lambda **kw: [
            handler.close() for handler in kw.get("handlers", [])
        ]):
            self.mod = harness.load_hub()
        self.mod.logger.propagate = False

    def sends(self, source, slugs):
        return sum(
            bool(self.mod.should_send_security_alert(
                2, "invalid node token", source,
                {"slug": slug, "action": "node api"}))
            for slug in slugs
        )

    def test_distinct_slugs_from_one_source_are_budget_capped(self):
        allowed = self.sends("203.0.113.9", [f"node-{i}" for i in range(40)])
        self.assertEqual(allowed, self.mod.SECURITY_ALERT_MAX_PER_SOURCE_WINDOW)
        # An exact repeat is throttled by the per-identity file as before.
        self.assertFalse(self.mod.should_send_security_alert(
            2, "invalid node token", "203.0.113.9",
            {"slug": "node-0", "action": "node api"}))

    def test_distinct_sources_share_one_event_budget(self):
        allowed = 0
        for n in range(10):
            allowed += self.sends(f"203.0.113.{n}", [f"s{n}-{i}" for i in range(8)])
        self.assertEqual(allowed, self.mod.SECURITY_ALERT_MAX_PER_EVENT_WINDOW)


if __name__ == "__main__":
    unittest.main()
