#!/usr/bin/env python3
"""Round-SU-gated regression test for the Core's inline Suricata drop-in
(lane L44, diff 05). Ships and lands only with diff 05.

Inline Suricata throttled at MemoryHigh stops issuing verdicts, and the
Core's fail-closed queue-0 rules then black-hole every queued stealth packet
while the Core still reports ready. The drop-in must set MemoryHigh=infinity
with MemoryMax still sized from host RAM (${suricata_max_mb}M, 50% of MemTotal
bounded to 768..1536 MiB) and Restart=on-failure, and postflight must verify
MemoryHigh at runtime.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.validate_deployment_scripts import parse_heredocs

CORE = ROOT / "server" / "wins_core_server_setup_ONETOUCH.sh"


class CoreSuricataMemoryHighTests(unittest.TestCase):
    def test_inline_suricata_is_never_throttled_at_memory_high(self):
        bodies = [
            block.body
            for block in parse_heredocs(CORE)
            if block.header.strip().endswith("30-wins-inline-ips.conf <<EOF")
        ]
        self.assertEqual(len(bodies), 1)
        dropin = bodies[0]
        self.assertIn("MemoryHigh=infinity", dropin)
        self.assertNotRegex(dropin, r"MemoryHigh=\$\{")
        self.assertRegex(dropin, r"(?m)^MemoryMax=\$\{suricata_max_mb\}M$")
        self.assertIn("Restart=on-failure", dropin)
        source = CORE.read_text(encoding="utf-8")
        start = source.index("verify_core_suricata_runtime() {")
        end = source.index("\nverify_core_resource_isolation() {", start)
        self.assertIn('-p MemoryHigh --value)" == "infinity"', source[start:end])


if __name__ == "__main__":
    unittest.main()
