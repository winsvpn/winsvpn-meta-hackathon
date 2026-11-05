#!/usr/bin/env python3
"""Pure resource-profile consumer tests; no gateway or installer is executed."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


# Saved producer profiles for UDP MTU1450/N64 and MTU8192/N2.
DEFAULT_PROFILE = json.loads(r'''{
  "accounting_scope": "queue_payload_backing_only",
  "batch_receive_slots": 64,
  "configured_queue_payload_backing_bytes": 1174667264,
  "demux_buffer_bytes": 4096,
  "demux_packets_per_side": 4096,
  "demux_sides": 2,
  "inner_payload_bytes": 1373,
  "max_sessions": 64,
  "message_bytes": 1402,
  "migration_plan": [
    "udp"
  ],
  "not_included": [
    "queue_and_packet_metadata",
    "runtime_gc_and_pool_retention",
    "session_device_cover_and_kernel_storage",
    "non_demux_in_flight_producer_and_consumer_buffers",
    "retained_and_temporary_send_receive_and_parser_batch_storage",
    "future_lifetime_ceiling_widening"
  ],
  "path_mtu": 1450,
  "pipe_buffer_slab_bytes": 2048,
  "pipe_inbox_packets": 512,
  "pipe_payload_backing_per_session_bytes": 1048576,
  "schema_version": 1,
  "send_buffer_slab_bytes": 2048,
  "send_payload_backing_per_session_bytes": 16777216,
  "send_queue_packets": 8192,
  "shared_demux_admitted_backing_bytes": 33554432,
  "shared_demux_staging_backing_bytes": 262144
}''')
LARGE_PROFILE = json.loads(r'''{
  "accounting_scope": "queue_payload_backing_only",
  "batch_receive_slots": 64,
  "configured_queue_payload_backing_bytes": 208532480,
  "demux_buffer_bytes": 8144,
  "demux_packets_per_side": 4096,
  "demux_sides": 2,
  "inner_payload_bytes": 8115,
  "max_sessions": 2,
  "message_bytes": 8144,
  "migration_plan": [
    "udp"
  ],
  "not_included": [
    "queue_and_packet_metadata",
    "runtime_gc_and_pool_retention",
    "session_device_cover_and_kernel_storage",
    "non_demux_in_flight_producer_and_consumer_buffers",
    "retained_and_temporary_send_receive_and_parser_batch_storage",
    "future_lifetime_ceiling_widening"
  ],
  "path_mtu": 8192,
  "pipe_buffer_slab_bytes": 2048,
  "pipe_inbox_packets": 512,
  "pipe_payload_backing_per_session_bytes": 4169728,
  "schema_version": 1,
  "send_buffer_slab_bytes": 2048,
  "send_payload_backing_per_session_bytes": 66478080,
  "send_queue_packets": 8192,
  "shared_demux_admitted_backing_bytes": 66715648,
  "shared_demux_staging_backing_bytes": 521216
}''')


def with_demux_capacity(profile, capacity):
    """Keep accounting identities consistent while changing one contract field."""
    result = copy.deepcopy(profile)
    result["demux_buffer_bytes"] = capacity
    admitted = result["demux_sides"] * result["demux_packets_per_side"] * capacity
    staging = result["batch_receive_slots"] * capacity
    result["shared_demux_admitted_backing_bytes"] = admitted
    result["shared_demux_staging_backing_bytes"] = staging
    per_session = (result["send_payload_backing_per_session_bytes"]
                   + result["pipe_payload_backing_per_session_bytes"])
    result["configured_queue_payload_backing_bytes"] = (
        result["max_sessions"] * per_session + admitted + staging)
    return result


class ResourceProfileDemuxTests(unittest.TestCase):
    def consume(self, profile):
        helper = Path(__file__).resolve().with_name("wins_winn3_gateway_resource_profile.sh")
        env = {"PATH": str(Path(sys.executable).resolve().parent) + os.pathsep + os.defpath,
               "LC_ALL": "C"}
        return subprocess.run(
            ["/bin/bash", "-c",
             'source "$1"; validate_gateway_resource_profile_json "$2" "$3" "$4"',
             "resource-profile-test", str(helper), str(profile["max_sessions"]),
             str(profile["path_mtu"]), ",".join(profile["migration_plan"])],
            input=json.dumps(profile), text=True, capture_output=True,
            env=env, timeout=5, check=False)

    def assert_valid(self, profile):
        result = self.consume(profile)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout), profile)
        self.assertTrue(result.stdout.endswith("\n"))

    def test_saved_default_minimum_capacity(self):
        self.assertEqual(DEFAULT_PROFILE["demux_buffer_bytes"], 4096)
        self.assertLess(DEFAULT_PROFILE["message_bytes"], 4096)
        self.assert_valid(DEFAULT_PROFILE)

    def test_saved_larger_message_capacity(self):
        self.assertGreater(LARGE_PROFILE["message_bytes"], 4096)
        self.assertEqual(LARGE_PROFILE["demux_buffer_bytes"], LARGE_PROFILE["message_bytes"])
        self.assert_valid(LARGE_PROFILE)

    def test_contract_mismatch_with_consistent_totals(self):
        for profile, capacities in [(DEFAULT_PROFILE, (2048, 4097)),
                                    (LARGE_PROFILE, (8143, 8145))]:
            for capacity in capacities:
                with self.subTest(message_bytes=profile["message_bytes"], capacity=capacity):
                    result = self.consume(with_demux_capacity(profile, capacity))
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr,
                                     "[winn3-gw][ERR] invalid or inconsistent resource profile.\n")


if __name__ == "__main__":
    unittest.main()
