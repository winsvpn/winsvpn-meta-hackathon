#!/usr/bin/env python3
"""Focused structural tests for the isolated three-role GCP proof topology."""

from __future__ import annotations

import pathlib
import sys
import unittest


TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gcp_proof_fleet as fleet


def proof_spec() -> fleet.FleetSpec:
    return fleet.build_spec(
        project="winsvpn-proof-lab",
        control_name="proof-control-a1",
        winn3_data_name="proof-winn3-a1",
        cover_data_name="proof-cover-a1",
        control_zone="us-east1-b",
        winn3_data_zone="us-central1-a",
        cover_data_zone="us-east1-b",
        control_machine="e2-standard-2",
        winn3_data_machine="e2-medium",
        cover_data_machine="e2-medium",
        admin_source_cidr="203.0.113.0/24",
        dataplane_source_cidr="198.51.100.0/24",
        image_family=fleet.DEFAULT_IMAGE_FAMILY,
        image_project=fleet.DEFAULT_IMAGE_PROJECT,
        gcloud_bin="gcloud",
    )


class GcpProofRoleIsolationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.spec = proof_spec()
        self.resources = fleet.resource_names(self.spec)
        self.commands = fleet.build_plan_commands(self.spec)

    def firewall_commands(self) -> list[list[str]]:
        return [
            command["argv"]
            for command in self.commands
            if command["argv"][1:4] == ["compute", "firewall-rules", "create"]
        ]

    def instance_command(self, name: str) -> list[str]:
        matches = [
            command["argv"]
            for command in self.commands
            if command["argv"][1:4] == ["compute", "instances", "create"]
            and command["argv"][4] == name
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_each_role_has_a_distinct_subnet(self) -> None:
        subnets = self.resources["subnets"]
        self.assertEqual({item["role"] for item in subnets}, set(fleet.ROLES))
        self.assertEqual(len({item["name"] for item in subnets}), 3)
        self.assertEqual(len({item["cidr"] for item in subnets}), 3)

    def test_v1_and_v3_firewalls_are_disjoint(self) -> None:
        rendered = [" ".join(argv) for argv in self.firewall_commands()]
        self.assertFalse(any("data-winn3,data-cover" in row for row in rendered))
        self.assertFalse(any("tcp,udp,icmp" in row for row in rendered))
        self.assertFalse(any("8443" in row for row in rendered))

        winn3 = next(row for row in rendered if "-winn3-in" in row)
        self.assertIn("--rules=tcp:9111,udp:9111", winn3)
        self.assertIn("--source-tags=pf-role-control", winn3)
        self.assertIn("--target-tags=pf-role-data-winn3", winn3)
        self.assertNotIn("20000-32767", winn3)

        cover = next(row for row in rendered if "-cover-in" in row)
        self.assertIn("--rules=tcp:80,tcp:443,udp:9110,udp:20000-32767", cover)
        self.assertIn("--source-tags=pf-role-control", cover)
        self.assertIn("--target-tags=pf-role-data-cover", cover)
        self.assertNotIn("9111", cover)

    def test_only_data_vms_can_forward_ip(self) -> None:
        self.assertIn("--can-ip-forward", self.instance_command("proof-winn3-a1"))
        self.assertIn("--can-ip-forward", self.instance_command("proof-cover-a1"))
        self.assertNotIn("--can-ip-forward", self.instance_command("proof-control-a1"))

    def test_winn3_runtime_contract_does_not_require_v1(self) -> None:
        self.assertEqual(
            fleet.ROLE_DEPLOY_SERVICES["data-winn3"],
            {fleet.GATEWAY_SERVICE: "active"},
        )
        self.assertEqual(
            fleet.ROLE_DEPLOY_UNITS["data-winn3"],
            {fleet.GATEWAY_SERVICE: "/etc/systemd/system/winn3-gateway.service"},
        )
        self.assertIsNone(fleet.ROLE_RUNTIME_BINARIES["data-winn3"]["xray"])
        self.assertEqual(fleet.ROLE_FILE_PAYLOADS["data-winn3"], b"data-winn3\n")


if __name__ == "__main__":
    unittest.main()
