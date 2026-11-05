#!/usr/bin/env python3
"""Fake-runner tests for GCP proof cleanup postconditions.

These tests never invoke gcloud, never read credentials, and never contact
cloud APIs. They prove the fail-closed plan/execution contract:
no deletion without explicit authorization, partial failure remains failure,
stale or mismatched names are refused, and post-delete presence is failure.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DEPLOY = load_module(
    "gcp_proof_cleanup_postconditions_under_test", TOOLS / "gcp_proof_deploy.py"
)


def utc_stamp(*, minutes: int = 0) -> str:
    value = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=minutes)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_context() -> Any:
    instances = {
        "control": {
            "name": "proof-control-a1",
            "zone": "us-east1-b",
            "machine_type": "e2-standard-2",
        },
        "data-winn3": {
            "name": "proof-winn3-a1",
            "zone": "us-east1-b",
            "machine_type": "e2-medium",
        },
        "data-cover": {
            "name": "proof-cover-a1",
            "zone": "us-east1-b",
            "machine_type": "e2-medium",
        },
    }
    return DEPLOY.Context(
        repo=Path("/tmp/winsvpn-proof-postcondition-repo"),
        plan_path=Path("/tmp/winsvpn-proof-postcondition-state/plan.json"),
        apply_path=Path("/tmp/winsvpn-proof-postcondition-state/apply.json"),
        manifest_path=Path(
            "/tmp/winsvpn-proof-postcondition-state/DEPLOYMENT_INPUTS.json"
        ),
        plan={},
        apply={"created_utc": utc_stamp(minutes=-2)},
        manifest={},
        client_release_binding={},
        plan_sha256="a" * 64,
        apply_sha256="b" * 64,
        manifest_sha256="c" * 64,
        manifest_bytes=1,
        instances=instances,
        project="winsvpn-proof-lab",
        fleet_id="proof-fleet-20260823",
        gcloud_bin="gcloud",
        installers=[],
    )


class PostconditionRunner:
    """In-process gcloud stand-in. Never executes a real subprocess."""

    ROLE_IDS = {"control": "1001", "data-winn3": "1002", "data-cover": "1003"}
    FIREWALL_IDS = {
        "admin-ssh": "2001",
        "winn3-in": "2002",
        "control-http": "2003",
        "cover-in": "2004",
    }

    def __init__(self, context: Any) -> None:
        self.context = context
        self.calls: list[list[str]] = []
        self.deleted: set[str] = set()
        self.present_after_delete: set[str] = set()
        self.fail_delete: set[str] = set()
        self.identity_swap: dict[str, dict[str, Any]] = {}
        self.describe_counts: dict[str, int] = {}
        self.cache: dict[str, dict[str, Any]] = {}

    def _created(self) -> str:
        return utc_stamp()

    def _resource_id(self, kind: str, name: str) -> str:
        if kind == "network":
            return "4001"
        if kind == "subnet":
            return {
                "control": "3001",
                "data-winn3": "3002",
                "data-cover": "3003",
            }[name.rsplit("-sn-", 1)[1]]
        for suffix, ident in self.FIREWALL_IDS.items():
            if name.endswith(suffix):
                return ident
        return "2999"

    def instance_document(self, role: str) -> dict[str, Any]:
        instance = self.context.instances[role]
        project = self.context.project
        payload = {
            "creationTimestamp": self._created(),
            "deletionProtection": True,
            "canIpForward": role in {"data-winn3", "data-cover"},
            "id": self.ROLE_IDS[role],
            "labels": DEPLOY._expected_labels(self.context.fleet_id, role),
            "machineType": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{project}/zones/{instance['zone']}/machineTypes/"
                f"{instance['machine_type']}"
            ),
            "metadata": {
                "items": [
                    {"key": "enable-oslogin", "value": "TRUE"},
                    {"key": "winsvpn-proof-role", "value": role},
                ]
            },
            "name": instance["name"],
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{project}/zones/{instance['zone']}/instances/{instance['name']}"
            ),
            "serviceAccounts": [],
            "shieldedInstanceConfig": {
                "enableIntegrityMonitoring": True,
                "enableSecureBoot": True,
                "enableVtpm": True,
            },
            "status": "RUNNING",
            "tags": {
                "items": DEPLOY._expected_tags(self.context.fleet_id, role)
            },
            "zone": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{project}/zones/{instance['zone']}"
            ),
        }
        return payload

    def resource_document(
        self, kind: str, name: str, region: str | None = None
    ) -> dict[str, Any]:
        project = self.context.project
        fleet_id = self.context.fleet_id
        ident = self._resource_id(kind, name)
        labels = DEPLOY._expected_resource_labels(fleet_id)
        created = self._created()
        if kind == "firewall":
            return {
                "creationTimestamp": created,
                "fingerprint": f"fprint{ident}=",
                "id": ident,
                "kind": "compute#firewall",
                "labelFingerprint": f"lprint{ident}=",
                "labels": labels,
                "name": name,
                "network": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{project}/global/networks/pf-{fleet_id}-net"
                ),
                "selfLink": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{project}/global/firewalls/{name}"
                ),
            }
        if kind == "subnet":
            assert region is not None
            return {
                "creationTimestamp": created,
                "fingerprint": f"fprint{ident}=",
                "id": ident,
                "ipCidrRange": "172.16.0.0/24",
                "kind": "compute#subnetwork",
                "labelFingerprint": f"lprint{ident}=",
                "labels": labels,
                "name": name,
                "network": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{project}/global/networks/pf-{fleet_id}-net"
                ),
                "region": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{project}/regions/{region}"
                ),
                "selfLink": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{project}/regions/{region}/subnetworks/{name}"
                ),
            }
        return {
            "autoCreateSubnetworks": False,
            "creationTimestamp": created,
            "fingerprint": f"fprint{ident}=",
            "id": ident,
            "kind": "compute#network",
            "labelFingerprint": f"lprint{ident}=",
            "labels": labels,
            "name": name,
            "routingConfig": {"routingMode": "REGIONAL"},
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{project}/global/networks/{name}"
            ),
        }

    @staticmethod
    def not_found(name: str, command: str) -> Any:
        message = (
            f"ERROR: (gcloud.{command}) Could not fetch resource:\n"
            f" - The resource '{name}' was not found\n"
        )
        return DEPLOY.RunResult(b"", message.encode("ascii"), 1)

    def _describe_payload(self, key: str, builder: Any, command: str) -> Any:
        self.describe_counts[key] = self.describe_counts.get(key, 0) + 1
        if key in self.deleted and key not in self.present_after_delete:
            return self.not_found(key, command)
        if key not in self.cache:
            self.cache[key] = builder()
        payload = copy.deepcopy(self.cache[key])
        if self.describe_counts[key] >= 2 and key in self.identity_swap:
            payload.update(copy.deepcopy(self.identity_swap[key]))
        return DEPLOY.RunResult(json.dumps(payload).encode("ascii"), b"", 0)

    def run(self, argv: list[str], *, timeout_seconds: int) -> Any:
        del timeout_seconds
        if argv and argv[0] != "gcloud":
            raise AssertionError(f"unexpected non-gcloud command: {argv!r}")
        self.calls.append(list(argv))
        if argv[:4] == ["gcloud", "compute", "instances", "describe"]:
            name = argv[4]
            role = next(
                item
                for item, spec in self.context.instances.items()
                if spec["name"] == name
            )
            return self._describe_payload(
                name,
                lambda: self.instance_document(role),
                "compute.instances.describe",
            )
        if argv[:4] == ["gcloud", "compute", "firewall-rules", "describe"]:
            name = argv[4]
            return self._describe_payload(
                name,
                lambda: self.resource_document("firewall", name),
                "compute.firewall-rules.describe",
            )
        if argv[:5] == ["gcloud", "compute", "networks", "subnets", "describe"]:
            name = argv[5]
            region = next(
                item.removeprefix("--region=")
                for item in argv
                if item.startswith("--region=")
            )
            return self._describe_payload(
                name,
                lambda: self.resource_document("subnet", name, region),
                "compute.networks.subnets.describe",
            )
        if argv[:4] == ["gcloud", "compute", "networks", "describe"]:
            name = argv[4]
            return self._describe_payload(
                name,
                lambda: self.resource_document("network", name),
                "compute.networks.describe",
            )
        if argv[:4] == ["gcloud", "compute", "instances", "update"]:
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "instances", "delete"]:
            name = argv[4]
            if name in self.fail_delete:
                return DEPLOY.RunResult(b"", b"delete failed", 1)
            self.deleted.add(name)
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "firewall-rules", "delete"]:
            name = argv[4]
            if name in self.fail_delete:
                return DEPLOY.RunResult(b"", b"delete failed", 1)
            self.deleted.add(name)
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:5] == ["gcloud", "compute", "networks", "subnets", "delete"]:
            name = argv[5]
            if name in self.fail_delete:
                return DEPLOY.RunResult(b"", b"delete failed", 1)
            self.deleted.add(name)
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "networks", "delete"]:
            name = argv[4]
            if name in self.fail_delete:
                return DEPLOY.RunResult(b"", b"delete failed", 1)
            self.deleted.add(name)
            return DEPLOY.RunResult(b"", b"", 0)
        raise AssertionError(f"unexpected gcloud argv: {argv!r}")


def mutation_names(calls: list[list[str]]) -> list[str]:
    names: list[str] = []
    for call in calls:
        if call[:4] == ["gcloud", "compute", "instances", "delete"]:
            names.append(call[4])
        elif call[:4] == ["gcloud", "compute", "instances", "update"]:
            names.append(call[4])
        elif call[:4] == ["gcloud", "compute", "firewall-rules", "delete"]:
            names.append(call[4])
        elif call[:5] == ["gcloud", "compute", "networks", "subnets", "delete"]:
            names.append(call[5])
        elif call[:4] == ["gcloud", "compute", "networks", "delete"]:
            names.append(call[4])
    return names


def rollback_payload(
    *,
    role: str = "control",
    instance: str = "proof-control-a1",
    fleet_id: str = "proof-fleet-20260823",
    residuals: dict[str, list[str]] | None = None,
    inspected: list[str] | None = None,
    ok: bool | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    residual_map = residuals
    if residual_map is None:
        residual_map = {cls: [] for cls in DEPLOY.ROLLBACK_RESIDUAL_CLASSES}
    inspected_list = (
        list(DEPLOY.ROLLBACK_RESIDUAL_CLASSES) if inspected is None else inspected
    )
    present = any(residual_map[cls] for cls in residual_map)
    error_list = list(errors) if errors is not None else (
        ["residuals-present"] if present else []
    )
    payload = {
        "errors": error_list,
        "fleet_id": fleet_id,
        "inspected": inspected_list,
        "instance": instance,
        "kind": DEPLOY.KIND_ROLLBACK,
        "ok": (not error_list) if ok is None else ok,
        "removed_files": [],
        "residuals": residual_map,
        "role": role,
        "schema_version": 1,
        "services_stopped": list(DEPLOY.ROLLBACK_SERVICES[role]),
        "state_removed": True,
    }
    return payload


class CleanupPostconditionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = make_context()
        self.runner = PostconditionRunner(self.context)

    def identities(self) -> dict[str, Any]:
        apply_created = DEPLOY._parse_gce_timestamp(
            self.context.apply["created_utc"], "apply creation time"
        )
        return DEPLOY._preflight_identities(
            self.context,
            self.runner,
            now=datetime.now(timezone.utc),
            apply_created=apply_created,
        )

    def test_unauthorized_plan_inventories_targets_and_contains_no_mutations(
        self,
    ) -> None:
        plan = DEPLOY.plan_cleanup_execution(
            self.context, {}, authorized=False
        )
        self.assertIs(plan["authorized"], False)
        self.assertEqual(plan["steps"], [])
        self.assertEqual(plan["reason"], "cleanup not authorized")
        targets = plan["targets"]
        self.assertEqual(targets["project"], "winsvpn-proof-lab")
        self.assertEqual(targets["network"], "pf-proof-fleet-20260823-net")
        self.assertEqual(len(targets["firewalls"]), 4)
        self.assertEqual(len(targets["instances"]), 3)
        self.assertTrue(targets["units"])
        self.assertTrue(targets["users"])
        self.assertTrue(targets["binaries"])
        self.assertTrue(targets["config"])
        self.assertTrue(targets["timers"])
        self.assertTrue(targets["firewall_nat"])
        self.assertFalse(
            any(
                step.get("action") in DEPLOY.CLEANUP_PLAN_MUTATIONS
                for step in plan["steps"]
            )
        )

    def test_truthy_authorized_flag_performs_no_cloud_action(self) -> None:
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, {}, authorized=1
        )
        self.assertEqual(resources["status"], "skipped")
        self.assertEqual(resources["reason"], "cleanup not authorized")
        self.assertEqual(self.runner.calls, [])
        self.assertEqual(self.runner.deleted, set())

    def test_explicit_false_authorization_performs_no_deletion(self) -> None:
        identities = self.identities()
        before = list(self.runner.calls)
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=False
        )
        self.assertEqual(resources["status"], "skipped")
        self.assertEqual(mutation_names(self.runner.calls[len(before) :]), [])
        self.assertEqual(self.runner.deleted, set())
        self.assertIn("/usr/local/bin/winn3-gateway", resources["targets"]["binaries"])

    def test_stale_instance_identity_refuses_to_delete_that_vm(self) -> None:
        identities = self.identities()
        self.runner.identity_swap["proof-control-a1"] = {
            "id": "8888",
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                "winsvpn-proof-lab/zones/us-east1-b/instances/proof-control-a1"
            ),
        }
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=True
        )
        self.assertEqual(resources["status"], "failed")
        self.assertNotIn("proof-control-a1", self.runner.deleted)
        self.assertIn("proof-winn3-a1", self.runner.deleted)
        self.assertIn("proof-cover-a1", self.runner.deleted)
        confused = next(
            item
            for item in resources["results"]
            if item.get("role") == "control" and item.get("action") == "describe"
        )
        self.assertIs(confused["ok"], False)
        self.assertIn("creation transaction", confused["error"])

    def test_mismatched_firewall_fingerprint_is_not_deleted(self) -> None:
        identities = self.identities()
        firewall = "pf-proof-fleet-20260823-admin-ssh"
        self.runner.identity_swap[firewall] = {
            "id": "8888",
            "fingerprint": "REPLACED1=",
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                "winsvpn-proof-lab/global/firewalls/"
                f"{firewall}"
            ),
        }
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=True
        )
        self.assertEqual(resources["status"], "failed")
        self.assertNotIn(firewall, self.runner.deleted)
        self.assertIn("pf-proof-fleet-20260823-winn3-in", self.runner.deleted)
        confused = next(
            item
            for item in resources["results"]
            if item.get("name") == firewall and item.get("action") == "describe"
        )
        self.assertIs(confused["ok"], False)

    def test_partial_delete_failure_remains_failure(self) -> None:
        identities = self.identities()
        self.runner.fail_delete.add("proof-control-a1")
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=True
        )
        self.assertEqual(resources["status"], "failed")
        self.assertNotEqual(resources["status"], "passed")
        self.assertNotIn("proof-control-a1", self.runner.deleted)
        self.assertIn("proof-winn3-a1", self.runner.deleted)
        self.assertIn("proof-cover-a1", self.runner.deleted)

    def test_post_delete_presence_fails_closed(self) -> None:
        self.assertFalse(getattr(PostconditionRunner, "TEST_ONLY", False))
        identities = self.identities()
        self.runner.present_after_delete.add("proof-winn3-a1")
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=True
        )
        self.assertEqual(resources["status"], "failed")
        self.assertIn("proof-winn3-a1", self.runner.deleted)
        presence = next(
            item
            for item in resources["results"]
            if item.get("action") == "prove-absence"
            and item.get("name") == "proof-winn3-a1"
        )
        self.assertIs(presence["ok"], False)
        self.assertIn("post-delete presence", presence["error"])

    def test_authorized_delete_proves_absence_with_exact_name_describes(
        self,
    ) -> None:
        identities = self.identities()
        resources = DEPLOY.execute_cleanup_plan(
            self.context, self.runner, identities, authorized=True
        )
        self.assertEqual(resources["status"], "passed")
        names = {
            "proof-control-a1",
            "proof-winn3-a1",
            "proof-cover-a1",
            "pf-proof-fleet-20260823-admin-ssh",
            "pf-proof-fleet-20260823-winn3-in",
            "pf-proof-fleet-20260823-control-http",
            "pf-proof-fleet-20260823-cover-in",
            "pf-proof-fleet-20260823-sn-control",
            "pf-proof-fleet-20260823-sn-data-winn3",
            "pf-proof-fleet-20260823-sn-data-cover",
            "pf-proof-fleet-20260823-net",
        }
        self.assertEqual(self.runner.deleted, names)
        absences = [
            item
            for item in resources["results"]
            if item.get("action") == "prove-absence"
        ]
        self.assertEqual(len(absences), 11)
        self.assertTrue(all(item.get("ok") is True for item in absences))
        joined = [" ".join(call) for call in self.runner.calls]
        self.assertTrue(
            all("--filter" not in item and "--regex" not in item for item in joined)
        )
        self.assertFalse(
            any(
                token == "--all" or token.startswith("--all=")
                for call in self.runner.calls
                for token in call
            )
        )
        describe_names = [
            call[4]
            for call in self.runner.calls
            if call[:4] == ["gcloud", "compute", "instances", "describe"]
        ]
        self.assertIn("proof-control-a1", describe_names)
        self.assertTrue(
            all("*" not in token for call in self.runner.calls for token in call)
        )

    def test_rollback_residuals_refuse_success(self) -> None:
        payload = rollback_payload(
            residuals={
                "binaries": ["/usr/local/bin/winn3-gateway"],
                "config": [],
                "firewall_nat": [],
                "timers": [],
                "units": ["wins-hub.service"],
                "users": [],
            }
        )
        verdict = DEPLOY.evaluate_rollback_postconditions(payload)
        self.assertIs(verdict["ok"], False)
        self.assertIn("binaries:/usr/local/bin/winn3-gateway", verdict["present"])
        self.assertIn("units:wins-hub.service", verdict["present"])
        raw = DEPLOY._parse_rollback(
            DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 1),
            "control",
            "proof-control-a1",
            "proof-fleet-20260823",
        )
        self.assertIs(raw["ok"], False)

    def test_rollback_success_requires_empty_inspected_residuals(self) -> None:
        payload = rollback_payload()
        verdict = DEPLOY.evaluate_rollback_postconditions(payload)
        self.assertIs(verdict["ok"], True)
        self.assertEqual(verdict["present"], [])
        raw = DEPLOY._parse_rollback(
            DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0),
            "control",
            "proof-control-a1",
            "proof-fleet-20260823",
        )
        self.assertIs(raw["ok"], True)

    def test_rollback_claimed_success_with_residuals_is_refused(self) -> None:
        payload = rollback_payload(
            residuals={
                "binaries": [],
                "config": ["/etc/winsvpn"],
                "firewall_nat": [],
                "timers": [],
                "units": [],
                "users": [],
            },
            ok=True,
            errors=[],
        )
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "residuals remain"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )

    def test_stale_residual_name_is_refused(self) -> None:
        payload = rollback_payload(
            residuals={
                "binaries": [],
                "config": [],
                "firewall_nat": [],
                "timers": [],
                "units": ["sshd.service"],
                "users": [],
            }
        )
        verdict = DEPLOY.evaluate_rollback_postconditions(payload)
        self.assertIs(verdict["ok"], False)
        self.assertIn("outside the exact role allowlist", verdict["reason"])

    def test_incomplete_residual_inspection_is_failure(self) -> None:
        payload = rollback_payload(inspected=["units", "users"])
        verdict = DEPLOY.evaluate_rollback_postconditions(payload)
        self.assertIs(verdict["ok"], False)
        self.assertIn("incomplete", verdict["reason"])

    def test_bootstrap_source_inspects_every_residual_class(self) -> None:
        source = DEPLOY.REMOTE_ROLLBACK_BOOTSTRAP
        self.assertIn("residuals-present", source)
        self.assertIn("inspected", source)
        for cls in DEPLOY.ROLLBACK_RESIDUAL_CLASSES:
            self.assertIn(f'"{cls}"', source)
        for role in DEPLOY.ROLES:
            spec = DEPLOY.ROLLBACK_RESIDUALS[role]
            for cls in DEPLOY.ROLLBACK_RESIDUAL_CLASSES:
                for item in spec[cls]:
                    self.assertIn(item, source)
        self.assertIn("iptables", source)
        self.assertIn("getent", source)
        self.assertIn("/etc/systemd/system/", source)

    def test_absence_state_distinguishes_presence_from_not_found(self) -> None:
        present = DEPLOY.RunResult(
            json.dumps({"name": "proof-control-a1"}).encode("ascii"), b"", 0
        )
        self.assertEqual(
            DEPLOY._describe_absence_state(present, "proof-control-a1"), "present"
        )
        missing = DEPLOY.RunResult(
            b"",
            b"ERROR: The resource 'proof-control-a1' was not found\n",
            1,
        )
        self.assertEqual(
            DEPLOY._describe_absence_state(missing, "proof-control-a1"), "absent"
        )
        other = DEPLOY.RunResult(b"", b"permission denied", 1)
        self.assertEqual(
            DEPLOY._describe_absence_state(other, "proof-control-a1"),
            "inconclusive",
        )

    def test_hostile_auth_and_service_account_messages_are_not_absence(self) -> None:
        name = "proof-control-a1"
        compute = (
            b"The resource 'projects/winsvpn-proof-lab/zones/us-east1-b/"
            b"instances/proof-control-a1' was not found"
        )
        hostile = (
            (
                b"ERROR: (gcloud.iam.service-accounts.describe) The service "
                b"account 'proof-control-a1' was not found\n"
            ),
            (
                b"ERROR: (gcloud.iam.service-accounts.describe) Could not fetch "
                b"resource:\n - The resource "
                b"'projects/-/serviceAccounts/proof-control-a1' was not found\n"
            ),
            (
                b"ERROR: NOT_FOUND: proof-control-a1 was not found while "
                b"impersonating service account\n"
            ),
            b"ERROR: (gcloud.auth) oauth token for proof-control-a1 was not found\n",
            (
                b"ERROR: permission denied\nThe resource 'proof-control-a1' "
                b"was not found\n"
            ),
            b"HTTP 403: The resource 'proof-control-a1' was not found\n",
            b"ERROR: proof-control-a1 was not found\n",
            b"ERROR: (gcloud.compute.instances.describe) NOT_FOUND\n",
            b"ERROR: PERMISSION_DENIED: " + compute + b"\n",
            (
                b"ERROR: google.api_core.exceptions.PermissionDenied: "
                b"403 PERMISSION_DENIED: " + compute + b"\n"
            ),
            (
                b"ERROR: grpc._channel._InactiveRpcError status="
                b"StatusCode.PERMISSION_DENIED code = 7 details=\""
                + compute
                + b"\"\n"
            ),
            b"ERROR: gRPC code 7: " + compute + b"\n",
            (
                b"ERROR: Request had invalid authentication credentials. "
                + compute
                + b"\n"
            ),
            b"ERROR: Insufficient Permission\n" + compute + b"\n",
            (
                b"ERROR: Please run: gcloud auth login\n - "
                + compute
                + b"\n"
            ),
            (
                b"ERROR: (gcloud.projects.get-iam-policy) "
                + compute
                + b"\n"
            ),
            (
                b"ERROR: Compute Engine API has not been used in project "
                b"winsvpn-proof-lab before or it is disabled. "
                + compute
                + b"\n"
            ),
            (
                b"ERROR: API [compute.googleapis.com] not enabled on project "
                b"winsvpn-proof-lab\n"
                + compute
                + b"\n"
            ),
            b"ERROR: API disabled\n" + compute + b"\n",
            (
                b"ERROR: (gcloud.compute.instances.describe) Could not fetch "
                b"resource:\n - The resource "
                b"'projects/winsvpn-proof-lab/locations/us-east1/functions/"
                b"proof-control-a1' was not found\n"
            ),
            (
                b"ERROR: (gcloud.compute.disks.describe) Could not fetch "
                b"resource:\n - The resource "
                b"'projects/winsvpn-proof-lab/zones/us-east1-b/disks/"
                b"proof-control-a1' was not found\n"
            ),
        )
        for stderr in hostile:
            with self.subTest(stderr=stderr):
                result = DEPLOY.RunResult(b"", stderr, 1)
                self.assertEqual(
                    DEPLOY._describe_absence_state(result, name),
                    "inconclusive",
                )

    def test_exact_compute_resource_path_not_found_is_absence(self) -> None:
        cases = (
            (
                "proof-control-a1",
                (
                    b"ERROR: (gcloud.compute.instances.describe) Could not fetch "
                    b"resource:\n - The resource "
                    b"'projects/winsproof123/zones/us-east1-b/instances/"
                    b"proof-control-a1' was not found\n"
                ),
            ),
            (
                "pf-proof-fleet-20260823-net",
                (
                    b"ERROR: (gcloud.compute.networks.describe) Could not fetch "
                    b"resource:\n - The resource "
                    b"'projects/winsvpn-proof-lab/global/networks/"
                    b"pf-proof-fleet-20260823-net' was not found\n"
                ),
            ),
            (
                "pf-proof-fleet-20260823-admin-ssh",
                (
                    b"ERROR: (gcloud.compute.firewall-rules.describe) Could not "
                    b"fetch resource:\n - The resource "
                    b"'projects/winsvpn-proof-lab/global/firewalls/"
                    b"pf-proof-fleet-20260823-admin-ssh' was not found\n"
                ),
            ),
            (
                "pf-proof-fleet-20260823-sn-control",
                (
                    b"ERROR: (gcloud.compute.networks.subnets.describe) Could "
                    b"not fetch resource:\n - The resource "
                    b"'projects/winsvpn-proof-lab/regions/us-east1/subnetworks/"
                    b"pf-proof-fleet-20260823-sn-control' was not found\n"
                ),
            ),
        )
        for name, stderr in cases:
            with self.subTest(name=name):
                missing = DEPLOY.RunResult(b"", stderr, 1)
                self.assertEqual(DEPLOY._describe_absence_state(missing, name), "absent")
        prefix = DEPLOY.RunResult(
            b"",
            b"ERROR: The resource 'proof-control-a1-extra' was not found\n",
            1,
        )
        self.assertEqual(
            DEPLOY._describe_absence_state(prefix, "proof-control-a1"),
            "inconclusive",
        )

    def test_hostile_product_auth_grpc_wrappers_are_not_absence(self) -> None:
        name = "proof-control-a1"
        compute = (
            b"The resource 'projects/winsvpn-proof-lab/zones/us-east1-b/"
            b"instances/proof-control-a1' was not found"
        )
        bare = b"The resource 'proof-control-a1' was not found"
        genuine = (
            b"ERROR: (gcloud.compute.instances.describe) Could not fetch "
            b"resource:\n - " + compute + b"\n"
        )
        products = (
            "functions.describe",
            "run.services.describe",
            "sql.instances.describe",
            "storage.buckets.describe",
            "container.clusters.describe",
            "compute.describe",
            "compute.disks.describe",
            "compute.addresses.describe",
            "pubsub.topics.describe",
        )
        hostile: list[tuple[str, bytes]] = []
        for product in products:
            envelope = (
                f"ERROR: (gcloud.{product}) Could not fetch resource:\n - ".encode(
                    "ascii"
                )
            )
            hostile.append((f"{product} typed", envelope + compute + b"\n"))
            hostile.append((f"{product} bare", envelope + bare + b"\n"))
        hostile.extend(
            (
                (
                    "access-token-space",
                    b"Failed to retrieve access token from metadata server\n"
                    + compute
                    + b"\n",
                ),
                (
                    "stripped-reauth",
                    b"There was a problem refreshing your current auth tokens: "
                    b"Reauthentication is needed.\n" + compute + b"\n",
                ),
                (
                    "stripped-credentials",
                    b"Could not automatically determine credentials.\n"
                    + compute
                    + b"\n",
                ),
                (
                    "grpc-status-quoted-5",
                    b'ERROR: grpc_status="5"\n' + compute + b"\n",
                ),
                (
                    "grpc-status-eq-5",
                    b"ERROR: grpc_status=5\n" + compute + b"\n",
                ),
                (
                    "grpc-status-colon-5",
                    b"ERROR: grpc_status: 5\n" + compute + b"\n",
                ),
                (
                    "surrounding-warning",
                    b"WARNING: retrying request\n" + genuine,
                ),
            )
        )
        for label, stderr in hostile:
            with self.subTest(label=label):
                result = DEPLOY.RunResult(b"", stderr, 1)
                self.assertEqual(
                    DEPLOY._describe_absence_state(result, name),
                    "inconclusive",
                )
        contaminated = DEPLOY.RunResult(b"warning\n", genuine, 1)
        self.assertEqual(
            DEPLOY._describe_absence_state(contaminated, name),
            "inconclusive",
        )
        self.assertEqual(
            DEPLOY._describe_absence_state(DEPLOY.RunResult(b"", genuine, 1), name),
            "absent",
        )
        self.assertEqual(
            DEPLOY._describe_absence_state(
                DEPLOY.RunResult(b"", b"ERROR: " + bare + b"\n", 1), name
            ),
            "absent",
        )

    def test_legal_hyphen_token_resource_identifiers_are_absence(self) -> None:
        tokens = ("iam", "oauth", "grpc", "preauth", "reauth")
        cases: list[tuple[str, str, bytes]] = []
        for token in tokens:
            project = f"proof-{token}-lab"
            resource = f"proof-{token}-a1"
            cases.extend(
                (
                    (
                        f"{token}-bare-name",
                        resource,
                        f"ERROR: The resource '{resource}' was not found\n".encode(
                            "ascii"
                        ),
                    ),
                    (
                        f"{token}-exact-token-name",
                        token,
                        f"The resource '{token}' was not found".encode("ascii"),
                    ),
                    (
                        f"{token}-typed-project",
                        "proof-control-a1",
                        (
                            "ERROR: The resource "
                            f"'projects/{project}/zones/us-east1-b/instances/"
                            "proof-control-a1' was not found\n"
                        ).encode("ascii"),
                    ),
                    (
                        f"{token}-envelope-project",
                        "proof-control-a1",
                        (
                            "ERROR: (gcloud.compute.instances.describe) Could "
                            "not fetch resource:\n - The resource "
                            f"'projects/{project}/zones/us-east1-b/instances/"
                            "proof-control-a1' was not found\n"
                        ).encode("ascii"),
                    ),
                    (
                        f"{token}-envelope-resource",
                        resource,
                        (
                            "ERROR: (gcloud.compute.instances.describe) Could "
                            "not fetch resource:\n - The resource "
                            f"'projects/winsvpn-proof-lab/zones/us-east1-b/"
                            f"instances/{resource}' was not found\n"
                        ).encode("ascii"),
                    ),
                    (
                        f"{token}-network",
                        f"pf-proof-fleet-{token}-net",
                        (
                            "ERROR: (gcloud.compute.networks.describe) Could "
                            "not fetch resource:\n - The resource "
                            f"'projects/{project}/global/networks/"
                            f"pf-proof-fleet-{token}-net' was not found\n"
                        ).encode("ascii"),
                    ),
                    (
                        f"{token}-firewall",
                        f"pf-proof-fleet-{token}-ssh",
                        (
                            "ERROR: (gcloud.compute.firewall-rules.describe) "
                            "Could not fetch resource:\n - The resource "
                            f"'projects/{project}/global/firewalls/"
                            f"pf-proof-fleet-{token}-ssh' was not found\n"
                        ).encode("ascii"),
                    ),
                    (
                        f"{token}-subnet-crlf",
                        f"pf-proof-fleet-{token}-sn",
                        (
                            "ERROR: (gcloud.compute.networks.subnets.describe) "
                            "Could not fetch resource:\r\n - The resource "
                            f"'projects/{project}/regions/us-east1/subnetworks/"
                            f"pf-proof-fleet-{token}-sn' was not found"
                        ).encode("ascii"),
                    ),
                )
            )
        for label, name, stderr in cases:
            with self.subTest(label=label):
                result = DEPLOY.RunResult(b"", stderr, 1)
                self.assertEqual(
                    DEPLOY._describe_absence_state(result, name), "absent"
                )

    def test_hostile_wrappers_over_legal_hyphen_token_names_are_not_absence(
        self,
    ) -> None:
        name = "proof-control-a1"
        legal = (
            b"The resource 'projects/proof-iam-lab/zones/us-east1-b/"
            b"instances/proof-control-a1' was not found"
        )
        preauth = (
            b"The resource 'projects/preauth-proof/zones/us-east1-b/"
            b"instances/proof-control-a1' was not found"
        )
        reauth_name = "reauth"
        reauth_bare = b"The resource 'reauth' was not found"
        hostile = (
            (
                "iam-product",
                name,
                b"ERROR: (gcloud.iam.service-accounts.describe) Could not "
                b"fetch resource:\n - " + legal + b"\n",
            ),
            (
                "oauth-wrapper",
                name,
                b"ERROR: (gcloud.auth) oauth token for proof-control-a1 was "
                b"not found\n",
            ),
            (
                "grpc-wrapper",
                name,
                b"ERROR: gRPC code 7: " + legal + b"\n",
            ),
            (
                "grpc-status-5",
                name,
                b'ERROR: grpc_status="5"\n' + legal + b"\n",
            ),
            (
                "reauth-wrapper",
                name,
                b"There was a problem refreshing your current auth tokens: "
                b"Reauthentication is needed.\n" + legal + b"\n",
            ),
            (
                "preauth-permission",
                name,
                b"ERROR: permission denied\n" + preauth + b"\n",
            ),
            (
                "credentials-wrapper",
                name,
                b"Could not automatically determine credentials.\n"
                + legal
                + b"\n",
            ),
            (
                "service-account-impersonation",
                name,
                b"ERROR: NOT_FOUND: proof-control-a1 was not found while "
                b"impersonating service account\n",
            ),
            (
                "iamcredentials",
                name,
                b"ERROR: iamcredentials.googleapis.com denied "
                + legal
                + b"\n",
            ),
            (
                "reauth-name-with-reauth-wrapper",
                reauth_name,
                b"ERROR: Reauthentication is needed.\n" + reauth_bare + b"\n",
            ),
            (
                "access-token-over-oauth-project",
                name,
                b"Failed to retrieve access token from metadata server\n"
                b"The resource 'projects/proof-oauth-lab/zones/us-east1-b/"
                b"instances/proof-control-a1' was not found\n",
            ),
        )
        for label, resource_name, stderr in hostile:
            with self.subTest(label=label):
                result = DEPLOY.RunResult(b"", stderr, 1)
                self.assertEqual(
                    DEPLOY._describe_absence_state(result, resource_name),
                    "inconclusive",
                )


class CollectorEvidenceClosureTests(unittest.TestCase):
    """Hostile collect() gates. Never invoke gcloud or read credentials."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.helpers = load_module(
            "gcp_proof_fleet_test_evidence_lane",
            TOOLS / "gcp_proof_fleet_test.py",
        )

    def _actions(self, fixture: Any) -> list[str]:
        return [
            self.helpers.FakeRunner.options(argv)["action"]
            for argv in fixture.runner.calls
        ]

    def _control_mutations(self, fixture: Any) -> list[str]:
        return [
            action
            for action in self._actions(fixture)
            if action.startswith("inject") or action.startswith("withdraw")
        ]

    def test_happy_path_still_captures_the_fixed_command_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))
            evidence = fixture.collect()
            payload = json.loads(evidence.read_text(encoding="ascii"))
            self.assertEqual(
                [item["action"] for item in payload["records"]],
                list(self.helpers.FLEET.COLLECTOR_ACTIONS),
            )

    def test_marker_only_deployment_does_not_run_control_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))

            def marker_only(data: dict[str, Any]) -> dict[str, Any]:
                return {
                    "roles": [
                        {
                            "role": row["role"],
                            "instance": row["instance"],
                            "marker": row["marker"],
                        }
                        for row in data["roles"]
                    ]
                }

            fixture.runner.mutate["deployment"] = marker_only
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "marker-only collector observation"
            ):
                fixture.collect(target)
            self.assertEqual(self._control_mutations(fixture), [])
            self.assertFalse(target.exists())

    def test_empty_restore_stdout_fails_cleanup_postcondition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))
            fixture.runner.fail_action = "inject-awg-block"
            original_run = fixture.runner.run

            def run(argv: list[str], *, timeout_seconds: int) -> Any:
                result = original_run(argv, timeout_seconds=timeout_seconds)
                action = self.helpers.FakeRunner.options(argv)["action"]
                if action == "restore-awg":
                    return self.helpers.COLLECTOR.RunResult(b"", b"", 0)
                return result

            fixture.runner.run = run
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "collector cleanup failed"
            ):
                fixture.collect(target)
            self.assertFalse(target.exists())
            self.assertIn("restore-awg", self._actions(fixture))

    def test_duplicate_execution_receipt_refuses_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))
            extra = fixture.state / "deployment-execution-old.json"
            extra.write_text(
                (fixture.state / self.helpers.FLEET.EXECUTION_NAME).read_text(
                    encoding="ascii"
                ),
                encoding="ascii",
            )
            extra.chmod(0o400)
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "duplicate or mixed"
            ):
                fixture.collect(target)
            self.assertEqual(self._actions(fixture), [])
            self.assertFalse(target.exists())

    def test_mixed_candidate_does_not_run_control_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))

            def mix_candidate(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                for row in changed["roles"]:
                    row["candidate"] = copy.deepcopy(row["candidate"])
                    row["candidate"]["id"] = "d" * 64
                return changed

            fixture.runner.mutate["deployment"] = mix_candidate
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "candidate.id does not match"
            ):
                fixture.collect(target)
            self.assertEqual(self._control_mutations(fixture), [])
            self.assertFalse(target.exists())

    def test_frozen_clock_does_not_run_control_mutations(self) -> None:
        class FrozenClock:
            def __init__(self) -> None:
                self.value = datetime.now(timezone.utc).replace(microsecond=0)

            def __call__(self) -> datetime:
                return self.value

        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))
            fixture.clock = FrozenClock()
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "timestamps are frozen"
            ):
                fixture.collect(target)
            self.assertEqual(self._control_mutations(fixture), [])
            self.assertFalse(target.exists())

    def test_two_vm_inventory_does_not_run_control_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.helpers.Fixture(Path(tmp))

            def drop_cover(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                changed["instances"] = [
                    item
                    for item in changed["instances"]
                    if item["role"] != "data-cover"
                ]
                return changed

            fixture.runner.mutate["inventory"] = drop_cover
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(
                self.helpers.FLEET.FleetRefused, "inventory instance scope"
            ):
                fixture.collect(target)
            self.assertEqual(self._actions(fixture), ["inventory"])
            self.assertEqual(self._control_mutations(fixture), [])
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
