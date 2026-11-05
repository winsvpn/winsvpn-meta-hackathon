#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load_module(name: str, path: Path) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


fleet = load_module("gcp_proof_fleet", TOOLS / "gcp_proof_fleet.py")
probe = load_module("gcp_proof_live_probe", TOOLS / "gcp_proof_live_probe.py")


def write_local_python_receipt(root: Path) -> Path:
    inputs = probe.deployment_inputs
    executable = Path(sys.executable).resolve(strict=True)
    root.mkdir(parents=True, exist_ok=True)
    archive = root / "python-archive.bin"
    source = root / "python-source.bin"
    tree = root / "python-tree"
    tree.mkdir()
    archive.write_bytes(b"winsvpn-python-archive\n")
    source.write_bytes(b"winsvpn-python-source\n")
    marker = tree / "marker"
    marker.write_bytes(b"winsvpn-python-tree\n")
    archive.chmod(0o400)
    source.chmod(0o400)
    marker.chmod(0o400)
    measured = inputs.measure_python_runtime_identity(
        executable=executable,
        archive=archive,
        install_tree=tree,
        source=source,
    )
    record = {
        "archive_path": measured["archive_path"],
        "archive_sha256": measured["archive_sha256"],
        "contract": inputs.PYTHON_RUNTIME_CONTRACT,
        "executable_path": measured["executable_path"],
        "executable_sha256": measured["executable_sha256"],
        "implementation": "cpython",
        "install_tree_path": measured["install_tree_path"],
        "install_tree_sha256": measured["install_tree_sha256"],
        "kind": inputs.PYTHON_RUNTIME_KIND,
        "schema_version": inputs.PYTHON_RUNTIME_SCHEMA_VERSION,
        "source_path": measured["source_path"],
        "source_sha256": measured["source_sha256"],
        "version": "%d.%d.%d" % sys.version_info[:3],
    }
    path = root / "python-runtime-receipt.json"
    path.write_bytes(inputs.canonical_bytes(record))
    path.chmod(0o400)
    return path


def write_remote_python_receipt(
    root: Path,
    *,
    executable: str = "/opt/winsvpn/python3.14",
    version: str = "3.14.0",
) -> Path:
    inputs = probe.deployment_inputs
    root.mkdir(parents=True, exist_ok=True)
    record = {
        "archive_path": "/opt/winsvpn/python-archive.bin",
        "archive_sha256": "a" * 64,
        "contract": inputs.PYTHON_RUNTIME_CONTRACT,
        "executable_path": executable,
        "executable_sha256": "b" * 64,
        "implementation": "cpython",
        "install_tree_path": "/opt/winsvpn/python-tree",
        "install_tree_sha256": "c" * 64,
        "kind": inputs.PYTHON_RUNTIME_KIND,
        "schema_version": inputs.PYTHON_RUNTIME_SCHEMA_VERSION,
        "source_path": "/opt/winsvpn/python-source.bin",
        "source_sha256": "d" * 64,
        "version": version,
    }
    path = root / "remote-python-runtime.json"
    path.write_bytes(inputs.canonical_bytes(record))
    path.chmod(0o400)
    return path


def write_service_account_credential(
    root: Path, *, account: str = "proof@winsproof123.iam.gserviceaccount.com",
    project: str = "winsproof123",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / "bound-credential.json"
    payload = {
        "type": "service_account",
        "project_id": project,
        "private_key_id": "fixture",
        "private_key": (
            "-----BEGIN PRIVATE KEY-----\n"
            "TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL\n"
            "-----END PRIVATE KEY-----\n"
        ),
        "client_email": account,
        "client_id": "1234567890",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="ascii")
    path.chmod(0o400)
    return path


def sample_spec() -> fleet.FleetSpec:
    return fleet.build_spec(
        project="winsproof123",
        control_name="proof-control-a1",
        winn3_data_name="proof-winn3-a1",
        cover_data_name="proof-cover-a1",
        control_zone="us-central1-a",
        winn3_data_zone="us-central1-b",
        cover_data_zone="us-east1-b",
        control_machine="e2-standard-2",
        winn3_data_machine="e2-standard-4",
        cover_data_machine="e2-standard-4",
        admin_source_cidr="203.0.113.0/24",
        dataplane_source_cidr="198.51.100.0/24",
        image_family=fleet.DEFAULT_IMAGE_FAMILY,
        image_project=fleet.DEFAULT_IMAGE_PROJECT,
        gcloud_bin="gcloud",
    )


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.spec = sample_spec()
        self.repo = self.root / "repo"
        self.repo.mkdir(mode=0o700)
        self.release_index = self.repo / ".artifacts/freeze/RELEASE_INPUT_INDEX.json"
        self.build_receipt = self.repo / ".artifacts/freeze/LINUX_BUILD_RECEIPT.json"
        self.client = self.repo / "build/linux/x64/winsvpn-proof-client"
        self.release_index.parent.mkdir(parents=True)
        self.client.parent.mkdir(parents=True)
        self.release_index.write_bytes(b"exact release input index\n")
        self.build_receipt.write_bytes(b"exact Linux build receipt\n")
        self.client.write_bytes(b"#!/bin/sh\nexit 91\n")
        os.chmod(self.client, 0o700)
        def ref(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "bytes": len(data),
                "path": str(path),
                "sha256": fleet.sha256_bytes(data),
            }
        binding = {
            "artifact": ref(self.client),
            "artifact_input_fingerprint_sha256": "d" * 64,
            "build_identity": f"linux:1.0.15+30:{'e' * 64}",
            "build_receipt": ref(self.build_receipt),
            "contract": fleet.client_binding.CONTRACT,
            "platform": "linux",
            "release": "1.0.15+30",
            "release_input_index": ref(self.release_index),
            "schema_version": fleet.client_binding.SCHEMA_VERSION,
            "shared_revision": "reviewed-linux-revision",
            "proof_build": {
                "build_contract": {"sha256": "1" * 64},
                "build_identity": "e" * 64,
                "builder": {"sha256": "2" * 64},
                "defines": {"release": "1.0.15+30"},
                "source": {"sha256": "3" * 64},
                "target": {"goos": "linux", "goarch": "amd64"},
                "toolchain": {"name": "Go", "version": "1.27.1"},
                "toolchain_pin_manifest": {"sha256": "4" * 64},
            },
        }
        self.client_release_binding_ref = {
            "binding": binding,
            "binding_sha256": fleet.sha256_bytes(
                fleet.client_binding.canonical_bytes(binding)
            ),
            "contract": fleet.CLIENT_BINDING_REFERENCE_CONTRACT,
            "repo_root": str(self.repo),
            "schema_version": 1,
            "verifier_closure": fleet._client_binding_verifier_closure(),
        }
        self.execution = self.root / "deployment-execution.json"
        self.execution.write_bytes(b'{"kind":"test-execution"}\n')
        execution_ref = {
            "bytes": self.execution.stat().st_size,
            "path": str(self.execution),
            "sha256": fleet.sha256_bytes(self.execution.read_bytes()),
        }
        self.driver = Path(probe.__file__).absolute()
        self.bindings = fleet.collector_record_bindings(
            spec=self.spec,
            plan_digest="a" * 64,
            apply_digest="b" * 64,
            client_release_binding=self.client_release_binding_ref,
            probe_driver=fleet.executable_ref(self.driver, label="test driver"),
            run_id="run-20260823-a",
            session_id="session-20260823-a",
            correlation_id="correlation-20260823-a",
            deployment_execution=execution_ref,
            deployment_candidate_id="c" * 64,
            deployment_manifest_sha256="b" * 64,
            deployment_record_chain_sha256="d" * 64,
        )

    def args(self, action: str) -> object:
        command = next(
            item
            for item in fleet.collector_command_specs(
                self.driver, self.spec, self.bindings
            )
            if item["action"] == action
        )
        return probe.parser().parse_args(command["argv"][1:])


class InventoryRunner:
    TEST_ONLY = True
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.calls: list[list[str]] = []
        self.source_image_matches = True
        self.can_ip_forward_overrides: dict[str, object] = {}

    @staticmethod
    def encoded(value: object) -> probe.Result:
        return probe.Result(
            (json.dumps(value, sort_keys=True) + "\n").encode("ascii"), b"", 0
        )

    def run(self, argv: list[str], *, timeout_seconds: int) -> probe.Result:
        self.calls.append(list(argv))
        self.fixture.test_case.assertIsInstance(argv, list)
        self.fixture.test_case.assertEqual(timeout_seconds, 120)
        spec = self.fixture.spec
        resources = fleet.resource_names(spec)
        joined = " ".join(argv)
        if " networks describe " in f" {joined} ":
            return self.encoded(
                {
                    "name": resources["network"],
                    "autoCreateSubnetworks": False,
                    "routingConfig": {"routingMode": "REGIONAL"},
                }
            )
        if " subnets describe " in f" {joined} ":
            name = argv[argv.index("describe") + 1]
            expected = next(item for item in resources["subnets"] if item["name"] == name)
            return self.encoded(
                {
                    "name": name,
                    "region": f"https://compute/v1/projects/x/regions/{expected['region']}",
                    "ipCidrRange": expected["cidr"],
                    "network": f"https://compute/v1/projects/x/global/networks/{resources['network']}",
                }
            )
        if " images describe " in f" {joined} ":
            name = argv[argv.index("describe") + 1]
            return self.encoded(
                {
                    "name": name,
                    "id": "1234567890123456789",
                    "selfLink": f"https://compute/v1/projects/ubuntu-os-cloud/global/images/{name}",
                    "family": self.fixture.spec.image_family if self.source_image_matches else "ubuntu-2204-lts",
                }
            )
        if " instances describe " in f" {joined} ":
            name = argv[argv.index("describe") + 1]
            item = next(value for value in spec.instances if value.name == name)
            subnet = next(
                value
                for value in resources["subnets"]
                if value["role"] == item.role
            )
            return self.encoded(
                {
                    "name": item.name,
                    "zone": f"https://compute/v1/projects/x/zones/{item.zone}",
                    "machineType": f"https://compute/v1/projects/x/zones/{item.zone}/machineTypes/{item.machine_type}",
                    "status": "RUNNING",
                    "disks": [{"source": f"https://compute/v1/projects/x/zones/{item.zone}/disks/{item.name}-boot"}],
                    "networkInterfaces": [
                        {
                            "network": f"https://compute/v1/projects/x/global/networks/{resources['network']}",
                            "subnetwork": f"https://compute/v1/projects/x/regions/{subnet['region']}/subnetworks/{subnet['name']}",
                        }
                    ],
                    "metadata": {
                        "items": [
                            {"key": "enable-oslogin", "value": "TRUE"},
                            {"key": "winsvpn-proof-role", "value": item.role},
                        ]
                    },
                    "serviceAccounts": [],
                    "shieldedInstanceConfig": {
                        "enableSecureBoot": True,
                        "enableVtpm": True,
                        "enableIntegrityMonitoring": True,
                    },
                    "deletionProtection": True,
                    "canIpForward": self.can_ip_forward_overrides.get(
                        item.role, item.role in {"data-winn3", "data-cover"}
                    ),
                    "labels": {
                        "winsvpn-proof-fleet": "1",
                        "winsvpn-proof-role": item.role,
                        "winsvpn-proof-id": resources["fleet_id"],
                    },
                    "tags": {
                        "items": [resources["tags"]["fleet"], resources["tags"][item.role]]
                    },
                }
            )
        if " disks describe " in f" {joined} ":
            suffix = "ubuntu-2404-noble-amd64-v20260801"
            return self.encoded(
                {"sourceImage": f"https://compute/v1/projects/ubuntu-os-cloud/global/images/{suffix}"}
            )
        raise AssertionError(f"unexpected fake command: {argv!r}")


class ClientActionRunner:
    TEST_ONLY = True
    def __init__(self, fixture: Fixture, action_data: dict[str, object]) -> None:
        self.fixture = fixture
        self.action_data = action_data
        self.calls: list[list[str]] = []
        self.foreign_network = False

    @staticmethod
    def encoded(value: object) -> probe.Result:
        return probe.Result(
            (json.dumps(value, sort_keys=True) + "\n").encode("ascii"), b"", 0
        )

    def run(self, argv: list[str], *, timeout_seconds: int) -> probe.Result:
        self.calls.append(list(argv))
        if timeout_seconds != 120:
            raise AssertionError("unexpected timeout")
        binding = self.fixture.client_release_binding_ref["binding"]
        proof_build = binding["proof_build"]
        if argv == [str(self.fixture.client), "--winsvpn-proof-identity"]:
            return self.encoded(
                {
                    "schema_version": 1,
                    "contract": "winsvpn-gcp-proof-client-identity-v1",
                    "release": binding["release"],
                    "shared_revision": binding["shared_revision"],
                    "source_sha256": proof_build["source"]["sha256"],
                    "build_contract_sha256": proof_build["build_contract"]["sha256"],
                    "toolchain_version": "go" + proof_build["toolchain"]["version"],
                    "target": "linux/amd64",
                    "build_identity": proof_build["build_identity"],
                }
            )
        if argv and argv[0] == str(self.fixture.client):
            return self.encoded(self.action_data)
        joined = " ".join(argv)
        if " instances list " in f" {joined} ":
            return self.encoded(
                [
                    {
                        "name": item.name,
                        "zone": f"https://compute/v1/projects/x/zones/{item.zone}",
                        "labels": {
                            "winsvpn-proof-fleet": "1",
                            "winsvpn-proof-id": self.fixture.bindings["fleet_id"],
                            "winsvpn-proof-role": item.role,
                        },
                    }
                    for item in self.fixture.spec.instances
                ]
            )
        resources = fleet.resource_names(self.fixture.spec)
        if " networks list " in f" {joined} ":
            rows = [{"name": resources["network"]}]
            if self.foreign_network:
                rows.append({"name": "pf-ffffffffffff-net"})
            return self.encoded(rows)
        if " subnets list " in f" {joined} ":
            return self.encoded([{"name": item["name"]} for item in resources["subnets"]])
        if " firewall-rules list " in f" {joined} ":
            return self.encoded([{"name": name} for name in resources["firewalls"].values()])
        raise AssertionError(f"unexpected fake command: {argv!r}")


class DeploymentRunner:
    TEST_ONLY = True
    def __init__(self, fixture: Fixture, observation: dict[str, object]) -> None:
        self.fixture = fixture
        self.observation = observation
        self.calls: list[list[str]] = []
        self.mutate_role: str | None = None
        self.mutator: Any = None

    @staticmethod
    def encoded(value: object) -> probe.Result:
        return probe.Result(
            (json.dumps(value, sort_keys=True) + "\n").encode("ascii"), b"", 0
        )

    def run(self, argv: list[str], *, timeout_seconds: int) -> probe.Result:
        self.calls.append(list(argv))
        self.fixture.test_case.assertEqual(timeout_seconds, 120)
        name = argv[argv.index("ssh") + 1]
        row = next(
            item
            for item in self.observation["roles"]
            if item["instance"] == name
        )
        payload = copy.deepcopy(row)
        if self.mutate_role == payload["role"] and self.mutator is not None:
            payload = self.mutator(payload)
        return self.encoded(payload)


class ProbeDriverTests(unittest.TestCase):
    def test_gcloud_581_runtime_version_is_accepted(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = probe.Result(
            b'{"Google Cloud SDK":"582.0.0"}\n', b"", 0
        )
        self.assertEqual(probe.verify_gcloud_version(runner, "gcloud"), "582.0.0")
        runner.run.assert_called_once_with(
            ["gcloud", "version", "--format=json"], timeout_seconds=120
        )

    def test_wrong_gcloud_runtime_version_is_refused(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = probe.Result(
            b'{"Google Cloud SDK":"579.0.0"}\n', b"", 0
        )
        with self.assertRaisesRegex(fleet.FleetRefused, "version mismatch"):
            probe.verify_gcloud_version(runner, "/opt/google/bin/gcloud")

    def test_collector_specs_are_exactly_sixteen_and_driver_parses_every_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            commands = fleet.collector_command_specs(
                fixture.driver, fixture.spec, fixture.bindings
            )
            self.assertEqual([item["action"] for item in commands], list(fleet.COLLECTOR_ACTIONS))
            self.assertEqual(len(commands), 16)
            for command in commands:
                parsed = probe.parser().parse_args(command["argv"][1:])
                self.assertEqual(parsed.action, command["action"])
                self.assertEqual(parsed.project, fixture.spec.project)
                self.assertEqual(parsed.image_family, fixture.spec.image_family)

    def test_inventory_is_parser_derived_and_matches_apply_bound_posture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.test_case = self
            runner = InventoryRunner(fixture)
            observed = probe.inventory(fixture.args("inventory"), runner)
            expected = fleet.expected_inventory_data(fixture.spec)
            for item in expected["instances"]:
                item["image_name"] = "ubuntu-2404-noble-amd64-v20260801"
                item["image_id"] = "1234567890123456789"
            self.assertEqual(observed, expected)
            self.assertGreaterEqual(len(runner.calls), 10)

    def test_inventory_rejects_boot_disk_outside_resolved_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.test_case = self
            runner = InventoryRunner(fixture)
            runner.source_image_matches = False
            with self.assertRaisesRegex(fleet.FleetRefused, "boot disk"):
                probe.inventory(fixture.args("inventory"), runner)

    def test_inventory_rejects_can_ip_forward_role_mutations(self) -> None:
        for role, mutation in (
            ("control", True),
            ("data-winn3", False),
            ("data-cover", False),
            ("data-winn3", 1),
        ):
            with self.subTest(role=role, mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                fixture = Fixture(Path(tmp))
                fixture.test_case = self
                runner = InventoryRunner(fixture)
                runner.can_ip_forward_overrides[role] = mutation
                with self.assertRaisesRegex(fleet.FleetRefused, "canIpForward"):
                    probe.inventory(fixture.args("inventory"), runner)

    def test_live_subprocess_runner_disables_shell(self) -> None:
        completed = mock.Mock(stdout=b"{}\n", stderr=b"", returncode=0)
        with mock.patch.object(probe.subprocess, "run", return_value=completed) as run:
            result = probe.SubprocessRunner().run(["gcloud", "version"], timeout_seconds=7)
        self.assertEqual(result.exit_code, 0)
        _, kwargs = run.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", kwargs["env"])
        self.assertNotIn(probe.CREDENTIAL_PATH_ENV, kwargs["env"])

    def test_client_action_checks_compiled_identity_and_uses_fixed_release_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            args = fixture.args("route-decision")
            data = {
                "served_carrier": "winn3",
                "descriptor_node": fixture.spec.by_role["data-winn3"].name,
                "selected_node": fixture.spec.by_role["data-winn3"].name,
                "descriptor_sha256": "a" * 64,
                "signature_state": "verified",
                "canary_state": "reachable",
            }
            runner = ClientActionRunner(fixture, data)
            with mock.patch.object(
                probe,
                "verified_client_release",
                return_value=fixture.client_release_binding_ref,
            ):
                self.assertEqual(probe.client_action(args, runner), data)
            self.assertEqual(
                runner.calls[0],
                [str(fixture.client), "--winsvpn-proof-identity"],
            )
            self.assertEqual(
                runner.calls[1],
                [
                    str(fixture.client),
                    "--winsvpn-proof-action", "route-decision",
                    "--project", fixture.spec.project,
                    "--gcloud-bin", fixture.spec.gcloud_bin,
                    "--fleet-id", fixture.bindings["fleet_id"],
                    "--control-instance", fixture.spec.by_role["control"].name,
                    "--control-zone", fixture.spec.by_role["control"].zone,
                    "--winn3-data-instance", fixture.spec.by_role["data-winn3"].name,
                    "--winn3-data-zone", fixture.spec.by_role["data-winn3"].zone,
                    "--cover-data-instance", fixture.spec.by_role["data-cover"].name,
                    "--cover-data-zone", fixture.spec.by_role["data-cover"].zone,
                    "--run-id", fixture.bindings["run_id"],
                    "--session-id", fixture.bindings["session_id"],
                    "--correlation-id", fixture.bindings["correlation_id"],
                ],
            )

    def test_client_action_forwards_bound_credential_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            args = fixture.args("route-decision")
            credential_path = write_service_account_credential(Path(tmp) / "cred")
            args.credential_kind = "service_account"
            args.credential_path = str(credential_path)
            args.credential_account = "proof@winsproof123.iam.gserviceaccount.com"
            args.credential_project = "winsproof123"
            data = {
                "served_carrier": "winn3",
                "descriptor_node": fixture.spec.by_role["data-winn3"].name,
                "selected_node": fixture.spec.by_role["data-winn3"].name,
                "descriptor_sha256": "a" * 64,
                "signature_state": "verified",
                "canary_state": "reachable",
            }
            runner = ClientActionRunner(fixture, data)
            with mock.patch.object(
                probe,
                "verified_client_release",
                return_value=fixture.client_release_binding_ref,
            ):
                self.assertEqual(probe.client_action(args, runner), data)
            self.assertEqual(
                runner.calls[1][-8:],
                [
                    "--credential-kind", "service_account",
                    "--credential-path", str(credential_path),
                    "--credential-account", "proof@winsproof123.iam.gserviceaccount.com",
                    "--credential-project", "winsproof123",
                ],
            )
            joined = " ".join(runner.calls[1])
            self.assertNotIn("BEGIN", joined)
            self.assertNotIn("PRIVATE", joined)
            self.assertNotIn("TEST_GCLOUD_FAKE_PRIVATE_KEY_MATERIAL", joined)

    def test_client_action_refuses_mismatched_credential_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            args = fixture.args("route-decision")
            credential_path = write_service_account_credential(Path(tmp) / "cred")
            args.credential_kind = "service_account"
            args.credential_path = str(credential_path)
            args.credential_account = "proof@winsproof123.iam.gserviceaccount.com"
            args.credential_project = "otherproof123"
            runner = ClientActionRunner(fixture, {"served_carrier": "winn3"})
            with mock.patch.object(
                probe,
                "verified_client_release",
                return_value=fixture.client_release_binding_ref,
            ), self.assertRaisesRegex(
                fleet.FleetRefused, "credential project does not match the bound project"
            ):
                probe.client_action(args, runner)
            self.assertEqual(
                runner.calls,
                [[str(fixture.client), "--winsvpn-proof-identity"]],
            )

    def test_client_action_refuses_partial_credential_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            args = fixture.args("route-decision")
            args.credential_kind = "service_account"
            args.credential_path = ""
            args.credential_account = ""
            args.credential_project = ""
            runner = ClientActionRunner(fixture, {"served_carrier": "winn3"})
            with mock.patch.object(
                probe,
                "verified_client_release",
                return_value=fixture.client_release_binding_ref,
            ), self.assertRaisesRegex(fleet.FleetRefused, "owner blocker:.*credential"):
                probe.client_action(args, runner)

    def test_teardown_refuses_client_empty_lists_when_project_inventory_is_foreign(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            args = fixture.args("teardown-check")
            resources = fleet.resource_identity(fixture.spec)
            data = {
                "expected_resources": resources,
                "observed_resources": resources,
                "unexpected_targets": [],
                "foreign_resource_ids": [],
                "credential_files_read": [],
                "production_resources_touched": [],
            }
            runner = ClientActionRunner(fixture, data)
            runner.foreign_network = True
            with mock.patch.object(
                probe,
                "verified_client_release",
                return_value=fixture.client_release_binding_ref,
            ), self.assertRaisesRegex(fleet.FleetRefused, "independent project inventory"):
                probe.client_action(args, runner)

    def test_output_parent_swap_is_detected_while_directory_fd_is_held(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            moved = root / "moved"
            original_link = fleet.os.link
            swapped = False

            def swap_then_link(*args: object, **kwargs: object) -> None:
                nonlocal swapped
                if not swapped:
                    state.rename(moved)
                    state.mkdir(mode=0o700)
                    os.chmod(state, 0o700)
                    swapped = True
                original_link(*args, **kwargs)

            with mock.patch.object(fleet.os, "link", side_effect=swap_then_link):
                with self.assertRaisesRegex(fleet.FleetRefused, "parent changed"):
                    fleet.write_json_document(state / "evidence.json", {"x": 1}, immutable=True)
            self.assertFalse((state / "evidence.json").exists())
            self.assertFalse((moved / "evidence.json").exists())

    def test_hardlinked_document_and_executable_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            document = root / "document.json"
            document.write_text("{}\n", encoding="ascii")
            os.link(document, root / "document-alias.json")
            with self.assertRaisesRegex(fleet.FleetRefused, "regular non-symlink"):
                fleet.read_stable_file(document.absolute(), label="hardlinked document")
            executable = root / "driver"
            executable.write_bytes(b"#!/bin/sh\nexit 1\n")
            os.chmod(executable, 0o700)
            os.link(executable, root / "driver-alias")
            with self.assertRaisesRegex(fleet.FleetRefused, "regular non-symlink"):
                fleet.executable_ref(executable, label="hardlinked executable")

    def test_deployment_binds_remote_marker_runtime_and_candidate(self) -> None:
        from gcp_proof_fleet_test import (
            CORRELATION_ID,
            RUN_ID,
            SESSION_ID,
            Fixture as CollectorFixture,
            sample_deployment_observation,
        )

        with tempfile.TemporaryDirectory() as tmp:
            collector = CollectorFixture(Path(tmp))
            driver = Path(probe.__file__).absolute()
            bindings = fleet.collector_record_bindings(
                spec=collector.spec,
                plan_digest=collector.plan_digest,
                apply_digest=collector.apply_digest,
                client_release_binding=collector.client_release_binding_ref,
                probe_driver=fleet.executable_ref(driver, label="reviewed probe driver"),
                run_id=RUN_ID,
                session_id=SESSION_ID,
                correlation_id=CORRELATION_ID,
                deployment_execution=collector.execution_ref,
                deployment_candidate_id=collector.candidate_id,
                deployment_manifest_sha256=collector.deployment_inputs_digest,
                deployment_record_chain_sha256=collector.execution_payload[
                    "record_chain_sha256"
                ],
            )
            args = probe.parser().parse_args(
                next(
                    item["argv"]
                    for item in fleet.collector_command_specs(
                        driver, collector.spec, bindings
                    )
                    if item["action"] == "deployment"
                )[1:]
            )
            observation = sample_deployment_observation(
                collector.spec,
                collector.candidate_id,
                collector.execution_payload["markers"],
            )
            probe_root = Path(tmp) / "probe-harness"
            probe_root.mkdir()
            fixture = Fixture(probe_root)
            fixture.test_case = self
            fixture.spec = collector.spec
            runner = DeploymentRunner(fixture, observation)
            receipt = write_remote_python_receipt(Path(tmp) / "remote-runtime")
            with mock.patch.dict(
                os.environ,
                {probe.deployment_inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(receipt)},
            ):
                observed = probe.deployment(args, runner)
            self.assertEqual(observed, observation)
            self.assertEqual(len(runner.calls), 3)
            for call in runner.calls:
                command = next(item for item in call if item.startswith("--command="))
                self.assertTrue(
                    command.startswith(
                        "--command=/usr/bin/sudo --non-interactive /opt/winsvpn/python3.14"
                    )
                )
                self.assertEqual(command.count("/usr/bin/sudo"), 1)
                self.assertNotIn(" sudo ", command)
                self.assertNotIn("--command=python3 ", command)
            self.assertEqual(
                probe.REMOTE_SUDO_ARGV,
                ("/usr/bin/sudo", "--non-interactive"),
            )
            self.assertFalse(
                any("sudo" in action.dest for action in probe.parser()._actions)
            )

    def test_live_probe_rejects_candidate_and_runtime_substitution(self) -> None:
        from gcp_proof_fleet_test import (
            CORRELATION_ID,
            RUN_ID,
            SESSION_ID,
            Fixture as CollectorFixture,
            sample_deployment_observation,
        )

        with tempfile.TemporaryDirectory() as tmp:
            collector = CollectorFixture(Path(tmp))
            driver = Path(probe.__file__).absolute()
            bindings = fleet.collector_record_bindings(
                spec=collector.spec,
                plan_digest=collector.plan_digest,
                apply_digest=collector.apply_digest,
                client_release_binding=collector.client_release_binding_ref,
                probe_driver=fleet.executable_ref(driver, label="reviewed probe driver"),
                run_id=RUN_ID,
                session_id=SESSION_ID,
                correlation_id=CORRELATION_ID,
                deployment_execution=collector.execution_ref,
                deployment_candidate_id=collector.candidate_id,
                deployment_manifest_sha256=collector.deployment_inputs_digest,
                deployment_record_chain_sha256=collector.execution_payload[
                    "record_chain_sha256"
                ],
            )
            args = probe.parser().parse_args(
                next(
                    item["argv"]
                    for item in fleet.collector_command_specs(
                        driver, collector.spec, bindings
                    )
                    if item["action"] == "deployment"
                )[1:]
            )
            observation = sample_deployment_observation(
                collector.spec,
                collector.candidate_id,
                collector.execution_payload["markers"],
            )
            probe_root = Path(tmp) / "probe-harness"
            probe_root.mkdir()
            fixture = Fixture(probe_root)
            fixture.test_case = self
            fixture.spec = collector.spec
            runner = DeploymentRunner(fixture, observation)
            runner.mutate_role = "data-winn3"
            runner.mutator = lambda row: {**row, "candidate": {**row["candidate"], "id": "0" * 64}}
            receipt = write_remote_python_receipt(Path(tmp) / "remote-runtime")
            with mock.patch.dict(
                os.environ,
                {probe.deployment_inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(receipt)},
            ):
                with self.assertRaisesRegex(fleet.FleetRefused, "candidate"):
                    probe.deployment(args, runner)
                runner.mutator = lambda row: {
                    **row,
                    "runtime": {
                        **row["runtime"],
                        "xray": {**row["runtime"]["xray"], "sha256": "f" * 64},
                    },
                }
                with self.assertRaisesRegex(fleet.FleetRefused, "runtime"):
                    probe.deployment(args, runner)

    def test_inherited_credential_env_does_not_reach_proof_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            client = Path(tmp) / "winsvpn-proof-client"
            client.write_text(
                "#!/bin/sh\n"
                "for name in GOOGLE_APPLICATION_CREDENTIALS "
                "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE "
                "DOCKER_CONFIG KUBECONFIG NETRC SSH_AUTH_SOCK "
                f"{probe.CREDENTIAL_PATH_ENV}; do\n"
                "  eval value=\\$$name\n"
                "  if [ -n \"$value\" ]; then printf 'HAS_%s\\n' \"$name\"; fi\n"
                "done\n"
                "printf 'CLEAN\\n'\n",
                encoding="ascii",
            )
            client.chmod(0o700)
            poisoned = {
                "GOOGLE_APPLICATION_CREDENTIALS": str(Path(tmp) / "secret.json"),
                "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": str(Path(tmp) / "secret.json"),
                "DOCKER_CONFIG": str(Path(tmp) / "docker"),
                "KUBECONFIG": str(Path(tmp) / "kube"),
                "NETRC": str(Path(tmp) / "netrc"),
                "SSH_AUTH_SOCK": str(Path(tmp) / "ssh"),
                probe.CREDENTIAL_PATH_ENV: str(Path(tmp) / "secret.json"),
            }
            with mock.patch.dict(os.environ, poisoned, clear=False):
                result = probe.SubprocessRunner().run([str(client)], timeout_seconds=5)
            combined = result.stdout + result.stderr
            self.assertEqual(result.stdout, b"CLEAN\n")
            self.assertNotIn(b"HAS_", combined)
            self.assertNotIn(b"secret.json", combined)

    def test_missing_credential_is_owner_blocker(self) -> None:
        cleared = {
            probe.CREDENTIAL_KIND_ENV: "",
            probe.CREDENTIAL_PATH_ENV: "",
            probe.CREDENTIAL_ACCOUNT_ENV: "",
            probe.CREDENTIAL_PROJECT_ENV: "",
        }
        with mock.patch.dict(os.environ, cleared, clear=False):
            with self.assertRaisesRegex(fleet.FleetRefused, "owner blocker:.*credential") as caught:
                probe.require_authenticated_gcloud_credential()
        self.assertNotIn("BEGIN", str(caught.exception))
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_production_runner_wires_authenticated_credential(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential_path = write_service_account_credential(root)
            local_receipt = write_local_python_receipt(root / "local-runtime")
            captured: dict[str, Any] = {}

            def fake_bind(delegate: object, gcloud_bin: object, credential: object, *, pin_manifest: object = None) -> object:
                captured["delegate"] = delegate
                captured["gcloud_bin"] = gcloud_bin
                captured["credential"] = credential
                bound = mock.Mock(name="bound-runner")
                bound.verified.executable = Path("/opt/google/bin/gcloud")
                bound.TEST_ONLY = False
                return bound

            environ = {
                probe.CREDENTIAL_KIND_ENV: "service_account",
                probe.CREDENTIAL_PATH_ENV: str(credential_path),
                probe.CREDENTIAL_ACCOUNT_ENV: "proof@winsproof123.iam.gserviceaccount.com",
                probe.CREDENTIAL_PROJECT_ENV: "winsproof123",
                probe.deployment_inputs.PYTHON_RUNTIME_RECEIPT_ENV: str(local_receipt),
            }
            args = SimpleNamespace(
                project="winsproof123",
                credential_kind="",
                credential_path="",
                credential_account="",
                credential_project="",
                python_runtime_receipt="",
            )
            with mock.patch.dict(os.environ, environ, clear=False), mock.patch.object(
                probe.gcloud_custody, "bind_production_runner", side_effect=fake_bind
            ):
                bound, gcloud_bin = probe.bind_live_production_runner(
                    probe.SubprocessRunner(), "/opt/google/bin/gcloud", args=args
                )
            self.assertEqual(gcloud_bin, "/opt/google/bin/gcloud")
            self.assertEqual(captured["credential"].kind, "service_account")
            self.assertEqual(captured["credential"].path, credential_path)
            self.assertEqual(
                captured["credential"].expected_account,
                "proof@winsproof123.iam.gserviceaccount.com",
            )
            self.assertEqual(captured["credential"].expected_project, "winsproof123")

    def test_ambient_python3_is_refused(self) -> None:
        with self.assertRaisesRegex(fleet.FleetRefused, "ambient python3"):
            probe.remote_python_argv({"executable_path": "python3"}, "print(1)", "{}")

    def test_nested_python_child_requires_complete_authenticated_cpython_314(self) -> None:
        base = {
            "executable_path": "/opt/winsvpn/python3.14",
            "executable_sha256": "a" * 64,
            "implementation": "cpython",
            "version": "3.14.7",
        }
        self.assertEqual(
            probe.remote_python_argv(base, "print(1)", "{}"),
            ["/opt/winsvpn/python3.14", "-I", "-c", "print(1)", "{}"],
        )
        for drift in (
            {"implementation": "pypy"},
            {"version": "3.13.9"},
            {"executable_sha256": "caller-selected"},
        ):
            with self.subTest(drift=drift), self.assertRaisesRegex(
                fleet.FleetRefused, "authenticated CPython 3.14"
            ):
                probe.remote_python_argv({**base, **drift}, "print(1)", "{}")

    def test_local_child_runtime_rejects_authenticated_non_314_record(self) -> None:
        record = {
            "executable_path": str(Path(sys.executable).resolve(strict=True)),
            "executable_sha256": "a" * 64,
            "implementation": "cpython",
            "version": "3.13.9",
        }
        args = SimpleNamespace(python_runtime_receipt="/private/tmp/runtime.json")
        with mock.patch.object(
            probe.deployment_inputs,
            "authenticate_local_python_runtime",
            return_value=record,
        ), self.assertRaisesRegex(fleet.FleetRefused, "authenticated CPython 3.14"):
            probe.require_local_python_runtime(args)

    def test_stale_extra_bool_and_wrong_type_remote_runtime_receipts_are_refused(self) -> None:
        inputs = probe.deployment_inputs
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            extra = write_remote_python_receipt(root / "extra")
            payload = json.loads(extra.read_text(encoding="ascii"))
            payload["extra"] = "nope"
            extra.chmod(0o600)
            extra.write_bytes(inputs.canonical_bytes(payload))
            extra.chmod(0o400)
            with mock.patch.dict(
                os.environ,
                {inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(extra)},
            ), self.assertRaisesRegex(fleet.FleetRefused, "schema fields"):
                probe.require_remote_python_runtime()

            boolean = write_remote_python_receipt(root / "bool")
            payload = json.loads(boolean.read_text(encoding="ascii"))
            payload["schema_version"] = True
            boolean.chmod(0o600)
            boolean.write_bytes(inputs.canonical_bytes(payload))
            boolean.chmod(0o400)
            with mock.patch.dict(
                os.environ,
                {inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(boolean)},
            ), self.assertRaisesRegex(fleet.FleetRefused, "exact integer"):
                probe.require_remote_python_runtime()

            wrong = write_remote_python_receipt(root / "wrong-type")
            payload = json.loads(wrong.read_text(encoding="ascii"))
            payload["executable_sha256"] = ["not-a-digest"]
            wrong.chmod(0o600)
            wrong.write_bytes(inputs.canonical_bytes(payload))
            wrong.chmod(0o400)
            with mock.patch.dict(
                os.environ,
                {inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(wrong)},
            ), self.assertRaisesRegex(fleet.FleetRefused, "executable_sha256"):
                probe.require_remote_python_runtime()

            local = write_local_python_receipt(root / "local")
            local_payload = json.loads(local.read_text(encoding="ascii"))
            Path(local_payload["source_path"]).chmod(0o600)
            Path(local_payload["source_path"]).write_bytes(b"stale-source\n")
            Path(local_payload["source_path"]).chmod(0o400)
            with self.assertRaisesRegex(inputs.DeploymentInputsError, "stale"):
                inputs.authenticate_local_python_runtime(local)

    def test_remote_python_runtime_must_be_cpython_314(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipt = write_remote_python_receipt(
                Path(tmp) / "stale-python", version="3.12.3"
            )
            with mock.patch.dict(
                os.environ,
                {probe.deployment_inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV: str(receipt)},
            ), self.assertRaisesRegex(fleet.FleetRefused, "CPython 3.14"):
                probe.require_remote_python_runtime()

    def test_deployment_observer_uses_absolute_systemctl_and_docker(self) -> None:
        script = probe._deployment_script()
        self.assertIn('["/usr/bin/systemctl", "is-active", unit]', script)
        self.assertIn('["/usr/bin/docker", "image", "inspect"', script)
        self.assertNotIn('["systemctl", "is-active", unit]', script)
        self.assertNotIn('["docker", "image", "inspect"', script)


class ApplyBoundPostureTests(unittest.TestCase):
    def test_correct_argv_cannot_override_wrong_posture_observation(self) -> None:
        from gcp_proof_fleet_test import Fixture as CollectorFixture

        mutations = (
            ("network", lambda data: data["network"].__setitem__("name", "default")),
            ("subnet", lambda data: data["subnets"][0].__setitem__("name", "wrong")),
            ("os-login", lambda data: data["instances"][0].__setitem__("os_login", False)),
            ("identity", lambda data: data["instances"][0].__setitem__("attached_identity_count", 1)),
            ("scope", lambda data: data["instances"][0].__setitem__("oauth_scopes", ["cloud-platform"])),
            ("secure-boot", lambda data: data["instances"][0]["shielded"].__setitem__("secure_boot", False)),
            ("deletion-protection", lambda data: data["instances"][0].__setitem__("deletion_protection", False)),
            ("label", lambda data: data["instances"][0]["labels"].__setitem__("winsvpn-proof-id", "wrong")),
            ("tag", lambda data: data["instances"][0].__setitem__("tags", ["wrong"])),
            ("image", lambda data: data["instances"][0].__setitem__("image_family", "ubuntu-2204-lts")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                fixture = CollectorFixture(Path(tmp))

                def mutation(data: dict[str, object]) -> dict[str, object]:
                    changed = copy.deepcopy(data)
                    mutate(changed)
                    return changed

                fixture.runner.TEST_ONLY = True
                fixture.runner.mutate["inventory"] = mutation
                with self.assertRaises(Exception) as caught:
                    fixture.collect()
                self.assertEqual(type(caught.exception).__name__, "FleetRefused")
                self.assertIn("inventory", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
