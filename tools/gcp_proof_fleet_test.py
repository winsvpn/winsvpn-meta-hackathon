#!/usr/bin/env python3
"""Adversarial tests for the command-executing local GCP proof collector."""

from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from unittest import mock

TOOLS = Path(__file__).resolve().parent
FLEET_PATH = TOOLS / "gcp_proof_fleet.py"
COLLECTOR_PATH = TOOLS / "gcp_proof_evidence.py"
RUNBOOK_PATH = TOOLS.parent / "docs" / "runbooks" / "GCP_PROOF_FLEET.md"
ACTION_CONTRACT_PATH = TOOLS / "gcp_proof_action_contract.json"
TOOLCHAIN_PINS_PATH = TOOLS / "toolchain-pins.json"


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FLEET = load_module("gcp_proof_fleet", FLEET_PATH)
COLLECTOR = load_module("gcp_proof_evidence", COLLECTOR_PATH)

CONTROL = "proof-control-a1"
WINN3 = "proof-winn3-a1"
COVER = "proof-cover-a1"
PROJECT = "winsvpn-proof-lab"
ADMIN_CIDR = "203.0.113.0/24"
RUN_ID = "run-20260823-001"
SESSION_ID = "session-20260823-001"
CORRELATION_ID = "correlation-20260823-001"
RELEASE_INDEX_BYTES = b"exact release input index\n"
BUILD_RECEIPT_BYTES = b"exact Linux build receipt\n"
CLIENT_ARTIFACT_BYTES = b"exact-tested-client\n"
PROOF_BUILD_ID = "e" * 64
BUILD_ID = "linux:1.0.15+30:" + PROOF_BUILD_ID


def sample_spec(**overrides: Any) -> Any:
    values = {
        "project": PROJECT,
        "control_name": CONTROL,
        "winn3_data_name": WINN3,
        "cover_data_name": COVER,
        "control_zone": "us-east1-b",
        "winn3_data_zone": "us-central1-a",
        "cover_data_zone": "us-east1-b",
        "control_machine": "e2-standard-2",
        "winn3_data_machine": "e2-medium",
        "cover_data_machine": "e2-medium",
        "admin_source_cidr": ADMIN_CIDR,
        "dataplane_source_cidr": "198.51.100.0/24",
        "image_family": FLEET.DEFAULT_IMAGE_FAMILY,
        "image_project": FLEET.DEFAULT_IMAGE_PROJECT,
        "gcloud_bin": "gcloud",
    }
    values.update(overrides)
    return FLEET.build_spec(**values)


def sample_deployment_manifest() -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    seed = 1
    installer_paths = list(
        dict.fromkeys(item[1] for item in FLEET.expected_installer_triples())
    )
    for path in installer_paths:
        files.append(
            {
                "bytes": 100 + seed,
                "class": "server",
                "mode": 0o755,
                "path": path,
                "sha256": f"{seed:064x}",
            }
        )
        seed += 1
    for path in sorted(set(FLEET.REVIEWED_UNIT_SOURCES.values())):
        files.append(
            {
                "bytes": 200 + seed,
                "class": "server",
                "mode": 0o644,
                "path": path,
                "sha256": f"{seed:064x}",
            }
        )
        seed += 1
    files.sort(key=lambda item: item["path"])
    by_path = {item["path"]: item for item in files}
    installers = [
        {key: by_path[path][key] for key in ("bytes", "mode", "path", "sha256")}
        for path in installer_paths
    ]
    return {
        "candidate_id": "c" * 64,
        "inputs": files,
        "installers": installers,
    }


def sample_capture(data: bytes = b"ok") -> dict[str, Any]:
    return {
        "bytes": len(data),
        "data": base64.b64encode(data).decode("ascii"),
        "encoding": "base64",
        "original_bytes": len(data),
        "sha256": FLEET.sha256_bytes(data),
        "truncated": False,
    }


def sample_file_runtime(
    *, applicable: bool, path: str | None = None, digest: str = "3" * 64, size: int = 2048
) -> dict[str, Any]:
    if not applicable:
        return {"applicable": False, "bytes": None, "path": None, "sha256": None}
    return {"applicable": True, "bytes": size, "path": path, "sha256": digest}


def sample_runtime(role: str) -> dict[str, Any]:
    cover_role = role == "data-cover"
    return {
        "awg": {
            "applicable": cover_role,
            "image": "ghcr.io/example/awg@sha256:" + "a" * 64 if cover_role else None,
            "image_id": "sha256:" + "b" * 64 if cover_role else None,
            "provenance_receipt": sample_file_runtime(
                applicable=cover_role,
                path=FLEET.AWG_PROVENANCE_PATH,
                digest="1" * 64,
                size=128,
            )
            if cover_role
            else None,
        },
        "router": {
            "applicable": False,
            "deployment_identity": None,
            "image_id": None,
            "manifest_base_image_digest": "sha256:" + "4" * 64,
            "manifest_base_image_reference": "example.com/router@sha256:" + "4" * 64,
        },
        "winn": sample_file_runtime(
            applicable=role == "data-winn3",
            path="/usr/local/libexec/winn/winn3-gateway",
            digest="2" * 64,
            size=4096,
        ),
        "xray": sample_file_runtime(
            applicable=cover_role,
            path="/usr/local/bin/xray",
            digest="3" * 64,
            size=2048,
        ),
    }


def sample_authenticated_file(
    path: str, *, digest: str = "5" * 64, size: int = 32, active_state: str | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "architecture": FLEET.TEXT_ARCHITECTURE,
        "bytes": size,
        "path": path,
        "sha256": digest,
        "version": "text-1",
    }
    if active_state is not None:
        payload["active_state"] = active_state
    return payload


def sample_marker(
    *,
    spec: Any,
    role: str,
    plan_digest: str,
    apply_digest: str,
    candidate_id: str,
    manifest_digest: str,
    record_chain: str,
    updated_utc: str = "2026-08-24T12:19:00Z",
) -> dict[str, Any]:
    role_steps = [
        index
        for index, item in enumerate(FLEET.expected_installer_triples())
        if item[0] == role
    ]
    return {
        "apply_sha256": apply_digest,
        "candidate_id": candidate_id,
        "completed_step_indices": role_steps,
        "deployment_manifest_sha256": manifest_digest,
        "fleet_completed_step_indices": list(
            range(len(FLEET.expected_installer_triples()))
        ),
        "fleet_id": FLEET.fleet_id_for(spec),
        "fleet_record_chain_sha256": record_chain,
        "instance": spec.by_role[role].name,
        "kind": FLEET.KIND_MARKER,
        "plan_sha256": plan_digest,
        "role": role,
        "runtime": sample_runtime(role),
        "schema_version": 1,
        "updated_utc": updated_utc,
    }


def sample_deployment_observation(
    spec: Any,
    candidate_id: str,
    markers: dict[str, Any],
    *,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    manifest = manifest or sample_deployment_manifest()
    rows = []
    for item in spec.instances:
        rows.append(
            {
                "candidate": {
                    "id": candidate_id,
                    "files": FLEET.expected_candidate_files(manifest, item.role),
                },
                "configs": {
                    path: FLEET.expected_config_identity(item.role, path)
                    for path in FLEET.ROLE_DEPLOY_CONFIGS[item.role]
                },
                "instance": item.name,
                "marker": markers[item.role],
                "os_id": "ubuntu",
                "os_version": "24.04",
                "role": item.role,
                "role_file": item.role,
                "runtime": markers[item.role]["runtime"],
                "services": FLEET.ROLE_DEPLOY_SERVICES[item.role],
                "units": {
                    name: FLEET.expected_unit_identity(
                        manifest, item.role, name, path
                    )
                    for name, path in FLEET.ROLE_DEPLOY_UNITS[item.role].items()
                },
            }
        )
    return {"roles": rows}


def sample_named_resource_identity(
    spec: Any,
    *,
    name: str,
    resource_type: str,
    identity_id: str,
    created_utc: str,
    self_link: str,
    network: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "creation_transaction": {
            "creation_timestamp": created_utc,
            "id": identity_id,
            "self_link": self_link,
        },
        "fingerprint": "AAAAAAAA",
        "kind": FLEET.RESOURCE_KINDS[resource_type],
        "label_fingerprint": "BBBBBBBB",
        "labels": FLEET.expected_resource_labels(spec),
        "name": name,
        "project": spec.project,
        "type": resource_type,
    }
    if network is not None:
        payload["network"] = network
    if region is not None:
        payload["region"] = region
    return payload


def sample_preflight(spec: Any, *, created_utc: str) -> dict[str, Any]:
    fleet_id = FLEET.fleet_id_for(spec)
    resources = FLEET.resource_names(spec)
    instances: dict[str, Any] = {}
    for index, item in enumerate(spec.instances):
        instances[item.role] = {
            "can_ip_forward": item.role in ("data-winn3", "data-cover"),
            "creation_transaction": {
                "creation_timestamp": created_utc,
                "id": str(1000 + index),
                "self_link": (
                    "https://www.googleapis.com/compute/v1/projects/"
                    f"{spec.project}/zones/{item.zone}/instances/{item.name}"
                ),
            },
            "fleet_id": fleet_id,
            "labels": FLEET.expected_preflight_labels(spec, item.role),
            "machine_type": item.machine_type,
            "name": item.name,
            "project": spec.project,
            "role": item.role,
            "zone": item.zone,
        }
    firewalls: dict[str, Any] = {}
    for index, name in enumerate(resources["firewalls"].values()):
        firewalls[name] = sample_named_resource_identity(
            spec,
            name=name,
            resource_type="firewall",
            identity_id=str(2000 + index),
            created_utc=created_utc,
            self_link=(
                "https://www.googleapis.com/compute/v1/projects/"
                f"{spec.project}/global/firewalls/{name}"
            ),
            network=resources["network"],
        )
    subnets: dict[str, Any] = {}
    for index, item in enumerate(resources["subnets"]):
        name = item["name"]
        subnets[name] = sample_named_resource_identity(
            spec,
            name=name,
            resource_type="subnet",
            identity_id=str(3000 + index),
            created_utc=created_utc,
            self_link=(
                "https://www.googleapis.com/compute/v1/projects/"
                f"{spec.project}/regions/{item['region']}/subnetworks/{name}"
            ),
            network=resources["network"],
            region=item["region"],
        )
    return {
        "firewalls": firewalls,
        "instances": instances,
        "network": sample_named_resource_identity(
            spec,
            name=resources["network"],
            resource_type="network",
            identity_id="4000",
            created_utc=created_utc,
            self_link=(
                "https://www.googleapis.com/compute/v1/projects/"
                f"{spec.project}/global/networks/{resources['network']}"
            ),
        ),
        "subnets": subnets,
    }


def sample_cleanup(*, status: str) -> dict[str, Any]:
    if status == "passed":
        return {
            "acceptance_receipt_required": False,
            "authorized": False,
            "remote": {},
            "resources": {
                "reason": "cleanup not required after passed deployment",
                "results": [],
                "status": "not_required",
                "targets": {},
            },
            "status": "not_required",
        }
    return {
        "acceptance_receipt_required": False,
        "authorized": False,
        "remote": {},
        "resources": {
            "reason": "cleanup not authorized",
            "results": [],
            "status": "skipped",
            "targets": {},
        },
        "status": "skipped",
    }


def sample_execution_payload(
    *,
    spec: Any,
    plan: Mapping[str, Any],
    plan_digest: str,
    apply_digest: str,
    client_release_binding: Mapping[str, Any],
    status: str = "passed",
    started_utc: str | None = None,
    ended_utc: str | None = None,
    marker_updated_utc: str | None = None,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    started_utc = started_utc or FLEET.format_utc(now - timedelta(minutes=10))
    ended_utc = ended_utc or FLEET.format_utc(now - timedelta(minutes=8))
    marker_updated_utc = marker_updated_utc or FLEET.format_utc(
        now - timedelta(minutes=9)
    )
    record_started = FLEET.format_utc(
        FLEET.parse_utc("execution start", started_utc) + timedelta(minutes=1)
    )
    record_ended = FLEET.format_utc(
        FLEET.parse_utc("record start", record_started) + timedelta(seconds=1)
    )
    deployment_inputs = plan["deployment_inputs"]
    previous = FLEET.ZERO_SHA256
    records: list[dict[str, Any]] = []
    if status == "passed":
        for index, installer in enumerate(plan["installers"]):
            record = {
                "apply_sha256": apply_digest,
                "ended_utc": record_ended,
                "exit_code": 0,
                "flag": installer["flag"],
                "fleet_id": FLEET.fleet_id_for(spec),
                "instance": installer["instance"],
                "kind": FLEET.KIND_RECORD,
                "manifest_sha256": deployment_inputs["sha256"],
                "plan_sha256": plan_digest,
                "previous_sha256": previous,
                "role": installer["role"],
                "schema_version": 1,
                "script": installer["script"],
                "script_ref": installer["script_ref"],
                "started_utc": record_started,
                "stderr": sample_capture(b""),
                "stdout": sample_capture(b"ok"),
                "step_index": index,
            }
            record["record_sha256"] = FLEET.execution_record_digest(record)
            previous = record["record_sha256"]
            records.append(record)
    payload: dict[str, Any] = {
        "apply_sha256": apply_digest,
        "bundle_sha256": "9" * 64,
        "candidate_id": deployment_inputs["candidate_id"],
        "cleanup": sample_cleanup(status=status),
        "client_release_binding": client_release_binding,
        "deployment_inputs": copy.deepcopy(deployment_inputs),
        "deployment_manifest_sha256": deployment_inputs["sha256"],
        "ended_utc": ended_utc,
        "failure": (
            {}
            if status == "passed"
            else {
                "command": "gcloud compute scp",
                "exit_code": 9,
                "role": "control",
                "stderr": sample_capture(b"failed"),
                "stdout": sample_capture(b""),
            }
        ),
        "fleet_id": FLEET.fleet_id_for(spec),
        "kind": FLEET.KIND_EXECUTION,
        "markers": {},
        "plan_sha256": plan_digest,
        "preflight": (
            sample_preflight(spec, created_utc=started_utc)
            if status == "passed"
            else FLEET.empty_preflight()
        ),
        "record_chain_sha256": FLEET.ZERO_SHA256,
        "records": records,
        "remote_helper_sha256": "a" * 64,
        "schema_version": FLEET.EXECUTION_SCHEMA_VERSION,
        "started_utc": started_utc,
        "status": status,
    }
    if status == "passed":
        payload["record_chain_sha256"] = previous
        payload["markers"] = {
            role: sample_marker(
                spec=spec,
                role=role,
                plan_digest=plan_digest,
                apply_digest=apply_digest,
                candidate_id=deployment_inputs["candidate_id"],
                manifest_digest=deployment_inputs["sha256"],
                record_chain=previous,
                updated_utc=marker_updated_utc,
            )
            for role in FLEET.ROLES
        }
    return payload


class ClientBindingVerifier:
    def __init__(self, fixture: "Fixture") -> None:
        self.fixture = fixture

    def __call__(
        self,
        repo: Path,
        release_input_index: Path,
        build_receipt: Path,
        artifact: Path,
        *,
        platform: str,
    ) -> dict[str, Any]:
        if (
            repo != self.fixture.repo
            or release_input_index != self.fixture.release_index
            or build_receipt != self.fixture.build_receipt
            or artifact != self.fixture.client
            or platform != "linux"
        ):
            raise FLEET.client_binding.ClientReleaseBindingError(
                "substituted client release path"
            )
        for key, path in (
            ("release_input_index", release_input_index),
            ("build_receipt", build_receipt),
            ("artifact", artifact),
        ):
            expected = self.fixture.client_binding[key]
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise FLEET.client_binding.ClientReleaseBindingError(
                    f"missing client {key}"
                ) from exc
            if (
                len(data) != expected["bytes"]
                or FLEET.sha256_bytes(data) != expected["sha256"]
            ):
                raise FLEET.client_binding.ClientReleaseBindingError(
                    f"changed client {key}"
                )
        return copy.deepcopy(self.fixture.client_binding)


class FakeClock:
    def __init__(self) -> None:
        self.value = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(
            minutes=5
        )

    def __call__(self) -> datetime:
        result = self.value
        self.value += timedelta(seconds=1)
        return result


class FakeRunner:
    """Structurally test-only collector runner. Cannot emit a production PASS."""

    TEST_ONLY = True

    def __init__(self, fixture: "Fixture") -> None:
        self.fixture = fixture
        self.calls: list[list[str]] = []
        self.fail_action: str | None = None
        self.replace_driver_action: str | None = None
        self.replace_client_action: str | None = None
        self.mutate: dict[str, Any] = {}

    def production_pass_allowed(self) -> bool:
        return False

    @staticmethod
    def options(argv: list[str]) -> dict[str, str]:
        result: dict[str, str] = {}
        index = 1
        while index < len(argv):
            if argv[index].startswith("--"):
                result[argv[index][2:]] = argv[index + 1]
                index += 2
            else:
                index += 1
        return result

    def data(self, action: str) -> dict[str, Any]:
        spec = self.fixture.spec
        if action == "inventory":
            result = FLEET.expected_inventory_data(spec)
            for item in result["instances"]:
                item["image_name"] = "ubuntu-2404-noble-amd64-v20260801"
                item["image_id"] = "1234567890123456789"
            return result
        if action == "deployment":
            return sample_deployment_observation(
                spec,
                self.fixture.candidate_id,
                self.fixture.execution_payload["markers"],
                manifest=self.fixture.deployment_manifest,
            )
        values: dict[str, dict[str, Any]] = {
            "route-decision": {
                "served_carrier": "winn3",
                "descriptor_node": WINN3,
                "selected_node": WINN3,
                "descriptor_sha256": "a" * 64,
                "signature_state": "verified",
                "canary_state": "reachable",
            },
            "connect-primary": {
                "attempts": [
                    {"protocol": "winn3", "node": WINN3, "result": "connected"}
                ],
                "bytes_rx": 2048,
                "bytes_tx": 1024,
                "interface": "winn3gw0",
                "status_delta": {
                    "inner_packets_delivered": 1,
                    "rx_device_writes": 1,
                },
            },
            "connect-cover-awg": {
                "protocol": "awg",
                "node": COVER,
                "result": "connected",
                "latest_handshake_utc": FLEET.format_utc(self.fixture.clock.value),
            },
            "connect-cover-xray": {
                "protocol": "xray",
                "node": COVER,
                "result": "connected",
            },
            "inject-awg-block": {
                "control_id": "negative-awg-block",
                "protocol": "awg",
                "state": "blocked",
            },
            "probe-awg-block": {
                "control_id": "negative-awg-block",
                "attempts": [
                    {"protocol": "awg", "node": COVER, "result": "blocked"},
                    {"protocol": "xray", "node": COVER, "result": "connected"},
                ],
                "attempt_events": [
                    {
                        "action": "probe-awg-block",
                        "correlation_id": CORRELATION_ID,
                        "monotonic_ns": 1000 + index,
                        "node": COVER,
                        "phase": phase,
                        "protocol": protocol,
                        "result": result,
                        "session_id": SESSION_ID,
                        "utc": FLEET.format_utc(
                            self.fixture.clock.value
                            - timedelta(milliseconds=800 - index * 200)
                        ),
                    }
                    for index, (protocol, phase, result) in enumerate(
                        (
                            ("awg", "started", "pending"),
                            ("awg", "finished", "failed"),
                            ("xray", "started", "pending"),
                            ("xray", "finished", "connected"),
                        )
                    )
                ],
                "awg_interface": "awg0",
                "xray_bytes_rx": 4000,
                "xray_bytes_tx": 5000,
            },
            "restore-awg": {
                "control_id": "negative-awg-block",
                "protocol": "awg",
                "state": "restored",
            },
            "inject-winn3-block": {
                "control_id": "negative-winn3-block",
                "protocol": "winn3",
                "state": "blocked",
            },
            "probe-winn3-block": {
                "control_id": "negative-winn3-block",
                "attempts": [
                    {"protocol": "winn3", "node": WINN3, "result": "blocked"},
                    {"protocol": "awg", "node": COVER, "result": "connected"},
                ],
                "attempt_events": [
                    {
                        "action": "probe-winn3-block",
                        "correlation_id": CORRELATION_ID,
                        "monotonic_ns": 2000 + index,
                        "node": node,
                        "phase": phase,
                        "protocol": protocol,
                        "result": result,
                        "session_id": SESSION_ID,
                        "utc": FLEET.format_utc(
                            self.fixture.clock.value
                            - timedelta(milliseconds=800 - index * 200)
                        ),
                    }
                    for index, (protocol, node, phase, result) in enumerate(
                        (
                            ("winn3", WINN3, "started", "pending"),
                            ("winn3", WINN3, "finished", "failed"),
                            ("awg", COVER, "started", "pending"),
                            ("awg", COVER, "finished", "connected"),
                        )
                    )
                ],
            },
            "withdraw-cover": {
                "control_id": "negative-cover-withdrawn",
                "node": COVER,
                "state": "withdrawn",
            },
            "probe-cover-withdrawn": {
                "control_id": "negative-cover-withdrawn",
                "attempts": [{"protocol": "winn3", "node": WINN3, "result": "blocked"}],
                "attempt_events": [
                    {
                        "action": "probe-cover-withdrawn",
                        "correlation_id": CORRELATION_ID,
                        "monotonic_ns": 3000 + index,
                        "node": WINN3,
                        "phase": phase,
                        "protocol": "winn3",
                        "result": result,
                        "session_id": SESSION_ID,
                        "utc": FLEET.format_utc(
                            self.fixture.clock.value
                            - timedelta(milliseconds=400 - index * 200)
                        ),
                    }
                    for index, (phase, result) in enumerate(
                        (("started", "pending"), ("finished", "failed"))
                    )
                ],
                "refusal_code": "same_node_downgrade_refused",
                "same_node_downgrade_attempts": 0,
            },
            "restore-cover": {
                "control_id": "negative-cover-withdrawn",
                "node": COVER,
                "state": "restored",
            },
            "restore-winn3": {
                "control_id": "negative-winn3-block",
                "protocol": "winn3",
                "state": "restored",
            },
            "teardown-check": {
                "expected_resources": FLEET.resource_identity(spec),
                "observed_resources": FLEET.resource_identity(spec),
                "unexpected_targets": [],
                "foreign_resource_ids": [],
                "credential_files_read": [],
                "production_resources_touched": [],
            },
        }
        return copy.deepcopy(values[action])

    def run(self, argv: list[str], *, timeout_seconds: int) -> Any:
        self.assert_argv(argv)
        self.calls.append(list(argv))
        options = self.options(argv)
        action = options["action"]
        data = self.data(action)
        mutation = self.mutate.get(action)
        if mutation:
            data = mutation(data)
        client = FLEET.file_ref(self.fixture.client, label="fake client")
        bindings = {
            "fleet_id": options["fleet-id"],
            "run_id": options["run-id"],
            "session_id": options["session-id"],
            "correlation_id": options["correlation-id"],
            "client_artifact": client,
            "client_build_identity": options["client-build-identity"],
            "client_release_binding": self.fixture.client_release_binding_ref,
        }
        observation = FLEET.observation_envelope(action, bindings, data)
        stdout = FLEET.canonical_bytes(observation)
        if action == self.replace_driver_action:
            self.fixture.driver.write_bytes(b"#!/bin/sh\nexit 98\n")
            os.chmod(self.fixture.driver, 0o700)
        if action == self.replace_client_action:
            self.fixture.client.write_bytes(b"changed-during-command")
        return COLLECTOR.RunResult(
            stdout=stdout, stderr=b"", exit_code=7 if action == self.fail_action else 0
        )

    def assert_argv(self, argv: list[str]) -> None:
        if not isinstance(argv, list) or "--action" not in argv:
            raise AssertionError("collector did not pass the exact driver argv")
        action = argv[argv.index("--action") + 1]
        driver = FLEET.executable_ref(self.fixture.driver, label="fake driver")
        bindings = FLEET.collector_record_bindings(
            spec=self.fixture.spec,
            plan_digest=self.fixture.plan_digest,
            apply_digest=self.fixture.apply_digest,
            client_release_binding=self.fixture.client_release_binding_ref,
            probe_driver=driver,
            run_id=RUN_ID,
            session_id=SESSION_ID,
            correlation_id=CORRELATION_ID,
            deployment_execution=self.fixture.execution_ref,
            deployment_candidate_id=self.fixture.candidate_id,
            deployment_manifest_sha256=self.fixture.deployment_inputs_digest,
            deployment_record_chain_sha256=self.fixture.execution_payload[
                "record_chain_sha256"
            ],
        )
        expected = {
            item["action"]: item["argv"]
            for item in FLEET.collector_command_specs(
                self.fixture.driver, self.fixture.spec, bindings
            )
        }
        if argv != expected.get(action):
            raise AssertionError("collector did not pass the exact driver argv")


class TestOnlySubprocessRunner(COLLECTOR.SubprocessRunner):
    """Local argv adapter for tests. Cannot emit a production PASS receipt."""

    TEST_ONLY = True

    def production_pass_allowed(self) -> bool:
        return False


def release_artifact_filename(target_id: str) -> str:
    suffix = FLEET.REQUIRED_RELEASE_ARTIFACT_SUFFIXES[target_id][0]
    return f"{target_id}{suffix}"


def write_distinct_release_artifacts(directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, Path] = {}
    for index, target_id in enumerate(FLEET.REQUIRED_RELEASE_ARTIFACTS, start=1):
        path = directory / release_artifact_filename(target_id)
        path.write_bytes(f"store-artifact-{index}-{target_id}\n".encode("ascii"))
        artifacts[target_id] = path
    return artifacts


def write_release_artifact_identity_receipt(
    directory: Path,
    *,
    target_id: str,
    artifact: Path,
    release_input_index: Path,
    created_utc: str | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": FLEET.KIND_RELEASE_ARTIFACT_IDENTITY,
        "schema_version": FLEET.RELEASE_ARTIFACTS_SCHEMA_VERSION,
        "target_id": target_id,
        "created_utc": created_utc or FLEET.utc_now(),
        "release_input_index": FLEET.file_ref(
            release_input_index, label="release input index"
        ),
        "artifact": FLEET.file_ref(artifact, label=f"{target_id} release artifact"),
    }
    path = directory / f"{target_id}.receipt.json"
    path.write_bytes(FLEET.canonical_bytes(payload))
    return path


def _repo_relative(repo: Path, path: Path) -> str:
    return path.resolve().relative_to(repo.resolve()).as_posix()


def write_authentic_cross_store_target_receipt(
    directory: Path,
    *,
    repo: Path,
    target_id: str,
    artifact: Path,
    release_input_index: Path,
    verified_utc: str | None = None,
    build_receipt_target: str | None = None,
    index_sha256: str | None = None,
    artifact_sha256: str | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = FLEET.required_upload_target(target_id)
    artifact_bytes = artifact.read_bytes()
    payload = {
        "ok": True,
        "schema_version": 2,
        "contract": "winsvpn-upload-target-receipt-v2",
        "release": "1.0.15+30",
        "target_id": target_id,
        "platform": target.platform,
        "verified_utc": verified_utc or FLEET.utc_now(),
        "build_receipt": {
            "path": ".artifacts/freeze/PLATFORM_BUILD_RECEIPT.json",
            "sha256": "b" * 64,
            "target": build_receipt_target or target.build_receipt_target,
        },
        "artifact": {
            "path": _repo_relative(repo, artifact),
            "sha256": artifact_sha256 or FLEET.sha256_bytes(artifact_bytes),
            "bytes": len(artifact_bytes),
        },
        "producer": {
            "id": target.producer_ids[0],
            "path": target.producer_ids[0],
            "sha256": "c" * 64,
        },
        "signing_verification_gate": {
            "id": target.signing_gate_id,
            "status": "passed",
            "executed_utc": verified_utc or FLEET.utc_now(),
            "evidence_path": ".artifacts/gates/signing.json",
            "evidence_sha256": "d" * 64,
        },
        "obfuscation_privacy_gate": {
            "id": target.hardening_gate_id,
            "status": "passed",
            "executed_utc": verified_utc or FLEET.utc_now(),
            "evidence_path": ".artifacts/gates/hardening.json",
            "evidence_sha256": "e" * 64,
        },
        "dependency_source_freeze": {
            "index_path": _repo_relative(repo, release_input_index),
            "index_sha256": index_sha256
            or FLEET.sha256_bytes(release_input_index.read_bytes()),
            "platform_manifest_path": ".artifacts/freeze/PLATFORM_INPUTS.json",
            "platform_manifest_sha256": "f" * 64,
            "artifact_input_fingerprint_sha256": "1" * 64,
            "shared_revision": "reviewed-linux-revision",
        },
        "publication_authorized": False,
        "upload_attempted": False,
    }
    path = directory / f"{target_id}.target-receipt.json"
    path.write_bytes(FLEET.canonical_bytes(payload))
    return path


def write_authentic_target_receipts(
    repo: Path,
    directory: Path,
    *,
    artifacts: Mapping[str, Path],
    release_input_index: Path,
    verified_utc: str | None = None,
    index_sha256: str | None = None,
) -> dict[str, Path]:
    return {
        target_id: write_authentic_cross_store_target_receipt(
            directory,
            repo=repo,
            target_id=target_id,
            artifact=path,
            release_input_index=release_input_index,
            verified_utc=verified_utc,
            index_sha256=index_sha256,
        )
        for target_id, path in artifacts.items()
    }


def fake_authenticate_cross_store_target_receipt(
    repo: Path,
    index_path: Path,
    target_id: str,
    receipt_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    del index_path, now
    payload = json.loads(Path(receipt_path).read_text(encoding="ascii"))
    if payload.get("contract") != "winsvpn-upload-target-receipt-v2":
        raise FLEET.FleetRefused("forged or invalid cross-store target receipt contract")
    if payload.get("target_id") != target_id:
        raise FLEET.FleetRefused(f"wrong target: {payload.get('target_id')}")
    artifact = payload["artifact"]
    live = repo / str(artifact["path"])
    data = live.read_bytes()
    if (
        FLEET.sha256_bytes(data) != artifact["sha256"]
        or len(data) != artifact["bytes"]
    ):
        raise FLEET.FleetRefused(
            f"{target_id} release artifact is caller-forged, stale, or substituted"
        )
    return {
        "receipt_path": _repo_relative(repo, Path(receipt_path)),
        "receipt_sha256": FLEET.sha256_bytes(Path(receipt_path).read_bytes()),
        "release": payload.get("release"),
        "build_receipt": copy.deepcopy(payload["build_receipt"]),
        "artifact": copy.deepcopy(payload["artifact"]),
        "producer_id": payload["producer"]["id"],
        "signing_verification_gate": copy.deepcopy(
            payload["signing_verification_gate"]
        ),
        "obfuscation_privacy_gate": copy.deepcopy(
            payload["obfuscation_privacy_gate"]
        ),
        "dependency_source_freeze": copy.deepcopy(
            payload["dependency_source_freeze"]
        ),
        "verified_utc": payload["verified_utc"],
    }


@contextmanager
def authentic_receipt_verifier() -> Any:
    with mock.patch.object(
        FLEET,
        "authenticate_cross_store_target_receipt",
        side_effect=fake_authenticate_cross_store_target_receipt,
    ):
        yield


def _refuse_gcp_acceptance_for_sixteen_target_proof(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError(
        "16-target receipt minting and authentication must not require GCP acceptance"
    )


@contextmanager
def authentic_cross_store_receipt_repo() -> Any:
    """Yield freeze-backed receipts minted through stable cross-store producers.

    GCP acceptance is set to raise *before* receipt minting and stays raised
    through later verification. Receipts are reminted with
    `cross_store_target_receipt.produce_target_receipt`, which calls the real
    unbound `cross_store_upload_readiness._verify_target_receipt`. That
    function is never wrapped or monkeypatched here.

    Linux store artifact bytes come from exact isolated copies of the live
    producers. An unparseable producer fails this proof; no fixture substitution
    is allowed.
    """

    import cross_store_target_receipt as receipt_producer
    import cross_store_upload_readiness as readiness
    from test_cross_store_upload_readiness import CrossStoreUploadReadinessTests

    class SixteenTargetAuthenticReceiptHarness(CrossStoreUploadReadinessTests):
        def runTest(self) -> None:
            return

        def _raise_gcp_acceptance_before_minting(self) -> None:
            try:
                self.gcp_receipt_patch.stop()
            except RuntimeError:
                pass
            try:
                self.gcp_receipt_environment.stop()
            except RuntimeError:
                pass
            os.environ.pop("WINS_GCP_PROOF_ACCEPTANCE_RECEIPT", None)
            gcp_receipt = getattr(self, "gcp_receipt", None)
            if gcp_receipt is not None:
                path = Path(gcp_receipt)
                if path.exists() or path.is_symlink():
                    path.unlink()
            self.gcp_receipt_patch = mock.patch.object(
                readiness,
                "_verify_gcp_proof_acceptance_receipt",
                side_effect=_refuse_gcp_acceptance_for_sixteen_target_proof,
            )
            self.gcp_receipt_patch.start()
            self.fleet_gcp_acceptance_patch = mock.patch.object(
                FLEET,
                "verify_acceptance_receipt_for_release",
                side_effect=_refuse_gcp_acceptance_for_sixteen_target_proof,
            )
            self.fleet_gcp_acceptance_patch.start()

        def _assert_parseable_linux_store_impls(self) -> None:
            import ast

            for target in readiness.ALL_UPLOAD_TARGETS:
                if target.manifest_verifier_path is None:
                    continue
                impl = (self.repo / target.manifest_verifier_path).with_name(
                    "_test_only_manifest_impl.py"
                )
                ast.parse(impl.read_text(encoding="utf-8"))

        def _remint_with_produce_target_receipt(
            self, handwritten: dict[str, Path]
        ) -> dict[str, Path]:
            produced = dict(handwritten)
            output_dir = self.repo / ".artifacts" / "produced-upload-receipts"
            output_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(output_dir, 0o700)
            for target in readiness.REQUIRED_UPLOAD_TARGETS:
                target_id = target.target_id
                fixture = json.loads(
                    handwritten[target_id].read_text(encoding="utf-8")
                )
                output = output_dir / f"{target_id}.json"
                receipt_producer.produce_target_receipt(
                    self.repo,
                    self.index,
                    target_id,
                    Path(str(fixture["artifact"]["path"])),
                    Path(str(fixture["build_receipt"]["path"])),
                    output,
                    Path(f".artifacts/produced-upload-gates/{target_id}"),
                )
                produced[target_id] = output
            return produced

        def _install_test_only_manifest_wrappers(self) -> None:
            super()._install_test_only_manifest_wrappers()
            self._assert_parseable_linux_store_impls()

        def _create_all_target_receipts(self) -> dict[str, Path]:
            self._raise_gcp_acceptance_before_minting()
            handwritten = CrossStoreUploadReadinessTests._create_all_target_receipts(
                self
            )
            return self._remint_with_produce_target_receipt(handwritten)

    harness = SixteenTargetAuthenticReceiptHarness("runTest")
    harness.setUp()
    try:
        yield harness
    finally:
        for name in (
            "gcp_receipt_patch",
            "gcp_receipt_environment",
            "fleet_gcp_acceptance_patch",
        ):
            patcher = getattr(harness, name, None)
            if patcher is not None:
                try:
                    patcher.stop()
                except RuntimeError:
                    pass
            setattr(harness, name, mock.MagicMock())
        try:
            harness.tearDown()
        finally:
            harness.doCleanups()


def plan_cli_argv(fixture: "Fixture", *, replace_plan: bool = False) -> list[str]:
    argv = [
        "plan",
        "--control-instance",
        CONTROL,
        "--winn3-data-instance",
        WINN3,
        "--cover-data-instance",
        COVER,
        "--project",
        PROJECT,
        "--state-dir",
        str(fixture.state),
        "--admin-source-cidr",
        ADMIN_CIDR,
        "--dataplane-source-cidr",
        "198.51.100.0/24",
        "--repo-root",
        str(fixture.repo),
        "--deployment-inputs",
        str(fixture.deployment_inputs),
        "--release-input-index",
        str(fixture.release_index),
        "--client-build-receipt",
        str(fixture.build_receipt),
        "--client-artifact",
        str(fixture.client),
    ]
    if replace_plan:
        argv.append("--replace-plan")
    return argv


def release_artifact_cli_args(artifacts: Mapping[str, Path]) -> list[str]:
    argv: list[str] = []
    for target_id, path in artifacts.items():
        argv.extend(["--release-artifact", f"{target_id}={path}"])
    return argv


def release_artifact_receipt_cli_args(
    receipts: Mapping[str, Path] | Sequence[Path],
    *,
    unlabeled: bool = False,
) -> list[str]:
    argv: list[str] = []
    if unlabeled or not isinstance(receipts, Mapping):
        paths = receipts.values() if isinstance(receipts, Mapping) else receipts
        for path in paths:
            argv.extend(["--release-artifact-receipt", str(path)])
        return argv
    for target_id, path in receipts.items():
        argv.extend(["--release-artifact-receipt", f"{target_id}={path}"])
    return argv


class Fixture:
    def __init__(
        self,
        root: Path,
        *,
        apply: bool = True,
        release_artifact_paths: Mapping[str, Path] | None = None,
        release_artifact_receipts: Mapping[str, Path] | None = None,
        bind_required_release_artifacts: bool = False,
    ) -> None:
        self.root = root.resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir(mode=0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        os.chmod(self.state, 0o700)
        self.spec = sample_spec()
        self.deployment_manifest = sample_deployment_manifest()
        self.deployment_inputs = self.state / "DEPLOYMENT_INPUTS.json"
        self.deployment_inputs.write_bytes(
            FLEET.canonical_bytes(self.deployment_manifest)
        )
        self.candidate_id = self.deployment_manifest["candidate_id"]
        self.deployment_inputs_digest = FLEET.sha256_bytes(
            self.deployment_inputs.read_bytes()
        )
        self.release_index = self.repo / ".artifacts/freeze/RELEASE_INPUT_INDEX.json"
        self.build_receipt = self.repo / ".artifacts/freeze/LINUX_BUILD_RECEIPT.json"
        self.client = self.repo / "build/linux/x64/winsvpn-client.bin"
        for path, data in (
            (self.release_index, RELEASE_INDEX_BYTES),
            (self.build_receipt, BUILD_RECEIPT_BYTES),
            (self.client, CLIENT_ARTIFACT_BYTES),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        os.chmod(self.client, 0o700)

        def ref(path: Path) -> dict[str, Any]:
            data = path.read_bytes()
            return {
                "bytes": len(data),
                "path": str(path),
                "sha256": FLEET.sha256_bytes(data),
            }

        self.client_binding = {
            "artifact": ref(self.client),
            "artifact_input_fingerprint_sha256": "d" * 64,
            "build_identity": BUILD_ID,
            "build_receipt": ref(self.build_receipt),
            "contract": FLEET.client_binding.CONTRACT,
            "platform": "linux",
            "release": "1.0.15+30",
            "release_input_index": ref(self.release_index),
            "schema_version": FLEET.client_binding.SCHEMA_VERSION,
            "shared_revision": "reviewed-linux-revision",
            "proof_build": {
                "build_contract": {"sha256": "1" * 64},
                "build_identity": PROOF_BUILD_ID,
                "builder": {"sha256": "2" * 64},
                "defines": {"release": "1.0.15+30"},
                "source": {"sha256": "3" * 64},
                "target": {"goos": "linux", "goarch": "amd64"},
                "toolchain": {"name": "Go", "version": "1.27.1"},
                "toolchain_pin_manifest": {"sha256": "4" * 64},
            },
        }
        self.client_verifier = ClientBindingVerifier(self)
        if bind_required_release_artifacts:
            release_artifact_paths = write_distinct_release_artifacts(
                self.repo / ".artifacts" / "store"
            )
            release_artifact_receipts = write_authentic_target_receipts(
                self.repo,
                self.repo / ".artifacts" / "receipts",
                artifacts=release_artifact_paths,
                release_input_index=self.release_index,
            )
        self.store_artifacts = dict(release_artifact_paths or {})
        self.store_receipts = dict(release_artifact_receipts or {})
        with self.input_verifiers():
            FLEET.phase_plan(
                self.spec,
                self.state,
                repo_root=self.repo,
                deployment_inputs_path=self.deployment_inputs,
                release_input_index=self.release_index,
                client_build_receipt=self.build_receipt,
                client_artifact=self.client,
                replace_plan=False,
                release_artifact_paths=release_artifact_paths,
                release_artifact_receipts=release_artifact_receipts,
            )
        plan_record = json.loads(self.plan.read_text(encoding="ascii"))
        self.client_release_binding_ref = plan_record["client_release_binding"]
        _, self.plan_digest = FLEET.load_json_document(
            self.state / FLEET.PLAN_NAME, require_immutable=True
        )
        if apply:
            with self.input_verifiers():
                FLEET.phase_apply(self.spec, self.state, confirm=True)
                plan, _ = FLEET.load_json_document(
                    self.plan, require_immutable=True
                )
                _, self.apply_digest = FLEET.load_immutable_apply(
                    self.state / FLEET.APPLY_NAME,
                    self.spec,
                    self.plan_digest,
                    plan,
                )
            self._write_execution()
        self.driver = self.root / "proof-driver"
        self.driver.write_bytes(b"#!/bin/sh\nexit 99\n")
        os.chmod(self.driver, 0o700)
        self.clock = FakeClock()
        self.runner = FakeRunner(self)

    def _write_execution(self, *, status: str = "passed") -> None:
        plan, _ = FLEET.load_json_document(self.plan, require_immutable=True)
        payload = sample_execution_payload(
            spec=self.spec,
            plan=plan,
            plan_digest=self.plan_digest,
            apply_digest=self.apply_digest,
            client_release_binding=self.client_release_binding_ref,
            status=status,
        )
        target = self.state / FLEET.EXECUTION_NAME
        sidecar = target.with_name(target.name + ".sha256")
        for path in (target, sidecar):
            if path.exists():
                os.chmod(path, 0o600)
                path.unlink()
        FLEET.write_json_document(target, payload, immutable=True)
        self.execution_payload = payload
        self.execution_ref = FLEET.file_ref(target, label="test execution")

    def _verify_deployment_manifest(
        self, repo: Path, manifest: Path
    ) -> dict[str, Any]:
        if repo != self.repo or manifest != self.deployment_inputs:
            raise FLEET.deployment_inputs.DeploymentInputsError(
                "substituted deployment inputs"
            )
        if manifest.read_bytes() != FLEET.canonical_bytes(self.deployment_manifest):
            raise FLEET.deployment_inputs.DeploymentInputsError(
                "changed deployment inputs"
            )
        return copy.deepcopy(self.deployment_manifest)

    @contextmanager
    def input_verifiers(self) -> Any:
        with authentic_receipt_verifier(), mock.patch.object(
            FLEET.deployment_inputs,
            "verify_manifest",
            side_effect=self._verify_deployment_manifest,
        ), mock.patch.object(
            FLEET.client_binding,
            "verify_client_release",
            side_effect=self.client_verifier,
        ):
            yield

    @property
    def plan(self) -> Path:
        return self.state / FLEET.PLAN_NAME

    @property
    def apply(self) -> Path:
        return self.state / FLEET.APPLY_NAME

    def collect(self, output: Path | None = None) -> Path:
        target = output or (self.state / "evidence.json")
        with self.input_verifiers():
            COLLECTOR.collect(
                plan_path=self.plan,
                apply_path=self.apply,
                probe_driver=self.driver,
                run_id=RUN_ID,
                session_id=SESSION_ID,
                correlation_id=CORRELATION_ID,
                output=target,
                runner=self.runner,
                clock=self.clock,
            )
        return target

    def verify(self, evidence: Path) -> dict[str, Any]:
        with self.input_verifiers():
            return FLEET.phase_verify(
                self.spec,
                self.state,
                evidence_path=evidence,
                probe_driver=self.driver,
                run_id=RUN_ID,
                session_id=SESSION_ID,
                correlation_id=CORRELATION_ID,
            )

    def reset(self) -> dict[str, Any]:
        with self.input_verifiers():
            return FLEET.phase_reset(self.spec, self.state, confirm=True)

    def emergency(self) -> dict[str, Any]:
        with self.input_verifiers():
            return FLEET.phase_emergency_cleanup(
                self.spec, self.state, confirm=True
            )

    def forge(self, payload: dict[str, Any], name: str = "forged.json") -> Path:
        path = self.root / name
        FLEET.write_json_document(path, payload, immutable=True)
        return path


def rechain(payload: dict[str, Any]) -> None:
    previous = "0" * 64
    for record in payload["records"]:
        record["previous_sha256"] = previous
        record["record_sha256"] = FLEET.command_record_digest(record)
        previous = record["record_sha256"]
    payload["record_chain_sha256"] = FLEET.record_chain_digest(payload["records"])


class TopologyAndRunnerTests(unittest.TestCase):
    def test_authorized_winn_v1_fallback_is_cover_only_and_awg_first(self) -> None:
        spec = sample_spec()
        by_action = {
            "connect-primary": {
                "attempts": [{"protocol": "winn3", "node": WINN3, "result": "connected"}]
            },
            "connect-cover-awg": {
                "protocol": "awg",
                "node": COVER,
                "result": "connected",
            },
            "connect-cover-xray": {
                "protocol": "xray",
                "node": COVER,
                "result": "connected",
            },
            "probe-awg-block": {
                "attempts": [
                    {"protocol": "awg", "node": COVER, "result": "blocked"},
                    {"protocol": "xray", "node": COVER, "result": "connected"},
                ]
            },
            "probe-winn3-block": {
                "attempts": [
                    {"protocol": "winn3", "node": WINN3, "result": "blocked"},
                    {"protocol": "awg", "node": COVER, "result": "connected"},
                ]
            },
            "probe-cover-withdrawn": {
                "refusal_code": "same_node_downgrade_refused",
                "same_node_downgrade_attempts": 0,
            },
        }
        FLEET._expect_authorized_winn_v1_fallback(spec, by_action)
        by_action["connect-primary"] = {
            "attempts": [{"protocol": "awg", "node": COVER, "result": "connected"}]
        }
        with self.assertRaisesRegex(FLEET.FleetRefused, "exclusive primary|authorized primary"):
            FLEET._expect_authorized_winn_v1_fallback(spec, by_action)
        by_action["connect-primary"] = {
            "attempts": [{"protocol": "winn3", "node": WINN3, "result": "connected"}]
        }
        by_action["probe-awg-block"] = {
            "attempts": [
                {"protocol": "xray", "node": COVER, "result": "connected"},
                {"protocol": "awg", "node": COVER, "result": "blocked"},
            ]
        }
        with self.assertRaisesRegex(FLEET.FleetRefused, "AWG-first then Xray"):
            FLEET._expect_authorized_winn_v1_fallback(spec, by_action)

    def test_shared_action_contract_matches_final_collector_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            contract = json.loads(ACTION_CONTRACT_PATH.read_text(encoding="ascii"))
            self.assertEqual(contract["contract"], "winsvpn-gcp-proof-action-data-v1")
            self.assertEqual(contract["schema_version"], 1)
            for action, record in contract["actions"].items():
                self.assertEqual(
                    sorted(fixture.runner.data(action)),
                    sorted(record["final_observation_keys"]),
                    action,
                )

    def test_final_verifier_rejects_can_ip_forward_role_mutations(self) -> None:
        spec = sample_spec()
        for role, mutation in (
            ("control", True),
            ("data-winn3", False),
            ("data-cover", False),
            ("data-winn3", 1),
        ):
            with self.subTest(role=role, mutation=mutation):
                preflight = sample_preflight(
                    spec, created_utc="2026-08-23T12:00:00Z"
                )
                preflight["instances"][role]["can_ip_forward"] = mutation
                with self.assertRaisesRegex(FLEET.FleetRefused, "can_ip_forward"):
                    FLEET.validate_preflight(preflight, spec, require_complete=True)

    def test_live_inventory_rejects_can_ip_forward_role_mutations(self) -> None:
        for role, mutation in (
            ("control", True),
            ("data-winn3", False),
            ("data-cover", False),
            ("data-cover", 1),
        ):
            with (
                self.subTest(role=role, mutation=mutation),
                tempfile.TemporaryDirectory() as tmp,
            ):
                fixture = Fixture(Path(tmp))

                def mutate(
                    data: dict[str, Any],
                    *,
                    selected_role: str = role,
                    selected_value: Any = mutation,
                ) -> dict[str, Any]:
                    changed = copy.deepcopy(data)
                    selected = next(
                        item
                        for item in changed["instances"]
                        if item["role"] == selected_role
                    )
                    selected["can_ip_forward"] = selected_value
                    return changed

                fixture.runner.mutate["inventory"] = mutate
                with self.assertRaisesRegex(FLEET.FleetRefused, "inventory"):
                    fixture.collect()

    def test_topology_and_emit_only_plan_are_unchanged(self) -> None:
        with self.assertRaisesRegex(FLEET.FleetRefused, "restricted IPv4"):
            sample_spec(dataplane_source_cidr="0.0.0.0/0")
        spec = sample_spec(dataplane_source_cidr="198.51.100.0/24")
        self.assertEqual(tuple(item.role for item in spec.instances), FLEET.ROLES)
        preview = "\n".join(item["preview"] for item in FLEET.build_plan_commands(spec))
        self.assertIn("udp:20000-32767", preview)
        self.assertIn("--no-service-account", preview)
        self.assertNotIn("--network=default", preview)
        self.assertEqual(
            [
                item["role"]
                for item in FLEET.build_installer_sequence(
                    spec, sample_deployment_manifest()
                )
                if item["script"] == FLEET.GATEWAY_INSTALLER
            ],
            ["data-winn3", "data-winn3", "data-winn3"],
        )

    def test_plan_commands_are_rebuilt_and_exactly_authenticated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            plan = json.loads(fixture.plan.read_text(encoding="ascii"))
            with fixture.input_verifiers():
                self.assertEqual(FLEET.spec_from_plan(plan), fixture.spec)
                plan["commands"][0]["argv"].append(
                    "--impersonate-service-account=x"
                )
                with self.assertRaisesRegex(FLEET.FleetRefused, "plan commands"):
                    FLEET.spec_from_plan(plan)

    def test_plan_is_immutable_and_cannot_be_replaced_after_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            self.assertEqual(stat.S_IMODE(fixture.plan.stat().st_mode), 0o400)
            self.assertEqual(
                stat.S_IMODE(
                    fixture.plan.with_name(fixture.plan.name + ".sha256").stat().st_mode
                ),
                0o400,
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "immutable apply binding"
            ):
                FLEET.phase_plan(
                    fixture.spec,
                    fixture.state,
                    repo_root=fixture.repo,
                    deployment_inputs_path=fixture.deployment_inputs,
                    release_input_index=fixture.release_index,
                    client_build_receipt=fixture.build_receipt,
                    client_artifact=fixture.client,
                    replace_plan=True,
                )

    def test_state_dir_dangling_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaisesRegex(FLEET.FleetRefused, "state dir"):
                FLEET.prepare_state_dir(state, create=True)

    def test_subprocess_runner_uses_explicit_argv_and_shell_false(self) -> None:
        original_popen = COLLECTOR.subprocess.Popen
        argv = [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'out'); "
            "sys.stderr.buffer.write(b'err')",
        ]
        with mock.patch.object(
            COLLECTOR.subprocess, "Popen", wraps=original_popen
        ) as popen:
            result = COLLECTOR.SubprocessRunner().run(
                argv, timeout_seconds=9
            )
        self.assertEqual(result.stdout, b"out")
        self.assertEqual(result.stderr, b"err")
        self.assertEqual(result.exit_code, 0)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], argv)
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["start_new_session"], True)
        self.assertIs(kwargs["close_fds"], True)
        self.assertIs(kwargs["stdin"], COLLECTOR.subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], COLLECTOR.subprocess.PIPE)
        self.assertIs(kwargs["stderr"], COLLECTOR.subprocess.PIPE)
        binary = b"\x00\xffstderr"
        capture = COLLECTOR.capture_stream(binary, "stderr")
        self.assertEqual(base64.b64decode(capture["data"]), binary)

    def test_legacy_transcript_api_is_disabled(self) -> None:
        with self.assertRaisesRegex(FLEET.FleetRefused, "legacy hand-authored"):
            FLEET.build_evidence_bundle()
        options = {action.dest for action in COLLECTOR.parser()._actions}
        self.assertNotIn("protocol_transcript", options)
        self.assertIn("probe_driver", options)
        self.assertIn("confirm_live_collection", options)

    def test_cli_refuses_to_start_runner_without_live_confirmation(self) -> None:
        argv = [
            "--plan",
            "/tmp/plan.json",
            "--apply",
            "/tmp/apply.json",
            "--probe-driver",
            "/tmp/driver",
            "--run-id",
            RUN_ID,
            "--session-id",
            SESSION_ID,
            "--correlation-id",
            CORRELATION_ID,
            "--output",
            "/tmp/evidence.json",
        ]
        runner = mock.Mock()
        with redirect_stderr(io.StringIO()):
            code = COLLECTOR.main(argv, runner=runner)
        self.assertEqual(code, FLEET.REFUSAL_EXIT)
        runner.run.assert_not_called()

    def test_arbitrary_runner_is_rejected_before_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            target = fixture.state / "evidence.json"

            class Stranger:
                def run(self, argv: list[str], *, timeout_seconds: int) -> Any:
                    raise AssertionError("arbitrary runner executed")

            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, COLLECTOR.gcloud_custody.ARBITRARY_RUNNER
            ):
                COLLECTOR.collect(
                    plan_path=fixture.plan,
                    apply_path=fixture.apply,
                    probe_driver=fixture.driver,
                    run_id=RUN_ID,
                    session_id=SESSION_ID,
                    correlation_id=CORRELATION_ID,
                    output=target,
                    runner=Stranger(),
                    clock=fixture.clock,
                )
            self.assertFalse(target.exists())
            self.assertFalse(
                COLLECTOR.gcloud_custody.runner_may_emit_production_pass(Stranger())
            )
            self.assertFalse(
                COLLECTOR.gcloud_custody.runner_may_emit_production_pass(fixture.runner)
            )
            self.assertIs(type(fixture.runner).TEST_ONLY, True)


class CollectorEvidenceTests(unittest.TestCase):
    def test_acceptance_receipt_cannot_be_minted_from_fake_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            self.assertFalse(
                COLLECTOR.gcloud_custody.runner_may_emit_production_pass(fixture.runner)
            )
            evidence = fixture.collect()
            result = fixture.verify(evidence)
            self.assertEqual(result["verdict"], "blocked")
            self.assertFalse(result["acceptance"])
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())
            blocked = [
                item
                for item in result["required_action_artifacts"]
                if item["status"] == "blocked"
            ]
            self.assertEqual(len(blocked), 15)
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "missing|blocked|FakeRunner"
            ):
                FLEET.verify_acceptance_receipt_for_release(
                    fixture.state / FLEET.RECEIPT_NAME,
                    repo_root=fixture.repo,
                    release_input_index=fixture.release_index,
                )

    def test_acceptance_receipt_rejects_release_index_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.verify(fixture.collect())
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())
            substituted = fixture.repo / ".artifacts/freeze/SUBSTITUTED_INDEX.json"
            substituted.write_bytes(RELEASE_INDEX_BYTES)
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "missing|blocked|FakeRunner"
            ):
                FLEET.verify_acceptance_receipt_for_release(
                    fixture.state / FLEET.RECEIPT_NAME,
                    repo_root=fixture.repo,
                    release_input_index=substituted,
                )

    def test_acceptance_receipt_rejects_stale_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.verify(fixture.collect())
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())

    def test_acceptance_receipt_rejects_mutable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.verify(fixture.collect())
            receipt = fixture.state / FLEET.RECEIPT_NAME
            self.assertFalse(receipt.exists())

    def test_reset_refuses_receipt_with_extra_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            _, plan_digest = FLEET.load_json_document(fixture.plan, require_immutable=True)
            _, apply_digest = FLEET.load_json_document(fixture.apply, require_immutable=True)
            receipt = {
                "kind": FLEET.KIND_RECEIPT,
                "schema_version": FLEET.SCHEMA_VERSION,
                "phase": "verify",
                "created_utc": FLEET.utc_now(),
                "verdict": "pass",
                "plan_sha256": plan_digest,
                "apply_sha256": apply_digest,
                "fleet": FLEET.spec_document(fixture.spec),
                "evidence_bundle": {
                    "path": str(fixture.state / "evidence.json"),
                    "sha256": "a" * 64,
                    "bytes": 1,
                },
                "bindings": {},
                "verifier": FLEET.verifier_ref(),
                "checks": [],
                "extra": True,
            }
            FLEET.write_json_document(
                fixture.state / FLEET.RECEIPT_NAME, receipt, immutable=True
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "keys mismatch"):
                FLEET.phase_reset(fixture.spec, fixture.state, confirm=True)

    def test_acceptance_receipt_rejects_reanchored_evidence_edit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            result = fixture.verify(evidence)
            self.assertEqual(result["verdict"], "blocked")
            payload = json.loads(evidence.read_text(encoding="ascii"))
            payload["record_chain_sha256"] = "0" * 64
            data = FLEET.canonical_bytes(payload)
            sidecar = evidence.with_name(evidence.name + ".sha256")
            for path in (evidence, sidecar):
                os.chmod(path, 0o600)
            evidence.write_bytes(data)
            sidecar.write_text(
                f"{FLEET.sha256_bytes(data)}  {evidence.name}\n",
                encoding="ascii",
            )
            for path in (evidence, sidecar):
                os.chmod(path, 0o400)
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "chain digest|edited"
            ):
                fixture.verify(evidence)

    def test_complete_fake_run_captures_all_commands_and_gates_reset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            payload = json.loads(evidence.read_text(encoding="ascii"))
            self.assertEqual(
                [item["action"] for item in payload["records"]],
                list(FLEET.COLLECTOR_ACTIONS),
            )
            self.assertTrue(
                all(
                    item["bindings"]["client_build_identity"] == BUILD_ID
                    for item in payload["records"]
                )
            )
            self.assertTrue(
                all(
                    item["bindings"]["client_artifact"]["sha256"]
                    == FLEET.file_ref(fixture.client, label="client")["sha256"]
                    for item in payload["records"]
                )
            )
            self.assertTrue(
                all(
                    item["bindings"]["fleet_id"] == FLEET.fleet_id_for(fixture.spec)
                    for item in payload["records"]
                )
            )
            self.assertTrue(
                all(
                    item["bindings"]["run_id"] == RUN_ID
                    and item["bindings"]["session_id"] == SESSION_ID
                    and item["bindings"]["correlation_id"] == CORRELATION_ID
                    for item in payload["records"]
                )
            )
            self.assertEqual(stat.S_IMODE(fixture.apply.stat().st_mode), 0o400)
            result = fixture.verify(evidence)
            self.assertEqual(result["verdict"], "blocked")
            self.assertFalse(result["acceptance"])
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing|receipt"):
                fixture.reset()

    def test_missing_or_writable_apply_state_refuses_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing|apply"):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            os.chmod(fixture.apply, 0o600)
            with self.assertRaisesRegex(FLEET.FleetRefused, "writable|immutable"):
                fixture.collect()

    def test_caller_written_status_json_cannot_enter_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.forge(
                {
                    "kind": FLEET.KIND_EVIDENCE,
                    "status": "pass",
                    "protocol": {"winn3": "ok"},
                },
                "caller.json",
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "keys mismatch|collector"):
                fixture.verify(evidence)
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())

    def test_edited_output_and_recomputed_semantic_forgery_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            payload = json.loads(evidence.read_text(encoding="ascii"))
            payload["records"][3]["stdout"]["data"] = base64.b64encode(b"{}\n").decode(
                "ascii"
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "hash/bytes|edited"):
                fixture.verify(fixture.forge(payload, "edited.json"))
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            payload = json.loads(evidence.read_text(encoding="ascii"))
            record = payload["records"][3]
            observation = json.loads(base64.b64decode(record["stdout"]["data"]))
            observation["data"]["bytes_rx"] = 0
            blob = FLEET.canonical_bytes(observation)
            record["stdout"] = {
                "encoding": "base64",
                "data": base64.b64encode(blob).decode("ascii"),
                "bytes": len(blob),
                "sha256": FLEET.sha256_bytes(blob),
            }
            rechain(payload)
            with self.assertRaisesRegex(FLEET.FleetRefused, "carried traffic"):
                fixture.verify(fixture.forge(payload, "semantic-forged.json"))

    def test_pre_posture_evidence_schema_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            payload = json.loads(fixture.collect().read_text(encoding="ascii"))
            payload["schema_version"] = 2
            payload["kind"] = "winsvpn.gcp_proof_evidence.collector_bundle.v2"
            with self.assertRaisesRegex(FLEET.FleetRefused, "collector contract|kind/schema"):
                fixture.verify(fixture.forge(payload, "legacy-v2.json"))

    def test_recomputed_secret_stderr_capture_is_independently_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            payload = json.loads(fixture.collect().read_text(encoding="ascii"))
            secret = b"-----BEGIN PRIVATE KEY-----\n"
            payload["records"][2]["stderr"] = {
                "encoding": "base64",
                "data": base64.b64encode(secret).decode("ascii"),
                "bytes": len(secret),
                "sha256": FLEET.sha256_bytes(secret),
            }
            rechain(payload)
            with self.assertRaisesRegex(FLEET.FleetRefused, "secrets"):
                fixture.verify(fixture.forge(payload, "secret-stderr.json"))

    def test_reordered_or_forged_commands_fail_even_with_new_chain(self) -> None:
        for mutation in ("reorder", "argv"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                fixture = Fixture(Path(tmp))
                payload = json.loads(fixture.collect().read_text(encoding="ascii"))
                if mutation == "reorder":
                    payload["records"][6], payload["records"][7] = (
                        payload["records"][7],
                        payload["records"][6],
                    )
                else:
                    payload["records"][4]["argv"].append("--forged")
                rechain(payload)
                with self.assertRaisesRegex(FLEET.FleetRefused, "forged|reordered"):
                    fixture.verify(fixture.forge(payload, f"{mutation}.json"))

    def test_wrong_client_hash_build_identity_and_closure_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            fixture.client.write_bytes(b"changed-client")
            with self.assertRaisesRegex(FLEET.FleetRefused, "client"):
                fixture.verify(evidence)
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            payload = json.loads(evidence.read_text(encoding="ascii"))
            payload["client_build_identity"] = (
                "linux:1.0.15+30:" + "0" * 64
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "client release binding"):
                fixture.verify(
                    fixture.forge(payload, "wrong-build-identity.json")
                )
            payload = json.loads(evidence.read_text(encoding="ascii"))
            payload["collector_closure"]["collector"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(FLEET.FleetRefused, "closure"):
                fixture.verify(fixture.forge(payload, "closure.json"))

    def test_pass_tokens_and_wrong_protocol_facts_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["route-decision"] = lambda data: {
                **data,
                "pass": True,
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "pass token|keys"):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["probe-winn3-block"] = lambda data: {
                **data,
                "attempts": list(reversed(data["attempts"])),
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "attempt order"):
                fixture.collect()

    def test_boolean_traffic_counters_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["connect-primary"] = lambda data: {
                **data,
                "bytes_rx": True,
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "carried traffic"):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["probe-cover-withdrawn"] = lambda data: {
                **data,
                "same_node_downgrade_attempts": False,
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "downgrade refusal"):
                fixture.collect()

    def test_synthetic_winn3_interface_cannot_prove_carried_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["connect-primary"] = lambda data: {
                **data,
                "interface": "winn3",
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "carried traffic"):
                fixture.collect()

    def test_awg_handshake_must_fall_inside_its_command_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            stale = FLEET.format_utc(fixture.clock.value)
            fixture.runner.mutate["connect-cover-awg"] = lambda data: {
                **data,
                "latest_handshake_utc": stale,
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "handshake"):
                fixture.collect()

    def test_nonzero_during_or_after_injection_runs_restore_and_writes_no_evidence(
        self,
    ) -> None:
        for failure, expected_restore in (
            ("inject-awg-block", "restore-awg"),
            ("probe-awg-block", "restore-awg"),
            ("inject-winn3-block", "restore-winn3"),
            ("probe-winn3-block", "restore-winn3"),
            ("withdraw-cover", "restore-cover"),
            ("probe-cover-withdrawn", "restore-cover"),
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = Fixture(Path(tmp))
                fixture.runner.fail_action = failure
                target = fixture.state / "evidence.json"
                with self.assertRaisesRegex(FLEET.FleetRefused, "exited 7"):
                    fixture.collect(target)
                actions = [
                    FakeRunner.options(argv)["action"] for argv in fixture.runner.calls
                ]
                self.assertIn(expected_restore, actions[-2:])
                self.assertFalse(target.exists())

    def test_replaced_driver_is_never_executed_for_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.replace_driver_action = "inject-awg-block"
            target = fixture.state / "evidence.json"
            with self.assertRaisesRegex(FLEET.FleetRefused, "cleanup failed"):
                fixture.collect(target)
            actions = [FakeRunner.options(argv)["action"] for argv in fixture.runner.calls]
            self.assertEqual(actions[-1], "inject-awg-block")
            self.assertNotIn("restore-awg", actions)
            self.assertFalse(target.exists())

    def test_driver_change_during_command_refuses_evidence(self) -> None:
        for target_kind in ("driver", "client"):
            with self.subTest(
                target_kind=target_kind
            ), tempfile.TemporaryDirectory() as tmp:
                fixture = Fixture(Path(tmp))
                setattr(fixture.runner, f"replace_{target_kind}_action", "deployment")
                target = fixture.state / "evidence.json"
                with self.assertRaisesRegex(
                    FLEET.FleetRefused, "driver|client release binding"
                ):
                    fixture.collect(target)
                self.assertFalse(target.exists())

    def test_group_writable_probe_driver_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            os.chmod(fixture.driver, 0o720)
            with self.assertRaisesRegex(FLEET.FleetRefused, "group/world writable"):
                fixture.collect()

    def test_missing_apply_after_collection_refuses_verification_and_reset(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            fixture.apply.unlink()
            fixture.apply.with_name(fixture.apply.name + ".sha256").unlink()
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing|apply"):
                fixture.verify(evidence)
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing|receipt"):
                FLEET.phase_reset(fixture.spec, fixture.state, confirm=True)

    def test_raw_streams_exit_times_and_identity_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            payload = json.loads(fixture.collect().read_text(encoding="ascii"))
            previous = "0" * 64
            for index, record in enumerate(payload["records"]):
                self.assertEqual(record["index"], index)
                self.assertEqual(record["exit_code"], 0)
                self.assertEqual(record["previous_sha256"], previous)
                self.assertEqual(
                    record["record_sha256"], FLEET.command_record_digest(record)
                )
                self.assertEqual(base64.b64decode(record["stderr"]["data"]), b"")
                self.assertLessEqual(
                    FLEET.parse_utc("start", record["started_utc"]),
                    FLEET.parse_utc("end", record["ended_utc"]),
                )
                previous = record["record_sha256"]
            self.assertEqual(
                payload["deployment_candidate_id"], fixture.candidate_id
            )
            self.assertEqual(
                payload["deployment_manifest_sha256"],
                fixture.deployment_inputs_digest,
            )
            self.assertEqual(
                payload["deployment_record_chain_sha256"],
                fixture.execution_payload["record_chain_sha256"],
            )


class DeployedServerBindingTests(unittest.TestCase):
    def test_omitted_execution_receipt_refuses_collection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            execution = fixture.state / FLEET.EXECUTION_NAME
            sidecar = execution.with_name(execution.name + ".sha256")
            execution.unlink()
            sidecar.unlink()
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing"):
                fixture.collect()

    def test_extra_or_missing_candidate_bytes_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["deployment"] = lambda data: _replace_candidate(
                data, {"id": fixture.candidate_id, "files": []}
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "missing candidate bytes"):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["deployment"] = lambda data: _replace_candidate(
                data,
                {
                    "id": "0" * 64,
                    "files": [
                        {"bytes": 4, "path": "step-0/x", "sha256": "6" * 64}
                    ],
                },
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "candidate"):
                fixture.collect()

    def test_candidate_substitution_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["deployment"] = lambda data: _replace_marker_field(
                data, "candidate_id", "d" * 64
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "candidate"):
                fixture.collect()

    def test_manifest_substitution_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["deployment"] = lambda data: _replace_marker_field(
                data, "deployment_manifest_sha256", "e" * 64
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "manifest"):
                fixture.collect()

    def test_runtime_substitution_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))

            def mutate(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                changed["roles"][1]["runtime"]["xray"]["sha256"] = "f" * 64
                return changed

            fixture.runner.mutate["deployment"] = mutate
            with self.assertRaisesRegex(FLEET.FleetRefused, "runtime"):
                fixture.collect()

    def test_stale_marker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            payload = copy.deepcopy(fixture.execution_payload)
            for role in payload["markers"]:
                payload["markers"][role]["updated_utc"] = "2026-08-22T00:00:00Z"
            target = fixture.state / FLEET.EXECUTION_NAME
            sidecar = target.with_name(target.name + ".sha256")
            for path in (target, sidecar):
                os.chmod(path, 0o600)
                path.unlink()
            FLEET.write_json_document(target, payload, immutable=True)
            with self.assertRaisesRegex(FLEET.FleetRefused, "stale"):
                fixture.collect()

    def test_data_roles_have_disjoint_runtime_stacks(self) -> None:
        FLEET.validate_runtime_identities("data-winn3", sample_runtime("data-winn3"))
        FLEET.validate_runtime_identities("data-cover", sample_runtime("data-cover"))
        wrong_winn3 = sample_runtime("data-cover")
        wrong_winn3["winn"] = sample_file_runtime(
            applicable=True,
            path="/usr/local/libexec/winn/winn3-gateway",
            digest="2" * 64,
            size=4096,
        )
        with self.assertRaisesRegex(FLEET.FleetRefused, "AWG runtime applicability"):
            FLEET.validate_runtime_identities("data-winn3", wrong_winn3)

    def test_bool_string_coercion_and_duplicate_keys_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            fixture.runner.mutate["deployment"] = lambda data: _replace_marker_field(
                data, "schema_version", True
            )
            with self.assertRaisesRegex(FLEET.FleetRefused, "JSON type|schema"):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            with self.assertRaisesRegex(FLEET.FleetRefused, "duplicate JSON key"):
                FLEET.strict_json_bytes("dup", b'{"a":1,"a":2}\n')
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            payload = json.loads(fixture.collect().read_text(encoding="ascii"))
            record = payload["records"][1]
            observation = json.loads(base64.b64decode(record["stdout"]["data"]))
            observation["data"]["roles"][0]["os_version"] = True
            blob = FLEET.canonical_bytes(observation)
            record["stdout"] = {
                "encoding": "base64",
                "data": base64.b64encode(blob).decode("ascii"),
                "bytes": len(blob),
                "sha256": FLEET.sha256_bytes(blob),
            }
            rechain(payload)
            with self.assertRaisesRegex(FLEET.FleetRefused, "type mismatch|JSON type"):
                fixture.verify(fixture.forge(payload, "coerced-os.json"))

    def test_state_path_symlink_and_swap_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real = root / "real-state"
            real.mkdir(mode=0o700)
            os.chmod(real, 0o700)
            linked = root / "state"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(FLEET.FleetRefused, "state dir"):
                FLEET.prepare_state_dir(linked, create=False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state = root / "state"
            state.mkdir(mode=0o700)
            os.chmod(state, 0o700)
            moved = root / "moved"
            original_open = FLEET.os.open
            swapped = False

            def swap_then_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
                nonlocal swapped
                if (
                    not swapped
                    and flags & getattr(os, "O_DIRECTORY", 0)
                    and Path(path) == state
                ):
                    descriptor = original_open(path, flags, *args, **kwargs)
                    state.rename(moved)
                    state.mkdir(mode=0o700)
                    os.chmod(state, 0o700)
                    swapped = True
                    return descriptor
                return original_open(path, flags, *args, **kwargs)

            with mock.patch.object(FLEET.os, "open", side_effect=swap_then_open):
                with self.assertRaisesRegex(FLEET.FleetRefused, "swapped|canonical|state dir"):
                    FLEET.prepare_state_dir(state, create=False)

    def test_receipt_replay_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            evidence = fixture.collect()
            fixture.verify(evidence)
            replayed = copy.deepcopy(fixture.execution_payload)
            replayed["started_utc"] = "2026-08-23T11:00:00Z"
            replayed["ended_utc"] = "2026-08-23T11:20:00Z"
            for role in replayed["markers"]:
                replayed["markers"][role]["updated_utc"] = "2026-08-23T11:19:00Z"
            target = fixture.state / FLEET.EXECUTION_NAME
            sidecar = target.with_name(target.name + ".sha256")
            for path in (target, sidecar):
                os.chmod(path, 0o600)
                path.unlink()
            FLEET.write_json_document(target, replayed, immutable=True)
            with self.assertRaisesRegex(
                FLEET.FleetRefused, "execution|digest|binding mismatch|transaction"
            ):
                fixture.verify(evidence)

    def test_emergency_cleanup_validates_failed_fleet_without_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            target = fixture.state / FLEET.EXECUTION_NAME
            sidecar = target.with_name(target.name + ".sha256")
            for path in (target, sidecar):
                os.chmod(path, 0o600)
                path.unlink()
            fixture._write_execution(status="failed")
            with self.assertRaisesRegex(FLEET.FleetRefused, "confirm"):
                FLEET.phase_emergency_cleanup(
                    fixture.spec, fixture.state, confirm=False
                )
            result = fixture.emergency()
            self.assertFalse(result["acceptance"])
            self.assertFalse(result["deletion_implemented"])
            self.assertTrue(result["fleet_identity_verified"])
            self.assertEqual(result["execution_status"], "failed")
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())
            emergency = json.loads(
                (fixture.state / FLEET.EMERGENCY_NAME).read_text(encoding="ascii")
            )
            self.assertEqual(emergency["kind"], FLEET.KIND_EMERGENCY)
            self.assertFalse(emergency["acceptance"])
            self.assertFalse(emergency["deletion_implemented"])
            self.assertNotIn("commands", emergency)


class VerifierFindingRegressionTests(unittest.TestCase):
    def test_synthetic_exit_99_cannot_mint_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            target = fixture.state / "evidence.json"
            runner = TestOnlySubprocessRunner()
            self.assertFalse(
                COLLECTOR.gcloud_custody.runner_may_emit_production_pass(runner)
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "exited 99"
            ):
                COLLECTOR.collect(
                    plan_path=fixture.plan,
                    apply_path=fixture.apply,
                    probe_driver=fixture.driver,
                    run_id=RUN_ID,
                    session_id=SESSION_ID,
                    correlation_id=CORRELATION_ID,
                    output=target,
                    runner=runner,
                    clock=fixture.clock,
                )
            self.assertFalse(target.exists())
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())

    def test_arbitrary_candidate_bytes_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))

            def mutate(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                for row in changed["roles"]:
                    files = copy.deepcopy(row["candidate"]["files"])
                    files[0]["path"] = "step-0/arbitrary-not-in-manifest.bin"
                    row["candidate"] = {
                        "id": fixture.candidate_id,
                        "files": files,
                    }
                return changed

            fixture.runner.mutate["deployment"] = mutate
            with self.assertRaisesRegex(
                FLEET.FleetRefused, "arbitrary candidate bytes"
            ):
                fixture.collect()

    def test_replaced_unit_and_config_digests_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))

            def mutate_unit(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                unit = next(iter(changed["roles"][0]["units"].values()))
                unit["sha256"] = "f" * 64
                return changed

            fixture.runner.mutate["deployment"] = mutate_unit
            with self.assertRaisesRegex(
                FLEET.FleetRefused, "unit|deployment-manifest"
            ):
                fixture.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))

            def mutate_config(data: dict[str, Any]) -> dict[str, Any]:
                changed = copy.deepcopy(data)
                config = next(iter(changed["roles"][0]["configs"].values()))
                config["sha256"] = "e" * 64
                return changed

            fixture.runner.mutate["deployment"] = mutate_config
            with self.assertRaisesRegex(
                FLEET.FleetRefused, "config|deployment-manifest"
            ):
                fixture.collect()

    def test_stale_deployment_refuses_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            stale_end = datetime.now(timezone.utc).replace(microsecond=0) - (
                FLEET.MAX_EVIDENCE_AGE + timedelta(minutes=10)
            )
            stale_start = stale_end - timedelta(minutes=2)
            plan, _ = FLEET.load_json_document(fixture.plan, require_immutable=True)
            payload = sample_execution_payload(
                spec=fixture.spec,
                plan=plan,
                plan_digest=fixture.plan_digest,
                apply_digest=fixture.apply_digest,
                client_release_binding=fixture.client_release_binding_ref,
                started_utc=FLEET.format_utc(stale_start),
                ended_utc=FLEET.format_utc(stale_end),
                marker_updated_utc=FLEET.format_utc(stale_end - timedelta(seconds=30)),
            )
            target = fixture.state / FLEET.EXECUTION_NAME
            sidecar = target.with_name(target.name + ".sha256")
            for path in (target, sidecar):
                os.chmod(path, 0o600)
                path.unlink()
            FLEET.write_json_document(target, payload, immutable=True)
            fixture.execution_payload = payload
            fixture.execution_ref = FLEET.file_ref(target, label="test execution")
            with self.assertRaisesRegex(FLEET.FleetRefused, "stale deployment"):
                fixture.collect()

    def test_single_artifact_reuse_is_refused_and_missing_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp))
            client = fixture.client_release_binding_ref["binding"]["artifact"]
            reused = {
                target_id: copy.deepcopy(client)
                for target_id in FLEET.REQUIRED_RELEASE_ARTIFACTS
            }
            with self.assertRaisesRegex(FLEET.FleetRefused, "single-artifact reuse"):
                FLEET.bind_action_release_artifacts(reused)
            rows = FLEET.evaluate_action_release_artifacts(
                fixture.client_release_binding_ref
            )
            self.assertEqual(len(rows), 16)
            self.assertEqual(
                sum(1 for item in rows if item["status"] == "blocked"), 15
            )
            proven = [item for item in rows if item["status"] == "proven"]
            self.assertEqual(len(proven), 1)
            self.assertEqual(proven[0]["target_id"], FLEET.LINUX_X64_ARTIFACT_ID)
            evidence = fixture.collect()
            result = fixture.verify(evidence)
            self.assertEqual(result["verdict"], "blocked")
            self.assertFalse(result["acceptance"])
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())


class RequiredReleaseArtifactContractTests(unittest.TestCase):
    def test_required_identities_remain_sixteen_and_distinct(self) -> None:
        self.assertEqual(len(FLEET.REQUIRED_RELEASE_ARTIFACTS), 16)
        self.assertEqual(len(FLEET.COLLECTOR_ACTIONS), 16)
        self.assertEqual(len(set(FLEET.REQUIRED_RELEASE_ARTIFACTS)), 16)
        self.assertEqual(
            list(FLEET.REQUIRED_RELEASE_ARTIFACTS),
            [
                "android-phone-tablet-aab",
                "android-tv-aab",
                "wear-os-aab",
                "ios-app-store-ipa",
                "macos-app-store-pkg",
                "windows-x64-installer",
                "windows-x64-partner-center",
                "windows-arm64-installer",
                "windows-arm64-partner-center",
                "linux-x64-package",
                "linux-arm64-package",
                "linux-flathub-manifest",
                "linux-snap-manifest",
                "chrome-extension-package",
                "edge-extension-package",
                "firefox-extension-package",
            ],
        )
        FLEET.assert_required_release_artifact_count()

    def test_authenticate_delegates_to_existing_cross_store_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            expected = {
                "artifact": {"path": "a.aab", "sha256": "a" * 64, "bytes": 1},
                "verified_utc": FLEET.utc_now(),
            }
            with mock.patch.object(FLEET, "_cross_store_readiness") as factory:
                readiness = mock.Mock()
                readiness.UploadReadinessError = type(
                    "UploadReadinessError", (Exception,), {}
                )
                readiness._verify_target_receipt.return_value = expected
                factory.return_value = readiness
                got = FLEET.authenticate_cross_store_target_receipt(
                    fixture.repo,
                    fixture.release_index,
                    "android-phone-tablet-aab",
                    receipts["android-phone-tablet-aab"],
                )
            self.assertEqual(got, expected)
            readiness._verify_target_receipt.assert_called_once_with(
                fixture.repo,
                fixture.release_index,
                "android-phone-tablet-aab",
                receipts["android-phone-tablet-aab"],
                now=None,
            )

    def test_delegated_verified_utc_is_required_without_payload_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            _artifacts, receipts = self._bindings(fixture)
            target_id = "android-phone-tablet-aab"
            receipt_path = receipts[target_id]
            payload = json.loads(receipt_path.read_text(encoding="ascii"))
            payload_utc = payload["verified_utc"]
            self.assertTrue(payload_utc)
            truncated = fake_authenticate_cross_store_target_receipt(
                fixture.repo,
                fixture.release_index,
                target_id,
                receipt_path,
            )
            truncated.pop("verified_utc", None)
            self.assertNotIn("verified_utc", truncated)
            index_ref = fixture.client_release_binding_ref["binding"][
                "release_input_index"
            ]
            with mock.patch.object(
                FLEET,
                "authenticate_cross_store_target_receipt",
                return_value=truncated,
            ):
                with self.assertRaisesRegex(
                    FLEET.FleetRefused,
                    "verified_utc is missing from the delegated verifier",
                ):
                    FLEET.load_authenticated_target_receipt(
                        receipt_path,
                        repo_root=fixture.repo,
                        expected_index=index_ref,
                        claimed_target_id=target_id,
                    )
            delegated_utc = FLEET.format_utc(
                datetime.now(timezone.utc).replace(microsecond=0)
                - timedelta(minutes=2)
            )
            self.assertNotEqual(delegated_utc, payload_utc)
            complete = dict(truncated)
            complete["verified_utc"] = delegated_utc
            with mock.patch.object(
                FLEET,
                "authenticate_cross_store_target_receipt",
                return_value=complete,
            ):
                identity = FLEET.load_authenticated_target_receipt(
                    receipt_path,
                    repo_root=fixture.repo,
                    expected_index=index_ref,
                    claimed_target_id=target_id,
                )
            self.assertEqual(identity["verified_utc"], delegated_utc)
            self.assertNotEqual(identity["verified_utc"], payload_utc)

    def test_real_unbound_verifier_binds_sixteen_authentic_receipts_without_gcp_acceptance(
        self,
    ) -> None:
        """Bind all 16 freeze-backed receipts through the unbound verifier.

        `cross_store_upload_readiness._verify_target_receipt` is called directly
        and through `authenticate_cross_store_target_receipt`; it is not wrapped.
        GCP acceptance remains set to raise from minting through this check.

        Linux store producers must be parseable exact copies of the live source.
        This proof permits no fixture substitution.
        """

        with authentic_cross_store_receipt_repo() as harness:
            repo = harness.repo.resolve()
            receipts = {
                target_id: path.resolve()
                for target_id, path in harness.receipts.items()
                if target_id in FLEET.REQUIRED_RELEASE_ARTIFACTS
            }
            self.assertEqual(set(receipts), set(FLEET.REQUIRED_RELEASE_ARTIFACTS))
            self.assertNotIn("macos-developer-id-app", receipts)
            import ast

            for relative in (
                "linux/packaging/snap/manifest_artifact.py",
                "linux/packaging/flathub/manifest_artifact.py",
            ):
                ast.parse((FLEET_PATH.parent.parent / relative).read_text(encoding="utf-8"))
            index_ref = FLEET.file_ref(
                harness.index.resolve(), label="release input index"
            )
            readiness = FLEET._cross_store_readiness()
            self.assertNotIsInstance(readiness._verify_target_receipt, mock.Mock)
            with self.assertRaisesRegex(
                AssertionError,
                "must not require GCP acceptance",
            ):
                readiness._verify_gcp_proof_acceptance_receipt(
                    repo, harness.index.resolve(), Path("/tmp/unused-gcp-receipt")
                )
            with self.assertRaisesRegex(
                AssertionError,
                "must not require GCP acceptance",
            ):
                FLEET.verify_acceptance_receipt_for_release(
                    Path("/tmp/unused-gcp-receipt"),
                    repo_root=repo,
                    release_input_index=harness.index.resolve(),
                )
            ordered = [
                (target_id, receipts[target_id])
                for target_id in FLEET.REQUIRED_RELEASE_ARTIFACTS
            ]
            verify_results = [
                readiness._verify_target_receipt(
                    repo, harness.index.resolve(), target_id, path
                )
                for target_id, path in ordered
            ]
            auth_results = [
                FLEET.authenticate_cross_store_target_receipt(
                    repo, harness.index.resolve(), target_id, path
                )
                for target_id, path in ordered
            ]
            self.assertEqual(len(auth_results), 16)
            self.assertEqual(len(verify_results), 16)
            self.assertEqual(
                [item.get("verified_utc") for item in auth_results],
                [item.get("verified_utc") for item in verify_results],
            )
            self.assertTrue(
                all(
                    isinstance(item.get("verified_utc"), str)
                    and item["verified_utc"].endswith("Z")
                    for item in verify_results
                )
            )
            document = FLEET.create_required_release_artifacts_document(
                repo_root=repo,
                artifact_paths={},
                receipt_paths=receipts,
                release_input_index=index_ref,
            )
            verified = FLEET.verify_required_release_artifacts_document(
                document,
                expected_index=index_ref,
                repo_root=repo,
            )
            self.assertNotIsInstance(readiness._verify_target_receipt, mock.Mock)
            self.assertEqual(len(document["artifacts"]), 16)
            self.assertEqual(len(document["target_receipts"]), 16)
            self.assertEqual(
                set(document["artifacts"]), set(FLEET.REQUIRED_RELEASE_ARTIFACTS)
            )
            self.assertEqual(len(verified["artifacts"]), 16)
            self.assertEqual(
                set(verified["artifacts"]), set(FLEET.REQUIRED_RELEASE_ARTIFACTS)
            )
            self.assertEqual(
                len({item["sha256"] for item in verified["artifacts"].values()}),
                16,
            )
            self.assertNotIn("macos-developer-id-app", verified["artifacts"])

    def _bindings(self, fixture: Fixture) -> tuple[dict[str, Path], dict[str, Path]]:
        artifacts = write_distinct_release_artifacts(
            fixture.repo / ".artifacts" / "store"
        )
        receipts = write_authentic_target_receipts(
            fixture.repo,
            fixture.repo / ".artifacts" / "receipts",
            artifacts=artifacts,
            release_input_index=fixture.release_index,
        )
        return artifacts, receipts

    def test_cli_missing_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            _artifacts, receipts = self._bindings(fixture)
            receipts.pop("firefox-extension-package")
            argv = (
                plan_cli_argv(fixture, replace_plan=True)
                + release_artifact_receipt_cli_args(receipts)
            )
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "missing")

    def test_cli_duplicate_identity_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            argv = plan_cli_argv(fixture, replace_plan=True)
            argv.extend(
                [
                    "--release-artifact",
                    f"android-phone-tablet-aab={artifacts['android-phone-tablet-aab']}",
                    "--release-artifact",
                    f"android-phone-tablet-aab={artifacts['android-tv-aab']}",
                ]
            )
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "duplicate")

    def test_cli_duplicate_receipt_path_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            _artifacts, receipts = self._bindings(fixture)
            first = next(iter(receipts.values()))
            argv = plan_cli_argv(fixture, replace_plan=True)
            argv.extend(
                [
                    "--release-artifact-receipt",
                    str(first),
                    "--release-artifact-receipt",
                    str(first),
                ]
            )
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "duplicate")

    def test_cli_complete_success_writes_sixteen_plan_bound_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            argv = (
                plan_cli_argv(fixture, replace_plan=True)
                + release_artifact_receipt_cli_args(receipts, unlabeled=True)
                + release_artifact_cli_args(artifacts)
            )
            stdout = io.StringIO()
            with fixture.input_verifiers(), mock.patch("sys.stdout", stdout):
                code = FLEET.main(argv)
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(len(payload["required_release_artifacts"]["artifacts"]), 16)
            self.assertEqual(
                len(payload["required_release_artifacts"]["target_receipts"]), 16
            )
            plan = json.loads(fixture.plan.read_text(encoding="ascii"))
            self.assertEqual(
                set(plan),
                {
                    "kind",
                    "schema_version",
                    "phase",
                    "created_utc",
                    "dry_run",
                    "fleet",
                    "commands",
                    "installers",
                    "deployment_inputs",
                    "client_release_binding",
                },
            )
            binding = json.loads(
                (fixture.state / FLEET.REQUIRED_RELEASE_ARTIFACTS_NAME).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(len(binding["artifacts"]), 16)
            self.assertEqual(len(binding["target_receipts"]), 16)
            self.assertEqual(
                binding["release_input_index"],
                fixture.client_release_binding_ref["binding"]["release_input_index"],
            )

    def test_cli_receipts_complete_success_writes_sixteen_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            _artifacts, receipts = self._bindings(fixture)
            argv = plan_cli_argv(fixture, replace_plan=True)
            argv.extend(release_artifact_receipt_cli_args(receipts))
            stdout = io.StringIO()
            with fixture.input_verifiers(), mock.patch("sys.stdout", stdout):
                code = FLEET.main(argv)
            self.assertEqual(code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(len(payload["required_release_artifacts"]["artifacts"]), 16)

    def test_artifact_only_labels_and_suffixes_cannot_assign_target_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            argv = (
                plan_cli_argv(fixture, replace_plan=True)
                + release_artifact_cli_args(artifacts)
            )
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "authentic cross-store target receipts")

    def test_caller_authored_identity_document_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            receipts = {
                target_id: write_release_artifact_identity_receipt(
                    fixture.repo / ".artifacts" / "receipts",
                    target_id=target_id,
                    artifact=path,
                    release_input_index=fixture.release_index,
                )
                for target_id, path in artifacts.items()
            }
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "caller-authored identity document"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_duplicate_digest_reuse_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, _receipts = self._bindings(fixture)
            reused = artifacts["android-tv-aab"]
            reused.write_bytes(artifacts["android-phone-tablet-aab"].read_bytes())
            receipts = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts-dup",
                artifacts=artifacts,
                release_input_index=fixture.release_index,
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "single-artifact reuse"
            ):
                FLEET.phase_plan(
                    fixture.spec,
                    fixture.state,
                    repo_root=fixture.repo,
                    deployment_inputs_path=fixture.deployment_inputs,
                    release_input_index=fixture.release_index,
                    client_build_receipt=fixture.build_receipt,
                    client_artifact=fixture.client,
                    replace_plan=True,
                    release_artifact_receipts=receipts,
                )

    def test_caller_forged_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            hashed = {
                target_id: FLEET.file_ref(path, label=target_id)
                for target_id, path in artifacts.items()
            }
            hashed["android-phone-tablet-aab"]["sha256"] = "a" * 64
            with self.assertRaisesRegex(FLEET.FleetRefused, "caller-forged"):
                FLEET.bind_action_release_artifacts(
                    hashed,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                    require_store_suffix=True,
                )

    def test_stale_binding_and_receipt_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            index_ref = fixture.client_release_binding_ref["binding"][
                "release_input_index"
            ]
            stale_utc = FLEET.format_utc(
                datetime.now(timezone.utc).replace(microsecond=0)
                - FLEET.MAX_EVIDENCE_AGE
                - timedelta(minutes=10)
            )
            receipts = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts",
                artifacts=artifacts,
                release_input_index=fixture.release_index,
                verified_utc=stale_utc,
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "stale"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=index_ref,
                )
            fresh = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts-fresh",
                artifacts=artifacts,
                release_input_index=fixture.release_index,
            )
            with fixture.input_verifiers():
                document = FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=fresh,
                    release_input_index=index_ref,
                )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "stale"
            ):
                FLEET.verify_required_release_artifacts_document(
                    document,
                    expected_index=index_ref,
                    repo_root=fixture.repo,
                    now=datetime.now(timezone.utc)
                    + FLEET.MAX_EVIDENCE_AGE
                    + timedelta(hours=1),
                )

    def test_cross_release_index_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            other_index = (
                fixture.repo / ".artifacts/freeze/OTHER_RELEASE_INPUT_INDEX.json"
            )
            other_index.write_bytes(b"different release input index\n")
            other_ref = FLEET.file_ref(other_index, label="other release input index")
            receipts = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts",
                artifacts=artifacts,
                release_input_index=fixture.release_index,
            )
            with fixture.input_verifiers():
                document = FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "different release input index"
            ):
                FLEET.verify_required_release_artifacts_document(
                    document,
                    expected_index=other_ref,
                    repo_root=fixture.repo,
                )
            other_receipts = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts-other",
                artifacts=artifacts,
                release_input_index=other_index,
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "different release input index"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=other_receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_matching_receipts_bind_all_sixteen_identities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            _artifacts, receipts = self._bindings(fixture)
            with fixture.input_verifiers():
                document = FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )
                verified = FLEET.verify_required_release_artifacts_document(
                    document,
                    expected_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                    repo_root=fixture.repo,
                )
            self.assertEqual(len(verified["artifacts"]), 16)
            self.assertEqual(
                set(verified["artifacts"]), set(FLEET.REQUIRED_RELEASE_ARTIFACTS)
            )
            self.assertEqual(
                set(verified["target_receipts"]), set(FLEET.REQUIRED_RELEASE_ARTIFACTS)
            )

    def test_wrong_target_label_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            swapped = dict(receipts)
            swapped["android-phone-tablet-aab"] = receipts["android-tv-aab"]
            swapped["android-tv-aab"] = receipts["android-phone-tablet-aab"]
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "wrong target"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths=artifacts,
                    receipt_paths=swapped,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_optional_target_receipt_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            optional = write_authentic_cross_store_target_receipt(
                fixture.repo / ".artifacts" / "optional",
                repo=fixture.repo,
                target_id="macos-developer-id-app",
                artifact=artifacts["macos-app-store-pkg"],
                release_input_index=fixture.release_index,
            )
            argv = plan_cli_argv(fixture, replace_plan=True)
            argv.extend(["--release-artifact-receipt", f"macos-developer-id-app={optional}"])
            for path in receipts.values():
                argv.extend(["--release-artifact-receipt", str(path)])
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "unexpected|wrong target")

    def test_gcp_acceptance_receipt_cannot_assign_target_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            acceptance = fixture.repo / ".artifacts" / "receipts" / "acceptance-receipt.json"
            acceptance.write_bytes(
                FLEET.canonical_bytes(
                    {
                        "kind": FLEET.KIND_RECEIPT,
                        "schema_version": FLEET.SCHEMA_VERSION,
                        "phase": "verify",
                        "created_utc": FLEET.utc_now(),
                        "verdict": "pass",
                        "target_id": "android-phone-tablet-aab",
                    }
                )
            )
            receipts["android-phone-tablet-aab"] = acceptance
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused,
                "caller-authored identity document or GCP acceptance receipt",
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_forged_authentic_receipt_digest_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, _receipts = self._bindings(fixture)
            receipts = write_authentic_target_receipts(
                fixture.repo,
                fixture.repo / ".artifacts" / "receipts-forged",
                artifacts=artifacts,
                release_input_index=fixture.release_index,
            )
            forged = write_authentic_cross_store_target_receipt(
                fixture.repo / ".artifacts" / "receipts-forged",
                repo=fixture.repo,
                target_id="android-phone-tablet-aab",
                artifact=artifacts["android-phone-tablet-aab"],
                release_input_index=fixture.release_index,
                artifact_sha256="a" * 64,
            )
            receipts["android-phone-tablet-aab"] = forged
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "caller-forged|invalid"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_wrong_freeze_build_receipt_target_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts, receipts = self._bindings(fixture)
            receipts["android-phone-tablet-aab"] = write_authentic_cross_store_target_receipt(
                fixture.repo / ".artifacts" / "receipts-wrong-target",
                repo=fixture.repo,
                target_id="android-phone-tablet-aab",
                artifact=artifacts["android-phone-tablet-aab"],
                release_input_index=fixture.release_index,
                build_receipt_target="android-tv-release-aab",
            )
            with fixture.input_verifiers(), self.assertRaisesRegex(
                FLEET.FleetRefused, "build receipt target was substituted|wrong target"
            ):
                FLEET.create_required_release_artifacts_document(
                    repo_root=fixture.repo,
                    artifact_paths={},
                    receipt_paths=receipts,
                    release_input_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_identity_receipt_loader_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            path = write_release_artifact_identity_receipt(
                fixture.repo / ".artifacts" / "receipts",
                target_id="android-phone-tablet-aab",
                artifact=artifacts["android-phone-tablet-aab"],
                release_input_index=fixture.release_index,
            )
            with self.assertRaisesRegex(
                FLEET.FleetRefused, "caller-authored identity document"
            ):
                FLEET.load_release_artifact_identity_receipt(
                    path,
                    target_id="android-phone-tablet-aab",
                    expected_index=fixture.client_release_binding_ref["binding"][
                        "release_input_index"
                    ],
                )

    def test_non_plan_cli_rejects_artifact_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), apply=False)
            artifacts = write_distinct_release_artifacts(
                fixture.repo / ".artifacts" / "store"
            )
            argv = [
                "verify",
                "--control-instance",
                CONTROL,
                "--winn3-data-instance",
                WINN3,
                "--cover-data-instance",
                COVER,
                "--project",
                PROJECT,
                "--state-dir",
                str(fixture.state),
                "--admin-source-cidr",
                ADMIN_CIDR,
            ] + release_artifact_cli_args(artifacts)
            stderr = io.StringIO()
            with fixture.input_verifiers(), redirect_stderr(stderr):
                code = FLEET.main(argv)
            self.assertEqual(code, FLEET.REFUSAL_EXIT)
            self.assertRegex(stderr.getvalue(), "plan-bound")

    def test_complete_success_binds_sixteen_and_mints_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), bind_required_release_artifacts=True)
            binding = json.loads(
                (fixture.state / FLEET.REQUIRED_RELEASE_ARTIFACTS_NAME).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(len(binding["artifacts"]), 16)
            self.assertEqual(
                set(binding["artifacts"]), set(FLEET.REQUIRED_RELEASE_ARTIFACTS)
            )
            self.assertEqual(len(binding["target_receipts"]), 16)
            rows = FLEET.evaluate_action_release_artifacts(
                fixture.client_release_binding_ref,
                supplied_artifacts=binding["artifacts"],
            )
            self.assertEqual(len(rows), 16)
            self.assertTrue(all(item["status"] == "proven" for item in rows))
            digests = {item["artifact"]["sha256"] for item in rows}
            self.assertEqual(len(digests), 16)
            index_ref = fixture.client_release_binding_ref["binding"][
                "release_input_index"
            ]
            self.assertTrue(
                all(item["release_input_index"] == index_ref for item in rows)
            )
            fixture.driver.write_bytes(FLEET.REVIEWED_LIVE_PROBE_PATH.read_bytes())
            os.chmod(fixture.driver, 0o700)
            evidence = fixture.collect()
            result = fixture.verify(evidence)
            self.assertEqual(result["verdict"], "pass")
            self.assertTrue(result["acceptance"])
            receipt = fixture.state / FLEET.RECEIPT_NAME
            self.assertTrue(receipt.exists())
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)
            with fixture.input_verifiers():
                verified = FLEET.verify_acceptance_receipt_for_release(
                    receipt,
                    repo_root=fixture.repo,
                    release_input_index=fixture.release_index,
                )
            self.assertTrue(verified["verified"])
            self.assertEqual(len(verified["required_action_artifacts"]), 16)
            self.assertTrue(
                all(
                    item["status"] == "proven"
                    for item in verified["required_action_artifacts"]
                )
            )

    def test_complete_artifacts_with_fake_probe_still_cannot_mint_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Fixture(Path(tmp), bind_required_release_artifacts=True)
            result = fixture.verify(fixture.collect())
            self.assertEqual(result["verdict"], "blocked")
            self.assertFalse(result["acceptance"])
            self.assertFalse((fixture.state / FLEET.RECEIPT_NAME).exists())
            proven = [
                item
                for item in result["required_action_artifacts"]
                if item["status"] == "proven"
            ]
            self.assertEqual(len(proven), 16)


def _replace_marker_field(
    data: dict[str, Any], field: str, value: Any
) -> dict[str, Any]:
    changed = copy.deepcopy(data)
    for row in changed["roles"]:
        row["marker"][field] = value
    return changed


def _replace_candidate(data: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(data)
    for row in changed["roles"]:
        row["candidate"] = copy.deepcopy(candidate)
    return changed


class RemoteGatewaySequenceTests(unittest.TestCase):
    def test_remote_gateway_order_is_install_provision_preflight_start(self) -> None:
        remote = load_module(
            "gcp_proof_remote_install_sequence", TOOLS / "gcp_proof_remote_install.py"
        )
        self.assertEqual(
            remote.gateway_sequence(),
            (
                (remote.GATEWAY_INSTALLER, "--install"),
                (remote.PROOF_KEY_PROVISION_ID, remote.PROOF_KEY_PROVISION_FLAG),
                (remote.GATEWAY_INSTALLER, "--preflight"),
                (remote.GATEWAY_INSTALLER, "--start"),
            ),
        )
        gateway_flags = [
            flag
            for _role, script, flag in remote.EXPECTED_STEPS
            if script == FLEET.GATEWAY_INSTALLER
        ]
        self.assertEqual(gateway_flags, ["--install", "--preflight", "--start"])
        self.assertNotEqual(gateway_flags, ["--preflight", "--start"])
        install = next(
            index
            for index, item in enumerate(remote.EXPECTED_STEPS)
            if item[1] == FLEET.GATEWAY_INSTALLER and item[2] == "--install"
        )
        provision = next(
            index
            for index, item in enumerate(remote.EXPECTED_STEPS)
            if item[1] == remote.PROOF_KEY_PROVISION_ID
        )
        preflight = next(
            index
            for index, item in enumerate(remote.EXPECTED_STEPS)
            if item[1] == FLEET.GATEWAY_INSTALLER and item[2] == "--preflight"
        )
        start = next(
            index
            for index, item in enumerate(remote.EXPECTED_STEPS)
            if item[1] == FLEET.GATEWAY_INSTALLER and item[2] == "--start"
        )
        self.assertLess(install, provision)
        self.assertLess(provision, preflight)
        self.assertLess(preflight, start)
        completed_for_start = remote.required_completed_indices("data-winn3", start)
        self.assertEqual(
            completed_for_start,
            remote.required_completed_indices("data-winn3", preflight) + [preflight],
        )
        self.assertIn(install, completed_for_start)
        self.assertIn(provision, completed_for_start)
        self.assertNotIn(start, completed_for_start)


class RunbookTests(unittest.TestCase):
    def test_runbook_uses_current_gcloud_pin(self) -> None:
        runbook = RUNBOOK_PATH.read_text(encoding="utf-8")
        manifest = json.loads(TOOLCHAIN_PINS_PATH.read_text(encoding="utf-8"))
        gcloud = manifest["tools"]["google_cloud_cli"]
        version = gcloud["version"]

        self.assertIsInstance(version, str)
        self.assertRegex(version, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        self.assertNotIn("581.0.0", runbook)
        self.assertGreaterEqual(runbook.count(version), 4)
        for platform, archive_name in gcloud["archive_name"].items():
            with self.subTest(platform=platform):
                self.assertIsInstance(archive_name, str)
                self.assertIn(version, archive_name)

    def test_runbook_documents_collector_and_live_only_boundary(self) -> None:
        text = RUNBOOK_PATH.read_text(encoding="utf-8")
        for marker in (
            "explicit argv",
            "shell",
            "stdout",
            "stderr",
            "exit",
            "client build",
            "immutable apply",
            "probe driver",
            "fake runner",
            "live",
            "never executes gcloud",
            "same_node_downgrade_refused",
            "six-hour freshness window",
            "RELEASE_INPUT_INDEX.json",
            "cross_store_upload_readiness.py record",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
