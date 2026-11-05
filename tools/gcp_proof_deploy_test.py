#!/usr/bin/env python3
"""No-network adversarial tests for the controlled GCP deployment executor."""

from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence


TOOLS = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DEPLOY = load_module("gcp_proof_deploy_under_test", TOOLS / "gcp_proof_deploy.py")
REMOTE = load_module("gcp_proof_remote_install_under_test", TOOLS / "gcp_proof_remote_install.py")
FLEET = load_module("gcp_proof_fleet_deploy_contract", TOOLS / "gcp_proof_fleet.py")


def capture(data: bytes) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "data": base64.b64encode(data).decode("ascii"),
        "encoding": "base64",
        "original_bytes": len(data),
        "sha256": DEPLOY.sha256_bytes(data),
        "truncated": False,
    }


class ManifestVerifier:
    def __init__(self, value: dict[str, Any]) -> None:
        self.value = value

    def verify_manifest(self, repo: Path, path: Path) -> dict[str, Any]:
        del repo, path
        return copy.deepcopy(self.value)


class ClientBindingVerifier:
    SCHEMA_VERSION = 2
    CONTRACT = "winsvpn-gcp-client-release-binding-v2"
    PLATFORM = "linux"

    def __init__(self, fixture: "Fixture") -> None:
        self.fixture = fixture
        self.__file__ = str(DEPLOY.CLIENT_BINDING_TOOL)
        self.freeze = SimpleNamespace(
            __file__=str(TOOLS / "release_dependency_freeze.py")
        )
        self.proof_builder = SimpleNamespace(
            __file__=str(TOOLS / "build_gcp_proof_client.py")
        )

    @staticmethod
    def canonical_bytes(value: dict[str, Any]) -> bytes:
        return DEPLOY.canonical_bytes(value)

    def verify_client_release(
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
            or artifact != self.fixture.client_artifact
            or platform != self.PLATFORM
        ):
            raise RuntimeError("substituted client release path")
        for key, path in (
            ("release_input_index", release_input_index),
            ("build_receipt", build_receipt),
            ("artifact", artifact),
        ):
            expected = self.fixture.client_binding[key]
            data = path.read_bytes()
            if (
                len(data) != expected["bytes"]
                or DEPLOY.sha256_bytes(data) != expected["sha256"]
            ):
                raise RuntimeError(f"changed client {key}")
        return copy.deepcopy(self.fixture.client_binding)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.repo = self.root / "repo"
        self.state = self.root / "state"
        self.repo.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        client_dir = self.repo / ".artifacts" / "freeze"
        client_dir.mkdir(parents=True)
        self.release_index = client_dir / "RELEASE_INPUT_INDEX.json"
        self.build_receipt = client_dir / "LINUX_BUILD_RECEIPT.json"
        self.client_artifact = self.repo / "build" / "linux" / "x64" / "wins_vpn"
        self.client_artifact.parent.mkdir(parents=True)
        self.release_index.write_bytes(b"exact release input index\n")
        self.build_receipt.write_bytes(b"exact Linux build receipt\n")
        self.client_artifact.write_bytes(b"exact Linux proof executable\n")
        os.chmod(self.client_artifact, 0o755)

        def ref(path: Path) -> dict[str, Any]:
            data = path.read_bytes()
            return {
                "bytes": len(data),
                "path": str(path),
                "sha256": DEPLOY.sha256_bytes(data),
            }

        proof_build_id = "e" * 64
        self.client_binding = {
            "artifact": ref(self.client_artifact),
            "artifact_input_fingerprint_sha256": "d" * 64,
            "build_identity": f"linux:1.0.15+30:{proof_build_id}",
            "build_receipt": ref(self.build_receipt),
            "contract": ClientBindingVerifier.CONTRACT,
            "platform": "linux",
            "release": "1.0.15+30",
            "release_input_index": ref(self.release_index),
            "schema_version": 2,
            "shared_revision": "reviewed-linux-revision",
            "proof_build": {
                "build_contract": {"sha256": "1" * 64},
                "build_identity": proof_build_id,
                "builder": {"sha256": "2" * 64},
                "defines": {"release": "1.0.15+30"},
                "source": {"sha256": "3" * 64},
                "target": {"goos": "linux", "goarch": "amd64"},
                "toolchain": {"name": "Go", "version": "1.27.1"},
                "toolchain_pin_manifest": {"sha256": "4" * 64},
            },
        }
        self.client_verifier = ClientBindingVerifier(self)
        self.client_binding_ref = {
            "binding": self.client_binding,
            "binding_sha256": DEPLOY.sha256_bytes(
                DEPLOY.canonical_bytes(self.client_binding)
            ),
            "contract": DEPLOY.CLIENT_BINDING_REFERENCE_CONTRACT,
            "repo_root": str(self.repo),
            "schema_version": 1,
            "verifier_closure": DEPLOY._client_verifier_closure(
                self.client_verifier
            ),
        }
        self.inputs: list[dict[str, Any]] = []
        for relative, data, mode, file_class in (
            ("server/wins_control_plane_setup_ONETOUCH.sh", b"#!/bin/bash\nexit 0\n", 0o755, "server"),
            ("server/wins_data_plane_setup_ONETOUCH.sh", b"#!/bin/bash\nexit 0\n# data\n", 0o755, "server"),
            ("server/wins_winn3_gateway_install.sh", b"#!/bin/bash\nexit 0\n# winn\n", 0o755, "server"),
            ("winn_protocol_experimental/dist/winn3-gateway-linux-amd64", b"\x7fELFfixture", 0o755, "artifact"),
            ("winn_protocol_experimental/dist/winn3-probe-linux-amd64", b"\x7fELFprobe-fixture", 0o755, "artifact"),
            ("winn_protocol_experimental/dist/winn-ech-keygen-linux-amd64", b"\x7fELFkeygen-fixture", 0o755, "artifact"),
            ("winn_protocol_experimental/dist/amneziawg-go-linux-amd64", b"\x7fELFamneziawg-go-fixture", 0o755, "client-runtime"),
            ("winn_protocol_experimental/dist/awg-linux-amd64", b"\x7fELFawg-fixture", 0o755, "client-runtime"),
            ("winn_protocol_experimental/dist/xray-linux-amd64", b"\x7fELFxray-fixture", 0o755, "client-runtime"),
            (
                "tools/gcp_proof_remote_action.py",
                (TOOLS / "gcp_proof_remote_action.py").read_bytes(),
                0o644,
                "tool",
            ),
            (
                "tools/gcp_proof_attempt_broker.py",
                (TOOLS / "gcp_proof_attempt_broker.py").read_bytes(),
                0o755,
                "tool",
            ),
            (
                REMOTE.ATTEMPT_BROKER_SOCKET_SOURCE,
                (TOOLS / "gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.socket").read_bytes(),
                0o644,
                "tool",
            ),
            (
                REMOTE.ATTEMPT_BROKER_SERVICE_SOURCE,
                (TOOLS / "gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.service").read_bytes(),
                0o644,
                "tool",
            ),
        ):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.chmod(path, mode)
            self.inputs.append(
                {
                    "bytes": len(data), "class": file_class, "mode": mode,
                    "path": relative, "sha256": DEPLOY.sha256_bytes(data),
                }
            )
        extra_broker_files = [
            *REMOTE.ATTEMPT_BROKER_UNITS,
            *REMOTE.ATTEMPT_BROKER_CONFIGS,
        ]
        for relative, _install, _name in extra_broker_files:
            data = Path(TOOLS).parent.joinpath(*PurePosixPath(relative).parts).read_bytes()
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.chmod(path, 0o644)
            self.inputs.append(
                {
                    "bytes": len(data),
                    "class": "tool",
                    "mode": 0o644,
                    "path": relative,
                    "sha256": DEPLOY.sha256_bytes(data),
                }
            )
        self.inputs.sort(key=lambda item: item["path"])
        installer_paths = [item[1] for item in DEPLOY.EXPECTED_STEPS]
        self.installers = []
        for relative in dict.fromkeys(installer_paths):
            if relative == DEPLOY.PROOF_KEY_PROVISION_ID:
                continue
            item = next(entry for entry in self.inputs if entry["path"] == relative)
            self.installers.append({key: item[key] for key in ("bytes", "mode", "path", "sha256")})
        artifact_inputs = [
            next(
                item for item in self.inputs
                if item["class"] == "artifact"
                and Path(item["path"]).name.startswith(f"{product}-linux-")
            )
            for product in REMOTE.PROOF_CLIENT_PRODUCTS
        ]
        helper_input = next(
            item
            for item in self.inputs
            if item["path"] == REMOTE.REMOTE_ACTION_HELPER_PATH
        )
        by_path = {item["path"]: item for item in self.inputs}

        def member(relative: str, install_path: str, name: str) -> dict[str, Any]:
            item = by_path[relative]
            return {
                "bytes": item["bytes"],
                "install_path": install_path,
                "mode": item["mode"],
                "name": name,
                "path": item["path"],
                "sha256": item["sha256"],
            }

        broker_input = by_path[REMOTE.ATTEMPT_BROKER_PATH]
        attempt_broker = {
            "bytes": broker_input["bytes"],
            "configs": [
                member(relative, install_path, name)
                for relative, install_path, name in REMOTE.ATTEMPT_BROKER_CONFIGS
            ],
            "contract": REMOTE.ATTEMPT_BROKER_CONTRACT,
            "install_path": REMOTE.ATTEMPT_BROKER_INSTALL_PATH,
            "mode": broker_input["mode"],
            "path": broker_input["path"],
            "required_roles": list(REMOTE.ATTEMPT_BROKER_REQUIRED_ROLES),
            "schema_version": 1,
            "service": member(
                REMOTE.ATTEMPT_BROKER_SERVICE_SOURCE,
                REMOTE.ATTEMPT_BROKER_SERVICE_INSTALL_PATH,
                "winsvpn-gcp-proof-attempt-broker.service",
            ),
            "sha256": broker_input["sha256"],
            "socket": member(
                REMOTE.ATTEMPT_BROKER_SOCKET_SOURCE,
                REMOTE.ATTEMPT_BROKER_SOCKET_INSTALL_PATH,
                "winsvpn-gcp-proof-attempt-broker.socket",
            ),
            "units": [
                member(relative, install_path, name)
                for relative, install_path, name in REMOTE.ATTEMPT_BROKER_UNITS
            ],
        }
        self.proof_client_artifacts = []
        for product, artifact_input in zip(REMOTE.PROOF_CLIENT_PRODUCTS, artifact_inputs):
            self.proof_client_artifacts.append({
                "architecture": "amd64",
                "elf_class": 2,
                "elf_data": 1,
                "elf_machine": 62,
                "elf_type": 3,
                "entry": 4096,
                "os": "linux",
                "path": artifact_input["path"],
                "product": product,
                "runtime": "linux-amd64",
                "sha256": artifact_input["sha256"],
            })
        self.gateway_artifact = dict(self.proof_client_artifacts[0])
        runtime_inputs = [
            next(
                item for item in self.inputs
                if item["class"] == "client-runtime"
                and Path(item["path"]).name == f"{product}-linux-amd64"
            )
            for product in REMOTE.CLIENT_RUNTIME_PRODUCTS
        ]
        self.client_runtime_artifacts = []
        for index, (product, runtime_input) in enumerate(
            zip(REMOTE.CLIENT_RUNTIME_PRODUCTS, runtime_inputs), start=1
        ):
            self.client_runtime_artifacts.append({
                "architecture": "amd64",
                "bytes": runtime_input["bytes"],
                "elf_class": 2,
                "elf_data": 1,
                "elf_machine": 62,
                "elf_type": 3,
                "entry": 4096,
                "mode": runtime_input["mode"],
                "os": "linux",
                "path": runtime_input["path"],
                "product": product,
                "provenance": {
                    "commit": str(index) * 40,
                    "repository": f"https://github.com/winsvpn-proof/{product}",
                    "source_sha256": str(index) * 64,
                    "tag": f"v-proof-{index}",
                },
                "runtime": "linux-amd64",
                "sha256": runtime_input["sha256"],
            })
        timestamp_free = {
            "client_runtime_artifacts": self.client_runtime_artifacts,
            "closure_policy": "winsvpn-gcp-deployment-closure-v1",
            "external_pins": {
                "awg": {"awg_server_image": "amneziavpn/amneziawg-go:v3.1.20260828"},
                "client_runtime": {
                    item["product"]: {
                        "architecture": item["architecture"],
                        "commit": item["provenance"]["commit"],
                        "os": item["os"],
                        "product": item["product"],
                        "repository": item["provenance"]["repository"],
                        "sha256": item["sha256"],
                        "source_sha256": item["provenance"]["source_sha256"],
                        "tag": item["provenance"]["tag"],
                    }
                    for item in self.client_runtime_artifacts
                },
                "router_base_image": {"digest": "sha256:" + "a" * 64, "reference": "python:3.14@sha256:" + "a" * 64},
                "xray": {"version": "26.9.30"},
            },
            "gateway_artifact": self.gateway_artifact,
            "proof_client_artifacts": self.proof_client_artifacts,
            "inputs": self.inputs,
            "installers": self.installers,
            "kind": "winsvpn.gcp_proof.deployment_inputs.v1",
            "publication_authorized": False,
            "attempt_broker": attempt_broker,
            "remote_action_helper": {
                "bytes": helper_input["bytes"],
                "contract": REMOTE.REMOTE_ACTION_HELPER_CONTRACT,
                "install_path": REMOTE.REMOTE_ACTION_HELPER_INSTALL_PATH,
                "mode": helper_input["mode"],
                "path": helper_input["path"],
                "required_roles": list(REMOTE.REMOTE_ACTION_HELPER_REQUIRED_ROLES),
                "schema_version": 1,
                "sha256": helper_input["sha256"],
            },
            "schema_version": 1,
            "scope_roots": ["server", "router", "winn_protocol_experimental"],
        }
        self.manifest = {
            **timestamp_free,
            "candidate_id": DEPLOY.sha256_bytes(DEPLOY.canonical_bytes(timestamp_free)),
            "created_utc": "2026-08-23T12:00:00Z",
        }
        self.manifest_path = self.state / "DEPLOYMENT_INPUTS.json"
        self.write_immutable(self.manifest_path, self.manifest)
        manifest_data = self.manifest_path.read_bytes()
        self.manifest_ref = {
            "bytes": len(manifest_data),
            "candidate_id": self.manifest["candidate_id"],
            "path": str(self.manifest_path),
            "sha256": DEPLOY.sha256_bytes(manifest_data),
        }
        self.fleet = {
            "fleet_id": "proof-fleet-20260823",
            "gcloud_bin": "gcloud",
            "instances": [
                {
                    "name": "proof-control-a1", "role": "control",
                    "zone": "us-east1-b", "machine_type": "e2-standard-2",
                },
                {
                    "name": "proof-winn3-a1", "role": "data-winn3",
                    "zone": "us-central1-a", "machine_type": "e2-medium",
                },
                {
                    "name": "proof-cover-a1", "role": "data-cover",
                    "zone": "us-east1-b", "machine_type": "e2-medium",
                },
            ],
            "project": "winsvpn-proof-lab",
        }
        instance_map = {item["role"]: item for item in self.fleet["instances"]}
        manifest_refs = {item["path"]: item for item in self.installers}
        installer_sequence = []
        for index, (role, script, flag) in enumerate(DEPLOY.EXPECTED_STEPS):
            ref = (
                {"bytes": 0, "mode": 0, "sha256": "0" * 64}
                if script == DEPLOY.PROOF_KEY_PROVISION_ID
                else manifest_refs[script]
            )
            installer_sequence.append(
                {
                    "execution_owner": "gcp_proof_deploy.py", "flag": flag,
                    "index": index, "instance": instance_map[role]["name"],
                    "remote_mutation": True, "role": role, "script": script,
                    "script_ref": {key: ref[key] for key in ("bytes", "mode", "sha256")},
                }
            )
        self.plan = {
            "client_release_binding": self.client_binding_ref,
            "commands": [], "created_utc": "2026-08-23T12:01:00Z",
            "deployment_inputs": self.manifest_ref, "dry_run": True,
            "fleet": self.fleet, "installers": installer_sequence,
            "kind": DEPLOY.KIND_PLAN, "phase": "plan", "schema_version": 4,
        }
        self.plan_path = self.state / "plan.json"
        self.write_immutable(self.plan_path, self.plan)
        self.apply = {
            **self.plan,
            "created_utc": "2026-08-23T12:02:00Z",
            "dry_run": False,
            "kind": DEPLOY.KIND_APPLY,
            "phase": "apply",
            "plan_sha256": DEPLOY.sha256_bytes(self.plan_path.read_bytes()),
        }
        self.apply_path = self.state / "apply.json"
        self.write_immutable(self.apply_path, self.apply)
        self.output = self.state / "deployment-execution.json"

    @staticmethod
    def write_immutable(path: Path, value: dict[str, Any]) -> None:
        data = DEPLOY.canonical_bytes(value)
        path.write_bytes(data)
        sidecar = path.with_name(path.name + ".sha256")
        sidecar.write_bytes(f"{DEPLOY.sha256_bytes(data)}  {path.name}\n".encode("ascii"))
        os.chmod(path, 0o400)
        os.chmod(sidecar, 0o400)

    def rewrite(self, path: Path, value: dict[str, Any]) -> None:
        sidecar = path.with_name(path.name + ".sha256")
        os.chmod(path, 0o600)
        os.chmod(sidecar, 0o600)
        path.unlink()
        sidecar.unlink()
        self.write_immutable(path, value)

    @contextmanager
    def context_patch(self) -> Any:
        with mock.patch.object(
            DEPLOY,
            "_load_manifest_module",
            return_value=ManifestVerifier(self.manifest),
        ), mock.patch.object(
            DEPLOY,
            "_load_client_binding_module",
            return_value=self.client_verifier,
        ):
            yield


class FakeRunner:
    TEST_ONLY = True
    ROLE_IDS = {"control": "1001", "data-winn3": "1002", "data-cover": "1003"}
    FIREWALL_IDS = {
        "admin-ssh": "2001",
        "winn3-in": "2002",
        "control-http": "2003",
        "cover-in": "2004",
    }

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.version_calls: list[list[str]] = []
        self.fail_step: int | None = None
        self.fail_exit_code = 7
        self.fail_transport_exit_code: int | None = None
        self.transfer_failure = False
        self.mutate_after_step: tuple[int, Any] | None = None
        self.secret_step: int | None = None
        self.mutate_before_preflight: Any = None
        self.describe_overrides: dict[str, dict[str, Any]] = {}
        self.describe_bytes: dict[str, bytes] = {}
        self.cleanup_identity_swap: dict[str, dict[str, Any]] = {}
        self.cleanup_resource_swap: dict[str, dict[str, Any]] = {}
        self.fail_rollback_roles: set[str] = set()
        self.fail_deployment_observation = False
        self.inactive_observed_socket = False
        self.failed_observed_service = False
        self.fail_delete_roles: set[str] = set()
        self.deleted_instances: list[str] = []
        self.deleted_resources: list[str] = []
        self.describe_counts: dict[str, int] = {}
        self.resource_describe_counts: dict[str, int] = {}
        self._resource_cache: dict[str, dict[str, Any]] = {}
        self.fixture: Fixture | None = None
        self.candidate_id = ""
        self.pipe_calls: list[dict[str, list[str]]] = []
        self.exchange_helper_actions: list[tuple[str, str]] = []
        self.missing_gce_identity = False
        self.already_sealed = False
        self.already_complete = False
        self.partial_exchange = False
        self.probe_id_overrides: dict[str, str] = {}
        self.probe_boot_overrides: dict[str, str] = {}
        self.ROLE_BOOT_IDS = {
            "control": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "data-winn3": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "data-cover": "cccccccc-cccc-cccc-cccc-cccccccccccc",
        }

    def describe_document(self, role: str) -> dict[str, Any]:
        assert self.fixture is not None
        instance = next(item for item in self.fixture.fleet["instances"] if item["role"] == role)
        created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        payload = {
            "creationTimestamp": created,
            "deletionProtection": True,
            "canIpForward": role in {"data-winn3", "data-cover"},
            "id": self.ROLE_IDS[role],
            "labels": DEPLOY._expected_labels(self.fixture.fleet["fleet_id"], role),
            "machineType": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{self.fixture.fleet['project']}/zones/{instance['zone']}/"
                f"machineTypes/{instance['machine_type']}"
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
                f"{self.fixture.fleet['project']}/zones/{instance['zone']}/"
                f"instances/{instance['name']}"
            ),
            "serviceAccounts": [],
            "shieldedInstanceConfig": {
                "enableIntegrityMonitoring": True,
                "enableSecureBoot": True,
                "enableVtpm": True,
            },
            "status": "RUNNING",
            "tags": {"items": DEPLOY._expected_tags(self.fixture.fleet["fleet_id"], role)},
            "zone": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{self.fixture.fleet['project']}/zones/{instance['zone']}"
            ),
        }
        payload.update(copy.deepcopy(self.describe_overrides.get(role, {})))
        return payload

    def _created_now(self) -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

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

    def resource_document(self, kind: str, name: str, region: str | None = None) -> dict[str, Any]:
        assert self.fixture is not None
        project = self.fixture.fleet["project"]
        fleet_id = self.fixture.fleet["fleet_id"]
        ident = self._resource_id(kind, name)
        created = self._created_now()
        labels = DEPLOY._expected_resource_labels(fleet_id)
        if kind == "firewall":
            payload = {
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
        elif kind == "subnet":
            assert region is not None
            payload = {
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
        else:
            payload = {
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
        return payload

    @staticmethod
    def options(remote: list[str]) -> dict[str, str | bool]:
        values: dict[str, str | bool] = {}
        index = 4
        while index < len(remote):
            item = remote[index]
            if item.startswith("--"):
                if "=" in item:
                    key, value = item[2:].split("=", 1)
                    values[key] = value
                    index += 1
                    continue
                key = item[2:]
                if index + 1 < len(remote) and not remote[index + 1].startswith("--"):
                    values[key] = remote[index + 1]
                    index += 2
                else:
                    values[key] = True
                    index += 1
            else:
                index += 1
        return values

    def _describe(self, argv: list[str]) -> Any:
        name = argv[4]
        assert self.fixture is not None
        if name in self.deleted_instances:
            return DEPLOY.RunResult(
                b"",
                f"ERROR: The resource '{name}' was not found\n".encode("ascii"),
                1,
            )
        role = next(item["role"] for item in self.fixture.fleet["instances"] if item["name"] == name)
        self.describe_counts[role] = self.describe_counts.get(role, 0) + 1
        if role in self.describe_bytes and self.describe_counts[role] == 1:
            return DEPLOY.RunResult(self.describe_bytes[role], b"", 0)
        payload = self.describe_document(role)
        if self.describe_counts[role] >= 2 and role in self.cleanup_identity_swap:
            payload.update(copy.deepcopy(self.cleanup_identity_swap[role]))
        return DEPLOY.RunResult(json.dumps(payload).encode("utf-8"), b"", 0)

    def _describe_resource(self, kind: str, name: str, region: str | None = None) -> Any:
        if name in self.deleted_resources:
            return DEPLOY.RunResult(
                b"",
                f"ERROR: The resource '{name}' was not found\n".encode("ascii"),
                1,
            )
        self.resource_describe_counts[name] = self.resource_describe_counts.get(name, 0) + 1
        if name not in self._resource_cache:
            self._resource_cache[name] = self.resource_document(kind, name, region)
        payload = copy.deepcopy(self._resource_cache[name])
        if self.resource_describe_counts[name] >= 2 and name in self.cleanup_resource_swap:
            payload.update(copy.deepcopy(self.cleanup_resource_swap[name]))
        return DEPLOY.RunResult(json.dumps(payload).encode("utf-8"), b"", 0)

    def _rollback(self, remote: list[str]) -> Any:
        token, role, instance, fleet = remote[6:10]
        files = list(remote[10:14])
        state = remote[14]
        if state != DEPLOY.REMOTE_STATE:
            raise AssertionError("rollback state root was not fixed")
        failed = role in self.fail_rollback_roles
        payload = {
            "errors": [] if not failed else ["winn3-gateway.service"],
            "fleet_id": fleet,
            "inspected": list(DEPLOY.ROLLBACK_RESIDUAL_CLASSES),
            "instance": instance,
            "kind": DEPLOY.KIND_ROLLBACK,
            "ok": not failed,
            "removed_files": files if not failed else [],
            "residuals": {
                key: [] for key in DEPLOY.ROLLBACK_RESIDUAL_CLASSES
            },
            "role": role,
            "schema_version": 1,
            "services_stopped": list(DEPLOY.ROLLBACK_SERVICES[role]) if not failed else [],
            "state_removed": not failed,
        }
        if failed and role == "control":
            payload["errors"] = ["wins-hub.service"]
        return DEPLOY.RunResult(
            DEPLOY.canonical_bytes(payload), b"", 0 if not failed else 1
        )

    def _deployment_observation(self, remote: list[str]) -> Any:
        if self.fail_deployment_observation:
            return DEPLOY.RunResult(b"", b"observation failed", 1)
        spec = json.loads(remote[6])
        service = {
            "active": False,
            "enabled": False,
            "failed": self.failed_observed_service,
            "installed": True,
            "name": spec["service"],
        }
        socket = {
            "active": not self.inactive_observed_socket,
            "enabled": True,
            "failed": False,
            "installed": True,
            "name": spec["socket"],
        }
        payload = {
            "client_units_verified": spec["client_units"],
            "files_verified": [item["path"] for item in spec["files"]],
            "kind": DEPLOY.KIND_DEPLOYMENT_OBSERVATION,
            "role": "control",
            "schema_version": 1,
            "service": service,
            "socket": socket,
        }
        return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0)

    def _runtime_probe(self, remote: list[str]) -> Any:
        role = remote[6]
        blocked = self.missing_gce_identity and role in {
            DEPLOY.EXCHANGE_SOURCE_ROLE, DEPLOY.EXCHANGE_TARGET_ROLE
        }
        status = "blocked" if blocked else "ok"
        marker = None
        if self.already_complete and self.fixture is not None and status == "ok":
            marker = {
                "apply_sha256": DEPLOY.sha256_bytes(self.fixture.apply_path.read_bytes()),
                "candidate_id": self.fixture.manifest["candidate_id"],
                "completed_step_indices": [
                    index for index, item in enumerate(DEPLOY.EXPECTED_STEPS) if item[0] == role
                ],
                "deployment_manifest_sha256": self.fixture.manifest_ref["sha256"],
                "fleet_completed_step_indices": list(range(len(DEPLOY.EXPECTED_STEPS))),
                "fleet_id": self.fixture.fleet["fleet_id"],
                "fleet_record_chain_sha256": DEPLOY.ZERO_SHA256,
                "instance": next(
                    item["name"] for item in self.fixture.fleet["instances"] if item["role"] == role
                ),
                "kind": DEPLOY.KIND_MARKER,
                "plan_sha256": DEPLOY.sha256_bytes(self.fixture.plan_path.read_bytes()),
                "role": role,
                "runtime": {"awg": {}, "router": {}, "winn": {}, "xray": {}},
                "schema_version": 1,
                "updated_utc": "2026-08-23T12:20:00Z",
            }
        payload = {
            "boot_id": (
                None if role == "data-cover" or blocked
                else self.probe_boot_overrides.get(role, self.ROLE_BOOT_IDS[role])
            ),
            "instance_id": (
                None if role == "data-cover" or blocked
                else self.probe_id_overrides.get(role, self.ROLE_IDS[role])
            ),
            "kind": DEPLOY.KIND_RUNTIME_PROBE,
            "marker": marker,
            "role": role,
            "schema_version": 1,
            "status": status,
        }
        return DEPLOY.RunResult(
            DEPLOY.canonical_bytes(payload), b"", 0 if status == "ok" else 2
        )

    def _exchange_envelope(self, action: str, role: str, *, sealed: bool = False) -> dict[str, Any]:
        instance = {
            "control": "proof-control-a1",
            "data-winn3": "proof-winn3-a1",
        }[role]
        receipt: dict[str, Any]
        if action == "exchange-status":
            completed = list(DEPLOY.EXCHANGE_ACTIONS[:-1]) if sealed else []
            receipt = {
                "action": action,
                "apply_sha256": "a" * 64,
                "binding_sha256": "b" * 64,
                "bundle_sha256": "c" * 64,
                "candidate_id": self.candidate_id or ("d" * 64),
                "completed_actions": completed,
                "contract": DEPLOY.EXCHANGE_CONTRACT,
                "expires_utc": "2026-08-23T12:30:00Z",
                "fleet_id": "proof-fleet-20260823",
                "helper_sha256": DEPLOY.REMOTE_HELPER_SHA256,
                "inner_v4": DEPLOY.PROOF_CLIENT_INNER_V4,
                "instance": instance,
                "kind": "winsvpn.gcp_proof.authenticated_key_exchange_receipt.v1",
                "manifest_sha256": "e" * 64,
                "plan_sha256": "f" * 64,
                "role": role,
                "schema_version": 1,
                "sealed": sealed,
                "skew_seconds": 30,
                "source_boot_id": self.ROLE_BOOT_IDS["data-winn3"],
                "source_instance": "proof-winn3-a1",
                "source_instance_id": self.ROLE_IDS["data-winn3"],
                "source_role": DEPLOY.EXCHANGE_SOURCE_ROLE,
                "target_boot_id": self.ROLE_BOOT_IDS["control"],
                "target_instance": "proof-control-a1",
                "target_instance_id": self.ROLE_IDS["control"],
                "target_role": DEPLOY.EXCHANGE_TARGET_ROLE,
                "ttl_seconds": 300,
            }
        else:
            receipt = {
                "action": action,
                "contract": DEPLOY.EXCHANGE_CONTRACT,
                "instance": instance,
                "kind": "winsvpn.gcp_proof.authenticated_key_exchange_event.v1",
                "role": role,
                "schema_version": 1,
            }
        return {
            "action": action,
            "contract": DEPLOY.EXCHANGE_CONTRACT,
            "kind": DEPLOY.KIND_EXCHANGE_RESPONSE,
            "public": None,
            "receipt": receipt,
            "schema_version": 1,
            "secret": None,
        }

    def _exchange_helper(self, remote: list[str]) -> Any:
        if remote[7] != DEPLOY.REMOTE_HELPER_SHA256:
            raise AssertionError("remote helper digest was not fixed")
        stdin_mode = remote[8]
        stdout_mode = remote[9]
        if stdin_mode == "pipe" or stdout_mode == "pipe-consumer":
            raise AssertionError("secret exchange hops must use the authenticated SSH pipe")
        if stdin_mode.startswith("b64:"):
            decoded = base64.b64decode(stdin_mode[4:].encode("ascii"), validate=True)
            if DEPLOY.SECRET_RE.search(decoded):
                raise AssertionError("peer stdin contained secret material")
        helper_argv = [
            "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I",
            remote[6], *remote[10:],
        ]
        options = self.options(helper_argv)
        action = str(options["action"])
        role = str(options["role"])
        if action == "exchange-status":
            sealed = self.already_sealed or (
                "exchange-control-seal" in {item[1] for item in self.exchange_helper_actions}
                and len(self.pipe_calls) >= 2
            )
            started = bool(self.exchange_helper_actions) or bool(self.pipe_calls)
            if self.partial_exchange and not started:
                payload = self._exchange_envelope(action, role, sealed=False)
                payload["receipt"]["completed_actions"] = ["exchange-identity"]
                payload["receipt"]["sealed"] = False
                return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0)
            if not sealed and not started:
                payload = {
                    "kind": DEPLOY.KIND_RESPONSE,
                    "marker_updated": False,
                    "ok": False,
                    "refusal": "key exchange directory is unsafe",
                    "schema_version": 1,
                }
                return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 2)
            return DEPLOY.RunResult(
                DEPLOY.canonical_bytes(self._exchange_envelope(action, role, sealed=sealed)),
                b"",
                0,
            )
        self.exchange_helper_actions.append((role, action))
        return DEPLOY.RunResult(
            DEPLOY.canonical_bytes(self._exchange_envelope(action, role)),
            b"",
            0,
        )

    def run_ssh_pipe(
        self,
        producer_argv: Sequence[str],
        consumer_argv: Sequence[str],
        *,
        timeout_seconds: int,
        consumer_response_validator: Any = None,
    ) -> Any:
        del timeout_seconds
        if consumer_response_validator is not DEPLOY.gcloud_custody.validate_ssh_pipe_consumer_response:
            raise AssertionError("SSH pipe validator was omitted or substituted")
        DEPLOY.gcloud_custody.validate_fixed_gcloud_ssh_argv(producer_argv)
        DEPLOY.gcloud_custody.validate_fixed_gcloud_ssh_argv(consumer_argv)
        producer = list(producer_argv)
        consumer = list(consumer_argv)
        for argv in (producer, consumer):
            for token in argv:
                if DEPLOY.SECRET_RE.search(token.encode("ascii", "replace")):
                    raise AssertionError("SSH pipe argv contained secret material")
        producer_command = next(
            item.removeprefix("--command=") for item in producer if item.startswith("--command=")
        )
        consumer_command = next(
            item.removeprefix("--command=") for item in consumer if item.startswith("--command=")
        )
        producer_remote = shlex.split(producer_command)
        consumer_remote = shlex.split(consumer_command)
        public_producer = producer_remote[:6] == [
            "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
            DEPLOY.REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP,
        ]
        if not public_producer:
            if producer_remote[:6] != [
                "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
                DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
            ]:
                raise AssertionError("SSH pipe producer was not the reviewed exchange bootstrap")
            producer_options = self.options(
                ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", producer_remote[6], *producer_remote[10:]]
            )
            if producer_options["action"] != "exchange-data-emit" or producer_remote[8] != "none":
                raise AssertionError("SSH pipe producer was not exchange-data-emit")
        if consumer_remote[:6] != [
            "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c",
            DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP,
        ]:
            raise AssertionError("SSH pipe consumer was not the reviewed exchange bootstrap")
        if consumer_remote[8] != "pipe" or consumer_remote[9] != "pipe-consumer":
            raise AssertionError("SSH pipe consumer stdin/stdout modes were not pipe-bound")
        consumer_options = self.options(
            ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", consumer_remote[6], *consumer_remote[10:]]
        )
        expected_consumer = (
            "exchange-data-consume" if public_producer else "exchange-control-import"
        )
        if consumer_options["action"] != expected_consumer:
            raise AssertionError("SSH pipe consumer action was not the reviewed hop")
        self.pipe_calls.append({"producer": producer, "consumer": consumer})
        digest = DEPLOY.sha256_bytes(b"fixture-ssh-pipe-receipt")
        payload = {
            "contract": DEPLOY.SSH_PIPE_RESPONSE_CONTRACT,
            "payload_sha256": digest,
            "schema_version": 1,
            "status": "ok",
        }
        return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0)

    def run(self, argv: list[str], *, timeout_seconds: int) -> Any:
        del timeout_seconds
        if argv == ["gcloud", "version", "--format=json"]:
            if self.mutate_before_preflight is not None:
                self.mutate_before_preflight()
            self.version_calls.append(list(argv))
            return DEPLOY.RunResult(b'{"Google Cloud SDK":"582.0.0"}\n', b"", 0)
        self.calls.append(list(argv))
        if argv[:4] == ["gcloud", "compute", "instances", "describe"]:
            return self._describe(argv)
        if argv[:4] == ["gcloud", "compute", "firewall-rules", "describe"]:
            return self._describe_resource("firewall", argv[4])
        if argv[:5] == ["gcloud", "compute", "networks", "subnets", "describe"]:
            region = next(item.removeprefix("--region=") for item in argv if item.startswith("--region="))
            return self._describe_resource("subnet", argv[5], region)
        if argv[:4] == ["gcloud", "compute", "networks", "describe"]:
            return self._describe_resource("network", argv[4])
        if argv[:4] == ["gcloud", "compute", "instances", "update"]:
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "instances", "delete"]:
            name = argv[4]
            role = next(
                item["role"] for item in self.fixture.fleet["instances"] if item["name"] == name
            ) if self.fixture else ""
            if role in self.fail_delete_roles:
                return DEPLOY.RunResult(b"", b"delete failed", 1)
            self.deleted_instances.append(name)
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "firewall-rules", "delete"]:
            self.deleted_resources.append(argv[4])
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:5] == ["gcloud", "compute", "networks", "subnets", "delete"]:
            self.deleted_resources.append(argv[5])
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:4] == ["gcloud", "compute", "networks", "delete"]:
            self.deleted_resources.append(argv[4])
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:3] == ["gcloud", "compute", "scp"]:
            if self.transfer_failure:
                return DEPLOY.RunResult(b"", b"authorization=secret-value", 9)
            return DEPLOY.RunResult(b"", b"", 0)
        if argv[:3] != ["gcloud", "compute", "ssh"]:
            raise AssertionError(f"unexpected non-gcloud command: {argv!r}")
        command = next(item.removeprefix("--command=") for item in argv if item.startswith("--command="))
        remote = shlex.split(command)
        if remote[:6] == ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_ROLLBACK_BOOTSTRAP]:
            return self._rollback(remote)
        if remote[:6] == ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_DEPLOYMENT_OBSERVATION_BOOTSTRAP]:
            return self._deployment_observation(remote)
        if remote[:6] == ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_RUNTIME_PROBE_BOOTSTRAP]:
            return self._runtime_probe(remote)
        if remote[:6] == ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_EXCHANGE_PUBLIC_BOOTSTRAP]:
            raise AssertionError("client.pub producer must use the authenticated SSH pipe")
        if remote[:6] == ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_EXCHANGE_BOOTSTRAP]:
            return self._exchange_helper(remote)
        if remote[:6] != ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", "-c", DEPLOY.REMOTE_HELPER_BOOTSTRAP]:
            raise AssertionError("remote helper argv was not fixed")
        if not remote[6].startswith("/tmp/winsvpn-proof-") or not remote[6].endswith("-remote.py"):
            raise AssertionError("remote helper path was not fixed")
        if remote[7] != DEPLOY.REMOTE_HELPER_SHA256:
            raise AssertionError("remote helper digest was not fixed")
        remote = ["/usr/bin/sudo", "--non-interactive", "/usr/bin/python3", "-I", remote[6], *remote[8:]]
        options = self.options(remote)
        if options["action"] == "finalize":
            role = str(options["role"])
            role_steps = [index for index, item in enumerate(DEPLOY.EXPECTED_STEPS) if item[0] == role]
            marker = {
                "apply_sha256": options["apply-sha256"],
                "candidate_id": self.candidate_id,
                "completed_step_indices": role_steps,
                "deployment_manifest_sha256": options["manifest-sha256"],
                "fleet_record_chain_sha256": options["previous-record-sha256"],
                "fleet_completed_step_indices": list(range(8)),
                "fleet_id": options["fleet-id"],
                "instance": options["instance"],
                "kind": DEPLOY.KIND_MARKER,
                "plan_sha256": options["plan-sha256"],
                "role": role,
                "runtime": {"awg": {}, "router": {}, "winn": {}, "xray": {}},
                "schema_version": 1,
                "updated_utc": "2026-08-23T12:20:00Z",
            }
            payload = {"kind": DEPLOY.KIND_RESPONSE, "marker": marker, "marker_updated": True, "ok": True, "schema_version": 1}
            return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0)
        step = int(str(options["step-index"]))
        exit_code = self.fail_exit_code if self.fail_step == step else 0
        stdout = b"api_key=top-secret" if self.secret_step == step else b"step output"
        record: dict[str, Any] = {
            "apply_sha256": options["apply-sha256"],
            "ended_utc": "2026-08-23T12:10:01Z",
            "exit_code": exit_code,
            "flag": options["flag"],
            "fleet_id": options["fleet-id"],
            "instance": options["instance"],
            "kind": DEPLOY.KIND_RECORD,
            "manifest_sha256": options["manifest-sha256"],
            "plan_sha256": options["plan-sha256"],
            "previous_sha256": options["previous-record-sha256"],
            "role": options["role"],
            "schema_version": 1,
            "script": options["script"],
            "script_ref": {
                "bytes": int(str(options["script-bytes"])),
                "mode": int(str(options["script-mode"])),
                "sha256": options["script-sha256"],
            },
            "started_utc": "2026-08-23T12:10:00Z",
            "stderr": capture(b"failure" if exit_code else b""),
            "stdout": capture(stdout),
            "step_index": step,
        }
        record["record_sha256"] = DEPLOY._record_digest(record)
        payload = {
            "kind": DEPLOY.KIND_RESPONSE, "marker_updated": exit_code == 0,
            "ok": exit_code == 0, "record": record, "schema_version": 1,
        }
        if self.mutate_after_step is not None and self.mutate_after_step[0] == step:
            self.mutate_after_step[1]()
        transport_exit = (
            self.fail_transport_exit_code
            if exit_code and self.fail_transport_exit_code is not None
            else exit_code
        )
        return DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", transport_exit)


class ExecutorTests(unittest.TestCase):
    def test_gcloud_581_runtime_version_is_accepted(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = DEPLOY.RunResult(
            b'{"Google Cloud SDK":"582.0.0"}\n', b"", 0
        )
        self.assertEqual(DEPLOY.verify_gcloud_version(runner, "gcloud"), "582.0.0")
        runner.run.assert_called_once_with(
            ["gcloud", "version", "--format=json"], timeout_seconds=30
        )

    def test_wrong_gcloud_runtime_version_is_refused(self) -> None:
        runner = mock.Mock()
        runner.run.return_value = DEPLOY.RunResult(
            b'{"Google Cloud SDK":"580.0.0"}\n', b"", 0
        )
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "version mismatch"):
            DEPLOY.verify_gcloud_version(runner, "/opt/google/bin/gcloud")

    def make(self) -> tuple[tempfile.TemporaryDirectory[str], Fixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Fixture(Path(temporary.name))

    def execute(self, fixture: Fixture, runner: FakeRunner, **kwargs: Any) -> dict[str, Any]:
        runner.candidate_id = fixture.manifest["candidate_id"]
        runner.fixture = fixture
        with fixture.context_patch():
            receipt = DEPLOY.execute(
                fixture.repo, fixture.plan_path, fixture.apply_path,
                fixture.manifest_path, fixture.output,
                confirm_live_deployment=kwargs.get("confirm_live_deployment", True),
                confirm_cleanup=kwargs.get("confirm_cleanup", False),
                runner=runner,
            )
        self.assert_receipt_schema(receipt)
        return receipt

    def assert_receipt_schema(self, receipt: Mapping[str, Any]) -> None:
        self.assertEqual(set(receipt), DEPLOY.EXECUTION_KEYS)
        self.assertEqual(receipt["kind"], DEPLOY.KIND_EXECUTION)
        self.assertEqual(receipt["schema_version"], DEPLOY.EXECUTION_SCHEMA_VERSION)
        self.assertEqual(set(receipt["cleanup"]), DEPLOY.CLEANUP_KEYS)
        self.assertEqual(set(receipt["cleanup"]["resources"]), DEPLOY.CLEANUP_RESOURCES_KEYS)
        self.assertEqual(set(receipt["preflight"]), DEPLOY.PREFLIGHT_KEYS)
        self.assertIs(receipt["cleanup"]["acceptance_receipt_required"], False)
        consumed = DEPLOY.consume_execution_receipt(receipt)
        self.assertIs(consumed, receipt)

    def write_credential(self, root: Path, project: str) -> Any:
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
            "client_email": "proof@winsvpn-proof-lab.iam.gserviceaccount.com",
            "client_id": "1234567890",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
        path.write_bytes(json.dumps(payload, sort_keys=True).encode("ascii"))
        os.chmod(path, 0o400)
        return DEPLOY.gcloud_custody.GcloudCredentialInput(
            kind=DEPLOY.gcloud_custody.SERVICE_ACCOUNT_KIND,
            path=path,
            expected_account="proof@winsvpn-proof-lab.iam.gserviceaccount.com",
            expected_project=project,
        )

    @staticmethod
    def compute_kind(call: list[str]) -> str:
        if call[2:4] == ["instances", "describe"]:
            return "describe"
        if call[2:4] == ["firewall-rules", "describe"]:
            return "describe-firewall"
        if call[2:5] == ["networks", "subnets", "describe"]:
            return "describe-subnet"
        if call[2:4] == ["networks", "describe"]:
            return "describe-network"
        if call[2] == "scp":
            return "scp"
        if call[2] == "ssh":
            return "ssh"
        if call[2:4] == ["firewall-rules", "delete"]:
            return "delete-firewall"
        if call[2:5] == ["networks", "subnets", "delete"]:
            return "delete-subnet"
        if call[2:4] == ["networks", "delete"]:
            return "delete-network"
        return call[2]

    PREFLIGHT_KINDS = (
        ["describe"] * 3
        + ["describe-firewall"] * 4
        + ["describe-subnet"] * 3
        + ["describe-network"]
    )

    def test_success_uses_only_fixed_mocked_gcloud_vectors_and_chains_all_steps(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertFalse(DEPLOY.gcloud_custody.runner_may_emit_production_pass(runner))
        self.assertEqual(len(receipt["records"]), 8)
        self.assertEqual(set(receipt["markers"]), {"control", "data-winn3", "data-cover"})
        self.assertEqual(set(receipt["preflight"]["instances"]), {"control", "data-winn3", "data-cover"})
        self.assertEqual(len(receipt["preflight"]["firewalls"]), 4)
        self.assertEqual(len(receipt["preflight"]["subnets"]), 3)
        self.assertEqual(receipt["preflight"]["network"]["type"], "network")
        self.assertEqual(receipt["cleanup"]["status"], "not_required")
        self.assertEqual(receipt["failure"], {})
        self.assertEqual(receipt["candidate_id"], fixture.manifest["candidate_id"])
        kinds = [self.compute_kind(call) for call in runner.calls]
        self.assertEqual(kinds[:14], self.PREFLIGHT_KINDS + ["scp"] * 3)
        self.assertEqual(len(runner.calls), 40)
        self.assertEqual(len(runner.pipe_calls), 2)
        self.assertEqual(runner.version_calls, [["gcloud", "version", "--format=json"]])
        self.assertTrue(all(call[:2] == ["gcloud", "compute"] for call in runner.calls))
        self.assertEqual([call[2] for call in runner.calls[:3]], ["instances"] * 3)
        previous = DEPLOY.ZERO_SHA256
        for index, record in enumerate(receipt["records"]):
            self.assertEqual(record["step_index"], index)
            self.assertEqual(record["previous_sha256"], previous)
            previous = record["record_sha256"]
        self.assertEqual(receipt["record_chain_sha256"], previous)
        self.assertEqual(stat.S_IMODE(fixture.output.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(fixture.output.with_name(fixture.output.name + ".sha256").stat().st_mode), 0o400)

    def test_missing_gce_identity_returns_blocked_receipt(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.missing_gce_identity = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"]["reason"], DEPLOY.OWNER_CLOUD_EVIDENCE_BLOCKED)
        self.assertEqual(receipt["records"], [])
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(runner.exchange_helper_actions, [])
        self.assertNotEqual(receipt.get("status"), "passed")

    def test_already_sealed_exchange_skips_secret_hops(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.already_sealed = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"], {})
        self.assertEqual(len(receipt["records"]), 8)
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(runner.exchange_helper_actions, [])
        self.assertEqual(set(receipt["markers"]), {"control", "data-winn3", "data-cover"})

    def test_already_complete_and_sealed_rerun_is_idempotent(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.already_complete = True
        runner.already_sealed = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        self.assertEqual(receipt["failure"], {})
        self.assertEqual(receipt["records"], [])
        self.assertEqual(set(receipt["markers"]), {"control", "data-winn3", "data-cover"})
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(runner.exchange_helper_actions, [])
        commands = [
            shlex.split(next(token.removeprefix("--command=") for token in call if token.startswith("--command=")))
            for call in runner.calls
            if call[2:3] == ["ssh"]
        ]
        self.assertFalse(
            any(
                command[:6] == [
                    "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3",
                    "-I", "-c", DEPLOY.REMOTE_HELPER_BOOTSTRAP,
                ]
                and "--action" in command
                and command[command.index("--action") + 1] == "step"
                for command in commands
            )
        )

    def test_partial_exchange_is_refused_before_secret_hops(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.partial_exchange = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("partial authenticated key exchange v1", receipt["failure"]["reason"])
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(runner.exchange_helper_actions, [])
        self.assertEqual(receipt["markers"], {})
        self.assertNotEqual(receipt.get("status"), "passed")

    def test_probe_instance_id_must_match_authenticated_describe(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.probe_id_overrides["control"] = "9999"
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("numeric instance id", receipt["failure"]["reason"])
        self.assertEqual(runner.pipe_calls, [])
        self.assertEqual(receipt["records"], [])
        self.assertNotEqual(receipt.get("status"), "passed")

    def test_control_observation_is_exact_manifest_bound_and_required(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        with fixture.context_patch():
            context = DEPLOY.load_context(
                fixture.repo,
                fixture.plan_path,
                fixture.apply_path,
                fixture.manifest_path,
            )
        spec = DEPLOY._control_deployment_observation_spec(context)
        self.assertEqual(spec["role"], "control")
        self.assertEqual(
            spec["socket"], "winsvpn-gcp-proof-attempt-broker.socket"
        )
        self.assertEqual(
            spec["service"], "winsvpn-gcp-proof-attempt-broker.service"
        )
        self.assertEqual(
            spec["client_units"],
            [item["name"] for item in fixture.manifest["attempt_broker"]["units"]],
        )
        observed_paths = {item["path"] for item in spec["files"]}
        self.assertTrue(
            {
                "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker",
                "/usr/local/libexec/winsvpn-gcp-proof-remote",
                "/usr/local/bin/winn3-probe",
                "/usr/local/bin/amneziawg-go",
                "/usr/local/bin/awg",
                "/usr/local/bin/xray",
                "/etc/winsvpn/role",
                "/var/lib/winsvpn-proof/fleet-binding.json",
                "/etc/winn/proof-client/awg0.conf",
                "/etc/winn/proof-client/winn3-probe.env",
                "/etc/winn/proof-client/xray-client.json",
                "/etc/winn/proof-client/xray-probe.env",
            }.issubset(observed_paths)
        )
        runner = FakeRunner()
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "blocked")
        commands = [
            shlex.split(next(token.removeprefix("--command=") for token in call if token.startswith("--command=")))
            for call in runner.calls
            if call[2:3] == ["ssh"]
        ]
        self.assertEqual(
            sum(
                command[:6] == [
                    "/usr/bin/sudo", "--non-interactive", "/usr/bin/python3",
                    "-I", "-c", DEPLOY.REMOTE_DEPLOYMENT_OBSERVATION_BOOTSTRAP,
                ]
                for command in commands
            ),
            1,
        )

    def test_control_observation_failure_or_inactive_socket_cannot_pass(self) -> None:
        for defect in ("transport", "socket", "service"):
            with self.subTest(defect=defect):
                temporary, fixture = self.make()
                try:
                    runner = FakeRunner()
                    runner.fail_deployment_observation = defect == "transport"
                    runner.inactive_observed_socket = defect == "socket"
                    runner.failed_observed_service = defect == "service"
                    receipt = self.execute(fixture, runner)
                    self.assertEqual(receipt["status"], "failed")
                    self.assertIn("observation", receipt["failure"]["reason"])
                    self.assertNotEqual(receipt.get("status"), "passed")
                finally:
                    temporary.cleanup()

    def test_control_rollback_allowlists_cover_attempt_broker_exactly(self) -> None:
        expected_units = {
            "winsvpn-gcp-proof-attempt-broker.socket",
            "winsvpn-gcp-proof-attempt-broker.service",
            "winsvpn-proof-winn3-probe.service",
            "winsvpn-proof-awg-client.service",
            "winsvpn-proof-xray-client.service",
            "winsvpn-proof-xray-probe.service",
        }
        self.assertTrue(expected_units.issubset(DEPLOY.ROLLBACK_SERVICES["control"]))
        self.assertTrue(expected_units.issubset(DEPLOY.ROLLBACK_RESIDUALS["control"]["units"]))
        self.assertIn(
            "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker",
            DEPLOY.ROLLBACK_RESIDUALS["control"]["binaries"],
        )
        self.assertIn(
            "/usr/local/libexec/winsvpn-gcp-proof-remote",
            DEPLOY.ROLLBACK_RESIDUALS["control"]["binaries"],
        )
        source = DEPLOY.REMOTE_ROLLBACK_BOOTSTRAP
        for value in expected_units:
            self.assertIn(value, source)
        for value in DEPLOY.ROLLBACK_RESIDUALS["control"]["binaries"]:
            self.assertIn(value, source)
        for value in DEPLOY.ROLLBACK_RESIDUALS["control"]["config"]:
            self.assertIn(value, source)
        self.assertIn('["systemctl","disable","--now",unit]', source)
        self.assertIn('["systemctl","disable","--now",timer]', source)
        self.assertIn('sorted(spec["config"]', source)
        self.assertIn('["iptables","-w","5","-t",table,"-D"]', source)
        self.assertIn('["userdel",user]', source)

    def test_rollback_parser_accepts_only_allowlisted_removed_config_and_timers(self) -> None:
        payload = {
            "errors": [],
            "fleet_id": "proof-fleet-20260823",
            "inspected": list(DEPLOY.ROLLBACK_RESIDUAL_CLASSES),
            "instance": "proof-control-a1",
            "kind": DEPLOY.KIND_ROLLBACK,
            "ok": True,
            "removed_files": [
                "/etc/winn",
                "/etc/systemd/system/wins-weekly-maintenance.timer",
            ],
            "residuals": {
                key: [] for key in DEPLOY.ROLLBACK_RESIDUAL_CLASSES
            },
            "role": "control",
            "schema_version": 1,
            "services_stopped": [],
            "state_removed": True,
        }
        result = DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0)
        parsed = DEPLOY._parse_rollback(
            result, "control", "proof-control-a1", "proof-fleet-20260823"
        )
        self.assertTrue(parsed["ok"])
        payload["removed_files"] = ["/etc/passwd"]
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "allowlist"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )

    def test_rollback_response_requires_complete_empty_residual_evidence(self) -> None:
        payload = {
            "errors": [],
            "fleet_id": "proof-fleet-20260823",
            "instance": "proof-control-a1",
            "kind": DEPLOY.KIND_ROLLBACK,
            "ok": True,
            "removed_files": [],
            "role": "control",
            "schema_version": 1,
            "services_stopped": [],
            "state_removed": True,
        }
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "schema"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )
        payload["inspected"] = list(DEPLOY.ROLLBACK_RESIDUAL_CLASSES)
        payload["residuals"] = {
            key: [] for key in DEPLOY.ROLLBACK_RESIDUAL_CLASSES
        }
        payload["ok"] = False
        payload["residuals"]["config"] = ["/etc/not-authorized"]
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "outside the exact role allowlist"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 1),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )
        payload["residuals"]["config"] = ["/etc/winsvpn/role"]
        payload["ok"] = True
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "claimed success"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 0),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )
        payload["residuals"]["config"] = []
        payload["ok"] = False
        payload["removed_files"] = ["/etc/not-authorized"]
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "removed-file"):
            DEPLOY._parse_rollback(
                DEPLOY.RunResult(DEPLOY.canonical_bytes(payload), b"", 1),
                "control",
                "proof-control-a1",
                "proof-fleet-20260823",
            )

    def test_preflight_rejects_can_ip_forward_role_mutations(self) -> None:
        for role, mutation in (
            ("control", True),
            ("data-winn3", False),
            ("data-cover", False),
            ("data-winn3", 1),
        ):
            with self.subTest(role=role, mutation=mutation):
                temporary, fixture = self.make()
                self.addCleanup(temporary.cleanup)
                runner = FakeRunner()
                runner.describe_overrides[role] = {"canIpForward": mutation}
                receipt = self.execute(fixture, runner)
                self.assertEqual(receipt["status"], "failed")
                self.assertIn("canIpForward", receipt["failure"]["reason"])
                self.assertFalse(any(call[2] == "scp" for call in runner.calls))

    def test_missing_confirmation_refuses_before_runner(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "confirm"):
            DEPLOY.execute(
                fixture.repo, fixture.plan_path, fixture.apply_path,
                fixture.manifest_path, fixture.output,
                confirm_live_deployment=False, runner=runner,
            )
        self.assertEqual(runner.calls, [])

    def test_cli_requires_confirmation_even_when_every_path_is_supplied(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        argv = [
            "--repo-root", str(fixture.repo), "--plan", str(fixture.plan_path),
            "--apply", str(fixture.apply_path), "--deployment-inputs", str(fixture.manifest_path),
            "--output", str(fixture.output),
        ]
        with mock.patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(DEPLOY.main(argv, runner=runner), 2)
        self.assertEqual(runner.calls, [])

    def test_nonzero_step_emits_only_failed_receipt_and_stops(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 3
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["markers"], {})
        self.assertEqual(receipt["failure"]["failed_step_index"], 3)
        self.assertEqual(len(receipt["records"]), 4)
        self.assertEqual(len(runner.calls), 24)
        kinds = [self.compute_kind(call) for call in runner.calls]
        self.assertEqual(kinds[:14], self.PREFLIGHT_KINDS + ["scp"] * 3)
        self.assertEqual(receipt["cleanup"]["status"], "passed")
        self.assertEqual(set(receipt["cleanup"]["remote"]), {"control", "data-winn3", "data-cover"})
        self.assertEqual(receipt["cleanup"]["resources"]["status"], "skipped")
        self.assertEqual(runner.deleted_instances, [])
        on_disk = json.loads(fixture.output.read_text("ascii"))
        self.assertEqual(on_disk["status"], "failed")
        self.assertNotEqual(on_disk.get("status"), "passed")

    def test_high_installer_exit_code_remains_a_failed_receipt_when_ssh_maps_it(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 2
        runner.fail_exit_code = 127
        runner.fail_transport_exit_code = 125
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["records"][-1]["exit_code"], 127)
        self.assertEqual(receipt["failure"]["failed_step_index"], 2)

    def test_transfer_failure_redacts_credentials_and_never_runs_ssh(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.transfer_failure = True
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(len(runner.calls), 13)
        kinds = [self.compute_kind(call) for call in runner.calls]
        self.assertEqual(kinds[:12], self.PREFLIGHT_KINDS + ["scp"])
        self.assertEqual(set(receipt["cleanup"]["remote"]), {"control"})
        decoded = base64.b64decode(receipt["failure"]["stderr"]["data"])
        self.assertNotIn(b"secret-value", decoded)
        self.assertIn(b"[REDACTED]", decoded)

    def test_manifest_mutation_between_steps_refuses_before_next_gcloud(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        def mutate() -> None:
            os.chmod(fixture.manifest_path, 0o600)
            fixture.manifest_path.write_bytes(fixture.manifest_path.read_bytes() + b" ")
        runner.mutate_after_step = (0, mutate)
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertRegex(receipt["failure"]["reason"], "immutable|sidecar|canonical")
        self.assertEqual(
            [self.compute_kind(call) for call in runner.calls][:14],
            self.PREFLIGHT_KINDS + ["scp"] * 3,
        )
        self.assertEqual(receipt["cleanup"]["status"], "passed")
        self.assertTrue(fixture.output.exists())

    def test_bundle_mutation_between_steps_is_detected_from_stable_bytes(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        def mutate() -> None:
            bundle = Path(next(call for call in runner.calls if call[2] == "scp")[3])
            bundle.write_bytes(bundle.read_bytes() + b"tamper")
        runner.mutate_after_step = (0, mutate)
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("bundle changed", receipt["failure"]["reason"])
        self.assertEqual(
            [self.compute_kind(call) for call in runner.calls][:14],
            self.PREFLIGHT_KINDS + ["scp"] * 3,
        )

    def test_staged_remote_helper_mutation_between_steps_is_detected(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        def mutate() -> None:
            helper = Path(next(call for call in runner.calls if call[2] == "scp")[4])
            os.chmod(helper, 0o700)
            helper.write_bytes(helper.read_bytes() + b"\n# tamper\n")
        runner.mutate_after_step = (0, mutate)
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("helper changed", receipt["failure"]["reason"])
        self.assertEqual(
            [self.compute_kind(call) for call in runner.calls][:14],
            self.PREFLIGHT_KINDS + ["scp"] * 3,
        )

    def test_credential_shaped_remote_capture_is_refused(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.secret_step = 0
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("redaction", receipt["failure"]["reason"])
        self.assertEqual(receipt["cleanup"]["status"], "passed")
        self.assertTrue(fixture.output.exists())

    def test_bundle_contains_exactly_manifest_members(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        with fixture.context_patch():
            context = DEPLOY.load_context(fixture.repo, fixture.plan_path, fixture.apply_path, fixture.manifest_path)
        bundle = fixture.root / "bundle.tar"
        digest = DEPLOY.build_bundle(context, bundle)
        DEPLOY.verify_bundle(context, bundle, digest)
        with tarfile.open(bundle, "r:") as archive:
            self.assertEqual(archive.getnames(), [item["path"] for item in fixture.inputs])
            self.assertTrue(all(member.isfile() and member.uid == 0 and member.gid == 0 for member in archive.getmembers()))

    def test_writable_or_stale_sidecars_are_rejected(self) -> None:
        for defect in ("writable", "stale"):
            with self.subTest(defect=defect):
                temporary, fixture = self.make()
                try:
                    sidecar = fixture.apply_path.with_name(fixture.apply_path.name + ".sha256")
                    os.chmod(sidecar, 0o600)
                    if defect == "stale":
                        sidecar.write_text("0" * 64 + "  apply.json\n", encoding="ascii")
                        os.chmod(sidecar, 0o400)
                    with fixture.context_patch(), self.assertRaises(DEPLOY.DeploymentRefused):
                        DEPLOY.load_context(fixture.repo, fixture.plan_path, fixture.apply_path, fixture.manifest_path)
                finally:
                    temporary.cleanup()

    def test_reordered_duplicate_skipped_wrong_role_and_caller_command_refuse(self) -> None:
        mutations = {
            "reordered": lambda values: values.__setitem__(slice(0, 2), [values[1], values[0]]),
            "duplicate": lambda values: values.__setitem__(1, copy.deepcopy(values[0])),
            "skipped": lambda values: values.pop(2),
            "wrong-role": lambda values: values[2].__setitem__("role", "control"),
            "caller-command": lambda values: values[0].__setitem__("argv", ["bash", "evil.sh"]),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                temporary, fixture = self.make()
                try:
                    changed_plan = copy.deepcopy(fixture.plan)
                    changed_apply = copy.deepcopy(fixture.apply)
                    mutation(changed_plan["installers"])
                    changed_apply["installers"] = copy.deepcopy(changed_plan["installers"])
                    fixture.rewrite(fixture.plan_path, changed_plan)
                    changed_apply["plan_sha256"] = DEPLOY.sha256_bytes(fixture.plan_path.read_bytes())
                    fixture.rewrite(fixture.apply_path, changed_apply)
                    with fixture.context_patch(), self.assertRaisesRegex(DEPLOY.DeploymentRefused, "installer"):
                        DEPLOY.load_context(fixture.repo, fixture.plan_path, fixture.apply_path, fixture.manifest_path)
                finally:
                    temporary.cleanup()

    def test_subprocess_runner_uses_shell_false(self) -> None:
        completed = subprocess.CompletedProcess(["gcloud"], 0, stdout=b"ok", stderr=b"")
        with mock.patch.object(DEPLOY.subprocess, "run", return_value=completed) as run:
            result = DEPLOY.SubprocessRunner().run(["gcloud", "version"], timeout_seconds=10)
        self.assertEqual(result.exit_code, 0)
        self.assertIs(run.call_args.kwargs["shell"], False)
        self.assertEqual(run.call_args.args[0], ["gcloud", "version"])

    def test_remote_bootstrap_executes_only_digest_bound_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            helper = Path(name) / "helper.py"
            helper.write_bytes(
                b"import sys\nprint(__file__)\nprint('|'.join(sys.argv[1:]))\n"
            )
            digest = DEPLOY.sha256_bytes(helper.read_bytes())
            valid = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    DEPLOY.REMOTE_HELPER_BOOTSTRAP,
                    str(helper),
                    digest,
                    "--fixed-argument",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr.decode("utf-8", "replace"))
            self.assertEqual(
                valid.stdout.decode("utf-8").splitlines(),
                [str(helper), "--fixed-argument"],
            )

            substituted = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    DEPLOY.REMOTE_HELPER_BOOTSTRAP,
                    str(helper),
                    "0" * 64,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(substituted.returncode, 0)
            self.assertNotIn(str(helper).encode("utf-8"), substituted.stdout)

    def test_remote_bootstrap_rejects_symlink_and_hardlink_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            helper = root / "helper.py"
            helper.write_bytes(b"raise SystemExit(0)\n")
            digest = DEPLOY.sha256_bytes(helper.read_bytes())
            for candidate in (root / "symlink.py", root / "hardlink.py"):
                if candidate.name == "symlink.py":
                    candidate.symlink_to(helper)
                else:
                    os.link(helper, candidate)
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-c",
                        DEPLOY.REMOTE_HELPER_BOOTSTRAP,
                        str(candidate),
                        digest,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, candidate.name)

    def test_stale_vm_is_refused_before_scp_and_is_not_deleted(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.describe_overrides["control"] = {"creationTimestamp": "2026-08-23T13:00:00Z"}
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertRegex(receipt["failure"]["reason"], "freshness|not newly created")
        self.assertFalse(any(call[2] == "scp" for call in runner.calls))
        self.assertEqual(runner.deleted_instances, [])
        self.assertEqual(receipt["cleanup"]["resources"]["status"], "skipped")

    def test_wrong_labels_and_creation_identity_are_refused(self) -> None:
        cases = {
            "labels": (
                {"labels": {"winsvpn-proof-fleet": "1", "winsvpn-proof-id": "other-fleet", "winsvpn-proof-role": "control"}},
                "labels",
            ),
            "creation-id": ({"id": 1001}, "creation id"),
            "machine": (
                {
                    "machineType": (
                        "https://www.googleapis.com/compute/v1/projects/"
                        "winsvpn-proof-lab/zones/us-east1-b/machineTypes/n2-standard-4"
                    )
                },
                "machine",
            ),
        }
        for label, (override, pattern) in cases.items():
            with self.subTest(label=label):
                temporary, fixture = self.make()
                self.addCleanup(temporary.cleanup)
                runner = FakeRunner()
                runner.describe_overrides["control"] = override
                receipt = self.execute(fixture, runner)
                self.assertEqual(receipt["status"], "failed")
                self.assertRegex(receipt["failure"]["reason"], pattern)
                self.assertFalse(any(call[2] == "scp" for call in runner.calls))
                self.assertEqual(runner.deleted_instances, [])

    def test_mutation_before_preflight_never_describes_or_copies(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        def mutate() -> None:
            os.chmod(fixture.manifest_path, 0o600)
            fixture.manifest_path.write_bytes(fixture.manifest_path.read_bytes() + b" ")
        runner.mutate_before_preflight = mutate
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "immutable|sidecar|canonical"):
            self.execute(fixture, runner)
        self.assertEqual(runner.calls, [])
        self.assertFalse(fixture.output.exists())

    def test_partial_scp_runs_bounded_remote_rollback_only_for_contacted_role(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.transfer_failure = True
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(set(receipt["cleanup"]["remote"]), {"control"})
        self.assertTrue(receipt["cleanup"]["remote"]["control"]["ok"])
        self.assertEqual(receipt["cleanup"]["authorized"], True)
        self.assertEqual(receipt["cleanup"]["resources"]["status"], "passed")
        self.assertEqual(
            runner.deleted_instances,
            ["proof-control-a1", "proof-winn3-a1", "proof-cover-a1"],
        )
        self.assertTrue(any(name.endswith("-net") for name in runner.deleted_resources))
        self.assertFalse(any("--filter" in token for call in runner.calls for token in call))

    def test_partial_ssh_and_service_rollback_failure_is_not_hidden(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 2
        runner.fail_rollback_roles.add("data-winn3")
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cleanup"]["status"], "failed")
        self.assertIs(receipt["cleanup"]["remote"]["data-winn3"]["ok"], False)
        self.assertNotEqual(receipt.get("status"), "passed")
        on_disk = json.loads(fixture.output.read_text("ascii"))
        self.assertEqual(on_disk["cleanup"]["status"], "failed")
        self.assertEqual(on_disk["status"], "failed")

    def test_cleanup_target_confusion_refuses_to_delete_the_substituted_vm(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 0
        runner.cleanup_identity_swap["control"] = {
            "id": "8888",
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                "winsvpn-proof-lab/zones/us-east1-b/instances/proof-control-a1"
            ),
        }
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cleanup"]["status"], "failed")
        self.assertNotIn("proof-control-a1", runner.deleted_instances)
        self.assertIn("proof-winn3-a1", runner.deleted_instances)
        self.assertIn("proof-cover-a1", runner.deleted_instances)
        confused = next(
            item for item in receipt["cleanup"]["resources"]["results"]
            if item.get("role") == "control" and item.get("action") == "describe"
        )
        self.assertIs(confused["ok"], False)
        self.assertIn("creation transaction", confused["error"])

    def test_duplicate_and_non_bool_describe_schemas_are_refused(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.describe_bytes["control"] = (
            b'{"creationTimestamp":"2026-08-24T18:00:00Z","deletionProtection":true,'
            b'"id":"1001","id":"1001","labels":{},"machineType":"x","metadata":{"items":[]},'
            b'"name":"proof-control-a1","selfLink":"x","status":"RUNNING","tags":{"items":[]},'
            b'"zone":"x"}\n'
        )
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("duplicate JSON key", receipt["failure"]["reason"])
        self.assertFalse(any(call[2] == "scp" for call in runner.calls))

        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.describe_overrides["control"] = {"deletionProtection": 1}
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("clean undeployed proof VM", receipt["failure"]["reason"])
        self.assertFalse(any(call[2] == "scp" for call in runner.calls))

    def test_truthy_cleanup_flag_does_not_authorize_resource_deletion(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 0
        runner.candidate_id = fixture.manifest["candidate_id"]
        runner.fixture = fixture
        with fixture.context_patch():
            receipt = DEPLOY.execute(
                fixture.repo, fixture.plan_path, fixture.apply_path,
                fixture.manifest_path, fixture.output,
                confirm_live_deployment=True, confirm_cleanup=1, runner=runner,
            )
        self.assertEqual(receipt["status"], "failed")
        self.assertIs(receipt["cleanup"]["authorized"], False)
        self.assertEqual(receipt["cleanup"]["resources"]["status"], "skipped")
        self.assertEqual(runner.deleted_instances, [])
        self.assert_receipt_schema(receipt)

    def test_command_injection_and_broad_delete_vectors_are_impossible(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        poisoned = copy.deepcopy(fixture.plan)
        poisoned["fleet"]["instances"][0]["name"] = "proof-control-a1;rm -rf /"
        fixture.rewrite(fixture.plan_path, poisoned)
        apply_doc = copy.deepcopy(fixture.apply)
        apply_doc["fleet"] = copy.deepcopy(poisoned["fleet"])
        apply_doc["plan_sha256"] = DEPLOY.sha256_bytes(fixture.plan_path.read_bytes())
        fixture.rewrite(fixture.apply_path, apply_doc)
        with fixture.context_patch(), self.assertRaisesRegex(DEPLOY.DeploymentRefused, "instance name"):
            DEPLOY.load_context(fixture.repo, fixture.plan_path, fixture.apply_path, fixture.manifest_path)

        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 0
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        joined = [" ".join(call) for call in runner.calls]
        self.assertTrue(all("--filter" not in item and "--regex" not in item for item in joined))
        self.assertTrue(
            all(
                "*" not in token
                for call in runner.calls
                for token in call
                if not token.startswith("--command=")
            )
        )
        self.assertFalse(any(token == "--all" or token.startswith("--all=") for call in runner.calls for token in call))
        delete_names = [call[4] for call in runner.calls if call[:4] == ["gcloud", "compute", "instances", "delete"]]
        self.assertEqual(delete_names, ["proof-control-a1", "proof-winn3-a1", "proof-cover-a1"])

    def test_cleanup_works_without_an_acceptance_receipt(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        self.assertFalse((fixture.state / "acceptance-receipt.json").exists())
        runner = FakeRunner()
        receipt = self.execute(
            fixture, runner, confirm_live_deployment=False, confirm_cleanup=True
        )
        self.assertEqual(receipt["status"], "blocked")
        self.assertIs(receipt["cleanup"]["acceptance_receipt_required"], False)
        self.assertEqual(receipt["cleanup"]["resources"]["status"], "passed")
        self.assertEqual(
            runner.deleted_instances,
            ["proof-control-a1", "proof-winn3-a1", "proof-cover-a1"],
        )
        kinds = [self.compute_kind(call) for call in runner.calls]
        self.assertEqual(kinds[:11], self.PREFLIGHT_KINDS)
        self.assertLess(kinds.index("describe-firewall"), kinds.index("delete-firewall"))
        self.assertLess(kinds.index("describe-subnet"), kinds.index("delete-subnet"))
        self.assertLess(kinds.index("describe-network"), kinds.index("delete-network"))
        self.assertFalse(any(call[2] == "scp" for call in runner.calls))

    def test_resource_delete_failure_keeps_a_strict_failed_receipt(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 0
        runner.fail_delete_roles.add("control")
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cleanup"]["status"], "failed")
        self.assertNotEqual(receipt["status"], "passed")
        self.assertNotIn("proof-control-a1", runner.deleted_instances)
        on_disk = json.loads(fixture.output.read_text("ascii"))
        self.assertEqual(on_disk["status"], "failed")
        self.assertEqual(on_disk["cleanup"]["status"], "failed")

    def test_rollback_bootstrap_refuses_wrong_state_root_without_touching_it(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            result = subprocess.run(
                [
                    sys.executable, "-I", "-c", DEPLOY.REMOTE_ROLLBACK_BOOTSTRAP,
                    "a" * 24, "control", "proof-control-a1", "proof-fleet-20260823",
                    f"/tmp/winsvpn-proof-{'a' * 24}.tar",
                    f"/tmp/winsvpn-proof-{'a' * 24}-remote.py",
                    f"/tmp/winsvpn-proof-{'a' * 24}-DEPLOYMENT_INPUTS.json",
                    f"/tmp/winsvpn-proof-{'a' * 24}-DEPLOYMENT_INPUTS.json.sha256",
                    str(Path(name) / "not-the-proof-state"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"rollback target identity is invalid", result.stderr)

    def test_partially_deployed_metadata_is_refused(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.describe_overrides["data-winn3"] = {
            "metadata": {
                "items": [
                    {"key": "enable-oslogin", "value": "TRUE"},
                    {"key": "winsvpn-proof-role", "value": "data-winn3"},
                    {"key": "ssh-keys", "value": "not-a-clean-vm"},
                ]
            }
        }
        receipt = self.execute(fixture, runner)
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("partial deployment", receipt["failure"]["reason"])
        self.assertFalse(any(call[2] == "scp" for call in runner.calls))

    def test_production_runner_missing_credential_is_exact_owner_blocker(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        with fixture.context_patch():
            with self.assertRaisesRegex(
                DEPLOY.DeploymentRefused,
                r"owner blocker:.*credential or workload identity",
            ):
                DEPLOY.execute(
                    fixture.repo, fixture.plan_path, fixture.apply_path,
                    fixture.manifest_path, fixture.output,
                    confirm_live_deployment=True,
                    runner=DEPLOY.SubprocessRunner(),
                )
        self.assertFalse(fixture.output.exists())

    def test_incomplete_credential_input_is_refused_before_custody_runner(self) -> None:
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "credential input is incomplete"):
            DEPLOY.load_credential_input(
                path=Path("/tmp/bound-credential.json"),
                kind="service_account",
                account=None,
                project="winsvpn-proof-lab",
            )

    def test_arbitrary_runner_cannot_produce_a_production_receipt(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)

        class Stranger:
            def run(self, argv, *, timeout_seconds):
                raise AssertionError("arbitrary runner executed")

        with fixture.context_patch():
            with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "arbitrary runner"):
                DEPLOY.execute(
                    fixture.repo, fixture.plan_path, fixture.apply_path,
                    fixture.manifest_path, fixture.output,
                    confirm_live_deployment=True,
                    runner=Stranger(),
                )
        self.assertFalse(fixture.output.exists())

    def test_credential_project_must_match_the_bound_plan_project(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        credential = self.write_credential(fixture.root, "winsproof123")
        runner = FakeRunner()
        with fixture.context_patch():
            with self.assertRaisesRegex(
                DEPLOY.DeploymentRefused,
                "does not match the bound plan project",
            ):
                DEPLOY.execute(
                    fixture.repo, fixture.plan_path, fixture.apply_path,
                    fixture.manifest_path, fixture.output,
                    confirm_live_deployment=True,
                    runner=runner,
                    credential=credential,
                )
        self.assertFalse(fixture.output.exists())

    def test_production_runner_wires_authenticated_credential_into_custody_runner(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        credential = self.write_credential(fixture.root, fixture.fleet["project"])
        captured: dict[str, Any] = {}

        def fake_bind(delegate: Any, gcloud_bin: Any, bound_credential: Any, *, pin_manifest: Any = None) -> Any:
            captured["credential"] = bound_credential
            captured["delegate"] = delegate
            captured["gcloud_bin"] = gcloud_bin
            inner = FakeRunner()
            inner.fixture = fixture
            inner.candidate_id = fixture.manifest["candidate_id"]
            inner.verified = SimpleNamespace(executable=gcloud_bin)
            return inner

        with fixture.context_patch(), mock.patch.object(
            DEPLOY.gcloud_custody, "bind_production_runner", side_effect=fake_bind
        ):
            receipt = DEPLOY.execute(
                fixture.repo, fixture.plan_path, fixture.apply_path,
                fixture.manifest_path, fixture.output,
                confirm_live_deployment=True,
                runner=DEPLOY.SubprocessRunner(),
                credential=credential,
            )
        self.assert_receipt_schema(receipt)
        self.assertEqual(receipt["status"], "blocked")
        self.assertIs(captured["credential"], credential)
        self.assertIsInstance(captured["delegate"], DEPLOY.SubprocessRunner)
        self.assertFalse(DEPLOY.gcloud_custody.runner_may_emit_production_pass(FakeRunner()))

    def test_replaced_firewall_and_fingerprint_are_not_deleted(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        runner.fail_step = 0
        firewall = f"pf-{fixture.fleet['fleet_id']}-admin-ssh"
        runner.cleanup_resource_swap[firewall] = {
            "id": "8888",
            "fingerprint": "REPLACED1=",
            "selfLink": (
                "https://www.googleapis.com/compute/v1/projects/"
                f"{fixture.fleet['project']}/global/firewalls/{firewall}"
            ),
        }
        receipt = self.execute(fixture, runner, confirm_cleanup=True)
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["cleanup"]["status"], "failed")
        self.assertNotIn(firewall, runner.deleted_resources)
        self.assertIn(f"pf-{fixture.fleet['fleet_id']}-winn3-in", runner.deleted_resources)
        self.assertIn(f"pf-{fixture.fleet['fleet_id']}-net", runner.deleted_resources)
        confused = next(
            item for item in receipt["cleanup"]["resources"]["results"]
            if item.get("name") == firewall and item.get("action") == "describe"
        )
        self.assertIs(confused["ok"], False)
        self.assertRegex(confused["error"], "creation transaction|fingerprint|labels|type")

    def test_integration_fixture_emits_real_fleet_consumable_receipt_without_hand_authored_fields(self) -> None:
        temporary, fixture = self.make()
        self.addCleanup(temporary.cleanup)
        runner = FakeRunner()
        receipt = self.execute(fixture, runner)
        on_disk = json.loads(fixture.output.read_text("ascii"))
        self.assertEqual(on_disk, receipt)
        consumed = DEPLOY.consume_execution_receipt(on_disk)
        self.assertIs(consumed, on_disk)
        self.assertEqual(consumed["candidate_id"], fixture.manifest["candidate_id"])
        self.assertEqual(consumed["deployment_inputs"], fixture.manifest_ref)
        self.assertEqual(consumed["client_release_binding"], fixture.client_binding_ref)
        self.assertEqual(len(consumed["records"]), 8)
        self.assertEqual(
            consumed["record_chain_sha256"], consumed["records"][-1]["record_sha256"]
        )
        self.assertEqual(set(consumed["cleanup"]), DEPLOY.CLEANUP_KEYS)
        self.assertEqual(set(consumed["preflight"]), DEPLOY.PREFLIGHT_KEYS)
        rewritten = dict(consumed)
        rewritten.pop("cleanup")
        with self.assertRaisesRegex(DEPLOY.DeploymentRefused, "schema is not exact"):
            DEPLOY.consume_execution_receipt(rewritten)
        self.assertEqual(set(consumed), DEPLOY.EXECUTION_KEYS)
        self.assertEqual(consumed["status"], "blocked")


class RemoteTests(unittest.TestCase):
    def test_remote_common_contract_rejects_alternate_marker_state_or_timeout(self) -> None:
        base = [
            "--action", "step", "--bundle", "/tmp/a", "--bundle-sha256", "a" * 64,
            "--manifest", "/tmp/b", "--manifest-sidecar", "/tmp/c",
            "--manifest-sha256", "b" * 64, "--helper-sha256", "c" * 64,
            "--plan-sha256", "d" * 64, "--apply-sha256", "e" * 64,
            "--fleet-id", "proof-fleet-20260823", "--role", "control",
            "--instance", "proof-control-a1", "--previous-record-sha256", "0" * 64,
        ]
        for extra in (
            ["--marker", "/tmp/marker"],
            ["--state-root", "/tmp/state"],
            ["--timeout-seconds", "3601"],
        ):
            args = REMOTE.parser().parse_args(base + extra)
            with self.subTest(extra=extra), mock.patch.object(REMOTE.os, "geteuid", return_value=0), self.assertRaises(REMOTE.RemoteInstallError):
                REMOTE._validate_common(args)

    def test_wrong_role_reordered_or_caller_authored_step_refuses_before_execution(self) -> None:
        namespace = mock.Mock(
            step_index=2, role="control", script=REMOTE.EXPECTED_STEPS[2][1],
            flag=REMOTE.EXPECTED_STEPS[2][2],
        )
        with mock.patch.object(REMOTE, "_validate_common"), self.assertRaisesRegex(REMOTE.RemoteInstallError, "caller-authored"):
            REMOTE.run_step(namespace)

    def test_bundle_extra_member_and_symlink_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            manifest = {
                "inputs": [{"bytes": 1, "class": "server", "mode": 0o755, "path": "server/a.sh", "sha256": REMOTE.sha256_bytes(b"x")}]
            }
            for kind in ("extra", "symlink"):
                bundle = root / f"{kind}.tar"
                with tarfile.open(bundle, "w") as archive:
                    item = tarfile.TarInfo("server/a.sh")
                    item.size, item.mode, item.uid, item.gid = 1, 0o755, 0, 0
                    if kind == "symlink":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "/etc/passwd"
                        item.size = 0
                        archive.addfile(item)
                    else:
                        archive.addfile(item, io.BytesIO(b"x"))
                        extra = tarfile.TarInfo("evil")
                        extra.size, extra.mode, extra.uid, extra.gid = 1, 0o600, 0, 0
                        archive.addfile(extra, io.BytesIO(b"y"))
                digest = REMOTE.sha256_bytes(bundle.read_bytes())
                with self.subTest(kind=kind), self.assertRaises(REMOTE.RemoteInstallError):
                    REMOTE.verify_bundle(bundle, digest, manifest)

    def test_existing_marker_rejects_symlink_nonroot_and_writable_modes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "marker.json"
            target.write_text("{}\n", encoding="ascii")
            os.chmod(target, 0o600)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unsafe"):
                REMOTE._validate_marker_file(target)
            target.unlink()
            real = root / "real"
            real.write_text("{}\n", encoding="ascii")
            target.symlink_to(real)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unsafe"):
                REMOTE._validate_marker_file(target)

    def test_capture_redacts_credentials_and_is_bounded(self) -> None:
        raw = b"password=hunter2\n" + b"x" * (REMOTE.MAX_CAPTURE_BYTES + 20)
        value = REMOTE._capture(raw)
        decoded = base64.b64decode(value["data"])
        self.assertNotIn(b"hunter2", decoded)
        self.assertIn(b"[REDACTED]", decoded)
        self.assertTrue(value["truncated"])
        self.assertLessEqual(value["bytes"], REMOTE.MAX_CAPTURE_BYTES)

    def test_remote_source_enforces_root_marker_and_fixed_subprocess_contract(self) -> None:
        source = (TOOLS / "gcp_proof_remote_install.py").read_text("utf-8")
        self.assertIn("os.geteuid() != 0", source)
        self.assertIn("info.st_uid != 0", source)
        self.assertIn("stat.S_IMODE(info.st_mode) != 0o400", source)
        self.assertIn("shell=False", source)
        self.assertNotIn("shell=True", source)
        self.assertGreaterEqual(len(REMOTE.EXPECTED_STEPS), 8)


class RealManifestContractTests(unittest.TestCase):
    def test_remote_deploy_and_fleet_step_contracts_are_exactly_equal(self) -> None:
        self.assertEqual(REMOTE.EXPECTED_STEPS, DEPLOY.EXPECTED_STEPS)
        self.assertEqual(DEPLOY.EXPECTED_STEPS, FLEET.expected_installer_triples())
        self.assertEqual(REMOTE.EXCHANGE_ACTIONS, DEPLOY.EXCHANGE_ACTIONS)
        self.assertEqual(REMOTE.OWNER_CLOUD_EVIDENCE_BLOCKED, DEPLOY.OWNER_CLOUD_EVIDENCE_BLOCKED)
        self.assertEqual(
            DEPLOY.REMOTE_HELPER_SHA256,
            DEPLOY.sha256_bytes((TOOLS / "gcp_proof_remote_install.py").read_bytes()),
        )

    def test_exact_real_manifest_fixture_loads_on_remote_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            fixture = Fixture(Path(name))
            producer = load_module(
                "gcp_deployment_inputs_deploy_contract", TOOLS / "gcp_deployment_inputs.py"
            )
            sidecar = fixture.manifest_path.with_name(fixture.manifest_path.name + ".sha256")
            loaded = REMOTE._load_manifest(
                fixture.manifest_path, sidecar, fixture.manifest_ref["sha256"]
            )
            self.assertEqual(set(loaded), REMOTE.MANIFEST_KEYS)
            self.assertEqual(set(loaded["gateway_artifact"]), producer.GATEWAY_ARTIFACT_KEYS)
            self.assertEqual(loaded["gateway_artifact"]["path"], fixture.gateway_artifact["path"])
            self.assertEqual(loaded["gateway_artifact"]["sha256"], fixture.gateway_artifact["sha256"])
            self.assertEqual(loaded["gateway_artifact"], fixture.gateway_artifact)


if __name__ == "__main__":
    unittest.main()
