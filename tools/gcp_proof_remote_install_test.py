#!/usr/bin/env python3
"""No-network tests for the GCP proof remote installer consumer contract."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from typing import Any
from unittest import mock


TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


REMOTE = load_module("gcp_proof_remote_install_contract", TOOLS / "gcp_proof_remote_install.py")
PRODUCER = load_module("gcp_deployment_inputs_producer_keys", TOOLS / "gcp_deployment_inputs.py")
# Slice S6: the real server/wins_winn3_gateway_install.sh is a tombstone. The
# data-winn3 role the GCP proof deploys is defined by the standalone installer,
# so the "real installer" contract below reads the frozen copy of it (deleted
# with the tombstone). INSTALLER_PATH stays the manifest path of the role step.
GATEWAY_INSTALLER_PATH = REPO / "server" / "testdata" / "winn3_gateway_install_retired" / "wins_winn3_gateway_install.sh.snapshot"
PROVISION_SCRIPT_PATH = TOOLS / "winn3_gateway_provision_keys.sh"
ARTIFACT_PATH = "winn_protocol_experimental/dist/winn3-gateway-linux-amd64"
PROBE_ARTIFACT_PATH = "winn_protocol_experimental/dist/winn3-probe-linux-amd64"
ECH_KEYGEN_ARTIFACT_PATH = "winn_protocol_experimental/dist/winn-ech-keygen-linux-amd64"
INSTALLER_PATH = "server/wins_winn3_gateway_install.sh"
DATA_INSTALLER_PATH = "server/wins_data_plane_setup_ONETOUCH.sh"
HELPER_PATH = "tools/gcp_proof_remote_action.py"
HELPER_BYTES = (
    b"#!/usr/bin/python3\n"
    b'RESPONSE_CONTRACT = "winsvpn-gcp-proof-remote-action-v1"\n'
    b'INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-remote"\n'
)
BROKER_PATH = "tools/gcp_proof_attempt_broker.py"
BROKER_BYTES = (
    b"#!/usr/bin/python3\n"
    b'ATTEMPT_REQUEST_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-request-v1"\n'
    b'ATTEMPT_SOCKET_PATH = "/run/winsvpn-proof/protocol-attempt.sock"\n'
    b'ROLE_FILE = "/etc/winsvpn/role"\n'
    b'FLEET_BINDING_PATH = "/var/lib/winsvpn-proof/fleet-binding.json"\n'
)
BROKER_SOCKET_BYTES = (
    b"[Socket]\nListenStream=/run/winsvpn-proof/protocol-attempt.sock\n"
    b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
)
BROKER_SERVICE_BYTES = (
    b"[Service]\nExecStart=/usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
    b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
)
BROKER_UNIT_BYTES = {
    "winsvpn-proof-winn3-probe.service": (
        b"[Service]\nExecStart=/usr/local/bin/winn3-probe -gw ${WINN3_PROOF_GW}\n"
        b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
    ),
    "winsvpn-proof-awg-client.service": (
        b"[Service]\nExecStart=/usr/local/bin/amneziawg-go -f awg0\n"
        b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
    ),
    "winsvpn-proof-xray-client.service": (
        b"[Service]\nExecStart=/usr/local/bin/xray run -c /etc/winn/proof-client/xray-client.json\n"
        b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
    ),
    "winsvpn-proof-xray-probe.service": (
        b"[Service]\nExecStart=/usr/bin/ping -n -c 2 -I xray0 ${XRAY_PROOF_PEER}\n"
        b"Documentation=file:///usr/local/libexec/winsvpn-gcp-proof-attempt-broker\n"
    ),
}
BROKER_CONFIG_BYTES = {
    "winn3-probe.env": (
        b"WINN3_PROOF_GW=192.0.2.10:443\n"
        b"WINN3_PROOF_GATEWAY_ID=proof-winn3-unprovisioned\n"
        + b"WINN3_PROOF_ED_PUB=" + b"a" * 64 + b"\n"
        + b"WINN3_PROOF_ML_PUB=" + b"b" * 3904 + b"\n"
    ),
    "awg0.conf": (
        b"[Interface]\nAddress = 10.10.0.2/32\n"
        b"[Peer]\nEndpoint = 192.0.2.20:51820\n"
    ),
    "xray-client.json": b'{"inbounds":[{"settings":{"name":"xray0"}}]}\n',
    "xray-probe.env": b"XRAY_PROOF_PEER=10.10.0.1\n",
}
CLIENT_RUNTIME_PATHS = {
    product: f".artifacts/gcp-proof/{product}-linux-amd64"
    for product in PRODUCER.CLIENT_RUNTIME_PRODUCTS
}


def finish_manifest(timestamp_free: dict[str, Any], created_utc: str = "2026-08-23T12:00:00Z") -> dict[str, Any]:
    return {
        **timestamp_free,
        "candidate_id": REMOTE.sha256_bytes(REMOTE.canonical_bytes(timestamp_free)),
        "created_utc": created_utc,
    }


def timestamp_free_of(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key not in {"candidate_id", "created_utc"}
    }


def input_record(path: str, data: bytes, mode: int, file_class: str) -> dict[str, Any]:
    return {
        "bytes": len(data),
        "class": file_class,
        "mode": mode,
        "path": path,
        "sha256": REMOTE.sha256_bytes(data),
    }


def sample_files() -> dict[str, bytes]:
    files = {
        INSTALLER_PATH: b"#!/bin/bash\n# real-contract placeholder bytes, not an installer fixture\n",
        DATA_INSTALLER_PATH: b"#!/bin/bash\n# data-plane contract placeholder bytes\n",
        ARTIFACT_PATH: b"\x7fELF-winn3-gateway-linux-amd64-bytes\n",
        PROBE_ARTIFACT_PATH: b"\x7fELF-winn3-probe-linux-amd64-bytes\n",
        ECH_KEYGEN_ARTIFACT_PATH: b"\x7fELF-winn-ech-keygen-linux-amd64-bytes\n",
        HELPER_PATH: HELPER_BYTES,
        BROKER_PATH: BROKER_BYTES,
        PRODUCER.ATTEMPT_BROKER_SOCKET_SOURCE: BROKER_SOCKET_BYTES,
        PRODUCER.ATTEMPT_BROKER_SERVICE_SOURCE: BROKER_SERVICE_BYTES,
    }
    for _relative, _install, name in PRODUCER.ATTEMPT_BROKER_UNITS:
        files[f"tools/gcp_proof_attempt_broker/{name}"] = BROKER_UNIT_BYTES[name]
    for relative, _install, name in PRODUCER.ATTEMPT_BROKER_CONFIGS:
        files[relative] = BROKER_CONFIG_BYTES[name]
    for product, path in CLIENT_RUNTIME_PATHS.items():
        files[path] = f"\x7fELF-{product}-linux-amd64-bytes\n".encode("ascii")
    return files


def sample_proof_artifact(
    artifact: dict[str, Any], product: str, **overrides: Any
) -> dict[str, Any]:
    payload = {
        "architecture": "amd64",
        "elf_class": 2,
        "elf_data": 1,
        "elf_machine": 62,
        "elf_type": 3,
        "entry": 4096,
        "os": "linux",
        "path": artifact["path"],
        "product": product,
        "runtime": "linux-amd64",
        "sha256": artifact["sha256"],
    }
    payload.update(overrides)
    return payload


def sample_gateway_artifact(artifact: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    return sample_proof_artifact(artifact, "winn3-gateway", **overrides)


def sample_client_runtime_artifact(
    artifact: dict[str, Any], product: str, **overrides: Any
) -> dict[str, Any]:
    index = list(PRODUCER.CLIENT_RUNTIME_PRODUCTS).index(product) + 1
    payload = {
        **sample_proof_artifact(artifact, product),
        "bytes": artifact["bytes"],
        "mode": artifact["mode"],
        "provenance": {
            "commit": str(index) * 40,
            "repository": f"https://github.com/winsvpn-proof/{product}",
            "source_sha256": str(index) * 64,
            "tag": f"v-proof-{index}",
        },
    }
    payload.update(overrides)
    return payload


def sample_helper_record(helper: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload = {
        "bytes": helper["bytes"],
        "contract": PRODUCER.REMOTE_ACTION_HELPER_CONTRACT,
        "install_path": PRODUCER.REMOTE_ACTION_HELPER_INSTALL_PATH,
        "mode": helper["mode"],
        "path": helper["path"],
        "required_roles": list(PRODUCER.REMOTE_ACTION_HELPER_REQUIRED_ROLES),
        "schema_version": 1,
        "sha256": helper["sha256"],
    }
    payload.update(overrides)
    return payload


def sample_member_record(
    item: dict[str, Any], install_path: str, name: str, **overrides: Any
) -> dict[str, Any]:
    payload = {
        "bytes": item["bytes"],
        "install_path": install_path,
        "mode": item["mode"],
        "name": name,
        "path": item["path"],
        "sha256": item["sha256"],
    }
    payload.update(overrides)
    return payload


def sample_attempt_broker_record(by_path: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    broker = by_path[BROKER_PATH]
    payload = {
        "bytes": broker["bytes"],
        "configs": [
            sample_member_record(by_path[relative], install_path, name)
            for relative, install_path, name in PRODUCER.ATTEMPT_BROKER_CONFIGS
        ],
        "contract": PRODUCER.ATTEMPT_BROKER_CONTRACT,
        "install_path": PRODUCER.ATTEMPT_BROKER_INSTALL_PATH,
        "mode": broker["mode"],
        "path": broker["path"],
        "required_roles": list(PRODUCER.ATTEMPT_BROKER_REQUIRED_ROLES),
        "schema_version": 1,
        "service": sample_member_record(
            by_path[PRODUCER.ATTEMPT_BROKER_SERVICE_SOURCE],
            PRODUCER.ATTEMPT_BROKER_SERVICE_INSTALL_PATH,
            "winsvpn-gcp-proof-attempt-broker.service",
        ),
        "sha256": broker["sha256"],
        "socket": sample_member_record(
            by_path[PRODUCER.ATTEMPT_BROKER_SOCKET_SOURCE],
            PRODUCER.ATTEMPT_BROKER_SOCKET_INSTALL_PATH,
            "winsvpn-gcp-proof-attempt-broker.socket",
        ),
        "units": [
            sample_member_record(by_path[relative], install_path, name)
            for relative, install_path, name in PRODUCER.ATTEMPT_BROKER_UNITS
        ],
    }
    payload.update(overrides)
    return payload


def sample_manifest(**overrides: Any) -> dict[str, Any]:
    files = sample_files()
    inputs = [
        input_record(INSTALLER_PATH, files[INSTALLER_PATH], 0o755, "server"),
        input_record(DATA_INSTALLER_PATH, files[DATA_INSTALLER_PATH], 0o755, "server"),
        input_record(ARTIFACT_PATH, files[ARTIFACT_PATH], 0o755, "artifact"),
        input_record(PROBE_ARTIFACT_PATH, files[PROBE_ARTIFACT_PATH], 0o755, "artifact"),
        input_record(
            ECH_KEYGEN_ARTIFACT_PATH,
            files[ECH_KEYGEN_ARTIFACT_PATH],
            0o755,
            "artifact",
        ),
        input_record(HELPER_PATH, files[HELPER_PATH], 0o755, "tool"),
        input_record(BROKER_PATH, files[BROKER_PATH], 0o755, "tool"),
        input_record(
            PRODUCER.ATTEMPT_BROKER_SOCKET_SOURCE,
            files[PRODUCER.ATTEMPT_BROKER_SOCKET_SOURCE],
            0o644,
            "tool",
        ),
        input_record(
            PRODUCER.ATTEMPT_BROKER_SERVICE_SOURCE,
            files[PRODUCER.ATTEMPT_BROKER_SERVICE_SOURCE],
            0o644,
            "tool",
        ),
    ]
    inputs.extend(
        input_record(relative, files[relative], 0o644, "tool")
        for relative, _install, _name in PRODUCER.ATTEMPT_BROKER_UNITS
    )
    inputs.extend(
        input_record(relative, files[relative], 0o644, "tool")
        for relative, _install, _name in PRODUCER.ATTEMPT_BROKER_CONFIGS
    )
    inputs.extend(
        input_record(CLIENT_RUNTIME_PATHS[product], files[CLIENT_RUNTIME_PATHS[product]], 0o755, "client-runtime")
        for product in PRODUCER.CLIENT_RUNTIME_PRODUCTS
    )
    inputs.sort(key=lambda item: item["path"])
    by_path = {item["path"]: item for item in inputs}
    artifact = by_path[ARTIFACT_PATH]
    probe_artifact = by_path[PROBE_ARTIFACT_PATH]
    ech_keygen_artifact = by_path[ECH_KEYGEN_ARTIFACT_PATH]
    helper = by_path[HELPER_PATH]
    client_runtime_artifacts = [
        sample_client_runtime_artifact(by_path[CLIENT_RUNTIME_PATHS[product]], product)
        for product in PRODUCER.CLIENT_RUNTIME_PRODUCTS
    ]
    installers = [
        {key: by_path[path][key] for key in ("bytes", "mode", "path", "sha256")}
        for path in (DATA_INSTALLER_PATH, INSTALLER_PATH)
    ]
    timestamp_free = {
        "closure_policy": PRODUCER.CLOSURE_POLICY,
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
                for item in client_runtime_artifacts
            },
            "router_base_image": {
                "digest": "sha256:" + "a" * 64,
                "reference": "python:3.14@sha256:" + "a" * 64,
            },
            "xray": {"version": "26.9.30"},
        },
        "client_runtime_artifacts": client_runtime_artifacts,
        "gateway_artifact": sample_gateway_artifact(artifact),
        "inputs": inputs,
        "installers": installers,
        "kind": PRODUCER.KIND,
        "publication_authorized": False,
        "proof_client_artifacts": [
            sample_gateway_artifact(artifact),
            sample_proof_artifact(probe_artifact, "winn3-probe"),
            sample_proof_artifact(ech_keygen_artifact, "winn-ech-keygen"),
        ],
        "attempt_broker": sample_attempt_broker_record(by_path),
        "remote_action_helper": sample_helper_record(helper),
        "schema_version": 1,
        "scope_roots": list(PRODUCER.SCOPE_ROOTS),
    }
    timestamp_free.update(overrides)
    return finish_manifest(timestamp_free)


def write_manifest(directory: Path, record: dict[str, Any]) -> tuple[Path, Path, str]:
    path = directory / "DEPLOYMENT_INPUTS.json"
    data = REMOTE.canonical_bytes(record)
    digest = REMOTE.sha256_bytes(data)
    path.write_bytes(data)
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_bytes(f"{digest}  {path.name}\n".encode("ascii"))
    return path, sidecar, digest


def write_extracted_tree(root: Path, record: dict[str, Any], files: dict[str, bytes]) -> None:
    for item in record["inputs"]:
        target = root.joinpath(*PurePosixPath(item["path"]).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[item["path"]])
        os.chmod(target, item["mode"])


def keygen_fixture_bytes() -> dict[str, bytes]:
    return {
        "static.key": b"aa" * 32,
        "static.pub": b"bb" * 32,
        "admission.key": b"cc" * 32,
        "client.key": b"dd" * 32,
        "client.pub": b"ee" * 32,
        "auth_ed25519.seed": b"11" * 64,
        "auth_ed25519.pub": b"22" * 32,
        "auth_mldsa65.seed": b"33" * 32,
        "auth_mldsa65.pub": b"44" * 1952,
    }


def write_keygen_output(directory: Path, files: dict[str, bytes]) -> None:
    for name, data in files.items():
        path = directory / name
        path.write_bytes(data)
        os.chmod(path, 0o600)


EXCHANGE_NOW = "2026-08-25T05:00:00Z"
PROOF_APPLY_SHA256 = "a1" * 32
PROOF_BUNDLE_SHA256 = "b2" * 32
PROOF_HELPER_SHA256 = "c3" * 32
PROOF_MANIFEST_SHA256 = "d4" * 32
PROOF_PLAN_SHA256 = "e5" * 32
PROOF_SOURCE_INSTANCE_ID = "1234567890123456789"
PROOF_TARGET_INSTANCE_ID = "9876543210987654321"
PROOF_SOURCE_BOOT_ID = "11111111-1111-4111-8111-111111111111"
PROOF_TARGET_BOOT_ID = "22222222-2222-4222-8222-222222222222"
FULL_BINDING_KEYS = (
    "apply_sha256",
    "bundle_sha256",
    "helper_sha256",
    "manifest_sha256",
    "plan_sha256",
    "source_instance_id",
    "target_instance_id",
    "source_boot_id",
    "target_boot_id",
)


def proof_binding(**overrides: Any) -> dict[str, str]:
    payload = {
        "fleet_id": "proof-fleet-20260823",
        "candidate_id": "0123456789abcdef" * 4,
        "source_role": "data-winn3",
        "source_instance": "proof-winn3-a1",
        "target_role": "control",
        "target_instance": "proof-control-a1",
        "inner_v4": "10.10.0.2",
        "apply_sha256": PROOF_APPLY_SHA256,
        "bundle_sha256": PROOF_BUNDLE_SHA256,
        "helper_sha256": PROOF_HELPER_SHA256,
        "manifest_sha256": PROOF_MANIFEST_SHA256,
        "plan_sha256": PROOF_PLAN_SHA256,
        "source_instance_id": PROOF_SOURCE_INSTANCE_ID,
        "target_instance_id": PROOF_TARGET_INSTANCE_ID,
        "source_boot_id": PROOF_SOURCE_BOOT_ID,
        "target_boot_id": PROOF_TARGET_BOOT_ID,
    }
    payload.update(overrides)
    return payload


HEX_FLEET = "123456789abc"
ATTEMPT_AWG_PRIVATE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
ATTEMPT_AWG_PEER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
ATTEMPT_XRAY_UUID = "550e8400-e29b-41d4-a716-446655440000"
ATTEMPT_CONFIG_NAMES = (
    "awg0.conf",
    "winn3-probe.env",
    "xray-client.json",
    "xray-probe.env",
)


def write_attempt_templates(proof_dir: Path) -> None:
    proof_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(proof_dir, 0o700)
    sources = {name: relative for relative, _install, name in PRODUCER.ATTEMPT_BROKER_CONFIGS}
    for name in ATTEMPT_CONFIG_NAMES:
        path = proof_dir / name
        path.write_bytes((REPO / sources[name]).read_bytes())
        os.chmod(path, 0o400)


def control_fleet_binding(fleet_id: str = HEX_FLEET) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": REMOTE.ATTEMPT_BROKER_FLEET_BINDING_CONTRACT,
        "project": "winsproof123",
        "fleet_id": fleet_id,
        "control": {"instance": "proof-control-a1", "zone": "us-east1-b"},
        "data-winn3": {"instance": "proof-winn3-a1", "zone": "us-central1-a"},
        "data-cover": {"instance": "proof-cover-a1", "zone": "us-east1-b"},
    }


def attempt_provision_document(binding_sha256: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "awg_endpoint": "10.240.0.20:51820",
        "awg_peer_public_key": ATTEMPT_AWG_PEER,
        "awg_private_key": ATTEMPT_AWG_PRIVATE,
        "binding_sha256": binding_sha256,
        "contract": REMOTE.ATTEMPT_PROVISION_CONTRACT,
        "fleet_id": HEX_FLEET,
        "kind": REMOTE.KIND_ATTEMPT_PROVISION,
        "schema_version": 1,
        "winn3_gateway": "10.240.0.10:443",
        "xray_address": "10.240.0.20",
        "xray_path": "/ws",
        "xray_port": 443,
        "xray_uuid": ATTEMPT_XRAY_UUID,
    }
    payload.update(overrides)
    return payload


class ProducerConsumerContractTests(unittest.TestCase):
    def test_consumer_key_sets_match_the_real_producer(self) -> None:
        self.assertEqual(REMOTE.GATEWAY_ARTIFACT_KEYS, PRODUCER.GATEWAY_ARTIFACT_KEYS)
        self.assertEqual(REMOTE.REMOTE_ACTION_HELPER_KEYS, PRODUCER.REMOTE_ACTION_HELPER_KEYS)
        self.assertEqual(REMOTE.REMOTE_ACTION_HELPER_PATH, PRODUCER.REMOTE_ACTION_HELPER_PATH)
        self.assertEqual(REMOTE.REMOTE_ACTION_HELPER_CONTRACT, PRODUCER.REMOTE_ACTION_HELPER_CONTRACT)
        self.assertEqual(
            REMOTE.REMOTE_ACTION_HELPER_INSTALL_PATH, PRODUCER.REMOTE_ACTION_HELPER_INSTALL_PATH
        )
        self.assertEqual(
            REMOTE.REMOTE_ACTION_HELPER_REQUIRED_ROLES, PRODUCER.REMOTE_ACTION_HELPER_REQUIRED_ROLES
        )
        self.assertEqual(REMOTE.ATTEMPT_BROKER_KEYS, PRODUCER.ATTEMPT_BROKER_KEYS)
        self.assertEqual(REMOTE.ATTEMPT_BROKER_PATH, PRODUCER.ATTEMPT_BROKER_PATH)
        self.assertEqual(REMOTE.ATTEMPT_BROKER_CONTRACT, PRODUCER.ATTEMPT_BROKER_CONTRACT)
        self.assertEqual(REMOTE.ATTEMPT_BROKER_INSTALL_PATH, PRODUCER.ATTEMPT_BROKER_INSTALL_PATH)
        self.assertEqual(
            REMOTE.ATTEMPT_BROKER_REQUIRED_ROLES, PRODUCER.ATTEMPT_BROKER_REQUIRED_ROLES
        )
        self.assertEqual(REMOTE.ATTEMPT_BROKER_UNITS, PRODUCER.ATTEMPT_BROKER_UNITS)
        self.assertEqual(REMOTE.ATTEMPT_BROKER_CONFIGS, PRODUCER.ATTEMPT_BROKER_CONFIGS)

    def test_awg_source_template_is_key_free_and_keyed_templates_are_refused(self) -> None:
        sources = {name: relative for relative, _install, name in PRODUCER.ATTEMPT_BROKER_CONFIGS}
        self.assertEqual(sources["awg0.conf"], "tools/gcp_proof_attempt_broker/awg0.conf.example")
        self.assertFalse((TOOLS / "gcp_proof_attempt_broker" / "awg0.conf").exists())
        template = (REPO / sources["awg0.conf"]).read_bytes()
        self.assertNotIn(b"privatekey", template.lower())
        self.assertNotIn(b"presharedkey", template.lower())
        REMOTE._require_attempt_config_bytes(template, "awg0.conf")
        PRODUCER._require_attempt_config(SimpleNamespace(data=template), "awg0.conf")
        keyed = template.replace(
            b"[Peer]\n", f"PrivateKey = {ATTEMPT_AWG_PRIVATE}\n[Peer]\n".encode("ascii")
        )
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "carries a key"):
            REMOTE._require_attempt_config_bytes(keyed, "awg0.conf")
        with self.assertRaisesRegex(PRODUCER.DeploymentInputsError, "carries a key"):
            PRODUCER._require_attempt_config(SimpleNamespace(data=keyed), "awg0.conf")
        # R22 Y3-11: a key-shaped value under another name is refused too.
        for field in ("Secret", "Key", "PeerSecret"):
            renamed = template.replace(
                b"[Peer]\n", f"{field} = {ATTEMPT_AWG_PRIVATE}\n[Peer]\n".encode("ascii")
            )
            with self.subTest(field=field):
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "carries a key"):
                    REMOTE._require_attempt_config_bytes(renamed, "awg0.conf")
                with self.assertRaisesRegex(PRODUCER.DeploymentInputsError, "carries a key"):
                    PRODUCER._require_attempt_config(SimpleNamespace(data=renamed), "awg0.conf")

    def test_awg_client_conf_missing_key_beside_an_extra_key_is_unprovisioned(self) -> None:
        # R22 Y3-11: the rendered config always carries PersistentKeepalive, so
        # a strict-subset test never fired and a missing key became KeyError.
        valid = REMOTE._render_awg_client_conf(
            private_key=ATTEMPT_AWG_PRIVATE,
            peer_public_key=ATTEMPT_AWG_PEER,
            endpoint="10.240.0.20:51820",
        )
        self.assertIn("Peer.PersistentKeepalive", REMOTE._parse_awg_client_conf(valid))
        for line in (
            b"AllowedIPs = 0.0.0.0/0\n",
            b"Endpoint = 10.240.0.20:51820\n",
            f"PublicKey = {ATTEMPT_AWG_PEER}\n".encode("ascii"),
            f"PrivateKey = {ATTEMPT_AWG_PRIVATE}\n".encode("ascii"),
        ):
            with self.subTest(missing=line.split(b" = ")[0].decode("ascii")):
                self.assertIn(line, valid)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unprovisioned"):
                    REMOTE._parse_awg_client_conf(valid.replace(line, b""))
        self.assertEqual(
            REMOTE.REMOTE_ACTION_HELPER_IDENTITY_KEYS,
            {
                "bytes",
                "candidate_id",
                "contract",
                "fleet_id",
                "instance",
                "kind",
                "mode",
                "path",
                "required_roles",
                "role",
                "schema_version",
                "sha256",
                "source_path",
                "st_dev",
                "st_ino",
            },
        )
        self.assertEqual(REMOTE.KIND_MANIFEST, PRODUCER.KIND)
        self.assertEqual(REMOTE.CLOSURE_POLICY, PRODUCER.CLOSURE_POLICY)
        self.assertEqual(tuple(REMOTE.SCOPE_ROOTS), tuple(PRODUCER.SCOPE_ROOTS))
        self.assertEqual(REMOTE.GATEWAY_PRODUCT, PRODUCER.GATEWAY_PRODUCT)
        self.assertEqual(REMOTE.GATEWAY_NAME_RE.pattern, PRODUCER.GATEWAY_NAME_RE.pattern)

    def test_real_producer_key_set_loads_on_the_real_loader(self) -> None:
        record = sample_manifest()
        self.assertEqual(set(record), REMOTE.MANIFEST_KEYS)
        self.assertEqual(set(record["gateway_artifact"]), PRODUCER.GATEWAY_ARTIFACT_KEYS)
        self.assertEqual(set(record["remote_action_helper"]), PRODUCER.REMOTE_ACTION_HELPER_KEYS)
        self.assertEqual(set(record["attempt_broker"]), PRODUCER.ATTEMPT_BROKER_KEYS)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            loaded = REMOTE._load_manifest(path, sidecar, digest)
        self.assertEqual(loaded, record)
        self.assertEqual(set(loaded["gateway_artifact"]), PRODUCER.GATEWAY_ARTIFACT_KEYS)
        self.assertEqual(set(loaded["remote_action_helper"]), PRODUCER.REMOTE_ACTION_HELPER_KEYS)
        self.assertEqual(set(loaded["attempt_broker"]), PRODUCER.ATTEMPT_BROKER_KEYS)

    def test_missing_gateway_artifact_is_refused(self) -> None:
        record = sample_manifest()
        del record["gateway_artifact"]
        record = finish_manifest(
            {key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}},
            created_utc=record["created_utc"],
        )
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "schema is invalid"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_extra_gateway_artifact_field_is_refused(self) -> None:
        record = sample_manifest()
        gateway = dict(record["gateway_artifact"])
        gateway["extra"] = True
        record = sample_manifest(gateway_artifact=gateway)
        self.assertIn("extra", record["gateway_artifact"])
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "gateway artifact schema"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_wrong_gateway_hash_is_refused(self) -> None:
        record = sample_manifest()
        gateway = dict(record["gateway_artifact"])
        gateway["sha256"] = "f" * 64
        record = sample_manifest(gateway_artifact=gateway)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_wrong_gateway_path_is_refused(self) -> None:
        record = sample_manifest()
        gateway = dict(record["gateway_artifact"])
        gateway["path"] = "winn_protocol_experimental/dist/winn3-gateway-linux-arm64"
        record = sample_manifest(gateway_artifact=gateway)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "missing from the input closure|not bound"
            ):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_missing_remote_action_helper_is_refused(self) -> None:
        record = sample_manifest()
        del record["remote_action_helper"]
        record = finish_manifest(
            {key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}},
            created_utc=record["created_utc"],
        )
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "schema is invalid"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_wrong_remote_action_helper_hash_is_refused(self) -> None:
        helper = dict(sample_manifest()["remote_action_helper"])
        helper["sha256"] = "f" * 64
        record = sample_manifest(remote_action_helper=helper)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_missing_attempt_broker_is_refused(self) -> None:
        record = sample_manifest()
        del record["attempt_broker"]
        record = finish_manifest(
            {key: value for key, value in record.items() if key not in {"candidate_id", "created_utc"}},
            created_utc=record["created_utc"],
        )
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "schema is invalid"):
                REMOTE._load_manifest(path, sidecar, digest)

    def test_wrong_attempt_broker_hash_is_refused(self) -> None:
        broker = dict(sample_manifest()["attempt_broker"])
        broker["sha256"] = "f" * 64
        record = sample_manifest(attempt_broker=broker)
        with tempfile.TemporaryDirectory() as name:
            path, sidecar, digest = write_manifest(Path(name), record)
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound"):
                REMOTE._load_manifest(path, sidecar, digest)


class GatewayStagingTests(unittest.TestCase):
    def test_stage_copies_exact_artifact_to_installer_path(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            staging = root / "staging"
            write_extracted_tree(extracted, record, files)
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(REMOTE.os, "fchown"):
                bound = REMOTE.stage_gateway_artifact(extracted, record, staging)
            staged = staging / REMOTE.GATEWAY_STAGED_BIN_NAME
            checksum = staging / f"{REMOTE.GATEWAY_STAGED_BIN_NAME}.sha256"
            self.assertEqual(bound["path"], str(staged))
            self.assertEqual(bound["source_path"], ARTIFACT_PATH)
            self.assertEqual(staged.read_bytes(), files[ARTIFACT_PATH])
            self.assertEqual(REMOTE.sha256_bytes(staged.read_bytes()), bound["sha256"])
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o755)
            self.assertEqual(
                checksum.read_bytes(),
                f"{bound['sha256']}  {REMOTE.GATEWAY_STAGED_BIN_NAME}\n".encode("ascii"),
            )
            self.assertFalse((staging / ARTIFACT_PATH).exists())
            REMOTE.require_complete_gateway_staging(
                staging, expected_sha256=bound["sha256"], expected_mode=0o755
            )

    def test_partial_staging_without_checksum_is_refused(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            staging = root / "staging"
            write_extracted_tree(extracted, record, files)
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(REMOTE.os, "fchown"):
                bound = REMOTE.stage_gateway_artifact(extracted, record, staging)
            (staging / f"{REMOTE.GATEWAY_STAGED_BIN_NAME}.sha256").unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                REMOTE.require_complete_gateway_staging(
                    staging, expected_sha256=bound["sha256"], expected_mode=0o755
                )

    def test_partial_staging_without_binary_is_refused(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            staging = root / "staging"
            write_extracted_tree(extracted, record, files)
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(REMOTE.os, "fchown"):
                bound = REMOTE.stage_gateway_artifact(extracted, record, staging)
            (staging / REMOTE.GATEWAY_STAGED_BIN_NAME).unlink()
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "incomplete"):
                REMOTE.require_complete_gateway_staging(
                    staging, expected_sha256=bound["sha256"], expected_mode=0o755
                )

    def test_extracted_hash_mismatch_refuses_staging(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            staging = root / "staging"
            write_extracted_tree(extracted, record, files)
            target = extracted.joinpath(*PurePosixPath(ARTIFACT_PATH).parts)
            target.write_bytes(b"tampered-gateway-bytes\n")
            os.chmod(target, 0o755)
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(REMOTE.os, "fchown"):
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "SHA-256"):
                    REMOTE.stage_gateway_artifact(extracted, record, staging)
            self.assertFalse((staging / REMOTE.GATEWAY_STAGED_BIN_NAME).exists())


class ProofClientArtifactInstallTests(unittest.TestCase):
    def test_probe_and_ech_keygen_install_from_exact_bound_bytes(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            write_extracted_tree(extracted, record, files)
            cases = (
                ("winn3-probe", PROBE_ARTIFACT_PATH, root / "bin" / "winn3-probe"),
                (
                    "winn-ech-keygen",
                    ECH_KEYGEN_ARTIFACT_PATH,
                    root / "libexec" / "winn-ech-keygen",
                ),
            )
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(
                REMOTE.os, "fchown"
            ):
                for product, source_path, destination in cases:
                    bound = REMOTE.install_proof_client_artifact(
                        extracted,
                        record,
                        product=product,
                        destination=destination,
                    )
                    self.assertEqual(bound["product"], product)
                    self.assertEqual(bound["source_path"], source_path)
                    self.assertEqual(destination.read_bytes(), files[source_path])
                    self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
                    self.assertEqual(
                        REMOTE.sha256_bytes(destination.read_bytes()), bound["sha256"]
                    )

    def test_tampered_probe_is_refused_before_install(self) -> None:
        record = sample_manifest()
        files = sample_files()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            extracted = root / "extracted"
            destination = root / "bin" / "winn3-probe"
            write_extracted_tree(extracted, record, files)
            source = extracted.joinpath(*PurePosixPath(PROBE_ARTIFACT_PATH).parts)
            source.write_bytes(b"tampered\n")
            os.chmod(source, 0o755)
            with mock.patch.object(REMOTE.os, "chown"), mock.patch.object(
                REMOTE.os, "fchown"
            ):
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "SHA-256"):
                    REMOTE.install_proof_client_artifact(
                        extracted,
                        record,
                        product="winn3-probe",
                        destination=destination,
                    )
            self.assertFalse(destination.exists())


class SequenceTests(unittest.TestCase):
    def test_documented_gateway_order_is_install_provision_preflight_start(self) -> None:
        self.assertEqual(
            REMOTE.gateway_sequence(),
            (
                (REMOTE.GATEWAY_INSTALLER, "--install"),
                (REMOTE.PROOF_KEY_PROVISION_ID, REMOTE.PROOF_KEY_PROVISION_FLAG),
                (REMOTE.GATEWAY_INSTALLER, "--preflight"),
                (REMOTE.GATEWAY_INSTALLER, "--start"),
            ),
        )
        gateway_flags = [
            flag
            for _role, script, flag in REMOTE.EXPECTED_STEPS
            if script == REMOTE.GATEWAY_INSTALLER
        ]
        self.assertEqual(gateway_flags, ["--install", "--preflight", "--start"])
        self.assertNotEqual(gateway_flags, ["--preflight", "--start"])

    def invoke(self, step_index: int, completed: list[int]) -> None:
        role, script, flag = REMOTE.EXPECTED_STEPS[step_index]
        provision = REMOTE._is_proof_key_provision(script, flag)
        installer = next(item for item in sample_manifest()["installers"] if item["path"] == INSTALLER_PATH)
        args = SimpleNamespace(
            apply_sha256="a" * 64,
            bundle="/tmp/bundle",
            bundle_sha256="b" * 64,
            flag=flag,
            fleet_completed_step_indices=[],
            fleet_id="proof-fleet-20260823",
            final_role_step=step_index in REMOTE.final_role_step_indices(),
            helper_sha256="c" * 64,
            instance="proof-winn3-a1",
            manifest="/tmp/manifest",
            manifest_sha256="d" * 64,
            manifest_sidecar="/tmp/sidecar",
            marker=str(REMOTE.MARKER_PATH),
            plan_sha256="e" * 64,
            previous_record_sha256="0" * 64,
            role=role,
            script=script,
            script_bytes=0 if provision else installer["bytes"],
            script_mode=0 if provision else installer["mode"],
            script_sha256=REMOTE.ZERO_SHA256 if provision else installer["sha256"],
            state_root=str(REMOTE.STATE_ROOT),
            step_index=step_index,
            timeout_seconds=3600,
        )
        manifest = sample_manifest()
        marker = None
        if completed:
            marker = {
                "apply_sha256": args.apply_sha256,
                "candidate_id": manifest["candidate_id"],
                "completed_step_indices": completed,
                "deployment_manifest_sha256": args.manifest_sha256,
                "fleet_id": args.fleet_id,
                "fleet_record_chain_sha256": args.previous_record_sha256,
                "instance": args.instance,
                "plan_sha256": args.plan_sha256,
                "role": args.role,
            }
        with mock.patch.object(REMOTE, "_validate_common"), mock.patch.object(
            REMOTE, "_read_regular", return_value=b"helper"
        ), mock.patch.object(
            REMOTE, "_load_manifest", return_value=manifest
        ), mock.patch.object(
            REMOTE, "_validate_staged_paths"
        ), mock.patch.object(
            REMOTE, "verify_bundle", return_value=b"bundle"
        ), mock.patch.object(
            REMOTE, "_validate_marker_file", return_value=marker
        ), mock.patch.object(
            REMOTE, "_extract_bundle"
        ) as extract:
            REMOTE.run_step(args)
            extract.assert_not_called()

    def test_missing_install_refuses_provision(self) -> None:
        provision = next(
            index
            for index, item in enumerate(REMOTE.EXPECTED_STEPS)
            if item[1] == REMOTE.PROOF_KEY_PROVISION_ID
        )
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "skipped or reordered"):
            self.invoke(provision, [])

    def test_missing_provision_refuses_gateway_preflight(self) -> None:
        preflight = next(
            index
            for index, item in enumerate(REMOTE.EXPECTED_STEPS)
            if item[1] == REMOTE.GATEWAY_INSTALLER and item[2] == "--preflight"
        )
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "skipped or reordered"):
            self.invoke(preflight, [2])

    def test_start_before_preflight_is_refused(self) -> None:
        start = next(
            index
            for index, item in enumerate(REMOTE.EXPECTED_STEPS)
            if item[1] == REMOTE.GATEWAY_INSTALLER and item[2] == "--start"
        )
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "skipped or reordered"):
            self.invoke(start, [2, 3])


class ProofKeyProvisionTests(unittest.TestCase):
    def test_wrong_role_is_refused(self) -> None:
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "data-winn3-only"):
            REMOTE.provision_proof_keys(role="control")


    def test_unbound_provision_refuses_before_inspecting_installed_binary(self) -> None:
        with mock.patch.object(
            REMOTE, "_generate_and_install_proof_keys_on_vm"
        ) as generate, mock.patch.object(
            REMOTE, "GATEWAY_INSTALL_PATH", Path("/tmp/missing-winn3-gateway")
        ):
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, REMOTE.OWNER_CLOUD_EVIDENCE_BLOCKED
            ):
                REMOTE.provision_proof_keys(role="data-winn3")
        generate.assert_not_called()

    def test_missing_control_channel_is_named_and_non_exporting(self) -> None:
        with self.assertRaises(REMOTE.RemoteInstallError) as caught:
            REMOTE._require_authenticated_control_admission_channel()
        message = str(caught.exception)
        self.assertIn(REMOTE.CONTROL_ADMISSION_EVIDENCE_CHANNEL, message)
        self.assertIn(REMOTE.CONTROL_ADMISSION_EXTERNAL_INPUT, message)
        self.assertIn("external input", message)
        self.assertNotIn("BEGIN", message)

    def test_unbound_provision_does_not_generate_or_write_keys(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            binary = root / "winn3-gateway"
            binary.write_bytes(b"fake-installed-gateway\n")
            os.chmod(binary, 0o755)
            creds = root / "credentials"
            keygen_dir = root / "keygen-out"

            with mock.patch.object(REMOTE, "GATEWAY_INSTALL_PATH", binary), mock.patch.object(
                REMOTE, "_generate_and_install_proof_keys_on_vm"
            ) as generate:
                with self.assertRaises(REMOTE.RemoteInstallError) as caught:
                    REMOTE.provision_proof_keys(role="data-winn3")
            message = str(caught.exception)
            self.assertEqual(message, REMOTE.OWNER_CLOUD_EVIDENCE_BLOCKED)
            self.assertIn("BLOCKED", message)
            generate.assert_not_called()
            self.assertFalse(creds.exists())
            self.assertFalse(keygen_dir.exists())

    def test_tar_binding_kwargs_are_refused(self) -> None:
        with mock.patch.object(REMOTE, "_generate_and_install_proof_keys_on_vm") as generate:
            with self.assertRaisesRegex(
                REMOTE.RemoteInstallError, "tar/archive key provisioning is refused"
            ):
                REMOTE.provision_proof_keys(
                    role="data-winn3",
                    fleet_id="proof-fleet-20260823",
                )
        generate.assert_not_called()

    def keygen_stack(
        self, root: Path, files: dict[str, bytes]
    ) -> tuple[ExitStack, Path, Path, Path, dict[str, int]]:
        binary = root / "winn3-gateway"
        binary.write_bytes(b"fake-installed-gateway\n")
        os.chmod(binary, 0o755)
        keygen_dir = root / "keygen-out"
        original_is_dir = Path.is_dir
        original_mkdtemp = REMOTE.tempfile.mkdtemp
        calls = {"keygen": 0}

        def fake_is_dir(self_path: Path) -> bool:
            if self_path.as_posix() == "/run":
                return True
            return original_is_dir(self_path)

        def fake_mkdtemp(prefix: str = "tmp", dir: str | None = None) -> str:
            if dir == "/run" and prefix.startswith("winn3-keygen."):
                keygen_dir.mkdir(exist_ok=True)
                return str(keygen_dir)
            return original_mkdtemp(prefix=prefix, dir=dir)

        def fake_run(argv: list[str], **kwargs: Any) -> Any:
            self.assertEqual(argv[:3], [str(binary), "-mode", "keygen"])
            self.assertIs(kwargs["shell"], False)
            calls["keygen"] += 1
            out = Path(argv[argv.index("-out") + 1])
            write_keygen_output(out, files)
            return SimpleNamespace(
                returncode=0,
                stdout=b'{"event":"keygen"}\n',
                stderr=b"",
            )

        stack = ExitStack()
        stack.enter_context(mock.patch.object(REMOTE.os, "chown"))
        stack.enter_context(mock.patch.object(REMOTE.os, "fchown"))
        stack.enter_context(mock.patch.object(Path, "is_dir", fake_is_dir))
        stack.enter_context(mock.patch.object(REMOTE.tempfile, "mkdtemp", side_effect=fake_mkdtemp))
        stack.enter_context(mock.patch.object(REMOTE.subprocess, "run", side_effect=fake_run))
        return stack, binary, keygen_dir, root / "credentials", calls

    def test_fresh_on_vm_generate_installs_least_privilege_keys(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            stack, binary, _keygen, creds, calls = self.keygen_stack(workspace, files)
            with stack:
                receipt = REMOTE.provision_proof_keys(
                    role="data-winn3",
                    gateway_binary=binary,
                    credentials_dir=creds,
                )
            self.assertEqual(calls["keygen"], 1)
            self.assertTrue(receipt["generated"])
            self.assertEqual(receipt["mode"], REMOTE.PROOF_KEY_INSTALL_MODE)
            self.assertEqual(receipt["kind"], REMOTE.PROOF_KEY_PROVISION_ID)
            self.assertEqual(
                receipt["installed"],
                sorted(item for _source, item in REMOTE.GATEWAY_PRIVATE_INSTALL),
            )
            encoded = REMOTE.canonical_bytes(receipt)
            for secret_name in (
                "static.key",
                "admission.key",
                "client.key",
                "auth_ed25519.seed",
                "auth_mldsa65.seed",
            ):
                self.assertNotIn(files[secret_name], encoded)
                self.assertNotIn(REMOTE.sha256_bytes(files[secret_name]).encode("ascii"), encoded)
            for source, installed in REMOTE.GATEWAY_PRIVATE_INSTALL:
                path = creds / installed
                self.assertEqual(path.read_bytes(), files[source])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), REMOTE.PROOF_KEY_INSTALL_MODE)
            hold = creds / REMOTE.PROOF_KEY_HOLD_NAME
            self.assertTrue(hold.is_dir())
            self.assertEqual(stat.S_IMODE(hold.stat().st_mode), 0o700)
            for name, payload in files.items():
                held = hold / name
                self.assertEqual(held.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(held.stat().st_mode), REMOTE.PROOF_KEY_INSTALL_MODE)
            self.assertFalse((creds / "client.key").exists())

    def test_idempotent_provision_does_not_regenerate(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            stack, binary, _keygen, creds, calls = self.keygen_stack(workspace, files)
            with stack:
                first = REMOTE.provision_proof_keys(
                    role="data-winn3",
                    gateway_binary=binary,
                    credentials_dir=creds,
                )
                second = REMOTE.provision_proof_keys(
                    role="data-winn3",
                    gateway_binary=binary,
                    credentials_dir=creds,
                )
            self.assertEqual(calls["keygen"], 1)
            self.assertTrue(first["generated"])
            self.assertFalse(second["generated"])
            self.assertEqual(first["installed"], second["installed"])
            self.assertEqual(
                (creds / REMOTE.STATIC_KEY_NAME).read_bytes(), files["static.key"]
            )

    def test_world_writable_gateway_binary_is_refused(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            stack, binary, _keygen, creds, calls = self.keygen_stack(workspace, files)
            os.chmod(binary, 0o777)
            with stack:
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unsafe"):
                    REMOTE.provision_proof_keys(
                        role="data-winn3",
                        gateway_binary=binary,
                        credentials_dir=creds,
                    )
            self.assertEqual(calls["keygen"], 0)
            self.assertFalse(creds.exists())


class RuntimeIdentityRoleTests(unittest.TestCase):
    @staticmethod
    def manifest() -> dict[str, Any]:
        return {
            "external_pins": {
                "awg": {"awg_server_image": "amneziavpn/amneziawg-go:v3.1.20260828"},
                "router_base_image": {
                    "digest": "sha256:" + "a" * 64,
                    "reference": "python:3.14@sha256:" + "a" * 64,
                },
            }
        }

    @staticmethod
    def fake_file(path: Path, *, applicable: bool) -> dict[str, Any]:
        return {
            "applicable": applicable,
            "bytes": 1 if applicable else None,
            "path": str(path) if applicable else None,
            "sha256": "b" * 64 if applicable else None,
        }

    def test_data_winn3_never_requires_cover_runtime(self) -> None:
        with mock.patch.object(REMOTE, "_file_runtime", side_effect=self.fake_file), mock.patch.object(
            REMOTE, "_run_identity", side_effect=AssertionError("cover runtime probed")
        ):
            runtime = REMOTE.runtime_identities("data-winn3", self.manifest())
        self.assertTrue(runtime["winn"]["applicable"])
        self.assertFalse(runtime["xray"]["applicable"])
        self.assertFalse(runtime["awg"]["applicable"])

    def test_data_cover_requires_awg_and_xray_but_not_winn3(self) -> None:
        with mock.patch.object(REMOTE, "_file_runtime", side_effect=self.fake_file), mock.patch.object(
            REMOTE, "_run_identity", return_value="sha256:" + "d" * 64
        ):
            runtime = REMOTE.runtime_identities("data-cover", self.manifest())
        self.assertFalse(runtime["winn"]["applicable"])
        self.assertTrue(runtime["xray"]["applicable"])
        self.assertTrue(runtime["awg"]["applicable"])


class RealInstallerContractTests(unittest.TestCase):
    def test_real_gateway_installer_is_inspected_not_replaced(self) -> None:
        text = GATEWAY_INSTALLER_PATH.read_text("utf-8")
        self.assertGreater(len(text), 20000)
        self.assertIn(
            'WINN3_GATEWAY_STAGING_DIR="${WINN3_GATEWAY_STAGING_DIR:-/root/wins-onetouch-staging/winn3}"',
            text,
        )
        self.assertIn("--install", text)
        self.assertIn("--preflight", text)
        self.assertIn("--start", text)
        self.assertIn("Correct order is:", text)
        self.assertIn("tools/winn3_gateway_provision_keys.sh", text)
        self.assertIn("does not need credentials", text)
        self.assertNotEqual(text.strip(), "#!/bin/bash\nexit 0")

    def test_real_provision_script_is_on_node_and_non_exporting(self) -> None:
        text = PROVISION_SCRIPT_PATH.read_text("utf-8")
        self.assertGreater(len(text), 5000)
        self.assertIn("-mode keygen", text)
        self.assertIn("PRIVATE KEY NEVER CROSSES THE NETWORK", text)
        self.assertIn('echo "static.pub', text)
        self.assertNotIn('echo "static.key', text)
        self.assertNotEqual(text.strip(), "#!/bin/bash\nexit 0")

    def test_remote_helper_does_not_invoke_the_ssh_provision_wrapper(self) -> None:
        text = (TOOLS / "gcp_proof_remote_install.py").read_text("ascii")
        self.assertNotIn("winn3_gateway_provision_keys.sh", text)
        self.assertIn("/root/wins-onetouch-staging/winn3", text)
        self.assertIn("keygen", text)
        self.assertIn("CONTROL_ADMISSION_EXTERNAL_INPUT", text)
        self.assertIn("OWNER_CLOUD_EVIDENCE_BLOCKED", text)
        self.assertIn("BLOCKED: owner/cloud GCE instance identity is absent", text)
        self.assertIn("owner-authenticated delivery of on-VM proof-only", text)
        self.assertIn("external input", text)
        self.assertIn("exchange-identity", text)
        self.assertIn("exchange-challenge", text)
        self.assertIn("exchange-control-offer", text)
        self.assertIn("exchange-data-accept", text)
        self.assertIn("exchange-data-emit", text)
        self.assertIn("exchange-control-import", text)
        self.assertIn("exchange-data-consume", text)
        self.assertIn("exchange-control-seal", text)
        self.assertIn("exchange-status", text)
        self.assertIn("/usr/local/libexec/winsvpn-gcp-proof-remote", text)
        self.assertIn("remote_action_helper", text)
        self.assertIn("/usr/local/libexec/winsvpn-gcp-proof-attempt-broker", text)
        self.assertIn("attempt_broker", text)
        self.assertNotIn("export_proof_client_credentials", text)
        self.assertNotIn("import_proof_client_credentials", text)
        self.assertNotIn("_write_transfer_archive", text)
        self.assertIn("tar/archive key provisioning is refused", text)
        self.assertNotIn("inner_packets_delivered", text)
        self.assertNotIn("same_node_downgrade_refused", text)

    def test_cli_actions_include_installer_and_exchange_primitives(self) -> None:
        choices = None
        for action in REMOTE.parser()._actions:
            if "--action" in action.option_strings:
                choices = set(action.choices or [])
        self.assertEqual(
            choices,
            {
                "step",
                "finalize",
                "exchange-identity",
                "exchange-challenge",
                "exchange-control-offer",
                "exchange-data-accept",
                "exchange-data-emit",
                "exchange-control-import",
                "exchange-data-consume",
                "exchange-control-seal",
                "exchange-status",
            },
        )


class AuthenticatedKeyExchangeTests(unittest.TestCase):
    def keygen_stack(
        self, root: Path, files: dict[str, bytes]
    ) -> tuple[ExitStack, Path, Path, Path]:
        binary = root / "winn3-gateway"
        binary.write_bytes(b"fake-installed-gateway\n")
        os.chmod(binary, 0o755)
        keygen_dir = root / "keygen-out"
        original_is_dir = Path.is_dir
        original_mkdtemp = REMOTE.tempfile.mkdtemp

        def fake_is_dir(self_path: Path) -> bool:
            if self_path.as_posix() == "/run":
                return True
            return original_is_dir(self_path)

        def fake_mkdtemp(prefix: str = "tmp", dir: str | None = None) -> str:
            if dir == "/run" and prefix.startswith("winn3-keygen."):
                keygen_dir.mkdir(exist_ok=True)
                return str(keygen_dir)
            return original_mkdtemp(prefix=prefix, dir=dir)

        def fake_run(argv: list[str], **kwargs: Any) -> Any:
            self.assertEqual(argv[:3], [str(binary), "-mode", "keygen"])
            self.assertIs(kwargs["shell"], False)
            out = Path(argv[argv.index("-out") + 1])
            write_keygen_output(out, files)
            return SimpleNamespace(
                returncode=0,
                stdout=b'{"event":"keygen"}\n',
                stderr=b"",
            )

        stack = ExitStack()
        stack.enter_context(mock.patch.object(REMOTE.os, "chown"))
        stack.enter_context(mock.patch.object(REMOTE.os, "fchown"))
        stack.enter_context(mock.patch.object(Path, "is_dir", fake_is_dir))
        stack.enter_context(mock.patch.object(REMOTE.tempfile, "mkdtemp", side_effect=fake_mkdtemp))
        stack.enter_context(mock.patch.object(REMOTE.subprocess, "run", side_effect=fake_run))
        return stack, binary, keygen_dir, root / "credentials"

    def exchange_stack(self) -> ExitStack:
        stack = ExitStack()
        stack.enter_context(mock.patch.object(REMOTE.os, "chown"))
        stack.enter_context(mock.patch.object(REMOTE.os, "fchown"))
        return stack

    def run_action(
        self,
        action: str,
        *,
        role: str,
        instance: str,
        exchange_root: Path,
        now_utc: str = EXCHANGE_NOW,
        **kwargs: Any,
    ) -> dict[str, Any]:
        payload = proof_binding()
        for key in (
            "fleet_id",
            "candidate_id",
            "source_role",
            "source_instance",
            "target_role",
            "target_instance",
            "inner_v4",
            "apply_sha256",
            "bundle_sha256",
            "helper_sha256",
            "manifest_sha256",
            "plan_sha256",
            "source_instance_id",
            "target_instance_id",
            "source_boot_id",
            "target_boot_id",
        ):
            if key in kwargs:
                payload[key] = kwargs.pop(key)
        return REMOTE.run_exchange_action(
            action,
            role=role,
            instance=instance,
            exchange_root=exchange_root,
            now_utc=now_utc,
            **payload,
            **kwargs,
        )

    def identities(self, control_root: Path, data_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        control = self.run_action(
            "exchange-identity",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
        )
        data = self.run_action(
            "exchange-identity",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
        )
        return control, data

    def challenged(
        self, control_root: Path, data_root: Path
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        control_id, data_id = self.identities(control_root, data_root)
        control = self.run_action(
            "exchange-challenge",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
            peer=data_id["receipt"],
        )
        data = self.run_action(
            "exchange-challenge",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
            peer=control_id["receipt"],
        )
        return control, data

    def accepted(self, control_root: Path, data_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        _challenge_c, challenge_d = self.challenged(control_root, data_root)
        offer = self.run_action(
            "exchange-control-offer",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
            peer=challenge_d["receipt"],
        )
        accept = self.run_action(
            "exchange-data-accept",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
            peer=offer["receipt"],
        )
        return offer, accept

    def assert_no_secrets(self, payload: dict[str, Any], files: dict[str, bytes]) -> None:
        encoded = REMOTE.canonical_bytes(payload)
        for name in (
            "static.key",
            "admission.key",
            "client.key",
            "auth_ed25519.seed",
            "auth_mldsa65.seed",
        ):
            secret = files[name]
            self.assertNotIn(secret, encoded)
            self.assertNotIn(REMOTE.sha256_bytes(secret).encode("ascii"), encoded)

    def assert_full_binding(self, payload: dict[str, Any]) -> None:
        for key in FULL_BINDING_KEYS:
            self.assertEqual(payload[key], proof_binding()[key], key)
        self.assertEqual(payload["source_instance_id"], PROOF_SOURCE_INSTANCE_ID)
        self.assertEqual(payload["target_instance_id"], PROOF_TARGET_INSTANCE_ID)
        self.assertEqual(payload["source_boot_id"], PROOF_SOURCE_BOOT_ID)
        self.assertEqual(payload["target_boot_id"], PROOF_TARGET_BOOT_ID)

    def hex_action(self, action: str, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("fleet_id", HEX_FLEET)
        return self.run_action(action, **kwargs)

    def hex_accepted(
        self, control_root: Path, data_root: Path
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        control = self.hex_action(
            "exchange-identity",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
        )
        data = self.hex_action(
            "exchange-identity",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
        )
        self.hex_action(
            "exchange-challenge",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
            peer=data["receipt"],
        )
        data_challenge = self.hex_action(
            "exchange-challenge",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
            peer=control["receipt"],
        )
        offer = self.hex_action(
            "exchange-control-offer",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
            peer=data_challenge["receipt"],
        )
        accept = self.hex_action(
            "exchange-data-accept",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
            peer=offer["receipt"],
        )
        return offer, accept

    def emit_and_import(
        self,
        control_root: Path,
        data_root: Path,
        proof_dir: Path,
        files: dict[str, bytes],
        binary: Path,
        creds: Path,
        *,
        hex_fleet: bool = False,
    ) -> dict[str, Any]:
        runner = self.hex_action if hex_fleet else self.run_action
        if hex_fleet:
            self.hex_accepted(control_root, data_root)
        else:
            self.accepted(control_root, data_root)
        emitted = runner(
            "exchange-data-emit",
            role="data-winn3",
            instance="proof-winn3-a1",
            exchange_root=data_root,
            credentials_dir=creds,
            gateway_binary=binary,
        )
        return runner(
            "exchange-control-import",
            role="control",
            instance="proof-control-a1",
            exchange_root=control_root,
            peer=emitted["receipt"],
            secret={
                name: emitted["secret"][name].encode("ascii")
                for name in REMOTE.EXCHANGE_SECRET_NAMES
            },
            public={
                name: emitted["public"][name].encode("ascii")
                for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
            },
            proof_client_dir=proof_dir,
        )

    def test_same_source_and_target_instance_is_refused(self) -> None:
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "distinct"):
            REMOTE._exchange_binding(
                **proof_binding(source_instance="proof-control-a1", target_instance="proof-control-a1")
            )

    def test_unusable_inner_addresses_are_refused(self) -> None:
        for inner in ("10.10.0.0", "10.10.0.1", "10.10.0.255", "8.8.8.8", "10.10.0.02"):
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "inner IPv4"):
                REMOTE._exchange_binding(**proof_binding(inner_v4=inner))

    def test_wrong_roles_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            with self.exchange_stack():
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not valid for this role"):
                    self.run_action(
                        "exchange-data-emit",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not valid for this role"):
                    self.run_action(
                        "exchange-control-import",
                        role="data-winn3",
                        instance="proof-winn3-a1",
                        exchange_root=root,
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not valid for this role"):
                    self.run_action(
                        "exchange-identity",
                        role="data-cover",
                        instance="proof-cover-a1",
                        exchange_root=root,
                    )

    def test_happy_path_control_retains_client_key_data_receives_only_client_pub(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            registry = workspace / "winn3-peers.json"
            kwargs = self.keygen_stack(workspace, files)
            stack, binary, _keygen, creds = kwargs
            with stack, self.exchange_stack():
                offer, _accept = self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                imported = self.run_action(
                    "exchange-control-import",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    peer=emitted["receipt"],
                    secret={
                        name: emitted["secret"][name].encode("ascii")
                        for name in REMOTE.EXCHANGE_SECRET_NAMES
                    },
                    public={
                        name: emitted["public"][name].encode("ascii")
                        for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                    },
                    proof_client_dir=proof_dir,
                )
                consumed = self.run_action(
                    "exchange-data-consume",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    public={"client.pub": files["client.pub"]},
                    peer_registry_path=registry,
                )
                sealed = self.run_action(
                    "exchange-control-seal",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    proof_client_dir=proof_dir,
                )
                status = self.run_action(
                    "exchange-status",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                )
            self.assertEqual(emitted["kind"], REMOTE.KIND_EXCHANGE_RESPONSE)
            self.assertEqual(emitted["action"], "exchange-data-emit")
            for item in (
                offer["receipt"],
                emitted["receipt"],
                imported["receipt"],
                consumed["receipt"],
                sealed["receipt"],
                status["receipt"],
            ):
                self.assert_full_binding(item)
            self.assertIsNotNone(emitted["secret"])
            self.assertEqual(emitted["secret"]["client.key"], files["client.key"].decode("ascii"))
            self.assertEqual(emitted["secret"]["admission.key"], files["admission.key"].decode("ascii"))
            self.assertEqual(emitted["public"]["client.pub"], files["client.pub"].decode("ascii"))
            self.assert_no_secrets(emitted["receipt"], files)
            self.assertIsNone(imported["secret"])
            self.assert_no_secrets(imported["receipt"], files)
            self.assert_no_secrets(consumed["receipt"], files)
            self.assert_no_secrets(sealed["receipt"], files)
            self.assertTrue(status["receipt"]["sealed"])
            self.assertEqual((creds / REMOTE.STATIC_KEY_NAME).read_bytes(), files["static.key"])
            self.assertEqual((creds / REMOTE.ADMISSION_KEY_NAME).read_bytes(), files["admission.key"])
            self.assertEqual(
                (creds / REMOTE.DUAL_AUTH_ED_KEY_NAME).read_bytes(), files["auth_ed25519.seed"]
            )
            self.assertEqual(
                (creds / REMOTE.DUAL_AUTH_ML_SEED_NAME).read_bytes(), files["auth_mldsa65.seed"]
            )
            self.assertFalse((creds / "client.key").exists())
            self.assertFalse((creds / "client.pub").exists())
            self.assertEqual((proof_dir / "client.key").read_bytes(), files["client.key"])
            self.assertEqual((proof_dir / "admission.key").read_bytes(), files["admission.key"])
            self.assertEqual((proof_dir / "static.pub").read_bytes(), files["static.pub"])
            self.assertFalse((proof_dir / "client.pub").exists())
            self.assertFalse((proof_dir / "static.key").exists())
            self.assertEqual(
                stat.S_IMODE((proof_dir / "client.key").stat().st_mode),
                REMOTE.EXCHANGE_CREDENTIAL_MODE,
            )
            document = REMOTE.strict_json(registry.read_bytes(), "peer registry")
            self.assertEqual(document["version"], 1)
            self.assertEqual(len(document["peers"]), 1)
            self.assertEqual(document["peers"][0]["inner_v4"], "10.10.0.2")
            self.assertEqual(
                document["peers"][0]["static_public"],
                base64.b64encode(bytes.fromhex(files["client.pub"].decode("ascii"))).decode("ascii"),
            )
            self.assertFalse((control_root / "proof-client-transfer.tar").exists())
            self.assertFalse((data_root / "proof-client-transfer.tar").exists())

    def test_consume_refuses_secret_material(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                self.accepted(control_root, data_root)
                self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "only client.pub"):
                    self.run_action(
                        "exchange-data-consume",
                        role="data-winn3",
                        instance="proof-winn3-a1",
                        exchange_root=data_root,
                        secret={"admission.key": files["admission.key"], "client.key": files["client.key"]},
                        public={"client.pub": files["client.pub"]},
                        peer_registry_path=workspace / "winn3-peers.json",
                    )
            self.assertFalse((workspace / "winn3-peers.json").exists())
            self.assertFalse((creds / "client.key").exists())

    def test_sequence_skip_and_event_replacement_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            with self.exchange_stack():
                first = self.run_action(
                    "exchange-identity",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "replacement"):
                    self.run_action(
                        "exchange-identity",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "skipped or reordered"):
                    self.run_action(
                        "exchange-control-offer",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )
            self.assertEqual(first["action"], "exchange-identity")

    def test_ttl_and_skew_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            control_root = Path(name) / "control" / "key-exchange-v1"
            data_root = Path(name) / "data" / "key-exchange-v1"
            with self.exchange_stack():
                control_id, data_id = self.identities(control_root, data_root)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "TTL has expired"):
                    self.run_action(
                        "exchange-challenge",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=data_id["receipt"],
                        now_utc="2026-08-25T05:05:31Z",
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "skew"):
                    self.run_action(
                        "exchange-challenge",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=data_id["receipt"],
                        now_utc="2026-08-25T04:59:29Z",
                    )
                self.run_action(
                    "exchange-challenge",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    peer=data_id["receipt"],
                    now_utc="2026-08-25T05:00:20Z",
                )
            self.assertEqual(control_id["action"], "exchange-identity")

    def test_stale_candidate_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            control_root = Path(name) / "control" / "key-exchange-v1"
            data_root = Path(name) / "data" / "key-exchange-v1"
            with self.exchange_stack():
                _control_id, data_id = self.identities(control_root, data_root)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale or cross-run"):
                    self.run_action(
                        "exchange-challenge",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=data_id["receipt"],
                        candidate_id="b" * 64,
                    )

    def test_legacy_tar_in_exchange_dir_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            with self.exchange_stack():
                self.run_action(
                    "exchange-identity",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
                (root / "proof-client-transfer.tar").write_bytes(b"ustar-not-used")
                os.chmod(root / "proof-client-transfer.tar", 0o400)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "tar/archive"):
                    self.run_action(
                        "exchange-status",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )

    def test_stdin_tar_archive_is_refused(self) -> None:
        args = SimpleNamespace(
            action="exchange-identity",
            role="control",
            instance="proof-control-a1",
            fleet_id="proof-fleet-20260823",
            candidate_id="0123456789abcdef" * 4,
            source_role="data-winn3",
            source_instance="proof-winn3-a1",
            target_role="control",
            target_instance="proof-control-a1",
            inner_v4="10.10.0.2",
        )
        tarish = (b"\0" * 257) + b"ustar" + b"\0" * 20
        with mock.patch.object(REMOTE.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(REMOTE.RemoteInstallError, "tar/archive"):
                REMOTE.run_exchange(args, stdin_data=tarish)

    def test_import_rollback_wipes_partial_destination(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            original = REMOTE._atomic_nofollow_at

            def flaky(
                directory_fd: int,
                name: str,
                data: bytes,
                mode: int,
                label: str,
            ) -> os.stat_result:
                if "imported client.key" in label:
                    raise REMOTE.RemoteInstallError("injected TOCTOU replacement")
                return original(directory_fd, name, data, mode, label)

            with stack, self.exchange_stack(), mock.patch.object(
                REMOTE, "_atomic_nofollow_at", side_effect=flaky
            ):
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "TOCTOU"):
                    self.run_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=emitted["receipt"],
                        secret={
                            name: emitted["secret"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_SECRET_NAMES
                        },
                        public={
                            name: emitted["public"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                        },
                        proof_client_dir=proof_dir,
                    )
            self.assertFalse(proof_dir.exists())

    def test_existing_destination_is_not_replaced(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            proof_dir.mkdir()
            (proof_dir / "client.key").write_bytes(b"old-secret")
            os.chmod(proof_dir / "client.key", 0o600)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "replacement"):
                    self.run_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=emitted["receipt"],
                        secret={
                            name: emitted["secret"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_SECRET_NAMES
                        },
                        public={
                            name: emitted["public"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                        },
                        proof_client_dir=proof_dir,
                    )
            self.assertEqual((proof_dir / "client.key").read_bytes(), b"old-secret")

    def test_export_refuses_existing_gateway_keys(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            creds.mkdir(mode=0o700)
            os.chmod(creds, 0o700)
            (creds / REMOTE.STATIC_KEY_NAME).write_bytes(b"aa" * 32)
            os.chmod(creds / REMOTE.STATIC_KEY_NAME, 0o600)
            with stack, self.exchange_stack():
                self.accepted(control_root, data_root)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "overwrite existing"):
                    self.run_action(
                        "exchange-data-emit",
                        role="data-winn3",
                        instance="proof-winn3-a1",
                        exchange_root=data_root,
                        credentials_dir=creds,
                        gateway_binary=binary,
                    )

    def test_emit_after_provision_reuses_hold_and_wipes_export_secrets(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                receipt = REMOTE.provision_proof_keys(
                    role="data-winn3",
                    gateway_binary=binary,
                    credentials_dir=creds,
                )
                self.assertTrue(receipt["generated"])
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                retry = REMOTE.provision_proof_keys(
                    role="data-winn3",
                    gateway_binary=binary,
                    credentials_dir=creds,
                )
            self.assertEqual(
                emitted["secret"]["client.key"], files["client.key"].decode("ascii")
            )
            self.assertEqual(
                emitted["public"]["static.pub"], files["static.pub"].decode("ascii")
            )
            self.assert_no_secrets(emitted["receipt"], files)
            hold = creds / REMOTE.PROOF_KEY_HOLD_NAME
            self.assertFalse((hold / "client.key").exists())
            self.assertFalse((hold / "client.pub").exists())
            self.assertEqual((hold / "static.pub").read_bytes(), files["static.pub"])
            self.assertEqual((creds / REMOTE.STATIC_KEY_NAME).read_bytes(), files["static.key"])
            self.assertEqual(
                stat.S_IMODE((creds / REMOTE.STATIC_KEY_NAME).stat().st_mode),
                REMOTE.PROOF_KEY_INSTALL_MODE,
            )
            self.assertFalse((creds / "client.key").exists())
            self.assertFalse(retry["generated"])

    def test_extra_and_missing_keygen_files_are_refused(self) -> None:
        extra = keygen_fixture_bytes()
        extra["extra.key"] = b"aa" * 32
        missing = keygen_fixture_bytes()
        del missing["client.pub"]
        for files, pattern in ((extra, "omitted or added"), (missing, "omitted or added")):
            with tempfile.TemporaryDirectory() as name:
                workspace = Path(name)
                control_root = workspace / "control" / "key-exchange-v1"
                data_root = workspace / "data" / "key-exchange-v1"
                stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
                with stack, self.exchange_stack():
                    self.accepted(control_root, data_root)
                    with self.assertRaisesRegex(REMOTE.RemoteInstallError, pattern):
                        self.run_action(
                            "exchange-data-emit",
                            role="data-winn3",
                            instance="proof-winn3-a1",
                            exchange_root=data_root,
                            credentials_dir=creds,
                            gateway_binary=binary,
                        )

    def test_world_writable_exchange_dir_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            with self.exchange_stack():
                self.run_action(
                    "exchange-identity",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
                os.chmod(root, 0o777)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "writable|mode"):
                    self.run_action(
                        "exchange-status",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )

    def test_production_exchange_root_is_refused_off_root(self) -> None:
        self.assertNotEqual(os.geteuid(), 0)
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "test-only host"):
            REMOTE.run_exchange_action(
                "exchange-identity",
                role="control",
                instance="proof-control-a1",
                **proof_binding(),
            )


    def test_same_gce_instance_ids_are_refused(self) -> None:
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "distinct"):
            REMOTE._exchange_binding(
                **proof_binding(source_instance_id="1234567890", target_instance_id="1234567890")
            )

    def test_same_boot_ids_are_refused(self) -> None:
        with self.assertRaisesRegex(REMOTE.RemoteInstallError, "distinct"):
            REMOTE._exchange_binding(
                **proof_binding(
                    source_boot_id=PROOF_SOURCE_BOOT_ID, target_boot_id=PROOF_SOURCE_BOOT_ID
                )
            )

    def test_full_binding_fields_are_on_every_event(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            control_root = Path(name) / "control" / "key-exchange-v1"
            data_root = Path(name) / "data" / "key-exchange-v1"
            with self.exchange_stack():
                control_ch, data_ch = self.challenged(control_root, data_root)
                offer = self.run_action(
                    "exchange-control-offer",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    peer=data_ch["receipt"],
                )
                accept = self.run_action(
                    "exchange-data-accept",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    peer=offer["receipt"],
                )
                for key, digest in (
                    ("bundle_sha256", "1" * 64),
                    ("manifest_sha256", "2" * 64),
                    ("helper_sha256", "3" * 64),
                    ("plan_sha256", "4" * 64),
                    ("apply_sha256", "5" * 64),
                    ("source_instance_id", "1111111111111111111"),
                    ("target_instance_id", "2222222222222222222"),
                    ("source_boot_id", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
                    ("target_boot_id", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
                ):
                    with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale or cross-run"):
                        self.run_action(
                            "exchange-status",
                            role="control",
                            instance="proof-control-a1",
                            exchange_root=control_root,
                            **{key: digest},
                        )
            for payload in (
                control_ch["receipt"],
                data_ch["receipt"],
                offer["receipt"],
                accept["receipt"],
            ):
                self.assert_full_binding(payload)
            on_disk = REMOTE.strict_json(
                (control_root / "00-identity.json").read_bytes(), "identity event"
            )
            self.assert_full_binding(on_disk)
            self.assertEqual(
                offer["receipt"]["peer_challenge_sha256"], data_ch["receipt"]["event_sha256"]
            )
            self.assertEqual(
                offer["receipt"]["challenge_sha256"], control_ch["receipt"]["event_sha256"]
            )
            self.assertEqual(
                accept["receipt"]["peer_challenge_sha256"], control_ch["receipt"]["event_sha256"]
            )
            self.assertEqual(
                accept["receipt"]["challenge_sha256"], data_ch["receipt"]["event_sha256"]
            )

    def test_same_binding_challenge_mixing_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_a = workspace / "a-control" / "key-exchange-v1"
            data_a = workspace / "a-data" / "key-exchange-v1"
            control_b = workspace / "b-control" / "key-exchange-v1"
            data_b = workspace / "b-data" / "key-exchange-v1"
            with self.exchange_stack():
                control_a_id, data_a_id = self.identities(control_a, data_a)
                control_b_id, data_b_id = self.identities(control_b, data_b)
                data_a_ch = self.run_action(
                    "exchange-challenge",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_a,
                    peer=control_a_id["receipt"],
                )
                self.run_action(
                    "exchange-challenge",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_a,
                    peer=data_a_id["receipt"],
                )
                self.run_action(
                    "exchange-challenge",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_b,
                    peer=data_b_id["receipt"],
                )
                self.run_action(
                    "exchange-challenge",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_b,
                    peer=control_b_id["receipt"],
                )
                offer_a = self.run_action(
                    "exchange-control-offer",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_a,
                    peer=data_a_ch["receipt"],
                )
                with self.assertRaisesRegex(
                    REMOTE.RemoteInstallError, REMOTE.EXCHANGE_MIXING_ERROR
                ):
                    self.run_action(
                        "exchange-control-offer",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_b,
                        peer=data_a_ch["receipt"],
                    )
                with self.assertRaisesRegex(
                    REMOTE.RemoteInstallError, REMOTE.EXCHANGE_MIXING_ERROR
                ):
                    self.run_action(
                        "exchange-data-accept",
                        role="data-winn3",
                        instance="proof-winn3-a1",
                        exchange_root=data_b,
                        peer=offer_a["receipt"],
                    )

    def test_concurrent_identity_writes_are_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            barrier = threading.Barrier(2)
            results: list[str] = []
            lock = threading.Lock()

            def worker() -> None:
                barrier.wait(timeout=5)
                try:
                    self.run_action(
                        "exchange-identity",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )
                    outcome = "ok"
                except REMOTE.RemoteInstallError as suc:
                    outcome = str(suc)
                with lock:
                    results.append(outcome)

            with self.exchange_stack(), ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(worker), pool.submit(worker)]
                for item in futures:
                    item.result(timeout=10)
            self.assertEqual(results.count("ok"), 1)
            self.assertTrue(any("replacement" in item for item in results))

    def test_crash_temp_recovery_order_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            with self.exchange_stack():
                first = self.run_action(
                    "exchange-identity",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
                identity = (root / "00-identity.json").read_bytes()
                temps = (
                    ".00-identity.json.aaaaaaaaaaaaaaaa",
                    ".zz-last.json.bbbbbbbbbbbbbbbb",
                    ".01-challenge.json.cccccccccccccccc",
                    ".02-control-offer.json.dddddddddddddddd",
                )
                for temp_name in temps:
                    (root / temp_name).write_bytes(b"crashed-temp")
                    os.chmod(root / temp_name, 0o600)
                status = self.run_action(
                    "exchange-status",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
            self.assertEqual(status["receipt"]["completed_actions"], ["exchange-identity"])
            self.assertEqual(first["action"], "exchange-identity")
            self.assertEqual((root / "00-identity.json").read_bytes(), identity)
            remaining = {item.name for item in root.iterdir()}
            self.assertEqual(remaining, {"00-identity.json"})

    def test_event_owner_mode_nlink_inode_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "key-exchange-v1"
            outside = Path(name) / "identity.link"
            with self.exchange_stack():
                self.run_action(
                    "exchange-identity",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=root,
                )
                event_path = root / "00-identity.json"
                before = event_path.stat()
                os.chmod(event_path, 0o644)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "mode is unsafe"):
                    self.run_action(
                        "exchange-status",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )
                os.chmod(event_path, REMOTE.EXCHANGE_EVENT_MODE)
                os.link(event_path, outside)
                self.assertEqual(event_path.stat().st_nlink, 2)
                self.assertEqual(event_path.stat().st_ino, before.st_ino)
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "single-link"):
                    self.run_action(
                        "exchange-status",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=root,
                    )

    def test_pathname_swap_during_import_does_not_follow(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            attacker = workspace / "attacker"
            attacker.mkdir()
            decoy = attacker / "client.key"
            decoy.write_bytes(b"attacker-secret")
            os.chmod(decoy, 0o600)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            original = REMOTE._mkdir_exclusive_at

            def swap_after_mkdir(
                parent_fd: int, dir_name: str, mode: int, label: str
            ) -> int:
                child = original(parent_fd, dir_name, mode, label)
                if "proof client credentials directory" in label:
                    os.rename(proof_dir, workspace / "proof-client.real")
                    os.symlink(attacker, proof_dir)
                return child

            with stack, self.exchange_stack(), mock.patch.object(
                REMOTE, "_mkdir_exclusive_at", side_effect=swap_after_mkdir
            ):
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "changed while being used"):
                    self.run_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=emitted["receipt"],
                        secret={
                            name: emitted["secret"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_SECRET_NAMES
                        },
                        public={
                            name: emitted["public"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                        },
                        proof_client_dir=proof_dir,
                    )
            self.assertEqual(decoy.read_bytes(), b"attacker-secret")
            self.assertFalse((attacker / "admission.key").exists())
            self.assertFalse((attacker / "client.key").read_bytes() == files["client.key"])

    def test_rollback_after_pathname_swap_does_not_unlink_attacker(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            attacker = workspace / "attacker"
            attacker.mkdir()
            decoy = attacker / "client.key"
            decoy.write_bytes(b"keep-me")
            os.chmod(decoy, 0o600)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            original = REMOTE._atomic_nofollow_at

            def swap_and_fail(
                directory_fd: int,
                file_name: str,
                data: bytes,
                mode: int,
                label: str,
            ) -> os.stat_result:
                written = original(directory_fd, file_name, data, mode, label)
                if "imported admission.key" in label:
                    if proof_dir.exists() and not proof_dir.is_symlink():
                        os.rename(proof_dir, workspace / "proof-client.real")
                        os.symlink(attacker, proof_dir)
                    raise REMOTE.RemoteInstallError("injected rollback")
                return written

            with stack, self.exchange_stack(), mock.patch.object(
                REMOTE, "_atomic_nofollow_at", side_effect=swap_and_fail
            ):
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "injected rollback"):
                    self.run_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=emitted["receipt"],
                        secret={
                            name: emitted["secret"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_SECRET_NAMES
                        },
                        public={
                            name: emitted["public"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                        },
                        proof_client_dir=proof_dir,
                    )
            self.assertEqual(decoy.read_bytes(), b"keep-me")
            self.assertTrue(decoy.exists())
            self.assertFalse((attacker / "admission.key").exists())

    def _open_dir(self, path: Path, *, dir_fd: int | None = None) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY
        if dir_fd is None:
            return os.open(path, flags)
        return os.open(os.fspath(path), flags, dir_fd=dir_fd)

    def _plant_after_mkdir(self, kind: str) -> Any:
        original_mkdir = REMOTE.os.mkdir

        def plant(name: str, mode: int = 0o777, *, dir_fd: int | None = None) -> None:
            original_mkdir(name, mode, dir_fd=dir_fd)
            os.rename(name, f"{name}.held", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            if kind == "symlink":
                os.symlink("attacker-target", name, dir_fd=dir_fd)
                return
            planted = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=dir_fd,
            )
            os.close(planted)

        return plant

    def _assert_sanitized_unsafe(self, exc: BaseException, label: str) -> None:
        self.assertIsInstance(exc, REMOTE.RemoteInstallError)
        self.assertEqual(str(exc), f"{label} is unsafe")
        self.assertIsInstance(exc.__cause__, OSError)
        self.assertNotIn("attacker-target", str(exc))
        self.assertNotIn("Errno", str(exc))

    def test_rollback_rmdir_requires_matching_live_inode(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            held = parent / "dest"
            held.mkdir(mode=0o700)
            (held / "client.key").write_bytes(b"secret")
            os.chmod(held / "client.key", 0o600)
            parent_fd = self._open_dir(parent)
            directory_fd = self._open_dir("dest", dir_fd=parent_fd)
            try:
                os.rename(held, parent / "dest.held")
                swapped = parent / "dest"
                swapped.mkdir(mode=0o700)
                swapped_inode = swapped.stat().st_ino
                self.assertNotEqual(os.fstat(directory_fd).st_ino, swapped_inode)
                REMOTE._rollback_at(
                    directory_fd=directory_fd,
                    names=["client.key"],
                    parent_fd=parent_fd,
                    directory_name="dest",
                )
                self.assertTrue(swapped.is_dir())
                self.assertFalse(swapped.is_symlink())
                self.assertEqual(swapped.stat().st_ino, swapped_inode)
                self.assertEqual(list(swapped.iterdir()), [])
                self.assertTrue((parent / "dest.held").is_dir())
                self.assertFalse((parent / "dest.held" / "client.key").exists())
            finally:
                os.close(directory_fd)
                os.close(parent_fd)

    def test_rollback_rmdir_when_live_inode_matches_held(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            held = parent / "dest"
            held.mkdir(mode=0o700)
            (held / "client.key").write_bytes(b"secret")
            os.chmod(held / "client.key", 0o600)
            parent_fd = self._open_dir(parent)
            directory_fd = self._open_dir("dest", dir_fd=parent_fd)
            try:
                held_inode = os.fstat(directory_fd).st_ino
                self.assertEqual(held.stat().st_ino, held_inode)
                REMOTE._rollback_at(
                    directory_fd=directory_fd,
                    names=["client.key"],
                    parent_fd=parent_fd,
                    directory_name="dest",
                )
                self.assertFalse(held.exists())
            finally:
                os.close(directory_fd)
                os.close(parent_fd)

    def test_rollback_after_empty_directory_swap_does_not_rmdir_victim(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            original = REMOTE._atomic_nofollow_at
            swapped_inode = {"value": 0}

            def swap_empty_and_fail(
                directory_fd: int,
                file_name: str,
                data: bytes,
                mode: int,
                label: str,
            ) -> os.stat_result:
                if "imported auth_ed25519.pub" in label:
                    if proof_dir.exists() and not proof_dir.is_symlink():
                        os.rename(proof_dir, workspace / "proof-client.real")
                        proof_dir.mkdir(mode=0o700)
                        swapped_inode["value"] = proof_dir.stat().st_ino
                    raise REMOTE.RemoteInstallError("injected rollback")
                return original(directory_fd, file_name, data, mode, label)

            with stack, self.exchange_stack(), mock.patch.object(
                REMOTE, "_atomic_nofollow_at", side_effect=swap_empty_and_fail
            ):
                self.accepted(control_root, data_root)
                emitted = self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "injected rollback"):
                    self.run_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        peer=emitted["receipt"],
                        secret={
                            name: emitted["secret"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_SECRET_NAMES
                        },
                        public={
                            name: emitted["public"][name].encode("ascii")
                            for name in REMOTE.EXCHANGE_PUBLIC_EMIT_NAMES
                        },
                        proof_client_dir=proof_dir,
                    )
            self.assertTrue(proof_dir.is_dir())
            self.assertFalse(proof_dir.is_symlink())
            self.assertEqual(proof_dir.stat().st_ino, swapped_inode["value"])
            self.assertEqual(list(proof_dir.iterdir()), [])
            real = workspace / "proof-client.real"
            self.assertTrue(real.is_dir())
            self.assertFalse((real / "admission.key").exists())
            self.assertFalse((real / "client.key").exists())

    def test_mkdir_to_open_symlink_or_file_swap_is_sanitized(self) -> None:
        label = "proof client credentials directory"
        for kind in ("symlink", "file"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as name:
                parent = Path(name)
                parent_fd = self._open_dir(parent)
                try:
                    with mock.patch.object(
                        REMOTE.os, "mkdir", side_effect=self._plant_after_mkdir(kind)
                    ), mock.patch.object(REMOTE.os, "chown"):
                        with self.assertRaises(REMOTE.RemoteInstallError) as caught:
                            REMOTE._mkdir_exclusive_at(parent_fd, "proof-client", 0o700, label)
                    self._assert_sanitized_unsafe(caught.exception, label)
                    with mock.patch.object(
                        REMOTE.os, "mkdir", side_effect=self._plant_after_mkdir(kind)
                    ), mock.patch.object(REMOTE.os, "chown"):
                        with self.assertRaises(REMOTE.RemoteInstallError) as created:
                            REMOTE._open_or_create_dir_at(
                                parent_fd, f"creds-{kind}", 0o700, "gateway credentials directory"
                            )
                    self._assert_sanitized_unsafe(
                        created.exception, "gateway credentials directory"
                    )
                finally:
                    os.close(parent_fd)

    def test_descended_mkdir_to_open_symlink_swap_is_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "root"
            root.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            with mock.patch.object(
                REMOTE.os, "mkdir", side_effect=self._plant_after_mkdir("symlink")
            ), mock.patch.object(REMOTE.os, "chown"):
                with self.assertRaises(REMOTE.RemoteInstallError) as caught:
                    REMOTE._open_descended_dir(
                        root, ("child",), "key exchange directory", create=True
                    )
            self._assert_sanitized_unsafe(caught.exception, "key exchange directory")

    def test_mkdir_to_open_oserror_emits_sanitized_json_refusal(self) -> None:
        label = "proof client credentials directory"
        argv = [
            "--action",
            "exchange-identity",
            "--bundle",
            "bundle",
            "--bundle-sha256",
            "b" * 64,
            "--manifest",
            "manifest",
            "--manifest-sidecar",
            "sidecar",
            "--manifest-sha256",
            "d" * 64,
            "--helper-sha256",
            "c" * 64,
            "--plan-sha256",
            "e" * 64,
            "--apply-sha256",
            "a" * 64,
            "--fleet-id",
            "proof-fleet-20260823",
            "--role",
            "control",
            "--instance",
            "proof-control-a1",
            "--previous-record-sha256",
            "0" * 64,
        ]
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            parent_fd = self._open_dir(parent)
            stdout = io.BytesIO()

            def invoke(_args: Any) -> dict[str, Any]:
                REMOTE._mkdir_exclusive_at(parent_fd, "proof-client", 0o700, label)
                raise AssertionError("mkdir-to-open must refuse before returning")

            try:
                with mock.patch.object(
                    REMOTE.os, "mkdir", side_effect=self._plant_after_mkdir("symlink")
                ), mock.patch.object(REMOTE.os, "chown"), mock.patch.object(
                    REMOTE, "run_exchange", side_effect=invoke
                ), mock.patch.object(
                    REMOTE.sys, "stdout", SimpleNamespace(buffer=stdout)
                ):
                    code = REMOTE.main(argv)
            finally:
                os.close(parent_fd)
        self.assertEqual(code, 2)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(
            payload,
            {
                "kind": REMOTE.KIND_RESPONSE,
                "marker_updated": False,
                "ok": False,
                "refusal": f"{label} is unsafe",
                "schema_version": 1,
            },
        )
        self.assertNotIn("attacker-target", payload["refusal"])
        self.assertNotIn("Errno", payload["refusal"])

    def test_consume_rollback_removes_registry_without_path_reopen(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            registry = workspace / "winn3-peers.json"
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            original = REMOTE._write_event

            def fail_consume_event(
                directory_fd: int,
                action: str,
                payload: Any,
                secrets: Any,
            ) -> dict[str, Any]:
                if action == "exchange-data-consume":
                    raise REMOTE.RemoteInstallError("injected consume crash")
                return original(directory_fd, action, payload, secrets)

            with stack, self.exchange_stack(), mock.patch.object(
                REMOTE, "_write_event", side_effect=fail_consume_event
            ):
                self.accepted(control_root, data_root)
                self.run_action(
                    "exchange-data-emit",
                    role="data-winn3",
                    instance="proof-winn3-a1",
                    exchange_root=data_root,
                    credentials_dir=creds,
                    gateway_binary=binary,
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "injected consume crash"):
                    self.run_action(
                        "exchange-data-consume",
                        role="data-winn3",
                        instance="proof-winn3-a1",
                        exchange_root=data_root,
                        public={"client.pub": files["client.pub"]},
                        peer_registry_path=registry,
                    )
            self.assertFalse(registry.exists())

    def test_import_adopts_template_only_proof_client_dir(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root, data_root, proof_dir, files, binary, creds
                )
            self.assertEqual(imported["action"], "exchange-control-import")
            self.assertEqual((proof_dir / "client.key").read_bytes(), files["client.key"])
            self.assertEqual(
                (proof_dir / "awg0.conf").read_bytes(),
                (TOOLS / "gcp_proof_attempt_broker" / "awg0.conf.example").read_bytes(),
            )
            self.assertEqual(
                set(os.listdir(proof_dir)),
                set(ATTEMPT_CONFIG_NAMES) | {name for name, _size in REMOTE.EXCHANGE_CONTROL_CREDENTIALS},
            )

    def test_seal_allows_template_configs_without_provision(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                self.emit_and_import(
                    control_root, data_root, proof_dir, files, binary, creds
                )
                sealed = self.run_action(
                    "exchange-control-seal",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    proof_client_dir=proof_dir,
                )
            self.assertTrue(sealed["receipt"]["action"] == "exchange-control-seal")
            self.assertEqual(
                (proof_dir / "winn3-probe.env").read_bytes(),
                (TOOLS / "gcp_proof_attempt_broker" / "winn3-probe.env").read_bytes(),
            )

    def test_seal_provision_writes_fleet_bound_configs_without_leaking_secrets(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root,
                    data_root,
                    proof_dir,
                    files,
                    binary,
                    creds,
                    hex_fleet=True,
                )
                provision = attempt_provision_document(imported["receipt"]["binding_sha256"])
                sealed = self.hex_action(
                    "exchange-control-seal",
                    role="control",
                    instance="proof-control-a1",
                    exchange_root=control_root,
                    proof_client_dir=proof_dir,
                    attempt_provision=provision,
                    fleet_binding=control_fleet_binding(),
                )
            encoded = REMOTE.canonical_bytes(sealed)
            self.assertNotIn(ATTEMPT_AWG_PRIVATE.encode("ascii"), encoded)
            self.assertNotIn(ATTEMPT_XRAY_UUID.encode("ascii"), encoded)
            event = (control_root / REMOTE.EXCHANGE_EVENT_FILES["exchange-control-seal"]).read_bytes()
            self.assertNotIn(ATTEMPT_AWG_PRIVATE.encode("ascii"), event)
            self.assertNotIn(ATTEMPT_XRAY_UUID.encode("ascii"), event)
            env = (proof_dir / "winn3-probe.env").read_text("ascii")
            self.assertIn("WINN3_PROOF_GW=10.240.0.10:443\n", env)
            self.assertIn("WINN3_PROOF_GATEWAY_ID=proof-winn3-a1\n", env)
            self.assertIn("WINN3_PROOF_ED_PUB=" + files["auth_ed25519.pub"].decode("ascii"), env)
            self.assertIn("WINN3_PROOF_ML_PUB=" + files["auth_mldsa65.pub"].decode("ascii"), env)
            awg = (proof_dir / "awg0.conf").read_text("ascii")
            self.assertIn(f"PrivateKey = {ATTEMPT_AWG_PRIVATE}\n", awg)
            self.assertIn(f"PublicKey = {ATTEMPT_AWG_PEER}\n", awg)
            self.assertIn("Endpoint = 10.240.0.20:51820\n", awg)
            self.assertNotIn("192.0.2.", awg)
            xray = REMOTE.strict_json(
                (proof_dir / "xray-client.json").read_bytes(), "xray"
            )
            self.assertEqual(xray["inbounds"][0]["settings"]["name"], "xray0")
            outbound = xray["outbounds"][0]
            self.assertEqual(outbound["protocol"], "vless")
            self.assertEqual(outbound["settings"]["vnext"][0]["address"], "10.240.0.20")
            self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["id"], ATTEMPT_XRAY_UUID)
            self.assertEqual(
                (proof_dir / "xray-probe.env").read_bytes(),
                b"XRAY_PROOF_PEER=10.10.0.1\n",
            )

    def test_seal_event_failure_restores_all_prior_attempt_configs(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            originals = {
                item.name: item.read_bytes()
                for item in proof_dir.iterdir()
                if item.name in REMOTE.ATTEMPT_BROKER_CONFIG_NAMES
            }
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root,
                    data_root,
                    proof_dir,
                    files,
                    binary,
                    creds,
                    hex_fleet=True,
                )
                provision = attempt_provision_document(imported["receipt"]["binding_sha256"])
                real_write_event = REMOTE._write_event

                def fail_seal_event(*args: Any, **kwargs: Any) -> Any:
                    if args[1] == "exchange-control-seal":
                        raise REMOTE.RemoteInstallError("injected seal event failure")
                    return real_write_event(*args, **kwargs)

                with mock.patch.object(REMOTE, "_write_event", side_effect=fail_seal_event):
                    with self.assertRaisesRegex(
                        REMOTE.RemoteInstallError, "injected seal event failure"
                    ):
                        self.hex_action(
                            "exchange-control-seal",
                            role="control",
                            instance="proof-control-a1",
                            exchange_root=control_root,
                            proof_client_dir=proof_dir,
                            attempt_provision=provision,
                            fleet_binding=control_fleet_binding(),
                        )
            self.assertEqual(
                {
                    item.name: item.read_bytes()
                    for item in proof_dir.iterdir()
                    if item.name in REMOTE.ATTEMPT_BROKER_CONFIG_NAMES
                },
                originals,
            )
            self.assertFalse(
                (control_root / REMOTE.EXCHANGE_EVENT_FILES["exchange-control-seal"]).exists()
            )

    def test_seal_provision_keeps_secrets_on_held_directory_after_path_swap(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            held_dir = workspace / "proof-client-held"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root,
                    data_root,
                    proof_dir,
                    files,
                    binary,
                    creds,
                    hex_fleet=True,
                )
                provision = attempt_provision_document(imported["receipt"]["binding_sha256"])
                real_provision = REMOTE._provision_attempt_broker_configs

                def swap_path_then_provision(**kwargs: Any) -> dict[str, bytes]:
                    proof_dir.rename(held_dir)
                    write_attempt_templates(proof_dir)
                    return real_provision(**kwargs)

                with mock.patch.object(
                    REMOTE,
                    "_provision_attempt_broker_configs",
                    side_effect=swap_path_then_provision,
                ):
                    self.hex_action(
                        "exchange-control-seal",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        proof_client_dir=proof_dir,
                        attempt_provision=provision,
                        fleet_binding=control_fleet_binding(),
                    )
            self.assertIn(
                f"PrivateKey = {ATTEMPT_AWG_PRIVATE}\n",
                (held_dir / "awg0.conf").read_text("ascii"),
            )
            self.assertNotIn(
                ATTEMPT_AWG_PRIVATE,
                (proof_dir / "awg0.conf").read_text("ascii"),
            )
            self.assertNotIn(
                ATTEMPT_XRAY_UUID,
                (proof_dir / "xray-client.json").read_text("ascii"),
            )

    def test_seal_provision_refuses_documentation_endpoints(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root,
                    data_root,
                    proof_dir,
                    files,
                    binary,
                    creds,
                    hex_fleet=True,
                )
                provision = attempt_provision_document(
                    imported["receipt"]["binding_sha256"],
                    winn3_gateway="192.0.2.10:443",
                )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "unprovisioned"):
                    self.hex_action(
                        "exchange-control-seal",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        proof_client_dir=proof_dir,
                        attempt_provision=provision,
                        fleet_binding=control_fleet_binding(),
                    )
            self.assertEqual(
                (proof_dir / "winn3-probe.env").read_bytes(),
                (TOOLS / "gcp_proof_attempt_broker" / "winn3-probe.env").read_bytes(),
            )

    def test_seal_provision_refuses_fleet_and_binding_mismatch(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            data_root = workspace / "data" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, binary, _keygen, creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                imported = self.emit_and_import(
                    control_root,
                    data_root,
                    proof_dir,
                    files,
                    binary,
                    creds,
                    hex_fleet=True,
                )
                digest = imported["receipt"]["binding_sha256"]
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "not bound to this fleet"):
                    self.hex_action(
                        "exchange-control-seal",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        proof_client_dir=proof_dir,
                        attempt_provision=attempt_provision_document(
                            digest, fleet_id="abcdef123456"
                        ),
                        fleet_binding=control_fleet_binding(),
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "stale or cross-run"):
                    self.hex_action(
                        "exchange-control-seal",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        proof_client_dir=proof_dir,
                        attempt_provision=attempt_provision_document("ab" * 32),
                        fleet_binding=control_fleet_binding(),
                    )

    def test_attempt_provision_is_seal_only(self) -> None:
        files = keygen_fixture_bytes()
        with tempfile.TemporaryDirectory() as name:
            workspace = Path(name)
            control_root = workspace / "control" / "key-exchange-v1"
            proof_dir = workspace / "proof-client"
            write_attempt_templates(proof_dir)
            stack, _binary, _keygen, _creds = self.keygen_stack(workspace, files)
            with stack, self.exchange_stack():
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "seal-only"):
                    self.hex_action(
                        "exchange-identity",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        attempt_provision=attempt_provision_document("ab" * 32),
                    )
                with self.assertRaisesRegex(REMOTE.RemoteInstallError, "seal-only"):
                    self.hex_action(
                        "exchange-control-import",
                        role="control",
                        instance="proof-control-a1",
                        exchange_root=control_root,
                        proof_client_dir=proof_dir,
                        attempt_provision=attempt_provision_document("ab" * 32),
                    )


if __name__ == "__main__":
    unittest.main()
