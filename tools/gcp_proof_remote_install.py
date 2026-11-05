#!/usr/bin/env python3
"""Root-side verifier and installer for a controlled WinsVPN GCP proof step.

This program is copied separately from the manifest-only deployment bundle.  It
never accepts an arbitrary command.  The only executable action is one member
of the fixed installer sequence below, selected by its numeric index.

Winn v3 gateway order is install, then explicit on-VM proof key provision,
then preflight, then start.  Gateway ELF bytes stay bound to the producer
gateway_artifact record and are copied atomically to the installer staging
path.  Authenticated key exchange v1 is the only control-role credential
channel.  It uses fixed action primitives, canonical bounded ASCII JSON,
root-owned descriptor walks, immutable no-replace event files, fsync
boundaries, crash recovery, and exact rollback.  Control retains client.key.
data-winn3 retains static.key, admission.key, and dual-auth private seeds and
receives only client.pub.  Secret material moves on stdin/stdout only and
never appears in argv, logs, errors, or receipts.  Tar/archive key
provisioning is refused.  Attempt-broker AWG/Winn3/Xray client files shipped
in the closure are unprovisioned templates.  Live configs are rendered only
from fleet binding plus exchanged credentials and an authenticated provision
document; placeholders and documentation endpoints fail closed.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import hmac
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Mapping, Sequence


KIND_MANIFEST = "winsvpn.gcp_proof.deployment_inputs.v1"
KIND_RESPONSE = "winsvpn.gcp_proof.remote_install_response.v1"
KIND_RECORD = "winsvpn.gcp_proof.deployment_step_record.v1"
KIND_MARKER = "winsvpn.gcp_proof.deployment_identity.v1"
KIND_HELPER_IDENTITY = "winsvpn.gcp_proof.remote_action_helper_install.v1"
KIND_ATTEMPT_BROKER_IDENTITY = "winsvpn.gcp_proof.attempt_broker_install.v1"
KIND_ATTEMPT_PROVISION = "winsvpn.gcp_proof.attempt_broker_provision.v1"
KIND_EXCHANGE_BINDING = "winsvpn.gcp_proof.authenticated_key_exchange_binding.v1"
KIND_EXCHANGE_EVENT = "winsvpn.gcp_proof.authenticated_key_exchange_event.v1"
KIND_EXCHANGE_RECEIPT = "winsvpn.gcp_proof.authenticated_key_exchange_receipt.v1"
KIND_EXCHANGE_RESPONSE = "winsvpn.gcp_proof.authenticated_key_exchange_response.v1"
KIND_EXCHANGE_SECRET = "winsvpn.gcp_proof.authenticated_key_exchange_secret.v1"
SCHEMA_VERSION = 1
CLOSURE_POLICY = "winsvpn-gcp-deployment-closure-v1"
SCOPE_ROOTS = ("server", "router", "winn_protocol_experimental")
MARKER_PATH = Path("/var/lib/winsvpn-proof/deployment-identity.json")
STATE_ROOT = Path("/var/lib/winsvpn-proof")
INSTANCE_ID_PATH = STATE_ROOT / "instance-id"
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
DMI_PRODUCT_SERIAL_PATH = Path("/sys/class/dmi/id/product_serial")
REMOTE_ACTION_HELPER_PATH = "tools/gcp_proof_remote_action.py"
REMOTE_ACTION_HELPER_CONTRACT = "winsvpn-gcp-proof-remote-action-v1"
REMOTE_ACTION_HELPER_INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-remote"
REMOTE_ACTION_HELPER_INSTALL_FILE = Path(REMOTE_ACTION_HELPER_INSTALL_PATH)
REMOTE_ACTION_HELPER_IDENTITY_PATH = Path(
    "/var/lib/winsvpn-proof/remote-action-helper.json"
)
REMOTE_ACTION_HELPER_IDENTITY_CONTRACT = (
    "winsvpn-gcp-proof-remote-action-helper-install-v1"
)
REMOTE_ACTION_HELPER_INSTALL_MODE = 0o555
REMOTE_ACTION_HELPER_REQUIRED_ROLES = ("control", "data-cover", "data-winn3")
REMOTE_ACTION_HELPER_KEYS = {
    "bytes",
    "contract",
    "install_path",
    "mode",
    "path",
    "required_roles",
    "schema_version",
    "sha256",
}
REMOTE_ACTION_HELPER_IDENTITY_KEYS = {
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
}
ATTEMPT_BROKER_PATH = "tools/gcp_proof_attempt_broker.py"
ATTEMPT_BROKER_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-request-v1"
ATTEMPT_BROKER_INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker"
ATTEMPT_BROKER_INSTALL_FILE = Path(ATTEMPT_BROKER_INSTALL_PATH)
ATTEMPT_BROKER_IDENTITY_PATH = Path("/var/lib/winsvpn-proof/attempt-broker.json")
ATTEMPT_BROKER_IDENTITY_CONTRACT = "winsvpn-gcp-proof-attempt-broker-install-v1"
ATTEMPT_BROKER_INSTALL_MODE = 0o555
ATTEMPT_BROKER_REQUIRED_ROLES = ("control",)
ATTEMPT_BROKER_ROLE_PATH = Path("/etc/winsvpn/role")
ATTEMPT_BROKER_FLEET_BINDING_PATH = Path("/var/lib/winsvpn-proof/fleet-binding.json")
ATTEMPT_BROKER_FLEET_BINDING_CONTRACT = "winsvpn-gcp-proof-fleet-binding-v1"
ATTEMPT_BROKER_SOCKET_SOURCE = (
    "tools/gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.socket"
)
ATTEMPT_BROKER_SERVICE_SOURCE = (
    "tools/gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.service"
)
ATTEMPT_BROKER_SOCKET_INSTALL_PATH = (
    "/etc/systemd/system/winsvpn-gcp-proof-attempt-broker.socket"
)
ATTEMPT_BROKER_SERVICE_INSTALL_PATH = (
    "/etc/systemd/system/winsvpn-gcp-proof-attempt-broker.service"
)
ATTEMPT_BROKER_UNIT_ROOT = Path("/etc/systemd/system")
ATTEMPT_BROKER_CONFIG_ROOT = Path("/etc/winn/proof-client")
ATTEMPT_BROKER_UNITS: tuple[tuple[str, str, str], ...] = (
    (
        "tools/gcp_proof_attempt_broker/winsvpn-proof-winn3-probe.service",
        "/etc/systemd/system/winsvpn-proof-winn3-probe.service",
        "winsvpn-proof-winn3-probe.service",
    ),
    (
        "tools/gcp_proof_attempt_broker/winsvpn-proof-awg-client.service",
        "/etc/systemd/system/winsvpn-proof-awg-client.service",
        "winsvpn-proof-awg-client.service",
    ),
    (
        "tools/gcp_proof_attempt_broker/winsvpn-proof-xray-client.service",
        "/etc/systemd/system/winsvpn-proof-xray-client.service",
        "winsvpn-proof-xray-client.service",
    ),
    (
        "tools/gcp_proof_attempt_broker/winsvpn-proof-xray-probe.service",
        "/etc/systemd/system/winsvpn-proof-xray-probe.service",
        "winsvpn-proof-xray-probe.service",
    ),
)
ATTEMPT_BROKER_CONFIGS: tuple[tuple[str, str, str], ...] = (
    (
        "tools/gcp_proof_attempt_broker/winn3-probe.env",
        "/etc/winn/proof-client/winn3-probe.env",
        "winn3-probe.env",
    ),
    (
        "tools/gcp_proof_attempt_broker/awg0.conf.example",
        "/etc/winn/proof-client/awg0.conf",
        "awg0.conf",
    ),
    (
        "tools/gcp_proof_attempt_broker/xray-client.json",
        "/etc/winn/proof-client/xray-client.json",
        "xray-client.json",
    ),
    (
        "tools/gcp_proof_attempt_broker/xray-probe.env",
        "/etc/winn/proof-client/xray-probe.env",
        "xray-probe.env",
    ),
)
ATTEMPT_BROKER_CONFIG_NAMES = frozenset(name for _src, _dst, name in ATTEMPT_BROKER_CONFIGS)
ATTEMPT_PROVISION_CONTRACT = "winsvpn-gcp-proof-attempt-broker-provision-v1"
ATTEMPT_PROVISION_KEYS = {
    "awg_endpoint",
    "awg_peer_public_key",
    "awg_private_key",
    "binding_sha256",
    "contract",
    "fleet_id",
    "kind",
    "schema_version",
    "winn3_gateway",
    "xray_address",
    "xray_path",
    "xray_port",
    "xray_uuid",
}
ATTEMPT_PROVISION_SECRET_NAMES = ("awg_private_key", "xray_uuid")
AWG_KEY_RE = re.compile(r"[A-Za-z0-9+/]{42,44}={0,2}\Z")
# A WireGuard/AWG key in its usual base64 form, wherever it appears.
AWG_KEY_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/]{43}=")
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
XRAY_PATH_RE = re.compile(r"/[A-Za-z0-9._~/-]{0,63}\Z")
DOCUMENTATION_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
ATTEMPT_BROKER_MEMBER_KEYS = {
    "bytes",
    "install_path",
    "mode",
    "name",
    "path",
    "sha256",
}
ATTEMPT_BROKER_KEYS = {
    "bytes",
    "configs",
    "contract",
    "install_path",
    "mode",
    "path",
    "required_roles",
    "schema_version",
    "service",
    "sha256",
    "socket",
    "units",
}
ATTEMPT_BROKER_IDENTITY_KEYS = {
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
}
ATTEMPT_BROKER_FLEET_BINDING_KEYS = {
    "schema_version",
    "contract",
    "project",
    "fleet_id",
    "control",
    "data-winn3",
    "data-cover",
}
ATTEMPT_BROKER_MEMBER_INSTANCE_KEYS = {"instance", "zone"}
ATTEMPT_BROKER_UNIT_MARKERS = {
    "winsvpn-proof-winn3-probe.service": b"ExecStart=/usr/local/bin/winn3-probe",
    "winsvpn-proof-awg-client.service": b"ExecStart=/usr/local/bin/amneziawg-go",
    "winsvpn-proof-xray-client.service": b"ExecStart=/usr/local/bin/xray",
    "winsvpn-proof-xray-probe.service": b"ExecStart=/usr/bin/ping",
}
ATTEMPT_BROKER_FLEET_ID_RE = re.compile(r"[a-f0-9]{12}\Z")
ATTEMPT_BROKER_INSTANCE_RE = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?\Z")
ATTEMPT_BROKER_ZONE_RE = re.compile(r"[a-z]+-[a-z]+[0-9]+-[a-z]\Z")
WINN3_PROBE_ENV_KEYS = (
    "WINN3_PROOF_GW",
    "WINN3_PROOF_GATEWAY_ID",
    "WINN3_PROOF_ED_PUB",
    "WINN3_PROOF_ML_PUB",
)
XRAY_PROBE_ENV_KEYS = ("XRAY_PROOF_PEER",)
ENV_LINE_RE = re.compile(r"([A-Z][A-Z0-9_]*)=(.*)\Z")
HEX3904_RE = re.compile(r"[0-9a-f]{3904}\Z")
ID_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
IPV4_PORT_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d):[1-9][0-9]{0,4}\Z"
)
IPV4_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\Z"
)
GATEWAY_STAGING_DIR = Path("/root/wins-onetouch-staging/winn3")
GATEWAY_STAGED_BIN_NAME = "winn3-gateway"
GATEWAY_INSTALL_PATH = Path("/usr/local/libexec/winn/winn3-gateway")
PROBE_INSTALL_PATH = Path("/usr/local/bin/winn3-probe")
ECH_KEYGEN_INSTALL_PATH = Path("/usr/local/libexec/winn/winn-ech-keygen")
WINN_CREDENTIALS_DIR = Path("/etc/winn/credentials")
STATIC_KEY_NAME = "winn3-gateway-static.key"
ADMISSION_KEY_NAME = "winn3-gateway-admission.key"
DUAL_AUTH_ED_KEY_NAME = "winn3-gateway-auth-ed25519.seed"
DUAL_AUTH_ML_SEED_NAME = "winn3-gateway-auth-mldsa65.seed"
WINN3_PEER_REGISTRY_PATH = Path("/etc/winn/winn3-peers.json")
PROOF_CLIENT_CREDENTIALS_DIR = Path("/etc/winn/proof-client")
PROOF_KEY_PROVISION_ID = "winsvpn.gcp_proof.winn3_on_vm_key_provision.v1"
PROOF_KEY_PROVISION_FLAG = "--on-vm-generate"
CONTROL_ADMISSION_EVIDENCE_CHANNEL = (
    "authenticated key exchange v1 control-role evidence channel for proof-only "
    "static.pub and opaque admission.key"
)
CONTROL_ADMISSION_EXTERNAL_INPUT = (
    "owner-authenticated delivery of on-VM proof-only static.pub and "
    "admission.key to the control role via authenticated key exchange v1; "
    "gateway static.key remains non-exportable on data-winn3"
)
OWNER_CLOUD_EVIDENCE_BLOCKED = (
    "BLOCKED: owner/cloud GCE instance identity is absent"
)
PROOF_KEY_INSTALL_MODE = 0o400
PROOF_KEY_HOLD_NAME = "proof-key-hold"
PROOF_KEY_EXPORT_HOLD_NAMES = ("client.key", "client.pub")
PROOF_KEY_OVERWRITE_ERROR = (
    "refusing to overwrite existing gateway key material; "
    "proof keys are generated once on a fresh data-winn3 VM"
)
EXCHANGE_CONTRACT = "winsvpn-gcp-proof-authenticated-key-exchange-v1"
EXCHANGE_DIRNAME = "key-exchange-v1"
EXCHANGE_ROOT = STATE_ROOT / EXCHANGE_DIRNAME
EXCHANGE_TTL_SECONDS = 300
EXCHANGE_SKEW_SECONDS = 30
EXCHANGE_MAX_BYTES = 64 * 1024
EXCHANGE_EVENT_MODE = 0o400
EXCHANGE_DIR_MODE = 0o700
EXCHANGE_CREDENTIAL_MODE = 0o400
PROOF_CLIENT_INNER_V4 = "10.10.0.2"
PROOF_CLIENT_INNER_PREFIX = ipaddress.IPv4Network("10.10.0.0/24")
PROOF_GATEWAY_INNER_V4 = ipaddress.IPv4Address("10.10.0.1")
INSTALLER_ACTIONS = ("step", "finalize")
EXCHANGE_ACTIONS = (
    "exchange-identity",
    "exchange-challenge",
    "exchange-control-offer",
    "exchange-data-accept",
    "exchange-data-emit",
    "exchange-control-import",
    "exchange-data-consume",
    "exchange-control-seal",
    "exchange-status",
)
EXCHANGE_ROLE_ACTIONS = {
    "control": {
        "exchange-identity",
        "exchange-challenge",
        "exchange-control-offer",
        "exchange-control-import",
        "exchange-control-seal",
        "exchange-status",
    },
    "data-winn3": {
        "exchange-identity",
        "exchange-challenge",
        "exchange-data-accept",
        "exchange-data-emit",
        "exchange-data-consume",
        "exchange-status",
    },
}
EXCHANGE_EVENT_FILES = {
    "exchange-identity": "00-identity.json",
    "exchange-challenge": "01-challenge.json",
    "exchange-control-offer": "02-control-offer.json",
    "exchange-data-accept": "03-data-accept.json",
    "exchange-data-emit": "04-data-emit.json",
    "exchange-control-import": "05-control-import.json",
    "exchange-data-consume": "06-data-consume.json",
    "exchange-control-seal": "07-control-seal.json",
}
EXCHANGE_PRIORS = {
    "exchange-identity": (),
    "exchange-challenge": ("exchange-identity",),
    "exchange-control-offer": ("exchange-identity", "exchange-challenge"),
    "exchange-data-accept": ("exchange-identity", "exchange-challenge"),
    "exchange-data-emit": (
        "exchange-identity",
        "exchange-challenge",
        "exchange-data-accept",
    ),
    "exchange-control-import": (
        "exchange-identity",
        "exchange-challenge",
        "exchange-control-offer",
    ),
    "exchange-data-consume": (
        "exchange-identity",
        "exchange-challenge",
        "exchange-data-accept",
        "exchange-data-emit",
    ),
    "exchange-control-seal": (
        "exchange-identity",
        "exchange-challenge",
        "exchange-control-offer",
        "exchange-control-import",
    ),
    "exchange-status": (),
}
EXCHANGE_CONTROL_CREDENTIALS: tuple[tuple[str, int], ...] = (
    ("admission.key", 64),
    ("auth_ed25519.pub", 64),
    ("auth_mldsa65.pub", 3904),
    ("client.key", 64),
    ("static.pub", 64),
)
EXCHANGE_SECRET_NAMES = ("admission.key", "client.key")
EXCHANGE_PUBLIC_EMIT_NAMES = (
    "auth_ed25519.pub",
    "auth_mldsa65.pub",
    "client.pub",
    "static.pub",
)
EXCHANGE_GATEWAY_SECRETS = (
    "admission.key",
    "auth_ed25519.seed",
    "auth_mldsa65.seed",
    "client.key",
    "static.key",
)
EXCHANGE_BINDING_SHA_KEYS = (
    "apply_sha256",
    "bundle_sha256",
    "helper_sha256",
    "manifest_sha256",
    "plan_sha256",
)
EXCHANGE_BINDING_KEYS = {
    "apply_sha256",
    "binding_sha256",
    "bundle_sha256",
    "candidate_id",
    "contract",
    "fleet_id",
    "helper_sha256",
    "inner_v4",
    "kind",
    "manifest_sha256",
    "plan_sha256",
    "schema_version",
    "source_boot_id",
    "source_instance",
    "source_instance_id",
    "source_role",
    "target_boot_id",
    "target_instance",
    "target_instance_id",
    "target_role",
}
EXCHANGE_COMMON_EVENT_KEYS = {
    "action",
    "apply_sha256",
    "binding_sha256",
    "bundle_sha256",
    "candidate_id",
    "contract",
    "created_utc",
    "event_sha256",
    "expires_utc",
    "fleet_id",
    "helper_sha256",
    "inner_v4",
    "instance",
    "kind",
    "manifest_sha256",
    "nonce",
    "plan_sha256",
    "role",
    "schema_version",
    "skew_seconds",
    "source_boot_id",
    "source_instance",
    "source_instance_id",
    "source_role",
    "target_boot_id",
    "target_instance",
    "target_instance_id",
    "target_role",
    "ttl_seconds",
}
EXCHANGE_IDENTITY_KEYS = set(EXCHANGE_COMMON_EVENT_KEYS)
EXCHANGE_CHALLENGE_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "identity_sha256",
    "peer_instance",
    "peer_nonce",
    "peer_role",
    "peer_sha256",
}
EXCHANGE_OFFER_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "challenge_sha256",
    "identity_sha256",
    "peer_challenge_sha256",
    "peer_instance",
    "peer_nonce",
    "peer_role",
    "peer_sha256",
}
EXCHANGE_ACCEPT_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "challenge_sha256",
    "identity_sha256",
    "offer_sha256",
    "peer_challenge_sha256",
}
EXCHANGE_EMIT_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "accept_sha256",
    "challenge_sha256",
    "identity_sha256",
    "peer_challenge_sha256",
    "public_names",
    "public_sha256",
}
EXCHANGE_IMPORT_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "challenge_sha256",
    "credential_names",
    "credentials_dir",
    "emit_sha256",
    "identity_sha256",
    "offer_sha256",
    "peer_challenge_sha256",
}
EXCHANGE_CONSUME_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "challenge_sha256",
    "client_pub_sha256",
    "emit_sha256",
    "identity_sha256",
    "peer_challenge_sha256",
    "peer_count",
    "peer_registry_path",
}
EXCHANGE_SEAL_KEYS = EXCHANGE_COMMON_EVENT_KEYS | {
    "challenge_sha256",
    "credential_names",
    "credentials_dir",
    "identity_sha256",
    "import_sha256",
    "peer_challenge_sha256",
}
EXCHANGE_STATUS_KEYS = {
    "action",
    "apply_sha256",
    "binding_sha256",
    "bundle_sha256",
    "candidate_id",
    "completed_actions",
    "contract",
    "expires_utc",
    "fleet_id",
    "helper_sha256",
    "inner_v4",
    "instance",
    "kind",
    "manifest_sha256",
    "plan_sha256",
    "role",
    "schema_version",
    "sealed",
    "skew_seconds",
    "source_boot_id",
    "source_instance",
    "source_instance_id",
    "source_role",
    "target_boot_id",
    "target_instance",
    "target_instance_id",
    "target_role",
    "ttl_seconds",
}
EXCHANGE_RECEIPT_KEYS = {
    "action",
    "apply_sha256",
    "binding_sha256",
    "bundle_sha256",
    "candidate_id",
    "contract",
    "created_utc",
    "event_sha256",
    "expires_utc",
    "fleet_id",
    "helper_sha256",
    "inner_v4",
    "instance",
    "kind",
    "manifest_sha256",
    "plan_sha256",
    "role",
    "schema_version",
    "source_boot_id",
    "source_instance",
    "source_instance_id",
    "source_role",
    "target_boot_id",
    "target_instance",
    "target_instance_id",
    "target_role",
}
EXCHANGE_MIXING_ERROR = "same-binding cross-session mixing is refused"
EXCHANGE_RESPONSE_KEYS = {
    "action",
    "contract",
    "kind",
    "public",
    "receipt",
    "schema_version",
    "secret",
}
EXCHANGE_SECRET_KEYS = {"admission.key", "client.key"}
EXCHANGE_PUBLIC_KEYS = {
    "auth_ed25519.pub",
    "auth_mldsa65.pub",
    "client.pub",
    "static.pub",
}
EXCHANGE_CONSUME_PUBLIC_KEYS = {"client.pub"}
EXCHANGE_TEMP_RE = re.compile(r"\.[A-Za-z0-9._-]+\.[0-9a-f]{16}\Z")
EXCHANGE_ARCHIVE_RE = re.compile(r"(?i).+\.(tar|tgz|tar\.gz|zip|cpio|7z)\Z")
LEGACY_TAR_NAME = "proof-client-transfer.tar"
KEYGEN_FILE_SIZES = {
    "static.key": 64,
    "static.pub": 64,
    "admission.key": 64,
    "client.key": 64,
    "client.pub": 64,
    "auth_ed25519.seed": 128,
    "auth_ed25519.pub": 64,
    "auth_mldsa65.seed": 64,
    "auth_mldsa65.pub": 3904,
}
GATEWAY_PRIVATE_INSTALL = (
    ("static.key", STATIC_KEY_NAME),
    ("admission.key", ADMISSION_KEY_NAME),
    ("auth_ed25519.seed", DUAL_AUTH_ED_KEY_NAME),
    ("auth_mldsa65.seed", DUAL_AUTH_ML_SEED_NAME),
)
HEX_EXACT = {
    64: re.compile(rb"[0-9a-f]{64}\Z"),
    128: re.compile(rb"[0-9a-f]{128}\Z"),
    3904: re.compile(rb"[0-9a-f]{3904}\Z"),
}
GATEWAY_PRODUCT = "winn3-gateway"
PROOF_CLIENT_PRODUCTS = (GATEWAY_PRODUCT, "winn3-probe", "winn-ech-keygen")
PROOF_CLIENT_NAME_RES = {
    product: re.compile(rf"{re.escape(product)}-linux-(amd64|arm64)\Z")
    for product in PROOF_CLIENT_PRODUCTS
}
GATEWAY_NAME_RE = PROOF_CLIENT_NAME_RES[GATEWAY_PRODUCT]
GATEWAY_MACHINES = {"amd64": 62, "arm64": 183}
ELF_CLASS_64 = 2
ELF_DATA_LSB = 1
ET_EXEC = 2
ET_DYN = 3
GATEWAY_ARTIFACT_KEYS = {
    "architecture",
    "elf_class",
    "elf_data",
    "elf_machine",
    "elf_type",
    "entry",
    "os",
    "path",
    "product",
    "runtime",
    "sha256",
}
PROOF_CLIENT_ARTIFACT_KEYS = GATEWAY_ARTIFACT_KEYS
CLIENT_RUNTIME_PRODUCTS = ("amneziawg-go", "awg", "xray")
CLIENT_RUNTIME_NAME_RES = {
    product: re.compile(rf"{re.escape(product)}-linux-amd64\Z")
    for product in CLIENT_RUNTIME_PRODUCTS
}
CLIENT_RUNTIME_PROVENANCE_KEYS = {
    "commit",
    "repository",
    "source_sha256",
    "tag",
}
CLIENT_RUNTIME_ARTIFACT_KEYS = PROOF_CLIENT_ARTIFACT_KEYS | {
    "bytes",
    "mode",
    "provenance",
}
CLIENT_RUNTIME_INSTALL_PATHS = {
    "amneziawg-go": Path("/usr/local/bin/amneziawg-go"),
    "awg": Path("/usr/local/bin/awg"),
    "xray": Path("/usr/local/bin/xray"),
}
MANIFEST_KEYS = {
    "attempt_broker",
    "candidate_id",
    "client_runtime_artifacts",
    "closure_policy",
    "created_utc",
    "external_pins",
    "gateway_artifact",
    "inputs",
    "installers",
    "kind",
    "publication_authorized",
    "proof_client_artifacts",
    "remote_action_helper",
    "schema_version",
    "scope_roots",
}
CREATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
MAX_CAPTURE_BYTES = 1024 * 1024
ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
SAFE_FLEET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
GCE_INSTANCE_ID_RE = re.compile(r"[1-9][0-9]{0,31}\Z")
DMI_INSTANCE_RE = re.compile(r"GoogleCloud-([1-9][0-9]{0,31})\Z")
SECRET_RE = re.compile(
    rb"(?i)(-----BEGIN [^-\r\n]{0,40}PRIVATE KEY-----|"
    rb"\bAIza[0-9A-Za-z_-]{20,}|\bya29\.[0-9A-Za-z._-]+|"
    rb"(?:access[_-]?token|admin[_-]?token|api[_-]?key|client[_-]?secret|"
    rb"private[_-]?key|password|authorization)\s*[:=]\s*[^\s,;]+)"
)
GATEWAY_INSTALLER = "server/wins_winn3_gateway_install.sh"
EXPECTED_STEPS: tuple[tuple[str, str, str], ...] = (
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--preflight"),
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-winn3", GATEWAY_INSTALLER, "--install"),
    ("data-winn3", PROOF_KEY_PROVISION_ID, PROOF_KEY_PROVISION_FLAG),
    ("data-winn3", GATEWAY_INSTALLER, "--preflight"),
    ("data-winn3", GATEWAY_INSTALLER, "--start"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
)


class RemoteInstallError(RuntimeError):
    """The remote deployment step is unauthenticated or unsafe."""


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _nofollow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if flag == 0:
        raise RemoteInstallError("O_NOFOLLOW is required")
    return flag


def _cloexec_flag() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _directory_nofollow_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise RemoteInstallError("O_DIRECTORY is required")
    return os.O_RDONLY | directory | _cloexec_flag() | _nofollow_flag()


def _regular_nofollow_flags(access: int) -> int:
    return access | _cloexec_flag() | _nofollow_flag()


def _stat_identity(
    item: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_nlink,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IFMT(item.st_mode),
        stat.S_IMODE(item.st_mode),
    )


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RemoteInstallError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def strict_json(data: bytes, label: str) -> Any:
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteInstallError(f"{label} is not strict ASCII JSON") from exc
    return value


def _safe_sha(label: str, value: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise RemoteInstallError(f"{label} is not a SHA-256 digest")
    return value


def _safe_name(label: str, value: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise RemoteInstallError(f"{label} is unsafe")
    return value


def _safe_fleet(value: str) -> str:
    if not SAFE_FLEET_RE.fullmatch(value):
        raise RemoteInstallError("fleet id is unsafe")
    return value


def _safe_gce_id(label: str, value: str) -> str:
    if not isinstance(value, str) or not GCE_INSTANCE_ID_RE.fullmatch(value):
        raise RemoteInstallError(f"{label} is not a GCE numeric instance id")
    return value


def _safe_boot_id(label: str, value: str) -> str:
    if not isinstance(value, str) or not BOOT_ID_RE.fullmatch(value):
        raise RemoteInstallError(f"{label} is not a boot id")
    return value


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise RemoteInstallError(f"{label} is not a relative POSIX path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or pure.as_posix() != value or any(
        part in {"", ".", ".."} for part in pure.parts
    ):
        raise RemoteInstallError(f"{label} is not a canonical relative POSIX path")
    return value


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RemoteInstallError(f"{label} schema is invalid")
    return value


def _exact_int(value: object, label: str, *, minimum: int | None = None) -> int:
    if type(value) is not int:
        raise RemoteInstallError(f"{label} is not an exact integer")
    if minimum is not None and value < minimum:
        raise RemoteInstallError(f"{label} is out of range")
    return value


def _is_proof_key_provision(script: str, flag: str) -> bool:
    return script == PROOF_KEY_PROVISION_ID and flag == PROOF_KEY_PROVISION_FLAG


def final_role_step_indices() -> frozenset[int]:
    last: dict[str, int] = {}
    for index, (role, _script, _flag) in enumerate(EXPECTED_STEPS):
        last[role] = index
    return frozenset(last.values())


def required_completed_indices(role: str, step_index: int) -> list[int]:
    role_expected = [index for index, item in enumerate(EXPECTED_STEPS) if item[0] == role]
    return [index for index in role_expected if index < step_index]


def gateway_sequence() -> tuple[tuple[str, str], ...]:
    return tuple(
        (script, flag)
        for _role, script, flag in EXPECTED_STEPS
        if script in {GATEWAY_INSTALLER, PROOF_KEY_PROVISION_ID}
    )


def _read_regular(path: Path, label: str, *, expected_sha256: str | None = None) -> bytes:
    fd = -1
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise RemoteInstallError(f"{label} is not a regular single-link file")
        fd = os.open(path, _regular_nofollow_flags(os.O_RDONLY))
        opened = os.fstat(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        after = path.lstat()
    except RemoteInstallError:
        raise
    except OSError as exc:
        raise RemoteInstallError(f"{label} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if (
        _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
    ):
        raise RemoteInstallError(f"{label} changed while being read")
    data = b"".join(chunks)
    if expected_sha256 is not None and sha256_bytes(data) != expected_sha256:
        raise RemoteInstallError(f"{label} failed SHA-256 verification")
    return data


def _load_manifest(path: Path, sidecar: Path, expected_sha256: str) -> dict[str, Any]:
    _safe_sha("manifest SHA-256", expected_sha256)
    data = _read_regular(path, "deployment manifest", expected_sha256=expected_sha256)
    anchor = _read_regular(sidecar, "deployment manifest sidecar")
    if anchor != f"{expected_sha256}  {path.name}\n".encode("ascii"):
        raise RemoteInstallError("deployment manifest sidecar is invalid")
    raw = strict_json(data, "deployment manifest")
    if not isinstance(raw, dict) or set(raw) != MANIFEST_KEYS:
        raise RemoteInstallError("deployment manifest schema is invalid")
    if raw["kind"] != KIND_MANIFEST or raw["schema_version"] != 1:
        raise RemoteInstallError("deployment manifest kind or version is invalid")
    if (
        raw["closure_policy"] != CLOSURE_POLICY
        or raw["scope_roots"] != list(SCOPE_ROOTS)
        or type(raw["publication_authorized"]) is not bool
        or raw["publication_authorized"] is not False
    ):
        raise RemoteInstallError("deployment manifest policy fields are invalid")
    if not isinstance(raw["created_utc"], str) or not CREATED_RE.fullmatch(raw["created_utc"]):
        raise RemoteInstallError("deployment manifest created_utc is invalid")
    _safe_sha("deployment candidate id", raw["candidate_id"])
    if canonical_bytes(raw) != data:
        raise RemoteInstallError("deployment manifest is not canonical ASCII JSON")
    timestamp_free = {key: item for key, item in raw.items() if key not in {"candidate_id", "created_utc"}}
    if sha256_bytes(canonical_bytes(timestamp_free)) != raw["candidate_id"]:
        raise RemoteInstallError("candidate_id does not match the timestamp-free payload")
    if not isinstance(raw["inputs"], list) or not raw["inputs"]:
        raise RemoteInstallError("deployment manifest input closure is empty")
    records = _manifest_records(raw)
    _validate_installers(raw, records)
    _proof_client_bindings(raw, records)
    _client_runtime_bindings(raw, records)
    _remote_action_helper_binding(raw, records)
    _attempt_broker_binding(raw, records)
    return raw


def _manifest_records(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(manifest["inputs"]):
        if not isinstance(item, dict) or set(item) != {"bytes", "class", "mode", "path", "sha256"}:
            raise RemoteInstallError(f"manifest input {index} schema is invalid")
        path = _safe_relative(item["path"], f"manifest input {index}")
        if path in result:
            raise RemoteInstallError("manifest input path is duplicated")
        if type(item["bytes"]) is not int or item["bytes"] <= 0:
            raise RemoteInstallError("manifest input byte count is invalid")
        if type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o7777:
            raise RemoteInstallError("manifest input mode is invalid")
        _safe_sha("manifest input SHA-256", item["sha256"])
        result[path] = item
    if list(result) != sorted(result):
        raise RemoteInstallError("manifest inputs are not sorted")
    return result


def _validate_installers(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> None:
    installers = manifest["installers"]
    if not isinstance(installers, list) or not installers:
        raise RemoteInstallError("deployment installer list is incomplete")
    seen: set[str] = set()
    for index, raw in enumerate(installers):
        item = _exact_keys(raw, {"bytes", "mode", "path", "sha256"}, f"installer {index}")
        path = _safe_relative(item["path"], f"installer {index}")
        if path in seen:
            raise RemoteInstallError("deployment installer paths are invalid")
        seen.add(path)
        matching = records.get(path)
        if matching is None or any(
            item[key] != matching[key] for key in ("bytes", "mode", "sha256")
        ):
            raise RemoteInstallError(f"installer {path!r} does not match its closure input")
        if type(item["mode"]) is not int or item["mode"] & 0o022:
            raise RemoteInstallError(f"installer {path!r} is group- or world-writable")


def _proof_client_bindings(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    artifact_items = [item for item in manifest["inputs"] if item["class"] == "artifact"]
    raw_artifacts = manifest["proof_client_artifacts"]
    if (
        len(artifact_items) != len(PROOF_CLIENT_PRODUCTS)
        or not isinstance(raw_artifacts, list)
        or len(raw_artifacts) != len(PROOF_CLIENT_PRODUCTS)
    ):
        raise RemoteInstallError("manifest must bind exactly three proof-client artifacts")
    bindings: list[dict[str, Any]] = []
    for index, product in enumerate(PROOF_CLIENT_PRODUCTS):
        artifact = _exact_keys(
            raw_artifacts[index],
            PROOF_CLIENT_ARTIFACT_KEYS,
            f"proof-client artifact {index}",
        )
        path = _safe_relative(artifact["path"], f"{product} artifact path")
        digest = _safe_sha(f"{product} artifact SHA-256", str(artifact["sha256"]))
        record = records.get(path)
        closure_matches = [item for item in artifact_items if item["path"] == path]
        match = PROOF_CLIENT_NAME_RES[product].fullmatch(PurePosixPath(path).name)
        if record is None or len(closure_matches) != 1 or match is None:
            raise RemoteInstallError(f"{product} artifact is missing from the input closure")
        closure = closure_matches[0]
        architecture = match.group(1)
        runtime = f"linux-{architecture}"
        machine = GATEWAY_MACHINES[architecture]
        if (
            digest != closure["sha256"]
            or digest != record["sha256"]
            or artifact["product"] != product
            or artifact["os"] != "linux"
            or artifact["architecture"] != architecture
            or artifact["runtime"] != runtime
            or _exact_int(artifact["elf_class"], f"{product} elf_class") != ELF_CLASS_64
            or _exact_int(artifact["elf_data"], f"{product} elf_data") != ELF_DATA_LSB
            or _exact_int(artifact["elf_machine"], f"{product} elf_machine") != machine
            or _exact_int(artifact["elf_type"], f"{product} elf_type") not in {ET_EXEC, ET_DYN}
            or _exact_int(artifact["entry"], f"{product} entry", minimum=1) < 1
            or record["mode"] != closure["mode"]
            or record["bytes"] != closure["bytes"]
            or type(record["mode"]) is not int
            or record["mode"] & 0o111 == 0
            or record["mode"] & 0o022
        ):
            raise RemoteInstallError(
                f"{product} artifact identity is not bound to the deployment manifest"
            )
        bindings.append(
            {
                "artifact": dict(artifact),
                "bytes": record["bytes"],
                "mode": record["mode"],
                "path": path,
                "product": product,
                "sha256": digest,
            }
        )
    gateway = _exact_keys(
        manifest["gateway_artifact"], GATEWAY_ARTIFACT_KEYS, "gateway artifact"
    )
    if (
        len({item["path"] for item in bindings}) != len(PROOF_CLIENT_PRODUCTS)
        or len({item["sha256"] for item in bindings}) != len(PROOF_CLIENT_PRODUCTS)
        or len({item["artifact"]["architecture"] for item in bindings}) != 1
        or len({item["artifact"]["elf_machine"] for item in bindings}) != 1
    ):
        raise RemoteInstallError("proof-client artifacts are reused, mixed, or reordered")
    if gateway != bindings[0]["artifact"]:
        raise RemoteInstallError(
            "gateway compatibility artifact is not bound to proof-client artifacts"
        )
    return bindings


def _client_runtime_bindings(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    runtime_items = [
        item for item in manifest["inputs"] if item["class"] == "client-runtime"
    ]
    raw_artifacts = manifest["client_runtime_artifacts"]
    if (
        len(runtime_items) != len(CLIENT_RUNTIME_PRODUCTS)
        or not isinstance(raw_artifacts, list)
        or len(raw_artifacts) != len(CLIENT_RUNTIME_PRODUCTS)
    ):
        raise RemoteInstallError("manifest must bind exactly three client-runtime artifacts")
    bindings: list[dict[str, Any]] = []
    for index, product in enumerate(CLIENT_RUNTIME_PRODUCTS):
        artifact = _exact_keys(
            raw_artifacts[index],
            CLIENT_RUNTIME_ARTIFACT_KEYS,
            f"client-runtime artifact {index}",
        )
        path = _safe_relative(artifact["path"], f"{product} client-runtime path")
        digest = _safe_sha(
            f"{product} client-runtime SHA-256", str(artifact["sha256"])
        )
        record = records.get(path)
        closure_matches = [item for item in runtime_items if item["path"] == path]
        provenance = _exact_keys(
            artifact["provenance"],
            CLIENT_RUNTIME_PROVENANCE_KEYS,
            f"{product} client-runtime provenance",
        )
        if any(
            type(provenance[key]) is not str or not provenance[key]
            for key in CLIENT_RUNTIME_PROVENANCE_KEYS
        ):
            raise RemoteInstallError(f"{product} client-runtime provenance is invalid")
        if (
            record is None
            or len(closure_matches) != 1
            or CLIENT_RUNTIME_NAME_RES[product].fullmatch(PurePosixPath(path).name)
            is None
        ):
            raise RemoteInstallError(
                f"{product} client-runtime is missing from the input closure"
            )
        closure = closure_matches[0]
        artifact_bytes = _exact_int(
            artifact["bytes"], f"{product} client-runtime bytes", minimum=1
        )
        artifact_mode = _exact_int(
            artifact["mode"], f"{product} client-runtime mode"
        )
        if (
            digest != closure["sha256"]
            or digest != record["sha256"]
            or artifact_bytes != closure["bytes"]
            or artifact_bytes != record["bytes"]
            or artifact_mode != closure["mode"]
            or artifact_mode != record["mode"]
            or artifact["product"] != product
            or artifact["os"] != "linux"
            or artifact["architecture"] != "amd64"
            or artifact["runtime"] != "linux-amd64"
            or _exact_int(artifact["elf_class"], f"{product} elf_class")
            != ELF_CLASS_64
            or _exact_int(artifact["elf_data"], f"{product} elf_data")
            != ELF_DATA_LSB
            or _exact_int(artifact["elf_machine"], f"{product} elf_machine") != 62
            or _exact_int(artifact["elf_type"], f"{product} elf_type")
            not in {ET_EXEC, ET_DYN}
            or _exact_int(artifact["entry"], f"{product} entry", minimum=1) < 1
            or artifact_mode & 0o111 == 0
            or artifact_mode & 0o022
        ):
            raise RemoteInstallError(
                f"{product} client-runtime identity is not bound to the deployment manifest"
            )
        bindings.append(
            {
                "bytes": artifact_bytes,
                "mode": artifact_mode,
                "path": path,
                "product": product,
                "provenance": dict(provenance),
                "sha256": digest,
            }
        )
    if (
        len({item["path"] for item in bindings}) != len(CLIENT_RUNTIME_PRODUCTS)
        or len({item["sha256"] for item in bindings}) != len(CLIENT_RUNTIME_PRODUCTS)
    ):
        raise RemoteInstallError("client-runtime artifacts are reused, mixed, or reordered")
    return bindings


def _gateway_binding(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    binding = dict(_proof_client_bindings(manifest, records)[0])
    binding["gateway_artifact"] = binding.pop("artifact")
    binding.pop("product")
    return binding


def _remote_action_helper_markers(data: bytes) -> None:
    if not data.startswith(b"#!/usr/bin/python3"):
        raise RemoteInstallError("remote proof-action helper is not an executable script")
    marker = ("RESPONSE_CONTRACT = \"" + REMOTE_ACTION_HELPER_CONTRACT + "\"").encode("ascii")
    install_marker = (
        "INSTALL_PATH = \"" + REMOTE_ACTION_HELPER_INSTALL_PATH + "\""
    ).encode("ascii")
    if marker not in data or install_marker not in data:
        raise RemoteInstallError("remote proof-action helper contract identity is missing")


def _remote_action_helper_binding(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    helper = _exact_keys(
        manifest["remote_action_helper"], REMOTE_ACTION_HELPER_KEYS, "remote action helper"
    )
    path = _safe_relative(helper["path"], "remote action helper path")
    digest = _safe_sha("remote action helper SHA-256", str(helper["sha256"]))
    helper_items = [item for item in manifest["inputs"] if item["path"] == REMOTE_ACTION_HELPER_PATH]
    if len(helper_items) != 1:
        raise RemoteInstallError("manifest must bind the remote proof-action helper")
    artifact = helper_items[0]
    record = records.get(path)
    if record is None:
        raise RemoteInstallError("remote proof-action helper path is missing from the input closure")
    helper_schema = _exact_int(helper["schema_version"], "remote action helper schema_version")
    helper_mode = _exact_int(helper["mode"], "remote action helper mode")
    helper_bytes = _exact_int(helper["bytes"], "remote action helper bytes", minimum=1)
    if (
        path != REMOTE_ACTION_HELPER_PATH
        or path != artifact["path"]
        or digest != artifact["sha256"]
        or digest != record["sha256"]
        or helper_bytes != artifact["bytes"]
        or helper_bytes != record["bytes"]
        or helper_mode != artifact["mode"]
        or helper_mode != record["mode"]
        or helper["contract"] != REMOTE_ACTION_HELPER_CONTRACT
        or helper["install_path"] != REMOTE_ACTION_HELPER_INSTALL_PATH
        or helper["required_roles"] != list(REMOTE_ACTION_HELPER_REQUIRED_ROLES)
        or helper_schema != SCHEMA_VERSION
        or artifact["class"] != "tool"
        or record["class"] != "tool"
        or type(record["mode"]) is not int
        or record["mode"] & 0o022
    ):
        raise RemoteInstallError(
            "remote proof-action helper identity is not bound to the deployment manifest"
        )
    return {
        "bytes": record["bytes"],
        "contract": helper["contract"],
        "install_path": helper["install_path"],
        "mode": record["mode"],
        "path": path,
        "required_roles": list(REMOTE_ACTION_HELPER_REQUIRED_ROLES),
        "schema_version": SCHEMA_VERSION,
        "sha256": digest,
    }


def _parse_env_keys(data: bytes, keys: Sequence[str], label: str) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise RemoteInstallError(f"{label} is not ASCII") from suc
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ENV_LINE_RE.fullmatch(line)
        if match is None:
            raise RemoteInstallError(f"{label} is unprovisioned")
        key, value = match.group(1), match.group(2)
        if key in parsed or not value:
            raise RemoteInstallError(f"{label} is unprovisioned")
        parsed[key] = value
    if set(parsed) != set(keys):
        raise RemoteInstallError(f"{label} is unprovisioned")
    return parsed


def _attempt_broker_markers(data: bytes) -> None:
    if not data.startswith(b"#!/usr/bin/python3"):
        raise RemoteInstallError("protocol-attempt broker is not an executable script")
    contract_marker = (
        "ATTEMPT_REQUEST_CONTRACT = \"" + ATTEMPT_BROKER_CONTRACT + "\""
    ).encode("ascii")
    socket_marker = b'ATTEMPT_SOCKET_PATH = "/run/winsvpn-proof/protocol-attempt.sock"'
    role_marker = ('ROLE_FILE = "' + os.fspath(ATTEMPT_BROKER_ROLE_PATH) + '"').encode("ascii")
    binding_marker = (
        'FLEET_BINDING_PATH = "' + os.fspath(ATTEMPT_BROKER_FLEET_BINDING_PATH) + '"'
    ).encode("ascii")
    if (
        contract_marker not in data
        or socket_marker not in data
        or role_marker not in data
        or binding_marker not in data
    ):
        raise RemoteInstallError("protocol-attempt broker contract identity is missing")


def _attempt_member_binding(
    raw: object,
    records: Mapping[str, dict[str, Any]],
    relative: str,
    install_path: str,
    name: str,
    label: str,
) -> dict[str, Any]:
    member = _exact_keys(raw, ATTEMPT_BROKER_MEMBER_KEYS, label)
    path = _safe_relative(member["path"], f"{label} path")
    digest = _safe_sha(f"{label} SHA-256", str(member["sha256"]))
    record = records.get(path)
    matching = [item for item in records.values() if item["path"] == relative]
    member_bytes = _exact_int(member["bytes"], f"{label} bytes", minimum=1)
    member_mode = _exact_int(member["mode"], f"{label} mode")
    if (
        record is None
        or len(matching) != 1
        or path != relative
        or path != matching[0]["path"]
        or digest != matching[0]["sha256"]
        or digest != record["sha256"]
        or member_bytes != matching[0]["bytes"]
        or member_bytes != record["bytes"]
        or member_mode != matching[0]["mode"]
        or member_mode != record["mode"]
        or member["install_path"] != install_path
        or member["name"] != name
        or matching[0]["class"] != "tool"
        or record["class"] != "tool"
        or member_mode & 0o022
        or type(record["mode"]) is not int
        or record["mode"] & 0o022
    ):
        raise RemoteInstallError(f"{label} identity is not bound to the deployment manifest")
    return {
        "bytes": record["bytes"],
        "install_path": install_path,
        "mode": record["mode"],
        "name": name,
        "path": path,
        "sha256": digest,
    }


def _attempt_broker_binding(
    manifest: Mapping[str, Any], records: Mapping[str, dict[str, Any]]
) -> dict[str, Any]:
    broker = _exact_keys(manifest["attempt_broker"], ATTEMPT_BROKER_KEYS, "attempt broker")
    path = _safe_relative(broker["path"], "attempt broker path")
    digest = _safe_sha("attempt broker SHA-256", str(broker["sha256"]))
    broker_items = [item for item in manifest["inputs"] if item["path"] == ATTEMPT_BROKER_PATH]
    if len(broker_items) != 1:
        raise RemoteInstallError("manifest must bind the protocol-attempt broker")
    artifact = broker_items[0]
    record = records.get(path)
    if record is None:
        raise RemoteInstallError("protocol-attempt broker path is missing from the input closure")
    broker_schema = _exact_int(broker["schema_version"], "attempt broker schema_version")
    broker_mode = _exact_int(broker["mode"], "attempt broker mode")
    broker_bytes = _exact_int(broker["bytes"], "attempt broker bytes", minimum=1)
    if (
        path != ATTEMPT_BROKER_PATH
        or path != artifact["path"]
        or digest != artifact["sha256"]
        or digest != record["sha256"]
        or broker_bytes != artifact["bytes"]
        or broker_bytes != record["bytes"]
        or broker_mode != artifact["mode"]
        or broker_mode != record["mode"]
        or broker["contract"] != ATTEMPT_BROKER_CONTRACT
        or broker["install_path"] != ATTEMPT_BROKER_INSTALL_PATH
        or broker["required_roles"] != list(ATTEMPT_BROKER_REQUIRED_ROLES)
        or broker_schema != SCHEMA_VERSION
        or artifact["class"] != "tool"
        or record["class"] != "tool"
        or type(record["mode"]) is not int
        or record["mode"] & 0o022
    ):
        raise RemoteInstallError(
            "protocol-attempt broker identity is not bound to the deployment manifest"
        )
    socket = _attempt_member_binding(
        broker["socket"],
        records,
        ATTEMPT_BROKER_SOCKET_SOURCE,
        ATTEMPT_BROKER_SOCKET_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.socket",
        "attempt broker socket",
    )
    service = _attempt_member_binding(
        broker["service"],
        records,
        ATTEMPT_BROKER_SERVICE_SOURCE,
        ATTEMPT_BROKER_SERVICE_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.service",
        "attempt broker service",
    )
    raw_units = broker["units"]
    if not isinstance(raw_units, list) or len(raw_units) != len(ATTEMPT_BROKER_UNITS):
        raise RemoteInstallError("attempt broker units schema is incomplete")
    units: list[dict[str, Any]] = []
    for raw_unit, (relative, install_path, name) in zip(raw_units, ATTEMPT_BROKER_UNITS):
        units.append(
            _attempt_member_binding(
                raw_unit, records, relative, install_path, name, f"attempt unit {name}"
            )
        )
    raw_configs = broker["configs"]
    if not isinstance(raw_configs, list) or len(raw_configs) != len(ATTEMPT_BROKER_CONFIGS):
        raise RemoteInstallError("attempt broker configs schema is incomplete")
    configs: list[dict[str, Any]] = []
    for raw_config, (relative, install_path, name) in zip(raw_configs, ATTEMPT_BROKER_CONFIGS):
        configs.append(
            _attempt_member_binding(
                raw_config,
                records,
                relative,
                install_path,
                name,
                f"attempt config {name}",
            )
        )
    return {
        "bytes": record["bytes"],
        "configs": configs,
        "contract": broker["contract"],
        "install_path": broker["install_path"],
        "mode": record["mode"],
        "path": path,
        "required_roles": list(ATTEMPT_BROKER_REQUIRED_ROLES),
        "schema_version": SCHEMA_VERSION,
        "service": service,
        "sha256": digest,
        "socket": socket,
        "units": units,
    }


def verify_bundle(bundle: Path, expected_sha256: str, manifest: Mapping[str, Any]) -> bytes:
    _safe_sha("bundle SHA-256", expected_sha256)
    bundle_data = _read_regular(bundle, "deployment bundle", expected_sha256=expected_sha256)
    expected = _manifest_records(manifest)
    try:
        with tarfile.open(fileobj=io.BytesIO(bundle_data), mode="r:") as archive:
            members = archive.getmembers()
            names = [_safe_relative(item.name, "bundle member") for item in members]
            if names != sorted(expected) or len(names) != len(set(names)):
                raise RemoteInstallError("bundle members do not exactly match the manifest")
            for member in members:
                record = expected[member.name]
                if not member.isfile() or member.issym() or member.islnk():
                    raise RemoteInstallError("bundle contains a non-regular member")
                if member.uid != 0 or member.gid != 0 or member.size != record["bytes"]:
                    raise RemoteInstallError("bundle member metadata is invalid")
                if member.mode != record["mode"]:
                    raise RemoteInstallError("bundle member mode does not match the manifest")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RemoteInstallError("bundle member is unreadable")
                data = stream.read(record["bytes"] + 1)
                if len(data) != record["bytes"] or sha256_bytes(data) != record["sha256"]:
                    raise RemoteInstallError("bundle member content does not match the manifest")
    except (tarfile.TarError, OSError) as exc:
        raise RemoteInstallError("deployment bundle is invalid") from exc
    return bundle_data


def _extract_bundle(bundle_data: bytes, destination: Path, manifest: Mapping[str, Any]) -> None:
    expected = _manifest_records(manifest)
    if destination.exists() or destination.is_symlink():
        raise RemoteInstallError("fresh per-step extraction directory already exists")
    destination.mkdir(parents=True, mode=0o700)
    os.chown(destination, 0, 0)
    with tarfile.open(fileobj=io.BytesIO(bundle_data), mode="r:") as archive:
        for member in archive.getmembers():
            record = expected[member.name]
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            current = destination
            for part in PurePosixPath(member.name).parts[:-1]:
                current = current / part
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise RemoteInstallError("bundle extraction crossed an unsafe directory")
                os.chown(current, 0, 0)
                os.chmod(current, 0o700)
            stream = archive.extractfile(member)
            if stream is None:
                raise RemoteInstallError("bundle member is unreadable")
            data = stream.read()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target, flags, record["mode"])
            try:
                _write_all(fd, data)
                os.fchmod(fd, record["mode"])
                os.fchown(fd, 0, 0)
                os.fsync(fd)
            finally:
                os.close(fd)


def _require_safe_dir(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RemoteInstallError(f"{label} is unsafe")


def _prepare_dir(path: Path, label: str, *, mode: int) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    _require_safe_dir(path, label)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def _prepare_root_dir(path: Path, label: str) -> None:
    _prepare_dir(path, label, mode=0o700)


def _open_parent_dir_fd(parent: Path, label: str) -> int:
    try:
        before = parent.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise RemoteInstallError(f"{label} directory is unsafe")
        directory_fd = os.open(parent, _directory_nofollow_flags())
    except RemoteInstallError:
        raise
    except OSError as exc:
        raise RemoteInstallError(f"{label} directory is unsafe") from exc
    try:
        opened = os.fstat(directory_fd)
        after = parent.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(after.st_mode)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise RemoteInstallError(f"{label} directory is unsafe")
    except RemoteInstallError:
        os.close(directory_fd)
        raise
    except OSError as exc:
        os.close(directory_fd)
        raise RemoteInstallError(f"{label} directory is unsafe") from exc
    return directory_fd


def _atomic_regular_file(
    path: Path,
    data: bytes,
    mode: int,
    label: str,
    *,
    parent_mode: int = 0o700,
    exist_ok: bool = True,
) -> os.stat_result:
    parent = path.parent
    name = path.name
    if not name or "/" in name or "\x00" in name or name in {".", ".."}:
        raise RemoteInstallError(f"{label} name is unsafe")
    _prepare_dir(parent, f"{label} directory", mode=parent_mode)
    directory_fd = _open_parent_dir_fd(parent, label)
    fd = -1
    temporary = f".{name}.{os.urandom(8).hex()}"
    written: os.stat_result | None = None
    bound: os.stat_result | None = None
    try:
        if not exist_ok:
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RemoteInstallError(f"{label} replacement is forbidden")
        fd = os.open(
            temporary,
            _regular_nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(fd, data)
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        os.fsync(fd)
        written = os.fstat(fd)
        if (
            not stat.S_ISREG(written.st_mode)
            or written.st_nlink != 1
            or stat.S_IMODE(written.st_mode) != mode
            or written.st_size != len(data)
        ):
            raise RemoteInstallError(f"{label} path/hash/mode/inode is not bound")
        os.close(fd)
        fd = -1
        if exist_ok:
            os.replace(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
        else:
            os.link(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.unlink(temporary, dir_fd=directory_fd)
        temporary = ""
        os.fsync(directory_fd)
        installed_fd = os.open(
            name, _regular_nofollow_flags(os.O_RDONLY), dir_fd=directory_fd
        )
        try:
            installed_stat = os.fstat(installed_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(installed_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            finished = os.fstat(installed_fd)
            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            installed = b"".join(chunks)
            if (
                (installed_stat.st_dev, installed_stat.st_ino)
                != (written.st_dev, written.st_ino)
                or (named.st_dev, named.st_ino) != (written.st_dev, written.st_ino)
                or (finished.st_dev, finished.st_ino) != (written.st_dev, written.st_ino)
                or (after.st_dev, after.st_ino) != (written.st_dev, written.st_ino)
                or _stat_identity(installed_stat) != _stat_identity(finished)
                or _stat_identity(finished) != _stat_identity(named)
                or _stat_identity(named) != _stat_identity(after)
                or installed_stat.st_nlink != 1
                or stat.S_IMODE(installed_stat.st_mode) != mode
                or installed_stat.st_size != len(data)
                or sha256_bytes(installed) != sha256_bytes(data)
            ):
                raise RemoteInstallError(f"{label} path/hash/mode/inode is not bound")
            bound = installed_stat
        finally:
            os.close(installed_fd)
    except RemoteInstallError:
        raise
    except OSError as exc:
        if not exist_ok and getattr(exc, "errno", None) == errno.EEXIST:
            raise RemoteInstallError(f"{label} replacement is forbidden") from exc
        raise RemoteInstallError(f"{label} could not be written atomically") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        os.close(directory_fd)
        directory_fd = -1
    if written is None or bound is None:
        raise RemoteInstallError(f"{label} is not a regular file after install")
    return bound


def _bind_extracted_tree(destination: Path, manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    expected = _manifest_records(manifest)
    bound: dict[str, dict[str, Any]] = {}
    for path, record in expected.items():
        target = destination.joinpath(*PurePosixPath(path).parts)
        data = _read_regular(target, f"extracted {path}", expected_sha256=record["sha256"])
        info = target.lstat()
        if stat.S_IMODE(info.st_mode) != record["mode"] or len(data) != record["bytes"]:
            raise RemoteInstallError(f"extracted {path} path/hash/mode is not bound")
        bound[path] = record
    return bound


def _sha256sum_line(digest: str, name: str) -> bytes:
    if name != GATEWAY_STAGED_BIN_NAME or "/" in name or "\n" in name:
        raise RemoteInstallError("gateway staged checksum name is invalid")
    return f"{digest}  {name}\n".encode("ascii")


def require_complete_gateway_staging(
    destination: Path, *, expected_sha256: str, expected_mode: int
) -> None:
    binary = destination / GATEWAY_STAGED_BIN_NAME
    checksum = destination / f"{GATEWAY_STAGED_BIN_NAME}.sha256"
    if (
        destination.is_symlink()
        or not destination.is_dir()
        or binary.is_symlink()
        or checksum.is_symlink()
        or not binary.is_file()
        or not checksum.is_file()
    ):
        raise RemoteInstallError("gateway staging is incomplete")
    data = _read_regular(binary, "staged gateway binary", expected_sha256=expected_sha256)
    info = binary.lstat()
    if stat.S_IMODE(info.st_mode) != expected_mode:
        raise RemoteInstallError("staged gateway binary mode is not bound")
    expected_checksum = _sha256sum_line(expected_sha256, GATEWAY_STAGED_BIN_NAME)
    observed = _read_regular(checksum, "staged gateway checksum")
    if observed != expected_checksum or sha256_bytes(data) != expected_sha256:
        raise RemoteInstallError("staged gateway checksum does not bind the artifact")


def stage_gateway_artifact(
    extracted_root: Path,
    manifest: Mapping[str, Any],
    destination: Path = GATEWAY_STAGING_DIR,
) -> dict[str, Any]:
    records = _manifest_records(manifest)
    binding = _gateway_binding(manifest, records)
    bound = _bind_extracted_tree(extracted_root, manifest)
    source_record = bound[binding["path"]]
    if (
        source_record["sha256"] != binding["sha256"]
        or source_record["mode"] != binding["mode"]
        or source_record["bytes"] != binding["bytes"]
    ):
        raise RemoteInstallError("gateway artifact path/hash/mode is not bound")
    source = extracted_root.joinpath(*PurePosixPath(binding["path"]).parts)
    data = _read_regular(source, "gateway artifact", expected_sha256=binding["sha256"])
    info = source.lstat()
    if stat.S_IMODE(info.st_mode) != binding["mode"] or len(data) != binding["bytes"]:
        raise RemoteInstallError("gateway artifact path/hash/mode is not bound")
    _prepare_root_dir(destination, "gateway staging directory")
    staged_bin = destination / GATEWAY_STAGED_BIN_NAME
    staged_sum = destination / f"{GATEWAY_STAGED_BIN_NAME}.sha256"
    _atomic_regular_file(staged_bin, data, binding["mode"], "staged gateway binary")
    _atomic_regular_file(
        staged_sum,
        _sha256sum_line(binding["sha256"], GATEWAY_STAGED_BIN_NAME),
        0o400,
        "staged gateway checksum",
    )
    require_complete_gateway_staging(
        destination, expected_sha256=binding["sha256"], expected_mode=binding["mode"]
    )
    return {
        "bytes": binding["bytes"],
        "mode": binding["mode"],
        "path": str(staged_bin),
        "sha256": binding["sha256"],
        "source_path": binding["path"],
    }


def install_proof_client_artifact(
    extracted_root: Path,
    manifest: Mapping[str, Any],
    *,
    product: str,
    destination: Path,
) -> dict[str, Any]:
    if product not in {"winn3-probe", "winn-ech-keygen"}:
        raise RemoteInstallError("proof-client install product is invalid")
    records = _manifest_records(manifest)
    matches = [
        item for item in _proof_client_bindings(manifest, records)
        if item["product"] == product
    ]
    if len(matches) != 1:
        raise RemoteInstallError(f"{product} artifact binding is incomplete")
    binding = matches[0]
    bound = _bind_extracted_tree(extracted_root, manifest)
    source_record = bound[binding["path"]]
    if (
        source_record["sha256"] != binding["sha256"]
        or source_record["mode"] != binding["mode"]
        or source_record["bytes"] != binding["bytes"]
    ):
        raise RemoteInstallError(f"{product} artifact path/hash/mode is not bound")
    source = extracted_root.joinpath(*PurePosixPath(binding["path"]).parts)
    data = _read_regular(source, f"{product} artifact", expected_sha256=binding["sha256"])
    info = source.lstat()
    if stat.S_IMODE(info.st_mode) != binding["mode"] or len(data) != binding["bytes"]:
        raise RemoteInstallError(f"{product} artifact path/hash/mode is not bound")
    installed = _atomic_regular_file(
        destination,
        data,
        binding["mode"],
        f"installed {product} artifact",
        parent_mode=0o755,
    )
    installed_data = _read_regular(
        destination,
        f"installed {product} artifact",
        expected_sha256=binding["sha256"],
    )
    if (
        installed.st_nlink != 1
        or stat.S_IMODE(installed.st_mode) != binding["mode"]
        or len(installed_data) != binding["bytes"]
    ):
        raise RemoteInstallError(f"installed {product} artifact is not bound")
    return {
        "bytes": binding["bytes"],
        "mode": binding["mode"],
        "path": str(destination),
        "product": product,
        "sha256": binding["sha256"],
        "source_path": binding["path"],
    }


def install_client_runtime_artifacts(
    extracted_root: Path,
    manifest: Mapping[str, Any],
    *,
    destinations: Mapping[str, Path] | None = None,
) -> list[dict[str, Any]]:
    records = _manifest_records(manifest)
    bindings = _client_runtime_bindings(manifest, records)
    bound = _bind_extracted_tree(extracted_root, manifest)
    target_paths = dict(CLIENT_RUNTIME_INSTALL_PATHS if destinations is None else destinations)
    if set(target_paths) != set(CLIENT_RUNTIME_PRODUCTS):
        raise RemoteInstallError("client-runtime install destinations are incomplete")
    installed_records: list[dict[str, Any]] = []
    for binding in bindings:
        product = str(binding["product"])
        source_record = bound[str(binding["path"])]
        if any(
            source_record[key] != binding[key] for key in ("bytes", "mode", "sha256")
        ):
            raise RemoteInstallError(
                f"{product} client-runtime path/hash/mode is not bound"
            )
        source = extracted_root.joinpath(*PurePosixPath(str(binding["path"])).parts)
        data = _read_regular(
            source,
            f"{product} client-runtime",
            expected_sha256=str(binding["sha256"]),
        )
        destination = target_paths[product]
        installed = _atomic_regular_file(
            destination,
            data,
            int(binding["mode"]),
            f"installed {product} client-runtime",
            parent_mode=0o755,
        )
        installed_data = _read_regular(
            destination,
            f"installed {product} client-runtime",
            expected_sha256=str(binding["sha256"]),
        )
        if (
            installed.st_nlink != 1
            or stat.S_IMODE(installed.st_mode) != int(binding["mode"])
            or len(installed_data) != int(binding["bytes"])
        ):
            raise RemoteInstallError(
                f"installed {product} client-runtime is not bound"
            )
        installed_records.append(
            {
                "bytes": int(binding["bytes"]),
                "mode": int(binding["mode"]),
                "path": os.fspath(destination),
                "product": product,
                "sha256": str(binding["sha256"]),
                "source_path": str(binding["path"]),
            }
        )
    return installed_records


def _helper_identity_payload(
    binding: Mapping[str, Any],
    *,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    destination: Path,
    helper_info: os.stat_result,
) -> dict[str, Any]:
    return {
        "bytes": binding["bytes"],
        "candidate_id": candidate_id,
        "contract": REMOTE_ACTION_HELPER_IDENTITY_CONTRACT,
        "fleet_id": fleet_id,
        "instance": instance,
        "kind": KIND_HELPER_IDENTITY,
        "mode": REMOTE_ACTION_HELPER_INSTALL_MODE,
        "path": os.fspath(destination),
        "required_roles": list(REMOTE_ACTION_HELPER_REQUIRED_ROLES),
        "role": role,
        "schema_version": SCHEMA_VERSION,
        "sha256": binding["sha256"],
        "source_path": binding["path"],
        "st_dev": helper_info.st_dev,
        "st_ino": helper_info.st_ino,
    }


def _production_helper_paths(destination: Path, identity_path: Path) -> bool:
    dest_prod = os.fspath(destination) == REMOTE_ACTION_HELPER_INSTALL_PATH
    ident_prod = os.fspath(identity_path) == os.fspath(REMOTE_ACTION_HELPER_IDENTITY_PATH)
    if dest_prod != ident_prod:
        raise RemoteInstallError("remote proof-action helper production paths are not bound")
    return dest_prod


def _refuse_test_only_production_helper(destination: Path, identity_path: Path) -> None:
    if _production_helper_paths(destination, identity_path) and os.geteuid() != 0:
        raise RemoteInstallError("test-only host cannot emit production evidence")


def _file_has_acl(path: Path) -> bool:
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        return False
    try:
        names = listxattr(path, follow_symlinks=False)
    except (OSError, NotImplementedError, TypeError):
        return False
    for name in names:
        text = name.decode("ascii") if isinstance(name, bytes) else name
        lowered = text.lower()
        if "acl" in lowered:
            return True
    return False


def _forbid_effective_write(path: Path, label: str) -> None:
    if _file_has_acl(path):
        raise RemoteInstallError(f"{label} has an ACL")
    if os.geteuid() == 0:
        return
    try:
        writable = os.access(os.fspath(path), os.W_OK, follow_symlinks=False)
    except TypeError:
        writable = os.access(os.fspath(path), os.W_OK)
    if writable:
        raise RemoteInstallError(f"{label} is effectively writable")


def _require_helper_parent(path: Path, label: str) -> None:
    parent = path.parent
    try:
        info = parent.lstat()
    except OSError as exc:
        raise RemoteInstallError(f"{label} directory is unsafe") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RemoteInstallError(f"{label} directory is unsafe")
    if stat.S_IMODE(info.st_mode) & 0o022 and not (info.st_mode & stat.S_ISVTX):
        raise RemoteInstallError(f"{label} directory is writable")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise RemoteInstallError(f"{label} directory is not root-owned")


def _require_root_owned_regular(
    info: os.stat_result, label: str, *, mode: int, executable: bool
) -> None:
    imode = stat.S_IMODE(info.st_mode)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or imode != mode
        or imode & 0o222
        or (executable and imode & 0o111 == 0)
        or (not executable and imode & 0o111)
    ):
        raise RemoteInstallError(f"{label} ownership or mode is unsafe")


def _forbid_extra_helper_state(destination: Path, identity_path: Path) -> None:
    for path in (destination, identity_path):
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir():
            raise RemoteInstallError("remote proof-action helper directory is unsafe")
        for child in parent.iterdir():
            if child.name == path.name:
                continue
            if child.name.startswith(path.name):
                raise RemoteInstallError("extra remote proof-action helper state is forbidden")


def _load_helper_identity(path: Path) -> dict[str, Any]:
    data = _read_regular(path, "remote proof-action helper identity")
    raw = strict_json(data, "remote proof-action helper identity")
    record = _exact_keys(raw, REMOTE_ACTION_HELPER_IDENTITY_KEYS, "remote proof-action helper identity")
    if (
        record["kind"] != KIND_HELPER_IDENTITY
        or _exact_int(record["schema_version"], "helper identity schema_version") != SCHEMA_VERSION
        or record["contract"] != REMOTE_ACTION_HELPER_IDENTITY_CONTRACT
    ):
        raise RemoteInstallError("remote proof-action helper identity is stale")
    if canonical_bytes(record) != data:
        raise RemoteInstallError("remote proof-action helper identity is not canonical")
    return record


def require_complete_remote_action_helper(
    destination: Path,
    identity_path: Path,
    *,
    expected_sha256: str,
    expected_bytes: int,
    expected_mode: int,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    source_path: str,
) -> dict[str, Any]:
    _refuse_test_only_production_helper(destination, identity_path)
    dest_info = None
    ident_info = None
    try:
        dest_info = destination.lstat()
        ident_info = identity_path.lstat()
    except OSError:
        dest_info = None
        ident_info = None
    if (
        dest_info is None
        or ident_info is None
        or stat.S_ISLNK(dest_info.st_mode)
        or stat.S_ISLNK(ident_info.st_mode)
        or not stat.S_ISREG(dest_info.st_mode)
        or not stat.S_ISREG(ident_info.st_mode)
    ):
        raise RemoteInstallError("remote proof-action helper install is incomplete")
    _forbid_extra_helper_state(destination, identity_path)
    _require_helper_parent(destination, "installed remote proof-action helper")
    _require_helper_parent(identity_path, "remote proof-action helper identity")
    data = _read_regular(
        destination, "installed remote proof-action helper", expected_sha256=expected_sha256
    )
    info = destination.lstat()
    _require_root_owned_regular(
        info,
        "installed remote proof-action helper",
        mode=expected_mode,
        executable=True,
    )
    if (
        expected_mode & 0o222
        or expected_mode & 0o111 == 0
        or len(data) != expected_bytes
        or sha256_bytes(data) != expected_sha256
        or source_path != REMOTE_ACTION_HELPER_PATH
    ):
        raise RemoteInstallError("installed remote proof-action helper path/hash/mode is not bound")
    _remote_action_helper_markers(data)
    _forbid_effective_write(destination, "installed remote proof-action helper")
    identity = _load_helper_identity(identity_path)
    identity_info = identity_path.lstat()
    _require_root_owned_regular(
        identity_info,
        "remote proof-action helper identity",
        mode=0o400,
        executable=False,
    )
    identity_dev = _exact_int(identity["st_dev"], "helper identity st_dev", minimum=0)
    identity_ino = _exact_int(identity["st_ino"], "helper identity st_ino", minimum=1)
    identity_bytes = _exact_int(identity["bytes"], "helper identity bytes", minimum=1)
    identity_mode = _exact_int(identity["mode"], "helper identity mode")
    if (
        identity["path"] != os.fspath(destination)
        or identity["source_path"] != source_path
        or identity["source_path"] != REMOTE_ACTION_HELPER_PATH
        or identity["sha256"] != expected_sha256
        or identity_bytes != expected_bytes
        or identity_mode != expected_mode
        or identity["role"] != role
        or identity["fleet_id"] != fleet_id
        or identity["instance"] != instance
        or identity["candidate_id"] != candidate_id
        or identity["required_roles"] != list(REMOTE_ACTION_HELPER_REQUIRED_ROLES)
        or identity_dev != info.st_dev
        or identity_ino != info.st_ino
    ):
        raise RemoteInstallError("remote proof-action helper identity is stale")
    _forbid_effective_write(identity_path, "remote proof-action helper identity")
    return identity


def install_remote_action_helper(
    extracted_root: Path,
    manifest: Mapping[str, Any],
    *,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    destination: Path | None = None,
    identity_path: Path | None = None,
) -> dict[str, Any]:
    if role not in REMOTE_ACTION_HELPER_REQUIRED_ROLES:
        raise RemoteInstallError("unexpected role")
    _safe_fleet(fleet_id)
    _safe_name("instance", instance)
    _safe_sha("candidate id", candidate_id)
    records = _manifest_records(manifest)
    binding = _remote_action_helper_binding(manifest, records)
    bound = _bind_extracted_tree(extracted_root, manifest)
    source_record = bound[binding["path"]]
    if (
        source_record["sha256"] != binding["sha256"]
        or source_record["mode"] != binding["mode"]
        or source_record["bytes"] != binding["bytes"]
        or source_record["path"] != REMOTE_ACTION_HELPER_PATH
        or binding["install_path"] != REMOTE_ACTION_HELPER_INSTALL_PATH
        or binding["path"] != REMOTE_ACTION_HELPER_PATH
    ):
        raise RemoteInstallError("remote proof-action helper path/hash/mode is not bound")
    source = extracted_root.joinpath(*PurePosixPath(binding["path"]).parts)
    data = _read_regular(
        source, "remote proof-action helper", expected_sha256=binding["sha256"]
    )
    info = source.lstat()
    if (
        stat.S_IMODE(info.st_mode) != binding["mode"]
        or len(data) != binding["bytes"]
        or sha256_bytes(data) != binding["sha256"]
    ):
        raise RemoteInstallError("remote proof-action helper path/hash/mode is not bound")
    _remote_action_helper_markers(data)
    target = destination if destination is not None else REMOTE_ACTION_HELPER_INSTALL_FILE
    identity_file = (
        identity_path if identity_path is not None else REMOTE_ACTION_HELPER_IDENTITY_PATH
    )
    _refuse_test_only_production_helper(target, identity_file)
    if target.is_symlink() or identity_file.is_symlink():
        raise RemoteInstallError("remote proof-action helper install is unsafe")
    dest_present = target.exists()
    ident_present = identity_file.exists()
    if dest_present != ident_present:
        raise RemoteInstallError("remote proof-action helper install is incomplete")
    if dest_present and ident_present:
        return require_complete_remote_action_helper(
            target,
            identity_file,
            expected_sha256=binding["sha256"],
            expected_bytes=binding["bytes"],
            expected_mode=REMOTE_ACTION_HELPER_INSTALL_MODE,
            role=role,
            fleet_id=fleet_id,
            instance=instance,
            candidate_id=candidate_id,
            source_path=binding["path"],
        )
    helper_info = _atomic_regular_file(
        target,
        data,
        REMOTE_ACTION_HELPER_INSTALL_MODE,
        "installed remote proof-action helper",
        parent_mode=0o755,
    )
    payload = _helper_identity_payload(
        binding,
        role=role,
        fleet_id=fleet_id,
        instance=instance,
        candidate_id=candidate_id,
        destination=target,
        helper_info=helper_info,
    )
    _atomic_regular_file(
        identity_file,
        canonical_bytes(payload),
        0o400,
        "remote proof-action helper identity",
    )
    return require_complete_remote_action_helper(
        target,
        identity_file,
        expected_sha256=binding["sha256"],
        expected_bytes=binding["bytes"],
        expected_mode=REMOTE_ACTION_HELPER_INSTALL_MODE,
        role=role,
        fleet_id=fleet_id,
        instance=instance,
        candidate_id=candidate_id,
        source_path=binding["path"],
    )


def _attempt_broker_identity_payload(
    binding: Mapping[str, Any],
    *,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    destination: Path,
    broker_info: os.stat_result,
) -> dict[str, Any]:
    return {
        "bytes": binding["bytes"],
        "candidate_id": candidate_id,
        "contract": ATTEMPT_BROKER_IDENTITY_CONTRACT,
        "fleet_id": fleet_id,
        "instance": instance,
        "kind": KIND_ATTEMPT_BROKER_IDENTITY,
        "mode": ATTEMPT_BROKER_INSTALL_MODE,
        "path": os.fspath(destination),
        "required_roles": list(ATTEMPT_BROKER_REQUIRED_ROLES),
        "role": role,
        "schema_version": SCHEMA_VERSION,
        "sha256": binding["sha256"],
        "source_path": binding["path"],
        "st_dev": broker_info.st_dev,
        "st_ino": broker_info.st_ino,
    }


def _production_attempt_broker_paths(destination: Path, identity_path: Path) -> bool:
    dest_prod = os.fspath(destination) == ATTEMPT_BROKER_INSTALL_PATH
    ident_prod = os.fspath(identity_path) == os.fspath(ATTEMPT_BROKER_IDENTITY_PATH)
    if dest_prod != ident_prod:
        raise RemoteInstallError("protocol-attempt broker production paths are not bound")
    return dest_prod


def _refuse_test_only_production_attempt_broker(
    destination: Path, identity_path: Path
) -> None:
    if _production_attempt_broker_paths(destination, identity_path) and os.geteuid() != 0:
        raise RemoteInstallError("test-only host cannot emit production evidence")


def _load_attempt_broker_identity(path: Path) -> dict[str, Any]:
    data = _read_regular(path, "protocol-attempt broker identity")
    raw = strict_json(data, "protocol-attempt broker identity")
    record = _exact_keys(raw, ATTEMPT_BROKER_IDENTITY_KEYS, "protocol-attempt broker identity")
    if (
        record["kind"] != KIND_ATTEMPT_BROKER_IDENTITY
        or _exact_int(record["schema_version"], "attempt broker identity schema_version")
        != SCHEMA_VERSION
        or record["contract"] != ATTEMPT_BROKER_IDENTITY_CONTRACT
    ):
        raise RemoteInstallError("protocol-attempt broker identity is stale")
    if canonical_bytes(record) != data:
        raise RemoteInstallError("protocol-attempt broker identity is not canonical")
    return record


def _adopt_exact_regular_or_absent(
    path: Path,
    data: bytes,
    mode: int,
    label: str,
) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RemoteInstallError(f"{label} is unreadable") from exc
    effective_uid = os.geteuid()
    allowed_uids = {0} if effective_uid == 0 else {0, effective_uid}
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in allowed_uids
        or stat.S_IMODE(info.st_mode) != mode
        or _read_regular(path, label) != data
    ):
        raise RemoteInstallError(f"{label} preexisting file is not exact")
    return True


def _created_record(path: Path, info: os.stat_result) -> tuple[Path, int, int]:
    return path, int(info.st_dev), int(info.st_ino)


def _rollback_created_files(paths: Sequence[tuple[Path, int, int]]) -> None:
    failures: list[str] = []
    for path, expected_dev, expected_ino in reversed(list(paths)):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            failures.append(os.fspath(path))
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or (int(info.st_dev), int(info.st_ino)) != (expected_dev, expected_ino)
        ):
            failures.append(os.fspath(path))
            continue
        try:
            path.unlink()
        except OSError:
            failures.append(os.fspath(path))
    if failures:
        raise RemoteInstallError(
            "protocol-attempt broker rollback failed for exact created files: "
            + ", ".join(failures)
        )


def _validate_fleet_binding_payload(
    raw: Mapping[str, Any], *, role: str, fleet_id: str, instance: str
) -> dict[str, Any]:
    record = _exact_keys(dict(raw), ATTEMPT_BROKER_FLEET_BINDING_KEYS, "fleet binding")
    if (
        _exact_int(record["schema_version"], "fleet binding schema_version") != SCHEMA_VERSION
        or record["contract"] != ATTEMPT_BROKER_FLEET_BINDING_CONTRACT
        or type(record["project"]) is not str
        or not record["project"]
        or type(record["fleet_id"]) is not str
        or record["fleet_id"] != fleet_id
        or ATTEMPT_BROKER_FLEET_ID_RE.fullmatch(str(record["fleet_id"])) is None
    ):
        raise RemoteInstallError("fleet binding is stale")
    names: list[str] = []
    for member_role in ("control", "data-winn3", "data-cover"):
        member = _exact_keys(
            record[member_role],
            ATTEMPT_BROKER_MEMBER_INSTANCE_KEYS,
            f"fleet binding {member_role}",
        )
        inst = str(member["instance"])
        zone = str(member["zone"])
        if (
            ATTEMPT_BROKER_INSTANCE_RE.fullmatch(inst) is None
            or ATTEMPT_BROKER_ZONE_RE.fullmatch(zone) is None
        ):
            raise RemoteInstallError(f"fleet binding {member_role} identity is invalid")
        names.append(inst)
    if len(set(names)) != 3:
        raise RemoteInstallError("same-node fallback is forbidden")
    expected_instance = record[role]["instance"]
    if expected_instance != instance:
        raise RemoteInstallError("fleet binding instance does not match the request")
    return record


def _fleet_binding_from_args(args: argparse.Namespace) -> dict[str, Any]:
    raw_text = getattr(args, "fleet_binding_json", "")
    if type(raw_text) is not str or not raw_text:
        raise RemoteInstallError("control deployment requires a fleet binding")
    if len(raw_text.encode("ascii", errors="ignore")) != len(raw_text) or len(raw_text) > 4096:
        raise RemoteInstallError("fleet binding argument is invalid")
    raw = strict_json(raw_text.encode("ascii"), "fleet binding argument")
    if not isinstance(raw, dict):
        raise RemoteInstallError("fleet binding argument is malformed")
    return _validate_fleet_binding_payload(
        raw,
        role=args.role,
        fleet_id=args.fleet_id,
        instance=args.instance,
    )


def _require_attempt_config_bytes(data: bytes, name: str) -> None:
    if name == "winn3-probe.env":
        env = _parse_env_keys(data, WINN3_PROBE_ENV_KEYS, "Winn3 probe env")
        if IPV4_PORT_RE.fullmatch(env["WINN3_PROOF_GW"]) is None:
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        if ID_VALUE_RE.fullmatch(env["WINN3_PROOF_GATEWAY_ID"]) is None:
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        if SHA256_RE.fullmatch(env["WINN3_PROOF_ED_PUB"]) is None:
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        if HEX3904_RE.fullmatch(env["WINN3_PROOF_ML_PUB"]) is None:
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        return
    if name == "xray-probe.env":
        env = _parse_env_keys(data, XRAY_PROBE_ENV_KEYS, "Xray probe env")
        if IPV4_RE.fullmatch(env["XRAY_PROOF_PEER"]) is None:
            raise RemoteInstallError("Xray probe env is unprovisioned")
        return
    if name == "awg0.conf":
        if len(data) < 16 or b"[Interface]" not in data or b"[Peer]" not in data:
            raise RemoteInstallError("AWG client config is unprovisioned")
        # The live key arrives only through the authenticated provision record
        # at exchange-control-seal; a source template never carries one.
        if b"privatekey" in data.lower() or b"presharedkey" in data.lower():
            raise RemoteInstallError("AWG client config template carries a key")
        # A key-shaped value under any other name is still key material.
        if AWG_KEY_TOKEN_RE.search(data):
            raise RemoteInstallError("AWG client config template carries a key")
        return
    if name == "xray-client.json":
        if len(data) < 16 or b"xray0" not in data:
            raise RemoteInstallError("Xray client config is unprovisioned")
        return
    raise RemoteInstallError(f"attempt config {name} is not allowed")


def _placeholder_token(value: str) -> bool:
    if type(value) is not str or len(value) < 8:
        return True
    body = value.rstrip("=")
    return not body or len(set(body.lower())) < 2


def _require_outer_ipv4(value: str, label: str) -> str:
    if type(value) is not str or not value:
        raise RemoteInstallError(f"{label} is unprovisioned")
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError) as suc:
        raise RemoteInstallError(f"{label} is unprovisioned") from suc
    if str(address) != value:
        raise RemoteInstallError(f"{label} is unprovisioned")
    if (
        address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    ):
        raise RemoteInstallError(f"{label} is unprovisioned")
    for network in DOCUMENTATION_NETWORKS:
        if address in network:
            raise RemoteInstallError(f"{label} is unprovisioned")
    return value


def _require_outer_ipv4_port(value: str, label: str) -> str:
    if type(value) is not str or ":" not in value:
        raise RemoteInstallError(f"{label} is unprovisioned")
    host, port_text = value.rsplit(":", 1)
    _require_outer_ipv4(host, label)
    if not port_text.isdigit():
        raise RemoteInstallError(f"{label} is unprovisioned")
    port = int(port_text)
    if port < 1 or port > 65535:
        raise RemoteInstallError(f"{label} is unprovisioned")
    return value


def _require_awg_key(value: str, label: str) -> str:
    if type(value) is not str or AWG_KEY_RE.fullmatch(value) is None or _placeholder_token(value):
        raise RemoteInstallError(f"{label} is unprovisioned")
    return value


def _parse_awg_client_conf(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as suc:
        raise RemoteInstallError("AWG client config is not ASCII") from suc
    section = ""
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in {"[Interface]", "[Peer]"}:
            section = line[1:-1]
            continue
        if " = " not in line or not section:
            raise RemoteInstallError("AWG client config is unprovisioned")
        key, value = line.split(" = ", 1)
        field = f"{section}.{key}"
        if field in parsed or not value:
            raise RemoteInstallError("AWG client config is unprovisioned")
        parsed[field] = value
    required = {
        "Interface.Address",
        "Interface.PrivateKey",
        "Peer.PublicKey",
        "Peer.Endpoint",
        "Peer.AllowedIPs",
    }
    if required - set(parsed):
        raise RemoteInstallError("AWG client config is unprovisioned")
    if parsed["Interface.Address"] != PROOF_CLIENT_INNER_V4 + "/32":
        raise RemoteInstallError("AWG client config is unprovisioned")
    if parsed["Peer.AllowedIPs"] != "0.0.0.0/0":
        raise RemoteInstallError("AWG client config is unprovisioned")
    private_key = _require_awg_key(parsed["Interface.PrivateKey"], "AWG private key")
    public_key = _require_awg_key(parsed["Peer.PublicKey"], "AWG peer public key")
    if private_key == public_key:
        raise RemoteInstallError("AWG client config is unprovisioned")
    _require_outer_ipv4_port(parsed["Peer.Endpoint"], "AWG endpoint")
    return parsed


def _require_provisioned_xray_client(data: bytes) -> dict[str, Any]:
    raw = strict_json(data, "Xray client config")
    if not isinstance(raw, dict):
        raise RemoteInstallError("Xray client config is unprovisioned")
    inbounds = raw.get("inbounds")
    outbounds = raw.get("outbounds")
    if not isinstance(inbounds, list) or not isinstance(outbounds, list):
        raise RemoteInstallError("Xray client config is unprovisioned")
    has_tun = False
    for item in inbounds:
        if not isinstance(item, dict):
            raise RemoteInstallError("Xray client config is unprovisioned")
        settings = item.get("settings")
        if item.get("protocol") == "tun" and isinstance(settings, dict) and settings.get("name") == "xray0":
            has_tun = True
    has_proxy = False
    for item in outbounds:
        if not isinstance(item, dict):
            raise RemoteInstallError("Xray client config is unprovisioned")
        if item.get("protocol") in {"vless", "vmess", "trojan"}:
            settings = item.get("settings")
            if not isinstance(settings, dict):
                raise RemoteInstallError("Xray client config is unprovisioned")
            vnext = settings.get("vnext")
            if not isinstance(vnext, list) or len(vnext) != 1 or not isinstance(vnext[0], dict):
                raise RemoteInstallError("Xray client config is unprovisioned")
            address = vnext[0].get("address")
            port = vnext[0].get("port")
            users = vnext[0].get("users")
            if type(port) is not int or port < 1 or port > 65535:
                raise RemoteInstallError("Xray client config is unprovisioned")
            _require_outer_ipv4(str(address), "Xray outbound address")
            if not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict):
                raise RemoteInstallError("Xray client config is unprovisioned")
            user_id = users[0].get("id")
            if type(user_id) is not str or UUID_RE.fullmatch(user_id) is None:
                raise RemoteInstallError("Xray client config is unprovisioned")
            has_proxy = True
    if not has_tun or not has_proxy:
        raise RemoteInstallError("Xray client config is unprovisioned")
    return raw


def _hex_file_at(
    directory: Path,
    name: str,
    size: int,
    *,
    directory_fd: int | None = None,
) -> str:
    payload = (
        _read_regular_at(
            directory_fd,
            name,
            f"proof client {name}",
            expected_mode=EXCHANGE_CREDENTIAL_MODE,
        )
        if directory_fd is not None
        else _read_regular(directory / name, f"proof client {name}")
    )
    _require_hex_bytes(payload, size, f"proof client {name}")
    return payload.decode("ascii")


def _require_provisioned_attempt_config(
    data: bytes,
    name: str,
    *,
    fleet: Mapping[str, Any],
    config_root: Path,
    config_directory_fd: int | None = None,
) -> None:
    if name == "winn3-probe.env":
        env = _parse_env_keys(data, WINN3_PROBE_ENV_KEYS, "Winn3 probe env")
        _require_outer_ipv4_port(env["WINN3_PROOF_GW"], "Winn3 probe gateway")
        expected_id = str(fleet["data-winn3"]["instance"])
        if env["WINN3_PROOF_GATEWAY_ID"] != expected_id:
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        ed_pub = _hex_file_at(
            config_root, "auth_ed25519.pub", 64, directory_fd=config_directory_fd
        )
        ml_pub = _hex_file_at(
            config_root, "auth_mldsa65.pub", 3904, directory_fd=config_directory_fd
        )
        if not hmac.compare_digest(env["WINN3_PROOF_ED_PUB"], ed_pub):
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        if not hmac.compare_digest(env["WINN3_PROOF_ML_PUB"], ml_pub):
            raise RemoteInstallError("Winn3 probe env is unprovisioned")
        return
    if name == "xray-probe.env":
        env = _parse_env_keys(data, XRAY_PROBE_ENV_KEYS, "Xray probe env")
        if env["XRAY_PROOF_PEER"] != str(PROOF_GATEWAY_INNER_V4):
            raise RemoteInstallError("Xray probe env is unprovisioned")
        return
    if name == "awg0.conf":
        _parse_awg_client_conf(data)
        return
    if name == "xray-client.json":
        _require_provisioned_xray_client(data)
        return
    raise RemoteInstallError(f"attempt config {name} is not allowed")


def _load_attempt_provision(raw: Mapping[str, Any]) -> dict[str, Any]:
    record = _exact_keys(dict(raw), ATTEMPT_PROVISION_KEYS, "attempt broker provision")
    if (
        record["kind"] != KIND_ATTEMPT_PROVISION
        or record["contract"] != ATTEMPT_PROVISION_CONTRACT
        or _exact_int(record["schema_version"], "attempt broker provision schema_version")
        != SCHEMA_VERSION
        or type(record["fleet_id"]) is not str
        or type(record["binding_sha256"]) is not str
    ):
        raise RemoteInstallError("attempt broker provision is stale")
    _safe_fleet(str(record["fleet_id"]))
    _safe_sha("attempt broker provision binding", str(record["binding_sha256"]))
    _require_outer_ipv4_port(str(record["winn3_gateway"]), "Winn3 probe gateway")
    _require_outer_ipv4_port(str(record["awg_endpoint"]), "AWG endpoint")
    _require_awg_key(str(record["awg_private_key"]), "AWG private key")
    _require_awg_key(str(record["awg_peer_public_key"]), "AWG peer public key")
    if str(record["awg_private_key"]) == str(record["awg_peer_public_key"]):
        raise RemoteInstallError("AWG client config is unprovisioned")
    _require_outer_ipv4(str(record["xray_address"]), "Xray outbound address")
    port = _exact_int(record["xray_port"], "Xray outbound port", minimum=1)
    if port > 65535:
        raise RemoteInstallError("Xray outbound port is unprovisioned")
    if type(record["xray_path"]) is not str or XRAY_PATH_RE.fullmatch(str(record["xray_path"])) is None:
        raise RemoteInstallError("Xray path is unprovisioned")
    if type(record["xray_uuid"]) is not str or UUID_RE.fullmatch(str(record["xray_uuid"])) is None:
        raise RemoteInstallError("Xray uuid is unprovisioned")
    return record


def _bind_attempt_provision(
    record: Mapping[str, Any],
    binding: Mapping[str, Any],
    fleet: Mapping[str, Any],
) -> dict[str, Any]:
    if str(record["fleet_id"]) != str(binding["fleet_id"]) or str(record["fleet_id"]) != str(
        fleet["fleet_id"]
    ):
        raise RemoteInstallError("attempt broker provision is not bound to this fleet")
    if not hmac.compare_digest(str(record["binding_sha256"]), str(binding["binding_sha256"])):
        raise RemoteInstallError("stale or cross-run authenticated key exchange v1 binding")
    if str(fleet["control"]["instance"]) != str(binding["target_instance"]):
        raise RemoteInstallError("fleet binding instance does not match the request")
    if str(fleet["data-winn3"]["instance"]) != str(binding["source_instance"]):
        raise RemoteInstallError("fleet binding instance does not match the request")
    return dict(record)


def _render_winn3_probe_env(
    *, gateway: str, gateway_id: str, ed_pub: str, ml_pub: str
) -> bytes:
    return (
        f"WINN3_PROOF_GW={gateway}\n"
        f"WINN3_PROOF_GATEWAY_ID={gateway_id}\n"
        f"WINN3_PROOF_ED_PUB={ed_pub}\n"
        f"WINN3_PROOF_ML_PUB={ml_pub}\n"
    ).encode("ascii")


def _render_awg_client_conf(*, private_key: str, peer_public_key: str, endpoint: str) -> bytes:
    return (
        "[Interface]\n"
        f"Address = {PROOF_CLIENT_INNER_V4}/32\n"
        f"PrivateKey = {private_key}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {peer_public_key}\n"
        f"Endpoint = {endpoint}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    ).encode("ascii")


def _render_xray_client_conf(*, address: str, port: int, uuid: str, path: str) -> bytes:
    return canonical_bytes(
        {
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": {"name": "xray0"},
                    "tag": "tun-in",
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": address,
                                "port": port,
                                "users": [{"encryption": "none", "id": uuid}],
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": "ws",
                        "wsSettings": {"path": path},
                    },
                    "tag": "proxy",
                }
            ],
        }
    )


def _render_xray_probe_env() -> bytes:
    return f"XRAY_PROOF_PEER={PROOF_GATEWAY_INNER_V4}\n".encode("ascii")


def _provision_attempt_broker_configs(
    *,
    dest: Path,
    directory_fd: int,
    binding: Mapping[str, Any],
    fleet: Mapping[str, Any],
    provision: Mapping[str, Any],
) -> dict[str, bytes]:
    bound = _bind_attempt_provision(provision, binding, fleet)
    ed_pub = _hex_file_at(dest, "auth_ed25519.pub", 64, directory_fd=directory_fd)
    ml_pub = _hex_file_at(dest, "auth_mldsa65.pub", 3904, directory_fd=directory_fd)
    files = {
        "winn3-probe.env": _render_winn3_probe_env(
            gateway=str(bound["winn3_gateway"]),
            gateway_id=str(fleet["data-winn3"]["instance"]),
            ed_pub=ed_pub,
            ml_pub=ml_pub,
        ),
        "awg0.conf": _render_awg_client_conf(
            private_key=str(bound["awg_private_key"]),
            peer_public_key=str(bound["awg_peer_public_key"]),
            endpoint=str(bound["awg_endpoint"]),
        ),
        "xray-client.json": _render_xray_client_conf(
            address=str(bound["xray_address"]),
            port=int(bound["xray_port"]),
            uuid=str(bound["xray_uuid"]),
            path=str(bound["xray_path"]),
        ),
        "xray-probe.env": _render_xray_probe_env(),
    }
    if set(files) != ATTEMPT_BROKER_CONFIG_NAMES:
        raise RemoteInstallError("attempt config set is incomplete")
    originals = {
        name: _read_regular_at(
            directory_fd,
            name,
            f"prior attempt config {name}",
            expected_mode=EXCHANGE_CREDENTIAL_MODE,
        )
        for name in sorted(files)
    }
    try:
        for name, payload in files.items():
            _require_provisioned_attempt_config(
                payload,
                name,
                fleet=fleet,
                config_root=dest,
                config_directory_fd=directory_fd,
            )
            _atomic_nofollow_at(
                directory_fd,
                name,
                payload,
                EXCHANGE_CREDENTIAL_MODE,
                f"provisioned attempt config {name}",
                replace=True,
            )
            installed = _read_regular_at(
                directory_fd,
                name,
                f"provisioned attempt config {name}",
                expected_mode=EXCHANGE_CREDENTIAL_MODE,
            )
            if installed != payload:
                raise RemoteInstallError(
                    f"provisioned attempt config {name} path/hash/mode is not bound"
                )
    except Exception:
        _restore_attempt_broker_configs(
            dest,
            originals,
            directory_fd=directory_fd,
        )
        raise
    return originals


def _restore_attempt_broker_configs(
    dest: Path,
    originals: Mapping[str, bytes],
    *,
    directory_fd: int,
) -> None:
    failed = False
    for name in sorted(originals):
        try:
            _atomic_nofollow_at(
                directory_fd,
                name,
                originals[name],
                EXCHANGE_CREDENTIAL_MODE,
                f"restored attempt config {name}",
                replace=True,
            )
        except Exception:
            failed = True
    if failed:
        for name in sorted(originals):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except OSError:
                pass
        raise RemoteInstallError(
            "attempt broker config rollback failed closed; live configs were removed"
        )


def _proof_client_allowed_names() -> frozenset[str]:
    return frozenset(name for name, _size in EXCHANGE_CONTROL_CREDENTIALS) | ATTEMPT_BROKER_CONFIG_NAMES


def _adopt_or_create_proof_client_dir(dest: Path) -> tuple[int, int, str, bool]:
    parent = dest.parent
    if parent.exists() or parent.is_symlink():
        _require_safe_dir(parent, "proof client credentials parent")
    else:
        _prepare_dir(parent, "proof client credentials parent", mode=0o755)
    parent_fd = _open_parent_dir_fd(parent, "proof client credentials")
    leaf = _leaf_name(dest.name, "proof client credentials directory")
    created = False
    child = -1
    try:
        try:
            existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            child = _mkdir_exclusive_at(
                parent_fd, leaf, EXCHANGE_DIR_MODE, "proof client credentials directory"
            )
            created = True
            return parent_fd, child, leaf, created
        if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
            raise RemoteInstallError("proof client credentials directory replacement is forbidden")
        child = os.open(leaf, _directory_nofollow_flags(), dir_fd=parent_fd)
        _named_inode_matches(parent_fd, leaf, child, "proof client credentials directory")
        members = [
            item for item in os.listdir(child) if not EXCHANGE_TEMP_RE.fullmatch(item)
        ]
        extra = set(members) - ATTEMPT_BROKER_CONFIG_NAMES
        if extra:
            raise RemoteInstallError("proof client credentials directory replacement is forbidden")
        _require_root_owned_dir(
            os.fstat(child), "proof client credentials directory", mode=EXCHANGE_DIR_MODE
        )
        return parent_fd, child, leaf, created
    except Exception:
        if child >= 0:
            os.close(child)
        os.close(parent_fd)
        raise


def _require_bound_installed_member(
    path: Path,
    member: Mapping[str, Any],
    label: str,
    *,
    expected_mode: int,
    executable: bool,
) -> bytes:
    _require_helper_parent(path, label)
    data = _read_regular(path, label, expected_sha256=str(member["sha256"]))
    info = path.lstat()
    _require_root_owned_regular(info, label, mode=expected_mode, executable=executable)
    if (
        len(data) != int(member["bytes"])
        or sha256_bytes(data) != member["sha256"]
        or expected_mode & 0o222
    ):
        raise RemoteInstallError(f"{label} path/hash/mode is not bound")
    _forbid_effective_write(path, label)
    return data


def require_complete_attempt_broker(
    destination: Path,
    identity_path: Path,
    *,
    expected_sha256: str,
    expected_bytes: int,
    expected_mode: int,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    source_path: str,
    binding: Mapping[str, Any],
    role_path: Path,
    fleet_binding_path: Path,
    unit_root: Path,
    config_root: Path,
    require_fleet_binding: bool = True,
) -> dict[str, Any]:
    _refuse_test_only_production_attempt_broker(destination, identity_path)
    dest_info = None
    ident_info = None
    try:
        dest_info = destination.lstat()
        ident_info = identity_path.lstat()
    except OSError:
        dest_info = None
        ident_info = None
    if (
        dest_info is None
        or ident_info is None
        or stat.S_ISLNK(dest_info.st_mode)
        or stat.S_ISLNK(ident_info.st_mode)
        or not stat.S_ISREG(dest_info.st_mode)
        or not stat.S_ISREG(ident_info.st_mode)
    ):
        raise RemoteInstallError("protocol-attempt broker install is incomplete")
    _forbid_extra_helper_state(destination, identity_path)
    _require_helper_parent(destination, "installed protocol-attempt broker")
    _require_helper_parent(identity_path, "protocol-attempt broker identity")
    data = _read_regular(
        destination, "installed protocol-attempt broker", expected_sha256=expected_sha256
    )
    info = destination.lstat()
    _require_root_owned_regular(
        info,
        "installed protocol-attempt broker",
        mode=expected_mode,
        executable=True,
    )
    if (
        expected_mode & 0o222
        or expected_mode & 0o111 == 0
        or len(data) != expected_bytes
        or sha256_bytes(data) != expected_sha256
        or source_path != ATTEMPT_BROKER_PATH
    ):
        raise RemoteInstallError("installed protocol-attempt broker path/hash/mode is not bound")
    _attempt_broker_markers(data)
    _forbid_effective_write(destination, "installed protocol-attempt broker")
    identity = _load_attempt_broker_identity(identity_path)
    identity_info = identity_path.lstat()
    _require_root_owned_regular(
        identity_info,
        "protocol-attempt broker identity",
        mode=0o400,
        executable=False,
    )
    identity_dev = _exact_int(identity["st_dev"], "attempt broker identity st_dev", minimum=0)
    identity_ino = _exact_int(identity["st_ino"], "attempt broker identity st_ino", minimum=1)
    identity_bytes = _exact_int(identity["bytes"], "attempt broker identity bytes", minimum=1)
    identity_mode = _exact_int(identity["mode"], "attempt broker identity mode")
    if (
        identity["path"] != os.fspath(destination)
        or identity["source_path"] != source_path
        or identity["source_path"] != ATTEMPT_BROKER_PATH
        or identity["sha256"] != expected_sha256
        or identity_bytes != expected_bytes
        or identity_mode != expected_mode
        or identity["role"] != role
        or identity["fleet_id"] != fleet_id
        or identity["instance"] != instance
        or identity["candidate_id"] != candidate_id
        or identity["required_roles"] != list(ATTEMPT_BROKER_REQUIRED_ROLES)
        or identity_dev != info.st_dev
        or identity_ino != info.st_ino
    ):
        raise RemoteInstallError("protocol-attempt broker identity is stale")
    _forbid_effective_write(identity_path, "protocol-attempt broker identity")
    unit_members = [binding["socket"], binding["service"], *list(binding["units"])]
    for member in unit_members:
        name = str(member["name"])
        installed = unit_root / name
        payload = _require_bound_installed_member(
            installed,
            member,
            f"installed attempt unit {name}",
            expected_mode=0o444,
            executable=False,
        )
        if name.endswith(".socket"):
            if b"ListenStream=/run/winsvpn-proof/protocol-attempt.sock" not in payload:
                raise RemoteInstallError("attempt broker socket identity is missing")
        elif name == "winsvpn-gcp-proof-attempt-broker.service":
            if ("ExecStart=" + ATTEMPT_BROKER_INSTALL_PATH).encode("ascii") not in payload:
                raise RemoteInstallError("attempt broker service identity is missing")
        else:
            marker = ATTEMPT_BROKER_UNIT_MARKERS.get(name)
            if marker is None or marker not in payload:
                raise RemoteInstallError(f"attempt unit {name} identity is missing")
    fleet_record: dict[str, Any] | None = None
    if require_fleet_binding:
        fleet_data = _read_regular(fleet_binding_path, "fleet binding")
        fleet_info = fleet_binding_path.lstat()
        _require_helper_parent(fleet_binding_path, "fleet binding")
        _require_root_owned_regular(
            fleet_info, "fleet binding", mode=0o400, executable=False
        )
        fleet_record = _validate_fleet_binding_payload(
            strict_json(fleet_data, "fleet binding"),
            role=role,
            fleet_id=fleet_id,
            instance=instance,
        )
        if canonical_bytes(fleet_record) != fleet_data:
            raise RemoteInstallError("fleet binding is not canonical")
        _forbid_effective_write(fleet_binding_path, "fleet binding")
    for member in binding["configs"]:
        name = str(member["name"])
        installed = config_root / name
        _require_helper_parent(installed, f"installed attempt config {name}")
        payload = _read_regular(installed, f"installed attempt config {name}")
        info = installed.lstat()
        _require_root_owned_regular(
            info, f"installed attempt config {name}", mode=0o400, executable=False
        )
        _forbid_effective_write(installed, f"installed attempt config {name}")
        template = (
            len(payload) == int(member["bytes"]) and sha256_bytes(payload) == member["sha256"]
        )
        if template:
            _require_attempt_config_bytes(payload, name)
            continue
        if fleet_record is None:
            raise RemoteInstallError(
                f"installed attempt config {name} path/hash/mode is not bound"
            )
        _require_provisioned_attempt_config(
            payload, name, fleet=fleet_record, config_root=config_root
        )
    role_data = _read_regular(role_path, "role file")
    role_info = role_path.lstat()
    _require_helper_parent(role_path, "role file")
    _require_root_owned_regular(role_info, "role file", mode=0o400, executable=False)
    if role_data != (role + "\n").encode("ascii"):
        raise RemoteInstallError("role file is invalid")
    _forbid_effective_write(role_path, "role file")
    return identity


def install_attempt_broker(
    extracted_root: Path,
    manifest: Mapping[str, Any],
    *,
    role: str,
    fleet_id: str,
    instance: str,
    candidate_id: str,
    destination: Path | None = None,
    identity_path: Path | None = None,
    role_path: Path | None = None,
    fleet_binding_path: Path | None = None,
    unit_root: Path | None = None,
    config_root: Path | None = None,
    fleet_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if role not in ATTEMPT_BROKER_REQUIRED_ROLES:
        raise RemoteInstallError("unexpected role")
    _safe_fleet(fleet_id)
    _safe_name("instance", instance)
    _safe_sha("candidate id", candidate_id)
    records = _manifest_records(manifest)
    binding = _attempt_broker_binding(manifest, records)
    bound = _bind_extracted_tree(extracted_root, manifest)
    source_record = bound[binding["path"]]
    if (
        source_record["sha256"] != binding["sha256"]
        or source_record["mode"] != binding["mode"]
        or source_record["bytes"] != binding["bytes"]
        or source_record["path"] != ATTEMPT_BROKER_PATH
        or binding["install_path"] != ATTEMPT_BROKER_INSTALL_PATH
        or binding["path"] != ATTEMPT_BROKER_PATH
    ):
        raise RemoteInstallError("protocol-attempt broker path/hash/mode is not bound")
    source = extracted_root.joinpath(*PurePosixPath(binding["path"]).parts)
    data = _read_regular(
        source, "protocol-attempt broker", expected_sha256=binding["sha256"]
    )
    info = source.lstat()
    if (
        stat.S_IMODE(info.st_mode) != binding["mode"]
        or len(data) != binding["bytes"]
        or sha256_bytes(data) != binding["sha256"]
    ):
        raise RemoteInstallError("protocol-attempt broker path/hash/mode is not bound")
    _attempt_broker_markers(data)
    target = destination if destination is not None else ATTEMPT_BROKER_INSTALL_FILE
    identity_file = (
        identity_path if identity_path is not None else ATTEMPT_BROKER_IDENTITY_PATH
    )
    role_file = role_path if role_path is not None else ATTEMPT_BROKER_ROLE_PATH
    fleet_file = (
        fleet_binding_path if fleet_binding_path is not None else ATTEMPT_BROKER_FLEET_BINDING_PATH
    )
    units_dir = unit_root if unit_root is not None else ATTEMPT_BROKER_UNIT_ROOT
    configs_dir = config_root if config_root is not None else ATTEMPT_BROKER_CONFIG_ROOT
    _refuse_test_only_production_attempt_broker(target, identity_file)
    if target.is_symlink() or identity_file.is_symlink():
        raise RemoteInstallError("protocol-attempt broker install is unsafe")
    dest_present = target.exists()
    ident_present = identity_file.exists()
    if dest_present != ident_present:
        raise RemoteInstallError("protocol-attempt broker install is incomplete")
    complete_kwargs = {
        "expected_sha256": binding["sha256"],
        "expected_bytes": binding["bytes"],
        "expected_mode": ATTEMPT_BROKER_INSTALL_MODE,
        "role": role,
        "fleet_id": fleet_id,
        "instance": instance,
        "candidate_id": candidate_id,
        "source_path": binding["path"],
        "binding": binding,
        "role_path": role_file,
        "fleet_binding_path": fleet_file,
        "unit_root": units_dir,
        "config_root": configs_dir,
        "require_fleet_binding": fleet_binding is not None or fleet_file.exists(),
    }
    production_paths = (
        target == ATTEMPT_BROKER_INSTALL_FILE
        and identity_file == ATTEMPT_BROKER_IDENTITY_PATH
        and role_file == ATTEMPT_BROKER_ROLE_PATH
        and fleet_file == ATTEMPT_BROKER_FLEET_BINDING_PATH
        and units_dir == ATTEMPT_BROKER_UNIT_ROOT
        and configs_dir == ATTEMPT_BROKER_CONFIG_ROOT
    )
    if dest_present and ident_present:
        identity = require_complete_attempt_broker(
            target, identity_file, **complete_kwargs
        )
        if production_paths:
            _activate_attempt_broker_socket()
        return identity
    planned: list[tuple[Path, bytes, int, str, int]] = []
    unit_members = [binding["socket"], binding["service"], *list(binding["units"])]
    for member in unit_members:
        member_source = extracted_root.joinpath(*PurePosixPath(str(member["path"])).parts)
        member_data = _read_regular(
            member_source,
            f"attempt unit {member['name']}",
            expected_sha256=str(member["sha256"]),
        )
        if len(member_data) != int(member["bytes"]) or sha256_bytes(member_data) != member["sha256"]:
            raise RemoteInstallError(
                f"attempt unit {member['name']} path/hash/mode is not bound"
            )
        planned.append(
            (
                units_dir / str(member["name"]),
                member_data,
                0o444,
                f"installed attempt unit {member['name']}",
                0o755,
            )
        )
    for member in binding["configs"]:
        member_source = extracted_root.joinpath(*PurePosixPath(str(member["path"])).parts)
        member_data = _read_regular(
            member_source,
            f"attempt config {member['name']}",
            expected_sha256=str(member["sha256"]),
        )
        _require_attempt_config_bytes(member_data, str(member["name"]))
        if len(member_data) != int(member["bytes"]) or sha256_bytes(member_data) != member["sha256"]:
            raise RemoteInstallError(
                f"attempt config {member['name']} path/hash/mode is not bound"
            )
        planned.append(
            (
                configs_dir / str(member["name"]),
                member_data,
                0o400,
                f"installed attempt config {member['name']}",
                0o700,
            )
        )
    planned.append((role_file, (role + "\n").encode("ascii"), 0o400, "role file", 0o755))
    if fleet_binding is not None:
        validated = _validate_fleet_binding_payload(
            fleet_binding, role=role, fleet_id=fleet_id, instance=instance
        )
        planned.append(
            (fleet_file, canonical_bytes(validated), 0o400, "fleet binding", 0o700)
        )
        complete_kwargs["require_fleet_binding"] = True
    adopted = {
        path
        for path, payload, mode, label, _parent_mode in planned
        if _adopt_exact_regular_or_absent(path, payload, mode, label)
    }
    created: list[tuple[Path, int, int]] = []
    try:
        broker_info = _atomic_regular_file(
            target,
            data,
            ATTEMPT_BROKER_INSTALL_MODE,
            "installed protocol-attempt broker",
            parent_mode=0o755,
        )
        created.append(_created_record(target, broker_info))
        payload = _attempt_broker_identity_payload(
            binding,
            role=role,
            fleet_id=fleet_id,
            instance=instance,
            candidate_id=candidate_id,
            destination=target,
            broker_info=broker_info,
        )
        identity_info = _atomic_regular_file(
            identity_file,
            canonical_bytes(payload),
            0o400,
            "protocol-attempt broker identity",
        )
        created.append(_created_record(identity_file, identity_info))
        for path, payload, mode, label, parent_mode in planned:
            if path in adopted:
                continue
            installed_info = _atomic_regular_file(
                path,
                payload,
                mode,
                label,
                parent_mode=parent_mode,
                exist_ok=False,
            )
            created.append(_created_record(path, installed_info))
        identity = require_complete_attempt_broker(
            target, identity_file, **complete_kwargs
        )
        if production_paths:
            _activate_attempt_broker_socket()
        return identity
    except Exception as original:
        if production_paths:
            _deactivate_attempt_broker_socket()
        try:
            _rollback_created_files(created)
        except RemoteInstallError as rollback_error:
            raise rollback_error from original
        raise


def _systemctl_attempt_broker(argv: Sequence[str], label: str) -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", *argv],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=30,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if result.returncode != 0:
        raise RemoteInstallError(f"{label} failed")


def _activate_attempt_broker_socket() -> None:
    _systemctl_attempt_broker(["daemon-reload"], "attempt broker daemon reload")
    _systemctl_attempt_broker(
        ["enable", "--now", "winsvpn-gcp-proof-attempt-broker.socket"],
        "attempt broker socket activation",
    )


def _deactivate_attempt_broker_socket() -> None:
    try:
        subprocess.run(
            [
                "/usr/bin/systemctl",
                "disable",
                "--now",
                "winsvpn-gcp-proof-attempt-broker.socket",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            check=False,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _wipe_tree(path: Path) -> None:
    if path.exists() or path.is_symlink():
        shutil.rmtree(path, ignore_errors=False)


def _require_installed_gateway_binary(gateway_binary: Path | None = None) -> Path:
    binary = gateway_binary if gateway_binary is not None else GATEWAY_INSTALL_PATH
    if binary.is_symlink() or not binary.is_file():
        raise RemoteInstallError(
            "proof key provision requires the installed gateway binary; "
            "run server/wins_winn3_gateway_install.sh --install first"
        )
    info = binary.lstat()
    imode = stat.S_IMODE(info.st_mode)
    if info.st_nlink != 1 or imode & 0o111 == 0 or imode & 0o022:
        raise RemoteInstallError("installed gateway binary is unsafe")
    return binary


def _require_authenticated_control_admission_channel() -> None:
    raise RemoteInstallError(
        "proof key public/admission material cannot be returned: missing "
        f"{CONTROL_ADMISSION_EVIDENCE_CHANNEL} (external input: "
        f"{CONTROL_ADMISSION_EXTERNAL_INPUT})"
    )


def _require_hex_bytes(data: bytes, size: int, label: str) -> bytes:
    pattern = HEX_EXACT.get(size)
    if pattern is None or not pattern.fullmatch(data):
        raise RemoteInstallError(f"{label} is not the exact keygen hex encoding")
    return data


def _safe_inner_v4(value: str) -> str:
    try:
        addr = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise RemoteInstallError("proof client inner IPv4 is invalid") from exc
    if str(addr) != value:
        raise RemoteInstallError("proof client inner IPv4 is not canonical")
    reserved = {
        PROOF_CLIENT_INNER_PREFIX.network_address,
        PROOF_CLIENT_INNER_PREFIX.broadcast_address,
        PROOF_GATEWAY_INNER_V4,
    }
    if addr not in PROOF_CLIENT_INNER_PREFIX or addr in reserved:
        raise RemoteInstallError("proof client inner IPv4 is not a usable run-bound host")
    return value


def _read_identity_text(path: Path, label: str) -> str:
    data = _read_regular(path, label)
    try:
        return data.decode("ascii").strip()
    except UnicodeDecodeError as suc:
        raise RemoteInstallError(f"{label} is not ASCII") from suc


def _load_local_instance_id() -> str:
    if INSTANCE_ID_PATH.exists() or INSTANCE_ID_PATH.is_symlink():
        text = _read_identity_text(INSTANCE_ID_PATH, "GCE numeric instance id")
        return _safe_gce_id("GCE numeric instance id", text)
    if DMI_PRODUCT_SERIAL_PATH.exists() or DMI_PRODUCT_SERIAL_PATH.is_symlink():
        text = _read_identity_text(DMI_PRODUCT_SERIAL_PATH, "DMI product serial")
        matched = DMI_INSTANCE_RE.fullmatch(text)
        if matched is None:
            raise RemoteInstallError("GCE numeric instance id is invalid")
        return _safe_gce_id("GCE numeric instance id", matched.group(1))
    raise RemoteInstallError("GCE numeric instance id is absent")


def _load_local_boot_id() -> str:
    return _safe_boot_id("boot id", _read_identity_text(BOOT_ID_PATH, "boot id"))


def _require_local_machine_binding(
    role: str,
    binding: Mapping[str, Any],
    root: Path,
) -> None:
    if os.fspath(root) != os.fspath(EXCHANGE_ROOT):
        return
    local_id = _load_local_instance_id()
    local_boot = _load_local_boot_id()
    if role == "data-winn3":
        expected_id = str(binding["source_instance_id"])
        expected_boot = str(binding["source_boot_id"])
    else:
        expected_id = str(binding["target_instance_id"])
        expected_boot = str(binding["target_boot_id"])
    if local_id != expected_id or local_boot != expected_boot:
        raise RemoteInstallError("local GCE numeric instance id or boot id is not bound")


def _exchange_binding(
    *,
    fleet_id: str,
    candidate_id: str,
    source_role: str,
    source_instance: str,
    target_role: str,
    target_instance: str,
    inner_v4: str,
    apply_sha256: str,
    bundle_sha256: str,
    helper_sha256: str,
    manifest_sha256: str,
    plan_sha256: str,
    source_instance_id: str,
    target_instance_id: str,
    source_boot_id: str,
    target_boot_id: str,
) -> dict[str, Any]:
    _safe_fleet(fleet_id)
    _safe_sha("candidate id", candidate_id)
    _safe_name("source instance", source_instance)
    _safe_name("target instance", target_instance)
    _safe_sha("apply SHA-256", apply_sha256)
    _safe_sha("bundle SHA-256", bundle_sha256)
    _safe_sha("helper SHA-256", helper_sha256)
    _safe_sha("manifest SHA-256", manifest_sha256)
    _safe_sha("plan SHA-256", plan_sha256)
    _safe_gce_id("source GCE numeric instance id", source_instance_id)
    _safe_gce_id("target GCE numeric instance id", target_instance_id)
    _safe_boot_id("source boot id", source_boot_id)
    _safe_boot_id("target boot id", target_boot_id)
    if source_role != "data-winn3" or target_role != "control":
        raise RemoteInstallError("authenticated key exchange v1 roles are invalid")
    if source_instance == target_instance:
        raise RemoteInstallError("authenticated key exchange v1 source and target must be distinct")
    if source_instance_id == target_instance_id:
        raise RemoteInstallError("authenticated key exchange v1 source and target must be distinct")
    if source_boot_id == target_boot_id:
        raise RemoteInstallError("authenticated key exchange v1 source and target must be distinct")
    payload = {
        "apply_sha256": apply_sha256,
        "bundle_sha256": bundle_sha256,
        "candidate_id": candidate_id,
        "contract": EXCHANGE_CONTRACT,
        "fleet_id": fleet_id,
        "helper_sha256": helper_sha256,
        "inner_v4": _safe_inner_v4(inner_v4),
        "kind": KIND_EXCHANGE_BINDING,
        "manifest_sha256": manifest_sha256,
        "plan_sha256": plan_sha256,
        "schema_version": SCHEMA_VERSION,
        "source_boot_id": source_boot_id,
        "source_instance": source_instance,
        "source_instance_id": source_instance_id,
        "source_role": source_role,
        "target_boot_id": target_boot_id,
        "target_instance": target_instance,
        "target_instance_id": target_instance_id,
        "target_role": target_role,
    }
    core = dict(payload)
    payload["binding_sha256"] = sha256_bytes(canonical_bytes(core))
    if set(payload) != EXCHANGE_BINDING_KEYS:
        raise RemoteInstallError("authenticated key exchange v1 binding schema is invalid")
    return payload


def _parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not CREATED_RE.fullmatch(value):
        raise RemoteInstallError("exchange timestamp is invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _exchange_stamp(now_utc: str | None) -> str:
    if now_utc is None:
        return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _parse_utc(now_utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_seconds(stamp: str, seconds: int) -> str:
    return (_parse_utc(stamp) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_exchange_time(created_utc: str, *, now: str, origin_utc: str | None = None) -> None:
    created = _parse_utc(created_utc)
    current = _parse_utc(now)
    if (current - created).total_seconds() < -EXCHANGE_SKEW_SECONDS:
        raise RemoteInstallError("exchange timestamp is outside the allowed skew")
    origin = _parse_utc(origin_utc) if origin_utc is not None else created
    age = (current - origin).total_seconds()
    if age > EXCHANGE_TTL_SECONDS + EXCHANGE_SKEW_SECONDS:
        raise RemoteInstallError("authenticated key exchange v1 TTL has expired")


def _exchange_nonce() -> str:
    return os.urandom(32).hex()


def _require_root_owned_dir(info: os.stat_result, label: str, *, mode: int) -> None:
    imode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RemoteInstallError(f"{label} is unsafe")
    if imode & 0o022 and not (info.st_mode & stat.S_ISVTX):
        raise RemoteInstallError(f"{label} is writable")
    if imode != mode:
        raise RemoteInstallError(f"{label} mode is unsafe")
    if os.geteuid() == 0 and (info.st_uid != 0 or info.st_gid != 0):
        raise RemoteInstallError(f"{label} is not root-owned")


def _open_descended_dir(root: Path, parts: Sequence[str], label: str, *, create: bool) -> int:
    fd = _open_parent_dir_fd(root, f"{label} root")
    try:
        opened = os.fstat(fd)
        _require_root_owned_dir(opened, f"{label} root", mode=EXCHANGE_DIR_MODE)
        for part in parts:
            if not part or part in {".", ".."} or "/" in part or "\x00" in part:
                raise RemoteInstallError(f"{label} path is unsafe")
            try:
                child = os.open(part, _directory_nofollow_flags(), dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise RemoteInstallError(f"{label} is missing") from None
                child = _mkdir_then_open_at(fd, part, EXCHANGE_DIR_MODE, label)
            except OSError as exc:
                raise RemoteInstallError(f"{label} is unsafe") from exc
            try:
                info = os.fstat(child)
                named = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if (
                    (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                    or stat.S_ISLNK(named.st_mode)
                    or not stat.S_ISDIR(info.st_mode)
                ):
                    raise RemoteInstallError(f"{label} changed while being opened")
                _require_root_owned_dir(info, label, mode=EXCHANGE_DIR_MODE)
            except RemoteInstallError:
                os.close(child)
                raise
            except OSError as exc:
                os.close(child)
                raise RemoteInstallError(f"{label} is unsafe") from exc
            os.close(fd)
            fd = child
        return fd
    except RemoteInstallError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise RemoteInstallError(f"{label} is unsafe") from exc


def _forbid_archive_name(name: str) -> None:
    if name == LEGACY_TAR_NAME or EXCHANGE_ARCHIVE_RE.fullmatch(name):
        raise RemoteInstallError("tar/archive key provisioning is refused")


def _recover_exchange_temps(directory_fd: int) -> None:
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        raise RemoteInstallError("key exchange directory is unreadable") from exc
    for name in names:
        if EXCHANGE_TEMP_RE.fullmatch(name):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise RemoteInstallError("key exchange crash recovery failed") from exc


def _atomic_nofollow_at(
    directory_fd: int,
    name: str,
    data: bytes,
    mode: int,
    label: str,
    *,
    replace: bool = False,
) -> os.stat_result:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise RemoteInstallError(f"{label} name is unsafe")
    temporary = f".{name}.{os.urandom(8).hex()}"
    fd = -1
    written: os.stat_result | None = None
    try:
        existing: os.stat_result | None = None
        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not replace:
                raise RemoteInstallError(f"{label} replacement is forbidden")
            _require_bound_regular_stat(existing, label, mode=mode)
        fd = os.open(
            temporary,
            _regular_nofollow_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(fd, data)
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        os.fsync(fd)
        written = os.fstat(fd)
        if (
            not stat.S_ISREG(written.st_mode)
            or written.st_nlink != 1
            or stat.S_IMODE(written.st_mode) != mode
            or written.st_size != len(data)
        ):
            raise RemoteInstallError(f"{label} path/hash/mode/inode is not bound")
        os.close(fd)
        fd = -1
        if replace:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if existing is None or _stat_identity(current) != _stat_identity(existing):
                raise RemoteInstallError(f"{label} changed before replacement")
            _require_bound_regular_stat(current, label, mode=mode)
            os.replace(
                temporary,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            temporary = ""
        else:
            os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.unlink(temporary, dir_fd=directory_fd)
            temporary = ""
        os.fsync(directory_fd)
        installed_fd = os.open(name, _regular_nofollow_flags(os.O_RDONLY), dir_fd=directory_fd)
        try:
            installed_stat = os.fstat(installed_fd)
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            chunks: list[bytes] = []
            while True:
                chunk = os.read(installed_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            finished = os.fstat(installed_fd)
            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (
                (installed_stat.st_dev, installed_stat.st_ino) != (written.st_dev, written.st_ino)
                or (named.st_dev, named.st_ino) != (written.st_dev, written.st_ino)
                or (finished.st_dev, finished.st_ino) != (written.st_dev, written.st_ino)
                or (after.st_dev, after.st_ino) != (written.st_dev, written.st_ino)
                or _stat_identity(installed_stat) != _stat_identity(finished)
                or _stat_identity(finished) != _stat_identity(named)
                or _stat_identity(named) != _stat_identity(after)
                or installed_stat.st_nlink != 1
                or stat.S_IMODE(installed_stat.st_mode) != mode
                or installed_stat.st_size != len(data)
                or sha256_bytes(b"".join(chunks)) != sha256_bytes(data)
            ):
                raise RemoteInstallError(f"{label} path/hash/mode/inode is not bound")
            written = installed_stat
        finally:
            os.close(installed_fd)
    except RemoteInstallError:
        raise
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.EEXIST:
            raise RemoteInstallError(f"{label} replacement is forbidden") from exc
        raise RemoteInstallError(f"{label} could not be written atomically") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        if temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
    if written is None:
        raise RemoteInstallError(f"{label} is not a regular file after install")
    return written


def _require_bound_regular_stat(
    info: os.stat_result,
    label: str,
    *,
    mode: int,
    nlink: int = 1,
) -> None:
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise RemoteInstallError(f"{label} is not a regular single-link file")
    if info.st_nlink != nlink:
        raise RemoteInstallError(f"{label} is not a regular single-link file")
    if stat.S_IMODE(info.st_mode) != mode:
        raise RemoteInstallError(f"{label} mode is unsafe")
    if os.geteuid() == 0:
        if info.st_uid != 0 or info.st_gid != 0:
            raise RemoteInstallError(f"{label} is not root-owned")
    elif info.st_uid != os.geteuid():
        raise RemoteInstallError(f"{label} is not owner-bound")


def _read_regular_at(
    directory_fd: int,
    name: str,
    label: str,
    *,
    expected_mode: int | None = None,
) -> bytes:
    fd = -1
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise RemoteInstallError(f"{label} is not a regular single-link file")
        if expected_mode is not None:
            _require_bound_regular_stat(before, label, mode=expected_mode)
        fd = os.open(name, _regular_nofollow_flags(os.O_RDONLY), dir_fd=directory_fd)
        opened = os.fstat(fd)
        if expected_mode is not None:
            _require_bound_regular_stat(opened, label, mode=expected_mode)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if expected_mode is not None:
            _require_bound_regular_stat(finished, label, mode=expected_mode)
            _require_bound_regular_stat(after, label, mode=expected_mode)
    except RemoteInstallError:
        raise
    except OSError as exc:
        raise RemoteInstallError(f"{label} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if (
        _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
        or before.st_nlink != 1
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
        or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise RemoteInstallError(f"{label} changed while being read")
    return b"".join(chunks)


def _refuse_test_only_production_exchange(path: Path) -> None:
    if os.fspath(path) == os.fspath(EXCHANGE_ROOT) and os.geteuid() != 0:
        raise RemoteInstallError("test-only host cannot emit production evidence")


def _open_exchange_dir(path: Path, *, create: bool) -> int:
    _refuse_test_only_production_exchange(path)
    if os.fspath(path) == os.fspath(EXCHANGE_ROOT):
        _prepare_root_dir(STATE_ROOT, "deployment state root")
        fd = _open_descended_dir(
            STATE_ROOT, (EXCHANGE_DIRNAME,), "key exchange directory", create=create
        )
    else:
        if create:
            _prepare_root_dir(path, "key exchange directory")
        fd = _open_descended_dir(path, (), "key exchange directory", create=False)
    try:
        _recover_exchange_temps(fd)
        os.fsync(fd)
        return fd
    except RemoteInstallError:
        os.close(fd)
        raise
    except OSError as exc:
        os.close(fd)
        raise RemoteInstallError("key exchange directory is unsafe") from exc


def _event_keys(action: str) -> set[str]:
    mapping = {
        "exchange-identity": EXCHANGE_IDENTITY_KEYS,
        "exchange-challenge": EXCHANGE_CHALLENGE_KEYS,
        "exchange-control-offer": EXCHANGE_OFFER_KEYS,
        "exchange-data-accept": EXCHANGE_ACCEPT_KEYS,
        "exchange-data-emit": EXCHANGE_EMIT_KEYS,
        "exchange-control-import": EXCHANGE_IMPORT_KEYS,
        "exchange-data-consume": EXCHANGE_CONSUME_KEYS,
        "exchange-control-seal": EXCHANGE_SEAL_KEYS,
    }
    expected = mapping.get(action)
    if expected is None:
        raise RemoteInstallError("authenticated key exchange v1 action is invalid")
    return expected


def _finish_event(payload: dict[str, Any], expected: set[str]) -> dict[str, Any]:
    core = dict(payload)
    core.pop("event_sha256", None)
    payload["event_sha256"] = sha256_bytes(canonical_bytes(core))
    if set(payload) != expected:
        raise RemoteInstallError("authenticated key exchange v1 event schema is invalid")
    data = canonical_bytes(payload)
    if len(data) > EXCHANGE_MAX_BYTES:
        raise RemoteInstallError("authenticated key exchange v1 event is too large")
    return payload


def _load_event_bytes(data: bytes, action: str) -> dict[str, Any]:
    if len(data) > EXCHANGE_MAX_BYTES:
        raise RemoteInstallError("authenticated key exchange v1 event is too large")
    raw = strict_json(data, f"{action} event")
    record = _exact_keys(raw, _event_keys(action), f"{action} event")
    if (
        record["kind"] != KIND_EXCHANGE_EVENT
        or record["contract"] != EXCHANGE_CONTRACT
        or record["action"] != action
        or _exact_int(record["schema_version"], "exchange schema_version") != SCHEMA_VERSION
        or _exact_int(record["ttl_seconds"], "exchange ttl") != EXCHANGE_TTL_SECONDS
        or _exact_int(record["skew_seconds"], "exchange skew") != EXCHANGE_SKEW_SECONDS
    ):
        raise RemoteInstallError("authenticated key exchange v1 event is stale")
    if canonical_bytes(record) != data:
        raise RemoteInstallError("authenticated key exchange v1 event is not canonical")
    rebuilt = dict(record)
    core = dict(rebuilt)
    core.pop("event_sha256")
    if not hmac.compare_digest(str(record["event_sha256"]), sha256_bytes(canonical_bytes(core))):
        raise RemoteInstallError("authenticated key exchange v1 event is stale")
    rebuilt_binding = _exchange_binding(
        apply_sha256=str(record["apply_sha256"]),
        bundle_sha256=str(record["bundle_sha256"]),
        candidate_id=str(record["candidate_id"]),
        fleet_id=str(record["fleet_id"]),
        helper_sha256=str(record["helper_sha256"]),
        inner_v4=str(record["inner_v4"]),
        manifest_sha256=str(record["manifest_sha256"]),
        plan_sha256=str(record["plan_sha256"]),
        source_boot_id=str(record["source_boot_id"]),
        source_instance=str(record["source_instance"]),
        source_instance_id=str(record["source_instance_id"]),
        source_role=str(record["source_role"]),
        target_boot_id=str(record["target_boot_id"]),
        target_instance=str(record["target_instance"]),
        target_instance_id=str(record["target_instance_id"]),
        target_role=str(record["target_role"]),
    )
    if not hmac.compare_digest(str(record["binding_sha256"]), str(rebuilt_binding["binding_sha256"])):
        raise RemoteInstallError("stale or cross-run authenticated key exchange v1 binding")
    return record


def _load_exchange_events(directory_fd: int, role: str) -> dict[str, dict[str, Any]]:
    try:
        names = os.listdir(directory_fd)
    except OSError as suc:
        raise RemoteInstallError("key exchange directory is unreadable") from suc
    allowed = {
        EXCHANGE_EVENT_FILES[item]
        for item in EXCHANGE_ROLE_ACTIONS[role]
        if item in EXCHANGE_EVENT_FILES
    }
    loaded: dict[str, dict[str, Any]] = {}
    for name in names:
        _forbid_archive_name(name)
        if EXCHANGE_TEMP_RE.fullmatch(name):
            raise RemoteInstallError("key exchange crash recovery failed")
        if name not in allowed:
            raise RemoteInstallError("extra authenticated key exchange v1 state is forbidden")
        action = next(item for item, filename in EXCHANGE_EVENT_FILES.items() if filename == name)
        data = _read_regular_at(
            directory_fd, name, f"{action} event", expected_mode=EXCHANGE_EVENT_MODE
        )
        loaded[action] = _load_event_bytes(data, action)
    _require_local_event_chain(loaded)
    return loaded


def _binding_fields(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "apply_sha256": binding["apply_sha256"],
        "binding_sha256": binding["binding_sha256"],
        "bundle_sha256": binding["bundle_sha256"],
        "candidate_id": binding["candidate_id"],
        "contract": EXCHANGE_CONTRACT,
        "expires_utc": "",
        "fleet_id": binding["fleet_id"],
        "helper_sha256": binding["helper_sha256"],
        "inner_v4": binding["inner_v4"],
        "kind": KIND_EXCHANGE_EVENT,
        "manifest_sha256": binding["manifest_sha256"],
        "plan_sha256": binding["plan_sha256"],
        "schema_version": SCHEMA_VERSION,
        "skew_seconds": EXCHANGE_SKEW_SECONDS,
        "source_boot_id": binding["source_boot_id"],
        "source_instance": binding["source_instance"],
        "source_instance_id": binding["source_instance_id"],
        "source_role": binding["source_role"],
        "target_boot_id": binding["target_boot_id"],
        "target_instance": binding["target_instance"],
        "target_instance_id": binding["target_instance_id"],
        "target_role": binding["target_role"],
        "ttl_seconds": EXCHANGE_TTL_SECONDS,
    }


def _same_binding(event: Mapping[str, Any], binding: Mapping[str, Any]) -> None:
    for key in EXCHANGE_BINDING_KEYS:
        if key == "kind":
            continue
        if event[key] != binding[key]:
            raise RemoteInstallError("stale or cross-run authenticated key exchange v1 binding")


def _require_local_event_chain(events: Mapping[str, Mapping[str, Any]]) -> None:
    identity = events.get("exchange-identity")
    if identity is None:
        extra = set(events)
        extra.discard("exchange-identity")
        if extra:
            raise RemoteInstallError("skipped or reordered authenticated key exchange v1 action")
        return
    ident_sha = str(identity["event_sha256"])
    challenge = events.get("exchange-challenge")
    for action, event in events.items():
        if action == "exchange-identity":
            continue
        if str(event.get("identity_sha256")) != ident_sha:
            raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
        if "challenge_sha256" in event:
            if challenge is None or str(event["challenge_sha256"]) != str(challenge["event_sha256"]):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if "exchange-control-offer" in events:
        offer = events["exchange-control-offer"]
        if challenge is None:
            raise RemoteInstallError("skipped or reordered authenticated key exchange v1 action")
        if str(offer["peer_sha256"]) != str(challenge["peer_sha256"]):
            raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if "exchange-data-accept" in events:
        accept = events["exchange-data-accept"]
        if challenge is None:
            raise RemoteInstallError("skipped or reordered authenticated key exchange v1 action")
        if str(accept["peer_challenge_sha256"]) == str(challenge["event_sha256"]):
            raise RemoteInstallError(EXCHANGE_MIXING_ERROR)


def _base_event(
    action: str,
    *,
    role: str,
    instance: str,
    binding: Mapping[str, Any],
    now_utc: str,
    origin_utc: str | None,
) -> dict[str, Any]:
    _require_exchange_time(now_utc, now=now_utc, origin_utc=origin_utc)
    payload = _binding_fields(binding)
    payload["action"] = action
    payload["created_utc"] = now_utc
    payload["expires_utc"] = _add_seconds(
        origin_utc if origin_utc is not None else now_utc, EXCHANGE_TTL_SECONDS
    )
    payload["instance"] = instance
    payload["nonce"] = _exchange_nonce()
    payload["role"] = role
    return payload


def _write_event(
    directory_fd: int,
    action: str,
    payload: Mapping[str, Any],
    secrets: Sequence[bytes],
) -> dict[str, Any]:
    finished = _finish_event(dict(payload), _event_keys(action))
    _forbid_secret_receipt(finished, secrets)
    _atomic_nofollow_at(
        directory_fd,
        EXCHANGE_EVENT_FILES[action],
        canonical_bytes(finished),
        EXCHANGE_EVENT_MODE,
        f"{action} event",
    )
    return finished


def _receipt_from_event(event: Mapping[str, Any]) -> dict[str, Any]:
    return dict(event)


def _response(
    action: str,
    receipt: Mapping[str, Any],
    *,
    public: Mapping[str, str] | None = None,
    secret: Mapping[str, str] | None = None,
    secrets: Sequence[bytes] = (),
) -> dict[str, Any]:
    payload = {
        "action": action,
        "contract": EXCHANGE_CONTRACT,
        "kind": KIND_EXCHANGE_RESPONSE,
        "public": None if public is None else dict(public),
        "receipt": dict(receipt),
        "schema_version": SCHEMA_VERSION,
        "secret": None if secret is None else dict(secret),
    }
    if set(payload) != EXCHANGE_RESPONSE_KEYS:
        raise RemoteInstallError("authenticated key exchange v1 response schema is invalid")
    if secret is None:
        _forbid_secret_receipt(payload, secrets)
    else:
        _forbid_secret_receipt(receipt, secrets)
        _forbid_secret_receipt({"action": action, "receipt": receipt, "public": public}, secrets)
    data = canonical_bytes(payload)
    if len(data) > EXCHANGE_MAX_BYTES:
        raise RemoteInstallError("authenticated key exchange v1 response is too large")
    return payload


def _require_priors(events: Mapping[str, Mapping[str, Any]], action: str) -> None:
    if action in events:
        raise RemoteInstallError(f"{action} replacement is forbidden")
    for prior in EXCHANGE_PRIORS[action]:
        if prior not in events:
            raise RemoteInstallError("skipped or reordered authenticated key exchange v1 action")


def _require_peer(peer: Mapping[str, Any] | None, action: str) -> dict[str, Any]:
    if peer is None:
        raise RemoteInstallError(f"{action} requires a peer event")
    return _load_event_bytes(canonical_bytes(peer), action)


def _require_peer_challenge(
    peer: Mapping[str, Any] | None,
    *,
    local_identity: Mapping[str, Any],
    local_challenge: Mapping[str, Any],
    binding: Mapping[str, Any],
    role: str,
    instance: str,
    now: str,
    origin: str | None,
) -> dict[str, Any]:
    peer_challenge = _require_peer(peer, "exchange-challenge")
    _same_binding(peer_challenge, binding)
    _require_exchange_time(str(peer_challenge["created_utc"]), now=now, origin_utc=origin)
    if peer_challenge["role"] == role or peer_challenge["instance"] == instance:
        raise RemoteInstallError("authenticated key exchange v1 peer role is invalid")
    if str(peer_challenge["identity_sha256"]) != str(local_challenge["peer_sha256"]):
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if str(peer_challenge["peer_sha256"]) != str(local_identity["event_sha256"]):
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if str(peer_challenge["peer_nonce"]) != str(local_identity["nonce"]):
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if peer_challenge["peer_instance"] != instance or peer_challenge["peer_role"] != role:
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if local_challenge["peer_instance"] != peer_challenge["instance"]:
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if local_challenge["peer_role"] != peer_challenge["role"]:
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    if str(peer_challenge["event_sha256"]) == str(local_challenge["event_sha256"]):
        raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
    return peer_challenge


def _identity_chain_fields(
    events: Mapping[str, Mapping[str, Any]],
    *,
    peer_challenge_sha256: str | None = None,
) -> dict[str, Any]:
    payload = {"identity_sha256": events["exchange-identity"]["event_sha256"]}
    if "exchange-challenge" in events:
        payload["challenge_sha256"] = events["exchange-challenge"]["event_sha256"]
    if peer_challenge_sha256 is not None:
        payload["peer_challenge_sha256"] = peer_challenge_sha256
    return payload


def _leaf_name(name: str, label: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise RemoteInstallError(f"{label} name is unsafe")
    _forbid_archive_name(name)
    return name


def _named_inode_matches(parent_fd: int, name: str, child_fd: int, label: str) -> None:
    opened = os.fstat(child_fd)
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino) or stat.S_ISLNK(
        named.st_mode
    ):
        raise RemoteInstallError(f"{label} changed while being used")


def _live_named_dir_inode_matches(parent_fd: int, name: str, child_fd: int) -> bool:
    try:
        held = os.fstat(child_fd)
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        (held.st_dev, held.st_ino) == (named.st_dev, named.st_ino)
        and not stat.S_ISLNK(named.st_mode)
        and stat.S_ISDIR(held.st_mode)
        and stat.S_ISDIR(named.st_mode)
    )


def _mkdir_then_open_at(parent_fd: int, name: str, mode: int, label: str) -> int:
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
        os.chmod(name, mode, dir_fd=parent_fd, follow_symlinks=False)
        os.chown(name, 0, 0, dir_fd=parent_fd, follow_symlinks=False)
        return os.open(name, _directory_nofollow_flags(), dir_fd=parent_fd)
    except FileExistsError as suc:
        raise RemoteInstallError(f"{label} replacement is forbidden") from suc
    except (OSError, NotImplementedError) as suc:
        raise RemoteInstallError(f"{label} is unsafe") from suc


def _mkdir_exclusive_at(parent_fd: int, name: str, mode: int, label: str) -> int:
    leaf = _leaf_name(name, label)
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise RemoteInstallError(f"{label} replacement is forbidden")
    child = _mkdir_then_open_at(parent_fd, leaf, mode, label)
    try:
        _named_inode_matches(parent_fd, leaf, child, label)
        _require_root_owned_dir(os.fstat(child), label, mode=mode)
        os.fsync(parent_fd)
        os.fsync(child)
    except Exception:
        os.close(child)
        raise
    return child


def _unlink_names_at(directory_fd: int, names: Sequence[str]) -> None:
    for name in reversed(list(names)):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    os.fsync(directory_fd)


def _open_existing_dir(path: Path, label: str, *, mode: int) -> tuple[int, int, str]:
    parent_fd = _open_parent_dir_fd(path.parent, f"{label} parent")
    leaf = _leaf_name(path.name, label)
    try:
        child = os.open(leaf, _directory_nofollow_flags(), dir_fd=parent_fd)
    except OSError as suc:
        os.close(parent_fd)
        raise RemoteInstallError(f"{label} is unsafe") from suc
    try:
        _named_inode_matches(parent_fd, leaf, child, label)
        _require_root_owned_dir(os.fstat(child), label, mode=mode)
    except RemoteInstallError:
        os.close(child)
        os.close(parent_fd)
        raise
    return parent_fd, child, leaf


def _wipe_map(values: dict[str, bytes]) -> None:
    for key in list(values):
        values[key] = b""


def _hex_values(payload: Mapping[str, bytes], names: Sequence[str], label: str) -> dict[str, str]:
    if set(payload) != set(names):
        raise RemoteInstallError(f"{label} set is invalid")
    result: dict[str, str] = {}
    for name in names:
        data = payload[name]
        _require_hex_bytes(data, KEYGEN_FILE_SIZES[name], name)
        result[name] = data.decode("ascii")
    return result


def _parse_hex_values(raw: object, names: Sequence[str], label: str) -> dict[str, bytes]:
    if not isinstance(raw, dict) or set(raw) != set(names):
        raise RemoteInstallError(f"{label} schema is invalid")
    result: dict[str, bytes] = {}
    for name in names:
        value = raw[name]
        if not isinstance(value, str):
            raise RemoteInstallError(f"{label} is invalid")
        try:
            data = value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise RemoteInstallError(f"{label} is not ASCII") from exc
        _require_hex_bytes(data, KEYGEN_FILE_SIZES[name], name)
        result[name] = data
    return result


def _refuse_secret_fields(raw: Mapping[str, Any], label: str) -> None:
    for name in EXCHANGE_GATEWAY_SECRETS:
        if name in raw:
            raise RemoteInstallError(f"{label} contains secret material")
    if "secret" in raw:
        raise RemoteInstallError(f"{label} contains secret material")


def _rollback_at(
    *,
    directory_fd: int | None,
    names: Sequence[str],
    parent_fd: int | None = None,
    directory_name: str | None = None,
) -> None:
    if directory_fd is not None and directory_fd >= 0:
        _unlink_names_at(directory_fd, names)
        if parent_fd is not None and parent_fd >= 0 and directory_name:
            try:
                if _live_named_dir_inode_matches(parent_fd, directory_name, directory_fd):
                    os.rmdir(directory_name, dir_fd=parent_fd)
            except OSError:
                pass
            try:
                os.fsync(parent_fd)
            except OSError:
                pass


def _peer_registry_document(client_pub: bytes, inner_v4: str) -> dict[str, Any]:
    _require_hex_bytes(client_pub, 64, "client public key")
    public = base64.b64encode(bytes.fromhex(client_pub.decode("ascii"))).decode("ascii")
    return {
        "peers": [
            {
                "inner_v4": inner_v4,
                "not_after": 0,
                "static_public": public,
            }
        ],
        "version": 1,
    }


def _forbid_secret_receipt(payload: Mapping[str, Any], secrets: Sequence[bytes]) -> None:
    encoded = canonical_bytes(payload)
    if SECRET_RE.search(encoded):
        raise RemoteInstallError("authenticated key exchange v1 receipt emitted secret material")
    for item in secrets:
        if not item:
            continue
        if item in encoded:
            raise RemoteInstallError("authenticated key exchange v1 receipt emitted secret material")
        digest = sha256_bytes(item).encode("ascii")
        if digest in encoded:
            raise RemoteInstallError("authenticated key exchange v1 receipt emitted secret material")


def _require_owner_regular_at(
    directory_fd: int,
    name: str,
    label: str,
    *,
    mode: int,
    data: bytes,
) -> None:
    installed = _read_regular_at(directory_fd, name, label, expected_mode=mode)
    if installed != data:
        raise RemoteInstallError(f"{label} ownership or mode is unsafe")
    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    _require_bound_regular_stat(info, label, mode=mode)
    if info.st_size != len(data):
        raise RemoteInstallError(f"{label} ownership or mode is unsafe")


def _install_peer_registry(client_pub: bytes, inner_v4: str, destination: Path) -> dict[str, Any]:
    parent = destination.parent
    if parent.exists() or parent.is_symlink():
        _require_safe_dir(parent, "peer registry parent")
    else:
        _prepare_dir(parent, "peer registry parent", mode=0o755)
    parent_fd = _open_parent_dir_fd(parent, "peer registry")
    leaf = _leaf_name(destination.name, "peer registry")
    try:
        try:
            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RemoteInstallError("peer registry replacement is forbidden")
        document = _peer_registry_document(client_pub, inner_v4)
        payload = canonical_bytes(document)
        _atomic_nofollow_at(parent_fd, leaf, payload, 0o640, "proof peer registry")
        _require_owner_regular_at(parent_fd, leaf, "proof peer registry", mode=0o640, data=payload)
        return document
    finally:
        os.close(parent_fd)


def _open_or_create_dir_at(parent_fd: int, name: str, mode: int, label: str) -> int:
    leaf = _leaf_name(name, label)
    try:
        child = os.open(leaf, _directory_nofollow_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        child = _mkdir_then_open_at(parent_fd, leaf, mode, label)
    except OSError as suc:
        raise RemoteInstallError(f"{label} is unsafe") from suc
    try:
        _named_inode_matches(parent_fd, leaf, child, label)
        _require_root_owned_dir(os.fstat(child), label, mode=mode)
        os.fsync(parent_fd)
    except Exception:
        os.close(child)
        raise
    return child


def _production_proof_key_paths(gateway_binary: Path, credentials_dir: Path) -> bool:
    return (
        os.fspath(gateway_binary) == os.fspath(GATEWAY_INSTALL_PATH)
        or os.fspath(credentials_dir) == os.fspath(WINN_CREDENTIALS_DIR)
    )


def _require_owner_cloud_machine_evidence(
    *, gateway_binary: Path, credentials_dir: Path
) -> None:
    if not _production_proof_key_paths(gateway_binary, credentials_dir):
        return
    instance_present = INSTANCE_ID_PATH.exists() or INSTANCE_ID_PATH.is_symlink()
    dmi_present = DMI_PRODUCT_SERIAL_PATH.exists() or DMI_PRODUCT_SERIAL_PATH.is_symlink()
    boot_present = BOOT_ID_PATH.exists() or BOOT_ID_PATH.is_symlink()
    if not ((instance_present or dmi_present) and boot_present):
        raise RemoteInstallError(OWNER_CLOUD_EVIDENCE_BLOCKED)
    _load_local_instance_id()
    _load_local_boot_id()


def _proof_key_provision_receipt(*, generated: bool) -> dict[str, Any]:
    return {
        "generated": generated,
        "installed": sorted(name for _source, name in GATEWAY_PRIVATE_INSTALL),
        "kind": PROOF_KEY_PROVISION_ID,
        "mode": PROOF_KEY_INSTALL_MODE,
        "schema_version": SCHEMA_VERSION,
    }


def _adopt_complete_gateway_privates(creds: Path) -> dict[str, bytes] | None:
    if creds.is_symlink():
        raise RemoteInstallError("gateway credentials directory is unsafe")
    present = 0
    materials: dict[str, bytes] = {}
    for source_name, installed_name in GATEWAY_PRIVATE_INSTALL:
        path = creds / installed_name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        present += 1
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != PROOF_KEY_INSTALL_MODE
        ):
            raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
        payload = _read_regular(path, f"gateway {installed_name}")
        materials[source_name] = _require_hex_bytes(
            payload, KEYGEN_FILE_SIZES[source_name], f"generated {source_name}"
        )
    if present == 0:
        return None
    if present != len(GATEWAY_PRIVATE_INSTALL):
        raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
    return materials


def _adopt_complete_emit_hold(creds: Path) -> dict[str, bytes] | None:
    hold = creds / PROOF_KEY_HOLD_NAME
    try:
        info = hold.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
    _require_root_owned_dir(info, "proof key hold", mode=0o700)
    observed = {
        item.name
        for item in hold.iterdir()
        if not EXCHANGE_TEMP_RE.fullmatch(item.name)
    }
    if observed != set(KEYGEN_FILE_SIZES):
        raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
    materials: dict[str, bytes] = {}
    for name, size in KEYGEN_FILE_SIZES.items():
        path = hold / name
        file_info = path.lstat()
        if (
            stat.S_ISLNK(file_info.st_mode)
            or not stat.S_ISREG(file_info.st_mode)
            or file_info.st_nlink != 1
            or stat.S_IMODE(file_info.st_mode) != PROOF_KEY_INSTALL_MODE
        ):
            raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
        payload = _read_regular(path, f"held {name}")
        materials[name] = _require_hex_bytes(payload, size, f"generated {name}")
    return materials


def _wipe_proof_key_export_hold(credentials_dir: Path) -> None:
    hold = credentials_dir / PROOF_KEY_HOLD_NAME
    try:
        info = hold.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RemoteInstallError("proof key hold is unsafe")
    creds_fd = _open_parent_dir_fd(credentials_dir, "gateway credentials directory")
    hold_fd = -1
    try:
        hold_fd = os.open(
            PROOF_KEY_HOLD_NAME, _directory_nofollow_flags(), dir_fd=creds_fd
        )
        _named_inode_matches(
            creds_fd, PROOF_KEY_HOLD_NAME, hold_fd, "proof key hold"
        )
        _require_root_owned_dir(os.fstat(hold_fd), "proof key hold", mode=0o700)
        _unlink_names_at(hold_fd, PROOF_KEY_EXPORT_HOLD_NAMES)
    except OSError as suc:
        raise RemoteInstallError("proof key export hold could not be wiped") from suc
    finally:
        if hold_fd >= 0:
            os.close(hold_fd)
        os.close(creds_fd)


def _generate_and_install_proof_keys_on_vm(
    *,
    gateway_binary: Path | None = None,
    credentials_dir: Path | None = None,
) -> tuple[dict[str, bytes], bool]:
    binary = gateway_binary if gateway_binary is not None else GATEWAY_INSTALL_PATH
    creds = credentials_dir if credentials_dir is not None else WINN_CREDENTIALS_DIR
    _require_owner_cloud_machine_evidence(gateway_binary=binary, credentials_dir=creds)
    binary = _require_installed_gateway_binary(binary)
    privates = _adopt_complete_gateway_privates(creds)
    hold = _adopt_complete_emit_hold(creds)
    if privates is not None and hold is not None:
        for source_name, _installed_name in GATEWAY_PRIVATE_INSTALL:
            if privates[source_name] != hold[source_name]:
                raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
        return dict(hold), False
    if privates is not None or hold is not None:
        raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
    tmp_root = Path("/run")
    if tmp_root.is_dir() and not tmp_root.is_symlink():
        tmp = Path(tempfile.mkdtemp(prefix="winn3-keygen.", dir=str(tmp_root)))
    else:
        raise RemoteInstallError("on-VM proof key generation requires tmpfs /run")
    materials: dict[str, bytes] = {}
    try:
        os.chmod(tmp, 0o700)
        os.chown(tmp, 0, 0)
        result = subprocess.run(
            [str(binary), "-mode", "keygen", "-out", str(tmp)],
            cwd=tmp,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=60,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        )
        if result.returncode != 0:
            raise RemoteInstallError("on-VM proof key generation failed")
        if SECRET_RE.search(result.stdout) or SECRET_RE.search(result.stderr):
            raise RemoteInstallError("on-VM proof key generation emitted secret material")
        observed = {item.name for item in tmp.iterdir()}
        if observed != set(KEYGEN_FILE_SIZES):
            raise RemoteInstallError("on-VM proof key generation omitted or added a required file")
        for name, size in KEYGEN_FILE_SIZES.items():
            payload = _read_regular(tmp / name, f"generated {name}")
            materials[name] = _require_hex_bytes(payload, size, f"generated {name}")
        parent = creds.parent
        if parent.exists() or parent.is_symlink():
            _require_safe_dir(parent, "gateway credentials parent")
        else:
            _prepare_dir(parent, "gateway credentials parent", mode=0o755)
        parent_fd = _open_parent_dir_fd(parent, "gateway credentials")
        creds_fd = -1
        hold_fd = -1
        installed_names: list[str] = []
        hold_names: list[str] = []
        try:
            creds_fd = _open_or_create_dir_at(
                parent_fd, creds.name, 0o700, "gateway credentials directory"
            )
            for _source_name, installed_name in GATEWAY_PRIVATE_INSTALL:
                try:
                    os.stat(installed_name, dir_fd=creds_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
            try:
                os.stat(PROOF_KEY_HOLD_NAME, dir_fd=creds_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RemoteInstallError(PROOF_KEY_OVERWRITE_ERROR)
            hold_fd = _open_or_create_dir_at(
                creds_fd, PROOF_KEY_HOLD_NAME, 0o700, "proof key hold"
            )
            for source_name, payload in materials.items():
                _atomic_nofollow_at(
                    hold_fd,
                    source_name,
                    payload,
                    PROOF_KEY_INSTALL_MODE,
                    f"held {source_name}",
                )
                hold_names.append(source_name)
                _require_owner_regular_at(
                    hold_fd,
                    source_name,
                    f"held {source_name}",
                    mode=PROOF_KEY_INSTALL_MODE,
                    data=payload,
                )
            for source_name, installed_name in GATEWAY_PRIVATE_INSTALL:
                _atomic_nofollow_at(
                    creds_fd,
                    installed_name,
                    materials[source_name],
                    PROOF_KEY_INSTALL_MODE,
                    f"gateway {installed_name}",
                )
                installed_names.append(installed_name)
                _require_owner_regular_at(
                    creds_fd,
                    installed_name,
                    f"gateway {installed_name}",
                    mode=PROOF_KEY_INSTALL_MODE,
                    data=materials[source_name],
                )
            _named_inode_matches(parent_fd, creds.name, creds_fd, "gateway credentials directory")
            _named_inode_matches(
                creds_fd, PROOF_KEY_HOLD_NAME, hold_fd, "proof key hold"
            )
        except Exception:
            if hold_fd >= 0:
                _rollback_at(
                    directory_fd=hold_fd,
                    names=hold_names,
                    parent_fd=creds_fd,
                    directory_name=PROOF_KEY_HOLD_NAME,
                )
            if creds_fd >= 0:
                _rollback_at(directory_fd=creds_fd, names=installed_names)
            raise
        finally:
            if hold_fd >= 0:
                os.close(hold_fd)
            if creds_fd >= 0:
                os.close(creds_fd)
            os.close(parent_fd)
        return dict(materials), True
    finally:
        _wipe_tree(tmp)


def _local_instance(role: str, binding: Mapping[str, Any]) -> str:
    if role == "data-winn3":
        return str(binding["source_instance"])
    return str(binding["target_instance"])


def _require_role_action(role: str, action: str) -> None:
    allowed = EXCHANGE_ROLE_ACTIONS.get(role)
    if allowed is None or action not in allowed:
        raise RemoteInstallError("authenticated key exchange v1 action is not valid for this role")


def _control_fleet_binding(
    *,
    role: str,
    instance: str,
    binding: Mapping[str, Any],
    fleet_binding: Mapping[str, Any] | None,
    fleet_binding_path: Path | None,
) -> dict[str, Any]:
    if role != "control":
        raise RemoteInstallError("attempt broker provision is control-only")
    if fleet_binding is not None:
        return _validate_fleet_binding_payload(
            fleet_binding,
            role=role,
            fleet_id=str(binding["fleet_id"]),
            instance=instance,
        )
    path = (
        fleet_binding_path
        if fleet_binding_path is not None
        else ATTEMPT_BROKER_FLEET_BINDING_PATH
    )
    data = _read_regular(path, "fleet binding")
    record = _validate_fleet_binding_payload(
        strict_json(data, "fleet binding"),
        role=role,
        fleet_id=str(binding["fleet_id"]),
        instance=instance,
    )
    if canonical_bytes(record) != data:
        raise RemoteInstallError("fleet binding is not canonical")
    return record


def run_exchange_action(
    action: str,
    *,
    role: str,
    instance: str,
    fleet_id: str,
    candidate_id: str,
    source_role: str,
    source_instance: str,
    target_role: str,
    target_instance: str,
    apply_sha256: str,
    bundle_sha256: str,
    helper_sha256: str,
    manifest_sha256: str,
    plan_sha256: str,
    source_instance_id: str,
    target_instance_id: str,
    source_boot_id: str,
    target_boot_id: str,
    inner_v4: str = PROOF_CLIENT_INNER_V4,
    peer: Mapping[str, Any] | None = None,
    secret: Mapping[str, bytes] | None = None,
    public: Mapping[str, bytes] | None = None,
    exchange_root: Path | None = None,
    credentials_dir: Path | None = None,
    proof_client_dir: Path | None = None,
    peer_registry_path: Path | None = None,
    gateway_binary: Path | None = None,
    now_utc: str | None = None,
    attempt_provision: Mapping[str, Any] | None = None,
    fleet_binding: Mapping[str, Any] | None = None,
    fleet_binding_path: Path | None = None,
) -> dict[str, Any]:
    if action not in EXCHANGE_ACTIONS:
        raise RemoteInstallError("authenticated key exchange v1 action is invalid")
    if attempt_provision is not None and action != "exchange-control-seal":
        raise RemoteInstallError("attempt broker provision is seal-only")
    _safe_name("instance", instance)
    _require_role_action(role, action)
    binding = _exchange_binding(
        fleet_id=fleet_id,
        candidate_id=candidate_id,
        source_role=source_role,
        source_instance=source_instance,
        target_role=target_role,
        target_instance=target_instance,
        inner_v4=inner_v4,
        apply_sha256=apply_sha256,
        bundle_sha256=bundle_sha256,
        helper_sha256=helper_sha256,
        manifest_sha256=manifest_sha256,
        plan_sha256=plan_sha256,
        source_instance_id=source_instance_id,
        target_instance_id=target_instance_id,
        source_boot_id=source_boot_id,
        target_boot_id=target_boot_id,
    )
    if instance != _local_instance(role, binding):
        raise RemoteInstallError("authenticated key exchange v1 instance does not match role")
    root = exchange_root if exchange_root is not None else EXCHANGE_ROOT
    _refuse_test_only_production_exchange(root)
    _require_local_machine_binding(role, binding, root)
    stamp = _exchange_stamp(now_utc)
    directory_fd = _open_exchange_dir(root, create=action == "exchange-identity")
    held: dict[str, bytes] = {}
    secret_parent_fd = -1
    secret_dir_fd = -1
    secret_dir_name = ""
    secret_names: list[str] = []
    provision_originals: dict[str, bytes] = {}
    try:
        events = _load_exchange_events(directory_fd, role)
        if action != "exchange-status":
            _require_priors(events, action)
        origin = None if not events else str(events["exchange-identity"]["created_utc"])
        if origin is not None:
            _require_exchange_time(stamp, now=stamp, origin_utc=origin)
            _same_binding(events["exchange-identity"], binding)
        for item in events.values():
            _same_binding(item, binding)
            _require_exchange_time(str(item["created_utc"]), now=stamp, origin_utc=origin)
        if action == "exchange-status":
            completed = [
                item for item in EXCHANGE_ACTIONS if item in events and item != "exchange-status"
            ]
            identity = events.get("exchange-identity")
            receipt = {
                "action": "exchange-status",
                "apply_sha256": binding["apply_sha256"],
                "binding_sha256": binding["binding_sha256"],
                "bundle_sha256": binding["bundle_sha256"],
                "candidate_id": binding["candidate_id"],
                "completed_actions": completed,
                "contract": EXCHANGE_CONTRACT,
                "expires_utc": (
                    str(identity["expires_utc"])
                    if identity is not None
                    else _add_seconds(stamp, EXCHANGE_TTL_SECONDS)
                ),
                "fleet_id": binding["fleet_id"],
                "helper_sha256": binding["helper_sha256"],
                "inner_v4": binding["inner_v4"],
                "instance": instance,
                "kind": KIND_EXCHANGE_RECEIPT,
                "manifest_sha256": binding["manifest_sha256"],
                "plan_sha256": binding["plan_sha256"],
                "role": role,
                "schema_version": SCHEMA_VERSION,
                "sealed": "exchange-control-seal" in events
                if role == "control"
                else "exchange-data-consume" in events,
                "skew_seconds": EXCHANGE_SKEW_SECONDS,
                "source_boot_id": binding["source_boot_id"],
                "source_instance": binding["source_instance"],
                "source_instance_id": binding["source_instance_id"],
                "source_role": binding["source_role"],
                "target_boot_id": binding["target_boot_id"],
                "target_instance": binding["target_instance"],
                "target_instance_id": binding["target_instance_id"],
                "target_role": binding["target_role"],
                "ttl_seconds": EXCHANGE_TTL_SECONDS,
            }
            if set(receipt) != EXCHANGE_STATUS_KEYS:
                raise RemoteInstallError("authenticated key exchange v1 status schema is invalid")
            return _response(action, receipt)
        if action == "exchange-identity":
            event = _base_event(
                action, role=role, instance=instance, binding=binding, now_utc=stamp, origin_utc=None
            )
            written = _write_event(directory_fd, action, event, ())
            return _response(action, _receipt_from_event(written))
        if action == "exchange-challenge":
            peer_event = _require_peer(peer, "exchange-identity")
            if peer_event["role"] == role or peer_event["instance"] == instance:
                raise RemoteInstallError("authenticated key exchange v1 peer role is invalid")
            _same_binding(peer_event, binding)
            _require_exchange_time(
                str(peer_event["created_utc"]), now=stamp, origin_utc=str(peer_event["created_utc"])
            )
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event["peer_instance"] = peer_event["instance"]
            event["peer_nonce"] = peer_event["nonce"]
            event["peer_role"] = peer_event["role"]
            event["peer_sha256"] = peer_event["event_sha256"]
            event["identity_sha256"] = events["exchange-identity"]["event_sha256"]
            written = _write_event(directory_fd, action, event, ())
            return _response(action, _receipt_from_event(written))
        if action == "exchange-control-offer":
            peer_challenge = _require_peer_challenge(
                peer,
                local_identity=events["exchange-identity"],
                local_challenge=events["exchange-challenge"],
                binding=binding,
                role=role,
                instance=instance,
                now=stamp,
                origin=origin,
            )
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event.update(_identity_chain_fields(events, peer_challenge_sha256=peer_challenge["event_sha256"]))
            event["peer_instance"] = peer_challenge["instance"]
            event["peer_nonce"] = peer_challenge["nonce"]
            event["peer_role"] = peer_challenge["role"]
            event["peer_sha256"] = peer_challenge["identity_sha256"]
            written = _write_event(directory_fd, action, event, ())
            return _response(action, _receipt_from_event(written))
        if action == "exchange-data-accept":
            offer = _require_peer(peer, "exchange-control-offer")
            if offer["role"] != "control":
                raise RemoteInstallError("authenticated key exchange v1 peer role is invalid")
            _same_binding(offer, binding)
            _require_exchange_time(str(offer["created_utc"]), now=stamp, origin_utc=origin)
            local_challenge = events["exchange-challenge"]
            if str(offer["peer_challenge_sha256"]) != str(local_challenge["event_sha256"]):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            if str(offer["identity_sha256"]) != str(local_challenge["peer_sha256"]):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            if str(offer["peer_sha256"]) != str(events["exchange-identity"]["event_sha256"]):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event.update(
                _identity_chain_fields(
                    events, peer_challenge_sha256=str(offer["challenge_sha256"])
                )
            )
            event["offer_sha256"] = offer["event_sha256"]
            written = _write_event(directory_fd, action, event, ())
            return _response(action, _receipt_from_event(written))
        if action == "exchange-data-emit":
            creds = credentials_dir if credentials_dir is not None else WINN_CREDENTIALS_DIR
            materials, created = _generate_and_install_proof_keys_on_vm(
                gateway_binary=gateway_binary,
                credentials_dir=creds,
            )
            held.update(materials)
            if created:
                secret_names.extend(name for _source, name in GATEWAY_PRIVATE_INSTALL)
                secret_dir_name = creds.name
            try:
                secret_parent_fd = _open_parent_dir_fd(creds.parent, "gateway credentials")
                secret_dir_fd = os.open(
                    creds.name, _directory_nofollow_flags(), dir_fd=secret_parent_fd
                )
                _named_inode_matches(
                    secret_parent_fd, creds.name, secret_dir_fd, "gateway credentials directory"
                )
            except OSError as suc:
                raise RemoteInstallError("gateway credentials directory is unsafe") from suc
            secret_map = _hex_values(
                {name: materials[name] for name in EXCHANGE_SECRET_NAMES},
                EXCHANGE_SECRET_NAMES,
                "emit secret",
            )
            public_map = _hex_values(
                {name: materials[name] for name in EXCHANGE_PUBLIC_EMIT_NAMES},
                EXCHANGE_PUBLIC_EMIT_NAMES,
                "emit public",
            )
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event.update(
                _identity_chain_fields(
                    events,
                    peer_challenge_sha256=str(
                        events["exchange-data-accept"]["peer_challenge_sha256"]
                    ),
                )
            )
            event["accept_sha256"] = events["exchange-data-accept"]["event_sha256"]
            event["public_names"] = list(EXCHANGE_PUBLIC_EMIT_NAMES)
            event["public_sha256"] = {
                name: sha256_bytes(materials[name]) for name in EXCHANGE_PUBLIC_EMIT_NAMES
            }
            written = _write_event(
                directory_fd,
                action,
                event,
                [materials[name] for name in EXCHANGE_GATEWAY_SECRETS],
            )
            secret_names.clear()
            secret_dir_name = ""
            _wipe_proof_key_export_hold(creds)
            return _response(
                action,
                _receipt_from_event(written),
                public=public_map,
                secret=secret_map,
                secrets=[materials[name] for name in EXCHANGE_GATEWAY_SECRETS],
            )
        if action == "exchange-control-import":
            if secret is None or public is None:
                raise RemoteInstallError("exchange-control-import requires stdin secret material")
            held.update(secret)
            held.update(public)
            emit_event = _require_peer(peer, "exchange-data-emit")
            _same_binding(emit_event, binding)
            _require_exchange_time(str(emit_event["created_utc"]), now=stamp, origin_utc=origin)
            if str(emit_event["peer_challenge_sha256"]) != str(
                events["exchange-challenge"]["event_sha256"]
            ):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            if str(emit_event["identity_sha256"]) != str(
                events["exchange-challenge"]["peer_sha256"]
            ):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            secret_map = _hex_values(secret, EXCHANGE_SECRET_NAMES, "import secret")
            public_map = _hex_values(public, EXCHANGE_PUBLIC_EMIT_NAMES, "import public")
            for name in EXCHANGE_PUBLIC_EMIT_NAMES:
                expected_digest = emit_event["public_sha256"][name]
                if not hmac.compare_digest(sha256_bytes(public[name]), str(expected_digest)):
                    raise RemoteInstallError("stale or cross-run authenticated key exchange v1 binding")
            dest = proof_client_dir if proof_client_dir is not None else PROOF_CLIENT_CREDENTIALS_DIR
            files = {
                "admission.key": secret["admission.key"],
                "auth_ed25519.pub": public["auth_ed25519.pub"],
                "auth_mldsa65.pub": public["auth_mldsa65.pub"],
                "client.key": secret["client.key"],
                "static.pub": public["static.pub"],
            }
            secret_parent_fd, secret_dir_fd, secret_dir_name, created_proof_dir = (
                _adopt_or_create_proof_client_dir(dest)
            )
            if not created_proof_dir:
                secret_dir_name = ""
            for name, payload in files.items():
                _atomic_nofollow_at(
                    secret_dir_fd,
                    name,
                    payload,
                    EXCHANGE_CREDENTIAL_MODE,
                    f"imported {name}",
                )
                secret_names.append(name)
            _named_inode_matches(
                secret_parent_fd, dest.name, secret_dir_fd, "proof client credentials directory"
            )
            installed = sorted(
                item
                for item in os.listdir(secret_dir_fd)
                if not EXCHANGE_TEMP_RE.fullmatch(item)
            )
            extra = set(installed) - _proof_client_allowed_names()
            missing = set(files) - set(installed)
            if extra or missing:
                raise RemoteInstallError("proof client credentials directory has extra state")
            for name, payload in files.items():
                _require_owner_regular_at(
                    secret_dir_fd,
                    name,
                    f"imported {name}",
                    mode=EXCHANGE_CREDENTIAL_MODE,
                    data=payload,
                )
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event.update(
                _identity_chain_fields(
                    events,
                    peer_challenge_sha256=str(emit_event["challenge_sha256"]),
                )
            )
            event["credential_names"] = sorted(files)
            event["credentials_dir"] = os.fspath(dest)
            event["emit_sha256"] = emit_event["event_sha256"]
            event["offer_sha256"] = events["exchange-control-offer"]["event_sha256"]
            written = _write_event(
                directory_fd,
                action,
                event,
                [secret["admission.key"], secret["client.key"]],
            )
            secret_names.clear()
            secret_dir_name = ""
            return _response(
                action,
                _receipt_from_event(written),
                secrets=[secret["admission.key"], secret["client.key"]],
            )
        if action == "exchange-data-consume":
            if secret is not None:
                raise RemoteInstallError("data-winn3 receives only client.pub")
            if public is None:
                raise RemoteInstallError("exchange-data-consume requires client.pub on stdin")
            _refuse_secret_fields(dict(public), "consume document")
            held.update(public)
            client_pub_map = _hex_values(public, EXCHANGE_CONSUME_PUBLIC_KEYS, "consume public")
            emit_event = events["exchange-data-emit"]
            digest = sha256_bytes(public["client.pub"])
            if not hmac.compare_digest(digest, str(emit_event["public_sha256"]["client.pub"])):
                raise RemoteInstallError("stale or cross-run authenticated key exchange v1 binding")
            if str(emit_event["identity_sha256"]) != str(events["exchange-identity"]["event_sha256"]):
                raise RemoteInstallError(EXCHANGE_MIXING_ERROR)
            registry = (
                peer_registry_path if peer_registry_path is not None else WINN3_PEER_REGISTRY_PATH
            )
            parent = registry.parent
            if parent.exists() or parent.is_symlink():
                _require_safe_dir(parent, "peer registry parent")
            else:
                _prepare_dir(parent, "peer registry parent", mode=0o755)
            secret_parent_fd = _open_parent_dir_fd(parent, "peer registry")
            secret_dir_fd = secret_parent_fd
            secret_dir_name = ""
            document = _peer_registry_document(public["client.pub"], binding["inner_v4"])
            payload = canonical_bytes(document)
            _atomic_nofollow_at(
                secret_parent_fd,
                registry.name,
                payload,
                0o640,
                "proof peer registry",
            )
            secret_names.append(registry.name)
            _require_owner_regular_at(
                secret_parent_fd,
                registry.name,
                "proof peer registry",
                mode=0o640,
                data=payload,
            )
            event = _base_event(
                action,
                role=role,
                instance=instance,
                binding=binding,
                now_utc=stamp,
                origin_utc=origin,
            )
            event.update(
                _identity_chain_fields(
                    events,
                    peer_challenge_sha256=str(emit_event["peer_challenge_sha256"]),
                )
            )
            event["client_pub_sha256"] = digest
            event["emit_sha256"] = emit_event["event_sha256"]
            event["peer_count"] = 1
            event["peer_registry_path"] = os.fspath(registry)
            written = _write_event(directory_fd, action, event, ())
            secret_names.clear()
            return _response(action, _receipt_from_event(written), public=client_pub_map)
        dest = proof_client_dir if proof_client_dir is not None else PROOF_CLIENT_CREDENTIALS_DIR
        names = sorted(name for name, _size in EXCHANGE_CONTROL_CREDENTIALS)
        secret_parent_fd, secret_dir_fd, secret_dir_name = _open_existing_dir(
            dest, "proof client credentials directory", mode=0o700
        )
        secret_dir_name = ""
        installed = sorted(
            item for item in os.listdir(secret_dir_fd) if not EXCHANGE_TEMP_RE.fullmatch(item)
        )
        extra = set(installed) - _proof_client_allowed_names()
        missing = set(names) - set(installed)
        if extra or missing:
            raise RemoteInstallError("proof client credentials directory is incomplete")
        event = _base_event(
            action,
            role=role,
            instance=instance,
            binding=binding,
            now_utc=stamp,
            origin_utc=origin,
        )
        for name, size in EXCHANGE_CONTROL_CREDENTIALS:
            payload = _read_regular_at(
                secret_dir_fd, name, f"imported {name}", expected_mode=EXCHANGE_CREDENTIAL_MODE
            )
            _require_hex_bytes(payload, size, f"imported {name}")
            _require_owner_regular_at(
                secret_dir_fd,
                name,
                f"imported {name}",
                mode=EXCHANGE_CREDENTIAL_MODE,
                data=payload,
            )
            if name in EXCHANGE_SECRET_NAMES:
                held[name] = payload
        event.update(
            _identity_chain_fields(
                events,
                peer_challenge_sha256=str(events["exchange-control-import"]["peer_challenge_sha256"]),
            )
        )
        event["credential_names"] = names
        event["credentials_dir"] = os.fspath(dest)
        event["import_sha256"] = events["exchange-control-import"]["event_sha256"]
        provision_secrets: list[bytes] = []
        if attempt_provision is not None:
            parsed_provision = _load_attempt_provision(attempt_provision)
            fleet = _control_fleet_binding(
                role=role,
                instance=instance,
                binding=binding,
                fleet_binding=fleet_binding,
                fleet_binding_path=fleet_binding_path,
            )
            provision_originals = _provision_attempt_broker_configs(
                dest=dest,
                directory_fd=secret_dir_fd,
                binding=binding,
                fleet=fleet,
                provision=parsed_provision,
            )
            provision_secrets = [
                str(parsed_provision["awg_private_key"]).encode("ascii"),
                str(parsed_provision["xray_uuid"]).encode("ascii"),
            ]
            held["awg_private_key"] = provision_secrets[0]
            held["xray_uuid"] = provision_secrets[1]
        written = _write_event(
            directory_fd,
            action,
            event,
            [held.get("admission.key", b""), held.get("client.key", b""), *provision_secrets],
        )
        response = _response(
            action,
            _receipt_from_event(written),
            secrets=[held.get("admission.key", b""), held.get("client.key", b""), *provision_secrets],
        )
        provision_originals.clear()
        return response
    except Exception:
        if provision_originals:
            _restore_attempt_broker_configs(
                dest,
                provision_originals,
                directory_fd=secret_dir_fd,
            )
        _rollback_at(
            directory_fd=secret_dir_fd if secret_dir_fd >= 0 else None,
            names=secret_names,
            parent_fd=secret_parent_fd if secret_parent_fd >= 0 else None,
            directory_name=secret_dir_name or None,
        )
        raise
    finally:
        if secret_dir_fd >= 0 and secret_dir_fd != secret_parent_fd:
            os.close(secret_dir_fd)
        if secret_parent_fd >= 0:
            os.close(secret_parent_fd)
        os.close(directory_fd)
        _wipe_map(held)


def provision_proof_keys(
    *,
    role: str,
    gateway_binary: Path | None = None,
    credentials_dir: Path | None = None,
    **forbidden: Any,
) -> dict[str, Any]:
    if role != "data-winn3":
        raise RemoteInstallError("proof key provision is data-winn3-only")
    if forbidden:
        raise RemoteInstallError("tar/archive key provisioning is refused")
    binary = gateway_binary if gateway_binary is not None else GATEWAY_INSTALL_PATH
    creds = credentials_dir if credentials_dir is not None else WINN_CREDENTIALS_DIR
    _require_owner_cloud_machine_evidence(gateway_binary=binary, credentials_dir=creds)
    existing = _adopt_complete_gateway_privates(creds)
    if existing is not None:
        receipt = _proof_key_provision_receipt(generated=False)
        _forbid_secret_receipt(receipt, list(existing.values()))
        _wipe_map(existing)
        return receipt
    materials, _created = _generate_and_install_proof_keys_on_vm(
        gateway_binary=binary,
        credentials_dir=creds,
    )
    receipt = _proof_key_provision_receipt(generated=True)
    _forbid_secret_receipt(receipt, list(materials.values()))
    _wipe_map(materials)
    return receipt


def _capture(data: bytes) -> dict[str, Any]:
    original_size = len(data)
    redacted = SECRET_RE.sub(b"[REDACTED]", data)[:MAX_CAPTURE_BYTES]
    return {
        "bytes": len(redacted),
        "data": base64.b64encode(redacted).decode("ascii"),
        "encoding": "base64",
        "original_bytes": original_size,
        "sha256": sha256_bytes(redacted),
        "truncated": original_size > MAX_CAPTURE_BYTES,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _record_digest(record: Mapping[str, Any]) -> str:
    core = dict(record)
    core.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(core))


def _file_runtime(path: Path, *, applicable: bool) -> dict[str, Any]:
    if not applicable:
        return {"applicable": False, "bytes": None, "path": None, "sha256": None}
    data = _read_regular(path, f"runtime artifact {path}")
    return {"applicable": True, "bytes": len(data), "path": str(path), "sha256": sha256_bytes(data)}


def _run_identity(argv: list[str], label: str) -> str:
    try:
        result = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemoteInstallError(f"unable to inspect {label}") from exc
    if result.returncode != 0:
        raise RemoteInstallError(f"unable to inspect {label}")
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RemoteInstallError(f"{label} identity is not ASCII") from exc
    if not value or len(value) > 512 or SECRET_RE.search(result.stdout):
        raise RemoteInstallError(f"{label} identity is invalid")
    return value


def runtime_identities(role: str, manifest: Mapping[str, Any]) -> dict[str, Any]:
    cover_role = role == "data-cover"
    winn = _file_runtime(
        Path("/usr/local/libexec/winn/winn3-gateway"), applicable=role == "data-winn3"
    )
    xray = _file_runtime(Path("/usr/local/bin/xray"), applicable=cover_role)
    if cover_role:
        image = str(manifest["external_pins"]["awg"]["awg_server_image"])
        image_id = _run_identity(
            ["docker", "image", "inspect", "--format={{.Id}}", image], "AWG image"
        )
        provenance = _file_runtime(
            Path("/var/lib/winsvpn/awg-server-image/provenance.json"), applicable=True
        )
        awg = {
            "applicable": True,
            "image": image,
            "image_id": image_id,
            "provenance_receipt": provenance,
        }
    else:
        awg = {"applicable": False, "image": None, "image_id": None, "provenance_receipt": None}
    router_pin = manifest["external_pins"]["router_base_image"]
    router = {
        "applicable": False,
        "deployment_identity": None,
        "image_id": None,
        "manifest_base_image_digest": router_pin["digest"],
        "manifest_base_image_reference": router_pin["reference"],
    }
    return {"awg": awg, "router": router, "winn": winn, "xray": xray}


def _validate_marker_file(path: Path) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o400
    ):
        raise RemoteInstallError("existing deployment identity marker is unsafe")
    raw = strict_json(_read_regular(path, "deployment identity marker"), "deployment identity marker")
    expected = {
        "apply_sha256", "candidate_id", "completed_step_indices",
        "deployment_manifest_sha256", "fleet_completed_step_indices", "fleet_id",
        "fleet_record_chain_sha256", "instance", "kind", "plan_sha256", "role",
        "runtime", "schema_version", "updated_utc",
    }
    if not isinstance(raw, dict) or set(raw) != expected or raw.get("kind") != KIND_MARKER or raw.get("schema_version") != 1:
        raise RemoteInstallError("existing deployment identity marker schema is invalid")
    for key in ("apply_sha256", "candidate_id", "deployment_manifest_sha256", "fleet_record_chain_sha256", "plan_sha256"):
        _safe_sha(f"marker {key}", raw[key])
    if raw["role"] not in {"control", "data-winn3", "data-cover"}:
        raise RemoteInstallError("existing deployment identity marker role is invalid")
    _safe_name("marker instance", raw["instance"])
    _safe_fleet(raw["fleet_id"])
    for key in ("completed_step_indices", "fleet_completed_step_indices"):
        values = raw[key]
        if not isinstance(values, list) or any(type(item) is not int for item in values) or values != sorted(set(values)):
            raise RemoteInstallError(f"existing deployment identity marker {key} is invalid")
    if not isinstance(raw["runtime"], dict) or set(raw["runtime"]) != {"awg", "router", "winn", "xray"}:
        raise RemoteInstallError("existing deployment identity marker runtime schema is invalid")
    if not isinstance(raw["updated_utc"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", raw["updated_utc"]):
        raise RemoteInstallError("existing deployment identity marker timestamp is invalid")
    return raw


def _atomic_marker(path: Path, payload: Mapping[str, Any]) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_info = parent.lstat()
    if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
        raise RemoteInstallError("deployment identity directory is unsafe")
    os.chown(parent, 0, 0)
    os.chmod(parent, 0o700)
    data = canonical_bytes(payload)
    fd, temporary = tempfile.mkstemp(prefix=".deployment-identity.", dir=parent)
    try:
        _write_all(fd, data)
        os.fsync(fd)
        os.fchmod(fd, 0o400)
        os.fchown(fd, 0, 0)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    _validate_marker_file(path)


def _marker_payload(
    args: argparse.Namespace,
    manifest: Mapping[str, Any],
    *,
    completed: list[int],
    chain: str,
    fleet_completed: list[int],
    runtime: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "apply_sha256": args.apply_sha256,
        "completed_step_indices": completed,
        "deployment_manifest_sha256": args.manifest_sha256,
        "fleet_completed_step_indices": fleet_completed,
        "fleet_id": args.fleet_id,
        "fleet_record_chain_sha256": chain,
        "instance": args.instance,
        "kind": KIND_MARKER,
        "plan_sha256": args.plan_sha256,
        "role": args.role,
        "runtime": dict(runtime),
        "schema_version": SCHEMA_VERSION,
        "updated_utc": _utc_now(),
        "candidate_id": manifest["candidate_id"],
    }


def _validate_common(args: argparse.Namespace) -> None:
    if os.geteuid() != 0:
        raise RemoteInstallError("remote installer must run as root")
    _safe_fleet(args.fleet_id)
    _safe_name("instance", args.instance)
    if args.role not in {"control", "data-winn3", "data-cover"}:
        raise RemoteInstallError("role is invalid")
    if Path(args.marker) != MARKER_PATH or Path(args.state_root) != STATE_ROOT:
        raise RemoteInstallError("deployment marker and state root are fixed")
    if args.timeout_seconds != 3600:
        raise RemoteInstallError("installer timeout is fixed")
    for label in ("plan", "apply", "manifest", "bundle", "helper", "previous record"):
        _safe_sha(f"{label} SHA-256", getattr(args, f"{label.replace(' ', '_')}_sha256"))


def _validate_staged_paths(args: argparse.Namespace, manifest: Mapping[str, Any]) -> None:
    token = manifest["candidate_id"][:24]
    expected = {
        "bundle": Path(f"/tmp/winsvpn-proof-{token}.tar"),
        "manifest": Path(f"/tmp/winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json"),
        "manifest_sidecar": Path(f"/tmp/winsvpn-proof-{token}-DEPLOYMENT_INPUTS.json.sha256"),
    }
    for attribute, path in expected.items():
        if Path(getattr(args, attribute)) != path:
            raise RemoteInstallError(f"remote staged {attribute} path is not fixed")
    if Path(__file__) != Path(f"/tmp/winsvpn-proof-{token}-remote.py"):
        raise RemoteInstallError("remote helper path is not fixed to the deployment candidate")


def _bind_step_installer(args: argparse.Namespace, manifest: Mapping[str, Any]) -> None:
    if _is_proof_key_provision(args.script, args.flag):
        if args.script_bytes != 0 or args.script_mode != 0 or args.script_sha256 != ZERO_SHA256:
            raise RemoteInstallError("proof key provision step refuses installer bytes")
        return
    installer = next((item for item in manifest["installers"] if item["path"] == args.script), None)
    if installer is None or installer != {
        "bytes": args.script_bytes,
        "mode": args.script_mode,
        "path": args.script,
        "sha256": args.script_sha256,
    }:
        raise RemoteInstallError("installer reference does not match the deployment manifest")


def run_step(args: argparse.Namespace) -> dict[str, Any]:
    _validate_common(args)
    if not 0 <= args.step_index < len(EXPECTED_STEPS):
        raise RemoteInstallError("step index is invalid")
    expected_role, expected_script, expected_flag = EXPECTED_STEPS[args.step_index]
    if (args.role, args.script, args.flag) != (expected_role, expected_script, expected_flag):
        raise RemoteInstallError("caller-authored, reordered, or wrong-role installer step refused")
    if args.final_role_step is not (args.step_index in final_role_step_indices()):
        raise RemoteInstallError("final-role-step marker does not match the fixed sequence")
    if args.fleet_completed_step_indices != []:
        raise RemoteInstallError("step action cannot accept caller-authored fleet completion state")
    helper_data = _read_regular(Path(__file__), "remote installer", expected_sha256=args.helper_sha256)
    if not helper_data:
        raise RemoteInstallError("remote installer is empty")
    manifest = _load_manifest(Path(args.manifest), Path(args.manifest_sidecar), args.manifest_sha256)
    _validate_staged_paths(args, manifest)
    bundle_data = verify_bundle(Path(args.bundle), args.bundle_sha256, manifest)
    _bind_step_installer(args, manifest)
    marker = _validate_marker_file(Path(args.marker))
    completed: list[int] = []
    if marker is not None:
        if (
            marker.get("fleet_id") != args.fleet_id
            or marker.get("role") != args.role
            or marker.get("instance") != args.instance
            or marker.get("plan_sha256") != args.plan_sha256
            or marker.get("apply_sha256") != args.apply_sha256
            or marker.get("deployment_manifest_sha256") != args.manifest_sha256
            or marker.get("candidate_id") != manifest["candidate_id"]
        ):
            raise RemoteInstallError("existing deployment marker belongs to another target")
        completed_raw = marker.get("completed_step_indices")
        if not isinstance(completed_raw, list) or any(type(item) is not int for item in completed_raw):
            raise RemoteInstallError("existing deployment marker step list is invalid")
        completed = list(completed_raw)
        if args.step_index in completed:
            raise RemoteInstallError("duplicate deployment step refused")
        if marker.get("fleet_record_chain_sha256") != args.previous_record_sha256:
            raise RemoteInstallError("deployment record chain does not continue the marker")
    expected_completed = required_completed_indices(args.role, args.step_index)
    if completed != expected_completed:
        raise RemoteInstallError("skipped or reordered deployment step refused")
    candidate_root = Path(args.state_root) / "candidates" / manifest["candidate_id"] / f"step-{args.step_index}"
    _extract_bundle(bundle_data, candidate_root, manifest)
    _bind_extracted_tree(candidate_root, manifest)
    if args.role == "control":
        install_proof_client_artifact(
            candidate_root,
            manifest,
            product="winn3-probe",
            destination=PROBE_INSTALL_PATH,
        )
        if args.step_index == 0:
            install_client_runtime_artifacts(candidate_root, manifest)
    elif args.role == "data-winn3":
        stage_gateway_artifact(candidate_root, manifest, GATEWAY_STAGING_DIR)
        install_proof_client_artifact(
            candidate_root,
            manifest,
            product="winn-ech-keygen",
            destination=ECH_KEYGEN_INSTALL_PATH,
        )
    install_remote_action_helper(
        candidate_root,
        manifest,
        role=args.role,
        fleet_id=args.fleet_id,
        instance=args.instance,
        candidate_id=str(manifest["candidate_id"]),
        destination=REMOTE_ACTION_HELPER_INSTALL_FILE,
        identity_path=REMOTE_ACTION_HELPER_IDENTITY_PATH,
    )
    if args.role == "control":
        install_attempt_broker(
            candidate_root,
            manifest,
            role=args.role,
            fleet_id=args.fleet_id,
            instance=args.instance,
            candidate_id=str(manifest["candidate_id"]),
            destination=ATTEMPT_BROKER_INSTALL_FILE,
            identity_path=ATTEMPT_BROKER_IDENTITY_PATH,
            role_path=ATTEMPT_BROKER_ROLE_PATH,
            fleet_binding_path=ATTEMPT_BROKER_FLEET_BINDING_PATH,
            unit_root=ATTEMPT_BROKER_UNIT_ROOT,
            config_root=ATTEMPT_BROKER_CONFIG_ROOT,
            fleet_binding=_fleet_binding_from_args(args),
        )
    started = _utc_now()
    if _is_proof_key_provision(args.script, args.flag):
        provision_proof_keys(role=args.role)
        exit_code = 0
        stdout, stderr = b"", b""
    else:
        script_path = candidate_root.joinpath(*PurePosixPath(args.script).parts)
        try:
            result = subprocess.run(
                ["bash", str(script_path), args.flag],
                cwd=candidate_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                check=False,
                timeout=args.timeout_seconds,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            )
            exit_code = int(result.returncode)
            stdout, stderr = bytes(result.stdout), bytes(result.stderr)
        except subprocess.TimeoutExpired as exc:
            exit_code = 124
            stdout = bytes(exc.stdout or b"")
            stderr = bytes(exc.stderr or b"") + b"\ninstaller timed out\n"
    ended = _utc_now()
    record: dict[str, Any] = {
        "apply_sha256": args.apply_sha256,
        "ended_utc": ended,
        "exit_code": exit_code,
        "flag": args.flag,
        "fleet_id": args.fleet_id,
        "instance": args.instance,
        "kind": KIND_RECORD,
        "manifest_sha256": args.manifest_sha256,
        "plan_sha256": args.plan_sha256,
        "previous_sha256": args.previous_record_sha256,
        "role": args.role,
        "schema_version": SCHEMA_VERSION,
        "script": args.script,
        "script_ref": {"bytes": args.script_bytes, "mode": args.script_mode, "sha256": args.script_sha256},
        "started_utc": started,
        "stderr": _capture(stderr),
        "stdout": _capture(stdout),
        "step_index": args.step_index,
    }
    record["record_sha256"] = _record_digest(record)
    if exit_code == 0:
        completed.append(args.step_index)
        runtime = runtime_identities(args.role, manifest) if args.final_role_step else {
            "awg": {"applicable": None}, "router": {"applicable": None},
            "winn": {"applicable": None}, "xray": {"applicable": None},
        }
        marker_payload = _marker_payload(
            args,
            manifest,
            completed=completed,
            chain=record["record_sha256"],
            fleet_completed=list(range(args.step_index + 1)),
            runtime=runtime,
        )
        _atomic_marker(Path(args.marker), marker_payload)
    return {
        "kind": KIND_RESPONSE,
        "marker_updated": exit_code == 0,
        "ok": exit_code == 0,
        "record": record,
        "schema_version": SCHEMA_VERSION,
    }


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    _validate_common(args)
    if (
        args.step_index != -1
        or args.script != ""
        or args.script_sha256 != ZERO_SHA256
        or args.script_bytes != 0
        or args.script_mode != 0
        or args.flag != ""
        or args.final_role_step
    ):
        raise RemoteInstallError("finalize action refuses installer fields")
    _read_regular(Path(__file__), "remote installer", expected_sha256=args.helper_sha256)
    manifest = _load_manifest(Path(args.manifest), Path(args.manifest_sidecar), args.manifest_sha256)
    _validate_staged_paths(args, manifest)
    verify_bundle(Path(args.bundle), args.bundle_sha256, manifest)
    marker = _validate_marker_file(Path(args.marker))
    if marker is None:
        raise RemoteInstallError("deployment marker is missing at finalization")
    if (
        marker.get("fleet_id") != args.fleet_id
        or marker.get("role") != args.role
        or marker.get("instance") != args.instance
        or marker.get("plan_sha256") != args.plan_sha256
        or marker.get("apply_sha256") != args.apply_sha256
        or marker.get("deployment_manifest_sha256") != args.manifest_sha256
        or marker.get("candidate_id") != manifest["candidate_id"]
    ):
        raise RemoteInstallError("deployment marker binding is invalid at finalization")
    role_steps = [index for index, item in enumerate(EXPECTED_STEPS) if item[0] == args.role]
    if marker.get("completed_step_indices") != role_steps:
        raise RemoteInstallError("role deployment steps are incomplete")
    if args.fleet_completed_step_indices != list(range(len(EXPECTED_STEPS))):
        raise RemoteInstallError("fleet deployment steps are incomplete or reordered")
    helper = _remote_action_helper_binding(manifest, _manifest_records(manifest))
    require_complete_remote_action_helper(
        REMOTE_ACTION_HELPER_INSTALL_FILE,
        REMOTE_ACTION_HELPER_IDENTITY_PATH,
        expected_sha256=helper["sha256"],
        expected_bytes=helper["bytes"],
        expected_mode=REMOTE_ACTION_HELPER_INSTALL_MODE,
        role=args.role,
        fleet_id=args.fleet_id,
        instance=args.instance,
        candidate_id=str(manifest["candidate_id"]),
        source_path=helper["path"],
    )
    if args.role == "control":
        broker = _attempt_broker_binding(manifest, _manifest_records(manifest))
        require_complete_attempt_broker(
            ATTEMPT_BROKER_INSTALL_FILE,
            ATTEMPT_BROKER_IDENTITY_PATH,
            expected_sha256=broker["sha256"],
            expected_bytes=broker["bytes"],
            expected_mode=ATTEMPT_BROKER_INSTALL_MODE,
            role=args.role,
            fleet_id=args.fleet_id,
            instance=args.instance,
            candidate_id=str(manifest["candidate_id"]),
            source_path=broker["path"],
            binding=broker,
            role_path=ATTEMPT_BROKER_ROLE_PATH,
            fleet_binding_path=ATTEMPT_BROKER_FLEET_BINDING_PATH,
            unit_root=ATTEMPT_BROKER_UNIT_ROOT,
            config_root=ATTEMPT_BROKER_CONFIG_ROOT,
            require_fleet_binding=True,
        )
    payload = _marker_payload(
        args,
        manifest,
        completed=role_steps,
        chain=args.previous_record_sha256,
        fleet_completed=args.fleet_completed_step_indices,
        runtime=runtime_identities(args.role, manifest),
    )
    _atomic_marker(Path(args.marker), payload)
    return {"kind": KIND_RESPONSE, "marker": payload, "marker_updated": True, "ok": True, "schema_version": 1}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--action", choices=INSTALLER_ACTIONS + EXCHANGE_ACTIONS, required=True)
    result.add_argument("--bundle", required=True)
    result.add_argument("--bundle-sha256", required=True)
    result.add_argument("--manifest", required=True)
    result.add_argument("--manifest-sidecar", required=True)
    result.add_argument("--manifest-sha256", required=True)
    result.add_argument("--helper-sha256", required=True)
    result.add_argument("--plan-sha256", required=True)
    result.add_argument("--apply-sha256", required=True)
    result.add_argument("--fleet-id", required=True)
    result.add_argument("--fleet-binding-json", default="")
    result.add_argument("--role", required=True)
    result.add_argument("--instance", required=True)
    result.add_argument("--previous-record-sha256", required=True)
    result.add_argument("--marker", default=str(MARKER_PATH))
    result.add_argument("--state-root", default=str(STATE_ROOT))
    result.add_argument("--step-index", type=int, default=-1)
    result.add_argument("--script", default="")
    result.add_argument("--script-sha256", default=ZERO_SHA256)
    result.add_argument("--script-bytes", type=int, default=0)
    result.add_argument("--script-mode", type=int, default=0)
    result.add_argument("--flag", default="")
    result.add_argument("--final-role-step", action="store_true")
    result.add_argument("--fleet-completed-step-indices", type=json.loads, default=[])
    result.add_argument("--timeout-seconds", type=int, default=3600)
    result.add_argument("--candidate-id", default="")
    result.add_argument("--source-role", default="")
    result.add_argument("--source-instance", default="")
    result.add_argument("--target-role", default="")
    result.add_argument("--target-instance", default="")
    result.add_argument("--source-instance-id", default="")
    result.add_argument("--target-instance-id", default="")
    result.add_argument("--source-boot-id", default="")
    result.add_argument("--target-boot-id", default="")
    result.add_argument("--inner-v4", default=PROOF_CLIENT_INNER_V4)
    return result


def _forbid_archive_bytes(data: bytes) -> None:
    if data.startswith(b"\x1f\x8b") or data.startswith(b"PK"):
        raise RemoteInstallError("tar/archive key provisioning is refused")
    if len(data) >= 262 and data[257:262] == b"ustar":
        raise RemoteInstallError("tar/archive key provisioning is refused")


def _read_bounded_stdin(stream: Any | None = None) -> bytes:
    source = sys.stdin.buffer if stream is None else stream
    data = source.read(EXCHANGE_MAX_BYTES + 1)
    if len(data) > EXCHANGE_MAX_BYTES:
        raise RemoteInstallError("authenticated key exchange v1 document is too large")
    return data


def _sanitize_refusal(message: str) -> str:
    try:
        encoded = message.encode("ascii")
    except UnicodeEncodeError:
        return "authenticated key exchange v1 refused without disclosing secret material"
    if SECRET_RE.search(encoded):
        return "authenticated key exchange v1 refused without disclosing secret material"
    return message


def run_exchange(args: argparse.Namespace, *, stdin_data: bytes | None = None) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise RemoteInstallError("remote installer must run as root")
    data = stdin_data if stdin_data is not None else _read_bounded_stdin()
    peer: dict[str, Any] | None = None
    secret: dict[str, bytes] | None = None
    public: dict[str, bytes] | None = None
    attempt_provision: dict[str, Any] | None = None
    fleet_binding: dict[str, Any] | None = None
    raw_binding = getattr(args, "fleet_binding_json", "")
    if type(raw_binding) is str and raw_binding:
        fleet_binding = _fleet_binding_from_args(args)
    if data:
        _forbid_archive_bytes(data)
        raw = strict_json(data, "authenticated key exchange v1 stdin")
        if not isinstance(raw, dict):
            raise RemoteInstallError("authenticated key exchange v1 stdin schema is invalid")
        if raw.get("kind") == KIND_ATTEMPT_PROVISION:
            attempt_provision = raw
        elif raw.get("kind") == KIND_EXCHANGE_RESPONSE:
            expected = set(EXCHANGE_RESPONSE_KEYS)
            if "attempt_provision" in raw:
                expected = expected | {"attempt_provision"}
            payload = _exact_keys(raw, expected, "authenticated key exchange v1 stdin")
            if args.action == "exchange-data-consume" and payload["secret"] is not None:
                raise RemoteInstallError("data-winn3 receives only client.pub")
            if payload["secret"] is not None:
                secret = _parse_hex_values(payload["secret"], EXCHANGE_SECRET_NAMES, "stdin secret")
            if payload["public"] is not None:
                names = (
                    EXCHANGE_CONSUME_PUBLIC_KEYS
                    if args.action == "exchange-data-consume"
                    else EXCHANGE_PUBLIC_EMIT_NAMES
                )
                public = _parse_hex_values(payload["public"], names, "stdin public")
            if isinstance(payload["receipt"], dict):
                peer = payload["receipt"]
            extra = payload.get("attempt_provision")
            if extra is not None:
                if not isinstance(extra, dict):
                    raise RemoteInstallError("attempt broker provision schema is invalid")
                attempt_provision = extra
        else:
            peer = raw
    return run_exchange_action(
        args.action,
        role=args.role,
        instance=args.instance,
        fleet_id=args.fleet_id,
        candidate_id=args.candidate_id,
        source_role=args.source_role,
        source_instance=args.source_instance,
        target_role=args.target_role,
        target_instance=args.target_instance,
        inner_v4=args.inner_v4,
        apply_sha256=args.apply_sha256,
        bundle_sha256=args.bundle_sha256,
        helper_sha256=args.helper_sha256,
        manifest_sha256=args.manifest_sha256,
        plan_sha256=args.plan_sha256,
        source_instance_id=args.source_instance_id,
        target_instance_id=args.target_instance_id,
        source_boot_id=args.source_boot_id,
        target_boot_id=args.target_boot_id,
        peer=peer,
        secret=secret,
        public=public,
        attempt_provision=attempt_provision,
        fleet_binding=fleet_binding,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action in EXCHANGE_ACTIONS:
            value = run_exchange(args)
        else:
            value = run_step(args) if args.action == "step" else finalize(args)
    except RemoteInstallError as exc:
        value = {
            "kind": KIND_RESPONSE,
            "marker_updated": False,
            "ok": False,
            "refusal": _sanitize_refusal(str(exc)),
            "schema_version": 1,
        }
        sys.stdout.buffer.write(canonical_bytes(value))
        return 2
    sys.stdout.buffer.write(canonical_bytes(value))
    if args.action == "step" and not value["ok"]:
        return max(1, min(125, int(value["record"]["exit_code"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
