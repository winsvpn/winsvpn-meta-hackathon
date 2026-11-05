#!/usr/bin/env python3
"""Emit-only three-VM GCP proof planner and fail-closed evidence verifier."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shlex
import stat
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gcp_client_release_binding as client_binding
import gcp_deployment_inputs as deployment_inputs
import release_dependency_freeze as freeze


KIND_PLAN = "winsvpn.gcp_proof_fleet.plan.v4"
KIND_APPLY = "winsvpn.gcp_proof_fleet.apply.v4"
KIND_VERIFY = "winsvpn.gcp_proof_fleet.verify.v4"
KIND_RESET = "winsvpn.gcp_proof_fleet.reset.v4"
KIND_RECEIPT = "winsvpn.gcp_proof_fleet.acceptance_receipt.v4"
KIND_EVIDENCE = "winsvpn.gcp_proof_evidence.collector_bundle.v4"
KIND_COMMAND = "winsvpn.gcp_proof.command_record.v2"
KIND_OBSERVATION = "winsvpn.gcp_proof.observation.v3"
KIND_EXECUTION = "winsvpn.gcp_proof.deployment_execution.v3"
KIND_MARKER = "winsvpn.gcp_proof.deployment_identity.v1"
KIND_RECORD = "winsvpn.gcp_proof.deployment_step_record.v1"
KIND_EMERGENCY = "winsvpn.gcp_proof_fleet.emergency_cleanup_evidence.v1"
KIND_RELEASE_ARTIFACTS = "winsvpn.gcp_proof_fleet.required_release_artifacts.v1"
KIND_RELEASE_ARTIFACT_IDENTITY = (
    "winsvpn.gcp_proof_fleet.release_artifact_identity.v1"
)
SCHEMA_VERSION = 4
RELEASE_ARTIFACTS_SCHEMA_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 4
EXECUTION_SCHEMA_VERSION = 3
EXECUTION_PRODUCER_NAME = "gcp_proof_deploy.py"
REVIEWED_LIVE_PROBE_NAME = "gcp_proof_live_probe.py"
REVIEWED_LIVE_PROBE_PATH = Path(__file__).with_name(REVIEWED_LIVE_PROBE_NAME)
MARKER_SCHEMA_VERSION = 1
PHASES = ("plan", "apply", "verify", "reset", "emergency-cleanup")
ROLES = ("control", "data-winn3", "data-cover")
REFUSAL_EXIT = 2
PLAN_NAME = "plan.json"
APPLY_NAME = "apply.json"
RECEIPT_NAME = "acceptance-receipt.json"
EXECUTION_NAME = "deployment-execution.json"
EMERGENCY_NAME = "emergency-cleanup-evidence.json"
REQUIRED_RELEASE_ARTIFACTS_NAME = "required-release-artifacts.json"
ZERO_SHA256 = "0" * 64
REMOTE_MARKER_PATH = "/var/lib/winsvpn-proof/deployment-identity.json"
REMOTE_STATE_ROOT = "/var/lib/winsvpn-proof"
REMOTE_CANDIDATES_ROOT = "/var/lib/winsvpn-proof/candidates"
EVIDENCE_PRODUCER_NAME = "gcp_proof_evidence.py"
EVIDENCE_PRODUCER_PATH = Path(__file__).with_name(EVIDENCE_PRODUCER_NAME)
VERIFIER_PATH = Path(__file__)
CLIENT_BINDING_REFERENCE_CONTRACT = (
    "winsvpn-gcp-client-release-binding-reference-v1"
)
CLIENT_BINDING_REFERENCE_KEYS = {
    "binding",
    "binding_sha256",
    "contract",
    "repo_root",
    "schema_version",
    "verifier_closure",
}
CLIENT_BINDING_KEYS = {
    "artifact",
    "artifact_input_fingerprint_sha256",
    "build_identity",
    "build_receipt",
    "contract",
    "platform",
    "release",
    "release_input_index",
    "schema_version",
    "shared_revision",
    "proof_build",
}
CLIENT_PROOF_BUILD_KEYS = {
    "build_contract", "build_identity", "builder", "defines", "source",
    "target", "toolchain", "toolchain_pin_manifest",
}
CLIENT_BINDING_FILE_KEYS = {"bytes", "path", "sha256"}
CLIENT_BINDING_CLOSURE_KEYS = {
    "proof_client_builder",
    "client_release_binding",
    "release_dependency_freeze",
}
DEPLOYMENT_INPUT_KEYS = {"bytes", "candidate_id", "path", "sha256"}
MAX_EVIDENCE_AGE = timedelta(hours=6)
MAX_PROOF_WINDOW = timedelta(hours=4)
MAX_CLOCK_SKEW = timedelta(minutes=5)
MAX_CAPTURE_BYTES = 4 * 1024 * 1024
ACCEPTANCE_RECEIPT_KEYS = {
    "kind",
    "schema_version",
    "phase",
    "created_utc",
    "verdict",
    "plan_sha256",
    "apply_sha256",
    "fleet",
    "evidence_bundle",
    "bindings",
    "verifier",
    "checks",
}

DEFAULT_IMAGE_FAMILY = "ubuntu-2404-lts-amd64"
DEFAULT_IMAGE_PROJECT = "ubuntu-os-cloud"
CONTROL_INSTALLER = "server/wins_control_plane_setup_ONETOUCH.sh"
DATA_INSTALLER = "server/wins_data_plane_setup_ONETOUCH.sh"
GATEWAY_INSTALLER = "server/wins_winn3_gateway_install.sh"
PROOF_KEY_PROVISION_ID = "winsvpn.gcp_proof.winn3_on_vm_key_provision.v1"
PROOF_KEY_PROVISION_FLAG = "--on-vm-generate"
GATEWAY_SERVICE = "winn3-gateway.service"
ROLE_DEPLOY_SERVICES = {
    "control": {"wins-hub.service": "active", GATEWAY_SERVICE: "inactive"},
    "data-winn3": {GATEWAY_SERVICE: "active"},
    "data-cover": {
        "docker.service": "active",
        "xray.service": "active",
        GATEWAY_SERVICE: "inactive",
    },
}
ROLE_DEPLOY_UNITS = {
    "control": {
        "wins-hub.service": "/etc/systemd/system/wins-hub.service",
    },
    "data-winn3": {
        GATEWAY_SERVICE: "/etc/systemd/system/winn3-gateway.service",
    },
    "data-cover": {
        "xray.service": "/etc/systemd/system/xray.service",
    },
}
ROLE_DEPLOY_CONFIGS = {
    "control": ("/etc/winsvpn/role",),
    "data-winn3": ("/etc/winsvpn/role",),
    "data-cover": ("/etc/winsvpn/role",),
}
ROLE_RUNTIME_BINARIES = {
    "control": {"winn": None, "xray": None},
    "data-winn3": {
        "winn": "/usr/local/libexec/winn/winn3-gateway",
        "xray": None,
    },
    "data-cover": {"winn": None, "xray": "/usr/local/bin/xray"},
}
AWG_PROVENANCE_PATH = "/var/lib/winsvpn/awg-server-image/provenance.json"
ELF_MACHINES = {3: "x86", 62: "x86_64", 183: "aarch64"}
TEXT_ARCHITECTURE = "text"
EXECUTION_RECEIPT_KEYS = {
    "apply_sha256",
    "bundle_sha256",
    "candidate_id",
    "cleanup",
    "client_release_binding",
    "deployment_inputs",
    "deployment_manifest_sha256",
    "ended_utc",
    "failure",
    "fleet_id",
    "kind",
    "markers",
    "plan_sha256",
    "preflight",
    "record_chain_sha256",
    "records",
    "remote_helper_sha256",
    "schema_version",
    "started_utc",
    "status",
}
CLEANUP_KEYS = {
    "acceptance_receipt_required",
    "authorized",
    "remote",
    "resources",
    "status",
}
CLEANUP_RESOURCES_KEYS = {
    "reason",
    "results",
    "status",
    "targets",
}
PREFLIGHT_KEYS = {
    "firewalls",
    "instances",
    "network",
    "subnets",
}
PREFLIGHT_IDENTITY_KEYS = {
    "can_ip_forward",
    "creation_transaction",
    "fleet_id",
    "labels",
    "machine_type",
    "name",
    "project",
    "role",
    "zone",
}
CREATION_TRANSACTION_KEYS = {"creation_timestamp", "id", "self_link"}
RESOURCE_IDENTITY_BASE_KEYS = {
    "creation_transaction",
    "fingerprint",
    "kind",
    "label_fingerprint",
    "labels",
    "name",
    "project",
    "type",
}
FIREWALL_IDENTITY_KEYS = RESOURCE_IDENTITY_BASE_KEYS | {"network"}
SUBNET_IDENTITY_KEYS = RESOURCE_IDENTITY_BASE_KEYS | {"network", "region"}
NETWORK_IDENTITY_KEYS = set(RESOURCE_IDENTITY_BASE_KEYS)
RESOURCE_KINDS = {
    "firewall": "compute#firewall",
    "network": "compute#network",
    "subnet": "compute#subnetwork",
}
ROLE_FILE_PAYLOADS = {
    "control": b"control\n",
    "data-winn3": b"data-winn3\n",
    "data-cover": b"data-cover\n",
}
RESOURCE_FIREWALL_SUFFIXES = {
    "admin_ssh": "admin-ssh",
    "control_http": "control-http",
    "winn3_ingress": "winn3-in",
    "cover_ingress": "cover-in",
}
REVIEWED_UNIT_SOURCES = {
    ("control", "wins-hub.service"): "remote-units/control/wins-hub.service",
    ("data-winn3", GATEWAY_SERVICE): (
        "winn_protocol_experimental/deploy/systemd/winn3-gateway.service"
    ),
    ("data-cover", "xray.service"): "remote-units/data-cover/xray.service",
}
REQUIRED_RELEASE_ARTIFACTS = (
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
)
LINUX_X64_ARTIFACT_ID = "linux-x64-package"
REQUIRED_RELEASE_ARTIFACT_COUNT = 16
REQUIRED_RELEASE_ARTIFACTS_CONTRACT = (
    "winsvpn-gcp-required-release-artifacts-v1"
)
REQUIRED_RELEASE_ARTIFACTS_DOCUMENT_KEYS = {
    "artifacts",
    "contract",
    "created_utc",
    "kind",
    "release_input_index",
    "schema_version",
    "target_receipts",
}
RELEASE_ARTIFACT_IDENTITY_KEYS = {
    "artifact",
    "created_utc",
    "kind",
    "release_input_index",
    "schema_version",
    "target_id",
}
CALLER_AUTHORED_TARGET_ASSIGNMENT_KINDS = frozenset(
    {
        KIND_RELEASE_ARTIFACT_IDENTITY,
        KIND_RELEASE_ARTIFACTS,
        KIND_RECEIPT,
    }
)
REQUIRED_RELEASE_ARTIFACT_SUFFIXES = {
    "android-phone-tablet-aab": (".aab",),
    "android-tv-aab": (".aab",),
    "wear-os-aab": (".aab",),
    "ios-app-store-ipa": (".ipa",),
    "macos-app-store-pkg": (".pkg",),
    "windows-x64-installer": (".exe",),
    "windows-x64-partner-center": (".exe",),
    "windows-arm64-installer": (".exe",),
    "windows-arm64-partner-center": (".exe",),
    "linux-x64-package": (".tar.gz",),
    "linux-arm64-package": (".tar.gz",),
    "linux-flathub-manifest": (".json",),
    "linux-snap-manifest": (".yaml", ".yml"),
    "chrome-extension-package": (".zip",),
    "edge-extension-package": (".zip",),
    "firefox-extension-package": (".xpi", ".zip"),
}
MARKER_KEYS = {
    "apply_sha256",
    "candidate_id",
    "completed_step_indices",
    "deployment_manifest_sha256",
    "fleet_completed_step_indices",
    "fleet_id",
    "fleet_record_chain_sha256",
    "instance",
    "kind",
    "plan_sha256",
    "role",
    "runtime",
    "schema_version",
    "updated_utc",
}
FILE_RUNTIME_KEYS = {"applicable", "bytes", "path", "sha256"}
AWG_RUNTIME_KEYS = {"applicable", "image", "image_id", "provenance_receipt"}
ROUTER_RUNTIME_KEYS = {
    "applicable",
    "deployment_identity",
    "image_id",
    "manifest_base_image_digest",
    "manifest_base_image_reference",
}
DEPLOYMENT_ROLE_OBSERVATION_KEYS = {
    "candidate",
    "configs",
    "instance",
    "marker",
    "os_id",
    "os_version",
    "role",
    "role_file",
    "runtime",
    "services",
    "units",
}
AUTHENTICATED_FILE_KEYS = {
    "architecture",
    "bytes",
    "path",
    "sha256",
    "version",
}
UNIT_IDENTITY_KEYS = AUTHENTICATED_FILE_KEYS | {"active_state"}
CANDIDATE_OBSERVATION_KEYS = {"files", "id"}
CANDIDATE_FILE_KEYS = {"bytes", "path", "sha256"}
EXECUTION_RECORD_KEYS = {
    "apply_sha256",
    "ended_utc",
    "exit_code",
    "flag",
    "fleet_id",
    "instance",
    "kind",
    "manifest_sha256",
    "plan_sha256",
    "previous_sha256",
    "record_sha256",
    "role",
    "schema_version",
    "script",
    "script_ref",
    "started_utc",
    "stderr",
    "stdout",
    "step_index",
}

GCE_NAME_RE = re.compile(r"^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$")
GCE_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+-[a-z]$")
MACHINE_TYPE_RE = re.compile(r"^[a-z][a-z0-9]*-[a-z0-9-]+$")
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
GCE_ID_RE = re.compile(r"^[1-9][0-9]{0,31}$")
SELF_LINK_RE = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/zones/"
    r"([a-z]+-[a-z]+[0-9]+-[a-z])/instances/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)$"
)
FIREWALL_LINK_RE = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/global/firewalls/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)$"
)
NETWORK_LINK_RE = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/global/networks/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)$"
)
SUBNET_LINK_RE = re.compile(
    r"^https://www\.googleapis\.com/compute/v1/projects/"
    r"([a-z][a-z0-9-]{4,28}[a-z0-9])/regions/"
    r"([a-z]+-[a-z]+[0-9]+)/subnetworks/"
    r"([a-z]([-a-z0-9]{0,61}[a-z0-9])?)$"
)
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9+/_-]{8,128}={0,3}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SHELL_META_RE = re.compile(r"[^\w./+-]")
RESERVED_INSTANCE_NAMES = frozenset(
    {
        "control-sim",
        "data-sim",
        "core-sim",
        "data-sim-winn3gw",
        "xprize-hub",
        "xprize-route-a",
        "xprize-route-b",
    }
)
RESERVED_NAME_MARKERS = frozenset(
    {
        "control-sim",
        "data-sim",
        "core-sim",
        "data-sim-winn3gw",
        "xprize",
        "xprize-hub",
        "xprize-route-a",
        "xprize-route-b",
    }
)
RESERVED_PROJECT_MARKERS = frozenset(
    {"prod", "production", "xprize", "staging", "live"}
)
FORBIDDEN_TAGS = frozenset({"hub", "allow-http-sim", "http-server", "https-server"})
FORBIDDEN_FLAGS = (
    "--execute",
    "--force-execute",
    "--apply-live",
    "--ssh-key",
    "--ssh-keys",
    "--metadata-from-file",
    "--service-account-key-file",
    "--impersonate-service-account",
    "--password",
    "--token",
    "--credential-file",
    "--private-key",
    "--account-file",
)
SECRET_RE = re.compile(
    r"(-----BEGIN )|(PRIVATE KEY)|\bAIza[0-9A-Za-z_\-]{20,}|\bya29\.[0-9A-Za-z._\-]+|(client_secret)|(GOOGLE_APPLICATION_CREDENTIALS)|(service_account)|(-----BEGIN OPENSSH)",
    re.IGNORECASE,
)
FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "metadata",
        "sshkeys",
        "ssh-keys",
        "privatekey",
        "private_key",
        "serviceaccounts",
        "disks",
        "networkinterfaces",
        "secrets",
        "token",
        "accessconfig",
        "accessconfigs",
    }
)
MUTATION_ARGV_PREFIXES = (
    ("compute", "instances", "create"),
    ("compute", "instances", "update"),
    ("compute", "instances", "delete"),
    ("compute", "networks", "create"),
    ("compute", "networks", "delete"),
    ("compute", "networks", "subnets", "create"),
    ("compute", "networks", "subnets", "delete"),
    ("compute", "firewall-rules", "create"),
    ("compute", "firewall-rules", "delete"),
)
COLLECTOR_ACTIONS = (
    "inventory",
    "deployment",
    "route-decision",
    "connect-primary",
    "connect-cover-awg",
    "connect-cover-xray",
    "inject-awg-block",
    "probe-awg-block",
    "restore-awg",
    "inject-winn3-block",
    "probe-winn3-block",
    "withdraw-cover",
    "probe-cover-withdrawn",
    "restore-cover",
    "restore-winn3",
    "teardown-check",
)
FORBIDDEN_OBSERVATION_KEYS = frozenset(
    {"pass", "passed", "ok", "success", "verdict", "acceptance"}
)


class FleetRefused(Exception):
    """Fail-closed refusal."""


@dataclass(frozen=True)
class InstanceSpec:
    role: str
    name: str
    zone: str
    machine_type: str

    def as_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "name": self.name,
            "zone": self.zone,
            "machine_type": self.machine_type,
            "region": region_of(self.zone),
        }


@dataclass(frozen=True)
class FleetSpec:
    project: str
    instances: tuple[InstanceSpec, ...]
    admin_source_cidr: str
    dataplane_source_cidr: str
    image_family: str
    image_project: str
    gcloud_bin: str

    @property
    def by_role(self) -> dict[str, InstanceSpec]:
        return {item.role: item for item in self.instances}

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.instances)


def utc_now() -> str:
    return format_utc(datetime.now(timezone.utc).replace(microsecond=0))


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(label: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise FleetRefused(f"{label} must be an RFC3339 UTC timestamp ending in Z")
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FleetRefused(f"{label} is invalid") from exc
    if result.utcoffset() != timedelta(0):
        raise FleetRefused(f"{label} must be UTC")
    return result


def parse_creation_timestamp(label: str, value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise FleetRefused(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FleetRefused(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise FleetRefused(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def region_of(zone: str) -> str:
    if not GCE_ZONE_RE.fullmatch(zone):
        raise FleetRefused("invalid zone")
    return zone.rsplit("-", 1)[0]


def normalize_name(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def bounded_marker(name: str, marker: str) -> bool:
    return f"-{marker}-" in f"-{name}-"


def is_reserved_instance_name(name: str) -> bool:
    value = normalize_name(name)
    return value in RESERVED_INSTANCE_NAMES or any(
        bounded_marker(value, marker) for marker in RESERVED_NAME_MARKERS
    )


def validate_gce_name(label: str, value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise FleetRefused(f"{label} must be caller-provided")
    if raw != raw.lower() or not GCE_NAME_RE.fullmatch(raw):
        raise FleetRefused(f"{label} must be a valid lowercase GCE name")
    if is_reserved_instance_name(raw):
        raise FleetRefused(f"{label} {raw!r} is reserved")
    return raw


def validate_token(label: str, value: str, pattern: re.Pattern[str]) -> str:
    raw = (value or "").strip()
    if not pattern.fullmatch(raw):
        raise FleetRefused(f"{label} is invalid")
    return raw


def validate_proof_project(value: str) -> str:
    project = validate_token("project", value, PROJECT_RE)
    normalized = normalize_name(project)
    if "proof" not in normalized or any(
        bounded_marker(normalized, marker) or marker in normalized
        for marker in RESERVED_PROJECT_MARKERS
    ):
        raise FleetRefused("project must be dedicated proof scope, never production")
    return project


def validate_cidr(label: str, value: str, *, allow_world: bool) -> str:
    try:
        network = ipaddress.ip_network((value or "").strip(), strict=True)
    except ValueError as exc:
        raise FleetRefused(f"{label} is invalid") from exc
    if network.version != 4 or (not allow_world and str(network) == "0.0.0.0/0"):
        raise FleetRefused(f"{label} must be restricted IPv4, not 0.0.0.0/0")
    return str(network)


def validate_gcloud_bin(value: str) -> str:
    raw = (value or "").strip()
    if SECRET_RE.search(raw):
        raise FleetRefused("gcloud binary path looks credential-bearing")
    if Path(raw).name not in {"gcloud", "gcloud.cmd"} or SHELL_META_RE.search(raw):
        raise FleetRefused("gcloud binary basename/path is invalid")
    return raw


def validate_id(label: str, value: Any) -> str:
    if not isinstance(value, str) or not ID_RE.fullmatch(value):
        raise FleetRefused(f"{label} is invalid")
    return value


def assert_exact_keys(label: str, raw: Mapping[str, Any], expected: set[str]) -> None:
    if set(raw) != expected:
        raise FleetRefused(
            f"{label} keys mismatch; missing={sorted(expected - set(raw))}, extra={sorted(set(raw) - expected)}"
        )


def assert_no_secrets(value: Any) -> None:
    if SECRET_RE.search(json.dumps(value, sort_keys=True, default=str)):
        raise FleetRefused("refusing secret-bearing input or output")


def assert_no_forbidden_keys(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_EVIDENCE_KEYS:
                raise FleetRefused("evidence contains forbidden secret-bearing fields")
            assert_no_forbidden_keys(item)
    elif isinstance(value, list):
        for item in value:
            assert_no_forbidden_keys(item)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_digest(left: str, right: str) -> bool:
    return bool(
        left and right and len(left) == len(right) and hmac.compare_digest(left, right)
    )


def require_type(label: str, value: Any, expected: type) -> Any:
    if type(value) is not expected:
        raise FleetRefused(
            f"{label} must be an exact {expected.__name__} JSON type; "
            "bool/string coercion is refused"
        )
    return value


def require_str(label: str, value: Any) -> str:
    return require_type(label, value, str)


def require_bool(label: str, value: Any) -> bool:
    return require_type(label, value, bool)


def require_int(label: str, value: Any) -> int:
    return require_type(label, value, int)


def require_sha256(label: str, value: Any) -> str:
    digest = require_str(label, value)
    if not SHA256_RE.fullmatch(digest):
        raise FleetRefused(f"{label} must be a SHA-256 digest")
    return digest


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str:
            raise FleetRefused("JSON object keys must be strings")
        if key in result:
            raise FleetRefused(f"duplicate JSON key {key!r} is forbidden")
        result[key] = value
    return result


def _assert_json_types(label: str, value: Any) -> None:
    kind = type(value)
    if kind is dict:
        for key, nested in value.items():
            if type(key) is not str:
                raise FleetRefused(f"{label} JSON object keys must be strings")
            _assert_json_types(label, nested)
        return
    if kind is list:
        for nested in value:
            _assert_json_types(label, nested)
        return
    if kind in {str, int, bool, type(None)}:
        return
    raise FleetRefused(
        f"{label} contains a non-exact JSON type; bool/string coercion and floats are refused"
    )


def exact_equal(label: str, actual: Any, expected: Any) -> None:
    if type(actual) is not type(expected):
        raise FleetRefused(
            f"{label} type mismatch; bool/string coercion is refused"
        )
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            raise FleetRefused(
                f"{label} keys mismatch; missing={sorted(set(expected) - set(actual))}, "
                f"extra={sorted(set(actual) - set(expected))}"
            )
        for key in expected:
            exact_equal(f"{label}.{key}", actual[key], expected[key])
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            raise FleetRefused(f"{label} length mismatch")
        for index, (left, right) in enumerate(zip(actual, expected)):
            exact_equal(f"{label}[{index}]", left, right)
        return
    if actual != expected:
        raise FleetRefused(f"{label} does not match the bound identity")


def strict_json_bytes(label: str, data: bytes) -> Any:
    def reject_constant(value: str) -> Any:
        raise FleetRefused(f"{label} contains a non-exact JSON constant")

    try:
        parsed = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=reject_constant,
        )
    except FleetRefused:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FleetRefused(f"{label} is not canonical ASCII JSON") from exc
    _assert_json_types(label, parsed)
    return parsed


def read_stable_file_with_stat(path: Path, *, label: str) -> tuple[bytes, os.stat_result]:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise FleetRefused(f"{label} path must be absolute")
    try:
        before = candidate.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise FleetRefused(f"{label} must be a regular non-symlink file")
        with candidate.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read()
            finished = os.fstat(handle.fileno())
        after = candidate.lstat()
    except OSError as exc:
        raise FleetRefused(f"{label} is not readable") from exc
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IMODE(item.st_mode),
    )
    if (
        identity(before) != identity(opened)
        or identity(before) != identity(finished)
        or identity(before) != identity(after)
    ):
        raise FleetRefused(f"{label} changed while being read")
    if not data:
        raise FleetRefused(f"{label} must not be empty")
    return data, finished


def read_stable_file(path: Path, *, label: str) -> bytes:
    data, _ = read_stable_file_with_stat(path, label=label)
    return data


def file_ref(path: Path, *, label: str) -> dict[str, Any]:
    data = read_stable_file(path.absolute(), label=label)
    return {
        "path": str(path.absolute()),
        "sha256": sha256_bytes(data),
        "bytes": len(data),
    }


def executable_ref(path: Path, *, label: str) -> dict[str, Any]:
    candidate = path.absolute()
    try:
        before = candidate.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise FleetRefused(f"{label} must be a regular non-symlink file")
        with candidate.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            data = handle.read()
            finished = os.fstat(handle.fileno())
        after = candidate.lstat()
    except OSError as exc:
        raise FleetRefused(f"{label} is not readable") from exc
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IMODE(item.st_mode),
    )
    if any(identity(before) != identity(item) for item in (opened, finished, after)):
        raise FleetRefused(f"{label} changed while being read")
    mode = stat.S_IMODE(opened.st_mode)
    if not data or mode & 0o022 or mode & 0o111 == 0:
        raise FleetRefused(f"{label} must be executable and not group/world writable")
    return {"path": str(candidate), "sha256": sha256_bytes(data), "bytes": len(data)}


def _canonical_repo_root(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute() or os.path.normpath(str(candidate)) != str(candidate):
        raise FleetRefused("repository root must be an absolute canonical path")
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise FleetRefused("repository root is not readable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or candidate.resolve() != candidate
    ):
        raise FleetRefused("repository root must be a canonical non-symlink directory")
    return candidate


def _client_binding_verifier_closure() -> dict[str, Any]:
    return {
        "proof_client_builder": file_ref(
            Path(client_binding.proof_builder.__file__).resolve(),
            label="proof client builder",
        ),
        "client_release_binding": file_ref(
            Path(client_binding.__file__).resolve(),
            label="client release binding verifier",
        ),
        "release_dependency_freeze": file_ref(
            Path(client_binding.freeze.__file__).resolve(),
            label="release dependency freeze verifier",
        ),
    }


def _validate_client_file_ref(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, value, CLIENT_BINDING_FILE_KEYS)
    path = value["path"]
    digest = value["sha256"]
    byte_count = value["bytes"]
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or os.path.normpath(path) != path
        or not isinstance(digest, str)
        or not SHA256_RE.fullmatch(digest)
        or type(byte_count) is not int
        or byte_count <= 0
    ):
        raise FleetRefused(f"{label} fields are invalid")
    return value


def validate_client_release_binding_reference(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused("client release binding reference is malformed")
    assert_exact_keys(
        "client release binding reference", raw, CLIENT_BINDING_REFERENCE_KEYS
    )
    if (
        raw["schema_version"] != 1
        or raw["contract"] != CLIENT_BINDING_REFERENCE_CONTRACT
        or not isinstance(raw["repo_root"], str)
        or not Path(raw["repo_root"]).is_absolute()
        or os.path.normpath(raw["repo_root"]) != raw["repo_root"]
    ):
        raise FleetRefused("client release binding reference policy is invalid")
    binding = raw["binding"]
    if not isinstance(binding, dict):
        raise FleetRefused("client release binding document is malformed")
    assert_exact_keys("client release binding document", binding, CLIENT_BINDING_KEYS)
    if (
        binding["schema_version"] != client_binding.SCHEMA_VERSION
        or binding["contract"] != client_binding.CONTRACT
        or binding["platform"] != client_binding.PLATFORM
    ):
        raise FleetRefused("client release binding document contract is invalid")
    for key in ("release_input_index", "build_receipt", "artifact"):
        ref = _validate_client_file_ref(binding[key], f"client binding {key}")
        try:
            Path(ref["path"]).relative_to(Path(raw["repo_root"]))
        except ValueError as exc:
            raise FleetRefused(
                f"client binding {key} must stay inside the bound repository"
            ) from exc
    for key in (
        "release",
        "shared_revision",
        "artifact_input_fingerprint_sha256",
        "build_identity",
    ):
        if not isinstance(binding[key], str) or not binding[key]:
            raise FleetRefused(f"client binding {key} is invalid")
    if not SHA256_RE.fullmatch(binding["artifact_input_fingerprint_sha256"]):
        raise FleetRefused("client artifact input fingerprint is invalid")
    proof_build = binding["proof_build"]
    if not isinstance(proof_build, dict):
        raise FleetRefused("client proof build is malformed")
    assert_exact_keys("client proof build", proof_build, CLIENT_PROOF_BUILD_KEYS)
    if (
        not isinstance(proof_build["build_identity"], str)
        or not SHA256_RE.fullmatch(proof_build["build_identity"])
        or binding["build_identity"]
        != f"linux:{binding['release']}:{proof_build['build_identity']}"
    ):
        raise FleetRefused("client proof build identity is invalid")
    validate_build_identity(binding["build_identity"])
    digest = sha256_bytes(client_binding.canonical_bytes(binding))
    if raw["binding_sha256"] != digest:
        raise FleetRefused("client release binding digest is invalid")
    closure = raw["verifier_closure"]
    if not isinstance(closure, dict):
        raise FleetRefused("client release binding verifier closure is malformed")
    assert_exact_keys(
        "client release binding verifier closure",
        closure,
        CLIENT_BINDING_CLOSURE_KEYS,
    )
    for key in sorted(CLIENT_BINDING_CLOSURE_KEYS):
        _validate_client_file_ref(closure[key], f"client verifier closure {key}")
    assert_no_secrets(raw)
    return copy.deepcopy(raw)


def create_client_release_binding_reference(
    repo_root: Path,
    release_input_index: Path,
    build_receipt: Path,
    artifact: Path,
) -> dict[str, Any]:
    repo = _canonical_repo_root(repo_root)
    try:
        binding = client_binding.verify_client_release(
            repo,
            release_input_index,
            build_receipt,
            artifact,
            platform=client_binding.PLATFORM,
        )
    except client_binding.ClientReleaseBindingError as exc:
        raise FleetRefused(f"client release binding verification failed: {exc}") from exc
    reference = {
        "schema_version": 1,
        "contract": CLIENT_BINDING_REFERENCE_CONTRACT,
        "repo_root": str(repo),
        "binding": binding,
        "binding_sha256": sha256_bytes(client_binding.canonical_bytes(binding)),
        "verifier_closure": _client_binding_verifier_closure(),
    }
    return validate_client_release_binding_reference(reference)


def verify_client_release_binding_reference(
    raw: Any, *, expected_repo_root: Path | None = None
) -> dict[str, Any]:
    reference = validate_client_release_binding_reference(raw)
    repo = _canonical_repo_root(Path(reference["repo_root"]))
    if expected_repo_root is not None and repo != _canonical_repo_root(expected_repo_root):
        raise FleetRefused("client release binding repository does not match")
    if reference["verifier_closure"] != _client_binding_verifier_closure():
        raise FleetRefused("client release binding verifier closure changed")
    binding = reference["binding"]
    try:
        rebuilt = client_binding.verify_client_release(
            repo,
            Path(binding["release_input_index"]["path"]),
            Path(binding["build_receipt"]["path"]),
            Path(binding["artifact"]["path"]),
            platform=client_binding.PLATFORM,
        )
    except client_binding.ClientReleaseBindingError as exc:
        raise FleetRefused(f"client release binding verification failed: {exc}") from exc
    if rebuilt != binding:
        raise FleetRefused("client release binding no longer matches exact release inputs")
    if sha256_bytes(client_binding.canonical_bytes(rebuilt)) != reference["binding_sha256"]:
        raise FleetRefused("client release binding digest changed")
    return reference


def validate_deployment_inputs_reference(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused("deployment inputs reference is malformed")
    assert_exact_keys("deployment inputs reference", raw, DEPLOYMENT_INPUT_KEYS)
    if (
        not isinstance(raw["path"], str)
        or not Path(raw["path"]).is_absolute()
        or os.path.normpath(raw["path"]) != raw["path"]
        or not isinstance(raw["sha256"], str)
        or not SHA256_RE.fullmatch(raw["sha256"])
        or not isinstance(raw["candidate_id"], str)
        or not SHA256_RE.fullmatch(raw["candidate_id"])
        or type(raw["bytes"]) is not int
        or raw["bytes"] <= 0
    ):
        raise FleetRefused("deployment inputs reference fields are invalid")
    return copy.deepcopy(raw)


def verify_deployment_inputs_reference(
    repo_root: Path, manifest_path: Path, expected: Any | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    repo = _canonical_repo_root(repo_root)
    manifest = manifest_path.expanduser()
    if not manifest.is_absolute() or os.path.normpath(str(manifest)) != str(manifest):
        raise FleetRefused("deployment inputs path must be absolute and canonical")
    try:
        verified = deployment_inputs.verify_manifest(repo, manifest)
    except deployment_inputs.DeploymentInputsError as exc:
        raise FleetRefused(f"deployment inputs verification failed: {exc}") from exc
    data = read_stable_file(manifest, label="deployment inputs")
    if data != canonical_bytes(verified):
        raise FleetRefused("deployment inputs changed after closure verification")
    reference = validate_deployment_inputs_reference(
        {
            "bytes": len(data),
            "candidate_id": verified["candidate_id"],
            "path": str(manifest),
            "sha256": sha256_bytes(data),
        }
    )
    if expected is not None and reference != validate_deployment_inputs_reference(expected):
        raise FleetRefused("deployment inputs do not match the plan-bound reference")
    return reference, copy.deepcopy(verified)


def manifest_file_index(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    raw_inputs = manifest.get("inputs")
    if isinstance(raw_inputs, list) and raw_inputs:
        source = raw_inputs
    else:
        source = manifest.get("installers")
        if not isinstance(source, list):
            raise FleetRefused("deployment manifest does not bind reviewed file identities")
    for item in source:
        if not isinstance(item, dict):
            raise FleetRefused("deployment manifest file identity is malformed")
        path = require_str("deployment manifest file path", item.get("path"))
        if path in records:
            raise FleetRefused("deployment manifest file identities are duplicated")
        records[path] = {
            "bytes": require_int(f"{path} bytes", item.get("bytes")),
            "path": path,
            "sha256": require_sha256(f"{path} digest", item.get("sha256")),
        }
        if records[path]["bytes"] <= 0:
            raise FleetRefused(f"{path} byte length is invalid")
    if not records:
        raise FleetRefused("deployment manifest file identities are empty")
    return records


def expected_candidate_files(
    manifest: Mapping[str, Any], role: str
) -> list[dict[str, Any]]:
    if role not in ROLES:
        raise FleetRefused("candidate role is invalid")
    records = manifest_file_index(manifest)
    files: list[dict[str, Any]] = []
    for index, (step_role, _script, _flag) in enumerate(expected_installer_triples()):
        if step_role != role:
            continue
        for path in sorted(records):
            item = records[path]
            files.append(
                {
                    "bytes": item["bytes"],
                    "path": f"step-{index}/{path}",
                    "sha256": item["sha256"],
                }
            )
    if not files:
        raise FleetRefused(f"{role} is missing reviewed candidate bytes")
    return files


def expected_config_identity(role: str, path: str) -> dict[str, Any]:
    payload = ROLE_FILE_PAYLOADS.get(role)
    if payload is None or path not in ROLE_DEPLOY_CONFIGS[role]:
        raise FleetRefused(f"{role} config {path} is not a reviewed deployment-manifest expectation")
    return {
        "architecture": TEXT_ARCHITECTURE,
        "bytes": len(payload),
        "path": path,
        "sha256": sha256_bytes(payload),
        "version": "text-1",
    }


def expected_unit_identity(
    manifest: Mapping[str, Any], role: str, name: str, path: str
) -> dict[str, Any]:
    records = manifest_file_index(manifest)
    source_path = REVIEWED_UNIT_SOURCES.get((role, name))
    source = records.get(source_path) if source_path is not None else None
    if source is None:
        matches = [
            item
            for item_path, item in records.items()
            if item_path == name or item_path.endswith("/" + name)
        ]
        if len(matches) == 1:
            source = matches[0]
    if source is None:
        raise FleetRefused(
            f"{role} unit {name} digest is not bound to reviewed deployment-manifest expectations"
        )
    return {
        "active_state": ROLE_DEPLOY_SERVICES[role][name],
        "architecture": TEXT_ARCHITECTURE,
        "bytes": source["bytes"],
        "path": path,
        "sha256": source["sha256"],
        "version": "text-1",
    }


def expected_preflight_labels(spec: FleetSpec, role: str) -> dict[str, str]:
    fleet_id = fleet_id_for(spec)
    return {
        "winsvpn-proof-fleet": "1",
        "winsvpn-proof-id": fleet_id,
        "winsvpn-proof-role": role,
    }


def expected_resource_labels(spec: FleetSpec) -> dict[str, str]:
    return {
        "winsvpn-proof-fleet": "1",
        "winsvpn-proof-id": fleet_id_for(spec),
    }


def empty_preflight() -> dict[str, Any]:
    return {"firewalls": {}, "instances": {}, "network": {}, "subnets": {}}


def validate_creation_identity(
    label: str,
    raw: Any,
    *,
    link_re: re.Pattern[str],
) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, CREATION_TRANSACTION_KEYS)
    created = require_str(f"{label}.creation_timestamp", raw["creation_timestamp"])
    parse_creation_timestamp(f"{label}.creation_timestamp", created)
    identity = require_str(f"{label}.id", raw["id"])
    if not GCE_ID_RE.fullmatch(identity):
        raise FleetRefused(f"{label} id is invalid")
    link = require_str(f"{label}.self_link", raw["self_link"])
    if link_re.fullmatch(link) is None:
        raise FleetRefused(f"{label} self_link is invalid")
    return {
        "creation_timestamp": created,
        "id": identity,
        "self_link": link,
    }


def validate_creation_transaction(
    role: str, raw: Any, spec: FleetSpec
) -> dict[str, str]:
    label = f"{role} creation transaction"
    transaction = validate_creation_identity(label, raw, link_re=SELF_LINK_RE)
    instance = spec.by_role[role]
    matched = SELF_LINK_RE.fullmatch(transaction["self_link"])
    if matched is None:
        raise FleetRefused(f"{label} self_link is invalid")
    project, zone, name = matched.group(1), matched.group(2), matched.group(3)
    if project != spec.project or zone != instance.zone or name != instance.name:
        raise FleetRefused(
            f"{label} is not bound to the exact project, zone, and instance"
        )
    return transaction


def validate_fingerprint(label: str, raw: Any) -> str:
    value = require_str(label, raw)
    if not FINGERPRINT_RE.fullmatch(value):
        raise FleetRefused(f"{label} is invalid")
    return value


def validate_named_resource_identity(
    label: str,
    raw: Any,
    *,
    spec: FleetSpec,
    name: str,
    resource_type: str,
    link_re: re.Pattern[str],
    extra_keys: set[str],
    network: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, RESOURCE_IDENTITY_BASE_KEYS | extra_keys)
    exact_equal(f"{label}.name", raw["name"], name)
    exact_equal(f"{label}.project", raw["project"], spec.project)
    exact_equal(f"{label}.type", raw["type"], resource_type)
    exact_equal(f"{label}.kind", raw["kind"], RESOURCE_KINDS[resource_type])
    exact_equal(f"{label}.labels", raw["labels"], expected_resource_labels(spec))
    validate_fingerprint(f"{label}.fingerprint", raw["fingerprint"])
    validate_fingerprint(f"{label}.label_fingerprint", raw["label_fingerprint"])
    transaction = validate_creation_identity(
        f"{label} creation transaction",
        raw["creation_transaction"],
        link_re=link_re,
    )
    matched = link_re.fullmatch(transaction["self_link"])
    if matched is None or matched.group(1) != spec.project:
        raise FleetRefused(f"{label} is not bound to the exact project")
    if resource_type == "subnet":
        if matched.group(2) != region or matched.group(3) != name:
            raise FleetRefused(
                f"{label} is not bound to the exact region and name"
            )
        exact_equal(f"{label}.region", raw["region"], region)
        exact_equal(f"{label}.network", raw["network"], network)
    else:
        if matched.group(2) != name:
            raise FleetRefused(f"{label} is not bound to the exact name")
        if network is not None:
            exact_equal(f"{label}.network", raw["network"], network)
    payload = copy.deepcopy(raw)
    payload["creation_transaction"] = transaction
    return payload


def remember_creation_identity(
    seen_ids: set[str],
    seen_links: set[str],
    transaction: Mapping[str, str],
    label: str,
) -> None:
    if transaction["id"] in seen_ids or transaction["self_link"] in seen_links:
        raise FleetRefused(f"proof {label} creation identity is duplicated")
    seen_ids.add(transaction["id"])
    seen_links.add(transaction["self_link"])


def preflight_is_complete(raw: Mapping[str, Any], spec: FleetSpec) -> bool:
    names = resource_names(spec)
    instances = raw.get("instances")
    firewalls = raw.get("firewalls")
    subnets = raw.get("subnets")
    network = raw.get("network")
    if not isinstance(instances, dict) or set(instances) != set(ROLES):
        return False
    if not isinstance(firewalls, dict) or set(firewalls) != set(
        names["firewalls"].values()
    ):
        return False
    expected_subnets = {item["name"] for item in names["subnets"]}
    if not isinstance(subnets, dict) or set(subnets) != expected_subnets:
        return False
    return isinstance(network, dict) and network.get("name") == names["network"]


def validate_preflight(
    raw: Any, spec: FleetSpec, *, require_complete: bool
) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != PREFLIGHT_KEYS:
        raise FleetRefused("deployment preflight identities are missing or mixed")
    if not all(isinstance(raw[key], dict) for key in PREFLIGHT_KEYS):
        raise FleetRefused("deployment preflight identities are malformed")
    complete = preflight_is_complete(raw, spec)
    if require_complete and not complete:
        raise FleetRefused("deployment preflight identities are incomplete")
    if not complete:
        if any(raw[key] for key in ("firewalls", "instances", "subnets")) or raw[
            "network"
        ]:
            raise FleetRefused("deployment preflight identities are incomplete")
        return empty_preflight()
    names = resource_names(spec)
    fleet_id = fleet_id_for(spec)
    seen_ids: set[str] = set()
    seen_links: set[str] = set()
    instances: dict[str, Any] = {}
    for role in ROLES:
        item = raw["instances"][role]
        label = f"{role} preflight identity"
        if not isinstance(item, dict):
            raise FleetRefused(f"{label} is malformed")
        assert_exact_keys(label, item, PREFLIGHT_IDENTITY_KEYS)
        instance = spec.by_role[role]
        exact_equal(f"{label}.project", item["project"], spec.project)
        exact_equal(f"{label}.fleet_id", item["fleet_id"], fleet_id)
        exact_equal(f"{label}.role", item["role"], role)
        exact_equal(f"{label}.name", item["name"], instance.name)
        exact_equal(f"{label}.zone", item["zone"], instance.zone)
        exact_equal(f"{label}.machine_type", item["machine_type"], instance.machine_type)
        exact_equal(
            f"{label}.can_ip_forward",
            item["can_ip_forward"],
            role in ("data-winn3", "data-cover"),
        )
        exact_equal(
            f"{label}.labels", item["labels"], expected_preflight_labels(spec, role)
        )
        transaction = validate_creation_transaction(
            role, item["creation_transaction"], spec
        )
        remember_creation_identity(seen_ids, seen_links, transaction, "instance")
        payload = copy.deepcopy(item)
        payload["creation_transaction"] = transaction
        instances[role] = payload
    firewalls: dict[str, Any] = {}
    for name in names["firewalls"].values():
        firewalls[name] = validate_named_resource_identity(
            f"firewall {name}",
            raw["firewalls"][name],
            spec=spec,
            name=name,
            resource_type="firewall",
            link_re=FIREWALL_LINK_RE,
            extra_keys={"network"},
            network=names["network"],
        )
        remember_creation_identity(
            seen_ids,
            seen_links,
            firewalls[name]["creation_transaction"],
            "firewall",
        )
    subnets: dict[str, Any] = {}
    for item in names["subnets"]:
        name = item["name"]
        subnets[name] = validate_named_resource_identity(
            f"subnet {name}",
            raw["subnets"][name],
            spec=spec,
            name=name,
            resource_type="subnet",
            link_re=SUBNET_LINK_RE,
            extra_keys={"network", "region"},
            network=names["network"],
            region=item["region"],
        )
        remember_creation_identity(
            seen_ids,
            seen_links,
            subnets[name]["creation_transaction"],
            "subnet",
        )
    network = validate_named_resource_identity(
        "proof network",
        raw["network"],
        spec=spec,
        name=names["network"],
        resource_type="network",
        link_re=NETWORK_LINK_RE,
        extra_keys=set(),
    )
    remember_creation_identity(
        seen_ids, seen_links, network["creation_transaction"], "network"
    )
    return {
        "firewalls": firewalls,
        "instances": instances,
        "network": network,
        "subnets": subnets,
    }


def validate_cleanup(raw: Any, *, execution_status: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused("deployment cleanup receipt is malformed")
    assert_exact_keys("deployment cleanup", raw, CLEANUP_KEYS)
    if raw.get("acceptance_receipt_required") is not False:
        raise FleetRefused("deployment cleanup must not require an acceptance receipt")
    require_bool("deployment cleanup authorized", raw["authorized"])
    status = require_str("deployment cleanup status", raw.get("status"))
    if not isinstance(raw["remote"], dict):
        raise FleetRefused("deployment cleanup remote receipt is malformed")
    resources = raw["resources"]
    if not isinstance(resources, dict):
        raise FleetRefused("deployment cleanup resources are malformed")
    assert_exact_keys("deployment cleanup resources", resources, CLEANUP_RESOURCES_KEYS)
    require_str("deployment cleanup resource reason", resources["reason"])
    if not isinstance(resources["results"], list):
        raise FleetRefused("deployment cleanup resource results are malformed")
    if not isinstance(resources["targets"], dict):
        raise FleetRefused("deployment cleanup resource targets are malformed")
    resource_status = require_str(
        "deployment cleanup resource status", resources["status"]
    )
    if resource_status not in {"passed", "failed", "skipped", "not_required"}:
        raise FleetRefused("deployment cleanup resource status is invalid")
    if execution_status == "passed":
        if status != "not_required" or resource_status != "not_required":
            raise FleetRefused("passed deployment cleanup status is invalid")
    elif status not in {"passed", "failed", "skipped", "not_required"}:
        raise FleetRefused("deployment cleanup status is invalid")
    return copy.deepcopy(raw)


def available_release_artifacts(
    client_reference: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    reference = validate_client_release_binding_reference(client_reference)
    binding = reference["binding"]
    platform = require_str("client platform", binding.get("platform"))
    artifact = copy.deepcopy(binding["artifact"])
    _validate_client_file_ref(artifact, "client release artifact")
    if platform != "linux":
        return {}
    target = binding.get("proof_build", {}).get("target") if isinstance(
        binding.get("proof_build"), dict
    ) else None
    goarch = target.get("goarch") if isinstance(target, dict) else None
    if goarch in {None, "amd64", "x86_64"}:
        return {LINUX_X64_ARTIFACT_ID: artifact}
    if goarch == "arm64":
        return {"linux-arm64-package": artifact}
    return {}


def _cross_store_readiness():
    """Load the existing target-receipt verifier without importing it at module load.

    cross_store_upload_readiness imports this module to revalidate a finished GCP
    acceptance receipt. Importing it here at function scope avoids that cycle and
    keeps 16-artifact plan binding independent of final GCP acceptance.
    """

    try:
        import cross_store_upload_readiness as readiness
    except Exception as exc:
        raise FleetRefused(
            f"cross-store target receipt verifier is unavailable: {exc}"
        ) from exc
    return readiness


def assert_required_release_artifact_count() -> None:
    if (
        len(REQUIRED_RELEASE_ARTIFACTS) != REQUIRED_RELEASE_ARTIFACT_COUNT
        or len(COLLECTOR_ACTIONS) != REQUIRED_RELEASE_ARTIFACT_COUNT
        or len(set(REQUIRED_RELEASE_ARTIFACTS)) != REQUIRED_RELEASE_ARTIFACT_COUNT
        or len(REQUIRED_RELEASE_ARTIFACT_SUFFIXES) != REQUIRED_RELEASE_ARTIFACT_COUNT
        or set(REQUIRED_RELEASE_ARTIFACT_SUFFIXES) != set(REQUIRED_RELEASE_ARTIFACTS)
    ):
        raise FleetRefused(
            "required release artifact identities must remain 16 distinct target ids"
        )
    readiness = _cross_store_readiness()
    readiness._assert_target_contract()
    expected_ids = tuple(
        target.target_id for target in readiness.REQUIRED_UPLOAD_TARGETS
    )
    if expected_ids != REQUIRED_RELEASE_ARTIFACTS:
        raise FleetRefused(
            "required release artifact identities must match the cross-store required target set"
        )
    if set(REQUIRED_RELEASE_ARTIFACTS) != set(readiness.REQUIRED_TARGET_IDS):
        raise FleetRefused(
            "required release artifact identities must match the cross-store required target set"
        )
    for target in readiness.REQUIRED_UPLOAD_TARGETS:
        if (
            REQUIRED_RELEASE_ARTIFACT_SUFFIXES[target.target_id]
            != target.artifact_suffixes
        ):
            raise FleetRefused(
                "required release artifact suffixes must match the cross-store target contract"
            )


def required_upload_target(target_id: str) -> Any:
    readiness = _cross_store_readiness()
    if target_id not in readiness.TARGET_BY_ID:
        raise FleetRefused(f"wrong target: {target_id}")
    return readiness.TARGET_BY_ID[target_id]


def parse_target_path_bindings(
    values: Sequence[str] | None,
    *,
    label: str,
) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for raw in values or ():
        if not isinstance(raw, str) or raw.count("=") != 1:
            raise FleetRefused(
                f"{label} binding must use target-id=/absolute/path"
            )
        target_id, text = (part.strip() for part in raw.split("=", 1))
        if target_id not in REQUIRED_RELEASE_ARTIFACTS:
            raise FleetRefused(f"unexpected {label} identity: {target_id}")
        if target_id in result:
            raise FleetRefused(f"duplicate {label} identity: {target_id}")
        if not text:
            raise FleetRefused(f"{label} path is empty")
        path = Path(text)
        if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
            raise FleetRefused(f"{label} path must be absolute and canonical")
        result[target_id] = path
    return result


def parse_receipt_path_bindings(
    values: Sequence[str] | None,
) -> list[tuple[str | None, Path]]:
    """Parse unlabeled receipt paths. Caller TARGET_ID= labels are claims only."""

    result: list[tuple[str | None, Path]] = []
    seen_paths: set[str] = set()
    seen_claims: set[str] = set()
    for raw in values or ():
        if not isinstance(raw, str) or not raw.strip():
            raise FleetRefused("release artifact receipt path is empty")
        claimed: str | None = None
        text = raw.strip()
        if text.count("=") == 1:
            left, right = (part.strip() for part in text.split("=", 1))
            if left in REQUIRED_RELEASE_ARTIFACTS:
                claimed = left
                text = right
            elif left:
                raise FleetRefused(f"unexpected release artifact receipt identity: {left}")
        if not text:
            raise FleetRefused("release artifact receipt path is empty")
        path = Path(text)
        if not path.is_absolute() or os.path.normpath(str(path)) != str(path):
            raise FleetRefused(
                "release artifact receipt path must be absolute and canonical"
            )
        resolved = str(path)
        if resolved in seen_paths:
            raise FleetRefused("duplicate release artifact receipt path")
        if claimed is not None:
            if claimed in seen_claims:
                raise FleetRefused(f"duplicate release artifact receipt identity: {claimed}")
            seen_claims.add(claimed)
        seen_paths.add(resolved)
        result.append((claimed, path))
    return result


def _normalize_receipt_bindings(
    receipt_paths: Mapping[str, Path] | Sequence[Any] | None,
) -> list[tuple[str | None, Path]]:
    if not receipt_paths:
        return []
    if isinstance(receipt_paths, Mapping):
        bindings: list[tuple[str | None, Path]] = []
        seen: set[str] = set()
        for target_id, path in receipt_paths.items():
            claimed = str(target_id)
            if claimed not in REQUIRED_RELEASE_ARTIFACTS:
                raise FleetRefused(
                    f"unexpected release artifact receipt identity: {claimed}"
                )
            if claimed in seen:
                raise FleetRefused(
                    f"duplicate release artifact receipt identity: {claimed}"
                )
            seen.add(claimed)
            bindings.append((claimed, Path(path)))
        return bindings
    bindings = []
    seen_paths: set[str] = set()
    for item in receipt_paths:
        claimed: str | None
        if isinstance(item, (tuple, list)) and len(item) == 2:
            claimed_raw, path = item
            claimed = None if claimed_raw is None else str(claimed_raw)
            if claimed == "":
                claimed = None
        else:
            claimed = None
            path = item
        resolved = str(Path(path))
        if resolved in seen_paths:
            raise FleetRefused("duplicate release artifact receipt path")
        seen_paths.add(resolved)
        if claimed is not None and claimed not in REQUIRED_RELEASE_ARTIFACTS:
            raise FleetRefused(
                f"unexpected release artifact receipt identity: {claimed}"
            )
        bindings.append((claimed, Path(path)))
    return bindings


def _require_complete_target_set(
    supplied: Mapping[str, Any], *, label: str
) -> None:
    expected = set(REQUIRED_RELEASE_ARTIFACTS)
    actual = set(supplied)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing and not extra:
        raise FleetRefused(f"required {label} identities are missing")
    if extra and not missing:
        raise FleetRefused(f"required {label} identities are extra")
    raise FleetRefused(f"required {label} identities are missing or extra")


def _current_utc() -> datetime:
    return datetime.now(timezone.utc)


def _release_artifact_file_ref(target_id: str, path: Path) -> dict[str, Any]:
    suffixes = REQUIRED_RELEASE_ARTIFACT_SUFFIXES[target_id]
    name = path.name.lower()
    if not any(name.endswith(suffix) for suffix in suffixes):
        raise FleetRefused(f"{target_id} artifact type is not allowed")
    return file_ref(path, label=f"{target_id} release artifact")


def _reverify_release_artifact_file_ref(
    raw: Any, *, target_id: str, require_store_suffix: bool
) -> dict[str, Any]:
    claimed = _validate_client_file_ref(raw, f"{target_id} release artifact")
    path = Path(claimed["path"])
    if require_store_suffix:
        verified = _release_artifact_file_ref(target_id, path)
    else:
        verified = file_ref(path, label=f"{target_id} release artifact")
    if verified != claimed:
        raise FleetRefused(
            f"{target_id} release artifact is caller-forged, stale, or substituted"
        )
    return verified


def _live_release_input_index_ref(raw: Any) -> dict[str, Any]:
    claimed = _validate_client_file_ref(raw, "release input index")
    live = file_ref(Path(claimed["path"]), label="release input index")
    if live != claimed:
        raise FleetRefused("release input index is stale or substituted")
    return live


def _require_fresh_timestamp(label: str, value: datetime, *, now: datetime) -> None:
    if value > now + MAX_CLOCK_SKEW or now - value > MAX_EVIDENCE_AGE:
        raise FleetRefused(f"{label} is stale or future-dated")


def authenticate_cross_store_target_receipt(
    repo: Path,
    index_path: Path,
    target_id: str,
    receipt_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify one existing cross-store target receipt. Does not mint GCP acceptance."""

    readiness = _cross_store_readiness()
    try:
        verified = readiness._verify_target_receipt(
            repo,
            index_path,
            target_id,
            receipt_path,
            now=now,
        )
    except FleetRefused:
        raise
    except (readiness.UploadReadinessError, freeze.DependencyFreezeError) as exc:
        raise FleetRefused(
            f"{target_id} authentic receipt binding is invalid: {exc}"
        ) from exc
    if not isinstance(verified, dict):
        raise FleetRefused(f"{target_id} authentic receipt verifier returned malformed evidence")
    _require_delegated_verified_utc(target_id, verified)
    return verified


def _require_delegated_verified_utc(target_id: str, verified: Mapping[str, Any]) -> str:
    verified_utc = verified.get("verified_utc")
    if not isinstance(verified_utc, str) or not verified_utc:
        raise FleetRefused(
            f"{target_id} authentic receipt verified_utc is missing from the delegated verifier"
        )
    return verified_utc


def _preflight_cross_store_target_id(payload: Mapping[str, Any]) -> str:
    kind = payload.get("kind")
    if kind in CALLER_AUTHORED_TARGET_ASSIGNMENT_KINDS:
        raise FleetRefused(
            "caller-authored identity document or GCP acceptance receipt cannot assign TARGET_ID"
        )
    readiness = _cross_store_readiness()
    if (
        payload.get("ok") is not True
        or payload.get("schema_version") != readiness.TARGET_RECEIPT_SCHEMA_VERSION
        or payload.get("contract") != readiness.TARGET_RECEIPT_CONTRACT
        or payload.get("publication_authorized") is not False
        or payload.get("upload_attempted") is not False
    ):
        raise FleetRefused("forged or invalid cross-store target receipt contract")
    target_id = payload.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        raise FleetRefused("cross-store target receipt target is missing")
    if target_id in readiness.OPTIONAL_TARGET_IDS or target_id not in REQUIRED_RELEASE_ARTIFACTS:
        raise FleetRefused(f"wrong target: {target_id}")
    if target_id not in readiness.REQUIRED_TARGET_IDS:
        raise FleetRefused(f"wrong target: {target_id}")
    return target_id


def load_authenticated_target_receipt(
    receipt_path: Path,
    *,
    repo_root: Path,
    expected_index: Mapping[str, Any],
    claimed_target_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = now or _current_utc()
    repo = _canonical_repo_root(repo_root)
    try:
        bound_receipt = freeze.secure_repo_path(
            repo, receipt_path, "cross-store target receipt", must_exist=True
        )
    except freeze.DependencyFreezeError as exc:
        raise FleetRefused(f"cross-store target receipt path is invalid: {exc}") from exc
    try:
        if bound_receipt.relative_to(repo).parts[0] != ".artifacts":
            raise FleetRefused("cross-store target receipt must stay under .artifacts/")
    except ValueError as exc:
        raise FleetRefused("cross-store target receipt must stay inside the repository") from exc
    data = read_stable_file(
        bound_receipt.absolute(), label="cross-store target receipt"
    )
    payload = strict_json_bytes("cross-store target receipt", data)
    if not isinstance(payload, dict):
        raise FleetRefused("cross-store target receipt must be an object")
    target_id = _preflight_cross_store_target_id(payload)
    if claimed_target_id is not None and claimed_target_id != target_id:
        raise FleetRefused(
            f"wrong target: caller label {claimed_target_id} does not match authentic receipt {target_id}"
        )
    expected = _live_release_input_index_ref(expected_index)
    index_path = Path(expected["path"])
    verified = authenticate_cross_store_target_receipt(
        repo,
        index_path,
        target_id,
        bound_receipt,
        now=current,
    )
    readiness = _cross_store_readiness()
    target = readiness.TARGET_BY_ID[target_id]
    verified_utc = _require_delegated_verified_utc(target_id, verified)
    verified_at = parse_utc(
        f"{target_id} authentic receipt verification",
        verified_utc,
    )
    _require_fresh_timestamp(f"{target_id} authentic receipt", verified_at, now=current)
    source = verified.get("dependency_source_freeze")
    if not isinstance(source, dict):
        raise FleetRefused(f"{target_id} authentic receipt freeze binding is missing")
    if source.get("index_sha256") != expected["sha256"]:
        raise FleetRefused(
            "required release artifacts are bound to a different release input index"
        )
    build_receipt = verified.get("build_receipt")
    if not isinstance(build_receipt, dict):
        raise FleetRefused(f"{target_id} authentic build receipt binding is missing")
    if build_receipt.get("target") != target.build_receipt_target:
        raise FleetRefused(f"{target_id} build receipt target was substituted")
    if target.manifest_verifier_path is None:
        try:
            allowed = freeze.allowed_targets(target.platform)
        except freeze.DependencyFreezeError as exc:
            raise FleetRefused(f"{target_id} freeze target map is invalid: {exc}") from exc
        if target.build_receipt_target not in allowed:
            raise FleetRefused(f"wrong target: {target_id} freeze build receipt target is not allowed")
    elif build_receipt.get("target") != target_id:
        raise FleetRefused(f"wrong target: {target_id} manifest receipt target was substituted")
    artifact_value = verified.get("artifact")
    if not isinstance(artifact_value, dict) or not isinstance(artifact_value.get("path"), str):
        raise FleetRefused(f"{target_id} authentic artifact binding is missing")
    try:
        artifact_path = freeze.secure_repo_path(
            repo,
            Path(str(artifact_value["path"])),
            f"{target_id} release artifact",
            must_exist=True,
        )
    except freeze.DependencyFreezeError as exc:
        raise FleetRefused(f"{target_id} release artifact path is invalid: {exc}") from exc
    hashed = _release_artifact_file_ref(target_id, artifact_path)
    if (
        hashed["sha256"] != artifact_value.get("sha256")
        or hashed["bytes"] != artifact_value.get("bytes")
    ):
        raise FleetRefused(
            f"{target_id} release artifact is caller-forged, stale, or substituted"
        )
    return {
        "artifact": hashed,
        "build_receipt": copy.deepcopy(build_receipt),
        "receipt": file_ref(bound_receipt, label=f"{target_id} authentic target receipt"),
        "target_id": target_id,
        "verified_utc": verified_utc,
    }


def load_release_artifact_identity_receipt(
    path: Path,
    *,
    target_id: str,
    expected_index: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    del path, target_id, expected_index, now
    raise FleetRefused(
        "caller-authored identity document or GCP acceptance receipt cannot assign TARGET_ID"
    )


def _unique_release_artifact_digests(
    artifacts: Mapping[str, Mapping[str, Any]],
) -> None:
    used: dict[str, str] = {}
    for target_id, artifact in artifacts.items():
        digest = require_sha256(f"{target_id} digest", artifact.get("sha256"))
        if digest in used:
            raise FleetRefused(
                "single-artifact reuse: each of the 16 target actions requires a distinct release artifact"
            )
        used[digest] = target_id


def create_required_release_artifacts_document(
    *,
    repo_root: Path,
    artifact_paths: Mapping[str, Path],
    receipt_paths: Mapping[str, Path] | Sequence[Any] | None,
    release_input_index: Mapping[str, Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    assert_required_release_artifact_count()
    current = now or _current_utc()
    index_ref = _live_release_input_index_ref(release_input_index)
    repo = _canonical_repo_root(repo_root)
    receipt_bindings = _normalize_receipt_bindings(receipt_paths)
    artifacts: dict[str, dict[str, Any]] = {}
    target_receipts: dict[str, dict[str, Any]] = {}
    if artifact_paths and not receipt_bindings:
        raise FleetRefused(
            "filename suffixes or caller labels cannot assign TARGET_ID; "
            "authentic cross-store target receipts are required"
        )
    if receipt_bindings:
        for claimed, receipt_path in receipt_bindings:
            identity = load_authenticated_target_receipt(
                receipt_path,
                repo_root=repo,
                expected_index=index_ref,
                claimed_target_id=claimed,
                now=current,
            )
            target_id = identity["target_id"]
            if target_id in artifacts:
                raise FleetRefused(f"duplicate release artifact receipt identity: {target_id}")
            artifacts[target_id] = identity["artifact"]
            target_receipts[target_id] = identity["receipt"]
        _require_complete_target_set(artifacts, label="release artifact receipt")
        _require_complete_target_set(target_receipts, label="release artifact receipt")
        if artifact_paths:
            _require_complete_target_set(artifact_paths, label="release artifact")
            for target_id, path in artifact_paths.items():
                hashed = _release_artifact_file_ref(target_id, path)
                if hashed != artifacts[target_id]:
                    raise FleetRefused(
                        f"{target_id} release artifact receipt does not match the supplied file"
                    )
        _unique_release_artifact_digests(artifacts)
    return {
        "kind": KIND_RELEASE_ARTIFACTS,
        "schema_version": RELEASE_ARTIFACTS_SCHEMA_VERSION,
        "contract": REQUIRED_RELEASE_ARTIFACTS_CONTRACT,
        "created_utc": format_utc(current.replace(microsecond=0)),
        "release_input_index": copy.deepcopy(index_ref),
        "artifacts": copy.deepcopy(artifacts),
        "target_receipts": copy.deepcopy(target_receipts),
    }


def verify_required_release_artifacts_document(
    raw: Any,
    *,
    expected_index: Mapping[str, Any],
    repo_root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    assert_required_release_artifact_count()
    current = now or _current_utc()
    if not isinstance(raw, dict):
        raise FleetRefused("required release artifact binding is malformed")
    assert_exact_keys(
        "required release artifact binding",
        raw,
        REQUIRED_RELEASE_ARTIFACTS_DOCUMENT_KEYS,
    )
    if (
        raw["kind"] != KIND_RELEASE_ARTIFACTS
        or raw["schema_version"] != RELEASE_ARTIFACTS_SCHEMA_VERSION
        or raw["contract"] != REQUIRED_RELEASE_ARTIFACTS_CONTRACT
    ):
        raise FleetRefused("required release artifact binding contract is invalid")
    created = parse_utc("required release artifact binding creation", raw["created_utc"])
    _require_fresh_timestamp("required release artifact binding", created, now=current)
    recorded_index = _live_release_input_index_ref(raw["release_input_index"])
    expected = _live_release_input_index_ref(expected_index)
    if recorded_index != expected:
        raise FleetRefused(
            "required release artifacts are bound to a different release input index"
        )
    artifacts_raw = raw["artifacts"]
    receipts_raw = raw["target_receipts"]
    if not isinstance(artifacts_raw, dict) or not isinstance(receipts_raw, dict):
        raise FleetRefused("required release artifact map is malformed")
    if bool(artifacts_raw) != bool(receipts_raw):
        raise FleetRefused(
            "required release artifacts must be bound to authentic target receipts"
        )
    if artifacts_raw:
        _require_complete_target_set(artifacts_raw, label="release artifact")
        _require_complete_target_set(receipts_raw, label="release artifact receipt")
    artifacts: dict[str, dict[str, Any]] = {}
    target_receipts: dict[str, dict[str, Any]] = {}
    for target_id, item in artifacts_raw.items():
        if target_id not in REQUIRED_RELEASE_ARTIFACTS:
            raise FleetRefused("required release artifact identities are extra")
        artifacts[target_id] = _reverify_release_artifact_file_ref(
            item,
            target_id=target_id,
            require_store_suffix=True,
        )
    for target_id, item in receipts_raw.items():
        if target_id not in REQUIRED_RELEASE_ARTIFACTS:
            raise FleetRefused("required release artifact receipt identities are extra")
        claimed = _validate_client_file_ref(item, f"{target_id} authentic target receipt")
        live = file_ref(Path(claimed["path"]), label=f"{target_id} authentic target receipt")
        if live != claimed:
            raise FleetRefused(
                f"{target_id} authentic target receipt is caller-forged, stale, or substituted"
            )
        target_receipts[target_id] = live
    if artifacts and repo_root is not None:
        repo = _canonical_repo_root(repo_root)
        for target_id, receipt_ref in target_receipts.items():
            identity = load_authenticated_target_receipt(
                Path(receipt_ref["path"]),
                repo_root=repo,
                expected_index=recorded_index,
                claimed_target_id=target_id,
                now=current,
            )
            if identity["artifact"] != artifacts[target_id]:
                raise FleetRefused(
                    f"{target_id} authentic receipt does not match the bound release artifact"
                )
            if identity["receipt"] != receipt_ref:
                raise FleetRefused(
                    f"{target_id} authentic target receipt is caller-forged, stale, or substituted"
                )
    elif artifacts and repo_root is None:
        raise FleetRefused(
            "required release artifacts must reverify authentic target receipts against the bound repository"
        )
    if artifacts:
        _unique_release_artifact_digests(artifacts)
    return {
        "artifacts": artifacts,
        "created_utc": raw["created_utc"],
        "release_input_index": recorded_index,
        "target_receipts": target_receipts,
    }


def bind_action_release_artifacts(
    artifacts: Mapping[str, Mapping[str, Any]],
    *,
    release_input_index: Mapping[str, Any] | None = None,
    reverify_files: bool = True,
    require_store_suffix: bool = False,
) -> list[dict[str, Any]]:
    assert_required_release_artifact_count()
    if set(artifacts) - set(REQUIRED_RELEASE_ARTIFACTS):
        raise FleetRefused("required release artifact identities are extra")
    index_ref = (
        _live_release_input_index_ref(release_input_index)
        if release_input_index is not None
        else None
    )
    used: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for action, target_id in zip(COLLECTOR_ACTIONS, REQUIRED_RELEASE_ARTIFACTS):
        artifact = artifacts.get(target_id)
        if artifact is None:
            rows.append(
                {
                    "action": action,
                    "reason": "missing required release artifact",
                    "status": "blocked",
                    "target_id": target_id,
                }
            )
            continue
        if not isinstance(artifact, dict):
            raise FleetRefused(f"{target_id} release artifact is malformed")
        if reverify_files:
            verified = _reverify_release_artifact_file_ref(
                artifact,
                target_id=target_id,
                require_store_suffix=require_store_suffix,
            )
        else:
            verified = _validate_client_file_ref(
                artifact, f"{target_id} release artifact"
            )
            require_sha256(f"{target_id} digest", verified["sha256"])
        digest = verified["sha256"]
        if digest in used and used[digest] != target_id:
            raise FleetRefused(
                "single-artifact reuse: each of the 16 target actions requires a distinct release artifact"
            )
        used[digest] = target_id
        row = {
            "action": action,
            "artifact": copy.deepcopy(verified),
            "status": "proven",
            "target_id": target_id,
        }
        if index_ref is not None:
            row["release_input_index"] = copy.deepcopy(index_ref)
        rows.append(row)
    if len(rows) != REQUIRED_RELEASE_ARTIFACT_COUNT:
        raise FleetRefused("required release artifact actions are missing or extra")
    return rows


def evaluate_action_release_artifacts(
    client_reference: Mapping[str, Any],
    supplied_artifacts: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    reference = validate_client_release_binding_reference(client_reference)
    index_ref = _live_release_input_index_ref(
        reference["binding"]["release_input_index"]
    )
    if supplied_artifacts:
        artifacts = supplied_artifacts
        require_store_suffix = True
    else:
        artifacts = available_release_artifacts(client_reference)
        require_store_suffix = False
    return bind_action_release_artifacts(
        artifacts,
        release_input_index=index_ref,
        require_store_suffix=require_store_suffix,
    )


def load_plan_required_release_artifacts(
    state: Path,
    *,
    expected_index: Mapping[str, Any],
    repo_root: Path,
    now: datetime | None = None,
) -> dict[str, dict[str, Any]] | None:
    paths = state_paths(state)
    if not paths["release_artifacts"].exists() and not paths["release_artifacts_hash"].exists():
        return None
    raw, _digest = load_json_document(
        paths["release_artifacts"], require_immutable=True
    )
    verified = verify_required_release_artifacts_document(
        raw, expected_index=expected_index, repo_root=repo_root, now=now
    )
    return verified["artifacts"] or None


def reviewed_live_probe_ref() -> dict[str, Any]:
    return file_ref(
        REVIEWED_LIVE_PROBE_PATH.absolute(), label="reviewed live probe"
    )


def execution_record_digest(record: Mapping[str, Any]) -> str:
    core = dict(record)
    core.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(core))


def validate_file_runtime(
    label: str, raw: Any, *, applicable: bool, path: str | None
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, FILE_RUNTIME_KEYS)
    actual_applicable = require_bool(f"{label}.applicable", raw["applicable"])
    if actual_applicable is not applicable:
        raise FleetRefused(f"{label} applicability does not match the role")
    if not applicable:
        if raw["bytes"] is not None or raw["path"] is not None or raw["sha256"] is not None:
            raise FleetRefused(f"{label} must be empty when not applicable")
        return copy.deepcopy(raw)
    if require_str(f"{label}.path", raw["path"]) != path:
        raise FleetRefused(f"{label} path does not match the bound runtime")
    bytes_count = require_int(f"{label}.bytes", raw["bytes"])
    if bytes_count <= 0:
        raise FleetRefused(f"{label} byte length is invalid")
    require_sha256(f"{label}.sha256", raw["sha256"])
    return copy.deepcopy(raw)


def validate_awg_runtime(role: str, raw: Any) -> dict[str, Any]:
    label = f"{role} AWG runtime"
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, AWG_RUNTIME_KEYS)
    applicable = require_bool(f"{label}.applicable", raw["applicable"])
    expected = role == "data-cover"
    if applicable is not expected:
        raise FleetRefused(f"{label} applicability does not match the role")
    if not applicable:
        if (
            raw["image"] is not None
            or raw["image_id"] is not None
            or raw["provenance_receipt"] is not None
        ):
            raise FleetRefused(f"{label} must be empty when not applicable")
        return copy.deepcopy(raw)
    require_str(f"{label}.image", raw["image"])
    require_str(f"{label}.image_id", raw["image_id"])
    validate_file_runtime(
        f"{label}.provenance_receipt",
        raw["provenance_receipt"],
        applicable=True,
        path=AWG_PROVENANCE_PATH,
    )
    return copy.deepcopy(raw)


def validate_router_runtime(role: str, raw: Any) -> dict[str, Any]:
    label = f"{role} router runtime"
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, ROUTER_RUNTIME_KEYS)
    if require_bool(f"{label}.applicable", raw["applicable"]) is not False:
        raise FleetRefused(f"{label} must remain not applicable")
    if raw["deployment_identity"] is not None or raw["image_id"] is not None:
        raise FleetRefused(f"{label} live image identity must be empty")
    digest = require_str(
        f"{label}.manifest_base_image_digest", raw["manifest_base_image_digest"]
    )
    reference = require_str(
        f"{label}.manifest_base_image_reference", raw["manifest_base_image_reference"]
    )
    if not digest or not reference:
        raise FleetRefused(f"{label} manifest pin is missing")
    return copy.deepcopy(raw)


def validate_runtime_identities(role: str, raw: Any) -> dict[str, Any]:
    if role not in ROLES or not isinstance(raw, dict):
        raise FleetRefused("runtime identity is malformed")
    assert_exact_keys(f"{role} runtime", raw, {"awg", "router", "winn", "xray"})
    binaries = ROLE_RUNTIME_BINARIES[role]
    return {
        "awg": validate_awg_runtime(role, raw["awg"]),
        "router": validate_router_runtime(role, raw["router"]),
        "winn": validate_file_runtime(
            f"{role} winn runtime",
            raw["winn"],
            applicable=binaries["winn"] is not None,
            path=binaries["winn"],
        ),
        "xray": validate_file_runtime(
            f"{role} xray runtime",
            raw["xray"],
            applicable=binaries["xray"] is not None,
            path=binaries["xray"],
        ),
    }


def validate_index_list(label: str, raw: Any, expected: list[int]) -> list[int]:
    if not isinstance(raw, list) or any(type(item) is not int for item in raw):
        raise FleetRefused(f"{label} must be exact integers")
    if raw != expected or raw != sorted(set(raw)):
        raise FleetRefused(f"{label} is missing, extra, or reordered")
    return list(raw)


def validate_deployment_marker(
    raw: Any,
    *,
    spec: FleetSpec,
    role: str,
    plan_digest: str,
    apply_digest: str,
    candidate_id: str,
    manifest_digest: str,
    record_chain: str,
    require_final: bool,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused(f"{role} installation marker is malformed")
    assert_exact_keys(f"{role} installation marker", raw, MARKER_KEYS)
    if (
        raw["kind"] != KIND_MARKER
        or require_int(f"{role} marker schema", raw["schema_version"])
        != MARKER_SCHEMA_VERSION
    ):
        raise FleetRefused(f"{role} installation marker kind/schema is invalid")
    instance = spec.by_role[role].name
    role_steps = [
        index
        for index, item in enumerate(expected_installer_triples())
        if item[0] == role
    ]
    fleet_steps = list(range(len(expected_installer_triples())))
    exact_equal(f"{role} marker.apply_sha256", raw["apply_sha256"], apply_digest)
    exact_equal(f"{role} marker.plan_sha256", raw["plan_sha256"], plan_digest)
    exact_equal(f"{role} marker.candidate_id", raw["candidate_id"], candidate_id)
    exact_equal(
        f"{role} marker.deployment_manifest_sha256",
        raw["deployment_manifest_sha256"],
        manifest_digest,
    )
    exact_equal(f"{role} marker.fleet_id", raw["fleet_id"], fleet_id_for(spec))
    exact_equal(f"{role} marker.instance", raw["instance"], instance)
    exact_equal(f"{role} marker.role", raw["role"], role)
    exact_equal(
        f"{role} marker.fleet_record_chain_sha256",
        raw["fleet_record_chain_sha256"],
        record_chain,
    )
    if require_final:
        validate_index_list(
            f"{role} marker completed steps",
            raw["completed_step_indices"],
            role_steps,
        )
        validate_index_list(
            f"{role} marker fleet completed steps",
            raw["fleet_completed_step_indices"],
            fleet_steps,
        )
    else:
        completed = raw["completed_step_indices"]
        if not isinstance(completed, list) or any(
            type(item) is not int for item in completed
        ):
            raise FleetRefused(f"{role} marker completed steps are invalid")
    parse_utc(f"{role} marker updated_utc", raw["updated_utc"])
    validate_runtime_identities(role, raw["runtime"])
    return copy.deepcopy(raw)


def validate_authenticated_file(
    label: str,
    raw: Any,
    *,
    path: str,
    architecture: str,
    extra_keys: set[str] = frozenset(),
) -> dict[str, Any]:
    expected = set(AUTHENTICATED_FILE_KEYS) | extra_keys
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, expected)
    exact_equal(f"{label}.path", raw["path"], path)
    require_sha256(f"{label}.sha256", raw["sha256"])
    if require_int(f"{label}.bytes", raw["bytes"]) <= 0:
        raise FleetRefused(f"{label} byte length is invalid")
    observed_arch = require_str(f"{label}.architecture", raw["architecture"])
    if observed_arch != architecture:
        raise FleetRefused(f"{label} architecture does not match the bound identity")
    version = require_str(f"{label}.version", raw["version"])
    if not version or len(version) > 128:
        raise FleetRefused(f"{label} version is invalid")
    return copy.deepcopy(raw)


def validate_candidate_observation(
    role: str,
    raw: Any,
    *,
    candidate_id: str,
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    label = f"{role} candidate"
    if not isinstance(raw, dict):
        raise FleetRefused(f"{label} is malformed")
    assert_exact_keys(label, raw, CANDIDATE_OBSERVATION_KEYS)
    exact_equal(f"{label}.id", raw["id"], candidate_id)
    files = raw["files"]
    expected = expected_candidate_files(manifest, role)
    expected_by_path = {item["path"]: item for item in expected}
    if not isinstance(files, list):
        raise FleetRefused(f"{label} files are malformed")
    if not files:
        raise FleetRefused(f"{label} is missing candidate bytes")
    if len(files) != len(expected) or len(expected_by_path) != len(expected):
        raise FleetRefused(
            f"{label} contains extra, missing, or mixed candidate bytes"
        )
    seen: set[str] = set()
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            raise FleetRefused(f"{label} file {index} is malformed")
        assert_exact_keys(f"{label} file {index}", item, CANDIDATE_FILE_KEYS)
        rel = require_str(f"{label} file {index}.path", item["path"])
        if (
            not rel
            or rel.startswith("/")
            or "\\" in rel
            or ".." in Path(rel).parts
            or rel in seen
        ):
            raise FleetRefused(
                f"{label} contains extra, missing, or mixed candidate paths"
            )
        if rel not in expected_by_path:
            raise FleetRefused(f"{label} contains arbitrary candidate bytes")
        if require_int(f"{label} file {index}.bytes", item["bytes"]) <= 0:
            raise FleetRefused(f"{label} file {index} byte length is invalid")
        require_sha256(f"{label} file {index}.sha256", item["sha256"])
        exact_equal(f"{label} file {index}", item, expected_by_path[rel])
        seen.add(rel)
    if seen != set(expected_by_path):
        raise FleetRefused(
            f"{label} contains extra, missing, or mixed candidate bytes"
        )
    return copy.deepcopy(raw)


def validate_deployment_execution_records(
    records: Any,
    *,
    spec: FleetSpec,
    plan_digest: str,
    apply_digest: str,
    manifest_digest: str,
    installers: Sequence[Mapping[str, Any]],
    require_complete: bool,
) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(records, list):
        raise FleetRefused("deployment execution records are malformed")
    if require_complete and len(records) != len(installers):
        raise FleetRefused("deployment execution records are missing or extra")
    if not require_complete and len(records) > len(installers):
        raise FleetRefused("deployment execution records are extra")
    previous = ZERO_SHA256
    verified: list[dict[str, Any]] = []
    for index, (installer, record) in enumerate(zip(installers, records)):
        if not isinstance(record, dict):
            raise FleetRefused("deployment execution record is malformed")
        assert_exact_keys("deployment execution record", record, EXECUTION_RECORD_KEYS)
        if (
            record["kind"] != KIND_RECORD
            or require_int("deployment record schema", record["schema_version"]) != 1
            or require_int("deployment record step", record["step_index"]) != index
            or require_int("deployment record exit", record["exit_code"]) != 0
        ):
            raise FleetRefused("deployment execution record step identity is invalid")
        exact_equal("deployment record plan", record["plan_sha256"], plan_digest)
        exact_equal("deployment record apply", record["apply_sha256"], apply_digest)
        exact_equal(
            "deployment record manifest", record["manifest_sha256"], manifest_digest
        )
        exact_equal("deployment record fleet", record["fleet_id"], fleet_id_for(spec))
        exact_equal("deployment record role", record["role"], installer["role"])
        exact_equal(
            "deployment record instance", record["instance"], installer["instance"]
        )
        exact_equal("deployment record script", record["script"], installer["script"])
        exact_equal("deployment record flag", record["flag"], installer["flag"])
        exact_equal(
            "deployment record script_ref",
            record["script_ref"],
            installer["script_ref"],
        )
        exact_equal("deployment record previous", record["previous_sha256"], previous)
        parse_utc("deployment record start", record["started_utc"])
        parse_utc("deployment record end", record["ended_utc"])
        if record["record_sha256"] != execution_record_digest(record):
            raise FleetRefused("deployment execution record was edited")
        previous = record["record_sha256"]
        verified.append(copy.deepcopy(record))
    if require_complete and previous == ZERO_SHA256:
        raise FleetRefused("deployment execution record chain is empty")
    return verified, previous


def validate_deployment_execution_payload(
    raw: Any,
    *,
    spec: FleetSpec,
    plan_digest: str,
    apply_digest: str,
    plan: Mapping[str, Any],
    require_passed: bool,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused("deployment execution receipt is malformed")
    _assert_json_types("deployment execution receipt", raw)
    status = require_str("deployment execution status", raw.get("status"))
    if status not in {"passed", "failed", "cleaned"}:
        raise FleetRefused("deployment execution status is invalid")
    if require_passed and status != "passed":
        raise FleetRefused("deployment execution receipt did not pass")
    assert_exact_keys("deployment execution receipt", raw, EXECUTION_RECEIPT_KEYS)
    if (
        raw["kind"] != KIND_EXECUTION
        or require_int("deployment execution schema", raw["schema_version"])
        != EXECUTION_SCHEMA_VERSION
    ):
        raise FleetRefused("deployment execution receipt kind/schema is invalid")
    deployment_reference, manifest = verify_deployment_inputs_reference(
        Path(str(plan["client_release_binding"]["repo_root"])),
        Path(str(plan["deployment_inputs"]["path"])),
        plan["deployment_inputs"],
    )
    client_reference = verify_client_release_binding_reference(
        plan["client_release_binding"]
    )
    exact_equal("execution plan digest", raw["plan_sha256"], plan_digest)
    exact_equal("execution apply digest", raw["apply_sha256"], apply_digest)
    exact_equal(
        "execution manifest digest",
        raw["deployment_manifest_sha256"],
        deployment_reference["sha256"],
    )
    exact_equal("execution fleet id", raw["fleet_id"], fleet_id_for(spec))
    exact_equal(
        "execution candidate id",
        raw["candidate_id"],
        deployment_reference["candidate_id"],
    )
    exact_equal(
        "execution deployment inputs",
        raw["deployment_inputs"],
        deployment_reference,
    )
    exact_equal(
        "execution client release binding",
        raw["client_release_binding"],
        client_reference,
    )
    if "release_input_index" not in client_reference["binding"]:
        raise FleetRefused(
            "execution producer receipt is not bound to an authenticated source freeze"
        )
    if not isinstance(raw["failure"], dict):
        raise FleetRefused("deployment execution failure record is malformed")
    if status == "passed" and raw["failure"]:
        raise FleetRefused("passed deployment execution must not carry a failure record")
    verified_preflight = validate_preflight(
        raw.get("preflight"), spec, require_complete=(status == "passed")
    )
    verified_cleanup = validate_cleanup(raw.get("cleanup"), execution_status=status)
    require_sha256("execution bundle digest", raw["bundle_sha256"])
    require_sha256("execution remote helper digest", raw["remote_helper_sha256"])
    started = parse_utc("execution start", raw["started_utc"])
    ended = parse_utc("execution end", raw["ended_utc"])
    if started > ended:
        raise FleetRefused("deployment execution timestamps are reordered")
    for role, identity in verified_preflight["instances"].items():
        created = parse_creation_timestamp(
            f"{role} creation timestamp",
            identity["creation_transaction"]["creation_timestamp"],
        )
        if created > ended + MAX_CLOCK_SKEW:
            raise FleetRefused(f"{role} creation transaction is not bound to this execution")
    installers = build_installer_sequence(spec, manifest)
    records = raw.get("records")
    if status == "passed":
        verified_records, chain = validate_deployment_execution_records(
            records,
            spec=spec,
            plan_digest=plan_digest,
            apply_digest=apply_digest,
            manifest_digest=deployment_reference["sha256"],
            installers=installers,
            require_complete=True,
        )
        exact_equal("execution record chain", raw["record_chain_sha256"], chain)
        markers = raw.get("markers")
        if not isinstance(markers, dict) or set(markers) != set(ROLES):
            raise FleetRefused("deployment markers are missing or mixed")
        verified_markers = {}
        for role in ROLES:
            marker = validate_deployment_marker(
                markers[role],
                spec=spec,
                role=role,
                plan_digest=plan_digest,
                apply_digest=apply_digest,
                candidate_id=deployment_reference["candidate_id"],
                manifest_digest=deployment_reference["sha256"],
                record_chain=chain,
                require_final=True,
            )
            marker_updated = parse_utc(
                f"{role} marker updated_utc", marker["updated_utc"]
            )
            if marker_updated < started or marker_updated > ended:
                raise FleetRefused(f"{role} installation marker is stale")
            verified_markers[role] = marker
        payload = copy.deepcopy(raw)
        payload["records"] = verified_records
        payload["markers"] = verified_markers
        payload["preflight"] = verified_preflight
        payload["cleanup"] = verified_cleanup
        payload["deployment_manifest"] = copy.deepcopy(manifest)
        return payload
    if not isinstance(raw.get("markers"), dict):
        raise FleetRefused("failed deployment markers are malformed")
    verified_records, chain = ([], ZERO_SHA256)
    if isinstance(records, list) and records:
        if any(
            not isinstance(item, dict) or type(item.get("exit_code")) is not int
            for item in records
        ):
            raise FleetRefused("failed deployment records are malformed")
        require_sha256("failed execution record chain", raw["record_chain_sha256"])
        chain = raw["record_chain_sha256"]
        verified_records = copy.deepcopy(records)
    else:
        exact_equal("failed execution record chain", raw["record_chain_sha256"], ZERO_SHA256)
    payload = copy.deepcopy(raw)
    payload["records"] = verified_records
    payload["preflight"] = verified_preflight
    payload["cleanup"] = verified_cleanup
    payload["deployment_manifest"] = copy.deepcopy(manifest)
    payload["record_chain_sha256"] = chain
    return payload


def load_deployment_execution(
    path: Path,
    *,
    spec: FleetSpec,
    plan_digest: str,
    apply_digest: str,
    plan: Mapping[str, Any],
    state_dir: Path,
    require_passed: bool,
) -> tuple[dict[str, Any], str]:
    execution_path = require_state_file(
        state_dir, path, label="deployment execution receipt"
    )
    if execution_path.name != EXECUTION_NAME:
        raise FleetRefused("deployment execution receipt name is invalid")
    raw, digest = load_json_document(execution_path, require_immutable=True)
    payload = validate_deployment_execution_payload(
        raw,
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        plan=plan,
        require_passed=require_passed,
    )
    return payload, digest


def deployment_binding(
    *,
    execution_path: Path,
    execution: Mapping[str, Any],
    execution_digest: str,
) -> dict[str, Any]:
    reference = file_ref(execution_path.absolute(), label="deployment execution receipt")
    if reference["sha256"] != execution_digest:
        raise FleetRefused("deployment execution receipt changed after verification")
    chain = execution.get("record_chain_sha256")
    if chain is None:
        chain = ZERO_SHA256
    return {
        "deployment_execution": reference,
        "deployment_candidate_id": require_sha256(
            "deployment candidate id", execution["candidate_id"]
        ),
        "deployment_manifest_sha256": require_sha256(
            "deployment manifest digest", execution["deployment_manifest_sha256"]
        ),
        "deployment_record_chain_sha256": require_sha256(
            "deployment record chain", chain
        ),
    }


def build_spec(
    *,
    project: str,
    control_name: str,
    winn3_data_name: str,
    cover_data_name: str,
    control_zone: str,
    winn3_data_zone: str,
    cover_data_zone: str,
    control_machine: str,
    winn3_data_machine: str,
    cover_data_machine: str,
    admin_source_cidr: str,
    dataplane_source_cidr: str | None,
    image_family: str,
    image_project: str,
    gcloud_bin: str,
) -> FleetSpec:
    instances = (
        InstanceSpec(
            "control",
            validate_gce_name("control instance", control_name),
            validate_token("control zone", control_zone, GCE_ZONE_RE),
            validate_token("control machine", control_machine, MACHINE_TYPE_RE),
        ),
        InstanceSpec(
            "data-winn3",
            validate_gce_name("Winn v3 data instance", winn3_data_name),
            validate_token("Winn v3 data zone", winn3_data_zone, GCE_ZONE_RE),
            validate_token("Winn v3 data machine", winn3_data_machine, MACHINE_TYPE_RE),
        ),
        InstanceSpec(
            "data-cover",
            validate_gce_name("cover data instance", cover_data_name),
            validate_token("cover data zone", cover_data_zone, GCE_ZONE_RE),
            validate_token("cover data machine", cover_data_machine, MACHINE_TYPE_RE),
        ),
    )
    if len(set(item.name for item in instances)) != 3:
        raise FleetRefused(
            "control, Winn v3 data, and cover data names must be distinct"
        )
    if image_project != DEFAULT_IMAGE_PROJECT or not re.fullmatch(
        r"ubuntu-(minimal-)?2404-lts(-(amd64|arm64))?", image_family or ""
    ):
        raise FleetRefused("image must be Ubuntu 24.04 LTS from ubuntu-os-cloud")
    admin = validate_cidr("admin source CIDR", admin_source_cidr, allow_world=False)
    return FleetSpec(
        validate_proof_project(project),
        instances,
        admin,
        validate_cidr(
            "dataplane source CIDR", dataplane_source_cidr or admin, allow_world=False
        ),
        image_family,
        image_project,
        validate_gcloud_bin(gcloud_bin),
    )


def fleet_id_for(spec: FleetSpec) -> str:
    return sha256_bytes(
        canonical_bytes(
            {
                "project": spec.project,
                "instances": [{"role": i.role, "name": i.name} for i in spec.instances],
            }
        )
    )[:12]


def canonical_resource_contract(
    fleet_id: str, role_zones: Mapping[str, str]
) -> dict[str, Any]:
    """Return the exact proof-resource names shared by every proof component."""
    if set(role_zones) != set(ROLES):
        raise FleetRefused("proof resource roles are missing or mixed")
    if not isinstance(fleet_id, str) or not fleet_id:
        raise FleetRefused("proof fleet id is invalid")
    subnets = []
    for role in ROLES:
        zone = role_zones[role]
        if not isinstance(zone, str) or not GCE_ZONE_RE.fullmatch(zone):
            raise FleetRefused(f"proof resource zone is invalid for {role}")
        subnets.append(
            {
                "name": f"pf-{fleet_id}-sn-{role}",
                "region": region_of(zone),
                "role": role,
            }
        )
    return {
        "network": f"pf-{fleet_id}-net",
        "subnets": subnets,
        "firewalls": {
            key: f"pf-{fleet_id}-{suffix}"
            for key, suffix in RESOURCE_FIREWALL_SUFFIXES.items()
        },
    }


def resource_names(spec: FleetSpec) -> dict[str, Any]:
    fleet_id = fleet_id_for(spec)
    first = int(fleet_id[:2], 16)
    canonical = canonical_resource_contract(
        fleet_id, {item.role: item.zone for item in spec.instances}
    )
    subnets = [
        {
            **item,
            "cidr": f"172.{16 + index}.{(first + index * 17) % 256}.0/24",
        }
        for index, item in enumerate(canonical["subnets"])
    ]
    subnet_networks = [ipaddress.ip_network(item["cidr"]) for item in subnets]
    source_networks = [
        ipaddress.ip_network(spec.admin_source_cidr),
        ipaddress.ip_network(spec.dataplane_source_cidr),
    ]
    if any(
        left.overlaps(right)
        for index, left in enumerate(subnet_networks)
        for right in subnet_networks[index + 1 :]
    ) or any(
        subnet.overlaps(source)
        for subnet in subnet_networks
        for source in source_networks
    ):
        raise FleetRefused("proof subnets overlap another proof or source CIDR")
    tags = {
        "fleet": f"pf-{fleet_id}",
        "control": "pf-role-control",
        "data-winn3": "pf-role-data-winn3",
        "data-cover": "pf-role-data-cover",
    }
    if FORBIDDEN_TAGS.intersection(tags.values()):
        raise FleetRefused("internal tag collision")
    return {
        "fleet_id": fleet_id,
        "network": canonical["network"],
        "subnets": subnets,
        "tags": tags,
        "firewalls": canonical["firewalls"],
    }


def command(gcloud_bin: str, args: Sequence[str]) -> dict[str, Any]:
    argv = [gcloud_bin, *args]
    for token in argv:
        if (
            not token
            or SECRET_RE.search(token)
            or any(
                token.lower() == flag or token.lower().startswith(flag + "=")
                for flag in FORBIDDEN_FLAGS
            )
        ):
            raise FleetRefused("refusing unsafe command token")
    return {
        "argv": argv,
        "mutation": any(
            tuple(args[: len(prefix)]) == prefix for prefix in MUTATION_ARGV_PREFIXES
        ),
        "preview": shlex.join(argv),
    }


def build_plan_commands(spec: FleetSpec) -> list[dict[str, Any]]:
    r = resource_names(spec)
    project, network, gcloud = spec.project, r["network"], spec.gcloud_bin
    result = [
        command(
            gcloud,
            [
                "compute",
                "networks",
                "create",
                network,
                f"--project={project}",
                "--subnet-mode=custom",
                "--bgp-routing-mode=regional",
                "--description=winsvpn-gcp-proof-fleet",
                "--quiet",
            ],
        )
    ]
    for subnet in r["subnets"]:
        result.append(
            command(
                gcloud,
                [
                    "compute",
                    "networks",
                    "subnets",
                    "create",
                    subnet["name"],
                    f"--project={project}",
                    f"--network={network}",
                    f"--region={subnet['region']}",
                    f"--range={subnet['cidr']}",
                    "--quiet",
                ],
            )
        )
    tags, fw = r["tags"], r["firewalls"]
    rules = (
        (fw["admin_ssh"], "tcp:22", "source-ranges", spec.admin_source_cidr, tags["fleet"]),
        (fw["control_http"], "tcp:80,tcp:443", "source-ranges", spec.admin_source_cidr, tags["control"]),
        (fw["winn3_ingress"], "tcp:9111,udp:9111", "source-tags", tags["control"], tags["data-winn3"]),
        (fw["cover_ingress"], "tcp:80,tcp:443,udp:9110,udp:20000-32767", "source-tags", tags["control"], tags["data-cover"]),
    )
    for name, allowed, source_kind, source, target in rules:
        result.append(
            command(
                gcloud,
                [
                    "compute",
                    "firewall-rules",
                    "create",
                    name,
                    f"--project={project}",
                    f"--network={network}",
                    "--direction=INGRESS",
                    "--action=ALLOW",
                    f"--rules={allowed}",
                    f"--{source_kind}={source}",
                    f"--target-tags={target}",
                    "--quiet",
                ],
            )
        )
    for item in spec.instances:
        subnet = next(s for s in r["subnets"] if s["role"] == item.role)
        forwarding = (
            ["--can-ip-forward"]
            if item.role in ("data-winn3", "data-cover")
            else []
        )
        result.append(
            command(
                gcloud,
                [
                    "compute",
                    "instances",
                    "create",
                    item.name,
                    f"--project={project}",
                    f"--zone={item.zone}",
                    f"--machine-type={item.machine_type}",
                    f"--network={network}",
                    f"--subnet={subnet['name']}",
                    "--network-tier=PREMIUM",
                    "--boot-disk-size=20GB",
                    "--boot-disk-type=pd-balanced",
                    f"--image-family={spec.image_family}",
                    f"--image-project={spec.image_project}",
                    "--no-service-account",
                    "--no-scopes",
                    "--shielded-secure-boot",
                    "--shielded-vtpm",
                    "--shielded-integrity-monitoring",
                    "--deletion-protection",
                    *forwarding,
                    "--provisioning-model=STANDARD",
                    f"--tags={tags['fleet']},{tags[item.role]}",
                    f"--labels=winsvpn-proof-fleet=1,winsvpn-proof-role={item.role},winsvpn-proof-id={r['fleet_id']}",
                    f"--metadata=enable-oslogin=TRUE,winsvpn-proof-role={item.role}",
                    "--quiet",
                ],
            )
        )
    return result


def expected_installer_triples() -> tuple[tuple[str, str, str], ...]:
    return (
        ("control", CONTROL_INSTALLER, "--preflight"),
        ("control", CONTROL_INSTALLER, "--deploy"),
        ("data-winn3", GATEWAY_INSTALLER, "--install"),
        ("data-winn3", PROOF_KEY_PROVISION_ID, PROOF_KEY_PROVISION_FLAG),
        ("data-winn3", GATEWAY_INSTALLER, "--preflight"),
        ("data-winn3", GATEWAY_INSTALLER, "--start"),
        ("data-cover", DATA_INSTALLER, "--preflight"),
        ("data-cover", DATA_INSTALLER, "--deploy"),
    )


def installer_command(
    role: str, instance: str, script: str, flag: str
) -> dict[str, Any]:
    expected = CONTROL_INSTALLER if role == "control" else DATA_INSTALLER
    proof_provision = (
        role == "data-winn3"
        and script == PROOF_KEY_PROVISION_ID
        and flag == PROOF_KEY_PROVISION_FLAG
    )
    if (
        role not in ROLES
        or (script == GATEWAY_INSTALLER and role != "data-winn3")
        or (
            not proof_provision
            and script != GATEWAY_INSTALLER
            and script != expected
        )
    ):
        raise FleetRefused(
            "Winn v3 gateway is data-winn3-only and installers must match roles"
        )
    argv = ["bash", script, flag]
    return {
        "argv": argv,
        "flag": flag,
        "instance": instance,
        "kind": "installer",
        "mutation": False,
        "preview": shlex.join(argv),
        "role": role,
        "script": script,
    }


def build_installer_sequence(
    spec: FleetSpec, manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    raw_installers = manifest.get("installers")
    if not isinstance(raw_installers, list):
        raise FleetRefused("deployment manifest installer bindings are malformed")
    refs: dict[str, Mapping[str, Any]] = {}
    for raw in raw_installers:
        if not isinstance(raw, dict) or set(raw) != {"bytes", "mode", "path", "sha256"}:
            raise FleetRefused("deployment manifest installer reference is malformed")
        path = raw["path"]
        if not isinstance(path, str) or path in refs:
            raise FleetRefused("deployment manifest installer paths are invalid")
        refs[path] = raw
    result: list[dict[str, Any]] = []
    for index, (role, script, flag) in enumerate(expected_installer_triples()):
        if script == PROOF_KEY_PROVISION_ID:
            source: Mapping[str, Any] = {
                "bytes": 0,
                "mode": 0,
                "sha256": "0" * 64,
            }
        else:
            bound = refs.get(script)
            if bound is None:
                raise FleetRefused(f"deployment manifest does not bind {script}")
            source = bound
        result.append(
            {
                "execution_owner": "gcp_proof_deploy.py",
                "flag": flag,
                "index": index,
                "instance": spec.by_role[role].name,
                "remote_mutation": True,
                "role": role,
                "script": script,
                "script_ref": {
                    key: source[key] for key in ("bytes", "mode", "sha256")
                },
            }
        )
    return result


def resource_identity(spec: FleetSpec) -> dict[str, Any]:
    r = resource_names(spec)
    return {
        "instances": [item.name for item in spec.instances],
        "network": r["network"],
        "subnets": [s["name"] for s in r["subnets"]],
        "firewalls": sorted(r["firewalls"].values()),
    }


def spec_document(spec: FleetSpec) -> dict[str, Any]:
    r = resource_names(spec)
    return {
        "project": spec.project,
        "fleet_id": r["fleet_id"],
        "instances": [i.as_dict() for i in spec.instances],
        "admin_source_cidr": spec.admin_source_cidr,
        "dataplane_source_cidr": spec.dataplane_source_cidr,
        "image_family": spec.image_family,
        "image_project": spec.image_project,
        "gcloud_bin": spec.gcloud_bin,
        "network": r["network"],
        "resources": r,
    }


def plan_bound_inputs(
    raw: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    client_reference = verify_client_release_binding_reference(
        raw.get("client_release_binding")
    )
    repo = Path(client_reference["repo_root"])
    deployment_reference, manifest = verify_deployment_inputs_reference(
        repo,
        Path(str(validate_deployment_inputs_reference(raw.get("deployment_inputs"))["path"])),
        raw.get("deployment_inputs"),
    )
    return deployment_reference, manifest, client_reference


def spec_from_plan(plan: Mapping[str, Any]) -> FleetSpec:
    expected_plan_keys = {
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
    }
    if (
        set(plan) != expected_plan_keys
        or
        plan.get("kind") != KIND_PLAN
        or plan.get("schema_version") != SCHEMA_VERSION
        or plan.get("phase") != "plan"
        or plan.get("dry_run") is not True
        or not isinstance(plan.get("fleet"), dict)
    ):
        raise FleetRefused("plan document kind/schema/fleet is invalid")
    parse_utc("plan creation UTC", plan.get("created_utc"))
    _, manifest, _ = plan_bound_inputs(plan)
    fleet = plan["fleet"]
    instances = fleet.get("instances")
    if not isinstance(instances, list) or len(instances) != 3:
        raise FleetRefused("plan must contain exactly three instances")
    by_role: dict[str, Mapping[str, Any]] = {}
    for item in instances:
        if (
            not isinstance(item, dict)
            or item.get("role") not in ROLES
            or item["role"] in by_role
        ):
            raise FleetRefused("plan roles are invalid or duplicated")
        by_role[item["role"]] = item
    if set(by_role) != set(ROLES):
        raise FleetRefused("plan must include control, data-winn3, and data-cover")
    spec = build_spec(
        project=str(fleet.get("project") or ""),
        control_name=str(by_role["control"].get("name") or ""),
        winn3_data_name=str(by_role["data-winn3"].get("name") or ""),
        cover_data_name=str(by_role["data-cover"].get("name") or ""),
        control_zone=str(by_role["control"].get("zone") or ""),
        winn3_data_zone=str(by_role["data-winn3"].get("zone") or ""),
        cover_data_zone=str(by_role["data-cover"].get("zone") or ""),
        control_machine=str(by_role["control"].get("machine_type") or ""),
        winn3_data_machine=str(by_role["data-winn3"].get("machine_type") or ""),
        cover_data_machine=str(by_role["data-cover"].get("machine_type") or ""),
        admin_source_cidr=str(fleet.get("admin_source_cidr") or ""),
        dataplane_source_cidr=str(fleet.get("dataplane_source_cidr") or ""),
        image_family=str(fleet.get("image_family") or ""),
        image_project=str(fleet.get("image_project") or ""),
        gcloud_bin=str(fleet.get("gcloud_bin") or "gcloud"),
    )
    expected = build_installer_sequence(spec, manifest)
    if fleet != spec_document(spec):
        raise FleetRefused("plan fleet document does not match the rebuilt topology")
    if plan.get("installers") != expected:
        raise FleetRefused("plan installer sequence does not match topology")
    if plan.get("commands") != build_plan_commands(spec):
        raise FleetRefused("plan commands do not match the rebuilt fleet specification")
    return spec


def state_paths(state: Path) -> dict[str, Path]:
    return {
        "plan": state / PLAN_NAME,
        "plan_hash": state / f"{PLAN_NAME}.sha256",
        "apply": state / APPLY_NAME,
        "apply_hash": state / f"{APPLY_NAME}.sha256",
        "receipt": state / RECEIPT_NAME,
        "receipt_hash": state / f"{RECEIPT_NAME}.sha256",
        "execution": state / EXECUTION_NAME,
        "execution_hash": state / f"{EXECUTION_NAME}.sha256",
        "emergency": state / EMERGENCY_NAME,
        "emergency_hash": state / f"{EMERGENCY_NAME}.sha256",
        "release_artifacts": state / REQUIRED_RELEASE_ARTIFACTS_NAME,
        "release_artifacts_hash": state / f"{REQUIRED_RELEASE_ARTIFACTS_NAME}.sha256",
    }


def _unlink_state_document(path: Path) -> None:
    if path.exists():
        if path.is_symlink():
            raise FleetRefused("state symlink refused")
        path.unlink()


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        stat.S_IMODE(info.st_mode),
    )


def prepare_state_dir(path: Path, *, create: bool) -> Path:
    raw = path.expanduser()
    if not raw.is_absolute():
        raise FleetRefused("state dir must be an absolute path")
    if os.path.normpath(str(raw)) != str(raw):
        raise FleetRefused("state dir must be a canonical path")
    try:
        current = raw.lstat()
        present = True
    except FileNotFoundError:
        present = False
        current = None
    if present and (stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode)):
        raise FleetRefused("state dir must be a stable non-symlink directory")
    if not present:
        if not create:
            raise FleetRefused("state dir does not exist")
        parent = raw.parent
        try:
            parent_info = parent.lstat()
        except OSError as exc:
            raise FleetRefused("state dir parent is not readable") from exc
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise FleetRefused("state dir parent must be a real directory")
        try:
            raw.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as exc:
            raise FleetRefused("state dir could not be created safely") from exc
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(raw, flags)
        opened = os.fstat(descriptor)
        linked = raw.lstat()
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(linked.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise FleetRefused("state dir must be a stable non-symlink directory")
        if opened.st_uid != os.geteuid():
            raise FleetRefused("state dir must be owner-only")
        os.fchmod(descriptor, 0o700)
        hardened = os.fstat(descriptor)
        if (
            hardened.st_uid != os.geteuid()
            or stat.S_IMODE(hardened.st_mode) != 0o700
        ):
            raise FleetRefused("state dir must remain an owner-only mode-0700 directory")
        canonical = Path(os.path.realpath(raw))
        try:
            canonical_link = canonical.lstat()
        except OSError as exc:
            raise FleetRefused("state dir canonical path is not readable") from exc
        if (
            stat.S_ISLNK(canonical_link.st_mode)
            or not stat.S_ISDIR(canonical_link.st_mode)
            or (canonical_link.st_dev, canonical_link.st_ino)
            != (opened.st_dev, opened.st_ino)
        ):
            raise FleetRefused("state dir canonical path does not match the opened directory")
        canonical_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        canonical_fd = os.open(canonical, canonical_flags)
        try:
            canonical_opened = os.fstat(canonical_fd)
            if _directory_identity(canonical_opened) != _directory_identity(hardened):
                raise FleetRefused("state dir swapped during descriptor authentication")
        finally:
            os.close(canonical_fd)
        return canonical
    except FleetRefused:
        raise
    except OSError as exc:
        raise FleetRefused("state dir could not be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def require_state_file(state: Path, path: Path, *, label: str) -> Path:
    authenticated = prepare_state_dir(state, create=False)
    candidate = path.expanduser()
    if not candidate.is_absolute() or os.path.normpath(str(candidate)) != str(candidate):
        raise FleetRefused(f"{label} must be an absolute canonical path")
    if candidate.parent != authenticated:
        raise FleetRefused(f"{label} must live in the authenticated state directory")
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise FleetRefused(f"{label} is missing") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise FleetRefused(f"{label} must be a regular non-symlink file")
    return candidate


def write_json_document(
    path: Path, payload: Mapping[str, Any], *, immutable: bool
) -> str:
    data = canonical_bytes(payload)
    digest = sha256_bytes(data)
    parent = path.parent
    names = {
        "target": path.name,
        "temp": path.name + ".tmp",
        "sidecar": path.name + ".sha256",
        "side_tmp": path.name + ".sha256.tmp",
    }
    mode = 0o400 if immutable else 0o600

    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_before = parent.lstat()
        directory_fd = os.open(parent, directory_flags)
        parent_opened = os.fstat(directory_fd)
    except OSError as exc:
        raise FleetRefused("output parent could not be opened safely") from exc
    if (
        stat.S_ISLNK(parent_before.st_mode)
        or not stat.S_ISDIR(parent_opened.st_mode)
        or (parent_before.st_dev, parent_before.st_ino)
        != (parent_opened.st_dev, parent_opened.st_ino)
        or stat.S_IMODE(parent_opened.st_mode) != 0o700
    ):
        os.close(directory_fd)
        raise FleetRefused("output parent must remain a private non-symlink directory")

    def create_exclusive(name: str, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, mode, dir_fd=directory_fd)
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise FleetRefused(
                f"refusing unsafe or existing output {name}"
            ) from exc

    try:
        for name in names.values():
            try:
                os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FleetRefused(f"refusing existing output {name}")
        create_exclusive(names["temp"], data)
        create_exclusive(
            names["side_tmp"], f"{digest}  {path.name}\n".encode("ascii")
        )
        os.link(
            names["temp"],
            names["target"],
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        try:
            os.link(
                names["side_tmp"],
                names["sidecar"],
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError:
            os.unlink(names["target"], dir_fd=directory_fd)
            raise
        os.fsync(directory_fd)
        parent_after = parent.lstat()
        if (
            (parent_after.st_dev, parent_after.st_ino)
            != (parent_opened.st_dev, parent_opened.st_ino)
            or stat.S_ISLNK(parent_after.st_mode)
            or stat.S_IMODE(os.fstat(directory_fd).st_mode) != 0o700
        ):
            for name in (names["target"], names["sidecar"]):
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
            raise FleetRefused("output parent changed during document creation")
    except OSError as exc:
        raise FleetRefused("refusing output replacement race") from exc
    finally:
        for name in (names["temp"], names["side_tmp"]):
            try:
                os.unlink(name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)
    return digest


def load_json_document(
    path: Path, *, require_immutable: bool
) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise FleetRefused(f"missing or unsafe document {path.name}")
    sidecar = path.with_name(path.name + ".sha256")
    if sidecar.is_symlink() or not sidecar.is_file():
        raise FleetRefused(f"missing integrity sidecar for {path.name}")
    data, document_stat = read_stable_file_with_stat(
        path.absolute(), label=path.name
    )
    digest = sha256_bytes(data)
    sidecar_data, sidecar_stat = read_stable_file_with_stat(
        sidecar.absolute(), label=sidecar.name
    )
    recorded = sidecar_data.decode("ascii").split()
    if recorded != [digest, path.name]:
        raise FleetRefused(f"{path.name} failed integrity verification")
    if require_immutable and (
        stat.S_IMODE(document_stat.st_mode) & 0o222
        or stat.S_IMODE(sidecar_stat.st_mode) & 0o222
    ):
        raise FleetRefused(
            f"{path.name} or its sidecar is writable; immutable required"
        )
    if (
        stat.S_IMODE(document_stat.st_mode) & 0o077
        or stat.S_IMODE(sidecar_stat.st_mode) & 0o077
    ):
        raise FleetRefused(f"{path.name} is group/other accessible")
    payload = strict_json_bytes(path.name, data)
    if not isinstance(payload, dict):
        raise FleetRefused(f"{path.name} must be an object")
    return payload, digest


def build_verify_commands(spec: FleetSpec) -> list[dict[str, Any]]:
    result = [
        command(
            spec.gcloud_bin,
            [
                "compute",
                "instances",
                "describe",
                item.name,
                f"--project={spec.project}",
                f"--zone={item.zone}",
                "--format=json(name,status,zone,machineType,labels,tags.items)",
            ],
        )
        for item in spec.instances
    ]
    result.append(
        command(
            spec.gcloud_bin,
            [
                "compute",
                "instances",
                "list",
                f"--project={spec.project}",
                "--filter="
                + " OR ".join(f"name={item.name}" for item in spec.instances),
                "--format=json(name,status,zone,machineType)",
            ],
        )
    )
    return result


def build_reset_commands(spec: FleetSpec) -> list[dict[str, Any]]:
    r, result = resource_names(spec), []
    for item in spec.instances:
        result.append(
            command(
                spec.gcloud_bin,
                [
                    "compute",
                    "instances",
                    "update",
                    item.name,
                    f"--project={spec.project}",
                    f"--zone={item.zone}",
                    "--no-deletion-protection",
                    "--quiet",
                ],
            )
        )
        result.append(
            command(
                spec.gcloud_bin,
                [
                    "compute",
                    "instances",
                    "delete",
                    item.name,
                    f"--project={spec.project}",
                    f"--zone={item.zone}",
                    "--quiet",
                ],
            )
        )
    for name in r["firewalls"].values():
        result.append(
            command(
                spec.gcloud_bin,
                [
                    "compute",
                    "firewall-rules",
                    "delete",
                    name,
                    f"--project={spec.project}",
                    "--quiet",
                ],
            )
        )
    for subnet in r["subnets"]:
        result.append(
            command(
                spec.gcloud_bin,
                [
                    "compute",
                    "networks",
                    "subnets",
                    "delete",
                    subnet["name"],
                    f"--project={spec.project}",
                    f"--region={subnet['region']}",
                    "--quiet",
                ],
            )
        )
    result.append(
        command(
            spec.gcloud_bin,
            [
                "compute",
                "networks",
                "delete",
                r["network"],
                f"--project={spec.project}",
                "--quiet",
            ],
        )
    )
    return result


def required_evidence_schema() -> dict[str, Any]:
    return {
        "collector": EVIDENCE_PRODUCER_NAME,
        "bindings": [
            "collector/verifier/probe-driver path/hash/bytes",
            "immutable apply path/hash/bytes",
            "fleet/plan/run/session/correlation",
            "UTC command window and record hash chain",
            "verified client release index/build receipt/artifact/shared revision",
            "immutable client release binding digest and verifier closure",
            "deployment-execution receipt/candidate/manifest/record-chain",
            "remote installation marker and descriptor-authenticated runtimes",
        ],
        "topology": list(ROLES),
        "negative_controls": [
            "AWG blocked -> Xray",
            "Winn v3 blocked -> distinct cover AWG",
            "cover withdrawn -> same_node_downgrade_refused with zero same-node attempts",
        ],
    }


# Keep the old public helper name as a fail-closed migration guard. It cannot
# produce evidence; only gcp_proof_evidence.collect can do that.
def build_evidence_bundle(*args: Any, **kwargs: Any) -> dict[str, Any]:
    del args, kwargs
    raise FleetRefused("legacy hand-authored transcript evidence is disabled")


def validate_build_identity(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"linux:[A-Za-z0-9._+\-]{1,96}:[a-f0-9]{64}", value)
    ):
        raise FleetRefused("client build identity is invalid")
    return value


def collector_closure_ref() -> dict[str, Any]:
    return {
        "collector": file_ref(
            EVIDENCE_PRODUCER_PATH.absolute(), label="reviewed collector"
        ),
        "verifier": file_ref(VERIFIER_PATH.absolute(), label="reviewed verifier"),
    }


def _apply_payload_is_exact(
    raw: Mapping[str, Any],
    spec: FleetSpec,
    plan_digest: str,
    plan: Mapping[str, Any],
) -> bool:
    expected_keys = {
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
        "plan_sha256",
    }
    try:
        _, manifest, client_reference = plan_bound_inputs(raw)
    except FleetRefused:
        return False
    return (
        set(raw) == expected_keys
        and raw.get("kind") == KIND_APPLY
        and raw.get("schema_version") == SCHEMA_VERSION
        and raw.get("phase") == "apply"
        and raw.get("dry_run") is False
        and raw.get("fleet") == spec_document(spec)
        and raw.get("commands") == build_plan_commands(spec)
        and raw.get("installers") == build_installer_sequence(spec, manifest)
        and raw.get("deployment_inputs") == plan.get("deployment_inputs")
        and raw.get("client_release_binding") == client_reference
        and raw.get("client_release_binding")
        == plan.get("client_release_binding")
        and raw.get("plan_sha256") == plan_digest
    )


def load_immutable_apply(
    path: Path,
    spec: FleetSpec,
    plan_digest: str,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    raw, digest = load_json_document(path, require_immutable=True)
    if not _apply_payload_is_exact(raw, spec, plan_digest, plan):
        raise FleetRefused("immutable apply state does not match the exact plan")
    parse_utc("apply creation UTC", raw.get("created_utc"))
    return raw, digest


def collector_record_bindings(
    *,
    spec: FleetSpec,
    plan_digest: str,
    apply_digest: str,
    client_release_binding: Mapping[str, Any],
    probe_driver: Mapping[str, Any],
    run_id: str,
    session_id: str,
    correlation_id: str,
    deployment_execution: Mapping[str, Any],
    deployment_candidate_id: str,
    deployment_manifest_sha256: str,
    deployment_record_chain_sha256: str,
) -> dict[str, Any]:
    client_reference = validate_client_release_binding_reference(
        client_release_binding
    )
    binding = client_reference["binding"]
    execution_ref = dict(deployment_execution)
    _validate_client_file_ref(execution_ref, "deployment execution receipt")
    return {
        "fleet_id": fleet_id_for(spec),
        "plan_sha256": plan_digest,
        "apply_sha256": apply_digest,
        "run_id": validate_id("run id", run_id),
        "session_id": validate_id("session id", session_id),
        "correlation_id": validate_id("correlation id", correlation_id),
        "client_release_binding": client_reference,
        "client_artifact": copy.deepcopy(binding["artifact"]),
        "client_build_identity": validate_build_identity(binding["build_identity"]),
        "probe_driver": dict(probe_driver),
        "deployment_execution": execution_ref,
        "deployment_candidate_id": require_sha256(
            "deployment candidate id", deployment_candidate_id
        ),
        "deployment_manifest_sha256": require_sha256(
            "deployment manifest digest", deployment_manifest_sha256
        ),
        "deployment_record_chain_sha256": require_sha256(
            "deployment record chain", deployment_record_chain_sha256
        ),
    }


def collector_command_specs(
    probe_driver: Path, spec: FleetSpec, bindings: Mapping[str, Any]
) -> list[dict[str, Any]]:
    resources = resource_names(spec)
    subnets_by_role = {item["role"]: item["name"] for item in resources["subnets"]}
    common = [
        "--fleet-id",
        str(bindings["fleet_id"]),
        "--run-id",
        str(bindings["run_id"]),
        "--session-id",
        str(bindings["session_id"]),
        "--correlation-id",
        str(bindings["correlation_id"]),
        "--client-repo-root",
        str(bindings["client_release_binding"]["repo_root"]),
        "--client-release-input-index",
        str(
            bindings["client_release_binding"]["binding"]["release_input_index"][
                "path"
            ]
        ),
        "--client-release-input-index-sha256",
        str(
            bindings["client_release_binding"]["binding"]["release_input_index"][
                "sha256"
            ]
        ),
        "--client-build-receipt",
        str(
            bindings["client_release_binding"]["binding"]["build_receipt"][
                "path"
            ]
        ),
        "--client-build-receipt-sha256",
        str(
            bindings["client_release_binding"]["binding"]["build_receipt"][
                "sha256"
            ]
        ),
        "--client-artifact",
        str(bindings["client_artifact"]["path"]),
        "--client-sha256",
        str(bindings["client_artifact"]["sha256"]),
        "--client-bytes",
        str(bindings["client_artifact"]["bytes"]),
        "--client-build-identity",
        str(bindings["client_build_identity"]),
        "--client-release",
        str(bindings["client_release_binding"]["binding"]["release"]),
        "--client-shared-revision",
        str(bindings["client_release_binding"]["binding"]["shared_revision"]),
        "--client-artifact-input-fingerprint-sha256",
        str(
            bindings["client_release_binding"]["binding"][
                "artifact_input_fingerprint_sha256"
            ]
        ),
        "--client-binding-sha256",
        str(bindings["client_release_binding"]["binding_sha256"]),
        "--client-binding-reference-sha256",
        sha256_bytes(
            canonical_bytes(bindings["client_release_binding"])
        ),
        "--deployment-execution",
        str(bindings["deployment_execution"]["path"]),
        "--deployment-execution-sha256",
        str(bindings["deployment_execution"]["sha256"]),
        "--deployment-candidate-id",
        str(bindings["deployment_candidate_id"]),
        "--deployment-manifest-sha256",
        str(bindings["deployment_manifest_sha256"]),
        "--deployment-record-chain-sha256",
        str(bindings["deployment_record_chain_sha256"]),
        "--project",
        spec.project,
        "--gcloud-bin",
        spec.gcloud_bin,
        "--image-family",
        spec.image_family,
        "--image-project",
        spec.image_project,
        "--network",
        resources["network"],
        "--fleet-tag",
        resources["tags"]["fleet"],
        "--control-instance",
        spec.by_role["control"].name,
        "--control-zone",
        spec.by_role["control"].zone,
        "--control-machine-type",
        spec.by_role["control"].machine_type,
        "--control-subnet",
        subnets_by_role["control"],
        "--winn3-data-instance",
        spec.by_role["data-winn3"].name,
        "--winn3-data-zone",
        spec.by_role["data-winn3"].zone,
        "--winn3-data-machine-type",
        spec.by_role["data-winn3"].machine_type,
        "--winn3-data-subnet",
        subnets_by_role["data-winn3"],
        "--cover-data-instance",
        spec.by_role["data-cover"].name,
        "--cover-data-zone",
        spec.by_role["data-cover"].zone,
        "--cover-data-machine-type",
        spec.by_role["data-cover"].machine_type,
        "--cover-data-subnet",
        subnets_by_role["data-cover"],
    ]
    result: list[dict[str, Any]] = []
    for index, action in enumerate(COLLECTOR_ACTIONS):
        argv = [str(probe_driver.absolute()), "--action", action, *common]
        identity = sha256_bytes(
            canonical_bytes(
                {
                    "index": index,
                    "action": action,
                    "argv": argv,
                    "bindings": dict(bindings),
                }
            )
        )
        result.append(
            {"index": index, "action": action, "argv": argv, "identity": identity}
        )
    return result


def _assert_no_pass_tokens(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_OBSERVATION_KEYS:
                raise FleetRefused(
                    "collector observation contains a caller-style pass token"
                )
            _assert_no_pass_tokens(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_pass_tokens(item)


def observation_envelope(
    action: str, bindings: Mapping[str, Any], data: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "kind": KIND_OBSERVATION,
        "action": action,
        "fleet_id": bindings["fleet_id"],
        "run_id": bindings["run_id"],
        "session_id": bindings["session_id"],
        "correlation_id": bindings["correlation_id"],
        "client_sha256": bindings["client_artifact"]["sha256"],
        "client_bytes": bindings["client_artifact"]["bytes"],
        "client_build_identity": bindings["client_build_identity"],
        "client_release_binding": copy.deepcopy(
            bindings["client_release_binding"]
        ),
        "data": dict(data),
    }


def command_record_digest(record: Mapping[str, Any]) -> str:
    core = dict(record)
    core.pop("record_sha256", None)
    return sha256_bytes(canonical_bytes(core))


def record_chain_digest(records: Sequence[Mapping[str, Any]]) -> str:
    return sha256_bytes(
        canonical_bytes(
            {"record_sha256": [item.get("record_sha256") for item in records]}
        )
    )


def _decode_capture(record: Mapping[str, Any], stream: str) -> bytes:
    raw = record.get(stream)
    if not isinstance(raw, dict):
        raise FleetRefused(f"collector {stream} capture is malformed")
    assert_exact_keys(
        f"collector {stream} capture", raw, {"encoding", "data", "bytes", "sha256"}
    )
    if raw["encoding"] != "base64" or not isinstance(raw["data"], str):
        raise FleetRefused(f"collector {stream} capture encoding is invalid")
    try:
        decoded = base64.b64decode(raw["data"].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise FleetRefused(
            f"collector {stream} capture is not canonical base64"
        ) from exc
    if len(decoded) > MAX_CAPTURE_BYTES:
        raise FleetRefused(f"collector {stream} capture exceeds the size limit")
    if raw["data"] != base64.b64encode(decoded).decode("ascii"):
        raise FleetRefused(f"collector {stream} capture is not canonical base64")
    if raw["bytes"] != len(decoded) or raw["sha256"] != sha256_bytes(decoded):
        raise FleetRefused(f"collector {stream} capture hash/bytes mismatch")
    if SECRET_RE.search(decoded.decode("utf-8", errors="ignore")):
        raise FleetRefused(f"collector {stream} capture appears to contain secrets")
    return decoded


def _expect_exact_data(action: str, actual: Any, expected: Any) -> None:
    exact_equal(
        f"collector observation {action}",
        actual,
        expected,
    )


def _expect_attempts(action: str, data: Any, expected: list[dict[str, str]]) -> None:
    if not isinstance(data, dict):
        raise FleetRefused(f"collector observation {action} data is malformed")
    assert_exact_keys(
        f"collector observation {action}",
        data,
        {"control_id", "attempts", "attempt_events"},
    )
    if data["attempts"] != expected:
        raise FleetRefused(
            f"collector observation {action} attempt order/state mismatch"
        )


def _expect_authorized_winn_v1_fallback(
    spec: FleetSpec,
    by_action: Mapping[str, Any],
) -> None:
    winn3 = spec.by_role["data-winn3"].name
    cover = spec.by_role["data-cover"].name
    if winn3 == cover:
        raise FleetRefused(
            "authorized Winn Protocol v1 fallback requires a distinct cover node"
        )
    primary = by_action["connect-primary"]
    if not isinstance(primary, dict) or primary.get("attempts") != [
        {"protocol": "winn3", "node": winn3, "result": "connected"}
    ]:
        raise FleetRefused("Winn Protocol v3 is not the exclusive primary")
    awg = by_action["connect-cover-awg"]
    xray = by_action["connect-cover-xray"]
    if not isinstance(awg, dict) or (
        awg.get("protocol"), awg.get("node"), awg.get("result")
    ) != ("awg", cover, "connected"):
        raise FleetRefused(
            "authorized Winn Protocol v1 AWG fallback is not bound to the cover node"
        )
    if not isinstance(xray, dict) or (
        xray.get("protocol"), xray.get("node"), xray.get("result")
    ) != ("xray", cover, "connected"):
        raise FleetRefused(
            "authorized Winn Protocol v1 Xray fallback is not bound to the cover node"
        )
    awg_block = by_action["probe-awg-block"]
    if not isinstance(awg_block, dict) or awg_block.get("attempts") != [
        {"protocol": "awg", "node": cover, "result": "blocked"},
        {"protocol": "xray", "node": cover, "result": "connected"},
    ]:
        raise FleetRefused(
            "authorized Winn Protocol v1 fallback is not AWG-first then Xray"
        )
    winn3_block = by_action["probe-winn3-block"]
    if not isinstance(winn3_block, dict) or winn3_block.get("attempts") != [
        {"protocol": "winn3", "node": winn3, "result": "blocked"},
        {"protocol": "awg", "node": cover, "result": "connected"},
    ]:
        raise FleetRefused(
            "authorized Winn Protocol v1 cover fallback is not Winn v3 then cover AWG"
        )
    withdrawn = by_action["probe-cover-withdrawn"]
    if (
        not isinstance(withdrawn, dict)
        or withdrawn.get("refusal_code") != "same_node_downgrade_refused"
        or withdrawn.get("same_node_downgrade_attempts") != 0
    ):
        raise FleetRefused(
            "authorized Winn Protocol v1 fallback does not prove same-node downgrade refusal"
        )


def _expect_attempt_events(
    action: str,
    events: Any,
    expected: tuple[tuple[str, str, str, str], ...],
    *,
    bindings: Mapping[str, str],
    window: tuple[datetime, datetime],
) -> None:
    if not isinstance(events, list) or len(events) != len(expected):
        raise FleetRefused(f"{action} attempt events are malformed")
    last_event_utc = window[0]
    last_monotonic = -1
    for index, (event, expected_state) in enumerate(zip(events, expected)):
        if not isinstance(event, dict):
            raise FleetRefused(f"{action} attempt event {index} is malformed")
        assert_exact_keys(
            f"{action} attempt event {index}",
            event,
            {
                "action",
                "correlation_id",
                "monotonic_ns",
                "node",
                "phase",
                "protocol",
                "result",
                "session_id",
                "utc",
            },
        )
        event_utc = parse_utc(f"{action} attempt event {index} UTC", event["utc"])
        if (
            (event["protocol"], event["node"], event["phase"], event["result"])
            != expected_state
            or event["action"] != action
            or event["correlation_id"] != bindings["correlation_id"]
            or event["session_id"] != bindings["session_id"]
            or type(event["monotonic_ns"]) is not int
            or event["monotonic_ns"] <= last_monotonic
            or not last_event_utc < event_utc < window[1]
        ):
            raise FleetRefused(f"{action} attempt event order/state mismatch")
        last_monotonic = event["monotonic_ns"]
        last_event_utc = event_utc


def expected_inventory_data(spec: FleetSpec) -> dict[str, Any]:
    resources = resource_names(spec)
    subnets_by_role = {item["role"]: item for item in resources["subnets"]}
    labels_common = {
        "winsvpn-proof-fleet": "1",
        "winsvpn-proof-id": resources["fleet_id"],
    }
    instances = []
    for item in spec.instances:
        subnet = subnets_by_role[item.role]
        instances.append(
            {
                "role": item.role,
                "name": item.name,
                "zone": item.zone,
                "machine_type": item.machine_type,
                "power_state": "RUNNING",
                "network": resources["network"],
                "subnet": subnet["name"],
                "image_project": spec.image_project,
                "image_family": spec.image_family,
                "image_name": None,
                "image_id": None,
                "os_login": True,
                "attached_identity_count": 0,
                "oauth_scopes": [],
                "shielded": {
                    "secure_boot": True,
                    "vtpm": True,
                    "integrity_monitoring": True,
                },
                "deletion_protection": True,
                "can_ip_forward": item.role in ("data-winn3", "data-cover"),
                "labels": {**labels_common, "winsvpn-proof-role": item.role},
                "tags": sorted(
                    [resources["tags"]["fleet"], resources["tags"][item.role]]
                ),
            }
        )
    return {
        "network": {
            "name": resources["network"],
            "auto_create_subnetworks": False,
            "routing_mode": "REGIONAL",
        },
        "subnets": [
            {
                "name": item["name"],
                "region": item["region"],
                "cidr": item["cidr"],
                "network": resources["network"],
            }
            for item in resources["subnets"]
        ],
        "instances": instances,
    }


def validate_deployment_observation(
    spec: FleetSpec,
    raw: Any,
    *,
    execution: Mapping[str, Any],
    bindings: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise FleetRefused("collector deployment observation is malformed")
    assert_exact_keys("deployment observation", raw, {"roles"})
    rows = raw["roles"]
    if not isinstance(rows, list) or len(rows) != len(spec.instances):
        raise FleetRefused("deployment observation roles are missing or extra")
    candidate_id = bindings["deployment_candidate_id"]
    manifest_digest = bindings["deployment_manifest_sha256"]
    record_chain = bindings["deployment_record_chain_sha256"]
    markers = execution["markers"]
    manifest = execution.get("deployment_manifest")
    if not isinstance(manifest, dict):
        raise FleetRefused("deployment execution receipt omitted the reviewed manifest")
    seen_roles: set[str] = set()
    verified_rows: list[dict[str, Any]] = []
    for item, expected_instance in zip(rows, spec.instances):
        if not isinstance(item, dict):
            raise FleetRefused("deployment role observation is malformed")
        assert_exact_keys(
            "deployment role observation", item, DEPLOYMENT_ROLE_OBSERVATION_KEYS
        )
        role = require_str("deployment role", item["role"])
        if role != expected_instance.role or role in seen_roles:
            raise FleetRefused("deployment role observation is mixed or duplicated")
        seen_roles.add(role)
        exact_equal("deployment instance", item["instance"], expected_instance.name)
        exact_equal("deployment os_id", item["os_id"], "ubuntu")
        exact_equal("deployment os_version", item["os_version"], "24.04")
        exact_equal(
            "deployment role_file",
            item["role_file"],
            role,
        )
        exact_equal(
            "deployment services", item["services"], ROLE_DEPLOY_SERVICES[role]
        )
        marker = validate_deployment_marker(
            item["marker"],
            spec=spec,
            role=role,
            plan_digest=str(bindings["plan_sha256"]),
            apply_digest=str(bindings["apply_sha256"]),
            candidate_id=candidate_id,
            manifest_digest=manifest_digest,
            record_chain=record_chain,
            require_final=True,
        )
        exact_equal(f"{role} live marker", marker, markers[role])
        runtime = validate_runtime_identities(role, item["runtime"])
        exact_equal(f"{role} live runtime", runtime, marker["runtime"])
        units = item["units"]
        expected_units = ROLE_DEPLOY_UNITS[role]
        if not isinstance(units, dict) or set(units) != set(expected_units):
            raise FleetRefused(f"{role} service units are extra or missing")
        for name, path in expected_units.items():
            unit = validate_authenticated_file(
                f"{role} unit {name}",
                units[name],
                path=path,
                architecture=TEXT_ARCHITECTURE,
                extra_keys={"active_state"},
            )
            exact_equal(
                f"{role} unit {name}",
                unit,
                expected_unit_identity(manifest, role, name, path),
            )
        configs = item["configs"]
        expected_configs = ROLE_DEPLOY_CONFIGS[role]
        if not isinstance(configs, dict) or set(configs) != set(expected_configs):
            raise FleetRefused(f"{role} configs are extra or missing")
        for path in expected_configs:
            config = validate_authenticated_file(
                f"{role} config {path}",
                configs[path],
                path=path,
                architecture=TEXT_ARCHITECTURE,
            )
            exact_equal(
                f"{role} config {path}",
                config,
                expected_config_identity(role, path),
            )
        validate_candidate_observation(
            role,
            item["candidate"],
            candidate_id=candidate_id,
            manifest=manifest,
        )
        verified_rows.append(copy.deepcopy(item))
    if set(seen_roles) != set(ROLES):
        raise FleetRefused("deployment observation omitted a proof role")
    return {"roles": verified_rows}


def verify_observations(
    spec: FleetSpec,
    observations: Sequence[Mapping[str, Any]],
    window: tuple[datetime, datetime],
    action_windows: Mapping[str, tuple[datetime, datetime]],
    *,
    execution: Mapping[str, Any],
    bindings: Mapping[str, Any],
) -> list[dict[str, Any]]:
    by_action = {item["action"]: item["data"] for item in observations}
    winn3 = spec.by_role["data-winn3"].name
    cover = spec.by_role["data-cover"].name
    inventory = by_action["inventory"]
    expected_inventory = expected_inventory_data(spec)
    if not isinstance(inventory, dict):
        raise FleetRefused("collector inventory observation is malformed")
    expected_names = {item["name"] for item in expected_inventory["instances"]}
    observed_instances = inventory.get("instances")
    if not isinstance(observed_instances, list) or {
        item.get("name") for item in observed_instances if isinstance(item, dict)
    } != expected_names:
        raise FleetRefused("collector inventory instance scope mismatch")
    normalized_instances = []
    for observed in observed_instances:
        if not isinstance(observed, dict):
            raise FleetRefused("collector inventory instance is malformed")
        image_name = observed.get("image_name")
        image_id = observed.get("image_id")
        if (
            not isinstance(image_name, str)
            or not re.fullmatch(r"ubuntu-(minimal-)?2404-[a-z0-9-]+", image_name)
            or not isinstance(image_id, str)
            or not re.fullmatch(r"[0-9]{6,32}", image_id)
        ):
            raise FleetRefused("collector inventory boot image identity is invalid")
        normalized = dict(observed)
        normalized["image_name"] = None
        normalized["image_id"] = None
        normalized_instances.append(normalized)
    normalized_inventory = dict(inventory)
    normalized_inventory["instances"] = normalized_instances
    _expect_exact_data("inventory", normalized_inventory, expected_inventory)
    preflight = execution.get("preflight")
    if not isinstance(preflight, dict):
        raise FleetRefused("deployment execution preflight is missing")
    instances = preflight.get("instances")
    if not isinstance(instances, dict):
        raise FleetRefused("deployment-to-evidence transaction continuity is missing")
    for observed in expected_inventory["instances"]:
        identity = instances.get(observed["role"])
        if not isinstance(identity, dict):
            raise FleetRefused("deployment-to-evidence transaction continuity is missing")
        exact_equal(
            f"{observed['role']} inventory name",
            observed["name"],
            identity["name"],
        )
        exact_equal(
            f"{observed['role']} inventory zone",
            observed["zone"],
            identity["zone"],
        )
        exact_equal(
            f"{observed['role']} inventory machine",
            observed["machine_type"],
            identity["machine_type"],
        )
        exact_equal(
            f"{observed['role']} inventory project",
            spec.project,
            identity["project"],
        )
        transaction = identity.get("creation_transaction")
        if not isinstance(transaction, dict):
            raise FleetRefused(
                f"{observed['role']} inventory is not bound to a creation transaction"
            )
        parse_creation_timestamp(
            f"{observed['role']} inventory creation timestamp",
            transaction.get("creation_timestamp"),
        )
    validate_deployment_observation(
        spec,
        by_action["deployment"],
        execution=execution,
        bindings=bindings,
    )
    route = by_action["route-decision"]
    if not isinstance(route, dict):
        raise FleetRefused("collector route-decision observation is malformed")
    assert_exact_keys(
        "route-decision observation",
        route,
        {
            "served_carrier",
            "descriptor_node",
            "selected_node",
            "descriptor_sha256",
            "signature_state",
            "canary_state",
        },
    )
    if (
        route
        != {
            "served_carrier": "winn3",
            "descriptor_node": winn3,
            "selected_node": winn3,
            "descriptor_sha256": route.get("descriptor_sha256"),
            "signature_state": "verified",
            "canary_state": "reachable",
        }
        or not isinstance(route["descriptor_sha256"], str)
        or not SHA256_RE.fullmatch(route["descriptor_sha256"])
    ):
        raise FleetRefused(
            "collector route-decision does not prove signed Winn v3 node binding"
        )
    primary = by_action["connect-primary"]
    if not isinstance(primary, dict):
        raise FleetRefused("collector primary observation is malformed")
    assert_exact_keys(
        "connect-primary observation",
        primary,
        {"attempts", "bytes_rx", "bytes_tx", "interface", "status_delta"},
    )
    status_delta = primary["status_delta"]
    if not isinstance(status_delta, dict):
        raise FleetRefused("collector primary Winn v3 status delta is malformed")
    assert_exact_keys(
        "connect-primary status delta",
        status_delta,
        {"inner_packets_delivered", "rx_device_writes"},
    )
    if (
        primary["attempts"]
        != [{"protocol": "winn3", "node": winn3, "result": "connected"}]
        or type(primary["bytes_rx"]) is not int
        or type(primary["bytes_tx"]) is not int
        or primary["interface"] != "winn3gw0"
        or type(status_delta["inner_packets_delivered"]) is not int
        or type(status_delta["rx_device_writes"]) is not int
        or primary["bytes_rx"] <= 0
        or primary["bytes_tx"] <= 0
        or status_delta["inner_packets_delivered"] <= 0
        or status_delta["rx_device_writes"] <= 0
        or status_delta["inner_packets_delivered"]
        > status_delta["rx_device_writes"]
        or primary["bytes_rx"] < status_delta["rx_device_writes"]
    ):
        raise FleetRefused(
            "collector primary observation does not prove Winn v3 carried traffic"
        )
    awg = by_action["connect-cover-awg"]
    if not isinstance(awg, dict):
        raise FleetRefused("collector AWG observation is malformed")
    assert_exact_keys(
        "connect-cover-awg observation",
        awg,
        {"protocol", "node", "result", "latest_handshake_utc"},
    )
    if (awg["protocol"], awg["node"], awg["result"]) != ("awg", cover, "connected"):
        raise FleetRefused(
            "collector AWG observation does not prove cover-node connection"
        )
    awg_handshake = parse_utc("AWG latest handshake UTC", awg["latest_handshake_utc"])
    awg_window = action_windows["connect-cover-awg"]
    if not awg_window[0] <= awg_handshake <= awg_window[1]:
        raise FleetRefused("collector AWG handshake is outside the command window")
    _expect_exact_data(
        "connect-cover-xray",
        by_action["connect-cover-xray"],
        {"protocol": "xray", "node": cover, "result": "connected"},
    )
    _expect_exact_data(
        "inject-awg-block",
        by_action["inject-awg-block"],
        {"control_id": "negative-awg-block", "protocol": "awg", "state": "blocked"},
    )
    awg_block = by_action["probe-awg-block"]
    if not isinstance(awg_block, dict):
        raise FleetRefused("collector AWG negative-control observation is malformed")
    assert_exact_keys(
        "probe-awg-block observation",
        awg_block,
        {
            "control_id",
            "attempts",
            "attempt_events",
            "awg_interface",
            "xray_bytes_rx",
            "xray_bytes_tx",
        },
    )
    expected_attempts = [
        {"protocol": "awg", "node": cover, "result": "blocked"},
        {"protocol": "xray", "node": cover, "result": "connected"},
    ]
    if (
        awg_block["control_id"] != "negative-awg-block"
        or awg_block["attempts"] != expected_attempts
        or awg_block["awg_interface"] != "awg0"
        or type(awg_block["xray_bytes_rx"]) is not int
        or type(awg_block["xray_bytes_tx"]) is not int
        or awg_block["xray_bytes_rx"] <= 0
        or awg_block["xray_bytes_tx"] <= 0
    ):
        raise FleetRefused("AWG negative control did not prove Xray fallback traffic")
    _expect_attempt_events(
        "probe-awg-block",
        awg_block["attempt_events"],
        (
            ("awg", cover, "started", "pending"),
            ("awg", cover, "finished", "failed"),
            ("xray", cover, "started", "pending"),
            ("xray", cover, "finished", "connected"),
        ),
        bindings=bindings,
        window=action_windows["probe-awg-block"],
    )
    _expect_exact_data(
        "restore-awg",
        by_action["restore-awg"],
        {"control_id": "negative-awg-block", "protocol": "awg", "state": "restored"},
    )
    _expect_exact_data(
        "inject-winn3-block",
        by_action["inject-winn3-block"],
        {"control_id": "negative-winn3-block", "protocol": "winn3", "state": "blocked"},
    )
    _expect_attempts(
        "probe-winn3-block",
        by_action["probe-winn3-block"],
        [
            {"protocol": "winn3", "node": winn3, "result": "blocked"},
            {"protocol": "awg", "node": cover, "result": "connected"},
        ],
    )
    if by_action["probe-winn3-block"]["control_id"] != "negative-winn3-block":
        raise FleetRefused("Winn v3 negative-control identity mismatch")
    _expect_attempt_events(
        "probe-winn3-block",
        by_action["probe-winn3-block"]["attempt_events"],
        (
            ("winn3", winn3, "started", "pending"),
            ("winn3", winn3, "finished", "failed"),
            ("awg", cover, "started", "pending"),
            ("awg", cover, "finished", "connected"),
        ),
        bindings=bindings,
        window=action_windows["probe-winn3-block"],
    )
    _expect_exact_data(
        "withdraw-cover",
        by_action["withdraw-cover"],
        {"control_id": "negative-cover-withdrawn", "node": cover, "state": "withdrawn"},
    )
    withdrawn = by_action["probe-cover-withdrawn"]
    if not isinstance(withdrawn, dict):
        raise FleetRefused("collector cover-withdrawn observation is malformed")
    assert_exact_keys(
        "probe-cover-withdrawn observation",
        withdrawn,
        {
            "attempt_events",
            "attempts",
            "control_id",
            "refusal_code",
            "same_node_downgrade_attempts",
        },
    )
    if type(withdrawn["same_node_downgrade_attempts"]) is not int or {
        key: value for key, value in withdrawn.items() if key != "attempt_events"
    } != {
        "control_id": "negative-cover-withdrawn",
        "attempts": [{"protocol": "winn3", "node": winn3, "result": "blocked"}],
        "refusal_code": "same_node_downgrade_refused",
        "same_node_downgrade_attempts": 0,
    }:
        raise FleetRefused(
            "cover-withdrawn observation does not prove fail-closed downgrade refusal"
        )
    _expect_attempt_events(
        "probe-cover-withdrawn",
        withdrawn["attempt_events"],
        (
            ("winn3", winn3, "started", "pending"),
            ("winn3", winn3, "finished", "failed"),
        ),
        bindings=bindings,
        window=action_windows["probe-cover-withdrawn"],
    )
    _expect_exact_data(
        "restore-cover",
        by_action["restore-cover"],
        {"control_id": "negative-cover-withdrawn", "node": cover, "state": "restored"},
    )
    _expect_exact_data(
        "restore-winn3",
        by_action["restore-winn3"],
        {
            "control_id": "negative-winn3-block",
            "protocol": "winn3",
            "state": "restored",
        },
    )
    teardown = by_action["teardown-check"]
    _expect_exact_data(
        "teardown-check",
        teardown,
        {
            "expected_resources": resource_identity(spec),
            "observed_resources": resource_identity(spec),
            "unexpected_targets": [],
            "foreign_resource_ids": [],
            "credential_files_read": [],
            "production_resources_touched": [],
        },
    )
    _expect_authorized_winn_v1_fallback(spec, by_action)
    return [
        {"name": "collector-command-chain", "ok": True},
        {"name": "inventory", "ok": True},
        {"name": "deployment", "ok": True},
        {"name": "deployed-server-identity", "ok": True},
        {"name": "signed-winn3-route", "ok": True},
        {"name": "winn3-carried-traffic", "ok": True},
        {"name": "cover-awg", "ok": True},
        {"name": "cover-xray", "ok": True},
        {"name": "awg-block-to-xray", "ok": True},
        {"name": "winn3-block-to-cover-awg", "ok": True},
        {"name": "cover-withdrawn-fail-closed", "ok": True},
        {"name": "authorized-winn-v1-fallback", "ok": True},
        {"name": "restoration-and-scope", "ok": True},
    ]


def verify_evidence_payload(
    spec: FleetSpec,
    plan_digest: str,
    plan: Mapping[str, Any],
    raw: Any,
    *,
    expected_apply: Path,
    expected_probe_driver: Path,
    expected_run_id: str,
    expected_session_id: str,
    expected_correlation_id: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(raw, dict):
        raise FleetRefused("collector evidence bundle must be an object")
    assert_no_secrets(raw)
    assert_no_forbidden_keys(raw)
    assert_exact_keys(
        "collector evidence bundle",
        raw,
        {
            "kind",
            "schema_version",
            "generated_utc",
            "fleet_id",
            "plan",
            "apply",
            "run_id",
            "session_id",
            "correlation_id",
            "window",
            "collector_closure",
            "probe_driver",
            "client_release_binding",
            "client_artifact",
            "client_build_identity",
            "deployment_execution",
            "deployment_candidate_id",
            "deployment_manifest_sha256",
            "deployment_record_chain_sha256",
            "records",
            "record_chain_sha256",
        },
    )
    if raw["kind"] != KIND_EVIDENCE or raw["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise FleetRefused(
            "evidence was not produced under the command collector contract"
        )
    run_id = validate_id("run id", raw["run_id"])
    session_id = validate_id("session id", raw["session_id"])
    correlation_id = validate_id("correlation id", raw["correlation_id"])
    client_reference = verify_client_release_binding_reference(
        plan.get("client_release_binding")
    )
    binding = client_reference["binding"]
    build_identity = validate_build_identity(binding["build_identity"])
    if (run_id, session_id, correlation_id) != (
        expected_run_id,
        expected_session_id,
        expected_correlation_id,
    ):
        raise FleetRefused("collector run/session/correlation identity mismatch")
    if (
        raw["client_release_binding"] != client_reference
        or raw["client_build_identity"] != build_identity
    ):
        raise FleetRefused("collector client release binding identity mismatch")
    if raw["fleet_id"] != fleet_id_for(spec):
        raise FleetRefused("collector fleet identity mismatch")
    plan_ref = file_ref(
        state_paths(expected_apply.parent)["plan"].absolute(), label="collector plan"
    )
    if raw["plan"] != plan_ref or plan_ref["sha256"] != plan_digest:
        raise FleetRefused("collector plan path/hash/bytes mismatch")
    _, apply_digest = load_immutable_apply(
        expected_apply, spec, plan_digest, plan
    )
    apply_ref = file_ref(expected_apply.absolute(), label="collector apply")
    if raw["apply"] != apply_ref or apply_ref["sha256"] != apply_digest:
        raise FleetRefused("collector apply path/hash/bytes mismatch")
    state_dir = prepare_state_dir(expected_apply.parent, create=False)
    execution_path = state_paths(state_dir)["execution"]
    execution, execution_digest = load_deployment_execution(
        execution_path,
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        plan=plan,
        state_dir=state_dir,
        require_passed=True,
    )
    deploy_refs = deployment_binding(
        execution_path=execution_path,
        execution=execution,
        execution_digest=execution_digest,
    )
    if (
        raw["deployment_execution"] != deploy_refs["deployment_execution"]
        or raw["deployment_candidate_id"] != deploy_refs["deployment_candidate_id"]
        or raw["deployment_manifest_sha256"]
        != deploy_refs["deployment_manifest_sha256"]
        or raw["deployment_record_chain_sha256"]
        != deploy_refs["deployment_record_chain_sha256"]
    ):
        raise FleetRefused("collector deployment execution binding mismatch")
    client_ref = copy.deepcopy(binding["artifact"])
    driver_ref = executable_ref(
        expected_probe_driver.absolute(), label="reviewed probe driver"
    )
    if raw["client_artifact"] != client_ref:
        raise FleetRefused("tested client path/hash/bytes mismatch")
    if raw["probe_driver"] != driver_ref:
        raise FleetRefused("probe driver path/hash/bytes mismatch")
    if raw["collector_closure"] != collector_closure_ref():
        raise FleetRefused("collector/producer/verifier closure mismatch")
    window = raw["window"]
    if not isinstance(window, dict):
        raise FleetRefused("collector evidence window is malformed")
    assert_exact_keys("collector evidence window", window, {"started_utc", "ended_utc"})
    started = parse_utc("collector window start", window["started_utc"])
    ended = parse_utc("collector window end", window["ended_utc"])
    generated = parse_utc("collector generated UTC", raw["generated_utc"])
    now = datetime.now(timezone.utc)
    if (
        started >= ended
        or ended - started > MAX_PROOF_WINDOW
        or generated < ended
        or generated > now + MAX_CLOCK_SKEW
        or now - ended > MAX_EVIDENCE_AGE
    ):
        raise FleetRefused("collector evidence window is stale, future, or invalid")
    execution_started = parse_utc("deployment execution start", execution["started_utc"])
    execution_ended = parse_utc("deployment execution end", execution["ended_utc"])
    if started < execution_ended:
        raise FleetRefused("evidence started before deployment execution ended")
    if started - execution_ended > MAX_EVIDENCE_AGE:
        raise FleetRefused("stale deployment: evidence is outside the deployment-to-evidence freshness window")
    if execution_started > started:
        raise FleetRefused("deployment execution is not continuous with collector evidence")
    bindings = collector_record_bindings(
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        client_release_binding=client_reference,
        probe_driver=driver_ref,
        run_id=run_id,
        session_id=session_id,
        correlation_id=correlation_id,
        deployment_execution=deploy_refs["deployment_execution"],
        deployment_candidate_id=deploy_refs["deployment_candidate_id"],
        deployment_manifest_sha256=deploy_refs["deployment_manifest_sha256"],
        deployment_record_chain_sha256=deploy_refs["deployment_record_chain_sha256"],
    )
    expected_commands = collector_command_specs(expected_probe_driver, spec, bindings)
    records = raw["records"]
    if not isinstance(records, list) or len(records) != len(expected_commands):
        raise FleetRefused("collector command records are missing or duplicated")
    previous = "0" * 64
    observations: list[Mapping[str, Any]] = []
    action_windows: dict[str, tuple[datetime, datetime]] = {}
    last_end: datetime | None = None
    for expected, record in zip(expected_commands, records):
        if not isinstance(record, dict):
            raise FleetRefused("collector command record is malformed")
        assert_exact_keys(
            "collector command record",
            record,
            {
                "kind",
                "index",
                "action",
                "identity",
                "argv",
                "started_utc",
                "ended_utc",
                "exit_code",
                "stdout",
                "stderr",
                "bindings",
                "previous_sha256",
                "record_sha256",
            },
        )
        if record["kind"] != KIND_COMMAND or any(
            record[key] != expected[key]
            for key in ("index", "action", "identity", "argv")
        ):
            raise FleetRefused("collector commands are forged, missing, or reordered")
        if record["bindings"] != bindings or record["previous_sha256"] != previous:
            raise FleetRefused("collector command binding/hash chain mismatch")
        if record["record_sha256"] != command_record_digest(record):
            raise FleetRefused("collector command record was edited")
        started_at = parse_utc("collector command start", record["started_utc"])
        ended_at = parse_utc("collector command end", record["ended_utc"])
        if (
            started_at > ended_at
            or started_at < started
            or ended_at > ended
            or (last_end is not None and started_at < last_end)
        ):
            raise FleetRefused("collector command timestamps are invalid or reordered")
        last_end = ended_at
        if type(record["exit_code"]) is not int or record["exit_code"] != 0:
            raise FleetRefused("collector command exited unsuccessfully")
        stdout = _decode_capture(record, "stdout")
        _decode_capture(record, "stderr")
        observation = strict_json_bytes(f"collector {record['action']} stdout", stdout)
        if not isinstance(observation, dict):
            raise FleetRefused("collector command stdout must be one JSON object")
        assert_exact_keys(
            "collector observation envelope",
            observation,
            {
                "kind",
                "action",
                "fleet_id",
                "run_id",
                "session_id",
                "correlation_id",
                "client_sha256",
                "client_bytes",
                "client_build_identity",
                "client_release_binding",
                "data",
            },
        )
        expected_envelope = observation_envelope(
            record["action"],
            bindings,
            observation["data"] if isinstance(observation.get("data"), dict) else {},
        )
        if observation != expected_envelope:
            raise FleetRefused("collector observation identity binding mismatch")
        _assert_no_pass_tokens(observation["data"])
        observations.append(observation)
        action_windows[str(record["action"])] = (started_at, ended_at)
        previous = record["record_sha256"]
    if raw["record_chain_sha256"] != record_chain_digest(records):
        raise FleetRefused("collector command chain digest mismatch")
    checks = verify_observations(
        spec,
        observations,
        (started, ended),
        action_windows,
        execution=execution,
        bindings=bindings,
    )
    receipt_bindings = {
        "fleet_id": raw["fleet_id"],
        "plan": plan_ref,
        "apply": apply_ref,
        "run_id": run_id,
        "session_id": session_id,
        "correlation_id": correlation_id,
        "window": window,
        "collector_closure": raw["collector_closure"],
        "probe_driver": driver_ref,
        "client_release_binding": client_reference,
        "client_artifact": client_ref,
        "client_build_identity": build_identity,
        "record_chain_sha256": raw["record_chain_sha256"],
        "deployment_execution": deploy_refs["deployment_execution"],
        "deployment_candidate_id": deploy_refs["deployment_candidate_id"],
        "deployment_manifest_sha256": deploy_refs["deployment_manifest_sha256"],
        "deployment_record_chain_sha256": deploy_refs["deployment_record_chain_sha256"],
        "resources": resource_identity(spec),
    }
    return checks, receipt_bindings


def phase_plan(
    spec: FleetSpec,
    state_dir: Path,
    *,
    repo_root: Path,
    deployment_inputs_path: Path,
    release_input_index: Path,
    client_build_receipt: Path,
    client_artifact: Path,
    replace_plan: bool,
    release_artifact_paths: Mapping[str, Path] | None = None,
    release_artifact_receipts: Mapping[str, Path] | Sequence[Any] | None = None,
) -> dict[str, Any]:
    state, paths = prepare_state_dir(state_dir, create=True), None
    paths = state_paths(state)
    if replace_plan:
        if paths["receipt"].exists():
            raise FleetRefused("cannot replace plan after acceptance")
        if paths["apply"].exists() or paths["apply_hash"].exists():
            raise FleetRefused("cannot replace a plan after immutable apply binding")
        for key in (
            "plan",
            "plan_hash",
            "release_artifacts",
            "release_artifacts_hash",
        ):
            _unlink_state_document(paths[key])
    elif paths["plan"].exists():
        raise FleetRefused("plan exists; use --replace-plan")
    elif (
        paths["release_artifacts"].exists()
        or paths["release_artifacts_hash"].exists()
    ):
        raise FleetRefused(
            "required release artifact binding exists; use --replace-plan"
        )
    deployment_reference, deployment_manifest = verify_deployment_inputs_reference(
        repo_root, deployment_inputs_path
    )
    client_reference = create_client_release_binding_reference(
        repo_root,
        release_input_index,
        client_build_receipt,
        client_artifact,
    )
    artifact_document = create_required_release_artifacts_document(
        repo_root=Path(client_reference["repo_root"]),
        artifact_paths=release_artifact_paths or {},
        receipt_paths=release_artifact_receipts or (),
        release_input_index=client_reference["binding"]["release_input_index"],
    )
    commands = build_plan_commands(spec)
    installers = build_installer_sequence(spec, deployment_manifest)
    payload = {
        "kind": KIND_PLAN,
        "schema_version": SCHEMA_VERSION,
        "phase": "plan",
        "created_utc": utc_now(),
        "dry_run": True,
        "fleet": spec_document(spec),
        "commands": commands,
        "installers": installers,
        "deployment_inputs": deployment_reference,
        "client_release_binding": client_reference,
    }
    digest = write_json_document(paths["plan"], payload, immutable=True)
    artifact_digest = write_json_document(
        paths["release_artifacts"], artifact_document, immutable=True
    )
    return {
        "kind": KIND_PLAN,
        "ok": True,
        "phase": "plan",
        "dry_run": True,
        "fleet": payload["fleet"],
        "commands": commands,
        "installers": installers,
        "deployment_inputs": deployment_reference,
        "client_release_binding": client_reference,
        "required_release_artifacts": artifact_document,
        "required_release_artifacts_sha256": artifact_digest,
        "plan_sha256": digest,
        "state_dir": str(state),
    }


def phase_apply(spec: FleetSpec, state_dir: Path, *, confirm: bool) -> dict[str, Any]:
    state, paths = prepare_state_dir(state_dir, create=False), None
    paths = state_paths(state)
    plan, plan_digest = load_json_document(paths["plan"], require_immutable=True)
    if spec_from_plan(plan) != spec:
        raise FleetRefused("fleet does not match plan")
    _, deployment_manifest, client_reference = plan_bound_inputs(plan)
    commands = build_plan_commands(spec)
    installers = build_installer_sequence(spec, deployment_manifest)
    if not confirm:
        return {
            "kind": KIND_APPLY,
            "ok": True,
            "phase": "apply",
            "dry_run": True,
            "would_apply": True,
            "commands": commands,
            "installers": installers,
            "deployment_inputs": plan["deployment_inputs"],
            "client_release_binding": client_reference,
            "plan_sha256": plan_digest,
        }
    if paths["apply"].exists():
        existing, digest = load_immutable_apply(
            paths["apply"], spec, plan_digest, plan
        )
        return {
            "kind": KIND_APPLY,
            "ok": True,
            "phase": "apply",
            "dry_run": False,
            "would_apply": False,
            "commands": existing["commands"],
            "installers": existing["installers"],
            "deployment_inputs": existing["deployment_inputs"],
            "client_release_binding": existing["client_release_binding"],
            "plan_sha256": plan_digest,
            "apply_sha256": digest,
        }
    payload = {
        "kind": KIND_APPLY,
        "schema_version": SCHEMA_VERSION,
        "phase": "apply",
        "created_utc": utc_now(),
        "dry_run": False,
        "fleet": spec_document(spec),
        "commands": commands,
        "installers": installers,
        "deployment_inputs": plan["deployment_inputs"],
        "client_release_binding": client_reference,
        "plan_sha256": plan_digest,
    }
    digest = write_json_document(paths["apply"], payload, immutable=True)
    return {
        "kind": KIND_APPLY,
        "ok": True,
        "phase": "apply",
        "dry_run": False,
        "would_apply": False,
        "commands": commands,
        "installers": installers,
        "deployment_inputs": plan["deployment_inputs"],
        "client_release_binding": client_reference,
        "plan_sha256": plan_digest,
        "apply_sha256": digest,
    }


def final_acceptance_state(
    *,
    client_reference: Mapping[str, Any],
    probe_driver_ref: Mapping[str, Any],
    supplied_artifacts: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    artifacts = evaluate_action_release_artifacts(
        client_reference, supplied_artifacts=supplied_artifacts
    )
    reviewed = reviewed_live_probe_ref()
    checks: list[dict[str, Any]] = []
    if (
        probe_driver_ref.get("sha256") != reviewed["sha256"]
        or probe_driver_ref.get("bytes") != reviewed["bytes"]
    ):
        checks.append(
            {
                "name": "execution-producer-runtime",
                "ok": False,
                "reason": (
                    "externally authenticated execution producer/runtime receipt "
                    f"from {EXECUTION_PRODUCER_NAME} "
                    "must bind the reviewed live probe, source freeze, candidate "
                    "manifest, driver bytes, project/transaction, and actual "
                    "command execution; caller JSON and FakeRunner observations "
                    "cannot reach final acceptance"
                ),
                "status": "blocked",
            }
        )
    else:
        checks.append({"name": "execution-producer-runtime", "ok": True})
    if any(item["status"] == "blocked" for item in artifacts):
        checks.append(
            {
                "actions": artifacts,
                "name": "required-release-artifacts",
                "ok": False,
                "reason": (
                    "missing required release artifacts are blocked; a single "
                    "Linux client cannot prove the 16 target actions"
                ),
                "status": "blocked",
            }
        )
    else:
        checks.append(
            {
                "actions": artifacts,
                "name": "required-release-artifacts",
                "ok": True,
            }
        )
    return checks, artifacts


def verifier_ref() -> dict[str, Any]:
    return file_ref(Path(__file__).absolute(), label="proof verifier")


def phase_verify(
    spec: FleetSpec,
    state_dir: Path,
    *,
    evidence_path: Path | None,
    probe_driver: Path | None,
    run_id: str | None,
    session_id: str | None,
    correlation_id: str | None,
) -> dict[str, Any]:
    state, paths = prepare_state_dir(state_dir, create=False), None
    paths = state_paths(state)
    plan, plan_digest = load_json_document(paths["plan"], require_immutable=True)
    if spec_from_plan(plan) != spec:
        raise FleetRefused("fleet does not match plan")
    commands = build_verify_commands(spec)
    if evidence_path is None:
        return {
            "kind": KIND_VERIFY,
            "ok": True,
            "phase": "verify",
            "acceptance": False,
            "verdict": "inconclusive",
            "commands": commands,
            "plan_sha256": plan_digest,
            "required_evidence": required_evidence_schema(),
            "reason": "producer evidence required; hand-authored pass tokens are rejected",
        }
    if (
        probe_driver is None
        or not run_id
        or not session_id
        or not correlation_id
    ):
        raise FleetRefused(
            "verify requires the plan-bound client release and exact probe-driver/run/session/correlation identity"
        )
    _, apply_digest = load_immutable_apply(
        paths["apply"], spec, plan_digest, plan
    )
    evidence, evidence_digest = load_json_document(
        evidence_path, require_immutable=True
    )
    checks, bindings = verify_evidence_payload(
        spec,
        plan_digest,
        plan,
        evidence,
        expected_apply=paths["apply"],
        expected_probe_driver=probe_driver,
        expected_run_id=run_id,
        expected_session_id=session_id,
        expected_correlation_id=correlation_id,
    )
    evidence_binding = file_ref(evidence_path.absolute(), label="evidence")
    if evidence_binding["sha256"] != evidence_digest:
        raise FleetRefused("evidence changed after integrity verification")
    supplied_artifacts = load_plan_required_release_artifacts(
        state,
        expected_index=bindings["client_release_binding"]["binding"][
            "release_input_index"
        ],
        repo_root=Path(bindings["client_release_binding"]["repo_root"]),
    )
    acceptance_checks, action_artifacts = final_acceptance_state(
        client_reference=bindings["client_release_binding"],
        probe_driver_ref=bindings["probe_driver"],
        supplied_artifacts=supplied_artifacts,
    )
    checks = list(checks) + acceptance_checks
    verifier = verifier_ref()
    if any(item.get("ok") is not True for item in acceptance_checks):
        if paths["receipt"].exists():
            raise FleetRefused(
                "existing acceptance receipt cannot be reused from FakeRunner or blocked artifacts"
            )
        return {
            "kind": KIND_VERIFY,
            "ok": True,
            "phase": "verify",
            "acceptance": False,
            "verdict": "blocked",
            "commands": commands,
            "checks": checks,
            "required_action_artifacts": action_artifacts,
            "reason": (
                "final acceptance requires an externally authenticated execution "
                "producer/runtime receipt and a distinct required release artifact "
                "for each of the 16 target actions"
            ),
        }
    if paths["receipt"].exists():
        receipt, digest = load_json_document(paths["receipt"], require_immutable=True)
        assert_exact_keys("GCP acceptance receipt", receipt, ACCEPTANCE_RECEIPT_KEYS)
        if (
            receipt.get("kind") != KIND_RECEIPT
            or receipt.get("verdict") != "pass"
            or receipt.get("plan_sha256") != plan_digest
            or receipt.get("apply_sha256") != apply_digest
            or receipt.get("evidence_bundle") != evidence_binding
            or receipt.get("bindings") != bindings
            or receipt.get("verifier") != verifier
        ):
            raise FleetRefused("existing receipt does not match reverified evidence")
        return {
            "kind": KIND_VERIFY,
            "ok": True,
            "phase": "verify",
            "acceptance": True,
            "verdict": "pass",
            "receipt_reused": True,
            "acceptance_sha256": digest,
            "commands": commands,
        }
    receipt = {
        "kind": KIND_RECEIPT,
        "schema_version": SCHEMA_VERSION,
        "phase": "verify",
        "created_utc": utc_now(),
        "verdict": "pass",
        "plan_sha256": plan_digest,
        "apply_sha256": apply_digest,
        "fleet": spec_document(spec),
        "evidence_bundle": evidence_binding,
        "bindings": bindings,
        "verifier": verifier,
        "checks": checks,
    }
    digest = write_json_document(paths["receipt"], receipt, immutable=True)
    return {
        "kind": KIND_VERIFY,
        "ok": True,
        "phase": "verify",
        "acceptance": True,
        "verdict": "pass",
        "receipt_reused": False,
        "acceptance_sha256": digest,
        "commands": commands,
        "checks": checks,
    }


def verify_acceptance_receipt_for_release(
    receipt_path: Path,
    *,
    repo_root: Path,
    release_input_index: Path,
) -> dict[str, Any]:
    """Reverify one immutable live-proof receipt against the current release.

    This is the local bridge from three-VM proof evidence to release tooling.
    It executes no gcloud command. The acceptance receipt is useful only while
    its complete immutable plan/apply/evidence chain and the exact bound release
    index, proof client, verifier closure, and observation window still verify.
    """

    repo = _canonical_repo_root(repo_root)
    index = release_input_index.expanduser().absolute()
    try:
        index.relative_to(repo)
    except ValueError as exc:
        raise FleetRefused(
            "release input index must stay inside the repository"
        ) from exc

    receipt_path = receipt_path.expanduser().absolute()
    receipt, receipt_digest = load_json_document(
        receipt_path, require_immutable=True
    )
    assert_exact_keys("GCP acceptance receipt", receipt, ACCEPTANCE_RECEIPT_KEYS)
    if (
        receipt["kind"] != KIND_RECEIPT
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != SCHEMA_VERSION
        or receipt["phase"] != "verify"
        or receipt["verdict"] != "pass"
    ):
        raise FleetRefused("GCP acceptance receipt contract is invalid")

    evidence_reference = receipt["evidence_bundle"]
    if not isinstance(evidence_reference, dict):
        raise FleetRefused("GCP acceptance evidence reference is malformed")
    assert_exact_keys(
        "GCP acceptance evidence reference",
        evidence_reference,
        {"path", "sha256", "bytes"},
    )
    evidence_path = Path(str(evidence_reference["path"]))
    evidence, evidence_digest = load_json_document(
        evidence_path, require_immutable=True
    )
    if (
        evidence_reference
        != file_ref(evidence_path.absolute(), label="acceptance evidence")
        or evidence_reference["sha256"] != evidence_digest
    ):
        raise FleetRefused("GCP acceptance evidence reference changed")

    if not isinstance(evidence.get("plan"), dict):
        raise FleetRefused("GCP acceptance evidence plan reference is malformed")
    plan_path = Path(str(evidence["plan"].get("path", "")))
    plan, plan_digest = load_json_document(plan_path, require_immutable=True)
    spec = spec_from_plan(plan)
    if evidence["plan"] != file_ref(plan_path.absolute(), label="acceptance plan"):
        raise FleetRefused("GCP acceptance plan reference changed")

    if not isinstance(evidence.get("apply"), dict):
        raise FleetRefused("GCP acceptance evidence apply reference is malformed")
    apply_path = Path(str(evidence["apply"].get("path", "")))
    _, apply_digest = load_immutable_apply(apply_path, spec, plan_digest, plan)

    probe_reference = evidence.get("probe_driver")
    if not isinstance(probe_reference, dict):
        raise FleetRefused("GCP acceptance probe-driver reference is malformed")
    probe_driver = Path(str(probe_reference.get("path", "")))
    checks, bindings = verify_evidence_payload(
        spec,
        plan_digest,
        plan,
        evidence,
        expected_apply=apply_path,
        expected_probe_driver=probe_driver,
        expected_run_id=str(evidence.get("run_id", "")),
        expected_session_id=str(evidence.get("session_id", "")),
        expected_correlation_id=str(evidence.get("correlation_id", "")),
    )
    supplied_artifacts = load_plan_required_release_artifacts(
        prepare_state_dir(plan_path.parent, create=False),
        expected_index=file_ref(index, label="current release input index"),
        repo_root=repo,
    )
    acceptance_checks, action_artifacts = final_acceptance_state(
        client_reference=bindings["client_release_binding"],
        probe_driver_ref=bindings["probe_driver"],
        supplied_artifacts=supplied_artifacts,
    )
    checks = list(checks) + acceptance_checks
    if any(item.get("ok") is not True for item in acceptance_checks):
        raise FleetRefused(
            "GCP acceptance receipt is blocked: FakeRunner observations and "
            "reused or missing release artifacts cannot reach final acceptance"
        )

    client_reference = verify_client_release_binding_reference(
        bindings["client_release_binding"], expected_repo_root=repo
    )
    client_binding = client_reference["binding"]
    expected_index_reference = file_ref(index, label="current release input index")
    if client_binding["release_input_index"] != expected_index_reference:
        raise FleetRefused(
            "GCP acceptance receipt is bound to a different release input index"
        )

    created = parse_utc("GCP acceptance receipt creation", receipt["created_utc"])
    evidence_ended = parse_utc(
        "GCP acceptance evidence end", bindings["window"]["ended_utc"]
    )
    current = datetime.now(timezone.utc)
    if (
        created < evidence_ended
        or created > current + MAX_CLOCK_SKEW
        or current - created > MAX_EVIDENCE_AGE
    ):
        raise FleetRefused("GCP acceptance receipt is stale, future, or reordered")

    if (
        receipt["plan_sha256"] != plan_digest
        or receipt["apply_sha256"] != apply_digest
        or receipt["fleet"] != spec_document(spec)
        or receipt["evidence_bundle"] != evidence_reference
        or receipt["bindings"] != bindings
        or receipt["verifier"] != verifier_ref()
        or receipt["checks"] != checks
        or receipt["verdict"] != "pass"
    ):
        raise FleetRefused("GCP acceptance receipt does not reverify exactly")

    return {
        "verified": True,
        "receipt_path": str(receipt_path),
        "receipt_sha256": receipt_digest,
        "receipt_created_utc": receipt["created_utc"],
        "evidence_ended_utc": bindings["window"]["ended_utc"],
        "fleet_id": bindings["fleet_id"],
        "project": spec.project,
        "release": client_binding["release"],
        "shared_revision": client_binding["shared_revision"],
        "release_input_index": expected_index_reference,
        "client_build_identity": bindings["client_build_identity"],
        "record_chain_sha256": bindings["record_chain_sha256"],
        "required_vm_roles": list(ROLES),
        "required_action_artifacts": action_artifacts,
        "publication_authorized": False,
        "cloud_calls_executed": False,
    }


def load_passing_receipt(state: Path, spec: FleetSpec) -> tuple[dict[str, Any], str]:
    paths = state_paths(state)
    receipt, digest = load_json_document(paths["receipt"], require_immutable=True)
    assert_exact_keys("GCP acceptance receipt", receipt, ACCEPTANCE_RECEIPT_KEYS)
    plan, plan_digest = load_json_document(paths["plan"], require_immutable=True)
    _, apply_digest = load_immutable_apply(
        paths["apply"], spec, plan_digest, plan
    )
    evidence_bundle = receipt.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        raise FleetRefused("reset refused: no matching immutable passing receipt")
    assert_exact_keys(
        "GCP acceptance evidence reference",
        evidence_bundle,
        {"path", "sha256", "bytes"},
    )
    if (
        spec_from_plan(plan) != spec
        or receipt.get("kind") != KIND_RECEIPT
        or receipt.get("schema_version") != SCHEMA_VERSION
        or receipt.get("verdict") != "pass"
        or receipt.get("plan_sha256") != plan_digest
        or receipt.get("apply_sha256") != apply_digest
        or receipt.get("fleet") != spec_document(spec)
        or receipt.get("verifier") != verifier_ref()
        or not isinstance(receipt.get("bindings"), dict)
    ):
        raise FleetRefused("reset refused: no matching immutable passing receipt")
    return receipt, digest


def phase_reset(spec: FleetSpec, state_dir: Path, *, confirm: bool) -> dict[str, Any]:
    state = prepare_state_dir(state_dir, create=False)
    receipt, digest = load_passing_receipt(state, spec)
    return {
        "kind": KIND_RESET,
        "ok": True,
        "phase": "reset",
        "dry_run": not confirm,
        "confirm_reset": confirm,
        "would_reset": not confirm,
        "commands": build_reset_commands(spec) if confirm else [],
        "acceptance_sha256": digest,
        "receipt_verdict": receipt["verdict"],
        "would_delete": resource_identity(spec),
    }


def phase_emergency_cleanup(
    spec: FleetSpec, state_dir: Path, *, confirm: bool
) -> dict[str, Any]:
    if not confirm:
        raise FleetRefused(
            "emergency cleanup evidence requires --confirm-emergency-cleanup"
        )
    state = prepare_state_dir(state_dir, create=False)
    paths = state_paths(state)
    plan, plan_digest = load_json_document(paths["plan"], require_immutable=True)
    if spec_from_plan(plan) != spec:
        raise FleetRefused("fleet does not match plan")
    _, apply_digest = load_immutable_apply(paths["apply"], spec, plan_digest, plan)
    if paths["receipt"].exists():
        raise FleetRefused(
            "emergency cleanup refused because an acceptance receipt already exists"
        )
    execution, execution_digest = load_deployment_execution(
        paths["execution"],
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        plan=plan,
        state_dir=state,
        require_passed=False,
    )
    deploy_refs = deployment_binding(
        execution_path=paths["execution"],
        execution=execution,
        execution_digest=execution_digest,
    )
    payload = {
        "kind": KIND_EMERGENCY,
        "schema_version": SCHEMA_VERSION,
        "phase": "emergency-cleanup",
        "created_utc": utc_now(),
        "acceptance": False,
        "deletion_implemented": False,
        "fleet_identity_verified": True,
        "execution_status": execution["status"],
        "fleet": spec_document(spec),
        "resources": resource_identity(spec),
        "plan_sha256": plan_digest,
        "apply_sha256": apply_digest,
        "deployment_execution": deploy_refs["deployment_execution"],
        "deployment_candidate_id": deploy_refs["deployment_candidate_id"],
        "deployment_manifest_sha256": deploy_refs["deployment_manifest_sha256"],
        "deployment_record_chain_sha256": deploy_refs["deployment_record_chain_sha256"],
    }
    if paths["emergency"].exists() or paths["emergency_hash"].exists():
        existing, digest = load_json_document(
            paths["emergency"], require_immutable=True
        )
        comparable = dict(existing)
        comparable.pop("created_utc", None)
        expected = dict(payload)
        expected.pop("created_utc", None)
        if comparable != expected:
            raise FleetRefused(
                "existing emergency cleanup evidence does not match the failed fleet"
            )
        return {
            "kind": KIND_EMERGENCY,
            "phase": "emergency-cleanup",
            "acceptance": False,
            "deletion_implemented": False,
            "fleet_identity_verified": True,
            "reused": True,
            "evidence_sha256": digest,
        }
    digest = write_json_document(paths["emergency"], payload, immutable=True)
    return {
        "kind": KIND_EMERGENCY,
        "phase": "emergency-cleanup",
        "acceptance": False,
        "deletion_implemented": False,
        "fleet_identity_verified": True,
        "reused": False,
        "evidence_sha256": digest,
        "resources": payload["resources"],
        "deployment_candidate_id": payload["deployment_candidate_id"],
        "execution_status": execution["status"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("--control-instance", required=True)
    parser.add_argument("--winn3-data-instance", required=True)
    parser.add_argument("--cover-data-instance", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--admin-source-cidr")
    parser.add_argument("--dataplane-source-cidr")
    parser.add_argument("--control-zone", default="us-east1-b")
    parser.add_argument("--winn3-data-zone", default="us-central1-a")
    parser.add_argument("--cover-data-zone", default="us-east1-b")
    parser.add_argument("--control-machine", default="e2-standard-2")
    parser.add_argument("--winn3-data-machine", default="e2-medium")
    parser.add_argument("--cover-data-machine", default="e2-medium")
    parser.add_argument("--image-family", default=DEFAULT_IMAGE_FAMILY)
    parser.add_argument("--image-project", default=DEFAULT_IMAGE_PROJECT)
    parser.add_argument("--gcloud-bin", default="gcloud")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--deployment-inputs", type=Path)
    parser.add_argument("--release-input-index", type=Path)
    parser.add_argument("--client-build-receipt", type=Path)
    parser.add_argument("--replace-plan", action="store_true")
    parser.add_argument("--confirm-apply", action="store_true")
    parser.add_argument("--confirm-reset", action="store_true")
    parser.add_argument("--confirm-emergency-cleanup", action="store_true")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--client-artifact", type=Path)
    parser.add_argument("--probe-driver", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--session-id")
    parser.add_argument("--correlation-id")
    parser.add_argument(
        "--release-artifact",
        action="append",
        metavar="TARGET_ID=PATH",
    )
    parser.add_argument(
        "--release-artifact-receipt",
        action="append",
        metavar="PATH",
    )
    return parser


def spec_from_args(args: argparse.Namespace) -> FleetSpec:
    if not args.admin_source_cidr:
        raise FleetRefused("plan requires --admin-source-cidr")
    return build_spec(
        project=args.project,
        control_name=args.control_instance,
        winn3_data_name=args.winn3_data_instance,
        cover_data_name=args.cover_data_instance,
        control_zone=args.control_zone,
        winn3_data_zone=args.winn3_data_zone,
        cover_data_zone=args.cover_data_zone,
        control_machine=args.control_machine,
        winn3_data_machine=args.winn3_data_machine,
        cover_data_machine=args.cover_data_machine,
        admin_source_cidr=args.admin_source_cidr,
        dataplane_source_cidr=args.dataplane_source_cidr,
        image_family=args.image_family,
        image_project=args.image_project,
        gcloud_bin=args.gcloud_bin,
    )


def dispatch(args: argparse.Namespace) -> dict[str, Any]:
    artifact_paths = parse_target_path_bindings(
        args.release_artifact, label="release artifact"
    )
    receipt_bindings = parse_receipt_path_bindings(args.release_artifact_receipt)
    if args.phase == "plan":
        if any(
            value is None
            for value in (
                args.repo_root,
                args.deployment_inputs,
                args.release_input_index,
                args.client_build_receipt,
                args.client_artifact,
            )
        ):
            raise FleetRefused(
                "plan requires repo/deployment/release-index/build-receipt/client-artifact inputs"
            )
        return phase_plan(
            spec_from_args(args),
            args.state_dir,
            repo_root=args.repo_root,
            deployment_inputs_path=args.deployment_inputs,
            release_input_index=args.release_input_index,
            client_build_receipt=args.client_build_receipt,
            client_artifact=args.client_artifact,
            replace_plan=args.replace_plan,
            release_artifact_paths=artifact_paths,
            release_artifact_receipts=receipt_bindings,
        )
    if (
        any(
            value is not None
            for value in (
                args.repo_root,
                args.deployment_inputs,
                args.release_input_index,
                args.client_build_receipt,
                args.client_artifact,
            )
        )
        or artifact_paths
        or receipt_bindings
    ):
        raise FleetRefused(
            "non-plan phases use only the immutable plan-bound release inputs"
        )
    state = prepare_state_dir(args.state_dir, create=False)
    plan, _ = load_json_document(state_paths(state)["plan"], require_immutable=True)
    spec = spec_from_plan(plan)
    supplied = (
        validate_token("project", args.project, PROJECT_RE),
        validate_gce_name("control instance", args.control_instance),
        validate_gce_name("Winn v3 data instance", args.winn3_data_instance),
        validate_gce_name("cover data instance", args.cover_data_instance),
    )
    if supplied != (spec.project, *spec.names):
        raise FleetRefused("instance names and project must match stored plan")
    if args.phase == "apply":
        return phase_apply(spec, state, confirm=args.confirm_apply)
    if args.phase == "verify":
        return phase_verify(
            spec,
            state,
            evidence_path=args.evidence,
            probe_driver=args.probe_driver,
            run_id=args.run_id,
            session_id=args.session_id,
            correlation_id=args.correlation_id,
        )
    if args.phase == "emergency-cleanup":
        return phase_emergency_cleanup(
            spec, state, confirm=args.confirm_emergency_cleanup
        )
    return phase_reset(spec, state, confirm=args.confirm_reset)


def main(argv: Sequence[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        for token in raw:
            if any(
                token.lower() == flag or token.lower().startswith(flag + "=")
                for flag in FORBIDDEN_FLAGS
            ):
                raise FleetRefused(
                    "this tool never executes gcloud or accepts credential/mutation flags"
                )
        payload = dispatch(build_parser().parse_args(raw))
        assert_no_secrets(payload)
    except FleetRefused as exc:
        print(str(exc), file=sys.stderr)
        return REFUSAL_EXIT
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
