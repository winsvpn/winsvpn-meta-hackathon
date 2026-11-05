#!/usr/bin/env python3
"""Create and verify the immutable GCP deployment-input closure.

The manifest is deliberately independent from the fleet executor.  It binds the
complete server and Winn Protocol source trees, the deployable router inputs,
the deployment producers/provenance, the exact architecture-matched set of
linux/amd64 or linux/arm64 Winn v3 proof-client ELFs, and the exact linux/amd64
AWG v3.1.20260828 plus Xray v26.9.30 client-runtime ELFs before any cloud
command is allowed to consume them. Client-runtime identity is derived from
reviewed closure pins; caller-authored digest/tag/commit arguments are refused.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import unicodedata
import zipfile
from typing import Any, Iterable, Mapping, Sequence


KIND = "winsvpn.gcp_proof.deployment_inputs.v1"
SCHEMA_VERSION = 1
CLOSURE_POLICY = "winsvpn-gcp-deployment-closure-v1"
SCOPE_ROOTS = ("server", "router", "winn_protocol_experimental")
INSTALLERS = (
    "server/wins_control_plane_setup_ONETOUCH.sh",
    "server/wins_data_plane_setup_ONETOUCH.sh",
    "server/wins_winn3_gateway_install.sh",
    "router/install_aicore_router.sh",
)
PROVENANCE_INPUTS: tuple[tuple[str, str], ...] = (
    ("docs/AMNEZIAWG_ENGINE_PROVENANCE.md", "provenance"),
    ("docs/RELEASE_ENGINE_BINARY_REFRESH.md", "provenance"),
    ("tools/toolchain-pins.json", "provenance"),
    ("tools/verify_deployment_supply_chain.py", "tool"),
    ("tools/verify_latest_awg_release.py", "tool"),
    ("tools/build_winn_protocol_engine.sh", "tool"),
    ("tools/winn_release.py", "tool"),
    ("tools/winn_release_authority.json", "provenance"),
    ("tools/build_xray_engine.sh", "tool"),
    ("tools/build_linux_release.sh", "tool"),
    ("tools/gcp_deployment_inputs.py", "tool"),
    ("tools/gcloud_custody.py", "tool"),
    ("tools/create_gcloud_custody_receipt.py", "tool"),
    ("tools/generate_gcloud_go_pin.py", "tool"),
    ("tools/gcp_proof_client/gcloud_pin_generated.go", "tool"),
    ("tools/gcp_proof_remote_action.py", "tool"),
    ("tools/gcp_proof_attempt_broker.py", "tool"),
    (
        "tools/gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.service",
        "tool",
    ),
    (
        "tools/gcp_proof_attempt_broker/winsvpn-gcp-proof-attempt-broker.socket",
        "tool",
    ),
    ("tools/gcp_proof_attempt_broker/winsvpn-proof-awg-client.service", "tool"),
    ("tools/gcp_proof_attempt_broker/winsvpn-proof-winn3-probe.service", "tool"),
    ("tools/gcp_proof_attempt_broker/winsvpn-proof-xray-client.service", "tool"),
    ("tools/gcp_proof_attempt_broker/winsvpn-proof-xray-probe.service", "tool"),
    ("tools/gcp_proof_attempt_broker/awg0.conf.example", "tool"),
    ("tools/gcp_proof_attempt_broker/winn3-probe.env", "tool"),
    ("tools/gcp_proof_attempt_broker/xray-client.json", "tool"),
    ("tools/gcp_proof_attempt_broker/xray-probe.env", "tool"),
)
ROUTER_REQUIRED = (
    "router/Dockerfile",
    "router/base-image.pin",
    "router/requirements.lock",
    "router/requirements.txt",
    "router/fallback.py",
    "router/gemini_client.py",
    "router/local_gemma_client.py",
    "router/main.py",
    "router/provider_common.py",
    "router/schemas.py",
    "router/security.py",
    "router/install_aicore_router.sh",
    "router/wins-edge-router.service.example",
)
ROUTER_KNOWN_NONDEPLOYABLE = {
    "router/.env.example",
    "router/aicore.env.example",
    "router/CONTINUE.md",
    "router/LANE_REPORT.md",
    "router/PROGRESS.json",
    "router/README.md",
    "router/receipts/prod_sanity.txt",
}
ROUTER_IGNORED_DIRS = {
    "router/.pytest_cache",
    "router/__pycache__",
    "router/tests",
}
ROUTER_CONFIG_SUFFIXES = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".lock",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
CREATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
COMPATIBLE_RUNTIME_IMPLEMENTATION = "cpython"
COMPATIBLE_RUNTIME_VERSION = (3, 14)
PYTHON_RUNTIME_KIND = "winsvpn.gcp_proof.python_runtime.v1"
PYTHON_RUNTIME_CONTRACT = "winsvpn-gcp-python-runtime-v1"
PYTHON_RUNTIME_SCHEMA_VERSION = 1
PYTHON_RUNTIME_RECEIPT_ENV = "WINS_GCP_PYTHON_RUNTIME_RECEIPT"
REMOTE_PYTHON_RUNTIME_RECEIPT_ENV = "WINS_GCP_REMOTE_PYTHON_RUNTIME_RECEIPT"
PYTHON_RUNTIME_KEYS = {
    "archive_path",
    "archive_sha256",
    "contract",
    "executable_path",
    "executable_sha256",
    "implementation",
    "install_tree_path",
    "install_tree_sha256",
    "kind",
    "schema_version",
    "source_path",
    "source_sha256",
    "version",
}
TOOLCHAIN_PINS = Path(__file__).resolve().with_name("toolchain-pins.json")
LINUX_CLIENT_BUILDER = "tools/build_linux_release.sh"
XRAY_ENGINE_BUILDER = "tools/build_xray_engine.sh"
GATEWAY_PRODUCT = "winn3-gateway"
PROOF_CLIENT_PRODUCTS = (GATEWAY_PRODUCT, "winn3-probe", "winn-ech-keygen")
# The proof broker directly starts amneziawg-go and applies configuration with
# awg. It does not invoke awg-quick. Upstream awg-quick is a Bash script, so it
# must not be mislabeled as an ELF or installed as an unused root runtime.
CLIENT_RUNTIME_PRODUCTS = ("amneziawg-go", "awg", "xray")
ALL_EXECUTABLE_PRODUCTS = PROOF_CLIENT_PRODUCTS + CLIENT_RUNTIME_PRODUCTS
CLIENT_RUNTIME_CLASS = "client-runtime"
PROOF_CLIENT_NAME_RES = {
    product: re.compile(rf"{re.escape(product)}-linux-(amd64|arm64)\Z")
    for product in PROOF_CLIENT_PRODUCTS
}
CLIENT_RUNTIME_NAME_RES = {
    product: re.compile(rf"{re.escape(product)}-linux-amd64\Z")
    for product in CLIENT_RUNTIME_PRODUCTS
}
GATEWAY_NAME_RE = PROOF_CLIENT_NAME_RES[GATEWAY_PRODUCT]
GATEWAY_MACHINES = {"amd64": 62, "arm64": 183}
REVIEWED_AWG_GO_TAG = "v3.1.20260828"
REVIEWED_AWG_GO_COMMIT = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
REVIEWED_AWG_TOOLS_TAG = "v3.1.20260812"
REVIEWED_AWG_TOOLS_COMMIT = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
REVIEWED_XRAY_TAG = "v26.9.30"
REVIEWED_XRAY_COMMIT = "b26a91de4f3294e26a0ad0a970b81a386a41f789"
REVIEWED_XRAY_VERSION = "26.9.30"
REVIEWED_GO_VERSION = "1.27.1"
ELF_MAGIC = b"\x7fELF"
ELF_CLASS_64 = 2
ELF_DATA_LSB = 1
ELF_VERSION = 1
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PF_X = 1
SHT_NULL = 0
SHT_SYMTAB = 2
SHT_SYMTAB_SHNDX = 18
SHT_NOBITS = 8
EHDR64_SIZE = 64
PHDR64_SIZE = 56
SHDR64_SIZE = 64
MAX_ELF_PHNUM = 128
MAX_ELF_SHNUM = 1024
MAX_ARCHIVE_OUTER = 64 * 1024 * 1024
MAX_ARCHIVE_MEMBER = 32 * 1024 * 1024
MAX_ARCHIVE_COUNT = 4096
MAX_ARCHIVE_RATIO = 100
MAX_ARCHIVE_AGGREGATE = 128 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2
MAX_ARCHIVE_PATH_PARTS = 32
ZIP_ENCRYPT = 1
PROOF_CLIENT_ARTIFACT_KEYS = {
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
GATEWAY_ARTIFACT_KEYS = PROOF_CLIENT_ARTIFACT_KEYS
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
REMOTE_ACTION_HELPER_PATH = "tools/gcp_proof_remote_action.py"
REMOTE_ACTION_HELPER_CONTRACT = "winsvpn-gcp-proof-remote-action-v1"
REMOTE_ACTION_HELPER_INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-remote"
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
ATTEMPT_BROKER_PATH = "tools/gcp_proof_attempt_broker.py"
ATTEMPT_BROKER_CONTRACT = "winsvpn-gcp-proof-protocol-attempt-request-v1"
ATTEMPT_BROKER_INSTALL_PATH = "/usr/local/libexec/winsvpn-gcp-proof-attempt-broker"
ATTEMPT_BROKER_REQUIRED_ROLES = ("control",)
ATTEMPT_BROKER_ROLE_PATH = "/etc/winsvpn/role"
ATTEMPT_BROKER_FLEET_BINDING_PATH = "/var/lib/winsvpn-proof/fleet-binding.json"
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
ATTEMPT_BROKER_UNIT_MARKERS = {
    "winsvpn-proof-winn3-probe.service": b"ExecStart=/usr/local/bin/winn3-probe",
    "winsvpn-proof-awg-client.service": b"ExecStart=/usr/local/bin/amneziawg-go",
    "winsvpn-proof-xray-client.service": b"ExecStart=/usr/local/bin/xray",
    "winsvpn-proof-xray-probe.service": b"ExecStart=/usr/bin/ping",
}
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
# A WireGuard/AWG key in its usual base64 form, wherever it appears.
AWG_KEY_TOKEN_RE = re.compile(rb"[A-Za-z0-9+/]{43}=")
IPV4_PORT_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d):[1-9][0-9]{0,4}\Z"
)
IPV4_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\Z"
)


class DeploymentInputsError(RuntimeError):
    """A deployment-input closure could not be proven."""


@dataclasses.dataclass(frozen=True)
class FileRecord:
    path: str
    file_class: str
    sha256: str
    size: int
    mode: int
    device: int = dataclasses.field(repr=False)
    inode: int = dataclasses.field(repr=False)
    data: bytes = dataclasses.field(compare=False, repr=False)

    def manifest_record(self) -> dict[str, object]:
        return {
            "bytes": self.size,
            "class": self.file_class,
            "mode": self.mode,
            "path": self.path,
            "sha256": self.sha256,
        }


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strip_sha256_prefix(value: str) -> str:
    if value.startswith("sha256:"):
        return value[7:]
    return value


def _exact_int(value: object, label: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    if type(value) is not int:
        raise DeploymentInputsError(f"{label} must be an exact integer")
    if minimum is not None and value < minimum:
        raise DeploymentInputsError(f"{label} is out of range")
    if maximum is not None and value > maximum:
        raise DeploymentInputsError(f"{label} is out of range")
    return value


def _exact_bool(value: object, expected: bool, label: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise DeploymentInputsError(f"{label} must be exactly {expected}")
    return value


def _strict_zip(
    left: Sequence[Any], right: Sequence[Any], label: str
) -> list[tuple[Any, Any]]:
    if len(left) != len(right):
        raise DeploymentInputsError(f"{label} length mismatch")
    return list(zip(left, right))


def runtime_identity() -> dict[str, object]:
    version = (
        int(sys.version_info[0]),
        int(sys.version_info[1]),
        int(sys.version_info[2]),
    )
    return {
        "implementation": str(sys.implementation.name),
        "version": "%d.%d.%d" % version,
        "version_info": version,
    }


def _pinned_python_version() -> str:
    try:
        payload = json.loads(TOOLCHAIN_PINS.read_bytes().decode("ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentInputsError("python toolchain pin is unreadable") from exc
    try:
        version = payload["tools"]["python"]["version"]
        implementation = payload["tools"]["python"]["implementation"]
    except (TypeError, KeyError) as exc:
        raise DeploymentInputsError("python toolchain pin is malformed") from exc
    if implementation != COMPATIBLE_RUNTIME_IMPLEMENTATION:
        raise DeploymentInputsError("python toolchain pin implementation is invalid")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise DeploymentInputsError("python toolchain pin version is invalid")
    return version


def _absolute_runtime_path(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise DeploymentInputsError(f"{label} must be an absolute path")
    if "\\" in value or "\x00" in value:
        raise DeploymentInputsError(f"{label} contains a forbidden path character")
    if unicodedata.normalize("NFC", value) != value:
        raise DeploymentInputsError(f"{label} is not Unicode NFC normalized")
    path = Path(value)
    if (
        not path.is_absolute()
        or os.path.normpath(value) != value
        or value.endswith("/")
        or any(part in {".", ".."} for part in path.parts)
    ):
        raise DeploymentInputsError(f"{label} is not a canonical absolute path")
    return value


def python_install_tree_sha256(root: Path) -> str:
    candidate = root.expanduser()
    try:
        before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise DeploymentInputsError("python install tree is unreadable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise DeploymentInputsError("python install tree must be a real directory")
    digest = hashlib.sha256()
    found = False
    for directory, dirnames, filenames in os.walk(resolved, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        base = Path(directory)
        for name in list(dirnames):
            child = base / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise DeploymentInputsError("python install tree contains a non-directory")
        for name in filenames:
            child = base / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise DeploymentInputsError("python install tree contains a non-regular file")
            relative = child.relative_to(resolved).as_posix().encode("utf-8")
            payload = _read_immutable(child, "python install tree member")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big"))
            digest.update(len(payload).to_bytes(8, "big"))
            digest.update(payload)
            found = True
    try:
        after = candidate.lstat()
    except OSError as exc:
        raise DeploymentInputsError("python install tree was replaced") from exc
    if _identity(before) != _identity(after):
        raise DeploymentInputsError("python install tree changed while being hashed")
    if not found:
        raise DeploymentInputsError("python install tree contains no files")
    return digest.hexdigest()


def _hash_runtime_file(path: Path, label: str) -> str:
    return _sha256(_read_immutable(path, label))


def measure_python_runtime_identity(
    *,
    executable: Path,
    archive: Path,
    install_tree: Path,
    source: Path,
) -> dict[str, str]:
    executable_path = _absolute_runtime_path(os.fspath(executable), "python executable path")
    archive_path = _absolute_runtime_path(os.fspath(archive), "python archive path")
    tree_path = _absolute_runtime_path(os.fspath(install_tree), "python install tree path")
    source_path = _absolute_runtime_path(os.fspath(source), "python source path")
    return {
        "archive_path": archive_path,
        "archive_sha256": _hash_runtime_file(Path(archive_path), "python archive"),
        "executable_path": executable_path,
        "executable_sha256": _hash_runtime_file(Path(executable_path), "python executable"),
        "install_tree_path": tree_path,
        "install_tree_sha256": python_install_tree_sha256(Path(tree_path)),
        "source_path": source_path,
        "source_sha256": _hash_runtime_file(Path(source_path), "python source"),
    }


def parse_python_runtime_receipt(path: Path) -> dict[str, object]:
    receipt_path = path.expanduser()
    payload = _read_immutable(receipt_path, "python runtime receipt")
    record = _exact_keys(
        _strict_json(payload, "python runtime receipt"),
        PYTHON_RUNTIME_KEYS,
        "python runtime receipt",
    )
    schema_version = _exact_int(record["schema_version"], "python runtime schema_version")
    if (
        record["kind"] != PYTHON_RUNTIME_KIND
        or schema_version != PYTHON_RUNTIME_SCHEMA_VERSION
        or record["contract"] != PYTHON_RUNTIME_CONTRACT
    ):
        raise DeploymentInputsError("python runtime receipt kind/schema/contract is invalid")
    if (
        type(record["implementation"]) is not str
        or record["implementation"] != COMPATIBLE_RUNTIME_IMPLEMENTATION
    ):
        raise DeploymentInputsError("python runtime receipt implementation is invalid")
    if type(record["version"]) is not str or not VERSION_RE.fullmatch(record["version"]):
        raise DeploymentInputsError("python runtime receipt version is invalid")
    for field in (
        "executable_path",
        "archive_path",
        "install_tree_path",
        "source_path",
    ):
        record[field] = _absolute_runtime_path(record[field], f"python runtime {field}")
    for field in (
        "executable_sha256",
        "archive_sha256",
        "install_tree_sha256",
        "source_sha256",
    ):
        digest = record[field]
        if type(digest) is not str or not HEX64_RE.fullmatch(digest):
            raise DeploymentInputsError(f"python runtime {field} is invalid")
    if payload != canonical_bytes(record):
        raise DeploymentInputsError("python runtime receipt is not canonical ASCII JSON")
    return record


def authenticate_local_python_runtime(path: Path) -> dict[str, object]:
    record = parse_python_runtime_receipt(path)
    try:
        live_executable = Path(sys.executable).expanduser().resolve(strict=True)
    except OSError as exc:
        raise DeploymentInputsError("authenticated Python executable is unreadable") from exc
    expected_executable = Path(str(record["executable_path"])).resolve(strict=True)
    if live_executable != expected_executable:
        raise DeploymentInputsError("python runtime executable was substituted")
    measured = measure_python_runtime_identity(
        executable=expected_executable,
        archive=Path(str(record["archive_path"])),
        install_tree=Path(str(record["install_tree_path"])),
        source=Path(str(record["source_path"])),
    )
    for field, observed in measured.items():
        if observed != record[field]:
            raise DeploymentInputsError(f"python runtime receipt {field} is stale")
    live = runtime_identity()
    if live["implementation"] != record["implementation"] or live["version"] != record["version"]:
        raise DeploymentInputsError("python runtime receipt no longer matches the live interpreter")
    return record


def _authenticate_compatible_runtime() -> dict[str, object]:
    identity = runtime_identity()
    implementation = identity["implementation"]
    version_info = identity["version_info"]
    if not isinstance(implementation, str) or implementation != COMPATIBLE_RUNTIME_IMPLEMENTATION:
        raise DeploymentInputsError(
            "incompatible Python runtime implementation; authenticated CPython 3.14 is required"
        )
    if (
        not isinstance(version_info, tuple)
        or len(version_info) != 3
        or any(type(part) is not int for part in version_info)
        or version_info[:2] != COMPATIBLE_RUNTIME_VERSION
    ):
        raise DeploymentInputsError(
            "incompatible Python runtime version; authenticated CPython 3.14 is required"
        )
    pinned = _pinned_python_version()
    if identity["version"] != pinned:
        raise DeploymentInputsError(
            "incompatible Python runtime version; authenticated CPython 3.14 is required"
        )
    receipt = os.environ.get(PYTHON_RUNTIME_RECEIPT_ENV)
    if type(receipt) is not str or not receipt:
        raise DeploymentInputsError(
            "Python runtime receipt is required; refusing version-only ambient python3"
        )
    authenticated = authenticate_local_python_runtime(Path(receipt))
    if authenticated["version"] != pinned or authenticated["version"] != identity["version"]:
        raise DeploymentInputsError("python runtime receipt version does not match the pinned interpreter")
    identity["receipt"] = authenticated
    return identity


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentInputsError(f"duplicate JSON key {key!r} is forbidden")
        result[key] = value
    return result


def _strict_json(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("ascii"), object_pairs_hook=_strict_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentInputsError(f"{label} is not canonical ASCII JSON") from exc


def _identity(item: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        stat.S_IFMT(item.st_mode),
        stat.S_IMODE(item.st_mode),
    )


def _secure_absolute_dir(path: Path, label: str) -> Path:
    candidate = path.expanduser().absolute()
    if not candidate.is_absolute():
        raise DeploymentInputsError(f"{label} must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
        info = candidate.lstat()
    except OSError as exc:
        raise DeploymentInputsError(f"{label} is not an existing directory") from exc
    if resolved != candidate or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise DeploymentInputsError(f"{label} must be a canonical non-symlink directory")
    return candidate


def _validate_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeploymentInputsError(f"{label} must be a nonempty relative POSIX path")
    if "\\" in value or "\x00" in value:
        raise DeploymentInputsError(f"{label} contains a forbidden path character")
    if unicodedata.normalize("NFC", value) != value:
        raise DeploymentInputsError(f"{label} is not Unicode NFC normalized")
    pure = PurePosixPath(value)
    if pure.is_absolute() or value != pure.as_posix() or any(
        part in {"", ".", ".."} for part in pure.parts
    ):
        raise DeploymentInputsError(f"{label} is not a canonical relative POSIX path")
    return value


def _repo_path(repo: Path, relative: str, label: str) -> Path:
    normalized = _validate_relative_path(relative, label)
    candidate = repo.joinpath(*PurePosixPath(normalized).parts)
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise DeploymentInputsError(f"{label} parent is missing") from exc
    if parent != candidate.parent or repo != parent and repo not in parent.parents:
        raise DeploymentInputsError(f"{label} escapes the repository or crosses a symlink")
    return candidate


def _read_regular(repo: Path, relative: str, file_class: str) -> FileRecord:
    normalized = _validate_relative_path(relative, f"input {relative!r}")
    parts = PurePosixPath(normalized).parts
    if not parts:
        raise DeploymentInputsError(f"input {relative!r} path is empty")
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        raise DeploymentInputsError("descriptor-relative no-follow traversal is unavailable")
    cloexec = getattr(os, "O_CLOEXEC", 0)
    fd = -1
    directory_fds: list[int] = []
    try:
        root_before = repo.lstat()
        if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
            raise DeploymentInputsError("repository root changed before input capture")
        root_fd = os.open(repo, os.O_RDONLY | directory | nofollow | cloexec)
        directory_fds.append(root_fd)
        root_opened = os.fstat(root_fd)
        current_fd = root_fd
        for component in parts[:-1]:
            component_before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(component_before.st_mode) or not stat.S_ISDIR(
                component_before.st_mode
            ):
                raise DeploymentInputsError(
                    f"input {relative!r} crosses a symlink or non-directory ancestor"
                )
            child_fd = os.open(
                component,
                os.O_RDONLY | directory | nofollow | cloexec,
                dir_fd=current_fd,
            )
            component_opened = os.fstat(child_fd)
            component_after = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if not (
                stat.S_ISDIR(component_opened.st_mode)
                and _identity(component_before) == _identity(component_opened)
                and _identity(component_opened) == _identity(component_after)
            ):
                os.close(child_fd)
                raise DeploymentInputsError(
                    f"input {relative!r} ancestor changed while being opened"
                )
            directory_fds.append(child_fd)
            current_fd = child_fd
        name = parts[-1]
        before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise DeploymentInputsError(f"input {relative!r} is not a regular file")
        if before.st_nlink != 1:
            raise DeploymentInputsError(f"input {relative!r} is hard-linked")
        fd = os.open(name, os.O_RDONLY | cloexec | nofollow, dir_fd=current_fd)
        opened = os.fstat(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        after = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
        root_after = repo.lstat()
    except DeploymentInputsError:
        raise
    except OSError as exc:
        raise DeploymentInputsError(f"input {relative!r} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)
    if not (
        stat.S_ISDIR(root_opened.st_mode)
        and _identity(root_before) == _identity(root_opened)
        and _identity(root_opened) == _identity(root_after)
    ):
        raise DeploymentInputsError("repository root changed during input capture")
    if not all(_identity(before) == _identity(item) for item in (opened, finished, after)):
        raise DeploymentInputsError(f"input {relative!r} changed while being read")
    data = b"".join(chunks)
    if not data:
        raise DeploymentInputsError(f"input {relative!r} is empty")
    if data.startswith(b"PK\x03\x04"):
        _inspect_zip_archive(data)
    return FileRecord(
        path=relative,
        file_class=file_class,
        sha256=_sha256(data),
        size=len(data),
        mode=stat.S_IMODE(opened.st_mode),
        device=opened.st_dev,
        inode=opened.st_ino,
        data=data,
    )


def _walk_tree(repo: Path, root_relative: str, file_class: str) -> list[FileRecord]:
    root = _repo_path(repo, root_relative, f"scope root {root_relative!r}")
    try:
        root_before = root.lstat()
    except OSError as exc:
        raise DeploymentInputsError(f"scope root {root_relative!r} is missing") from exc
    if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
        raise DeploymentInputsError(f"scope root {root_relative!r} is not a real directory")
    relatives: list[str] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in sorted(dirnames):
            child = current_path / name
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                rel = child.relative_to(repo).as_posix()
                raise DeploymentInputsError(f"scope member {rel!r} is not a real directory")
        dirnames.sort()
        for name in sorted(filenames):
            child = current_path / name
            rel = child.relative_to(repo).as_posix()
            _validate_relative_path(rel, "scope member")
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise DeploymentInputsError(f"scope member {rel!r} is not a regular file")
            relatives.append(rel)
    try:
        root_after = root.lstat()
    except OSError as exc:
        raise DeploymentInputsError(f"scope root {root_relative!r} was replaced") from exc
    if _identity(root_before) != _identity(root_after):
        raise DeploymentInputsError(f"scope root {root_relative!r} changed during enumeration")
    if not relatives:
        raise DeploymentInputsError(f"scope root {root_relative!r} contains no files")
    return [_read_regular(repo, relative, file_class) for relative in sorted(relatives)]


def _router_deployable_paths(repo: Path) -> list[str]:
    router = _repo_path(repo, "router", "router scope")
    deployable = set(ROUTER_REQUIRED)
    receipts = router / "receipts"
    if not receipts.is_dir() or receipts.is_symlink():
        raise DeploymentInputsError("router/receipts must be a real directory")
    for current, dirnames, filenames in os.walk(router, topdown=True, followlinks=False):
        current_path = Path(current)
        current_rel = current_path.relative_to(repo).as_posix()
        for name in list(dirnames):
            rel = f"{current_rel}/{name}"
            info = (current_path / name).lstat()
            if stat.S_ISLNK(info.st_mode):
                raise DeploymentInputsError(f"router member {rel!r} is a symlink")
            if rel in ROUTER_IGNORED_DIRS:
                dirnames.remove(name)
        dirnames.sort()
        for name in sorted(filenames):
            path = current_path / name
            rel = path.relative_to(repo).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise DeploymentInputsError(f"router member {rel!r} is not a regular file")
            if rel in deployable or rel in ROUTER_KNOWN_NONDEPLOYABLE:
                continue
            if rel.startswith("router/receipts/") and (
                path.suffix in {".py", ".sh"} or stat.S_IMODE(info.st_mode) & 0o111
            ):
                deployable.add(rel)
                continue
            if (
                stat.S_IMODE(info.st_mode) & 0o111
                or path.suffix.lower() in ROUTER_CONFIG_SUFFIXES
                or name == "Dockerfile"
            ):
                raise DeploymentInputsError(
                    f"unclassified router executable/configuration input {rel!r}"
                )
    missing = [relative for relative in ROUTER_REQUIRED if not (repo / relative).is_file()]
    if missing:
        raise DeploymentInputsError(f"required router inputs are missing: {', '.join(missing)}")
    if not any(path.startswith("router/receipts/") for path in deployable):
        raise DeploymentInputsError("router has no deployment receipt script")
    return sorted(deployable)


def _artifact_runtime(path: str, product: str) -> tuple[str, int, str]:
    name = PurePosixPath(path).name
    if product in PROOF_CLIENT_NAME_RES:
        match = PROOF_CLIENT_NAME_RES[product].fullmatch(name)
        if match is None:
            raise DeploymentInputsError(
                f"Winn v3 {product} artifact must be named {product}-linux-amd64 or {product}-linux-arm64"
            )
        architecture = match.group(1)
        return architecture, GATEWAY_MACHINES[architecture], f"linux-{architecture}"
    if product not in CLIENT_RUNTIME_NAME_RES:
        raise DeploymentInputsError("executable product is not allowed")
    if CLIENT_RUNTIME_NAME_RES[product].fullmatch(name) is None:
        raise DeploymentInputsError(
            f"{product} artifact must be named {product}-linux-amd64"
        )
    return "amd64", GATEWAY_MACHINES["amd64"], "linux-amd64"


def _gateway_runtime(path: str) -> tuple[str, int, str]:
    return _artifact_runtime(path, GATEWAY_PRODUCT)


def _tables_overlap(left_off: int, left_size: int, right_off: int, right_size: int) -> bool:
    left_end = left_off + left_size
    right_end = right_off + right_size
    return left_off < right_end and right_off < left_end


def _elf_section_name(strtab: bytes, offset: int) -> str:
    if type(offset) is not int or offset < 0 or offset >= len(strtab):
        raise DeploymentInputsError("ELF section name is invalid")
    end = strtab.find(b"\x00", offset)
    if end < 0:
        raise DeploymentInputsError("ELF section name is not NUL terminated")
    try:
        return strtab[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeploymentInputsError("ELF section name is not ASCII") from exc


def _is_debug_section(name: str, sh_type: int) -> bool:
    if (
        name == ".debug"
        or name.startswith(".debug_")
        or name.startswith(".zdebug_")
        or name.startswith(".rel.debug")
        or name.startswith(".rela.debug")
        or name.startswith(".rel.zdebug")
        or name.startswith(".rela.zdebug")
        or name == ".symtab"
        or name == ".gnu_debugdata"
        or name == ".gdb_index"
        or name.startswith(".stab")
    ):
        return True
    return sh_type in {SHT_SYMTAB, SHT_SYMTAB_SHNDX}


def _inspect_elf64(
    data: bytes,
    *,
    expected_machine: int,
    product: str,
    runtime: str,
    require_product_markers: bool = True,
) -> dict[str, object]:
    label = f"{product} artifact"
    if len(data) < EHDR64_SIZE or data[:4] != ELF_MAGIC:
        raise DeploymentInputsError(f"{label} is not an ELF executable")
    if data[4] != ELF_CLASS_64 or data[5] != ELF_DATA_LSB or data[6] != ELF_VERSION:
        raise DeploymentInputsError(
            f"{label} must be ELF64 little-endian version 1"
        )
    if len(data) == EHDR64_SIZE:
        raise DeploymentInputsError(f"{label} is a header-only ELF")
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if e_ehsize != EHDR64_SIZE or e_phentsize != PHDR64_SIZE or e_shentsize != SHDR64_SIZE:
        raise DeploymentInputsError(f"{label} ELF header sizes are invalid")
    if e_version != ELF_VERSION:
        raise DeploymentInputsError(f"{label} ELF version is invalid")
    if e_type not in {ET_EXEC, ET_DYN}:
        raise DeploymentInputsError(f"{label} ELF type is invalid")
    if e_machine != expected_machine:
        raise DeploymentInputsError(
            f"{label} ELF machine does not match architecture"
        )
    if e_entry == 0:
        raise DeploymentInputsError(f"{label} ELF entry is zero")
    if e_phoff == 0 or e_phnum == 0 or e_phnum > MAX_ELF_PHNUM:
        raise DeploymentInputsError(f"{label} program table is invalid")
    if e_shoff == 0 or e_shnum == 0 or e_shnum > MAX_ELF_SHNUM:
        raise DeploymentInputsError(f"{label} section table is invalid")
    if e_shstrndx == 0 or e_shstrndx >= e_shnum:
        raise DeploymentInputsError(f"{label} section string table is invalid")
    ph_size = e_phnum * e_phentsize
    sh_size = e_shnum * e_shentsize
    if e_phoff > len(data) or ph_size > len(data) - e_phoff:
        raise DeploymentInputsError(f"{label} program table is truncated")
    if e_shoff > len(data) or sh_size > len(data) - e_shoff:
        raise DeploymentInputsError(f"{label} section table is truncated")
    if _tables_overlap(e_phoff, ph_size, e_shoff, sh_size):
        raise DeploymentInputsError(f"{label} program and section tables overlap")
    executable_load = False
    entry_mapped = False
    for index in range(e_phnum):
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, _p_align = (
            struct.unpack_from("<IIQQQQQQ", data, e_phoff + index * e_phentsize)
        )
        if p_offset > len(data) or p_filesz > len(data) - p_offset:
            raise DeploymentInputsError(
                f"{label} load segment exceeds file bounds"
            )
        if p_memsz < p_filesz:
            raise DeploymentInputsError(
                f"{label} load segment memory size is invalid"
            )
        if p_type != PT_LOAD:
            continue
        if p_flags & PF_X:
            executable_load = True
            if e_entry >= p_vaddr and e_entry - p_vaddr < p_memsz and e_entry - p_vaddr < p_filesz:
                entry_mapped = True
    if not executable_load:
        raise DeploymentInputsError(
            f"{label} has no executable load segment"
        )
    if not entry_mapped:
        raise DeploymentInputsError(
            f"{label} ELF entry is not in an executable load segment"
        )
    strtab_off = None
    strtab_size = None
    debug_sections: list[str] = []
    for index in range(e_shnum):
        (
            sh_name,
            sh_type,
            _sh_flags,
            _sh_addr,
            sh_offset,
            section_size,
            sh_link,
            _sh_info,
            _sh_addralign,
            _sh_entsize,
        ) = struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + index * e_shentsize)
        if index == 0 and (sh_type != SHT_NULL or sh_offset != 0 or section_size != 0):
            raise DeploymentInputsError(f"{label} null section is invalid")
        if sh_link >= e_shnum:
            raise DeploymentInputsError(f"{label} section link is invalid")
        if index == e_shstrndx:
            strtab_off = sh_offset
            strtab_size = section_size
        if sh_type == SHT_NOBITS:
            continue
        if sh_offset > len(data) or section_size > len(data) - sh_offset:
            raise DeploymentInputsError(f"{label} section exceeds file bounds")
    if strtab_off is None or strtab_size is None:
        raise DeploymentInputsError(f"{label} section string table is invalid")
    if strtab_off > len(data) or strtab_size > len(data) - strtab_off:
        raise DeploymentInputsError(f"{label} section string table exceeds file bounds")
    strtab = data[strtab_off : strtab_off + strtab_size]
    for index in range(e_shnum):
        sh_name, sh_type = struct.unpack_from("<II", data, e_shoff + index * e_shentsize)
        name = _elf_section_name(strtab, sh_name)
        if _is_debug_section(name, sh_type):
            debug_sections.append(name or f"type-{sh_type}")
    if debug_sections:
        raise DeploymentInputsError(
            f"{label} retains debug sections: " + ", ".join(debug_sections)
        )
    product_marker = ("winsvpn.product=" + product + "\x00").encode("ascii")
    runtime_marker = ("winsvpn.runtime=" + runtime + "\x00").encode("ascii")
    conflicting_products = [
        candidate
        for candidate in ALL_EXECUTABLE_PRODUCTS
        if candidate != product
        and ("winsvpn.product=" + candidate + "\x00").encode("ascii") in data
    ]
    if conflicting_products:
        raise DeploymentInputsError(f"{label} product identity is ambiguous")
    if require_product_markers:
        if product_marker not in data:
            raise DeploymentInputsError(f"{label} product identity is missing")
        if runtime_marker not in data:
            raise DeploymentInputsError(f"{label} runtime identity is missing")
    architecture = "amd64" if expected_machine == GATEWAY_MACHINES["amd64"] else "arm64"
    return {
        "architecture": architecture,
        "elf_class": ELF_CLASS_64,
        "elf_data": ELF_DATA_LSB,
        "elf_machine": e_machine,
        "elf_type": e_type,
        "entry": e_entry,
        "os": "linux",
        "product": product,
        "runtime": runtime,
        "sha256": _sha256(data),
    }


def _member_path_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise DeploymentInputsError("archive member path is unsafe")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise DeploymentInputsError("archive member path is unsafe")
    if len(pure.parts) > MAX_ARCHIVE_PATH_PARTS:
        raise DeploymentInputsError("archive member path exceeds the depth limit")
    return pure.parts


def _inspect_zip_archive(data: bytes, *, depth: int = 0) -> list[str]:
    if depth > MAX_ARCHIVE_DEPTH:
        raise DeploymentInputsError("archive nesting exceeds the depth limit")
    if len(data) > MAX_ARCHIVE_OUTER:
        raise DeploymentInputsError("archive outer size exceeds the limit")
    if len(data) < 22 or not data.startswith(b"PK\x03\x04"):
        raise DeploymentInputsError("archive is not a ZIP file")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            if bundle.comment:
                raise DeploymentInputsError("archive comments are forbidden")
            entries = bundle.infolist()
            if not entries or len(entries) > MAX_ARCHIVE_COUNT:
                raise DeploymentInputsError("archive member count is outside the accepted range")
            names: list[str] = []
            seen: set[str] = set()
            aggregate = 0
            for entry in entries:
                _member_path_parts(entry.filename)
                if entry.filename in seen:
                    raise DeploymentInputsError("archive contains duplicate members")
                seen.add(entry.filename)
                names.append(entry.filename)
                if entry.flag_bits & ZIP_ENCRYPT:
                    raise DeploymentInputsError("encrypted archive members are forbidden")
                if entry.is_dir():
                    continue
                if entry.file_size < 0 or entry.file_size > MAX_ARCHIVE_MEMBER:
                    raise DeploymentInputsError("archive member exceeds the size limit")
                if entry.compress_size < 0:
                    raise DeploymentInputsError("archive member compressed size is invalid")
                if entry.compress_size == 0:
                    if entry.file_size:
                        raise DeploymentInputsError("archive member compression ratio is invalid")
                elif entry.file_size > entry.compress_size * MAX_ARCHIVE_RATIO:
                    raise DeploymentInputsError("archive compression ratio exceeds the limit")
                aggregate += entry.file_size
                if aggregate > MAX_ARCHIVE_AGGREGATE:
                    raise DeploymentInputsError("archive aggregate size exceeds the limit")
            for entry in entries:
                if entry.is_dir():
                    continue
                with bundle.open(entry, "r") as handle:
                    payload = handle.read(MAX_ARCHIVE_MEMBER + 1)
                if len(payload) != entry.file_size:
                    raise DeploymentInputsError("archive member length mismatch")
                if payload.startswith(b"PK\x03\x04"):
                    _inspect_zip_archive(payload, depth=depth + 1)
    except DeploymentInputsError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise DeploymentInputsError("archive is unsafe or malformed") from exc
    return names


def _require_remote_action_helper(record: FileRecord) -> dict[str, object]:
    if record.path != REMOTE_ACTION_HELPER_PATH:
        raise DeploymentInputsError("remote proof-action helper path is not bound")
    if not record.data.startswith(b"#!/usr/bin/python3"):
        raise DeploymentInputsError("remote proof-action helper is not an executable script")
    if type(record.mode) is not int or record.mode & 0o022:
        raise DeploymentInputsError("remote proof-action helper is group- or world-writable")
    marker = ("RESPONSE_CONTRACT = \"" + REMOTE_ACTION_HELPER_CONTRACT + "\"").encode("ascii")
    install_marker = ("INSTALL_PATH = \"" + REMOTE_ACTION_HELPER_INSTALL_PATH + "\"").encode(
        "ascii"
    )
    if marker not in record.data or install_marker not in record.data:
        raise DeploymentInputsError("remote proof-action helper contract identity is missing")
    return {
        "bytes": record.size,
        "contract": REMOTE_ACTION_HELPER_CONTRACT,
        "install_path": REMOTE_ACTION_HELPER_INSTALL_PATH,
        "mode": record.mode,
        "path": record.path,
        "required_roles": list(REMOTE_ACTION_HELPER_REQUIRED_ROLES),
        "schema_version": SCHEMA_VERSION,
        "sha256": record.sha256,
    }


def _parse_env_keys(data: bytes, keys: Sequence[str], label: str) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DeploymentInputsError(f"{label} is not ASCII") from exc
    parsed: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ENV_LINE_RE.fullmatch(line)
        if match is None:
            raise DeploymentInputsError(f"{label} is unprovisioned")
        key, value = match.group(1), match.group(2)
        if key in parsed or not value:
            raise DeploymentInputsError(f"{label} is unprovisioned")
        parsed[key] = value
    if set(parsed) != set(keys):
        raise DeploymentInputsError(f"{label} is unprovisioned")
    return parsed


def _bind_attempt_member(
    records: Mapping[str, FileRecord],
    relative: str,
    install_path: str,
    name: str,
    label: str,
) -> dict[str, object]:
    record = records.get(relative)
    if record is None or record.path != relative:
        raise DeploymentInputsError(f"{label} is outside the closure")
    if record.file_class != "tool":
        raise DeploymentInputsError(f"{label} class is invalid")
    if type(record.mode) is not int or record.mode & 0o022:
        raise DeploymentInputsError(f"{label} is group- or world-writable")
    if type(record.size) is not int or record.size <= 0 or record.size != len(record.data):
        raise DeploymentInputsError(f"{label} byte count is invalid")
    return {
        "bytes": record.size,
        "install_path": install_path,
        "mode": record.mode,
        "name": name,
        "path": relative,
        "sha256": record.sha256,
    }


def _require_attempt_unit(record: FileRecord, name: str) -> None:
    marker = ATTEMPT_BROKER_UNIT_MARKERS[name]
    documentation = ("Documentation=file://" + ATTEMPT_BROKER_INSTALL_PATH).encode("ascii")
    if marker not in record.data or documentation not in record.data:
        raise DeploymentInputsError(f"attempt unit {name} identity is missing")


def _require_attempt_config(record: FileRecord, name: str) -> None:
    if name == "winn3-probe.env":
        env = _parse_env_keys(record.data, WINN3_PROBE_ENV_KEYS, "Winn3 probe env")
        if IPV4_PORT_RE.fullmatch(env["WINN3_PROOF_GW"]) is None:
            raise DeploymentInputsError("Winn3 probe env is unprovisioned")
        if ID_VALUE_RE.fullmatch(env["WINN3_PROOF_GATEWAY_ID"]) is None:
            raise DeploymentInputsError("Winn3 probe env is unprovisioned")
        if HEX64_RE.fullmatch(env["WINN3_PROOF_ED_PUB"]) is None:
            raise DeploymentInputsError("Winn3 probe env is unprovisioned")
        if HEX3904_RE.fullmatch(env["WINN3_PROOF_ML_PUB"]) is None:
            raise DeploymentInputsError("Winn3 probe env is unprovisioned")
        return
    if name == "xray-probe.env":
        env = _parse_env_keys(record.data, XRAY_PROBE_ENV_KEYS, "Xray probe env")
        if IPV4_RE.fullmatch(env["XRAY_PROOF_PEER"]) is None:
            raise DeploymentInputsError("Xray probe env is unprovisioned")
        return
    if name == "awg0.conf":
        if len(record.data) < 16 or b"[Interface]" not in record.data or b"[Peer]" not in record.data:
            raise DeploymentInputsError("AWG client config is unprovisioned")
        # The live key arrives only through the authenticated provision record
        # at exchange-control-seal; a source template never carries one.
        if b"privatekey" in record.data.lower() or b"presharedkey" in record.data.lower():
            raise DeploymentInputsError("AWG client config template carries a key")
        # A key-shaped value under any other name is still key material.
        if AWG_KEY_TOKEN_RE.search(record.data):
            raise DeploymentInputsError("AWG client config template carries a key")
        return
    if name == "xray-client.json":
        if len(record.data) < 16 or b"xray0" not in record.data:
            raise DeploymentInputsError("Xray client config is unprovisioned")
        return
    raise DeploymentInputsError(f"attempt config {name} is not allowed")


def _require_attempt_broker(
    record: FileRecord, records: Mapping[str, FileRecord]
) -> dict[str, object]:
    if record.path != ATTEMPT_BROKER_PATH:
        raise DeploymentInputsError("protocol-attempt broker path is not bound")
    if not record.data.startswith(b"#!/usr/bin/python3"):
        raise DeploymentInputsError("protocol-attempt broker is not an executable script")
    if type(record.mode) is not int or record.mode & 0o022:
        raise DeploymentInputsError("protocol-attempt broker is group- or world-writable")
    contract_marker = (
        "ATTEMPT_REQUEST_CONTRACT = \"" + ATTEMPT_BROKER_CONTRACT + "\""
    ).encode("ascii")
    socket_marker = b'ATTEMPT_SOCKET_PATH = "/run/winsvpn-proof/protocol-attempt.sock"'
    role_marker = ('ROLE_FILE = "' + ATTEMPT_BROKER_ROLE_PATH + '"').encode("ascii")
    binding_marker = (
        'FLEET_BINDING_PATH = "' + ATTEMPT_BROKER_FLEET_BINDING_PATH + '"'
    ).encode("ascii")
    if (
        contract_marker not in record.data
        or socket_marker not in record.data
        or role_marker not in record.data
        or binding_marker not in record.data
    ):
        raise DeploymentInputsError("protocol-attempt broker contract identity is missing")
    socket = _bind_attempt_member(
        records,
        ATTEMPT_BROKER_SOCKET_SOURCE,
        ATTEMPT_BROKER_SOCKET_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.socket",
        "attempt broker socket",
    )
    socket_record = records[ATTEMPT_BROKER_SOCKET_SOURCE]
    if (
        b"ListenStream=/run/winsvpn-proof/protocol-attempt.sock" not in socket_record.data
        or ("Documentation=file://" + ATTEMPT_BROKER_INSTALL_PATH).encode("ascii")
        not in socket_record.data
    ):
        raise DeploymentInputsError("attempt broker socket identity is missing")
    service = _bind_attempt_member(
        records,
        ATTEMPT_BROKER_SERVICE_SOURCE,
        ATTEMPT_BROKER_SERVICE_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.service",
        "attempt broker service",
    )
    service_record = records[ATTEMPT_BROKER_SERVICE_SOURCE]
    if (
        ("ExecStart=" + ATTEMPT_BROKER_INSTALL_PATH).encode("ascii") not in service_record.data
        or ("Documentation=file://" + ATTEMPT_BROKER_INSTALL_PATH).encode("ascii")
        not in service_record.data
    ):
        raise DeploymentInputsError("attempt broker service identity is missing")
    units: list[dict[str, object]] = []
    for relative, install_path, name in ATTEMPT_BROKER_UNITS:
        member = _bind_attempt_member(
            records, relative, install_path, name, f"attempt unit {name}"
        )
        _require_attempt_unit(records[relative], name)
        units.append(member)
    configs: list[dict[str, object]] = []
    for relative, install_path, name in ATTEMPT_BROKER_CONFIGS:
        member = _bind_attempt_member(
            records, relative, install_path, name, f"attempt config {name}"
        )
        _require_attempt_config(records[relative], name)
        configs.append(member)
    if (
        [item["name"] for item in units] != [name for _path, _install, name in ATTEMPT_BROKER_UNITS]
        or [item["name"] for item in configs]
        != [name for _path, _install, name in ATTEMPT_BROKER_CONFIGS]
    ):
        raise DeploymentInputsError("attempt broker units or configs are incomplete or reordered")
    return {
        "bytes": record.size,
        "configs": configs,
        "contract": ATTEMPT_BROKER_CONTRACT,
        "install_path": ATTEMPT_BROKER_INSTALL_PATH,
        "mode": record.mode,
        "path": record.path,
        "required_roles": list(ATTEMPT_BROKER_REQUIRED_ROLES),
        "schema_version": SCHEMA_VERSION,
        "service": service,
        "sha256": record.sha256,
        "socket": socket,
        "units": units,
    }


def _validate_attempt_member(
    raw: object,
    inputs: Sequence[Mapping[str, Any]],
    relative: str,
    install_path: str,
    name: str,
    label: str,
) -> dict[str, Any]:
    member = _exact_keys(raw, ATTEMPT_BROKER_MEMBER_KEYS, label)
    matching = [item for item in inputs if item["path"] == relative]
    member_bytes = _exact_int(member["bytes"], f"{label} bytes", minimum=1)
    member_mode = _exact_int(member["mode"], f"{label} mode")
    if (
        len(matching) != 1
        or member["path"] != relative
        or member["path"] != matching[0]["path"]
        or member["sha256"] != matching[0]["sha256"]
        or member_bytes != matching[0]["bytes"]
        or member_mode != matching[0]["mode"]
        or member["install_path"] != install_path
        or member["name"] != name
        or matching[0]["class"] != "tool"
        or member_mode & 0o022
        or not isinstance(member["sha256"], str)
        or not HEX64_RE.fullmatch(member["sha256"])
    ):
        raise DeploymentInputsError(f"{label} identity is not bound to the deployment manifest")
    return member


def _require_artifact_elf(record: FileRecord, product: str) -> dict[str, object]:
    if record.mode & 0o111 == 0:
        raise DeploymentInputsError(f"Winn v3 {product} artifact is not executable")
    architecture, machine, runtime = _artifact_runtime(record.path, product)
    identity = _inspect_elf64(
        record.data,
        expected_machine=machine,
        product=product,
        runtime=runtime,
        require_product_markers=True,
    )
    if identity["sha256"] != record.sha256:
        raise DeploymentInputsError(
            f"Winn v3 {product} artifact digest does not match the file content"
        )
    identity["path"] = record.path
    identity["architecture"] = architecture
    identity["runtime"] = runtime
    return identity


def _require_client_runtime_elf(record: FileRecord, product: str) -> dict[str, object]:
    if product not in CLIENT_RUNTIME_PRODUCTS:
        raise DeploymentInputsError("client-runtime product is not allowed")
    if record.mode & 0o111 == 0:
        raise DeploymentInputsError(f"{product} artifact is not executable")
    if record.mode & 0o022:
        raise DeploymentInputsError(f"{product} artifact is group- or world-writable")
    architecture, machine, runtime = _artifact_runtime(record.path, product)
    if architecture != "amd64" or machine != GATEWAY_MACHINES["amd64"] or runtime != "linux-amd64":
        raise DeploymentInputsError(f"{product} artifact must be Linux amd64")
    identity = _inspect_elf64(
        record.data,
        expected_machine=machine,
        product=product,
        runtime=runtime,
        require_product_markers=False,
    )
    if identity["sha256"] != record.sha256:
        raise DeploymentInputsError(f"{product} artifact digest does not match the file content")
    if (
        identity["architecture"] != "amd64"
        or identity["elf_machine"] != GATEWAY_MACHINES["amd64"]
        or identity["os"] != "linux"
        or identity["runtime"] != "linux-amd64"
        or identity["product"] != product
    ):
        raise DeploymentInputsError(f"{product} artifact ELF identity is not Linux amd64")
    identity["path"] = record.path
    identity["architecture"] = architecture
    identity["runtime"] = runtime
    identity["bytes"] = record.size
    identity["mode"] = record.mode
    return identity


def _require_named_executable(record: FileRecord, product: str) -> dict[str, object]:
    if product in CLIENT_RUNTIME_PRODUCTS:
        return _require_client_runtime_elf(record, product)
    return _require_artifact_elf(record, product)


def _require_gateway_elf(record: FileRecord) -> dict[str, object]:
    return _require_artifact_elf(record, GATEWAY_PRODUCT)


def _collect_snapshot(
    repo: Path, artifact_relatives: Sequence[tuple[str, str]]
) -> dict[str, FileRecord]:
    repo_before = repo.lstat()
    if stat.S_ISLNK(repo_before.st_mode) or not stat.S_ISDIR(repo_before.st_mode):
        raise DeploymentInputsError("repository root was replaced")
    records: list[FileRecord] = []
    records.extend(_walk_tree(repo, "server", "server"))
    records.extend(_walk_tree(repo, "winn_protocol_experimental", "winn"))
    records.extend(_read_regular(repo, path, "router") for path in _router_deployable_paths(repo))
    records.extend(_read_regular(repo, path, file_class) for path, file_class in PROVENANCE_INPUTS)
    if tuple(product for product, _ in artifact_relatives) != ALL_EXECUTABLE_PRODUCTS:
        raise DeploymentInputsError("executable artifact products are incomplete or reordered")
    relative_paths = [relative for _, relative in artifact_relatives]
    if len(set(relative_paths)) != len(ALL_EXECUTABLE_PRODUCTS):
        raise DeploymentInputsError("executable artifact paths must be distinct")
    artifacts: list[FileRecord] = []
    for product, relative in artifact_relatives:
        file_class = CLIENT_RUNTIME_CLASS if product in CLIENT_RUNTIME_PRODUCTS else "artifact"
        artifact = _read_regular(repo, relative, file_class)
        _require_named_executable(artifact, product)
        artifacts.append(artifact)
    if len({artifact.sha256 for artifact in artifacts}) != len(ALL_EXECUTABLE_PRODUCTS):
        raise DeploymentInputsError("executable artifact digests must be distinct")
    records.extend(artifacts)
    result: dict[str, FileRecord] = {}
    for record in records:
        if record.path in result:
            raise DeploymentInputsError(f"duplicate closure path {record.path!r}")
        result[record.path] = record
    repo_after = repo.lstat()
    if _identity(repo_before) != _identity(repo_after):
        raise DeploymentInputsError("repository root changed while collecting inputs")
    return dict(sorted(result.items()))


def _stable_snapshot(
    repo: Path, artifact_relatives: Sequence[tuple[str, str]]
) -> dict[str, FileRecord]:
    first = _collect_snapshot(repo, artifact_relatives)
    second = _collect_snapshot(repo, artifact_relatives)
    if first != second:
        first_paths = set(first)
        second_paths = set(second)
        added = sorted(second_paths - first_paths)
        removed = sorted(first_paths - second_paths)
        detail = []
        if added:
            detail.append(f"added={added}")
        if removed:
            detail.append(f"removed={removed}")
        if not detail:
            detail.append("file content or metadata changed")
        raise DeploymentInputsError("deployment closure mutated during capture: " + "; ".join(detail))
    return first


def _shell_literal(data: bytes, key: str, label: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeploymentInputsError(f"{label} is not UTF-8") from exc
    pattern = re.compile(
        rf"^{re.escape(key)}=(?:\"([^\"\r\n]*)\"|'([^'\r\n]*)'|([A-Za-z0-9_./:@+\-]+))$",
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise DeploymentInputsError(f"{label} must define {key} exactly once as a literal")
    return next(value for value in matches[0] if value != "")


def _extract_external_pins(records: Mapping[str, FileRecord]) -> dict[str, object]:
    awg_record = records["server/build_amneziawg_go_server_image.sh"]
    awg_keys = (
        "AWG_SERVER_IMAGE",
        "AWG_GO_REPOSITORY",
        "AWG_GO_TAG",
        "AWG_GO_COMMIT",
        "AWG_GO_SOURCE_SHA256",
        "AWG_GO_BINARY_SHA256_AMD64",
        "AWG_GO_BINARY_SHA256_ARM64",
        "AWG_TOOLS_REPOSITORY",
        "AWG_TOOLS_TAG",
        "AWG_TOOLS_COMMIT",
        "AWG_TOOLS_SOURCE_SHA256",
        "AWG_QUICK_SHA256",
        "GO_VERSION",
        "GO_ARCHIVE_SHA256_AMD64",
        "GO_ARCHIVE_SHA256_ARM64",
        "ALPINE_VERSION",
        "ALPINE_BASE_DIGEST_AMD64",
        "ALPINE_BASE_DIGEST_ARM64",
    )
    awg = {
        key.lower(): _shell_literal(awg_record.data, key, awg_record.path)
        for key in awg_keys
    }
    for key, value in awg.items():
        if "sha256" in key and not HEX64_RE.fullmatch(_strip_sha256_prefix(value)):
            raise DeploymentInputsError(f"invalid AWG SHA-256 pin {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", str(awg["awg_go_commit"])):
        raise DeploymentInputsError("invalid AWG Go commit pin")
    if not re.fullmatch(r"[0-9a-f]{40}", str(awg["awg_tools_commit"])):
        raise DeploymentInputsError("invalid AWG tools commit pin")
    if awg["awg_go_tag"] != REVIEWED_AWG_GO_TAG or awg["awg_go_commit"] != REVIEWED_AWG_GO_COMMIT:
        raise DeploymentInputsError("AWG Go identity is not the reviewed v3.1.20260828 freeze")
    if (
        awg["awg_tools_tag"] != REVIEWED_AWG_TOOLS_TAG
        or awg["awg_tools_commit"] != REVIEWED_AWG_TOOLS_COMMIT
    ):
        raise DeploymentInputsError("AWG tools identity is not the reviewed v3.1.20260812 freeze")
    if awg["go_version"] != REVIEWED_GO_VERSION:
        raise DeploymentInputsError("AWG Go toolchain is not the reviewed version")

    linux_record = records.get(LINUX_CLIENT_BUILDER)
    if linux_record is None:
        raise DeploymentInputsError("Linux client runtime producer is outside the closure")
    linux_keys = (
        "AWG_GO_TAG",
        "AWG_GO_COMMIT",
        "AWG_GO_SOURCE_SHA256",
        "AWG_GO_BINARY_SHA256",
        "AWG_TOOLS_VERSION",
        "AWG_BINARY_SHA256",
        "AWG_QUICK_SHA256",
        "XRAY_SHA256_AMD64",
        "GO_VERSION",
    )
    linux = {
        key.lower(): _shell_literal(linux_record.data, key, linux_record.path)
        for key in linux_keys
    }
    for key, value in linux.items():
        if "sha256" in key and not HEX64_RE.fullmatch(_strip_sha256_prefix(value)):
            raise DeploymentInputsError(f"invalid Linux client SHA-256 pin {key}")
    if not re.fullmatch(r"[0-9a-f]{40}", str(linux["awg_go_commit"])):
        raise DeploymentInputsError("invalid Linux client AWG Go commit pin")
    if (
        linux["awg_go_tag"] != awg["awg_go_tag"]
        or linux["awg_go_commit"] != awg["awg_go_commit"]
        or linux["awg_go_source_sha256"] != awg["awg_go_source_sha256"]
        or linux["awg_tools_version"] != awg["awg_tools_tag"]
        or linux["awg_quick_sha256"] != awg["awg_quick_sha256"]
        or linux["go_version"] != awg["go_version"]
    ):
        raise DeploymentInputsError("Linux client AWG pins do not match the reviewed server freeze")

    xray_engine = records.get(XRAY_ENGINE_BUILDER)
    if xray_engine is None:
        raise DeploymentInputsError("Xray engine producer is outside the closure")
    xray_repo = _shell_literal(xray_engine.data, "XRAY_REPO", xray_engine.path)
    xray_tag = _shell_literal(xray_engine.data, "XRAY_TAG", xray_engine.path)
    xray_commit = _shell_literal(xray_engine.data, "XRAY_COMMIT", xray_engine.path)
    xray_go = _shell_literal(xray_engine.data, "REVIEWED_GO_VERSION", xray_engine.path)
    if not re.fullmatch(r"[0-9a-f]{40}", xray_commit):
        raise DeploymentInputsError("invalid Xray commit pin")
    if xray_tag != REVIEWED_XRAY_TAG or xray_commit != REVIEWED_XRAY_COMMIT:
        raise DeploymentInputsError("Xray identity is not the reviewed v26.9.30 freeze")
    if xray_go != REVIEWED_GO_VERSION:
        raise DeploymentInputsError("Xray Go toolchain is not the reviewed version")

    xray_record = records["server/wins_data_plane_setup_ONETOUCH.sh"]
    try:
        xray_text = xray_record.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeploymentInputsError("data-plane installer is not UTF-8") from exc
    version_matches = re.findall(
        r'^XRAY_VERSION_DEFAULT="\$\{XRAY_VERSION:-([^}"\r\n]+)\}"$',
        xray_text,
        re.MULTILINE,
    )
    sha_matches = re.findall(
        r'^XRAY_LINUX_64_SHA256_DEFAULT="\$\{XRAY_LINUX_64_SHA256:-([0-9a-f]{64})\}"$',
        xray_text,
        re.MULTILINE,
    )
    if len(version_matches) != 1 or len(sha_matches) != 1:
        raise DeploymentInputsError("data-plane installer must define exact Xray pins once")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", version_matches[0]):
        raise DeploymentInputsError("Xray version pin is invalid")
    if version_matches[0] != REVIEWED_XRAY_VERSION or xray_tag != f"v{version_matches[0]}":
        raise DeploymentInputsError("Xray version is not the reviewed v26.9.30 freeze")

    router_record = records["router/base-image.pin"]
    try:
        pin_lines = [
            line.strip()
            for line in router_record.data.decode("ascii").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except UnicodeDecodeError as exc:
        raise DeploymentInputsError("router base image pin is not ASCII") from exc
    if len(pin_lines) != 1:
        raise DeploymentInputsError("router base-image.pin must contain exactly one image reference")
    image_match = re.fullmatch(
        r"([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9][A-Za-z0-9._-]*)@sha256:([0-9a-f]{64})",
        pin_lines[0],
    )
    if not image_match:
        raise DeploymentInputsError("router base image is not tag-and-digest pinned")
    client_runtime = {
        "amneziawg-go": {
            "architecture": "amd64",
            "commit": str(awg["awg_go_commit"]),
            "os": "linux",
            "product": "amneziawg-go",
            "repository": str(awg["awg_go_repository"]),
            "sha256": str(linux["awg_go_binary_sha256"]),
            "source_sha256": str(awg["awg_go_source_sha256"]),
            "tag": str(awg["awg_go_tag"]),
        },
        "awg": {
            "architecture": "amd64",
            "commit": str(awg["awg_tools_commit"]),
            "os": "linux",
            "product": "awg",
            "repository": str(awg["awg_tools_repository"]),
            "sha256": str(linux["awg_binary_sha256"]),
            "source_sha256": str(awg["awg_tools_source_sha256"]),
            "tag": str(awg["awg_tools_tag"]),
        },
        "xray": {
            "architecture": "amd64",
            "commit": xray_commit,
            "os": "linux",
            "product": "xray",
            "repository": xray_repo,
            "sha256": str(linux["xray_sha256_amd64"]),
            "source_sha256": xray_commit,
            "tag": xray_tag,
        },
    }
    if [item["product"] for item in client_runtime.values()] != list(CLIENT_RUNTIME_PRODUCTS):
        raise DeploymentInputsError("client-runtime pin products are incomplete or reordered")
    if len({item["sha256"] for item in client_runtime.values()}) != len(CLIENT_RUNTIME_PRODUCTS):
        raise DeploymentInputsError("client-runtime pin digests must be distinct")
    return {
        "awg": awg,
        "client_runtime": client_runtime,
        "router_base_image": {
            "digest": f"sha256:{image_match.group(3)}",
            "reference": pin_lines[0],
            "repository": image_match.group(1),
            "tag": image_match.group(2),
        },
        "xray": {
            "commit": xray_commit,
            "linux_amd64_archive_sha256": sha_matches[0],
            "linux_amd64_executable_sha256": str(linux["xray_sha256_amd64"]),
            "release_asset": f"Xray-linux-64.zip",
            "release_url": (
                "https://github.com/XTLS/Xray-core/releases/download/"
                f"v{version_matches[0]}/Xray-linux-64.zip"
            ),
            "repository": xray_repo,
            "tag": xray_tag,
            "version": version_matches[0],
        },
    }


def _parse_created(value: str | None) -> str:
    if value is None:
        return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    if not CREATED_RE.fullmatch(value):
        raise DeploymentInputsError("created_utc must be RFC3339 UTC with whole seconds")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DeploymentInputsError(
            "created_utc must be a real RFC3339 UTC timestamp"
        ) from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise DeploymentInputsError("created_utc is not canonical")
    return value


def _artifact_relative(repo: Path, artifact: Path, product: str = GATEWAY_PRODUCT) -> str:
    candidate = artifact.expanduser().absolute()
    try:
        relative = candidate.relative_to(repo).as_posix()
    except ValueError as exc:
        raise DeploymentInputsError(f"{product} artifact must be inside the repository") from exc
    return _validate_relative_path(relative, f"{product} artifact")


def _proof_client_artifact_relatives(
    repo: Path,
    winn3_gateway_artifact: Path,
    winn3_probe_artifact: Path,
    winn_ech_keygen_artifact: Path,
) -> tuple[tuple[str, str], ...]:
    paths = (
        winn3_gateway_artifact,
        winn3_probe_artifact,
        winn_ech_keygen_artifact,
    )
    artifact_relatives = tuple(
        (product, _artifact_relative(repo, path, product))
        for product, path in _strict_zip(PROOF_CLIENT_PRODUCTS, paths, "proof-client artifact")
    )
    if len({relative for _, relative in artifact_relatives}) != len(PROOF_CLIENT_PRODUCTS):
        raise DeploymentInputsError("proof-client artifact paths must be distinct")
    return artifact_relatives


def _client_runtime_artifact_relatives(
    repo: Path,
    amneziawg_go_artifact: Path,
    awg_artifact: Path,
    xray_artifact: Path,
) -> tuple[tuple[str, str], ...]:
    paths = (
        amneziawg_go_artifact,
        awg_artifact,
        xray_artifact,
    )
    artifact_relatives = tuple(
        (product, _artifact_relative(repo, path, product))
        for product, path in _strict_zip(
            CLIENT_RUNTIME_PRODUCTS, paths, "client-runtime artifact"
        )
    )
    if len({relative for _, relative in artifact_relatives}) != len(CLIENT_RUNTIME_PRODUCTS):
        raise DeploymentInputsError("client-runtime artifact paths must be distinct")
    return artifact_relatives


def _all_executable_relatives(
    repo: Path,
    winn3_gateway_artifact: Path,
    winn3_probe_artifact: Path,
    winn_ech_keygen_artifact: Path,
    amneziawg_go_artifact: Path,
    awg_artifact: Path,
    xray_artifact: Path,
) -> tuple[tuple[str, str], ...]:
    combined = _proof_client_artifact_relatives(
        repo,
        winn3_gateway_artifact,
        winn3_probe_artifact,
        winn_ech_keygen_artifact,
    ) + _client_runtime_artifact_relatives(
        repo,
        amneziawg_go_artifact,
        awg_artifact,
        xray_artifact,
    )
    if len({relative for _, relative in combined}) != len(ALL_EXECUTABLE_PRODUCTS):
        raise DeploymentInputsError("executable artifact paths must be distinct")
    if tuple(product for product, _ in combined) != ALL_EXECUTABLE_PRODUCTS:
        raise DeploymentInputsError("executable artifact products are incomplete or reordered")
    return combined


def _client_runtime_provenance(pin: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(pin, Mapping):
        raise DeploymentInputsError("client-runtime provenance is malformed")
    try:
        record = _exact_keys(
            {
                "commit": pin["commit"],
                "repository": pin["repository"],
                "source_sha256": pin["source_sha256"],
                "tag": pin["tag"],
            },
            CLIENT_RUNTIME_PROVENANCE_KEYS,
            "client-runtime provenance",
        )
    except KeyError as exc:
        raise DeploymentInputsError("client-runtime provenance is incomplete") from exc
    if type(record["repository"]) is not str or not record["repository"]:
        raise DeploymentInputsError("client-runtime repository is invalid")
    if type(record["tag"]) is not str or not record["tag"]:
        raise DeploymentInputsError("client-runtime tag is invalid")
    if type(record["commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", record["commit"]):
        raise DeploymentInputsError("client-runtime commit is invalid")
    digest = record["source_sha256"]
    if type(digest) is not str or not (
        HEX64_RE.fullmatch(digest) or re.fullmatch(r"[0-9a-f]{40}", digest)
    ):
        raise DeploymentInputsError("client-runtime source hash is invalid")
    return record


def _bind_client_runtime_artifacts(
    records: Mapping[str, FileRecord],
    runtime_relatives: Sequence[tuple[str, str]],
    pins: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    if tuple(product for product, _ in runtime_relatives) != CLIENT_RUNTIME_PRODUCTS:
        raise DeploymentInputsError("client-runtime artifacts are incomplete or reordered")
    if set(pins) != set(CLIENT_RUNTIME_PRODUCTS):
        raise DeploymentInputsError("client-runtime pins are incomplete")
    bound: list[dict[str, object]] = []
    for product, relative in runtime_relatives:
        record = records.get(relative)
        if record is None or record.file_class != CLIENT_RUNTIME_CLASS:
            raise DeploymentInputsError(f"{product} artifact is outside the closure")
        identity = _require_client_runtime_elf(record, product)
        pin = pins[product]
        if (
            pin["product"] != product
            or pin["os"] != "linux"
            or pin["architecture"] != "amd64"
            or pin["sha256"] != identity["sha256"]
            or pin["sha256"] != record.sha256
        ):
            raise DeploymentInputsError(
                f"{product} artifact is unproven against the reviewed Linux amd64 pin"
            )
        provenance = _client_runtime_provenance(pin)
        identity["provenance"] = provenance
        bound.append(identity)
    if (
        len({item["path"] for item in bound}) != len(CLIENT_RUNTIME_PRODUCTS)
        or len({item["sha256"] for item in bound}) != len(CLIENT_RUNTIME_PRODUCTS)
        or len({item["product"] for item in bound}) != len(CLIENT_RUNTIME_PRODUCTS)
    ):
        raise DeploymentInputsError("client-runtime artifact paths, digests, and products must be distinct")
    if {item["architecture"] for item in bound} != {"amd64"} or {
        int(item["elf_machine"]) for item in bound
    } != {GATEWAY_MACHINES["amd64"]}:
        raise DeploymentInputsError("client-runtime artifacts must be Linux amd64")
    return bound


def build_manifest(
    repo_root: Path,
    winn3_gateway_artifact: Path,
    winn3_probe_artifact: Path,
    winn_ech_keygen_artifact: Path,
    amneziawg_go_artifact: Path,
    awg_artifact: Path,
    xray_artifact: Path,
    *,
    created_utc: str | None = None,
) -> dict[str, object]:
    _authenticate_compatible_runtime()
    repo = _secure_absolute_dir(repo_root, "repository root")
    artifact_relatives = _all_executable_relatives(
        repo,
        winn3_gateway_artifact,
        winn3_probe_artifact,
        winn_ech_keygen_artifact,
        amneziawg_go_artifact,
        awg_artifact,
        xray_artifact,
    )
    records = _stable_snapshot(repo, artifact_relatives)
    installer_records: list[dict[str, object]] = []
    for path in INSTALLERS:
        record = records.get(path)
        if record is None:
            raise DeploymentInputsError(f"required installer {path!r} is outside the closure")
        if record.mode & 0o022:
            raise DeploymentInputsError(
                f"required installer {path!r} is group- or world-writable"
            )
        installer_records.append(
            {
                "bytes": record.size,
                "mode": record.mode,
                "path": record.path,
                "sha256": record.sha256,
            }
        )
    proof_relatives = artifact_relatives[: len(PROOF_CLIENT_PRODUCTS)]
    runtime_relatives = artifact_relatives[len(PROOF_CLIENT_PRODUCTS) :]
    proof_client_artifacts = [
        _require_artifact_elf(records[relative], product)
        for product, relative in proof_relatives
    ]
    architectures = {str(artifact["architecture"]) for artifact in proof_client_artifacts}
    machines = {int(artifact["elf_machine"]) for artifact in proof_client_artifacts}
    digests = {str(artifact["sha256"]) for artifact in proof_client_artifacts}
    if len(architectures) != 1 or len(machines) != 1:
        raise DeploymentInputsError("proof-client artifacts must use one architecture and ELF machine")
    if len(digests) != len(PROOF_CLIENT_PRODUCTS):
        raise DeploymentInputsError("proof-client artifact digests must be distinct")
    gateway_artifact = dict(proof_client_artifacts[0])
    helper = records.get(REMOTE_ACTION_HELPER_PATH)
    if helper is None:
        raise DeploymentInputsError("remote proof-action helper is outside the closure")
    remote_action_helper = _require_remote_action_helper(helper)
    broker = records.get(ATTEMPT_BROKER_PATH)
    if broker is None:
        raise DeploymentInputsError("protocol-attempt broker is outside the closure")
    attempt_broker = _require_attempt_broker(broker, records)
    external_pins = _extract_external_pins(records)
    client_runtime_pins = external_pins["client_runtime"]
    if not isinstance(client_runtime_pins, dict):
        raise DeploymentInputsError("client-runtime pins are malformed")
    client_runtime_artifacts = _bind_client_runtime_artifacts(
        records,
        runtime_relatives,
        client_runtime_pins,
    )
    if {item["sha256"] for item in client_runtime_artifacts} & digests:
        raise DeploymentInputsError("client-runtime artifacts reuse a proof-client digest")
    if {item["path"] for item in client_runtime_artifacts} & {
        item["path"] for item in proof_client_artifacts
    }:
        raise DeploymentInputsError("client-runtime artifacts reuse a proof-client path")
    timestamp_free: dict[str, object] = {
        "attempt_broker": attempt_broker,
        "client_runtime_artifacts": client_runtime_artifacts,
        "closure_policy": CLOSURE_POLICY,
        "external_pins": external_pins,
        "gateway_artifact": gateway_artifact,
        "inputs": [record.manifest_record() for record in records.values()],
        "installers": installer_records,
        "kind": KIND,
        "publication_authorized": False,
        "proof_client_artifacts": proof_client_artifacts,
        "remote_action_helper": remote_action_helper,
        "schema_version": SCHEMA_VERSION,
        "scope_roots": list(SCOPE_ROOTS),
    }
    candidate_id = _sha256(canonical_bytes(timestamp_free))
    return {
        **timestamp_free,
        "candidate_id": candidate_id,
        "created_utc": _parse_created(created_utc),
    }


def _secure_output(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    if candidate.name != "DEPLOYMENT_INPUTS.json":
        raise DeploymentInputsError("manifest filename must be DEPLOYMENT_INPUTS.json")
    parent = _secure_absolute_dir(candidate.parent, "manifest parent")
    if candidate.parent != parent:
        raise DeploymentInputsError("manifest parent is not canonical")
    return candidate


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except FileExistsError as exc:
        raise DeploymentInputsError(f"refusing to overwrite immutable file {path}") from exc
    except OSError as exc:
        raise DeploymentInputsError(f"unable to write immutable file {path}") from exc


def create_manifest(
    repo_root: Path,
    output: Path,
    winn3_gateway_artifact: Path,
    winn3_probe_artifact: Path,
    winn_ech_keygen_artifact: Path,
    amneziawg_go_artifact: Path,
    awg_artifact: Path,
    xray_artifact: Path,
    *,
    created_utc: str | None = None,
) -> dict[str, object]:
    _authenticate_compatible_runtime()
    repo = _secure_absolute_dir(repo_root, "repository root")
    destination = _secure_output(output)
    if destination == repo or repo in destination.parents:
        raise DeploymentInputsError("DEPLOYMENT_INPUTS.json must be outside the repository closure")
    record = build_manifest(
        repo,
        winn3_gateway_artifact,
        winn3_probe_artifact,
        winn_ech_keygen_artifact,
        amneziawg_go_artifact,
        awg_artifact,
        xray_artifact,
        created_utc=created_utc,
    )
    payload = canonical_bytes(record)
    anchor = destination.with_name(destination.name + ".sha256")
    if destination.exists() or anchor.exists():
        raise DeploymentInputsError("refusing to overwrite immutable manifest or sidecar")
    _write_new(destination, payload)
    _write_new(anchor, f"{_sha256(payload)}  {destination.name}\n".encode("ascii"))
    return record


def _read_immutable(path: Path, label: str) -> bytes:
    candidate = path.expanduser().absolute()
    fd = -1
    try:
        before = candidate.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise DeploymentInputsError(
                f"{label} must be an immutable regular non-symlink file"
            )
        fd = os.open(
            candidate,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(fd)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        finished = os.fstat(fd)
        after = candidate.lstat()
    except DeploymentInputsError:
        raise
    except OSError as exc:
        raise DeploymentInputsError(f"{label} is unreadable") from exc
    finally:
        if fd >= 0:
            os.close(fd)
    if not all(_identity(before) == _identity(item) for item in (opened, finished, after)):
        raise DeploymentInputsError(f"{label} changed while being read")
    data = b"".join(chunks)
    if not data:
        raise DeploymentInputsError(f"{label} is empty")
    return data


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise DeploymentInputsError(f"{label} schema fields are invalid")
    return value


def _validate_manifest_schema(value: object) -> dict[str, Any]:
    record = _exact_keys(
        value,
        {
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
        },
        "deployment manifest",
    )
    if (
        record["kind"] != KIND
        or type(record["schema_version"]) is not int
        or record["schema_version"] != SCHEMA_VERSION
        or record["closure_policy"] != CLOSURE_POLICY
        or record["scope_roots"] != list(SCOPE_ROOTS)
        or type(record["publication_authorized"]) is not bool
        or record["publication_authorized"] is not False
    ):
        raise DeploymentInputsError("deployment manifest policy fields are invalid")
    if not isinstance(record["created_utc"], str):
        raise DeploymentInputsError("deployment manifest created_utc is invalid")
    _parse_created(record["created_utc"])
    if not isinstance(record["candidate_id"], str) or not HEX64_RE.fullmatch(
        record["candidate_id"]
    ):
        raise DeploymentInputsError("deployment manifest candidate_id is invalid")
    inputs = record["inputs"]
    if not isinstance(inputs, list) or not inputs:
        raise DeploymentInputsError("deployment manifest inputs are empty")
    seen: set[str] = set()
    parsed_paths: list[str] = []
    for index, raw in enumerate(inputs):
        item = _exact_keys(raw, {"bytes", "class", "mode", "path", "sha256"}, f"input {index}")
        path = _validate_relative_path(item["path"], f"input {index} path")
        if path in seen:
            raise DeploymentInputsError(f"duplicate manifest input path {path!r}")
        seen.add(path)
        parsed_paths.append(path)
        if item["class"] not in {
            "artifact",
            CLIENT_RUNTIME_CLASS,
            "provenance",
            "router",
            "server",
            "tool",
            "winn",
        }:
            raise DeploymentInputsError(f"input {index} class is invalid")
        if type(item["bytes"]) is not int or item["bytes"] <= 0:
            raise DeploymentInputsError(f"input {index} byte count is invalid")
        if type(item["mode"]) is not int or not 0 <= item["mode"] <= 0o7777:
            raise DeploymentInputsError(f"input {index} mode is invalid")
        if not isinstance(item["sha256"], str) or not HEX64_RE.fullmatch(item["sha256"]):
            raise DeploymentInputsError(f"input {index} SHA-256 is invalid")
    if parsed_paths != sorted(parsed_paths):
        raise DeploymentInputsError("deployment manifest inputs are not sorted")
    installers = record["installers"]
    if not isinstance(installers, list) or len(installers) != len(INSTALLERS):
        raise DeploymentInputsError("deployment installer list is incomplete")
    for index, (raw, expected_path) in enumerate(
        _strict_zip(installers, INSTALLERS, "deployment installer")
    ):
        item = _exact_keys(raw, {"bytes", "mode", "path", "sha256"}, f"installer {index}")
        if item["path"] != expected_path:
            raise DeploymentInputsError("deployment installers are missing, reordered, or duplicated")
        matching = next((entry for entry in inputs if entry["path"] == expected_path), None)
        if matching is None or any(item[key] != matching[key] for key in ("bytes", "mode", "sha256")):
            raise DeploymentInputsError(f"installer {expected_path!r} does not match its closure input")
        if type(item["mode"]) is not int or item["mode"] & 0o022:
            raise DeploymentInputsError(
                f"installer {expected_path!r} is group- or world-writable"
            )
    artifact_items = [item for item in inputs if item["class"] == "artifact"]
    if len(artifact_items) != len(PROOF_CLIENT_PRODUCTS):
        raise DeploymentInputsError("manifest must bind exactly three proof-client artifacts")
    raw_proof_artifacts = record["proof_client_artifacts"]
    if not isinstance(raw_proof_artifacts, list) or len(raw_proof_artifacts) != len(
        PROOF_CLIENT_PRODUCTS
    ):
        raise DeploymentInputsError("proof_client_artifacts schema is incomplete")
    proof_artifacts: list[dict[str, Any]] = []
    for index, (raw, product) in enumerate(
        _strict_zip(raw_proof_artifacts, PROOF_CLIENT_PRODUCTS, "proof-client artifact")
    ):
        artifact = _exact_keys(
            raw,
            PROOF_CLIENT_ARTIFACT_KEYS,
            f"proof-client artifact {index}",
        )
        architecture, machine, runtime = _artifact_runtime(str(artifact["path"]), product)
        elf_class = _exact_int(artifact["elf_class"], f"{product} elf_class")
        elf_data = _exact_int(artifact["elf_data"], f"{product} elf_data")
        elf_machine = _exact_int(artifact["elf_machine"], f"{product} elf_machine")
        elf_type = _exact_int(artifact["elf_type"], f"{product} elf_type")
        _exact_int(artifact["entry"], f"{product} entry", minimum=1)
        matching = [item for item in artifact_items if item["path"] == artifact["path"]]
        if (
            len(matching) != 1
            or artifact["sha256"] != matching[0]["sha256"]
            or artifact["product"] != product
            or artifact["os"] != "linux"
            or artifact["architecture"] != architecture
            or artifact["runtime"] != runtime
            or elf_class != ELF_CLASS_64
            or elf_data != ELF_DATA_LSB
            or elf_machine != machine
            or elf_type not in {ET_EXEC, ET_DYN}
            or not isinstance(artifact["sha256"], str)
            or not HEX64_RE.fullmatch(artifact["sha256"])
        ):
            raise DeploymentInputsError(
                f"{product} artifact identity is not bound to the deployment manifest"
            )
        proof_artifacts.append(artifact)
    if (
        len({artifact["path"] for artifact in proof_artifacts}) != len(PROOF_CLIENT_PRODUCTS)
        or len({artifact["sha256"] for artifact in proof_artifacts}) != len(PROOF_CLIENT_PRODUCTS)
        or len({artifact["product"] for artifact in proof_artifacts}) != len(PROOF_CLIENT_PRODUCTS)
    ):
        raise DeploymentInputsError("proof-client artifact paths, digests, and products must be distinct")
    if (
        {artifact["architecture"] for artifact in proof_artifacts}
        != {proof_artifacts[0]["architecture"]}
        or {artifact["elf_machine"] for artifact in proof_artifacts}
        != {proof_artifacts[0]["elf_machine"]}
    ):
        raise DeploymentInputsError("proof-client artifacts are not architecture-matched")
    if {item["path"] for item in artifact_items} != {
        artifact["path"] for artifact in proof_artifacts
    }:
        raise DeploymentInputsError("manifest contains an extra or reused proof-client artifact")
    gateway = _exact_keys(record["gateway_artifact"], GATEWAY_ARTIFACT_KEYS, "gateway artifact")
    _gateway_runtime(str(gateway["path"]))
    _exact_int(gateway["elf_class"], "gateway elf_class")
    _exact_int(gateway["elf_data"], "gateway elf_data")
    _exact_int(gateway["elf_machine"], "gateway elf_machine")
    _exact_int(gateway["elf_type"], "gateway elf_type")
    _exact_int(gateway["entry"], "gateway entry", minimum=1)
    if gateway != proof_artifacts[0]:
        raise DeploymentInputsError("gateway compatibility artifact is not bound to proof_client_artifacts")
    runtime_items = [item for item in inputs if item["class"] == CLIENT_RUNTIME_CLASS]
    if len(runtime_items) != len(CLIENT_RUNTIME_PRODUCTS):
        raise DeploymentInputsError("manifest must bind exactly three client-runtime artifacts")
    raw_runtime_artifacts = record["client_runtime_artifacts"]
    if not isinstance(raw_runtime_artifacts, list) or len(raw_runtime_artifacts) != len(
        CLIENT_RUNTIME_PRODUCTS
    ):
        raise DeploymentInputsError("client_runtime_artifacts schema is incomplete")
    runtime_artifacts: list[dict[str, Any]] = []
    for index, (raw, product) in enumerate(
        _strict_zip(raw_runtime_artifacts, CLIENT_RUNTIME_PRODUCTS, "client-runtime artifact")
    ):
        artifact = _exact_keys(
            raw,
            CLIENT_RUNTIME_ARTIFACT_KEYS,
            f"client-runtime artifact {index}",
        )
        architecture, machine, runtime = _artifact_runtime(str(artifact["path"]), product)
        elf_class = _exact_int(artifact["elf_class"], f"{product} elf_class")
        elf_data = _exact_int(artifact["elf_data"], f"{product} elf_data")
        elf_machine = _exact_int(artifact["elf_machine"], f"{product} elf_machine")
        elf_type = _exact_int(artifact["elf_type"], f"{product} elf_type")
        _exact_int(artifact["entry"], f"{product} entry", minimum=1)
        artifact_bytes = _exact_int(artifact["bytes"], f"{product} bytes", minimum=1)
        artifact_mode = _exact_int(artifact["mode"], f"{product} mode")
        matching = [item for item in runtime_items if item["path"] == artifact["path"]]
        provenance = _client_runtime_provenance(artifact["provenance"])
        if (
            len(matching) != 1
            or artifact["sha256"] != matching[0]["sha256"]
            or artifact_bytes != matching[0]["bytes"]
            or artifact_mode != matching[0]["mode"]
            or artifact["product"] != product
            or artifact["os"] != "linux"
            or artifact["architecture"] != "amd64"
            or artifact["architecture"] != architecture
            or artifact["runtime"] != "linux-amd64"
            or artifact["runtime"] != runtime
            or elf_class != ELF_CLASS_64
            or elf_data != ELF_DATA_LSB
            or elf_machine != GATEWAY_MACHINES["amd64"]
            or elf_machine != machine
            or elf_type not in {ET_EXEC, ET_DYN}
            or artifact_mode & 0o111 == 0
            or artifact_mode & 0o022
            or not isinstance(artifact["sha256"], str)
            or not HEX64_RE.fullmatch(artifact["sha256"])
        ):
            raise DeploymentInputsError(
                f"{product} client-runtime identity is not bound to the deployment manifest"
            )
        artifact["provenance"] = provenance
        runtime_artifacts.append(artifact)
    if (
        len({item["path"] for item in runtime_artifacts}) != len(CLIENT_RUNTIME_PRODUCTS)
        or len({item["sha256"] for item in runtime_artifacts}) != len(CLIENT_RUNTIME_PRODUCTS)
        or len({item["product"] for item in runtime_artifacts}) != len(CLIENT_RUNTIME_PRODUCTS)
    ):
        raise DeploymentInputsError(
            "client-runtime artifact paths, digests, and products must be distinct"
        )
    if {item["path"] for item in runtime_items} != {
        item["path"] for item in runtime_artifacts
    }:
        raise DeploymentInputsError("manifest contains an extra or reused client-runtime artifact")
    if {item["path"] for item in runtime_artifacts} & {
        item["path"] for item in proof_artifacts
    } or {item["sha256"] for item in runtime_artifacts} & {
        item["sha256"] for item in proof_artifacts
    }:
        raise DeploymentInputsError("client-runtime artifacts reuse a proof-client path or digest")
    helper_items = [item for item in inputs if item["path"] == REMOTE_ACTION_HELPER_PATH]
    if len(helper_items) != 1:
        raise DeploymentInputsError("manifest must bind the remote proof-action helper")
    helper_input = helper_items[0]
    helper = _exact_keys(record["remote_action_helper"], REMOTE_ACTION_HELPER_KEYS, "remote action helper")
    helper_schema = _exact_int(helper["schema_version"], "remote action helper schema_version")
    helper_mode = _exact_int(helper["mode"], "remote action helper mode")
    helper_bytes = _exact_int(helper["bytes"], "remote action helper bytes", minimum=1)
    if (
        helper["path"] != REMOTE_ACTION_HELPER_PATH
        or helper["path"] != helper_input["path"]
        or helper["sha256"] != helper_input["sha256"]
        or helper_bytes != helper_input["bytes"]
        or helper_mode != helper_input["mode"]
        or helper["contract"] != REMOTE_ACTION_HELPER_CONTRACT
        or helper["install_path"] != REMOTE_ACTION_HELPER_INSTALL_PATH
        or helper["required_roles"] != list(REMOTE_ACTION_HELPER_REQUIRED_ROLES)
        or helper_schema != SCHEMA_VERSION
        or helper_mode & 0o022
        or helper_input["class"] != "tool"
        or not isinstance(helper["sha256"], str)
        or not HEX64_RE.fullmatch(helper["sha256"])
    ):
        raise DeploymentInputsError("remote proof-action helper identity is not bound to the deployment manifest")
    broker_items = [item for item in inputs if item["path"] == ATTEMPT_BROKER_PATH]
    if len(broker_items) != 1:
        raise DeploymentInputsError("manifest must bind the protocol-attempt broker")
    broker_input = broker_items[0]
    broker = _exact_keys(record["attempt_broker"], ATTEMPT_BROKER_KEYS, "attempt broker")
    broker_schema = _exact_int(broker["schema_version"], "attempt broker schema_version")
    broker_mode = _exact_int(broker["mode"], "attempt broker mode")
    broker_bytes = _exact_int(broker["bytes"], "attempt broker bytes", minimum=1)
    if (
        broker["path"] != ATTEMPT_BROKER_PATH
        or broker["path"] != broker_input["path"]
        or broker["sha256"] != broker_input["sha256"]
        or broker_bytes != broker_input["bytes"]
        or broker_mode != broker_input["mode"]
        or broker["contract"] != ATTEMPT_BROKER_CONTRACT
        or broker["install_path"] != ATTEMPT_BROKER_INSTALL_PATH
        or broker["required_roles"] != list(ATTEMPT_BROKER_REQUIRED_ROLES)
        or broker_schema != SCHEMA_VERSION
        or broker_mode & 0o022
        or broker_input["class"] != "tool"
        or not isinstance(broker["sha256"], str)
        or not HEX64_RE.fullmatch(broker["sha256"])
    ):
        raise DeploymentInputsError(
            "protocol-attempt broker identity is not bound to the deployment manifest"
        )
    _validate_attempt_member(
        broker["socket"],
        inputs,
        ATTEMPT_BROKER_SOCKET_SOURCE,
        ATTEMPT_BROKER_SOCKET_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.socket",
        "attempt broker socket",
    )
    _validate_attempt_member(
        broker["service"],
        inputs,
        ATTEMPT_BROKER_SERVICE_SOURCE,
        ATTEMPT_BROKER_SERVICE_INSTALL_PATH,
        "winsvpn-gcp-proof-attempt-broker.service",
        "attempt broker service",
    )
    raw_units = broker["units"]
    if not isinstance(raw_units, list) or len(raw_units) != len(ATTEMPT_BROKER_UNITS):
        raise DeploymentInputsError("attempt broker units schema is incomplete")
    for raw_unit, (relative, install_path, name) in _strict_zip(
        raw_units, ATTEMPT_BROKER_UNITS, "attempt broker unit"
    ):
        _validate_attempt_member(
            raw_unit, inputs, relative, install_path, name, f"attempt unit {name}"
        )
    raw_configs = broker["configs"]
    if not isinstance(raw_configs, list) or len(raw_configs) != len(ATTEMPT_BROKER_CONFIGS):
        raise DeploymentInputsError("attempt broker configs schema is incomplete")
    for raw_config, (relative, install_path, name) in _strict_zip(
        raw_configs, ATTEMPT_BROKER_CONFIGS, "attempt broker config"
    ):
        _validate_attempt_member(
            raw_config, inputs, relative, install_path, name, f"attempt config {name}"
        )
    pins = _exact_keys(
        record["external_pins"],
        {"awg", "client_runtime", "router_base_image", "xray"},
        "external pins",
    )
    raw_runtime_pins = pins["client_runtime"]
    if not isinstance(raw_runtime_pins, dict) or list(raw_runtime_pins) != list(
        CLIENT_RUNTIME_PRODUCTS
    ):
        raise DeploymentInputsError("client-runtime pins are incomplete or reordered")
    for product, artifact in zip(CLIENT_RUNTIME_PRODUCTS, runtime_artifacts):
        pin = raw_runtime_pins[product]
        if not isinstance(pin, dict):
            raise DeploymentInputsError(f"{product} client-runtime pin is malformed")
        if pin.get("sha256") != artifact["sha256"] or pin.get("product") != product:
            raise DeploymentInputsError(
                f"{product} artifact is unproven against the reviewed Linux amd64 pin"
            )
        if artifact["provenance"] != _client_runtime_provenance(pin):
            raise DeploymentInputsError(f"{product} provenance is not bound to the reviewed pin")
    timestamp_free = {
        key: item for key, item in record.items() if key not in {"candidate_id", "created_utc"}
    }
    if _sha256(canonical_bytes(timestamp_free)) != record["candidate_id"]:
        raise DeploymentInputsError("candidate_id does not match the timestamp-free payload")
    return record


def verify_manifest(repo_root: Path, manifest: Path) -> dict[str, object]:
    _authenticate_compatible_runtime()
    repo = _secure_absolute_dir(repo_root, "repository root")
    manifest_path = _secure_output(manifest)
    if manifest_path == repo or repo in manifest_path.parents:
        raise DeploymentInputsError("DEPLOYMENT_INPUTS.json must be outside the repository closure")
    payload = _read_immutable(manifest_path, "deployment manifest")
    anchor_path = manifest_path.with_name(manifest_path.name + ".sha256")
    anchor = _read_immutable(anchor_path, "deployment manifest sidecar")
    expected_anchor = f"{_sha256(payload)}  {manifest_path.name}\n".encode("ascii")
    if anchor != expected_anchor:
        raise DeploymentInputsError("deployment manifest SHA-256 sidecar is invalid")
    record = _validate_manifest_schema(_strict_json(payload, "deployment manifest"))
    if payload != canonical_bytes(record):
        raise DeploymentInputsError("deployment manifest is not canonical ASCII JSON")
    artifact_paths = [Path(item["path"]) for item in record["proof_client_artifacts"]]
    runtime_paths = [Path(item["path"]) for item in record["client_runtime_artifacts"]]
    expected = build_manifest(
        repo,
        repo / artifact_paths[0],
        repo / artifact_paths[1],
        repo / artifact_paths[2],
        repo / runtime_paths[0],
        repo / runtime_paths[1],
        repo / runtime_paths[2],
        created_utc=record["created_utc"],
    )
    if expected != record:
        raise DeploymentInputsError("deployment manifest no longer matches the complete closure")
    return record


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create", help="create a new immutable manifest")
    create.add_argument("--repo-root", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--winn3-gateway-artifact", type=Path, required=True)
    create.add_argument("--winn3-probe-artifact", type=Path, required=True)
    create.add_argument("--winn-ech-keygen-artifact", type=Path, required=True)
    create.add_argument("--amneziawg-go-artifact", type=Path, required=True)
    create.add_argument("--awg-artifact", type=Path, required=True)
    create.add_argument("--xray-artifact", type=Path, required=True)
    verify = subparsers.add_parser("verify", help="verify a manifest and live closure")
    verify.add_argument("--repo-root", type=Path, required=True)
    verify.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        _authenticate_compatible_runtime()
        if args.command == "create":
            record = create_manifest(
                args.repo_root,
                args.output,
                args.winn3_gateway_artifact,
                args.winn3_probe_artifact,
                args.winn_ech_keygen_artifact,
                args.amneziawg_go_artifact,
                args.awg_artifact,
                args.xray_artifact,
            )
            print(
                f"PASS created {args.output.absolute()} candidate_id={record['candidate_id']}"
            )
        else:
            record = verify_manifest(args.repo_root, args.manifest)
            print(
                f"PASS verified {args.manifest.absolute()} candidate_id={record['candidate_id']}"
            )
    except DeploymentInputsError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
