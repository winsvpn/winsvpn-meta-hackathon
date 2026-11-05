#!/usr/bin/env python3
"""Fixed external owner boundary for ReleasePython receipt migration.

This file is installed, reviewed, hashed, root-owned, single-link, mode 0555,
and SF_IMMUTABLE at the fixed owner boundary.  It does not mint authority,
authorization, receipt, or repository trust.  It consumes one externally
signed authorization and performs a recoverable two-file publication.

Repository code may prepare a candidate migration plan.  Only this fixed
boundary may publish it, and only after binding the immutable external
authority, the current receipt, the signed authorization, the exact 17-file
repository closure, the running boundary bytes, and the candidate runtime.
"""

from __future__ import annotations

import argparse
import ast
import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import secrets
import select
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Iterable, Optional


AUTHORITY_PATH = Path("/Library/WinsVPN/ReleasePythonAuthority/v2/authority.json")
OWNER_PROVISION_PATH = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision"
)
OWNER_LAUNCHER_PATH = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher"
)
JOURNAL_PATH = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision.transaction.json"
)
JOURNAL_NEXT_PATH = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision.transaction.next"
)
INITIAL_AUTHORITY_JOURNAL_NAME = "owner-provision.authority-publish.json"
INITIAL_AUTHORITY_JOURNAL_NEXT_NAME = "owner-provision.authority-publish.next"
RECEIPT_PATH = Path("/Library/WinsVPN/ReleasePython/3.14.7.receipt.json")
RUNTIME_PATH = Path("/Library/WinsVPN/ReleasePython/3.14.7")
RUNTIME_PYTHON = RUNTIME_PATH / "Python.framework/Versions/3.14/bin/python3.14"
RUNTIME_APP_PYTHON = (
    RUNTIME_PATH
    / "Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python"
)
RUNTIME_LAUNCHER = RUNTIME_PATH / "launcher/python3.14"
RUNTIME_LAUNCHER_ALIAS = RUNTIME_PATH / "launcher/python3"
PIN_MANIFEST_RELATIVE = "tools/toolchain-pins.json"
RECEIPT_SCHEMA_RELATIVE = "tools/macos_release_python_runtime_receipt.py"

AUTHORITY_CONTRACT = "winsvpn-macos-release-python-runtime-receipt-authority-v2"
PLAN_CONTRACT = "winsvpn-macos-release-python-runtime-receipt-migration-v2"
RECEIPT_CONTRACT = "winsvpn-macos-release-python-runtime-v2"
AUTHORIZATION_CONTRACT = (
    "winsvpn-macos-release-python-owner-provision-authorization-v2"
)
AUTHORIZATION_ENVELOPE_CONTRACT = (
    "winsvpn-macos-release-python-owner-provision-envelope-v2"
)
JOURNAL_CONTRACT = "winsvpn-macos-release-python-owner-provision-journal-v1"
ALGORITHM = "ed25519"
AUTHORITY_ALGORITHM = "external-owner-approval-v1"
DOMAIN = b"WINSVPN-MACOS-RELEASE-PYTHON-OWNER-PROVISION-V2\0"
INITIAL_AUTHORITY_DOMAIN = (
    b"WINSVPN-MACOS-RELEASE-PYTHON-INITIAL-AUTHORITY-V2\0"
)
INITIAL_AUTHORITY_KEY_ID = (
    "fac60c882c05f585377dfb16f21e7be71b67bcb2c1539ca9d1d780ed491dd669"
)
INITIAL_AUTHORITY_ENVELOPE_CONTRACT = (
    "winsvpn-macos-release-python-initial-authority-envelope-v1"
)
INITIAL_AUTHORITY_AUTHORIZATION_CONTRACT = (
    "winsvpn-macos-release-python-initial-authority-authorization-v1"
)
INITIAL_AUTHORITY_JOURNAL_CONTRACT = (
    "winsvpn-macos-release-python-initial-authority-journal-v1"
)
OWNER_BLOCKED = "OWNER-BLOCKED: ReleasePython owner provision refused"
NATIVE_CAPABILITY_CONTRACT = (
    "winsvpn-macos-release-python-native-capability-v1"
)
NATIVE_LAUNCHER_SOURCE_RELATIVE = "tools/macos_release_python_owner_launcher.c"
NATIVE_LAUNCHER_BUILD_RELATIVE = (
    "tools/build_macos_release_python_owner_launcher.sh"
)
NATIVE_RUNTIME_FD = 197
NATIVE_CAPABILITY_FD = 198
NATIVE_CONTROLLER_FD = 199

MAX_AUTHORITY = 256 * 1024
MAX_PLAN = 512 * 1024
MAX_AUTHORIZATION = 256 * 1024
MAX_RECEIPT = 256 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
MAX_RUNTIME_EXECUTABLE = 256 * 1024 * 1024
MAX_RUNTIME_LAUNCHER = 64 * 1024
MAX_PACKAGE = 1024 * 1024 * 1024
MAX_WHEEL = 512 * 1024 * 1024
MAX_SIGSTORE_BUNDLE = 8 * 1024 * 1024
MAX_SIGSTORE_TRUSTED_ROOT = 8 * 1024 * 1024
MAX_SIGSTORE_VERIFIER = 256 * 1024 * 1024
MAX_JOURNAL = 128 * 1024
MAX_OUTPUT = 256 * 1024
MAX_NATIVE_LAUNCHER = 8 * 1024 * 1024
MAX_NATIVE_CAPABILITY = 4096
MAX_CHILD_STDOUT = 256 * 1024
MAX_CHILD_STDERR = 256 * 1024
MAX_CHILD_TOTAL_OUTPUT = MAX_CHILD_STDOUT + MAX_CHILD_STDERR
MAX_CHILD_FAILURE_EXCERPT = 1024
REAUTH_CODESIGN_INVOCATION_LIMIT = 21
MAX_AUTHORIZATION_SECONDS = 15 * 60
MAX_FUTURE_SKEW_SECONDS = 30
MAX_JOURNALED_RECOVERY_SECONDS = 30 * 60
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,180}\Z")
SIGSTORE_BUNDLE_SHA256 = (
    "c8e8af7129581634031508dbbf4831b0436e11716796d85eccb08f305664dd6b"
)
INPUT_CUSTODY_ROOT = Path("/Library/WinsVPN/ReleasePythonInputs/sha256")
SIGSTORE_BUNDLE_PATH = (
    INPUT_CUSTODY_ROOT
    / SIGSTORE_BUNDLE_SHA256
    / "python-3.14.7-macos11.pkg.sigstore"
)
SIGSTORE_VERIFIER_CONTRACT = "cosign-v3-keyless-bundle-offline-v1"
PYTHON_PACKAGE_OIDC_ISSUER = "https://github.com/login/oauth"
SIGSTORE_POLICY_KEYS = {
    "certificate_identity",
    "certificate_oidc_issuer",
    "verifier_contract",
}

MIGRATION_CLOSURE_PATHS = {
    "android_custody_sha256": "tools/release_android_toolchain_archive_custody.sh",
    "archive_test_sha256": "tools/test_release_python_archive_custody.py",
    "browser_custody_sha256": "tools/release_browser_archive_custody.sh",
    "custody_controller_sha256": RECEIPT_SCHEMA_RELATIVE,
    "custody_metadata_sha256": "tools/macos_release_python_runtime.custody.json",
    "fin_g00_test_sha256": "tools/test_fin_release_gate_g00_python_custody.py",
    "fin_release_gate_sha256": "tools/fin_release_gate.sh",
    "gcp_proof_collector_sha256": "tools/gcp_proof_evidence.py",
    "gcp_proof_live_probe_sha256": "tools/gcp_proof_live_probe.py",
    "go_custody_sha256": "tools/release_go_archive_custody.sh",
    "node_custody_sha256": "tools/release_node_archive_custody.sh",
    "openssl_custody_sha256": "tools/release_openssl_archive_custody.sh",
    "pin_manifest_sha256": PIN_MANIFEST_RELATIVE,
    "provision_test_sha256": "tools/test_provision_macos_release_python_runtime.py",
    "provisioner_sha256": "tools/provision_macos_release_python_runtime.sh",
    "receipt_test_sha256": "tools/test_macos_release_python_runtime_receipt.py",
    "wrapper_sha256": "tools/release_python_archive_custody.sh",
}

AUTHORITY_KEYS = {
    "active_receipt_sha256",
    "active_sequence",
    "authorized_repo_root",
    "authority_id",
    "closure",
    "contract",
    "key_id",
    "expires_utc",
    "not_before_utc",
    "owner_provision_boundary",
    "owner_provision_boundary_sha256",
    "owner_provision_launcher",
    "owner_provision_launcher_build_sha256",
    "owner_provision_launcher_compiler_sha256",
    "owner_provision_launcher_device",
    "owner_provision_launcher_inode",
    "owner_provision_launcher_linker_sha256",
    "owner_provision_launcher_sha256",
    "owner_provision_launcher_sdk_closure_sha256",
    "owner_provision_launcher_source_sha256",
    "runtime_launcher_sha256",
    "runtime_python_sha256",
    "schema_version",
    "signing_policy",
    "signature_algorithm",
}
PLAN_KEYS = {
    "authority",
    "candidate_receipt_ascii",
    "candidate_receipt_sha256",
    "closure",
    "contract",
    "created_utc",
    "current_receipt_sha256",
    "expected_external_authority_operation",
    "expires_utc",
    "migration_id",
    "schema_version",
    "status",
}
OPERATION_KEYS = {
    "action",
    "authority_id",
    "authority_key_id",
    "authority_path",
    "candidate_receipt_sha256",
    "current_receipt_sha256",
    "expected_active_sequence",
    "migration_id",
    "next_sequence",
    "receipt_path",
}
SIGNED_AUTHORIZATION_KEYS = {
    "authority_id",
    "authorization_id",
    "authorization_path",
    "authorized_repo_root",
    "candidate_receipt_sha256",
    "closure",
    "contract",
    "current_receipt_sha256",
    "expires_utc",
    "issued_utc",
    "migration_id",
    "nonce",
    "not_before_utc",
    "owner_provision_boundary_sha256",
    "owner_provision_launcher_compiler_sha256",
    "owner_provision_launcher_linker_sha256",
    "owner_provision_launcher_sha256",
    "owner_provision_launcher_sdk_closure_sha256",
    "plan_sha256",
    "receipt_path",
    "schema_version",
    "sequence",
}
AUTHORIZATION_KEYS = {
    "algorithm",
    "authorization",
    "contract",
    "key_id",
    "schema_version",
    "signature",
}
INITIAL_AUTHORITY_ENVELOPE_KEYS = {
    "algorithm",
    "authorization",
    "contract",
    "key_id",
    "schema_version",
    "signature",
}
INITIAL_AUTHORITY_AUTHORIZATION_KEYS = {
    "action",
    "active_receipt_sha256",
    "authority_path",
    "authority_sha256",
    "contract",
    "expires_utc",
    "issued_utc",
    "nonce",
    "not_before_utc",
    "owner_provision_boundary_sha256",
    "owner_provision_launcher_device",
    "owner_provision_launcher_inode",
    "owner_provision_launcher_sha256",
    "schema_version",
}
INITIAL_AUTHORITY_JOURNAL_KEYS = {
    "authority_sha256",
    "contract",
    "created_utc",
    "envelope_sha256",
    "generation",
    "phase",
    "schema_version",
    "stage_name",
    "transaction_id",
}
JOURNAL_KEYS = {
    "authorization_sha256",
    "authority_backup_name",
    "authority_stage_name",
    "authorized_repo_root",
    "contract",
    "created_utc",
    "generation",
    "migration_id",
    "new_authority_sha256",
    "new_receipt_sha256",
    "old_authority_flags",
    "old_authority_mode",
    "old_authority_sha256",
    "old_receipt_flags",
    "old_receipt_mode",
    "old_receipt_sha256",
    "phase",
    "plan_sha256",
    "receipt_backup_name",
    "receipt_stage_name",
    "schema_version",
    "transaction_id",
}
PHASES = {
    "preparing": 0,
    "prepared": 1,
    "publishing-receipt": 2,
    "receipt-published": 3,
    "publishing-authority": 4,
    "authority-published": 5,
    "verified": 6,
}


class ProvisionError(RuntimeError):
    """The external owner transaction failed closed."""


class SimulatedProcessCrash(BaseException):
    """Test-only process-death marker; production never catches this type."""


def _fail(message: str) -> None:
    raise ProvisionError(f"{OWNER_BLOCKED}: {message}")


def _duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    _fail(f"non-finite JSON number rejected: {value}")


def canonical_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ProvisionError(f"canonical JSON encoding failed: {exc}") from exc


def _json(
    data: bytes,
    label: str,
    *,
    maximum: int,
    canonical: bool = True,
) -> dict[str, object]:
    if not data or len(data) > maximum or b"\0" in data:
        _fail(f"{label} byte bounds are invalid")
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_duplicate,
            parse_constant=_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ProvisionError(f"{OWNER_BLOCKED}: {label} is invalid JSON") from exc
    if type(value) is not dict:
        _fail(f"{label} must be a JSON object")
    if canonical and canonical_bytes(value) != data:
        _fail(f"{label} is not canonical ASCII JSON")
    return value


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != expected:
        _fail(f"{label} keys are not exact")
    return value


def _sha(value: object, label: str, *, allow_zero: bool = False) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        _fail(f"{label} is not an exact SHA-256")
    if not allow_zero and value == "0" * 64:
        _fail(f"{label} cannot be zero")
    return value


def _time(value: object, label: str) -> datetime:
    if type(value) is not str or UTC.fullmatch(value) is None:
        _fail(f"{label} is not exact UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ProvisionError(f"{OWNER_BLOCKED}: {label} is invalid") from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity(info: os.stat_result, flags: int) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_uid,
        info.st_gid,
        flags,
    )


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        int(getattr(info, "st_flags", 0)),
    )


class SystemOperations:
    """Small fixed filesystem boundary, replaceable only by direct unit tests."""

    def flags_fd(self, fd: int) -> int:
        return int(getattr(os.fstat(fd), "st_flags", 0))

    def set_flags_fd(self, fd: int, flags: int) -> None:
        if type(fd) is not int or not 0 <= fd <= 0x7FFFFFFF:
            _fail("file descriptor must be an exact non-negative 32-bit integer")
        if type(flags) is not int or not 0 <= flags <= 0xFFFFFFFF:
            _fail("file flags must be an exact unsigned 32-bit integer")
        operation = getattr(os, "fchflags", None)
        if callable(operation):
            operation(fd, flags)
            return
        if sys.platform != "darwin":
            _fail("fchflags is unavailable")
        libc = ctypes.CDLL(None, use_errno=True)
        operation = libc.fchflags
        operation.argtypes = [ctypes.c_int, ctypes.c_uint]
        operation.restype = ctypes.c_int
        if operation(fd, flags) == -1:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))

    def full_sync(self, fd: int) -> None:
        full = getattr(fcntl, "F_FULLFSYNC", None)
        if sys.platform == "darwin" and full is not None:
            fcntl.fcntl(fd, full)
        else:
            os.fsync(fd)

    def sync_directory(self, fd: int) -> None:
        os.fsync(fd)

    def rename_exclusive(
        self, source_fd: int, source: str, destination_fd: int, destination: str
    ) -> None:
        if sys.platform != "darwin":
            _fail("exclusive authority publication is unavailable")
        libc = ctypes.CDLL(None, use_errno=True)
        operation = libc.renameatx_np
        operation.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        operation.restype = ctypes.c_int
        if operation(
            source_fd,
            os.fsencode(source),
            destination_fd,
            os.fsencode(destination),
            0x00000004,
        ) == -1:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))


SYSTEM_OPERATIONS = SystemOperations()


@dataclass(frozen=True)
class CustodyPolicy:
    uid: int
    gid: int
    require_immutable: bool = True
    strict_ancestry: bool = True
    trusted_root: Path = Path("/")
    exact_ancestor_owner: bool = True
    allowed_ancestor_uids: frozenset[int] | None = None
    forbidden_writable_uid: int | None = None

    @classmethod
    def production(cls) -> "CustodyPolicy":
        return cls(
            uid=0,
            gid=0,
            require_immutable=True,
            strict_ancestry=True,
            trusted_root=Path("/"),
        )


@dataclass(frozen=True)
class ProvisionPaths:
    authority: Path
    boundary: Path
    journal: Path
    journal_next: Path
    receipt: Path
    runtime: Path
    runtime_python: Path

    @classmethod
    def production(
        cls,
        _fixed: tuple[str, str, str, str, str, str, str] = (
            "/Library/WinsVPN/ReleasePythonAuthority/v2/authority.json",
            "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision",
            "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision.transaction.json",
            "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision.transaction.next",
            "/Library/WinsVPN/ReleasePython/3.14.7.receipt.json",
            "/Library/WinsVPN/ReleasePython/3.14.7",
            "/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/bin/python3.14",
        ),
    ) -> "ProvisionPaths":
        """Return literal production geometry immune to module-global rebinding."""

        return cls(
            authority=Path(_fixed[0]),
            boundary=Path(_fixed[1]),
            journal=Path(_fixed[2]),
            journal_next=Path(_fixed[3]),
            receipt=Path(_fixed[4]),
            runtime=Path(_fixed[5]),
            runtime_python=Path(_fixed[6]),
        )


PRODUCTION_PATHS = ProvisionPaths.production()


def _production_paths_requested(
    paths: ProvisionPaths,
    _fixed: ProvisionPaths = PRODUCTION_PATHS,
) -> bool:
    """Classify every protected target independently, never by tuple equality."""

    fixed = _fixed
    protected_roots = (
        fixed.authority.parents[1],
        fixed.receipt.parent,
    )
    for name in ProvisionPaths.__dataclass_fields__:
        candidate = getattr(paths, name)
        if candidate == getattr(fixed, name):
            return True
        for root in protected_roots:
            try:
                candidate.relative_to(root)
            except ValueError:
                continue
            return True
    return False


def _require_exact_production_paths(
    paths: ProvisionPaths,
    operation: str,
    _fixed: ProvisionPaths = PRODUCTION_PATHS,
) -> None:
    if paths != _fixed:
        _fail(f"production {operation} requires every fixed path to be exact")

LAUNCHER_ENVIRONMENT = {
    "PATH": f"{RUNTIME_PATH}/launcher:/usr/bin:/bin:/usr/sbin:/sbin",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONEXECUTABLE": str(RUNTIME_LAUNCHER),
    "PYTHONNOUSERSITE": "1",
    "PYTHONPATH": str(RUNTIME_PATH / "vendor"),
}
LAUNCHER_OPTIONAL_ENVIRONMENT = {
    "HOME",
    "LC_CTYPE",
    "TMPDIR",
    "__CF_USER_TEXT_ENCODING",
}


class HeldDirectory:
    """Descriptor-retained absolute directory and all of its ancestors."""

    def __init__(
        self,
        path: Path,
        descriptors: list[tuple[int, int | None, str | None, tuple[int, ...]]],
        policy: CustodyPolicy,
    ) -> None:
        self.path = path
        self.descriptors = descriptors
        self.fd = descriptors[-1][0]
        self.policy = policy

    @classmethod
    def open(cls, path: Path, policy: CustodyPolicy) -> "HeldDirectory":
        if not path.is_absolute() or path == Path("/"):
            _fail(f"unsafe retained directory path: {path}")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptors: list[tuple[int, int | None, str | None, tuple[int, ...]]] = []
        parent: int | None = None
        try:
            root = os.open("/", flags)
            root_info = os.fstat(root)
            descriptors.append((root, None, None, _directory_identity(root_info)))
            parent = root
            current_path = Path("/")
            for component in path.parts[1:]:
                if not component or component in {".", ".."}:
                    _fail(f"unsafe retained directory component: {path}")
                child = os.open(component, flags, dir_fd=parent)
                info = os.fstat(child)
                current_path = current_path / component
                if not stat.S_ISDIR(info.st_mode):
                    os.close(child)
                    _fail(f"retained ancestor is not a directory: {path}")
                enforce = False
                if policy.strict_ancestry:
                    try:
                        current_path.relative_to(policy.trusted_root)
                        enforce = True
                    except ValueError:
                        enforce = False
                exact_owner_mismatch = policy.exact_ancestor_owner and (
                    info.st_uid != policy.uid or info.st_gid != policy.gid
                )
                allowed_owner_mismatch = (
                    policy.allowed_ancestor_uids is not None
                    and info.st_uid not in policy.allowed_ancestor_uids
                )
                same_uid_writable = (
                    policy.forbidden_writable_uid is not None
                    and info.st_uid == policy.forbidden_writable_uid
                    and bool(info.st_mode & 0o200)
                )
                if enforce and (
                    exact_owner_mismatch
                    or allowed_owner_mismatch
                    or same_uid_writable
                    or info.st_mode & 0o022
                    or info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                ):
                    os.close(child)
                    _fail(f"retained ancestor custody mismatch: {path}")
                descriptors.append(
                    (child, parent, component, _directory_identity(info))
                )
                parent = child
            held = cls(path, descriptors, policy)
            held.validate()
            return held
        except Exception:
            for descriptor, _parent, _name, _identity_value in reversed(descriptors):
                os.close(descriptor)
            raise

    def validate(self) -> None:
        for descriptor, parent, name, expected in self.descriptors:
            if _directory_identity(os.fstat(descriptor)) != expected:
                _fail(f"retained directory identity changed: {self.path}")
            if parent is not None and name is not None:
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if _directory_identity(current) != expected:
                    _fail(f"retained directory pathname changed: {self.path}")

    def close(self) -> None:
        for descriptor, _parent, _name, _expected in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors.clear()


class HeldFile:
    """A pathname, all ancestors, exact bytes, and one open file description."""

    def __init__(
        self,
        *,
        path: Path,
        directory: HeldDirectory,
        fd: int,
        data: bytes,
        identity: tuple[int, ...],
        operations: SystemOperations,
    ) -> None:
        self.path = path
        self.directory = directory
        self.fd = fd
        self.data = data
        self.identity = identity
        self.operations = operations

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        maximum: int,
        policy: CustodyPolicy,
        operations: SystemOperations,
        mode: int | None = None,
        immutable: bool = False,
        allow_owner_write: bool = False,
    ) -> "HeldFile":
        directory = HeldDirectory.open(path.parent, policy)
        fd: int | None = None
        try:
            before = os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > maximum
                or before.st_uid != policy.uid
                or before.st_gid != policy.gid
                or before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
            ):
                _fail(f"file custody mismatch: {path}")
            if mode is not None and stat.S_IMODE(before.st_mode) != mode:
                _fail(f"file mode custody mismatch: {path}")
            if not allow_owner_write and before.st_mode & 0o222:
                _fail(f"writable file rejected: {path}")
            fd = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory.fd,
            )
            opened = os.fstat(fd)
            flags = operations.flags_fd(fd)
            identity = _identity(opened, flags)
            if identity != _identity(before, flags):
                _fail(f"file changed before descriptor binding: {path}")
            if immutable and policy.require_immutable:
                if flags & UF_IMMUTABLE and not flags & SF_IMMUTABLE:
                    _fail(f"user immutable flag is insufficient: {path}")
                if not flags & SF_IMMUTABLE:
                    _fail(f"system immutable flag is required: {path}")
            chunks: list[bytes] = []
            total = 0
            while True:
                block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
                if not block:
                    break
                total += len(block)
                if total > maximum:
                    _fail(f"file exceeds its byte ceiling: {path}")
                chunks.append(block)
            data = b"".join(chunks)
            held = cls(
                path=path,
                directory=directory,
                fd=fd,
                data=data,
                identity=identity,
                operations=operations,
            )
            held.validate()
            return held
        except Exception:
            if fd is not None:
                os.close(fd)
            directory.close()
            raise

    def validate(self) -> None:
        self.directory.validate()
        current = _identity(os.fstat(self.fd), self.operations.flags_fd(self.fd))
        if current != self.identity:
            _fail(f"retained file identity changed: {self.path}")
        pathname = os.stat(
            self.path.name,
            dir_fd=self.directory.fd,
            follow_symlinks=False,
        )
        if _identity(pathname, self.operations.flags_fd(self.fd)) != self.identity:
            _fail(f"retained file pathname changed: {self.path}")
        offset = 0
        chunks: list[bytes] = []
        while offset <= len(self.data):
            block = os.pread(
                self.fd,
                min(1024 * 1024, len(self.data) + 1 - offset),
                offset,
            )
            if not block:
                break
            chunks.append(block)
            offset += len(block)
            if offset > len(self.data):
                _fail(f"retained file grew while held: {self.path}")
        if b"".join(chunks) != self.data:
            _fail(f"retained file bytes changed: {self.path}")
        if _identity(os.fstat(self.fd), self.operations.flags_fd(self.fd)) != self.identity:
            _fail(f"retained file changed during validation: {self.path}")

    def close(self) -> None:
        os.close(self.fd)
        self.directory.close()


def _digest_fd_pread(fd: int, maximum: int, label: str) -> str:
    info = os.fstat(fd)
    if info.st_size <= 0 or info.st_size > maximum:
        _fail(f"{label} size is outside its reviewed ceiling")
    digest = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        block = os.pread(fd, min(1024 * 1024, info.st_size - offset), offset)
        if not block:
            _fail(f"{label} ended before its retained size")
        digest.update(block)
        offset += len(block)
    if os.pread(fd, 1, offset):
        _fail(f"{label} grew while hashed")
    return digest.hexdigest()


def _retained_ancestor_descriptor(
    directory: HeldDirectory, target: Path
) -> int | None:
    if not target.is_absolute() or target == Path("/"):
        _fail("retained event exception target is unsafe")
    target_parts = target.parts
    directory_parts = directory.path.parts
    if directory_parts[: len(target_parts)] != target_parts:
        return None
    index = len(target_parts) - 1
    if index >= len(directory.descriptors):
        _fail("retained event exception target is not descriptor-bound")
    descriptor, parent, name, expected = directory.descriptors[index]
    if parent is None or name != target.name:
        _fail("retained event exception descriptor geometry is invalid")
    held = os.fstat(descriptor)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if _directory_identity(held) != expected or _directory_identity(named) != expected:
        _fail("retained event exception pathname changed before binding")
    return descriptor


class VnodeWatch:
    """One fail-closed macOS vnode event set over retained descriptors."""

    def __init__(
        self,
        queue: object,
        allow_attrib: dict[int, tuple[int, int]],
        allow_write: dict[int, tuple[int, int]],
    ) -> None:
        self.queue = queue
        self.allow_attrib = allow_attrib
        self.allow_write = allow_write

    @classmethod
    def open(
        cls,
        descriptors: Iterable[int],
        *,
        allow_attrib: Iterable[int] = (),
        allow_write: Iterable[int] = (),
    ) -> "VnodeWatch":
        if sys.platform != "darwin" or not hasattr(select, "kqueue"):
            _fail("macOS kqueue custody is required")
        queue = select.kqueue()
        flags = (
            select.KQ_NOTE_DELETE
            | select.KQ_NOTE_WRITE
            | select.KQ_NOTE_EXTEND
            | select.KQ_NOTE_ATTRIB
            | select.KQ_NOTE_LINK
            | select.KQ_NOTE_RENAME
            | select.KQ_NOTE_REVOKE
        )
        retained = sorted(set(descriptors))
        attrib_descriptors = frozenset(allow_attrib)
        write_descriptors = frozenset(allow_write)
        if (
            not attrib_descriptors.isdisjoint(write_descriptors)
            or not attrib_descriptors.issubset(retained)
            or not write_descriptors.issubset(retained)
        ):
            queue.close()
            _fail("vnode event exception inventory is invalid")
        changes = [
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=flags,
            )
            for descriptor in retained
        ]
        try:
            queue.control(changes, 0, 0)
        except Exception:
            queue.close()
            raise

        def identities(descriptors: frozenset[int]) -> dict[int, tuple[int, int]]:
            result: dict[int, tuple[int, int]] = {}
            for descriptor in descriptors:
                info = os.fstat(descriptor)
                result[descriptor] = (info.st_dev, info.st_ino)
            return result

        return cls(
            queue,
            identities(attrib_descriptors),
            identities(write_descriptors),
        )

    def validate(self, label: str) -> None:
        events = self.queue.control(None, 1024, 0)
        for event in events:
            expected = None
            if event.fflags == select.KQ_NOTE_ATTRIB:
                expected = self.allow_attrib.get(event.ident)
            elif event.fflags == select.KQ_NOTE_WRITE:
                expected = self.allow_write.get(event.ident)
            if expected is None:
                _fail(f"{label} changed while retained")
            current = os.fstat(event.ident)
            if (current.st_dev, current.st_ino) != expected:
                _fail(f"{label} exception descriptor changed while retained")

    def close(self) -> None:
        self.queue.close()


class HeldArtifact:
    """A large retained file with exact bytes and pathname ancestry."""

    def __init__(
        self,
        *,
        path: Path,
        directory: HeldDirectory,
        fd: int,
        identity: tuple[int, ...],
        digest: str,
        maximum: int,
        operations: SystemOperations,
    ) -> None:
        self.path = path
        self.directory = directory
        self.fd = fd
        self.identity = identity
        self.digest = digest
        self.maximum = maximum
        self.operations = operations

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        expected_sha256: str,
        maximum: int,
        policy: CustodyPolicy,
        operations: SystemOperations,
        allowed_leaf_uids: frozenset[int],
        mode: int | None = None,
        immutable: bool = False,
    ) -> "HeldArtifact":
        expected = _sha(expected_sha256, f"retained artifact digest {path}")
        directory = HeldDirectory.open(path.parent, policy)
        fd: int | None = None
        try:
            named = os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(named.st_mode)
                or named.st_nlink != 1
                or named.st_uid not in allowed_leaf_uids
                or named.st_mode & 0o222
                or named.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                or (mode is not None and stat.S_IMODE(named.st_mode) != mode)
            ):
                _fail(f"retained artifact custody mismatch: {path}")
            fd = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory.fd,
            )
            opened = os.fstat(fd)
            flags = operations.flags_fd(fd)
            identity = _identity(opened, flags)
            if identity != _identity(named, flags):
                _fail(f"retained artifact changed while opened: {path}")
            if immutable and policy.require_immutable:
                if flags & UF_IMMUTABLE and not flags & SF_IMMUTABLE:
                    _fail(f"user immutable flag is insufficient: {path}")
                if not flags & SF_IMMUTABLE:
                    _fail(f"system immutable flag is required: {path}")
            digest = _digest_fd_pread(fd, maximum, str(path))
            if digest != expected:
                _fail(f"retained artifact digest mismatch: {path}")
            result = cls(
                path=path,
                directory=directory,
                fd=fd,
                identity=identity,
                digest=digest,
                maximum=maximum,
                operations=operations,
            )
            result.validate()
            return result
        except Exception:
            if fd is not None:
                os.close(fd)
            directory.close()
            raise

    def watch_descriptors(self) -> list[int]:
        return [self.fd, *(item[0] for item in self.directory.descriptors)]

    def validate(self) -> None:
        self.directory.validate()
        current = os.fstat(self.fd)
        flags = self.operations.flags_fd(self.fd)
        if _identity(current, flags) != self.identity:
            _fail(f"retained artifact identity changed: {self.path}")
        named = os.stat(
            self.path.name,
            dir_fd=self.directory.fd,
            follow_symlinks=False,
        )
        if _identity(named, flags) != self.identity:
            _fail(f"retained artifact pathname changed: {self.path}")
        if _digest_fd_pread(self.fd, self.maximum, str(self.path)) != self.digest:
            _fail(f"retained artifact bytes changed: {self.path}")

    def close(self) -> None:
        os.close(self.fd)
        self.directory.close()


def _receipt_identity(info: os.stat_result) -> str:
    return ":".join(
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            format(stat.S_IMODE(info.st_mode), "o"),
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
        )
    )


def _tree_feed(digest: Any, *parts: object) -> None:
    for part in parts:
        value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def _launcher_tree_hashes(
    launchers: dict[str, HeldFile], operations: SystemOperations
) -> tuple[str, str, str]:
    if set(launchers) != {"python3", "python3.14"}:
        _fail("ReleasePython launcher inventory is not exact")
    directory = launchers["python3.14"].directory
    if set(os.listdir(directory.fd)) != set(launchers):
        _fail("ReleasePython launcher directory has unexpected entries")
    content = hashlib.sha256()
    identity = hashlib.sha256()
    for name in sorted(launchers, key=os.fsencode):
        held = launchers[name]
        held.validate()
        info = os.fstat(held.fd)
        flags = operations.flags_fd(held.fd)
        _tree_feed(
            identity,
            name,
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
        )
        _tree_feed(
            content,
            "F",
            name,
            stat.S_IMODE(info.st_mode),
            info.st_size,
            _sha256(held.data),
            flags,
        )
    return (
        content.hexdigest(),
        identity.hexdigest(),
        _receipt_identity(os.fstat(directory.fd)),
    )


def _argv_sha256(values: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = os.fsencode(value)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _process_path(pid: int) -> Path:
    if sys.platform != "darwin" or type(pid) is not int or pid <= 1:
        _fail("native capability parent process identity is unavailable")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pidpath
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    count = function(pid, buffer, len(buffer))
    if count <= 0 or count >= len(buffer):
        _fail("native capability parent process path is unavailable")
    try:
        return Path(buffer.raw[:count].rstrip(b"\0").decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ProvisionError(
            f"{OWNER_BLOCKED}: native capability parent path is not UTF-8"
        ) from exc


def _socket_read_exact(
    channel: socket.socket, count: int, *, deadline: float
) -> bytes:
    if count <= 0 or count > MAX_NATIVE_CAPABILITY:
        _fail("native capability frame length is invalid")
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            _fail("native capability exceeded its monotonic handshake deadline")
        channel.settimeout(timeout)
        chunk = channel.recv(remaining)
        if not chunk:
            _fail("native capability channel closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _socket_read_line(
    channel: socket.socket, *, maximum: int, deadline: float
) -> bytes:
    value = bytearray()
    while not value.endswith(b"\n"):
        if len(value) >= maximum:
            _fail("native capability line exceeds its byte cap")
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            _fail("native capability exceeded its monotonic handshake deadline")
        channel.settimeout(timeout)
        block = channel.recv(maximum - len(value))
        if not block:
            _fail("native capability channel closed before a complete line")
        value.extend(block)
    if value.count(b"\n") != 1:
        _fail("native capability supplied multiple messages at once")
    return bytes(value)


class NativeCapability:
    """Live, one-use capability held by the fixed native parent process."""

    _ORDER = (
        "contract",
        "nonce",
        "parent_pid",
        "child_pid",
        "launcher_sha256",
        "launcher_source_sha256",
        "launcher_build_sha256",
        "launcher_compiler_sha256",
        "launcher_linker_sha256",
        "launcher_sdk_closure_sha256",
        "launcher_device",
        "launcher_inode",
        "controller_sha256",
        "runtime_launcher_sha256",
        "runtime_python_sha256",
        "runtime_closure_sha256",
        "runtime_closure_nodes",
        "runtime_macho_files",
        "runtime_framework_tree_sha256",
        "runtime_vendor_tree_sha256",
        "runtime_launcher_tree_sha256",
        "runtime_executable_device",
        "runtime_executable_inode",
        "argv_sha256",
    )
    _KEYS = frozenset(_ORDER)

    def __init__(
        self,
        *,
        channel: socket.socket,
        controller_fd: int,
        controller_identity: tuple[int, ...],
        controller_sha256: str,
        runtime_fd: int,
        runtime_identity: tuple[int, ...],
        runtime_sha256: str,
        launcher: HeldArtifact,
        nonce: str,
        parent_pid: int,
        record: dict[str, str],
    ) -> None:
        self.channel = channel
        self.controller_fd = controller_fd
        self.controller_identity = controller_identity
        self.controller_sha256 = controller_sha256
        self.runtime_fd = runtime_fd
        self.runtime_identity = runtime_identity
        self.runtime_sha256 = runtime_sha256
        self.launcher = launcher
        self.nonce = nonce
        self.parent_pid = parent_pid
        self.record = record
        self.closed = False

    @classmethod
    def consume(
        cls,
        *,
        authority: dict[str, object] | None,
        receipt: dict[str, object] | None,
        controller: HeldFile,
        policy: CustodyPolicy,
        operations: SystemOperations,
        allow_generation_activation: bool = False,
    ) -> "NativeCapability":
        capability_text = os.environ.pop("WINS_OWNER_CAPABILITY_FD", None)
        controller_text = os.environ.pop("WINS_OWNER_CONTROLLER_FD", None)
        runtime_text = os.environ.pop("WINS_OWNER_RUNTIME_FD", None)
        if capability_text != str(NATIVE_CAPABILITY_FD) or controller_text != str(
            NATIVE_CONTROLLER_FD
        ) or runtime_text != str(NATIVE_RUNTIME_FD):
            _fail("native launcher capability descriptors are absent or invalid")
        try:
            channel_info = os.fstat(NATIVE_CAPABILITY_FD)
            controller_info = os.fstat(NATIVE_CONTROLLER_FD)
            runtime_info = os.fstat(NATIVE_RUNTIME_FD)
        except OSError as exc:
            raise ProvisionError(
                f"{OWNER_BLOCKED}: native launcher capability descriptors are closed"
            ) from exc
        if not stat.S_ISSOCK(channel_info.st_mode) or not stat.S_ISREG(
            controller_info.st_mode
        ) or not stat.S_ISREG(runtime_info.st_mode):
            _fail("native launcher capability descriptor types are invalid")
        if fcntl.fcntl(NATIVE_CAPABILITY_FD, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            _fail("native launcher capability descriptor was not retained")
        if fcntl.fcntl(NATIVE_CONTROLLER_FD, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            _fail("native launcher controller descriptor was not retained")
        if fcntl.fcntl(NATIVE_RUNTIME_FD, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
            _fail("native launcher runtime descriptor was not retained")
        channel = socket.socket(fileno=NATIVE_CAPABILITY_FD)
        deadline = time.monotonic() + 5.0
        launcher: HeldArtifact | None = None
        try:
            frame_length = struct.unpack(
                "!I", _socket_read_exact(channel, 4, deadline=deadline)
            )[0]
            payload = _socket_read_exact(channel, frame_length, deadline=deadline)
            if not payload.endswith(b"\n") or b"\0" in payload:
                _fail("native capability framing is invalid")
            try:
                lines = payload.decode("ascii").splitlines()
            except UnicodeDecodeError as exc:
                raise ProvisionError(
                    f"{OWNER_BLOCKED}: native capability is not ASCII"
                ) from exc
            record: dict[str, str] = {}
            order: list[str] = []
            for line in lines:
                if line.count("=") != 1:
                    _fail("native capability record syntax is invalid")
                key, value = line.split("=", 1)
                if key in record:
                    _fail(f"duplicate native capability field rejected: {key}")
                record[key] = value
                order.append(key)
            if set(record) != cls._KEYS or tuple(order) != cls._ORDER:
                _fail("native capability fields are not exact")
            if record["contract"] != NATIVE_CAPABILITY_CONTRACT:
                _fail("native capability contract is invalid")
            for key in (
                "argv_sha256",
                "controller_sha256",
                "launcher_build_sha256",
                "launcher_compiler_sha256",
                "launcher_linker_sha256",
                "launcher_sdk_closure_sha256",
                "launcher_sha256",
                "launcher_source_sha256",
                "nonce",
                "runtime_closure_sha256",
                "runtime_framework_tree_sha256",
                "runtime_vendor_tree_sha256",
                "runtime_launcher_tree_sha256",
                "runtime_launcher_sha256",
                "runtime_python_sha256",
            ):
                _sha(record[key], f"native capability {key}")
            try:
                parent_pid = int(record["parent_pid"], 10)
                child_pid = int(record["child_pid"], 10)
                launcher_device = int(record["launcher_device"], 10)
                launcher_inode = int(record["launcher_inode"], 10)
                runtime_closure_nodes = int(record["runtime_closure_nodes"], 10)
                runtime_macho_files = int(record["runtime_macho_files"], 10)
                runtime_executable_device = int(
                    record["runtime_executable_device"], 10
                )
                runtime_executable_inode = int(
                    record["runtime_executable_inode"], 10
                )
            except ValueError as exc:
                raise ProvisionError(
                    f"{OWNER_BLOCKED}: native capability process identity is invalid"
                ) from exc
            if any(
                str(value) != record[key]
                for key, value in (
                    ("parent_pid", parent_pid),
                    ("child_pid", child_pid),
                    ("launcher_device", launcher_device),
                    ("launcher_inode", launcher_inode),
                    ("runtime_closure_nodes", runtime_closure_nodes),
                    ("runtime_macho_files", runtime_macho_files),
                    ("runtime_executable_device", runtime_executable_device),
                    ("runtime_executable_inode", runtime_executable_inode),
                )
            ):
                _fail("native capability numeric identity is not canonical")
            if child_pid != os.getpid() or parent_pid != os.getppid():
                _fail("native capability process identity mismatch")
            if (
                runtime_closure_nodes < 1
                or runtime_closure_nodes > 20000
                or runtime_macho_files < 1
                or runtime_macho_files > runtime_closure_nodes
            ):
                _fail("native capability runtime closure counts are invalid")
            if _process_path(parent_pid) != OWNER_LAUNCHER_PATH:
                _fail("native capability parent is not the fixed launcher")
            expected_record: dict[str, object] = {
                "argv_sha256": _argv_sha256(sys.argv[1:]),
                "controller_sha256": _sha256(controller.data),
            }
            if authority is not None:
                expected_record.update(
                    {
                        "launcher_build_sha256": authority[
                            "owner_provision_launcher_build_sha256"
                        ],
                        "launcher_compiler_sha256": authority[
                            "owner_provision_launcher_compiler_sha256"
                        ],
                        "launcher_linker_sha256": authority[
                            "owner_provision_launcher_linker_sha256"
                        ],
                        "launcher_sha256": authority[
                            "owner_provision_launcher_sha256"
                        ],
                        "launcher_sdk_closure_sha256": authority[
                            "owner_provision_launcher_sdk_closure_sha256"
                        ],
                        "launcher_source_sha256": authority[
                            "owner_provision_launcher_source_sha256"
                        ],
                        "runtime_launcher_sha256": authority[
                            "runtime_launcher_sha256"
                        ],
                        "runtime_python_sha256": authority["runtime_python_sha256"],
                    }
                )
            for key, expected in expected_record.items():
                if record[key] != expected:
                    _fail(f"native capability binding mismatch: {key}")
            if (
                receipt is not None
                and authority is not None
                and receipt.get("schema_version") == 3
                and not allow_generation_activation
            ):
                for key in (
                    "owner_provision_launcher_sha256",
                    "owner_provision_launcher_source_sha256",
                    "owner_provision_launcher_build_sha256",
                    "owner_provision_launcher_compiler_sha256",
                    "owner_provision_launcher_linker_sha256",
                    "owner_provision_launcher_sdk_closure_sha256",
                ):
                    if receipt.get(key) != authority[key]:
                        _fail(
                            f"active receipt and authority native binding differ: {key}"
                        )
            receipt_identity = (
                receipt.get("contract"),
                receipt.get("schema_version"),
            ) if receipt is not None else None
            if allow_generation_activation and receipt_identity != (
                RECEIPT_CONTRACT,
                3,
            ):
                _fail("native generation activation requires a schema-three receipt")
            if receipt is not None:
                receipt_trees = {
                    "runtime_framework_tree_sha256": "framework_tree_sha256",
                    "runtime_vendor_tree_sha256": "vendor_tree_sha256",
                    "runtime_launcher_tree_sha256": "launcher_tree_sha256",
                }
                for capability_key, receipt_key in receipt_trees.items():
                    receipt_tree = _sha(
                        receipt.get(receipt_key), f"active receipt {receipt_key}"
                    )
                    if (
                        receipt_identity == (RECEIPT_CONTRACT, 3)
                        and record[capability_key] != receipt_tree
                    ):
                        _fail(
                            f"native runtime closure binding mismatch: {receipt_key}"
                        )
            named_controller = os.fstat(controller.fd)
            if (
                controller_info.st_dev != named_controller.st_dev
                or controller_info.st_ino != named_controller.st_ino
                or _digest_fd_pread(
                    NATIVE_CONTROLLER_FD,
                    MAX_CONTROLLER,
                    "native controller capability",
                )
                != record["controller_sha256"]
            ):
                _fail("native controller descriptor does not bind the held controller")
            runtime_flags = int(getattr(runtime_info, "st_flags", 0))
            if (
                runtime_executable_device != runtime_info.st_dev
                or runtime_executable_inode != runtime_info.st_ino
                or _digest_fd_pread(
                    NATIVE_RUNTIME_FD,
                    MAX_RUNTIME_EXECUTABLE,
                    "native retained runtime executable",
                )
                != record["runtime_python_sha256"]
            ):
                _fail("native runtime descriptor does not bind the executed Mach-O")
            launcher = HeldArtifact.open(
                OWNER_LAUNCHER_PATH,
                expected_sha256=record["launcher_sha256"],
                maximum=MAX_NATIVE_LAUNCHER,
                policy=policy,
                operations=operations,
                allowed_leaf_uids=frozenset({policy.uid}),
                mode=0o555,
                immutable=True,
            )
            launcher_info = os.fstat(launcher.fd)
            if (
                launcher_device != launcher_info.st_dev
                or launcher_inode != launcher_info.st_ino
            ):
                _fail("native launcher installed inode identity is invalid")
            if authority is not None and (
                launcher_device != authority["owner_provision_launcher_device"]
                or launcher_inode != authority["owner_provision_launcher_inode"]
            ):
                _fail("native launcher installed inode identity is not authorized")
            if (
                receipt_identity == (RECEIPT_CONTRACT, 3)
                and not allow_generation_activation
                and (
                    launcher_device != receipt["owner_provision_launcher_device"]
                    or launcher_inode != receipt["owner_provision_launcher_inode"]
                )
            ):
                _fail("native launcher installed inode identity is not authorized")
            retained_runtime_launcher = HeldArtifact.open(
                RUNTIME_LAUNCHER,
                expected_sha256=record["runtime_launcher_sha256"],
                maximum=MAX_RUNTIME_LAUNCHER,
                policy=policy,
                operations=operations,
                allowed_leaf_uids=frozenset({policy.uid}),
                mode=0o555,
                immutable=True,
            )
            retained_runtime_launcher.close()
            channel.sendall(f"READY {record['nonce']}\n".encode("ascii"))
            response = _socket_read_line(channel, maximum=96, deadline=deadline)
            if response != f"GO {record['nonce']}\n".encode("ascii"):
                _fail("native launcher capability grant is invalid")
            capability = cls(
                channel=channel,
                controller_fd=NATIVE_CONTROLLER_FD,
                controller_identity=_identity(
                    controller_info, operations.flags_fd(NATIVE_CONTROLLER_FD)
                ),
                controller_sha256=record["controller_sha256"],
                runtime_fd=NATIVE_RUNTIME_FD,
                runtime_identity=_identity(runtime_info, runtime_flags),
                runtime_sha256=record["runtime_python_sha256"],
                launcher=launcher,
                nonce=record["nonce"],
                parent_pid=parent_pid,
                record=record,
            )
            launcher = None
            capability.validate()
            return capability
        except Exception:
            channel.close()
            if launcher is not None:
                launcher.close()
            raise

    def validate(self) -> None:
        if self.closed or os.getppid() != self.parent_pid:
            _fail("native launcher capability is closed or orphaned")
        if _process_path(self.parent_pid) != OWNER_LAUNCHER_PATH:
            _fail("native launcher parent process identity changed")
        self.launcher.validate()
        info = os.fstat(self.controller_fd)
        flags = int(getattr(info, "st_flags", 0))
        if _identity(info, flags) != self.controller_identity:
            _fail("native controller capability identity changed")
        if (
            _digest_fd_pread(
                self.controller_fd,
                MAX_CONTROLLER,
                "native controller capability",
            )
            != self.controller_sha256
        ):
            _fail("native controller capability bytes changed")
        runtime_info = os.fstat(self.runtime_fd)
        runtime_flags = int(getattr(runtime_info, "st_flags", 0))
        if (
            _identity(runtime_info, runtime_flags) != self.runtime_identity
            or _digest_fd_pread(
                self.runtime_fd,
                MAX_RUNTIME_EXECUTABLE,
                "native retained runtime executable",
            )
            != self.runtime_sha256
        ):
            _fail("native retained runtime executable changed")
        self.channel.sendall(f"PING {self.nonce}\n".encode("ascii"))
        response = _socket_read_line(
            self.channel, maximum=96, deadline=time.monotonic() + 5.0
        )
        if response != f"PONG {self.nonce}\n".encode("ascii"):
            _fail("native launcher liveness response is invalid")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.channel.close()
        try:
            os.close(self.controller_fd)
        except OSError:
            pass
        try:
            os.close(self.runtime_fd)
        except OSError:
            pass
        self.launcher.close()


class RuntimeInvocation:
    def __init__(
        self,
        *,
        controller: HeldFile,
        native_capability: NativeCapability,
        executable: HeldArtifact,
        launchers: dict[str, HeldFile],
        expected_launcher_tree: str,
        expected_launcher_identity: str,
        expected_launcher_directory: str,
        watch: VnodeWatch,
        operations: SystemOperations,
    ) -> None:
        self.controller = controller
        self.native_capability = native_capability
        self.executable = executable
        self.launchers = launchers
        self.expected_launcher_tree = expected_launcher_tree
        self.expected_launcher_identity = expected_launcher_identity
        self.expected_launcher_directory = expected_launcher_directory
        self.watch = watch
        self.operations = operations

    def validate(self) -> None:
        self.native_capability.validate()
        self.watch.validate("ReleasePython invocation custody")
        self.controller.validate()
        self.executable.validate()
        measured = _launcher_tree_hashes(self.launchers, self.operations)
        expected = (
            self.expected_launcher_tree,
            self.expected_launcher_identity,
            self.expected_launcher_directory,
        )
        if measured != expected:
            _fail("ReleasePython launcher closure changed while retained")

    def close(self) -> None:
        self.watch.close()
        for held in reversed(list(self.launchers.values())):
            held.close()
        self.executable.close()
        self.controller.close()
        self.native_capability.close()


def _validate_production_invocation(
    invocation: RuntimeInvocation | None,
    _owner_provision_path: Path = OWNER_PROVISION_PATH,
    _runtime_python: Path = RUNTIME_PYTHON,
    _runtime_launcher: Path = RUNTIME_LAUNCHER,
    _runtime_launcher_alias: Path = RUNTIME_LAUNCHER_ALIAS,
    _owner_launcher_path: Path = OWNER_LAUNCHER_PATH,
) -> None:
    if (
        type(invocation) is not RuntimeInvocation
        or type(invocation.native_capability) is not NativeCapability
        or type(invocation.controller) is not HeldFile
        or type(invocation.executable) is not HeldArtifact
        or type(invocation.watch) is not VnodeWatch
        or invocation.controller.path != _owner_provision_path
        or invocation.executable.path != _runtime_python
        or set(invocation.launchers) != {"python3", "python3.14"}
        or invocation.launchers["python3.14"].path != _runtime_launcher
        or invocation.launchers["python3"].path != _runtime_launcher_alias
        or invocation.native_capability.launcher.path != _owner_launcher_path
    ):
        _fail("production requires the exact held ReleasePython invocation closure")
    _require_production_process_state(invocation.native_capability)
    invocation.validate()


def _sigstore_policy(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != SIGSTORE_POLICY_KEYS:
        _fail("Sigstore verification policy keys are not exact")
    contract = value["verifier_contract"]
    identity = value["certificate_identity"]
    issuer = value["certificate_oidc_issuer"]
    if contract != SIGSTORE_VERIFIER_CONTRACT:
        _fail("Sigstore verifier contract is not reviewed")
    for label, candidate in (
        ("certificate identity", identity),
        ("certificate OIDC issuer", issuer),
    ):
        if (
            type(candidate) is not str
            or not candidate
            or len(candidate.encode("utf-8")) > 2048
            or candidate != candidate.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in candidate)
        ):
            _fail(f"Sigstore {label} is invalid")
    if issuer != PYTHON_PACKAGE_OIDC_ISSUER:
        _fail("Sigstore certificate OIDC issuer is not the exact reviewed issuer")
    return {
        "certificate_identity": identity,
        "certificate_oidc_issuer": issuer,
        "verifier_contract": contract,
    }


def _verify_sigstore_bundle(
    verifier: HeldArtifact,
    trusted_root: HeldArtifact,
    bundle: HeldArtifact,
    package: HeldArtifact,
    policy: dict[str, str],
) -> None:
    argv = [
        str(verifier.path),
        "verify-blob",
        "--bundle",
        str(bundle.path),
        "--trusted-root",
        str(trusted_root.path),
        "--certificate-identity",
        policy["certificate_identity"],
        "--certificate-oidc-issuer",
        policy["certificate_oidc_issuer"],
        "--offline=true",
        "--max-workers=1",
        str(package.path),
    ]
    returncode, stdout, stderr = _run_bounded_child(
        argv,
        env={
            "HOME": "/private/var/empty",
            "NO_COLOR": "1",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": "/private/tmp",
        },
        forbid_descendants=True,
        timeout=30.0,
    )
    if returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        if len(detail) > 512:
            detail = detail[:512]
        raise ProvisionError(
            f"{OWNER_BLOCKED}: Sigstore certificate, transparency, signature, "
            f"or package digest verification failed"
            + (f": {detail}" if detail else "")
        )
    lowered = stdout.lower() + stderr.lower()
    if any(
        marker in lowered
        for marker in (
            b"insecure-ignore",
            b"transparency log verification disabled",
            b"certificate verification disabled",
        )
    ):
        _fail("Sigstore verifier reported an insecure verification mode")


class HeldDependencies:
    def __init__(
        self,
        *,
        package: HeldArtifact,
        sigstore_bundle: HeldArtifact,
        sigstore_trusted_root: HeldArtifact,
        sigstore_verifier: HeldArtifact,
        sigstore_policy: dict[str, str],
        wheels: list[HeldArtifact],
        package_signature_status: str,
        watch: VnodeWatch,
    ) -> None:
        self.package = package
        self.sigstore_bundle = sigstore_bundle
        self.sigstore_trusted_root = sigstore_trusted_root
        self.sigstore_verifier = sigstore_verifier
        self.sigstore_policy = sigstore_policy
        self.wheels = wheels
        self.package_signature_status = package_signature_status
        self.watch = watch

    @classmethod
    def open(
        cls,
        pin_data: bytes,
        candidate_receipt: dict[str, object],
        *,
        owner_uid: int,
        operations: SystemOperations,
        trusted_root: Path = Path("/"),
        sigstore_path: Path = SIGSTORE_BUNDLE_PATH,
        sigstore_sha256: str = SIGSTORE_BUNDLE_SHA256,
        sigstore_runner: Callable[
            [HeldArtifact, HeldArtifact, HeldArtifact, HeldArtifact, dict[str, str]],
            None,
        ] = _verify_sigstore_bundle,
    ) -> "HeldDependencies":
        manifest = _json(
            pin_data,
            "dependency pin manifest",
            maximum=MAX_PLAN,
            canonical=False,
        )
        try:
            custody = manifest["tools"]["python"]["archive_custody"]["darwin_arm64"]
            package_record = custody["package"]
            wheel_count = custody["wheel_count"]
            wheel_records = custody["wheels"]
            sigstore_bundle_record = custody["sigstore_bundle"]
            sigstore_root_record = custody["sigstore_trusted_root"]
            sigstore_verifier_record = custody["sigstore_verifier"]
            sigstore_policy = _sigstore_policy(custody["sigstore_policy"])
        except (KeyError, TypeError) as exc:
            raise ProvisionError(f"{OWNER_BLOCKED}: Python dependency pins are incomplete") from exc
        if type(wheel_count) is not int or wheel_count < 1 or wheel_count > 128:
            _fail("Python dependency wheel count is invalid")
        expected_wheel_keys = {str(index) for index in range(wheel_count)}
        if type(wheel_records) is not dict or set(wheel_records) != expected_wheel_keys:
            _fail("Python dependency wheel pin keys are not exact")
        if type(package_record) is not dict or set(package_record) != {"path", "sha256"}:
            _fail("Python package pin is not exact")
        for label, record in (
            ("Sigstore bundle", sigstore_bundle_record),
            ("Sigstore trusted root", sigstore_root_record),
            ("Sigstore verifier", sigstore_verifier_record),
        ):
            if type(record) is not dict or set(record) != {"path", "sha256"}:
                _fail(f"{label} pin is not exact")
        package_path = Path(str(package_record["path"]))
        package_sha = _sha(package_record["sha256"], "Python package pin")
        if not package_path.is_absolute() or package_path.name != "python-3.14.7-macos11.pkg":
            _fail("Python package path is not exact")
        if candidate_receipt.get("package_sha256") != package_sha:
            _fail("candidate receipt package digest does not match held pins")
        production_custody = trusted_root == Path("/")
        if production_custody:
            expected_package_path = INPUT_CUSTODY_ROOT / package_sha / package_path.name
            if package_path != expected_package_path:
                _fail("Python package is outside fixed content-addressed custody")
            if sigstore_path != SIGSTORE_BUNDLE_PATH:
                _fail("Sigstore bundle is outside fixed content-addressed custody")
            if sigstore_runner is not _verify_sigstore_bundle:
                _fail("production refuses an injected Sigstore verifier")
        bundle_path = Path(str(sigstore_bundle_record["path"]))
        bundle_sha = _sha(sigstore_bundle_record["sha256"], "Sigstore bundle pin")
        verifier_path = Path(str(sigstore_verifier_record["path"]))
        verifier_sha = _sha(
            sigstore_verifier_record["sha256"], "Sigstore verifier pin"
        )
        trusted_root_path = Path(str(sigstore_root_record["path"]))
        trusted_root_sha = _sha(
            sigstore_root_record["sha256"], "Sigstore trusted root pin"
        )
        if bundle_path != sigstore_path or bundle_sha != sigstore_sha256:
            _fail("Sigstore bundle path or digest differs from the held pin")
        if (
            not verifier_path.is_absolute()
            or verifier_path.name != "cosign"
            or not trusted_root_path.is_absolute()
            or trusted_root_path.name != "trusted_root.json"
        ):
            _fail("Sigstore verifier or trusted-root path is not exact")
        if production_custody:
            for label, path, digest in (
                ("verifier", verifier_path, verifier_sha),
                ("trusted root", trusted_root_path, trusted_root_sha),
            ):
                if path != INPUT_CUSTODY_ROOT / digest / path.name:
                    _fail(
                        f"Sigstore {label} is outside fixed content-addressed custody"
                    )
        expected_wheels = candidate_receipt.get("wheels")
        if type(expected_wheels) is not list or len(expected_wheels) != wheel_count:
            _fail("candidate receipt wheel inventory is not exact")
        if candidate_receipt.get("wheel_count") != wheel_count:
            _fail("candidate receipt wheel count does not match held pins")
        status = candidate_receipt.get("package_signature_status")
        if type(status) is not str or not status.startswith("Status: signed"):
            _fail("candidate receipt package signature status is invalid")

        opened: list[HeldArtifact] = []

        def hold(
            path: Path, digest: str, maximum: int, *, mode: int = 0o444
        ) -> HeldArtifact:
            try:
                info = os.stat(path, follow_symlinks=False)
            except OSError as exc:
                raise ProvisionError(f"{OWNER_BLOCKED}: dependency is unavailable: {path}: {exc}") from exc
            allowed_uids = (
                frozenset({0})
                if production_custody
                else frozenset({0, owner_uid})
            )
            if info.st_uid not in allowed_uids:
                _fail(f"dependency owner is not authorized: {path}")
            policy = CustodyPolicy(
                uid=info.st_uid,
                gid=info.st_gid,
                require_immutable=True,
                strict_ancestry=True,
                trusted_root=trusted_root,
                exact_ancestor_owner=False,
                allowed_ancestor_uids=allowed_uids,
                forbidden_writable_uid=owner_uid,
            )
            artifact = HeldArtifact.open(
                path,
                expected_sha256=digest,
                maximum=maximum,
                policy=policy,
                operations=operations,
                allowed_leaf_uids=allowed_uids,
                mode=mode,
                immutable=True,
            )
            opened.append(artifact)
            return artifact

        watch: VnodeWatch | None = None
        try:
            package = hold(package_path, package_sha, MAX_PACKAGE)
            bundle = hold(sigstore_path, sigstore_sha256, MAX_SIGSTORE_BUNDLE)
            held_trusted_root = hold(
                trusted_root_path, trusted_root_sha, MAX_SIGSTORE_TRUSTED_ROOT
            )
            verifier = hold(
                verifier_path, verifier_sha, MAX_SIGSTORE_VERIFIER, mode=0o555
            )
            wheels: list[HeldArtifact] = []
            for index in range(wheel_count):
                record = wheel_records[str(index)]
                if type(record) is not dict or set(record) != {"path", "sha256"}:
                    _fail(f"wheel pin {index} is not exact")
                wheel_path = Path(str(record["path"]))
                wheel_sha = _sha(record["sha256"], f"wheel pin {index}")
                if not wheel_path.is_absolute() or wheel_path.suffix != ".whl":
                    _fail(f"wheel path {index} is not exact")
                if production_custody:
                    expected_wheel_path = (
                        INPUT_CUSTODY_ROOT / wheel_sha / wheel_path.name
                    )
                    if wheel_path != expected_wheel_path:
                        _fail(
                            f"wheel {index} is outside fixed content-addressed custody"
                        )
                expected = expected_wheels[index]
                if (
                    type(expected) is not dict
                    or expected != {"name": wheel_path.name, "sha256": wheel_sha}
                ):
                    _fail(f"candidate receipt wheel {index} does not match held pins")
                wheels.append(hold(wheel_path, wheel_sha, MAX_WHEEL))
            descriptors = [
                descriptor
                for artifact in opened
                for descriptor in artifact.watch_descriptors()
            ]
            if descriptors.count(verifier.fd) != 1:
                _fail("Sigstore verifier watch descriptor inventory is invalid")
            watch = VnodeWatch.open(
                descriptors,
                allow_attrib=(verifier.fd,),
            )
            sigstore_runner(
                verifier,
                held_trusted_root,
                bundle,
                package,
                sigstore_policy,
            )
            result = cls(
                package=package,
                sigstore_bundle=bundle,
                sigstore_trusted_root=held_trusted_root,
                sigstore_verifier=verifier,
                sigstore_policy=sigstore_policy,
                wheels=wheels,
                package_signature_status=status,
                watch=watch,
            )
            result.validate()
            return result
        except Exception:
            if watch is not None:
                watch.close()
            for artifact in reversed(opened):
                artifact.close()
            raise

    def validate(self) -> None:
        self.watch.validate("ReleasePython package and wheel custody")
        self.package.validate()
        self.sigstore_bundle.validate()
        self.sigstore_trusted_root.validate()
        self.sigstore_verifier.validate()
        for wheel in self.wheels:
            wheel.validate()

    def child_records(self) -> list[dict[str, object]]:
        return [
            {
                "fd": self.package.fd,
                "kind": "package",
                "path": str(self.package.path),
                "sha256": self.package.digest,
            },
            {
                "fd": self.sigstore_bundle.fd,
                "kind": "sigstore",
                "path": str(self.sigstore_bundle.path),
                "sha256": self.sigstore_bundle.digest,
            },
            {
                "fd": self.sigstore_trusted_root.fd,
                "kind": "sigstore-root",
                "path": str(self.sigstore_trusted_root.path),
                "sha256": self.sigstore_trusted_root.digest,
            },
            {
                "fd": self.sigstore_verifier.fd,
                "kind": "sigstore-verifier",
                "path": str(self.sigstore_verifier.path),
                "sha256": self.sigstore_verifier.digest,
            },
            *(
                {
                    "fd": wheel.fd,
                    "kind": "wheel",
                    "path": str(wheel.path),
                    "sha256": wheel.digest,
                }
                for wheel in self.wheels
            ),
        ]

    def pass_fds(self) -> tuple[int, ...]:
        return (
            self.package.fd,
            self.sigstore_bundle.fd,
            self.sigstore_trusted_root.fd,
            self.sigstore_verifier.fd,
            *(wheel.fd for wheel in self.wheels),
        )

    def close(self) -> None:
        self.watch.close()
        for wheel in reversed(self.wheels):
            wheel.close()
        self.sigstore_verifier.close()
        self.sigstore_trusted_root.close()
        self.sigstore_bundle.close()
        self.package.close()


class HeldClosure:
    def __init__(self, files: dict[str, HeldFile], expected: dict[str, str]) -> None:
        self.files = files
        self.expected = expected

    @classmethod
    def open(
        cls,
        repo: Path,
        expected: dict[str, str],
        *,
        uid: int,
        gid: int,
        operations: SystemOperations,
    ) -> "HeldClosure":
        files: dict[str, HeldFile] = {}
        policy = CustodyPolicy(
            uid=uid,
            gid=gid,
            require_immutable=False,
            strict_ancestry=False,
            trusted_root=repo,
        )
        try:
            for key, relative in MIGRATION_CLOSURE_PATHS.items():
                path = repo / relative
                held = HeldFile.open(
                    path,
                    maximum=MAX_CONTROLLER,
                    policy=policy,
                    operations=operations,
                    immutable=False,
                    allow_owner_write=True,
                )
                if _sha256(held.data) != expected[key]:
                    _fail(f"repository closure digest mismatch: {relative}")
                files[key] = held
            closure = cls(files, dict(expected))
            closure.validate()
            return closure
        except Exception:
            for held in files.values():
                held.close()
            raise

    def validate(self) -> None:
        for key, held in self.files.items():
            held.validate()
            if _sha256(held.data) != self.expected[key]:
                _fail(f"repository closure changed: {key}")

    def close(self) -> None:
        for held in self.files.values():
            held.close()
        self.files.clear()
        self.expected.clear()


def _validate_closure(value: object, label: str) -> dict[str, str]:
    if type(value) is not dict or set(value) != set(MIGRATION_CLOSURE_PATHS):
        _fail(f"{label} closure keys are not exact")
    return {key: _sha(value[key], f"{label} closure {key}") for key in value}


def _parse_authority(data: bytes) -> dict[str, object]:
    authority = _exact_keys(
        _json(data, "authority", maximum=MAX_AUTHORITY),
        AUTHORITY_KEYS,
        "authority",
    )
    if (
        authority["contract"] != AUTHORITY_CONTRACT
        or authority["schema_version"] != 3
        or type(authority["schema_version"]) is not int
        or authority["signature_algorithm"] != AUTHORITY_ALGORITHM
    ):
        _fail("authority contract is invalid")
    _sha(authority["active_receipt_sha256"], "authority active receipt")
    _sha(authority["authority_id"], "authority id")
    public_key = _sha(authority["key_id"], "authority Ed25519 public key")
    if len(bytes.fromhex(public_key)) != 32:
        _fail("authority Ed25519 public key length is invalid")
    sequence = authority["active_sequence"]
    if type(sequence) is not int or sequence < 1 or sequence > 2**63 - 2:
        _fail("authority active sequence is invalid")
    repo = authority["authorized_repo_root"]
    if (
        type(repo) is not str
        or not repo.startswith("/")
        or repo == "/"
        or "\0" in repo
    ):
        _fail("authority repository root is invalid")
    if authority["owner_provision_boundary"] != str(OWNER_PROVISION_PATH):
        _fail("authority owner boundary path is invalid")
    _sha(authority["owner_provision_boundary_sha256"], "authority boundary digest")
    if authority["owner_provision_launcher"] != str(OWNER_LAUNCHER_PATH):
        _fail("authority native launcher path is invalid")
    _sha(
        authority["owner_provision_launcher_sha256"],
        "authority native launcher digest",
    )
    _sha(
        authority["owner_provision_launcher_source_sha256"],
        "authority native launcher source digest",
    )
    _sha(
        authority["owner_provision_launcher_build_sha256"],
        "authority native launcher build digest",
    )
    _sha(
        authority["owner_provision_launcher_compiler_sha256"],
        "authority native launcher compiler digest",
    )
    _sha(
        authority["owner_provision_launcher_linker_sha256"],
        "authority native launcher linker digest",
    )
    _sha(
        authority["owner_provision_launcher_sdk_closure_sha256"],
        "authority native launcher SDK closure digest",
    )
    _sha(authority["runtime_launcher_sha256"], "authority runtime launcher")
    _sha(authority["runtime_python_sha256"], "authority runtime Mach-O")
    for key in ("owner_provision_launcher_device", "owner_provision_launcher_inode"):
        if type(authority[key]) is not int or authority[key] <= 0:
            _fail(f"authority native launcher identity is invalid: {key}")
    _validate_closure(authority["closure"], "authority")
    not_before = _time(authority["not_before_utc"], "authority not_before_utc")
    expires = _time(authority["expires_utc"], "authority expires_utc")
    if expires <= not_before:
        _fail("authority validity interval is invalid")
    if type(authority["signing_policy"]) is not dict:
        _fail("authority signing policy is invalid")
    return authority


def _require_authority_current(
    authority: dict[str, object], now: datetime, *, label: str
) -> None:
    if now.tzinfo is None:
        _fail(f"{label} trusted time is not timezone-aware")
    not_before = _time(authority["not_before_utc"], f"{label} not_before_utc")
    expires = _time(authority["expires_utc"], f"{label} expires_utc")
    if now < not_before or now >= expires:
        _fail(f"{label} authority is expired or not yet active")


def _require_journaled_recovery_window(
    authority: dict[str, object], journal: dict[str, object], now: datetime
) -> None:
    """Permit only a recent crash whose transaction began under valid authority."""

    if now.tzinfo is None:
        _fail("journaled recovery trusted time is not timezone-aware")
    created = _time(journal["created_utc"], "journal created_utc")
    not_before = _time(
        authority["not_before_utc"], "journaled recovery authority not_before_utc"
    )
    expires = _time(
        authority["expires_utc"], "journaled recovery authority expires_utc"
    )
    age = (now - created).total_seconds()
    if (
        created < not_before
        or created >= expires
        or age < -MAX_FUTURE_SKEW_SECONDS
        or age > MAX_JOURNALED_RECOVERY_SECONDS
    ):
        _fail("journaled recovery is outside its bounded authority window")


def _migration_id(
    *,
    current_receipt_sha256: str,
    candidate_receipt_sha256: str,
    closure: dict[str, str],
    authority: dict[str, object],
    created_utc: str,
    expires_utc: str,
) -> str:
    intent = {
        "authority_id": authority["authority_id"],
        "authority_key_id": authority["key_id"],
        "candidate_receipt_sha256": candidate_receipt_sha256,
        "closure": closure,
        "contract": PLAN_CONTRACT,
        "created_utc": created_utc,
        "current_receipt_sha256": current_receipt_sha256,
        "expected_active_sequence": authority["active_sequence"],
        "expires_utc": expires_utc,
        "next_sequence": int(authority["active_sequence"]) + 1,
    }
    return _sha256(canonical_bytes(intent))


def _parse_candidate_receipt(data: bytes, closure: dict[str, str]) -> dict[str, object]:
    receipt = _json(data, "candidate receipt", maximum=MAX_RECEIPT)
    if (
        receipt.get("contract") != RECEIPT_CONTRACT
        or receipt.get("schema_version") != 3
        or type(receipt.get("schema_version")) is not int
        or receipt.get("authenticated") is not True
    ):
        _fail("candidate receipt is not authenticated schema v3")
    if receipt.get("runtime_path") != str(RUNTIME_PATH):
        _fail("candidate receipt runtime path is invalid")
    if receipt.get("executable_path") != str(RUNTIME_PYTHON):
        _fail("candidate receipt interpreter path is invalid")
    _sha(receipt.get("executable_sha256"), "candidate receipt interpreter")
    _sha(receipt.get("launcher_primary_sha256"), "candidate receipt launcher")
    launcher_bindings = {
        "owner_provision_launcher": str(OWNER_LAUNCHER_PATH),
        "owner_provision_launcher_sha256": None,
        "owner_provision_launcher_source_sha256": None,
        "owner_provision_launcher_build_sha256": None,
        "owner_provision_launcher_compiler_sha256": None,
        "owner_provision_launcher_linker_sha256": None,
        "owner_provision_launcher_sdk_closure_sha256": None,
        "owner_provision_launcher_device": None,
        "owner_provision_launcher_inode": None,
    }
    for key, expected_value in launcher_bindings.items():
        value = receipt.get(key)
        if expected_value is not None:
            if value != expected_value:
                _fail(f"candidate receipt native launcher binding mismatch: {key}")
        elif key.endswith("_sha256"):
            _sha(value, f"candidate receipt native launcher binding {key}")
        elif type(value) is not int or value <= 0:
            _fail(f"candidate receipt native launcher identity is invalid: {key}")
    _sha(receipt.get("package_sha256"), "candidate receipt package")
    wheel_count = receipt.get("wheel_count")
    wheels = receipt.get("wheels")
    if (
        type(wheel_count) is not int
        or wheel_count < 1
        or type(wheels) is not list
        or len(wheels) != wheel_count
    ):
        _fail("candidate receipt wheel inventory is invalid")
    for index, wheel in enumerate(wheels):
        if (
            type(wheel) is not dict
            or set(wheel) != {"name", "sha256"}
            or type(wheel["name"]) is not str
            or Path(wheel["name"]).name != wheel["name"]
        ):
            _fail(f"candidate receipt wheel {index} is invalid")
        _sha(wheel["sha256"], f"candidate receipt wheel {index}")
    status = receipt.get("package_signature_status")
    if type(status) is not str or not status.startswith("Status: signed"):
        _fail("candidate receipt package signature status is invalid")
    if receipt.get("custody_closure") != closure:
        _fail("candidate receipt closure does not match the authority")
    expected = {
        "controller_sha256": closure["wrapper_sha256"],
        "provisioner_sha256": closure["provisioner_sha256"],
        "receipt_schema_sha256": closure["custody_controller_sha256"],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            _fail(f"candidate receipt controller binding mismatch: {key}")
    return receipt


def _validate_native_receipt_authority(
    receipt: dict[str, object], authority: dict[str, object]
) -> None:
    expected = {
        "owner_provision_launcher": authority["owner_provision_launcher"],
        "owner_provision_launcher_sha256": authority[
            "owner_provision_launcher_sha256"
        ],
        "owner_provision_launcher_source_sha256": authority[
            "owner_provision_launcher_source_sha256"
        ],
        "owner_provision_launcher_build_sha256": authority[
            "owner_provision_launcher_build_sha256"
        ],
        "owner_provision_launcher_compiler_sha256": authority[
            "owner_provision_launcher_compiler_sha256"
        ],
        "owner_provision_launcher_linker_sha256": authority[
            "owner_provision_launcher_linker_sha256"
        ],
        "owner_provision_launcher_sdk_closure_sha256": authority[
            "owner_provision_launcher_sdk_closure_sha256"
        ],
        "owner_provision_launcher_device": authority[
            "owner_provision_launcher_device"
        ],
        "owner_provision_launcher_inode": authority[
            "owner_provision_launcher_inode"
        ],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            _fail(f"candidate receipt and authority native binding differ: {key}")
    if receipt.get("launcher_primary_sha256") != authority["runtime_launcher_sha256"]:
        _fail("candidate receipt and authority runtime launcher binding differ")
    if receipt.get("executable_sha256") != authority["runtime_python_sha256"]:
        _fail("candidate receipt and authority runtime Mach-O binding differ")


def _validate_active_runtime_receipt(
    receipt: dict[str, object],
    authority: dict[str, object],
    *,
    allow_sequence_one_activation: bool = False,
) -> None:
    identity = (receipt.get("contract"), receipt.get("schema_version"))
    if identity not in {
        ("winsvpn-macos-release-python-runtime-v1", 1),
        (RECEIPT_CONTRACT, 3),
    } or receipt.get("authenticated") is not True:
        _fail("active runtime receipt schema is not migration-compatible")
    if (
        receipt.get("runtime_path") != str(RUNTIME_PATH)
        or receipt.get("executable_path") != str(RUNTIME_PYTHON)
    ):
        _fail("active runtime receipt path identity is invalid")
    active_interpreter = _sha(
        receipt.get("executable_sha256"), "active runtime interpreter"
    )
    if (
        identity == (RECEIPT_CONTRACT, 3)
        and active_interpreter != authority["runtime_python_sha256"]
    ):
        _fail("active runtime receipt interpreter differs from authority")
    _sha(receipt.get("launcher_tree_sha256"), "active launcher tree")
    _sha(receipt.get("launcher_identity_sha256"), "active launcher identity")
    directory = receipt.get("launcher_dir_identity")
    if type(directory) is not str or not directory:
        _fail("active launcher directory identity is invalid")
    activation_receipt = _is_sequence_one_activation_receipt(receipt, authority)
    if activation_receipt and not allow_sequence_one_activation:
        _fail("sequence-one activation receipt is restricted to apply")
    if identity == (RECEIPT_CONTRACT, 3) and not activation_receipt:
        _validate_native_receipt_authority(receipt, authority)


def _is_sequence_one_activation_receipt(
    receipt: dict[str, object], authority: dict[str, object]
) -> bool:
    if (
        authority.get("active_sequence") != 1
        or (receipt.get("contract"), receipt.get("schema_version"))
        != (RECEIPT_CONTRACT, 3)
    ):
        return False
    receipt_closure = _validate_closure(
        receipt.get("custody_closure"), "sequence-one activation receipt"
    )
    authority_closure = _validate_closure(
        authority.get("closure"), "sequence-one activation authority"
    )
    return receipt_closure != authority_closure


def _authenticate_runtime_invocation(
    executable_path: Path,
    launcher_path: Path,
    reported_executable: str,
    reported_base_executable: str,
    receipt_data: bytes,
    *,
    controller: HeldFile,
    native_capability: NativeCapability,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> RuntimeInvocation:
    held: HeldArtifact | None = None
    launchers: dict[str, HeldFile] = {}
    watch: VnodeWatch | None = None
    try:
        receipt = _json(receipt_data, "active runtime receipt", maximum=MAX_RECEIPT)
        receipt_identity = (receipt.get("contract"), receipt.get("schema_version"))
        if receipt_identity not in {
            ("winsvpn-macos-release-python-runtime-v1", 1),
            (RECEIPT_CONTRACT, 3),
        }:
            _fail("active runtime receipt schema is not migration-compatible")
        legacy = receipt_identity == (
            "winsvpn-macos-release-python-runtime-v1",
            1,
        )
        if (
            receipt.get("runtime_path") != str(RUNTIME_PATH)
            or receipt.get("executable_path") != str(executable_path)
        ):
            _fail("active receipt does not bind the fixed ReleasePython interpreter")
        receipt_digest = _sha(
            receipt.get("executable_sha256"), "active receipt interpreter"
        )
        receipt_launcher_tree = _sha(
            receipt.get("launcher_tree_sha256"), "launcher tree"
        )
        receipt_launcher_identity = _sha(
            receipt.get("launcher_identity_sha256"), "launcher identity"
        )
        receipt_launcher_directory = receipt.get("launcher_dir_identity")
        digest = (
            _sha(
                native_capability.record["runtime_python_sha256"],
                "native capability runtime interpreter",
            )
            if legacy
            else receipt_digest
        )
        launcher_primary = _sha(
            native_capability.record["runtime_launcher_sha256"],
            "native capability launcher primary",
        )
        if (
            type(receipt_launcher_directory) is not str
            or not receipt_launcher_directory
        ):
            _fail("active receipt launcher directory identity is invalid")
        if reported_executable != str(launcher_path):
            _fail("running Python does not report the fixed ReleasePython launcher")
        if reported_base_executable != str(executable_path):
            _fail("running Python does not report the fixed underlying Mach-O")
        held = HeldArtifact.open(
            executable_path,
            expected_sha256=digest,
            maximum=MAX_RUNTIME_EXECUTABLE,
            policy=policy,
            operations=operations,
            allowed_leaf_uids=frozenset({policy.uid}),
            mode=0o555,
            immutable=True,
        )
        if type(native_capability) is NativeCapability:
            held_info = os.fstat(held.fd)
            runtime_info = os.fstat(native_capability.runtime_fd)
            if (
                held_info.st_dev != runtime_info.st_dev
                or held_info.st_ino != runtime_info.st_ino
                or _digest_fd_pread(
                    native_capability.runtime_fd,
                    MAX_RUNTIME_EXECUTABLE,
                    "native executed ReleasePython Mach-O",
                )
                != digest
            ):
                _fail(
                    "executed ReleasePython Mach-O does not match its retained descriptor"
                )
        for path in (launcher_path.parent / "python3", launcher_path):
            launchers[path.name] = HeldFile.open(
                path,
                maximum=MAX_RUNTIME_LAUNCHER,
                policy=policy,
                operations=operations,
                mode=0o555,
                immutable=True,
            )
        measured = _launcher_tree_hashes(launchers, operations)
        expected_launcher = (
            measured
            if legacy
            else (
                receipt_launcher_tree,
                receipt_launcher_identity,
                receipt_launcher_directory,
            )
        )
        if not legacy and measured != expected_launcher:
            _fail("active receipt does not bind the retained launcher closure")
        if _sha256(launchers["python3.14"].data) != launcher_primary:
            _fail("active receipt does not bind the retained primary launcher")
        reported_launcher = os.stat(reported_executable, follow_symlinks=False)
        if _identity(
            reported_launcher, operations.flags_fd(launchers["python3.14"].fd)
        ) != launchers["python3.14"].identity:
            _fail("reported launcher pathname does not identify the held launcher")
        reported_base = os.stat(reported_base_executable, follow_symlinks=False)
        if _identity(reported_base, operations.flags_fd(held.fd)) != held.identity:
            _fail("reported base executable does not identify the held Mach-O")
        descriptors = [
            controller.fd,
            *(item[0] for item in controller.directory.descriptors),
            *held.watch_descriptors(),
            *(
                descriptor
                for launcher in launchers.values()
                for descriptor in (
                    launcher.fd,
                    *(item[0] for item in launcher.directory.descriptors),
                )
            ),
        ]
        receipt_parent_descriptors = tuple(
            descriptor
            for directory in (
                held.directory,
                *(launcher.directory for launcher in launchers.values()),
            )
            if (
                descriptor := _retained_ancestor_descriptor(
                    directory, RECEIPT_PATH.parent
                )
            )
            is not None
        )
        if executable_path == RUNTIME_PYTHON and launcher_path == RUNTIME_LAUNCHER:
            if (
                RECEIPT_PATH.parent != RUNTIME_PATH.parent
                or len(receipt_parent_descriptors) != 3
            ):
                _fail("production receipt directory watch inventory is invalid")
        if descriptors.count(held.fd) != 1:
            _fail("runtime executable watch descriptor inventory is invalid")
        watch = VnodeWatch.open(
            descriptors,
            allow_attrib=(held.fd,),
            allow_write=(controller.directory.fd, *receipt_parent_descriptors),
        )
        result = RuntimeInvocation(
            controller=controller,
            native_capability=native_capability,
            executable=held,
            launchers=launchers,
            expected_launcher_tree=expected_launcher[0],
            expected_launcher_identity=expected_launcher[1],
            expected_launcher_directory=expected_launcher[2],
            watch=watch,
            operations=operations,
        )
        result.validate()
        return result
    except Exception:
        if watch is not None:
            watch.close()
        for launcher in reversed(list(launchers.values())):
            launcher.close()
        if held is not None:
            held.close()
        controller.close()
        raise


def _parse_plan(
    data: bytes,
    *,
    authority: dict[str, object],
    authority_data: bytes,
    current_receipt_data: bytes,
    now: datetime,
) -> tuple[dict[str, object], bytes, dict[str, str]]:
    plan = _exact_keys(_json(data, "migration plan", maximum=MAX_PLAN), PLAN_KEYS, "plan")
    if (
        plan["contract"] != PLAN_CONTRACT
        or plan["schema_version"] != 2
        or type(plan["schema_version"]) is not int
        or plan["status"]
        != "OWNER-BLOCKED: Python runtime receipt migration requires a current external owner-authority approval"
    ):
        _fail("migration plan contract is invalid")
    if canonical_bytes(plan["authority"]) != authority_data or plan["authority"] != authority:
        _fail("migration plan does not bind the fixed authority bytes")
    closure = _validate_closure(plan["closure"], "plan")
    if closure != authority["closure"]:
        _fail("migration plan closure does not match authority")
    current_digest = _sha(plan["current_receipt_sha256"], "plan current receipt")
    if current_digest != _sha256(current_receipt_data):
        _fail("migration plan current receipt is stale")
    if authority["active_receipt_sha256"] != current_digest:
        _fail("authority active receipt is stale or replayed")
    candidate_ascii = plan["candidate_receipt_ascii"]
    if type(candidate_ascii) is not str:
        _fail("candidate receipt ASCII bytes are absent")
    try:
        candidate = candidate_ascii.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProvisionError(f"{OWNER_BLOCKED}: candidate receipt is not ASCII") from exc
    candidate_digest = _sha(plan["candidate_receipt_sha256"], "candidate receipt")
    if _sha256(candidate) != candidate_digest:
        _fail("candidate receipt digest mismatch")
    candidate_record = _parse_candidate_receipt(candidate, closure)
    _validate_native_receipt_authority(candidate_record, authority)
    created = _time(plan["created_utc"], "plan created_utc")
    expires = _time(plan["expires_utc"], "plan expires_utc")
    if expires <= created or (expires - created).total_seconds() > 24 * 60 * 60:
        _fail("migration plan validity interval is invalid")
    if now < created or now >= expires:
        _fail("migration plan is expired or not yet active")
    authority_not_before = _time(authority["not_before_utc"], "authority not_before_utc")
    authority_expires = _time(authority["expires_utc"], "authority expires_utc")
    if now < authority_not_before or now >= authority_expires or expires > authority_expires:
        _fail("authority is expired or not yet active")
    expected_id = _migration_id(
        current_receipt_sha256=current_digest,
        candidate_receipt_sha256=candidate_digest,
        closure=closure,
        authority=authority,
        created_utc=str(plan["created_utc"]),
        expires_utc=str(plan["expires_utc"]),
    )
    if _sha(plan["migration_id"], "migration id") != expected_id:
        _fail("migration identity mismatch")
    operation = _exact_keys(
        plan["expected_external_authority_operation"],
        OPERATION_KEYS,
        "migration operation",
    )
    expected_operation = {
        "action": "owner-authority-approve-and-atomically-publish-receipt",
        "authority_id": authority["authority_id"],
        "authority_key_id": authority["key_id"],
        "authority_path": str(AUTHORITY_PATH),
        "candidate_receipt_sha256": candidate_digest,
        "current_receipt_sha256": current_digest,
        "expected_active_sequence": authority["active_sequence"],
        "migration_id": expected_id,
        "next_sequence": int(authority["active_sequence"]) + 1,
        "receipt_path": str(RECEIPT_PATH),
    }
    if operation != expected_operation:
        _fail("migration operation is not exact")
    return plan, candidate, closure


# Pure-Python Ed25519 verification, copied from the independently reviewed
# Windows owner-authorization boundary so this fixed script has no package or
# OpenSSL import surface while deciding whether root state may change.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx % _P, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P or (x == 0 and sign):
        return None
    return _P - x if x & 1 != sign else x


def _decode(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, value >> 255)
    return None if x is None else (x, y, 1, x * y % _P)


def _add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    aa = (y1 - x1) * (y2 - x2) % _P
    bb = (y1 + x1) * (y2 + x2) % _P
    cc = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    return (
        (bb - aa) * (dd - cc) % _P,
        (dd + cc) * (bb + aa) % _P,
        (dd - cc) * (dd + cc) % _P,
        (bb - aa) * (bb + aa) % _P,
    )


def _mul(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
if _BX is None:
    raise RuntimeError("Ed25519 base point construction failed")
_BASE = (_BX, _BY, 1, _BX * _BY % _P)


def _equal(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % _P == 0
        and (left[1] * right[2] - right[1] * left[2]) % _P == 0
    )


def verify_ed25519(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    authority = _decode(public)
    nonce = _decode(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    neutral = (0, 1, 1, 0)
    if (
        authority is None
        or nonce is None
        or scalar >= _L
        or _equal(authority, neutral)
        or _equal(nonce, neutral)
    ):
        return False
    if not _equal(_mul(authority, _L), neutral) or not _equal(
        _mul(nonce, _L), neutral
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public + message).digest(), "little"
    ) % _L
    return _equal(
        _mul(_BASE, scalar), _add(nonce, _mul(authority, challenge))
    )


def _parse_initial_authority_envelope(
    data: bytes,
    *,
    authority: dict[str, object],
    authority_data: bytes,
    current_receipt_sha256: str,
    capability: NativeCapability,
    now: datetime,
    journal_created_utc: datetime | None = None,
) -> dict[str, object]:
    envelope = _exact_keys(
        _json(data, "initial authority envelope", maximum=MAX_AUTHORIZATION),
        INITIAL_AUTHORITY_ENVELOPE_KEYS,
        "initial authority envelope",
    )
    if (
        envelope["schema_version"] != 1
        or type(envelope["schema_version"]) is not int
        or envelope["contract"] != INITIAL_AUTHORITY_ENVELOPE_CONTRACT
        or envelope["algorithm"] != ALGORITHM
        or envelope["key_id"] != INITIAL_AUTHORITY_KEY_ID
        or type(envelope["authorization"]) is not dict
    ):
        _fail("initial authority envelope identity is invalid")
    signature = envelope["signature"]
    if type(signature) is not str or HEX128.fullmatch(signature) is None:
        _fail("initial authority envelope signature is invalid")
    signed_bytes = canonical_bytes(envelope["authorization"])
    if not verify_ed25519(
        bytes.fromhex(INITIAL_AUTHORITY_KEY_ID),
        INITIAL_AUTHORITY_DOMAIN + signed_bytes,
        bytes.fromhex(signature),
    ):
        _fail("initial authority envelope signature is invalid or uses the wrong key")
    signed = _exact_keys(
        envelope["authorization"],
        INITIAL_AUTHORITY_AUTHORIZATION_KEYS,
        "initial authority authorization",
    )
    if (
        signed["schema_version"] != 1
        or type(signed["schema_version"]) is not int
        or signed["contract"] != INITIAL_AUTHORITY_AUTHORIZATION_CONTRACT
        or signed["action"] != "publish-create-only-v2-authority"
    ):
        _fail("initial authority authorization contract is invalid")
    expected = {
        "active_receipt_sha256": current_receipt_sha256,
        "authority_path": str(AUTHORITY_PATH),
        "authority_sha256": _sha256(authority_data),
        "owner_provision_boundary_sha256": capability.record["controller_sha256"],
        "owner_provision_launcher_device": int(capability.record["launcher_device"]),
        "owner_provision_launcher_inode": int(capability.record["launcher_inode"]),
        "owner_provision_launcher_sha256": capability.record["launcher_sha256"],
    }
    for key, expected_value in expected.items():
        if signed.get(key) != expected_value:
            _fail(f"initial authority authorization binding mismatch: {key}")
    _sha(signed["nonce"], "initial authority authorization nonce")
    issued = _time(signed["issued_utc"], "initial authority authorization issued_utc")
    not_before = _time(
        signed["not_before_utc"], "initial authority authorization not_before_utc"
    )
    expires = _time(signed["expires_utc"], "initial authority authorization expires_utc")
    if (
        not_before < issued
        or expires <= not_before
        or (expires - issued).total_seconds() > MAX_AUTHORIZATION_SECONDS
        or now < not_before
        or now >= expires
        or issued > now
        or (now - issued).total_seconds() > MAX_AUTHORIZATION_SECONDS
        or (not_before - issued).total_seconds() > MAX_FUTURE_SKEW_SECONDS
    ):
        _fail("initial authority authorization is expired, future, or overlong")
    if (
        authority["active_sequence"] != 1
        or authority["key_id"] != INITIAL_AUTHORITY_KEY_ID
        or authority["active_receipt_sha256"] != current_receipt_sha256
        or authority["owner_provision_boundary_sha256"]
        != capability.record["controller_sha256"]
        or authority["owner_provision_launcher_sha256"]
        != capability.record["launcher_sha256"]
        or authority["owner_provision_launcher_source_sha256"]
        != capability.record["launcher_source_sha256"]
        or authority["owner_provision_launcher_build_sha256"]
        != capability.record["launcher_build_sha256"]
        or authority["owner_provision_launcher_compiler_sha256"]
        != capability.record["launcher_compiler_sha256"]
        or authority["owner_provision_launcher_linker_sha256"]
        != capability.record["launcher_linker_sha256"]
        or authority["owner_provision_launcher_sdk_closure_sha256"]
        != capability.record["launcher_sdk_closure_sha256"]
        or authority["owner_provision_launcher_device"]
        != int(capability.record["launcher_device"])
        or authority["owner_provision_launcher_inode"]
        != int(capability.record["launcher_inode"])
        or authority["runtime_launcher_sha256"]
        != capability.record["runtime_launcher_sha256"]
        or authority["runtime_python_sha256"]
        != capability.record["runtime_python_sha256"]
    ):
        _fail("initial authority does not bind the native capability")
    if journal_created_utc is None:
        _require_authority_current(
            authority, now, label="initial authority publication"
        )
    else:
        authority_not_before = _time(
            authority["not_before_utc"], "initial authority not_before_utc"
        )
        authority_expires = _time(
            authority["expires_utc"], "initial authority expires_utc"
        )
        if (
            journal_created_utc < authority_not_before
            or journal_created_utc >= authority_expires
            or now < authority_not_before
        ):
            _fail("initial authority journal was not created while authority was current")
    return signed


def _parse_initial_authority_journal(data: bytes) -> dict[str, object]:
    journal = _exact_keys(
        _json(data, "initial authority journal", maximum=MAX_JOURNAL),
        INITIAL_AUTHORITY_JOURNAL_KEYS,
        "initial authority journal",
    )
    if (
        journal["schema_version"] != 1
        or type(journal["schema_version"]) is not int
        or journal["contract"] != INITIAL_AUTHORITY_JOURNAL_CONTRACT
        or journal["phase"] not in {"preparing", "staged", "published"}
        or type(journal["generation"]) is not int
        or int(journal["generation"]) < 1
    ):
        _fail("initial authority journal contract is invalid")
    for key in ("authority_sha256", "envelope_sha256", "transaction_id"):
        _sha(journal[key], f"initial authority journal {key}")
    expected_stage = (
        f"authority.json.initial-publish.{journal['transaction_id']}.new"
    )
    if journal["stage_name"] != expected_stage or SAFE_NAME.fullmatch(
        str(journal["stage_name"])
    ) is None:
        _fail("initial authority journal stage name is invalid")
    _time(journal["created_utc"], "initial authority journal created_utc")
    return journal


def _parse_authorization(
    data: bytes,
    *,
    authorization_path: Path,
    authority: dict[str, object],
    plan: dict[str, object],
    plan_data: bytes,
    closure: dict[str, str],
    now: datetime,
) -> dict[str, object]:
    envelope = _exact_keys(
        _json(data, "owner authorization", maximum=MAX_AUTHORIZATION),
        AUTHORIZATION_KEYS,
        "owner authorization",
    )
    if (
        envelope["schema_version"] != 2
        or type(envelope["schema_version"]) is not int
        or envelope["contract"] != AUTHORIZATION_ENVELOPE_CONTRACT
        or envelope["algorithm"] != ALGORITHM
        or envelope["key_id"] != authority["key_id"]
    ):
        _fail("owner authorization envelope identity is invalid")
    signed = _exact_keys(
        envelope["authorization"],
        SIGNED_AUTHORIZATION_KEYS,
        "signed owner authorization",
    )
    if (
        signed["schema_version"] != 2
        or type(signed["schema_version"]) is not int
        or signed["contract"] != AUTHORIZATION_CONTRACT
    ):
        _fail("signed owner authorization contract is invalid")
    signature = envelope["signature"]
    if type(signature) is not str or HEX128.fullmatch(signature) is None:
        _fail("owner authorization signature is invalid")
    public_key = bytes.fromhex(str(authority["key_id"]))
    if not verify_ed25519(
        public_key, DOMAIN + canonical_bytes(signed), bytes.fromhex(signature)
    ):
        _fail("owner authorization signature is invalid or uses the wrong key")
    expected = {
        "authority_id": authority["authority_id"],
        "authorization_path": str(authorization_path),
        "authorized_repo_root": authority["authorized_repo_root"],
        "candidate_receipt_sha256": plan["candidate_receipt_sha256"],
        "closure": closure,
        "current_receipt_sha256": plan["current_receipt_sha256"],
        "migration_id": plan["migration_id"],
        "owner_provision_boundary_sha256": authority[
            "owner_provision_boundary_sha256"
        ],
        "owner_provision_launcher_sha256": authority[
            "owner_provision_launcher_sha256"
        ],
        "owner_provision_launcher_compiler_sha256": authority[
            "owner_provision_launcher_compiler_sha256"
        ],
        "owner_provision_launcher_linker_sha256": authority[
            "owner_provision_launcher_linker_sha256"
        ],
        "owner_provision_launcher_sdk_closure_sha256": authority[
            "owner_provision_launcher_sdk_closure_sha256"
        ],
        "plan_sha256": _sha256(plan_data),
        "receipt_path": str(RECEIPT_PATH),
        "sequence": authority["active_sequence"],
    }
    for key, value in expected.items():
        if signed.get(key) != value:
            _fail(f"signed owner authorization binding mismatch: {key}")
    _sha(signed["authorization_id"], "authorization id")
    _sha(signed["nonce"], "authorization nonce")
    issued = _time(signed["issued_utc"], "authorization issued_utc")
    not_before = _time(signed["not_before_utc"], "authorization not_before_utc")
    expires = _time(signed["expires_utc"], "authorization expires_utc")
    if (
        not_before < issued
        or expires <= not_before
        or (expires - issued).total_seconds() > MAX_AUTHORIZATION_SECONDS
        or now < not_before
        or now >= expires
        or issued > now
        or (now - issued).total_seconds() > MAX_AUTHORIZATION_SECONDS
        or (not_before - issued).total_seconds() > MAX_FUTURE_SKEW_SECONDS
    ):
        _fail("owner authorization is expired, future, or overlong")
    return signed


def _next_authority(
    authority: dict[str, object], candidate_receipt_sha256: str
) -> dict[str, object]:
    result = json.loads(canonical_bytes(authority).decode("ascii"))
    result["active_receipt_sha256"] = candidate_receipt_sha256
    result["active_sequence"] = int(authority["active_sequence"]) + 1
    return _parse_authority(canonical_bytes(result))


def _safe_transaction_name(prefix: str, transaction_id: str, suffix: str) -> str:
    name = f"{prefix}.owner-provision.{transaction_id}.{suffix}"
    if SAFE_NAME.fullmatch(name) is None:
        _fail("unsafe transaction filename")
    return name


def _validate_journal_transaction_names(
    journal: dict[str, object],
    _authority_name: str = "authority.json",
    _receipt_name: str = "3.14.7.receipt.json",
    _reserved_names: frozenset[str] = frozenset(
        {
            "authority.json",
            "owner-launcher",
            "owner-provision",
            "owner-provision.transaction.json",
            "owner-provision.transaction.next",
            "3.14.7",
            "3.14.7.receipt.json",
        }
    ),
) -> None:
    """Bind every mutable transaction leaf to its role and transaction ID."""

    transaction_id = journal.get("transaction_id")
    _sha(transaction_id, "journal transaction_id")
    expected = {
        "authority_backup_name": _safe_transaction_name(
            _authority_name, str(transaction_id), "backup"
        ),
        "authority_stage_name": _safe_transaction_name(
            _authority_name, str(transaction_id), "new"
        ),
        "receipt_backup_name": _safe_transaction_name(
            _receipt_name, str(transaction_id), "backup"
        ),
        "receipt_stage_name": _safe_transaction_name(
            _receipt_name, str(transaction_id), "new"
        ),
    }
    actual = {key: journal.get(key) for key in expected}
    if any(type(value) is not str for value in actual.values()):
        _fail("transaction journal filename types are invalid")
    if len(set(actual.values())) != len(actual):
        _fail("transaction journal filenames are not pairwise distinct")
    for key, expected_name in expected.items():
        value = str(actual[key])
        if value in _reserved_names:
            _fail(f"transaction journal filename aliases a reserved leaf: {key}")
        if value != expected_name:
            _fail(f"transaction journal filename is not transaction-bound: {key}")


def _read_fd(fd: int, maximum: int, label: str) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
        if not block:
            break
        total += len(block)
        if total > maximum:
            _fail(f"{label} exceeds its byte ceiling")
        chunks.append(block)
    return b"".join(chunks)


def _create_file(
    directory: HeldDirectory,
    name: str,
    data: bytes,
    *,
    mode: int,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    if SAFE_NAME.fullmatch(name) is None:
        _fail("unsafe transaction leaf name")
    fd = os.open(
        name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
        dir_fd=directory.fd,
    )
    try:
        if os.fstat(fd).st_uid != policy.uid or os.fstat(fd).st_gid != policy.gid:
            os.fchown(fd, policy.uid, policy.gid)
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                _fail("short transaction file write")
            offset += written
        operations.full_sync(fd)
    finally:
        os.close(fd)
    directory.validate()
    operations.sync_directory(directory.fd)


def _seal_recovery_anchor(
    directory: HeldDirectory,
    name: str,
    *,
    expected_sha256: str,
    maximum: int,
    immutable_flags: int,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    if immutable_flags & SF_IMMUTABLE == 0 or immutable_flags & UF_IMMUTABLE:
        _fail("recovery anchor requires exact system-immutable custody")
    anchor = HeldFile.open(
        directory.path / name,
        maximum=maximum,
        policy=policy,
        operations=operations,
        mode=0o400,
        immutable=False,
    )
    try:
        if _sha256(anchor.data) != expected_sha256:
            _fail(f"recovery anchor digest mismatch: {name}")
        operations.set_flags_fd(anchor.fd, immutable_flags)
        operations.full_sync(anchor.fd)
        if (
            _sha256(_read_fd(anchor.fd, maximum, name)) != expected_sha256
            or operations.flags_fd(anchor.fd) != immutable_flags
        ):
            _fail(f"recovery anchor immutable flags are not exact: {name}")
    finally:
        anchor.close()
    directory.validate()
    operations.sync_directory(directory.fd)


def _unlink_if_exists(
    directory: HeldDirectory,
    name: str,
    *,
    operations: SystemOperations | None = None,
) -> None:
    if operations is not None:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory.fd,
            )
        except FileNotFoundError:
            return
        try:
            if operations.flags_fd(descriptor):
                operations.set_flags_fd(descriptor, 0)
                operations.full_sync(descriptor)
        finally:
            os.close(descriptor)
    try:
        os.unlink(name, dir_fd=directory.fd)
    except FileNotFoundError:
        return


def _leaf_bytes(directory: HeldDirectory, name: str, maximum: int) -> bytes | None:
    try:
        info = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
        _fail(f"transaction leaf custody mismatch: {name}")
    fd = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory.fd,
    )
    try:
        before = os.fstat(fd)
        data = _read_fd(fd, maximum, name)
        after = os.fstat(fd)
        if _identity(before, 0) != _identity(after, 0):
            _fail(f"transaction leaf changed while read: {name}")
        return data
    finally:
        os.close(fd)


def _write_journal(
    authority_dir: HeldDirectory,
    paths: ProvisionPaths,
    journal: dict[str, object],
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    data = canonical_bytes(journal)
    if len(data) > MAX_JOURNAL:
        _fail("transaction journal exceeds its byte ceiling")
    _parse_journal(data)
    _unlink_if_exists(authority_dir, paths.journal_next.name)
    _create_file(
        authority_dir,
        paths.journal_next.name,
        data,
        mode=0o600,
        policy=policy,
        operations=operations,
    )
    os.replace(
        paths.journal_next.name,
        paths.journal.name,
        src_dir_fd=authority_dir.fd,
        dst_dir_fd=authority_dir.fd,
    )
    operations.sync_directory(authority_dir.fd)


def _parse_journal(data: bytes) -> dict[str, object]:
    journal = _exact_keys(
        _json(data, "transaction journal", maximum=MAX_JOURNAL),
        JOURNAL_KEYS,
        "transaction journal",
    )
    if (
        journal["schema_version"] != 1
        or type(journal["schema_version"]) is not int
        or journal["contract"] != JOURNAL_CONTRACT
        or journal["phase"] not in PHASES
    ):
        _fail("transaction journal contract is invalid")
    for key in (
        "authorization_sha256",
        "migration_id",
        "new_authority_sha256",
        "new_receipt_sha256",
        "old_authority_sha256",
        "old_receipt_sha256",
        "plan_sha256",
        "transaction_id",
    ):
        _sha(journal[key], f"journal {key}")
    for key in (
        "authority_backup_name",
        "authority_stage_name",
        "receipt_backup_name",
        "receipt_stage_name",
    ):
        if type(journal[key]) is not str or SAFE_NAME.fullmatch(str(journal[key])) is None:
            _fail(f"transaction journal filename is unsafe: {key}")
    _validate_journal_transaction_names(journal)
    for key in ("generation", "old_authority_flags", "old_receipt_flags"):
        if type(journal[key]) is not int or int(journal[key]) < 0:
            _fail(f"transaction journal integer is invalid: {key}")
    for key in ("old_authority_mode", "old_receipt_mode"):
        if type(journal[key]) is not int or int(journal[key]) not in {0o400, 0o444}:
            _fail(f"transaction journal mode is invalid: {key}")
    repo = journal["authorized_repo_root"]
    if type(repo) is not str or not repo.startswith("/") or repo == "/":
        _fail("transaction journal repository root is invalid")
    _time(journal["created_utc"], "journal created_utc")
    return journal


def _advance_journal(
    authority_dir: HeldDirectory,
    paths: ProvisionPaths,
    journal: dict[str, object],
    phase: str,
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> dict[str, object]:
    if phase not in PHASES or PHASES[phase] < PHASES[str(journal["phase"])]:
        _fail("transaction journal phase regression")
    updated = dict(journal)
    updated["generation"] = int(journal["generation"]) + 1
    updated["phase"] = phase
    _write_journal(
        authority_dir,
        paths,
        updated,
        policy=policy,
        operations=operations,
    )
    return updated


def _current_leaf_digest(directory: HeldDirectory, name: str, maximum: int) -> str:
    data = _leaf_bytes(directory, name, maximum)
    if data is None:
        return ""
    return _sha256(data)


def _replace_from_stage(
    directory: HeldDirectory,
    stage_name: str,
    target_name: str,
    *,
    expected_sha256: str,
    mode: int,
    immutable_flags: int,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    stage_fd = os.open(
        stage_name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory.fd,
    )
    try:
        stage = os.fstat(stage_fd)
        if (
            not stat.S_ISREG(stage.st_mode)
            or stage.st_nlink != 1
            or stage.st_uid != policy.uid
            or stage.st_gid != policy.gid
            or _sha256(_read_fd(stage_fd, MAX_PLAN, stage_name)) != expected_sha256
        ):
            _fail(f"transaction stage is invalid: {stage_name}")
        operations.set_flags_fd(stage_fd, 0)
    finally:
        os.close(stage_fd)
    try:
        target_fd = os.open(
            target_name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory.fd,
        )
    except FileNotFoundError:
        target_fd = None
    if target_fd is not None:
        try:
            operations.set_flags_fd(target_fd, 0)
        finally:
            os.close(target_fd)
    os.replace(
        stage_name,
        target_name,
        src_dir_fd=directory.fd,
        dst_dir_fd=directory.fd,
    )
    operations.sync_directory(directory.fd)
    published = os.open(
        target_name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory.fd,
    )
    try:
        if os.fstat(published).st_uid != policy.uid or os.fstat(published).st_gid != policy.gid:
            os.fchown(published, policy.uid, policy.gid)
        os.fchmod(published, mode)
        if _sha256(_read_fd(published, MAX_PLAN, target_name)) != expected_sha256:
            _fail(f"published transaction digest mismatch: {target_name}")
        operations.set_flags_fd(published, immutable_flags)
        operations.full_sync(published)
    finally:
        os.close(published)
    operations.sync_directory(directory.fd)


def _restore_leaf_custody(
    directory: HeldDirectory,
    name: str,
    *,
    expected_sha256: str,
    maximum: int,
    mode: int,
    immutable_flags: int,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    fd = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory.fd,
    )
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or _sha256(_read_fd(fd, maximum, name)) != expected_sha256
        ):
            _fail(f"published leaf cannot be restored safely: {name}")
        current_flags = operations.flags_fd(fd)
        exact = (
            info.st_uid == policy.uid
            and info.st_gid == policy.gid
            and stat.S_IMODE(info.st_mode) == mode
            and current_flags == immutable_flags
        )
        if not exact:
            if current_flags:
                operations.set_flags_fd(fd, 0)
            if info.st_uid != policy.uid or info.st_gid != policy.gid:
                os.fchown(fd, policy.uid, policy.gid)
            os.fchmod(fd, mode)
            operations.set_flags_fd(fd, immutable_flags)
            operations.full_sync(fd)
        final = os.fstat(fd)
        if (
            final.st_uid != policy.uid
            or final.st_gid != policy.gid
            or stat.S_IMODE(final.st_mode) != mode
            or operations.flags_fd(fd) != immutable_flags
            or _sha256(_read_fd(fd, maximum, name)) != expected_sha256
        ):
            _fail(f"published leaf custody restoration failed: {name}")
    finally:
        os.close(fd)
    directory.validate()
    operations.sync_directory(directory.fd)


Reauthenticate = Callable[
    [Path, bytes, dict[str, str], Optional[HeldDependencies], int, int], None
]
CrashHook = Callable[[str], None]


def _noop_crash_hook(_point: str) -> None:
    return


def _acquire_transaction_lock(authority_dir: HeldDirectory) -> None:
    try:
        fcntl.flock(authority_dir.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, OSError) as exc:
        _fail(f"another owner-provision transaction holds the authority lock: {exc}")
    authority_dir.validate()


def _authorized_repo_owner(info: os.stat_result) -> tuple[int, int]:
    if not stat.S_ISDIR(info.st_mode):
        _fail("authorized repository root is not a directory")
    uid = info.st_uid
    gid = info.st_gid
    if uid <= 0 or gid < 0:
        _fail("authorized repository owner identity is invalid")
    try:
        account = pwd.getpwuid(uid)
    except KeyError as exc:
        raise ProvisionError(
            f"{OWNER_BLOCKED}: authorized repository owner account is absent"
        ) from exc
    return uid, account.pw_gid


def _darwin_child_pids(parent_pid: int) -> set[int]:
    if sys.platform != "darwin" or parent_pid <= 1:
        _fail("complete descendant inventory is unavailable")
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_listchildpids
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    function.restype = ctypes.c_int
    capacity = 4096
    values = (ctypes.c_int * capacity)()
    ctypes.set_errno(0)
    count = function(parent_pid, values, ctypes.sizeof(values))
    if count < 0:
        if ctypes.get_errno() == errno.ESRCH:
            return set()
        _fail("complete descendant inventory failed closed")
    if count >= capacity:
        _fail("complete descendant inventory exceeded its fixed cap")
    return {
        int(values[index])
        for index in range(count)
        if int(values[index]) > 1
    }


def _track_descendants(root_pid: int, tracked: set[int]) -> None:
    pending = [root_pid]
    visited: set[int] = set()
    while pending:
        parent = pending.pop()
        if parent in visited:
            continue
        visited.add(parent)
        try:
            children = _darwin_child_pids(parent)
        except ProvisionError:
            if parent == root_pid:
                raise
            children = set()
        for child in children:
            if child not in tracked:
                tracked.add(child)
            pending.append(child)


def _kill_child_group(
    process: subprocess.Popen[bytes], tracked: set[int] | None = None
) -> None:
    descendants = tracked if tracked is not None else {process.pid}
    if sys.platform == "darwin":
        try:
            _track_descendants(process.pid, descendants)
        except ProvisionError:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    for pid in sorted(descendants, reverse=True):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            pass


def _require_process_group_gone(process_group: int, *, timeout: float = 5.0) -> None:
    if timeout <= 0:
        _fail("bounded child process-group cleanup deadline expired")
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.kill(-process_group, 0)
        except ProcessLookupError:
            return
        except PermissionError as exc:
            raise ProvisionError(
                f"{OWNER_BLOCKED}: bounded child process-group custody is unprovable"
            ) from exc
        if time.monotonic() >= deadline:
            _fail("bounded child process group survived forced cleanup")
        time.sleep(0.01)


def _kill_unreturned_child_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _reap_unreturned_child(pid: int, *, deadline: float) -> None:
    while True:
        try:
            waited, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        if waited == pid:
            return
        if time.monotonic() >= deadline:
            _fail("bounded child creation cleanup deadline expired")
        time.sleep(0.01)


def _read_spawn_pid(descriptor: int, *, deadline: float) -> int:
    data = bytearray()
    eof = False
    selector = selectors.DefaultSelector()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        while not eof:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("bounded child PID custody exceeded its absolute deadline")
            if not selector.select(remaining):
                _fail("bounded child PID custody exceeded its absolute deadline")
            try:
                block = os.read(descriptor, 9 - len(data))
            except BlockingIOError:
                continue
            if not block:
                eof = True
            else:
                data.extend(block)
                if len(data) > 8:
                    _fail("bounded child PID custody frame is oversized")
    finally:
        selector.close()
    if len(data) != 8:
        _fail("bounded child PID custody frame is incomplete")
    pid = int(struct.unpack("!Q", data)[0])
    if pid <= 1:
        _fail("bounded child PID custody frame is invalid")
    return pid


def _start_bounded_process(
    argv: list[str],
    *,
    env: dict[str, str],
    pass_fds: tuple[int, ...],
    preexec_fn: Callable[[], None] | None,
    forbid_descendants: bool,
    deadline: float,
) -> subprocess.Popen[bytes]:
    if (
        threading.current_thread() is not threading.main_thread()
        or threading.active_count() != 1
    ):
        _fail("bounded child creation requires the sole main thread")
    prior_handler = signal.getsignal(signal.SIGALRM)
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    if prior_timer != (0.0, 0.0):
        _fail("bounded child creation found an active real-time interval timer")
    status_read, status_write = os.pipe()
    os.set_blocking(status_read, False)
    creation_pid: dict[str, int | None] = {"value": None}
    creation_expired = {"value": False}

    def prepare_child() -> None:
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            os._exit(124)
        signal.setitimer(signal.ITIMER_REAL, remaining, 0.0)
        os.write(status_write, struct.pack("!Q", os.getpid()))
        if preexec_fn is not None:
            preexec_fn()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if forbid_descendants:
            # This blocks direct forks by the dropped child. Launchd-brokered
            # XPC services are not descendants and remain outside this PID proof.
            resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
        os.close(status_write)

    def creation_alarm(_signum: int, _frame: object) -> None:
        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
        creation_expired["value"] = True
        if creation_pid["value"] is None:
            try:
                data = os.read(status_read, 8)
            except BlockingIOError:
                data = b""
            if len(data) == 8:
                observed = int(struct.unpack("!Q", data)[0])
                if observed > 1:
                    creation_pid["value"] = observed
        if creation_pid["value"] is not None:
            _kill_unreturned_child_group(creation_pid["value"])

    process: subprocess.Popen[bytes] | None = None
    primary: BaseException | None = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("bounded child creation exceeded its monotonic absolute deadline")
        signal.signal(signal.SIGALRM, creation_alarm)
        signal.setitimer(signal.ITIMER_REAL, remaining, 0.0)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                pass_fds=tuple(sorted({*pass_fds, status_write})),
                close_fds=True,
                start_new_session=True,
                preexec_fn=prepare_child,
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
            signal.signal(signal.SIGALRM, prior_handler)
            signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        os.close(status_write)
        status_write = -1
        expired = creation_expired["value"] or time.monotonic() >= deadline
        status_deadline = time.monotonic() + 5.0 if expired else deadline
        observed_pid = creation_pid["value"]
        if observed_pid is None:
            observed_pid = _read_spawn_pid(status_read, deadline=status_deadline)
        creation_pid["value"] = observed_pid
        if observed_pid != process.pid:
            _fail("bounded child PID custody differs from Popen")
        if expired:
            _fail("bounded child creation exceeded its monotonic absolute deadline")
        return process
    except BaseException as exc:
        primary = exc
        cleanup_deadline = time.monotonic() + 5.0
        if status_write >= 0:
            os.close(status_write)
            status_write = -1
        if creation_pid["value"] is None:
            try:
                creation_pid["value"] = _read_spawn_pid(
                    status_read, deadline=cleanup_deadline
                )
            except (ProvisionError, OSError, ValueError):
                creation_pid["value"] = None
        if process is not None:
            creation_pid["value"] = process.pid
        if creation_pid["value"] is None:
            raise ProvisionError(
                f"{OWNER_BLOCKED}: bounded child creation failed and PID custody is unavailable"
            ) from primary
        if process is None:
            try:
                waited, _status = os.waitpid(creation_pid["value"], os.WNOHANG)
            except ChildProcessError:
                waited = creation_pid["value"]
            if waited == 0:
                _kill_unreturned_child_group(creation_pid["value"])
                _reap_unreturned_child(
                    creation_pid["value"], deadline=cleanup_deadline
                )
        else:
            _kill_unreturned_child_group(creation_pid["value"])
            try:
                process.wait(
                    timeout=max(0.001, cleanup_deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(
                        timeout=max(0.001, cleanup_deadline - time.monotonic())
                    )
                except subprocess.TimeoutExpired:
                    _fail("bounded child creation cleanup wait exceeded its fixed deadline")
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
        signal.signal(signal.SIGALRM, prior_handler)
        signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        if status_write >= 0:
            os.close(status_write)
        os.close(status_read)


def _run_bounded_child(
    argv: list[str],
    *,
    env: dict[str, str],
    pass_fds: tuple[int, ...] = (),
    preexec_fn: Callable[[], None] | None = None,
    forbid_descendants: bool = False,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    if timeout <= 0:
        _fail("child absolute deadline is invalid")

    deadline = time.monotonic() + timeout
    process = _start_bounded_process(
        argv,
        env=env,
        pass_fds=pass_fds,
        preexec_fn=preexec_fn,
        forbid_descendants=forbid_descendants,
        deadline=deadline,
    )
    if process.stdout is None or process.stderr is None:
        _kill_child_group(process)
        process.wait()
        _fail("bounded child output pipes are absent")
    selector = selectors.DefaultSelector()
    streams = {
        process.stdout.fileno(): ("stdout", process.stdout, MAX_CHILD_STDOUT),
        process.stderr.fileno(): ("stderr", process.stderr, MAX_CHILD_STDERR),
    }
    output: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    totals = {"stdout": 0, "stderr": 0}
    group_cleaned = False
    tracked = {process.pid}
    try:
        for descriptor, (_name, stream, _cap) in streams.items():
            os.set_blocking(descriptor, False)
            selector.register(stream, selectors.EVENT_READ, descriptor)
        while selector.get_map() or process.poll() is None:
            running = process.poll() is None
            if sys.platform == "darwin" and running:
                _track_descendants(process.pid, tracked)
                if forbid_descendants and tracked != {process.pid}:
                    _fail("bounded child created a forbidden descendant")
            if not running and not group_cleaned:
                _kill_child_group(process, tracked)
                group_cleaned = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("bounded child exceeded its monotonic absolute deadline")
            select_timeout = min(remaining, 0.05)
            events = selector.select(select_timeout)
            if not events and time.monotonic() >= deadline:
                _fail("bounded child exceeded its monotonic absolute deadline")
            for key, _mask in events:
                descriptor = int(key.data)
                name, stream, cap = streams[descriptor]
                try:
                    block = os.read(descriptor, min(64 * 1024, cap + 1 - totals[name]))
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(stream)
                    stream.close()
                    continue
                totals[name] += len(block)
                if (
                    totals[name] > cap
                    or totals["stdout"] + totals["stderr"] > MAX_CHILD_TOTAL_OUTPUT
                ):
                    _fail(f"bounded child {name} exceeded its exact byte cap")
                output[name].append(block)
            if process.poll() is not None and not group_cleaned:
                _kill_child_group(process, tracked)
                group_cleaned = True
        if not group_cleaned:
            _kill_child_group(process, tracked)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _fail("bounded child wait exceeded its monotonic absolute deadline")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _fail("bounded child wait exceeded its monotonic absolute deadline")
        if returncode == -signal.SIGALRM:
            _fail("bounded child exceeded its monotonic absolute deadline")
        remaining = deadline - time.monotonic()
        _require_process_group_gone(process.pid, timeout=remaining)
        for pid in tracked - {process.pid}:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            _fail("complete descendant cleanup could not be proven")
        return returncode, b"".join(output["stdout"]), b"".join(output["stderr"])
    except Exception:
        cleanup_deadline = time.monotonic() + 5.0
        _kill_child_group(process, tracked)
        try:
            process.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(
                    timeout=max(0.001, cleanup_deadline - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                _fail("bounded child cleanup wait exceeded its fixed deadline")
        _require_process_group_gone(
            process.pid,
            timeout=max(0.001, cleanup_deadline - time.monotonic()),
        )
        raise
    finally:
        selector.close()
        for _name, stream, _cap in streams.values():
            if not stream.closed:
                stream.close()


def _package_signature_stream_is_current_psf_trust(
    stdout: bytes,
    stderr: bytes,
    *,
    package_name: str,
    expected_status: str,
) -> bool:
    if (
        stderr
        or not stdout
        or len(stdout) > 128 * 1024
        or not stdout.endswith(b"\n")
        or b"\r" in stdout
        or b"\0" in stdout
    ):
        return False
    try:
        lines = stdout.decode("utf-8", "strict")[:-1].split("\n")
    except UnicodeDecodeError:
        return False
    header = f'Package "{package_name}":'
    status = f"   {expected_status}"
    notarization = "   Notarization: trusted by the Apple notary service"
    timestamp_prefix = "   Signed with a trusted timestamp on: "
    chain = "   Certificate Chain:"
    leaf = (
        "    1. Developer ID Installer: Python Software Foundation "
        "(BMM5U3QVKW)"
    )
    if len(lines) < 6 or lines[:3] != [header, status, notarization]:
        return False
    timestamp = lines[3]
    timestamp_value = timestamp.removeprefix(timestamp_prefix)
    if (
        not timestamp.startswith(timestamp_prefix)
        or not timestamp_value
        or timestamp_value.strip() != timestamp_value
        or lines[4:6] != [chain, leaf]
    ):
        return False
    return (
        lines.count(header) == 1
        and lines.count(status) == 1
        and lines.count(notarization) == 1
        and sum(line.startswith(timestamp_prefix) for line in lines) == 1
        and lines.count(chain) == 1
        and lines.count(leaf) == 1
    )


def _escape_failure_bytes(data: bytes) -> str:
    escaped: list[str] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E and byte not in {0x22, 0x5C}:
            escaped.append(chr(byte))
        elif byte == 0x0A:
            escaped.append("\\n")
        elif byte == 0x0D:
            escaped.append("\\r")
        elif byte == 0x09:
            escaped.append("\\t")
        else:
            escaped.append(f"\\x{byte:02x}")
    return "".join(escaped)


def _bounded_child_failure_details(
    returncode: int, stdout: bytes, stderr: bytes
) -> str:
    if len(stderr) <= MAX_CHILD_FAILURE_EXCERPT:
        excerpt = _escape_failure_bytes(stderr)
    else:
        head_size = MAX_CHILD_FAILURE_EXCERPT // 2
        tail_size = MAX_CHILD_FAILURE_EXCERPT - head_size
        omitted = len(stderr) - head_size - tail_size
        excerpt = (
            _escape_failure_bytes(stderr[:head_size])
            + f"<...{omitted} bytes omitted...>"
            + _escape_failure_bytes(stderr[-tail_size:])
        )
    return (
        f"returncode={returncode} "
        f"stdout_bytes={len(stdout)} stdout_sha256={_sha256(stdout)} "
        f"stderr_bytes={len(stderr)} stderr_sha256={_sha256(stderr)} "
        f"stderr_excerpt={json.dumps(excerpt, ensure_ascii=True)}"
    )


_EXPECTED_RECEIPT_IMPORTS = frozenset(
    {
        ("from", "__future__", "annotations", None),
        ("import", "hashlib", "", None),
        ("import", "hmac", "", None),
        ("import", "json", "", None),
        ("import", "os", "", None),
        ("from", "pathlib", "Path", None),
        ("import", "re", "", None),
        ("import", "stat", "", None),
        ("import", "subprocess", "", None),
        ("import", "sys", "", None),
        ("import", "xml.etree.ElementTree", "", "ElementTree"),
        ("from", "contextlib", "contextmanager", None),
        ("from", "datetime", "datetime", None),
        ("from", "datetime", "timedelta", None),
        ("from", "datetime", "timezone", None),
        ("from", "typing", "Iterator", None),
    }
)


def _validate_reauthentication_exec_surface(source_data: bytes) -> None:
    try:
        source = source_data.decode("utf-8", "strict")
        tree = ast.parse(source, filename=RECEIPT_SCHEMA_RELATIVE, mode="exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ProvisionError(
            f"{OWNER_BLOCKED}: held receipt schema source is not parseable"
        ) from exc
    imports: set[tuple[str, str, str, str | None]] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.update(
                ("import", alias.name, "", alias.asname) for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level != 0 or node.module is None:
                _fail("held receipt schema relative import rejected")
            imports.update(
                ("from", node.module, alias.name, alias.asname)
                for alias in node.names
            )
    if imports != _EXPECTED_RECEIPT_IMPORTS:
        _fail("held receipt schema import surface drift rejected")

    class ExecSurfaceVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.functions: list[str] = []
            self.subprocess_runs: list[tuple[str, ast.Call]] = []
            self.gate_calls: list[tuple[str, int]] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.functions.append(node.name)
            self.generic_visit(node)
            self.functions.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            _fail("held receipt schema asynchronous function surface rejected")

        def visit_Call(self, node: ast.Call) -> None:
            function = node.func
            if isinstance(function, ast.Name) and function.id in {
                "eval",
                "exec",
                "compile",
                "__import__",
            }:
                _fail("held receipt schema dynamic execution surface rejected")
            if isinstance(function, ast.Name) and function.id in {
                "_consume_codesign_invocation_budget",
                "_validate_codesign_command",
            }:
                self.gate_calls.append((function.id, node.lineno))
            if isinstance(function, ast.Attribute) and isinstance(
                function.value, ast.Name
            ):
                module = function.value.id
                name = function.attr
                if module == "subprocess":
                    if name != "run":
                        _fail("held receipt schema subprocess surface drift rejected")
                    self.subprocess_runs.append(
                        (self.functions[-1] if self.functions else "", node)
                    )
                if module == "os" and (
                    name in {"fork", "forkpty", "popen", "setsid", "system"}
                    or name.startswith("exec")
                    or name.startswith("spawn")
                    or name.startswith("posix_spawn")
                ):
                    _fail("held receipt schema process surface drift rejected")
            if (
                isinstance(function, ast.Name)
                and function.id == "getattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in {"os", "subprocess"}
            ):
                if (
                    node.args[0].id != "os"
                    or len(node.args) < 2
                    or not isinstance(node.args[1], ast.Constant)
                    or node.args[1].value not in {"O_CLOEXEC", "O_NOFOLLOW"}
                ):
                    _fail("held receipt schema dynamic process lookup rejected")
            self.generic_visit(node)

    visitor = ExecSurfaceVisitor()
    visitor.visit(tree)
    if len(visitor.subprocess_runs) != 1 or visitor.subprocess_runs[0][0] != "_run_codesign":
        _fail("held receipt schema subprocess gate is not exact")
    run_call = visitor.subprocess_runs[0][1]
    if (
        len(run_call.args) != 1
        or not isinstance(run_call.args[0], ast.Name)
        or run_call.args[0].id != "expected"
        or any(keyword.arg is None for keyword in run_call.keywords)
    ):
        _fail("held receipt schema subprocess call shape rejected")
    keywords = {keyword.arg: keyword.value for keyword in run_call.keywords}
    expected_keywords = {
        "capture_output",
        "check",
        "close_fds",
        "cwd",
        "env",
        "pass_fds",
        "shell",
        "stdin",
        "timeout",
    }
    if set(keywords) != expected_keywords:
        _fail("held receipt schema subprocess keyword surface rejected")

    def literal_matches(key: str, expected: object) -> bool:
        try:
            return ast.literal_eval(keywords[key]) == expected
        except (ValueError, TypeError):
            return False

    if any(
        not literal_matches(key, expected)
        for key, expected in {
            "capture_output": True,
            "check": False,
            "close_fds": True,
            "cwd": "/",
            "env": {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
            "pass_fds": (),
            "shell": False,
        }.items()
    ):
        _fail("held receipt schema subprocess literal policy rejected")
    stdin = keywords["stdin"]
    timeout = keywords["timeout"]
    if (
        not isinstance(stdin, ast.Attribute)
        or not isinstance(stdin.value, ast.Name)
        or stdin.value.id != "subprocess"
        or stdin.attr != "DEVNULL"
        or not isinstance(timeout, ast.Name)
        or timeout.id != "CODESIGN_TIMEOUT_SECONDS"
    ):
        _fail("held receipt schema subprocess runtime policy rejected")
    required_gates = {
        "_validate_codesign_command": 0,
        "_consume_codesign_invocation_budget": 0,
    }
    for name, lineno in visitor.gate_calls:
        if name in required_gates:
            if required_gates[name] != 0:
                _fail("held receipt schema subprocess gate is duplicated")
            required_gates[name] = lineno
    if any(lineno == 0 or lineno >= run_call.lineno for lineno in required_gates.values()):
        _fail("held receipt schema subprocess gate does not dominate execution")


@contextmanager
def _held_package_probe_descriptor(package: HeldArtifact) -> Iterable[int]:
    """Open one private description of the retained package for one pkgutil call."""
    fd = os.open(
        package.path.name,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=package.directory.fd,
    )
    try:
        opened = os.fstat(fd)
        flags = package.operations.flags_fd(fd)
        if _identity(opened, flags) != package.identity:
            _fail(
                f"held package probe descriptor is not the retained package: "
                f"{package.path}"
            )
        if _digest_fd_pread(fd, package.maximum, str(package.path)) != package.digest:
            _fail(
                f"held package probe descriptor bytes are not retained: {package.path}"
            )
        if os.lseek(fd, 0, os.SEEK_CUR) != 0:
            _fail(
                f"held package probe descriptor offset is not exact: {package.path}"
            )
        yield fd
    finally:
        os.close(fd)


def _production_reauthenticate(
    receipt_path: Path,
    candidate_data: bytes,
    closure: dict[str, str],
    dependencies: HeldDependencies | None,
    owner_uid: int,
    owner_gid: int,
) -> None:
    if dependencies is None:
        _fail("production dependency descriptor custody is absent")
    dependencies.validate()
    try:
        owner_account = pwd.getpwuid(owner_uid)
    except KeyError as exc:
        raise ProvisionError(
            f"{OWNER_BLOCKED}: authorized repository owner account is absent"
        ) from exc
    if owner_uid <= 0 or owner_gid < 0 or owner_account.pw_gid != owner_gid:
        _fail("authorized repository owner handoff is invalid")
    repo = Path(os.environ.get("WINS_RELEASE_PYTHON_AUTHORIZED_REPO", ""))
    if not repo.is_absolute() or repo == Path("/"):
        _fail("authorized repository handoff is missing")
    source_path = repo / RECEIPT_SCHEMA_RELATIVE
    source_fd = os.open(
        source_path,
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    source_data = _read_fd(source_fd, MAX_CONTROLLER, "receipt schema")
    if _sha256(source_data) != closure["custody_controller_sha256"]:
        os.close(source_fd)
        _fail("post-publication receipt schema digest mismatch")
    _validate_reauthentication_exec_surface(source_data)
    try:
        receipt_fd = os.open(
            receipt_path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
    except Exception:
        os.close(source_fd)
        raise
    receipt_before = os.fstat(receipt_fd)
    receipt_data = _read_fd(receipt_fd, MAX_RECEIPT, "candidate receipt")
    receipt_after = os.fstat(receipt_fd)
    if (
        not stat.S_ISREG(receipt_before.st_mode)
        or receipt_before.st_nlink != 1
        or _identity(receipt_before, 0) != _identity(receipt_after, 0)
        or receipt_data != candidate_data
    ):
        os.close(receipt_fd)
        os.close(source_fd)
        _fail("candidate receipt descriptor or bytes changed before reauthentication")
    bootstrap = r'''import hashlib,json,os,pathlib,stat,sys
assert sys.flags.isolated==1 and sys.flags.no_site==1
fd=int(os.environ["WINS_HELD_SCHEMA_FD"])
expected=os.environ["WINS_HELD_SCHEMA_SHA256"]
path=os.environ["WINS_HELD_SCHEMA_PATH"]
identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns,getattr(s,"st_flags",0))
before=os.fstat(fd)
os.lseek(fd,0,0)
data=b"".join(iter(lambda:os.read(fd,1048576),b""))
after=os.fstat(fd)
assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
assert identity(before)==identity(after) and hashlib.sha256(data).hexdigest()==expected
namespace={"__name__":"_winsvpn_bound_release_python_receipt","__file__":path}
exec(compile(data,path,"exec"),namespace,namespace)
repo=pathlib.Path(os.environ["WINS_AUTHORIZED_REPO"])
manifest=repo / "tools/toolchain-pins.json"
receipt_path=pathlib.Path(os.environ["WINS_CANDIDATE_RECEIPT"])
rfd=int(os.environ["WINS_CANDIDATE_RECEIPT_FD"])
rbefore=os.fstat(rfd)
os.lseek(rfd,0,0)
rdata=b"".join(iter(lambda:os.read(rfd,1048576),b""))
rafter=os.fstat(rfd)
assert stat.S_ISREG(rbefore.st_mode) and rbefore.st_nlink==1
assert identity(rbefore)==identity(rafter)==identity(os.stat(receipt_path,follow_symlinks=False))
assert hashlib.sha256(rdata).hexdigest()==os.environ["WINS_CANDIDATE_RECEIPT_SHA256"]
os.environ["WINS_RECEIPT_EXECUTED_SOURCE_SHA256"]=expected
receipt=namespace["parse_receipt"](rdata)
records=json.loads(os.environ["WINS_HELD_DEPENDENCIES_JSON"])
assert isinstance(records,list) and len(records)>=3
seen=set()
held_dependencies=[]
for record in records:
    assert isinstance(record,dict) and set(record)=={"fd","kind","path","sha256"}
    dfd=record["fd"]
    assert isinstance(dfd,int) and dfd>=0 and dfd not in seen
    seen.add(dfd)
    dpath=pathlib.Path(record["path"])
    assert dpath.is_absolute() and record["kind"] in {"package","sigstore","sigstore-root","sigstore-verifier","wheel"}
    dinfo=os.fstat(dfd)
    assert stat.S_ISREG(dinfo.st_mode) and dinfo.st_nlink==1 and not (dinfo.st_mode & 0o222)
    assert identity(dinfo)==identity(os.stat(dpath,follow_symlinks=False))
    offset=0
    digest=hashlib.sha256()
    while offset<dinfo.st_size:
        block=os.pread(dfd,min(1048576,dinfo.st_size-offset),offset)
        assert block
        digest.update(block)
        offset+=len(block)
    assert not os.pread(dfd,1,offset)
    assert digest.hexdigest()==record["sha256"]
    held_dependencies.append((record,identity(dinfo)))
packages=[record for record,_identity in held_dependencies if record["kind"]=="package"]
bundles=[record for record,_identity in held_dependencies if record["kind"]=="sigstore"]
roots=[record for record,_identity in held_dependencies if record["kind"]=="sigstore-root"]
verifiers=[record for record,_identity in held_dependencies if record["kind"]=="sigstore-verifier"]
wheel_records=[record for record,_identity in held_dependencies if record["kind"]=="wheel"]
assert len(packages)==1 and len(bundles)==1 and len(roots)==1 and len(verifiers)==1 and len(wheel_records)==receipt["wheel_count"]
package_record=packages[0]
assert package_record["sha256"]==receipt["package_sha256"]
assert [{"name":pathlib.Path(item["path"]).name,"sha256":item["sha256"]} for item in wheel_records]==receipt["wheels"]
if os.environ["WINS_REAUTH_MODE"]=="published":
    namespace["authenticate"](repo,manifest,required_uid=0)
else:
    with namespace["hold_repo_closure"](repo,manifest) as held:
        closure=held.closure()
        authority=namespace["_read_migration_authority"]()
        namespace["require_authority_current"](authority,namespace["production_utc_now"]())
        namespace["require_authority_for_repo"](authority,repo,closure)
        namespace["require_authority_bound_custody_metadata"](repo,closure,data=held.data["custody_metadata_sha256"])
        if receipt["custody_closure"]!=closure:
            raise RuntimeError("candidate custody closure mismatch")
        pin=namespace["parse_pin_manifest_bytes"](held.data["pin_manifest_sha256"])
        package_sha,wheels=namespace["pin_wheels"](pin)
        if package_sha!=package_record["sha256"] or wheels!=receipt["wheels"]:
            raise RuntimeError("held dependency pins changed")
        measured=namespace["measure_runtime"](pathlib.Path(receipt["runtime_path"]),required_uid=0)
        namespace["require_owner_signing_policy"](authority,measured["codesign_entrypoints"],measured["gatekeeper_assessment"])
        controllers={"controller_sha256":closure["wrapper_sha256"],"provisioner_sha256":closure["provisioner_sha256"],"receipt_schema_sha256":closure["custody_controller_sha256"]}
        namespace["match_receipt_to_runtime"](receipt,runtime=pathlib.Path(receipt["runtime_path"]),framework=measured["framework"],vendor=measured["vendor"],launcher=measured["launcher"],executable=pathlib.Path(measured["executable_path"]),controllers=controllers,package_sha256=package_sha,wheels=wheels,codesign=measured["codesign"],package_signature_status=receipt["package_signature_status"],codesign_entrypoints=measured["codesign_entrypoints"],custody_closure=closure,gatekeeper=measured["gatekeeper_assessment"])
        held.assert_current()
assert os.environ["WINS_CODESIGN_INVOCATION_LIMIT"]==str(namespace["CODESIGN_INVOCATION_LIMIT"])
assert namespace["_codesign_invocation_count"]==namespace["CODESIGN_INVOCATION_LIMIT"]
os.lseek(rfd,0,0)
rfinal=b"".join(iter(lambda:os.read(rfd,1048576),b""))
assert identity(os.fstat(rfd))==identity(rbefore)==identity(os.stat(receipt_path,follow_symlinks=False))
assert rfinal==rdata
for record,expected_identity in held_dependencies:
    assert identity(os.fstat(record["fd"]))==expected_identity==identity(os.stat(record["path"],follow_symlinks=False))
print("REAUTHENTICATED")
'''
    mode = "published" if receipt_path == RECEIPT_PATH else "candidate"
    env = {
        "DYLD_FRAMEWORK_PATH": str(RUNTIME_PATH),
        "DYLD_LIBRARY_PATH": str(RUNTIME_PATH / "Python.framework/Versions/3.14/lib"),
        "HOME": "/private/var/empty",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": str(RUNTIME_PATH / "vendor"),
        "WINS_HELD_SCHEMA_FD": str(source_fd),
        "WINS_HELD_SCHEMA_PATH": str(source_path),
        "WINS_HELD_SCHEMA_SHA256": closure["custody_controller_sha256"],
        "WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT": str(receipt_path),
        "WINS_AUTHORIZED_REPO": str(repo),
        "WINS_CANDIDATE_RECEIPT": str(receipt_path),
        "WINS_CANDIDATE_RECEIPT_FD": str(receipt_fd),
        "WINS_CANDIDATE_RECEIPT_SHA256": _sha256(candidate_data),
        "WINS_CODESIGN_INVOCATION_LIMIT": str(REAUTH_CODESIGN_INVOCATION_LIMIT),
        "WINS_HELD_DEPENDENCIES_JSON": canonical_bytes(
            dependencies.child_records()
        ).decode("ascii").rstrip("\n"),
        "WINS_REAUTH_MODE": mode,
    }

    def drop() -> None:
        os.setgroups([])
        os.setgid(owner_gid)
        os.setuid(owner_uid)
        os.umask(0o077)

    try:
        if os.lseek(dependencies.package.fd, 0, os.SEEK_CUR) != 0:
            _fail("retained Python package descriptor offset moved while held")
        with _held_package_probe_descriptor(dependencies.package) as probe_fd:
            signature_code, signature_stdout, signature_stderr = _run_bounded_child(
                [
                    "/usr/sbin/pkgutil",
                    "--check-signature",
                    f"/dev/fd/{probe_fd}",
                ],
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
                pass_fds=(probe_fd,),
                preexec_fn=drop,
                forbid_descendants=True,
                timeout=30.0,
            )
        if (
            signature_code != 0
            or not _package_signature_stream_is_current_psf_trust(
                signature_stdout,
                signature_stderr,
                package_name=dependencies.package.path.name,
                expected_status=dependencies.package_signature_status,
            )
        ):
            _fail(
                "held Python package signature/status is not current PSF trust: "
                + _bounded_child_failure_details(
                    signature_code, signature_stdout, signature_stderr
                )
            )
        dependencies.validate()
        if os.lseek(dependencies.package.fd, 0, os.SEEK_CUR) != 0:
            _fail("retained Python package descriptor offset moved during signature check")
        returncode, stdout, stderr = _run_bounded_child(
            [
                str(RUNTIME_PYTHON),
                "-I",
                "-S",
                "-c",
                bootstrap,
            ],
            env=env,
            pass_fds=(source_fd, receipt_fd, *dependencies.pass_fds()),
            preexec_fn=drop,
            # The held receipt source is AST-restricted to one strict codesign/spctl
            # gate and exactly 21 sequential invocations. RLIMIT_NPROC is per-UID,
            # so it cannot contain this subtree on a busy console account.
            forbid_descendants=False,
            timeout=180.0,
        )
        if os.lseek(dependencies.package.fd, 0, os.SEEK_CUR) != 0:
            _fail("retained Python package descriptor offset moved during reauthentication")
    finally:
        os.close(receipt_fd)
        os.close(source_fd)
        dependencies.validate()
    if (
        returncode != 0
        or stdout != b"REAUTHENTICATED\n"
        or stderr
    ):
        _fail(
            f"{'post-publication' if mode == 'published' else 'preflight'} "
            "runtime reauthentication failed closed: "
            + _bounded_child_failure_details(returncode, stdout, stderr)
        )


def _preconditions_for_fixed_boundary(
    boundary: HeldFile,
    authority: dict[str, object],
) -> None:
    if _sha256(boundary.data) != authority["owner_provision_boundary_sha256"]:
        _fail("fixed owner-provision boundary executable digest mismatch")


def _assert_no_transaction_leftovers(
    authority_dir: HeldDirectory,
    receipt_dir: HeldDirectory,
    paths: ProvisionPaths,
    *,
    allow_initial_authority_publish: bool = False,
) -> None:
    if _leaf_bytes(authority_dir, paths.journal.name, MAX_JOURNAL) is not None:
        _fail("an unfinished owner-provision transaction requires recovery")
    if _leaf_bytes(authority_dir, paths.journal_next.name, MAX_JOURNAL) is not None:
        _fail("an unfinished next journal requires recovery")
    if not allow_initial_authority_publish:
        if (
            _leaf_bytes(authority_dir, INITIAL_AUTHORITY_JOURNAL_NAME, MAX_JOURNAL)
            is not None
            or _leaf_bytes(
                authority_dir, INITIAL_AUTHORITY_JOURNAL_NEXT_NAME, MAX_JOURNAL
            )
            is not None
        ):
            _fail("an unfinished initial-authority publication requires recovery")
    prefixes = ("authority.json.owner-provision.", "3.14.7.receipt.json.owner-provision.")
    for name in os.listdir(authority_dir.fd):
        if name.startswith(prefixes[0]):
            _fail("unowned authority transaction residue requires recovery")
        if (
            not allow_initial_authority_publish
            and name.startswith("authority.json.initial-publish.")
        ):
            _fail("unowned initial-authority stage requires recovery")
    for name in os.listdir(receipt_dir.fd):
        if name.startswith(prefixes[1]):
            _fail("unowned receipt transaction residue requires recovery")


def _write_initial_authority_journal(
    authority_dir: HeldDirectory,
    journal: dict[str, object],
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    data = canonical_bytes(journal)
    _parse_initial_authority_journal(data)
    if (
        _leaf_bytes(authority_dir, INITIAL_AUTHORITY_JOURNAL_NEXT_NAME, MAX_JOURNAL)
        is not None
    ):
        _fail("initial authority next journal was not reconciled")
    _create_file(
        authority_dir,
        INITIAL_AUTHORITY_JOURNAL_NEXT_NAME,
        data,
        mode=0o600,
        policy=policy,
        operations=operations,
    )
    os.replace(
        INITIAL_AUTHORITY_JOURNAL_NEXT_NAME,
        INITIAL_AUTHORITY_JOURNAL_NAME,
        src_dir_fd=authority_dir.fd,
        dst_dir_fd=authority_dir.fd,
    )
    operations.sync_directory(authority_dir.fd)


def _advance_initial_authority_journal(
    authority_dir: HeldDirectory,
    journal: dict[str, object],
    phase: str,
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> dict[str, object]:
    order = {"preparing": 0, "staged": 1, "published": 2}
    if phase not in order or order[phase] < order[str(journal["phase"])]:
        _fail("initial authority journal phase regression")
    updated = dict(journal)
    updated["generation"] = int(journal["generation"]) + 1
    updated["phase"] = phase
    _write_initial_authority_journal(
        authority_dir, updated, policy=policy, operations=operations
    )
    return updated


def _initial_authority_leaf(
    authority_dir: HeldDirectory,
    name: str,
    *,
    expected_sha256: str,
    allowed_states: frozenset[tuple[int, int]],
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> HeldFile | None:
    try:
        held = HeldFile.open(
            authority_dir.path / name,
            maximum=MAX_AUTHORITY,
            policy=policy,
            operations=operations,
            immutable=False,
            allow_owner_write=True,
        )
        state = (
            stat.S_IMODE(os.fstat(held.fd).st_mode),
            operations.flags_fd(held.fd),
        )
        if state not in allowed_states or _sha256(held.data) != expected_sha256:
            held.close()
            _fail(f"initial authority transaction leaf mismatch: {name}")
        return held
    except FileNotFoundError:
        return None


def _read_initial_authority_journal_leaf(
    authority_dir: HeldDirectory,
    name: str,
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> bytes | None:
    try:
        held = HeldFile.open(
            authority_dir.path / name,
            maximum=MAX_JOURNAL,
            policy=policy,
            operations=operations,
            mode=0o600,
            immutable=False,
            allow_owner_write=True,
        )
    except FileNotFoundError:
        return None
    try:
        if operations.flags_fd(held.fd) != 0:
            _fail(f"initial authority journal flags are invalid: {name}")
        return held.data
    finally:
        held.close()


def _reconcile_initial_authority_journals(
    authority_dir: HeldDirectory,
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> bytes | None:
    current_data = _read_initial_authority_journal_leaf(
        authority_dir,
        INITIAL_AUTHORITY_JOURNAL_NAME,
        policy=policy,
        operations=operations,
    )
    next_data = _read_initial_authority_journal_leaf(
        authority_dir,
        INITIAL_AUTHORITY_JOURNAL_NEXT_NAME,
        policy=policy,
        operations=operations,
    )
    if next_data is None:
        return current_data
    next_journal = _parse_initial_authority_journal(next_data)
    if current_data is not None:
        current_journal = _parse_initial_authority_journal(current_data)
        for key in (
            "authority_sha256",
            "stage_name",
            "transaction_id",
        ):
            if current_journal[key] != next_journal[key]:
                _fail(f"initial authority journal recovery mismatch: {key}")
        phase_order = {"preparing": 0, "staged": 1, "published": 2}
        if (
            int(next_journal["generation"])
            != int(current_journal["generation"]) + 1
            or phase_order[str(next_journal["phase"])]
            < phase_order[str(current_journal["phase"])]
        ):
            _fail("initial authority next journal generation is invalid")
    os.replace(
        INITIAL_AUTHORITY_JOURNAL_NEXT_NAME,
        INITIAL_AUTHORITY_JOURNAL_NAME,
        src_dir_fd=authority_dir.fd,
        dst_dir_fd=authority_dir.fd,
    )
    operations.sync_directory(authority_dir.fd)
    return next_data


def publish_initial_authority(
    authority_source_path: Path,
    envelope_path: Path,
    *,
    paths: ProvisionPaths = PRODUCTION_PATHS,
    policy: CustodyPolicy | None = None,
    operations: SystemOperations = SYSTEM_OPERATIONS,
    now: datetime | None = None,
    capability: NativeCapability | None = None,
    crash_hook: CrashHook = _noop_crash_hook,
) -> dict[str, object]:
    """Publish the absent v2 authority through one signed, recoverable transaction."""

    supplied_now = now is not None
    if policy is None:
        policy = CustodyPolicy.production()
    if now is None:
        now = _utc_now()
    if now.tzinfo is None:
        _fail("initial authority publication time must be timezone-aware")
    production = _production_paths_requested(paths)
    if production:
        _require_exact_production_paths(paths, "initial authority publication")
        if (
            policy != CustodyPolicy.production()
            or operations is not SYSTEM_OPERATIONS
            or supplied_now
            or crash_hook is not _noop_crash_hook
            or type(capability) is not NativeCapability
        ):
            _fail("production initial authority publication refuses injected dependencies")
    if (
        not authority_source_path.is_absolute()
        or not envelope_path.is_absolute()
        or authority_source_path == envelope_path
        or authority_source_path == paths.authority
        or envelope_path == paths.authority
    ):
        _fail("initial authority inputs must be distinct external absolute paths")
    if capability is None:
        _fail("initial authority publication requires a native capability")
    authority_dir = HeldDirectory.open(paths.authority.parent, policy)
    receipt_dir = HeldDirectory.open(paths.receipt.parent, policy)
    authority_input: HeldFile | None = None
    envelope_input: HeldFile | None = None
    receipt: HeldFile | None = None
    closure: HeldClosure | None = None
    try:
        capability.validate()
        _acquire_transaction_lock(authority_dir)
        _assert_no_transaction_leftovers(
            authority_dir,
            receipt_dir,
            paths,
            allow_initial_authority_publish=True,
        )
        input_policy = CustodyPolicy(
            uid=os.stat(authority_source_path, follow_symlinks=False).st_uid,
            gid=os.stat(authority_source_path, follow_symlinks=False).st_gid,
            require_immutable=False,
            strict_ancestry=False,
            trusted_root=authority_source_path.parent,
        )
        envelope_policy = CustodyPolicy(
            uid=os.stat(envelope_path, follow_symlinks=False).st_uid,
            gid=os.stat(envelope_path, follow_symlinks=False).st_gid,
            require_immutable=False,
            strict_ancestry=False,
            trusted_root=envelope_path.parent,
        )
        authority_input = HeldFile.open(
            authority_source_path,
            maximum=MAX_AUTHORITY,
            policy=input_policy,
            operations=operations,
            immutable=False,
            allow_owner_write=True,
        )
        envelope_input = HeldFile.open(
            envelope_path,
            maximum=MAX_AUTHORIZATION,
            policy=envelope_policy,
            operations=operations,
            immutable=False,
            allow_owner_write=True,
        )
        receipt = HeldFile.open(
            paths.receipt,
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=operations,
            mode=0o444,
            immutable=True,
        )
        authority_record = _parse_authority(authority_input.data)
        receipt_sha256 = _sha256(receipt.data)
        current_journal_data = _reconcile_initial_authority_journals(
            authority_dir, policy=policy, operations=operations
        )
        journal_created_utc = None
        if current_journal_data is not None:
            journal_created_utc = _time(
                _parse_initial_authority_journal(current_journal_data)["created_utc"],
                "initial authority journal created_utc",
            )
        _parse_initial_authority_envelope(
            envelope_input.data,
            authority=authority_record,
            authority_data=authority_input.data,
            current_receipt_sha256=receipt_sha256,
            capability=capability,
            now=now,
            journal_created_utc=journal_created_utc,
        )
        current_receipt_record = _json(
            receipt.data, "initial authority active receipt", maximum=MAX_RECEIPT
        )
        _validate_active_runtime_receipt(
            current_receipt_record,
            authority_record,
            allow_sequence_one_activation=True,
        )
        if not _is_sequence_one_activation_receipt(
            current_receipt_record, authority_record
        ):
            _fail("initial authority requires the exact sequence-one activation receipt")
        repo = Path(str(authority_record["authorized_repo_root"]))
        repo_info = os.stat(repo, follow_symlinks=False)
        closure = HeldClosure.open(
            repo,
            _validate_closure(authority_record["closure"], "initial authority"),
            uid=repo_info.st_uid,
            gid=repo_info.st_gid,
            operations=operations,
        )
        authority_digest = _sha256(authority_input.data)
        envelope_digest = _sha256(envelope_input.data)
        transaction_id = _sha256(
            INITIAL_AUTHORITY_DOMAIN
            + bytes.fromhex(authority_digest)
        )
        stage_name = f"authority.json.initial-publish.{transaction_id}.new"
        journal: dict[str, object] | None = None
        if current_journal_data is not None:
            journal = _parse_initial_authority_journal(current_journal_data)
            expected_bindings = {
                "authority_sha256": authority_digest,
                "stage_name": stage_name,
                "transaction_id": transaction_id,
            }
            for key, expected_value in expected_bindings.items():
                if journal.get(key) != expected_value:
                    _fail(f"initial authority recovery binding mismatch: {key}")
            if journal["envelope_sha256"] != envelope_digest:
                refreshed_journal = dict(journal)
                refreshed_journal["envelope_sha256"] = envelope_digest
                refreshed_journal["generation"] = int(journal["generation"]) + 1
                _write_initial_authority_journal(
                    authority_dir,
                    refreshed_journal,
                    policy=policy,
                    operations=operations,
                )
                journal = refreshed_journal
        else:
            if _leaf_bytes(authority_dir, paths.authority.name, MAX_AUTHORITY) is not None:
                _fail("initial authority target already exists without active journal")
            for name in os.listdir(authority_dir.fd):
                if name.startswith("authority.json.initial-publish."):
                    _fail("unowned initial authority stage requires recovery")
            journal = {
                "authority_sha256": authority_digest,
                "contract": INITIAL_AUTHORITY_JOURNAL_CONTRACT,
                "created_utc": now.astimezone(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "envelope_sha256": envelope_digest,
                "generation": 1,
                "phase": "preparing",
                "schema_version": 1,
                "stage_name": stage_name,
                "transaction_id": transaction_id,
            }
            _write_initial_authority_journal(
                authority_dir, journal, policy=policy, operations=operations
            )
            crash_hook("initial-authority-intent")
        capability.validate()
        authority_input.validate()
        envelope_input.validate()
        receipt.validate()
        closure.validate()
        target = _initial_authority_leaf(
            authority_dir,
            paths.authority.name,
            expected_sha256=authority_digest,
            allowed_states=frozenset(
                {
                    (0o400, 0),
                    (0o444, 0),
                    (0o444, SF_IMMUTABLE),
                }
            ),
            policy=policy,
            operations=operations,
        )
        if target is not None:
            if journal["phase"] == "preparing":
                target.close()
                _fail("initial authority target exists before staged journal phase")
            try:
                state = (
                    stat.S_IMODE(os.fstat(target.fd).st_mode),
                    operations.flags_fd(target.fd),
                )
                if state != (0o444, SF_IMMUTABLE):
                    os.fchmod(target.fd, 0o444)
                    operations.set_flags_fd(target.fd, SF_IMMUTABLE)
                    operations.full_sync(target.fd)
            finally:
                target.close()
            if _leaf_bytes(authority_dir, stage_name, MAX_AUTHORITY) is not None:
                _fail("initial authority target and stage coexist")
        else:
            stage = _initial_authority_leaf(
                authority_dir,
                stage_name,
                expected_sha256=authority_digest,
                allowed_states=frozenset({(0o400, 0)}),
                policy=policy,
                operations=operations,
            )
            if stage is None:
                if journal["phase"] != "preparing":
                    _fail("initial authority stage is missing after preparation")
                _create_file(
                    authority_dir,
                    stage_name,
                    authority_input.data,
                    mode=0o400,
                    policy=policy,
                    operations=operations,
                )
            else:
                try:
                    if _sha256(stage.data) != authority_digest:
                        _fail("initial authority stage digest mismatch")
                finally:
                    stage.close()
            journal = _advance_initial_authority_journal(
                authority_dir,
                journal,
                "staged",
                policy=policy,
                operations=operations,
            )
            crash_hook("initial-authority-staged")
            capability.validate()
            authority_input.validate()
            envelope_input.validate()
            receipt.validate()
            closure.validate()
            operations.rename_exclusive(
                authority_dir.fd,
                stage_name,
                authority_dir.fd,
                paths.authority.name,
            )
            operations.sync_directory(authority_dir.fd)
            crash_hook("initial-authority-renamed")
            target = _initial_authority_leaf(
                authority_dir,
                paths.authority.name,
                expected_sha256=authority_digest,
                allowed_states=frozenset({(0o400, 0)}),
                policy=policy,
                operations=operations,
            )
            if target is None:
                _fail("exclusively published initial authority is missing")
            try:
                os.fchmod(target.fd, 0o444)
                operations.set_flags_fd(target.fd, SF_IMMUTABLE)
                operations.full_sync(target.fd)
            finally:
                target.close()
        operations.sync_directory(authority_dir.fd)
        target = HeldFile.open(
            paths.authority,
            maximum=MAX_AUTHORITY,
            policy=policy,
            operations=operations,
            mode=0o444,
            immutable=True,
        )
        try:
            if _sha256(target.data) != authority_digest:
                _fail("final initial authority digest mismatch")
        finally:
            target.close()
        journal = _advance_initial_authority_journal(
            authority_dir,
            journal,
            "published",
            policy=policy,
            operations=operations,
        )
        crash_hook("initial-authority-published")
        _unlink_if_exists(authority_dir, stage_name)
        operations.sync_directory(authority_dir.fd)
        _unlink_if_exists(authority_dir, INITIAL_AUTHORITY_JOURNAL_NEXT_NAME)
        operations.sync_directory(authority_dir.fd)
        _unlink_if_exists(authority_dir, INITIAL_AUTHORITY_JOURNAL_NAME)
        operations.sync_directory(authority_dir.fd)
        capability.validate()
        authority_input.validate()
        envelope_input.validate()
        receipt.validate()
        closure.validate()
        return {
            "authority_sha256": authority_digest,
            "result": "initial-authority-published-and-sealed",
            "sequence": 1,
        }
    finally:
        if closure is not None:
            closure.close()
        if receipt is not None:
            receipt.close()
        if envelope_input is not None:
            envelope_input.close()
        if authority_input is not None:
            authority_input.close()
        receipt_dir.close()
        authority_dir.close()


def _cleanup_transaction(
    authority_dir: HeldDirectory,
    receipt_dir: HeldDirectory,
    paths: ProvisionPaths,
    journal: dict[str, object],
    operations: SystemOperations,
    crash_hook: CrashHook = _noop_crash_hook,
    terminal: str = "new",
) -> None:
    _validate_journal_transaction_names(journal)
    if terminal not in {"old", "new"}:
        _fail("transaction cleanup terminal selection is invalid")
    if terminal == "new" and journal.get("phase") != "verified":
        _fail("transaction cleanup requires authenticated terminal state")
    receipt_key = f"{terminal}_receipt_sha256"
    authority_key = f"{terminal}_authority_sha256"
    if (
        _current_leaf_digest(receipt_dir, paths.receipt.name, MAX_RECEIPT)
        != journal[receipt_key]
        or _current_leaf_digest(authority_dir, paths.authority.name, MAX_AUTHORITY)
        != journal[authority_key]
    ):
        _fail("transaction cleanup terminal bytes are not exact")
    for directory, key in (
        (authority_dir, "authority_stage_name"),
        (receipt_dir, "receipt_stage_name"),
        (authority_dir, "authority_backup_name"),
        (receipt_dir, "receipt_backup_name"),
    ):
        crash_hook(f"cleanup-before-unlink-{key}")
        _unlink_if_exists(directory, str(journal[key]), operations=operations)
        crash_hook(f"cleanup-after-unlink-{key}")
        operations.sync_directory(directory.fd)
        crash_hook(f"cleanup-after-fsync-{key}")
    crash_hook("cleanup-before-unlink-journal-next")
    _unlink_if_exists(
        authority_dir, paths.journal_next.name, operations=operations
    )
    crash_hook("cleanup-after-unlink-journal-next")
    operations.sync_directory(authority_dir.fd)
    crash_hook("cleanup-after-fsync-journal-next")
    crash_hook("cleanup-before-unlink-journal")
    _unlink_if_exists(authority_dir, paths.journal.name, operations=operations)
    crash_hook("cleanup-after-unlink-journal")
    operations.sync_directory(authority_dir.fd)
    crash_hook("cleanup-after-fsync-journal")


def _rollback(
    authority_dir: HeldDirectory,
    receipt_dir: HeldDirectory,
    paths: ProvisionPaths,
    journal: dict[str, object],
    *,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> None:
    _validate_journal_transaction_names(journal)
    current_receipt = _current_leaf_digest(receipt_dir, paths.receipt.name, MAX_RECEIPT)
    current_authority = _current_leaf_digest(authority_dir, paths.authority.name, MAX_AUTHORITY)
    if current_receipt == journal["new_receipt_sha256"]:
        _replace_from_stage(
            receipt_dir,
            str(journal["receipt_backup_name"]),
            paths.receipt.name,
            expected_sha256=str(journal["old_receipt_sha256"]),
            mode=int(journal["old_receipt_mode"]),
            immutable_flags=int(journal["old_receipt_flags"]),
            policy=policy,
            operations=operations,
        )
    elif current_receipt != journal["old_receipt_sha256"]:
        _fail("rollback cannot identify the current receipt")
    else:
        _restore_leaf_custody(
            receipt_dir,
            paths.receipt.name,
            expected_sha256=str(journal["old_receipt_sha256"]),
            maximum=MAX_RECEIPT,
            mode=int(journal["old_receipt_mode"]),
            immutable_flags=int(journal["old_receipt_flags"]),
            policy=policy,
            operations=operations,
        )
    if current_authority == journal["new_authority_sha256"]:
        _replace_from_stage(
            authority_dir,
            str(journal["authority_backup_name"]),
            paths.authority.name,
            expected_sha256=str(journal["old_authority_sha256"]),
            mode=int(journal["old_authority_mode"]),
            immutable_flags=int(journal["old_authority_flags"]),
            policy=policy,
            operations=operations,
        )
    elif current_authority != journal["old_authority_sha256"]:
        _fail("rollback cannot identify the current authority")
    else:
        _restore_leaf_custody(
            authority_dir,
            paths.authority.name,
            expected_sha256=str(journal["old_authority_sha256"]),
            maximum=MAX_AUTHORITY,
            mode=int(journal["old_authority_mode"]),
            immutable_flags=int(journal["old_authority_flags"]),
            policy=policy,
            operations=operations,
        )
    if (
        _current_leaf_digest(receipt_dir, paths.receipt.name, MAX_RECEIPT)
        != journal["old_receipt_sha256"]
        or _current_leaf_digest(authority_dir, paths.authority.name, MAX_AUTHORITY)
        != journal["old_authority_sha256"]
    ):
        _fail("exact rollback verification failed")
    _cleanup_transaction(
        authority_dir,
        receipt_dir,
        paths,
        journal,
        operations,
        terminal="old",
    )


def apply_transaction(
    plan_path: Path,
    authorization_path: Path,
    *,
    paths: ProvisionPaths = PRODUCTION_PATHS,
    policy: CustodyPolicy | None = None,
    operations: SystemOperations = SYSTEM_OPERATIONS,
    now: datetime | None = None,
    reauthenticate: Reauthenticate | None = None,
    crash_hook: CrashHook = _noop_crash_hook,
    production_invocation: RuntimeInvocation | None = None,
    dependency_custody: HeldDependencies | None = None,
) -> dict[str, object]:
    """Apply one signed migration.  Tests may inject only direct API dependencies."""
    supplied_now = now is not None
    if policy is None:
        policy = CustodyPolicy.production()
    if now is None:
        now = _utc_now()
    if now.tzinfo is None:
        _fail("trusted transaction time must be timezone-aware")
    if reauthenticate is None:
        reauthenticate = _production_reauthenticate
    production = _production_paths_requested(paths)
    if production:
        _require_exact_production_paths(paths, "apply")
        if (
            policy != CustodyPolicy.production()
            or operations is not SYSTEM_OPERATIONS
            or reauthenticate is not _production_reauthenticate
            or crash_hook is not _noop_crash_hook
            or dependency_custody is not None
            or supplied_now
        ):
            _fail("production apply refuses injected transaction dependencies")
        _validate_production_invocation(production_invocation)
    authority_dir = HeldDirectory.open(paths.authority.parent, policy)
    receipt_dir = HeldDirectory.open(paths.receipt.parent, policy)
    boundary: HeldFile | None = None
    authority: HeldFile | None = None
    receipt: HeldFile | None = None
    plan: HeldFile | None = None
    authorization: HeldFile | None = None
    closure: HeldClosure | None = None
    dependencies = dependency_custody
    dependencies_owned = False
    journal: dict[str, object] | None = None
    terminal_authenticated = False

    def validate_transition() -> None:
        if production_invocation is not None:
            production_invocation.validate()
        if dependencies is not None:
            dependencies.validate()

    try:
        validate_transition()
        _acquire_transaction_lock(authority_dir)
        _assert_no_transaction_leftovers(authority_dir, receipt_dir, paths)
        boundary = HeldFile.open(
            paths.boundary,
            maximum=MAX_CONTROLLER,
            policy=policy,
            operations=operations,
            mode=0o555,
            immutable=True,
        )
        authority = HeldFile.open(
            paths.authority,
            maximum=MAX_AUTHORITY,
            policy=policy,
            operations=operations,
            mode=0o444,
            immutable=True,
        )
        receipt = HeldFile.open(
            paths.receipt,
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=operations,
            mode=0o444,
            immutable=True,
        )
        input_policy = CustodyPolicy(
            uid=os.stat(plan_path, follow_symlinks=False).st_uid,
            gid=os.stat(plan_path, follow_symlinks=False).st_gid,
            require_immutable=False,
            strict_ancestry=False,
            trusted_root=plan_path.parent,
        )
        plan = HeldFile.open(
            plan_path,
            maximum=MAX_PLAN,
            policy=input_policy,
            operations=operations,
            immutable=False,
            allow_owner_write=True,
        )
        auth_policy = CustodyPolicy(
            uid=os.stat(authorization_path, follow_symlinks=False).st_uid,
            gid=os.stat(authorization_path, follow_symlinks=False).st_gid,
            require_immutable=False,
            strict_ancestry=False,
            trusted_root=authorization_path.parent,
        )
        authorization = HeldFile.open(
            authorization_path,
            maximum=MAX_AUTHORIZATION,
            policy=auth_policy,
            operations=operations,
            immutable=False,
            allow_owner_write=True,
        )
        authority_record = _parse_authority(authority.data)
        _preconditions_for_fixed_boundary(boundary, authority_record)
        parsed_plan, candidate, expected_closure = _parse_plan(
            plan.data,
            authority=authority_record,
            authority_data=authority.data,
            current_receipt_data=receipt.data,
            now=now,
        )
        signed = _parse_authorization(
            authorization.data,
            authorization_path=authorization_path,
            authority=authority_record,
            plan=parsed_plan,
            plan_data=plan.data,
            closure=expected_closure,
            now=now,
        )
        repo = Path(str(authority_record["authorized_repo_root"]))
        repo_info = os.stat(repo, follow_symlinks=False)
        owner_uid, owner_gid = _authorized_repo_owner(repo_info)
        closure = HeldClosure.open(
            repo,
            expected_closure,
            uid=repo_info.st_uid,
            gid=repo_info.st_gid,
            operations=operations,
        )
        candidate_record = _parse_candidate_receipt(candidate, expected_closure)
        _validate_native_receipt_authority(candidate_record, authority_record)
        if production:
            dependencies = HeldDependencies.open(
                closure.files["pin_manifest_sha256"].data,
                candidate_record,
                owner_uid=owner_uid,
                operations=operations,
            )
            dependencies_owned = True
        validate_transition()
        next_authority = _next_authority(
            authority_record, str(parsed_plan["candidate_receipt_sha256"])
        )
        next_authority_data = canonical_bytes(next_authority)
        transaction_id = _sha256(
            DOMAIN
            + str(signed["authorization_id"]).encode("ascii")
            + bytes.fromhex(str(signed["nonce"]))
            + secrets.token_bytes(32)
        )
        receipt_stage = _safe_transaction_name(
            paths.receipt.name, transaction_id, "new"
        )
        receipt_backup = _safe_transaction_name(
            paths.receipt.name, transaction_id, "backup"
        )
        authority_stage = _safe_transaction_name(
            paths.authority.name, transaction_id, "new"
        )
        authority_backup = _safe_transaction_name(
            paths.authority.name, transaction_id, "backup"
        )
        journal = {
            "authorization_sha256": _sha256(authorization.data),
            "authority_backup_name": authority_backup,
            "authority_stage_name": authority_stage,
            "authorized_repo_root": str(repo),
            "contract": JOURNAL_CONTRACT,
            "created_utc": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generation": 1,
            "migration_id": parsed_plan["migration_id"],
            "new_authority_sha256": _sha256(next_authority_data),
            "new_receipt_sha256": _sha256(candidate),
            "old_authority_flags": operations.flags_fd(authority.fd),
            "old_authority_mode": stat.S_IMODE(os.fstat(authority.fd).st_mode),
            "old_authority_sha256": _sha256(authority.data),
            "old_receipt_flags": operations.flags_fd(receipt.fd),
            "old_receipt_mode": stat.S_IMODE(os.fstat(receipt.fd).st_mode),
            "old_receipt_sha256": _sha256(receipt.data),
            "phase": "preparing",
            "plan_sha256": _sha256(plan.data),
            "receipt_backup_name": receipt_backup,
            "receipt_stage_name": receipt_stage,
            "schema_version": 1,
            "transaction_id": transaction_id,
        }
        _parse_journal(canonical_bytes(journal))
        _write_journal(
            authority_dir,
            paths,
            journal,
            policy=policy,
            operations=operations,
        )
        validate_transition()
        crash_hook("journal-created")
        _create_file(
            receipt_dir,
            receipt_stage,
            candidate,
            mode=0o400,
            policy=policy,
            operations=operations,
        )
        crash_hook("receipt-stage-created")
        _create_file(
            receipt_dir,
            receipt_backup,
            receipt.data,
            mode=0o400,
            policy=policy,
            operations=operations,
        )
        _seal_recovery_anchor(
            receipt_dir,
            receipt_backup,
            expected_sha256=str(journal["old_receipt_sha256"]),
            maximum=MAX_RECEIPT,
            immutable_flags=int(journal["old_receipt_flags"]),
            policy=policy,
            operations=operations,
        )
        crash_hook("receipt-backup-created")
        _create_file(
            authority_dir,
            authority_stage,
            next_authority_data,
            mode=0o400,
            policy=policy,
            operations=operations,
        )
        crash_hook("authority-stage-created")
        _create_file(
            authority_dir,
            authority_backup,
            authority.data,
            mode=0o400,
            policy=policy,
            operations=operations,
        )
        _seal_recovery_anchor(
            authority_dir,
            authority_backup,
            expected_sha256=str(journal["old_authority_sha256"]),
            maximum=MAX_AUTHORITY,
            immutable_flags=int(journal["old_authority_flags"]),
            policy=policy,
            operations=operations,
        )
        crash_hook("authority-backup-created")
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "prepared",
            policy=policy,
            operations=operations,
        )
        validate_transition()
        crash_hook("journal-prepared")
        for held in (boundary, authority, receipt, plan, authorization):
            held.validate()
        closure.validate()
        os.environ["WINS_RELEASE_PYTHON_AUTHORIZED_REPO"] = str(repo)
        reauthenticate(
            receipt_dir.path / receipt_stage,
            candidate,
            expected_closure,
            dependencies,
            owner_uid,
            owner_gid,
        )
        validate_transition()
        crash_hook("preflight-reauthenticated")
        for held in (boundary, authority, receipt, plan, authorization):
            held.validate()
        closure.validate()
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "publishing-receipt",
            policy=policy,
            operations=operations,
        )
        validate_transition()
        _replace_from_stage(
            receipt_dir,
            receipt_stage,
            paths.receipt.name,
            expected_sha256=str(journal["new_receipt_sha256"]),
            mode=0o444,
            immutable_flags=int(journal["old_receipt_flags"]),
            policy=policy,
            operations=operations,
        )
        validate_transition()
        crash_hook("receipt-replaced")
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "receipt-published",
            policy=policy,
            operations=operations,
        )
        validate_transition()
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "publishing-authority",
            policy=policy,
            operations=operations,
        )
        validate_transition()
        _replace_from_stage(
            authority_dir,
            authority_stage,
            paths.authority.name,
            expected_sha256=str(journal["new_authority_sha256"]),
            mode=0o444,
            immutable_flags=int(journal["old_authority_flags"]),
            policy=policy,
            operations=operations,
        )
        validate_transition()
        crash_hook("authority-replaced")
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "authority-published",
            policy=policy,
            operations=operations,
        )
        validate_transition()
        reauthenticate(
            paths.receipt,
            candidate,
            expected_closure,
            dependencies,
            owner_uid,
            owner_gid,
        )
        validate_transition()
        crash_hook("post-publication-reauthenticated")
        journal = _advance_journal(
            authority_dir,
            paths,
            journal,
            "verified",
            policy=policy,
            operations=operations,
        )
        terminal_authenticated = True
        _cleanup_transaction(
            authority_dir,
            receipt_dir,
            paths,
            journal,
            operations,
            crash_hook,
        )
        validate_transition()
        return {
            "authorization_id": signed["authorization_id"],
            "migration_id": parsed_plan["migration_id"],
            "receipt_sha256": parsed_plan["candidate_receipt_sha256"],
            "result": "published-and-reauthenticated",
            "sequence": next_authority["active_sequence"],
        }
    except Exception:
        if journal is not None and not terminal_authenticated:
            try:
                _rollback(
                    authority_dir,
                    receipt_dir,
                    paths,
                    journal,
                    policy=policy,
                    operations=operations,
                )
            except Exception as rollback_error:
                raise ProvisionError(
                    f"{OWNER_BLOCKED}: transaction failed and exact rollback also failed: {rollback_error}"
                )
        raise
    finally:
        os.environ.pop("WINS_RELEASE_PYTHON_AUTHORIZED_REPO", None)
        if dependencies_owned and dependencies is not None:
            dependencies.close()
        if closure is not None:
            closure.close()
        for held in (authorization, plan, receipt, authority, boundary):
            if held is not None:
                held.close()
        receipt_dir.close()
        authority_dir.close()


def _load_recovery_journal(
    authority_dir: HeldDirectory,
    paths: ProvisionPaths,
) -> dict[str, object]:
    current = _leaf_bytes(authority_dir, paths.journal.name, MAX_JOURNAL)
    pending = _leaf_bytes(authority_dir, paths.journal_next.name, MAX_JOURNAL)
    candidates: list[tuple[dict[str, object], bytes, str]] = []
    if current is not None:
        candidates.append((_parse_journal(current), current, paths.journal.name))
    if pending is not None:
        candidates.append((_parse_journal(pending), pending, paths.journal_next.name))
    if not candidates:
        _fail("no recoverable owner-provision journal exists")
    transaction_ids = {str(item[0]["transaction_id"]) for item in candidates}
    if len(transaction_ids) != 1:
        _fail("journal and next-journal transaction identities conflict")
    selected = max(candidates, key=lambda item: int(item[0]["generation"]))
    if selected[2] == paths.journal_next.name:
        os.replace(
            paths.journal_next.name,
            paths.journal.name,
            src_dir_fd=authority_dir.fd,
            dst_dir_fd=authority_dir.fd,
        )
    return selected[0]


def _recover_authenticated_terminal_without_journal(
    authority_dir: HeldDirectory,
    receipt_dir: HeldDirectory,
    paths: ProvisionPaths,
    *,
    operations: SystemOperations,
    reauthenticate: Reauthenticate,
    production: bool,
    production_invocation: RuntimeInvocation | None,
    dependency_custody: HeldDependencies | None,
    now: datetime,
) -> dict[str, object]:
    """Prove and refresh a schema-v3 terminal pair after journal cleanup."""
    _assert_no_transaction_leftovers(authority_dir, receipt_dir, paths)
    authority_data = _leaf_bytes(
        authority_dir, paths.authority.name, MAX_AUTHORITY
    )
    receipt_data = _leaf_bytes(receipt_dir, paths.receipt.name, MAX_RECEIPT)
    if authority_data is None or receipt_data is None:
        _fail("no recoverable owner-provision journal exists")
    authority = _parse_authority(authority_data)
    _require_authority_current(
        authority, now, label="journal-free terminal recovery"
    )
    if _sha256(receipt_data) != authority["active_receipt_sha256"]:
        _fail("journal-free terminal receipt differs from active authority")
    closure_digest = _validate_closure(
        authority["closure"], "journal-free terminal authority"
    )
    receipt = _parse_candidate_receipt(receipt_data, closure_digest)
    _validate_native_receipt_authority(receipt, authority)
    repo = Path(str(authority["authorized_repo_root"]))
    repo_info = os.stat(repo, follow_symlinks=False)
    owner_uid, owner_gid = _authorized_repo_owner(repo_info)
    closure: HeldClosure | None = None
    dependencies = dependency_custody
    dependencies_owned = False
    try:
        closure = HeldClosure.open(
            repo,
            closure_digest,
            uid=repo_info.st_uid,
            gid=repo_info.st_gid,
            operations=operations,
        )
        if production:
            dependencies = HeldDependencies.open(
                closure.files["pin_manifest_sha256"].data,
                receipt,
                owner_uid=owner_uid,
                operations=operations,
            )
            dependencies_owned = True
        if production_invocation is not None:
            production_invocation.validate()
        closure.validate()
        if dependencies is not None:
            dependencies.validate()
        os.environ["WINS_RELEASE_PYTHON_AUTHORIZED_REPO"] = str(repo)
        reauthenticate(
            paths.receipt,
            receipt_data,
            closure_digest,
            dependencies,
            owner_uid,
            owner_gid,
        )
        if production_invocation is not None:
            production_invocation.validate()
        closure.validate()
        if dependencies is not None:
            dependencies.validate()
        if (
            _current_leaf_digest(receipt_dir, paths.receipt.name, MAX_RECEIPT)
            != authority["active_receipt_sha256"]
            or _current_leaf_digest(
                authority_dir, paths.authority.name, MAX_AUTHORITY
            )
            != _sha256(authority_data)
        ):
            _fail("journal-free terminal bytes changed during reauthentication")
        _assert_no_transaction_leftovers(authority_dir, receipt_dir, paths)
        return {
            "receipt_sha256": authority["active_receipt_sha256"],
            "result": "authenticated-terminal-already-clean",
            "sequence": authority["active_sequence"],
        }
    finally:
        os.environ.pop("WINS_RELEASE_PYTHON_AUTHORIZED_REPO", None)
        if dependencies_owned and dependencies is not None:
            dependencies.close()
        if closure is not None:
            closure.close()


def recover_transaction(
    *,
    paths: ProvisionPaths = PRODUCTION_PATHS,
    policy: CustodyPolicy | None = None,
    operations: SystemOperations = SYSTEM_OPERATIONS,
    reauthenticate: Reauthenticate | None = None,
    production_invocation: RuntimeInvocation | None = None,
    dependency_custody: HeldDependencies | None = None,
    crash_hook: CrashHook = _noop_crash_hook,
    now: datetime | None = None,
) -> dict[str, object]:
    """Recover only the exact root-owned journaled transaction."""
    supplied_now = now is not None
    if now is None:
        now = _utc_now()
    if now.tzinfo is None:
        _fail("trusted recovery time must be timezone-aware")
    if policy is None:
        policy = CustodyPolicy.production()
    if reauthenticate is None:
        reauthenticate = _production_reauthenticate
    production = _production_paths_requested(paths)
    if production:
        _require_exact_production_paths(paths, "recovery")
        if (
            policy != CustodyPolicy.production()
            or operations is not SYSTEM_OPERATIONS
            or reauthenticate is not _production_reauthenticate
            or dependency_custody is not None
            or crash_hook is not _noop_crash_hook
            or supplied_now
        ):
            _fail("production recovery refuses injected transaction dependencies")
        _validate_production_invocation(production_invocation)
    authority_dir = HeldDirectory.open(paths.authority.parent, policy)
    receipt_dir = HeldDirectory.open(paths.receipt.parent, policy)
    try:
        if production_invocation is not None:
            production_invocation.validate()
        _acquire_transaction_lock(authority_dir)
        if (
            _leaf_bytes(authority_dir, paths.journal.name, MAX_JOURNAL) is None
            and _leaf_bytes(authority_dir, paths.journal_next.name, MAX_JOURNAL)
            is None
        ):
            return _recover_authenticated_terminal_without_journal(
                authority_dir,
                receipt_dir,
                paths,
                operations=operations,
                reauthenticate=reauthenticate,
                production=production,
                production_invocation=production_invocation,
                dependency_custody=dependency_custody,
                now=now,
            )
        journal = _load_recovery_journal(authority_dir, paths)
        old_receipt = str(journal["old_receipt_sha256"])
        new_receipt = str(journal["new_receipt_sha256"])
        old_authority = str(journal["old_authority_sha256"])
        new_authority = str(journal["new_authority_sha256"])
        receipt_digest = _current_leaf_digest(receipt_dir, paths.receipt.name, MAX_RECEIPT)
        authority_digest = _current_leaf_digest(authority_dir, paths.authority.name, MAX_AUTHORITY)
        valid_receipts = {old_receipt, new_receipt}
        valid_authorities = {old_authority, new_authority}
        if receipt_digest not in valid_receipts or authority_digest not in valid_authorities:
            _fail("recovery encountered unrecognized published bytes")
        current_authority_data = _leaf_bytes(
            authority_dir, paths.authority.name, MAX_AUTHORITY
        )
        if current_authority_data is None:
            _fail("recovery authority is missing")
        current_authority = _parse_authority(current_authority_data)
        _require_journaled_recovery_window(current_authority, journal, now)
        if receipt_digest == old_receipt and authority_digest == old_authority:
            _rollback(
                authority_dir,
                receipt_dir,
                paths,
                journal,
                policy=policy,
                operations=operations,
            )
            if production_invocation is not None:
                production_invocation.validate()
            return {"result": "rolled-back-before-publication"}
        if receipt_digest == old_receipt and authority_digest == new_authority:
            _rollback(
                authority_dir,
                receipt_dir,
                paths,
                journal,
                policy=policy,
                operations=operations,
            )
            if production_invocation is not None:
                production_invocation.validate()
            return {"result": "rolled-back-inverted-publication"}
        candidate = _leaf_bytes(receipt_dir, paths.receipt.name, MAX_RECEIPT)
        if candidate is None or _sha256(candidate) != new_receipt:
            _fail("recovery candidate receipt is missing")
        expected_closure = _validate_closure(
            current_authority["closure"], "recovery authority"
        )
        candidate_record = _parse_candidate_receipt(candidate, expected_closure)
        _validate_native_receipt_authority(candidate_record, current_authority)
        repo = Path(str(journal["authorized_repo_root"]))
        repo_info = os.stat(repo, follow_symlinks=False)
        owner_uid, owner_gid = _authorized_repo_owner(repo_info)
        recovery_closure: HeldClosure | None = None
        dependencies = dependency_custody
        dependencies_owned = False
        terminal_authenticated = False
        try:
            recovery_closure = HeldClosure.open(
                repo,
                expected_closure,
                uid=repo_info.st_uid,
                gid=repo_info.st_gid,
                operations=operations,
            )
            if production:
                dependencies = HeldDependencies.open(
                    recovery_closure.files["pin_manifest_sha256"].data,
                    candidate_record,
                    owner_uid=owner_uid,
                    operations=operations,
                )
                dependencies_owned = True

            def validate_recovery_transition() -> None:
                if production_invocation is not None:
                    production_invocation.validate()
                if recovery_closure is not None:
                    recovery_closure.validate()
                if dependencies is not None:
                    dependencies.validate()

            validate_recovery_transition()
            if receipt_digest == new_receipt and authority_digest == old_authority:
                _replace_from_stage(
                    authority_dir,
                    str(journal["authority_stage_name"]),
                    paths.authority.name,
                    expected_sha256=new_authority,
                    mode=0o444,
                    immutable_flags=int(journal["old_authority_flags"]),
                    policy=policy,
                    operations=operations,
                )
                validate_recovery_transition()
            authority_data = _leaf_bytes(
                authority_dir, paths.authority.name, MAX_AUTHORITY
            )
            if authority_data is None or _sha256(authority_data) != new_authority:
                _fail("recovery next authority is missing")
            _restore_leaf_custody(
                receipt_dir,
                paths.receipt.name,
                expected_sha256=new_receipt,
                maximum=MAX_RECEIPT,
                mode=0o444,
                immutable_flags=int(journal["old_receipt_flags"]),
                policy=policy,
                operations=operations,
            )
            validate_recovery_transition()
            _restore_leaf_custody(
                authority_dir,
                paths.authority.name,
                expected_sha256=new_authority,
                maximum=MAX_AUTHORITY,
                mode=0o444,
                immutable_flags=int(journal["old_authority_flags"]),
                policy=policy,
                operations=operations,
            )
            validate_recovery_transition()
            authority = _parse_authority(authority_data)
            os.environ["WINS_RELEASE_PYTHON_AUTHORIZED_REPO"] = str(repo)
            reauthenticate(
                paths.receipt,
                candidate,
                expected_closure,
                dependencies,
                owner_uid,
                owner_gid,
            )
            validate_recovery_transition()
            journal = _advance_journal(
                authority_dir,
                paths,
                journal,
                "verified",
                policy=policy,
                operations=operations,
            )
            validate_recovery_transition()
            terminal_authenticated = True
            _cleanup_transaction(
                authority_dir,
                receipt_dir,
                paths,
                journal,
                operations,
                crash_hook,
            )
            validate_recovery_transition()
            return {
                "migration_id": journal["migration_id"],
                "receipt_sha256": new_receipt,
                "result": "rolled-forward-and-reauthenticated",
                "sequence": authority["active_sequence"],
            }
        except Exception:
            if not terminal_authenticated:
                _rollback(
                    authority_dir,
                    receipt_dir,
                    paths,
                    journal,
                    policy=policy,
                    operations=operations,
                )
            raise
        finally:
            os.environ.pop("WINS_RELEASE_PYTHON_AUTHORIZED_REPO", None)
            if dependencies_owned and dependencies is not None:
                dependencies.close()
            if recovery_closure is not None:
                recovery_closure.close()
    finally:
        receipt_dir.close()
        authority_dir.close()


def _require_direct_script_execution() -> None:
    if (
        __name__ != "__main__"
        or __spec__ is not None
        or __package__ not in {None, ""}
        or not sys.argv
        or Path(sys.argv[0]).resolve(strict=False)
        != Path(__file__).resolve(strict=False)
    ):
        _fail("owner provision refuses imported or replacement-module execution")
    original = list(getattr(sys, "orig_argv", ()))
    if (
        not original
        or any(value in {"-c", "-m"} for value in original[1:])
        or len(original) < len(sys.argv) + 1
        or original[-len(sys.argv) :] != sys.argv
    ):
        _fail("owner provision refuses runpy, -c, -m, or rewritten argv execution")


def _require_exact_launcher_environment() -> None:
    for name, expected in LAUNCHER_ENVIRONMENT.items():
        if os.environ.get(name) != expected:
            _fail(f"authenticated launcher environment mismatch: {name}")
    allowed = set(LAUNCHER_ENVIRONMENT) | LAUNCHER_OPTIONAL_ENVIRONMENT
    unexpected = sorted(set(os.environ) - allowed)
    if unexpected:
        _fail(f"authenticated launcher supplied unexpected environment: {unexpected[0]}")
    if Path(os.environ.get("HOME", "")).resolve(strict=False) != Path(
        "/private/var/root"
    ):
        _fail("authenticated launcher HOME is not the root home")
    if os.environ.get("TMPDIR") != "/private/tmp":
        _fail("authenticated launcher TMPDIR is not the reviewed private root")
    if os.environ.get("LC_CTYPE") not in {None, "C.UTF-8"}:
        _fail("authenticated launcher locale is not exact")
    user_text = os.environ.get("__CF_USER_TEXT_ENCODING")
    if user_text not in {None, "0x0:0:0"}:
        _fail("authenticated launcher user-text environment is invalid")


def _require_production_process_state(capability: NativeCapability) -> None:
    _require_direct_script_execution()
    script_path = f"/dev/fd/{capability.controller_fd}"
    expected_original = [
        str(RUNTIME_PYTHON),
        "-I",
        "-S",
        script_path,
        *sys.argv[1:],
    ]
    if (
        type(capability) is not NativeCapability
        or Path(__file__) != Path(script_path)
        or sys.argv[0] != script_path
        or list(sys.orig_argv) != expected_original
        or str(sys.executable) != str(RUNTIME_LAUNCHER)
        or str(getattr(sys, "_base_executable", "")) != str(RUNTIME_PYTHON)
    ):
        _fail("production actions require the exact authenticated launcher invocation")
    _require_exact_launcher_environment()
    if sys.platform != "darwin" or os.geteuid() != 0:
        _fail("fixed owner provision requires macOS euid 0")
    flags = sys.flags
    if flags.isolated != 1 or flags.no_site != 1 or getattr(flags, "safe_path", False) is not True:
        _fail("fixed owner provision requires authenticated Python -I -S")


def _require_native_bootstrap() -> None:
    if os.environ.get("WINS_OWNER_RUNTIME_FD") != str(NATIVE_RUNTIME_FD):
        _fail("native launcher bootstrap runtime descriptor is absent")
    if os.environ.get("WINS_OWNER_CAPABILITY_FD") != str(NATIVE_CAPABILITY_FD):
        _fail("native launcher bootstrap capability is absent")
    if os.environ.get("WINS_OWNER_CONTROLLER_FD") != str(NATIVE_CONTROLLER_FD):
        _fail("native launcher bootstrap controller descriptor is absent")
    try:
        runtime = os.fstat(NATIVE_RUNTIME_FD)
        capability = os.fstat(NATIVE_CAPABILITY_FD)
        controller = os.fstat(NATIVE_CONTROLLER_FD)
    except OSError as exc:
        raise ProvisionError(
            f"{OWNER_BLOCKED}: native launcher bootstrap descriptors are closed"
        ) from exc
    if (
        not stat.S_ISREG(runtime.st_mode)
        or not stat.S_ISSOCK(capability.st_mode)
        or not stat.S_ISREG(controller.st_mode)
    ):
        _fail("native launcher bootstrap descriptor types are invalid")
    if os.getppid() <= 1 or _process_path(os.getppid()) != OWNER_LAUNCHER_PATH:
        _fail("native launcher bootstrap parent process is invalid")


def _open_interrupted_recovery_receipt(
    authority: HeldFile,
    authority_record: dict[str, object],
    *,
    paths: ProvisionPaths,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> HeldFile:
    """Authenticate only the crash window after clearing the receipt flags.

    This is not a general mutable-receipt allowance.  The old receipt, both
    backups, both stages, the old immutable flags, the exact next authority,
    and the root-owned generation-three journal must all describe the single
    publishing-receipt transition before the mutable old receipt can bootstrap
    the already authenticated runtime invocation used by recovery.
    """

    receipt = HeldFile.open(
        paths.receipt,
        maximum=MAX_RECEIPT,
        policy=policy,
        operations=operations,
        mode=0o444,
        immutable=False,
    )
    authority_dir: HeldDirectory | None = None
    receipt_dir: HeldDirectory | None = None
    journal: HeldFile | None = None
    transaction_files: list[HeldFile] = []
    try:
        if operations.flags_fd(receipt.fd) != 0:
            _fail("interrupted recovery receipt flags are not the exact cleared state")
        authority.validate()
        authority_dir = HeldDirectory.open(paths.authority.parent, policy)
        receipt_dir = HeldDirectory.open(paths.receipt.parent, policy)
        if _leaf_bytes(authority_dir, paths.journal_next.name, MAX_JOURNAL) is not None:
            _fail("interrupted recovery has an ambiguous next journal")
        journal = HeldFile.open(
            paths.journal,
            maximum=MAX_JOURNAL,
            policy=policy,
            operations=operations,
            mode=0o600,
            immutable=False,
            allow_owner_write=True,
        )
        record = _parse_journal(journal.data)
        if record["phase"] != "publishing-receipt" or record["generation"] != 3:
            _fail("mutable receipt is not in the exact interrupted publication phase")
        if (
            record["authorized_repo_root"] != authority_record["authorized_repo_root"]
            or record["old_authority_sha256"] != _sha256(authority.data)
            or record["old_receipt_sha256"] != authority_record["active_receipt_sha256"]
            or record["old_receipt_sha256"] != _sha256(receipt.data)
            or not int(record["old_receipt_flags"]) & SF_IMMUTABLE
            or int(record["old_receipt_flags"]) & UF_IMMUTABLE
            or not int(record["old_authority_flags"]) & SF_IMMUTABLE
            or int(record["old_authority_flags"]) & UF_IMMUTABLE
        ):
            _fail("interrupted recovery journal is not bound to the active authority")

        specs = (
            (
                receipt_dir,
                str(record["receipt_backup_name"]),
                str(record["old_receipt_sha256"]),
                MAX_RECEIPT,
            ),
            (
                receipt_dir,
                str(record["receipt_stage_name"]),
                str(record["new_receipt_sha256"]),
                MAX_RECEIPT,
            ),
            (
                authority_dir,
                str(record["authority_backup_name"]),
                str(record["old_authority_sha256"]),
                MAX_AUTHORITY,
            ),
            (
                authority_dir,
                str(record["authority_stage_name"]),
                str(record["new_authority_sha256"]),
                MAX_AUTHORITY,
            ),
        )
        for directory, name, expected, maximum in specs:
            held = HeldFile.open(
                directory.path / name,
                maximum=maximum,
                policy=policy,
                operations=operations,
                mode=0o400,
                immutable=False,
            )
            transaction_files.append(held)
            if _sha256(held.data) != expected:
                _fail(f"interrupted recovery transaction digest mismatch: {name}")

        candidate_data = transaction_files[1].data
        closure = _validate_closure(
            authority_record["closure"], "interrupted recovery authority"
        )
        candidate_record = _parse_candidate_receipt(candidate_data, closure)
        _validate_native_receipt_authority(candidate_record, authority_record)
        expected_next = canonical_bytes(
            _next_authority(authority_record, str(record["new_receipt_sha256"]))
        )
        if transaction_files[3].data != expected_next:
            _fail("interrupted recovery next authority is not the exact derivation")
        receipt.validate()
        authority.validate()
        journal.validate()
        for held in transaction_files:
            held.validate()
        authority_dir.validate()
        receipt_dir.validate()
        return receipt
    except Exception:
        receipt.close()
        raise
    finally:
        for held in reversed(transaction_files):
            held.close()
        if journal is not None:
            journal.close()
        if receipt_dir is not None:
            receipt_dir.close()
        if authority_dir is not None:
            authority_dir.close()


def _open_runtime_receipt_for_invocation(
    authority: HeldFile,
    authority_record: dict[str, object],
    *,
    allow_interrupted_recovery: bool,
    paths: ProvisionPaths,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> HeldFile:
    try:
        return HeldFile.open(
            paths.receipt,
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=operations,
            mode=0o444,
            immutable=True,
        )
    except ProvisionError:
        if not allow_interrupted_recovery:
            raise
        return _open_interrupted_recovery_receipt(
            authority,
            authority_record,
            paths=paths,
            policy=policy,
            operations=operations,
        )


def _open_interrupted_recovery_bootstrap(
    *,
    paths: ProvisionPaths,
    policy: CustodyPolicy,
    operations: SystemOperations,
) -> tuple[HeldFile, dict[str, object], HeldFile]:
    """Open immutable old-state anchors for an interrupted leaf replacement."""

    authority_dir = HeldDirectory.open(paths.authority.parent, policy)
    receipt_dir = HeldDirectory.open(paths.receipt.parent, policy)
    journal: HeldFile | None = None
    authority_anchor: HeldFile | None = None
    receipt_anchor: HeldFile | None = None
    try:
        if _leaf_bytes(authority_dir, paths.journal_next.name, MAX_JOURNAL) is not None:
            _fail("interrupted production recovery has an ambiguous next journal")
        journal = HeldFile.open(
            paths.journal,
            maximum=MAX_JOURNAL,
            policy=policy,
            operations=operations,
            mode=0o600,
            immutable=False,
            allow_owner_write=True,
        )
        record = _parse_journal(journal.data)
        phase = str(record["phase"])
        expected_generation = {
            "publishing-receipt": 3,
            "receipt-published": 4,
            "publishing-authority": 5,
        }
        if phase not in expected_generation or record["generation"] != expected_generation[phase]:
            _fail("production recovery bootstrap phase is not exact")
        if (
            int(record["old_authority_flags"]) & SF_IMMUTABLE == 0
            or int(record["old_authority_flags"]) & UF_IMMUTABLE
            or int(record["old_receipt_flags"]) & SF_IMMUTABLE == 0
            or int(record["old_receipt_flags"]) & UF_IMMUTABLE
        ):
            _fail("production recovery anchor flags are invalid")
        authority_anchor = HeldFile.open(
            paths.authority.parent / str(record["authority_backup_name"]),
            maximum=MAX_AUTHORITY,
            policy=policy,
            operations=operations,
            mode=0o400,
            immutable=True,
        )
        receipt_anchor = HeldFile.open(
            paths.receipt.parent / str(record["receipt_backup_name"]),
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=operations,
            mode=0o400,
            immutable=True,
        )
        if (
            _sha256(authority_anchor.data) != record["old_authority_sha256"]
            or _sha256(receipt_anchor.data) != record["old_receipt_sha256"]
        ):
            _fail("production recovery anchor digest is not journal-bound")
        old_authority = _parse_authority(authority_anchor.data)
        old_receipt = _json(
            receipt_anchor.data,
            "recovery anchor receipt",
            maximum=MAX_RECEIPT,
        )
        if _sha256(receipt_anchor.data) != old_authority["active_receipt_sha256"]:
            _fail("recovery receipt anchor is not active in the authority anchor")
        _validate_active_runtime_receipt(old_receipt, old_authority)

        current_authority = _leaf_bytes(
            authority_dir, paths.authority.name, MAX_AUTHORITY
        )
        current_receipt = _leaf_bytes(
            receipt_dir, paths.receipt.name, MAX_RECEIPT
        )
        authority_stage = _leaf_bytes(
            authority_dir, str(record["authority_stage_name"]), MAX_AUTHORITY
        )
        receipt_stage = _leaf_bytes(
            receipt_dir, str(record["receipt_stage_name"]), MAX_RECEIPT
        )
        if current_authority is None or current_receipt is None:
            _fail("production recovery active leaf is missing")
        authority_digest = _sha256(current_authority)
        receipt_digest = _sha256(current_receipt)
        old_authority_digest = str(record["old_authority_sha256"])
        new_authority_digest = str(record["new_authority_sha256"])
        old_receipt_digest = str(record["old_receipt_sha256"])
        new_receipt_digest = str(record["new_receipt_sha256"])
        if phase == "publishing-receipt":
            exact = (
                authority_digest == old_authority_digest
                and authority_stage is not None
                and _sha256(authority_stage) == new_authority_digest
                and (
                    (
                        receipt_digest == old_receipt_digest
                        and receipt_stage is not None
                        and _sha256(receipt_stage) == new_receipt_digest
                    )
                    or (
                        receipt_digest == new_receipt_digest
                        and receipt_stage is None
                    )
                )
            )
        else:
            exact = (
                receipt_digest == new_receipt_digest
                and receipt_stage is None
                and (
                    (
                        authority_digest == old_authority_digest
                        and authority_stage is not None
                        and _sha256(authority_stage) == new_authority_digest
                    )
                    or (
                        phase == "publishing-authority"
                        and authority_digest == new_authority_digest
                        and authority_stage is None
                    )
                )
            )
        if not exact:
            _fail("production recovery leaf and stage geometry is not exact")
        candidate_data = (
            current_receipt
            if receipt_digest == new_receipt_digest
            else receipt_stage
        )
        if candidate_data is None:
            _fail("production recovery candidate receipt is missing")
        closure = _validate_closure(
            old_authority["closure"], "recovery anchor authority"
        )
        candidate = _parse_candidate_receipt(candidate_data, closure)
        _validate_native_receipt_authority(candidate, old_authority)
        next_authority = canonical_bytes(
            _next_authority(old_authority, new_receipt_digest)
        )
        selected_new_authority = (
            current_authority
            if authority_digest == new_authority_digest
            else authority_stage
        )
        if selected_new_authority != next_authority:
            _fail("production recovery next authority derivation is not exact")
        authority_anchor.validate()
        receipt_anchor.validate()
        journal.validate()
        authority_dir.validate()
        receipt_dir.validate()
        return authority_anchor, old_authority, receipt_anchor
    except Exception:
        if receipt_anchor is not None:
            receipt_anchor.close()
        if authority_anchor is not None:
            authority_anchor.close()
        raise
    finally:
        if journal is not None:
            journal.close()
        receipt_dir.close()
        authority_dir.close()


def _require_production_invocation(
    *,
    allow_interrupted_recovery: bool = False,
    allow_sequence_one_activation: bool = False,
) -> RuntimeInvocation:
    _require_native_bootstrap()
    if sys.platform != "darwin" or os.geteuid() != 0:
        _fail("fixed owner provision requires macOS euid 0")
    flags = sys.flags
    if (
        flags.isolated != 1
        or flags.no_site != 1
        or getattr(flags, "safe_path", False) is not True
    ):
        _fail("fixed owner provision requires authenticated Python -I -S")
    policy = CustodyPolicy.production()
    boundary = HeldFile.open(
        OWNER_PROVISION_PATH,
        maximum=MAX_CONTROLLER,
        policy=policy,
        operations=SYSTEM_OPERATIONS,
        mode=0o555,
        immutable=True,
    )
    authority: HeldFile | None = None
    transferred = False
    capability: NativeCapability | None = None
    receipt: HeldFile | None = None
    try:
        try:
            authority = HeldFile.open(
                AUTHORITY_PATH,
                maximum=MAX_AUTHORITY,
                policy=policy,
                operations=SYSTEM_OPERATIONS,
                mode=0o444,
                immutable=True,
            )
            authority_record = _parse_authority(authority.data)
            receipt = HeldFile.open(
                PRODUCTION_PATHS.receipt,
                maximum=MAX_RECEIPT,
                policy=policy,
                operations=SYSTEM_OPERATIONS,
                mode=0o444,
                immutable=True,
            )
            if _sha256(receipt.data) != authority_record["active_receipt_sha256"]:
                _fail("active runtime receipt is not authority-bound")
        except ProvisionError:
            if receipt is not None:
                receipt.close()
                receipt = None
            if authority is not None:
                authority.close()
                authority = None
            if not allow_interrupted_recovery:
                raise
            authority, authority_record, receipt = (
                _open_interrupted_recovery_bootstrap(
                    paths=PRODUCTION_PATHS,
                    policy=policy,
                    operations=SYSTEM_OPERATIONS,
                )
            )
        receipt_record = _json(
            receipt.data, "active runtime receipt", maximum=MAX_RECEIPT
        )
        sequence_one_activation = _is_sequence_one_activation_receipt(
            receipt_record, authority_record
        )
        _validate_active_runtime_receipt(
            receipt_record,
            authority_record,
            allow_sequence_one_activation=allow_sequence_one_activation,
        )
        _preconditions_for_fixed_boundary(boundary, authority_record)
        capability = NativeCapability.consume(
            authority=authority_record,
            receipt=receipt_record,
            controller=boundary,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
            allow_generation_activation=sequence_one_activation,
        )
        _require_production_process_state(capability)
        invocation = _authenticate_runtime_invocation(
            RUNTIME_PYTHON,
            RUNTIME_LAUNCHER,
            str(sys.executable),
            str(getattr(sys, "_base_executable", "")),
            receipt.data,
            controller=boundary,
            native_capability=capability,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
        )
        transferred = True
        return invocation
    finally:
        if authority is not None:
            authority.close()
        if receipt is not None:
            receipt.close()
        if not transferred:
            if capability is not None:
                try:
                    capability.close()
                except OSError:
                    pass
            try:
                boundary.close()
            except OSError:
                pass


def _require_initial_authority_invocation() -> tuple[NativeCapability, HeldFile]:
    _require_native_bootstrap()
    if sys.platform != "darwin" or os.geteuid() != 0:
        _fail("initial authority publication requires macOS euid 0")
    policy = CustodyPolicy.production()
    boundary = HeldFile.open(
        OWNER_PROVISION_PATH,
        maximum=MAX_CONTROLLER,
        policy=policy,
        operations=SYSTEM_OPERATIONS,
        mode=0o555,
        immutable=True,
    )
    capability: NativeCapability | None = None
    receipt: HeldFile | None = None
    try:
        receipt = HeldFile.open(
            RECEIPT_PATH,
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
            mode=0o444,
            immutable=True,
        )
        receipt_record = _json(
            receipt.data, "initial authority active receipt", maximum=MAX_RECEIPT
        )
        capability = NativeCapability.consume(
            authority=None,
            receipt=receipt_record,
            controller=boundary,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
            allow_generation_activation=True,
        )
        _require_production_process_state(capability)
        receipt.validate()
        receipt.close()
        receipt = None
        return capability, boundary
    except Exception:
        if receipt is not None:
            receipt.close()
        if capability is not None:
            capability.close()
        boundary.close()
        raise


def selftest() -> None:
    sample_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    sample_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    if not verify_ed25519(sample_public, b"", sample_signature):
        raise RuntimeError("Ed25519 verification self-test failed")
    if verify_ed25519(sample_public, b"x", sample_signature):
        raise RuntimeError("Ed25519 hostile self-test failed")
    if len(MIGRATION_CLOSURE_PATHS) != 17:
        raise RuntimeError("ReleasePython closure count changed")


def _authenticated_selftest() -> None:
    policy = CustodyPolicy.production()
    invocation = _require_production_invocation()
    authority: HeldFile | None = None
    receipt: HeldFile | None = None
    closure: HeldClosure | None = None
    dependencies: HeldDependencies | None = None
    authority_dir: HeldDirectory | None = None
    receipt_dir: HeldDirectory | None = None
    try:
        authority = HeldFile.open(
            AUTHORITY_PATH,
            maximum=MAX_AUTHORITY,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
            mode=0o444,
            immutable=True,
        )
        authority_record = _parse_authority(authority.data)
        _require_authority_current(
            authority_record, _utc_now(), label="authenticated selftest"
        )
        receipt = HeldFile.open(
            RECEIPT_PATH,
            maximum=MAX_RECEIPT,
            policy=policy,
            operations=SYSTEM_OPERATIONS,
            mode=0o444,
            immutable=True,
        )
        if _sha256(receipt.data) != authority_record["active_receipt_sha256"]:
            _fail("authenticated selftest receipt is not active in the authority")
        authority_dir = HeldDirectory.open(AUTHORITY_PATH.parent, policy)
        receipt_dir = HeldDirectory.open(RECEIPT_PATH.parent, policy)
        _assert_no_transaction_leftovers(
            authority_dir, receipt_dir, PRODUCTION_PATHS
        )
        closure_digest = _validate_closure(
            authority_record["closure"], "authenticated selftest authority"
        )
        receipt_record = _parse_candidate_receipt(receipt.data, closure_digest)
        _validate_native_receipt_authority(receipt_record, authority_record)
        repo = Path(str(authority_record["authorized_repo_root"]))
        repo_info = os.stat(repo, follow_symlinks=False)
        owner_uid, _owner_gid = _authorized_repo_owner(repo_info)
        closure = HeldClosure.open(
            repo,
            closure_digest,
            uid=repo_info.st_uid,
            gid=repo_info.st_gid,
            operations=SYSTEM_OPERATIONS,
        )
        dependencies = HeldDependencies.open(
            closure.files["pin_manifest_sha256"].data,
            receipt_record,
            owner_uid=owner_uid,
            operations=SYSTEM_OPERATIONS,
        )
        invocation.validate()
        authority.validate()
        receipt.validate()
        closure.validate()
        dependencies.validate()
        selftest()
        dependencies.validate()
        closure.validate()
        receipt.validate()
        authority.validate()
        invocation.validate()
    finally:
        if receipt_dir is not None:
            receipt_dir.close()
        if authority_dir is not None:
            authority_dir.close()
        if dependencies is not None:
            dependencies.close()
        if closure is not None:
            closure.close()
        if receipt is not None:
            receipt.close()
        if authority is not None:
            authority.close()
        invocation.close()


class _NoColorHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)


def _argument_parser() -> argparse.ArgumentParser:
    options: dict[str, Any] = {
        "allow_abbrev": False,
        "formatter_class": _NoColorHelpFormatter,
    }
    if sys.version_info >= (3, 14):
        options["color"] = False
    return argparse.ArgumentParser(**options)


def main(argv: list[str] | None = None) -> int:
    try:
        if argv is not None:
            _fail("owner provision main refuses caller-supplied argv")
        _require_direct_script_execution()
        parser = _argument_parser()
        sub = parser.add_subparsers(dest="action", required=True)
        apply_parser = sub.add_parser("apply", allow_abbrev=False)
        apply_parser.add_argument("plan", type=Path)
        apply_parser.add_argument("authorization", type=Path)
        publish_parser = sub.add_parser("publish-authority", allow_abbrev=False)
        publish_parser.add_argument("authority", type=Path)
        publish_parser.add_argument("envelope", type=Path)
        sub.add_parser("recover", allow_abbrev=False)
        sub.add_parser("selftest", allow_abbrev=False)
        args = parser.parse_args()
        if args.action == "selftest":
            _authenticated_selftest()
            print("macOS ReleasePython owner-provision self-test passed")
            return 0
        if args.action == "publish-authority":
            capability, boundary = _require_initial_authority_invocation()
            try:
                result = publish_initial_authority(
                    args.authority,
                    args.envelope,
                    capability=capability,
                )
                capability.validate()
                boundary.validate()
            finally:
                capability.close()
                boundary.close()
            sys.stdout.buffer.write(canonical_bytes(result))
            return 0
        invocation = _require_production_invocation(
            allow_interrupted_recovery=args.action == "recover",
            allow_sequence_one_activation=args.action in {"apply", "recover"},
        )
        try:
            if args.action == "apply":
                result = apply_transaction(
                    args.plan,
                    args.authorization,
                    production_invocation=invocation,
                )
            else:
                result = recover_transaction(production_invocation=invocation)
            invocation.validate()
        finally:
            invocation.close()
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except ProvisionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"{OWNER_BLOCKED}: unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
