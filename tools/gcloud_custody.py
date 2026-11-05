#!/usr/bin/env python3
"""Fail-closed Google Cloud CLI archive, tree, credential, and execution custody.

Production call boundaries require a genuinely external authenticated owner
issuance identity. The in-repo trust-anchor is a local hash pin only; same-UID
chmod 0444 files and source-freeze producer execution are not a trust root.
Production Google Cloud CLI execution uses an owner-provisioned immutable
runtime (SF_IMMUTABLE or Linux FS_IMMUTABLE_FL), descriptor-bound credential
reads, and macOS parent directory binding via
posix_spawn_file_actions_addfchdir_np before spawn. If this host cannot prove
immutability against same-user replacement, execution fails closed as an
owner/environment blocker before any spawn. Test-only runners and receipts are
structurally unable to emit production PASS.
"""

from __future__ import annotations

import array
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import types
from typing import Any, Callable, Iterator, Sequence
import weakref
import zipfile


PIN_KEYS = {"version", "archive_sha256", "archive_name", "note"}
PLATFORMS = {
    "darwin_amd64": ("darwin", "x86_64", ".tar.gz"),
    "darwin_arm64": ("darwin", "arm", ".tar.gz"),
    "linux_amd64": ("linux", "x86_64", ".tar.gz"),
    "linux_arm64": ("linux", "arm", ".tar.gz"),
    "windows_amd64": ("windows", "x86_64", ".zip"),
}
RECEIPT_NAME = ".winsvpn-gcloud-custody-v1.json"
CUSTODY_ARCHIVE_NAME = ".winsvpn-gcloud-official-archive"
SEALED_PUBLIC_DATA_MODE = 0o444
SEALED_PUBLIC_EXEC_MODE = 0o555
SEALED_PUBLIC_DIR_MODE = 0o555
RECEIPT_KEYS = {
    "schema_version", "contract", "version", "platform", "archive_name",
    "archive_sha256", "install_tree_sha256", "executable_path",
    "install_root_sha256", "issued_utc", "expires_utc", "issuance_id",
    "authority_key_id", "controller_sha256", "manifest_sha256",
    "trust_anchor_sha256", "issuance_signature",
}
SIGNED_RECEIPT_KEYS = RECEIPT_KEYS - {"issuance_signature"}
DURABLE_RECEIPT_VOLATILE_KEYS = {
    "issued_utc", "expires_utc", "issuance_id",
}
TEST_RECEIPT_KEYS = {
    "schema_version", "contract", "version", "platform", "archive_name",
    "archive_sha256", "install_tree_sha256", "executable_path",
    "test_only",
}
RECEIPT_CONTRACT = "winsvpn-gcloud-install-custody-v1"
CONTROLLER_NAME = "gcloud_custody.py"
MANIFEST_NAME = "toolchain-pins.json"
TRUST_ANCHOR_NAME = "gcloud_custody.trust.json"
PYTHON_CUSTODY_NAME = "macos_release_python_runtime_receipt.py"
TRUST_CONTRACT = "winsvpn-gcloud-custody-trust-v1"
TRUST_KEYS = (
    "contract",
    "schema_version",
    "controller",
    "manifest",
    "trust_anchor",
    "python_custody",
    "controller_sha256",
    "manifest_sha256",
    "python_custody_sha256",
    "component_contract",
    "components",
)
TRUST_COMPONENT_CONTRACT = "winsvpn-gcloud-release-components-v1"
TRUST_COMPONENT_KEYS = ("kind", "path", "sha256")
TRUST_COMPONENTS = (
    ("test", "tools/gcloud_custody_test.py"),
    ("source", "tools/create_gcloud_custody_receipt.py"),
    ("test", "tools/test_create_gcloud_custody_receipt.py"),
    ("source", "tools/gcloud_immutable_helper.go"),
    ("test", "tools/gcloud_immutable_helper_test.go"),
    ("build_script", "tools/build_gcloud_immutable_helper.sh"),
    ("artifact", "build/gcloud_runtime_provisioner/gcloud_immutable_helper_linux_amd64"),
    ("source", "tools/gcloud_runtime_provisioner.go"),
    ("test", "tools/gcloud_runtime_provisioner_test.go"),
    ("build_script", "tools/build_gcloud_runtime_provisioner.sh"),
    ("artifact", "build/gcloud_runtime_provisioner/gcloud_runtime_provisioner_linux_amd64"),
)
OWNER_ISSUANCE_CONTRACT = "winsvpn-gcloud-owner-issuance-v1"
OWNER_ISSUANCE_ISSUER = "winsvpn-owner"
OWNER_ISSUANCE_PATH = Path("/var/lib/winsvpn/gcloud-owner-issuance.json")
OWNER_AUTHORITY_CONTRACT = "winsvpn-gcloud-owner-authority-v1"
OWNER_AUTHORITY_PATH = Path("/var/lib/winsvpn/gcloud-owner-authority-v1.json")
OWNER_SIGNATURE_ALGORITHM = "ed25519"
OWNER_SIGNATURE_DOMAIN = b"winsvpn-gcloud-owner-receipt-v1\n"
OWNER_AUTHORITY_KEYS = (
    "contract",
    "schema_version",
    "algorithm",
    "key_id",
    "public_key",
    "owner_uid",
)
OWNER_ISSUANCE_KEYS = (
    "contract",
    "schema_version",
    "issuer",
    "algorithm",
    "key_id",
    "receipt",
    "signature",
)
SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
ISSUANCE_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
ED25519_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
ED25519_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")
UTC_SECONDS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
ZERO_SHA = "0" * 64
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,64}\Z")
PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
SSH_INSTANCE_RE = re.compile(r"^[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
SSH_ZONE_RE = re.compile(r"^[a-z]+-[a-z]+[0-9]+-[a-z]\Z")
WIF_EMAIL_RE = re.compile(
    r"^https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,64}):generateAccessToken\Z"
)
WIF_AUDIENCE_RE = re.compile(
    r"^//iam\.googleapis\.com/projects/[0-9]{1,20}/locations/global/"
    r"workloadIdentityPools/[A-Za-z0-9-]{1,64}/providers/[A-Za-z0-9-]{1,64}\Z"
)
WIF_TOKEN_URL = "https://sts.googleapis.com/v1/token"
WIF_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
SA_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
SA_TOKEN_URI = "https://oauth2.googleapis.com/token"
SA_PRIVATE_KEY_RE = re.compile(
    "^-----BEGIN (?:RSA )?PRIVATE KEY-----\n"
    "[A-Za-z0-9+_/=\\n]+\n"
    "-----END (?:RSA )?PRIVATE KEY-----\n?\\Z"
)
SA_CLIENT_ID_RE = re.compile(r"^[0-9]{6,32}\Z")
SA_PRIVATE_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")
SA_CREDENTIAL_KEYS = {
    "type", "project_id", "private_key_id", "private_key",
    "client_email", "client_id", "auth_uri", "token_uri",
}
WIF_CREDENTIAL_KEYS = {
    "type", "audience", "subject_token_type", "token_url",
    "service_account_impersonation_url", "credential_source",
}
WIF_CREDENTIAL_SOURCE_KEYS = {"file"}
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MEMBER = 512 * 1024 * 1024
MAX_MEMBERS = 200_000
MAX_RATIO = 100
MAX_EXPANDED = 3 * 1024 * 1024 * 1024
MAX_DEPTH = 32
MAX_PATH_BYTES = 1024
MAX_CREDENTIAL = 256 * 1024
MAX_SUBJECT_TOKEN = 256 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
MAX_TRUST = 64 * 1024
MAX_ISSUANCE = 64 * 1024
MIN_PYTHON = (3, 12)
MAX_RECEIPT_AGE = timedelta(hours=6)
MAX_RECEIPT_CLOCK_SKEW = timedelta(minutes=5)
MAX_SSH_COMMAND = 32 * 1024
MAX_PIPE_CAPTURE = 1024 * 1024
MAX_COMMAND_CAPTURE = 4 * 1024 * 1024
MAX_SSH_PIPE_RESPONSE = 4096
MAX_PIPE_TIMEOUT = 3600
FIXED_SSH_ARGC = 7
PIPE_PRODUCER_STDERR = "gcloud-pipe-producer-stderr"
PIPE_CONSUMER_STDOUT = "gcloud-pipe-consumer-stdout"
PIPE_CONSUMER_STDERR = "gcloud-pipe-consumer-stderr"
SSH_PIPE_RESPONSE_CONTRACT = "winsvpn-gcloud-ssh-pipe-response-v1"
SSH_PIPE_RESPONSE_STATUS = "ok"
SSH_PIPE_RESPONSE_KEYS = frozenset(
    {"contract", "payload_sha256", "schema_version", "status"}
)
SSH_PIPE_TIMEOUT = "Google Cloud CLI SSH pipe timed out"
SSH_PIPE_EXIT = "Google Cloud CLI SSH pipe processes did not both exit zero"
SSH_PIPE_STDERR = "Google Cloud CLI SSH producer stderr is not empty"
SSH_PIPE_CONSUMER_STDERR = "Google Cloud CLI SSH consumer stderr is not empty"
SSH_PIPE_STREAM_LIMIT = "captured Google Cloud CLI stream exceeds the size limit"
SSH_PIPE_RESPONSE = "Google Cloud CLI SSH pipe consumer response is invalid"
SSH_PIPE_VALIDATOR = "Google Cloud CLI SSH pipe consumer response validator is required"
SSH_PIPE_ARGV = "fixed Google Cloud CLI SSH argv is invalid"
SERVICE_ACCOUNT_KIND = "service_account"
WORKLOAD_IDENTITY_KIND = "workload_identity"
CLONE_NOFOLLOW = 0x0001
POSIX_SPAWN_SETSID = 0x0400
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
LINUX_CAP_IMMUTABLE = 9
LINUX_BUNDLED_PYTHON_RELATIVE = "platform/bundledpythonunix/bin/python3.14"
DARWIN_CREDENTIAL_CHILD_FD = 197
DARWIN_SUBJECT_TOKEN_CHILD_FD = 198
PRODUCTION_RUNTIME_PREFIXES = {
    "darwin_amd64": Path("/Library/WinsVPN/ReleaseGcloudRuntime/v1"),
    "darwin_arm64": Path("/Library/WinsVPN/ReleaseGcloudRuntime/v1"),
    "linux_amd64": Path("/var/lib/winsvpn/gcloud-runtime-v1"),
    "linux_arm64": Path("/var/lib/winsvpn/gcloud-runtime-v1"),
}
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Google Cloud CLI tree "
    "immutable against same-user path replacement through execution"
)
OWNER_BLOCKED_TRUST = (
    "owner-blocked: Google Cloud CLI custody requires a genuinely external "
    "authenticated trust root that the candidate transaction cannot mint or rewrite"
)
TEST_ONLY_RECEIPT = (
    "test-only Google Cloud CLI receipt cannot satisfy production custody"
)
SYNTHETIC_PIN = "caller self-authored synthetic Google Cloud CLI pin"
TEST_ONLY_RUNNER = (
    "test-only runner cannot emit a production PASS receipt"
)
ARBITRARY_RUNNER = (
    "arbitrary runner cannot execute production Google Cloud CLI commands"
)
MISSING_IDENTITY = (
    "owner blocker: Google Cloud CLI execution requires an exact "
    "descriptor-authenticated service-account credential or workload identity input"
)
CREDENTIAL_ENV_EXACT = frozenset(
    {
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_APPLICATION_CREDENTIALS_JSON",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
        "CLOUDSDK_CONFIG",
        "CLOUDSDK_CORE_ACCOUNT",
        "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
        "GCLOUD_KEYFILE",
        "GCLOUD_KEY_FILE",
        "GOOGLE_GHA_CREDS_PATH",
        "GOOGLE_API_KEY",
        "DOCKER_CONFIG",
        "KUBECONFIG",
        "NETRC",
        "SSH_AUTH_SOCK",
    }
)
CREDENTIAL_ENV_PREFIXES = (
    "CLOUDSDK_",
    "GOOGLE_",
    "GCLOUD_",
    "GCE_",
    "AWS_",
    "AZURE_",
    "ARM_",
)
CREDENTIAL_ENV_MARKERS = (
    "CREDENTIAL",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
)
INJECTION_ENV_EXACT = frozenset(
    {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONEXECUTABLE",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DOCKER_CONFIG",
        "KUBECONFIG",
        "NETRC",
        "SSH_AUTH_SOCK",
    }
)
_DIR_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_LIBC: ctypes.CDLL | None
try:
    if sys.platform == "darwin":
        _LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        _LIBC.fclonefileat.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint32,
        ]
        _LIBC.fclonefileat.restype = ctypes.c_int
        _LIBC.posix_spawn.restype = ctypes.c_int
        _LIBC.posix_spawnattr_init.restype = ctypes.c_int
        _LIBC.posix_spawnattr_setflags.restype = ctypes.c_int
        _LIBC.posix_spawnattr_destroy.restype = ctypes.c_int
        _LIBC.posix_spawn_file_actions_init.restype = ctypes.c_int
        _LIBC.posix_spawn_file_actions_adddup2.restype = ctypes.c_int
        _LIBC.posix_spawn_file_actions_addopen.restype = ctypes.c_int
        _LIBC.posix_spawn_file_actions_addfchdir_np.restype = ctypes.c_int
        _LIBC.posix_spawn_file_actions_destroy.restype = ctypes.c_int
        _LIBC.fchflags.restype = ctypes.c_int
        _LIBC.fchflags.argtypes = [ctypes.c_int, ctypes.c_ulong]
    elif sys.platform.startswith("linux"):
        _LIBC = ctypes.CDLL("libc.so.6", use_errno=True)
    else:
        _LIBC = None
except OSError:
    _LIBC = None


class GcloudCustodyError(RuntimeError):
    pass


def require_compatible_python() -> None:
    """Refuse unauthenticated or pre-3.12 CPython, including a Python 3.9 false green."""
    info = sys.version_info
    if sys.implementation.name != "cpython":
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI custody requires an authenticated CPython runtime"
        )
    if info.releaselevel != "final" or info.serial != 0:
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI custody requires a final authenticated CPython runtime"
        )
    if (info.major, info.minor) == (3, 9):
        raise GcloudCustodyError(
            "owner blocker: Python 3.9 cannot authenticate Google Cloud CLI archives; "
            "refusing a false-green extraction"
        )
    if (info.major, info.minor) < MIN_PYTHON:
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI custody requires authenticated CPython 3.12 or newer"
        )


@dataclass(frozen=True)
class GcloudCredentialInput:
    """Exact caller-supplied identity. Values are compared and never printed."""

    kind: str
    path: Path
    expected_account: str
    expected_project: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", Path(self.path))


@dataclass(frozen=True)
class AuthenticatedCredential:
    data: bytes = field(repr=False)
    subject_token: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuthenticatedPython:
    path: Path
    data: bytes = field(repr=False)
    sha256: str


@dataclass(frozen=True)
class CustodyRunResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GcloudCustodyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _ssh_pipe_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GcloudCustodyError(SSH_PIPE_RESPONSE)
        result[key] = value
    return result


def strict_json_bytes(data: bytes, label: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except GcloudCustodyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GcloudCustodyError(f"{label} is not strict UTF-8 JSON") from exc


def _stat_identity(item: os.stat_result) -> tuple[int, ...]:
    return (
        item.st_dev,
        item.st_ino,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
        item.st_nlink,
    )


def _stable_file(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise GcloudCustodyError(f"{label} must be a regular single-link file")
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            chunks: list[bytes] = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = path.lstat()
    except GcloudCustodyError:
        raise
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if (
        _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
    ):
        raise GcloudCustodyError(f"{label} changed while it was read")
    return b"".join(chunks)


def _stable_file_at_with_identity(
    dir_fd: int, name: str, label: str
) -> tuple[bytes, tuple[int, ...]]:
    try:
        before = os.lstat(name, dir_fd=dir_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise GcloudCustodyError(f"{label} must be a regular single-link file")
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        try:
            opened = os.fstat(fd)
            chunks: list[bytes] = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            finished = os.fstat(fd)
        finally:
            os.close(fd)
        after = os.lstat(name, dir_fd=dir_fd)
    except GcloudCustodyError:
        raise
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if (
        _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(finished) != _stat_identity(after)
    ):
        raise GcloudCustodyError(f"{label} changed while it was read")
    identity = (
        finished.st_dev,
        finished.st_ino,
        finished.st_size,
        finished.st_mtime_ns,
        finished.st_ctime_ns,
        finished.st_nlink,
        stat.S_IMODE(finished.st_mode),
    )
    return b"".join(chunks), identity


def _stable_file_at(dir_fd: int, name: str, label: str) -> bytes:
    data, _identity = _stable_file_at_with_identity(dir_fd, name, label)
    return data


def _file_identity(path: Path, label: str) -> tuple[int, ...]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise GcloudCustodyError(f"{label} must be a regular single-link file")
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
    )


def _fd_identity(fd: int, label: str) -> tuple[int, ...]:
    try:
        info = os.fstat(fd)
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise GcloudCustodyError(f"{label} has an unsupported file type")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise GcloudCustodyError(f"{label} must have exactly one link")
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_nlink,
        stat.S_IMODE(info.st_mode),
    )


def _write_exclusive_held(path: Path, data: bytes, mode: int) -> int:
    descriptor = os.open(
        path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        mode,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short custody write")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    descriptor = _write_exclusive_held(path, data, mode)
    os.close(descriptor)


def _stable_fd_bytes(fd: int, *, max_size: int, label: str) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > max_size
    ):
        raise GcloudCustodyError(f"{label} must be one bounded regular single-link file")
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        block = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
        if not block:
            raise GcloudCustodyError(f"{label} was truncated")
        chunks.append(block)
        offset += len(block)
    after = os.fstat(fd)
    if _stat_identity(before) != _stat_identity(after):
        raise GcloudCustodyError(f"{label} changed while it was read")
    return b"".join(chunks), _fd_identity(fd, label)


def _secure_unlink(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode):
        try:
            os.unlink(path)
        except OSError:
            return
        return
    try:
        held = os.open(path, _FILE_FLAGS)
    except OSError:
        return
    try:
        opened = os.fstat(held)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            return
        _clear_immutable_fd(held)
        try:
            os.fchmod(held, 0o600)
        except OSError:
            pass
    finally:
        os.close(held)
    try:
        if stat.S_ISREG(info.st_mode):
            fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                remaining = min(int(info.st_size), MAX_CREDENTIAL)
                while remaining > 0:
                    block = b"\0" * min(remaining, 65536)
                    written = os.write(fd, block)
                    if written <= 0:
                        break
                    remaining -= written
                os.fsync(fd)
            finally:
                os.close(fd)
        os.unlink(path)
    except OSError:
        return


def _secure_unlink_held(fd: int, path: Path, *, max_size: int) -> None:
    if type(fd) is not int or fd < 0:
        return
    try:
        held = os.fstat(fd)
        if stat.S_ISREG(held.st_mode):
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
            remaining = min(max(int(held.st_size), 0), max_size)
            offset = 0
            while remaining > 0:
                block = b"\0" * min(remaining, 65536)
                written = os.pwrite(fd, block, offset)
                if written <= 0:
                    break
                offset += written
                remaining -= written
            try:
                os.fsync(fd)
            except OSError:
                pass
        try:
            visible = path.lstat()
        except OSError:
            return
        if (visible.st_dev, visible.st_ino) == (held.st_dev, held.st_ino):
            path.unlink(missing_ok=True)
    except OSError:
        return


def _safe_archive_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = Path(normalized)
    return (
        bool(normalized)
        and not normalized.startswith("/")
        and not re.match(r"[A-Za-z]:", normalized)
        and ".." not in path.parts
        and "." not in path.parts
        and "" not in path.parts
    )


def _canonical_archive_member(name: str) -> str:
    if not _safe_archive_member(name):
        raise GcloudCustodyError("official archive contains an unsafe member")
    normalized = name.replace("\\", "/").rstrip("/")
    if not normalized:
        raise GcloudCustodyError("official archive contains an unsafe member")
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        raise GcloudCustodyError("official archive member path is too long")
    parts = Path(normalized).parts
    if not parts or parts[0] != "google-cloud-sdk" or any(part in {"", ".", ".."} for part in parts):
        raise GcloudCustodyError("official archive contains an unsafe member")
    if len(parts) > MAX_DEPTH:
        raise GcloudCustodyError("official archive member exceeds the depth limit")
    return "/".join(parts)


def _validate_archive_symlink(member: str, target: str) -> None:
    if not target or "\\" in target or target.startswith("/") or re.match(r"[A-Za-z]:", target):
        raise GcloudCustodyError("official archive contains an unsafe symlink")
    resolved = list(Path(member).parts[:-1])
    for part in Path(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise GcloudCustodyError("official archive symlink escapes the SDK root")
            resolved.pop()
            continue
        resolved.append(part)
        if len(resolved) > MAX_DEPTH:
            raise GcloudCustodyError("official archive symlink exceeds the depth limit")
    if not resolved or resolved[0] != "google-cloud-sdk":
        raise GcloudCustodyError("official archive symlink escapes the SDK root")


def _ensure_safe_parents(output: Path, relative: str) -> None:
    current = output
    for part in Path(relative).parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        except OSError as exc:
            raise GcloudCustodyError("official archive traverses a non-directory parent") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise GcloudCustodyError("official archive traverses a non-directory parent")


class _BoundedReader(io.RawIOBase):
    """Count decompressed bytes and refuse bombs before large allocation."""

    def __init__(self, inner: Any, *, compressed_size: int) -> None:
        self._inner = inner
        self._compressed_size = compressed_size
        self._uncompressed = 0

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:  # noqa: A003
        remaining_agg = MAX_EXPANDED - self._uncompressed
        remaining_ratio = self._compressed_size * MAX_RATIO - self._uncompressed
        remaining = min(remaining_agg, remaining_ratio)
        if remaining <= 0:
            raise GcloudCustodyError("official archive compression ratio or expanded size exceeds the limit")
        if size is None or size < 0:
            want = min(1024 * 1024, remaining + 1)
        else:
            want = min(size, remaining + 1)
        chunk = self._inner.read(want)
        if not chunk:
            return b""
        self._uncompressed += len(chunk)
        if self._uncompressed > MAX_EXPANDED:
            raise GcloudCustodyError("official archive expanded size exceeds the aggregate limit")
        if self._compressed_size <= 0 or self._uncompressed > self._compressed_size * MAX_RATIO:
            raise GcloudCustodyError("official archive compression ratio exceeds the limit")
        return chunk


def _write_extracted_regular(path: Path, reader: Any, size: int, executable: bool) -> None:
    if size < 0 or size > MAX_MEMBER:
        raise GcloudCustodyError("official archive member size exceeds the limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        remaining = size
        while remaining:
            block = reader.read(min(1024 * 1024, remaining))
            if not block:
                raise GcloudCustodyError("official archive member could not be extracted exactly")
            remaining -= len(block)
            view = memoryview(block)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise GcloudCustodyError("official archive member could not be extracted exactly")
                view = view[written:]
        extra = reader.read(1)
        if extra:
            raise GcloudCustodyError("official archive member size is invalid")
        os.fchmod(fd, 0o700 if executable else 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def extract_official_archive_bytes(data: bytes, archive_name: str, output: Path) -> Path:
    """Safely extract already SHA-256-verified official archive bytes."""
    require_compatible_python()
    if not isinstance(data, (bytes, bytearray)) or len(data) < 22 or len(data) > MAX_ARCHIVE:
        raise GcloudCustodyError("official archive outer size is outside the accepted range")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        if archive_name.endswith(".tar.gz"):
            _extract_tar_gz(bytes(data), output)
        elif archive_name.endswith(".zip"):
            _extract_zip(bytes(data), output)
        else:
            raise GcloudCustodyError("Google Cloud CLI archive type is unsupported")
    except GcloudCustodyError:
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile, gzip.BadGzipFile, EOFError) as exc:
        raise GcloudCustodyError("official archive could not be extracted") from exc
    root = output / "google-cloud-sdk"
    try:
        info = root.lstat()
    except OSError as exc:
        raise GcloudCustodyError("official archive lacks the canonical SDK root") from exc
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise GcloudCustodyError("official archive lacks the canonical SDK root")
    return root


def _extract_tar_gz(data: bytes, output: Path) -> None:
    gzip_file = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")
    try:
        counted = _BoundedReader(gzip_file, compressed_size=len(data))
        with tarfile.open(fileobj=counted, mode="r|") as bundle:
            seen: set[str] = set()
            aggregate = 0
            members = 0
            for member in bundle:
                members += 1
                if members > MAX_MEMBERS:
                    raise GcloudCustodyError("official archive has too many members")
                relative = _canonical_archive_member(member.name)
                if relative in seen:
                    raise GcloudCustodyError("official archive contains duplicate members")
                seen.add(relative)
                if member.isdev() or member.isfifo() or member.islnk():
                    raise GcloudCustodyError("official archive contains an unsafe member")
                destination = output.joinpath(*Path(relative).parts)
                if member.isdir():
                    _ensure_safe_parents(output, relative + "/.keep")
                    try:
                        info = destination.lstat()
                    except FileNotFoundError:
                        destination.mkdir(mode=0o700)
                    else:
                        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                            raise GcloudCustodyError("official archive directory collides with another entry")
                    continue
                if member.issym():
                    _validate_archive_symlink(relative, member.linkname or "")
                    _ensure_safe_parents(output, relative)
                    if destination.exists() or destination.is_symlink():
                        raise GcloudCustodyError("official archive symlink collides with another entry")
                    os.symlink(member.linkname, destination)
                    continue
                if not member.isreg():
                    raise GcloudCustodyError("official archive contains an unsupported member type")
                if member.size < 0 or member.size > MAX_MEMBER:
                    raise GcloudCustodyError("official archive member size exceeds the limit")
                aggregate += member.size
                if aggregate > MAX_EXPANDED:
                    raise GcloudCustodyError("official archive expanded size exceeds the aggregate limit")
                source = bundle.extractfile(member)
                if source is None:
                    raise GcloudCustodyError("official archive member could not be extracted exactly")
                _ensure_safe_parents(output, relative)
                _write_extracted_regular(destination, source, member.size, bool(member.mode & 0o111))
    finally:
        gzip_file.close()


def _extract_zip(data: bytes, output: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        infos = bundle.infolist()
        if not infos or len(infos) > MAX_MEMBERS:
            raise GcloudCustodyError("official archive member count is outside the accepted range")
        seen: set[str] = set()
        aggregate = 0
        for info in infos:
            name = info.filename
            is_dir = name.endswith("/") or name.endswith("\\")
            relative = _canonical_archive_member(name)
            if relative in seen:
                raise GcloudCustodyError("official archive contains duplicate members")
            seen.add(relative)
            destination = output.joinpath(*Path(relative).parts)
            if is_dir:
                _ensure_safe_parents(output, relative + "/.keep")
                try:
                    existing = destination.lstat()
                except FileNotFoundError:
                    destination.mkdir(mode=0o700)
                else:
                    if stat.S_ISLNK(existing.st_mode) or not stat.S_ISDIR(existing.st_mode):
                        raise GcloudCustodyError("official archive directory collides with another entry")
                continue
            if info.file_size < 0 or info.file_size > MAX_MEMBER:
                raise GcloudCustodyError("official archive member size exceeds the limit")
            if info.compress_size == 0 and info.file_size:
                raise GcloudCustodyError("official archive member has an invalid compression ratio")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise GcloudCustodyError("official archive compression ratio exceeds the limit")
            aggregate += info.file_size
            if aggregate > MAX_EXPANDED:
                raise GcloudCustodyError("official archive expanded size exceeds the aggregate limit")
            _ensure_safe_parents(output, relative)
            with bundle.open(info, "r") as source:
                _write_extracted_regular(
                    destination,
                    source,
                    info.file_size,
                    bool(info.external_attr >> 16 & 0o111),
                )


def _exact_str(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        raise GcloudCustodyError(f"Google Cloud CLI {label} has the wrong type")
    return value


def _exact_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise GcloudCustodyError(f"Google Cloud CLI {label} has the wrong type")
    return value


def parse_google_cloud_cli_pin_document(raw: bytes) -> dict[str, Any]:
    """Parse already-authenticated pin bytes. This does not authorize a file path."""
    require_compatible_python()
    parsed = strict_json_bytes(raw, "toolchain pin manifest")
    if type(parsed) is not dict:
        raise GcloudCustodyError("Google Cloud CLI pin is missing")
    tools = parsed.get("tools")
    if type(tools) is not dict:
        raise GcloudCustodyError("Google Cloud CLI pin is missing")
    pin = tools.get("google_cloud_cli")
    if type(pin) is not dict or set(pin) != PIN_KEYS:
        raise GcloudCustodyError("Google Cloud CLI pin keys are not exact")
    version = pin["version"]
    names, hashes = pin["archive_name"], pin["archive_sha256"]
    if type(version) is not str or not SEMVER_RE.fullmatch(version):
        raise GcloudCustodyError("Google Cloud CLI version is not a stable semantic version")
    if type(pin["note"]) is not str or not pin["note"].strip():
        raise GcloudCustodyError("Google Cloud CLI pin note is invalid")
    if type(names) is not dict or set(names) != set(PLATFORMS):
        raise GcloudCustodyError("Google Cloud CLI archive-name platforms are incomplete")
    if type(hashes) is not dict or set(hashes) != set(PLATFORMS):
        raise GcloudCustodyError("Google Cloud CLI archive-hash platforms are incomplete")
    for key, (os_name, arch_name, suffix) in PLATFORMS.items():
        expected = f"google-cloud-cli-{version}-{os_name}-{arch_name}{suffix}"
        if type(names[key]) is not str or names[key] != expected:
            raise GcloudCustodyError(f"Google Cloud CLI archive filename is invalid for {key}")
        digest = hashes[key]
        if type(digest) is not str or not SHA_RE.fullmatch(digest) or digest == ZERO_SHA:
            raise GcloudCustodyError(f"Google Cloud CLI archive hash is invalid for {key}")
    return pin


def current_platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "amd64" if machine in {"x86_64", "amd64"} else ""
    key = f"{system}_{arch}"
    if key not in PLATFORMS:
        raise GcloudCustodyError("this platform has no reviewed Google Cloud CLI archive")
    return key


def _repository_tools_dir() -> Path:
    tools_dir = Path(__file__).resolve(strict=True).parent
    if tools_dir.name != "tools":
        raise GcloudCustodyError("Google Cloud CLI custody controller is not in the repository tools directory")
    return tools_dir


def _bind_repository_file(path: Path, *, max_size: int, label: str) -> bytes:
    if not path.is_absolute():
        raise GcloudCustodyError(f"{label} must be absolute")
    try:
        before = path.lstat()
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise GcloudCustodyError(f"{label} must be a regular single-link file")
    if before.st_uid not in {0, os.getuid()}:
        raise GcloudCustodyError(f"{label} is not owner-controlled")
    if before.st_size <= 0 or before.st_size > max_size:
        raise GcloudCustodyError(f"{label} size is outside the accepted range")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if _stat_identity(before) != _stat_identity(opened):
            raise GcloudCustodyError(f"{label} was replaced before it was opened")
        chunks: list[bytes] = []
        while block := os.read(fd, 1024 * 1024):
            chunks.append(block)
        finished = os.fstat(fd)
        if _stat_identity(opened) != _stat_identity(finished):
            raise GcloudCustodyError(f"{label} changed while it was read")
    finally:
        os.close(fd)
    after = path.lstat()
    if _stat_identity(finished) != _stat_identity(after):
        raise GcloudCustodyError(f"{label} was replaced after it was opened")
    data = b"".join(chunks)
    if not data:
        raise GcloudCustodyError(f"{label} snapshot is empty")
    return data


def _utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _parse_utc(value: str, label: str) -> datetime:
    if type(value) is not str or UTC_SECONDS_RE.fullmatch(value) is None:
        raise GcloudCustodyError(f"Google Cloud CLI {label} timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise GcloudCustodyError(f"Google Cloud CLI {label} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise GcloudCustodyError(f"Google Cloud CLI {label} timestamp is invalid")
    normalized = parsed.astimezone(timezone.utc)
    if normalized.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise GcloudCustodyError(f"Google Cloud CLI {label} timestamp is invalid")
    return normalized


def _require_fresh(created: datetime, label: str) -> None:
    now = datetime.now(timezone.utc)
    if created.year < 2026:
        raise GcloudCustodyError(f"Google Cloud CLI {label} is stale")
    if created > now + MAX_RECEIPT_CLOCK_SKEW or now - created > MAX_RECEIPT_AGE:
        raise GcloudCustodyError(f"Google Cloud CLI {label} is stale or future-dated")


def _require_authorization_window(issued: datetime, expires: datetime) -> None:
    _require_fresh(issued, "issued_utc")
    now = datetime.now(timezone.utc)
    if expires <= issued or expires - issued > MAX_RECEIPT_AGE:
        raise GcloudCustodyError("Google Cloud CLI owner issuance validity window is invalid")
    if expires < now - MAX_RECEIPT_CLOCK_SKEW:
        raise GcloudCustodyError("Google Cloud CLI owner issuance is expired")


def _path_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _bind_regular_file_with_identity_from_parent(
    path: Path, *, max_size: int, label: str
) -> tuple[bytes, tuple[int, ...]]:
    if not path.is_absolute():
        raise GcloudCustodyError(f"{label} must be absolute")
    parent = path.parent
    name = path.name
    if name in {"", ".", ".."} or "/" in name or "\\" in name:
        raise GcloudCustodyError(f"{label} name is unsafe")
    try:
        parent_before = parent.lstat()
        file_before = path.lstat()
    except OSError as exc:
        raise GcloudCustodyError(f"{label} is unreadable") from exc
    if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(parent_before.st_mode):
        raise GcloudCustodyError(f"{label} parent must be a real directory")
    if stat.S_ISLNK(file_before.st_mode) or not stat.S_ISREG(file_before.st_mode) or file_before.st_nlink != 1:
        raise GcloudCustodyError(f"{label} must be a regular single-link file")
    if file_before.st_size <= 0 or file_before.st_size > max_size:
        raise GcloudCustodyError(f"{label} size is outside the accepted range")
    parent_fd = os.open(parent, _DIR_FLAGS)
    try:
        parent_opened = os.fstat(parent_fd)
        if (parent_opened.st_dev, parent_opened.st_ino) != (parent_before.st_dev, parent_before.st_ino):
            raise GcloudCustodyError(f"{label} parent was replaced")
        data, identity = _stable_file_at_with_identity(parent_fd, name, label)
    finally:
        os.close(parent_fd)
    after = path.lstat()
    if _stat_identity(file_before) != _stat_identity(after):
        raise GcloudCustodyError(f"{label} was replaced after it was opened")
    if not data:
        raise GcloudCustodyError(f"{label} snapshot is empty")
    return data, identity


def _bind_regular_file_from_parent(path: Path, *, max_size: int, label: str) -> bytes:
    data, _identity = _bind_regular_file_with_identity_from_parent(
        path, max_size=max_size, label=label
    )
    return data


_ED25519_P = 2**255 - 19
_ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)


def _ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= _ED25519_P:
        return None
    xx = (y * y - 1) * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P)
    x = pow(xx % _ED25519_P, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = x * _ED25519_I % _ED25519_P
    if (x * x - xx) % _ED25519_P != 0 or (x == 0 and sign == 1):
        return None
    if x & 1 != sign:
        x = _ED25519_P - x
    return x


def _ed25519_decode_point(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    x = _ed25519_recover_x(y, value >> 255)
    if x is None:
        return None
    return (x, y, 1, x * y % _ED25519_P)


def _ed25519_add(
    left: tuple[int, int, int, int], right: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _ED25519_P
    b = (y1 + x1) * (y2 + x2) % _ED25519_P
    c = 2 * t1 * t2 * _ED25519_D % _ED25519_P
    d = 2 * z1 * z2 % _ED25519_P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    return (e * f % _ED25519_P, g * h % _ED25519_P, f * g % _ED25519_P, e * h % _ED25519_P)


def _ed25519_mul(point: tuple[int, int, int, int], scalar: int) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    current = point
    while scalar:
        if scalar & 1:
            result = _ed25519_add(result, current)
        current = _ed25519_add(current, current)
        scalar >>= 1
    return result


_ED25519_BASE_Y = 4 * pow(5, _ED25519_P - 2, _ED25519_P) % _ED25519_P
_ED25519_BASE_X = _ed25519_recover_x(_ED25519_BASE_Y, 0)
if _ED25519_BASE_X is None:
    raise RuntimeError("Ed25519 base point construction failed")
_ED25519_BASE = (
    _ED25519_BASE_X,
    _ED25519_BASE_Y,
    1,
    _ED25519_BASE_X * _ED25519_BASE_Y % _ED25519_P,
)


def _ed25519_equal(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    return (
        (left[0] * right[2] - right[0] * left[2]) % _ED25519_P == 0
        and (left[1] * right[2] - right[1] * left[2]) % _ED25519_P == 0
    )


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = _ed25519_decode_point(public_key)
    signature_point = _ed25519_decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    neutral = (0, 1, 1, 0)
    if public_point is None or signature_point is None or scalar >= _ED25519_L:
        return False
    if _ed25519_equal(public_point, neutral):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED25519_L
    return _ed25519_equal(
        _ed25519_mul(_ED25519_BASE, scalar),
        _ed25519_add(signature_point, _ed25519_mul(public_point, challenge)),
    )


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST) from exc


def _owner_receipt_message(receipt: dict[str, Any]) -> bytes:
    if type(receipt) is not dict or set(receipt) != SIGNED_RECEIPT_KEYS:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return OWNER_SIGNATURE_DOMAIN + _canonical_json_bytes(receipt)


def _parse_owner_authority(data: bytes, expected_owner_uid: int = 0) -> tuple[str, bytes]:
    parsed = strict_json_bytes(data, "Google Cloud CLI owner authority")
    if type(parsed) is not dict or set(parsed) != set(OWNER_AUTHORITY_KEYS):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if (
        _exact_int(parsed["schema_version"], "owner authority schema_version") != 1
        or _exact_str(parsed["contract"], "owner authority contract") != OWNER_AUTHORITY_CONTRACT
        or _exact_str(parsed["algorithm"], "owner authority algorithm") != OWNER_SIGNATURE_ALGORITHM
        or _exact_int(parsed["owner_uid"], "owner authority owner_uid") != expected_owner_uid
    ):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    key_id = _exact_str(parsed["key_id"], "owner authority key_id")
    public_key_hex = _exact_str(parsed["public_key"], "owner authority public_key")
    if ED25519_PUBLIC_KEY_RE.fullmatch(public_key_hex) is None:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    public_key = bytes.fromhex(public_key_hex)
    if key_id != hashlib.sha256(public_key).hexdigest():
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return key_id, public_key


def _validate_signed_receipt_authorization(
    receipt: Any, *, require_fresh: bool = True
) -> dict[str, Any]:
    if type(receipt) is not dict or set(receipt) != SIGNED_RECEIPT_KEYS:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if _exact_int(receipt["schema_version"], "owner receipt schema_version") != 1:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if _exact_str(receipt["contract"], "owner receipt contract") != RECEIPT_CONTRACT:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    issued = _parse_utc(_exact_str(receipt["issued_utc"], "issued_utc"), "issued_utc")
    expires = _parse_utc(_exact_str(receipt["expires_utc"], "expires_utc"), "expires_utc")
    if require_fresh:
        _require_authorization_window(issued, expires)
    elif (
        issued.year < 2026
        or expires <= issued
        or expires - issued > MAX_RECEIPT_AGE
    ):
        raise GcloudCustodyError(
            "Google Cloud CLI durable receipt authorization window is invalid"
        )
    if ISSUANCE_ID_RE.fullmatch(_exact_str(receipt["issuance_id"], "issuance_id")) is None:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if SHA_RE.fullmatch(_exact_str(receipt["install_root_sha256"], "install_root_sha256")) is None:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if SHA_RE.fullmatch(_exact_str(receipt["authority_key_id"], "authority_key_id")) is None:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    for key in ("controller_sha256", "manifest_sha256", "trust_anchor_sha256"):
        digest = _exact_str(receipt[key], key)
        if SHA_RE.fullmatch(digest) is None or digest == ZERO_SHA:
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return receipt


def _require_same_release_authorization(
    durable: dict[str, Any], fresh: dict[str, Any]
) -> None:
    """Bind a refreshable external issuance to one immutable runtime receipt."""
    if type(fresh) is not dict or set(fresh) != SIGNED_RECEIPT_KEYS:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    for key in SIGNED_RECEIPT_KEYS - DURABLE_RECEIPT_VOLATILE_KEYS:
        if durable.get(key) != fresh.get(key):
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)


def _parse_owner_issuance(
    data: bytes, *, authority_key_id: str, public_key: bytes
) -> dict[str, Any]:
    parsed = strict_json_bytes(data, "Google Cloud CLI owner issuance")
    if type(parsed) is not dict or set(parsed) != set(OWNER_ISSUANCE_KEYS):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if (
        _exact_str(parsed["contract"], "owner issuance contract") != OWNER_ISSUANCE_CONTRACT
        or _exact_int(parsed["schema_version"], "owner issuance schema_version") != 1
        or _exact_str(parsed["issuer"], "owner issuance issuer") != OWNER_ISSUANCE_ISSUER
        or _exact_str(parsed["algorithm"], "owner issuance algorithm") != OWNER_SIGNATURE_ALGORITHM
        or _exact_str(parsed["key_id"], "owner issuance key_id") != authority_key_id
    ):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    receipt = _validate_signed_receipt_authorization(parsed["receipt"])
    if receipt["authority_key_id"] != authority_key_id:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    signature_hex = _exact_str(parsed["signature"], "owner issuance signature")
    if ED25519_SIGNATURE_RE.fullmatch(signature_hex) is None:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if not _verify_ed25519(public_key, _owner_receipt_message(receipt), bytes.fromhex(signature_hex)):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return parsed


def bind_owner_issuance_for_tests(path: Path) -> dict[str, Any]:
    """Test helper that still enforces genuinely external owner semantics."""
    return _bind_owner_issuance(Path(path))


def _bind_external_authority_file(
    path: Path, *, max_size: int, label: str, owner_uid: int
) -> bytes:
    if not path.is_absolute():
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST) from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if info.st_uid != owner_uid or stat.S_IMODE(info.st_mode) & 0o222:
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    for ancestor in (resolved.parent, *resolved.parents[1:]):
        ancestor_info = ancestor.lstat()
        if (
            not stat.S_ISDIR(ancestor_info.st_mode)
            or ancestor_info.st_uid not in {0, owner_uid}
            or stat.S_IMODE(ancestor_info.st_mode) & 0o022
        ):
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return _bind_regular_file_from_parent(resolved, max_size=max_size, label=label)


def _bind_owner_issuance(
    path: Path,
    *,
    repo: Path | None = None,
    authority_path: Path = OWNER_AUTHORITY_PATH,
    owner_uid: int = 0,
) -> dict[str, Any]:
    if repo is not None and (_path_inside(path, repo) or _path_inside(authority_path, repo)):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    if owner_uid == os.geteuid():
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    authority_data = _bind_external_authority_file(
        authority_path,
        max_size=MAX_ISSUANCE,
        label="Google Cloud CLI owner authority",
        owner_uid=owner_uid,
    )
    key_id, public_key = _parse_owner_authority(authority_data, owner_uid)
    issuance_data = _bind_external_authority_file(
        path,
        max_size=MAX_ISSUANCE,
        label="Google Cloud CLI owner issuance",
        owner_uid=owner_uid,
    )
    return _parse_owner_issuance(
        issuance_data, authority_key_id=key_id, public_key=public_key
    )


def _parse_trust_anchor(data: bytes) -> dict[str, Any]:
    parsed = strict_json_bytes(data, "Google Cloud CLI custody trust-anchor")
    if type(parsed) is not dict or set(parsed) != set(TRUST_KEYS):
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor keys are not exact")
    if _exact_str(parsed["contract"], "trust-anchor contract") != TRUST_CONTRACT:
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor contract mismatch")
    if _exact_int(parsed["schema_version"], "trust-anchor schema_version") != 3:
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor schema_version mismatch")
    if _exact_str(parsed["controller"], "trust-anchor controller") != f"tools/{CONTROLLER_NAME}":
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor controller path mismatch")
    if _exact_str(parsed["manifest"], "trust-anchor manifest") != f"tools/{MANIFEST_NAME}":
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor manifest path mismatch")
    if _exact_str(parsed["trust_anchor"], "trust-anchor path") != f"tools/{TRUST_ANCHOR_NAME}":
        raise GcloudCustodyError("Google Cloud CLI custody trust-anchor path mismatch")
    if _exact_str(parsed["python_custody"], "trust-anchor Python custody") != f"tools/{PYTHON_CUSTODY_NAME}":
        raise GcloudCustodyError("Google Cloud CLI custody Python custody path mismatch")
    for key in ("controller_sha256", "manifest_sha256", "python_custody_sha256"):
        digest = _exact_str(parsed[key], f"trust-anchor {key}")
        if not SHA_RE.fullmatch(digest) or digest == ZERO_SHA:
            raise GcloudCustodyError(f"Google Cloud CLI custody trust-anchor {key} is invalid")
    if (
        _exact_str(parsed["component_contract"], "trust-anchor component contract")
        != TRUST_COMPONENT_CONTRACT
    ):
        raise GcloudCustodyError("Google Cloud CLI custody component contract mismatch")
    components = parsed["components"]
    if type(components) is not list or len(components) != len(TRUST_COMPONENTS):
        raise GcloudCustodyError("Google Cloud CLI custody component inventory is not exact")
    for observed, (expected_kind, expected_path) in zip(
        components, TRUST_COMPONENTS, strict=True
    ):
        if type(observed) is not dict or set(observed) != set(TRUST_COMPONENT_KEYS):
            raise GcloudCustodyError("Google Cloud CLI custody component keys are not exact")
        if _exact_str(observed["kind"], "trust-anchor component kind") != expected_kind:
            raise GcloudCustodyError("Google Cloud CLI custody component kind mismatch")
        if _exact_str(observed["path"], "trust-anchor component path") != expected_path:
            raise GcloudCustodyError("Google Cloud CLI custody component path mismatch")
        digest = _exact_str(observed["sha256"], "trust-anchor component sha256")
        if SHA_RE.fullmatch(digest) is None or digest == ZERO_SHA:
            raise GcloudCustodyError("Google Cloud CLI custody component digest is invalid")
    return parsed


def _verify_trust_anchor_components(
    repo: Path, trust: dict[str, Any], *, require_artifacts: bool = False
) -> None:
    for component in trust["components"]:
        relative = Path(component["path"])
        selected = repo.joinpath(*relative.parts)
        if component["kind"] == "artifact" and not require_artifacts:
            continue
        if component["kind"] == "artifact" and not selected.exists() and not selected.is_symlink():
            raise GcloudCustodyError("owner blocker: reviewed GCP custody artifact is absent")
        current = selected.parent
        while current != repo:
            try:
                info = current.lstat()
            except OSError as exc:
                raise GcloudCustodyError(OWNER_BLOCKED_TRUST) from exc
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
            parent = current.parent
            if parent == current or not _path_inside(parent, repo):
                raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
            current = parent
        data = _bind_regular_file_from_parent(
            selected,
            max_size=MAX_CONTROLLER * 32,
            label=f"Google Cloud CLI custody component {component['path']}",
        )
        if hashlib.sha256(data).hexdigest() != component["sha256"]:
            if component["kind"] == "artifact":
                raise GcloudCustodyError(
                    "owner blocker: reviewed GCP custody artifact is stale"
                )
            raise GcloudCustodyError("Google Cloud CLI custody component digest mismatch")


def _authorize_repository_google_cloud_cli_pin_with_issuance(
    pin_manifest: Path | None = None,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    """Bind the in-repo pin through a genuinely external owner issuance identity."""
    require_compatible_python()
    tools_dir = _repository_tools_dir()
    repo = tools_dir.parent
    expected_controller = tools_dir / CONTROLLER_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    expected_trust = tools_dir / TRUST_ANCHOR_NAME
    expected_python_custody = tools_dir / PYTHON_CUSTODY_NAME
    if pin_manifest is not None:
        caller = Path(pin_manifest)
        try:
            caller_resolved = caller.resolve(strict=True)
            expected_resolved = expected_manifest.resolve(strict=True)
            caller_info = caller.lstat()
            expected_info = expected_manifest.lstat()
        except OSError as suc:
            raise GcloudCustodyError(SYNTHETIC_PIN) from suc
        if caller_resolved != expected_resolved:
            raise GcloudCustodyError(SYNTHETIC_PIN)
        if (caller_info.st_dev, caller_info.st_ino) != (expected_info.st_dev, expected_info.st_ino):
            raise GcloudCustodyError(SYNTHETIC_PIN)
    controller_data = _bind_regular_file_from_parent(
        expected_controller, max_size=MAX_CONTROLLER, label="Google Cloud CLI custody controller"
    )
    manifest_data = _bind_regular_file_from_parent(
        expected_manifest, max_size=MAX_MANIFEST, label="Google Cloud CLI pin manifest"
    )
    trust_data = _bind_regular_file_from_parent(
        expected_trust, max_size=MAX_TRUST, label="Google Cloud CLI custody trust-anchor"
    )
    python_custody_data = _bind_regular_file_from_parent(
        expected_python_custody,
        max_size=MAX_CONTROLLER,
        label="Google Cloud CLI release Python custody verifier",
    )
    trust = _parse_trust_anchor(trust_data)
    _verify_trust_anchor_components(repo, trust)
    controller_sha = hashlib.sha256(controller_data).hexdigest()
    manifest_sha = hashlib.sha256(manifest_data).hexdigest()
    trust_sha = hashlib.sha256(trust_data).hexdigest()
    python_custody_sha = hashlib.sha256(python_custody_data).hexdigest()
    if controller_sha != trust["controller_sha256"]:
        raise GcloudCustodyError("Google Cloud CLI custody controller digest does not match the trust-anchor")
    if manifest_sha != trust["manifest_sha256"]:
        raise GcloudCustodyError("Google Cloud CLI pin manifest digest does not match the trust-anchor")
    if python_custody_sha != trust["python_custody_sha256"]:
        raise GcloudCustodyError("Google Cloud CLI release Python custody digest does not match the trust-anchor")
    issuance = _bind_owner_issuance(OWNER_ISSUANCE_PATH, repo=repo)
    authorized_receipt = issuance["receipt"]
    if (
        authorized_receipt["controller_sha256"] != controller_sha
        or authorized_receipt["manifest_sha256"] != manifest_sha
        or authorized_receipt["trust_anchor_sha256"] != trust_sha
    ):
        raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return (
        expected_manifest,
        parse_google_cloud_cli_pin_document(manifest_data),
        issuance,
    )


def authorize_repository_google_cloud_cli_pin(
    pin_manifest: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    manifest, pin, _issuance = (
        _authorize_repository_google_cloud_cli_pin_with_issuance(pin_manifest)
    )
    return manifest, pin


def validate_google_cloud_cli_pin(manifest_path: Path) -> dict[str, Any]:
    """Production pin bind. Caller-authored synthetic pin files never self-authorize."""
    _manifest, pin = authorize_repository_google_cloud_cli_pin(Path(manifest_path))
    return pin


def install_tree_sha256(root: Path) -> str:
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    entries: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        dirnames.sort()
        filenames.sort()
        entries.extend(base / name for name in dirnames if (base / name).is_symlink())
        for name in filenames:
            if name == RECEIPT_NAME:
                if base != root:
                    raise GcloudCustodyError(
                        "nested Google Cloud CLI custody receipt is forbidden"
                    )
                continue
            entries.append(base / name)
    for path in sorted(entries, key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            payload = target.encode("utf-8")
            kind = b"L"
        elif stat.S_ISREG(info.st_mode):
            payload = _stable_file(path, f"Google Cloud CLI tree file {relative}")
            kind = b"F"
        else:
            raise GcloudCustodyError(f"unsupported Google Cloud CLI tree entry {relative!r}")
        digest.update(kind + b"\0" + relative.encode("utf-8") + b"\0")
        digest.update(str(len(payload)).encode("ascii") + b"\0" + hashlib.sha256(payload).digest())
    return digest.hexdigest()


def install_tree_sha256_from_fd(root_fd: int) -> str:
    """Hash the held runtime inode so a swapped pathname cannot become authoritative."""
    entries: list[tuple[str, bytes, int, bytes]] = []

    def walk(dir_fd: int, relative: str) -> None:
        try:
            names = os.listdir(dir_fd)
        except OSError as exc:
            raise GcloudCustodyError("private Google Cloud CLI snapshot is unreadable") from exc
        for name in names:
            if name in {".", ".."}:
                continue
            if name == RECEIPT_NAME:
                if relative:
                    raise GcloudCustodyError(
                        "nested Google Cloud CLI custody receipt is forbidden"
                    )
                continue
            child_relative = name if not relative else f"{relative}/{name}"
            try:
                info = os.lstat(name, dir_fd=dir_fd)
            except OSError as exc:
                raise GcloudCustodyError("private Google Cloud CLI snapshot is unreadable") from exc
            if stat.S_ISLNK(info.st_mode):
                try:
                    target = os.readlink(name, dir_fd=dir_fd)
                except OSError as exc:
                    raise GcloudCustodyError("private Google Cloud CLI snapshot is unreadable") from exc
                payload = target.encode("utf-8")
                entries.append(
                    (child_relative, b"L", len(payload), hashlib.sha256(payload).digest())
                )
            elif stat.S_ISDIR(info.st_mode):
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
                try:
                    walk(child_fd, child_relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                payload = _stable_file_at(dir_fd, name, f"Google Cloud CLI tree file {child_relative}")
                entries.append(
                    (child_relative, b"F", len(payload), hashlib.sha256(payload).digest())
                )
            else:
                raise GcloudCustodyError(f"unsupported Google Cloud CLI tree entry {child_relative!r}")

    walk(root_fd, "")
    digest = hashlib.sha256()
    for relative, kind, size, payload_sha256 in sorted(
        entries, key=lambda item: item[0].encode("utf-8")
    ):
        digest.update(kind + b"\0" + relative.encode("utf-8") + b"\0")
        digest.update(str(size).encode("ascii") + b"\0" + payload_sha256)
    return digest.hexdigest()


def _validate_snapshot_symlink(parts: tuple[str, ...], target: str) -> None:
    if not target or "\\" in target or target.startswith("/") or re.match(r"[A-Za-z]:", target):
        raise GcloudCustodyError("private Google Cloud CLI runtime contains an unsafe symlink")
    resolved = list(parts[:-1])
    for part in Path(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                raise GcloudCustodyError("private Google Cloud CLI runtime symlink escapes the SDK root")
            resolved.pop()
            continue
        resolved.append(part)
        if len(resolved) > MAX_DEPTH:
            raise GcloudCustodyError("private Google Cloud CLI runtime exceeds the depth limit")


def _snapshot_tree(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise GcloudCustodyError("private Google Cloud CLI snapshot destination already exists")
    src_fd = os.open(source, _DIR_FLAGS)
    try:
        info = os.fstat(src_fd)
        if not stat.S_ISDIR(info.st_mode):
            raise GcloudCustodyError("Google Cloud CLI runtime root must be a directory")
        _snapshot_dir(src_fd, destination, ())
    finally:
        os.close(src_fd)


def _snapshot_dir(src_fd: int, dest: Path, relative_parts: tuple[str, ...]) -> None:
    if len(relative_parts) > MAX_DEPTH:
        raise GcloudCustodyError("private Google Cloud CLI runtime exceeds the depth limit")
    dest.mkdir(mode=0o700, exist_ok=False)
    try:
        names = sorted(os.listdir(src_fd))
    except OSError as exc:
        raise GcloudCustodyError("private Google Cloud CLI runtime is unreadable") from exc
    for name in names:
        if name in {".", "..", RECEIPT_NAME}:
            continue
        if name in {"", ".", ".."} or "/" in name or "\\" in name:
            raise GcloudCustodyError("private Google Cloud CLI runtime contains an unsafe name")
        try:
            info = os.lstat(name, dir_fd=src_fd)
        except OSError as exc:
            raise GcloudCustodyError("private Google Cloud CLI runtime is unreadable") from exc
        child = dest / name
        child_parts = relative_parts + (name,)
        if stat.S_ISLNK(info.st_mode):
            try:
                target = os.readlink(name, dir_fd=src_fd)
            except OSError as exc:
                raise GcloudCustodyError("private Google Cloud CLI runtime is unreadable") from exc
            _validate_snapshot_symlink(child_parts, target)
            os.symlink(target, child)
        elif stat.S_ISDIR(info.st_mode):
            child_fd = os.open(name, _DIR_FLAGS, dir_fd=src_fd)
            try:
                _snapshot_dir(child_fd, child, child_parts)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(info.st_mode):
            payload = _stable_file_at(
                src_fd,
                name,
                "Google Cloud CLI runtime file " + "/".join(child_parts),
            )
            mode = 0o700 if info.st_mode & 0o111 else 0o600
            _write_exclusive(child, payload, mode)
        else:
            raise GcloudCustodyError("private Google Cloud CLI runtime contains an unsupported entry")


def authenticate_credential(credential: GcloudCredentialInput) -> AuthenticatedCredential:
    """Bind one descriptor-authenticated identity document. Never emit key material."""
    require_compatible_python()
    if not isinstance(credential, GcloudCredentialInput):
        raise GcloudCustodyError(MISSING_IDENTITY)
    if credential.kind not in {SERVICE_ACCOUNT_KIND, WORKLOAD_IDENTITY_KIND}:
        raise GcloudCustodyError("Google Cloud CLI credential kind is unsupported")
    if not ACCOUNT_RE.fullmatch(credential.expected_account):
        raise GcloudCustodyError("Google Cloud CLI bound account is invalid")
    if not PROJECT_RE.fullmatch(credential.expected_project):
        raise GcloudCustodyError("Google Cloud CLI bound project is invalid")
    path = credential.path
    if not path.is_absolute():
        raise GcloudCustodyError("Google Cloud CLI credential path must be absolute")
    data, identity = _bind_regular_file_with_identity_from_parent(
        path, max_size=MAX_CREDENTIAL, label="Google Cloud CLI credential"
    )
    if identity[-1] != 0o400:
        raise GcloudCustodyError("Google Cloud CLI credential must be immutable mode 0400")
    if not data or len(data) > MAX_CREDENTIAL:
        raise GcloudCustodyError("Google Cloud CLI credential size is outside the accepted range")
    parsed = strict_json_bytes(data, "Google Cloud CLI credential")
    if type(parsed) is not dict:
        raise GcloudCustodyError("Google Cloud CLI credential is invalid")
    subject_token: bytes | None = None
    try:
        if credential.kind == SERVICE_ACCOUNT_KIND:
            if set(parsed) != SA_CREDENTIAL_KEYS or parsed.get("type") != "service_account":
                raise GcloudCustodyError("Google Cloud CLI credential keys are not exact")
            account = parsed.get("client_email")
            project = parsed.get("project_id")
            private_key = parsed.get("private_key")
            private_key_id = parsed.get("private_key_id")
            client_id = parsed.get("client_id")
            if type(private_key) is not str or not SA_PRIVATE_KEY_RE.fullmatch(private_key):
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            if type(private_key_id) is not str or not SA_PRIVATE_KEY_ID_RE.fullmatch(private_key_id):
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            if type(client_id) is not str or not SA_CLIENT_ID_RE.fullmatch(client_id):
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            if parsed.get("auth_uri") != SA_AUTH_URI or parsed.get("token_uri") != SA_TOKEN_URI:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
        else:
            if set(parsed) != WIF_CREDENTIAL_KEYS or parsed.get("type") != "external_account":
                raise GcloudCustodyError("Google Cloud CLI credential keys are not exact")
            if parsed.get("token_url") != WIF_TOKEN_URL:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            if parsed.get("subject_token_type") != WIF_SUBJECT_TOKEN_TYPE:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            audience = parsed.get("audience")
            if type(audience) is not str or not WIF_AUDIENCE_RE.fullmatch(audience):
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            url = parsed.get("service_account_impersonation_url")
            if type(url) is not str:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            matched = WIF_EMAIL_RE.fullmatch(url)
            if matched is None:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            account = matched.group(1)
            project = credential.expected_project
            source = parsed.get("credential_source")
            if type(source) is not dict or set(source) != WIF_CREDENTIAL_SOURCE_KEYS:
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            source_file = source.get("file")
            if (
                type(source_file) is not str
                or not source_file.startswith("/")
                or ".." in Path(source_file).parts
                or "\\" in source_file
            ):
                raise GcloudCustodyError("Google Cloud CLI credential is invalid")
            source_path = Path(source_file)
            subject_token, source_identity = _bind_regular_file_with_identity_from_parent(
                source_path,
                max_size=MAX_SUBJECT_TOKEN,
                label="Google Cloud CLI workload identity subject token",
            )
            if source_identity[-1] != 0o400:
                raise GcloudCustodyError(
                    "Google Cloud CLI workload identity subject token must be immutable mode 0400"
                )
            if not subject_token or b"\x00" in subject_token:
                raise GcloudCustodyError(
                    "Google Cloud CLI workload identity subject token is invalid"
                )
        if type(account) is not str or type(project) is not str:
            raise GcloudCustodyError("Google Cloud CLI credential is invalid")
        if account != credential.expected_account or project != credential.expected_project:
            raise GcloudCustodyError("Google Cloud CLI credential identity does not match the bound identity")
    except GcloudCustodyError:
        raise
    except Exception as suc:
        raise GcloudCustodyError("Google Cloud CLI credential is invalid") from suc
    return AuthenticatedCredential(data=data, subject_token=subject_token)


def _credential_snapshot_bytes(
    authenticated: AuthenticatedCredential, subject_token_file: Path | None
) -> bytes:
    if authenticated.subject_token is None:
        if subject_token_file is not None:
            raise GcloudCustodyError("Google Cloud CLI credential snapshot is invalid")
        return authenticated.data
    if subject_token_file is None or not subject_token_file.is_absolute():
        raise GcloudCustodyError("Google Cloud CLI workload identity token snapshot is missing")
    parsed = strict_json_bytes(authenticated.data, "Google Cloud CLI credential")
    if type(parsed) is not dict or set(parsed) != WIF_CREDENTIAL_KEYS:
        raise GcloudCustodyError("Google Cloud CLI credential keys are not exact")
    parsed["credential_source"] = {"file": str(subject_token_file)}
    return _canonical_json_bytes(parsed) + b"\n"


def require_bound_project(credential: GcloudCredentialInput, expected_project: str) -> None:
    """Bind one plan/project to the authenticated credential. Never emit project values."""
    if not isinstance(credential, GcloudCredentialInput):
        raise GcloudCustodyError(MISSING_IDENTITY)
    if type(expected_project) is not str or not PROJECT_RE.fullmatch(expected_project):
        raise GcloudCustodyError("Google Cloud CLI bound project is invalid")
    if credential.expected_project != expected_project:
        raise GcloudCustodyError(
            "Google Cloud CLI credential project does not match the bound plan project"
        )

def _authenticated_macos_release_python(manifest: Path) -> AuthenticatedPython:
    tools_dir = _repository_tools_dir()
    repo = tools_dir.parent
    verifier_path = tools_dir / PYTHON_CUSTODY_NAME
    trust_path = tools_dir / TRUST_ANCHOR_NAME
    trust_data = _bind_regular_file_from_parent(
        trust_path,
        max_size=MAX_TRUST,
        label="Google Cloud CLI custody trust-anchor",
    )
    trust = _parse_trust_anchor(trust_data)
    verifier_data = _bind_regular_file_from_parent(
        verifier_path,
        max_size=MAX_CONTROLLER,
        label="Google Cloud CLI release Python custody verifier",
    )
    if hashlib.sha256(verifier_data).hexdigest() != trust["python_custody_sha256"]:
        raise GcloudCustodyError(
            "owner blocker: release Python custody verifier does not match the authenticated trust anchor"
        )
    try:
        source = verifier_data.decode("ascii")
        module = types.ModuleType("_winsvpn_authenticated_release_python_custody")
        module.__file__ = str(verifier_path)
        module.__package__ = ""
        exec(compile(source, str(verifier_path), "exec"), module.__dict__)
        authenticate = getattr(module, "authenticate")
        record = authenticate(repo, manifest, required_uid=0)
    except Exception as exc:
        raise GcloudCustodyError(
            "owner blocker: authenticated macOS release Python runtime is unavailable"
        ) from exc
    expected_keys = {
        "RUNTIME", "RUNTIME_ID", "BIN", "BIN_SHA256", "VENDOR",
        "VENDOR_SHA256", "VENDOR_ID", "VENDOR_DIR_ID", "LAUNCHER",
        "LAUNCHER_SHA256", "LAUNCHER_ID", "LAUNCHER_DIR_ID", "FRAMEWORK",
        "FRAMEWORK_SHA256", "FRAMEWORK_ID", "FRAMEWORK_DIR_ID", "OWNER_COMMAND",
    }
    if type(record) is not dict or set(record) != expected_keys:
        raise GcloudCustodyError(
            "owner blocker: authenticated macOS release Python custody result is invalid"
        )
    selected = Path(sys.executable).resolve(strict=True)
    reviewed = Path(_exact_str(record["BIN"], "release Python executable")).resolve(strict=True)
    reviewed_sha = _exact_str(record["BIN_SHA256"], "release Python executable sha256")
    if selected != reviewed or not SHA_RE.fullmatch(reviewed_sha) or reviewed_sha == ZERO_SHA:
        raise GcloudCustodyError(
            "owner blocker: controller is not running from the authenticated macOS release Python runtime"
        )
    python_data = _bind_regular_file_from_parent(
        selected,
        max_size=MAX_CONTROLLER * 16,
        label="authenticated macOS release Python executable",
    )
    observed_sha = hashlib.sha256(python_data).hexdigest()
    if observed_sha != reviewed_sha:
        raise GcloudCustodyError(
            "owner blocker: running macOS release Python bytes changed after custody authentication"
        )
    return AuthenticatedPython(path=selected, data=python_data, sha256=observed_sha)


def _controller_python(manifest: Path, *, production: bool = False) -> AuthenticatedPython:
    require_compatible_python()
    if production and sys.platform == "darwin":
        return _authenticated_macos_release_python(manifest)
    if production and sys.platform.startswith("linux"):
        raise GcloudCustodyError(
            "owner blocker: Linux production must use the bundled Python inside the sealed Google Cloud CLI tree"
        )
    manifest_data = _bind_regular_file_from_parent(
        manifest.resolve(strict=True),
        max_size=MAX_MANIFEST,
        label="Google Cloud CLI Python pin manifest",
    )
    parsed = strict_json_bytes(manifest_data, "Google Cloud CLI Python pin manifest")
    try:
        python_pin = parsed["tools"]["python"]
        platform_key = current_platform_key()
        version = _exact_str(python_pin["version"], "Python version")
        implementation = _exact_str(python_pin["implementation"], "Python implementation")
        reviewed_path = Path(
            _exact_str(
                python_pin["reviewed_executable_path"][platform_key],
                "Python reviewed executable path",
            )
        )
        reviewed_sha = _exact_str(
            python_pin["executable_sha256"][platform_key], "Python executable_sha256"
        )
    except (KeyError, TypeError, GcloudCustodyError) as exc:
        raise GcloudCustodyError(
            "owner blocker: reviewed Python interpreter custody is unavailable"
        ) from exc
    selected = Path(sys.executable).resolve(strict=True)
    if (
        implementation != "cpython"
        or version != platform.python_version()
        or not reviewed_path.is_absolute()
        or reviewed_path.resolve(strict=True) != selected
        or SHA_RE.fullmatch(reviewed_sha) is None
        or reviewed_sha == ZERO_SHA
    ):
        raise GcloudCustodyError(
            "owner blocker: running Python does not match the reviewed manifest identity"
        )
    python_data = _bind_regular_file_from_parent(
        selected,
        max_size=MAX_CONTROLLER * 16,
        label="reviewed Python executable",
    )
    observed_sha = hashlib.sha256(python_data).hexdigest()
    if observed_sha != reviewed_sha:
        raise GcloudCustodyError(
            "owner blocker: running Python bytes do not match the reviewed manifest digest"
        )
    return AuthenticatedPython(path=selected, data=python_data, sha256=observed_sha)


def _isolated_environment(
    *,
    home: Path,
    config: Path,
    tmp: Path,
    credential_file: Path,
    python: Path,
    project: str,
    root: Path,
) -> dict[str, str]:
    if not PROJECT_RE.fullmatch(project):
        raise GcloudCustodyError("Google Cloud CLI bound project is invalid")
    python_dir = str(python.parent)
    return {
        "HOME": str(home),
        "TMPDIR": str(tmp),
        "TMP": str(tmp),
        "TEMP": str(tmp),
        "PATH": f"{python_dir}:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "CLOUDSDK_CONFIG": str(config),
        "CLOUDSDK_ROOT_DIR": str(root),
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "CLOUDSDK_CORE_PROJECT": project,
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": str(credential_file),
        "CLOUDSDK_PYTHON": str(python),
        "CLOUDSDK_PYTHON_SITEPACKAGES": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def credential_bearing_environment_name(name: str) -> bool:
    upper = name.upper()
    if upper in CREDENTIAL_ENV_EXACT or upper in INJECTION_ENV_EXACT:
        return True
    if any(upper.startswith(prefix) for prefix in CREDENTIAL_ENV_PREFIXES):
        return True
    return any(marker in upper for marker in CREDENTIAL_ENV_MARKERS)


@contextmanager
def sanitized_delegated_environment() -> Iterator[None]:
    """Strip credential-bearing process environment around a non-gcloud delegate."""
    original = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="winsvpn-gcloud-delegate-") as isolated_home:
        try:
            os.chmod(isolated_home, 0o700)
            for name in list(os.environ):
                if credential_bearing_environment_name(name):
                    del os.environ[name]
            os.environ["HOME"] = isolated_home
            os.environ["TMPDIR"] = isolated_home
            os.environ["TMP"] = isolated_home
            os.environ["TEMP"] = isolated_home
            os.environ["CLOUDSDK_CONFIG"] = isolated_home
            yield
        finally:
            os.environ.clear()
            os.environ.update(original)


class _CStringArray:
    def __init__(self, values: list[str]) -> None:
        encoded = [value.encode("utf-8") for value in values]
        array_values = (ctypes.c_char_p * (len(encoded) + 1))()
        for index, item in enumerate(encoded):
            array_values[index] = item
        array_values[len(encoded)] = None
        self._encoded = encoded
        self.array = array_values


def _posix_errno(rc: int, what: str) -> OSError:
    return OSError(rc, f"{what}: {os.strerror(rc)}")


def _must(rc: int, what: str) -> None:
    if rc:
        raise _posix_errno(rc if rc > 0 else ctypes.get_errno() or rc, what)


def _posix_spawn(
    path: str,
    argv: list[str],
    env: dict[str, str],
    *,
    root_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    inherited_fds: tuple[tuple[int, int], ...] = (),
) -> int:
    if _LIBC is None or sys.platform != "darwin":
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if root_fd < 0 or stdout_fd < 0 or stderr_fd < 0:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    targets: set[int] = set()
    for source_fd, target_fd in inherited_fds:
        if (
            type(source_fd) is not int
            or source_fd < 0
            or type(target_fd) is not int
            or target_fd < 3
            or target_fd in targets
        ):
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        targets.add(target_fd)
    if not hasattr(_LIBC, "posix_spawn_file_actions_addfchdir_np"):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if not hasattr(_LIBC, "posix_spawn_file_actions_adddup2"):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or ".." in path.split("/")
        or path in {".", ".."}
    ):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    _must(_LIBC.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
    try:
        _must(
            _LIBC.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT),
            ),
            "posix_spawnattr_setflags",
        )
        _must(_LIBC.posix_spawn_file_actions_init(ctypes.byref(actions)), "posix_spawn_file_actions_init")
        try:
            _must(
                _LIBC.posix_spawn_file_actions_addfchdir_np(ctypes.byref(actions), int(root_fd)),
                "posix_spawn_file_actions_addfchdir_np",
            )
            _must(
                _LIBC.posix_spawn_file_actions_addopen(
                    ctypes.byref(actions), 0, b"/dev/null", os.O_RDONLY, 0
                ),
                "posix_spawn_file_actions_addopen stdin",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(
                    ctypes.byref(actions), int(stdout_fd), 1
                ),
                "posix_spawn_file_actions_adddup2 stdout",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(
                    ctypes.byref(actions), int(stderr_fd), 2
                ),
                "posix_spawn_file_actions_adddup2 stderr",
            )
            for source_fd, target_fd in inherited_fds:
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(
                        ctypes.byref(actions), int(source_fd), int(target_fd)
                    ),
                    "posix_spawn_file_actions_adddup2 identity",
                )
            pid = ctypes.c_int()
            argv_c = _CStringArray(argv)
            env_c = _CStringArray([f"{name}={value}" for name, value in env.items()])
            rc = _LIBC.posix_spawn(
                ctypes.byref(pid),
                os.fsencode(path),
                ctypes.byref(actions),
                ctypes.byref(attr),
                argv_c.array,
                env_c.array,
            )
            _must(rc, "posix_spawn")
            return pid.value
        finally:
            _LIBC.posix_spawn_file_actions_destroy(ctypes.byref(actions))
    finally:
        _LIBC.posix_spawnattr_destroy(ctypes.byref(attr))

def _wait_pid(pid: int, timeout: float) -> int:
    deadline = time.time() + timeout
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return os.waitstatus_to_exitcode(status)
        if time.time() >= deadline:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            raise GcloudCustodyError("Google Cloud CLI command timed out")
        time.sleep(0.02)


def _read_capture_fd(fd: int, stream: str) -> bytes:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_COMMAND_CAPTURE:
        raise GcloudCustodyError(
            f"captured Google Cloud CLI {stream} exceeds the size limit"
        )
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = info.st_size
    while remaining:
        block = os.read(fd, min(remaining, 1024 * 1024))
        if not block:
            raise GcloudCustodyError(f"captured Google Cloud CLI {stream} was truncated")
        chunks.append(block)
        remaining -= len(block)
    finished = os.fstat(fd)
    if _stat_identity(info) != _stat_identity(finished):
        raise GcloudCustodyError(f"captured Google Cloud CLI {stream} changed while read")
    return b"".join(chunks)


@dataclass
class _SpawnedChild:
    pid: int
    popen: subprocess.Popen[bytes] | None = None


def _require_pipe_timeout(timeout_seconds: int) -> int:
    if type(timeout_seconds) is not int or timeout_seconds <= 0 or timeout_seconds > MAX_PIPE_TIMEOUT:
        raise GcloudCustodyError("Google Cloud CLI SSH pipe timeout is invalid")
    return timeout_seconds


def _ssh_flag_value(token: str, prefix: str) -> str:
    if type(token) is not str or not token.startswith(prefix):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    return token[len(prefix) :]


def validate_fixed_gcloud_ssh_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return the exact seven-token compute ssh vector. Never print argv values."""
    require_compatible_python()
    if type(argv) not in {list, tuple}:
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    tokens = list(argv)
    if not tokens or any(type(item) is not str for item in tokens):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    if Path(tokens[0]).name in {"gcloud", "gcloud.cmd"}:
        tokens = tokens[1:]
    if len(tokens) != FIXED_SSH_ARGC:
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    if tokens[0] != "compute" or tokens[1] != "ssh":
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    instance = tokens[2]
    project_flag = tokens[3]
    zone_flag = tokens[4]
    quiet = tokens[5]
    command_flag = tokens[6]
    if not SSH_INSTANCE_RE.fullmatch(instance):
        raise GcloudCustodyError("fixed Google Cloud CLI SSH instance is invalid")
    if not project_flag.startswith("--project="):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    project = _ssh_flag_value(project_flag, "--project=")
    if not PROJECT_RE.fullmatch(project):
        raise GcloudCustodyError("fixed Google Cloud CLI SSH project is invalid")
    if not zone_flag.startswith("--zone="):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    zone = _ssh_flag_value(zone_flag, "--zone=")
    if not SSH_ZONE_RE.fullmatch(zone):
        raise GcloudCustodyError("fixed Google Cloud CLI SSH zone is invalid")
    if quiet != "--quiet":
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    if not command_flag.startswith("--command="):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    command = _ssh_flag_value(command_flag, "--command=")
    encoded = command.encode("utf-8")
    if not command or len(encoded) > MAX_SSH_COMMAND:
        raise GcloudCustodyError("fixed Google Cloud CLI SSH command is invalid")
    if "\x00" in command or "\n" in command or "\r" in command:
        raise GcloudCustodyError("fixed Google Cloud CLI SSH command is invalid")
    for token in tokens[:6]:
        if "*" in token or "\n" in token or "\r" in token or "\x00" in token:
            raise GcloudCustodyError(SSH_PIPE_ARGV)
        lower = token.lower()
        if any(lower == flag or lower.startswith(flag + "=") for flag in ("--filter", "--regex", "--all")):
            raise GcloudCustodyError(SSH_PIPE_ARGV)
    command_lower = command_flag.lower()
    if any(command_lower == flag or command_lower.startswith(flag + "=") for flag in ("--filter", "--regex", "--all")):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    return tuple(tokens)


def validate_ssh_pipe_consumer_response(data: bytes) -> bytes:
    """Exact bounded canonical ASCII JSON for the SSH pipe consumer exchange.

    Production callers must pass this function object. A substitute or omitted
    validator cannot satisfy PrivateGcloudRuntime.run_ssh_pipe or CustodyRunner.
    """
    if type(data) is not bytes or not data or len(data) > MAX_SSH_PIPE_RESPONSE:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    raw = data[:-1] if data.endswith(b"\n") else data
    if not raw or b"\n" in raw or b"\r" in raw or b"\0" in raw:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as suc:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE) from suc
    try:
        parsed = json.loads(text, object_pairs_hook=_ssh_pipe_pairs)
    except json.JSONDecodeError as suc:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE) from suc
    except GcloudCustodyError:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE) from None
    if type(parsed) is not dict or set(parsed) != SSH_PIPE_RESPONSE_KEYS:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    if _exact_str(parsed.get("contract"), "SSH pipe contract") != SSH_PIPE_RESPONSE_CONTRACT:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    if _exact_int(parsed.get("schema_version"), "SSH pipe schema_version") != 1:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    if _exact_str(parsed.get("status"), "SSH pipe status") != SSH_PIPE_RESPONSE_STATUS:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    digest = _exact_str(parsed.get("payload_sha256"), "SSH pipe payload_sha256")
    if not SHA_RE.fullmatch(digest) or digest == ZERO_SHA:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    canonical = json.dumps(
        {
            "contract": SSH_PIPE_RESPONSE_CONTRACT,
            "payload_sha256": digest,
            "schema_version": 1,
            "status": SSH_PIPE_RESPONSE_STATUS,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if raw != canonical:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    return canonical


def _require_canonical_ssh_pipe_validator(validator: Any) -> Callable[[bytes], bytes]:
    if validator is not validate_ssh_pipe_consumer_response:
        raise GcloudCustodyError(SSH_PIPE_VALIDATOR)
    return validator


def _cloexec_pipe() -> tuple[int, int]:
    if not hasattr(os, "O_CLOEXEC") or not hasattr(fcntl, "FD_CLOEXEC"):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    read_fd = -1
    write_fd = -1
    try:
        if hasattr(os, "pipe2"):
            read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        else:
            read_fd, write_fd = os.pipe()
            for fd in (read_fd, write_fd):
                flags = fcntl.fcntl(fd, fcntl.F_GETFD)
                fcntl.fcntl(fd, fcntl.F_SETFD, flags | fcntl.FD_CLOEXEC)
                os.set_inheritable(fd, False)
        for fd in (read_fd, write_fd):
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            if flags & fcntl.FD_CLOEXEC == 0:
                raise GcloudCustodyError(EXECUTION_BLOCKER)
        return read_fd, write_fd
    except GcloudCustodyError:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        raise
    except OSError as suc:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)
        raise GcloudCustodyError(EXECUTION_BLOCKER) from suc


def _cloexec_capture_pipe() -> tuple[int, int]:
    return _cloexec_pipe()


def _cloexec_devnull() -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.devnull, flags)
    except OSError as suc:
        raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
    try:
        info = os.fstat(fd)
    except OSError as suc:
        _close_fd(fd)
        raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISCHR(info.st_mode):
        _close_fd(fd)
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    return fd


def _close_fd(fd: int) -> None:
    if type(fd) is not int or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


@dataclass
class _KernelStream:
    label: str
    read_fd: int
    write_fd: int
    limit: int
    chunks: list[bytes] = field(default_factory=list)
    size: int = 0
    eof: bool = False


def _open_kernel_stream(label: str, *, limit: int | None = None) -> _KernelStream:
    selected_limit = MAX_PIPE_CAPTURE if limit is None else limit
    if type(selected_limit) is not int or selected_limit <= 0:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    read_fd, write_fd = _cloexec_capture_pipe()
    try:
        os.set_blocking(read_fd, False)
    except OSError as suc:
        _close_fd(read_fd)
        _close_fd(write_fd)
        raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
    return _KernelStream(
        label=label,
        read_fd=read_fd,
        write_fd=write_fd,
        limit=selected_limit,
    )


def _close_stream_write(stream: _KernelStream) -> None:
    _close_fd(stream.write_fd)
    stream.write_fd = -1


def _close_stream_read(stream: _KernelStream) -> None:
    _close_fd(stream.read_fd)
    stream.read_fd = -1


def _drain_kernel_stream(stream: _KernelStream) -> None:
    if stream.eof or stream.read_fd < 0:
        return
    while True:
        try:
            chunk = os.read(stream.read_fd, 65536)
        except BlockingIOError:
            return
        except OSError as suc:
            raise GcloudCustodyError("captured Google Cloud CLI stream is unreadable") from suc
        if not chunk:
            stream.eof = True
            return
        if stream.size + len(chunk) > stream.limit:
            raise GcloudCustodyError(
                f"captured Google Cloud CLI {stream.label} exceeds the size limit"
            )
        stream.chunks.append(chunk)
        stream.size += len(chunk)


def _drain_kernel_streams(streams: Sequence[_KernelStream]) -> None:
    for stream in streams:
        _drain_kernel_stream(stream)


def _stream_read_fds(streams: Sequence[_KernelStream]) -> list[int]:
    return [stream.read_fd for stream in streams if not stream.eof and stream.read_fd >= 0]


def _select_stream_reads(streams: Sequence[_KernelStream], timeout_seconds: float) -> None:
    readable = _stream_read_fds(streams)
    if not readable or timeout_seconds <= 0:
        return
    try:
        select.select(readable, [], [], timeout_seconds)
    except (ValueError, OSError):
        time.sleep(min(0.02, timeout_seconds))


def _drain_kernel_streams_until_eof(
    streams: Sequence[_KernelStream],
    deadline: float,
    *,
    timeout_message: str = SSH_PIPE_TIMEOUT,
) -> None:
    while any(not stream.eof for stream in streams):
        _drain_kernel_streams(streams)
        if all(stream.eof for stream in streams):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GcloudCustodyError(timeout_message)
        if not _stream_read_fds(streams):
            return
        _select_stream_reads(streams, min(0.02, remaining))


def _stream_bytes(stream: _KernelStream) -> bytes:
    return b"".join(stream.chunks)


def _kill_process_group(pid: int) -> None:
    if type(pid) is not int or pid <= 0:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _kill_spawned(child: _SpawnedChild) -> None:
    _kill_process_group(child.pid)
    try:
        if child.popen is not None:
            child.popen.wait()
        else:
            os.waitpid(child.pid, 0)
    except (ChildProcessError, OSError):
        pass


def _child_exit(child: _SpawnedChild) -> int | None:
    if child.popen is not None:
        return child.popen.poll()
    waited, status = os.waitpid(child.pid, os.WNOHANG)
    if waited == 0:
        return None
    if waited != child.pid:
        raise GcloudCustodyError("Google Cloud CLI process wait is invalid")
    return os.waitstatus_to_exitcode(status)


def _wait_two_children(
    consumer: _SpawnedChild,
    producer: _SpawnedChild,
    timeout_seconds: int,
    streams: Sequence[_KernelStream],
) -> tuple[int, int]:
    deadline = time.monotonic() + timeout_seconds
    consumer_code: int | None = None
    producer_code: int | None = None
    while True:
        _drain_kernel_streams(streams)
        if consumer_code is None:
            consumer_code = _child_exit(consumer)
        if producer_code is None:
            producer_code = _child_exit(producer)
        if consumer_code is not None and producer_code is not None:
            _drain_kernel_streams_until_eof(
                streams, deadline, timeout_message=SSH_PIPE_TIMEOUT
            )
            return int(producer_code), int(consumer_code)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_spawned(consumer)
            _kill_spawned(producer)
            raise GcloudCustodyError(SSH_PIPE_TIMEOUT)
        _select_stream_reads(streams, min(0.02, remaining))


def _wait_one_child(
    child: _SpawnedChild,
    timeout_seconds: int,
    streams: Sequence[_KernelStream],
) -> int:
    deadline = time.monotonic() + timeout_seconds
    while True:
        _drain_kernel_streams(streams)
        exit_code = _child_exit(child)
        if exit_code is not None:
            _drain_kernel_streams_until_eof(
                streams,
                deadline,
                timeout_message="Google Cloud CLI command timed out",
            )
            return int(exit_code)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_spawned(child)
            raise GcloudCustodyError("Google Cloud CLI command timed out")
        _select_stream_reads(streams, min(0.02, remaining))


def _posix_spawn_stdio(
    path: str,
    argv: list[str],
    env: dict[str, str],
    *,
    root_fd: int,
    stdin_fd: int,
    stdout_fd: int,
    stderr_fd: int,
    inherited_fds: tuple[tuple[int, int], ...] = (),
) -> int:
    if _LIBC is None or sys.platform != "darwin":
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if root_fd < 0:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if not hasattr(_LIBC, "posix_spawn_file_actions_addfchdir_np"):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if not hasattr(_LIBC, "posix_spawn_file_actions_adddup2"):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or ".." in path.split("/")
        or path in {".", ".."}
    ):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if any(type(fd) is not int or fd < 0 for fd in (stdin_fd, stdout_fd, stderr_fd)):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    targets: set[int] = set()
    for source_fd, target_fd in inherited_fds:
        if (
            type(source_fd) is not int
            or source_fd < 0
            or type(target_fd) is not int
            or target_fd < 3
            or target_fd in targets
        ):
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        targets.add(target_fd)
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    _must(_LIBC.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
    try:
        _must(
            _LIBC.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT),
            ),
            "posix_spawnattr_setflags",
        )
        _must(_LIBC.posix_spawn_file_actions_init(ctypes.byref(actions)), "posix_spawn_file_actions_init")
        try:
            _must(
                _LIBC.posix_spawn_file_actions_addfchdir_np(ctypes.byref(actions), int(root_fd)),
                "posix_spawn_file_actions_addfchdir_np",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(
                    ctypes.byref(actions), int(stdin_fd), 0
                ),
                "posix_spawn_file_actions_adddup2 stdin",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(
                    ctypes.byref(actions), int(stdout_fd), 1
                ),
                "posix_spawn_file_actions_adddup2 stdout",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(
                    ctypes.byref(actions), int(stderr_fd), 2
                ),
                "posix_spawn_file_actions_adddup2 stderr",
            )
            for source_fd, target_fd in inherited_fds:
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(
                        ctypes.byref(actions), int(source_fd), int(target_fd)
                    ),
                    "posix_spawn_file_actions_adddup2 identity",
                )
            pid = ctypes.c_int()
            argv_c = _CStringArray(argv)
            env_c = _CStringArray([f"{name}={value}" for name, value in env.items()])
            rc = _LIBC.posix_spawn(
                ctypes.byref(pid),
                os.fsencode(path),
                ctypes.byref(actions),
                ctypes.byref(attr),
                argv_c.array,
                env_c.array,
            )
            _must(rc, "posix_spawn")
            return pid.value
        finally:
            _LIBC.posix_spawn_file_actions_destroy(ctypes.byref(actions))
    finally:
        _LIBC.posix_spawnattr_destroy(ctypes.byref(attr))


def _popen_stdio(
    argv: Sequence[str],
    *,
    env: dict[str, str],
    cwd: str | None,
    stdin: int | object,
    stdout: int | object,
    stderr: int | object,
    pass_fds: tuple[int, ...],
    executable: str | None,
) -> _SpawnedChild:
    if type(argv) not in {list, tuple} or not argv or any(type(item) is not str for item in argv):
        raise GcloudCustodyError(SSH_PIPE_ARGV)
    if type(env) is not dict or any(type(name) is not str or type(value) is not str for name, value in env.items()):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    try:
        proc = subprocess.Popen(
            list(argv),
            executable=executable,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=False,
            env=env,
            cwd=cwd,
            pass_fds=pass_fds,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as suc:
        raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
    return _SpawnedChild(pid=int(proc.pid), popen=proc)


def _finish_ssh_pipe(
    producer_err: _KernelStream,
    consumer_out: _KernelStream,
    consumer_err: _KernelStream,
    producer_code: int,
    consumer_code: int,
    consumer_response_validator: Callable[[bytes], bytes],
) -> CustodyRunResult:
    if producer_code != 0 or consumer_code != 0:
        raise GcloudCustodyError(SSH_PIPE_EXIT)
    if _stream_bytes(producer_err):
        raise GcloudCustodyError(SSH_PIPE_STDERR)
    if _stream_bytes(consumer_err):
        raise GcloudCustodyError(SSH_PIPE_CONSUMER_STDERR)
    if not callable(consumer_response_validator):
        raise GcloudCustodyError(SSH_PIPE_VALIDATOR)
    validated = consumer_response_validator(_stream_bytes(consumer_out))
    if type(validated) is not bytes:
        raise GcloudCustodyError(SSH_PIPE_RESPONSE)
    return CustodyRunResult(validated, b"", 0)


def _execute_secret_pipe(
    *,
    spawn_consumer: Callable[[int, int, int], _SpawnedChild],
    spawn_producer: Callable[[int, int, int], _SpawnedChild],
    timeout_seconds: int,
    pass_fds: tuple[int, ...],
    consumer_response_validator: Callable[[bytes], bytes],
) -> CustodyRunResult:
    """Consumer first; producer stdout stays in one O_CLOEXEC kernel pipe."""
    timeout_seconds = _require_pipe_timeout(timeout_seconds)
    if type(pass_fds) is not tuple or any(type(fd) is not int or fd < 0 for fd in pass_fds):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if not callable(consumer_response_validator):
        raise GcloudCustodyError(SSH_PIPE_VALIDATOR)
    secret_read = -1
    secret_write = -1
    null_fd = -1
    streams: list[_KernelStream] = []
    consumer: _SpawnedChild | None = None
    producer: _SpawnedChild | None = None
    try:
        secret_read, secret_write = _cloexec_pipe()
        producer_err = _open_kernel_stream(PIPE_PRODUCER_STDERR)
        consumer_out = _open_kernel_stream(PIPE_CONSUMER_STDOUT)
        consumer_err = _open_kernel_stream(PIPE_CONSUMER_STDERR)
        streams = [producer_err, consumer_out, consumer_err]
        owned = [secret_read, secret_write]
        for stream in streams:
            owned.extend((stream.read_fd, stream.write_fd))
        if any(fd in pass_fds for fd in owned):
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        consumer = spawn_consumer(secret_read, consumer_out.write_fd, consumer_err.write_fd)
        null_fd = _cloexec_devnull()
        if null_fd in pass_fds:
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        producer = spawn_producer(null_fd, secret_write, producer_err.write_fd)
        _close_fd(secret_read)
        secret_read = -1
        _close_fd(secret_write)
        secret_write = -1
        _close_fd(null_fd)
        null_fd = -1
        for stream in streams:
            _close_stream_write(stream)
        producer_code, consumer_code = _wait_two_children(
            consumer, producer, timeout_seconds, streams
        )
        return _finish_ssh_pipe(
            producer_err,
            consumer_out,
            consumer_err,
            producer_code,
            consumer_code,
            consumer_response_validator,
        )
    except BaseException:
        if consumer is not None:
            _kill_spawned(consumer)
        if producer is not None:
            _kill_spawned(producer)
        raise
    finally:
        _close_fd(secret_read)
        _close_fd(secret_write)
        _close_fd(null_fd)
        for stream in streams:
            _close_stream_write(stream)
            _close_stream_read(stream)


def _execute_bounded_command(
    *,
    spawn: Callable[[int, int, int], _SpawnedChild],
    timeout_seconds: int,
) -> CustodyRunResult:
    """Capture one command through held kernel pipes with fixed memory bounds."""
    timeout_seconds = _require_pipe_timeout(timeout_seconds)
    null_fd = -1
    streams: list[_KernelStream] = []
    child: _SpawnedChild | None = None
    try:
        stdout = _open_kernel_stream("stdout", limit=MAX_COMMAND_CAPTURE)
        stderr = _open_kernel_stream("stderr", limit=MAX_COMMAND_CAPTURE)
        streams = [stdout, stderr]
        null_fd = _cloexec_devnull()
        child = spawn(null_fd, stdout.write_fd, stderr.write_fd)
        _close_fd(null_fd)
        null_fd = -1
        for stream in streams:
            _close_stream_write(stream)
        exit_code = _wait_one_child(child, timeout_seconds, streams)
        return CustodyRunResult(
            _stream_bytes(stdout),
            _stream_bytes(stderr),
            exit_code,
        )
    except BaseException:
        if child is not None:
            _kill_spawned(child)
        raise
    finally:
        _close_fd(null_fd)
        for stream in streams:
            _close_stream_write(stream)
            _close_stream_read(stream)


def _run_two_process_kernel_pipe(
    producer_argv: Sequence[str],
    consumer_argv: Sequence[str],
    *,
    env: dict[str, str],
    timeout_seconds: int,
    capture_dir: Path | None = None,
    cwd: str | None = None,
    pass_fds: tuple[int, ...] = (),
    executable: str | None = None,
    consumer_response_validator: Callable[[bytes], bytes] = validate_ssh_pipe_consumer_response,
) -> CustodyRunResult:
    """Consumer first; producer stdout stays in one O_CLOEXEC kernel pipe."""
    del capture_dir

    def spawn_consumer(stdin_fd: int, stdout_fd: int, stderr_fd: int) -> _SpawnedChild:
        return _popen_stdio(
            consumer_argv,
            env=env,
            cwd=cwd,
            stdin=stdin_fd,
            stdout=stdout_fd,
            stderr=stderr_fd,
            pass_fds=pass_fds,
            executable=executable,
        )

    def spawn_producer(stdin_fd: int, stdout_fd: int, stderr_fd: int) -> _SpawnedChild:
        return _popen_stdio(
            producer_argv,
            env=env,
            cwd=cwd,
            stdin=stdin_fd,
            stdout=stdout_fd,
            stderr=stderr_fd,
            pass_fds=pass_fds,
            executable=executable,
        )

    return _execute_secret_pipe(
        spawn_consumer=spawn_consumer,
        spawn_producer=spawn_producer,
        timeout_seconds=timeout_seconds,
        pass_fds=pass_fds,
        consumer_response_validator=consumer_response_validator,
    )


def _same_user_cannot_replace(path: Path) -> bool:
    """UF_IMMUTABLE is insufficient: the owner can clear it and replace the path."""
    if hasattr(os, "chflags"):
        try:
            os.chflags(path, 0)
        except OSError:
            pass
        else:
            return False
    try:
        fd = os.open(
            path,
            os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError:
        pass
    else:
        os.close(fd)
        return False
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    else:
        return False
    try:
        os.unlink(path)
    except IsADirectoryError:
        try:
            os.chmod(path, 0o700)
            os.rmdir(path)
        except OSError:
            pass
        else:
            return False
    except OSError:
        pass
    else:
        return False
    return True


def _same_user_cannot_replace_tree(root: Path, *required_paths: Path) -> bool:
    if not required_paths:
        return False
    root_absolute = root.absolute()
    checked: set[Path] = set()
    for required in required_paths:
        required_absolute = required.absolute()
        if required_absolute != root_absolute and root_absolute not in required_absolute.parents:
            return False
        current = required_absolute
        while current != root_absolute:
            if current in checked:
                break
            if current.is_symlink() or not current.exists() or not _same_user_cannot_replace(current):
                return False
            checked.add(current)
            current = current.parent
    if not _same_user_cannot_replace(root):
        return False
    return True


def _apply_linux_immutable(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        info = path.lstat()
    except OSError as exc:
        raise GcloudCustodyError(f"{EXECUTION_BLOCKER}: {exc}") from exc
    if stat.S_ISDIR(info.st_mode):
        flags |= getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        buf = array.array("i", [0])
        fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
        buf[0] |= FS_IMMUTABLE_FL
        fcntl.ioctl(fd, FS_IOC_SETFLAGS, buf)
    except OSError as exc:
        raise GcloudCustodyError(f"{EXECUTION_BLOCKER}: {exc}") from exc
    finally:
        os.close(fd)


def _kernel_seal_tree(root: Path, *required_paths: Path) -> None:
    """Make the cloned SDK tree immutable against same-user replacement.

    UF_IMMUTABLE is insufficient because the owner can clear it. Only
    SF_IMMUTABLE or Linux FS_IMMUTABLE_FL counts, and the proof is that the
    same user cannot clear the flag or replace a sealed path. If this host
    cannot do that, fail closed instead of executing a pathname.
    """
    if sys.platform == "darwin":
        if not SF_IMMUTABLE:
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        for base, directories, files in os.walk(root, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in files + directories:
                path = base_path / name
                if path.is_symlink():
                    continue
                try:
                    os.chflags(path, SF_IMMUTABLE)
                except OSError as exc:
                    raise GcloudCustodyError(f"{EXECUTION_BLOCKER}: {exc}") from exc
            try:
                os.chflags(base_path, SF_IMMUTABLE)
            except OSError as exc:
                raise GcloudCustodyError(f"{EXECUTION_BLOCKER}: {exc}") from exc
    elif sys.platform.startswith("linux"):
        for base, directories, files in os.walk(root, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in files + directories:
                path = base_path / name
                if path.is_symlink():
                    continue
                _apply_linux_immutable(path)
            _apply_linux_immutable(base_path)
    else:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if not _same_user_cannot_replace_tree(root, *required_paths):
        raise GcloudCustodyError(EXECUTION_BLOCKER)


def _clone_execution_tree(source: Path, scratch: Path) -> Path:
    if sys.platform != "darwin" or _LIBC is None:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    exec_dir = scratch / "exec"
    exec_dir.mkdir(mode=0o700, exist_ok=False)
    root_fd = os.open(source, _DIR_FLAGS)
    try:
        dir_fd = os.open(exec_dir, _DIR_FLAGS)
        try:
            rc = _LIBC.fclonefileat(root_fd, dir_fd, b"tree", CLONE_NOFOLLOW)
            if rc != 0:
                raise GcloudCustodyError(
                    "owner/environment blocker: macOS fclonefileat of the authenticated "
                    f"Google Cloud CLI tree failed: {os.strerror(ctypes.get_errno())}"
                )
        finally:
            os.close(dir_fd)
    finally:
        os.close(root_fd)
    clone = exec_dir / "tree"
    if not clone.is_dir() or clone.is_symlink():
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    return clone


def _linux_descriptor_executable(executable_fd: int, root_fd: int) -> tuple[str, str]:
    proc = Path("/proc/self/fd")
    if not proc.is_dir():
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    return f"/proc/self/fd/{executable_fd}", f"/proc/self/fd/{root_fd}"


def _linux_effective_capabilities() -> int:
    try:
        data = Path("/proc/self/status").read_bytes()
    except OSError as exc:
        raise GcloudCustodyError(
            "owner blocker: Linux effective capabilities are unavailable"
        ) from exc
    if not data or len(data) > 256 * 1024 or b"\0" in data:
        raise GcloudCustodyError(
            "owner blocker: Linux effective capabilities are invalid"
        )
    values: list[bytes] = []
    for line in data.splitlines():
        if line.startswith(b"CapEff:"):
            values.append(line.removeprefix(b"CapEff:").strip())
    if len(values) != 1 or not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", values[0]):
        raise GcloudCustodyError(
            "owner blocker: Linux effective capabilities are invalid"
        )
    return int(values[0], 16)


def _safe_runtime_symlink(root: Path, path: Path) -> None:
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise GcloudCustodyError(EXECUTION_BLOCKER) from exc
    if not target or target.startswith("/") or "\\" in target or "\0" in target:
        raise GcloudCustodyError("sealed Google Cloud CLI runtime contains an unsafe symlink")
    resolved = Path(os.path.normpath(str(path.parent / target)))
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise GcloudCustodyError("sealed Google Cloud CLI runtime symlink escapes its root") from exc


def _production_public_mode_allowed(info: os.stat_result) -> bool:
    """A root-owned sealed SDK must remain readable by the non-root proof client."""
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        return mode == SEALED_PUBLIC_DIR_MODE
    if stat.S_ISREG(info.st_mode):
        return mode in {SEALED_PUBLIC_DATA_MODE, SEALED_PUBLIC_EXEC_MODE}
    return False


def _entry_kernel_immutable(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return False
    if sys.platform == "darwin":
        flags = int(getattr(info, "st_flags", 0))
        return bool(flags & SF_IMMUTABLE)
    if sys.platform.startswith("linux"):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        if stat.S_ISDIR(info.st_mode):
            flags |= getattr(os, "O_DIRECTORY", 0)
        try:
            fd = os.open(path, flags)
            try:
                attrs = array.array("i", [0])
                fcntl.ioctl(fd, FS_IOC_GETFLAGS, attrs)
                return bool(attrs[0] & FS_IMMUTABLE_FL)
            finally:
                os.close(fd)
        except OSError:
            return False
    return False


def _expected_production_runtime_root(tree_sha256: str) -> Path:
    if not SHA_RE.fullmatch(tree_sha256) or tree_sha256 == ZERO_SHA:
        raise GcloudCustodyError("Google Cloud CLI production runtime tree identity is invalid")
    try:
        prefix = PRODUCTION_RUNTIME_PREFIXES[current_platform_key()]
    except KeyError as exc:
        raise GcloudCustodyError(EXECUTION_BLOCKER) from exc
    return prefix / tree_sha256


def _verify_presealed_production_runtime(
    root: Path,
    root_fd: int,
    *,
    expected_tree_sha256: str,
    executable: Path,
) -> None:
    if os.geteuid() == 0:
        raise GcloudCustodyError(
            "owner blocker: root cannot execute the Google Cloud CLI custody controller"
        )
    if sys.platform.startswith("linux"):
        capabilities = _linux_effective_capabilities()
        if capabilities & (1 << LINUX_CAP_IMMUTABLE):
            raise GcloudCustodyError(
                "owner blocker: Google Cloud CLI custody controller must not hold CAP_LINUX_IMMUTABLE"
            )
    expected_root = _expected_production_runtime_root(expected_tree_sha256)
    if not root.is_absolute() or root != expected_root or root.absolute() != expected_root:
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI production runtime is outside its fixed sealed root"
        )
    expected_prefix = expected_root.parent
    current = Path("/")
    for part in expected_prefix.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise GcloudCustodyError(EXECUTION_BLOCKER) from exc
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise GcloudCustodyError(
                "owner blocker: Google Cloud CLI sealed runtime ancestor custody is invalid"
            )
    root_info = root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != 0
        or not _production_public_mode_allowed(root_info)
        or not _entry_kernel_immutable(root, root_info)
    ):
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI production runtime root is not system-immutable"
        )
    root_device = root_info.st_dev
    for base, directories, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        for name in sorted(directories + files):
            path = base_path / name
            info = path.lstat()
            if info.st_dev != root_device or info.st_uid != 0:
                raise GcloudCustodyError(
                    "owner blocker: Google Cloud CLI sealed runtime crosses an ownership or mount boundary"
                )
            if stat.S_ISLNK(info.st_mode):
                _safe_runtime_symlink(root, path)
                continue
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise GcloudCustodyError(
                    "owner blocker: Google Cloud CLI sealed runtime contains an unsupported entry"
                )
            if not _production_public_mode_allowed(info):
                raise GcloudCustodyError(
                    "owner blocker: Google Cloud CLI sealed runtime is unreadable by the non-root proof client"
                )
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise GcloudCustodyError(
                    "owner blocker: Google Cloud CLI sealed runtime contains a hard-linked file"
                )
            if not _entry_kernel_immutable(path, info):
                raise GcloudCustodyError(
                    "owner blocker: Google Cloud CLI production runtime is not system-immutable"
                )
    if executable != root / "bin" / executable.name:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    if install_tree_sha256_from_fd(root_fd) != expected_tree_sha256:
        raise GcloudCustodyError(
            "owner blocker: Google Cloud CLI sealed runtime tree does not match its signed receipt"
        )



def _seal_regular_file(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return False
    try:
        if sys.platform == "darwin":
            if not SF_IMMUTABLE:
                return False
            os.chflags(path, SF_IMMUTABLE)
        elif sys.platform.startswith("linux"):
            _apply_linux_immutable(path)
        else:
            return False
    except OSError:
        return False
    return _same_user_cannot_replace(path)


def _clear_immutable_fd(fd: int) -> None:
    if sys.platform == "darwin" and _LIBC is not None and hasattr(_LIBC, "fchflags"):
        rc = _LIBC.fchflags(int(fd), 0)
        if rc != 0:
            errno = ctypes.get_errno()
            if errno not in {0, 1, 13}:
                pass
        return
    if sys.platform.startswith("linux"):
        try:
            buf = array.array("i", [0])
            fcntl.ioctl(fd, FS_IOC_GETFLAGS, buf)
            buf[0] &= ~FS_IMMUTABLE_FL
            fcntl.ioctl(fd, FS_IOC_SETFLAGS, buf)
        except OSError:
            return


def _destroy_runtime_tree(root: Path) -> None:
    if not root.exists() and not root.is_symlink():
        return
    try:
        root_info = root.lstat()
    except OSError:
        return
    if stat.S_ISLNK(root_info.st_mode):
        raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime symlink")
    if not stat.S_ISDIR(root_info.st_mode):
        raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime")
    root_fd = os.open(root, _DIR_FLAGS)
    try:
        opened = os.fstat(root_fd)
        if (opened.st_dev, opened.st_ino) != (root_info.st_dev, root_info.st_ino):
            raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime")
        _clear_immutable_fd(root_fd)
        try:
            os.fchmod(root_fd, 0o700)
        except OSError:
            pass
        _destroy_dir_fd(root_fd)
    finally:
        os.close(root_fd)
    try:
        os.rmdir(root)
    except OSError:
        pass


def _destroy_dir_fd(dir_fd: int) -> None:
    try:
        names = list(os.listdir(dir_fd))
    except OSError:
        return
    for name in names:
        if name in {".", ".."}:
            continue
        if "/" in name or "\\" in name:
            raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime")
        try:
            info = os.lstat(name, dir_fd=dir_fd)
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError:
                pass
            continue
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            try:
                _clear_immutable_fd(child)
                try:
                    os.fchmod(child, 0o700)
                except OSError:
                    pass
                _destroy_dir_fd(child)
            finally:
                os.close(child)
            try:
                os.rmdir(name, dir_fd=dir_fd)
            except TypeError:
                try:
                    os.unlink(name, dir_fd=dir_fd)
                except OSError:
                    pass
            except OSError:
                pass
            continue
        if not stat.S_ISREG(info.st_mode):
            raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime")
        child = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
        try:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise GcloudCustodyError("refusing cleanup of a substituted Google Cloud CLI runtime")
            _clear_immutable_fd(child)
            try:
                os.fchmod(child, 0o600)
            except OSError:
                pass
        finally:
            os.close(child)
        try:
            os.unlink(name, dir_fd=dir_fd)
        except OSError:
            pass



@dataclass(frozen=True)
class PrivateGcloudRuntime:
    """Descriptor-bound immutable runtime used for one gcloud execution."""

    scratch: Path
    root: Path
    root_fd: int
    executable_fd: int
    root_identity: tuple[int, ...]
    executable_identity: tuple[int, ...]
    home: Path
    config: Path
    tmp: Path
    credential_file: Path = field(repr=False)
    credential_fd: int = field(repr=False)
    credential_sha256: str = field(repr=False)
    python: Path
    python_fd: int = field(repr=False)
    python_sha256: str
    python_identity: tuple[int, ...]
    subject_token_file: Path | None = field(repr=False)
    subject_token_fd: int | None = field(repr=False)
    subject_token_sha256: str | None = field(repr=False)
    subject_token_identity: tuple[int, ...] | None = field(repr=False)
    expected_project: str = field(repr=False)
    snapshot_tree_sha256: str
    sealed: bool
    credential_sealed: bool
    executable_path: Path
    production_presealed: bool = False

    def _environment(self) -> dict[str, str]:
        credential = self.credential_file
        python = self.python
        root = self.root
        if self.production_presealed and sys.platform.startswith("linux"):
            credential = Path(f"/proc/self/fd/{self.credential_fd}")
            root = Path(f"/proc/self/fd/{self.root_fd}")
            python = root / LINUX_BUNDLED_PYTHON_RELATIVE
        elif self.production_presealed and sys.platform == "darwin":
            credential = Path(f"/dev/fd/{DARWIN_CREDENTIAL_CHILD_FD}")
        return _isolated_environment(
            home=self.home,
            config=self.config,
            tmp=self.tmp,
            credential_file=credential,
            python=python,
            project=self.expected_project,
            root=root,
        )

    def _darwin_identity_fds(self) -> tuple[tuple[int, int], ...]:
        inherited = [(self.credential_fd, DARWIN_CREDENTIAL_CHILD_FD)]
        if self.subject_token_fd is not None:
            inherited.append(
                (self.subject_token_fd, DARWIN_SUBJECT_TOKEN_CHILD_FD)
            )
        return tuple(inherited)

    def _linux_pass_fds(self) -> tuple[int, ...]:
        descriptors = [
            self.root_fd,
            self.executable_fd,
            self.credential_fd,
        ]
        if self.subject_token_fd is not None:
            descriptors.append(self.subject_token_fd)
        return tuple(descriptors)

    def run(self, args: Sequence[str], *, timeout_seconds: int) -> CustodyRunResult:
        """Execute only after a genuine immutable boundary. Never pathname-exec ``bin/gcloud``."""
        if not self.sealed or not self.credential_sealed:
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        if self.production_presealed:
            _verify_presealed_production_runtime(
                self.root,
                self.root_fd,
                expected_tree_sha256=self.snapshot_tree_sha256,
                executable=self.executable_path,
            )
        if not _same_user_cannot_replace_tree(self.root, self.executable_path):
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        if _fd_identity(self.root_fd, "private Google Cloud CLI root") != self.root_identity:
            raise GcloudCustodyError("private Google Cloud CLI root changed before execution")
        if _fd_identity(self.executable_fd, "private Google Cloud CLI executable") != self.executable_identity:
            raise GcloudCustodyError("private Google Cloud CLI executable changed before execution")
        _verify_private_python_custody(self, "before execution")
        if install_tree_sha256_from_fd(self.root_fd) != self.snapshot_tree_sha256:
            raise GcloudCustodyError("private Google Cloud CLI snapshot changed before execution")
        live_credential, live_credential_identity = _stable_fd_bytes(
            self.credential_fd,
            max_size=MAX_CREDENTIAL,
            label="Google Cloud CLI bound credential",
        )
        if (
            hashlib.sha256(live_credential).hexdigest() != self.credential_sha256
            or live_credential_identity
            != _fd_identity(self.credential_fd, "Google Cloud CLI bound credential")
        ):
            raise GcloudCustodyError("private Google Cloud CLI credential descriptor changed before execution")
        _verify_private_subject_token(self)
        environment = self._environment()
        try:
            if sys.platform == "darwin":

                def spawn_darwin(
                    stdin_fd: int, stdout_fd: int, stderr_fd: int
                ) -> _SpawnedChild:
                    return _SpawnedChild(
                        pid=_posix_spawn_stdio(
                            "bin/gcloud",
                            ["bin/gcloud", *args],
                            environment,
                            root_fd=self.root_fd,
                            stdin_fd=stdin_fd,
                            stdout_fd=stdout_fd,
                            stderr_fd=stderr_fd,
                            inherited_fds=self._darwin_identity_fds(),
                        )
                    )

                result = _execute_bounded_command(
                    spawn=spawn_darwin,
                    timeout_seconds=timeout_seconds,
                )
            elif sys.platform.startswith("linux"):
                executable, cwd = _linux_descriptor_executable(
                    self.executable_fd, self.root_fd
                )

                def spawn_linux(
                    stdin_fd: int, stdout_fd: int, stderr_fd: int
                ) -> _SpawnedChild:
                    return _popen_stdio(
                        (executable, *args),
                        env=environment,
                        cwd=cwd,
                        stdin=stdin_fd,
                        stdout=stdout_fd,
                        stderr=stderr_fd,
                        pass_fds=self._linux_pass_fds(),
                        executable=executable,
                    )

                result = _execute_bounded_command(
                    spawn=spawn_linux,
                    timeout_seconds=timeout_seconds,
                )
            else:
                raise GcloudCustodyError(EXECUTION_BLOCKER)
        except subprocess.TimeoutExpired as suc:
            raise GcloudCustodyError("Google Cloud CLI command timed out") from suc
        except OSError as suc:
            raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
        finally:
            _reverify_private_runtime_after_execution(self)
        return result

    def run_ssh_pipe(
        self,
        producer_args: Sequence[str],
        consumer_args: Sequence[str],
        *,
        timeout_seconds: int,
        consumer_response_validator: Callable[[bytes], bytes] | None = None,
    ) -> CustodyRunResult:
        """Pipe producer gcloud SSH stdout into consumer stdin; never expose producer stdout."""
        validator = _require_canonical_ssh_pipe_validator(consumer_response_validator)
        timeout_seconds = _require_pipe_timeout(timeout_seconds)
        producer_args = validate_fixed_gcloud_ssh_argv(producer_args)
        consumer_args = validate_fixed_gcloud_ssh_argv(consumer_args)
        producer_project = _ssh_flag_value(producer_args[3], "--project=")
        consumer_project = _ssh_flag_value(consumer_args[3], "--project=")
        if producer_project != self.expected_project or consumer_project != self.expected_project:
            raise GcloudCustodyError(
                "Google Cloud CLI credential project does not match the bound plan project"
            )
        try:
            if not self.sealed or not self.credential_sealed:
                raise GcloudCustodyError(EXECUTION_BLOCKER)
            if self.production_presealed:
                _verify_presealed_production_runtime(
                    self.root,
                    self.root_fd,
                    expected_tree_sha256=self.snapshot_tree_sha256,
                    executable=self.executable_path,
                )
            if not _same_user_cannot_replace_tree(self.root, self.executable_path):
                raise GcloudCustodyError(EXECUTION_BLOCKER)
            if _fd_identity(self.root_fd, "private Google Cloud CLI root") != self.root_identity:
                raise GcloudCustodyError("private Google Cloud CLI root changed before execution")
            if _fd_identity(self.executable_fd, "private Google Cloud CLI executable") != self.executable_identity:
                raise GcloudCustodyError("private Google Cloud CLI executable changed before execution")
            _verify_private_python_custody(self, "before execution")
            if install_tree_sha256_from_fd(self.root_fd) != self.snapshot_tree_sha256:
                raise GcloudCustodyError("private Google Cloud CLI snapshot changed before execution")
            live_credential, live_credential_identity = _stable_fd_bytes(
                self.credential_fd,
                max_size=MAX_CREDENTIAL,
                label="Google Cloud CLI bound credential",
            )
            if (
                hashlib.sha256(live_credential).hexdigest() != self.credential_sha256
                or live_credential_identity
                != _fd_identity(self.credential_fd, "Google Cloud CLI bound credential")
            ):
                raise GcloudCustodyError("private Google Cloud CLI credential descriptor changed before execution")
            _verify_private_subject_token(self)
            environment = self._environment()
            if sys.platform == "darwin":
                return _run_darwin_gcloud_ssh_pipe(
                    producer_args,
                    consumer_args,
                    env=environment,
                    timeout_seconds=timeout_seconds,
                    root_fd=self.root_fd,
                    inherited_fds=self._darwin_identity_fds(),
                    consumer_response_validator=validator,
                )
            if sys.platform.startswith("linux"):
                executable, cwd = _linux_descriptor_executable(self.executable_fd, self.root_fd)
                return _run_two_process_kernel_pipe(
                    (executable, *producer_args),
                    (executable, *consumer_args),
                    env=environment,
                    timeout_seconds=timeout_seconds,
                    cwd=cwd,
                    pass_fds=self._linux_pass_fds(),
                    executable=executable,
                    consumer_response_validator=validator,
                )
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        except subprocess.TimeoutExpired as suc:
            raise GcloudCustodyError(SSH_PIPE_TIMEOUT) from suc
        except OSError as suc:
            raise GcloudCustodyError(EXECUTION_BLOCKER) from suc
        finally:
            _reverify_private_runtime_after_execution(self)


def _verify_private_python_custody(runtime: PrivateGcloudRuntime, phase: str) -> None:
    data, identity = _stable_fd_bytes(
        runtime.python_fd,
        max_size=MAX_CONTROLLER * 16,
        label="private reviewed Python interpreter",
    )
    if (
        identity != runtime.python_identity
        or hashlib.sha256(data).hexdigest() != runtime.python_sha256
    ):
        raise GcloudCustodyError(
            f"private reviewed Python interpreter changed {phase}"
        )
    if not runtime.production_presealed and not _same_user_cannot_replace_tree(
        runtime.python.parent, runtime.python
    ):
        raise GcloudCustodyError(
            f"private reviewed Python interpreter changed {phase}"
        )


def _verify_private_subject_token(runtime: PrivateGcloudRuntime) -> None:
    if runtime.subject_token_file is None:
        if (
            runtime.subject_token_fd is not None
            or runtime.subject_token_identity is not None
            or runtime.subject_token_sha256 is not None
        ):
            raise GcloudCustodyError(EXECUTION_BLOCKER)
        return
    if runtime.subject_token_fd is None:
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    data, identity = _stable_fd_bytes(
        runtime.subject_token_fd,
        max_size=MAX_SUBJECT_TOKEN,
        label="private workload identity subject token",
    )
    if (
        runtime.subject_token_identity is None
        or identity != runtime.subject_token_identity
        or hashlib.sha256(data).hexdigest() != runtime.subject_token_sha256
    ):
        raise GcloudCustodyError(EXECUTION_BLOCKER)


def _reverify_private_runtime_after_execution(runtime: PrivateGcloudRuntime) -> None:
    if runtime.production_presealed:
        _verify_presealed_production_runtime(
            runtime.root,
            runtime.root_fd,
            expected_tree_sha256=runtime.snapshot_tree_sha256,
            executable=runtime.executable_path,
        )
    if _fd_identity(runtime.root_fd, "private Google Cloud CLI root") != runtime.root_identity:
        raise GcloudCustodyError("private Google Cloud CLI root changed during execution")
    if _fd_identity(runtime.executable_fd, "private Google Cloud CLI executable") != runtime.executable_identity:
        raise GcloudCustodyError("private Google Cloud CLI executable changed during execution")
    if install_tree_sha256_from_fd(runtime.root_fd) != runtime.snapshot_tree_sha256:
        raise GcloudCustodyError("private Google Cloud CLI snapshot changed during execution")
    if not _same_user_cannot_replace_tree(runtime.root, runtime.executable_path):
        raise GcloudCustodyError(EXECUTION_BLOCKER)
    _verify_private_python_custody(runtime, "during execution")
    live_credential, live_credential_identity = _stable_fd_bytes(
        runtime.credential_fd,
        max_size=MAX_CREDENTIAL,
        label="Google Cloud CLI bound credential",
    )
    if (
        hashlib.sha256(live_credential).hexdigest() != runtime.credential_sha256
        or live_credential_identity
        != _fd_identity(runtime.credential_fd, "Google Cloud CLI bound credential")
    ):
        raise GcloudCustodyError("private Google Cloud CLI credential descriptor changed during execution")
    _verify_private_subject_token(runtime)


def _run_darwin_gcloud_ssh_pipe(
    producer_args: Sequence[str],
    consumer_args: Sequence[str],
    *,
    env: dict[str, str],
    timeout_seconds: int,
    root_fd: int,
    consumer_response_validator: Callable[[bytes], bytes],
    inherited_fds: tuple[tuple[int, int], ...] = (),
) -> CustodyRunResult:
    def spawn_consumer(stdin_fd: int, stdout_fd: int, stderr_fd: int) -> _SpawnedChild:
        return _SpawnedChild(
            pid=_posix_spawn_stdio(
                "bin/gcloud",
                ["bin/gcloud", *consumer_args],
                env,
                root_fd=root_fd,
                stdin_fd=stdin_fd,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
                inherited_fds=inherited_fds,
            )
        )

    def spawn_producer(stdin_fd: int, stdout_fd: int, stderr_fd: int) -> _SpawnedChild:
        return _SpawnedChild(
            pid=_posix_spawn_stdio(
                "bin/gcloud",
                ["bin/gcloud", *producer_args],
                env,
                root_fd=root_fd,
                stdin_fd=stdin_fd,
                stdout_fd=stdout_fd,
                stderr_fd=stderr_fd,
                inherited_fds=inherited_fds,
            )
        )

    return _execute_secret_pipe(
        spawn_consumer=spawn_consumer,
        spawn_producer=spawn_producer,
        timeout_seconds=timeout_seconds,
        pass_fds=(root_fd, *(source for source, _target in inherited_fds)),
        consumer_response_validator=consumer_response_validator,
    )


@dataclass(frozen=True)
class VerifiedGcloud:
    executable: Path
    install_root: Path
    receipt: Path
    receipt_sha256: str
    tree_sha256: str
    runtime_tree_sha256: str
    version: str
    platform_key: str
    archive_name: str
    archive_sha256: str
    custody_archive: Path
    pin_manifest: Path
    authority_path: Path = field(repr=False, compare=False)
    authority_owner_uid: int = field(repr=False, compare=False)
    receipt_identity: tuple[int, ...]
    archive_identity: tuple[int, ...]
    executable_identity: tuple[int, ...]
    test_only: bool
    custody_hashes: tuple[str, str, str] | None = field(repr=False, compare=False)
    custody_bytes: tuple[bytes, bytes, bytes] | None = field(repr=False, compare=False)
    issuance_path: Path | None = field(repr=False, compare=False)
    issuance_repo: Path | None = field(repr=False, compare=False)
    archive_bytes: bytes = field(repr=False, compare=False)
    pin: dict[str, Any] = field(repr=False, compare=False)

    def verify_unchanged(self) -> None:
        manifest_data = _bind_regular_file_from_parent(
            self.pin_manifest, max_size=MAX_MANIFEST, label="toolchain pin manifest"
        )
        fresh_authorization: dict[str, Any] | None = None
        live_custody_hashes: tuple[str, str, str] | None = None
        if not self.test_only:
            if (
                self.custody_hashes is None
                or self.custody_bytes is None
                or self.issuance_path is None
                or self.issuance_repo is None
            ):
                raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
            tools_dir = self.pin_manifest.resolve(strict=True).parent
            controller_data = _bind_regular_file_from_parent(
                tools_dir / CONTROLLER_NAME,
                max_size=MAX_CONTROLLER,
                label="Google Cloud CLI custody controller",
            )
            trust_data = _bind_regular_file_from_parent(
                tools_dir / TRUST_ANCHOR_NAME,
                max_size=MAX_TRUST,
                label="Google Cloud CLI custody trust-anchor",
            )
            live_custody_bytes = (controller_data, manifest_data, trust_data)
            live_custody_hashes = tuple(
                hashlib.sha256(data).hexdigest() for data in live_custody_bytes
            )
            if (
                live_custody_bytes != self.custody_bytes
                or live_custody_hashes != self.custody_hashes
            ):
                raise GcloudCustodyError(
                    "Google Cloud CLI custody components changed during execution"
                )
            issuance = _bind_owner_issuance(
                self.issuance_path,
                repo=self.issuance_repo,
                authority_path=self.authority_path,
                owner_uid=self.authority_owner_uid,
            )
            fresh_authorization = _validate_signed_receipt_authorization(
                issuance["receipt"], require_fresh=True
            )
        pin = parse_google_cloud_cli_pin_document(manifest_data)
        if (
            current_platform_key() != self.platform_key
            or pin["version"] != self.version
            or pin["archive_name"][self.platform_key] != self.archive_name
            or pin["archive_sha256"][self.platform_key] != self.archive_sha256
        ):
            raise GcloudCustodyError("Google Cloud CLI reviewed pin changed during execution")
        if _resolve_executable(self.executable) != self.executable:
            raise GcloudCustodyError("Google Cloud CLI executable changed during execution")
        if _file_identity(self.executable, "Google Cloud CLI executable") != self.executable_identity:
            raise GcloudCustodyError("Google Cloud CLI executable identity changed during execution")
        receipt_bytes = _bind_regular_file_from_parent(
            self.receipt, max_size=MAX_TRUST, label="Google Cloud CLI custody receipt"
        )
        if _file_identity(self.receipt, "Google Cloud CLI custody receipt") != self.receipt_identity:
            raise GcloudCustodyError("Google Cloud CLI custody receipt changed during execution")
        if hashlib.sha256(receipt_bytes).hexdigest() != self.receipt_sha256:
            raise GcloudCustodyError("Google Cloud CLI custody receipt changed during execution")
        receipt = strict_json_bytes(receipt_bytes, "Google Cloud CLI custody receipt")
        recorded_tree, test_only = _validate_receipt(
            receipt,
            pin,
            self.platform_key,
            self.executable.name,
            install_root=self.install_root,
            expected_custody_hashes=live_custody_hashes,
            fresh_authorization=fresh_authorization,
            authority_path=self.authority_path,
            authority_owner_uid=self.authority_owner_uid,
        )
        if recorded_tree != self.tree_sha256 or test_only is not self.test_only:
            raise GcloudCustodyError("Google Cloud CLI custody receipt changed during execution")
        archive_bytes = _bind_regular_file_from_parent(
            self.custody_archive, max_size=MAX_ARCHIVE, label="Google Cloud CLI retained official archive"
        )
        if _file_identity(self.custody_archive, "Google Cloud CLI retained official archive") != self.archive_identity:
            raise GcloudCustodyError("Google Cloud CLI retained official archive changed during execution")
        if hashlib.sha256(archive_bytes).hexdigest() != self.archive_sha256:
            raise GcloudCustodyError("Google Cloud CLI retained official archive changed during execution")
        if install_tree_sha256(self.install_root) != self.tree_sha256:
            raise GcloudCustodyError("Google Cloud CLI installation tree changed during execution")

    @contextmanager
    def _production_private_runtime(
        self, credential: GcloudCredentialInput
    ) -> Iterator[PrivateGcloudRuntime]:
        authenticated = authenticate_credential(credential)
        with tempfile.TemporaryDirectory(prefix="winsvpn-gcloud-state-") as scratch_name:
            scratch = Path(scratch_name)
            os.chmod(scratch, 0o700)
            root_fd = -1
            executable_fd = -1
            credential_fd = -1
            subject_token_fd = -1
            python_fd = -1
            bound_credential: Path | None = None
            bound_subject_token: Path | None = None
            try:
                root_fd = os.open(self.install_root, _DIR_FLAGS)
                executable_path = self.install_root / "bin" / self.executable.name
                executable_fd = os.open(
                    f"bin/{self.executable.name}", _FILE_FLAGS, dir_fd=root_fd
                )
                _verify_presealed_production_runtime(
                    self.install_root,
                    root_fd,
                    expected_tree_sha256=self.tree_sha256,
                    executable=executable_path,
                )
                if _fd_identity(
                    executable_fd, "sealed Google Cloud CLI executable"
                ) != self.executable_identity:
                    raise GcloudCustodyError(
                        "sealed Google Cloud CLI executable identity does not match the signed runtime"
                    )

                if sys.platform == "darwin":
                    python_custody = _controller_python(
                        self.pin_manifest, production=True
                    )
                    python_path = python_custody.path
                    python_fd = os.open(python_path, _FILE_FLAGS)
                    python_data, python_identity = _stable_fd_bytes(
                        python_fd,
                        max_size=MAX_CONTROLLER * 16,
                        label="authenticated macOS release Python interpreter",
                    )
                    python_sha256 = hashlib.sha256(python_data).hexdigest()
                    if python_sha256 != python_custody.sha256:
                        raise GcloudCustodyError(
                            "authenticated macOS release Python changed before gcloud execution"
                        )
                elif sys.platform.startswith("linux"):
                    python_path = (
                        self.install_root / LINUX_BUNDLED_PYTHON_RELATIVE
                    )
                    python_fd = os.open(
                        LINUX_BUNDLED_PYTHON_RELATIVE,
                        _FILE_FLAGS,
                        dir_fd=root_fd,
                    )
                    python_data, python_identity = _stable_fd_bytes(
                        python_fd,
                        max_size=MAX_CONTROLLER * 16,
                        label="sealed Google Cloud CLI bundled Python interpreter",
                    )
                    python_sha256 = hashlib.sha256(python_data).hexdigest()
                    current_python_fd = os.open(
                        "/proc/self/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    )
                    try:
                        current_python = os.fstat(current_python_fd)
                        bundled_python = os.fstat(python_fd)
                    finally:
                        os.close(current_python_fd)
                    if (current_python.st_dev, current_python.st_ino) != (
                        bundled_python.st_dev,
                        bundled_python.st_ino,
                    ):
                        raise GcloudCustodyError(
                            "owner blocker: Linux custody controller must run from the bundled Python inside the sealed Google Cloud CLI tree"
                        )
                else:
                    raise GcloudCustodyError(EXECUTION_BLOCKER)

                home = scratch / "home"
                config = scratch / "config"
                tmp = scratch / "tmp"
                for directory in (
                    home,
                    config,
                    tmp,
                    home / ".config",
                    home / ".config" / "gcloud",
                ):
                    directory.mkdir(mode=0o700)
                identity_root = scratch / "identity"
                identity_root.mkdir(mode=0o700)
                if authenticated.subject_token is not None:
                    bound_subject_token = identity_root / "bound_subject_token"
                    subject_token_fd = _write_exclusive_held(
                        bound_subject_token, authenticated.subject_token, 0o400
                    )
                subject_token_reference: Path | None = None
                if subject_token_fd >= 0:
                    if sys.platform == "darwin":
                        subject_token_reference = Path(
                            f"/dev/fd/{DARWIN_SUBJECT_TOKEN_CHILD_FD}"
                        )
                    else:
                        subject_token_reference = Path(
                            f"/proc/self/fd/{subject_token_fd}"
                        )
                bound_credential = identity_root / "bound_credential.json"
                credential_bytes = _credential_snapshot_bytes(
                    authenticated, subject_token_reference
                )
                credential_fd = _write_exclusive_held(
                    bound_credential, credential_bytes, 0o400
                )
                credential_data, credential_identity = _stable_fd_bytes(
                    credential_fd,
                    max_size=MAX_CREDENTIAL,
                    label="Google Cloud CLI bound credential",
                )
                if credential_data != credential_bytes:
                    raise GcloudCustodyError(EXECUTION_BLOCKER)
                subject_identity: tuple[int, ...] | None = None
                if subject_token_fd >= 0:
                    subject_data, subject_identity = _stable_fd_bytes(
                        subject_token_fd,
                        max_size=MAX_SUBJECT_TOKEN,
                        label="Google Cloud CLI workload identity subject token",
                    )
                    if subject_data != authenticated.subject_token:
                        raise GcloudCustodyError(EXECUTION_BLOCKER)
                runtime = PrivateGcloudRuntime(
                    scratch=scratch,
                    root=self.install_root,
                    root_fd=root_fd,
                    executable_fd=executable_fd,
                    root_identity=_fd_identity(
                        root_fd, "sealed Google Cloud CLI root"
                    ),
                    executable_identity=_fd_identity(
                        executable_fd, "sealed Google Cloud CLI executable"
                    ),
                    home=home,
                    config=config,
                    tmp=tmp,
                    credential_file=bound_credential,
                    credential_fd=credential_fd,
                    credential_sha256=hashlib.sha256(credential_data).hexdigest(),
                    python=python_path,
                    python_fd=python_fd,
                    python_sha256=python_sha256,
                    python_identity=python_identity,
                    subject_token_file=bound_subject_token,
                    subject_token_fd=(
                        subject_token_fd if subject_token_fd >= 0 else None
                    ),
                    subject_token_sha256=(
                        hashlib.sha256(authenticated.subject_token).hexdigest()
                        if authenticated.subject_token is not None
                        else None
                    ),
                    subject_token_identity=subject_identity,
                    expected_project=credential.expected_project,
                    snapshot_tree_sha256=self.tree_sha256,
                    sealed=True,
                    credential_sealed=True,
                    executable_path=executable_path,
                    production_presealed=True,
                )
                yield runtime
                _verify_presealed_production_runtime(
                    self.install_root,
                    root_fd,
                    expected_tree_sha256=self.tree_sha256,
                    executable=executable_path,
                )
                if credential_identity != _fd_identity(
                    credential_fd, "Google Cloud CLI bound credential"
                ):
                    raise GcloudCustodyError(
                        "Google Cloud CLI bound credential changed during execution"
                    )
            finally:
                if credential_fd >= 0 and bound_credential is not None:
                    _secure_unlink_held(
                        credential_fd, bound_credential, max_size=MAX_CREDENTIAL
                    )
                    os.close(credential_fd)
                if subject_token_fd >= 0 and bound_subject_token is not None:
                    _secure_unlink_held(
                        subject_token_fd,
                        bound_subject_token,
                        max_size=MAX_SUBJECT_TOKEN,
                    )
                    os.close(subject_token_fd)
                if python_fd >= 0:
                    os.close(python_fd)
                if executable_fd >= 0:
                    os.close(executable_fd)
                if root_fd >= 0:
                    os.close(root_fd)

    @contextmanager
    def private_runtime(self, credential: GcloudCredentialInput) -> Iterator[PrivateGcloudRuntime]:
        """Yield an immutable production runtime or an explicitly test-only snapshot."""
        require_compatible_python()
        if not self.test_only:
            with self._production_private_runtime(credential) as runtime:
                yield runtime
            return
        authenticated = authenticate_credential(credential)
        python_custody = _controller_python(self.pin_manifest)
        with tempfile.TemporaryDirectory(prefix="winsvpn-gcloud-runtime-") as scratch_name:
            scratch = Path(scratch_name)
            os.chmod(scratch, 0o700)
            snapshot: Path | None = None
            clone: Path | None = None
            identity_root: Path | None = None
            python_root: Path | None = None
            bound_credential: Path | None = None
            bound_subject_token: Path | None = None
            bound_python: Path | None = None
            root_fd = -1
            executable_fd = -1
            credential_fd = -1
            subject_token_fd = -1
            python_fd = -1
            sealed = False
            credential_sealed = False
            python_sealed = False
            try:
                extracted = extract_official_archive_bytes(
                    self.archive_bytes,
                    self.archive_name,
                    scratch / "archive",
                )
                if install_tree_sha256(extracted) != self.runtime_tree_sha256:
                    raise GcloudCustodyError("private Google Cloud CLI runtime does not match the official archive")
                snapshot = scratch / "runtime"
                _snapshot_tree(extracted, snapshot)
                if install_tree_sha256(snapshot) != self.runtime_tree_sha256:
                    raise GcloudCustodyError("private Google Cloud CLI snapshot does not match the official archive")
                home = scratch / "home"
                config = scratch / "config"
                tmp = scratch / "tmp"
                home.mkdir(mode=0o700)
                config.mkdir(mode=0o700)
                tmp.mkdir(mode=0o700)
                (home / ".config").mkdir(mode=0o700)
                (home / ".config" / "gcloud").mkdir(mode=0o700)
                identity_root = scratch / "identity"
                identity_root.mkdir(mode=0o700)
                if authenticated.subject_token is not None:
                    bound_subject_token = identity_root / "bound_subject_token"
                    _write_exclusive(bound_subject_token, authenticated.subject_token, 0o400)
                    subject_token_fd = os.open(bound_subject_token, _FILE_FLAGS)
                bound_credential = identity_root / "bound_credential.json"
                credential_bytes = _credential_snapshot_bytes(
                    authenticated, bound_subject_token
                )
                _write_exclusive(bound_credential, credential_bytes, 0o400)
                credential_fd = os.open(bound_credential, _FILE_FLAGS)
                credential_sha256 = hashlib.sha256(credential_bytes).hexdigest()
                credential_bytes = b""
                _freeze_runtime_tree(identity_root)
                try:
                    identity_required = [bound_credential]
                    if bound_subject_token is not None:
                        identity_required.append(bound_subject_token)
                    _kernel_seal_tree(identity_root, *identity_required)
                    credential_sealed = True
                except GcloudCustodyError as exc:
                    if EXECUTION_BLOCKER not in str(exc) and "owner/environment blocker" not in str(exc):
                        raise
                    credential_sealed = False
                python_root = scratch / "python"
                python_root.mkdir(mode=0o700)
                bound_python = python_root / "python3"
                _write_exclusive(bound_python, python_custody.data, 0o500)
                python_fd = os.open(bound_python, _FILE_FLAGS)
                _freeze_runtime_tree(python_root)
                try:
                    _kernel_seal_tree(python_root, bound_python)
                    python_sealed = True
                except GcloudCustodyError as exc:
                    if EXECUTION_BLOCKER not in str(exc) and "owner/environment blocker" not in str(exc):
                        raise
                    python_sealed = False
                executable = snapshot / "bin" / self.executable.name
                if not os.access(executable, os.X_OK):
                    raise GcloudCustodyError("private Google Cloud CLI executable is not executable")
                _freeze_runtime_tree(snapshot)
                exec_root = snapshot
                try:
                    if sys.platform == "darwin":
                        clone = _clone_execution_tree(snapshot, scratch)
                        if install_tree_sha256(clone) != self.runtime_tree_sha256:
                            raise GcloudCustodyError("private Google Cloud CLI clone does not match the official archive")
                        _kernel_seal_tree(
                            clone, clone / "bin" / self.executable.name
                        )
                        exec_root = clone
                        sealed = True
                    elif sys.platform.startswith("linux"):
                        _kernel_seal_tree(snapshot, executable)
                        exec_root = snapshot
                        sealed = True
                    else:
                        raise GcloudCustodyError(EXECUTION_BLOCKER)
                except GcloudCustodyError as suc:
                    if EXECUTION_BLOCKER not in str(suc) and "owner/environment blocker" not in str(suc):
                        raise
                    sealed = False
                    exec_root = snapshot
                root_fd = os.open(exec_root, _DIR_FLAGS)
                executable_fd = os.open("bin/gcloud", _FILE_FLAGS, dir_fd=root_fd)
                if install_tree_sha256_from_fd(root_fd) != self.runtime_tree_sha256:
                    raise GcloudCustodyError("private Google Cloud CLI descriptor snapshot does not match the official archive")
                bound_python_data, bound_python_identity = (
                    _bind_regular_file_with_identity_from_parent(
                        bound_python,
                        max_size=MAX_CONTROLLER * 16,
                        label="private reviewed Python interpreter",
                    )
                )
                if hashlib.sha256(bound_python_data).hexdigest() != python_custody.sha256:
                    raise GcloudCustodyError("private reviewed Python interpreter custody failed")
                bound_subject_identity: tuple[int, ...] | None = None
                if bound_subject_token is not None:
                    bound_subject_data, bound_subject_identity = (
                        _bind_regular_file_with_identity_from_parent(
                            bound_subject_token,
                            max_size=MAX_SUBJECT_TOKEN,
                            label="private workload identity subject token",
                        )
                    )
                    if bound_subject_data != authenticated.subject_token:
                        raise GcloudCustodyError(EXECUTION_BLOCKER)
                runtime = PrivateGcloudRuntime(
                    scratch=scratch,
                    root=exec_root,
                    root_fd=root_fd,
                    executable_fd=executable_fd,
                    root_identity=_fd_identity(root_fd, "private Google Cloud CLI root"),
                    executable_identity=_fd_identity(executable_fd, "private Google Cloud CLI executable"),
                    home=home,
                    config=config,
                    tmp=tmp,
                    credential_file=bound_credential,
                    credential_fd=credential_fd,
                    credential_sha256=credential_sha256,
                    python=bound_python,
                    python_fd=python_fd,
                    python_sha256=python_custody.sha256,
                    python_identity=bound_python_identity,
                    subject_token_file=bound_subject_token,
                    subject_token_fd=(
                        subject_token_fd if subject_token_fd >= 0 else None
                    ),
                    subject_token_sha256=(
                        hashlib.sha256(authenticated.subject_token).hexdigest()
                        if authenticated.subject_token is not None
                        else None
                    ),
                    subject_token_identity=bound_subject_identity,
                    expected_project=credential.expected_project,
                    snapshot_tree_sha256=self.runtime_tree_sha256,
                    sealed=sealed and credential_sealed and python_sealed,
                    credential_sealed=credential_sealed,
                    executable_path=exec_root / "bin" / self.executable.name,
                )
                yield runtime
                if sealed and snapshot is not None and install_tree_sha256(snapshot) != self.runtime_tree_sha256:
                    raise GcloudCustodyError("private Google Cloud CLI snapshot changed during execution")
            finally:
                if credential_fd >= 0:
                    os.close(credential_fd)
                if subject_token_fd >= 0:
                    os.close(subject_token_fd)
                if python_fd >= 0:
                    os.close(python_fd)
                if executable_fd >= 0:
                    os.close(executable_fd)
                if root_fd >= 0:
                    os.close(root_fd)
                if clone is not None:
                    _destroy_runtime_tree(clone)
                if snapshot is not None:
                    _destroy_runtime_tree(snapshot)
                if identity_root is not None:
                    _destroy_runtime_tree(identity_root)
                if python_root is not None:
                    _destroy_runtime_tree(python_root)


def _freeze_runtime_tree(root: Path) -> None:
    directories: list[Path] = []
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        directories.append(base)
        for name in filenames:
            path = base / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise GcloudCustodyError("private Google Cloud CLI runtime contains an unsupported entry")
            os.chmod(path, 0o500 if info.st_mode & 0o111 else 0o400)
        dirnames.sort()
    for directory in reversed(directories):
        os.chmod(directory, 0o500)


def _resolve_executable(value: str | Path) -> Path:
    raw = os.fspath(value)
    selected = shutil.which(raw) if not os.path.isabs(raw) else raw
    if not selected:
        raise GcloudCustodyError("Google Cloud CLI executable was not found")
    path = Path(selected)
    try:
        if path.is_symlink():
            raise GcloudCustodyError("Google Cloud CLI executable must not be a symlink")
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
    except OSError as suc:
        raise GcloudCustodyError("Google Cloud CLI executable is unreadable") from suc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise GcloudCustodyError("Google Cloud CLI path is not an executable regular file")
    return resolved


def _validate_receipt(
    receipt: Any,
    pin: dict[str, Any],
    platform_key: str,
    executable_name: str,
    *,
    install_root: Path | None = None,
    expected_custody_hashes: tuple[str, str, str] | None = None,
    fresh_authorization: dict[str, Any] | None = None,
    authority_path: Path = OWNER_AUTHORITY_PATH,
    authority_owner_uid: int = 0,
) -> tuple[str, bool]:
    if type(receipt) is not dict:
        raise GcloudCustodyError("Google Cloud CLI custody receipt keys are not exact")
    test_only = receipt.get("test_only") is True
    expected_keys = TEST_RECEIPT_KEYS if test_only else RECEIPT_KEYS
    extra = set(receipt) - expected_keys
    if extra:
        raise GcloudCustodyError("Google Cloud CLI custody receipt has extra keys")
    if set(receipt) != expected_keys:
        raise GcloudCustodyError("Google Cloud CLI custody receipt keys are not exact")
    if test_only and receipt.get("test_only") is not True:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    expected = {
        "schema_version": 1,
        "contract": RECEIPT_CONTRACT,
        "version": pin["version"],
        "platform": platform_key,
        "archive_name": pin["archive_name"][platform_key],
        "archive_sha256": pin["archive_sha256"][platform_key],
        "executable_path": f"bin/{executable_name}",
    }
    for key, wanted in expected.items():
        observed = receipt.get(key)
        if type(observed) is bool or type(observed) is not type(wanted):
            raise GcloudCustodyError(f"Google Cloud CLI custody receipt {key} has the wrong type")
        if key == "version" and observed != wanted:
            raise GcloudCustodyError("Google Cloud CLI custody receipt version is stale")
        if observed != wanted:
            raise GcloudCustodyError(f"Google Cloud CLI custody receipt {key} is invalid")
    recorded_tree = receipt.get("install_tree_sha256")
    if type(recorded_tree) is not str:
        raise GcloudCustodyError("Google Cloud CLI custody receipt install_tree_sha256 has the wrong type")
    if not SHA_RE.fullmatch(recorded_tree) or recorded_tree == ZERO_SHA:
        raise GcloudCustodyError("Google Cloud CLI custody tree hash is invalid")
    if not test_only:
        if install_root is None or expected_custody_hashes is None:
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
        signature_hex = _exact_str(receipt.get("issuance_signature"), "issuance_signature")
        if ED25519_SIGNATURE_RE.fullmatch(signature_hex) is None:
            raise GcloudCustodyError("Google Cloud CLI custody receipt signature is invalid")
        authorized = dict(receipt)
        del authorized["issuance_signature"]
        _validate_signed_receipt_authorization(
            authorized, require_fresh=False
        )
        if fresh_authorization is None:
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
        _require_same_release_authorization(authorized, fresh_authorization)
        resolved_root = install_root.resolve(strict=True)
        root_sha = hashlib.sha256(str(resolved_root).encode("utf-8")).hexdigest()
        if authorized["install_root_sha256"] != root_sha:
            raise GcloudCustodyError("Google Cloud CLI custody receipt install root is invalid")
        expected_controller, expected_manifest, expected_trust = expected_custody_hashes
        if (
            authorized["controller_sha256"] != expected_controller
            or authorized["manifest_sha256"] != expected_manifest
            or authorized["trust_anchor_sha256"] != expected_trust
        ):
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
        authority_data = _bind_external_authority_file(
            authority_path,
            max_size=MAX_ISSUANCE,
            label="Google Cloud CLI owner authority",
            owner_uid=authority_owner_uid,
        )
        key_id, public_key = _parse_owner_authority(
            authority_data, authority_owner_uid
        )
        if authorized["authority_key_id"] != key_id or not _verify_ed25519(
            public_key,
            _owner_receipt_message(authorized),
            bytes.fromhex(signature_hex),
        ):
            raise GcloudCustodyError(OWNER_BLOCKED_TRUST)
    return recorded_tree, test_only


def _bind_installed_gcloud_to_authenticated_pin(
    value: str | Path,
    pin: dict[str, Any],
    manifest: Path,
    *,
    test_only: bool = False,
    fresh_authorization: dict[str, Any] | None = None,
    authority_path: Path = OWNER_AUTHORITY_PATH,
    authority_owner_uid: int = 0,
    issuance_path: Path | None = None,
    issuance_repo: Path | None = None,
) -> VerifiedGcloud:
    executable = _resolve_executable(value)
    if executable.parent.name != "bin" or executable.name not in {"gcloud", "gcloud.cmd"}:
        raise GcloudCustodyError("Google Cloud CLI executable is outside the canonical SDK layout")
    root = executable.parent.parent
    receipt_path = root / RECEIPT_NAME
    receipt_bytes = _bind_regular_file_from_parent(
        receipt_path, max_size=MAX_TRUST, label="Google Cloud CLI custody receipt"
    )
    receipt_info = receipt_path.lstat()
    if stat.S_IMODE(receipt_info.st_mode) != SEALED_PUBLIC_DATA_MODE:
        raise GcloudCustodyError("Google Cloud CLI custody receipt must be sealed mode 0444")
    receipt = strict_json_bytes(receipt_bytes, "Google Cloud CLI custody receipt")
    platform_key = current_platform_key()
    custody_hashes: tuple[str, str, str] | None = None
    custody_bytes: tuple[bytes, bytes, bytes] | None = None
    if receipt.get("test_only") is True:
        recorded_tree, receipt_test_only = _validate_receipt(
            receipt, pin, platform_key, executable.name
        )
        if not test_only:
            raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    else:
        if not test_only:
            tools_dir = manifest.resolve(strict=True).parent
            controller_data = _bind_regular_file_from_parent(
                tools_dir / CONTROLLER_NAME,
                max_size=MAX_CONTROLLER,
                label="Google Cloud CLI custody controller",
            )
            manifest_data = _bind_regular_file_from_parent(
                manifest.resolve(strict=True),
                max_size=MAX_MANIFEST,
                label="Google Cloud CLI pin manifest",
            )
            trust_data = _bind_regular_file_from_parent(
                tools_dir / TRUST_ANCHOR_NAME,
                max_size=MAX_TRUST,
                label="Google Cloud CLI custody trust-anchor",
            )
            custody_hashes = (
                hashlib.sha256(controller_data).hexdigest(),
                hashlib.sha256(manifest_data).hexdigest(),
                hashlib.sha256(trust_data).hexdigest(),
            )
            custody_bytes = (controller_data, manifest_data, trust_data)
        recorded_tree, receipt_test_only = _validate_receipt(
            receipt,
            pin,
            platform_key,
            executable.name,
            install_root=root,
            expected_custody_hashes=custody_hashes,
            fresh_authorization=fresh_authorization,
            authority_path=authority_path,
            authority_owner_uid=authority_owner_uid,
        )
    if test_only is not receipt_test_only:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT if receipt_test_only else "Google Cloud CLI custody receipt keys are not exact")
    if not test_only and receipt_test_only:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    custody_archive = root / CUSTODY_ARCHIVE_NAME
    archive_identity = _file_identity(custody_archive, "Google Cloud CLI retained official archive")
    if archive_identity[-1] != SEALED_PUBLIC_DATA_MODE:
        raise GcloudCustodyError("Google Cloud CLI retained official archive must be sealed mode 0444")
    archive_bytes = _bind_regular_file_from_parent(
        custody_archive, max_size=MAX_ARCHIVE, label="Google Cloud CLI retained official archive"
    )
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    if archive_sha256 != pin["archive_sha256"][platform_key]:
        raise GcloudCustodyError("retained Google Cloud CLI archive does not match the reviewed pin")
    with tempfile.TemporaryDirectory(prefix="winsvpn-gcloud-verify-") as scratch_name:
        scratch = Path(scratch_name)
        extracted = extract_official_archive_bytes(
            archive_bytes,
            pin["archive_name"][platform_key],
            scratch / "archive",
        )
        runtime_tree = install_tree_sha256(extracted)
        retained_copy = extracted / CUSTODY_ARCHIVE_NAME
        retained_copy.write_bytes(archive_bytes)
        os.chmod(retained_copy, SEALED_PUBLIC_DATA_MODE)
        expected_tree = install_tree_sha256(extracted)
    observed_tree = install_tree_sha256(root)
    if observed_tree != recorded_tree or expected_tree != recorded_tree:
        raise GcloudCustodyError("Google Cloud CLI installation tree does not match its reviewed archive")
    return VerifiedGcloud(
        executable=executable,
        install_root=root,
        receipt=receipt_path,
        receipt_sha256=hashlib.sha256(receipt_bytes).hexdigest(),
        tree_sha256=observed_tree,
        runtime_tree_sha256=runtime_tree,
        version=pin["version"],
        platform_key=platform_key,
        archive_name=pin["archive_name"][platform_key],
        archive_sha256=archive_sha256,
        custody_archive=custody_archive,
        pin_manifest=manifest,
        authority_path=authority_path,
        authority_owner_uid=authority_owner_uid,
        receipt_identity=_file_identity(receipt_path, "Google Cloud CLI custody receipt"),
        archive_identity=archive_identity,
        executable_identity=_file_identity(executable, "Google Cloud CLI executable"),
        test_only=receipt_test_only,
        custody_hashes=custody_hashes,
        custody_bytes=custody_bytes,
        issuance_path=issuance_path,
        issuance_repo=issuance_repo,
        archive_bytes=archive_bytes,
        pin=pin,
    )


def bind_test_only_installed_gcloud(value: str | Path, pin: dict[str, Any], manifest: Path) -> VerifiedGcloud:
    """TEST ONLY. Structurally unable to satisfy production verify_installed_gcloud."""
    require_compatible_python()
    verified = _bind_installed_gcloud_to_authenticated_pin(value, pin, manifest, test_only=True)
    if not verified.test_only:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    return verified


def verify_installed_gcloud(value: str | Path, *, pin_manifest: Path | None = None) -> VerifiedGcloud:
    require_compatible_python()
    manifest, pin, issuance = (
        _authorize_repository_google_cloud_cli_pin_with_issuance(pin_manifest)
    )
    verified = _bind_installed_gcloud_to_authenticated_pin(
        value,
        pin,
        manifest,
        test_only=False,
        fresh_authorization=issuance["receipt"],
        issuance_path=OWNER_ISSUANCE_PATH,
        issuance_repo=_repository_tools_dir().parent,
    )
    if verified.test_only:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    return verified


_BOUND_PRODUCTION_RUNNERS: weakref.WeakKeyDictionary[
    "CustodyRunner", tuple[VerifiedGcloud, GcloudCredentialInput, str]
] = weakref.WeakKeyDictionary()
_ATTESTED_PRODUCTION_RUNNERS: weakref.WeakKeyDictionary[
    "CustodyRunner", tuple[VerifiedGcloud, GcloudCredentialInput, str]
] = weakref.WeakKeyDictionary()


class CustodyRunner:
    """Run gcloud from an immutable runtime; sanitize every other argv."""

    def __init__(
        self,
        delegate: Any,
        verified: VerifiedGcloud,
        credential: GcloudCredentialInput | None = None,
    ):
        if credential is None or not isinstance(credential, GcloudCredentialInput):
            raise GcloudCustodyError(MISSING_IDENTITY)
        self.delegate = delegate
        self.verified = verified
        self.credential = credential
        self.test_only = bool(getattr(verified, "test_only", True))

    TEST_ONLY = False

    def _production_binding(self) -> tuple[VerifiedGcloud, GcloudCredentialInput, str] | None:
        binding = _BOUND_PRODUCTION_RUNNERS.get(self)
        if not (
            type(self) is CustodyRunner
            and self.test_only is False
            and binding is not None
            and binding[0] is self.verified
            and binding[1] is self.credential
            and binding[2] == self.verified.receipt_sha256
        ):
            return None
        return binding

    def _record_successful_sealed_execution(self, result: Any) -> None:
        binding = self._production_binding()
        if (
            binding is None
            or type(result) is not CustodyRunResult
            or type(result.exit_code) is not int
            or result.exit_code != 0
        ):
            return
        _ATTESTED_PRODUCTION_RUNNERS[self] = binding

    def production_pass_allowed(self) -> bool:
        binding = self._production_binding()
        if binding is None or _ATTESTED_PRODUCTION_RUNNERS.get(self) != binding:
            return False
        try:
            authenticate_credential(self.credential)
            self.verified.verify_unchanged()
        except Exception:
            _ATTESTED_PRODUCTION_RUNNERS.pop(self, None)
            return False
        return (
            self._production_binding() == binding
            and _ATTESTED_PRODUCTION_RUNNERS.get(self) == binding
        )

    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> Any:
        if not argv:
            raise GcloudCustodyError("empty Google Cloud CLI argv")
        if Path(argv[0]).name not in {"gcloud", "gcloud.cmd"}:
            with sanitized_delegated_environment():
                return self.delegate.run(list(argv), timeout_seconds=timeout_seconds)
        _ATTESTED_PRODUCTION_RUNNERS.pop(self, None)
        authenticate_credential(self.credential)
        self.verified.verify_unchanged()
        with self.verified.private_runtime(self.credential) as runtime:
            result = runtime.run(list(argv[1:]), timeout_seconds=timeout_seconds)
        self.verified.verify_unchanged()
        self._record_successful_sealed_execution(result)
        return result

    def run_ssh_pipe(
        self,
        producer_argv: Sequence[str],
        consumer_argv: Sequence[str],
        *,
        timeout_seconds: int,
        consumer_response_validator: Callable[[bytes], bytes] | None = None,
    ) -> CustodyRunResult:
        """Authenticated two-process SSH pipe. Reverify custody before and after."""
        validator = _require_canonical_ssh_pipe_validator(consumer_response_validator)
        _require_pipe_timeout(timeout_seconds)
        producer_args = validate_fixed_gcloud_ssh_argv(producer_argv)
        consumer_args = validate_fixed_gcloud_ssh_argv(consumer_argv)
        _ATTESTED_PRODUCTION_RUNNERS.pop(self, None)
        require_bound_project(self.credential, _ssh_flag_value(producer_args[3], "--project="))
        require_bound_project(self.credential, _ssh_flag_value(consumer_args[3], "--project="))
        authenticate_credential(self.credential)
        try:
            self.verified.verify_unchanged()
            with self.verified.private_runtime(self.credential) as runtime:
                result = runtime.run_ssh_pipe(
                    producer_args,
                    consumer_args,
                    timeout_seconds=timeout_seconds,
                    consumer_response_validator=validator,
                )
        finally:
            self.verified.verify_unchanged()
        self._record_successful_sealed_execution(result)
        return result


def runner_may_emit_production_pass(runner: Any) -> bool:
    if type(runner) is not CustodyRunner:
        return False
    if getattr(type(runner), "TEST_ONLY", False) is True:
        return False
    marker = getattr(runner, "production_pass_allowed", None)
    if not callable(marker):
        return False
    return marker() is True


def bind_production_runner(
    delegate: Any,
    gcloud_bin: str | Path,
    credential: GcloudCredentialInput,
    *,
    pin_manifest: Path | None = None,
) -> CustodyRunner:
    """Stable production call boundary other modules can call.

    Requires an exact descriptor-authenticated service-account or workload
    identity input and a genuinely external authenticated trust root.
    """
    if not isinstance(credential, GcloudCredentialInput):
        raise GcloudCustodyError(MISSING_IDENTITY)
    authenticate_credential(credential)
    verified = verify_installed_gcloud(gcloud_bin, pin_manifest=pin_manifest)
    if verified.test_only:
        raise GcloudCustodyError(TEST_ONLY_RECEIPT)
    runner = CustodyRunner(delegate, verified, credential)
    _BOUND_PRODUCTION_RUNNERS[runner] = (
        verified,
        credential,
        verified.receipt_sha256,
    )
    if runner._production_binding() is None:
        raise GcloudCustodyError(TEST_ONLY_RUNNER)
    return runner
