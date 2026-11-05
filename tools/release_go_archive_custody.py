#!/usr/bin/env python3
"""Provision, prepare, verify, run, and clean the Go release runtime.

The ``tools.go`` pin binds this macOS arm64 custody schema:

    tools.go.version
    tools.go.platform
    tools.go.architecture
    tools.go.archive_format
    tools.go.archive_path.darwin_arm64
    tools.go.archive_sha256.darwin_arm64
    tools.go.install_tree_sha256.darwin_arm64
    tools.go.top_level_root
    tools.go.executable
    tools.go.executable_sha256

``version`` is the exact stable dotted release, ``platform`` is
``darwin-arm64``, ``architecture`` is ``arm64``, ``archive_format`` is
``tar.gz``, ``top_level_root`` is ``go``, and ``executable`` is ``bin/go``.
The versioned archive basename must be ``go<version>.darwin-arm64.tar.gz``.
Bounded PAX ``path`` records are authenticated; symlink targets are resolved
only after the effective PAX path is known. Global PAX, hardlinks, specials,
duplicates, collisions, traversal, ACLs, non-OS xattrs, and gzip bombs are
refused. Adjacent trust-anchor hashes are a local pin only. Authorization
requires a genuinely external owner issuance contract from
``WINS_GO_CUSTODY_ISSUANCE`` or fails closed owner-blocked. A one-time,
authenticated root provisioning action publishes the exact Go tree at
``/Library/WinsVPN/ReleaseGo/<version>`` with root ownership, 0555/0444
modes, and ``SF_IMMUTABLE``. Routine release use is always non-root and
creates only private HOME/TMP state. The freeze producer is bound by digest
and is never exec'd. ``run`` keeps the executable descriptor and every
execution parent bound through spawn, or fails closed before candidate Go.
Linux Ubuntu 24.04 uses FS_IMMUTABLE only for synthetic hostile coverage;
the production pin is darwin-arm64. TAR names are NFKC plus casefold
canonical. Cleanup is descriptor-relative, symlink-safe, residue-fatal,
and never attempts to remove the owner-provisioned runtime.
"""

from __future__ import annotations

import array
import base64
import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import zlib


MAX_ARCHIVE = 128 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
MAX_TRUST = 64 * 1024
MAX_ISSUANCE = 64 * 1024
MAX_FREEZE_PRODUCER = 4 * 1024 * 1024
MAX_EXPANDED = 768 * 1024 * 1024
MAX_MEMBER = 384 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_RATIO = 250
MAX_DECODE_CHUNK = 8 * 1024 * 1024
MAX_PATH_BYTES = 1024
MAX_DEPTH = 32
MAX_PAX = 4096
MAX_PAX_RECORDS = 8
DEFAULT_RUN_TIMEOUT = 3600
MAX_RUN_TIMEOUT = 21600
BLOCK = 512
ARM64_CPU_TYPE = 0x0100000C
VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
ISSUANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
ISO_UTC = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PLATFORM = "darwin-arm64"
ARCHITECTURE = "arm64"
ARCHIVE_FORMAT = "tar.gz"
ROOT_NAME = "go"
EXECUTABLE = "bin/go"
RUNTIME_PREFIX = "wins-release-go."
PRIVATE_TMP = Path("/private/tmp")
OWNER_LIBRARY_ROOT = Path("/Library/WinsVPN")
OWNER_RUNTIME_PREFIX = OWNER_LIBRARY_ROOT / "ReleaseGo"
OWNER_BOOTSTRAP_PREFIX = OWNER_LIBRARY_ROOT / "ReleaseGoBootstrap"
PRODUCTION_AUTHORITY_PREFIX = OWNER_LIBRARY_ROOT / "ReleaseGoAuthority" / "v1"
PRODUCTION_AUTHORITY_PATH = PRODUCTION_AUTHORITY_PREFIX / "authority.json"
OWNER_AUTHORITY_PREFIX = PRODUCTION_AUTHORITY_PREFIX
OWNER_AUTHORITY_PATH = PRODUCTION_AUTHORITY_PATH
OWNER_RECEIPT_NAME = "custody-receipt.json"
BOOTSTRAP_RECEIPT_NAME = "bootstrap-receipt.json"
CONTROLLER_NAME = "release_go_archive_custody.py"
WRAPPER_NAME = "release_go_archive_custody.sh"
PROVISIONER_NAME = "provision_macos_release_go_runtime.sh"
MANIFEST_NAME = "toolchain-pins.json"
TRUST_ANCHOR_NAME = "release_go_archive_custody.trust.json"
TRUST_CONTRACT = "winsvpn-go-archive-custody-trust-v1"
AUTHORITY_CONTRACT = "winsvpn-go-archive-custody-authority-v1"
ISSUANCE_CONTRACT = "winsvpn-go-archive-custody-issuance-v2"
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256-x962"
ISSUANCE_ENV = "WINS_GO_CUSTODY_ISSUANCE"
ISSUANCE_ISSUER = "winsvpn-go-archive-custody"
SOURCE_FREEZE_PRODUCER = "release_source_freeze.py"
REVIEWED_ISSUANCE_UTC = dt.datetime(2026, 8, 19, 0, 0, 0, tzinfo=dt.timezone.utc)
MAX_ISSUANCE_AGE = dt.timedelta(hours=72)
MAX_ISSUANCE_SKEW = dt.timedelta(minutes=5)
GO_KEYS = (
    "version",
    "platform",
    "architecture",
    "archive_format",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
    "top_level_root",
    "executable",
    "executable_sha256",
    "review_status",
    "note",
    "compatibility_note",
)
GO_STRING_KEYS = (
    "version",
    "platform",
    "architecture",
    "archive_format",
    "top_level_root",
    "executable",
    "executable_sha256",
    "review_status",
    "note",
    "compatibility_note",
)
PLATFORM_KEYS = ("darwin_arm64",)
# Optional tools.go fields this controller does not consume but must accept.
# executable_sha256_by_platform carries the bin/go digest of the other hosts
# (tools/winn_release.py, tools/build_winn_protocol_engine.sh and
# tools/build_linux_release.sh read it); darwin_arm64 stays in
# executable_sha256 only, so the two can never disagree.
GO_OPTIONAL_KEYS = ("executable_sha256_by_platform",)
EXECUTABLE_BY_PLATFORM_KEYS = (
    "darwin_amd64",
    "linux_amd64",
    "linux_arm64",
    "windows_amd64",
    "windows_arm64",
)
ARCHIVE_SHA256_KEYS = (
    "darwin_amd64",
    "darwin_arm64",
    "linux_amd64",
    "linux_arm64",
    "windows_amd64",
    "windows_arm64",
)
TRUST_KEYS = (
    "contract",
    "schema_version",
    "controller",
    "wrapper",
    "provisioner",
    "manifest",
    "trust_anchor",
    "issuance_env",
    "issuance_contract",
    "authority",
    "authority_contract",
    "signature_algorithm",
    "controller_sha256",
    "wrapper_sha256",
    "provisioner_sha256",
    "manifest_sha256",
)
ISSUANCE_KEYS = (
    "contract",
    "schema_version",
    "issuance_id",
    "created_utc",
    "sequence",
    "expires_utc",
    "issuer",
    "authority_key_id",
    "signature_algorithm",
    "controller",
    "wrapper",
    "provisioner",
    "manifest",
    "trust_anchor",
    "source_freeze_producer",
    "controller_sha256",
    "wrapper_sha256",
    "provisioner_sha256",
    "manifest_sha256",
    "trust_anchor_sha256",
    "source_freeze_producer_sha256",
    "signature_base64",
)
AUTHORITY_KEYS = (
    "contract",
    "schema_version",
    "key_id",
    "signature_algorithm",
    "public_key_pem_base64",
    "active_issuance_id",
    "active_sequence",
    "not_before_utc",
)
OWNER_RECEIPT_KEYS = (
    "contract",
    "schema_version",
    "version",
    "runtime",
    "sealed_bootstrap",
    "sealed_bootstrap_identity",
    "archive_name",
    "archive_size",
    "archive_sha256",
    "tree_sha256",
    "executable",
    "executable_sha256",
    "controller_sha256",
    "wrapper_sha256",
    "provisioner_sha256",
    "manifest_sha256",
    "trust_anchor_sha256",
    "source_freeze_producer_sha256",
    "provisioned_issuance_id",
)
OWNER_RECEIPT_CONTRACT = "winsvpn-go-owner-runtime-v1"
BOOTSTRAP_RECEIPT_CONTRACT = "winsvpn-go-sealed-bootstrap-v1"
BOOTSTRAP_RECEIPT_KEYS = (
    "contract",
    "schema_version",
    "identity",
    "path",
    "version",
    "archive_name",
    "archive_size",
    "archive_sha256",
    "tree_sha256",
    "executable",
    "executable_sha256",
    "controller_sha256",
    "wrapper_sha256",
    "provisioner_sha256",
    "manifest_sha256",
    "trust_anchor_sha256",
    "source_freeze_producer_sha256",
)
GZIP_FLAG_FTEXT = 0x01
GZIP_FLAG_FNAME = 0x08
GZIP_ALLOWED_FLAGS = GZIP_FLAG_FTEXT | GZIP_FLAG_FNAME
CLONE_NOFOLLOW = 0x0001
POSIX_SPAWN_SETSID = 0x0400
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
FS_IMMUTABLE_FL = 0x00000010
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Go tree "
    "immutable against same-user path replacement through execution"
)
MACOS_BLOCKER = "owner/environment blocker: macOS kernel-bound Go execution is required"
LINUX_UNSUPPORTED = (
    "owner/environment blocker: Ubuntu 24.04 Linux FS_IMMUTABLE custody is "
    "unsupported on this host before Go execution"
)
FREEZE_BLOCKER = (
    "authenticated current source-freeze producer digest is required; "
    "unauthenticated freeze source is never executed"
)
OWNER_BLOCKED_UNAVAILABLE = (
    "owner blocked: current reviewed Go custody issuance identity is unavailable"
)
OWNER_BLOCKED_WRITABLE = (
    "owner blocked: current reviewed Go custody issuance identity is writable"
)
OWNER_BLOCKED_ADJACENT = (
    "owner blocked: Go custody issuance must be external to the candidate repository"
)
XATTR_NOFOLLOW = 0x0001
ACL_TYPE_EXTENDED = 0x00000100
ALLOWED_XATTRS = {b"com.apple.provenance"}
GO_ENV_ALLOWLIST = {
    "GOOS",
    "GOARCH",
    "GOARM",
    "GOAMD64",
    "CGO_ENABLED",
    "CC",
    "CXX",
    "CGO_CFLAGS",
    "CGO_CPPFLAGS",
    "CGO_CXXFLAGS",
    "CGO_LDFLAGS",
    "GOMODCACHE",
    "GOCACHE",
    "GOPRIVATE",
    "GONOPROXY",
    "GONOSUMDB",
    "GODEBUG",
    "GOTELEMETRY",
}
REFUSED_INHERITED_GO_ENV = {
    "GOEXPERIMENT",
    "GOFLAGS",
    "GOPROXY",
    "GOSUMDB",
    "GOWORK",
}
ALLOWED_CUSTODY_ENV = {
    ISSUANCE_ENV,
    "WINS_RELEASE_GO_ROOT",
    "WINS_RELEASE_GO_RUNTIME",
    "WINS_RELEASE_GO_RUNTIME_ID",
    "WINS_RELEASE_GO_SHA256",
    "WINS_RELEASE_GO_TREE_SHA256",
}
CGO_HOST_ENV_ALLOWLIST = {
    "SDKROOT",
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "TVOS_DEPLOYMENT_TARGET",
    "WATCHOS_DEPLOYMENT_TARGET",
    "PKG_CONFIG_PATH",
}
_LIBC = None
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
    _LIBC.posix_spawn_file_actions_destroy.restype = ctypes.c_int
    _LIBC.listxattr.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_int,
    ]
    _LIBC.listxattr.restype = ctypes.c_ssize_t
    _LIBC.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _LIBC.removexattr.restype = ctypes.c_int
    _LIBC.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    _LIBC.acl_get_link_np.restype = ctypes.c_void_p
    _LIBC.acl_free.argtypes = [ctypes.c_void_p]
    _LIBC.acl_free.restype = ctypes.c_int
    if hasattr(_LIBC, "lchflags"):
        _LIBC.lchflags.argtypes = [ctypes.c_char_p, ctypes.c_ulong]
        _LIBC.lchflags.restype = ctypes.c_int


class Refused(ValueError):
    """A fail-closed custody refusal."""


def fail(message: str) -> None:
    raise Refused(message)


def _nofollow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required for Go custody")
    return flag


def _cloexec_flag() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _open_flags() -> int:
    return os.O_RDONLY | _cloexec_flag() | _nofollow_flag()


def _trusted_input_uids() -> set[int]:
    """Return identities allowed to own reviewed inputs for this invocation."""
    allowed = {0, os.getuid()}
    if os.geteuid() == 0:
        raw = os.environ.get("SUDO_UID", "")
        if raw.isdigit() and int(raw) > 0:
            allowed.add(int(raw))
    return allowed


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _pathname_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
    )


def _private_tmp() -> Path:
    if sys.platform == "darwin":
        return PRIVATE_TMP
    if sys.platform.startswith("linux"):
        return Path("/var/tmp")
    fail(EXECUTION_BLOCKER)
    raise AssertionError("unreachable")


def _require_darwin_libc():
    if sys.platform != "darwin" or _LIBC is None:
        fail(MACOS_BLOCKER)
    return _LIBC


def _posix_errno(rc: int, what: str) -> OSError:
    return OSError(rc, f"{what}: {os.strerror(rc)}")


def _must(rc: int, what: str) -> None:
    if rc:
        raise _posix_errno(rc if rc > 0 else ctypes.get_errno(), what)


def digest_file(path: Path) -> str:
    fd = os.open(path, _open_flags())
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"hashed Go file must be one regular non-hardlinked file: {path}")
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = path.lstat()
    if not (_identity(before) == _identity(after) == _identity(latest)):
        fail(f"file changed while it was hashed: {path}")
    return digest.hexdigest()


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while block := os.read(fd, 1024 * 1024):
        digest.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _safe_parent_components(path: Path) -> None:
    if not path.is_absolute():
        fail(f"path is not absolute: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        if part in {"", ".", ".."}:
            fail(f"unsafe path component: {path}")
        current /= part
        info = current.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            fail(f"symbolic path component rejected: {current}")
        if not stat.S_ISDIR(info.st_mode):
            fail(f"non-directory path component rejected: {current}")
        if info.st_uid not in _trusted_input_uids():
            fail(f"foreign-owned path component rejected: {current}")
        if mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX):
            fail(f"unsafe writable path component rejected: {current}")


def _safe_path_components(path: Path) -> None:
    _safe_parent_components(path)
    if not path.parts[1:]:
        fail(f"path is not absolute: {path}")
    info = path.lstat()
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISLNK(info.st_mode):
        fail(f"symbolic path component rejected: {path}")
    if info.st_uid not in _trusted_input_uids():
        fail(f"foreign-owned path component rejected: {path}")
    if mode & 0o022 and not (
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and mode & stat.S_ISVTX
    ):
        fail(f"unsafe writable path component rejected: {path}")


def require_safe_input(path: Path, expected_name: str) -> None:
    if path.name != expected_name:
        fail("Go archive basename does not match its release identity")
    _safe_path_components(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid not in _trusted_input_uids()
    ):
        fail("Go archive must be one owner-controlled regular file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail("Go archive must have immutable mode 0444")


def bind_regular_file(path: Path, *, max_size: int, label: str) -> bytes:
    """Bind one O_NOFOLLOW single-link file from lstat through read.

    Path replacement between validation and open is refused because the
    opened descriptor identity must match the pre-open lstat snapshot.
    """
    _safe_parent_components(path)
    if path.name in {"", ".", ".."}:
        fail(f"unsafe path component: {path}")
    try:
        before = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is absent")
    if stat.S_ISLNK(before.st_mode):
        fail(f"{label} symbolic link rejected")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be one regular non-hardlinked file")
    if before.st_uid not in _trusted_input_uids():
        fail(f"{label} is not owner-controlled")
    if before.st_size <= 0 or before.st_size > max_size:
        fail(f"{label} size is outside the accepted range")
    fd = os.open(path, _open_flags())
    try:
        opened = os.fstat(fd)
        if _identity(before) != _identity(opened):
            fail(f"{label} was replaced before it was opened")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail(f"{label} must be one regular non-hardlinked file")
        chunks: list[bytes] = []
        while block := os.read(fd, 1024 * 1024):
            chunks.append(block)
        after = os.fstat(fd)
        if _identity(opened) != _identity(after):
            fail(f"{label} changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    if _identity(after) != _identity(latest):
        fail(f"{label} was replaced after it was opened")
    data = b"".join(chunks)
    if not data:
        fail(f"{label} snapshot is empty")
    return data


def snapshot_trust_roots(controller: Path, manifest: Path) -> tuple[bytes, bytes]:
    """Bind controller and manifest through one pair of descriptor snapshots."""
    controller_data = bind_regular_file(
        controller, max_size=MAX_CONTROLLER, label="Go custody controller"
    )
    manifest_data = bind_regular_file(
        manifest, max_size=MAX_MANIFEST, label="Go pin manifest"
    )
    if b"\0" in controller_data:
        fail("invalid Go custody controller source")
    if b"\0" in manifest_data:
        fail("Go pin manifest contains a NUL")
    return controller_data, manifest_data


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_trust_anchor(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Go custody trust-anchor contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go custody trust-anchor is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go custody trust-anchor is not JSON: {exc}")
    root = _mapping(document, "trust-anchor")
    _require_keys(root, TRUST_KEYS, "trust-anchor")
    if _text(root, "contract") != TRUST_CONTRACT:
        fail("Go custody trust-anchor contract mismatch")
    if _exact_int(root.get("schema_version"), "schema_version") != 1:
        fail("Go custody trust-anchor schema_version mismatch")
    if _text(root, "controller") != f"tools/{CONTROLLER_NAME}":
        fail("Go custody trust-anchor controller path mismatch")
    if _text(root, "wrapper") != f"tools/{WRAPPER_NAME}":
        fail("Go custody trust-anchor wrapper path mismatch")
    if _text(root, "provisioner") != f"tools/{PROVISIONER_NAME}":
        fail("Go custody trust-anchor provisioner path mismatch")
    if _text(root, "manifest") != f"tools/{MANIFEST_NAME}":
        fail("Go custody trust-anchor manifest path mismatch")
    if _text(root, "trust_anchor") != f"tools/{TRUST_ANCHOR_NAME}":
        fail("Go custody trust-anchor path mismatch")
    if _text(root, "issuance_env") != ISSUANCE_ENV:
        fail("Go custody trust-anchor issuance_env mismatch")
    if _text(root, "issuance_contract") != ISSUANCE_CONTRACT:
        fail("Go custody trust-anchor issuance_contract mismatch")
    if _text(root, "authority") != str(PRODUCTION_AUTHORITY_PATH):
        fail("Go custody trust-anchor authority path mismatch")
    if _text(root, "authority_contract") != AUTHORITY_CONTRACT:
        fail("Go custody trust-anchor authority_contract mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Go custody trust-anchor signature_algorithm mismatch")
    for key in (
        "controller_sha256",
        "wrapper_sha256",
        "provisioner_sha256",
        "manifest_sha256",
    ):
        if HEX_RE.fullmatch(_text(root, key)) is None:
            fail(f"invalid Go custody trust-anchor digest: {key}")
    return root


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _decode_base64(value: str, label: str, *, maximum: int) -> bytes:
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        fail(f"invalid base64 for {label}: {exc}")
    if not data or len(data) > maximum:
        fail(f"decoded {label} size is outside the accepted range")
    return data


def _parse_authority(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Go custody authority contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go custody authority is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go custody authority is not JSON: {exc}")
    root = _mapping(document, "authority")
    if data != _canonical_json_bytes(root):
        fail("Go custody authority is not canonical JSON")
    _require_keys(root, AUTHORITY_KEYS, "authority")
    if _text(root, "contract") != AUTHORITY_CONTRACT:
        fail("Go custody authority contract mismatch")
    if _exact_int(root.get("schema_version"), "authority schema_version") != 1:
        fail("Go custody authority schema_version mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Go custody authority signature_algorithm mismatch")
    public_key = _decode_base64(
        _text(root, "public_key_pem_base64"),
        "authority public key",
        maximum=16 * 1024,
    )
    if (
        not public_key.startswith(b"-----BEGIN PUBLIC KEY-----\n")
        or not public_key.endswith(b"-----END PUBLIC KEY-----\n")
        or b"PRIVATE KEY" in public_key
    ):
        fail("Go custody authority must contain one PEM public key")
    key_id = _text(root, "key_id")
    if HEX_RE.fullmatch(key_id) is None or key_id != _digest_bytes(public_key):
        fail("Go custody authority key_id mismatch")
    issuance_id = _text(root, "active_issuance_id")
    if ISSUANCE_RE.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Go custody authority active_issuance_id is invalid")
    sequence = _exact_int(root.get("active_sequence"), "authority active_sequence")
    if sequence <= 0:
        fail("Go custody authority active_sequence is invalid")
    not_before = _text(root, "not_before_utc")
    if ISO_UTC.fullmatch(not_before) is None:
        fail("Go custody authority not_before_utc must be exact ISO UTC")
    return root


def _verify_authority_path(path: Path, *, require_immutable: bool) -> bytes:
    if path != OWNER_AUTHORITY_PATH:
        fail("Go custody authority path mismatch")
    if not path.is_absolute():
        fail("Go custody authority path must be absolute")
    expected_uid, expected_gid = _owner_identity()
    current = Path(path.anchor)
    authority_roots = {OWNER_AUTHORITY_PREFIX.parent, OWNER_AUTHORITY_PREFIX}
    for part in path.parts[1:-1]:
        current /= part
        info = current.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"unsafe Go custody authority ancestor: {current}")
        writable = bool(mode & 0o022)
        sticky_root_boundary = (
            info.st_uid == 0
            and info.st_gid == 0
            and bool(mode & stat.S_ISVTX)
            and current not in authority_roots
        )
        if (
            info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or (writable and not sticky_root_boundary)
        ):
            fail(f"writable or foreign Go custody authority ancestor: {current}")
        if require_immutable and current in authority_roots:
            _require_system_immutable(info, f"authority ancestor {current}")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != expected_uid
        or info.st_gid != expected_gid
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        fail("Go custody authority file custody mismatch")
    if require_immutable:
        _require_system_immutable(info, "authority file")
    return bind_regular_file(path, max_size=MAX_TRUST, label="Go custody authority")


def _verify_system_openssl() -> Path:
    path = Path("/usr/bin/openssl")
    for parent in (Path("/usr"), Path("/usr/bin")):
        parent_info = parent.lstat()
        if (
            stat.S_ISLNK(parent_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_gid != 0
            or stat.S_IMODE(parent_info.st_mode) & 0o022
        ):
            fail("platform signature verifier ancestor custody mismatch")
    info = path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o111
    ):
        fail("platform signature verifier custody mismatch")
    return path


def _verify_issuance_signature(
    authority: dict[str, object], issuance: dict[str, object]
) -> None:
    signature = _decode_base64(
        _text(issuance, "signature_base64"),
        "issuance signature",
        maximum=1024,
    )
    public_key = _decode_base64(
        _text(authority, "public_key_pem_base64"),
        "authority public key",
        maximum=16 * 1024,
    )
    signed = dict(issuance)
    signed.pop("signature_base64", None)
    message = _canonical_json_bytes(signed)
    openssl = _verify_system_openssl()
    with tempfile.TemporaryFile(dir=str(_private_tmp())) as key_file, tempfile.TemporaryFile(
        dir=str(_private_tmp())
    ) as signature_file:
        key_file.write(public_key)
        signature_file.write(signature)
        key_file.flush()
        signature_file.flush()
        os.lseek(key_file.fileno(), 0, os.SEEK_SET)
        os.lseek(signature_file.fileno(), 0, os.SEEK_SET)
        completed = subprocess.run(
            [
                str(openssl),
                "dgst",
                "-sha256",
                "-verify",
                f"/dev/fd/{key_file.fileno()}",
                "-signature",
                f"/dev/fd/{signature_file.fileno()}",
            ],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": str(_private_tmp()),
                "TMPDIR": str(_private_tmp()),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
                "OPENSSL_CONF": "/dev/null",
            },
            pass_fds=(key_file.fileno(), signature_file.fileno()),
            close_fds=True,
            timeout=10,
            check=False,
        )
    if completed.returncode != 0 or completed.stdout.strip() != b"Verified OK":
        fail("Go custody issuance signature verification failed")


def _parse_issuance(
    data: bytes, authority: dict[str, object]
) -> dict[str, object]:
    if b"\0" in data:
        fail("Go custody issuance contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go custody issuance is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go custody issuance is not JSON: {exc}")
    root = _mapping(document, "issuance")
    if data != _canonical_json_bytes(root):
        fail("Go custody issuance is not canonical JSON")
    _require_keys(root, ISSUANCE_KEYS, "issuance")
    if _text(root, "contract") != ISSUANCE_CONTRACT:
        fail("Go custody issuance contract mismatch")
    if _exact_int(root.get("schema_version"), "issuance schema_version") != 2:
        fail("Go custody issuance schema_version mismatch")
    issuance_id = _text(root, "issuance_id")
    if ISSUANCE_RE.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Go custody issuance_id is not a current reviewed identity")
    created_text = _text(root, "created_utc")
    if ISO_UTC.fullmatch(created_text) is None:
        fail("Go custody issuance created_utc must be exact ISO UTC")
    expires_text = _text(root, "expires_utc")
    if ISO_UTC.fullmatch(expires_text) is None:
        fail("Go custody issuance expires_utc must be exact ISO UTC")
    created = dt.datetime.strptime(created_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    expires = dt.datetime.strptime(expires_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    now = dt.datetime.now(dt.timezone.utc)
    if created < REVIEWED_ISSUANCE_UTC:
        fail("Go custody issuance created_utc is stale")
    if created > now + MAX_ISSUANCE_SKEW:
        fail("Go custody issuance created_utc is future-dated")
    if now - created > MAX_ISSUANCE_AGE or expires <= now:
        fail("Go custody issuance created_utc is stale")
    if expires <= created or expires - created > MAX_ISSUANCE_AGE:
        fail("Go custody issuance validity interval is invalid")
    authority_not_before = dt.datetime.strptime(
        _text(authority, "not_before_utc"), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=dt.timezone.utc)
    if created < authority_not_before:
        fail("Go custody issuance predates the active authority")
    sequence = _exact_int(root.get("sequence"), "issuance sequence")
    if sequence != _exact_int(authority.get("active_sequence"), "authority sequence"):
        fail("Go custody issuance sequence is replayed or inactive")
    if issuance_id != _text(authority, "active_issuance_id"):
        fail("Go custody issuance identity is replayed or inactive")
    if _text(root, "issuer") != ISSUANCE_ISSUER:
        fail("Go custody issuance issuer mismatch")
    if _text(root, "authority_key_id") != _text(authority, "key_id"):
        fail("Go custody issuance authority key mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Go custody issuance signature_algorithm mismatch")
    if _text(root, "controller") != f"tools/{CONTROLLER_NAME}":
        fail("Go custody issuance controller path mismatch")
    if _text(root, "wrapper") != f"tools/{WRAPPER_NAME}":
        fail("Go custody issuance wrapper path mismatch")
    if _text(root, "provisioner") != f"tools/{PROVISIONER_NAME}":
        fail("Go custody issuance provisioner path mismatch")
    if _text(root, "manifest") != f"tools/{MANIFEST_NAME}":
        fail("Go custody issuance manifest path mismatch")
    if _text(root, "trust_anchor") != f"tools/{TRUST_ANCHOR_NAME}":
        fail("Go custody issuance trust-anchor path mismatch")
    if _text(root, "source_freeze_producer") != f"tools/{SOURCE_FREEZE_PRODUCER}":
        fail("Go custody issuance freeze-producer path mismatch")
    for key in (
        "controller_sha256",
        "wrapper_sha256",
        "provisioner_sha256",
        "manifest_sha256",
        "trust_anchor_sha256",
        "source_freeze_producer_sha256",
    ):
        digest = _text(root, key)
        if HEX_RE.fullmatch(digest) is None or digest == "0" * 64:
            fail(f"invalid Go custody issuance digest: {key}")
    _verify_issuance_signature(authority, root)
    return root


def _bind_external_issuance(
    repo: Path,
    *,
    authority_path: Path | None = None,
    require_authority_immutable: bool = True,
) -> dict[str, object]:
    raw = os.environ.get(ISSUANCE_ENV, "")
    if type(raw) is not str or not raw:
        fail(OWNER_BLOCKED_UNAVAILABLE)
    path = Path(raw)
    if not path.is_absolute():
        fail(OWNER_BLOCKED_UNAVAILABLE)
    if _path_is_within(path, repo):
        fail(OWNER_BLOCKED_ADJACENT)
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(OWNER_BLOCKED_UNAVAILABLE)
    if stat.S_ISLNK(info.st_mode):
        fail("Go custody issuance symbolic link rejected")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("Go custody issuance must be one regular non-hardlinked file")
    permitted_uids = {0, os.getuid()}
    if os.getuid() == 0 and os.geteuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID", "")
        if sudo_uid.isdigit() and int(sudo_uid) > 0:
            permitted_uids.add(int(sudo_uid))
    if info.st_uid not in permitted_uids:
        fail("Go custody issuance is not owner-controlled")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail(OWNER_BLOCKED_WRITABLE)
    authority_data = _verify_authority_path(
        authority_path or OWNER_AUTHORITY_PATH,
        require_immutable=require_authority_immutable,
    )
    authority = _parse_authority(authority_data)
    data = bind_regular_file(path, max_size=MAX_ISSUANCE, label="Go custody issuance")
    return _parse_issuance(data, authority)


def _bind_source_freeze_producer(repo: Path, expected_sha: str) -> bytes:
    producer = repo / "tools" / SOURCE_FREEZE_PRODUCER
    data = bind_regular_file(
        producer, max_size=MAX_FREEZE_PRODUCER, label="source-freeze producer"
    )
    if b"\0" in data:
        fail("invalid source-freeze producer source")
    if _digest_bytes(data) != expected_sha:
        fail(FREEZE_BLOCKER)
    return data


def _verify_source_freeze_receipt(repo: Path) -> None:
    """Bind the freeze producer digest. Never execute unauthenticated source."""
    del repo
    fail(FREEZE_BLOCKER)


def tools_dir_from_controller(controller: Path) -> Path:
    tools_dir = controller.resolve(strict=False).parent
    if tools_dir.name != "tools":
        fail("Go custody controller is not in the repository tools directory")
    return tools_dir


def authorize_snapshot(controller: Path) -> bytes:
    del controller
    fail("malicious or substituted Go custody controller rejected")
    raise AssertionError("unreachable")


def authorize_custody_inputs(
    controller: Path,
    manifest: Path,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Bind in-repo controller, wrapper, manifest, and trust-anchor.

    Caller-supplied absolute paths must be the exact in-repo identities.
    Adjacent trust hashes never self-authorize. External issuance is required.
    """
    if not controller.is_absolute() or not manifest.is_absolute():
        fail("Go custody tool and manifest must be absolute")
    tools_dir = tools_dir_from_controller(controller)
    repo = tools_dir.parent
    expected_controller = tools_dir / CONTROLLER_NAME
    expected_wrapper = tools_dir / WRAPPER_NAME
    expected_provisioner = tools_dir / PROVISIONER_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    expected_trust = tools_dir / TRUST_ANCHOR_NAME
    if controller != expected_controller:
        fail("malicious or substituted Go custody controller rejected")
    if manifest != expected_manifest:
        fail("replacement Go pin manifest cannot self-authorize")
    controller_data, wrapper_data, manifest_data, trust_data = authorize_repo(repo)
    return controller_data, wrapper_data, manifest_data, trust_data


def authorize_repo(
    repo: Path,
) -> tuple[bytes, bytes, bytes, bytes]:
    if not repo.is_absolute():
        fail("Go custody repository must be absolute")
    tools_dir = repo / "tools"
    expected_controller = tools_dir / CONTROLLER_NAME
    expected_wrapper = tools_dir / WRAPPER_NAME
    expected_provisioner = tools_dir / PROVISIONER_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    expected_trust = tools_dir / TRUST_ANCHOR_NAME
    controller_data, manifest_data = snapshot_trust_roots(
        expected_controller, expected_manifest
    )
    wrapper_data = bind_regular_file(
        expected_wrapper, max_size=MAX_CONTROLLER, label="Go custody wrapper"
    )
    provisioner_data = bind_regular_file(
        expected_provisioner,
        max_size=MAX_CONTROLLER,
        label="Go runtime provisioner",
    )
    trust_data = bind_regular_file(
        expected_trust, max_size=MAX_TRUST, label="Go custody trust-anchor"
    )
    if b"\0" in wrapper_data:
        fail("invalid Go custody wrapper source")
    if b"\0" in provisioner_data:
        fail("invalid Go runtime provisioner source")
    trust = _parse_trust_anchor(trust_data)
    if _digest_bytes(controller_data) != trust["controller_sha256"]:
        fail("Go custody controller digest does not match the trust-anchor")
    if _digest_bytes(wrapper_data) != trust["wrapper_sha256"]:
        fail("Go custody wrapper digest does not match the trust-anchor")
    if _digest_bytes(provisioner_data) != trust["provisioner_sha256"]:
        fail("Go runtime provisioner digest does not match the trust-anchor")
    if _digest_bytes(manifest_data) != trust["manifest_sha256"]:
        fail("Go pin manifest digest does not match the trust-anchor")
    issuance = _bind_external_issuance(repo)
    if _digest_bytes(controller_data) != issuance["controller_sha256"]:
        fail("Go custody controller digest does not match the external issuance")
    if _digest_bytes(wrapper_data) != issuance["wrapper_sha256"]:
        fail("Go custody wrapper digest does not match the external issuance")
    if _digest_bytes(provisioner_data) != issuance["provisioner_sha256"]:
        fail("Go runtime provisioner digest does not match the external issuance")
    if _digest_bytes(manifest_data) != issuance["manifest_sha256"]:
        fail("Go pin manifest digest does not match the external issuance")
    if _digest_bytes(trust_data) != issuance["trust_anchor_sha256"]:
        fail("Go custody trust-anchor digest does not match the external issuance")
    _bind_source_freeze_producer(repo, str(issuance["source_freeze_producer_sha256"]))
    return controller_data, wrapper_data, manifest_data, trust_data


def write_trust_snapshot(
    snap: Path, repo: Path, controller: Path, manifest: Path
) -> None:
    del snap, repo, controller, manifest
    fail("Go custody snapshot self-authorization is owner-blocked")


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _canonical_json_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"Go pin field must be an object: {label}")
    return value


def _text(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        fail(f"Go pin field must be one non-empty string: {key}")
    if any(ord(character) < 32 for character in value) or value.strip() != value:
        fail(f"Go pin field contains a control character: {key}")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int:
        fail(f"Go pin field must be an integer: {label}")
    return value


def _require_keys(mapping: dict[str, object], required: tuple[str, ...], label: str) -> None:
    missing = [key for key in required if key not in mapping]
    if missing:
        fail(f"Go pin field is absent: {label}.{missing[0]}")
    extra = [key for key in mapping if key not in required]
    if extra:
        fail(f"unexpected Go pin field rejected: {label}.{extra[0]}")


def parse_pin_bytes(data: bytes) -> dict[str, str]:
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go pin manifest is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go pin manifest is not JSON: {exc}")
    root = _mapping(document, "document")
    tools = _mapping(root.get("tools"), "tools")
    go = _mapping(tools.get("go"), "tools.go")
    _require_keys(
        {key: value for key, value in go.items() if key not in GO_OPTIONAL_KEYS},
        GO_KEYS,
        "tools.go",
    )
    for key in GO_STRING_KEYS:
        _text(go, key)
    if "executable_sha256_by_platform" in go:
        by_platform = _mapping(
            go.get("executable_sha256_by_platform"), "executable_sha256_by_platform"
        )
        for key in by_platform:
            if key not in EXECUTABLE_BY_PLATFORM_KEYS:
                fail(
                    "unexpected Go pin field rejected: "
                    f"executable_sha256_by_platform.{key}"
                )
            if HEX_RE.fullmatch(_text(by_platform, key)) is None:
                fail(f"invalid Go digest pin: executable_sha256_by_platform.{key}")
    paths = _mapping(go.get("archive_path"), "archive_path")
    archive_hashes = _mapping(go.get("archive_sha256"), "archive_sha256")
    tree_hashes = _mapping(go.get("install_tree_sha256"), "install_tree_sha256")
    _require_keys(paths, PLATFORM_KEYS, "archive_path")
    _require_keys(archive_hashes, ARCHIVE_SHA256_KEYS, "archive_sha256")
    _require_keys(tree_hashes, PLATFORM_KEYS, "install_tree_sha256")
    result = {
        "version": _text(go, "version"),
        "platform": _text(go, "platform"),
        "architecture": _text(go, "architecture"),
        "archive_format": _text(go, "archive_format"),
        "archive": _text(paths, "darwin_arm64"),
        "archive_sha": _text(archive_hashes, "darwin_arm64"),
        "tree_sha": _text(tree_hashes, "darwin_arm64"),
        "root": _text(go, "top_level_root"),
        "executable": _text(go, "executable"),
        "executable_sha": _text(go, "executable_sha256"),
    }
    for key in ARCHIVE_SHA256_KEYS:
        digest = _text(archive_hashes, key)
        if HEX_RE.fullmatch(digest) is None:
            fail(f"invalid Go digest pin: archive_sha256.{key}")
    if VERSION_RE.fullmatch(result["version"]) is None:
        fail("Go version pin must be an exact stable dotted version")
    if result["platform"] != PLATFORM or result["architecture"] != ARCHITECTURE:
        fail("Go platform or architecture pin mismatch")
    if result["archive_format"] != ARCHIVE_FORMAT:
        fail("only exact official Go tar.gz archives are accepted")
    if result["root"] != ROOT_NAME or result["executable"] != EXECUTABLE:
        fail("Go archive layout pin mismatch")
    for key in ("archive_sha", "tree_sha", "executable_sha"):
        if HEX_RE.fullmatch(result[key]) is None:
            fail(f"invalid Go digest pin: {key}")
    return result


def load_pin(manifest: Path) -> dict[str, str]:
    return parse_pin_bytes(
        bind_regular_file(manifest, max_size=MAX_MANIFEST, label="Go pin manifest")
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail("short write while copying the Go archive")
        view = view[written:]


def copy_stable(source: Path, destination: Path, expected_sha: str) -> None:
    source_fd = os.open(source, _open_flags())
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("Go archive must be one regular non-hardlinked file")
        hasher = hashlib.sha256()
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec_flag() | _nofollow_flag(),
            0o400,
        )
        while block := os.read(source_fd, 1024 * 1024):
            hasher.update(block)
            _write_all(destination_fd, block)
        os.fsync(destination_fd)
        after_source = os.fstat(source_fd)
        if hasher.hexdigest() != expected_sha or _identity(before) != _identity(after_source):
            fail("Go archive SHA-256 mismatch")
        if _identity(before) != _identity(source.lstat()):
            fail("Go archive changed during authenticated copying")
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
    if digest_file(destination) != expected_sha:
        fail("Go archive changed during authenticated copying")


def decompress_exact_gzip(archive: Path, output: Path) -> int:
    compressed_size = archive.stat().st_size
    if compressed_size <= 0 or compressed_size > MAX_ARCHIVE:
        fail("Go archive size is outside the accepted range")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    total = 0
    pending = b""
    with archive.open("rb") as source, output.open("xb") as target:
        header = source.read(10)
        if len(header) != 10 or header[:2] != b"\x1f\x8b" or header[2] != 8:
            fail("invalid Go gzip header")
        if header[3] & ~GZIP_ALLOWED_FLAGS:
            fail("Go gzip extra fields, comments, or header CRC are forbidden")
        source.seek(0)
        while True:
            if decoder.eof:
                if decoder.unused_data or source.read(1):
                    fail("Go gzip concatenated streams or trailing data are forbidden")
                break
            if not pending:
                pending = source.read(1024 * 1024)
                if not pending:
                    fail("Go gzip stream is truncated")
            remaining = min(
                MAX_EXPANDED - total + 1,
                compressed_size * MAX_RATIO - total + 1,
                MAX_DECODE_CHUNK,
            )
            if remaining <= 0:
                fail("Go archive expansion limit exceeded")
            try:
                expanded = decoder.decompress(pending, remaining)
            except zlib.error as exc:
                fail(f"invalid Go gzip stream: {exc}")
            pending = decoder.unconsumed_tail
            total += len(expanded)
            if total > MAX_EXPANDED or total > compressed_size * MAX_RATIO:
                fail("Go archive expansion limit exceeded")
            if expanded:
                target.write(expanded)
            elif not pending and not decoder.eof:
                fail("Go gzip decoder made no progress")
        target.flush()
        os.fsync(target.fileno())
    if total < BLOCK * 3 or total % BLOCK:
        fail("Go TAR framing is malformed")
    return total


def _tar_text(field: bytes, label: str) -> str:
    value, separator, padding = field.partition(b"\0")
    if separator and any(padding):
        fail(f"non-zero TAR padding in {label}")
    try:
        text = value.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        fail(f"non-UTF-8 TAR {label}: {exc}")
    if "\x00" in text:
        fail(f"embedded NUL in TAR {label}")
    return text


def _tar_number(field: bytes, label: str) -> int:
    if field and field[0] & 0x80:
        fail(f"base-256 TAR number rejected: {label}")
    value = field.strip(b" \0")
    if not value:
        return 0
    if any(byte not in b"01234567" for byte in value):
        fail(f"invalid TAR octal number: {label}")
    return int(value, 8)


def _raw_tar_components(
    name: str, *, directory: bool, label: str, allow_parent: bool = False
) -> tuple[str, ...]:
    if any(ord(character) < 32 for character in name):
        fail(f"{label} contains a control character")
    if unicodedata.normalize("NFKC", name) != name:
        fail(f"unsafe or non-canonical {label}")
    if not name or name.startswith("/") or "\\" in name:
        fail(f"unsafe or non-canonical {label}")
    if name.endswith("/"):
        if not directory:
            fail(f"unsafe or non-canonical {label}")
        body = name[:-1]
    else:
        body = name
    if (
        not body
        or "//" in name
        or "/./" in name
        or body.startswith("/")
        or body.endswith("/")
        or name.startswith("./")
    ):
        fail(f"unsafe or non-canonical {label}")
    parts = tuple(body.split("/"))
    forbidden = {"", "."} if allow_parent else {"", ".", ".."}
    if any(part in forbidden for part in parts):
        fail(f"unsafe or non-canonical {label}")
    if not allow_parent and any(part == ".." for part in parts):
        fail(f"unsafe or non-canonical {label}")
    if any(part != part.strip() for part in parts):
        fail(f"unsafe or non-canonical {label}")
    if not allow_parent:
        pure = PurePosixPath(body)
        if pure.as_posix() != body or pure.parts != parts:
            fail(f"unsafe or non-canonical {label}")
    return parts


def _member_path(name: str, expected_root: str, *, directory: bool) -> str:
    parts = _raw_tar_components(name, directory=directory, label="Go TAR member path")
    canonical = "/".join(parts)
    if len(canonical.encode("utf-8")) > MAX_PATH_BYTES:
        fail("Go TAR member path is too long")
    if len(parts) > MAX_DEPTH:
        fail("Go TAR member path exceeds the depth limit")
    if parts[0] != expected_root:
        fail("Go TAR member escaped its pinned top-level root")
    return canonical


def _symlink_target(member: str, target: str, expected_root: str) -> str:
    parts = _raw_tar_components(
        target,
        directory=False,
        label="Go TAR symbolic-link target",
        allow_parent=True,
    )
    resolved_parts = list(PurePosixPath(member).parent.parts)
    for part in parts:
        if part == "..":
            if len(resolved_parts) <= 1:
                fail("Go TAR symbolic link escaped its pinned top-level root")
            resolved_parts.pop()
        else:
            resolved_parts.append(part)
    if not resolved_parts or resolved_parts[0] != expected_root:
        fail("Go TAR symbolic link escaped its pinned top-level root")
    resolved = PurePosixPath(*resolved_parts).as_posix()
    if len(target.encode("utf-8")) > MAX_PATH_BYTES or len(resolved.encode("utf-8")) > MAX_PATH_BYTES:
        fail("Go TAR symbolic-link target is too long")
    if len(PurePosixPath(resolved).parts) > MAX_DEPTH:
        fail("Go TAR symbolic-link target exceeds the depth limit")
    return resolved


def _parse_pax(payload: bytes) -> str:
    if not payload or len(payload) > MAX_PAX:
        fail("Go TAR PAX header size is outside the accepted range")
    offset = 0
    path = ""
    records = 0
    while offset < len(payload):
        records += 1
        if records > MAX_PAX_RECORDS:
            fail("Go TAR PAX record-count limit exceeded")
        space = payload.find(b" ", offset)
        newline = payload.find(b"\n", offset)
        if space < 0 or newline < 0 or space > newline:
            fail("malformed Go TAR PAX record")
        length_bytes = payload[offset:space]
        if (
            not length_bytes
            or not length_bytes.isdigit()
            or length_bytes.startswith(b"0")
            or len(length_bytes) > 4
        ):
            fail("invalid Go TAR PAX length")
        length = int(length_bytes, 10)
        if length != newline - offset + 1 or offset + length > len(payload):
            fail("Go TAR PAX record length mismatch")
        body = payload[space + 1 : newline]
        key, separator, value = body.partition(b"=")
        if not separator or not key:
            fail("malformed Go TAR PAX record")
        if key != b"path":
            fail("unsupported Go TAR PAX key rejected")
        if path:
            fail("duplicate Go TAR PAX path rejected")
        try:
            path = value.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            fail(f"non-UTF-8 Go TAR PAX path: {exc}")
        offset += length
    if offset != len(payload) or not path:
        fail("Go TAR PAX header is missing a path")
    return path


def _validate_header(
    header: bytes, offset: int, expected_root: str
) -> tuple[str, str, int, str, int]:
    stored = _tar_number(header[148:156], "checksum")
    calculated = sum(header[:148]) + (8 * 32) + sum(header[156:])
    if stored != calculated:
        fail(f"Go TAR header checksum mismatch at offset {offset}")
    if header[257:263] != b"ustar\0" or header[263:265] != b"00":
        fail("only strict POSIX ustar Go archives are accepted")
    mode = _tar_number(header[100:108], "mode")
    _tar_number(header[108:116], "uid")
    _tar_number(header[116:124], "gid")
    _tar_number(header[136:148], "mtime")
    if _tar_number(header[329:337], "device major") or _tar_number(
        header[337:345], "device minor"
    ):
        fail("Go TAR device metadata is forbidden")
    if any(header[500:512]):
        fail("Go TAR header padding is non-zero")
    name = _tar_text(header[0:100], "name")
    prefix = _tar_text(header[345:500], "prefix")
    full_name = f"{prefix}/{name}" if prefix else name
    kind_byte = header[156:157]
    if kind_byte in {b"\0", b"0"}:
        kind = "file"
    elif kind_byte == b"5":
        kind = "dir"
    elif kind_byte == b"2":
        kind = "symlink"
    elif kind_byte == b"x":
        kind = "pax"
    elif kind_byte == b"g":
        fail("Go TAR global PAX headers are forbidden")
    else:
        fail("Go TAR hardlinks, special files, and extension records are forbidden")
    canonical = _member_path(full_name, expected_root, directory=kind == "dir")
    raw_target = _tar_text(header[157:257], "link target")
    if kind == "symlink":
        if not raw_target:
            fail("Go TAR symbolic link is missing a target")
    elif raw_target:
        fail("Go TAR link target metadata is forbidden")
        raw_target = ""
    size = _tar_number(header[124:136], "size")
    if kind in {"dir", "symlink"} and size != 0:
        fail("Go TAR directory or symbolic link has non-zero content")
    if kind == "pax" and (size <= 0 or size > MAX_PAX):
        fail("Go TAR PAX header size is outside the accepted range")
    if kind != "pax" and size > MAX_MEMBER:
        fail("Go TAR member exceeds the size limit")
    return canonical, kind, size, raw_target, mode


def scan_tar(
    tar_path: Path, expected_root: str
) -> list[tuple[str, str, int, int, str, bool]]:
    members: list[tuple[str, str, int, int, str, bool]] = []
    seen: set[str] = set()
    folded: set[str] = set()
    declared_dirs: set[str] = set()
    total_files = 0
    offset = 0
    counted = 0
    pending_pax: str | None = None
    archive_size = tar_path.stat().st_size
    with tar_path.open("rb") as stream:
        while True:
            stream.seek(offset)
            header = stream.read(BLOCK)
            if len(header) != BLOCK:
                fail("Go TAR ended before its required trailer")
            if header == b"\0" * BLOCK:
                second = stream.read(BLOCK)
                if second != b"\0" * BLOCK:
                    fail("Go TAR requires two zero trailer blocks")
                while trailer := stream.read(1024 * 1024):
                    if any(trailer):
                        fail("Go TAR comments or non-zero trailing data are forbidden")
                break
            counted += 1
            if counted > MAX_MEMBERS:
                fail("Go TAR member-count limit exceeded")
            ustar_path, kind, size, raw_target, mode = _validate_header(
                header, offset, expected_root
            )
            data_offset = offset + BLOCK
            padded = ((size + BLOCK - 1) // BLOCK) * BLOCK
            next_offset = data_offset + padded
            if next_offset > archive_size:
                fail("Go TAR member extends beyond the archive")
            if padded > size:
                stream.seek(data_offset + size)
                if any(stream.read(padded - size)):
                    fail("Go TAR member has non-zero data padding")
            if kind == "pax":
                if pending_pax is not None:
                    fail("Go TAR PAX header was not followed by a member")
                stream.seek(data_offset)
                payload = stream.read(size)
                if len(payload) != size:
                    fail("Go TAR PAX header was truncated")
                pending_pax = _parse_pax(payload)
                offset = next_offset
                continue
            canonical = ustar_path
            if pending_pax is not None:
                canonical = _member_path(
                    pending_pax, expected_root, directory=kind == "dir"
                )
                pending_pax = None
            if kind == "symlink":
                resolved_target = _symlink_target(canonical, raw_target, expected_root)
            else:
                resolved_target = ""
            collision = unicodedata.normalize("NFKC", canonical).casefold()
            if canonical in seen or collision in folded:
                fail("Go TAR duplicate, Unicode, or case-fold collision rejected")
            parent = PurePosixPath(canonical).parent
            if canonical != expected_root and parent.as_posix() not in declared_dirs:
                fail("Go TAR member parent directory was not declared first")
            if canonical == expected_root and kind != "dir":
                fail("Go TAR top-level root must be a directory")
            seen.add(canonical)
            folded.add(collision)
            executable = kind == "file" and (
                canonical == f"{expected_root}/{EXECUTABLE}" or bool(mode & 0o111)
            )
            if kind == "dir":
                declared_dirs.add(canonical)
            else:
                total_files += size
                if total_files > MAX_EXPANDED:
                    fail("Go TAR expanded file-size limit exceeded")
            members.append((canonical, kind, size, data_offset, resolved_target, executable))
            offset = next_offset
    if pending_pax is not None:
        fail("Go TAR PAX header was not followed by a member")
    if expected_root not in declared_dirs:
        fail("Go TAR pinned top-level root is absent")
    if not members:
        fail("empty Go TAR rejected")
    return members


def _xattr_names(path: Path) -> list[bytes]:
    if sys.platform == "darwin":
        libc = _require_darwin_libc()
        encoded = os.fsencode(path)
        size = libc.listxattr(encoded, None, 0, XATTR_NOFOLLOW)
        if size == 0:
            return []
        if size < 0:
            fail(f"Go tree xattr inspection failed: {path}")
        buf = ctypes.create_string_buffer(size)
        got = libc.listxattr(encoded, buf, size, XATTR_NOFOLLOW)
        if got < 0:
            fail(f"Go tree xattr inspection failed: {path}")
        return [name for name in buf.raw[:got].split(b"\0") if name]
    if not hasattr(os, "listxattr"):
        return []
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        fail(f"Go tree xattr inspection failed: {path}: {exc}")
    return [os.fsencode(name) for name in names]


def _has_acl(path: Path) -> bool:
    if sys.platform != "darwin":
        return False
    libc = _require_darwin_libc()
    acl = libc.acl_get_link_np(os.fsencode(path), ACL_TYPE_EXTENDED)
    if not acl:
        return False
    libc.acl_free(acl)
    return True


def reject_acl_and_xattr(path: Path, relative: str) -> None:
    extra = [name for name in _xattr_names(path) if name not in ALLOWED_XATTRS]
    if extra:
        fail(f"Go tree extended attributes are forbidden: {relative}")
    if _has_acl(path):
        fail(f"Go tree ACL is forbidden: {relative}")


def reject_all_acl_and_xattr(path: Path, relative: str) -> None:
    extra = [name for name in _xattr_names(path) if name not in ALLOWED_XATTRS]
    if extra:
        fail(f"Go owner runtime extended attributes are forbidden: {relative}")
    if _has_acl(path):
        fail(f"Go owner runtime ACL is forbidden: {relative}")


def _clear_allowed_owner_xattrs(root: Path) -> None:
    if sys.platform != "darwin":
        return
    libc = _require_darwin_libc()
    paths = [root]
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        paths.extend(base_path / name for name in files + directories)
    for path in paths:
        if path.is_symlink():
            fail("owner-provisioned Go runtime symbolic links are forbidden")
        relative = "." if path == root else str(path.relative_to(root))
        names = _xattr_names(path)
        unexpected = [name for name in names if name not in ALLOWED_XATTRS]
        if unexpected:
            fail(f"Go owner runtime extended attributes are forbidden: {relative}")
        for name in names:
            if libc.removexattr(os.fsencode(path), name, XATTR_NOFOLLOW) != 0:
                error = ctypes.get_errno()
                if error not in (errno.EPERM, errno.EACCES):
                    fail(
                        "Go owner runtime provenance normalization failed: "
                        f"{relative}: {os.strerror(error)}"
                    )
        reject_all_acl_and_xattr(path, relative)


def safe_extract(archive: Path, destination: Path, expected_root: str) -> Path:
    if destination.exists() or destination.is_symlink():
        fail("Go extraction destination already exists")
    tar_path = destination.parent / f".{destination.name}.authenticated.tar"
    try:
        decompress_exact_gzip(archive, tar_path)
        members = scan_tar(tar_path, expected_root)
        destination.mkdir(mode=0o700)
        with tar_path.open("rb") as stream:
            for canonical, kind, size, data_offset, _link_target, executable in members:
                target = destination.joinpath(*PurePosixPath(canonical).parts)
                if kind == "dir":
                    target.mkdir(mode=0o700)
                    continue
                if kind == "symlink":
                    continue
                parent = target.parent
                parent_info = parent.lstat()
                if parent.is_symlink() or not stat.S_ISDIR(parent_info.st_mode):
                    fail("Go TAR member parent directory was not declared first")
                fd = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec_flag() | _nofollow_flag(),
                    0o400,
                )
                try:
                    stream.seek(data_offset)
                    remaining = size
                    while remaining:
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            fail("Go TAR member was truncated during extraction")
                        _write_all(fd, block)
                        remaining -= len(block)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                target.chmod(0o500 if executable else 0o400)
        for canonical, kind, _size, _data_offset, resolved_target, _executable in members:
            if kind != "symlink":
                continue
            target = destination.joinpath(*PurePosixPath(canonical).parts)
            resolved_parts = PurePosixPath(resolved_target).parts
            resolved = destination
            for index, part in enumerate(resolved_parts):
                resolved /= part
                info = resolved.lstat()
                if stat.S_ISLNK(info.st_mode):
                    fail("Go TAR symbolic link target traverses another symbolic link")
                if index < len(resolved_parts) - 1 and not stat.S_ISDIR(info.st_mode):
                    fail("Go TAR symbolic link target parent is not a directory")
            if not stat.S_ISREG(resolved.lstat().st_mode):
                fail("Go TAR symbolic link target is absent or not a regular file")
            relative_target = os.path.relpath(resolved, start=target.parent)
            if relative_target.startswith("/"):
                fail("Go TAR symbolic link target became absolute")
            os.symlink(relative_target, target)
    finally:
        if tar_path.exists() and not tar_path.is_symlink():
            tar_path.unlink()
    root = destination / expected_root
    binary = root / EXECUTABLE
    try:
        info = binary.lstat()
    except FileNotFoundError:
        fail("pinned Go executable is absent")
    if binary.is_symlink() or not stat.S_ISREG(info.st_mode):
        fail("pinned Go executable is absent")
    binary.chmod(0o500)
    for base, directories, files in os.walk(destination, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            relative = path.relative_to(destination).as_posix()
            reject_acl_and_xattr(path, relative)
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("extracted Go hardlink or special file rejected")
        for name in directories:
            path = base_path / name
            info = path.lstat()
            relative = path.relative_to(destination).as_posix()
            reject_acl_and_xattr(path, relative)
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISDIR(info.st_mode):
                fail("extracted Go special file rejected")
            path.chmod(0o500)
        reject_acl_and_xattr(base_path, base_path.relative_to(destination).as_posix() or ".")
        if not base_path.is_symlink():
            base_path.chmod(0o500)
    destination.chmod(0o500)
    reject_acl_and_xattr(destination, ".")
    return root


def _require_system_immutable(info: os.stat_result, label: str) -> None:
    if sys.platform != "darwin":
        fail(MACOS_BLOCKER)
    flags = int(getattr(info, "st_flags", 0))
    if flags & UF_IMMUTABLE and not flags & SF_IMMUTABLE:
        fail(f"UF_IMMUTABLE is insufficient for owner-provisioned Go runtime: {label}")
    if not SF_IMMUTABLE or not (flags & SF_IMMUTABLE):
        fail(f"owner-provisioned Go runtime lacks SF_IMMUTABLE: {label}")


def _owner_identity() -> tuple[int, int]:
    return (0, 0)


def tree_hash(
    root: Path,
    *,
    owner_runtime: bool = False,
    require_immutable: bool = True,
) -> str:
    if root.is_symlink():
        fail("Go root symbolic link rejected")
    root = root.resolve(strict=True)
    root_info = root.lstat()
    expected_uid, expected_gid = (
        _owner_identity() if owner_runtime else (os.getuid(), root_info.st_gid)
    )
    directory_mode = 0o555 if owner_runtime else 0o500
    regular_mode = 0o444 if owner_runtime else 0o400
    executable_mode = 0o555 if owner_runtime else 0o500
    if (
        root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
        or stat.S_IMODE(root_info.st_mode) != directory_mode
    ):
        fail("Go root is not owner-controlled and frozen")
    if owner_runtime and require_immutable:
        _require_system_immutable(root_info, ".")
    if owner_runtime:
        reject_all_acl_and_xattr(root, ".")
    else:
        reject_acl_and_xattr(root, ".")
    root_device = root_info.st_dev
    digest = hashlib.sha256()

    def feed(*parts: object) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_dev != root_device:
                fail(f"Go owner runtime crossed a filesystem boundary: {relative}")
            if owner_runtime:
                reject_all_acl_and_xattr(path, relative)
            else:
                reject_acl_and_xattr(path, relative)
            if info.st_uid != expected_uid or info.st_gid != expected_gid:
                fail(f"unsafe Go tree ownership or mode: {relative}")
            if owner_runtime and require_immutable:
                _require_system_immutable(info, relative)
            if stat.S_ISLNK(info.st_mode):
                if owner_runtime:
                    fail(f"Go owner runtime symbolic link rejected: {relative}")
                target = os.readlink(path)
                resolved_relative = _symlink_target(
                    f"{ROOT_NAME}/{relative}", target, ROOT_NAME
                )
                resolved = root
                target_parts = PurePosixPath(resolved_relative).parts[1:]
                for index, part in enumerate(target_parts):
                    resolved /= part
                    resolved_info = resolved.lstat()
                    if stat.S_ISLNK(resolved_info.st_mode):
                        fail(f"unsafe Go symbolic-link target: {relative}")
                    if index < len(target_parts) - 1 and not stat.S_ISDIR(
                        resolved_info.st_mode
                    ):
                        fail(f"unsafe Go symbolic-link target: {relative}")
                if not stat.S_ISREG(resolved.lstat().st_mode):
                    fail(f"unsafe Go symbolic-link target: {relative}")
                feed("L", relative, target)
            elif mode & 0o022:
                fail(f"unsafe Go tree ownership or mode: {relative}")
            elif stat.S_ISDIR(info.st_mode):
                if mode != directory_mode:
                    fail(f"Go directory is not frozen: {relative}")
                # The digest retains the existing canonical 0500/0400 mode
                # encoding. Owner-runtime 0555/0444 permissions are enforced
                # above and therefore cannot weaken or silently change the
                # reviewed install_tree_sha256 pin.
                feed("D", relative, 0o500)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                expected_mode = (
                    executable_mode
                    if relative == EXECUTABLE or mode == executable_mode
                    else regular_mode
                )
                if info.st_nlink != 1 or mode != expected_mode:
                    fail(f"Go file mode or hardlink rejected: {relative}")
                canonical_mode = 0o500 if expected_mode == executable_mode else 0o400
                feed("F", relative, canonical_mode, info.st_size, digest_file(path))
            else:
                fail(f"unsupported Go tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def owner_runtime_path(version: str) -> Path:
    if VERSION_RE.fullmatch(version) is None:
        fail("Go version pin must be an exact stable dotted version")
    return OWNER_RUNTIME_PREFIX / version


def _owner_material_digests(
    repo: Path,
    authorized: tuple[bytes, bytes, bytes, bytes],
    issuance: dict[str, object],
) -> dict[str, str]:
    controller_data, wrapper_data, manifest_data, trust_data = authorized
    provisioner_data = bind_regular_file(
        repo / "tools" / PROVISIONER_NAME,
        max_size=MAX_CONTROLLER,
        label="Go runtime provisioner",
    )
    freeze_data = _bind_source_freeze_producer(
        repo, str(issuance["source_freeze_producer_sha256"])
    )
    result = {
        "controller_sha256": _digest_bytes(controller_data),
        "wrapper_sha256": _digest_bytes(wrapper_data),
        "provisioner_sha256": _digest_bytes(provisioner_data),
        "manifest_sha256": _digest_bytes(manifest_data),
        "trust_anchor_sha256": _digest_bytes(trust_data),
        "source_freeze_producer_sha256": _digest_bytes(freeze_data),
    }
    for key, value in result.items():
        if key in issuance and value != issuance[key]:
            fail(f"Go owner runtime {key} disagrees with the external issuance")
    return result


def _verify_owner_ancestors(path: Path) -> None:
    if not path.is_absolute():
        fail("Go owner-runtime path is not absolute")
    uid, gid = _owner_identity()
    expected_device = path.lstat().st_dev
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        info = current.lstat()
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"unsafe Go owner-runtime ancestor: {current}")
        if info.st_uid != uid or info.st_gid != gid:
            fail(f"foreign-owned Go owner-runtime ancestor: {current}")
        if info.st_dev != expected_device:
            fail(f"cross-device Go owner-runtime ancestor: {current}")
        if mode & 0o022:
            fail(f"writable Go owner-runtime ancestor: {current}")


def _bootstrap_identity(materials: dict[str, str], pin: dict[str, str]) -> str:
    required = {
        "controller_sha256",
        "wrapper_sha256",
        "provisioner_sha256",
        "manifest_sha256",
        "trust_anchor_sha256",
        "source_freeze_producer_sha256",
    }
    if set(materials) != required:
        fail("Go sealed-bootstrap material set is not exact")
    payload = "".join(f"{key}={materials[key]}\n" for key in sorted(required))
    payload += "".join(
        f"{key}={pin[key]}\n"
        for key in ("version", "archive_sha", "tree_sha", "executable_sha")
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _parse_bootstrap_receipt(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Go sealed-bootstrap receipt contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go sealed-bootstrap receipt is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go sealed-bootstrap receipt is not JSON: {exc}")
    root = _mapping(document, "Go sealed-bootstrap receipt")
    if data != _canonical_json_bytes(root):
        fail("Go sealed-bootstrap receipt is not canonical JSON")
    _require_keys(root, BOOTSTRAP_RECEIPT_KEYS, "Go sealed-bootstrap receipt")
    if _text(root, "contract") != BOOTSTRAP_RECEIPT_CONTRACT:
        fail("Go sealed-bootstrap receipt contract mismatch")
    if _exact_int(root.get("schema_version"), "sealed-bootstrap schema_version") != 1:
        fail("Go sealed-bootstrap receipt schema_version mismatch")
    if _exact_int(root.get("archive_size"), "sealed-bootstrap archive_size") <= 0:
        fail("Go sealed-bootstrap receipt archive_size is invalid")
    if HEX_RE.fullmatch(_text(root, "identity")) is None:
        fail("Go sealed-bootstrap receipt identity is invalid")
    for key in BOOTSTRAP_RECEIPT_KEYS:
        if key.endswith("_sha256") and HEX_RE.fullmatch(_text(root, key)) is None:
            fail(f"Go sealed-bootstrap receipt digest is invalid: {key}")
    return root


def verify_sealed_bootstrap(
    materials: dict[str, str],
    pin: dict[str, str],
    *,
    require_immutable: bool = True,
) -> dict[str, str]:
    identity = _bootstrap_identity(materials, pin)
    bootstrap = OWNER_BOOTSTRAP_PREFIX / identity
    _verify_owner_ancestors(bootstrap)
    bootstrap_info = _require_owner_entry(
        bootstrap,
        mode=0o555,
        directory=True,
        immutable=require_immutable,
        label="sealed bootstrap",
    )
    files = {
        CONTROLLER_NAME: materials["controller_sha256"],
        WRAPPER_NAME: materials["wrapper_sha256"],
        PROVISIONER_NAME: materials["provisioner_sha256"],
        MANIFEST_NAME: materials["manifest_sha256"],
        TRUST_ANCHOR_NAME: materials["trust_anchor_sha256"],
        SOURCE_FREEZE_PRODUCER: materials["source_freeze_producer_sha256"],
    }
    archive_name = f"go{pin['version']}.darwin-arm64.tar.gz"
    _exact_names(
        bootstrap,
        set(files) | {archive_name, BOOTSTRAP_RECEIPT_NAME},
        "sealed bootstrap",
    )
    for name, expected_sha in files.items():
        path = bootstrap / name
        file_info = _require_owner_entry(
            path,
            mode=0o444,
            directory=False,
            immutable=require_immutable,
            label=f"sealed bootstrap {name}",
        )
        if file_info.st_dev != bootstrap_info.st_dev:
            fail("Go sealed bootstrap crossed a filesystem boundary")
        if digest_file(path) != expected_sha:
            fail(f"Go sealed-bootstrap digest mismatch: {name}")
    archive = bootstrap / archive_name
    archive_info = _require_owner_entry(
        archive,
        mode=0o444,
        directory=False,
        immutable=require_immutable,
        label="sealed bootstrap Go archive",
    )
    if archive_info.st_dev != bootstrap_info.st_dev:
        fail("Go sealed bootstrap crossed a filesystem boundary")
    if digest_file(archive) != pin["archive_sha"]:
        fail("Go sealed-bootstrap archive digest mismatch")
    receipt_path = bootstrap / BOOTSTRAP_RECEIPT_NAME
    receipt_info = _require_owner_entry(
        receipt_path,
        mode=0o444,
        directory=False,
        immutable=require_immutable,
        label="sealed bootstrap receipt",
    )
    if receipt_info.st_dev != bootstrap_info.st_dev:
        fail("Go sealed bootstrap crossed a filesystem boundary")
    receipt = _parse_bootstrap_receipt(
        bind_regular_file(
            receipt_path,
            max_size=MAX_TRUST,
            label="Go sealed-bootstrap receipt",
        )
    )
    expected: dict[str, object] = {
        "contract": BOOTSTRAP_RECEIPT_CONTRACT,
        "schema_version": 1,
        "identity": identity,
        "path": str(bootstrap),
        "version": pin["version"],
        "archive_name": archive_name,
        "archive_size": archive_info.st_size,
        "archive_sha256": pin["archive_sha"],
        "tree_sha256": pin["tree_sha"],
        "executable": EXECUTABLE,
        "executable_sha256": pin["executable_sha"],
        **materials,
    }
    if receipt != expected:
        fail("Go sealed-bootstrap receipt does not match current reviewed inputs")
    return {"path": str(bootstrap), "identity": identity}


def _parse_owner_receipt(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Go owner runtime receipt contains a NUL")
    try:
        document = json.loads(data, object_pairs_hook=_json_object)
    except UnicodeDecodeError as exc:
        fail(f"Go owner runtime receipt is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Go owner runtime receipt is not JSON: {exc}")
    root = _mapping(document, "Go owner runtime receipt")
    if data != _canonical_json_bytes(root):
        fail("Go owner runtime receipt is not canonical JSON")
    _require_keys(root, OWNER_RECEIPT_KEYS, "Go owner runtime receipt")
    if _text(root, "contract") != OWNER_RECEIPT_CONTRACT:
        fail("Go owner runtime receipt contract mismatch")
    if _exact_int(root.get("schema_version"), "owner runtime schema_version") != 1:
        fail("Go owner runtime receipt schema_version mismatch")
    if _exact_int(root.get("archive_size"), "owner runtime archive_size") <= 0:
        fail("Go owner runtime receipt archive_size is invalid")
    for key in (
        "archive_sha256",
        "tree_sha256",
        "executable_sha256",
        "controller_sha256",
        "wrapper_sha256",
        "provisioner_sha256",
        "manifest_sha256",
        "trust_anchor_sha256",
        "source_freeze_producer_sha256",
    ):
        if HEX_RE.fullmatch(_text(root, key)) is None:
            fail(f"Go owner runtime receipt digest is invalid: {key}")
    issuance_id = _text(root, "provisioned_issuance_id")
    if ISSUANCE_RE.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Go owner runtime receipt issuance identity is invalid")
    return root


def _require_owner_entry(
    path: Path,
    *,
    mode: int,
    directory: bool,
    immutable: bool,
    label: str,
) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"owner-provisioned Go runtime is absent: {label}")
    uid, gid = _owner_identity()
    if stat.S_ISLNK(info.st_mode):
        fail(f"owner-provisioned Go runtime symbolic link rejected: {label}")
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_kind(info.st_mode):
        fail(f"owner-provisioned Go runtime type mismatch: {label}")
    if not directory and info.st_nlink != 1:
        fail(f"owner-provisioned Go runtime hardlink rejected: {label}")
    if info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
        fail(f"owner-provisioned Go runtime ownership or mode mismatch: {label}")
    if immutable:
        _require_system_immutable(info, label)
    reject_all_acl_and_xattr(path, label)
    return info


def _exact_names(path: Path, expected: set[str], label: str) -> None:
    with os.scandir(path) as scan:
        observed = {entry.name for entry in scan}
    if observed != expected:
        fail(f"owner-provisioned Go runtime entries mismatch: {label}")


def verify_owner_runtime(
    repo: Path,
    pin: dict[str, str],
    authorized: tuple[bytes, bytes, bytes, bytes],
    issuance: dict[str, object],
    *,
    require_immutable: bool = True,
) -> dict[str, str]:
    if sys.platform != "darwin":
        fail(MACOS_BLOCKER)
    runtime = owner_runtime_path(pin["version"])
    root = runtime / "extracted" / ROOT_NAME
    binary = root / EXECUTABLE
    receipt_path = runtime / OWNER_RECEIPT_NAME
    archive_name = f"go{pin['version']}.darwin-arm64.tar.gz"
    archive = runtime / "archive" / archive_name

    _verify_owner_ancestors(runtime)
    runtime_info = _require_owner_entry(
        runtime,
        mode=0o555,
        directory=True,
        immutable=require_immutable,
        label="runtime",
    )
    _exact_names(runtime, {"archive", "extracted", OWNER_RECEIPT_NAME}, "runtime")
    archive_dir_info = _require_owner_entry(
        runtime / "archive",
        mode=0o555,
        directory=True,
        immutable=require_immutable,
        label="archive directory",
    )
    _exact_names(runtime / "archive", {archive_name}, "archive directory")
    archive_info = _require_owner_entry(
        archive,
        mode=0o444,
        directory=False,
        immutable=require_immutable,
        label="archive",
    )
    extracted_info = _require_owner_entry(
        runtime / "extracted",
        mode=0o555,
        directory=True,
        immutable=require_immutable,
        label="extracted directory",
    )
    _exact_names(runtime / "extracted", {ROOT_NAME}, "extracted directory")
    receipt_info = _require_owner_entry(
        receipt_path,
        mode=0o444,
        directory=False,
        immutable=require_immutable,
        label="receipt",
    )
    for info in (archive_dir_info, archive_info, extracted_info, receipt_info):
        if info.st_dev != runtime_info.st_dev:
            fail("Go owner runtime crossed a filesystem boundary")
    receipt = _parse_owner_receipt(
        bind_regular_file(
            receipt_path, max_size=MAX_TRUST, label="Go owner runtime receipt"
        )
    )
    materials = _owner_material_digests(repo, authorized, issuance)
    bootstrap = verify_sealed_bootstrap(
        materials, pin, require_immutable=require_immutable
    )
    expected = {
        "version": pin["version"],
        "runtime": str(runtime),
        "sealed_bootstrap": bootstrap["path"],
        "sealed_bootstrap_identity": bootstrap["identity"],
        "archive_name": archive_name,
        "archive_sha256": pin["archive_sha"],
        "tree_sha256": pin["tree_sha"],
        "executable": EXECUTABLE,
        "executable_sha256": pin["executable_sha"],
        **materials,
        "provisioned_issuance_id": str(issuance["issuance_id"]),
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            fail(f"Go owner runtime receipt mismatch: {key}")
    if int(receipt["archive_size"]) != archive_info.st_size:
        fail("Go owner runtime receipt mismatch: archive_size")
    if digest_file(archive) != pin["archive_sha"]:
        fail("Go owner runtime archive digest mismatch")
    if tree_hash(
        root,
        owner_runtime=True,
        require_immutable=require_immutable,
    ) != pin["tree_sha"]:
        fail("Go owner runtime tree digest mismatch")
    if digest_file(binary) != pin["executable_sha"]:
        fail("Go owner runtime executable digest mismatch")
    return {
        "OWNER_RUNTIME": str(runtime),
        "ROOT": str(root),
        "TREE_SHA256": pin["tree_sha"],
        "BINARY": str(binary),
        "BINARY_SHA256": pin["executable_sha"],
    }


def _ensure_owner_prefix(*, require_root: bool) -> None:
    uid, gid = _owner_identity()
    paths = (OWNER_LIBRARY_ROOT, OWNER_RUNTIME_PREFIX)
    if require_root and paths != (
        Path("/Library/WinsVPN"),
        Path("/Library/WinsVPN/ReleaseGo"),
    ):
        fail("production Go owner-runtime prefix changed")
    for path in paths:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail(f"Go owner-runtime prefix is not a real directory: {path}")
            if (
                info.st_uid != uid
                or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o755
            ):
                fail(f"Go owner-runtime prefix ownership or mode mismatch: {path}")
            continue
        parent = path.parent
        if not parent.is_dir() or parent.is_symlink():
            fail(f"Go owner-runtime prefix parent is unsafe: {parent}")
        path.mkdir(mode=0o755)
        os.chown(path, uid, gid)
        path.chmod(0o755)


def _normalize_owner_tree(root: Path) -> None:
    uid, gid = _owner_identity()
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                fail("owner-provisioned Go runtime symbolic links are forbidden")
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("owner-provisioned Go runtime special file rejected")
            mode = 0o555 if stat.S_IMODE(info.st_mode) & 0o111 else 0o444
            os.chown(path, uid, gid, follow_symlinks=False)
            os.chmod(path, mode, follow_symlinks=False)
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail("owner-provisioned Go runtime directory link rejected")
            os.chown(path, uid, gid, follow_symlinks=False)
            os.chmod(path, 0o555, follow_symlinks=False)
        os.chown(base_path, uid, gid, follow_symlinks=False)
        os.chmod(base_path, 0o555, follow_symlinks=False)


def _write_owner_receipt(path: Path, receipt: dict[str, object]) -> None:
    data = _canonical_json_bytes(receipt)
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec_flag() | _nofollow_flag(),
        0o444,
    )
    try:
        _write_all(fd, data)
        os.fsync(fd)
        uid, gid = _owner_identity()
        os.fchown(fd, uid, gid)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)


def _seal_owner_tree(runtime: Path) -> None:
    if sys.platform != "darwin" or not SF_IMMUTABLE:
        fail(MACOS_BLOCKER)
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            if path.is_symlink():
                fail("owner-provisioned Go runtime symbolic links are forbidden")
            try:
                os.chflags(path, SF_IMMUTABLE, follow_symlinks=False)
            except OSError as exc:
                fail(f"could not apply SF_IMMUTABLE to {path}: {exc}")
        try:
            os.chflags(base_path, SF_IMMUTABLE, follow_symlinks=False)
        except OSError as exc:
            fail(f"could not apply SF_IMMUTABLE to {base_path}: {exc}")


def _publish_directory_exclusive(staging: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        fail("refusing to replace an existing Go owner runtime")
    if sys.platform == "darwin":
        libc = _require_darwin_libc()
        if not hasattr(libc, "renameatx_np"):
            fail("renameatx_np with RENAME_EXCL is required for Go provisioning")
        libc.renameatx_np.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        libc.renameatx_np.restype = ctypes.c_int
        rc = libc.renameatx_np(
            -2,
            os.fsencode(staging),
            -2,
            os.fsencode(destination),
            0x00000004,
        )
        if rc != 0:
            error = ctypes.get_errno()
            fail(f"exclusive Go owner-runtime publication failed: {os.strerror(error)}")
        return
    # Portable hostile tests exercise the same no-replace precondition. The
    # production action is Darwin-only and always uses renameatx_np above.
    os.rename(staging, destination)


def _destroy_unpublished_staging(staging: Path) -> None:
    if not (staging.exists() or staging.is_symlink()):
        return
    if staging.parent != OWNER_RUNTIME_PREFIX or not staging.name.startswith(
        ".go-provisioning."
    ):
        fail("refusing cleanup outside the Go provisioning staging prefix")
    if staging.is_symlink() or not staging.is_dir():
        fail("Go provisioning staging path was substituted")
    for base, directories, files in os.walk(staging, topdown=False, followlinks=False):
        base_path = Path(base)
        base_path.chmod(0o700)
        for name in files:
            path = base_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o600)
                path.unlink()
        for name in directories:
            path = base_path / name
            if path.is_symlink():
                path.unlink()
            else:
                path.chmod(0o700)
                path.rmdir()
    staging.rmdir()


def _destroy_exact_partial_owner_runtime(runtime: Path) -> None:
    """Remove only an already authenticated, partially sealed publication.

    The caller must first verify the complete archive, tree, executable, receipt,
    and bootstrap with ``require_immutable=False``. This function then binds every
    inode before clearing root-only flags and deleting the one exact version path.
    It never accepts a symbolic link, mount crossing, hardlink, special file, or
    path outside ``OWNER_RUNTIME_PREFIX/<exact-version>``.
    """
    if os.getuid() != 0 or os.geteuid() != 0:
        fail("partial Go owner-runtime recovery must run as root")
    if (
        runtime.parent != OWNER_RUNTIME_PREFIX
        or VERSION_RE.fullmatch(runtime.name) is None
        or runtime.is_symlink()
    ):
        fail("partial Go owner-runtime recovery path is outside the exact prefix")
    root_info = runtime.lstat()
    expected_uid, expected_gid = _owner_identity()
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
    ):
        fail("partial Go owner-runtime recovery root custody mismatch")
    plan: list[tuple[str, Path, tuple[int, ...], tuple[int, ...]]] = []
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != expected_uid
                or info.st_gid != expected_gid
                or info.st_dev != root_info.st_dev
            ):
                fail("partial Go owner-runtime recovery file custody mismatch")
            plan.append(
                (
                    "file",
                    path,
                    _identity(info),
                    (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_nlink),
                )
            )
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != expected_uid
                or info.st_gid != expected_gid
                or info.st_dev != root_info.st_dev
            ):
                fail("partial Go owner-runtime recovery directory custody mismatch")
            plan.append(
                (
                    "dir",
                    path,
                    _identity(info),
                    (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_nlink),
                )
            )
    plan.append(
        (
            "dir",
            runtime,
            _identity(root_info),
            (
                root_info.st_dev,
                root_info.st_ino,
                root_info.st_uid,
                root_info.st_gid,
                root_info.st_nlink,
            ),
        )
    )
    for _kind, path, expected, _stable in plan:
        current = path.lstat()
        if _identity(current) != expected:
            fail("partial Go owner-runtime changed before recovery")
        _lchflags(path, 0)
        os.chmod(
            path,
            0o700 if stat.S_ISDIR(current.st_mode) else 0o600,
            follow_symlinks=False,
        )
    for kind, path, _expected, stable in plan:
        current = path.lstat()
        observed_stable = (
            current.st_dev,
            current.st_ino,
            current.st_uid,
            current.st_gid,
            current.st_nlink,
        )
        if observed_stable[:4] != stable[:4] or (
            kind == "file" and observed_stable[4] != stable[4]
        ):
            fail("partial Go owner-runtime changed during recovery")
        if kind == "file":
            path.unlink()
        else:
            path.rmdir()
    if runtime.exists() or runtime.is_symlink():
        fail("partial Go owner-runtime recovery left residue")


def provision_owner_runtime(
    repo_text: str,
    manifest_text: str,
    provisioner_text: str,
    *,
    require_root: bool = True,
    apply_kernel_seal: bool = True,
) -> str:
    repo = Path(repo_text)
    manifest = Path(manifest_text)
    provisioner = Path(provisioner_text)
    if not repo.is_absolute() or not manifest.is_absolute() or not provisioner.is_absolute():
        fail("Go provisioning paths must be absolute")
    if manifest != repo / "tools" / MANIFEST_NAME:
        fail("replacement Go pin manifest cannot self-authorize")
    if provisioner != repo / "tools" / PROVISIONER_NAME:
        fail("replacement Go runtime provisioner cannot self-authorize")
    if require_root:
        if sys.platform != "darwin" or os.uname().machine != ARCHITECTURE:
            fail("Go owner runtime provisioning requires macOS arm64")
        if os.getuid() != 0 or os.geteuid() != 0:
            fail("Go owner runtime provisioning must run as root")
        sudo_uid = os.environ.get("SUDO_UID", "")
        sudo_gid = os.environ.get("SUDO_GID", "")
        if not sudo_uid.isdigit() or int(sudo_uid) <= 0:
            fail("root preflight refused: SUDO_UID is missing")
        if not sudo_gid.isdigit() or int(sudo_gid) <= 0:
            fail("root preflight refused: SUDO_GID is missing")
        if os.environ.get("SUDO_ASKPASS"):
            fail("SUDO_ASKPASS is refused; provisioning never reads a password")

    authorized = authorize_repo(repo)
    issuance = _bind_external_issuance(repo)
    pin = parse_pin_bytes(authorized[2])
    materials = _owner_material_digests(repo, authorized, issuance)
    bootstrap = verify_sealed_bootstrap(
        materials, pin, require_immutable=apply_kernel_seal
    )
    if require_root:
        executing = Path(globals().get("__file__", ""))
        expected_controller = Path(bootstrap["path"]) / CONTROLLER_NAME
        if not executing.is_absolute() or executing != expected_controller:
            fail("root refused to execute a user-writable Go custody controller")
    destination = owner_runtime_path(pin["version"])
    if destination.exists() or destination.is_symlink():
        try:
            verify_owner_runtime(
                repo,
                pin,
                authorized,
                issuance,
                require_immutable=apply_kernel_seal,
            )
        except Refused as exc:
            try:
                verify_owner_runtime(
                    repo,
                    pin,
                    authorized,
                    issuance,
                    require_immutable=False,
                )
                _destroy_exact_partial_owner_runtime(destination)
            except (OSError, Refused) as recovery_exc:
                fail(
                    "refusing to replace an unauthenticated Go owner runtime; "
                    f"exact recovery is bounded to {destination}: "
                    f"immutable verification={exc}; recovery verification={recovery_exc}"
                )
        else:
            return f"already provisioned at {destination}"

    _ensure_owner_prefix(require_root=require_root)
    staging = Path(
        tempfile.mkdtemp(prefix=".go-provisioning.", dir=str(OWNER_RUNTIME_PREFIX))
    )
    published = False
    try:
        uid, gid = _owner_identity()
        os.chown(staging, uid, gid)
        staging.chmod(0o700)
        archive_dir = staging / "archive"
        archive_dir.mkdir(mode=0o700)
        os.chown(archive_dir, uid, gid)
        archive_name = f"go{pin['version']}.darwin-arm64.tar.gz"
        staged_archive = archive_dir / archive_name
        source_archive = Path(bootstrap["path"]) / archive_name
        _require_owner_entry(
            source_archive,
            mode=0o444,
            directory=False,
            immutable=apply_kernel_seal,
            label="sealed bootstrap Go archive",
        )
        copy_stable(source_archive, staged_archive, pin["archive_sha"])
        os.chown(staged_archive, uid, gid)
        staged_archive.chmod(0o444)
        extracted = staging / "extracted"
        root = safe_extract(staged_archive, extracted, pin["root"])
        _normalize_owner_tree(root)
        os.chown(extracted, uid, gid)
        extracted.chmod(0o555)
        archive_dir.chmod(0o555)
        binary = root / EXECUTABLE
        measured_tree = tree_hash(
            root, owner_runtime=True, require_immutable=False
        )
        measured_binary = digest_file(binary)
        if measured_tree != pin["tree_sha"] or measured_binary != pin["executable_sha"]:
            fail("Go provisioned tree or executable digest mismatch")
        receipt: dict[str, object] = {
            "contract": OWNER_RECEIPT_CONTRACT,
            "schema_version": 1,
            "version": pin["version"],
            "runtime": str(destination),
            "sealed_bootstrap": bootstrap["path"],
            "sealed_bootstrap_identity": bootstrap["identity"],
            "archive_name": archive_name,
            "archive_size": staged_archive.stat().st_size,
            "archive_sha256": pin["archive_sha"],
            "tree_sha256": pin["tree_sha"],
            "executable": EXECUTABLE,
            "executable_sha256": pin["executable_sha"],
            **materials,
            "provisioned_issuance_id": str(issuance["issuance_id"]),
        }
        _write_owner_receipt(staging / OWNER_RECEIPT_NAME, receipt)
        staging.chmod(0o555)
        os.chown(staging, uid, gid)
        _publish_directory_exclusive(staging, destination)
        published = True
        try:
            _clear_allowed_owner_xattrs(destination)
            if apply_kernel_seal:
                _seal_owner_tree(destination)
            verify_owner_runtime(
                repo,
                pin,
                authorized,
                issuance,
                require_immutable=apply_kernel_seal,
            )
        except BaseException as publication_exc:
            try:
                verify_owner_runtime(
                    repo,
                    pin,
                    authorized,
                    issuance,
                    require_immutable=False,
                )
                _destroy_exact_partial_owner_runtime(destination)
            except (OSError, Refused) as recovery_exc:
                fail(
                    "Go owner-runtime publication failed and exact bounded "
                    f"recovery could not authenticate {destination}: "
                    f"publication={publication_exc}; recovery={recovery_exc}"
                )
            fail(
                "Go owner-runtime publication failed after exclusive rename; "
                f"the exact partial runtime was rolled back: {publication_exc}"
            )
        return f"provisioned {destination}"
    finally:
        if not published and (staging.exists() or staging.is_symlink()):
            _destroy_unpublished_staging(staging)


def runtime_identity(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("Go runtime is not one private owner-controlled directory")
    return ":".join(
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_mode,
            info.st_nlink,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    )


def _require_private_state(runtime: Path) -> None:
    for relative in ("state", "state/home", "state/tmp", "exec"):
        path = runtime / relative
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            fail(f"unsafe Go runtime state directory: {relative}")
        if stat.S_IMODE(info.st_mode) != 0o700:
            fail(f"Go runtime state directory mode changed: {relative}")


def macho_architectures(binary: Path) -> set[str]:
    fd = os.open(binary, _open_flags())
    try:
        header = os.read(fd, 4096)
    finally:
        os.close(fd)
    if len(header) < 8:
        fail("Go executable is too small to be Mach-O")
    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu_type = struct.unpack_from("<I", header, 4)[0]
        return {"arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}"}
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64 = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", header, 4)[0]
        entry_size = 32 if is_64 else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(header):
            fail("Go universal Mach-O header is malformed")
        result: set[str] = set()
        for index in range(count):
            cpu_type = struct.unpack_from(">I", header, 8 + index * entry_size)[0]
            result.add("arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}")
        return result
    fail("Go executable is not a supported Mach-O binary")


def _validated_go_environment(runtime: Path, root: Path) -> dict[str, str]:
    if os.environ.get("WINS_RELEASE_GO"):
        fail("ambient WINS_RELEASE_GO is refused; use fd-bound custody execution")
    refused = {
        "GOROOT",
        "GOTOOLCHAIN",
        "GOENV",
        "GOPATH",
        "GOBIN",
        "GOTOOLDIR",
        "GOHOSTOS",
        "GOHOSTARCH",
        "GOVERSION",
        "GOMOD",
        "GOINSECURE",
        "GOVCS",
        "GOAUTH",
        "GO111MODULE",
    }
    contaminated = sorted(
        name for name in refused | REFUSED_INHERITED_GO_ENV if name in os.environ
    )
    if contaminated:
        fail(f"ambient Go environment is refused: {contaminated[0]}")
    arbitrary_custody = sorted(
        name
        for name in os.environ
        if name.startswith(("WINS_GO_CUSTODY_", "WINS_RELEASE_GO_"))
        and name not in ALLOWED_CUSTODY_ENV
    )
    if arbitrary_custody:
        fail(f"arbitrary release Go custody label is refused: {arbitrary_custody[0]}")
    result = {
        "HOME": str(runtime / "state/home"),
        "TMPDIR": str(runtime / "state/tmp"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "GOROOT": str(root),
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GOFLAGS": "-mod=readonly",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOWORK": "off",
    }
    for name in sorted(GO_ENV_ALLOWLIST | CGO_HOST_ENV_ALLOWLIST):
        if name not in os.environ:
            continue
        value = os.environ[name]
        if not value or len(value) > 32768 or any(ord(ch) < 32 for ch in value):
            fail(f"unsafe release Go environment value: {name}")
        if name in {"GOOS", "GOARCH", "GOARM", "GOAMD64"} and re.fullmatch(
            r"[A-Za-z0-9_.-]+", value
        ) is None:
            fail(f"unsafe release Go target value: {name}")
        if name == "CGO_ENABLED" and value not in {"0", "1"}:
            fail("CGO_ENABLED must be exactly 0 or 1")
        if name in {"GOMODCACHE", "GOCACHE", "SDKROOT"} and not Path(value).is_absolute():
            fail(f"release Go path must be absolute: {name}")
        result[name] = value
    return result


def _reject_go_command_overrides(arguments: list[str]) -> None:
    for index, argument in enumerate(arguments):
        flag = argument.split("=", 1)[0]
        if flag in {"-overlay", "-toolexec"}:
            fail(f"release Go command override is refused: {flag}")
        if index and arguments[index - 1] in {"-overlay", "-toolexec"}:
            fail(f"release Go command override is refused: {arguments[index - 1]}")


def _minimal_environment(runtime: Path, root: Path) -> dict[str, str]:
    """Compatibility name for tests and callers; policy is deny-by-default."""
    return _validated_go_environment(runtime, root)


class _CStringArray:
    def __init__(self, values: list[str]):
        encoded = [value.encode("utf-8") for value in values]
        array = (ctypes.c_char_p * (len(encoded) + 1))()
        for index, item in enumerate(encoded):
            array[index] = item
        array[len(encoded)] = None
        self._encoded = encoded
        self.array = array


def _posix_spawn(
    path: str,
    argv: list[str],
    env: dict[str, str],
    *,
    inherit_stdio: bool,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
) -> int:
    libc = _require_darwin_libc()
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    _must(libc.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
    try:
        _must(
            libc.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT),
            ),
            "posix_spawnattr_setflags",
        )
        _must(
            libc.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "posix_spawn_file_actions_init",
        )
        try:
            if inherit_stdio:
                _must(
                    libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 0, 0),
                    "posix_spawn_file_actions_adddup2 stdin",
                )
                _must(
                    libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 1, 1),
                    "posix_spawn_file_actions_adddup2 stdout",
                )
                _must(
                    libc.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 2, 2),
                    "posix_spawn_file_actions_adddup2 stderr",
                )
            else:
                _must(
                    libc.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions), 0, b"/dev/null", os.O_RDONLY, 0
                    ),
                    "posix_spawn_file_actions_addopen stdin",
                )
                stdout = os.fsencode(stdout_path or "/dev/null")
                stderr = os.fsencode(stderr_path or "/dev/null")
                stdout_flags = os.O_WRONLY
                if stdout_path:
                    stdout_flags |= os.O_CREAT | os.O_TRUNC
                stderr_flags = os.O_WRONLY
                if stderr_path:
                    stderr_flags |= os.O_CREAT | os.O_TRUNC
                _must(
                    libc.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions),
                        1,
                        stdout,
                        stdout_flags,
                        0o600,
                    ),
                    "posix_spawn_file_actions_addopen stdout",
                )
                _must(
                    libc.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions),
                        2,
                        stderr,
                        stderr_flags,
                        0o600,
                    ),
                    "posix_spawn_file_actions_addopen stderr",
                )
            pid = ctypes.c_int()
            argv_c = _CStringArray(argv)
            env_c = _CStringArray([f"{name}={value}" for name, value in env.items()])
            rc = libc.posix_spawn(
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
            libc.posix_spawn_file_actions_destroy(ctypes.byref(actions))
    finally:
        libc.posix_spawnattr_destroy(ctypes.byref(attr))


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
            fail("Go runtime execution timed out")
        time.sleep(0.02)


def _clear_linux_immutable(path: Path) -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        flags = os.O_RDONLY | _cloexec_flag() | _nofollow_flag()
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return
        if stat.S_ISDIR(info.st_mode):
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            _get, set_flags = _fs_ioctl_numbers()
            buf = _fs_flag_buffer(0)
            fcntl.ioctl(fd, set_flags, buf, True)
        finally:
            os.close(fd)
    except OSError:
        return


def _lchflags(path: Path, flags: int) -> None:
    if sys.platform != "darwin":
        _clear_linux_immutable(path)
        return
    libc = _require_darwin_libc()
    if not hasattr(libc, "lchflags"):
        os.chflags(path, flags, follow_symlinks=False)
        return
    rc = libc.lchflags(os.fsencode(path), flags)
    if rc != 0:
        raise OSError(ctypes.get_errno(), f"lchflags: {os.strerror(ctypes.get_errno())}")


def _chmod_nofollow(path: Path, mode: int) -> None:
    os.chmod(path, mode, follow_symlinks=False)


def _destroy_clone_tree(tree: Path) -> None:
    if not (tree.exists() or tree.is_symlink()):
        return
    info = tree.lstat()
    if stat.S_ISLNK(info.st_mode):
        tree.unlink()
        if tree.exists() or tree.is_symlink():
            fail("Go execution clone residue remains")
        return
    if not stat.S_ISDIR(info.st_mode):
        fail("Go execution clone slot is not a disposable tree")
    for base, directories, files in os.walk(tree, topdown=False, followlinks=False):
        base_path = Path(base)
        try:
            _lchflags(base_path, 0)
        except OSError:
            pass
        try:
            _chmod_nofollow(base_path, 0o700)
        except OSError:
            pass
        parent_fd = os.open(
            base_path,
            os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
        )
        try:
            for name in files + directories:
                path = base_path / name
                child = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(child.st_mode):
                    os.unlink(name, dir_fd=parent_fd)
                    continue
                try:
                    _lchflags(path, 0)
                except OSError:
                    pass
                try:
                    os.chmod(
                        name,
                        0o700 if stat.S_ISDIR(child.st_mode) else 0o600,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except (OSError, TypeError, NotImplementedError):
                    _chmod_nofollow(
                        path, 0o700 if stat.S_ISDIR(child.st_mode) else 0o600
                    )
                if stat.S_ISDIR(child.st_mode):
                    os.rmdir(name, dir_fd=parent_fd)
                else:
                    os.unlink(name, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    try:
        _lchflags(tree, 0)
    except OSError:
        pass
    try:
        _chmod_nofollow(tree, 0o700)
    except OSError:
        pass
    os.rmdir(tree)
    if tree.exists() or tree.is_symlink():
        fail("Go execution clone residue remains")


def _fs_ioctl_numbers() -> tuple[int, int]:
    size = ctypes.sizeof(ctypes.c_long)
    # _IOC_READ = 2, _IOC_WRITE = 1, type 'f', GET nr=1, SET nr=2
    get_flags = (2 << 30) | (size << 16) | (ord("f") << 8) | 1
    set_flags = (1 << 30) | (size << 16) | (ord("f") << 8) | 2
    return get_flags, set_flags


def _fs_flag_buffer(value: int = 0) -> array.array:
    long_size = ctypes.sizeof(ctypes.c_long)
    if array.array("l").itemsize == long_size:
        buf = array.array("l", [0])
    elif array.array("q").itemsize == long_size:
        buf = array.array("q", [0])
    else:
        fail(LINUX_UNSUPPORTED)
    buf[0] = value
    return buf


def _apply_linux_immutable(path: Path) -> None:
    flags = os.O_RDONLY | _cloexec_flag() | _nofollow_flag()
    try:
        info = path.lstat()
    except OSError as exc:
        fail(f"{LINUX_UNSUPPORTED}: {exc}")
    if stat.S_ISLNK(info.st_mode):
        return
    if stat.S_ISDIR(info.st_mode):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        get_flags, set_flags = _fs_ioctl_numbers()
        buf = _fs_flag_buffer(0)
        try:
            fcntl.ioctl(fd, get_flags, buf, True)
        except OSError as exc:
            fail(f"{LINUX_UNSUPPORTED}: {exc}")
        buf[0] = int(buf[0]) | FS_IMMUTABLE_FL
        try:
            fcntl.ioctl(fd, set_flags, buf, True)
        except OSError as exc:
            fail(f"{LINUX_UNSUPPORTED}: {exc}")
    finally:
        os.close(fd)


def _same_user_cannot_replace(path: Path) -> bool:
    if sys.platform == "darwin":
        try:
            os.chflags(path, 0, follow_symlinks=False)
        except OSError:
            pass
        else:
            return False
    elif sys.platform.startswith("linux"):
        try:
            flags = os.O_RDONLY | _cloexec_flag() | _nofollow_flag()
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                flags |= os.O_DIRECTORY
            fd = os.open(path, flags)
            try:
                _get, set_flags = _fs_ioctl_numbers()
                buf = _fs_flag_buffer(0)
                fcntl.ioctl(fd, set_flags, buf, True)
            finally:
                os.close(fd)
        except OSError:
            pass
        else:
            return False
    try:
        fd = os.open(path, os.O_WRONLY | _cloexec_flag() | _nofollow_flag())
    except OSError:
        pass
    else:
        os.close(fd)
        return False
    try:
        os.chmod(path, 0o700, follow_symlinks=False)
    except OSError:
        pass
    else:
        return False
    try:
        os.unlink(path)
    except IsADirectoryError:
        try:
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


def _kernel_seal_tree(root: Path) -> None:
    """Seal a synthetic Linux execution tree for hostile coverage.

    macOS release execution categorically uses the separately root-provisioned
    SF_IMMUTABLE tree. A same-user Darwin clone is never accepted.
    """
    if sys.platform == "darwin":
        fail(
            "owner/environment blocker: same-user Darwin Go clone custody is "
            "forbidden; provision the sealed /Library/WinsVPN ReleaseGo runtime"
        )
    elif sys.platform.startswith("linux"):
        for base, directories, files in os.walk(root, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in files + directories:
                path = base_path / name
                if path.is_symlink():
                    continue
                _apply_linux_immutable(path)
                if not _same_user_cannot_replace(path):
                    fail(LINUX_UNSUPPORTED)
            _apply_linux_immutable(base_path)
            if not _same_user_cannot_replace(base_path):
                fail(LINUX_UNSUPPORTED)
    else:
        fail(EXECUTION_BLOCKER)
    probe = root / EXECUTABLE
    if not _same_user_cannot_replace(probe):
        fail(LINUX_UNSUPPORTED if sys.platform.startswith("linux") else EXECUTION_BLOCKER)


def _linux_copy_tree(root: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        fail("Go execution clone slot is not a disposable tree")
    destination.mkdir(mode=0o700)
    for base, directories, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        relative = base_path.relative_to(root)
        target_dir = destination.joinpath(*relative.parts) if relative.parts else destination
        for name in directories:
            source = base_path / name
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode):
                fail("Go clone directory symbolic link rejected")
            (target_dir / name).mkdir(mode=0o700)
        for name in files:
            source = base_path / name
            info = source.lstat()
            target = target_dir / name
            if stat.S_ISLNK(info.st_mode):
                os.symlink(os.readlink(source), target)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("Go clone special file rejected")
            src_fd = os.open(source, _open_flags())
            try:
                dst_fd = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec_flag() | _nofollow_flag(),
                    0o400,
                )
                try:
                    while True:
                        block = os.read(src_fd, 1024 * 1024)
                        if not block:
                            break
                        _write_all(dst_fd, block)
                    os.fsync(dst_fd)
                finally:
                    os.close(dst_fd)
            finally:
                os.close(src_fd)
            target.chmod(stat.S_IMODE(info.st_mode))
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        relative = base_path.relative_to(root)
        target_dir = destination.joinpath(*relative.parts) if relative.parts else destination
        info = base_path.lstat()
        if not stat.S_ISLNK(info.st_mode):
            target_dir.chmod(stat.S_IMODE(info.st_mode))
    destination.chmod(stat.S_IMODE(root.lstat().st_mode))


def clone_execution_tree(root: Path, runtime: Path) -> Path:
    exec_dir = runtime / "exec"
    clone_root = exec_dir / "tree"
    if clone_root.exists() or clone_root.is_symlink():
        _destroy_clone_tree(clone_root)
        if clone_root.exists() or clone_root.is_symlink():
            fail("Go execution clone slot is not a disposable tree")
    if sys.platform == "darwin":
        fail(
            "owner/environment blocker: Darwin release Go execution must use "
            "the root-provisioned sealed tree in place"
        )
    if sys.platform.startswith("linux"):
        _linux_copy_tree(root, clone_root)
        return clone_root
    fail(EXECUTION_BLOCKER)
    raise AssertionError("unreachable")


class BoundParent:
    def __init__(
        self,
        path: Path,
        fd: int,
        identity: tuple[int, ...],
        child_name: str | None,
        child_identity: tuple[int, ...] | None,
    ):
        self.path = path
        self.fd = fd
        self.identity = identity
        self.child_name = child_name
        self.child_identity = child_identity


def _bind_execution_parents(path: Path) -> list[BoundParent]:
    if not path.is_absolute():
        fail("Go execution path is not absolute")
    private = _private_tmp()
    if _path_is_within(path, private):
        anchor = private
    elif _path_is_within(path, OWNER_RUNTIME_PREFIX):
        anchor = Path("/")
    else:
        fail("Go execution path escaped its authenticated prefixes")
    parents: list[BoundParent] = []
    current = anchor
    remainder = path.relative_to(anchor)
    parts = remainder.parts
    current_fd = os.open(
        current, os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag()
    )
    try:
        current_info = os.fstat(current_fd)
        if _pathname_identity(current_info) != _pathname_identity(current.lstat()):
            fail("Go execution parent was replaced before it was bound")
        for index, part in enumerate(parts):
            child_path = current / part
            child = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            parents.append(
                BoundParent(
                    current,
                    current_fd,
                    _pathname_identity(current_info),
                    part,
                    _pathname_identity(child),
                )
            )
            current_fd = -1
            if index == len(parts) - 1:
                break
            if not stat.S_ISDIR(child.st_mode):
                fail("Go execution parent is not a directory")
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
                dir_fd=parents[-1].fd,
            )
            current = child_path
            current_fd = next_fd
            current_info = os.fstat(current_fd)
    except BaseException:
        if current_fd >= 0:
            os.close(current_fd)
        for parent in parents:
            if parent.fd >= 0:
                os.close(parent.fd)
                parent.fd = -1
        raise
    return parents


def _confirm_bound_parents(parents: list[BoundParent], executable_fd: int) -> None:
    if not parents:
        fail("Go execution parents are not bound")
    for parent in parents:
        held = os.fstat(parent.fd)
        if _pathname_identity(held) != parent.identity:
            fail("Go execution parent mutated before spawn")
        if parent.child_name is None or parent.child_identity is None:
            fail("Go execution parent child is unbound")
        child = os.stat(parent.child_name, dir_fd=parent.fd, follow_symlinks=False)
        if _pathname_identity(child) != parent.child_identity:
            fail("Go execution parent child mutated before spawn")
    opened = os.fstat(executable_fd)
    last = parents[-1]
    if last.child_identity is None:
        fail("Go execution executable parent is unbound")
    if _pathname_identity(opened) != last.child_identity:
        fail("Go executable descriptor escaped its bound parent")


def _close_parents(parents: list[BoundParent]) -> None:
    for parent in parents:
        if parent.fd >= 0:
            os.close(parent.fd)
            parent.fd = -1


def _execution_fd_path(executable_fd: int) -> str:
    if sys.platform == "darwin":
        path = f"/dev/fd/{executable_fd}"
    elif sys.platform.startswith("linux"):
        path = f"/proc/self/fd/{executable_fd}"
    else:
        fail(EXECUTION_BLOCKER)
    info = os.stat(path, follow_symlinks=False)
    opened = os.fstat(executable_fd)
    if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino) and not stat.S_ISLNK(info.st_mode):
        fail("Go execution descriptor path does not match the bound file")
    if stat.S_ISLNK(info.st_mode):
        # /proc/self/fd and /dev/fd are typically symlinks to the file.
        target_info = os.stat(path, follow_symlinks=True)
        if (target_info.st_dev, target_info.st_ino) != (opened.st_dev, opened.st_ino):
            fail("Go execution descriptor path does not match the bound file")
    return path


class ExecutionImage:
    def __init__(
        self,
        runtime: Path,
        path: Path,
        digest: str,
        exec_dir: Path,
        tree: Path,
        executable_fd: int,
        parents: list[BoundParent],
        tree_sha: str,
        destroy_tree: bool = True,
    ):
        self.runtime = runtime
        self.path = path
        self.digest = digest
        self.exec_dir = exec_dir
        self.tree = tree
        self.executable_fd = executable_fd
        self.parents = parents
        self.tree_sha = tree_sha
        self.destroy_tree = destroy_tree
        self._cleaned = False

    def cleanup(self) -> None:
        if self._cleaned:
            return
        try:
            if self.executable_fd >= 0:
                os.close(self.executable_fd)
                self.executable_fd = -1
            _close_parents(self.parents)
            if self.destroy_tree:
                exec_info = self.exec_dir.lstat()
                if stat.S_ISLNK(exec_info.st_mode) or not stat.S_ISDIR(exec_info.st_mode):
                    fail("Go execution directory was replaced")
                os.chmod(self.exec_dir, 0o700, follow_symlinks=False)
                _destroy_clone_tree(self.tree)
                if self.tree.exists() or self.tree.is_symlink():
                    fail("Go execution clone residue remains")
        except BaseException:
            self._cleaned = False
            raise
        self._cleaned = True


def authenticated_execution_image(
    binary: Path, expected_sha: str, runtime: Path, expected_tree: str | None = None
) -> ExecutionImage:
    if _path_is_within(binary, OWNER_RUNTIME_PREFIX):
        root = binary.parent.parent
        version_runtime = root.parent.parent
        if (
            version_runtime.parent != OWNER_RUNTIME_PREFIX
            or root != version_runtime / "extracted" / ROOT_NAME
            or binary != root / EXECUTABLE
        ):
            fail("Go executable escaped its owner-provisioned runtime")
        if expected_tree is None:
            fail("Go owner execution requires the authenticated tree digest")
        _verify_prepared_owner_runtime(
            root, binary, expected_tree, expected_sha
        )
        fd = os.open(binary, _open_flags())
        parents: list[BoundParent] = []
        try:
            opened = os.fstat(fd)
            uid, gid = _owner_identity()
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != uid
                or opened.st_gid != gid
                or stat.S_IMODE(opened.st_mode) != 0o555
            ):
                fail("Go owner executable ownership or mode mismatch")
            _require_system_immutable(opened, EXECUTABLE)
            latest = binary.lstat()
            if _identity(opened) != _identity(latest):
                fail("Go owner executable was replaced before it was opened")
            digest = _hash_fd(fd)
            if digest != expected_sha:
                fail("Go owner executable digest mismatch at execution")
            measured_tree = tree_hash(root, owner_runtime=True)
            if expected_tree is not None and measured_tree != expected_tree:
                fail("Go owner tree digest mismatch at execution")
            parents = _bind_execution_parents(binary)
            _confirm_bound_parents(parents, fd)
            if _hash_fd(fd) != expected_sha:
                fail("Go owner executable digest changed before execution")
            return ExecutionImage(
                runtime,
                binary,
                expected_sha,
                runtime / "exec",
                root,
                fd,
                parents,
                measured_tree,
                destroy_tree=False,
            )
        except BaseException:
            if fd >= 0:
                os.close(fd)
            _close_parents(parents)
            raise
    if sys.platform == "darwin":
        fail(
            "owner/environment blocker: private Darwin Go execution is refused; "
            "use the root-provisioned sealed tree"
        )
    exec_dir = runtime / "exec"
    root = runtime / "extracted" / ROOT_NAME
    if binary != root / EXECUTABLE:
        fail("Go executable escaped its extracted root")
    fd = os.open(binary, _open_flags())
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail("Go executable must be one regular non-hardlinked file")
        latest = binary.lstat()
        if _identity(opened) != _identity(latest):
            fail("Go executable was replaced before it was opened")
        digest = _hash_fd(fd)
        if digest != expected_sha:
            fail("Go executable digest mismatch at execution")
    finally:
        os.close(fd)
    clone_root = clone_execution_tree(root, runtime)
    clone_binary = clone_root / EXECUTABLE
    clone_fd = -1
    parents: list[BoundParent] = []
    try:
        clone_fd = os.open(clone_binary, _open_flags())
        clone_info = os.fstat(clone_fd)
        if not stat.S_ISREG(clone_info.st_mode) or clone_info.st_nlink != 1:
            fail("cloned Go executable must be one regular non-hardlinked file")
        if (clone_info.st_dev, clone_info.st_ino) == (
            latest.st_dev,
            latest.st_ino,
        ):
            fail(EXECUTION_BLOCKER)
        if _hash_fd(clone_fd) != expected_sha:
            fail("fd-cloned Go execution image digest mismatch")
        tree_sha = tree_hash(clone_root)
        if expected_tree is not None and tree_sha != expected_tree:
            fail("cloned Go tree digest mismatch at execution")
        _kernel_seal_tree(clone_root)
        after = os.fstat(clone_fd)
        if _pathname_identity(after) != _pathname_identity(clone_info):
            fail("cloned Go executable changed after sealing")
        if _hash_fd(clone_fd) != expected_sha:
            fail("fd-cloned Go execution image digest mismatch")
        if tree_hash(clone_root) != tree_sha:
            fail("cloned Go tree changed after sealing")
        parents = _bind_execution_parents(clone_binary)
        _confirm_bound_parents(parents, clone_fd)
        os.chmod(exec_dir, 0o500, follow_symlinks=False)
    except BaseException:
        if clone_fd >= 0:
            os.close(clone_fd)
            clone_fd = -1
        _close_parents(parents)
        _destroy_clone_tree(clone_root)
        raise
    return ExecutionImage(
        runtime,
        clone_binary,
        expected_sha,
        exec_dir,
        clone_root,
        clone_fd,
        parents,
        tree_sha,
    )


def _spawn_cloned_go(
    image: ExecutionImage,
    arguments: list[str],
    *,
    timeout: float,
    capture: bool,
) -> subprocess.CompletedProcess[str]:
    if image.executable_fd < 0:
        fail("Go execution descriptor is not bound")
    _confirm_bound_parents(image.parents, image.executable_fd)
    if _hash_fd(image.executable_fd) != image.digest:
        fail("fd-cloned Go execution image digest mismatch")
    spawn_path = _execution_fd_path(image.executable_fd)
    env = _minimal_environment(image.runtime, image.tree)
    argv = [spawn_path, *arguments]
    stdout_path = None
    stderr_path = None
    if capture:
        stdout_path = str(image.runtime / "state/tmp/go-stdout")
        stderr_path = str(image.runtime / "state/tmp/go-stderr")
        for path in (stdout_path, stderr_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    _confirm_bound_parents(image.parents, image.executable_fd)
    if sys.platform == "darwin":
        pid = _posix_spawn(
            spawn_path,
            argv,
            env,
            inherit_stdio=not capture,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        returncode = _wait_pid(pid, timeout)
        stdout = ""
        stderr = ""
        if capture:
            stdout = Path(stdout_path or "").read_text(encoding="utf-8", errors="replace")
            stderr = Path(stderr_path or "").read_text(encoding="utf-8", errors="replace")
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    if sys.platform.startswith("linux"):
        stdout_file = None
        stderr_file = None
        try:
            if capture:
                stdout_file = open(stdout_path or os.devnull, "wb")
                stderr_file = open(stderr_path or os.devnull, "wb")
            completed = subprocess.run(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file if capture else subprocess.DEVNULL,
                stderr=stderr_file if capture else subprocess.DEVNULL,
                timeout=timeout,
                check=False,
                pass_fds=(image.executable_fd,),
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            fail("Go runtime execution timed out")
        finally:
            if stdout_file is not None:
                stdout_file.close()
            if stderr_file is not None:
                stderr_file.close()
        stdout = ""
        stderr = ""
        if capture:
            stdout = Path(stdout_path or "").read_text(encoding="utf-8", errors="replace")
            stderr = Path(stderr_path or "").read_text(encoding="utf-8", errors="replace")
        return subprocess.CompletedProcess(argv, completed.returncode, stdout, stderr)
    fail(EXECUTION_BLOCKER)
    raise AssertionError("unreachable")


def _run_go(
    binary: Path,
    runtime: Path,
    root: Path,
    expected_sha: str,
    arguments: list[str],
    *,
    timeout: float,
    capture: bool,
    expected_tree: str | None = None,
) -> subprocess.CompletedProcess[str]:
    image = authenticated_execution_image(
        binary, expected_sha, runtime, expected_tree=expected_tree
    )
    if image.tree != root and not image.destroy_tree:
        image.cleanup()
        fail("Go owner runtime root changed before execution")
    try:
        return _spawn_cloned_go(image, arguments, timeout=timeout, capture=capture)
    finally:
        image.cleanup()


def check_go_identity(
    binary: Path,
    runtime: Path,
    root: Path,
    version: str,
    architecture: str,
    expected_sha: str,
    expected_tree: str | None = None,
) -> None:
    if macho_architectures(binary) != {architecture}:
        fail("Go Mach-O architecture does not match the exact pin")
    expected_version = f"go{version}"
    version_result = _run_go(
        binary,
        runtime,
        root,
        expected_sha,
        ["version"],
        timeout=30,
        capture=True,
        expected_tree=expected_tree,
    )
    expected_banner = f"go version {expected_version} darwin/{architecture}"
    if (
        version_result.returncode != 0
        or version_result.stdout.strip() != expected_banner
        or version_result.stderr
    ):
        fail(
            "Go runtime version probe mismatch: "
            f"rc={version_result.returncode} "
            f"stdout={version_result.stdout!r} stderr={version_result.stderr!r}"
        )
    probes = (
        (["env", "GOVERSION"], expected_version, "Go runtime GOVERSION probe mismatch"),
        (["env", "GOHOSTOS"], "darwin", "Go runtime GOHOSTOS probe mismatch"),
        (["env", "GOHOSTARCH"], architecture, "Go runtime GOHOSTARCH probe mismatch"),
        (["env", "GOTOOLCHAIN"], "local", "Go runtime GOTOOLCHAIN probe mismatch"),
    )
    for arguments, expected, message in probes:
        result = _run_go(
            binary,
            runtime,
            root,
            expected_sha,
            arguments,
            timeout=30,
            capture=True,
            expected_tree=expected_tree,
        )
        if result.returncode != 0 or result.stdout.strip() != expected or result.stderr:
            fail(
                f"{message}: rc={result.returncode} "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )


def _runtime_parts(
    arguments: list[str],
) -> tuple[Path, str, Path, str, Path, str, Path | None, Path | None]:
    if len(arguments) not in {6, 8}:
        fail("Go runtime verification arguments are malformed")
    runtime_text, expected_id, root_text, expected_tree, binary_text, expected_binary = (
        arguments[:6]
    )
    if HEX_RE.fullmatch(expected_tree) is None or HEX_RE.fullmatch(expected_binary) is None:
        fail("Go runtime digest arguments are malformed")
    repo = Path(arguments[6]) if len(arguments) == 8 else None
    manifest = Path(arguments[7]) if len(arguments) == 8 else None
    return (
        Path(runtime_text),
        expected_id,
        Path(root_text),
        expected_tree,
        Path(binary_text),
        expected_binary,
        repo,
        manifest,
    )


def _verify_prepared_owner_runtime(
    root: Path,
    binary: Path,
    expected_tree: str,
    expected_binary: str,
) -> None:
    version_runtime = root.parent.parent
    if (
        version_runtime.parent != OWNER_RUNTIME_PREFIX
        or VERSION_RE.fullmatch(version_runtime.name) is None
        or root != version_runtime / "extracted" / ROOT_NAME
        or binary != root / EXECUTABLE
    ):
        fail("Go owner-runtime pointers changed")
    _verify_owner_ancestors(version_runtime)
    _require_owner_entry(
        version_runtime,
        mode=0o555,
        directory=True,
        immutable=True,
        label="runtime",
    )
    _exact_names(
        version_runtime,
        {"archive", "extracted", OWNER_RECEIPT_NAME},
        "runtime",
    )
    archive_name = f"go{version_runtime.name}.darwin-arm64.tar.gz"
    archive_dir = version_runtime / "archive"
    _require_owner_entry(
        archive_dir,
        mode=0o555,
        directory=True,
        immutable=True,
        label="archive directory",
    )
    _exact_names(archive_dir, {archive_name}, "archive directory")
    archive = archive_dir / archive_name
    archive_info = _require_owner_entry(
        archive,
        mode=0o444,
        directory=False,
        immutable=True,
        label="archive",
    )
    extracted = version_runtime / "extracted"
    _require_owner_entry(
        extracted,
        mode=0o555,
        directory=True,
        immutable=True,
        label="extracted directory",
    )
    _exact_names(extracted, {ROOT_NAME}, "extracted directory")
    receipt_path = version_runtime / OWNER_RECEIPT_NAME
    _require_owner_entry(
        receipt_path,
        mode=0o444,
        directory=False,
        immutable=True,
        label="receipt",
    )
    receipt = _parse_owner_receipt(
        bind_regular_file(
            receipt_path,
            max_size=MAX_TRUST,
            label="Go owner runtime receipt",
        )
    )
    pin = {
        "version": _text(receipt, "version"),
        "archive_sha": _text(receipt, "archive_sha256"),
        "tree_sha": _text(receipt, "tree_sha256"),
        "executable_sha": _text(receipt, "executable_sha256"),
    }
    materials = {
        key: _text(receipt, key)
        for key in (
            "controller_sha256",
            "wrapper_sha256",
            "provisioner_sha256",
            "manifest_sha256",
            "trust_anchor_sha256",
            "source_freeze_producer_sha256",
        )
    }
    bootstrap = verify_sealed_bootstrap(materials, pin)
    expected = {
        "version": version_runtime.name,
        "runtime": str(version_runtime),
        "sealed_bootstrap": bootstrap["path"],
        "sealed_bootstrap_identity": bootstrap["identity"],
        "archive_name": archive_name,
        "archive_size": archive_info.st_size,
        "tree_sha256": expected_tree,
        "executable": EXECUTABLE,
        "executable_sha256": expected_binary,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            fail(f"Go owner runtime receipt mismatch during execution: {key}")
    if digest_file(archive) != pin["archive_sha"]:
        fail("Go owner runtime archive digest changed during execution")
    if tree_hash(root, owner_runtime=True) != expected_tree:
        fail("Go owner runtime tree content changed")
    if digest_file(binary) != expected_binary:
        fail("Go runtime executable content changed")


def verify_runtime(arguments: list[str]) -> tuple[Path, Path, Path, str]:
    (
        runtime,
        expected_id,
        root,
        expected_tree,
        binary,
        expected_binary,
        repo,
        manifest,
    ) = _runtime_parts(arguments)
    if runtime_identity(runtime) != expected_id:
        fail("Go runtime identity changed")
    if runtime.parent != _private_tmp() or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("Go runtime pointer escaped its private prefix")
    _require_private_state(runtime)
    if _path_is_within(root, OWNER_RUNTIME_PREFIX):
        if repo is None or manifest is None or not repo.is_absolute():
            fail("Go owner-runtime verification requires the live reviewed repository")
        expected_manifest = repo / "tools" / MANIFEST_NAME
        if not manifest.is_absolute() or manifest != expected_manifest:
            fail("replacement Go pin manifest cannot self-authorize during execution")
        authorized = authorize_repo(repo)
        issuance = _bind_external_issuance(repo)
        pin = parse_pin_bytes(authorized[2])
        owner = verify_owner_runtime(repo, pin, authorized, issuance)
        expected_owner = {
            "ROOT": str(root),
            "TREE_SHA256": expected_tree,
            "BINARY": str(binary),
            "BINARY_SHA256": expected_binary,
        }
        for key, value in expected_owner.items():
            if owner[key] != value:
                fail(f"Go live owner-runtime binding changed: {key}")
    else:
        if repo is not None or manifest is not None:
            fail("private Go runtime received unexpected repository arguments")
        expected_root_prefix = runtime / "extracted"
        if root.parent != expected_root_prefix or binary != root / EXECUTABLE:
            fail("Go runtime pointers changed")
        if tree_hash(root) != expected_tree:
            fail("Go runtime tree content changed")
    if not _path_is_within(root, OWNER_RUNTIME_PREFIX) and digest_file(binary) != expected_binary:
        fail("Go runtime executable content changed")
    return runtime, root, binary, expected_binary


def _plan_cleanup(runtime: Path) -> list[tuple[str, Path, tuple[int, ...]]]:
    runtime_info = runtime.lstat()
    if runtime.is_symlink() or not stat.S_ISDIR(runtime_info.st_mode):
        fail("refusing cleanup of a substituted Go runtime")
    if runtime_info.st_uid != os.getuid():
        fail("refusing cleanup of a foreign-owned Go runtime")
    plan: list[tuple[str, Path, tuple[int, ...]]] = []
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external Go runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, _identity(info)))
                continue
            if not stat.S_ISREG(info.st_mode):
                fail("refusing cleanup of an unsupported Go runtime entry")
            if info.st_nlink != 1:
                fail("refusing cleanup of a hardlinked Go runtime file")
            plan.append(("file", path, _identity(info)))
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external Go runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, _identity(info)))
                continue
            if not stat.S_ISDIR(info.st_mode):
                fail("refusing cleanup of an unsupported Go runtime directory")
            plan.append(("dir", path, _identity(info)))
    plan.append(("dir", runtime, _identity(runtime_info)))
    return plan


def _destroy_runtime(runtime: Path) -> None:
    if _path_is_within(runtime, Path("/Library")):
        fail("Go cleanup categorically refuses every /Library path")
    private = _private_tmp()
    if runtime.parent != private or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing Go cleanup outside the private runtime prefix")
    plan = _plan_cleanup(runtime)
    for kind, path, expected in plan:
        current = path.lstat()
        if _identity(current) != expected:
            fail("Go runtime changed after cleanup validation")
        if kind == "file":
            if current.st_nlink != 1:
                fail("refusing cleanup of a hardlinked Go runtime file")
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
            )
            try:
                fd = os.open(
                    path.name,
                    os.O_RDONLY | _cloexec_flag() | _nofollow_flag(),
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(fd)
                    if opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (
                        expected[0],
                        expected[1],
                    ):
                        fail("refusing cleanup of a hardlinked or external Go runtime file")
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)
            finally:
                os.close(parent_fd)
        elif kind == "dir":
            os.chmod(path, 0o700, follow_symlinks=False)
    for kind, path, expected in plan:
        current = path.lstat()
        parent_fd = -1
        if path != runtime:
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
            )
        try:
            if kind == "file":
                if current.st_nlink != 1 or (current.st_dev, current.st_ino) != (
                    expected[0],
                    expected[1],
                ):
                    fail("refusing unlink of a hardlinked or external Go runtime file")
                os.unlink(path.name, dir_fd=parent_fd)
            elif kind == "symlink":
                if not stat.S_ISLNK(current.st_mode):
                    fail("refusing unlink of a substituted Go runtime symlink")
                if (current.st_dev, current.st_ino) != (expected[0], expected[1]):
                    fail("refusing unlink of a substituted Go runtime symlink")
                os.unlink(path.name, dir_fd=parent_fd)
            elif kind == "dir":
                if path == runtime:
                    os.rmdir(path)
                else:
                    os.rmdir(path.name, dir_fd=parent_fd)
        except OSError as exc:
            if runtime.exists() or runtime.is_symlink():
                fail(f"Go runtime cleanup left residue: {exc}")
            raise
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)
    if runtime.exists() or runtime.is_symlink():
        fail("Go runtime cleanup left residue")


def install_extracted_runtime(pin: dict[str, str]) -> dict[str, str]:
    """Extract and freeze a Go runtime without claiming execution custody."""
    archive = Path(pin["archive"])
    require_safe_input(archive, f"go{pin['version']}.darwin-arm64.tar.gz")
    if sys.platform != "darwin":
        fail(
            "owner/environment blocker: official Go archive pin is darwin-arm64; "
            "Linux FS_IMMUTABLE execution is unsupported without a reviewed Linux archive identity"
        )
    runtime = Path(tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir=str(_private_tmp())))
    runtime.chmod(0o700)
    try:
        incoming = runtime / "incoming.tar.gz"
        extracted = runtime / "extracted"
        state = runtime / "state"
        exec_dir = runtime / "exec"
        state.mkdir(mode=0o700)
        (state / "home").mkdir(mode=0o700)
        (state / "tmp").mkdir(mode=0o700)
        exec_dir.mkdir(mode=0o700)
        copy_stable(archive, incoming, pin["archive_sha"])
        root = safe_extract(incoming, extracted, pin["root"])
        binary = root / pin["executable"]
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Go extracted tree or executable digest mismatch")
        return {
            "RUNTIME": str(runtime),
            "RUNTIME_ID": runtime_identity(runtime),
            "ROOT": str(root),
            "TREE_SHA256": pin["tree_sha"],
            "BINARY": str(binary),
            "BINARY_SHA256": pin["executable_sha"],
        }
    except BaseException as exc:
        try:
            _destroy_runtime(runtime)
        except (OSError, Refused):
            pass
        if runtime.exists() or runtime.is_symlink():
            fail(f"Go runtime cleanup left residue after: {exc}")
        raise


def _create_private_execution_state() -> dict[str, str]:
    if os.getuid() == 0 or os.geteuid() == 0:
        fail(
            "owner-blocked: Go release use must execute as a non-root user "
            "against the previously root-provisioned runtime"
        )
    runtime = Path(tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir=str(_private_tmp())))
    runtime.chmod(0o700)
    try:
        state = runtime / "state"
        exec_dir = runtime / "exec"
        state.mkdir(mode=0o700)
        (state / "home").mkdir(mode=0o700)
        (state / "tmp").mkdir(mode=0o700)
        exec_dir.mkdir(mode=0o700)
        return {
            "RUNTIME": str(runtime),
            "RUNTIME_ID": runtime_identity(runtime),
        }
    except BaseException:
        _destroy_runtime(runtime)
        raise


def prepare(repo_text: str, manifest_text: str) -> None:
    repo = Path(repo_text)
    manifest = Path(manifest_text)
    if not repo.is_absolute() or not manifest.is_absolute():
        fail("Go custody repository and manifest must be absolute")
    expected_manifest = repo / "tools" / MANIFEST_NAME
    if manifest != expected_manifest:
        fail("replacement Go pin manifest cannot self-authorize")
    if os.getuid() == 0 or os.geteuid() == 0:
        fail(
            "owner-blocked: Go release use must execute as a non-root user "
            "against the previously root-provisioned runtime"
        )
    authorized = authorize_repo(repo)
    manifest_data = authorized[2]
    issuance = _bind_external_issuance(repo)
    if manifest != expected_manifest:
        fail("replacement Go pin manifest cannot self-authorize")
    pin = parse_pin_bytes(manifest_data)
    owner = verify_owner_runtime(repo, pin, authorized, issuance)
    fields = {**_create_private_execution_state(), **owner}
    runtime = Path(fields["RUNTIME"])
    root = Path(fields["ROOT"])
    binary = Path(fields["BINARY"])
    try:
        check_go_identity(
            binary,
            runtime,
            root,
            pin["version"],
            pin["architecture"],
            pin["executable_sha"],
            pin["tree_sha"],
        )
        if (
            tree_hash(root, owner_runtime=True) != pin["tree_sha"]
            or digest_file(binary) != pin["executable_sha"]
        ):
            fail("Go runtime changed during identity validation")
        print(f"RUNTIME|{fields['RUNTIME']}")
        print(f"RUNTIME_ID|{fields['RUNTIME_ID']}")
        print(f"ROOT|{fields['ROOT']}")
        print(f"TREE_SHA256|{fields['TREE_SHA256']}")
        print(f"BINARY|{fields['BINARY']}")
        print(f"BINARY_SHA256|{fields['BINARY_SHA256']}")
        print(f"REPO|{repo}")
        print(f"MANIFEST|{manifest}")
    except BaseException as exc:
        try:
            _destroy_runtime(runtime)
        except (OSError, Refused):
            pass
        if runtime.exists() or runtime.is_symlink():
            fail(f"Go runtime cleanup left residue after: {exc}")
        raise


def cleanup(runtime_text: str, expected_id: str) -> None:
    runtime = Path(runtime_text)
    if _path_is_within(runtime, Path("/Library")):
        fail("Go cleanup categorically refuses every /Library path")
    if runtime.parent != _private_tmp() or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing Go cleanup outside the private runtime prefix")
    if runtime.is_symlink() or not runtime.is_dir():
        fail("refusing cleanup of a substituted Go runtime")
    if runtime_identity(runtime) != expected_id:
        fail("refusing cleanup of a replaced Go runtime")
    _destroy_runtime(runtime)


def run_action(arguments: list[str]) -> int:
    try:
        separator = arguments.index("--")
    except ValueError:
        fail("Go run action requires an argument separator")
    verification = arguments[:separator]
    command = arguments[separator + 1 :]
    _reject_go_command_overrides(command)
    timeout = DEFAULT_RUN_TIMEOUT
    if len(verification) in {7, 9}:
        timeout_text = verification.pop()
        if not timeout_text.isdigit():
            fail("Go run timeout must be an integer")
        timeout = int(timeout_text)
        if timeout <= 300 or timeout > MAX_RUN_TIMEOUT:
            fail("Go run timeout must be greater than 300 and at most 21600 seconds")
    runtime, root, binary, expected_binary = verify_runtime(verification)
    try:
        completed = _run_go(
            binary,
            runtime,
            root,
            expected_binary,
            command,
            timeout=timeout,
            capture=False,
            expected_tree=verification[3] if len(verification) in {6, 8} else None,
        )
    except BaseException:
        verify_runtime(verification)
        raise
    verify_runtime(verification)
    return completed.returncode


def main() -> int:
    try:
        if len(sys.argv) < 2:
            fail("missing Go custody action")
        action = sys.argv[1]
        if action == "provision" and len(sys.argv) == 5:
            print(provision_owner_runtime(sys.argv[2], sys.argv[3], sys.argv[4]))
        elif action == "prepare" and len(sys.argv) == 4:
            prepare(sys.argv[2], sys.argv[3])
        elif action == "snapshot":
            fail("Go custody snapshot self-authorization is owner-blocked")
        elif action == "verify":
            verify_runtime(sys.argv[2:])
        elif action == "run":
            return run_action(sys.argv[2:])
        elif action == "cleanup" and len(sys.argv) == 4:
            cleanup(sys.argv[2], sys.argv[3])
        else:
            fail("unknown or malformed Go custody action")
    except (
        Refused,
        OSError,
        KeyError,
        json.JSONDecodeError,
        zlib.error,
        subprocess.SubprocessError,
    ) as exc:
        print(f"release-go custody: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
