#!/usr/bin/env python3
"""Prepare, verify, run, and clean a private Chrome for Testing runtime.

The production ``tools.browser`` pin in ``tools/toolchain-pins.json`` binds
this exact schema:

    tools.browser.product
    tools.browser.version
    tools.browser.platform
    tools.browser.architecture
    tools.browser.archive_format
    tools.browser.archive_path.darwin_arm64
    tools.browser.archive_sha256.darwin_arm64
    tools.browser.install_tree_sha256.darwin_arm64
    tools.browser.top_level_root
    tools.browser.executable
    tools.browser.executable_sha256
    tools.browser.signing_identity

The production document is parsed with its complete repository schema.
Caller-supplied manifests and controllers never self-authorize. Adjacent
trust-anchor hashes are a local pin only. Authorization requires a genuinely
external owner issuance contract from ``WINS_BROWSER_CUSTODY_ISSUANCE`` or
fails closed owner-blocked. Controller, wrapper, production pin manifest, and
the dedicated trust-anchor are bound through O_NOFOLLOW single-link descriptor
reads and must match the trust-anchor digests; stale trust is refused and
reported and is never rehashed. The freeze producer is bound by digest and is
never exec'd. Snapshot self-authorization and injected test runners cannot
produce a production PASS.

``product`` is ``Google Chrome for Testing``, ``platform`` is the official
Chrome for Testing ``mac-arm64`` slug, ``architecture`` is ``arm64``, and
``archive_format`` is ``zip``. The versioned archive basename must be
``chrome-mac-arm64-<version>.zip``. Relative in-root framework symlinks are
authenticated; escaping, absolute, duplicate, colliding, and special members
are refused. Local and central ZIP compression method, complete flags, CRC,
compressed size, and uncompressed size are compared canonically.

``run`` fclonefileat-clones the pinned install tree and posix_spawn-executes
that clone only after the host proves the clone bytes and tree are immutable
against same-user path replacement. If this host cannot provide that
kernel-bound execution custody, execution fails closed with an explicit
owner/environment blocker before any browser code runs. Authenticated Python
plus Chrome Seatbelt nesting is required; nesting failure is fail-closed and
never falls back to ambient Python. Cleanup reports failure and never marks
complete while residue remains.

Official Chrome for Testing is ad-hoc signed. The trust root is the official
archive, install-tree, and executable SHA-256 pins. ``/usr/bin/codesign
--verify --deep --strict`` runs on the exact frozen application bundle
together with ``--display`` identity capture. Strict verification checks
sealed-bundle integrity, not Apple publisher identity.
"""

from __future__ import annotations

import ctypes
import datetime as dt
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile


MAX_ARCHIVE = 512 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
MAX_TRUST = 64 * 1024
MAX_ISSUANCE = 64 * 1024
MAX_FREEZE_PRODUCER = 4 * 1024 * 1024
MAX_EXPANDED = 2 * 1024 * 1024 * 1024
MAX_MEMBER = 512 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_CENTRAL_DIR = 16 * 1024 * 1024
MAX_ZIP_EXTRA = 4096
MAX_RATIO = 100
MAX_DEPTH = 32
MAX_PATH_BYTES = 1024
ZIP_EOCD = 22
ZIP64_EXTRA_ID = 1
ZIP_ENCRYPT = 1
ZIP_DATA_DESCRIPTOR = 8
ARM64_CPU_TYPE = 0x0100000C
VERSION_RE = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z"
)
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
ISSUANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
ISO_UTC = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PRODUCT = "Google Chrome for Testing"
TARGET_ID = "chrome-for-testing"
EDGE_TARGET_ID = "edge-extension-package"
FIREFOX_TARGET_ID = "firefox-extension-package"
CROSS_TARGET_IDS = (EDGE_TARGET_ID, FIREFOX_TARGET_ID)
BUNDLE_IDENTIFIER = "com.google.chrome.for.testing"
PLATFORM = "mac-arm64"
ARCHITECTURE = "arm64"
ARCHIVE_FORMAT = "zip"
ROOT_NAME = "chrome-mac-arm64"
APP_NAME = "Google Chrome for Testing.app"
EXECUTABLE = "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
INFO_PLIST = "Google Chrome for Testing.app/Contents/Info.plist"
CODESIGN = Path("/usr/bin/codesign")
PLUTIL = Path("/usr/bin/plutil")
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
TRUE_BIN = Path("/usr/bin/true")
RUNTIME_PREFIX = "wins-release-browser."
PRIVATE_TMP = Path("/private/tmp")
OWNER_LIBRARY_ROOT = Path("/Library/WinsVPN")
PRODUCTION_AUTHORITY_PREFIX = OWNER_LIBRARY_ROOT / "ReleaseBrowserAuthority" / "v1"
PRODUCTION_AUTHORITY_PATH = PRODUCTION_AUTHORITY_PREFIX / "authority.json"
OWNER_AUTHORITY_PREFIX = PRODUCTION_AUTHORITY_PREFIX
OWNER_AUTHORITY_PATH = PRODUCTION_AUTHORITY_PATH
CONTROLLER_NAME = "release_browser_archive_custody.py"
WRAPPER_NAME = "release_browser_archive_custody.sh"
MANIFEST_NAME = "toolchain-pins.json"
TRUST_ANCHOR_NAME = "release_browser_archive_custody.trust.json"
TRUST_CONTRACT = "winsvpn-browser-archive-custody-trust-v1"
AUTHORITY_CONTRACT = "winsvpn-browser-archive-custody-authority-v1"
ISSUANCE_CONTRACT = "winsvpn-browser-archive-custody-issuance-v2"
SIGNATURE_ALGORITHM = "ecdsa-p256-sha256-x962"
ISSUANCE_ENV = "WINS_BROWSER_CUSTODY_ISSUANCE"
ISSUANCE_ISSUER = "winsvpn-browser-archive-custody"
SOURCE_FREEZE_PRODUCER = "release_source_freeze.py"
REVIEWED_ISSUANCE_UTC = dt.datetime(2026, 8, 23, 0, 0, 0, tzinfo=dt.timezone.utc)
MAX_ISSUANCE_AGE = dt.timedelta(hours=72)
MAX_ISSUANCE_SKEW = dt.timedelta(minutes=5)
DOCUMENT_KEYS = (
    "schema_version",
    "_purpose",
    "tools",
    "pending_convergence",
    "_declared_divergences_note",
    "declared_divergences",
    "sites",
    "discovery_scan_roots",
    "_not_covered",
)
TOOLS_KEYS = (
    "python",
    "node",
    "browser",
    "openssl",
    "google_cloud_cli",
    "flutter",
    "flutter_pub_cache",
    "java",
    "cocoapods",
    "go",
    "gradle",
    "android_gradle_plugin",
    "kotlin",
    "xcode",
    "android_ndk",
    "linux",
)
PENDING_KEYS = (
    "target",
    "status",
    "decided_on",
    "last_live_audit_utc",
    "last_live_audit_note",
    "decision",
)
BROWSER_KEYS = (
    "product",
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
    "signing_identity",
)
PLATFORM_KEYS = ("darwin_arm64",)
TRUST_KEYS = (
    "contract",
    "schema_version",
    "controller",
    "wrapper",
    "manifest",
    "trust_anchor",
    "issuance_env",
    "issuance_contract",
    "authority",
    "authority_contract",
    "signature_algorithm",
    "controller_sha256",
    "wrapper_sha256",
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
    "target",
    "product",
    "version",
    "archive_sha256",
    "controller",
    "wrapper",
    "manifest",
    "trust_anchor",
    "source_freeze_producer",
    "controller_sha256",
    "wrapper_sha256",
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
CLONE_NOFOLLOW = 0x0001
POSIX_SPAWN_SETSID = 0x0400
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Chrome tree "
    "immutable against same-user path replacement through execution"
)
MACOS_BLOCKER = (
    "owner/environment blocker: macOS kernel-bound Chrome execution is required"
)
NESTING_BLOCKER = (
    "owner/environment blocker: authenticated Python Seatbelt cannot nest a "
    "Chrome Seatbelt; ambient Python is refused"
)
FREEZE_BLOCKER = (
    "authenticated current source-freeze producer digest is required to bind "
    "Chrome controller, wrapper, manifest, and trust-anchor bytes"
)
OWNER_BLOCKED_UNAVAILABLE = (
    "owner blocked: current reviewed Chrome custody issuance identity is unavailable"
)
OWNER_BLOCKED_WRITABLE = (
    "owner blocked: current reviewed Chrome custody issuance identity is writable"
)
OWNER_BLOCKED_ADJACENT = (
    "owner blocked: Chrome custody issuance must be external to the candidate repository"
)
OWNER_BLOCKED_AUTHORITY = (
    "owner blocked: immutable external Chrome custody authority is unavailable"
)
OWNER_BLOCKED_STORE_IDS = (
    "owner blocked: Chrome and Edge store IDs and store publication authority are unavailable"
)
INJECTED_RUNNER_BLOCKER = (
    "production Chrome custody PASS through an injected or test runner is refused"
)
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
_LIBC.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_LIBC.sandbox_check.restype = ctypes.c_int
TRUST_ROOT_NOTE = (
    "Official Chrome for Testing is ad-hoc signed. "
    "/usr/bin/codesign --verify --deep --strict checks frozen-bundle integrity, "
    "not Apple publisher identity. Trust is the official archive, install-tree, "
    "and executable SHA-256 pins."
)


class Refused(ValueError):
    """A fail-closed custody refusal."""


def fail(message: str) -> None:
    raise Refused(message)


def _nofollow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required for Chrome custody")
    return flag


def _cloexec_flag() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _posix_errno(rc: int, what: str) -> OSError:
    return OSError(rc, f"{what}: {os.strerror(rc)}")


def _must(rc: int, what: str) -> None:
    if rc:
        raise _posix_errno(rc if rc > 0 else ctypes.get_errno(), what)


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


class AuthenticatedArchive:
    """One bound descriptor for an authenticated Chrome ZIP snapshot."""

    def __init__(self, path: Path, fd: int, identity: tuple[int, ...], digest: str) -> None:
        self.path = path
        self.fd = fd
        self.identity = identity
        self.digest = digest
        self.central_offset = -1
        self.member_count = -1
        self.layout: list[tuple[bytes, int, int, int, int, int, int]] = []

    def ensure_bound(self) -> None:
        if self.fd < 0:
            fail("authenticated Chrome archive descriptor is closed")
        current = os.fstat(self.fd)
        if _identity(current) != self.identity:
            fail("authenticated Chrome archive was replaced")
        try:
            latest = self.path.lstat()
        except FileNotFoundError:
            fail("authenticated Chrome archive was replaced")
        if _identity(latest) != self.identity:
            fail("authenticated Chrome archive was replaced")

    def fileobj(self):
        self.ensure_bound()
        dup = os.dup(self.fd)
        try:
            os.lseek(dup, 0, os.SEEK_SET)
            return os.fdopen(dup, "rb")
        except Exception:
            os.close(dup)
            raise

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> AuthenticatedArchive:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def digest_file(path: Path) -> str:
    fd = os.open(path, _open_flags())
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = path.lstat()
    if not (_identity(before) == _identity(after) == _identity(latest)):
        fail(f"file changed while it was hashed: {path}")
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
        if info.st_uid not in {0, os.getuid()}:
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
    if info.st_uid not in {0, os.getuid()}:
        fail(f"foreign-owned path component rejected: {path}")
    if mode & 0o022 and not (
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and mode & stat.S_ISVTX
    ):
        fail(f"unsafe writable path component rejected: {path}")


def require_safe_input(path: Path, expected_name: str) -> None:
    if path.suffix.lower() == ".xpi" or expected_name.lower().endswith(".xpi"):
        fail("Firefox/XPI archives cannot substitute for the Chrome for Testing pin")
    if not expected_name.endswith(".zip"):
        fail("only exact official Chrome for Testing ZIP archives are accepted")
    if path.name != expected_name:
        fail("Chrome archive basename does not match its release identity")
    lowered = path.name.lower()
    if "wins-vpn-companion-chrome" in lowered or "wins-vpn-companion-edge" in lowered or "wins-vpn-companion-firefox" in lowered:
        fail("Chrome, Edge, or Firefox/XPI extension archives cannot substitute for the Chrome for Testing pin")
    _safe_path_components(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
        fail("Chrome archive must be one owner-controlled regular file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail("Chrome archive must have immutable mode 0444")


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
    if before.st_uid not in {0, os.getuid()}:
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
        controller, max_size=MAX_CONTROLLER, label="Chrome custody controller"
    )
    manifest_data = bind_regular_file(
        manifest, max_size=MAX_MANIFEST, label="Chrome pin manifest"
    )
    if b"\0" in controller_data:
        fail("invalid Chrome custody controller source")
    if b"\0" in manifest_data:
        fail("Chrome pin manifest contains a NUL")
    return controller_data, manifest_data


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_trust_anchor(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Chrome custody trust-anchor contains a NUL")
    try:
        document = json.loads(
            data,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Chrome custody trust-anchor is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Chrome custody trust-anchor is not JSON: {exc}")
    root = _mapping(document, "trust-anchor")
    _require_keys(root, TRUST_KEYS, "trust-anchor")
    if _text(root, "contract") != TRUST_CONTRACT:
        fail("Chrome custody trust-anchor contract mismatch")
    if _exact_int(root.get("schema_version"), "schema_version") != 1:
        fail("Chrome custody trust-anchor schema_version mismatch")
    if _text(root, "controller") != f"tools/{CONTROLLER_NAME}":
        fail("Chrome custody trust-anchor controller path mismatch")
    if _text(root, "wrapper") != f"tools/{WRAPPER_NAME}":
        fail("Chrome custody trust-anchor wrapper path mismatch")
    if _text(root, "manifest") != f"tools/{MANIFEST_NAME}":
        fail("Chrome custody trust-anchor manifest path mismatch")
    if _text(root, "trust_anchor") != f"tools/{TRUST_ANCHOR_NAME}":
        fail("Chrome custody trust-anchor path mismatch")
    if _text(root, "issuance_env") != ISSUANCE_ENV:
        fail("Chrome custody trust-anchor issuance_env mismatch")
    if _text(root, "issuance_contract") != ISSUANCE_CONTRACT:
        fail("Chrome custody trust-anchor issuance_contract mismatch")
    if _text(root, "authority") != str(PRODUCTION_AUTHORITY_PATH):
        fail("Chrome custody trust-anchor authority path mismatch")
    if _text(root, "authority_contract") != AUTHORITY_CONTRACT:
        fail("Chrome custody trust-anchor authority_contract mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Chrome custody trust-anchor signature_algorithm mismatch")
    for key in ("controller_sha256", "wrapper_sha256", "manifest_sha256"):
        if HEX_RE.fullmatch(_text(root, key)) is None:
            fail(f"invalid Chrome custody trust-anchor digest: {key}")
    return root


def _stale_trust_refused(label: str, live: str, pinned: str) -> None:
    fail(
        f"stale Chrome custody trust refused: {label} digest does not match "
        f"the trust-anchor (live={live} trust={pinned})"
    )


def _require_digest(actual: str, expected: str, label: str) -> None:
    if actual != expected:
        _stale_trust_refused(label, actual, expected)


def _canonical_json_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("ascii")


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
        fail("Chrome custody authority contains a NUL")
    try:
        document = json.loads(
            data,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Chrome custody authority is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Chrome custody authority is not JSON: {exc}")
    root = _mapping(document, "authority")
    if data != _canonical_json_bytes(root):
        fail("Chrome custody authority is not canonical JSON")
    _require_keys(root, AUTHORITY_KEYS, "authority")
    if _text(root, "contract") != AUTHORITY_CONTRACT:
        fail("Chrome custody authority contract mismatch")
    if _exact_int(root.get("schema_version"), "authority schema_version") != 1:
        fail("Chrome custody authority schema_version mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Chrome custody authority signature_algorithm mismatch")
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
        fail("Chrome custody authority must contain one PEM public key")
    key_id = _text(root, "key_id")
    if HEX_RE.fullmatch(key_id) is None or key_id != _digest_bytes(public_key):
        fail("Chrome custody authority key_id mismatch")
    issuance_id = _text(root, "active_issuance_id")
    if ISSUANCE_RE.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Chrome custody authority active_issuance_id is invalid")
    sequence = _exact_int(root.get("active_sequence"), "authority active_sequence")
    if sequence <= 0:
        fail("Chrome custody authority active_sequence is invalid")
    not_before = _text(root, "not_before_utc")
    if ISO_UTC.fullmatch(not_before) is None:
        fail("Chrome custody authority not_before_utc must be exact ISO UTC")
    return root


def _require_system_immutable(info: os.stat_result, label: str) -> None:
    if not info.st_flags & SF_IMMUTABLE:
        fail(f"{label} must be protected by SF_IMMUTABLE")


def _verify_authority_path(path: Path, *, require_immutable: bool) -> bytes:
    if path != OWNER_AUTHORITY_PATH or not path.is_absolute():
        fail("Chrome custody authority path mismatch")
    current = Path(path.anchor)
    authority_roots = {OWNER_AUTHORITY_PREFIX.parent, OWNER_AUTHORITY_PREFIX}
    try:
        for part in path.parts[1:-1]:
            current /= part
            info = current.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail(f"unsafe Chrome custody authority ancestor: {current}")
            writable = bool(mode & 0o022)
            sticky_root_boundary = (
                info.st_uid == 0
                and info.st_gid == 0
                and bool(mode & stat.S_ISVTX)
                and current not in authority_roots
            )
            if (
                info.st_uid != 0
                or info.st_gid != 0
                or (writable and not sticky_root_boundary)
            ):
                fail(f"writable or foreign Chrome custody authority ancestor: {current}")
            if require_immutable and current in authority_roots:
                _require_system_immutable(info, f"authority ancestor {current}")
        info = path.lstat()
    except FileNotFoundError:
        fail(OWNER_BLOCKED_AUTHORITY)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o444
    ):
        fail("Chrome custody authority file custody mismatch")
    if require_immutable:
        _require_system_immutable(info, "authority file")
    return bind_regular_file(path, max_size=MAX_TRUST, label="Chrome custody authority")


def _verify_system_openssl() -> Path:
    path = Path("/usr/bin/openssl")
    for parent in (Path("/usr"), Path("/usr/bin")):
        info = parent.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
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
    with tempfile.TemporaryFile(dir=str(PRIVATE_TMP)) as key_file, tempfile.TemporaryFile(
        dir=str(PRIVATE_TMP)
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
                "HOME": str(PRIVATE_TMP),
                "TMPDIR": str(PRIVATE_TMP),
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
        fail("Chrome custody issuance signature verification failed")


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


def _parse_issuance(
    data: bytes, authority: dict[str, object]
) -> dict[str, object]:
    if b"\0" in data:
        fail("Chrome custody issuance contains a NUL")
    try:
        document = json.loads(
            data,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Chrome custody issuance is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Chrome custody issuance is not JSON: {exc}")
    root = _mapping(document, "issuance")
    if data != _canonical_json_bytes(root):
        fail("Chrome custody issuance is not canonical JSON")
    _require_keys(root, ISSUANCE_KEYS, "issuance")
    if _text(root, "contract") != ISSUANCE_CONTRACT:
        fail("Chrome custody issuance contract mismatch")
    if _exact_int(root.get("schema_version"), "issuance schema_version") != 2:
        fail("Chrome custody issuance schema_version mismatch")
    issuance_id = _text(root, "issuance_id")
    if ISSUANCE_RE.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Chrome custody issuance_id is not a current reviewed identity")
    created_text = _text(root, "created_utc")
    expires_text = _text(root, "expires_utc")
    if ISO_UTC.fullmatch(created_text) is None or ISO_UTC.fullmatch(expires_text) is None:
        fail("Chrome custody issuance timestamps must be exact ISO UTC")
    created = dt.datetime.strptime(created_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    expires = dt.datetime.strptime(expires_text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    now = dt.datetime.now(dt.timezone.utc)
    if created < REVIEWED_ISSUANCE_UTC:
        fail("Chrome custody issuance created_utc is stale")
    if created > now + MAX_ISSUANCE_SKEW:
        fail("Chrome custody issuance created_utc is future-dated")
    if now - created > MAX_ISSUANCE_AGE or expires <= now:
        fail("Chrome custody issuance created_utc is stale")
    if expires <= created or expires - created > MAX_ISSUANCE_AGE:
        fail("Chrome custody issuance validity interval is invalid")
    authority_not_before = dt.datetime.strptime(
        _text(authority, "not_before_utc"), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=dt.timezone.utc)
    if created < authority_not_before:
        fail("Chrome custody issuance predates the active authority")
    sequence = _exact_int(root.get("sequence"), "issuance sequence")
    if sequence != _exact_int(authority.get("active_sequence"), "authority sequence"):
        fail("Chrome custody issuance sequence is replayed or inactive")
    if issuance_id != _text(authority, "active_issuance_id"):
        fail("Chrome custody issuance identity is replayed or inactive")
    if _text(root, "issuer") != ISSUANCE_ISSUER:
        fail("Chrome custody issuance issuer mismatch")
    if _text(root, "authority_key_id") != _text(authority, "key_id"):
        fail("Chrome custody issuance authority key mismatch")
    if _text(root, "signature_algorithm") != SIGNATURE_ALGORITHM:
        fail("Chrome custody issuance signature_algorithm mismatch")
    target = _text(root, "target")
    if target in CROSS_TARGET_IDS:
        fail("Chrome custody issuance target cannot be reused across Edge or Firefox/XPI")
    if target != TARGET_ID:
        fail("Chrome custody issuance target mismatch")
    if _text(root, "product") != PRODUCT:
        fail("Chrome custody issuance product mismatch")
    version = _text(root, "version")
    if VERSION_RE.fullmatch(version) is None:
        fail("Chrome custody issuance version is not an exact Chrome for Testing version")
    archive_sha = _text(root, "archive_sha256")
    if HEX_RE.fullmatch(archive_sha) is None or archive_sha == "0" * 64:
        fail("invalid Chrome custody issuance digest: archive_sha256")
    if _text(root, "controller") != f"tools/{CONTROLLER_NAME}":
        fail("Chrome custody issuance controller path mismatch")
    if _text(root, "wrapper") != f"tools/{WRAPPER_NAME}":
        fail("Chrome custody issuance wrapper path mismatch")
    if _text(root, "manifest") != f"tools/{MANIFEST_NAME}":
        fail("Chrome custody issuance manifest path mismatch")
    if _text(root, "trust_anchor") != f"tools/{TRUST_ANCHOR_NAME}":
        fail("Chrome custody issuance trust-anchor path mismatch")
    if _text(root, "source_freeze_producer") != f"tools/{SOURCE_FREEZE_PRODUCER}":
        fail("Chrome custody issuance freeze-producer path mismatch")
    for key in (
        "controller_sha256",
        "wrapper_sha256",
        "manifest_sha256",
        "trust_anchor_sha256",
        "source_freeze_producer_sha256",
    ):
        digest = _text(root, key)
        if HEX_RE.fullmatch(digest) is None or digest == "0" * 64:
            fail(f"invalid Chrome custody issuance digest: {key}")
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
        fail("Chrome custody issuance symbolic link rejected")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("Chrome custody issuance must be one regular non-hardlinked file")
    if info.st_uid not in {0, os.getuid()}:
        fail("Chrome custody issuance is not owner-controlled")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail(OWNER_BLOCKED_WRITABLE)
    authority_data = _verify_authority_path(
        authority_path or OWNER_AUTHORITY_PATH,
        require_immutable=require_authority_immutable,
    )
    authority = _parse_authority(authority_data)
    data = bind_regular_file(path, max_size=MAX_ISSUANCE, label="Chrome custody issuance")
    return _parse_issuance(data, authority)


def tools_dir_from_controller(controller: Path) -> Path:
    tools_dir = controller.resolve(strict=False).parent
    if tools_dir.name != "tools":
        fail("Chrome custody controller is not in the repository tools directory")
    return tools_dir


def authorize_snapshot(controller: Path) -> bytes:
    del controller
    fail(INJECTED_RUNNER_BLOCKER)
    raise AssertionError("unreachable")


def authorize_custody_inputs(
    controller: Path,
    manifest: Path,
) -> tuple[bytes, bytes, bytes, bytes]:
    """Bind in-repo controller, wrapper, manifest, and trust-anchor.

    Caller-supplied absolute paths must be the exact in-repo identities.
    Adjacent trust hashes never self-authorize. External issuance is required.
    Stale trust is reported and refused; it is never rehashed.
    """
    if not controller.is_absolute() or not manifest.is_absolute():
        fail("Chrome custody tool and manifest must be absolute")
    tools_dir = tools_dir_from_controller(controller)
    expected_controller = tools_dir / CONTROLLER_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    if controller != expected_controller:
        fail("malicious or substituted Chrome custody controller rejected")
    if manifest != expected_manifest:
        fail("replacement Chrome pin manifest cannot self-authorize")
    return authorize_repo(tools_dir.parent)


def authorize_repo(repo: Path) -> tuple[bytes, bytes, bytes, bytes]:
    if not repo.is_absolute():
        fail("Chrome custody repository must be absolute")
    tools_dir = repo / "tools"
    expected_controller = tools_dir / CONTROLLER_NAME
    expected_wrapper = tools_dir / WRAPPER_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    expected_trust = tools_dir / TRUST_ANCHOR_NAME
    controller_data, manifest_data = snapshot_trust_roots(
        expected_controller, expected_manifest
    )
    wrapper_data = bind_regular_file(
        expected_wrapper, max_size=MAX_CONTROLLER, label="Chrome custody wrapper"
    )
    trust_data = bind_regular_file(
        expected_trust, max_size=MAX_TRUST, label="Chrome custody trust-anchor"
    )
    if b"\0" in wrapper_data:
        fail("invalid Chrome custody wrapper source")
    trust = _parse_trust_anchor(trust_data)
    _require_digest(
        _digest_bytes(controller_data),
        str(trust["controller_sha256"]),
        "controller",
    )
    _require_digest(
        _digest_bytes(wrapper_data),
        str(trust["wrapper_sha256"]),
        "wrapper",
    )
    _require_digest(
        _digest_bytes(manifest_data),
        str(trust["manifest_sha256"]),
        "manifest",
    )
    issuance = _bind_external_issuance(repo)
    if _digest_bytes(controller_data) != issuance["controller_sha256"]:
        fail("Chrome custody controller digest does not match the external issuance")
    if _digest_bytes(wrapper_data) != issuance["wrapper_sha256"]:
        fail("Chrome custody wrapper digest does not match the external issuance")
    if _digest_bytes(manifest_data) != issuance["manifest_sha256"]:
        fail("Chrome pin manifest digest does not match the external issuance")
    if _digest_bytes(trust_data) != issuance["trust_anchor_sha256"]:
        fail("Chrome custody trust-anchor digest does not match the external issuance")
    _bind_source_freeze_producer(repo, str(issuance["source_freeze_producer_sha256"]))
    live_trust = bind_regular_file(
        expected_trust, max_size=MAX_TRUST, label="in-repo Chrome custody trust-anchor"
    )
    if live_trust != trust_data:
        fail("Chrome custody trust-anchor identity is not the authenticated in-repo identity")
    live_controller = bind_regular_file(
        expected_controller,
        max_size=MAX_CONTROLLER,
        label="in-repo Chrome custody controller",
    )
    live_wrapper = bind_regular_file(
        expected_wrapper,
        max_size=MAX_CONTROLLER,
        label="in-repo Chrome custody wrapper",
    )
    live_manifest = bind_regular_file(
        expected_manifest,
        max_size=MAX_MANIFEST,
        label="in-repo Chrome pin manifest",
    )
    if live_controller != controller_data:
        fail("Chrome custody controller identity is not the authenticated in-repo identity")
    if live_wrapper != wrapper_data:
        fail("Chrome custody wrapper identity is not the authenticated in-repo identity")
    if live_manifest != manifest_data:
        fail("Chrome pin manifest identity is not the authenticated in-repo identity")
    return controller_data, wrapper_data, manifest_data, trust_data


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _reject_json_constant(token: str) -> None:
    fail(f"non-finite JSON constant rejected: {token}")


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"Chrome pin field must be an object: {label}")
    return value


def _text(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        fail(f"Chrome pin field must be one non-empty string: {key}")
    if any(ord(character) < 32 for character in value) or value.strip() != value:
        fail(f"Chrome pin field contains a control character: {key}")
    return value


def _exact_int(value: object, label: str) -> int:
    if type(value) is not int:
        fail(f"Chrome pin field must be an integer: {label}")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = False) -> list[str]:
    if type(value) is not list:
        fail(f"Chrome pin field must be an array: {label}")
    if not value and not allow_empty:
        fail(f"Chrome pin field must be one non-empty array: {label}")
    result: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str:
            fail(f"Chrome pin field must be a string: {label}[{index}]")
        if any(ord(character) < 32 for character in item) or item.strip() != item:
            fail(f"Chrome pin field contains a control character: {label}[{index}]")
        result.append(item)
    return result


def _require_keys(mapping: dict[str, object], required: tuple[str, ...], label: str) -> None:
    missing = [key for key in required if key not in mapping]
    if missing:
        fail(f"Chrome pin field is absent: {label}.{missing[0]}")
    extra = [key for key in mapping if key not in required]
    if extra:
        fail(f"unexpected Chrome pin field rejected: {label}.{extra[0]}")


def parse_browser_pin(data: bytes) -> dict[str, str]:
    try:
        document = json.loads(
            data,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Chrome pin manifest is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Chrome pin manifest is not JSON: {exc}")
    root = _mapping(document, "document")
    tools = _mapping(root.get("tools"), "tools")
    if "browser" not in tools:
        fail("Chrome pin field is absent: tools.browser")
    browser = _mapping(tools.get("browser"), "tools.browser")
    _require_keys(browser, BROWSER_KEYS, "tools.browser")
    paths = _mapping(browser.get("archive_path"), "archive_path")
    archive_hashes = _mapping(browser.get("archive_sha256"), "archive_sha256")
    tree_hashes = _mapping(browser.get("install_tree_sha256"), "install_tree_sha256")
    for label, mapping in (
        ("archive_path", paths),
        ("archive_sha256", archive_hashes),
        ("install_tree_sha256", tree_hashes),
    ):
        _require_keys(mapping, PLATFORM_KEYS, label)
    result = {
        "product": _text(browser, "product"),
        "version": _text(browser, "version"),
        "platform": _text(browser, "platform"),
        "architecture": _text(browser, "architecture"),
        "archive_format": _text(browser, "archive_format"),
        "archive": _text(paths, "darwin_arm64"),
        "archive_sha": _text(archive_hashes, "darwin_arm64"),
        "tree_sha": _text(tree_hashes, "darwin_arm64"),
        "root": _text(browser, "top_level_root"),
        "executable": _text(browser, "executable"),
        "executable_sha": _text(browser, "executable_sha256"),
        "signing_identity": _text(browser, "signing_identity"),
        "target": TARGET_ID,
    }
    if VERSION_RE.fullmatch(result["version"]) is None:
        fail("Chrome version pin must be an exact four-part Chrome for Testing version")
    if result["product"] != PRODUCT:
        fail("Chrome product pin mismatch")
    if result["platform"] != PLATFORM or result["architecture"] != ARCHITECTURE:
        fail("Chrome platform or architecture pin mismatch")
    if result["archive_format"] != ARCHIVE_FORMAT:
        fail("only exact official Chrome for Testing ZIP archives are accepted")
    archive_name = Path(result["archive"]).name.lower()
    if result["archive_format"] == "xpi" or archive_name.endswith(".xpi"):
        fail("Firefox/XPI archives cannot substitute for the Chrome for Testing pin")
    if (
        "wins-vpn-companion-chrome" in archive_name
        or "wins-vpn-companion-edge" in archive_name
        or "wins-vpn-companion-firefox" in archive_name
    ):
        fail("Chrome, Edge, or Firefox/XPI extension archives cannot substitute for the Chrome for Testing pin")
    if result["root"] != ROOT_NAME or result["executable"] != EXECUTABLE:
        fail("Chrome archive layout pin mismatch")
    if len(result["signing_identity"]) > 256:
        fail("Chrome signing identity pin is too long")
    for key in ("archive_sha", "tree_sha", "executable_sha"):
        if HEX_RE.fullmatch(result[key]) is None:
            fail(f"invalid Chrome digest pin: {key}")
    return result


def parse_production_manifest(data: bytes) -> dict[str, str]:
    try:
        document = json.loads(
            data,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Chrome pin manifest is not UTF-8: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Chrome pin manifest is not JSON: {exc}")
    root = _mapping(document, "document")
    _require_keys(root, DOCUMENT_KEYS, "document")
    if _exact_int(root.get("schema_version"), "schema_version") != 1:
        fail("Chrome pin manifest schema_version mismatch")
    _string_list(root.get("_purpose"), "_purpose")
    _string_list(root.get("_declared_divergences_note"), "_declared_divergences_note")
    _string_list(root.get("declared_divergences"), "declared_divergences", allow_empty=True)
    _string_list(root.get("sites"), "sites", allow_empty=True)
    _string_list(root.get("discovery_scan_roots"), "discovery_scan_roots")
    _string_list(root.get("_not_covered"), "_not_covered")
    pending = _mapping(root.get("pending_convergence"), "pending_convergence")
    _require_keys(pending, PENDING_KEYS, "pending_convergence")
    _text(pending, "target")
    _text(pending, "status")
    _text(pending, "decided_on")
    _text(pending, "last_live_audit_utc")
    _text(pending, "last_live_audit_note")
    _string_list(pending.get("decision"), "pending_convergence.decision")
    tools = _mapping(root.get("tools"), "tools")
    _require_keys(tools, TOOLS_KEYS, "tools")
    for name in TOOLS_KEYS:
        _mapping(tools.get(name), f"tools.{name}")
    return parse_browser_pin(data)


def parse_pin_bytes(data: bytes) -> dict[str, str]:
    return parse_browser_pin(data)


def load_pin(manifest: Path) -> dict[str, str]:
    return parse_browser_pin(
        bind_regular_file(manifest, max_size=MAX_MANIFEST, label="Chrome pin manifest")
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            fail("short write while copying the Chrome archive")
        view = view[written:]


def _open_flags(write: bool = False) -> int:
    flags = _cloexec_flag() | _nofollow_flag()
    if write:
        return flags | os.O_RDWR | os.O_CREAT | os.O_EXCL
    return flags | os.O_RDONLY


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while block := os.read(fd, 1024 * 1024):
        digest.update(block)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def copy_stable(source: Path, destination: Path, expected_sha: str) -> AuthenticatedArchive:
    source_fd = os.open(source, _open_flags())
    dest_fd = -1
    read_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail("Chrome archive must be one regular non-hardlinked file")
        if before.st_size <= 0 or before.st_size > MAX_ARCHIVE:
            fail("Chrome archive size is outside the accepted range")
        dest_fd = os.open(destination, _open_flags(write=True), 0o400)
        hasher = hashlib.sha256()
        copied = 0
        while copied < before.st_size:
            remaining = before.st_size - copied
            if remaining > MAX_ARCHIVE or copied > MAX_ARCHIVE:
                fail("Chrome archive size is outside the accepted range")
            block = os.read(source_fd, min(1024 * 1024, remaining))
            if not block:
                fail("Chrome archive truncated during authenticated copying")
            copied += len(block)
            hasher.update(block)
            _write_all(dest_fd, block)
        extra = os.read(source_fd, 1)
        if extra:
            fail("Chrome archive size is outside the accepted range")
        os.fsync(dest_fd)
        after_source = os.fstat(source_fd)
        if hasher.hexdigest() != expected_sha or _identity(before) != _identity(after_source):
            fail("Chrome archive SHA-256 mismatch")
        if _identity(before) != _identity(source.lstat()):
            fail("Chrome archive changed during authenticated copying")
        os.lseek(dest_fd, 0, os.SEEK_SET)
        before_dest = os.fstat(dest_fd)
        if before_dest.st_size <= 0 or before_dest.st_size > MAX_ARCHIVE:
            fail("Chrome archive size is outside the accepted range")
        digest = _hash_fd(dest_fd)
        after_dest = os.fstat(dest_fd)
        latest = destination.lstat()
        if not (_identity(before_dest) == _identity(after_dest) == _identity(latest)):
            fail("Chrome archive changed during authenticated copying")
        if digest != expected_sha:
            fail("Chrome archive SHA-256 mismatch")
        read_fd = os.open(destination, _open_flags())
        opened = os.fstat(read_fd)
        dest_info = os.fstat(dest_fd)
        latest = destination.lstat()
        if not (
            _identity(opened)
            == _identity(latest)
            == _identity(after_dest)
            == _identity(dest_info)
        ):
            fail("authenticated Chrome archive was replaced")
        os.close(dest_fd)
        dest_fd = -1
        rehashed = _hash_fd(read_fd)
        after_reopen = os.fstat(read_fd)
        latest = destination.lstat()
        if not (_identity(opened) == _identity(after_reopen) == _identity(latest)):
            fail("Chrome archive changed during authenticated copying")
        if rehashed != expected_sha or rehashed != digest:
            fail("Chrome archive SHA-256 mismatch")
        handle = AuthenticatedArchive(
            destination, read_fd, _identity(after_reopen), rehashed
        )
        read_fd = -1
        return handle
    finally:
        os.close(source_fd)
        if dest_fd >= 0:
            os.close(dest_fd)
        if read_fd >= 0:
            os.close(read_fd)


def _require_system_tool(path: Path) -> None:
    if path.parent != Path("/usr/bin") or path.name not in {"codesign", "plutil"}:
        fail(f"Chrome custody refused a non-fixed system tool: {path}")
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        fail(f"fixed system tool must be one regular file: {path}")
    if info.st_uid != 0 or not os.access(path, os.X_OK):
        fail(f"fixed system tool is not an executable root-owned file: {path}")


def _minimal_environment(runtime: Path) -> dict[str, str]:
    return {
        "HOME": str(runtime / "state/home"),
        "TMPDIR": str(runtime / "state/tmp"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _tool_environment(runtime: Path) -> dict[str, str]:
    return {
        "HOME": str(runtime / "state/home"),
        "TMPDIR": str(runtime / "state/tmp"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_system(runtime: Path, tool: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    _require_system_tool(tool)
    return subprocess.run(
        [str(tool), *arguments],
        env=_tool_environment(runtime),
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def _read_fd(fd: int, offset: int, size: int) -> bytes:
    if size <= 0:
        return b""
    os.lseek(fd, offset, os.SEEK_SET)
    chunks = bytearray()
    remaining = size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            fail("Chrome ZIP structure is truncated")
        chunks.extend(block)
        remaining -= len(block)
    return bytes(chunks)


def _reject_zip_extra(extra: bytes, label: str) -> None:
    if len(extra) > MAX_ZIP_EXTRA:
        fail(f"Chrome ZIP {label} extra field exceeds the limit")
    offset = 0
    while offset < len(extra):
        if offset + 4 > len(extra):
            fail(f"Chrome ZIP {label} extra field is malformed")
        header_id, data_size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if header_id == ZIP64_EXTRA_ID:
            fail("Chrome ZIP64 extra fields are forbidden")
        if data_size > MAX_ZIP_EXTRA or offset + data_size > len(extra):
            fail(f"Chrome ZIP {label} extra field is malformed")
        offset += data_size
    if offset != len(extra):
        fail(f"Chrome ZIP {label} extra field is malformed")


def _validate_zip_layout(handle: AuthenticatedArchive) -> None:
    handle.ensure_bound()
    size = os.fstat(handle.fd).st_size
    if size <= 0 or size > MAX_ARCHIVE:
        fail("Chrome archive size is outside the accepted range")
    if size < ZIP_EOCD + 30:
        fail("Chrome ZIP end record is absent")
    if _read_fd(handle.fd, 0, 4) != b"PK\x03\x04":
        fail("Chrome ZIP preamble or concatenated prefix is forbidden")
    tail_size = min(size, ZIP_EOCD + 65_535)
    tail = _read_fd(handle.fd, size - tail_size, tail_size)
    eocd_rel = tail.rfind(b"PK\x05\x06")
    if eocd_rel < 0 or eocd_rel + ZIP_EOCD > len(tail):
        fail("Chrome ZIP end record is absent")
    eocd = tail[eocd_rel : eocd_rel + ZIP_EOCD]
    (
        disk,
        cd_disk,
        disk_entries,
        total_entries,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack_from("<HHHHIIH", eocd, 4)
    eocd_offset = size - tail_size + eocd_rel
    if eocd_offset + ZIP_EOCD + comment_len != size or comment_len:
        fail("Chrome ZIP comments or trailing bytes are forbidden")
    if disk or cd_disk or disk_entries != total_entries:
        fail("Chrome ZIP spanning archives are forbidden")
    if total_entries == 0 or total_entries > MAX_MEMBERS:
        fail("Chrome ZIP member count is outside the accepted range")
    if (
        disk_entries == 0xFFFF
        or total_entries == 0xFFFF
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
    ):
        fail("Chrome ZIP64 archives are forbidden")
    if cd_size > MAX_CENTRAL_DIR:
        fail("Chrome ZIP central directory exceeds the metadata limit")
    if cd_size < 46 * total_entries:
        fail("Chrome ZIP central directory is truncated")
    if cd_offset <= 0 or cd_offset + cd_size != eocd_offset:
        fail("Chrome ZIP preamble, gap, or concatenated data is forbidden")
    central = _read_fd(handle.fd, cd_offset, cd_size)
    records: list[tuple[int, bytes, int, int, int, int, int]] = []
    cursor = 0
    while cursor < cd_size:
        if cursor + 46 > cd_size or central[cursor : cursor + 4] != b"PK\x01\x02":
            fail("Chrome ZIP central directory is malformed")
        flag, method = struct.unpack_from("<HH", central, cursor + 8)
        crc, compress, uncompress = struct.unpack_from("<III", central, cursor + 16)
        name_len, extra_len, comment_len_member = struct.unpack_from(
            "<HHH", central, cursor + 28
        )
        local_offset = struct.unpack_from("<I", central, cursor + 42)[0]
        if flag & ZIP_ENCRYPT:
            fail("encrypted Chrome ZIP members are forbidden")
        if flag & ZIP_DATA_DESCRIPTOR:
            fail("Chrome ZIP data descriptors are forbidden")
        if method not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            fail("unsupported Chrome ZIP compression method rejected")
        if comment_len_member:
            fail("Chrome ZIP member comments are forbidden")
        if extra_len > MAX_ZIP_EXTRA:
            fail("Chrome ZIP extra field exceeds the limit")
        if name_len == 0 or name_len > MAX_PATH_BYTES:
            fail("Chrome ZIP member path is too long")
        header_end = cursor + 46 + name_len + extra_len + comment_len_member
        if header_end > cd_size:
            fail("Chrome ZIP central directory is truncated")
        name = central[cursor + 46 : cursor + 46 + name_len]
        extra = central[cursor + 46 + name_len : cursor + 46 + name_len + extra_len]
        _reject_zip_extra(extra, "central")
        if local_offset >= cd_offset:
            fail("Chrome ZIP local header overlaps the central directory")
        records.append((local_offset, name, flag, method, crc, compress, uncompress))
        cursor = header_end
    if cursor != cd_size or len(records) != total_entries:
        fail("Chrome ZIP central directory member count mismatch")
    seen_names: set[bytes] = set()
    for _offset, name, _flag, _method, _crc, _compress, _uncompress in records:
        if name in seen_names:
            fail("Chrome ZIP duplicate, Unicode, or case-fold collision rejected")
        seen_names.add(name)
    offset_order = sorted(records, key=lambda item: item[0])
    offset = 0
    for local_offset, name, flag, method, crc, compress, uncompress in offset_order:
        if local_offset != offset:
            fail("Chrome ZIP preamble or pre-central-directory gap is forbidden")
        local = _read_fd(handle.fd, offset, 30)
        if local[:4] != b"PK\x03\x04":
            fail("Chrome ZIP local header is malformed")
        local_flag, local_method = struct.unpack_from("<HH", local, 6)
        local_crc, local_compress, local_uncompress = struct.unpack_from(
            "<III", local, 14
        )
        local_name_len, local_extra_len = struct.unpack_from("<HH", local, 26)
        if local_flag & (ZIP_ENCRYPT | ZIP_DATA_DESCRIPTOR):
            fail("encrypted Chrome ZIP members are forbidden")
        if local_name_len != len(name) or local_extra_len > MAX_ZIP_EXTRA:
            fail("Chrome ZIP local header metadata exceeds the limit")
        local_name = _read_fd(handle.fd, offset + 30, local_name_len)
        local_extra = _read_fd(handle.fd, offset + 30 + local_name_len, local_extra_len)
        if local_name != name:
            fail("Chrome ZIP local header name does not match the central directory")
        _reject_zip_extra(local_extra, "local")
        if local_flag != flag:
            fail("Chrome ZIP local flags do not match the central directory")
        if local_method != method:
            fail("Chrome ZIP local compression method does not match the central directory")
        if local_crc != crc:
            fail("Chrome ZIP local CRC does not match the central directory")
        if local_compress != compress:
            fail("Chrome ZIP local compressed size does not match the central directory")
        if local_uncompress != uncompress:
            fail("Chrome ZIP local uncompressed size does not match the central directory")
        offset += 30 + local_name_len + local_extra_len + compress
        if offset > cd_offset:
            fail("Chrome ZIP local records overlap the central directory")
    if offset != cd_offset:
        fail("Chrome ZIP pre-central-directory gap or overlap is forbidden")
    handle.central_offset = cd_offset
    handle.member_count = total_entries
    handle.layout = [
        (name, flag, method, crc, compress, uncompress, local_offset)
        for local_offset, name, flag, method, crc, compress, uncompress in records
    ]
    handle.ensure_bound()


def _open_archive_snapshot(path: Path) -> AuthenticatedArchive:
    fd = os.open(path, _open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("Chrome archive must be one regular non-hardlinked file")
        if info.st_size <= 0 or info.st_size > MAX_ARCHIVE:
            fail("Chrome archive size is outside the accepted range")
        latest = path.lstat()
        if _identity(info) != _identity(latest):
            fail("Chrome archive changed while it was opened")
        handle = AuthenticatedArchive(path, fd, _identity(info), "")
        fd = -1
        return handle
    finally:
        if fd >= 0:
            os.close(fd)


def _raw_zip_components(name: str, label: str) -> tuple[str, ...]:
    if any(ord(character) < 32 for character in name):
        fail(f"Chrome ZIP {label} contains a control character")
    if unicodedata.normalize("NFC", name) != name:
        fail(f"unsafe or non-canonical Chrome ZIP {label}")
    if not name or name.startswith("/") or "\\" in name:
        fail(f"unsafe or non-canonical Chrome ZIP {label}")
    body = name[:-1] if name.endswith("/") else name
    if not body or "//" in name or body.startswith("/") or body.endswith("/"):
        fail(f"unsafe or non-canonical Chrome ZIP {label}")
    parts = tuple(body.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"unsafe or non-canonical Chrome ZIP {label}")
    pure = PurePosixPath(body)
    if pure.as_posix() != body or pure.parts != parts:
        fail(f"unsafe or non-canonical Chrome ZIP {label}")
    return parts


def _member_path(name: str, expected_root: str) -> str:
    parts = _raw_zip_components(name, "member path")
    if len("/".join(parts).encode("utf-8")) > MAX_PATH_BYTES:
        fail("Chrome ZIP member path is too long")
    if len(parts) > MAX_DEPTH:
        fail("Chrome ZIP member path exceeds the depth limit")
    if parts[0] != expected_root:
        fail("Chrome ZIP member escaped its pinned top-level root")
    return "/".join(parts)


def _symlink_target(member: str, target: str, expected_root: str) -> str:
    if any(ord(character) < 32 for character in target):
        fail("Chrome ZIP symbolic-link target contains a control character")
    if unicodedata.normalize("NFC", target) != target:
        fail("unsafe or non-canonical Chrome ZIP symbolic-link target")
    if not target or target.startswith("/") or "\\" in target or "//" in target:
        fail("unsafe or non-canonical Chrome ZIP symbolic-link target")
    raw_parts = tuple(target.split("/"))
    if any(part in {"", "."} for part in raw_parts):
        fail("unsafe or non-canonical Chrome ZIP symbolic-link target")
    if PurePosixPath(target).as_posix() != target:
        fail("unsafe or non-canonical Chrome ZIP symbolic-link target")
    parts = list(PurePosixPath(member).parent.parts)
    for part in raw_parts:
        if part == "..":
            if not parts or parts[0] != expected_root or len(parts) <= 1:
                fail("Chrome ZIP symbolic link escaped its pinned top-level root")
            parts.pop()
        else:
            parts.append(part)
    if not parts or parts[0] != expected_root:
        fail("Chrome ZIP symbolic link escaped its pinned top-level root")
    resolved = PurePosixPath(*parts).as_posix()
    if len(target.encode("utf-8")) > MAX_PATH_BYTES or len(resolved.encode("utf-8")) > MAX_PATH_BYTES:
        fail("Chrome ZIP symbolic-link target is too long")
    if len(PurePosixPath(resolved).parts) > MAX_DEPTH:
        fail("Chrome ZIP symbolic-link target exceeds the depth limit")
    return resolved


def _member_kind(entry: zipfile.ZipInfo, canonical: str) -> str:
    unix_mode = (entry.external_attr >> 16) & 0xFFFF
    if entry.is_dir() or entry.filename.endswith("/"):
        if entry.file_size != 0:
            fail(f"Chrome ZIP directory carries unexpected data: {canonical}")
        return "dir"
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFLNK or stat.S_ISLNK(unix_mode):
        return "symlink"
    if file_type and not stat.S_ISREG(unix_mode):
        fail("Chrome ZIP links, special files, and extension records are forbidden")
    return "file"


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _create_parents(path: Path, stop: Path) -> None:
    relative = path.relative_to(stop)
    current = stop
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            fail(f"Chrome ZIP parent collides on a symbolic link: {current}")
        if _lexists(current) and not current.is_dir():
            fail(f"Chrome ZIP parent collides on disk: {current}")
        if not _lexists(current):
            current.mkdir(mode=0o700)


def _freeze_tree(destination: Path, root: Path) -> None:
    binary = root / EXECUTABLE
    try:
        info = binary.lstat()
    except FileNotFoundError:
        fail("pinned Chrome executable is absent")
    if binary.is_symlink() or not stat.S_ISREG(info.st_mode):
        fail("pinned Chrome executable is absent")
    binary.chmod(0o500)
    for base, directories, files in os.walk(destination, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail("extracted Chrome hardlink or special file rejected")
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISDIR(info.st_mode):
                fail("extracted Chrome special file rejected")
            path.chmod(0o500)
        if not base_path.is_symlink():
            base_path.chmod(0o500)
    destination.chmod(0o500)


def _validate_extracted_symlink(destination: Path, canonical: str, expected_root: str) -> None:
    root = (destination / expected_root).resolve(strict=True)
    link = destination.joinpath(*PurePosixPath(canonical).parts)
    try:
        resolved = link.resolve(strict=True)
        resolved.relative_to(root)
    except (FileNotFoundError, RuntimeError, ValueError, OSError):
        fail(f"extracted Chrome symbolic link is broken, cyclic, or escaping: {canonical}")
    info = resolved.lstat()
    if stat.S_ISLNK(info.st_mode) or not (
        stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
    ):
        fail(f"extracted Chrome symbolic-link target is unsupported: {canonical}")


def safe_extract(
    archive: Path | AuthenticatedArchive, destination: Path, expected_root: str
) -> Path:
    if destination.exists() or destination.is_symlink():
        fail("Chrome extraction destination already exists")
    owned: AuthenticatedArchive | None = None
    stream = None
    if isinstance(archive, AuthenticatedArchive):
        handle = archive
        handle.ensure_bound()
    else:
        owned = _open_archive_snapshot(archive)
        handle = owned
    try:
        _validate_zip_layout(handle)
        members: list[tuple[str, str, int, zipfile.ZipInfo, str]] = []
        seen: set[str] = set()
        folded: set[str] = set()
        total = 0
        stream = handle.fileobj()
        with zipfile.ZipFile(stream) as bundle:
            handle.ensure_bound()
            if bundle.comment or bundle.start_dir <= 0:
                fail("Chrome ZIP structure is malformed")
            if handle.central_offset >= 0 and bundle.start_dir != handle.central_offset:
                fail("Chrome ZIP central directory shifted")
            entries = bundle.infolist()
            if not entries or len(entries) > MAX_MEMBERS:
                fail("Chrome ZIP member count is outside the accepted range")
            if handle.member_count >= 0 and len(entries) != handle.member_count:
                fail("Chrome ZIP parsed member count mismatch")
            if handle.layout and len(handle.layout) != len(entries):
                fail("Chrome ZIP parsed member count mismatch")
            for index, entry in enumerate(entries):
                if entry.flag_bits & (ZIP_ENCRYPT | ZIP_DATA_DESCRIPTOR):
                    fail("encrypted Chrome ZIP members are forbidden")
                if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    fail("unsupported Chrome ZIP compression method rejected")
                if entry.comment:
                    fail("Chrome ZIP member comments are forbidden")
                if len(entry.extra) > MAX_ZIP_EXTRA:
                    fail("Chrome ZIP extra field exceeds the limit")
                if handle.layout:
                    name, flag, method, crc, compress, uncompress, _offset = handle.layout[
                        index
                    ]
                    encoded = entry.filename.encode("utf-8")
                    if encoded != name:
                        fail("Chrome ZIP local header name does not match the central directory")
                    if entry.flag_bits != flag:
                        fail("Chrome ZIP local flags do not match the central directory")
                    if entry.compress_type != method:
                        fail(
                            "Chrome ZIP local compression method does not match the central directory"
                        )
                    if entry.CRC != crc:
                        fail("Chrome ZIP local CRC does not match the central directory")
                    if entry.compress_size != compress:
                        fail(
                            "Chrome ZIP local compressed size does not match the central directory"
                        )
                    if entry.file_size != uncompress:
                        fail(
                            "Chrome ZIP local uncompressed size does not match the central directory"
                        )
                canonical = _member_path(entry.filename, expected_root)
                collision = canonical.casefold()
                if canonical in seen or collision in folded:
                    fail("Chrome ZIP duplicate, Unicode, or case-fold collision rejected")
                seen.add(canonical)
                folded.add(collision)
                kind = _member_kind(entry, canonical)
                link_target = ""
                if kind == "file":
                    total += entry.file_size
                    if total > MAX_EXPANDED or entry.file_size > MAX_MEMBER:
                        fail("Chrome ZIP expanded size exceeds the limit")
                    if entry.compress_size == 0 and entry.file_size:
                        fail("Chrome ZIP member has an invalid compression ratio")
                    if entry.compress_size and entry.file_size / entry.compress_size > MAX_RATIO:
                        fail("Chrome ZIP compression ratio exceeds the limit")
                elif kind == "symlink":
                    if entry.file_size <= 0 or entry.file_size > MAX_PATH_BYTES:
                        fail("Chrome ZIP symbolic-link target is too long")
                    with bundle.open(entry) as source:
                        payload = source.read(MAX_PATH_BYTES + 1)
                    if len(payload) != entry.file_size:
                        fail("Chrome ZIP symbolic-link target was truncated")
                    try:
                        link_target = payload.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        fail(f"Chrome ZIP symbolic-link target is not UTF-8: {exc}")
                    _symlink_target(canonical, link_target, expected_root)
                members.append((canonical, kind, entry.file_size, entry, link_target))
            if not any(name == expected_root or name.startswith(f"{expected_root}/") for name in seen):
                fail("Chrome ZIP pinned top-level root is absent")
            destination.mkdir(mode=0o700)
            for canonical, kind, size, entry, _link_target in members:
                target = destination.joinpath(*PurePosixPath(canonical).parts)
                if kind == "dir":
                    _create_parents(target, destination)
                    continue
                if kind != "file":
                    continue
                if target.exists() or target.is_symlink():
                    fail(f"Chrome ZIP member collides on disk: {canonical}")
                _create_parents(target.parent, destination)
                unix_mode = (entry.external_attr >> 16) & 0xFFFF
                executable = canonical == f"{expected_root}/{EXECUTABLE}" or bool(
                    unix_mode & 0o111
                )
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
                try:
                    with bundle.open(entry) as source:
                        remaining = size
                        while remaining:
                            block = source.read(min(1024 * 1024, remaining))
                            if not block:
                                fail("Chrome ZIP member was truncated during extraction")
                            _write_all(fd, block)
                            remaining -= len(block)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                target.chmod(0o500 if executable else 0o400)
            for canonical, kind, _size, _entry, link_target in members:
                if kind != "symlink":
                    continue
                target = destination.joinpath(*PurePosixPath(canonical).parts)
                if target.exists() or target.is_symlink():
                    fail(f"Chrome ZIP member collides on disk: {canonical}")
                _create_parents(target.parent, destination)
                os.symlink(link_target, target)
            for canonical, kind, _size, _entry, _link_target in members:
                if kind == "symlink":
                    _validate_extracted_symlink(destination, canonical, expected_root)
        handle.ensure_bound()
        root = destination / expected_root
        if root.is_symlink() or not root.is_dir():
            fail("Chrome ZIP pinned top-level root is not a directory")
        _freeze_tree(destination, root)
        handle.ensure_bound()
        return root
    finally:
        if stream is not None:
            stream.close()
        if owned is not None:
            owned.close()


def tree_hash(root: Path) -> str:
    if root.is_symlink():
        fail("Chrome root symbolic link rejected")
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o500:
        fail("Chrome root is not owner-controlled and frozen")
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
            if info.st_uid != os.getuid():
                fail(f"unsafe Chrome tree ownership or mode: {relative}")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _symlink_target(f"{ROOT_NAME}/{relative}", target, ROOT_NAME)
                try:
                    final = path.resolve(strict=True)
                    final.relative_to(root)
                except (FileNotFoundError, RuntimeError, ValueError, OSError):
                    fail(f"unsafe Chrome symbolic-link target: {relative}")
                feed("L", relative, target)
            elif mode & 0o022:
                fail(f"unsafe Chrome tree ownership or mode: {relative}")
            elif stat.S_ISDIR(info.st_mode):
                if mode != 0o500:
                    fail(f"Chrome directory is not frozen: {relative}")
                feed("D", relative, mode)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                expected_mode = 0o500 if relative == EXECUTABLE or mode == 0o500 else 0o400
                if info.st_nlink != 1 or mode != expected_mode:
                    fail(f"Chrome file mode or hardlink rejected: {relative}")
                feed("F", relative, mode, info.st_size, digest_file(path))
            else:
                fail(f"unsupported Chrome tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def runtime_identity(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        fail("Chrome runtime is not one private owner-controlled directory")
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
            fail(f"unsafe Chrome runtime state directory: {relative}")
        if stat.S_IMODE(info.st_mode) != 0o700:
            fail(f"Chrome runtime state directory mode changed: {relative}")


def macho_architectures(binary: Path) -> set[str]:
    fd = os.open(binary, _open_flags())
    try:
        header = os.read(fd, 4096)
    finally:
        os.close(fd)
    if len(header) < 8:
        fail("Chrome executable is too small to be Mach-O")
    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu_type = struct.unpack_from("<I", header, 4)[0]
        return {"arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}"}
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64 = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", header, 4)[0]
        entry_size = 32 if is_64 else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(header):
            fail("Chrome universal Mach-O header is malformed")
        result: set[str] = set()
        for index in range(count):
            cpu_type = struct.unpack_from(">I", header, 8 + index * entry_size)[0]
            result.add("arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}")
        return result
    fail("Chrome executable is not a supported Mach-O binary")


def _codesign_verify_frozen_bundle(runtime: Path, app: Path, binary: Path) -> None:
    verified = _run_system(
        runtime, CODESIGN, "--verify", "--deep", "--strict", str(app)
    )
    if verified.returncode == 0:
        return
    text = f"{verified.stdout}\n{verified.stderr}"
    if "code has no resources but signature indicates they must be present" not in text:
        fail("Chrome code signature failed strict verification")
    # Official Chrome for Testing is linker-signed ad-hoc and has no sealed
    # bundle resources. ``codesign --verify --deep --strict`` of the .app path
    # then fails that resource check. Trust remains the official archive,
    # tree, and executable digests. Verify Mach-O integrity of the exact frozen
    # executable inode via a private same-directory hardlink so codesign does
    # not misread the .app layout.
    try:
        info = binary.lstat()
    except FileNotFoundError:
        fail("pinned Chrome executable is absent")
    if binary.is_symlink() or not stat.S_ISREG(info.st_mode):
        fail("pinned Chrome executable is absent")
    link = runtime / "state/tmp/.chrome-macho-verify"
    if link.exists() or link.is_symlink():
        fail("Chrome macho verification path already exists")
    os.link(binary, link)
    try:
        linked = link.lstat()
        if (linked.st_dev, linked.st_ino) != (info.st_dev, info.st_ino):
            fail("Chrome macho verification link is not the frozen executable")
        macho = _run_system(
            runtime, CODESIGN, "--verify", "--deep", "--strict", str(link)
        )
        if macho.returncode != 0:
            fail("Chrome code signature failed strict verification")
    finally:
        try:
            link.unlink()
        except FileNotFoundError:
            pass


def _codesign_identity(runtime: Path, app: Path, binary: Path) -> str:
    _codesign_verify_frozen_bundle(runtime, app, binary)
    displayed = _run_system(runtime, CODESIGN, "--display", "--verbose=2", str(app))
    if displayed.returncode != 0:
        fail("Chrome code signature identity could not be read")
    text = f"{displayed.stdout}\n{displayed.stderr}"
    authorities: list[str] = []
    signature = ""
    identifier = ""
    fmt = ""
    for line in text.splitlines():
        if line.startswith("Authority="):
            authorities.append(line.split("=", 1)[1])
        elif line.startswith("Signature="):
            signature = line.split("=", 1)[1]
        elif line.startswith("Identifier="):
            identifier = line.split("=", 1)[1]
        elif line.startswith("Format="):
            fmt = line.split("=", 1)[1]
    if identifier != PRODUCT:
        fail("Chrome code signature identifier does not match the product")
    if "arm64" not in fmt:
        fail("Chrome code signature format is not arm64")
    if authorities:
        return authorities[0]
    if signature == "adhoc":
        return "adhoc"
    fail("Chrome code signature identity is absent")


def _plist_text(runtime: Path, plist: Path, key: str) -> str:
    completed = _run_system(
        runtime,
        PLUTIL,
        "-extract",
        key,
        "raw",
        "-o",
        "-",
        "--",
        str(plist),
    )
    if completed.returncode != 0:
        fail(f"Chrome Info.plist field is absent: {key}")
    return completed.stdout.strip()


def _scheme_literal(path: Path) -> str:
    text = str(path)
    if any(character in text for character in '"\\\n\r'):
        fail("unsafe Seatbelt path")
    return text


def _require_sandbox_exec() -> Path:
    info = SANDBOX_EXEC.lstat()
    if (
        SANDBOX_EXEC.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or not os.access(SANDBOX_EXEC, os.X_OK)
    ):
        fail(EXECUTION_BLOCKER)
    return SANDBOX_EXEC


def _in_sandbox() -> bool:
    return _LIBC.sandbox_check(os.getpid(), None, 0) == 1


def _require_nested_seatbelt() -> None:
    sandbox = _require_sandbox_exec()
    if not _in_sandbox():
        return
    profile = "(version 1) (allow default)"
    true_info = TRUE_BIN.lstat()
    if (
        TRUE_BIN.is_symlink()
        or not stat.S_ISREG(true_info.st_mode)
        or true_info.st_uid != 0
        or not os.access(TRUE_BIN, os.X_OK)
    ):
        fail(NESTING_BLOCKER)
    try:
        pid = _posix_spawn(
            str(sandbox),
            [str(sandbox), "-p", profile, str(TRUE_BIN)],
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
                "LC_ALL": "C",
            },
            inherit_stdio=False,
        )
    except OSError as exc:
        fail(f"{NESTING_BLOCKER}: {exc}")
    try:
        status = _wait_pid(pid, 5)
    except Refused as exc:
        fail(f"{NESTING_BLOCKER}: {exc}")
    if status != 0:
        fail(NESTING_BLOCKER)


def _seatbelt_profile(runtime: Path) -> str:
    runtime_text = _scheme_literal(runtime)
    incoming = _scheme_literal(runtime / "incoming.zip")
    extracted = _scheme_literal(runtime / "extracted")
    exec_dir = _scheme_literal(runtime / "exec")
    return (
        "(version 1) (allow default) "
        f'(deny file-write* (literal "{runtime_text}") '
        f'(literal "{incoming}") '
        f'(subpath "{extracted}") '
        f'(subpath "{exec_dir}"))'
    )


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
        _must(
            _LIBC.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "posix_spawn_file_actions_init",
        )
        try:
            if inherit_stdio:
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 0, 0),
                    "posix_spawn_file_actions_adddup2 stdin",
                )
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 1, 1),
                    "posix_spawn_file_actions_adddup2 stdout",
                )
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 2, 2),
                    "posix_spawn_file_actions_adddup2 stderr",
                )
            else:
                _must(
                    _LIBC.posix_spawn_file_actions_addopen(
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
                    _LIBC.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions),
                        1,
                        stdout,
                        stdout_flags,
                        0o600,
                    ),
                    "posix_spawn_file_actions_addopen stdout",
                )
                _must(
                    _LIBC.posix_spawn_file_actions_addopen(
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
            fail("Chrome runtime execution timed out")
        time.sleep(0.02)


class ExecutionImage:
    def __init__(self, runtime: Path, path: Path, digest: str, exec_dir: Path, tree: Path):
        self.runtime = runtime
        self.path = path
        self.digest = digest
        self.exec_dir = exec_dir
        self.tree = tree
        self._cleaned = False

    def cleanup(self) -> None:
        if self._cleaned:
            return
        self._cleaned = True
        try:
            if self.exec_dir.exists() and not self.exec_dir.is_symlink():
                try:
                    os.chflags(self.exec_dir, 0)
                except OSError:
                    pass
                os.chmod(self.exec_dir, 0o700)
        except OSError:
            pass
        _destroy_clone_tree(self.tree)
        if self.tree.exists() or self.tree.is_symlink():
            fail("Chrome execution clone cleanup left residue")


def _destroy_clone_tree(tree: Path) -> None:
    if not (tree.exists() or tree.is_symlink()):
        return
    info = tree.lstat()
    if stat.S_ISLNK(info.st_mode):
        tree.unlink()
        return
    if not stat.S_ISDIR(info.st_mode):
        fail("Chrome execution clone slot is not a disposable tree")
    for base, directories, files in os.walk(tree, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            try:
                if not path.is_symlink():
                    os.chflags(path, 0)
            except OSError:
                pass
            try:
                if not path.is_symlink():
                    os.chmod(path, 0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        try:
            if not base_path.is_symlink():
                os.chflags(base_path, 0)
                os.chmod(base_path, 0o700)
        except OSError:
            pass
    shutil.rmtree(tree, ignore_errors=True)


def _kernel_seal_tree(root: Path) -> None:
    """Make the cloned Chrome tree immutable against same-user replacement.

    UF_IMMUTABLE is insufficient because the owner can clear it. Only
    SF_IMMUTABLE counts, and the proof is that the same user cannot clear
    the flag or replace a sealed path. If this host cannot do that, fail
    closed instead of claiming runtime PASS.
    """
    if sys.platform != "darwin" or not SF_IMMUTABLE:
        fail(EXECUTION_BLOCKER)
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            if path.is_symlink():
                continue
            try:
                os.chflags(path, SF_IMMUTABLE)
            except OSError as exc:
                fail(f"{EXECUTION_BLOCKER}: {exc}")
        try:
            os.chflags(base_path, SF_IMMUTABLE)
        except OSError as exc:
            fail(f"{EXECUTION_BLOCKER}: {exc}")
    probe = root / EXECUTABLE
    try:
        os.chflags(probe, 0)
    except OSError:
        pass
    else:
        fail(EXECUTION_BLOCKER)
    try:
        fd = os.open(probe, os.O_WRONLY | _cloexec_flag() | _nofollow_flag())
    except OSError:
        pass
    else:
        os.close(fd)
        fail(EXECUTION_BLOCKER)
    try:
        os.unlink(probe)
    except OSError:
        pass
    else:
        fail(EXECUTION_BLOCKER)
    parent = root.parent
    if parent.name == "exec":
        try:
            os.chflags(parent, SF_IMMUTABLE)
        except OSError as exc:
            fail(f"{EXECUTION_BLOCKER}: {exc}")
        try:
            os.chflags(parent, 0)
        except OSError:
            pass
        else:
            fail(EXECUTION_BLOCKER)


def clone_execution_tree(root: Path, runtime: Path) -> Path:
    exec_dir = runtime / "exec"
    clone_root = exec_dir / "tree"
    if clone_root.exists() or clone_root.is_symlink():
        _destroy_clone_tree(clone_root)
        if clone_root.exists() or clone_root.is_symlink():
            fail("Chrome execution clone slot is not a disposable tree")
    root_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag()
    )
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
            fail("Chrome extracted root is not an owner-controlled directory")
        if _identity(root_info) != _identity(root.lstat()):
            fail("Chrome extracted root was replaced before it was cloned")
        dirfd = os.open(
            exec_dir,
            os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
        )
        try:
            rc = _LIBC.fclonefileat(root_fd, dirfd, b"tree", CLONE_NOFOLLOW)
            if rc != 0:
                fail(
                    "owner/environment blocker: macOS fclonefileat of the authenticated "
                    f"Chrome tree failed: {os.strerror(ctypes.get_errno())}"
                )
        finally:
            os.close(dirfd)
    finally:
        os.close(root_fd)
    return clone_root


def authenticated_execution_image(
    binary: Path, expected_sha: str, runtime: Path
) -> ExecutionImage:
    if sys.platform != "darwin":
        fail(MACOS_BLOCKER)
    _require_sandbox_exec()
    _require_nested_seatbelt()
    exec_dir = runtime / "exec"
    root = runtime / "extracted" / ROOT_NAME
    if binary != root / EXECUTABLE:
        fail("Chrome executable escaped its extracted root")
    fd = os.open(binary, _open_flags())
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail("Chrome executable must be one regular non-hardlinked file")
        latest = binary.lstat()
        if _identity(opened) != _identity(latest):
            fail("Chrome executable was replaced before it was opened")
        digest = _hash_fd(fd)
        if digest != expected_sha:
            fail("Chrome executable digest mismatch at execution")
    finally:
        os.close(fd)
    clone_root = clone_execution_tree(root, runtime)
    clone_binary = clone_root / EXECUTABLE
    clone_fd = os.open(clone_binary, _open_flags())
    try:
        clone_info = os.fstat(clone_fd)
        if not stat.S_ISREG(clone_info.st_mode) or clone_info.st_nlink != 1:
            fail("cloned Chrome executable must be one regular non-hardlinked file")
        if (clone_info.st_dev, clone_info.st_ino) == (latest.st_dev, latest.st_ino):
            fail(EXECUTION_BLOCKER)
        if _hash_fd(clone_fd) != expected_sha:
            fail("fd-cloned Chrome execution image digest mismatch")
    finally:
        os.close(clone_fd)
    try:
        _kernel_seal_tree(clone_root)
    except BaseException:
        _destroy_clone_tree(clone_root)
        raise
    return ExecutionImage(runtime, clone_binary, expected_sha, exec_dir, clone_root)


def _spawn_sandboxed_chrome(
    image: ExecutionImage,
    arguments: list[str],
    *,
    timeout: float,
    capture: bool,
) -> subprocess.CompletedProcess[str]:
    sandbox = _require_sandbox_exec()
    profile = _seatbelt_profile(image.runtime)
    env = _minimal_environment(image.runtime)
    argv = [str(sandbox), "-p", profile, str(image.path), *arguments]
    stdout_path = None
    stderr_path = None
    if capture:
        stdout_path = str(image.runtime / "state/tmp/chrome-stdout")
        stderr_path = str(image.runtime / "state/tmp/chrome-stderr")
        for path in (stdout_path, stderr_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    pid = _posix_spawn(
        str(sandbox),
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


def _run_browser(
    binary: Path,
    runtime: Path,
    expected_sha: str,
    arguments: list[str],
    timeout: int,
    *,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    image = authenticated_execution_image(binary, expected_sha, runtime)
    try:
        return _spawn_sandboxed_chrome(
            image, arguments, timeout=timeout, capture=capture
        )
    finally:
        image.cleanup()


def check_frozen_bundle_identity(
    runtime: Path,
    root: Path,
    binary: Path,
    product: str,
    version: str,
    architecture: str,
    signing_identity: str,
) -> Path:
    app = root / APP_NAME
    plist = root / INFO_PLIST
    if app.is_symlink() or not app.is_dir():
        fail("pinned Chrome application bundle is absent")
    if plist.is_symlink() or not plist.is_file():
        fail("pinned Chrome Info.plist is absent")
    if macho_architectures(binary) != {architecture}:
        fail("Chrome Mach-O architecture does not match the exact pin")
    if _plist_text(runtime, plist, "CFBundleShortVersionString") != version:
        fail("Chrome Info.plist version does not match the exact pin")
    if _plist_text(runtime, plist, "CFBundleExecutable") != product:
        fail("Chrome Info.plist executable name does not match the product")
    if _plist_text(runtime, plist, "CFBundleName") != product:
        fail("Chrome Info.plist product name does not match the exact pin")
    if _plist_text(runtime, plist, "CFBundleIdentifier") != BUNDLE_IDENTIFIER:
        fail("Chrome Info.plist bundle identifier does not match Chrome for Testing")
    identity = _codesign_identity(runtime, app, binary)
    if identity != signing_identity:
        fail("Chrome Apple signing identity does not match the exact pin")
    return app


def check_browser_identity(
    runtime: Path,
    root: Path,
    binary: Path,
    product: str,
    version: str,
    architecture: str,
    signing_identity: str,
    expected_sha: str,
) -> Path:
    app = check_frozen_bundle_identity(
        runtime, root, binary, product, version, architecture, signing_identity
    )
    probed = _run_browser(binary, runtime, expected_sha, ["--version"], 30)
    if (
        probed.returncode != 0
        or probed.stdout.strip() != f"{product} {version}"
        or probed.stderr.strip()
    ):
        fail(
            "Chrome runtime version probe mismatch: "
            f"rc={probed.returncode} stdout={probed.stdout!r} stderr={probed.stderr!r}"
        )
    return app


def _runtime_parts(
    arguments: list[str],
) -> tuple[Path, str, Path, str, Path, str, Path, str]:
    if len(arguments) != 8:
        fail("Chrome runtime verification arguments are malformed")
    (
        runtime_text,
        expected_id,
        root_text,
        expected_tree,
        binary_text,
        expected_binary,
        app_text,
        expected_identity,
    ) = arguments
    if HEX_RE.fullmatch(expected_tree) is None or HEX_RE.fullmatch(expected_binary) is None:
        fail("Chrome runtime digest arguments are malformed")
    if not expected_identity or any(ord(character) < 32 for character in expected_identity):
        fail("Chrome signing identity argument is malformed")
    return (
        Path(runtime_text),
        expected_id,
        Path(root_text),
        expected_tree,
        Path(binary_text),
        expected_binary,
        Path(app_text),
        expected_identity,
    )


def verify_runtime(arguments: list[str]) -> tuple[Path, Path, Path, str]:
    runtime, expected_id, root, expected_tree, binary, expected_binary, app, expected_identity = (
        _runtime_parts(arguments)
    )
    if runtime_identity(runtime) != expected_id:
        fail("Chrome runtime identity changed")
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("Chrome runtime pointer escaped its private prefix")
    if root.parent != runtime / "extracted" or binary != root / EXECUTABLE or app != root / APP_NAME:
        fail("Chrome runtime pointers changed")
    _require_private_state(runtime)
    if tree_hash(root) != expected_tree or digest_file(binary) != expected_binary:
        fail("Chrome runtime tree or executable content changed")
    if _codesign_identity(runtime, app, binary) != expected_identity:
        fail("Chrome runtime code signature changed")
    return runtime, root, binary, expected_binary


def _plan_cleanup(runtime: Path) -> list[tuple[str, Path, tuple[int, ...]]]:
    runtime_info = runtime.lstat()
    if runtime.is_symlink() or not stat.S_ISDIR(runtime_info.st_mode):
        fail("refusing cleanup of a substituted Chrome runtime")
    if runtime_info.st_uid != os.getuid():
        fail("refusing cleanup of a foreign-owned Chrome runtime")
    plan: list[tuple[str, Path, tuple[int, ...]]] = []
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external Chrome runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, _identity(info)))
                continue
            if not stat.S_ISREG(info.st_mode):
                fail("refusing cleanup of an unsupported Chrome runtime entry")
            if info.st_nlink != 1:
                fail("refusing cleanup of a hardlinked Chrome runtime file")
            plan.append(("file", path, _identity(info)))
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external Chrome runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, _identity(info)))
                continue
            if not stat.S_ISDIR(info.st_mode):
                fail("refusing cleanup of an unsupported Chrome runtime directory")
            plan.append(("dir", path, _identity(info)))
    plan.append(("dir", runtime, _identity(runtime_info)))
    return plan


def _destroy_runtime(runtime: Path) -> None:
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing Chrome cleanup outside the private runtime prefix")
    plan = _plan_cleanup(runtime)
    for kind, path, expected in plan:
        current = path.lstat()
        if _identity(current) != expected:
            fail("Chrome runtime changed after cleanup validation")
        if kind == "file":
            if current.st_nlink != 1:
                fail("refusing cleanup of a hardlinked Chrome runtime file")
            fd = os.open(path, os.O_RDONLY | _cloexec_flag() | _nofollow_flag())
            try:
                opened = os.fstat(fd)
                if opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (
                    expected[0],
                    expected[1],
                ):
                    fail("refusing cleanup of a hardlinked or external Chrome runtime file")
                try:
                    os.chflags(path, 0)
                except OSError:
                    pass
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        elif kind == "dir":
            try:
                os.chflags(path, 0)
            except OSError:
                pass
            os.chmod(path, 0o700)
    for kind, path, expected in plan:
        current = path.lstat()
        if kind == "file":
            if current.st_nlink != 1 or (current.st_dev, current.st_ino) != (
                expected[0],
                expected[1],
            ):
                fail("refusing unlink of a hardlinked or external Chrome runtime file")
            os.unlink(path)
        elif kind == "symlink":
            if not stat.S_ISLNK(current.st_mode):
                fail("refusing unlink of a substituted Chrome runtime symlink")
            os.unlink(path)
        elif kind == "dir":
            os.rmdir(path)
    if runtime.exists() or runtime.is_symlink():
        fail("Chrome cleanup left residue")


def install_extracted_runtime(pin: dict[str, str]) -> dict[str, str]:
    """Extract and freeze a Chrome runtime without claiming execution custody."""
    archive = Path(pin["archive"])
    require_safe_input(archive, f"{pin['root']}-{pin['version']}.zip")
    _require_system_tool(CODESIGN)
    _require_system_tool(PLUTIL)
    runtime = Path(tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir=str(PRIVATE_TMP)))
    runtime.chmod(0o700)
    try:
        incoming = runtime / "incoming.zip"
        extracted = runtime / "extracted"
        state = runtime / "state"
        exec_dir = runtime / "exec"
        state.mkdir(mode=0o700)
        (state / "home").mkdir(mode=0o700)
        (state / "tmp").mkdir(mode=0o700)
        exec_dir.mkdir(mode=0o700)
        authenticated = copy_stable(archive, incoming, pin["archive_sha"])
        try:
            root = safe_extract(authenticated, extracted, pin["root"])
        finally:
            authenticated.close()
        binary = root / pin["executable"]
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Chrome extracted tree or executable digest mismatch")
        app = check_frozen_bundle_identity(
            runtime,
            root,
            binary,
            pin["product"],
            pin["version"],
            pin["architecture"],
            pin["signing_identity"],
        )
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Chrome runtime changed during identity validation")
        return {
            "RUNTIME": str(runtime),
            "RUNTIME_ID": runtime_identity(runtime),
            "ROOT": str(root),
            "TREE_SHA256": pin["tree_sha"],
            "BINARY": str(binary),
            "BINARY_SHA256": pin["executable_sha"],
            "APP": str(app),
            "SIGNING_IDENTITY": pin["signing_identity"],
            "PRODUCT": pin["product"],
            "VERSION": pin["version"],
            "TARGET": pin["target"],
        }
    except BaseException:
        try:
            _destroy_runtime(runtime)
        except (OSError, Refused):
            pass
        raise


def _print_prepare_fields(
    runtime: Path,
    root: Path,
    binary: Path,
    app: Path,
    tree_sha: str,
    binary_sha: str,
    signing_identity: str,
    product: str,
    version: str,
    target: str,
) -> None:
    print(f"RUNTIME|{runtime}")
    print(f"RUNTIME_ID|{runtime_identity(runtime)}")
    print(f"ROOT|{root}")
    print(f"TREE_SHA256|{tree_sha}")
    print(f"BINARY|{binary}")
    print(f"BINARY_SHA256|{binary_sha}")
    print(f"APP|{app}")
    print(f"SIGNING_IDENTITY|{signing_identity}")
    print(f"PRODUCT|{product}")
    print(f"VERSION|{version}")
    print(f"TARGET|{target}")


def prepare(repo_text: str, manifest_text: str) -> None:
    repo = Path(repo_text)
    manifest = Path(manifest_text)
    if not repo.is_absolute() or not manifest.is_absolute():
        fail("Chrome custody repository and manifest must be absolute")
    expected_manifest = repo / "tools" / MANIFEST_NAME
    if manifest != expected_manifest:
        fail("replacement Chrome pin manifest cannot self-authorize")
    _controller, _wrapper, manifest_data, _trust = authorize_repo(repo)
    issuance = _bind_external_issuance(repo)
    pin = parse_production_manifest(manifest_data)
    if issuance["archive_sha256"] != pin["archive_sha"]:
        fail("Chrome custody issuance archive digest does not match the pin")
    if issuance["version"] != pin["version"] or issuance["product"] != pin["product"]:
        fail("Chrome custody issuance identity does not match the pin")
    if issuance["target"] != pin["target"]:
        fail("Chrome custody issuance target cannot be reused across Edge or Firefox/XPI")
    fields = install_extracted_runtime(pin)
    runtime = Path(fields["RUNTIME"])
    root = Path(fields["ROOT"])
    binary = Path(fields["BINARY"])
    try:
        check_browser_identity(
            runtime,
            root,
            binary,
            pin["product"],
            pin["version"],
            pin["architecture"],
            pin["signing_identity"],
            pin["executable_sha"],
        )
        if tree_hash(root) != pin["tree_sha"] or digest_file(binary) != pin["executable_sha"]:
            fail("Chrome runtime changed during identity validation")
        _print_prepare_fields(
            runtime,
            root,
            binary,
            Path(fields["APP"]),
            pin["tree_sha"],
            pin["executable_sha"],
            pin["signing_identity"],
            pin["product"],
            pin["version"],
            pin["target"],
        )
    except BaseException:
        try:
            _destroy_runtime(runtime)
        except (OSError, Refused):
            pass
        raise


def cleanup(runtime_text: str, expected_id: str) -> None:
    runtime = Path(runtime_text)
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing Chrome cleanup outside the private runtime prefix")
    if runtime.is_symlink() or not runtime.is_dir():
        fail("refusing cleanup of a substituted Chrome runtime")
    if runtime_identity(runtime) != expected_id:
        fail("refusing cleanup of a replaced Chrome runtime")
    _destroy_runtime(runtime)


def selftest(repo_text: str) -> None:
    """Validate local custody invariants without claiming release authority."""
    repo = Path(repo_text)
    if not repo.is_absolute():
        fail("Chrome custody selftest repository must be absolute")
    tools_dir = repo / "tools"
    controller_data = bind_regular_file(
        tools_dir / CONTROLLER_NAME,
        max_size=MAX_CONTROLLER,
        label="Chrome custody controller",
    )
    wrapper_data = bind_regular_file(
        tools_dir / WRAPPER_NAME,
        max_size=MAX_CONTROLLER,
        label="Chrome custody wrapper",
    )
    manifest_data = bind_regular_file(
        tools_dir / MANIFEST_NAME,
        max_size=MAX_MANIFEST,
        label="Chrome pin manifest",
    )
    trust_data = bind_regular_file(
        tools_dir / TRUST_ANCHOR_NAME,
        max_size=MAX_TRUST,
        label="Chrome custody trust-anchor",
    )
    trust = _parse_trust_anchor(trust_data)
    _require_digest(_digest_bytes(controller_data), str(trust["controller_sha256"]), "controller")
    _require_digest(_digest_bytes(wrapper_data), str(trust["wrapper_sha256"]), "wrapper")
    _require_digest(_digest_bytes(manifest_data), str(trust["manifest_sha256"]), "manifest")
    pin = parse_production_manifest(manifest_data)
    if pin["target"] != TARGET_ID:
        fail("Chrome custody selftest target mismatch")
    environment = _minimal_environment(PRIVATE_TMP / f"{RUNTIME_PREFIX}selftest")
    forbidden = [
        name
        for name in environment
        if "PROXY" in name.upper()
        or "AUTH" in name.upper()
        or "TOKEN" in name.upper()
        or "COOKIE" in name.upper()
        or "KEY" in name.upper()
    ]
    if forbidden or set(environment) != {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL"}:
        fail("Chrome custody selftest found a browser environment leak")
    for hostile in (b'{"x":1,"x":2}', b'{"x":NaN}'):
        try:
            json.loads(
                hostile,
                object_pairs_hook=_json_object,
                parse_constant=_reject_json_constant,
            )
        except Refused:
            pass
        else:
            fail("Chrome custody strict JSON selftest failed")
    print("INTERNAL_SELFTEST|PASS")
    try:
        _verify_authority_path(OWNER_AUTHORITY_PATH, require_immutable=True)
    except Refused as exc:
        print(f"PRODUCTION_AUTHORIZATION|OWNER_BLOCKED|{exc}")
    else:
        print("PRODUCTION_AUTHORIZATION|PROVISIONED_NOT_ISSUED")
    print(f"STORE_PUBLICATION|OWNER_BLOCKED|{OWNER_BLOCKED_STORE_IDS}")


def run_action(arguments: list[str]) -> int:
    try:
        separator = arguments.index("--")
    except ValueError:
        fail("Chrome run action requires an argument separator")
    verification = arguments[:separator]
    command = arguments[separator + 1 :]
    runtime, _root, binary, expected_binary = verify_runtime(verification)
    image: ExecutionImage | None = None
    try:
        image = authenticated_execution_image(binary, expected_binary, runtime)
        completed = _spawn_sandboxed_chrome(
            image, command, timeout=300, capture=False
        )
    except BaseException:
        if image is not None:
            image.cleanup()
            image = None
        verify_runtime(verification)
        raise
    if image is not None:
        image.cleanup()
        image = None
    verify_runtime(verification)
    return completed.returncode


def main() -> int:
    try:
        if len(sys.argv) < 2:
            fail("missing Chrome custody action")
        action = sys.argv[1]
        if action == "prepare" and len(sys.argv) == 4:
            prepare(sys.argv[2], sys.argv[3])
        elif action == "verify":
            verify_runtime(sys.argv[2:])
        elif action == "run":
            return run_action(sys.argv[2:])
        elif action == "cleanup" and len(sys.argv) == 4:
            cleanup(sys.argv[2], sys.argv[3])
        elif action == "selftest" and len(sys.argv) == 3:
            selftest(sys.argv[2])
        else:
            fail("unknown or malformed Chrome custody action")
    except (
        Refused,
        OSError,
        KeyError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        zipfile.BadZipFile,
    ) as exc:
        print(f"release-browser custody: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
