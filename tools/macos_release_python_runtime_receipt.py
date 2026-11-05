#!/usr/bin/env python3
"""External receipt schema for the owner-provisioned macOS release Python runtime.

A same-UID attacker must not replace the interpreter, stdlib, dylibs, launcher,
or vendor wheels between verification and execution. User-writable copies plus
pre-exec rehashing are not sufficient. The production path binds one root-owned,
non-user-writable runtime derived from the exact pinned python.org 3.14.7
package and wheels. This module never downloads, elevates privilege, installs,
or publishes a receipt or authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator


CONTRACT = "winsvpn-macos-release-python-runtime-v2"
SCHEMA_VERSION = 3
LEGACY_CONTRACT = "winsvpn-macos-release-python-runtime-v1"
ISSUER = "winsvpn-owner"
PLATFORM = "darwin_arm64"
PYTHON_VERSION = "3.14.7"
IMPLEMENTATION = "cpython"
EXECUTABLE_RELATIVE = "Python.framework/Versions/3.14/bin/python3.14"
FRAMEWORK_COMPONENT = "Python_Framework.pkg"
CONTROLLER = "tools/release_python_archive_custody.sh"
PROVISIONER = "tools/provision_macos_release_python_runtime.sh"
RECEIPT_SCHEMA = "tools/macos_release_python_runtime_receipt.py"
CUSTODY_METADATA = "tools/macos_release_python_runtime.custody.json"
RECEIPT_TEST = "tools/test_macos_release_python_runtime_receipt.py"
PROVISION_TEST = "tools/test_provision_macos_release_python_runtime.py"
ARCHIVE_TEST = "tools/test_release_python_archive_custody.py"
FIN_G00_TEST = "tools/test_fin_release_gate_g00_python_custody.py"
GCP_PROOF_COLLECTOR = "tools/gcp_proof_evidence.py"
GCP_PROOF_LIVE_PROBE = "tools/gcp_proof_live_probe.py"
FIN_RELEASE_GATE = "tools/fin_release_gate.sh"
FIN_RELEASE_GATE_SOURCE_CLOSURE = (
    "tools/release_android_toolchain_archive_custody.sh",
    "tools/release_openssl_archive_custody.sh",
    "tools/release_node_archive_custody.sh",
    "tools/release_browser_archive_custody.sh",
    "tools/release_go_archive_custody.sh",
)
PIN_MANIFEST = "tools/toolchain-pins.json"
DEFAULT_RUNTIME = "/Library/WinsVPN/ReleasePython/3.14.7"
DEFAULT_RECEIPT = "/Library/WinsVPN/ReleasePython/3.14.7.receipt.json"
OWNER_PROVISION_BOUNDARY = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision"
)
OWNER_PROVISION_LAUNCHER = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/owner-launcher"
)
OWNER_PROVISION_ACTION = (
    "owner action: use the fixed ReleasePython owner-provisioning boundary at "
    f"{OWNER_PROVISION_BOUNDARY} from a visible macOS Terminal"
)
RECEIPT_ENV = "WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_CDHASH = re.compile(r"[0-9a-f]{40,64}\Z")
CODESIGN_REQUIREMENT_TEXT = re.compile(r"[\x20-\x7e]+\Z")
GATEKEEPER_SOURCE_TEXT = re.compile(r"[\x20-\x7e]+\Z")
REQUIRED_GATEKEEPER_SOURCE = "Notarized Developer ID"
APPROVED_PACKAGE_SIGNATURE_STATUS = (
    "Status: signed by a developer certificate issued by Apple for distribution"
)
IDENTITY_RE = re.compile(
    r"^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:[0-9]+:[0-9]+:[0-9]+$"
)
CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
CS_REQUIRE_LV = 0x00002000
CS_RUNTIME = 0x00010000
REQUIRED_CODESIGN_FLAGS = CS_RUNTIME
CODESIGN_TIMEOUT_SECONDS = 30
MAX_CODESIGN_OUTPUT = 128 * 1024
MAX_ENTITLEMENT_NODES = 512
STANDARD_ENTITLEMENT_DOCTYPES = (
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    b'"https://www.apple.com/DTDs/PropertyList-1.0.dtd">',
)
PYTHON_APP_RELATIVE = "Python.framework/Versions/3.14/Resources/Python.app"
PYTHON_APP_EXECUTABLE_RELATIVE = f"{PYTHON_APP_RELATIVE}/Contents/MacOS/Python"
AUTHORITY_ENTRYPOINTS = (
    EXECUTABLE_RELATIVE,
    "Python.framework/Versions/3.14/bin/python3.14-intel64",
    PYTHON_APP_RELATIVE,
)
AUTHORITY_CODE_SLICES = (
    (AUTHORITY_ENTRYPOINTS[0], EXECUTABLE_RELATIVE, "arm64", "mach-o-thin"),
    (AUTHORITY_ENTRYPOINTS[0], EXECUTABLE_RELATIVE, "x86_64", "mach-o-thin"),
    (AUTHORITY_ENTRYPOINTS[1], AUTHORITY_ENTRYPOINTS[1], "x86_64", "mach-o-thin"),
    (AUTHORITY_ENTRYPOINTS[2], PYTHON_APP_EXECUTABLE_RELATIVE, "arm64", "app-bundle"),
    (AUTHORITY_ENTRYPOINTS[2], PYTHON_APP_EXECUTABLE_RELATIVE, "x86_64", "app-bundle"),
)
CODESIGN_INVOCATION_LIMIT = len(AUTHORITY_CODE_SLICES) * 4 + 1
CODESIGN_INVOCATION_LIMIT_ENV = "WINS_CODESIGN_INVOCATION_LIMIT"
REAUTH_MODE_ENV = "WINS_REAUTH_MODE"
_codesign_invocation_count = 0
FORBIDDEN_ENTITLEMENTS = frozenset(
    {
        "com.apple.security.automation.apple-events",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.debugger",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.get-task-allow",
        "get-task-allow",
    }
)
REQUIRED_EXECUTABLE_ENTITLEMENTS = {
    "com.apple.security.cs.allow-unsigned-executable-memory": True,
}
CODESIGN_ENTRYPOINT_KEYS = (
    "architecture",
    "codesign_authority",
    "codesign_authority_chain",
    "codesign_cdhash",
    "codesign_entitlements",
    "codesign_flags",
    "codesign_identifier",
    "codesign_kind",
    "codesign_requirement",
    "codesign_team_identifier",
    "executable_relative_path",
    "relative_path",
)
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
MAX_RECEIPT = 256 * 1024
MAX_CONTROLLER = 2 * 1024 * 1024
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Python tree "
    "immutable against same-user path replacement through execution"
)
OWNER_BLOCKED_UNAVAILABLE = (
    f"{EXECUTION_BLOCKER}; owner-provisioned root-owned Python 3.14.7 "
    "runtime is unavailable"
)
OWNER_BLOCKED_WRITABLE = (
    "owner-blocked: current reviewed Python runtime receipt is writable"
)
OWNER_BLOCKED_ADJACENT = (
    "owner-blocked: Python runtime receipt must be external to the candidate repository"
)
OWNER_BLOCKED_SELF_AUTH = (
    "owner-blocked: candidate-controlled Python runtime receipt cannot self-authorize"
)
OWNER_BLOCKED_ROOT_EXEC = (
    "owner-blocked: release Python custody must execute as a non-root user "
    "against a previously root-provisioned runtime"
)
OWNER_BLOCKED_MIGRATION = (
    "OWNER-BLOCKED: Python runtime receipt migration requires a current "
    "external owner-authority approval"
)
MIGRATION_CONTRACT = "winsvpn-macos-release-python-runtime-receipt-migration-v2"
MIGRATION_AUTHORITY_CONTRACT = (
    "winsvpn-macos-release-python-runtime-receipt-authority-v2"
)
MIGRATION_AUTHORITY_PATH = Path(
    "/Library/WinsVPN/ReleasePythonAuthority/v2/authority.json"
)
MIGRATION_SOURCE_FD_ENV = "WINS_RECEIPT_MIGRATION_HELD_SOURCE_FD"
MIGRATION_TEST_FD_ENV = "WINS_RECEIPT_MIGRATION_HELD_TEST_FD"
MIGRATION_EXECUTED_SOURCE_SHA256_ENV = (
    "WINS_RECEIPT_MIGRATION_EXECUTED_SOURCE_SHA256"
)
EXECUTED_SOURCE_SHA256_ENV = "WINS_RECEIPT_EXECUTED_SOURCE_SHA256"
MIGRATION_VALIDITY = timedelta(hours=24)
MIGRATION_ID_RE = re.compile(r"[0-9a-f]{64}\Z")
ISO_UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
RECEIPT_KEYS = (
    "authenticated",
    "codesign_authority",
    "codesign_authority_chain",
    "codesign_cdhash",
    "codesign_entitlements",
    "codesign_entrypoints",
    "codesign_flags",
    "codesign_identifier",
    "codesign_kind",
    "codesign_requirement",
    "codesign_team_identifier",
    "contract",
    "controller",
    "controller_sha256",
    "custody_closure",
    "executable_identity",
    "executable_path",
    "executable_sha256",
    "framework_dir_identity",
    "framework_identity_sha256",
    "framework_tree_sha256",
    "gatekeeper_assessment",
    "implementation",
    "issuer",
    "launcher_dir_identity",
    "launcher_identity_sha256",
    "launcher_primary_sha256",
    "launcher_tree_sha256",
    "owner_provision_launcher",
    "owner_provision_launcher_build_sha256",
    "owner_provision_launcher_compiler_sha256",
    "owner_provision_launcher_device",
    "owner_provision_launcher_inode",
    "owner_provision_launcher_linker_sha256",
    "owner_provision_launcher_sdk_closure_sha256",
    "owner_provision_launcher_sha256",
    "owner_provision_launcher_source_sha256",
    "package_sha256",
    "package_signature_status",
    "platform",
    "provisioner",
    "provisioner_sha256",
    "python_version",
    "receipt_schema",
    "receipt_schema_sha256",
    "runtime_dir_identity",
    "runtime_path",
    "schema_version",
    "vendor_dir_identity",
    "vendor_identity_sha256",
    "vendor_tree_sha256",
    "wheel_count",
    "wheels",
)
LEGACY_RECEIPT_KEYS = tuple(
    key
    for key in RECEIPT_KEYS
    if key not in {
        "codesign_authority_chain",
        "codesign_entitlements",
        "codesign_entrypoints",
        "codesign_flags",
        "codesign_kind",
        "codesign_requirement",
        "custody_closure",
        "gatekeeper_assessment",
        "launcher_primary_sha256",
        "owner_provision_launcher",
        "owner_provision_launcher_build_sha256",
        "owner_provision_launcher_compiler_sha256",
        "owner_provision_launcher_device",
        "owner_provision_launcher_inode",
        "owner_provision_launcher_linker_sha256",
        "owner_provision_launcher_sdk_closure_sha256",
        "owner_provision_launcher_sha256",
        "owner_provision_launcher_source_sha256",
    }
)
MIGRATION_CLOSURE_KEYS = (
    "archive_test_sha256",
    "browser_custody_sha256",
    "custody_controller_sha256",
    "custody_metadata_sha256",
    "fin_release_gate_sha256",
    "fin_g00_test_sha256",
    "go_custody_sha256",
    "gcp_proof_collector_sha256",
    "gcp_proof_live_probe_sha256",
    "node_custody_sha256",
    "openssl_custody_sha256",
    "pin_manifest_sha256",
    "provision_test_sha256",
    "provisioner_sha256",
    "receipt_test_sha256",
    "android_custody_sha256",
    "wrapper_sha256",
)
MIGRATION_AUTHORITY_KEYS = (
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
    "owner_provision_launcher_sdk_closure_sha256",
    "owner_provision_launcher_sha256",
    "owner_provision_launcher_source_sha256",
    "runtime_launcher_sha256",
    "runtime_python_sha256",
    "schema_version",
    "signing_policy",
    "signature_algorithm",
)
MIGRATION_OPERATION_KEYS = (
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
)
MIGRATION_PLAN_KEYS = (
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
)
SIGNING_POLICY_KEYS = (
    "authority_chain",
    "gatekeeper_origin",
    "gatekeeper_source",
    "requirements",
    "team_identifier",
)
GATEKEEPER_KEYS = ("origin", "relative_path", "source")
REPO_CLOSURE_PATHS = {
    "android_custody_sha256": FIN_RELEASE_GATE_SOURCE_CLOSURE[0],
    "archive_test_sha256": ARCHIVE_TEST,
    "browser_custody_sha256": FIN_RELEASE_GATE_SOURCE_CLOSURE[3],
    "custody_controller_sha256": RECEIPT_SCHEMA,
    "custody_metadata_sha256": CUSTODY_METADATA,
    "fin_g00_test_sha256": FIN_G00_TEST,
    "fin_release_gate_sha256": FIN_RELEASE_GATE,
    "go_custody_sha256": FIN_RELEASE_GATE_SOURCE_CLOSURE[4],
    "gcp_proof_collector_sha256": GCP_PROOF_COLLECTOR,
    "gcp_proof_live_probe_sha256": GCP_PROOF_LIVE_PROBE,
    "node_custody_sha256": FIN_RELEASE_GATE_SOURCE_CLOSURE[2],
    "openssl_custody_sha256": FIN_RELEASE_GATE_SOURCE_CLOSURE[1],
    "pin_manifest_sha256": PIN_MANIFEST,
    "provision_test_sha256": PROVISION_TEST,
    "provisioner_sha256": PROVISIONER,
    "receipt_test_sha256": RECEIPT_TEST,
    "wrapper_sha256": CONTROLLER,
}


class Refused(ValueError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


if os.geteuid() == 0:
    fail(OWNER_BLOCKED_ROOT_EXEC)


def _nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required for Python custody")
    return flag


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _json_constant(value: str) -> object:
    fail(f"non-finite JSON value rejected: {value}")


def canonical_bytes(payload: object) -> bytes:
    try:
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        fail(f"value cannot be represented as canonical JSON: {exc}")
    return (encoded + "\n").encode("ascii")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stat_identity(info: os.stat_result) -> tuple[int, ...]:
    flags = int(getattr(info, "st_flags", 0))
    return (
        info.st_dev,
        info.st_ino,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        flags,
    )


def file_identity(info: os.stat_result) -> str:
    # Durable receipt identity excludes ctime and BSD flags. The atomic
    # publication must clear and restore schg, which intentionally changes both
    # while preserving the inode and bytes. Race checks continue to use
    # _stat_identity(), which includes those transitional fields.
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


def dir_identity(info: os.stat_result) -> str:
    return file_identity(info)


def digest_file(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | _cloexec() | _nofollow())
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"hashed file must be one regular non-hardlinked file: {path}")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = path.lstat()
    if not (_stat_identity(before) == _stat_identity(after) == _stat_identity(latest)):
        fail(f"file changed while it was hashed: {path}")
    return digest.hexdigest()


class HeldRepoClosure:
    def __init__(self, repo: Path, manifest: Path) -> None:
        expected_repo = tools_dir().parent
        expected_manifest = expected_repo / PIN_MANIFEST
        if repo != expected_repo or manifest != expected_manifest:
            fail("replacement repository or pin manifest cannot self-authorize custody")
        self.repo = repo
        self.fds: dict[str, int] = {}
        self.data: dict[str, bytes] = {}
        self.identities: dict[str, tuple[int, ...]] = {}
        self.paths: dict[str, Path] = {}
        allowed = repo_file_uids()
        try:
            for key in MIGRATION_CLOSURE_KEYS:
                path = repo / REPO_CLOSURE_PATHS[key]
                info = path.lstat()
                if info.st_uid not in allowed:
                    fail(f"untrusted custody closure owner rejected: {path}")
                require_regular_file(
                    path,
                    allowed_uids=allowed,
                    allow_sticky_tmp=True,
                    forbid_owner_write=False,
                    leaf_uid=info.st_uid,
                )
                fd = os.open(path, os.O_RDONLY | _cloexec() | _nofollow())
                self.fds[key] = fd
                opened = os.fstat(fd)
                if _stat_identity(opened) != _stat_identity(info):
                    fail(f"custody closure file was replaced before open: {path}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_CONTROLLER:
                        fail(f"custody closure file exceeds the size limit: {path}")
                    chunks.append(block)
                if total <= 0:
                    fail(f"custody closure file is empty: {path}")
                after = os.fstat(fd)
                latest = path.lstat()
                if not (
                    _stat_identity(opened)
                    == _stat_identity(after)
                    == _stat_identity(latest)
                ):
                    fail(f"custody closure file changed while held: {path}")
                self.data[key] = b"".join(chunks)
                self.identities[key] = _stat_identity(opened)
                self.paths[key] = path
        except BaseException:
            self.close()
            raise

    def closure(self) -> dict[str, str]:
        return {
            key: digest_bytes(self.data[key])
            for key in MIGRATION_CLOSURE_KEYS
        }

    def assert_current(self) -> None:
        for key in MIGRATION_CLOSURE_KEYS:
            fd = self.fds[key]
            path = self.paths[key]
            try:
                held = os.fstat(fd)
                latest = path.lstat()
            except OSError as exc:
                fail(f"custody closure identity check failed: {path}: {exc}")
            if not (
                _stat_identity(held)
                == self.identities[key]
                == _stat_identity(latest)
            ):
                fail(f"custody closure path or bytes drift rejected: {path}")

    def close(self) -> None:
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds.clear()


@contextmanager
def hold_repo_closure(repo: Path, manifest: Path) -> Iterator[HeldRepoClosure]:
    held = HeldRepoClosure(repo, manifest)
    try:
        yield held
        held.assert_current()
    finally:
        held.close()


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
    except ValueError:
        return False
    return True


def require_path_components(
    path: Path,
    *,
    allowed_uids: set[int],
    allow_sticky_tmp: bool = False,
    leaf_must_match: int | None = None,
) -> None:
    if not path.is_absolute():
        fail(f"path is not absolute: {path}")
    current = Path("/")
    parts = path.parts[1:]
    for index, part in enumerate(parts):
        if part in {"", ".", ".."}:
            fail(f"unsafe path component in {path}")
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            fail(f"missing path component: {current}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"symlink path component rejected: {current}")
        is_last = index == len(parts) - 1
        if not is_last and not stat.S_ISDIR(info.st_mode):
            fail(f"non-directory path component rejected: {current}")
        allowed = {leaf_must_match} if is_last and leaf_must_match is not None else allowed_uids
        if info.st_uid not in allowed:
            fail(f"untrusted path owner rejected: {current}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022:
            sticky_ok = (
                allow_sticky_tmp
                and info.st_uid == 0
                and bool(mode & stat.S_ISVTX)
                and current in {Path("/tmp"), Path("/private/tmp")}
            )
            if not sticky_ok:
                fail(f"group/world-writable path component rejected: {current}")


def require_regular_file(
    path: Path,
    *,
    allowed_uids: set[int],
    required_mode: int | None = None,
    allow_sticky_tmp: bool = False,
    forbid_owner_write: bool = True,
    leaf_uid: int | None = None,
) -> os.stat_result:
    required_leaf = leaf_uid if leaf_uid is not None else next(iter(allowed_uids))
    require_path_components(
        path,
        allowed_uids=allowed_uids,
        allow_sticky_tmp=allow_sticky_tmp,
        leaf_must_match=required_leaf,
    )
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"regular non-symlink file required: {path}")
    if info.st_nlink != 1:
        fail(f"hardlinked input rejected: {path}")
    if info.st_uid != required_leaf:
        fail(f"untrusted path owner rejected: {path}")
    mode = stat.S_IMODE(info.st_mode)
    if required_mode is not None and mode != required_mode:
        fail(f"unexpected file mode for {path}")
    writable = 0o222 if forbid_owner_write else 0o022
    if mode & writable:
        fail(f"writable input rejected: {path}")
    return info


def _reject_escaping_symlink(root: Path, path: Path, target: str, relative: str) -> None:
    if not target or target.startswith("/") or "\\" in target:
        fail(f"absolute extracted symlink rejected: {relative}")
    try:
        base = path.parent.relative_to(root)
    except ValueError:
        fail(f"escaping extracted symlink rejected: {relative}")
    parts = [part for part in base.parts if part not in {"", "."}]
    for part in Path(target).parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                fail(f"escaping extracted symlink rejected: {relative}")
            parts.pop()
            continue
        if part.startswith("/") or "\\" in part:
            fail(f"absolute extracted symlink rejected: {relative}")
        parts.append(part)


def bind_tree(
    root: Path,
    *,
    required_uid: int,
    allow_symlinks: bool,
    require_system_immutable: bool = False,
) -> dict[str, str]:
    if root.is_symlink():
        fail("tree root symbolic link rejected")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | _cloexec() | _nofollow())
    try:
        root_info = os.fstat(fd)
        latest = root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            fail("directory descriptor is not a directory")
        if _stat_identity(root_info) != _stat_identity(latest):
            fail("directory was replaced before it was bound")
        if root_info.st_uid != required_uid:
            fail("wrong owner")
        if stat.S_IMODE(root_info.st_mode) & 0o222:
            fail("tree root is writable")
        if require_system_immutable:
            root_flags = int(getattr(root_info, "st_flags", 0))
            if root_flags & UF_IMMUTABLE and not (root_flags & SF_IMMUTABLE):
                fail("UF_IMMUTABLE is insufficient for tree root")
            if not (root_flags & SF_IMMUTABLE):
                fail("SF_IMMUTABLE is required for tree root")
        content = hashlib.sha256()
        identity = hashlib.sha256()

        def feed(digest: "hashlib._Hash", *parts: object) -> None:
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
                if (
                    not relative
                    or relative.startswith("/")
                    or "\\" in relative
                    or "/./" in f"/{relative}/"
                    or "/../" in f"/{relative}/"
                ):
                    fail(f"unsafe tree path: {relative}")
                info = entry.stat(follow_symlinks=False)
                mode = stat.S_IMODE(info.st_mode)
                flags = int(getattr(info, "st_flags", 0))
                if info.st_uid != required_uid:
                    fail(f"wrong owner: {relative}")
                if require_system_immutable and not stat.S_ISLNK(info.st_mode):
                    if flags & UF_IMMUTABLE and not (flags & SF_IMMUTABLE):
                        fail(f"UF_IMMUTABLE is insufficient: {relative}")
                    if not (flags & SF_IMMUTABLE):
                        fail(f"SF_IMMUTABLE is required: {relative}")
                feed(
                    identity,
                    relative,
                    info.st_dev,
                    info.st_ino,
                    info.st_nlink,
                    info.st_uid,
                    info.st_gid,
                    info.st_mode,
                    info.st_size,
                    info.st_mtime_ns,
                )
                if stat.S_ISLNK(info.st_mode):
                    if not allow_symlinks:
                        fail("custody tree symlink rejected")
                    target = os.readlink(path)
                    _reject_escaping_symlink(root, path, target, relative)
                    feed(content, "L", relative, target)
                elif mode & 0o222:
                    fail(f"writable tree entry rejected: {relative}")
                elif stat.S_ISDIR(info.st_mode):
                    feed(content, "D", relative, mode, flags)
                    walk(path)
                elif stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1:
                        fail(f"hardlinked tree file rejected: {relative}")
                    file_digest = digest_file(path)
                    hashed = path.lstat()
                    if _stat_identity(hashed) != _stat_identity(info):
                        fail(f"file identity changed while bound: {relative}")
                    feed(content, "F", relative, mode, info.st_size, file_digest, flags)
                else:
                    fail(f"custody tree special file rejected: {relative}")

        walk(root)
        finished = os.fstat(fd)
        latest = root.lstat()
        if not (
            _stat_identity(root_info)
            == _stat_identity(finished)
            == _stat_identity(latest)
        ):
            fail("tree root was replaced while it was bound")
        content_digest = content.hexdigest()
        identity_digest = identity.hexdigest()
        if len(content_digest) != 64 or len(identity_digest) != 64:
            fail("incomplete tree bind")
        return {
            "content": content_digest,
            "identity": identity_digest,
            "dir_identity": dir_identity(root_info),
        }
    finally:
        os.close(fd)


def prove_not_user_mutable(paths: list[Path]) -> None:
    if not paths:
        fail(EXECUTION_BLOCKER)
    for path in paths:
        try:
            info = path.lstat()
        except OSError as exc:
            fail(f"{EXECUTION_BLOCKER}: {exc}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"{EXECUTION_BLOCKER}: probe path is a symlink: {path}")
        if info.st_uid == os.getuid():
            fail(f"{EXECUTION_BLOCKER}: probe path is same-UID mutable: {path}")
        try:
            os.chmod(path, 0o700 if stat.S_ISDIR(info.st_mode) else 0o600)
        except OSError:
            pass
        else:
            fail(EXECUTION_BLOCKER)
        if stat.S_ISREG(info.st_mode):
            try:
                fd = os.open(path, os.O_WRONLY | _cloexec() | _nofollow())
            except OSError:
                pass
            else:
                os.close(fd)
                fail(EXECUTION_BLOCKER)
            try:
                os.unlink(path)
            except OSError:
                pass
            else:
                fail(EXECUTION_BLOCKER)
        if sys.platform == "darwin":
            try:
                os.chflags(path, 0)
            except OSError:
                pass
            else:
                fail(EXECUTION_BLOCKER)
        after = path.lstat()
        if _stat_identity(after) != _stat_identity(info):
            fail(EXECUTION_BLOCKER)


def _codesign_blocker(message: str) -> None:
    fail(f"OWNER-BLOCKED: {EXECUTION_BLOCKER}: {message}")


def _validate_codesign_command(argv: list[str]) -> None:
    if not argv or any(type(item) is not str for item in argv):
        _codesign_blocker("code-signing policy command drift rejected")
    target = argv[-1]
    target_path = Path(target)
    if (
        not target_path.is_absolute()
        or target != str(target_path)
        or target.startswith(("-", "@"))
        or any(character in target for character in ("\0", "\n", "\r"))
        or any(part in {".", ".."} for part in target_path.parts)
    ):
        _codesign_blocker("code-signing target path substitution rejected")
    try:
        resolved = target_path.resolve(strict=True)
    except OSError as exc:
        _codesign_blocker(f"code-signing target path is unavailable: {exc}")
    if resolved != target_path or target_path.is_symlink():
        _codesign_blocker("code-signing target path indirection rejected")
    if argv[0] == CODESIGN:
        if len(argv) < 2 or any(
            item in {"--sign", "-s", "--remove-signature"} for item in argv[1:]
        ):
            _codesign_blocker("mutating codesign operation rejected")
        try:
            architecture = argv[argv.index("--architecture") + 1]
        except (ValueError, IndexError):
            architecture = ""
        if architecture not in {"arm64", "x86_64"}:
            _codesign_blocker("code-signing architecture selector is invalid")
        approved = (
            [CODESIGN, "--verify", "--strict", "--architecture", architecture, target],
            [CODESIGN, "--display", "--architecture", architecture, "--verbose=4", target],
            [
                CODESIGN,
                "--display",
                "--architecture",
                architecture,
                "--requirements",
                "-",
                target,
            ],
            [
                CODESIGN,
                "--display",
                "--architecture",
                architecture,
                "--entitlements",
                "-",
                "--xml",
                target,
            ],
        )
    elif argv[0] == SPCTL:
        approved = (
            [SPCTL, "--assess", "--type", "execute", "--verbose=4", target],
        )
    else:
        _codesign_blocker("code-signing policy command drift rejected")
    if argv not in approved:
        _codesign_blocker("code-signing argv shape substitution rejected")


def _consume_codesign_invocation_budget() -> None:
    configured = os.environ.get(CODESIGN_INVOCATION_LIMIT_ENV)
    mode = os.environ.get(REAUTH_MODE_ENV)
    if mode is None and configured is None:
        return
    if mode not in {"candidate", "published"}:
        _codesign_blocker("code-signing invocation budget scope rejected")
    if configured != str(CODESIGN_INVOCATION_LIMIT):
        _codesign_blocker("code-signing invocation budget configuration rejected")
    global _codesign_invocation_count
    if _codesign_invocation_count >= CODESIGN_INVOCATION_LIMIT:
        _codesign_blocker("code-signing invocation budget exhausted")
    _codesign_invocation_count += 1


def _run_codesign(argv: list[str], *, label: str) -> subprocess.CompletedProcess[bytes]:
    expected = list(argv)
    _validate_codesign_command(expected)
    _consume_codesign_invocation_budget()
    try:
        completed = subprocess.run(
            expected,
            check=False,
            capture_output=True,
            close_fds=True,
            cwd="/",
            stdin=subprocess.DEVNULL,
            pass_fds=(),
            shell=False,
            timeout=CODESIGN_TIMEOUT_SECONDS,
            env={
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _codesign_blocker(f"{label} command failed: {exc}")
    if completed.args != expected:
        _codesign_blocker(f"{label} response substitution rejected")
    if type(completed.returncode) is not int:
        _codesign_blocker(f"{label} return code is malformed")
    if type(completed.stdout) is not bytes or type(completed.stderr) is not bytes:
        _codesign_blocker(f"{label} output type is malformed")
    if len(completed.stdout) > MAX_CODESIGN_OUTPUT or len(completed.stderr) > MAX_CODESIGN_OUTPUT:
        _codesign_blocker(f"{label} output exceeds the size limit")
    if b"\0" in completed.stdout or b"\0" in completed.stderr:
        _codesign_blocker(f"{label} output contains a NUL")
    return completed


def _decode_codesign(data: bytes, *, label: str) -> str:
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        _codesign_blocker(f"{label} output is not UTF-8: {exc}")
    if "\r" in value:
        _codesign_blocker(f"{label} output has ambiguous line endings")
    return value


def _parse_codesign_details(
    data: bytes,
    executable_path: Path,
    architecture: str,
    codesign_kind: str,
) -> dict[str, object]:
    text = _decode_codesign(data, label="codesign detail")
    lines = text.splitlines()
    expected_executable = f"Executable={executable_path}"
    if not lines or lines[0] != expected_executable or lines.count(expected_executable) != 1:
        _codesign_blocker("codesign detail response substitution rejected")

    single: dict[str, str] = {}
    authorities: list[str] = []
    adhoc = False
    prefixes = {
        "Identifier=": "identifier",
        "Format=": "format",
        "CDHash=": "cdhash",
        "TeamIdentifier=": "team",
        "CodeDirectory ": "code_directory",
    }
    for line in lines[1:]:
        matched = False
        for prefix, key in prefixes.items():
            if line.startswith(prefix):
                if key in single:
                    _codesign_blocker(f"duplicate {key} in codesign detail output")
                single[key] = line[len(prefix):]
                matched = True
                break
        if matched:
            continue
        if line.startswith("Authority="):
            authority = line.split("=", 1)[1]
            if not authority:
                _codesign_blocker("empty authority in codesign detail output")
            authorities.append(authority)
        elif line == "Signature=adhoc":
            if adhoc:
                _codesign_blocker("duplicate ad hoc signature state")
            adhoc = True

    required = {"identifier", "format", "cdhash", "team", "code_directory"}
    if set(single) != required:
        _codesign_blocker("code signature identity or flags are incomplete")
    identifier = single["identifier"]
    cdhash = single["cdhash"].lower()
    team = single["team"]
    if team == "not set":
        team = ""
    if not identifier or "/" in identifier or "\\" in identifier:
        _codesign_blocker("code signature identifier is invalid")
    if HEX_CDHASH.fullmatch(cdhash) is None:
        _codesign_blocker("code signature digest is invalid")
    expected_format = {
        "mach-o-thin": f"Mach-O thin ({architecture})",
        "app-bundle": f"app bundle with Mach-O thin ({architecture})",
    }.get(codesign_kind)
    if expected_format is None or single["format"] != expected_format:
        _codesign_blocker("codesign kind/path/architecture response substitution rejected")
    if any("\n" in value or "\0" in value for value in (identifier, team, *authorities)):
        _codesign_blocker("code signature identity text is unsafe")
    if adhoc and authorities:
        _codesign_blocker("ambiguous ad hoc and authority signature state")
    if not adhoc and not authorities:
        _codesign_blocker("code signature authority state is incomplete")

    code_directory = re.fullmatch(
        r"v=[0-9]+ size=[0-9]+ flags=0x([0-9a-fA-F]{1,8})"
        r"\(([a-z0-9,-]+)\) hashes=[0-9]+\+[0-9]+ location=embedded",
        single["code_directory"],
    )
    if code_directory is None:
        _codesign_blocker("CodeDirectory flags output is malformed or absent")
    flags = int(code_directory.group(1), 16)
    flag_names = code_directory.group(2).split(",")
    if len(flag_names) != len(set(flag_names)):
        _codesign_blocker("CodeDirectory flag names are duplicated")
    if (flags == 0) != (flag_names == ["none"]):
        _codesign_blocker("CodeDirectory flag names do not match the numeric flags")
    if flags & CS_RUNTIME and "runtime" not in flag_names:
        _codesign_blocker("CodeDirectory runtime flag output is ambiguous")
    if flags & CS_REQUIRE_LV and "library" not in flag_names:
        _codesign_blocker("CodeDirectory library-validation flag output is ambiguous")

    return {
        "codesign_authority": authorities[0] if authorities else "adhoc",
        "codesign_authority_chain": authorities,
        "codesign_cdhash": cdhash,
        "codesign_flags": flags,
        "codesign_identifier": identifier,
        "codesign_kind": codesign_kind,
        "codesign_team_identifier": team,
    }


def _parse_codesign_requirement(
    stdout: bytes,
    stderr: bytes,
    executable_path: Path,
) -> str:
    if type(stdout) is not bytes or type(stderr) is not bytes:
        _codesign_blocker("codesign requirement output type is malformed")
    if stderr != f"Executable={executable_path}\n".encode("utf-8"):
        _codesign_blocker("codesign requirement response substitution rejected")
    text = _decode_codesign(stdout, label="codesign requirement")
    if text.count("\n") != 1 or not text.endswith("\n"):
        _codesign_blocker("codesign requirement stream shape is ambiguous")
    prefix = "designated => "
    line = text[:-1]
    if not line.startswith(prefix):
        _codesign_blocker("designated requirement is missing")
    requirement = line[len(prefix):]
    if (
        CODESIGN_REQUIREMENT_TEXT.fullmatch(requirement) is None
        or requirement != requirement.strip()
    ):
        _codesign_blocker("designated requirement is malformed")
    return requirement


def _parse_gatekeeper_assessment(
    data: bytes,
    app_path: Path,
    expected_origin: str,
) -> dict[str, str]:
    text = _decode_codesign(data, label="Gatekeeper assessment")
    if not text.endswith("\n") or text.count("\n") not in {2, 3}:
        _codesign_blocker("Gatekeeper assessment stream shape is ambiguous")
    lines = text[:-1].split("\n")
    prefix = f"{app_path}: accepted"
    if lines[0] != prefix:
        _codesign_blocker("Gatekeeper did not accept the exact Python.app bundle")
    source_prefix = "source="
    if not lines[1].startswith(source_prefix):
        _codesign_blocker("Gatekeeper policy output is malformed")
    source = lines[1][len(source_prefix):]
    if (
        not source
        or GATEKEEPER_SOURCE_TEXT.fullmatch(source) is None
        or source != source.strip()
    ):
        _codesign_blocker("Gatekeeper policy identity is incomplete")
    if len(lines) == 3:
        origin_prefix = "origin="
        if not lines[2].startswith(origin_prefix):
            _codesign_blocker("Gatekeeper policy output is malformed")
        if lines[2][len(origin_prefix):] != expected_origin:
            _codesign_blocker(
                "Gatekeeper origin does not match the measured signing identity"
            )
    return {
        "origin": expected_origin,
        "relative_path": PYTHON_APP_RELATIVE,
        "source": source,
    }


def parse_codesign_entitlements(data: bytes) -> dict[str, object]:
    if type(data) is not bytes or not data or len(data) > MAX_CODESIGN_OUTPUT:
        fail("codesign entitlements plist size is invalid")
    if b"\0" in data:
        fail("codesign entitlements plist contains a NUL")
    upper = data.upper()
    if b"<!DOCTYPE" in upper:
        declared = sum(
            data.count(doctype) for doctype in STANDARD_ENTITLEMENT_DOCTYPES
        )
        if upper.count(b"<!DOCTYPE") != 1 or declared != 1:
            fail("codesign entitlements plist has an unexpected document type")
    if b"<!ENTITY" in upper or b"<![CDATA[" in upper or b"<!--" in data:
        fail("codesign entitlements plist contains ambiguous XML constructs")
    after_declaration = data
    if data.startswith(b"<?xml"):
        declaration_end = data.find(b"?>")
        if declaration_end < 0:
            fail("codesign entitlements plist declaration is malformed")
        after_declaration = data[declaration_end + 2:]
    if b"<?" in after_declaration:
        fail("codesign entitlements plist contains an ambiguous processing instruction")
    try:
        text = data.decode("utf-8")
        root = ElementTree.fromstring(text)
    except (UnicodeDecodeError, ElementTree.ParseError) as exc:
        fail(f"codesign entitlements plist is malformed: {exc}")
    if root.tag != "plist" or root.attrib != {"version": "1.0"} or len(root) != 1:
        fail("codesign entitlements plist root is malformed")
    if root.text is not None and root.text.strip():
        fail("codesign entitlements plist root text is ambiguous")

    nodes = 0

    def parse_value(element: ElementTree.Element, *, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_ENTITLEMENT_NODES or depth > 32:
            fail("codesign entitlements plist is too complex")
        if element.attrib:
            fail("codesign entitlements plist value attributes are forbidden")
        if element.tail is not None and element.tail.strip():
            fail("codesign entitlements plist tail text is ambiguous")
        if element.tag == "dict":
            if element.text is not None and element.text.strip():
                fail("codesign entitlements dictionary text is ambiguous")
            children = list(element)
            if len(children) % 2:
                fail("codesign entitlements dictionary is malformed")
            result: dict[str, object] = {}
            for index in range(0, len(children), 2):
                key_node = children[index]
                if key_node.tag != "key" or key_node.attrib or len(key_node):
                    fail("codesign entitlements dictionary key is malformed")
                key = key_node.text or ""
                if not key or "\0" in key or key in result:
                    if key in result:
                        fail(f"duplicate codesign entitlement key rejected: {key}")
                    fail("codesign entitlements dictionary key is unsafe")
                if key_node.tail is not None and key_node.tail.strip():
                    fail("codesign entitlements dictionary key tail is ambiguous")
                result[key] = parse_value(children[index + 1], depth=depth + 1)
            return result
        if element.tag == "array":
            if element.text is not None and element.text.strip():
                fail("codesign entitlements array text is ambiguous")
            return [parse_value(child, depth=depth + 1) for child in element]
        if len(element):
            fail("codesign entitlements scalar contains child nodes")
        if element.tag == "string":
            value = element.text or ""
            if "\0" in value:
                fail("codesign entitlement string contains a NUL")
            return value
        if element.tag == "integer":
            value = element.text or ""
            if re.fullmatch(r"-?(?:0|[1-9][0-9]*)", value) is None:
                fail("codesign entitlement integer is malformed")
            parsed = int(value, 10)
            if parsed < -(2**63) or parsed > 2**63 - 1:
                fail("codesign entitlement integer is out of range")
            return parsed
        if element.tag in {"true", "false"}:
            if element.text is not None and element.text.strip():
                fail("codesign entitlement Boolean is malformed")
            return element.tag == "true"
        fail(f"codesign entitlement value type is unsupported: {element.tag}")

    document = parse_value(root[0], depth=0)
    if type(document) is not dict:
        fail("codesign entitlements plist must contain one dictionary")
    return document


def _receipt_entitlements(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    nodes = 0

    def copy(item: object, *, depth: int) -> object:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_ENTITLEMENT_NODES or depth > 32:
            fail(f"{label} is too complex")
        if type(item) is dict:
            result: dict[str, object] = {}
            for key, child in item.items():
                if type(key) is not str or not key or "\0" in key:
                    fail(f"{label} contains an unsafe key")
                result[key] = copy(child, depth=depth + 1)
            return result
        if type(item) is list:
            return [copy(child, depth=depth + 1) for child in item]
        if type(item) in {str, bool, int}:
            if type(item) is str and "\0" in item:
                fail(f"{label} contains a NUL")
            if type(item) is int and (item < -(2**63) or item > 2**63 - 1):
                fail(f"{label} integer is out of range")
            return item
        fail(f"{label} contains an unsupported value type")

    copied = copy(value, depth=0)
    if type(copied) is not dict:
        fail(f"{label} must be a JSON object")
    return copied


def _validate_codesign_posture(flags: object, entitlements: object, *, label: str) -> None:
    if type(flags) is not int or flags < 0 or flags > 0xFFFFFFFF:
        _codesign_blocker(f"{label} CodeDirectory flags are invalid")
    if flags & CS_RUNTIME == 0:
        _codesign_blocker(f"{label} is missing the hardened runtime flag")
    parsed = _receipt_entitlements(entitlements, label=f"{label} entitlements")
    for key in sorted(parsed):
        if key in FORBIDDEN_ENTITLEMENTS:
            _codesign_blocker(f"{label} has forbidden entitlement: {key}")
        if key not in REQUIRED_EXECUTABLE_ENTITLEMENTS:
            _codesign_blocker(
                f"{label} has unknown security-sensitive entitlement state: {key}"
            )
    if parsed != REQUIRED_EXECUTABLE_ENTITLEMENTS:
        _codesign_blocker(f"{label} executable entitlement policy is not exact")


def codesign_record(
    path: Path,
    architecture: str,
    *,
    executable_path: Path | None = None,
    codesign_kind: str = "mach-o-thin",
) -> dict[str, object]:
    path_text = str(path)
    executable = path if executable_path is None else executable_path
    executable_text = str(executable)
    expected_target_kind = (
        path.is_file()
        if codesign_kind == "mach-o-thin"
        else path.is_dir()
        if codesign_kind == "app-bundle"
        else False
    )
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not expected_target_kind
        or any(character in path_text for character in ("\0", "\n", "\r"))
    ):
        fail("code signature target kind/path substitution rejected")
    if (
        not executable.is_absolute()
        or executable.is_symlink()
        or not executable.is_file()
        or any(character in executable_text for character in ("\0", "\n", "\r"))
    ):
        fail("code signature executable must be one safe absolute regular file")
    if codesign_kind == "app-bundle" and executable != path / "Contents/MacOS/Python":
        fail("code signature app-bundle executable path substitution rejected")
    if codesign_kind == "mach-o-thin" and executable != path:
        fail("code signature Mach-O executable path substitution rejected")
    if architecture not in {"arm64", "x86_64"}:
        fail("code signature architecture selector is invalid")

    verify_argv = [
        CODESIGN,
        "--verify",
        "--strict",
        "--architecture",
        architecture,
        path_text,
    ]
    verify = _run_codesign(verify_argv, label="codesign verification")
    if verify.returncode != 0:
        _codesign_blocker("code signature is missing or invalid")
    if verify.stdout or verify.stderr:
        _codesign_blocker("codesign verification output is ambiguous")

    detail_argv = [
        CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--verbose=4",
        path_text,
    ]
    detail = _run_codesign(detail_argv, label="codesign detail")
    if detail.returncode != 0 or detail.stdout:
        _codesign_blocker("codesign detail output is missing or ambiguous")
    record = _parse_codesign_details(
        detail.stderr,
        executable,
        architecture,
        codesign_kind,
    )

    requirement_argv = [
        CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--requirements",
        "-",
        path_text,
    ]
    requirement = _run_codesign(requirement_argv, label="codesign requirement")
    if requirement.returncode != 0:
        _codesign_blocker("codesign requirement output is missing or ambiguous")
    record["codesign_requirement"] = _parse_codesign_requirement(
        requirement.stdout,
        requirement.stderr,
        executable,
    )

    entitlement_argv = [
        CODESIGN,
        "--display",
        "--architecture",
        architecture,
        "--entitlements",
        "-",
        "--xml",
        path_text,
    ]
    entitlement = _run_codesign(entitlement_argv, label="codesign entitlements")
    expected_stderr = f"Executable={executable}\n".encode("utf-8")
    if entitlement.returncode != 0 or entitlement.stderr != expected_stderr:
        _codesign_blocker("codesign entitlements output is missing or ambiguous")
    entitlements: dict[str, object] = {}
    if entitlement.stdout:
        try:
            entitlements = parse_codesign_entitlements(entitlement.stdout)
        except Refused as exc:
            _codesign_blocker(str(exc))
    record["codesign_entitlements"] = entitlements
    _validate_codesign_posture(
        record["codesign_flags"],
        record["codesign_entitlements"],
        label=path_text,
    )
    return record


def codesign_entrypoint_records(runtime: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for relative, executable_relative, architecture, codesign_kind in AUTHORITY_CODE_SLICES:
        record = codesign_record(
            runtime / relative,
            architecture,
            executable_path=runtime / executable_relative,
            codesign_kind=codesign_kind,
        )
        records.append(
            {
                **record,
                "architecture": architecture,
                "executable_relative_path": executable_relative,
                "relative_path": relative,
            }
        )
    first = records[0]
    for record in records[1:]:
        for key in (
            "codesign_authority",
            "codesign_authority_chain",
            "codesign_entitlements",
            "codesign_flags",
            "codesign_team_identifier",
        ):
            if record[key] != first[key]:
                _codesign_blocker(f"cross-entrypoint {key} drift rejected")
    return records


def gatekeeper_assessment(
    runtime: Path,
    *,
    expected_origin: str,
) -> dict[str, str]:
    app = runtime / PYTHON_APP_RELATIVE
    app_text = str(app)
    if (
        type(expected_origin) is not str
        or not expected_origin
        or expected_origin == "adhoc"
        or CODESIGN_REQUIREMENT_TEXT.fullmatch(expected_origin) is None
        or expected_origin != expected_origin.strip()
        or any(character in app_text for character in ("\0", "\n", "\r"))
    ):
        _codesign_blocker("Gatekeeper signing identity binding is invalid")
    argv = [SPCTL, "--assess", "--type", "execute", "--verbose=4", app_text]
    completed = _run_codesign(argv, label="Gatekeeper assessment")
    if completed.returncode != 0 or completed.stdout:
        _codesign_blocker("Gatekeeper policy rejected Python.app")
    assessment = _parse_gatekeeper_assessment(
        completed.stderr,
        app,
        expected_origin,
    )
    if assessment["source"] != REQUIRED_GATEKEEPER_SOURCE:
        _codesign_blocker(
            "Gatekeeper did not accept Python.app as notarized Developer ID code"
        )
    return assessment


def _text(root: dict[str, object], key: str) -> str:
    value = root.get(key)
    if type(value) is not str or "\0" in value:
        fail(f"{key} must be a string")
    return value


def _hex_digest(root: dict[str, object], key: str) -> str:
    value = _text(root, key)
    if HEX64.fullmatch(value) is None or value == "0" * 64:
        fail(f"invalid Python digest pin: {key}")
    return value


def _wheels(value: object, wheel_count: int) -> list[dict[str, str]]:
    if type(value) is not list or len(value) != wheel_count:
        fail("wheels must be an exact-length JSON array")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if type(item) is not dict or set(item.keys()) != {"name", "sha256"}:
            fail(f"wheel {index} keys are not exact")
        name = item["name"]
        digest = item["sha256"]
        if (
            type(name) is not str
            or not name.endswith(".whl")
            or "/" in name
            or "\\" in name
            or name in seen
        ):
            fail(f"wheel {index} name is unsafe")
        if type(digest) is not str or HEX64.fullmatch(digest) is None or digest == "0" * 64:
            fail(f"wheel {index} digest is invalid")
        seen.add(name)
        result.append({"name": name, "sha256": digest})
    return result


def _codesign_entrypoints(value: object) -> list[dict[str, object]]:
    if type(value) is not list or len(value) != len(AUTHORITY_CODE_SLICES):
        fail("codesign_entrypoints must bind the exact authority entrypoint set")
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if type(item) is not dict or set(item) != set(CODESIGN_ENTRYPOINT_KEYS):
            fail(f"codesign entrypoint {index} keys are not exact")
        relative = _text(item, "relative_path")
        executable_relative = _text(item, "executable_relative_path")
        architecture = _text(item, "architecture")
        codesign_kind = _text(item, "codesign_kind")
        (
            expected_relative,
            expected_executable,
            expected_architecture,
            expected_kind,
        ) = AUTHORITY_CODE_SLICES[index]
        if (
            relative != expected_relative
            or executable_relative != expected_executable
            or architecture != expected_architecture
            or codesign_kind != expected_kind
        ):
            fail("codesign entrypoints have a cross-kind/path/architecture substitution")
        cdhash = _text(item, "codesign_cdhash").lower()
        if HEX_CDHASH.fullmatch(cdhash) is None:
            fail(f"codesign entrypoint {index} digest is invalid")
        identifier = _text(item, "codesign_identifier")
        if not identifier or "/" in identifier or "\\" in identifier:
            fail(f"codesign entrypoint {index} identifier is invalid")
        authority = _text(item, "codesign_authority")
        authority_chain = item.get("codesign_authority_chain")
        team = _text(item, "codesign_team_identifier")
        requirement = _text(item, "codesign_requirement")
        if (
            type(authority_chain) is not list
            or not authority_chain
            or any(type(value) is not str or not value or "\n" in value for value in authority_chain)
            or authority != authority_chain[0]
            or not requirement
            or "\n" in requirement
        ):
            fail(f"codesign entrypoint {index} external signing identity is invalid")
        if not authority or "\n" in authority or "\n" in team:
            fail(f"codesign entrypoint {index} authority state is invalid")
        flags = item.get("codesign_flags")
        entitlements = _receipt_entitlements(
            item.get("codesign_entitlements"),
            label=f"codesign entrypoint {index} entitlements",
        )
        _validate_codesign_posture(flags, entitlements, label=relative)
        result.append(
            {
                "architecture": architecture,
                "codesign_authority": authority,
                "codesign_authority_chain": list(authority_chain),
                "codesign_cdhash": cdhash,
                "codesign_entitlements": entitlements,
                "codesign_flags": flags,
                "codesign_identifier": identifier,
                "codesign_kind": codesign_kind,
                "codesign_requirement": requirement,
                "codesign_team_identifier": team,
                "executable_relative_path": executable_relative,
                "relative_path": relative,
            }
        )
    first = result[0]
    for record in result[1:]:
        for key in (
            "codesign_authority",
            "codesign_authority_chain",
            "codesign_entitlements",
            "codesign_flags",
            "codesign_team_identifier",
        ):
            if record[key] != first[key]:
                fail(f"cross-entrypoint {key} drift rejected")
    return result


def _gatekeeper_receipt(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != set(GATEKEEPER_KEYS):
        fail("Gatekeeper assessment keys are not exact")
    result = {key: _text(value, key) for key in GATEKEEPER_KEYS}
    if result["relative_path"] != PYTHON_APP_RELATIVE:
        fail("Gatekeeper assessment path substitution rejected")
    if not result["source"] or not result["origin"]:
        fail("Gatekeeper assessment identity is incomplete")
    return result


def parse_signing_policy(value: object) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(SIGNING_POLICY_KEYS):
        fail("owner signing policy keys are not exact")
    chain = value.get("authority_chain")
    requirements = value.get("requirements")
    expected_paths = tuple(dict.fromkeys(item[0] for item in AUTHORITY_CODE_SLICES))
    if (
        type(chain) is not list
        or not chain
        or any(type(item) is not str or not item or "\n" in item for item in chain)
    ):
        fail("owner signing authority chain is invalid")
    if type(requirements) is not dict or set(requirements) != set(expected_paths):
        fail("owner designated requirements do not bind every exact code path")
    parsed_requirements: dict[str, str] = {}
    for path in expected_paths:
        requirement = requirements.get(path)
        if type(requirement) is not str or not requirement or "\n" in requirement:
            fail(f"owner designated requirement is invalid: {path}")
        parsed_requirements[path] = requirement
    team = value.get("team_identifier")
    source = value.get("gatekeeper_source")
    origin = value.get("gatekeeper_origin")
    if any(type(item) is not str or not item or "\n" in item for item in (team, source, origin)):
        fail("owner signing team or Gatekeeper policy is invalid")
    if chain[0] != origin:
        fail("owner Gatekeeper origin does not match the authorized leaf identity")
    return {
        "authority_chain": list(chain),
        "gatekeeper_origin": origin,
        "gatekeeper_source": source,
        "requirements": parsed_requirements,
        "team_identifier": team,
    }


def require_owner_signing_policy(
    authority: dict[str, object],
    entrypoints: list[dict[str, object]],
    gatekeeper: dict[str, str],
) -> None:
    policy = parse_signing_policy(authority.get("signing_policy"))
    for entrypoint in entrypoints:
        relative = str(entrypoint["relative_path"])
        if (
            entrypoint["codesign_authority"] == "adhoc"
            or entrypoint["codesign_authority_chain"] != policy["authority_chain"]
            or entrypoint["codesign_team_identifier"] != policy["team_identifier"]
            or entrypoint["codesign_requirement"] != policy["requirements"][relative]
        ):
            fail(f"OWNER-BLOCKED: code signing identity is not owner-authorized: {relative}")
    if (
        gatekeeper.get("relative_path") != PYTHON_APP_RELATIVE
        or gatekeeper.get("source") != policy["gatekeeper_source"]
        or gatekeeper.get("origin") != policy["gatekeeper_origin"]
    ):
        fail("OWNER-BLOCKED: Python.app Gatekeeper policy is not owner-authorized")


def parse_receipt(data: bytes) -> dict[str, object]:
    if b"\0" in data:
        fail("Python runtime receipt contains a NUL")
    try:
        document = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_json_object,
            parse_constant=_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"Python runtime receipt is not ASCII: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"Python runtime receipt is not JSON: {exc}")
    root = document
    if type(root) is not dict:
        fail("Python runtime receipt must be a JSON object")
    schema = root.get("schema_version")
    if type(schema) is not int or schema != SCHEMA_VERSION:
        fail("Python runtime receipt schema_version mismatch")
    if set(root.keys()) != set(RECEIPT_KEYS):
        fail("Python runtime receipt keys are not exact")
    if canonical_bytes(root) != data:
        fail("Python runtime receipt is not canonical ASCII JSON")
    if _text(root, "contract") != CONTRACT:
        fail("Python runtime receipt contract mismatch")
    authenticated = root.get("authenticated")
    if type(authenticated) is not bool or authenticated is not True:
        fail("Python runtime receipt authenticated must be JSON true")
    if _text(root, "issuer") != ISSUER:
        fail("Python runtime receipt issuer mismatch")
    if _text(root, "platform") != PLATFORM:
        fail("Python runtime receipt platform mismatch")
    if _text(root, "python_version") != PYTHON_VERSION:
        fail("Python runtime receipt version is not the frozen Python 3.14.7 release")
    if _text(root, "implementation") != IMPLEMENTATION:
        fail("Python runtime receipt implementation mismatch")
    wheel_count = root.get("wheel_count")
    if type(wheel_count) is not int or wheel_count < 1 or wheel_count > 64:
        fail("Python runtime receipt wheel_count is invalid")
    wheels = _wheels(root.get("wheels"), wheel_count)
    runtime_path = _text(root, "runtime_path")
    executable_path = _text(root, "executable_path")
    if runtime_path != DEFAULT_RUNTIME:
        fail("Python runtime receipt runtime_path is not the owner prefix")
    if executable_path != f"{DEFAULT_RUNTIME}/{EXECUTABLE_RELATIVE}":
        fail("Python runtime receipt executable_path is unsafe")
    if _text(root, "controller") != CONTROLLER:
        fail("Python runtime receipt controller path mismatch")
    if _text(root, "provisioner") != PROVISIONER:
        fail("Python runtime receipt provisioner path mismatch")
    if _text(root, "receipt_schema") != RECEIPT_SCHEMA:
        fail("Python runtime receipt schema path mismatch")
    cdhash = _text(root, "codesign_cdhash").lower()
    if HEX_CDHASH.fullmatch(cdhash) is None:
        fail("Python runtime receipt code signature digest is invalid")
    identifier = _text(root, "codesign_identifier")
    if not identifier or "/" in identifier or "\\" in identifier:
        fail("Python runtime receipt code signature identifier is invalid")
    authority = _text(root, "codesign_authority")
    authority_chain = root.get("codesign_authority_chain")
    team = _text(root, "codesign_team_identifier")
    requirement = _text(root, "codesign_requirement")
    codesign_kind = _text(root, "codesign_kind")
    if (
        type(authority_chain) is not list
        or not authority_chain
        or any(type(value) is not str or not value or "\n" in value for value in authority_chain)
        or authority != authority_chain[0]
        or not requirement
        or "\n" in requirement
        or codesign_kind != "mach-o-thin"
    ):
        fail("Python runtime receipt external code signing identity is invalid")
    if not authority or "\n" in authority or "\n" in team:
        fail("Python runtime receipt code signature authority state is invalid")
    codesign_flags = root.get("codesign_flags")
    codesign_entitlements = _receipt_entitlements(
        root.get("codesign_entitlements"),
        label="Python runtime receipt code signature entitlements",
    )
    _validate_codesign_posture(
        codesign_flags,
        codesign_entitlements,
        label=EXECUTABLE_RELATIVE,
    )
    entrypoints = _codesign_entrypoints(root.get("codesign_entrypoints"))
    gatekeeper = _gatekeeper_receipt(root.get("gatekeeper_assessment"))
    custody_closure = validate_migration_closure(
        root.get("custody_closure"), label="receipt"
    )
    launcher_primary_sha256 = _hex_digest(root, "launcher_primary_sha256")
    if _text(root, "owner_provision_launcher") != str(OWNER_PROVISION_LAUNCHER):
        fail("Python runtime receipt owner launcher path mismatch")
    native_launcher_digests = {
        key: _hex_digest(root, key)
        for key in (
            "owner_provision_launcher_sha256",
            "owner_provision_launcher_source_sha256",
            "owner_provision_launcher_build_sha256",
            "owner_provision_launcher_compiler_sha256",
            "owner_provision_launcher_linker_sha256",
            "owner_provision_launcher_sdk_closure_sha256",
        )
    }
    native_launcher_identity: dict[str, int] = {}
    for key in ("owner_provision_launcher_device", "owner_provision_launcher_inode"):
        value = root.get(key)
        if type(value) is not int or value <= 0:
            fail(f"Python runtime receipt {key} is invalid")
        native_launcher_identity[key] = value
    primary = entrypoints[0]
    primary_fields = {
        "codesign_authority": authority,
        "codesign_authority_chain": authority_chain,
        "codesign_cdhash": cdhash,
        "codesign_entitlements": codesign_entitlements,
        "codesign_flags": codesign_flags,
        "codesign_identifier": identifier,
        "codesign_kind": codesign_kind,
        "codesign_requirement": requirement,
        "codesign_team_identifier": team,
    }
    for key, value in primary_fields.items():
        if primary[key] != value:
            fail(f"primary codesign field does not match codesign_entrypoints: {key}")
    for key in (
        "runtime_dir_identity",
        "framework_dir_identity",
        "vendor_dir_identity",
        "launcher_dir_identity",
        "executable_identity",
    ):
        identity = _text(root, key)
        if IDENTITY_RE.fullmatch(identity) is None:
            fail(f"Python runtime receipt {key} is invalid")
    package_signature = _text(root, "package_signature_status")
    if not package_signature or "\n" in package_signature:
        fail("Python runtime receipt package signature status is invalid")
    return {
        "authenticated": True,
        "codesign_authority": authority,
        "codesign_authority_chain": list(authority_chain),
        "codesign_cdhash": cdhash,
        "codesign_entitlements": codesign_entitlements,
        "codesign_entrypoints": entrypoints,
        "codesign_flags": codesign_flags,
        "codesign_identifier": identifier,
        "codesign_kind": codesign_kind,
        "codesign_requirement": requirement,
        "codesign_team_identifier": team,
        "contract": CONTRACT,
        "controller": CONTROLLER,
        "controller_sha256": _hex_digest(root, "controller_sha256"),
        "custody_closure": custody_closure,
        "executable_identity": _text(root, "executable_identity"),
        "executable_path": executable_path,
        "executable_sha256": _hex_digest(root, "executable_sha256"),
        "framework_dir_identity": _text(root, "framework_dir_identity"),
        "framework_identity_sha256": _hex_digest(root, "framework_identity_sha256"),
        "framework_tree_sha256": _hex_digest(root, "framework_tree_sha256"),
        "gatekeeper_assessment": gatekeeper,
        "implementation": IMPLEMENTATION,
        "issuer": ISSUER,
        "launcher_dir_identity": _text(root, "launcher_dir_identity"),
        "launcher_identity_sha256": _hex_digest(root, "launcher_identity_sha256"),
        "launcher_primary_sha256": launcher_primary_sha256,
        "launcher_tree_sha256": _hex_digest(root, "launcher_tree_sha256"),
        "owner_provision_launcher": str(OWNER_PROVISION_LAUNCHER),
        **native_launcher_digests,
        **native_launcher_identity,
        "package_sha256": _hex_digest(root, "package_sha256"),
        "package_signature_status": package_signature,
        "platform": PLATFORM,
        "provisioner": PROVISIONER,
        "provisioner_sha256": _hex_digest(root, "provisioner_sha256"),
        "python_version": PYTHON_VERSION,
        "receipt_schema": RECEIPT_SCHEMA,
        "receipt_schema_sha256": _hex_digest(root, "receipt_schema_sha256"),
        "runtime_dir_identity": _text(root, "runtime_dir_identity"),
        "runtime_path": runtime_path,
        "schema_version": SCHEMA_VERSION,
        "vendor_dir_identity": _text(root, "vendor_dir_identity"),
        "vendor_identity_sha256": _hex_digest(root, "vendor_identity_sha256"),
        "vendor_tree_sha256": _hex_digest(root, "vendor_tree_sha256"),
        "wheel_count": wheel_count,
        "wheels": wheels,
    }


def parse_legacy_receipt_for_migration(data: bytes) -> dict[str, object]:
    """Strictly parse schema 1 only as non-authorizing migration input."""
    if b"\0" in data:
        fail("legacy Python runtime receipt contains a NUL")
    try:
        document = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_json_object,
            parse_constant=_json_constant,
        )
    except UnicodeDecodeError as exc:
        fail(f"legacy Python runtime receipt is not ASCII: {exc}")
    except json.JSONDecodeError as exc:
        fail(f"legacy Python runtime receipt is not JSON: {exc}")
    if type(document) is not dict:
        fail("legacy Python runtime receipt must be a JSON object")
    if document.get("schema_version") != 1 or type(document.get("schema_version")) is not int:
        fail("legacy Python runtime receipt must be exact schema_version 1")
    if set(document) != set(LEGACY_RECEIPT_KEYS):
        fail("legacy Python runtime receipt keys are not exact")
    if canonical_bytes(document) != data:
        fail("legacy Python runtime receipt is not canonical ASCII JSON")
    if document.get("contract") != LEGACY_CONTRACT:
        fail("legacy Python runtime receipt contract mismatch")

    authority = _text(document, "codesign_authority")
    cdhash = _text(document, "codesign_cdhash")
    identifier = _text(document, "codesign_identifier")
    team = _text(document, "codesign_team_identifier")
    upgraded = dict(document)
    upgraded["contract"] = CONTRACT
    upgraded["schema_version"] = SCHEMA_VERSION
    upgraded["codesign_authority_chain"] = [authority]
    upgraded["codesign_entitlements"] = dict(REQUIRED_EXECUTABLE_ENTITLEMENTS)
    upgraded["codesign_flags"] = REQUIRED_CODESIGN_FLAGS
    upgraded["codesign_kind"] = "mach-o-thin"
    upgraded["codesign_requirement"] = "legacy-migration-input-only"
    upgraded["custody_closure"] = {
        key: "01" * 32 for key in MIGRATION_CLOSURE_KEYS
    }
    upgraded["gatekeeper_assessment"] = {
        "origin": authority,
        "relative_path": PYTHON_APP_RELATIVE,
        "source": "legacy-migration-input-only",
    }
    upgraded["launcher_primary_sha256"] = "02" * 32
    upgraded["owner_provision_launcher"] = str(OWNER_PROVISION_LAUNCHER)
    for key in (
        "owner_provision_launcher_sha256",
        "owner_provision_launcher_source_sha256",
        "owner_provision_launcher_build_sha256",
        "owner_provision_launcher_compiler_sha256",
        "owner_provision_launcher_linker_sha256",
        "owner_provision_launcher_sdk_closure_sha256",
    ):
        upgraded[key] = "03" * 32
    upgraded["owner_provision_launcher_device"] = 1
    upgraded["owner_provision_launcher_inode"] = 1
    upgraded["codesign_entrypoints"] = [
        {
            "architecture": architecture,
            "codesign_authority": authority,
            "codesign_authority_chain": [authority],
            "codesign_cdhash": cdhash,
            "codesign_entitlements": dict(REQUIRED_EXECUTABLE_ENTITLEMENTS),
            "codesign_flags": REQUIRED_CODESIGN_FLAGS,
            "codesign_identifier": identifier,
            "codesign_kind": codesign_kind,
            "codesign_requirement": "legacy-migration-input-only",
            "codesign_team_identifier": team,
            "executable_relative_path": executable_relative,
            "relative_path": relative,
        }
        for relative, executable_relative, architecture, codesign_kind in AUTHORITY_CODE_SLICES
    ]
    validated = parse_receipt(canonical_bytes(upgraded))
    legacy = {key: validated[key] for key in LEGACY_RECEIPT_KEYS}
    legacy["contract"] = LEGACY_CONTRACT
    legacy["schema_version"] = 1
    return legacy


def _parse_utc(value: object, *, label: str) -> datetime:
    if type(value) is not str or ISO_UTC_RE.fullmatch(value) is None:
        fail(f"{label} must be exact UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        fail(f"{label} is invalid: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        fail("migration time must be timezone-aware")
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_migration_authority(data: bytes) -> dict[str, object]:
    try:
        authority = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_json_object,
            parse_constant=_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Python receipt migration authority is malformed: {exc}")
    if type(authority) is not dict or set(authority) != set(MIGRATION_AUTHORITY_KEYS):
        fail("Python receipt migration authority keys are not exact")
    if canonical_bytes(authority) != data:
        fail("Python receipt migration authority is not canonical ASCII JSON")
    if authority.get("contract") != MIGRATION_AUTHORITY_CONTRACT:
        fail("Python receipt migration authority contract mismatch")
    if authority.get("schema_version") != 3 or type(authority.get("schema_version")) is not int:
        fail("Python receipt migration authority schema mismatch")
    for key in ("active_receipt_sha256", "authority_id", "key_id"):
        value = authority.get(key)
        if type(value) is not str or HEX64.fullmatch(value) is None or value == "0" * 64:
            fail(f"Python receipt migration authority {key} is invalid")
    if authority.get("signature_algorithm") != "external-owner-approval-v1":
        fail("Python receipt migration authority signature algorithm mismatch")
    closure = authority.get("closure")
    validate_migration_closure(closure, label="authority")
    repo_root = authority.get("authorized_repo_root")
    if (
        type(repo_root) is not str
        or not repo_root.startswith("/")
        or Path(repo_root) == Path("/")
        or "\x00" in repo_root
    ):
        fail("Python receipt migration authority repository root is invalid")
    if authority.get("owner_provision_boundary") != str(OWNER_PROVISION_BOUNDARY):
        fail("Python receipt migration authority owner boundary mismatch")
    boundary_sha = authority.get("owner_provision_boundary_sha256")
    if (
        type(boundary_sha) is not str
        or HEX64.fullmatch(boundary_sha) is None
        or boundary_sha == "0" * 64
    ):
        fail("Python receipt authority owner boundary digest is invalid")
    if authority.get("owner_provision_launcher") != str(OWNER_PROVISION_LAUNCHER):
        fail("Python receipt migration authority owner launcher mismatch")
    for key in (
        "owner_provision_launcher_sha256",
        "owner_provision_launcher_source_sha256",
        "owner_provision_launcher_build_sha256",
        "owner_provision_launcher_compiler_sha256",
        "owner_provision_launcher_linker_sha256",
        "owner_provision_launcher_sdk_closure_sha256",
        "runtime_launcher_sha256",
        "runtime_python_sha256",
    ):
        value = authority.get(key)
        if type(value) is not str or HEX64.fullmatch(value) is None or value == "0" * 64:
            fail(f"Python receipt migration authority {key} is invalid")
    for key in ("owner_provision_launcher_device", "owner_provision_launcher_inode"):
        value = authority.get(key)
        if type(value) is not int or value <= 0:
            fail(f"Python receipt migration authority {key} is invalid")
    sequence = authority.get("active_sequence")
    if type(sequence) is not int or sequence < 1 or sequence > 2**63 - 2:
        fail("Python receipt migration authority sequence is invalid")
    not_before = _parse_utc(
        authority.get("not_before_utc"), label="authority not_before_utc"
    )
    expires = _parse_utc(authority.get("expires_utc"), label="authority expires_utc")
    if expires <= not_before:
        fail("Python receipt authority validity interval is invalid")
    parse_signing_policy(authority.get("signing_policy"))
    return authority


def require_authority_current(authority: dict[str, object], now: datetime) -> None:
    if now.tzinfo is None:
        fail("trusted authority time must be timezone-aware")
    trusted_now = now.astimezone(timezone.utc)
    not_before = _parse_utc(
        authority.get("not_before_utc"), label="authority not_before_utc"
    )
    expires = _parse_utc(authority.get("expires_utc"), label="authority expires_utc")
    if trusted_now < not_before:
        fail("Python receipt authority is not yet valid")
    if trusted_now >= expires:
        fail("Python receipt authority is expired")


def validate_native_receipt_authority(
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
        "launcher_primary_sha256": authority["runtime_launcher_sha256"],
        "executable_sha256": authority["runtime_python_sha256"],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            fail(f"Python receipt and authority native binding differ: {key}")


def production_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def validate_migration_closure(value: object, *, label: str) -> dict[str, str]:
    if type(value) is not dict or set(value) != set(MIGRATION_CLOSURE_KEYS):
        fail(f"Python receipt migration {label} closure keys are not exact")
    closure: dict[str, str] = {}
    for key in MIGRATION_CLOSURE_KEYS:
        digest = value.get(key)
        if type(digest) is not str or HEX64.fullmatch(digest) is None or digest == "0" * 64:
            fail(f"Python receipt migration {label} closure digest is invalid: {key}")
        closure[key] = digest
    return closure


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
        "contract": MIGRATION_CONTRACT,
        "created_utc": created_utc,
        "current_receipt_sha256": current_receipt_sha256,
        "expected_active_sequence": authority["active_sequence"],
        "expires_utc": expires_utc,
        "next_sequence": int(authority["active_sequence"]) + 1,
    }
    return digest_bytes(canonical_bytes(intent))


def parse_migration_plan(data: bytes, *, now: datetime) -> dict[str, object]:
    try:
        plan = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_json_object,
            parse_constant=_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Python receipt migration plan is malformed: {exc}")
    if type(plan) is not dict or set(plan) != set(MIGRATION_PLAN_KEYS):
        fail("Python receipt migration plan keys are not exact")
    if canonical_bytes(plan) != data:
        fail("Python receipt migration plan is not canonical ASCII JSON")
    if (
        plan.get("contract") != MIGRATION_CONTRACT
        or plan.get("schema_version") != 2
        or type(plan.get("schema_version")) is not int
    ):
        fail("Python receipt migration plan contract mismatch")
    if plan.get("status") != OWNER_BLOCKED_MIGRATION:
        fail("Python receipt migration plan must remain OWNER-BLOCKED")

    closure = validate_migration_closure(plan.get("closure"), label="plan")

    authority = plan.get("authority")
    if type(authority) is not dict:
        fail("Python receipt migration authority is missing")
    parsed_authority = parse_migration_authority(canonical_bytes(authority))
    require_authority_current(parsed_authority, now)
    if parsed_authority["closure"] != closure:
        fail("Python receipt migration authority closure drift rejected")
    current_digest = plan.get("current_receipt_sha256")
    candidate_digest = plan.get("candidate_receipt_sha256")
    if (
        type(current_digest) is not str
        or HEX64.fullmatch(current_digest) is None
        or type(candidate_digest) is not str
        or HEX64.fullmatch(candidate_digest) is None
    ):
        fail("Python receipt migration receipt digest is invalid")
    if parsed_authority["active_receipt_sha256"] != current_digest:
        fail("Python receipt migration authority active receipt is replayed or stale")

    candidate_ascii = plan.get("candidate_receipt_ascii")
    if type(candidate_ascii) is not str:
        fail("Python receipt migration candidate bytes are missing")
    try:
        candidate_bytes = candidate_ascii.encode("ascii")
    except UnicodeEncodeError as exc:
        fail(f"Python receipt migration candidate is not ASCII: {exc}")
    if digest_bytes(candidate_bytes) != candidate_digest:
        fail("Python receipt migration candidate output drift rejected")
    parsed_candidate = parse_receipt(candidate_bytes)
    validate_native_receipt_authority(parsed_candidate, parsed_authority)

    created_text = plan.get("created_utc")
    expires_text = plan.get("expires_utc")
    created = _parse_utc(created_text, label="migration created_utc")
    expires = _parse_utc(expires_text, label="migration expires_utc")
    not_before = _parse_utc(
        parsed_authority["not_before_utc"], label="authority not_before_utc"
    )
    if created < not_before or expires <= created or expires - created > MIGRATION_VALIDITY:
        fail("Python receipt migration validity interval is invalid")
    trusted_now = now.astimezone(timezone.utc)
    if trusted_now < created or trusted_now >= expires:
        fail("Python receipt migration plan is not currently valid")

    expected_id = _migration_id(
        current_receipt_sha256=current_digest,
        candidate_receipt_sha256=candidate_digest,
        closure=closure,
        authority=parsed_authority,
        created_utc=str(created_text),
        expires_utc=str(expires_text),
    )
    migration_id = plan.get("migration_id")
    if (
        type(migration_id) is not str
        or MIGRATION_ID_RE.fullmatch(migration_id) is None
        or migration_id != expected_id
    ):
        fail("Python receipt migration identity drift rejected")
    operation = plan.get("expected_external_authority_operation")
    if type(operation) is not dict or set(operation) != set(MIGRATION_OPERATION_KEYS):
        fail("Python receipt migration external operation keys are not exact")
    expected_operation = {
        "action": "owner-authority-approve-and-atomically-publish-receipt",
        "authority_id": parsed_authority["authority_id"],
        "authority_key_id": parsed_authority["key_id"],
        "authority_path": str(MIGRATION_AUTHORITY_PATH),
        "candidate_receipt_sha256": candidate_digest,
        "current_receipt_sha256": current_digest,
        "expected_active_sequence": parsed_authority["active_sequence"],
        "migration_id": expected_id,
        "next_sequence": int(parsed_authority["active_sequence"]) + 1,
        "receipt_path": DEFAULT_RECEIPT,
    }
    if operation != expected_operation:
        fail("Python receipt migration external operation drift rejected")
    return plan


def receipt_document(values: dict[str, object]) -> dict[str, object]:
    document = {key: values[key] for key in RECEIPT_KEYS}
    parse_receipt(canonical_bytes(document))
    return document


def tools_dir() -> Path:
    path = Path(__file__)
    if not path.is_absolute():
        path = Path.cwd() / path
    if path.name != "macos_release_python_runtime_receipt.py" or path.is_symlink():
        fail("malicious or substituted Python receipt schema rejected")
    return path.parent


def repo_file_uids() -> set[int]:
    return {0, os.getuid()}


def snapshot_controllers() -> dict[str, str]:
    directory = tools_dir()
    mapping = {
        "controller": directory / "release_python_archive_custody.sh",
        "provisioner": directory / "provision_macos_release_python_runtime.sh",
        "receipt_schema": directory / "macos_release_python_runtime_receipt.py",
    }
    digests: dict[str, str] = {}
    allowed = repo_file_uids()
    for key, path in mapping.items():
        info = path.lstat()
        if info.st_uid not in allowed:
            fail(f"untrusted path owner rejected: {path}")
        require_regular_file(
            path,
            allowed_uids=allowed,
            allow_sticky_tmp=True,
            forbid_owner_write=False,
            leaf_uid=info.st_uid,
        )
        if path.stat().st_size > MAX_CONTROLLER:
            fail(f"{key} exceeds the size limit")
        digests[f"{key}_sha256"] = digest_file(path)
    return digests


def owner_provision_action(manifest: Path) -> str:
    del manifest
    return OWNER_PROVISION_ACTION


def locate_receipt_path() -> Path:
    raw = os.environ.get(RECEIPT_ENV, "")
    if type(raw) is not str:
        fail(OWNER_BLOCKED_UNAVAILABLE)
    if raw:
        path = Path(raw)
    else:
        path = Path(DEFAULT_RECEIPT)
    if not path.is_absolute():
        fail(OWNER_BLOCKED_UNAVAILABLE)
    return path


def require_external_receipt(
    repo: Path,
    *,
    required_uid: int,
    pin_manifest: Path | None = None,
) -> tuple[Path, bytes]:
    path = locate_receipt_path()
    if _path_is_within(path, repo):
        fail(OWNER_BLOCKED_ADJACENT)
    try:
        info = path.lstat()
    except FileNotFoundError:
        pin = pin_manifest if pin_manifest is not None else repo / "tools" / "toolchain-pins.json"
        fail(
            f"{OWNER_BLOCKED_UNAVAILABLE}; {owner_provision_action(pin)}"
        )
    if stat.S_ISLNK(info.st_mode):
        fail("Python runtime receipt symbolic link rejected")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("Python runtime receipt must be one regular non-hardlinked file")
    if stat.S_IMODE(info.st_mode) != 0o444:
        fail(OWNER_BLOCKED_WRITABLE)
    if os.getuid() != 0 and info.st_uid == os.getuid():
        fail(OWNER_BLOCKED_SELF_AUTH)
    if info.st_uid != required_uid:
        fail("wrong owner")
    require_path_components(
        path,
        allowed_uids={required_uid},
        allow_sticky_tmp=False,
        leaf_must_match=required_uid,
    )
    fd = os.open(path, os.O_RDONLY | _cloexec() | _nofollow())
    try:
        opened = os.fstat(fd)
        if _stat_identity(opened) != _stat_identity(info):
            fail("Python runtime receipt was replaced before it was bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_RECEIPT:
                fail("Python runtime receipt exceeds the size limit")
            chunks.append(block)
        after = os.fstat(fd)
        if _stat_identity(after) != _stat_identity(opened):
            fail("Python runtime receipt changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    if _stat_identity(latest) != _stat_identity(info):
        fail("Python runtime receipt was replaced after it was opened")
    data = b"".join(chunks)
    if not data:
        fail("Python runtime receipt snapshot is empty")
    return path, data


def match_receipt_to_runtime(
    receipt: dict[str, object],
    *,
    runtime: Path,
    framework: dict[str, str],
    vendor: dict[str, str],
    launcher: dict[str, str],
    executable: Path,
    controllers: dict[str, str],
    package_sha256: str,
    wheels: list[dict[str, str]],
    codesign: dict[str, object],
    package_signature_status: str,
    codesign_entrypoints: list[dict[str, object]] | None = None,
    custody_closure: dict[str, str] | None = None,
    gatekeeper: dict[str, str] | None = None,
) -> None:
    if receipt["runtime_path"] != str(runtime):
        fail("wrong archive/tree")
    live_runtime = runtime.lstat()
    if dir_identity(live_runtime) != receipt["runtime_dir_identity"]:
        fail("changed inode")
    if framework["content"] != receipt["framework_tree_sha256"]:
        fail("wrong archive/tree")
    if framework["identity"] != receipt["framework_identity_sha256"]:
        fail("changed inode")
    if framework["dir_identity"] != receipt["framework_dir_identity"]:
        fail("changed inode")
    if vendor["content"] != receipt["vendor_tree_sha256"]:
        fail("wrong archive/tree")
    if vendor["identity"] != receipt["vendor_identity_sha256"]:
        fail("changed inode")
    if vendor["dir_identity"] != receipt["vendor_dir_identity"]:
        fail("changed inode")
    if launcher["content"] != receipt["launcher_tree_sha256"]:
        fail("wrong archive/tree")
    if launcher["identity"] != receipt["launcher_identity_sha256"]:
        fail("changed inode")
    if launcher["dir_identity"] != receipt["launcher_dir_identity"]:
        fail("changed inode")
    if "launcher_primary_sha256" in receipt:
        launcher_primary = runtime / "launcher" / "python3.14"
        if digest_file(launcher_primary) != receipt["launcher_primary_sha256"]:
            fail("wrong archive/tree")
    exec_info = executable.lstat()
    if file_identity(exec_info) != receipt["executable_identity"]:
        fail("changed inode")
    if digest_file(executable) != receipt["executable_sha256"]:
        fail("wrong archive/tree")
    if str(executable) != receipt["executable_path"]:
        fail("wrong archive/tree")
    if receipt["package_sha256"] != package_sha256:
        fail("wrong archive/tree")
    if receipt["wheels"] != wheels:
        fail("wrong archive/tree")
    if receipt["wheel_count"] != len(wheels):
        fail("wrong archive/tree")
    for key, digest in controllers.items():
        if receipt[key] != digest:
            fail("stale receipt")
    for key, value in codesign.items():
        if receipt[key] != value:
            fail("stale receipt")
    if "codesign_entrypoints" in receipt:
        if codesign_entrypoints is None:
            fail("stale receipt")
        if receipt["codesign_entrypoints"] != codesign_entrypoints:
            fail("cross-entrypoint code signing posture drift rejected")
    if "custody_closure" in receipt and receipt["custody_closure"] != custody_closure:
        fail("schema-v3 custody closure drift rejected")
    if "gatekeeper_assessment" in receipt and receipt["gatekeeper_assessment"] != gatekeeper:
        fail("Python.app Gatekeeper policy drift rejected")
    if not package_signature_status:
        fail("stale receipt")
    if receipt.get("package_signature_status") != package_signature_status:
        fail("stale receipt")


def pin_wheels(manifest: dict[str, object]) -> tuple[str, list[dict[str, str]]]:
    try:
        python = manifest["tools"]["python"]
        custody = python["archive_custody"][PLATFORM]
        package = custody["package"]
        package_sha = package["sha256"]
        wheel_count = custody["wheel_count"]
        wheels_root = custody["wheels"]
    except (KeyError, TypeError) as exc:
        fail(f"reviewed toolchain pin manifest is invalid: {exc}")
    if type(package_sha) is not str or HEX64.fullmatch(package_sha) is None:
        fail("invalid package SHA-256 pin")
    if type(wheel_count) is not int or wheel_count < 1 or wheel_count > 64:
        fail("wheel_count must be between 1 and 64")
    if type(wheels_root) is not dict:
        fail("wheels pin must be a JSON object")
    wheels: list[dict[str, str]] = []
    for index in range(wheel_count):
        record = wheels_root.get(str(index))
        if type(record) is not dict:
            fail(f"missing wheel path pin {index}")
        path = record.get("path")
        digest = record.get("sha256")
        if type(path) is not str or type(digest) is not str:
            fail(f"missing wheel SHA-256 pin {index}")
        name = Path(path).name
        wheels.append({"name": name, "sha256": digest})
    return package_sha, wheels


def load_pin_manifest(path: Path) -> dict[str, object]:
    allowed = repo_file_uids()
    info = path.lstat()
    if info.st_uid not in allowed:
        fail(f"untrusted path owner rejected: {path}")
    require_regular_file(
        path,
        allowed_uids=allowed,
        allow_sticky_tmp=True,
        forbid_owner_write=False,
        leaf_uid=info.st_uid,
    )
    fd = os.open(path, os.O_RDONLY | _cloexec() | _nofollow())
    try:
        opened = os.fstat(fd)
        if _stat_identity(opened) != _stat_identity(info):
            fail("pin manifest was replaced before open")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_CONTROLLER:
                fail("pin manifest exceeds the size limit")
            chunks.append(block)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if not (
        _stat_identity(opened)
        == _stat_identity(after)
        == _stat_identity(path.lstat())
    ):
        fail("pin manifest changed while held")
    return parse_pin_manifest_bytes(b"".join(chunks))


def parse_pin_manifest_bytes(data: bytes) -> dict[str, object]:
    try:
        document = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_json_object,
            parse_constant=_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"pin manifest is not JSON: {exc}")
    if type(document) is not dict:
        fail("pin manifest must be a JSON object")
    return document


def _authenticate_held(
    repo: Path,
    manifest: Path,
    held: HeldRepoClosure,
    *,
    required_uid: int = 0,
) -> dict[str, str]:
    if sys.platform != "darwin":
        fail("macOS is required")
    if os.geteuid() == 0:
        fail(OWNER_BLOCKED_ROOT_EXEC)
    if required_uid != 0:
        fail("production Python runtime owner must be root")
    closure = held.closure()
    executed_source = os.environ.get(EXECUTED_SOURCE_SHA256_ENV, "")
    if executed_source != closure["custody_controller_sha256"]:
        fail("OWNER-BLOCKED: normal authenticate did not execute held custody-controller bytes")
    pin = parse_pin_manifest_bytes(held.data["pin_manifest_sha256"])
    package_sha, wheels = pin_wheels(pin)
    _receipt_path, data = require_external_receipt(
        repo,
        required_uid=required_uid,
        pin_manifest=manifest,
    )
    try:
        receipt = parse_receipt(data)
    except Refused as exc:
        fail(
            f"{OWNER_BLOCKED_UNAVAILABLE}: {exc}; "
            f"{owner_provision_action(manifest)}"
        )
    authority = _read_migration_authority()
    require_authority_current(authority, production_utc_now())
    require_authority_for_repo(authority, repo, closure)
    validate_native_receipt_authority(receipt, authority)
    if authority["active_receipt_sha256"] != digest_bytes(data):
        fail("Python receipt authority active receipt is replayed or stale")
    require_authority_bound_custody_metadata(
        repo,
        closure,
        data=held.data["custody_metadata_sha256"],
    )
    if receipt["custody_closure"] != closure:
        fail("OWNER-BLOCKED: schema-v3 receipt custody closure is stale or substituted")
    controllers = {
        "controller_sha256": closure["wrapper_sha256"],
        "provisioner_sha256": closure["provisioner_sha256"],
        "receipt_schema_sha256": closure["custody_controller_sha256"],
    }
    runtime = Path(str(receipt["runtime_path"]))
    require_path_components(
        runtime,
        allowed_uids={required_uid},
        allow_sticky_tmp=False,
        leaf_must_match=required_uid,
    )
    runtime_info = runtime.lstat()
    if runtime.is_symlink() or not stat.S_ISDIR(runtime_info.st_mode):
        fail("Python runtime must be one root-owned directory")
    if runtime_info.st_uid != required_uid:
        fail("wrong owner")
    framework = runtime / "Python.framework"
    vendor = runtime / "vendor"
    launcher = runtime / "launcher"
    executable = Path(str(receipt["executable_path"]))
    framework_bind = bind_tree(
        framework, required_uid=required_uid, allow_symlinks=True,
        require_system_immutable=True,
    )
    vendor_bind = bind_tree(
        vendor, required_uid=required_uid, allow_symlinks=False,
        require_system_immutable=True,
    )
    launcher_bind = bind_tree(
        launcher, required_uid=required_uid, allow_symlinks=False,
        require_system_immutable=True,
    )
    require_regular_file(
        executable,
        allowed_uids={required_uid},
        allow_sticky_tmp=False,
        forbid_owner_write=True,
        leaf_uid=required_uid,
    )
    codesign_entrypoints = codesign_entrypoint_records(runtime)
    gatekeeper = gatekeeper_assessment(
        runtime,
        expected_origin=str(codesign_entrypoints[0]["codesign_authority"]),
    )
    require_owner_signing_policy(authority, codesign_entrypoints, gatekeeper)
    codesign = {
        key: codesign_entrypoints[0][key]
        for key in CODESIGN_ENTRYPOINT_KEYS
        if key not in {"architecture", "executable_relative_path", "relative_path"}
    }
    match_receipt_to_runtime(
        receipt,
        runtime=runtime,
        framework=framework_bind,
        vendor=vendor_bind,
        launcher=launcher_bind,
        executable=executable,
        controllers=controllers,
        package_sha256=package_sha,
        wheels=wheels,
        codesign=codesign,
        package_signature_status=str(receipt["package_signature_status"]),
        codesign_entrypoints=codesign_entrypoints,
        custody_closure=closure,
        gatekeeper=gatekeeper,
    )
    prove_not_user_mutable(
        [
            runtime,
            framework,
            vendor,
            launcher,
            executable,
            *(runtime / relative for relative in AUTHORITY_ENTRYPOINTS[1:]),
            launcher / "python3.14",
            launcher / "python3",
        ]
    )
    flags = int(getattr(runtime_info, "st_flags", 0))
    if flags & UF_IMMUTABLE and not (flags & SF_IMMUTABLE):
        fail("UF_IMMUTABLE is insufficient")
    if not (flags & SF_IMMUTABLE):
        fail("SF_IMMUTABLE is required")
    held.assert_current()
    return {
        "RUNTIME": str(runtime),
        "RUNTIME_ID": dir_identity(runtime_info),
        "BIN": str(executable),
        "BIN_SHA256": str(receipt["executable_sha256"]),
        "VENDOR": str(vendor),
        "VENDOR_SHA256": vendor_bind["content"],
        "VENDOR_ID": vendor_bind["identity"],
        "VENDOR_DIR_ID": vendor_bind["dir_identity"],
        "LAUNCHER": str(launcher / "python3.14"),
        "LAUNCHER_SHA256": launcher_bind["content"],
        "LAUNCHER_ID": launcher_bind["identity"],
        "LAUNCHER_DIR_ID": launcher_bind["dir_identity"],
        "FRAMEWORK": str(framework),
        "FRAMEWORK_SHA256": framework_bind["content"],
        "FRAMEWORK_ID": framework_bind["identity"],
        "FRAMEWORK_DIR_ID": framework_bind["dir_identity"],
        "OWNER_ACTION": owner_provision_action(manifest),
    }


def authenticate(
    repo: Path,
    manifest: Path,
    *,
    required_uid: int = 0,
) -> dict[str, str]:
    with hold_repo_closure(repo, manifest) as held:
        return _authenticate_held(
            repo,
            manifest,
            held,
            required_uid=required_uid,
        )


def measure_runtime_support_closure(
    runtime: Path,
    *,
    required_uid: int,
) -> dict[str, object]:
    if runtime.is_symlink() or not runtime.is_dir():
        fail("Python runtime must be one directory")
    runtime_info = runtime.lstat()
    if runtime_info.st_uid != required_uid:
        fail("Python runtime root has the wrong owner")
    if stat.S_IMODE(runtime_info.st_mode) & 0o222:
        fail("Python runtime root is writable")
    if required_uid == 0:
        require_path_components(
            runtime,
            allowed_uids={0},
            allow_sticky_tmp=False,
            leaf_must_match=0,
        )
        runtime_flags = int(getattr(runtime_info, "st_flags", 0))
        if runtime_flags & UF_IMMUTABLE and not (runtime_flags & SF_IMMUTABLE):
            fail("UF_IMMUTABLE is insufficient for Python runtime root")
        if not (runtime_flags & SF_IMMUTABLE):
            fail("SF_IMMUTABLE is required for Python runtime root")
    framework = runtime / "Python.framework"
    vendor = runtime / "vendor"
    launcher = runtime / "launcher"
    executable = runtime / EXECUTABLE_RELATIVE
    immutable = required_uid == 0
    framework_bind = bind_tree(
        framework, required_uid=required_uid, allow_symlinks=True,
        require_system_immutable=immutable,
    )
    vendor_bind = bind_tree(
        vendor, required_uid=required_uid, allow_symlinks=False,
        require_system_immutable=immutable,
    )
    launcher_bind = bind_tree(
        launcher, required_uid=required_uid, allow_symlinks=False,
        require_system_immutable=immutable,
    )
    require_regular_file(
        executable,
        allowed_uids={required_uid} if required_uid == 0 else repo_file_uids(),
        allow_sticky_tmp=required_uid != 0,
        forbid_owner_write=True,
        leaf_uid=required_uid,
    )
    launcher_primary = launcher / "python3.14"
    require_regular_file(
        launcher_primary,
        allowed_uids={required_uid} if required_uid == 0 else repo_file_uids(),
        allow_sticky_tmp=required_uid != 0,
        forbid_owner_write=True,
        leaf_uid=required_uid,
    )
    return {
        "runtime_path": str(runtime),
        "runtime_dir_identity": dir_identity(runtime_info),
        "framework": framework_bind,
        "vendor": vendor_bind,
        "launcher": launcher_bind,
        "launcher_primary_sha256": digest_file(launcher_primary),
        "executable_path": str(executable),
        "executable_sha256": digest_file(executable),
        "executable_identity": file_identity(executable.lstat()),
    }


def measure_runtime(runtime: Path, *, required_uid: int) -> dict[str, object]:
    measured = measure_runtime_support_closure(runtime, required_uid=required_uid)
    codesign_entrypoints = codesign_entrypoint_records(runtime)
    codesign = {
        key: codesign_entrypoints[0][key]
        for key in CODESIGN_ENTRYPOINT_KEYS
        if key not in {"architecture", "executable_relative_path", "relative_path"}
    }
    gatekeeper = gatekeeper_assessment(
        runtime,
        expected_origin=str(codesign["codesign_authority"]),
    )
    return {
        **measured,
        "codesign": codesign,
        "codesign_entrypoints": codesign_entrypoints,
        "gatekeeper_assessment": gatekeeper,
    }


def build_receipt(
    *,
    measured: dict[str, object],
    package_sha256: str,
    wheels: list[dict[str, str]],
    package_signature_status: str,
    controllers: dict[str, str],
    custody_closure: dict[str, str],
    authority: dict[str, object],
) -> dict[str, object]:
    authority = parse_migration_authority(canonical_bytes(authority))
    framework = measured["framework"]
    vendor = measured["vendor"]
    launcher = measured["launcher"]
    codesign = measured["codesign"]
    codesign_entrypoints = measured["codesign_entrypoints"]
    gatekeeper = measured["gatekeeper_assessment"]
    if type(framework) is not dict or type(vendor) is not dict or type(launcher) is not dict:
        fail("incomplete runtime measurement")
    if type(codesign) is not dict:
        fail("incomplete code signature measurement")
    if type(codesign_entrypoints) is not list:
        fail("incomplete code signature entrypoint measurement")
    document = {
        "authenticated": True,
        "codesign_authority": codesign["codesign_authority"],
        "codesign_authority_chain": codesign["codesign_authority_chain"],
        "codesign_cdhash": codesign["codesign_cdhash"],
        "codesign_entitlements": codesign["codesign_entitlements"],
        "codesign_entrypoints": codesign_entrypoints,
        "codesign_flags": codesign["codesign_flags"],
        "codesign_identifier": codesign["codesign_identifier"],
        "codesign_kind": codesign["codesign_kind"],
        "codesign_requirement": codesign["codesign_requirement"],
        "codesign_team_identifier": codesign["codesign_team_identifier"],
        "contract": CONTRACT,
        "controller": CONTROLLER,
        "controller_sha256": controllers["controller_sha256"],
        "custody_closure": custody_closure,
        "executable_identity": measured["executable_identity"],
        "executable_path": measured["executable_path"],
        "executable_sha256": measured["executable_sha256"],
        "framework_dir_identity": framework["dir_identity"],
        "framework_identity_sha256": framework["identity"],
        "framework_tree_sha256": framework["content"],
        "gatekeeper_assessment": gatekeeper,
        "implementation": IMPLEMENTATION,
        "issuer": ISSUER,
        "launcher_dir_identity": launcher["dir_identity"],
        "launcher_identity_sha256": launcher["identity"],
        "launcher_primary_sha256": measured["launcher_primary_sha256"],
        "launcher_tree_sha256": launcher["content"],
        "owner_provision_launcher": authority["owner_provision_launcher"],
        "owner_provision_launcher_build_sha256": authority[
            "owner_provision_launcher_build_sha256"
        ],
        "owner_provision_launcher_compiler_sha256": authority[
            "owner_provision_launcher_compiler_sha256"
        ],
        "owner_provision_launcher_device": authority[
            "owner_provision_launcher_device"
        ],
        "owner_provision_launcher_inode": authority[
            "owner_provision_launcher_inode"
        ],
        "owner_provision_launcher_linker_sha256": authority[
            "owner_provision_launcher_linker_sha256"
        ],
        "owner_provision_launcher_sdk_closure_sha256": authority[
            "owner_provision_launcher_sdk_closure_sha256"
        ],
        "owner_provision_launcher_sha256": authority[
            "owner_provision_launcher_sha256"
        ],
        "owner_provision_launcher_source_sha256": authority[
            "owner_provision_launcher_source_sha256"
        ],
        "package_sha256": package_sha256,
        "package_signature_status": package_signature_status,
        "platform": PLATFORM,
        "provisioner": PROVISIONER,
        "provisioner_sha256": controllers["provisioner_sha256"],
        "python_version": PYTHON_VERSION,
        "receipt_schema": RECEIPT_SCHEMA,
        "receipt_schema_sha256": controllers["receipt_schema_sha256"],
        "runtime_dir_identity": measured["runtime_dir_identity"],
        "runtime_path": measured["runtime_path"],
        "schema_version": SCHEMA_VERSION,
        "vendor_dir_identity": vendor["dir_identity"],
        "vendor_identity_sha256": vendor["identity"],
        "vendor_tree_sha256": vendor["content"],
        "wheel_count": len(wheels),
        "wheels": wheels,
    }
    receipt = receipt_document(document)
    validate_native_receipt_authority(receipt, authority)
    return receipt


def write_receipt(path: Path, document: dict[str, object]) -> None:
    del path, document
    fail(
        "OWNER-BLOCKED: repository code cannot publish or reissue the runtime receipt; "
        f"{OWNER_PROVISION_ACTION}"
    )


def sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | _cloexec() | _nofollow()
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            fail(f"directory sync target is not a directory: {path}")
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(path: Path) -> None:
    root = path.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        fail(f"tree sync target is not a real directory: {path}")
    directories: list[Path] = []
    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        for name in dirnames:
            child = current_path / name
            if child.is_symlink():
                continue
            if not child.is_dir():
                fail(f"tree sync encountered a non-directory entry: {child}")
        for name in filenames:
            child = current_path / name
            if child.is_symlink():
                continue
            fd = os.open(child, os.O_RDONLY | _cloexec() | _nofollow())
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    fail(f"tree sync encountered a non-regular file: {child}")
                os.fsync(fd)
            finally:
                os.close(fd)
    for directory in reversed(directories):
        sync_directory(directory)


def inspect_existing(repo: Path, manifest: Path) -> str:
    if not Path(DEFAULT_RUNTIME).is_dir() and not Path(DEFAULT_RECEIPT).is_file():
        return "UNAVAILABLE"
    try:
        authenticate(repo, manifest, required_uid=0)
    except Refused as exc:
        message = str(exc)
        if OWNER_BLOCKED_UNAVAILABLE in message:
            return "UNAVAILABLE"
        return f"MISMATCH:{message}"
    return "MATCH"


def snapshot_migration_closure(repo: Path, manifest: Path) -> dict[str, str]:
    with hold_repo_closure(repo, manifest) as held:
        return held.closure()


def _held_descriptor_digest(environment_name: str, *, label: str) -> str:
    raw = os.environ.get(environment_name, "")
    if type(raw) is not str or not raw.isdigit():
        fail(f"OWNER-BLOCKED: migration requires a held {label} descriptor")
    fd = int(raw)
    if fd < 3:
        fail(f"OWNER-BLOCKED: migration {label} descriptor is unsafe")
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_CONTROLLER
        ):
            fail(f"OWNER-BLOCKED: migration held {label} is not one safe file")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_CONTROLLER:
                fail(f"OWNER-BLOCKED: migration held {label} exceeds the size limit")
            digest.update(block)
        after = os.fstat(fd)
    except OSError as exc:
        fail(f"OWNER-BLOCKED: migration held {label} descriptor failed: {exc}")
    if _stat_identity(before) != _stat_identity(after) or total != before.st_size:
        fail(f"OWNER-BLOCKED: migration held {label} changed while read")
    return digest.hexdigest()


def require_held_migration_sources(closure: dict[str, str]) -> None:
    held_source = _held_descriptor_digest(
        MIGRATION_SOURCE_FD_ENV,
        label="receipt-schema source",
    )
    held_test = _held_descriptor_digest(
        MIGRATION_TEST_FD_ENV,
        label="receipt-schema test",
    )
    if held_source != closure["custody_controller_sha256"]:
        fail("OWNER-BLOCKED: held receipt-schema source/path swap rejected")
    if held_test != closure["receipt_test_sha256"]:
        fail("OWNER-BLOCKED: held receipt-schema test/path swap rejected")
    executed_source = os.environ.get(MIGRATION_EXECUTED_SOURCE_SHA256_ENV, "")
    if executed_source != held_source:
        fail("OWNER-BLOCKED: migration planner did not execute authenticated held source")


def require_authority_bound_custody_metadata(
    repo: Path,
    closure: dict[str, str],
    *,
    data: bytes | None = None,
) -> None:
    path = repo / CUSTODY_METADATA
    if data is None:
        with hold_repo_closure(repo, repo / PIN_MANIFEST) as held:
            data = held.data["custody_metadata_sha256"]
    try:
        metadata = json.loads(data, object_pairs_hook=_json_object, parse_constant=_json_constant)
    except json.JSONDecodeError as exc:
        fail(f"Python custody metadata is malformed: {exc}")
    if type(metadata) is not dict:
        fail("Python custody metadata must be a JSON object")
    expected = {
        "contract": CONTRACT,
        "migration_authority_path": str(MIGRATION_AUTHORITY_PATH),
        "owner_action": "use-fixed-external-owner-provisioning-boundary",
        "owner_provision_boundary": str(OWNER_PROVISION_BOUNDARY),
        "platform": PLATFORM,
        "python_version": PYTHON_VERSION,
        "receipt_path": DEFAULT_RECEIPT,
        "runtime_path": DEFAULT_RUNTIME,
        "schema_version": 3,
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            fail(f"Python custody metadata mismatch: {key}")
    bindings = {
        "archive_test": (ARCHIVE_TEST, "archive_test_sha256"),
        "android_custody": (FIN_RELEASE_GATE_SOURCE_CLOSURE[0], "android_custody_sha256"),
        "browser_custody": (FIN_RELEASE_GATE_SOURCE_CLOSURE[3], "browser_custody_sha256"),
        "custody_controller": (RECEIPT_SCHEMA, "custody_controller_sha256"),
        "fin_g00_test": (FIN_G00_TEST, "fin_g00_test_sha256"),
        "fin_release_gate": (FIN_RELEASE_GATE, "fin_release_gate_sha256"),
        "go_custody": (FIN_RELEASE_GATE_SOURCE_CLOSURE[4], "go_custody_sha256"),
        "gcp_proof_collector": (GCP_PROOF_COLLECTOR, "gcp_proof_collector_sha256"),
        "gcp_proof_live_probe": (GCP_PROOF_LIVE_PROBE, "gcp_proof_live_probe_sha256"),
        "node_custody": (FIN_RELEASE_GATE_SOURCE_CLOSURE[2], "node_custody_sha256"),
        "openssl_custody": (FIN_RELEASE_GATE_SOURCE_CLOSURE[1], "openssl_custody_sha256"),
        "pin_manifest": (PIN_MANIFEST, "pin_manifest_sha256"),
        "provision_test": (PROVISION_TEST, "provision_test_sha256"),
        "provisioner": (PROVISIONER, "provisioner_sha256"),
        "receipt_test": (RECEIPT_TEST, "receipt_test_sha256"),
        "wrapper": (CONTROLLER, "wrapper_sha256"),
    }
    for key, (relative, closure_key) in bindings.items():
        if metadata.get(key) != relative or metadata.get(f"{key}_sha256") != closure[closure_key]:
            fail(f"Python custody metadata authority binding mismatch: {key}")
    if digest_bytes(data) != closure["custody_metadata_sha256"]:
        fail("Python custody metadata authority digest mismatch")


def _read_migration_authority() -> dict[str, object]:
    path = MIGRATION_AUTHORITY_PATH
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{OWNER_BLOCKED_MIGRATION}; authority is absent at {path}")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o444
        or not int(getattr(info, "st_flags", 0)) & SF_IMMUTABLE
    ):
        fail(f"{OWNER_BLOCKED_MIGRATION}; authority custody mismatch")
    require_path_components(
        path,
        allowed_uids={0},
        allow_sticky_tmp=False,
        leaf_must_match=0,
    )
    fd = os.open(path, os.O_RDONLY | _cloexec() | _nofollow())
    try:
        opened = os.fstat(fd)
        if _stat_identity(opened) != _stat_identity(info):
            fail("Python receipt migration authority was replaced before open")
        data = bytearray()
        while True:
            block = os.read(fd, 64 * 1024)
            if not block:
                break
            data.extend(block)
            if len(data) > MAX_RECEIPT:
                fail("Python receipt migration authority exceeds the size limit")
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if not (_stat_identity(opened) == _stat_identity(after) == _stat_identity(path.lstat())):
        fail("Python receipt migration authority changed while read")
    authority = parse_migration_authority(bytes(data))
    boundary_digest = require_fixed_owner_boundary()
    if authority["owner_provision_boundary_sha256"] != boundary_digest:
        fail(f"{OWNER_BLOCKED_MIGRATION}; fixed owner boundary implementation drift")
    return authority


def require_fixed_owner_boundary() -> str:
    path = OWNER_PROVISION_BOUNDARY
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{OWNER_BLOCKED_MIGRATION}; fixed owner-provisioning boundary is absent")
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o555
        or not int(getattr(info, "st_flags", 0)) & SF_IMMUTABLE
    ):
        fail(f"{OWNER_BLOCKED_MIGRATION}; fixed owner-provisioning boundary custody mismatch")
    require_path_components(
        path,
        allowed_uids={0},
        allow_sticky_tmp=False,
        leaf_must_match=0,
    )
    return digest_file(path)


def require_authority_for_repo(
    authority: dict[str, object],
    repo: Path,
    closure: dict[str, str],
) -> None:
    expected_repo = tools_dir().parent
    if repo != expected_repo or authority.get("authorized_repo_root") != str(expected_repo):
        fail("OWNER-BLOCKED: copied or replacement repository is not owner-authorized")
    if authority.get("closure") != closure:
        fail("OWNER-BLOCKED: migration authority hash drift rejected")


def require_authenticated_planner_interpreter(measured: dict[str, object]) -> None:
    expected = Path(DEFAULT_RUNTIME) / EXECUTABLE_RELATIVE
    expected_launcher = Path(DEFAULT_RUNTIME) / "launcher" / "python3.14"
    reported = Path(sys.executable)
    actual_raw = os.environ.get("WINS_RELEASE_CHILD_PYTHON", "")
    flags = sys.flags
    if (
        sys.platform != "darwin"
        or os.geteuid() == 0
        or reported != expected_launcher
        or reported.is_symlink()
        or not reported.is_file()
        or actual_raw != str(expected)
        or expected.is_symlink()
        or not expected.is_file()
        or flags.isolated != 1
        or flags.no_site != 1
        or getattr(flags, "safe_path", False) is not True
    ):
        fail("OWNER-BLOCKED: migration planner requires authenticated ReleasePython -I -S")
    if (
        measured.get("executable_path") != str(expected)
        or measured.get("executable_sha256") != digest_file(expected)
        or measured.get("executable_identity") != file_identity(expected.lstat())
    ):
        fail("OWNER-BLOCKED: migration planner interpreter is substituted")


def build_migration_plan(
    *,
    current_receipt_data: bytes,
    candidate: dict[str, object],
    closure: dict[str, str],
    authority: dict[str, object],
    now: datetime,
) -> dict[str, object]:
    closure = validate_migration_closure(closure, label="candidate")
    parsed_authority = parse_migration_authority(canonical_bytes(authority))
    require_authority_current(parsed_authority, now)
    if parsed_authority["closure"] != closure:
        fail("Python receipt migration authority closure drift rejected")
    current_digest = digest_bytes(current_receipt_data)
    if parsed_authority["active_receipt_sha256"] != current_digest:
        fail("Python receipt migration authority active receipt is replayed or stale")
    candidate_bytes = canonical_bytes(receipt_document(candidate))
    candidate_digest = digest_bytes(candidate_bytes)
    created = now.astimezone(timezone.utc).replace(microsecond=0)
    created_text = _utc_text(created)
    authority_expires = _parse_utc(
        parsed_authority["expires_utc"], label="authority expires_utc"
    )
    expires_text = _utc_text(min(created + MIGRATION_VALIDITY, authority_expires))
    not_before = _parse_utc(
        parsed_authority["not_before_utc"], label="authority not_before_utc"
    )
    if created < not_before:
        fail("Python receipt migration authority is not active")
    migration_id = _migration_id(
        current_receipt_sha256=current_digest,
        candidate_receipt_sha256=candidate_digest,
        closure=closure,
        authority=parsed_authority,
        created_utc=created_text,
        expires_utc=expires_text,
    )
    operation = {
        "action": "owner-authority-approve-and-atomically-publish-receipt",
        "authority_id": parsed_authority["authority_id"],
        "authority_key_id": parsed_authority["key_id"],
        "authority_path": str(MIGRATION_AUTHORITY_PATH),
        "candidate_receipt_sha256": candidate_digest,
        "current_receipt_sha256": current_digest,
        "expected_active_sequence": parsed_authority["active_sequence"],
        "migration_id": migration_id,
        "next_sequence": int(parsed_authority["active_sequence"]) + 1,
        "receipt_path": DEFAULT_RECEIPT,
    }
    plan: dict[str, object] = {
        "authority": parsed_authority,
        "candidate_receipt_ascii": candidate_bytes.decode("ascii"),
        "candidate_receipt_sha256": candidate_digest,
        "closure": closure,
        "contract": MIGRATION_CONTRACT,
        "created_utc": created_text,
        "current_receipt_sha256": current_digest,
        "expected_external_authority_operation": operation,
        "expires_utc": expires_text,
        "migration_id": migration_id,
        "schema_version": 2,
        "status": OWNER_BLOCKED_MIGRATION,
    }
    return parse_migration_plan(canonical_bytes(plan), now=created)


def require_legacy_migration_input(
    current_receipt_data: bytes,
    authority: dict[str, object],
) -> None:
    active_digest = authority.get("active_receipt_sha256")
    current_digest = digest_bytes(current_receipt_data)
    if (
        type(active_digest) is not str
        or HEX64.fullmatch(active_digest) is None
        or not hmac.compare_digest(active_digest, current_digest)
    ):
        fail("Python receipt migration authority active receipt is replayed or stale")


def legacy_package_signature_status(
    legacy: dict[str, object],
    current_package_sha256: str,
) -> str:
    if legacy.get("package_sha256") != current_package_sha256:
        fail("legacy receipt package differs from the replacement package")
    flattened = legacy.get("package_signature_status")
    marker = "Status:"
    separator = "    Notarization:"
    if (
        type(flattened) is not str
        or flattened.count(marker) != 1
        or "\n" in flattened
        or "\r" in flattened
    ):
        fail("legacy package signature status is invalid")
    start = flattened.index(marker)
    end = flattened.find(separator, start)
    status = flattened[start:] if end < 0 else flattened[start:end]
    status = status.strip()
    if status != APPROVED_PACKAGE_SIGNATURE_STATUS:
        fail("legacy package signature status is not the approved Apple status")
    return status


def plan_migration(repo: Path, manifest: Path) -> dict[str, object]:
    if sys.platform != "darwin":
        fail("macOS is required")
    if os.geteuid() == 0:
        fail(OWNER_BLOCKED_ROOT_EXEC)
    _receipt_path, current_data = require_external_receipt(
        repo,
        required_uid=0,
        pin_manifest=manifest,
    )
    legacy = parse_legacy_receipt_for_migration(current_data)
    pin = load_pin_manifest(manifest)
    package_sha, wheels = pin_wheels(pin)
    controllers = snapshot_controllers()
    support = measure_runtime_support_closure(Path(DEFAULT_RUNTIME), required_uid=0)
    require_authenticated_planner_interpreter(support)
    authority = _read_migration_authority()
    require_legacy_migration_input(
        current_data,
        authority,
    )
    package_signature_status = legacy_package_signature_status(legacy, package_sha)
    closure = snapshot_migration_closure(repo, manifest)
    require_authority_for_repo(authority, repo, closure)
    require_held_migration_sources(closure)
    require_authority_bound_custody_metadata(repo, closure)
    if (
        closure["wrapper_sha256"] != controllers["controller_sha256"]
        or closure["provisioner_sha256"] != controllers["provisioner_sha256"]
        or closure["custody_controller_sha256"] != controllers["receipt_schema_sha256"]
    ):
        fail("Python receipt migration controller closure changed during measurement")
    try:
        measured = measure_runtime(Path(DEFAULT_RUNTIME), required_uid=0)
    except Refused as exc:
        fail(
            f"{OWNER_BLOCKED_MIGRATION}; legacy runtime/tree/support closure MATCH; "
            f"current schema {SCHEMA_VERSION} posture failed: {exc}"
        )
    require_owner_signing_policy(
        authority,
        measured["codesign_entrypoints"],  # type: ignore[arg-type]
        measured["gatekeeper_assessment"],  # type: ignore[arg-type]
    )
    candidate = build_receipt(
        measured=measured,
        package_sha256=package_sha,
        wheels=wheels,
        package_signature_status=package_signature_status,
        controllers=controllers,
        custody_closure=closure,
        authority=authority,
    )
    if snapshot_migration_closure(repo, manifest) != closure:
        fail("OWNER-BLOCKED: migration candidate closure drift rejected")
    require_held_migration_sources(closure)
    if _read_migration_authority() != authority:
        fail("OWNER-BLOCKED: migration authority changed during planning")
    return build_migration_plan(
        current_receipt_data=current_data,
        candidate=candidate,
        closure=closure,
        authority=authority,
        now=production_utc_now(),
    )


def emit_bindings(values: dict[str, str]) -> None:
    for key in (
        "RUNTIME",
        "RUNTIME_ID",
        "BIN",
        "BIN_SHA256",
        "VENDOR",
        "VENDOR_SHA256",
        "VENDOR_ID",
        "VENDOR_DIR_ID",
        "LAUNCHER",
        "LAUNCHER_SHA256",
        "LAUNCHER_ID",
        "LAUNCHER_DIR_ID",
        "FRAMEWORK",
        "FRAMEWORK_SHA256",
        "FRAMEWORK_ID",
        "FRAMEWORK_DIR_ID",
    ):
        value = values[key]
        if "\n" in value or "\0" in value:
            fail("binding value is unsafe")
        print(f"{key}={value}")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if not args:
            fail("missing Python runtime receipt action")
        action = args[0]
        if action == "authenticate" and len(args) == 3:
            emit_bindings(authenticate(Path(args[1]), Path(args[2]), required_uid=0))
            return 0
        if action == "inspect-existing" and len(args) == 3:
            print(inspect_existing(Path(args[1]), Path(args[2])))
            return 0
        if action == "plan-migration" and len(args) == 3:
            plan = plan_migration(Path(args[1]), Path(args[2]))
            sys.stdout.buffer.write(canonical_bytes(plan))
            return 1
        if action == "pin-wheels" and len(args) == 2:
            _package_sha, wheels = pin_wheels(load_pin_manifest(Path(args[1])))
            sys.stdout.buffer.write(canonical_bytes(wheels))
            return 0
        if action == "measure-runtime" and len(args) == 3:
            required = args[1]
            if required not in {"0", "self"}:
                fail("unknown required-uid selector")
            uid = 0 if required == "0" else os.getuid()
            measured = measure_runtime(Path(args[2]), required_uid=uid)
            sys.stdout.buffer.write(canonical_bytes({
                "runtime_path": measured["runtime_path"],
                "runtime_dir_identity": measured["runtime_dir_identity"],
                "framework_tree_sha256": measured["framework"]["content"],
                "framework_identity_sha256": measured["framework"]["identity"],
                "framework_dir_identity": measured["framework"]["dir_identity"],
                "vendor_tree_sha256": measured["vendor"]["content"],
                "vendor_identity_sha256": measured["vendor"]["identity"],
                "vendor_dir_identity": measured["vendor"]["dir_identity"],
                "launcher_tree_sha256": measured["launcher"]["content"],
                "launcher_identity_sha256": measured["launcher"]["identity"],
                "launcher_dir_identity": measured["launcher"]["dir_identity"],
                "executable_path": measured["executable_path"],
                "executable_sha256": measured["executable_sha256"],
                "executable_identity": measured["executable_identity"],
                "codesign": measured["codesign"],
                "codesign_entrypoints": measured["codesign_entrypoints"],
            }))
            return 0
        if action == "write-receipt":
            fail(
                "OWNER-BLOCKED: repository code cannot publish or reissue the runtime receipt; "
                f"{OWNER_PROVISION_ACTION}"
            )
        if action == "sync-directory" and len(args) == 2:
            sync_directory(Path(args[1]))
            return 0
        if action == "sync-tree" and len(args) == 2:
            sync_tree(Path(args[1]))
            return 0
        if action == "bind-tree" and len(args) in {4, 5}:
            allow = False
            required = args[1]
            offset = 2
            if args[2] == "--allow-in-tree-symlinks":
                allow = True
                offset = 3
            if required not in {"0", "self"}:
                fail("unknown required-uid selector")
            uid = 0 if required == "0" else os.getuid()
            bind = bind_tree(
                Path(args[offset]),
                required_uid=uid,
                allow_symlinks=allow,
            )
            print(f"{bind['content']} {bind['identity']} {bind['dir_identity']}")
            return 0
        if action == "parse-receipt" and len(args) == 2:
            data = Path(args[1]).read_bytes()
            receipt = parse_receipt(data)
            sys.stdout.buffer.write(canonical_bytes(receipt))
            return 0
        if action == "owner-action" and len(args) == 2:
            print(owner_provision_action(Path(args[1])))
            return 0
        if action == "codesign" and len(args) == 3:
            record = codesign_record(Path(args[1]), args[2])
            print(canonical_bytes(record).decode("ascii"), end="")
            return 0
        fail("unknown or malformed Python runtime receipt action")
    except Refused as exc:
        print(f"release-python custody: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"release-python custody: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
