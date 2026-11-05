#!/usr/bin/env python3
"""Verify frozen app sources while allowing separately bound website staging.

The five native artifacts do not embed ``web/``.  A release may therefore stage
audited website links after the native binaries have passed their device gates,
but changes to any app/runtime/installer source must invalidate the release.
The immutable lock is created only after the original combined fingerprint has
already been frozen; this verifier never creates or updates that lock.
Mutated application or website sources cannot self-author replacement receipts:
APP_SOURCE_LOCK, SCOPE_FREEZE, and WEBSITE_STAGE must match the sha256 pins in
the committed pin record tools/release_source_freeze.trust.json and carry its
issuance_id and created_utc. A missing, malformed or mismatched pin refuses
with a message naming that pin; a symlinked, hard-linked, special or
group/world-writable pin record is refused. Production verification also binds
the exact tracked Git HEAD tree plus an explicit intentionally-untracked source
allowlist, refuses index/worktree splits including CRLF and mode drift, and
binds the reviewed toolchain manifest, this controller, and its focused test.
Isolated fixture/test mode exists only for local harnesses without Git; it
never authorizes release and cannot be selected from the production CLI.
Dependency freeze consumes this same pin record.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import unicodedata
from typing import Iterable


LOCK_CONTRACT = "winsvpn-app-source-lock-v1"
APP_SOURCE_CONTRACT = "winsvpn-native-app-sources-v1"
WEBSITE_SOURCE_CONTRACT = "winsvpn-website-staging-sources-v1"
WEBSITE_STAGE_CONTRACT = "winsvpn-website-stage-v1"
SCOPE_CONTRACT = "winsvpn-scope-freeze-v1"
EXTERNAL_TRUST_NAME = "release_source_freeze.trust.json"
EXTERNAL_TRUST_CONTRACT = "winsvpn-source-freeze-external-trust-v1"
EXTERNAL_TRUST_ISSUER = "winsvpn-release-source-freeze"
TRUST_PIN_LABEL = "source-freeze pin record"
TRUST_PIN_MISSING = "missing pin: source-freeze pin record"
TRUST_PIN_HOW_TO = (
    "measure each pin with shasum -a 256 and record it in "
    f"tools/{EXTERNAL_TRUST_NAME}: controller_sha256 of "
    "tools/release_source_freeze.py, test_sha256 of "
    "tools/test_release_source_freeze.py, manifest_sha256 of "
    "tools/toolchain-pins.json, app_source_lock_sha256 and scope_freeze_sha256 "
    "of .artifacts/release-freeze-<release>/APP_SOURCE_LOCK.json and "
    "SCOPE_FREEZE.json; release, issuance_id and created_utc must equal the "
    "values those receipts carry"
)
RECEIPT_REBIND_CHANGED = (
    "freeze receipt identity changed before freeze verification returned"
)
REPO_REBIND_CHANGED = (
    "release repository path was replaced while a bound descriptor remained readable"
)
FREEZE_DIR_REBIND_CHANGED = (
    "freeze receipt directory identity changed before freeze verification returned"
)
SOURCE_PATHS_NATIVE_HOST = (
    # Shipping native-messaging host inputs. Hash these files only: do not
    # freeze all of tools/, generated host output, caches, harness sources, or
    # browser-specific manifest templates.
    "tools/native_messaging/host/pubspec.yaml",
    "tools/native_messaging/host/pubspec.lock",
    "tools/native_messaging/host/bin/wins_bridge_host.dart",
    "tools/native_messaging/install_native_host.sh",
    "tools/native_messaging/native_host_layout.py",
    "tools/native_messaging/render_host_manifest.py",
    "tools/native_messaging/manifests/store_ids.json",
)
SOURCE_PATHS_APP = (
    "pubspec.yaml",
    "pubspec.lock",
    "lib",
    "assets",
    "android",
    "wear_os",
    "extension",
    "windows",
    "linux",
    "ios",
    "macos",
    "apple",
    "installer/windows",
    # Winn v3 is compiled into the shipping native engines.  Leaving its Go
    # sources outside the app-source boundary could make a changed transport
    # runtime look frozen while its platform artifact is not.
    "winn_protocol_experimental",
) + SOURCE_PATHS_NATIVE_HOST
SOURCE_PATHS_WEBSITE = ("web",)
SOURCE_PATHS_COMBINED = SOURCE_PATHS_APP + SOURCE_PATHS_WEBSITE
SOURCE_SYMLINK_ALIASES = (
    (
        "tools/native_messaging/host/lib/browser_bridge_app_ipc.dart",
        "../../../../lib/browser_bridge_app_ipc.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_framing.dart",
        "../../../../lib/browser_bridge_framing.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_protocol.dart",
        "../../../../lib/browser_bridge_protocol.dart",
    ),
    (
        "tools/native_messaging/host/lib/browser_bridge_proxy.dart",
        "../../../../lib/browser_bridge_proxy.dart",
    ),
    (
        "tools/native_messaging/host/lib/vpn_config_validation.dart",
        "../../../../lib/vpn_config_validation.dart",
    ),
    (
        "tools/native_messaging/host/lib/windows_system_executable.dart",
        "../../../../lib/windows_system_executable.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_carrier_profile_keys.dart",
        "../../../../lib/winn_carrier_profile_keys.dart",
    ),
    (
        "tools/native_messaging/host/lib/winn_protocol_dispatch.dart",
        "../../../../lib/winn_protocol_dispatch.dart",
    ),
)
SOURCE_SYMLINK_ALIAS_DIR = "tools/native_messaging/host/lib"
# Exact reviewed generated-output directories. Component-name matching is not
# used: an unreviewed directory named build/.gradle/Pods would hide shipping
# source and must fail closed instead of being omitted.
REVIEWED_EXCLUDED_DIRECTORIES = frozenset(
    {
        "android/.cxx",
        "android/.gradle",
        "android/.kotlin",
        "android/build",
        "android/devicecheck/.gradle",
        "android/devicecheck/.kotlin",
        "android/devicecheck/app/build",
        "ios/.symlinks",
        "ios/Flutter/ephemeral",
        "ios/Pods",
        "ios/Runner.xcodeproj/xcuserdata",
        "ios/Runner.xcworkspace/xcuserdata",
        "linux/flutter/ephemeral",
        "macos/Flutter/ephemeral",
        "macos/Pods",
        "macos/Runner.xcodeproj/xcuserdata",
        "macos/Runner.xcworkspace/xcuserdata",
        "wear_os/.gradle",
        "wear_os/.kotlin",
        "wear_os/app/build",
        "wear_os/build",
        "web/downloads",
        "windows/flutter/ephemeral",
    }
)
GENERATED_DIRECTORY_NAMES = frozenset(
    {
        ".cxx",
        ".dart_tool",
        ".gradle",
        ".kotlin",
        ".symlinks",
        "build",
        "deriveddata",
        "downloads",
        "ephemeral",
        "pods",
        "xcuserdata",
    }
)
EXCLUDED_FILENAMES = {
    ".ds_store",
    "thumbs.db",
    "local.properties",
    "key.properties",
    "generated.xcconfig",
    "flutter_export_environment.sh",
    "flutter.podspec",
}
EXCLUDED_EXTENSIONS = {
    ".apk",
    ".aab",
    ".exe",
    ".dll",
    ".msi",
    ".sys",
    ".zip",
    ".pkg",
    ".ipa",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".dylib",
    ".so",
}
SHIPPING_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".dart",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".htm",
    ".java",
    ".js",
    ".kt",
    ".kts",
    ".m",
    ".mm",
    ".py",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}
SCOPE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "scope_frozen",
        "publication_locked",
        "source_fingerprint_sha256",
        "issuance_id",
        "created_utc",
    }
)
LOCK_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "scope_frozen",
        "publication_locked",
        "scope_freeze_sha256",
        "frozen_combined_source_fingerprint_sha256",
        "frozen_combined_source_file_count",
        "app_source_contract",
        "app_source_fingerprint_sha256",
        "app_source_file_count",
        "website_source_contract",
        "website_source_fingerprint_sha256_at_freeze",
        "website_source_file_count_at_freeze",
        "website_index_sha256_at_freeze",
        "immutable_website_source_fingerprint_sha256_at_freeze",
        "immutable_website_source_file_count_at_freeze",
        "website_mutable_paths_after_scope_freeze",
        "website_staging_allowed_after_scope_freeze",
        "issuance_id",
        "created_utc",
    }
)
STAGE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "boundary_lock_sha256",
        "app_source_fingerprint_sha256",
        "app_source_file_count",
        "immutable_website_source_fingerprint_sha256",
        "immutable_website_source_file_count",
        "website_index_sha256_before",
        "website_index_sha256_after",
        "staged_website_source_fingerprint_sha256",
        "staged_website_source_file_count",
        "mutated_paths",
        "publication_authorized",
        "issuance_id",
        "created_utc",
    }
)
EXTERNAL_TRUST_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "release",
        "created_utc",
        "issuance_id",
        "authenticated",
        "issuer",
        "app_source_lock_sha256",
        "scope_freeze_sha256",
        "website_stage_sha256",
        "controller_sha256",
        "test_sha256",
        "manifest_sha256",
    }
)
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_JSON_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_COUNT = 100_000
MAX_SOURCE_AGGREGATE_BYTES = 512 * 1024 * 1024
MAX_TRUST_BYTES = 64 * 1024
_FILE_ROOTS = frozenset(("pubspec.yaml", "pubspec.lock", *SOURCE_PATHS_NATIVE_HOST))
_WRITABLE_MASK = stat.S_IWGRP | stat.S_IWOTH
ISSUANCE_ID = re.compile(r"[0-9a-f]{32}\Z")
_SEMVER_CORE = r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
_SEMVER_PRERELEASE_ID = r"(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
_SEMVER_PLUS_BUILD = re.compile(
    rf"^version:\s*"
    rf"({_SEMVER_CORE}(?:-{_SEMVER_PRERELEASE_ID}(?:\.{_SEMVER_PRERELEASE_ID})*)?)"
    rf"\+(0|[1-9]\d*)\s*$"
)
_VERSION_LINE = re.compile(r"(?m)^version:\s*.*$")
# Tests may assign a callable that runs after the first independent capture and
# before the second. Production verification leaves this unset.
_POST_TREE_CAPTURE_HOOK = None
# Tests may assign a callable that runs after each directory is bound through
# openat and before child lookup continues. Production verification leaves this
# unset.
_POST_DIRECTORY_BIND_HOOK = None
# Tests may assign a callable that runs after the last verification recapture
# and before the immediate pre-return revalidation. Production verification
# leaves this unset.
_POST_FINAL_CAPTURE_HOOK = None
# Tests may assign an absolute issuance path outside the candidate repository.
# Production verification binds tools/release_source_freeze.trust.json beside
# this producer.
_EXTERNAL_TRUST_PATH = None
CONTROLLER_NAME = "release_source_freeze.py"
TEST_NAME = "test_release_source_freeze.py"
TOOLCHAIN_PIN_NAME = "toolchain-pins.json"
TOOLCHAIN_PIN_PATH = f"tools/{TOOLCHAIN_PIN_NAME}"
FREEZE_LOCK_NAME = "APP_SOURCE_LOCK.json"
FREEZE_SCOPE_NAME = "SCOPE_FREEZE.json"
FREEZE_STAGE_NAME = "WEBSITE_STAGE.json"
# Shipping source that is not in Git HEAD must be enumerated here. An empty
# allowlist means the hashed denominator is exactly the tracked source tree.
INTENTIONALLY_UNTRACKED_SOURCE: frozenset[str] = frozenset()
# Isolated fixture/test mode. Tests may set this True. Production verification
# leaves it False. The CLI refuses it and cannot claim PASS.
_FIXTURE_MODE = False
# Set only by main() for the duration of a CLI invocation. Library harnesses
# without Git stay on the isolated fixture path; the CLI cannot.
_PRODUCTION_REQUIRED = False
_GIT_UNSET_VARS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
)
_GIT_TIMEOUT_SEC = 120
GIT_UNTRACKED_INPUT = (
    "untracked filesystem file is not a tracked Git tree input"
)
GIT_STAGED_ONLY_INPUT = (
    "staged-only path is not in the exact tracked Git tree"
)
GIT_INDEX_WORKTREE_SPLIT = (
    "source index/worktree split is not an exact tracked Git tree"
)
GIT_CRLF_DRIFT = "source CRLF or newline identity drifted from the tracked Git tree"
GIT_METADATA_DRIFT = "source metadata drifted from the tracked Git tree"
GIT_SYMLINK_INPUT = (
    "tracked Git symlink is forbidden as a hashed release source file"
)
GIT_DIRTY_SOURCE = (
    "source state is not immutable/clean according to the local release policy"
)
GIT_REQUIRED = "production release freeze requires a Git repository"
FIXTURE_CANNOT_AUTHORIZE = (
    "isolated fixture/test mode cannot authorize a production release freeze"
)
PRODUCER_INJECTION = (
    "source-freeze producer identity is not bound to the current reviewed issuance"
)
TEST_INJECTION = (
    "source-freeze test identity is not bound to the current reviewed issuance"
)
TOOLCHAIN_CLOSURE = (
    "source-freeze toolchain manifest/controller/test closure is not exact"
)
PARTIAL_PUBLICATION = (
    "freeze receipt directory is not an exact lock/scope/stage publication set"
)
REVIEWED_PYTHON_MAJOR_MINOR = (3, 14)


class SourceFreezeError(RuntimeError):
    """Raised when a frozen source contract cannot be verified."""


@dataclasses.dataclass(frozen=True)
class TreeState:
    sha256: str
    file_count: int
    latest_write_utc: dt.datetime
    capture_identity: str


@dataclasses.dataclass(frozen=True)
class ReleaseSourceState:
    source_fingerprint_sha256: str
    source_file_count: int
    latest_write_utc: dt.datetime
    app_source_fingerprint_sha256: str
    app_source_file_count: int
    website_source_fingerprint_sha256: str
    website_source_file_count: int
    immutable_website_source_fingerprint_sha256: str
    immutable_website_source_file_count: int
    website_changed_from_freeze: bool
    lock_path: str
    website_stage_path: str


@dataclasses.dataclass(frozen=True)
class WebsiteSourceState:
    website_source_fingerprint_sha256: str
    website_source_file_count: int
    website_latest_write_utc: dt.datetime
    immutable_website_source_fingerprint_sha256: str
    immutable_website_source_file_count: int


@dataclasses.dataclass(frozen=True)
class _SourceCapture:
    sha256: str
    file_count: int
    latest_write_utc: dt.datetime
    capture_identity: str
    paths: tuple[str, ...]
    identities: tuple[tuple[str, tuple[int, ...]], ...]
    aliases: tuple[tuple[str, str], ...]
    payloads: tuple[tuple[str, bytes], ...]


@dataclasses.dataclass(frozen=True)
class _HashedFile:
    relative: str
    payload: bytes
    identity: tuple[int, ...]
    info: os.stat_result


@dataclasses.dataclass(frozen=True)
class _ScopeSnapshot:
    app: TreeState
    website: TreeState
    immutable_website: TreeState
    payloads: tuple[tuple[str, bytes], ...]
    identities: tuple[tuple[str, tuple[int, ...]], ...]
    aliases: tuple[tuple[str, str], ...]


@dataclasses.dataclass(frozen=True)
class _BoundDocument:
    relative: str
    record: dict[str, object]
    digest: str
    identity: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class _IssuanceBinding:
    path: str
    record: dict[str, object]
    digest: str
    identity: tuple[int, ...]
    parent_identity: tuple[int, ...]
    issuance_id: str
    created_utc: str
    release: str
    app_source_lock_sha256: str
    scope_freeze_sha256: str
    website_stage_sha256: str | None
    controller_sha256: str
    test_sha256: str
    manifest_sha256: str


def _empty_tree() -> _SourceCapture:
    digest = hashlib.sha256().hexdigest()
    return _SourceCapture(
        sha256=digest,
        file_count=0,
        latest_write_utc=dt.datetime.min.replace(tzinfo=dt.timezone.utc),
        capture_identity=digest,
        paths=(),
        identities=(),
        aliases=(),
        payloads=(),
    )


def _canonical_repo(repo: pathlib.Path) -> pathlib.Path:
    try:
        resolved = pathlib.Path(os.path.realpath(repo))
        info = os.lstat(resolved)
    except OSError as exc:
        raise SourceFreezeError("release repository could not be inspected") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise SourceFreezeError("release repository must be a real directory")
    return resolved


def _allowed_owners(repo: pathlib.Path) -> frozenset[int]:
    owners: set[int] = set()
    getuid = getattr(os, "getuid", None)
    if getuid is not None:
        owners.add(int(getuid()))
    try:
        owners.add(int(os.lstat(repo).st_uid))
    except OSError as exc:
        raise SourceFreezeError("release repository could not be inspected") from exc
    if not owners:
        raise SourceFreezeError("source freeze requires an owner identity")
    return frozenset(owners)


def _nofollow_flags() -> int:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0:
        raise SourceFreezeError("source freeze requires O_NOFOLLOW")
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0) | nofollow


def _directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", 0)
    if directory == 0:
        raise SourceFreezeError("source freeze requires O_DIRECTORY")
    return _nofollow_flags() | directory


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _fold_key(value: str) -> str:
    try:
        normalized = unicodedata.normalize("NFKC", value)
    except Exception as suc:
        raise SourceFreezeError("source path is not a valid Unicode name") from suc
    return normalized.casefold()


def _is_special_node(info: os.stat_result) -> bool:
    mode = info.st_mode
    return bool(
        stat.S_ISFIFO(mode)
        or stat.S_ISCHR(mode)
        or stat.S_ISBLK(mode)
        or stat.S_ISSOCK(mode)
    )


def _allocated_bytes(info: os.stat_result) -> int:
    return int(getattr(info, "st_blocks", 0)) * 512


def _reject_oversized_file(relative: str, info: os.stat_result) -> None:
    if info.st_size < 0 or info.st_size > MAX_SOURCE_FILE_BYTES:
        raise SourceFreezeError(
            f"source file size is outside the accepted bound: {relative}"
        )
    allocated = _allocated_bytes(info)
    if allocated < 0 or allocated > MAX_SOURCE_FILE_BYTES:
        raise SourceFreezeError(
            f"source allocated size is outside the accepted bound: {relative}"
        )


def _shipping_source_extension(relative: str) -> bool:
    suffix = pathlib.PurePosixPath(relative).suffix
    if not suffix:
        return False
    folded = _fold_key(suffix)
    for item in SHIPPING_SOURCE_EXTENSIONS:
        if _fold_key(item) == folded:
            return True
    return False


def _utc_now_text() -> str:
    return (
        dt.datetime.now(tz=dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _join_relative(parent: str, name: str) -> str:
    return f"{parent}/{name}" if parent else name


def _parent_relative(relative: str) -> str:
    if not relative or "/" not in relative:
        return ""
    return relative.rsplit("/", 1)[0]


def _split_relative(relative: str) -> tuple[str, ...]:
    posix = relative.replace("\\", "/")
    if posix.startswith("/") or posix in {"", "."}:
        raise SourceFreezeError(f"source path escapes the repository: {relative}")
    parts = pathlib.PurePosixPath(posix).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SourceFreezeError(f"source path escapes the repository: {relative}")
    for part in parts:
        _fold_key(part)
    return parts


def _split_link_components(relative: str, alias: str) -> tuple[str, ...]:
    posix = relative.replace("\\", "/")
    if posix.startswith("/") or posix in {"", "."}:
        raise SourceFreezeError(
            f"source symlink alias target escapes the repository: {alias}"
        )
    parts = pathlib.PurePosixPath(posix).parts
    if not parts or any(part == "" for part in parts):
        raise SourceFreezeError(
            f"source symlink alias target escapes the repository: {alias}"
        )
    return parts


def _is_group_or_world_writable(info: os.stat_result) -> bool:
    return bool(info.st_mode & _WRITABLE_MASK)


def _require_owned_mode(
    relative: str,
    info: os.stat_result,
    allowed_owners: frozenset[int],
    *,
    kind: str,
) -> None:
    if info.st_uid not in allowed_owners:
        raise SourceFreezeError(
            f"{kind} is not owned by the current user or repository owner: {relative}"
        )
    if _is_group_or_world_writable(info):
        raise SourceFreezeError(f"group/world-writable {kind}: {relative}")


def _reviewed_excluded_directory(posix: str) -> str | None:
    folded = _fold_key(posix)
    for reviewed in REVIEWED_EXCLUDED_DIRECTORIES:
        reviewed_folded = _fold_key(reviewed)
        if folded == reviewed_folded or folded.startswith(reviewed_folded + "/"):
            if posix == reviewed or posix.startswith(reviewed + "/"):
                return reviewed
            raise SourceFreezeError(f"case-fold collision: {reviewed} and {posix}")
    return None


def _reject_unreviewed_generated_directory(posix: str) -> None:
    name = pathlib.PurePosixPath(posix).name
    generated = {_fold_key(item) for item in GENERATED_DIRECTORY_NAMES}
    if _fold_key(name) not in generated:
        return
    if _reviewed_excluded_directory(posix) is not None:
        return
    raise SourceFreezeError(
        "unexpected excluded shipping source under source-bearing root: "
        f"{posix}"
    )


def _is_excluded_file(posix: str, excluded: dict[str, str]) -> bool:
    relative = pathlib.PurePosixPath(posix)
    filenames = {_fold_key(item) for item in EXCLUDED_FILENAMES}
    if _fold_key(relative.name) in filenames:
        return True
    suffix = pathlib.Path(relative.name).suffix
    extensions = {_fold_key(item) for item in EXCLUDED_EXTENSIONS}
    if suffix and _fold_key(suffix) in extensions:
        return True
    folded = _fold_key(posix)
    if folded in excluded:
        exact = excluded[folded]
        if posix != exact:
            raise SourceFreezeError(f"case-fold collision: {exact} and {posix}")
        return True
    return False


def _open_repo_dir(
    repo: pathlib.Path,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    flags = _directory_flags()
    try:
        path_before = os.lstat(repo)
        descriptor = os.open(repo, flags)
    except OSError as exc:
        raise SourceFreezeError("release repository could not be inspected") from exc
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise SourceFreezeError("release repository could not be inspected") from exc
    if (
        stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (path_before.st_dev, path_before.st_ino) != (opened.st_dev, opened.st_ino)
        or _identity(path_before) != _identity(opened)
    ):
        os.close(descriptor)
        raise SourceFreezeError("release repository must be a real directory")
    try:
        _require_owned_mode(".", opened, allowed_owners, kind="source directory")
        hook = _POST_DIRECTORY_BIND_HOOK
        if callable(hook):
            hook(".")
        rebound = _rebind_requested_path(
            repo,
            descriptor,
            opened,
            kind="release repository",
            directory=True,
        )
        _require_owned_mode(".", rebound, allowed_owners, kind="source directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, rebound


def _rebind_requested_path(
    path: pathlib.Path,
    bound_fd: int,
    bound_info: os.stat_result,
    *,
    kind: str,
    directory: bool,
) -> os.stat_result:
    """Reject pathname replacement of a bound descriptor before return."""

    replaced = f"{kind} path was replaced while a bound descriptor remained readable"
    try:
        rebound = os.fstat(bound_fd)
        path_now = os.lstat(path)
        flags = _directory_flags() if directory else _nofollow_flags()
        descriptor = os.open(path, flags)
    except OSError as suc:
        raise SourceFreezeError(replaced) from suc
    try:
        opened = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        stat.S_ISLNK(path_now.st_mode)
        or (directory and not stat.S_ISDIR(rebound.st_mode))
        or (not directory and not stat.S_ISREG(opened.st_mode))
        or (path_now.st_dev, path_now.st_ino) != (rebound.st_dev, rebound.st_ino)
        or (opened.st_dev, opened.st_ino) != (rebound.st_dev, rebound.st_ino)
    ):
        raise SourceFreezeError(replaced)
    if _identity(rebound) != _identity(bound_info):
        raise SourceFreezeError(
            f"{kind} identity changed while a bound descriptor remained readable"
        )
    if _identity(opened) != _identity(rebound) or _identity(path_now) != _identity(
        rebound
    ):
        raise SourceFreezeError(replaced)
    return rebound


def _require_repo_path_identity(
    repo: pathlib.Path,
    repo_fd: int,
    opened: os.stat_result,
) -> os.stat_result:
    try:
        return _rebind_requested_path(
            repo,
            repo_fd,
            opened,
            kind="release repository",
            directory=True,
        )
    except SourceFreezeError as suc:
        message = str(suc)
        if "release repository" in message:
            raise
        raise SourceFreezeError(REPO_REBIND_CHANGED) from suc


def _lstat_at(
    parent_fd: int,
    name: str,
    relative: str,
    *,
    required_root: bool = False,
) -> os.stat_result:
    try:
        return os.lstat(name, dir_fd=parent_fd)
    except FileNotFoundError as exc:
        if required_root:
            raise SourceFreezeError(
                f"Required release source root is missing: {relative}"
            ) from exc
        raise SourceFreezeError(
            f"source path could not be inspected: {relative}"
        ) from exc
    except OSError as exc:
        raise SourceFreezeError(
            f"source path could not be inspected: {relative}"
        ) from exc


def _open_at(parent_fd: int, name: str, flags: int, relative: str) -> int:
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        path_info = None
        try:
            path_info = os.lstat(name, dir_fd=parent_fd)
        except OSError:
            path_info = None
        if path_info is not None and stat.S_ISLNK(path_info.st_mode):
            raise SourceFreezeError(f"Unexpected source symlink: {relative}") from exc
        raise SourceFreezeError(
            f"source path could not be opened without following: {relative}"
        ) from exc


def _bind_directory_fd(
    parent_fd: int,
    name: str,
    relative: str,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    _reject_casefold_lookup(parent_fd, _parent_relative(relative), name)
    path_before = _lstat_at(parent_fd, name, relative)
    if stat.S_ISLNK(path_before.st_mode):
        raise SourceFreezeError(f"Unexpected source symlink: {relative}")
    if not stat.S_ISDIR(path_before.st_mode):
        raise SourceFreezeError(
            f"Required release source root is missing: {relative}"
        )
    descriptor = _open_at(parent_fd, name, _directory_flags(), relative)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (path_before.st_dev, path_before.st_ino)
            != (opened.st_dev, opened.st_ino)
            or _identity(path_before) != _identity(opened)
        ):
            raise SourceFreezeError(
                f"source directory identity changed while traversing: {relative}"
            )
        _require_owned_mode(relative, opened, allowed_owners, kind="source directory")
        hook = _POST_DIRECTORY_BIND_HOOK
        if callable(hook):
            hook(relative)
        path_after = _lstat_at(parent_fd, name, relative)
        rebound = os.fstat(descriptor)
        if stat.S_ISLNK(path_after.st_mode):
            raise SourceFreezeError(f"Unexpected source symlink: {relative}")
        if (
            _identity(opened) != _identity(rebound)
            or (path_after.st_dev, path_after.st_ino)
            != (opened.st_dev, opened.st_ino)
            or _identity(path_after) != _identity(rebound)
        ):
            raise SourceFreezeError(
                f"source directory identity changed while traversing: {relative}"
            )
        _require_owned_mode(relative, rebound, allowed_owners, kind="source directory")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, rebound


def _close_quietly(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _walk_open_dir(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
) -> tuple[int, os.stat_result]:
    current = repo_fd
    owned: list[int] = []
    info: os.stat_result | None = None
    rel = ""
    try:
        for part in _split_relative(relative):
            rel = _join_relative(rel, part)
            nxt, info = _bind_directory_fd(current, part, rel, allowed_owners)
            owned.append(nxt)
            current = nxt
        if info is None:
            raise SourceFreezeError(f"source path could not be inspected: {relative}")
        owned.pop()
        return current, info
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _list_directory_names(dir_fd: int, relative: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    folded: dict[str, str] = {}
    try:
        iterator = os.scandir(dir_fd)
    except OSError as exc:
        raise SourceFreezeError(
            f"source directory is unreadable: {relative or '.'}"
        ) from exc
    with iterator:
        for entry in iterator:
            name = entry.name
            if name in {".", ".."}:
                continue
            if "\x00" in name or "/" in name or "\\" in name:
                raise SourceFreezeError(
                    f"source directory has an unsafe entry name: {_join_relative(relative, name)}"
                )
            if name in seen:
                raise SourceFreezeError(
                    f"source directory has a duplicate entry: {_join_relative(relative, name)}"
                )
            seen.add(name)
            key = _fold_key(name)
            previous = folded.get(key)
            if previous is not None and previous != name:
                left = _join_relative(relative, previous)
                right = _join_relative(relative, name)
                raise SourceFreezeError(f"case-fold collision: {left} and {right}")
            folded[key] = name
            names.append(name)
    return names


def _reject_casefold_lookup(parent_fd: int, parent_rel: str, name: str) -> None:
    names = _list_directory_names(parent_fd, parent_rel)
    folded = _fold_key(name)
    for existing in names:
        if _fold_key(existing) == folded and existing != name:
            left = _join_relative(parent_rel, existing)
            right = _join_relative(parent_rel, name)
            raise SourceFreezeError(f"case-fold collision: {left} and {right}")


def _stable_read_regular_file_at(
    parent_fd: int,
    name: str,
    relative: str,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    flags = _nofollow_flags()
    _reject_casefold_lookup(parent_fd, _parent_relative(relative), name)
    path_before = _lstat_at(parent_fd, name, relative)
    if stat.S_ISLNK(path_before.st_mode):
        raise SourceFreezeError(f"Unexpected source symlink: {relative}")
    descriptor = _open_at(parent_fd, name, flags, relative)
    try:
        before = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (path_before.st_dev, path_before.st_ino):
            raise SourceFreezeError(
                f"source file identity changed while opening: {relative}"
            )
        if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise SourceFreezeError(
                f"source file must be a regular non-symlink file: {relative}"
            )
        if before.st_nlink != 1:
            raise SourceFreezeError(f"source file must have link count 1: {relative}")
        _require_owned_mode(relative, before, allowed_owners, kind="source file")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SourceFreezeError(
                f"source file size is outside the accepted bound: {relative}"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                raise SourceFreezeError(
                    f"source file ended before its declared size: {relative}"
                )
            remaining -= len(block)
            chunks.append(block)
        extra = os.read(descriptor, 1)
        if extra:
            raise SourceFreezeError(
                f"source file grew while it was read: {relative}"
            )
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        path_after = os.lstat(name, dir_fd=parent_fd)
    except OSError as exc:
        raise SourceFreezeError(
            f"source file disappeared after hashing: {relative}"
        ) from exc
    if not (
        _identity(path_before)
        == _identity(before)
        == _identity(after)
        == _identity(path_after)
    ):
        raise SourceFreezeError(
            f"source file changed while it was hashed: {relative}"
        )
    payload = b"".join(chunks)
    if len(payload) != before.st_size:
        raise SourceFreezeError(
            f"source file size is outside the accepted bound: {relative}"
        )
    return payload, _identity(before), before


def _stable_read_regular_file(
    path: pathlib.Path,
    allowed_owners: frozenset[int],
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    parent = path.parent
    repo_fd, _info = _open_repo_dir(parent, allowed_owners)
    try:
        return _stable_read_regular_file_at(
            repo_fd, path.name, path.name, allowed_owners
        )
    finally:
        os.close(repo_fd)


def _read_relative_file(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
    *,
    max_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> tuple[bytes, tuple[int, ...], os.stat_result]:
    parts = _split_relative(relative)
    current = repo_fd
    owned: list[int] = []
    rel = ""
    try:
        for part in parts[:-1]:
            rel = _join_relative(rel, part)
            nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
            owned.append(nxt)
            current = nxt
        return _stable_read_regular_file_at(
            current,
            parts[-1],
            relative,
            allowed_owners,
            max_bytes=max_bytes,
        )
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _add_selected(
    selected: dict[str, _HashedFile],
    hashed: _HashedFile,
    *,
    aggregate_bytes: int,
) -> int:
    if len(selected) + 1 > MAX_SOURCE_FILE_COUNT:
        raise SourceFreezeError("source file count is outside the accepted bound")
    added = aggregate_bytes + hashed.info.st_size
    if added > MAX_SOURCE_AGGREGATE_BYTES:
        raise SourceFreezeError(
            "source aggregate size is outside the accepted bound"
        )
    key = _fold_key(hashed.relative)
    existing = selected.get(key)
    if existing is not None and existing.relative != hashed.relative:
        raise SourceFreezeError(
            f"case-fold collision: {existing.relative} and {hashed.relative}"
        )
    selected[key] = hashed
    return added


def _inspect_unhashed_tree(
    dir_fd: int,
    dir_info: os.stat_result,
    relative: str,
    allowed_owners: frozenset[int],
    inspected: int = 0,
) -> int:
    """Reject unsafe nodes in excluded trees without hashing ordinary caches."""

    _require_owned_mode(relative, dir_info, allowed_owners, kind="source directory")
    names = _list_directory_names(dir_fd, relative)
    for name in names:
        inspected += 1
        if inspected > MAX_SOURCE_FILE_COUNT:
            raise SourceFreezeError("source file count is outside the accepted bound")
        child_rel = _join_relative(relative, name)
        child_info = _lstat_at(dir_fd, name, child_rel)
        if stat.S_ISLNK(child_info.st_mode):
            raise SourceFreezeError(f"Unexpected source symlink: {child_rel}")
        if _is_special_node(child_info):
            raise SourceFreezeError(
                f"source path must be a regular file or directory: {child_rel}"
            )
        if stat.S_ISDIR(child_info.st_mode):
            child_fd, bound = _bind_directory_fd(
                dir_fd, name, child_rel, allowed_owners
            )
            try:
                inspected = _inspect_unhashed_tree(
                    child_fd,
                    bound,
                    child_rel,
                    allowed_owners,
                    inspected,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(child_info.st_mode):
            raise SourceFreezeError(
                f"source path must be a regular file or directory: {child_rel}"
            )
        if child_info.st_nlink != 1:
            raise SourceFreezeError(f"source file must have link count 1: {child_rel}")
        _require_owned_mode(child_rel, child_info, allowed_owners, kind="source file")
        _reject_oversized_file(child_rel, child_info)
        if _shipping_source_extension(child_rel):
            raise SourceFreezeError(
                "unexpected excluded shipping source under source-bearing root: "
                f"{child_rel}"
            )
    rebound = os.fstat(dir_fd)
    if _identity(rebound) != _identity(dir_info):
        raise SourceFreezeError(
            f"source directory identity changed while traversing: {relative}"
        )
    return inspected


def _walk_source_directory(
    dir_fd: int,
    dir_info: os.stat_result,
    relative: str,
    excluded: dict[str, str],
    allowed_owners: frozenset[int],
    selected: dict[str, _HashedFile],
    aggregate_bytes: int,
) -> int:
    names = _list_directory_names(dir_fd, relative)
    for name in names:
        child_rel = _join_relative(relative, name)
        child_info = _lstat_at(dir_fd, name, child_rel)
        if stat.S_ISLNK(child_info.st_mode):
            raise SourceFreezeError(f"Unexpected source symlink: {child_rel}")
        if _is_special_node(child_info):
            raise SourceFreezeError(
                f"source path must be a regular file or directory: {child_rel}"
            )
        if stat.S_ISDIR(child_info.st_mode):
            _reject_unreviewed_generated_directory(child_rel)
            child_fd, bound = _bind_directory_fd(
                dir_fd, name, child_rel, allowed_owners
            )
            try:
                if _reviewed_excluded_directory(child_rel) == child_rel:
                    _inspect_unhashed_tree(
                        child_fd, bound, child_rel, allowed_owners
                    )
                    continue
                aggregate_bytes = _walk_source_directory(
                    child_fd,
                    bound,
                    child_rel,
                    excluded,
                    allowed_owners,
                    selected,
                    aggregate_bytes,
                )
            finally:
                os.close(child_fd)
            continue
        if not stat.S_ISREG(child_info.st_mode):
            raise SourceFreezeError(
                f"source path must be a regular file or directory: {child_rel}"
            )
        if _is_excluded_file(child_rel, excluded):
            continue
        if child_info.st_size > MAX_SOURCE_FILE_BYTES:
            raise SourceFreezeError(
                f"source file size is outside the accepted bound: {child_rel}"
            )
        if aggregate_bytes + child_info.st_size > MAX_SOURCE_AGGREGATE_BYTES:
            raise SourceFreezeError(
                "source aggregate size is outside the accepted bound"
            )
        if len(selected) + 1 > MAX_SOURCE_FILE_COUNT:
            raise SourceFreezeError(
                "source file count is outside the accepted bound"
            )
        payload, identity, info = _stable_read_regular_file_at(
            dir_fd, name, child_rel, allowed_owners
        )
        aggregate_bytes = _add_selected(
            selected,
            _HashedFile(child_rel, payload, identity, info),
            aggregate_bytes=aggregate_bytes,
        )
    rebound = os.fstat(dir_fd)
    if _identity(rebound) != _identity(dir_info):
        raise SourceFreezeError(
            f"source directory identity changed while traversing: {relative}"
        )
    return aggregate_bytes


def _reject_path_list_collisions(
    paths: Iterable[str], *, allow_dotdot: bool = False
) -> None:
    folded: dict[str, str] = {}
    for relative in paths:
        posix = relative.replace("\\", "/")
        key = _fold_key(posix)
        previous = folded.get(key)
        if previous is not None and previous != posix:
            raise SourceFreezeError(f"case-fold collision: {previous} and {posix}")
        folded[key] = posix
        if allow_dotdot:
            parts = pathlib.PurePosixPath(posix).parts
        else:
            parts = _split_relative(posix)
        for part in parts:
            _fold_key(part)


def _reject_configured_name_collisions() -> None:
    _reject_path_list_collisions(SOURCE_PATHS_COMBINED)
    _reject_path_list_collisions(REVIEWED_EXCLUDED_DIRECTORIES)
    _reject_path_list_collisions(GENERATED_DIRECTORY_NAMES)
    _reject_path_list_collisions(EXCLUDED_FILENAMES)
    _reject_path_list_collisions(EXCLUDED_EXTENSIONS)
    _reject_path_list_collisions(SHIPPING_SOURCE_EXTENSIONS)
    aliases = tuple(alias for alias, _target in SOURCE_SYMLINK_ALIASES)
    targets = tuple(target for _alias, target in SOURCE_SYMLINK_ALIASES)
    _reject_path_list_collisions(aliases)
    _reject_path_list_collisions(targets, allow_dotdot=True)


def _reject_configured_path_components(
    repo_fd: int,
    paths: Iterable[str],
    allowed_owners: frozenset[int],
) -> None:
    """Enumerate every fixed path component from the repository root."""

    for relative in paths:
        parts = _split_relative(relative)
        current = repo_fd
        owned: list[int] = []
        rel = ""
        try:
            for index, part in enumerate(parts):
                _reject_casefold_lookup(current, rel, part)
                if index == len(parts) - 1:
                    break
                child_rel = _join_relative(rel, part)
                try:
                    info = os.lstat(part, dir_fd=current)
                except FileNotFoundError:
                    break
                except OSError as suc:
                    raise SourceFreezeError(
                        f"source path could not be inspected: {child_rel}"
                    ) from suc
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    break
                nxt, _info = _bind_directory_fd(
                    current, part, child_rel, allowed_owners
                )
                owned.append(nxt)
                current = nxt
                rel = child_rel
        finally:
            for descriptor in reversed(owned):
                _close_quietly(descriptor)


def _capture_from_repo_fd(
    repo_fd: int,
    paths: Iterable[str],
    excluded: dict[str, str],
    allowed_owners: frozenset[int],
    allow_empty: bool,
) -> _SourceCapture:
    selected: dict[str, _HashedFile] = {}
    aggregate_bytes = 0
    path_list = tuple(paths)
    _reject_configured_name_collisions()
    _reject_path_list_collisions(path_list)
    _reject_path_list_collisions(excluded.values())
    _reject_configured_path_components(repo_fd, path_list, allowed_owners)
    for relative in path_list:
        parts = _split_relative(relative)
        current = repo_fd
        owned: list[int] = []
        rel = ""
        try:
            try:
                root_info = os.lstat(parts[0], dir_fd=repo_fd)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise SourceFreezeError(
                    f"source path could not be inspected: {relative}"
                ) from exc
            if stat.S_ISLNK(root_info.st_mode):
                raise SourceFreezeError(f"Unexpected source symlink: {relative}")
            if _is_special_node(root_info):
                raise SourceFreezeError(
                    f"source path must be a regular file or directory: {relative}"
                )
            for part in parts[:-1]:
                rel = _join_relative(rel, part)
                nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
                owned.append(nxt)
                current = nxt
            leaf = parts[-1]
            leaf_rel = relative
            leaf_info = _lstat_at(current, leaf, leaf_rel)
            if stat.S_ISLNK(leaf_info.st_mode):
                raise SourceFreezeError(f"Unexpected source symlink: {leaf_rel}")
            if _is_special_node(leaf_info):
                raise SourceFreezeError(
                    f"source path must be a regular file or directory: {leaf_rel}"
                )
            if stat.S_ISREG(leaf_info.st_mode):
                if not _is_excluded_file(leaf_rel, excluded):
                    if aggregate_bytes + leaf_info.st_size > MAX_SOURCE_AGGREGATE_BYTES:
                        raise SourceFreezeError(
                            "source aggregate size is outside the accepted bound"
                        )
                    payload, identity, info = _stable_read_regular_file_at(
                        current, leaf, leaf_rel, allowed_owners
                    )
                    aggregate_bytes = _add_selected(
                        selected,
                        _HashedFile(leaf_rel, payload, identity, info),
                        aggregate_bytes=aggregate_bytes,
                    )
                continue
            if not stat.S_ISDIR(leaf_info.st_mode):
                raise SourceFreezeError(
                    f"Required release source root is missing: {relative}"
                )
            _reject_unreviewed_generated_directory(leaf_rel)
            leaf_fd, bound = _bind_directory_fd(
                current, leaf, leaf_rel, allowed_owners
            )
            owned.append(leaf_fd)
            if _reviewed_excluded_directory(leaf_rel) == leaf_rel:
                _inspect_unhashed_tree(leaf_fd, bound, leaf_rel, allowed_owners)
                continue
            aggregate_bytes = _walk_source_directory(
                leaf_fd,
                bound,
                leaf_rel,
                excluded,
                allowed_owners,
                selected,
                aggregate_bytes,
            )
        finally:
            for descriptor in reversed(owned):
                _close_quietly(descriptor)

    files = sorted(
        selected.values(),
        key=lambda item: item.relative.replace("/", "\\").upper(),
    )
    digest = hashlib.sha256()
    latest = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    identities: list[tuple[str, tuple[int, ...]]] = []
    selected_relatives: set[str] = set()
    payloads: list[tuple[str, bytes]] = []
    for hashed in files:
        digest.update(hashed.relative.encode("utf-8") + b"\0")
        digest.update(
            f"mode={hashed.info.st_mode}\0size={hashed.info.st_size}\0".encode("ascii")
        )
        digest.update(hashed.payload)
        digest.update(b"\0")
        latest = max(
            latest,
            dt.datetime.fromtimestamp(hashed.info.st_mtime, tz=dt.timezone.utc),
        )
        identities.append((hashed.relative, hashed.identity))
        selected_relatives.add(hashed.relative)
        payloads.append((hashed.relative, hashed.payload))
    aliases: tuple[tuple[str, str], ...] = ()
    if _binds_source_aliases(paths):
        aliases = _bind_source_symlink_aliases_at(
            repo_fd, selected_relatives, allowed_owners
        )
        for alias, target in aliases:
            digest.update(b"symlink-alias\0")
            digest.update(alias.encode("utf-8") + b"\0")
            digest.update(target.encode("utf-8") + b"\0")
    if not files:
        if allow_empty and not aliases:
            return _empty_tree()
        raise SourceFreezeError("No release source files were found.")
    identity_tuple = tuple(identities)
    return _SourceCapture(
        sha256=digest.hexdigest(),
        file_count=len(files),
        latest_write_utc=latest,
        capture_identity=_capture_identity_digest(identity_tuple, aliases),
        paths=tuple(relative for relative, _identity in identity_tuple),
        identities=identity_tuple,
        aliases=aliases,
        payloads=tuple(payloads),
    )


def _binds_source_aliases(paths: Iterable[str]) -> bool:
    return "lib" in tuple(paths)


def _capture_identity_digest(
    identities: tuple[tuple[str, tuple[int, ...]], ...],
    aliases: tuple[tuple[str, str], ...],
) -> str:
    digest = hashlib.sha256()
    for relative, identity in identities:
        digest.update(relative.encode("utf-8") + b"\0")
        digest.update(b",".join(str(part).encode("ascii") for part in identity) + b"\0")
    for alias, target in aliases:
        digest.update(b"symlink-alias-id\0")
        digest.update(alias.encode("utf-8") + b"\0")
        digest.update(target.encode("utf-8") + b"\0")
    return digest.hexdigest()


def _bind_source_symlink_aliases_at(
    repo_fd: int,
    selected_relatives: set[str],
    allowed_owners: frozenset[int],
) -> tuple[tuple[str, str], ...]:
    alias_fd, _info = _walk_open_dir(
        repo_fd, SOURCE_SYMLINK_ALIAS_DIR, allowed_owners
    )
    try:
        expected_by_name = {
            pathlib.PurePosixPath(alias).name: (alias, target)
            for alias, target in SOURCE_SYMLINK_ALIASES
        }
        names = _list_directory_names(alias_fd, SOURCE_SYMLINK_ALIAS_DIR)
        observed: set[str] = set()
        excluded_names = {_fold_key(item) for item in EXCLUDED_FILENAMES}
        expected_folded = {
            _fold_key(name): name for name in expected_by_name
        }
        for name in names:
            if _fold_key(name) in excluded_names:
                continue
            if name in observed:
                raise SourceFreezeError(
                    f"source symlink alias directory has a duplicate entry: {name}"
                )
            observed.add(name)
            folded = _fold_key(name)
            expected_name = expected_folded.get(folded)
            if expected_name is None:
                raise SourceFreezeError(
                    f"source symlink alias directory has an unexpected entry: {name}"
                )
            if expected_name != name:
                raise SourceFreezeError(
                    f"case-fold collision: {expected_name} and {name}"
                )
            if name not in expected_by_name:
                raise SourceFreezeError(
                    f"source symlink alias directory has an unexpected entry: {name}"
                )
            entry_rel = _join_relative(SOURCE_SYMLINK_ALIAS_DIR, name)
            entry_info = _lstat_at(alias_fd, name, entry_rel)
            if not stat.S_ISLNK(entry_info.st_mode):
                alias, _target = expected_by_name[name]
                raise SourceFreezeError(
                    f"source symlink alias must be a symbolic link: {alias}"
                )
        missing = set(expected_by_name) - observed
        if missing:
            name = sorted(missing)[0]
            raise SourceFreezeError(
                f"source symlink alias is missing: {expected_by_name[name][0]}"
            )

        selected_folded = {_fold_key(item) for item in selected_relatives}
        bound: list[tuple[str, str]] = []
        for alias, expected_target in SOURCE_SYMLINK_ALIASES:
            alias_name = pathlib.PurePosixPath(alias).name
            alias_info = _lstat_at(alias_fd, alias_name, alias)
            if not stat.S_ISLNK(alias_info.st_mode):
                raise SourceFreezeError(
                    f"source symlink alias must be a symbolic link: {alias}"
                )
            try:
                link_text = os.readlink(alias_name, dir_fd=alias_fd)
            except OSError as exc:
                raise SourceFreezeError(
                    f"source symlink alias is unreadable: {alias}"
                ) from exc
            if isinstance(link_text, bytes):
                link_text = os.fsdecode(link_text)
            if os.path.isabs(link_text) or os.path.isabs(expected_target):
                raise SourceFreezeError(
                    f"source symlink alias target must not be absolute: {alias}"
                )
            if link_text != expected_target:
                raise SourceFreezeError(
                    "source symlink alias target is not the exact expected relative "
                    f"path: {alias}"
                )
            alias_parent = str(pathlib.PurePosixPath(alias).parent)
            joined_parts = _split_relative(alias_parent) + _split_link_components(
                link_text, alias
            )
            normalized: list[str] = []
            for part in joined_parts:
                if part == "..":
                    if not normalized:
                        raise SourceFreezeError(
                            f"source symlink alias target escapes the repository: {alias}"
                        )
                    normalized.pop()
                    continue
                if part in {"", "."}:
                    continue
                normalized.append(part)
            target_rel = "/".join(normalized)
            if any(part in {"", ".", ".."} for part in pathlib.PurePosixPath(target_rel).parts):
                raise SourceFreezeError(
                    f"source symlink alias target escapes the repository: {alias}"
                )
            expected_lib_rel = f"lib/{pathlib.PurePosixPath(alias).name}"
            if target_rel != expected_lib_rel:
                raise SourceFreezeError(
                    "source symlink alias target is not the exact expected relative "
                    f"path: {alias}"
                )
            if (
                expected_lib_rel not in selected_relatives
                and expected_lib_rel.casefold() not in selected_folded
            ):
                raise SourceFreezeError(
                    f"source symlink alias target must be a regular file bound by lib: {alias}"
                )
            payload, _identity, target_info = _read_relative_file(
                repo_fd, expected_lib_rel, allowed_owners
            )
            del payload
            if not stat.S_ISREG(target_info.st_mode):
                raise SourceFreezeError(
                    f"source symlink alias target must be a regular file bound by lib: {alias}"
                )
            bound.append((alias, expected_target))
        return tuple(bound)
    finally:
        os.close(alias_fd)


def _bind_source_symlink_aliases(
    repo: pathlib.Path,
    selected_relatives: set[str],
) -> tuple[tuple[str, str], ...]:
    allowed_owners = _allowed_owners(repo)
    repo_fd, _info = _open_repo_dir(repo, allowed_owners)
    try:
        return _bind_source_symlink_aliases_at(
            repo_fd, selected_relatives, allowed_owners
        )
    finally:
        os.close(repo_fd)


def _excluded_map(exclude_relative: Iterable[str]) -> dict[str, str]:
    excluded: dict[str, str] = {}
    for path in exclude_relative:
        posix = path.replace("\\", "/")
        key = _fold_key(posix)
        previous = excluded.get(key)
        if previous is not None and previous != posix:
            raise SourceFreezeError(f"case-fold collision: {previous} and {posix}")
        excluded[key] = posix
    return excluded


def _capture_source_tree(
    repo: pathlib.Path,
    paths: Iterable[str],
    exclude_relative: Iterable[str],
    allowed_owners: frozenset[int],
    allow_empty: bool,
) -> _SourceCapture:
    repo_fd, _info = _open_repo_dir(repo, allowed_owners)
    try:
        return _capture_from_repo_fd(
            repo_fd,
            paths,
            _excluded_map(exclude_relative),
            allowed_owners,
            allow_empty,
        )
    finally:
        os.close(repo_fd)


def _tree_state_at(
    repo_fd: int,
    paths: Iterable[str],
    exclude_relative: Iterable[str],
    allowed_owners: frozenset[int],
    allow_empty: bool,
) -> TreeState:
    excluded = _excluded_map(exclude_relative)
    first = _capture_from_repo_fd(
        repo_fd, paths, excluded, allowed_owners, allow_empty
    )
    hook = _POST_TREE_CAPTURE_HOOK
    if callable(hook):
        hook()
    second = _capture_from_repo_fd(
        repo_fd, paths, excluded, allowed_owners, allow_empty
    )
    if (
        first.sha256 != second.sha256
        or first.file_count != second.file_count
        or first.capture_identity != second.capture_identity
        or first.paths != second.paths
        or first.identities != second.identities
        or first.aliases != second.aliases
    ):
        raise SourceFreezeError("source tree changed during freeze capture")
    return TreeState(
        first.sha256,
        first.file_count,
        first.latest_write_utc,
        first.capture_identity,
    )


def _tree_from_capture(capture: _SourceCapture) -> TreeState:
    return TreeState(
        capture.sha256,
        capture.file_count,
        capture.latest_write_utc,
        capture.capture_identity,
    )


def _merge_named_bytes(
    *groups: tuple[tuple[str, bytes], ...]
) -> tuple[tuple[str, bytes], ...]:
    merged: dict[str, bytes] = {}
    for group in groups:
        for relative, payload in group:
            merged[relative] = payload
    return tuple(sorted(merged.items()))


def _merge_named_identities(
    *groups: tuple[tuple[str, tuple[int, ...]], ...]
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    merged: dict[str, tuple[int, ...]] = {}
    for group in groups:
        for relative, identity in group:
            merged[relative] = identity
    return tuple(sorted(merged.items()))


def _snapshot_release_scopes(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> _ScopeSnapshot:
    app = _capture_from_repo_fd(
        repo_fd, SOURCE_PATHS_APP, {}, allowed_owners, False
    )
    website = _capture_from_repo_fd(
        repo_fd, SOURCE_PATHS_WEBSITE, {}, allowed_owners, True
    )
    immutable_website = _capture_from_repo_fd(
        repo_fd,
        SOURCE_PATHS_WEBSITE,
        _excluded_map(("web/index.html",)),
        allowed_owners,
        True,
    )
    return _ScopeSnapshot(
        app=_tree_from_capture(app),
        website=_tree_from_capture(website),
        immutable_website=_tree_from_capture(immutable_website),
        payloads=_merge_named_bytes(app.payloads, website.payloads),
        identities=_merge_named_identities(app.identities, website.identities),
        aliases=app.aliases,
    )


def _scope_snapshots_match(first: _ScopeSnapshot, second: _ScopeSnapshot) -> bool:
    return (
        _captures_match(first.app, second.app)
        and _captures_match(first.website, second.website)
        and _captures_match(
            first.immutable_website, second.immutable_website
        )
        and first.payloads == second.payloads
        and first.identities == second.identities
        and first.aliases == second.aliases
    )


def _capture_release_scopes_at(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> _ScopeSnapshot:
    first = _snapshot_release_scopes(repo_fd, allowed_owners)
    hook = _POST_TREE_CAPTURE_HOOK
    if callable(hook):
        hook()
    second = _snapshot_release_scopes(repo_fd, allowed_owners)
    if not _scope_snapshots_match(first, second):
        raise SourceFreezeError("source tree changed during freeze capture")
    return first


def _revalidate_release_scopes_at(
    repo: pathlib.Path,
    repo_fd: int,
    opened: os.stat_result,
    allowed_owners: frozenset[int],
    expected: _ScopeSnapshot,
) -> os.stat_result:
    actual = _snapshot_release_scopes(repo_fd, allowed_owners)
    if not _scope_snapshots_match(expected, actual):
        raise SourceFreezeError("source tree changed after freeze hashing")
    return _require_repo_path_identity(repo, repo_fd, opened)


def _snapshot_website_scopes(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> tuple[TreeState, TreeState, tuple[tuple[str, bytes], ...]]:
    website = _capture_from_repo_fd(
        repo_fd, SOURCE_PATHS_WEBSITE, {}, allowed_owners, True
    )
    immutable_website = _capture_from_repo_fd(
        repo_fd,
        SOURCE_PATHS_WEBSITE,
        _excluded_map(("web/index.html",)),
        allowed_owners,
        True,
    )
    return (
        _tree_from_capture(website),
        _tree_from_capture(immutable_website),
        website.payloads,
    )


def _capture_website_scopes_at(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> tuple[TreeState, TreeState, tuple[tuple[str, bytes], ...]]:
    first_website, first_immutable, first_payloads = _snapshot_website_scopes(
        repo_fd, allowed_owners
    )
    hook = _POST_TREE_CAPTURE_HOOK
    if callable(hook):
        hook()
    second_website, second_immutable, second_payloads = _snapshot_website_scopes(
        repo_fd, allowed_owners
    )
    if (
        not _captures_match(first_website, second_website)
        or not _captures_match(first_immutable, second_immutable)
        or first_payloads != second_payloads
    ):
        raise SourceFreezeError("source tree changed during freeze capture")
    return first_website, first_immutable, first_payloads


def tree_state(
    repo: pathlib.Path,
    paths: Iterable[str],
    exclude_relative: Iterable[str] = (),
    allow_empty: bool = False,
) -> TreeState:
    repo = _canonical_repo(pathlib.Path(repo))
    allowed_owners = _allowed_owners(repo)
    repo_fd, opened = _open_repo_dir(repo, allowed_owners)
    try:
        _require_repo_path_identity(repo, repo_fd, opened)
        state = _tree_state_at(
            repo_fd, paths, exclude_relative, allowed_owners, allow_empty
        )
        _require_repo_path_identity(repo, repo_fd, opened)
        return state
    finally:
        os.close(repo_fd)


def _sha256_file(path: pathlib.Path, allowed_owners: frozenset[int] | None = None) -> str:
    owners = allowed_owners
    if owners is None:
        getuid = getattr(os, "getuid", None)
        if getuid is None:
            raise SourceFreezeError("source freeze requires an owner identity")
        owners = frozenset({int(getuid())})
        try:
            owners = frozenset({*owners, int(os.lstat(path).st_uid)})
        except OSError as exc:
            raise SourceFreezeError(
                f"source file could not be opened without following: {path}"
            ) from exc
    payload, _identity, _info = _stable_read_regular_file(path, owners)
    return hashlib.sha256(payload).hexdigest()


def _sha256_relative(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
) -> str:
    payload, _identity, _info = _read_relative_file(
        repo_fd, relative, allowed_owners
    )
    return hashlib.sha256(payload).hexdigest()


def current_website_source_state(repo: pathlib.Path) -> WebsiteSourceState:
    """Fingerprint website staging without consulting the superseded app lock."""

    repo = _canonical_repo(pathlib.Path(repo))
    allowed_owners = _allowed_owners(repo)
    repo_fd, opened = _open_repo_dir(repo, allowed_owners)
    try:
        opened = _require_repo_path_identity(repo, repo_fd, opened)
        website, immutable_website, payloads = _capture_website_scopes_at(
            repo_fd, allowed_owners
        )
        first_git = _bind_production_git_tree(repo)
        _require_production_git_inputs(
            first_git,
            payloads,
            (),
            SOURCE_PATHS_WEBSITE,
        )
        hook = _POST_FINAL_CAPTURE_HOOK
        if callable(hook):
            hook()
        actual_website, actual_immutable, actual_payloads = _snapshot_website_scopes(
            repo_fd, allowed_owners
        )
        if (
            not _captures_match(website, actual_website)
            or not _captures_match(immutable_website, actual_immutable)
            or payloads != actual_payloads
        ):
            raise SourceFreezeError("source tree changed after freeze hashing")
        _require_repo_path_identity(repo, repo_fd, opened)
        second_git = _bind_production_git_tree(repo)
        if first_git != second_git:
            raise SourceFreezeError(GIT_DIRTY_SOURCE)
        _require_production_git_inputs(
            second_git,
            actual_payloads,
            (),
            SOURCE_PATHS_WEBSITE,
        )
        return WebsiteSourceState(
            website_source_fingerprint_sha256=website.sha256,
            website_source_file_count=website.file_count,
            website_latest_write_utc=website.latest_write_utc,
            immutable_website_source_fingerprint_sha256=immutable_website.sha256,
            immutable_website_source_file_count=immutable_website.file_count,
        )
    finally:
        os.close(repo_fd)


def _require_app_source_roots_at(
    repo_fd: int,
    allowed_owners: frozenset[int],
) -> None:
    """Refuse a partial target checkout before claiming its source is frozen."""

    _reject_configured_path_components(repo_fd, SOURCE_PATHS_APP, allowed_owners)
    for relative in SOURCE_PATHS_APP:
        parts = _split_relative(relative)
        current = repo_fd
        owned: list[int] = []
        rel = ""
        try:
            try:
                root_info = os.lstat(parts[0], dir_fd=repo_fd)
            except OSError as exc:
                raise SourceFreezeError(
                    f"Required release source root is missing: {relative}"
                ) from exc
            if stat.S_ISLNK(root_info.st_mode):
                raise SourceFreezeError(
                    f"Required release source root must not be symbolic: {relative}"
                )
            for part in parts[:-1]:
                rel = _join_relative(rel, part)
                nxt, _info = _bind_directory_fd(current, part, rel, allowed_owners)
                owned.append(nxt)
                current = nxt
            leaf_info = _lstat_at(
                current, parts[-1], relative, required_root=True
            )
            if stat.S_ISLNK(leaf_info.st_mode):
                raise SourceFreezeError(
                    f"Required release source root must not be symbolic: {relative}"
                )
            if relative in _FILE_ROOTS:
                if not stat.S_ISREG(leaf_info.st_mode):
                    raise SourceFreezeError(
                        f"Required release source root is missing: {relative}"
                    )
            elif not stat.S_ISDIR(leaf_info.st_mode):
                raise SourceFreezeError(
                    f"Required release source root is missing: {relative}"
                )
        finally:
            for descriptor in reversed(owned):
                _close_quietly(descriptor)


def _require_app_source_roots(repo: pathlib.Path) -> None:
    allowed_owners = _allowed_owners(repo)
    repo_fd, _info = _open_repo_dir(repo, allowed_owners)
    try:
        _require_app_source_roots_at(repo_fd, allowed_owners)
    finally:
        os.close(repo_fd)


def _captures_match(first: TreeState, second: TreeState) -> bool:
    return (
        first.sha256 == second.sha256
        and first.file_count == second.file_count
        and first.capture_identity == second.capture_identity
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    record: dict[str, object] = {}
    for key, value in pairs:
        if key in record:
            raise SourceFreezeError(f"duplicate JSON key: {key}")
        record[key] = value
    return record


def _load_json_object(payload: bytes, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SourceFreezeError(f"{label} is not valid UTF-8.") from exc
    try:
        record = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise SourceFreezeError(f"Frozen source metadata is unreadable: {exc}") from exc
    if type(record) is not dict:
        raise SourceFreezeError(f"{label} must be a JSON object.")
    return record


def _require_exact_keys(
    record: object, expected: frozenset[str], label: str
) -> dict[str, object]:
    if type(record) is not dict or set(record) != set(expected):
        raise SourceFreezeError(f"{label} schema fields are invalid.")
    return record


def _require_bool(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise SourceFreezeError(f"{label} must be a JSON boolean.")
    return value


def _require_int(value: object, label: str) -> int:
    if type(value) is not int:
        raise SourceFreezeError(f"{label} must be a JSON integer.")
    return value


def _require_source_count(
    value: object, label: str, *, allow_zero: bool = False
) -> int:
    count = _require_int(value, label)
    minimum = 0 if allow_zero else 1
    if count < minimum or count > MAX_SOURCE_FILE_COUNT:
        raise SourceFreezeError(f"{label} is outside the accepted bound")
    return count


def _require_str(value: object, label: str) -> str:
    if type(value) is not str:
        raise SourceFreezeError(f"{label} must be a JSON string.")
    if not value:
        raise SourceFreezeError(f"{label} must be a non-empty JSON string.")
    return value


def _require_sha256(value: object, label: str) -> str:
    digest = _require_str(value, label)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SourceFreezeError(f"{label} is not a SHA-256 digest.")
    return digest


def _require_optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _require_sha256(value, label)


def _require_issuance(value: object, label: str) -> str:
    issuance = _require_str(value, label)
    if ISSUANCE_ID.fullmatch(issuance) is None:
        raise SourceFreezeError(f"{label} must be a 32-hex issuance identity.")
    return issuance


def _parse_timestamp(value: object, label: str) -> dt.datetime:
    text = _require_str(value, label)
    if not text.endswith("Z"):
        raise SourceFreezeError(f"{label} timestamp is invalid.")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as suc:
        raise SourceFreezeError(f"{label} timestamp is invalid.") from suc
    if parsed.tzinfo is None:
        raise SourceFreezeError(f"{label} timestamp is invalid.")
    return parsed.astimezone(dt.timezone.utc)


def _require_str_list(value: object, label: str) -> list[str]:
    if type(value) is not list:
        raise SourceFreezeError(f"{label} must be a JSON array.")
    parsed: list[str] = []
    for item in value:
        parsed.append(_require_str(item, label))
    return parsed


def _release_identity_at(
    repo_fd: int, allowed_owners: frozenset[int]
) -> tuple[str, str]:
    payload, _identity, _info = _read_relative_file(
        repo_fd, "pubspec.yaml", allowed_owners
    )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as suc:
        raise SourceFreezeError("pubspec.yaml is not valid UTF-8.") from suc
    declarations = list(_VERSION_LINE.finditer(text))
    if len(declarations) != 1:
        raise SourceFreezeError(
            "pubspec.yaml must contain exactly one version declaration."
        )
    match = _SEMVER_PLUS_BUILD.fullmatch(declarations[0].group(0))
    if match is None:
        raise SourceFreezeError("pubspec.yaml must contain version: <semver>+<integer>.")
    return match.group(1), match.group(2)


def _release_identity(repo: pathlib.Path, allowed_owners: frozenset[int]) -> tuple[str, str]:
    repo_fd, _info = _open_repo_dir(repo, allowed_owners)
    try:
        return _release_identity_at(repo_fd, allowed_owners)
    finally:
        os.close(repo_fd)


def _read_json_relative(
    repo_fd: int,
    relative: str,
    allowed_owners: frozenset[int],
    label: str,
    *,
    missing_message: str | None = None,
) -> tuple[dict[str, object], str]:
    parts = _split_relative(relative)
    current = repo_fd
    owned: list[int] = []
    rel = ""
    try:
        try:
            os.lstat(parts[0], dir_fd=repo_fd)
        except FileNotFoundError as exc:
            raise SourceFreezeError(
                missing_message or f"Frozen source metadata is unreadable: {relative}"
            ) from exc
        except OSError as exc:
            raise SourceFreezeError(
                missing_message or f"Frozen source metadata is unreadable: {relative}"
            ) from exc
        for part in parts[:-1]:
            rel = _join_relative(rel, part)
            try:
                nxt, _info = _bind_directory_fd(
                    current, part, rel, allowed_owners
                )
            except SourceFreezeError as exc:
                message = str(exc)
                if "could not be inspected" in message or "could not be opened" in message:
                    raise SourceFreezeError(
                        missing_message
                        or f"Frozen source metadata is unreadable: {relative}"
                    ) from exc
                raise
            owned.append(nxt)
            current = nxt
        try:
            payload, _identity, _info = _stable_read_regular_file_at(
                current,
                parts[-1],
                relative,
                allowed_owners,
                max_bytes=MAX_SOURCE_JSON_BYTES,
            )
        except SourceFreezeError as exc:
            message = str(exc)
            if missing_message and (
                "could not be inspected" in message
                or "could not be opened" in message
                or "must be a regular non-symlink file" in message
            ):
                raise SourceFreezeError(missing_message) from exc
            raise
        return (
            _load_json_object(payload, label),
            hashlib.sha256(payload).hexdigest(),
        )
    finally:
        for descriptor in reversed(owned):
            _close_quietly(descriptor)


def _require_transaction_issuance(
    record: dict[str, object],
    label: str,
    issuance: _IssuanceBinding,
) -> None:
    if (
        _require_issuance(record["issuance_id"], f"{label} issuance_id")
        != issuance.issuance_id
    ):
        raise SourceFreezeError(
            f"{label} issuance_id does not match the {TRUST_PIN_LABEL} issuance_id"
        )
    created_text = _require_str(record["created_utc"], f"{label} created_utc")
    _parse_timestamp(created_text, f"{label} created_utc")
    if created_text != issuance.created_utc:
        raise SourceFreezeError(
            f"{label} created_utc does not match the {TRUST_PIN_LABEL} created_utc"
        )


def _parse_scope(
    record: dict[str, object],
    release: str,
    frozen_fingerprint: str,
    issuance: _IssuanceBinding,
) -> None:
    scope = _require_exact_keys(record, SCOPE_KEYS, "SCOPE_FREEZE.json")
    if _require_int(scope["schema_version"], "SCOPE_FREEZE.json schema_version") != 1:
        raise SourceFreezeError(
            "SCOPE_FREEZE.json has an unsupported schema or contract."
        )
    if _require_str(scope["contract"], "SCOPE_FREEZE.json contract") != SCOPE_CONTRACT:
        raise SourceFreezeError(
            "SCOPE_FREEZE.json has an unsupported schema or contract."
        )
    if _require_str(scope["release"], "SCOPE_FREEZE.json release") != release:
        raise SourceFreezeError("Scope-freeze release does not match pubspec.yaml.")
    if _require_bool(scope["scope_frozen"], "SCOPE_FREEZE.json scope_frozen") is not True:
        raise SourceFreezeError("Scope-freeze identity does not match the app source lock.")
    if (
        _require_bool(scope["publication_locked"], "SCOPE_FREEZE.json publication_locked")
        is not True
    ):
        raise SourceFreezeError("Scope-freeze identity does not match the app source lock.")
    fingerprint = _require_sha256(
        scope["source_fingerprint_sha256"],
        "SCOPE_FREEZE.json source_fingerprint_sha256",
    )
    if fingerprint != frozen_fingerprint:
        raise SourceFreezeError("Scope-freeze identity does not match the app source lock.")
    _require_transaction_issuance(scope, "SCOPE_FREEZE.json", issuance)


def _parse_lock(
    record: dict[str, object], release: str, issuance: _IssuanceBinding
) -> dict[str, object]:
    lock = _require_exact_keys(record, LOCK_KEYS, "APP_SOURCE_LOCK.json")
    if _require_int(lock["schema_version"], "APP_SOURCE_LOCK.json schema_version") != 1:
        raise SourceFreezeError(
            "APP_SOURCE_LOCK.json has an unsupported schema or contract."
        )
    if _require_str(lock["contract"], "APP_SOURCE_LOCK.json contract") != LOCK_CONTRACT:
        raise SourceFreezeError(
            "APP_SOURCE_LOCK.json has an unsupported schema or contract."
        )
    if _require_str(lock["release"], "APP_SOURCE_LOCK.json release") != release:
        raise SourceFreezeError("App source lock release does not match pubspec.yaml.")
    if _require_bool(lock["scope_frozen"], "APP_SOURCE_LOCK.json scope_frozen") is not True:
        raise SourceFreezeError("App source lock is not fail-closed for publication.")
    if (
        _require_bool(lock["publication_locked"], "APP_SOURCE_LOCK.json publication_locked")
        is not True
    ):
        raise SourceFreezeError("App source lock is not fail-closed for publication.")
    if (
        _require_str(lock["app_source_contract"], "APP_SOURCE_LOCK.json app_source_contract")
        != APP_SOURCE_CONTRACT
    ):
        raise SourceFreezeError("App source lock has the wrong app-source contract.")
    if (
        _require_str(
            lock["website_source_contract"],
            "APP_SOURCE_LOCK.json website_source_contract",
        )
        != WEBSITE_SOURCE_CONTRACT
    ):
        raise SourceFreezeError("App source lock has the wrong website-source contract.")
    if (
        _require_bool(
            lock["website_staging_allowed_after_scope_freeze"],
            "APP_SOURCE_LOCK.json website_staging_allowed_after_scope_freeze",
        )
        is not True
    ):
        raise SourceFreezeError(
            "Post-freeze website staging is not explicitly authorized by the lock."
        )
    mutable_paths = _require_str_list(
        lock["website_mutable_paths_after_scope_freeze"],
        "APP_SOURCE_LOCK.json website_mutable_paths_after_scope_freeze",
    )
    if mutable_paths != ["web/index.html"]:
        raise SourceFreezeError(
            "Post-freeze website mutable paths are not exactly web/index.html."
        )
    _require_sha256(
        lock["scope_freeze_sha256"], "APP_SOURCE_LOCK.json scope_freeze_sha256"
    )
    frozen_fingerprint = _require_sha256(
        lock["frozen_combined_source_fingerprint_sha256"],
        "APP_SOURCE_LOCK.json frozen_combined_source_fingerprint_sha256",
    )
    frozen_count = _require_source_count(
        lock["frozen_combined_source_file_count"],
        "APP_SOURCE_LOCK.json frozen_combined_source_file_count",
    )
    del frozen_count
    _require_sha256(
        lock["app_source_fingerprint_sha256"],
        "APP_SOURCE_LOCK.json app_source_fingerprint_sha256",
    )
    _require_source_count(
        lock["app_source_file_count"], "APP_SOURCE_LOCK.json app_source_file_count"
    )
    _require_sha256(
        lock["website_source_fingerprint_sha256_at_freeze"],
        "APP_SOURCE_LOCK.json website_source_fingerprint_sha256_at_freeze",
    )
    _require_source_count(
        lock["website_source_file_count_at_freeze"],
        "APP_SOURCE_LOCK.json website_source_file_count_at_freeze",
        allow_zero=True,
    )
    _require_sha256(
        lock["website_index_sha256_at_freeze"],
        "APP_SOURCE_LOCK.json website_index_sha256_at_freeze",
    )
    _require_sha256(
        lock["immutable_website_source_fingerprint_sha256_at_freeze"],
        "APP_SOURCE_LOCK.json immutable_website_source_fingerprint_sha256_at_freeze",
    )
    _require_source_count(
        lock["immutable_website_source_file_count_at_freeze"],
        "APP_SOURCE_LOCK.json immutable_website_source_file_count_at_freeze",
        allow_zero=True,
    )
    _require_transaction_issuance(lock, "APP_SOURCE_LOCK.json", issuance)
    del frozen_fingerprint
    return lock


def _parse_stage(
    record: dict[str, object],
    expected: dict[str, object],
    issuance: _IssuanceBinding,
) -> None:
    stage = _require_exact_keys(record, STAGE_KEYS, "WEBSITE_STAGE.json")
    if _require_int(stage["schema_version"], "WEBSITE_STAGE.json schema_version") != 1:
        raise SourceFreezeError(
            "Website stage attestation field schema_version does not match current frozen state."
        )
    if (
        _require_str(stage["contract"], "WEBSITE_STAGE.json contract")
        != WEBSITE_STAGE_CONTRACT
    ):
        raise SourceFreezeError(
            "Website stage attestation field contract does not match current frozen state."
        )
    _require_str(stage["release"], "WEBSITE_STAGE.json release")
    _require_sha256(
        stage["boundary_lock_sha256"], "WEBSITE_STAGE.json boundary_lock_sha256"
    )
    _require_sha256(
        stage["app_source_fingerprint_sha256"],
        "WEBSITE_STAGE.json app_source_fingerprint_sha256",
    )
    _require_source_count(
        stage["app_source_file_count"], "WEBSITE_STAGE.json app_source_file_count"
    )
    _require_sha256(
        stage["immutable_website_source_fingerprint_sha256"],
        "WEBSITE_STAGE.json immutable_website_source_fingerprint_sha256",
    )
    _require_source_count(
        stage["immutable_website_source_file_count"],
        "WEBSITE_STAGE.json immutable_website_source_file_count",
        allow_zero=True,
    )
    _require_sha256(
        stage["website_index_sha256_before"],
        "WEBSITE_STAGE.json website_index_sha256_before",
    )
    _require_sha256(
        stage["website_index_sha256_after"],
        "WEBSITE_STAGE.json website_index_sha256_after",
    )
    _require_sha256(
        stage["staged_website_source_fingerprint_sha256"],
        "WEBSITE_STAGE.json staged_website_source_fingerprint_sha256",
    )
    _require_source_count(
        stage["staged_website_source_file_count"],
        "WEBSITE_STAGE.json staged_website_source_file_count",
        allow_zero=True,
    )
    _require_str_list(stage["mutated_paths"], "WEBSITE_STAGE.json mutated_paths")
    if _require_bool(
        stage["publication_authorized"], "WEBSITE_STAGE.json publication_authorized"
    ):
        raise SourceFreezeError(
            "Website stage attestation field publication_authorized does not match current frozen state."
        )
    _require_transaction_issuance(stage, "WEBSITE_STAGE.json", issuance)
    for field, value in expected.items():
        if stage.get(field) != value:
            raise SourceFreezeError(
                f"Website stage attestation field {field} does not match current frozen state."
            )


def _external_trust_path() -> pathlib.Path:
    override = _EXTERNAL_TRUST_PATH
    if override is not None:
        path = pathlib.Path(override)
        if not path.is_absolute():
            raise SourceFreezeError(f"{TRUST_PIN_LABEL} path must be absolute: {path}")
        return path
    return pathlib.Path(__file__).resolve().with_name(EXTERNAL_TRUST_NAME)


def _trust_inside_artifacts(trust_path: pathlib.Path, candidate: pathlib.Path) -> bool:
    try:
        relative = trust_path.resolve().relative_to(candidate.resolve())
    except ValueError:
        return False
    posix = relative.as_posix()
    return posix == ".artifacts" or posix.startswith(".artifacts/")


def _bind_issuance_file(
    path: pathlib.Path,
) -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
    """Read the committed pin record: a single-link regular file, not a
    symlink or special node, and not group/world-writable."""

    if not path.is_absolute():
        raise SourceFreezeError(f"{TRUST_PIN_LABEL} path must be absolute: {path}")
    changed = f"{TRUST_PIN_LABEL} changed while it was read: {path}"
    parent = path.parent
    try:
        parent_before = os.lstat(parent)
        file_before = os.lstat(path)
    except OSError as suc:
        raise SourceFreezeError(
            f"{TRUST_PIN_MISSING} {path} is absent or unreadable; {TRUST_PIN_HOW_TO}"
        ) from suc
    if stat.S_ISLNK(parent_before.st_mode) or not stat.S_ISDIR(parent_before.st_mode):
        raise SourceFreezeError(
            f"{TRUST_PIN_LABEL} directory must be a real directory: {parent}"
        )
    if (
        stat.S_ISLNK(file_before.st_mode)
        or not stat.S_ISREG(file_before.st_mode)
        or _is_special_node(file_before)
    ):
        raise SourceFreezeError(
            f"{TRUST_PIN_LABEL} must be a regular non-symlink file: {path}"
        )
    if _is_group_or_world_writable(file_before):
        raise SourceFreezeError(f"group/world-writable {TRUST_PIN_LABEL}: {path}")
    if file_before.st_nlink != 1:
        raise SourceFreezeError(f"{TRUST_PIN_LABEL} must have link count 1: {path}")
    parent_fd = None
    try:
        parent_fd = os.open(parent, _directory_flags())
        parent_opened = os.fstat(parent_fd)
        if (parent_opened.st_dev, parent_opened.st_ino) != (
            parent_before.st_dev,
            parent_before.st_ino,
        ):
            raise SourceFreezeError(changed)
        parent_identity = _identity(parent_opened)
        payload, identity, info = _stable_read_regular_file_at(
            parent_fd,
            path.name,
            path.name,
            frozenset({int(file_before.st_uid)}),
            max_bytes=MAX_TRUST_BYTES,
        )
        del info
        if identity != _identity(file_before):
            raise SourceFreezeError(changed)
        parent_after = os.fstat(parent_fd)
        if _identity(parent_after) != parent_identity:
            raise SourceFreezeError(changed)
        return payload, identity, parent_identity
    except SourceFreezeError:
        raise
    except OSError as suc:
        raise SourceFreezeError(f"{TRUST_PIN_LABEL} could not be read: {path}") from suc
    finally:
        _close_quietly(parent_fd)


def _parse_external_issuance(
    record: dict[str, object],
) -> tuple[str, str, str, str, str, str | None, str, str, str]:
    missing = sorted(EXTERNAL_TRUST_KEYS - set(record))
    if missing:
        raise SourceFreezeError(
            f"{TRUST_PIN_MISSING} lacks {', '.join(missing)}; {TRUST_PIN_HOW_TO}"
        )
    trust = _require_exact_keys(record, EXTERNAL_TRUST_KEYS, TRUST_PIN_LABEL)
    if (
        _require_int(trust["schema_version"], "source-freeze issuance schema_version")
        != 1
    ):
        raise SourceFreezeError(f"{TRUST_PIN_LABEL} schema_version must be 1")
    if (
        _require_str(trust["contract"], "source-freeze issuance contract")
        != EXTERNAL_TRUST_CONTRACT
    ):
        raise SourceFreezeError(
            f"{TRUST_PIN_LABEL} contract must be {EXTERNAL_TRUST_CONTRACT}"
        )
    if (
        _require_bool(trust["authenticated"], "source-freeze issuance authenticated")
        is not True
    ):
        raise SourceFreezeError(f"{TRUST_PIN_LABEL} authenticated must be true")
    if (
        _require_str(trust["issuer"], "source-freeze issuance issuer")
        != EXTERNAL_TRUST_ISSUER
    ):
        raise SourceFreezeError(
            f"{TRUST_PIN_LABEL} issuer must be {EXTERNAL_TRUST_ISSUER}"
        )
    release = _require_str(trust["release"], "source-freeze issuance release")
    issuance_id = _require_issuance(
        trust["issuance_id"], "source-freeze issuance issuance_id"
    )
    created_text = _require_str(
        trust["created_utc"], "source-freeze issuance created_utc"
    )
    _parse_timestamp(created_text, "source-freeze issuance created_utc")
    lock_digest = _require_sha256(
        trust["app_source_lock_sha256"],
        "source-freeze issuance app_source_lock_sha256",
    )
    scope_digest = _require_sha256(
        trust["scope_freeze_sha256"], "source-freeze issuance scope_freeze_sha256"
    )
    stage_digest = _require_optional_sha256(
        trust["website_stage_sha256"], "source-freeze issuance website_stage_sha256"
    )
    controller_digest = _require_sha256(
        trust["controller_sha256"], "source-freeze issuance controller_sha256"
    )
    test_digest = _require_sha256(
        trust["test_sha256"], "source-freeze issuance test_sha256"
    )
    manifest_digest = _require_sha256(
        trust["manifest_sha256"], "source-freeze issuance manifest_sha256"
    )
    return (
        issuance_id,
        created_text,
        release,
        lock_digest,
        scope_digest,
        stage_digest,
        controller_digest,
        test_digest,
        manifest_digest,
    )


def _bind_external_issuance(candidate: pathlib.Path) -> _IssuanceBinding:
    path = _external_trust_path()
    if _trust_inside_artifacts(path, candidate):
        raise SourceFreezeError(
            f"{TRUST_PIN_LABEL} must not be inside the candidate .artifacts: {path}"
        )
    payload, identity, parent_identity = _bind_issuance_file(path)
    record = _load_json_object(payload, TRUST_PIN_LABEL)
    (
        issuance_id,
        created_utc,
        release,
        lock_digest,
        scope_digest,
        stage_digest,
        controller_digest,
        test_digest,
        manifest_digest,
    ) = _parse_external_issuance(record)
    return _IssuanceBinding(
        path=str(path),
        record=record,
        digest=hashlib.sha256(payload).hexdigest(),
        identity=identity,
        parent_identity=parent_identity,
        issuance_id=issuance_id,
        created_utc=created_utc,
        release=release,
        app_source_lock_sha256=lock_digest,
        scope_freeze_sha256=scope_digest,
        website_stage_sha256=stage_digest,
        controller_sha256=controller_digest,
        test_sha256=test_digest,
        manifest_sha256=manifest_digest,
    )


def _rebind_external_issuance(expected: _IssuanceBinding) -> None:
    payload, identity, parent_identity = _bind_issuance_file(
        pathlib.Path(expected.path)
    )
    digest = hashlib.sha256(payload).hexdigest()
    if (
        digest != expected.digest
        or identity != expected.identity
        or parent_identity != expected.parent_identity
    ):
        raise SourceFreezeError(RECEIPT_REBIND_CHANGED)


def isolated_fixture_mode_active() -> bool:
    return _FIXTURE_MODE is True


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in _GIT_UNSET_VARS:
        env.pop(name, None)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_PAGER"] = "cat"
    env["LC_ALL"] = "C"
    return env


def _git_blob_oid(payload: bytes, object_format: str) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    body = header + payload
    if object_format == "sha1":
        return hashlib.sha1(body, usedforsecurity=False).hexdigest()
    if object_format == "sha256":
        return hashlib.sha256(body).hexdigest()
    raise SourceFreezeError("unsupported Git object format for release freeze")


def _git_metadata_kind(repo: pathlib.Path) -> str | None:
    git_dir = repo / ".git"
    try:
        info = os.lstat(git_dir)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SourceFreezeError(GIT_REQUIRED) from exc
    if stat.S_ISLNK(info.st_mode) or _is_special_node(info):
        raise SourceFreezeError(
            "Git metadata uses a symlink, junction, or special node"
        )
    if stat.S_ISDIR(info.st_mode):
        return "dir"
    if stat.S_ISREG(info.st_mode):
        return "file"
    raise SourceFreezeError("Git metadata must be a regular directory or gitfile")


def _run_git(repo: pathlib.Path, *args: str, check: bool = True) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_env(),
            check=False,
            timeout=_GIT_TIMEOUT_SEC,
        )
    except FileNotFoundError as suc:
        raise SourceFreezeError(GIT_REQUIRED) from suc
    except subprocess.TimeoutExpired as suc:
        raise SourceFreezeError("Git command timed out during release freeze") from suc
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise SourceFreezeError(
            f"Git command failed during release freeze: {detail or 'no diagnostic'}"
        )
    return completed.stdout


def _parse_ls_tree_z(payload: bytes) -> dict[str, tuple[str, str, str]]:
    blobs: dict[str, tuple[str, str, str]] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        meta, sep, path_bytes = raw.partition(b"\t")
        if not sep:
            raise SourceFreezeError("Git ls-tree output is invalid")
        parts = meta.split(b" ")
        if len(parts) != 3:
            raise SourceFreezeError("Git ls-tree output is invalid")
        try:
            mode = parts[0].decode("ascii")
            kind = parts[1].decode("ascii")
            oid = parts[2].decode("ascii")
        except UnicodeDecodeError as suc:
            raise SourceFreezeError("Git ls-tree output is invalid") from suc
        if not re.fullmatch(r"[0-7]{6}", mode) or not re.fullmatch(
            r"[0-9a-f]{40,64}", oid
        ):
            raise SourceFreezeError("Git ls-tree output is invalid")
        path = path_bytes.decode("utf-8", "surrogateescape").replace("\\", "/")
        if not path or path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
            raise SourceFreezeError("Git ls-tree path escapes the repository")
        blobs[path] = (mode, kind, oid)
    return blobs


def _parse_ls_files_stage_z(payload: bytes) -> dict[str, tuple[str, str, str]]:
    blobs: dict[str, tuple[str, str, str]] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        meta, sep, path_bytes = raw.partition(b"\t")
        if not sep:
            raise SourceFreezeError("Git index output is invalid")
        parts = meta.split(b" ")
        if len(parts) != 3:
            raise SourceFreezeError("Git index output is invalid")
        try:
            mode = parts[0].decode("ascii")
            oid = parts[1].decode("ascii")
            stage = parts[2].decode("ascii")
        except UnicodeDecodeError as suc:
            raise SourceFreezeError("Git index output is invalid") from suc
        if stage != "0":
            raise SourceFreezeError(GIT_INDEX_WORKTREE_SPLIT)
        if not re.fullmatch(r"[0-7]{6}", mode) or not re.fullmatch(
            r"[0-9a-f]{40,64}", oid
        ):
            raise SourceFreezeError("Git index output is invalid")
        path = path_bytes.decode("utf-8", "surrogateescape").replace("\\", "/")
        if not path or path.startswith("/") or ".." in pathlib.PurePosixPath(path).parts:
            raise SourceFreezeError("Git index path escapes the repository")
        blobs[path] = (mode, "blob" if mode != "160000" else "commit", oid)
    return blobs


def _parse_ls_files_verbose_z(payload: bytes) -> dict[str, str]:
    tags: dict[str, str] = {}
    for raw in payload.split(b"\0"):
        if not raw:
            continue
        if len(raw) < 3 or raw[1:2] != b" ":
            raise SourceFreezeError("Git ls-files -v output is invalid")
        tag = chr(raw[0])
        path = raw[2:].decode("utf-8", "surrogateescape").replace("\\", "/")
        tags[path] = tag
    return tags


def _parse_porcelain_z(payload: bytes) -> tuple[tuple[str, str], ...]:
    entries: list[tuple[str, str]] = []
    index = 0
    while index < len(payload):
        if payload[index : index + 1] == b"\0":
            index += 1
            continue
        if index + 3 > len(payload) or payload[index + 2 : index + 3] != b" ":
            raise SourceFreezeError("Git status output is invalid")
        try:
            xy = payload[index : index + 2].decode("ascii")
        except UnicodeDecodeError as suc:
            raise SourceFreezeError("Git status output is invalid") from suc
        index += 3
        nul = payload.find(b"\0", index)
        if nul < 0:
            raise SourceFreezeError("Git status output is invalid")
        path = payload[index:nul].decode("utf-8", "surrogateescape").replace("\\", "/")
        index = nul + 1
        if "R" in xy or "C" in xy:
            nul = payload.find(b"\0", index)
            if nul < 0:
                raise SourceFreezeError("Git status output is invalid")
            dest = payload[index:nul].decode("utf-8", "surrogateescape").replace(
                "\\", "/"
            )
            index = nul + 1
            entries.append((xy, path))
            entries.append((xy, dest))
            continue
        entries.append((xy, path))
    return tuple(entries)


@dataclasses.dataclass(frozen=True)
class _GitTreeState:
    object_format: str
    head: str
    blobs: dict[str, tuple[str, str, str]]
    index: dict[str, tuple[str, str, str]]
    flags: dict[str, str]
    porcelain: tuple[tuple[str, str], ...]


def _load_git_tree_state(repo: pathlib.Path) -> _GitTreeState:
    toplevel = _run_git(repo, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    repo_real = os.path.realpath(repo)
    top_real = os.path.realpath(toplevel)
    if top_real != repo_real:
        raise SourceFreezeError("production freeze must run from the exact Git worktree")
    head = _run_git(repo, "rev-parse", "--verify", "HEAD").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", head):
        raise SourceFreezeError("Git HEAD revision is invalid")
    fmt_out = _run_git(
        repo, "rev-parse", "--show-object-format", check=False
    ).decode("ascii", errors="replace").strip()
    object_format = fmt_out if fmt_out in {"sha1", "sha256"} else "sha1"
    blobs = _parse_ls_tree_z(
        _run_git(repo, "ls-tree", "-r", "--full-tree", "-z", "HEAD")
    )
    index = _parse_ls_files_stage_z(_run_git(repo, "ls-files", "--stage", "-z"))
    flags = _parse_ls_files_verbose_z(_run_git(repo, "ls-files", "-v", "-z"))
    porcelain = _parse_porcelain_z(
        _run_git(
            repo,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        )
    )
    return _GitTreeState(
        object_format=object_format,
        head=head,
        blobs=blobs,
        index=index,
        flags=flags,
        porcelain=porcelain,
    )


def _bind_production_git_tree(repo: pathlib.Path) -> _GitTreeState | None:
    if isolated_fixture_mode_active():
        return None
    kind = _git_metadata_kind(repo)
    if kind is None:
        if _PRODUCTION_REQUIRED:
            raise SourceFreezeError(GIT_REQUIRED)
        return None
    return _load_git_tree_state(repo)


def _porcelain_by_path(tree: _GitTreeState) -> dict[str, str]:
    latest: dict[str, str] = {}
    for xy, path in tree.porcelain:
        latest[path] = xy
    return latest


def _path_in_roots(relative: str, roots: Iterable[str]) -> bool:
    posix = relative.replace("\\", "/")
    for root in roots:
        root_posix = root.replace("\\", "/")
        if posix == root_posix or posix.startswith(root_posix + "/"):
            return True
    return False


def _excluded_from_git_denominator(relative: str) -> bool:
    if _reviewed_excluded_directory(relative) is not None:
        return True
    try:
        return _is_excluded_file(relative, {})
    except SourceFreezeError:
        return False


def _normalized_symlink_target(alias: str, target: str) -> str:
    parent = str(pathlib.PurePosixPath(alias).parent)
    joined = _split_relative(parent) + _split_link_components(target, alias)
    normalized: list[str] = []
    for part in joined:
        if part == "..":
            if not normalized:
                raise SourceFreezeError(
                    f"source symlink alias target escapes the repository: {alias}"
                )
            normalized.pop()
            continue
        if part in {"", "."}:
            continue
        normalized.append(part)
    return "/".join(normalized)


def _require_blob_matches_worktree(
    relative: str,
    payload: bytes,
    identity: tuple[int, ...] | None,
    record: tuple[str, str, str],
    object_format: str,
) -> None:
    mode, kind, oid = record
    if mode == "120000" or kind == "commit":
        raise SourceFreezeError(f"{GIT_SYMLINK_INPUT}: {relative}")
    if mode not in {"100644", "100755"} or kind != "blob":
        raise SourceFreezeError(
            f"release source is not a regular tracked Git blob: {relative}"
        )
    actual = _git_blob_oid(payload, object_format)
    if actual != oid:
        git_lf = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        if git_lf != payload and _git_blob_oid(git_lf, object_format) == oid:
            raise SourceFreezeError(f"{GIT_CRLF_DRIFT}: {relative}")
        if b"\r" in payload:
            raise SourceFreezeError(f"{GIT_CRLF_DRIFT}: {relative}")
        raise SourceFreezeError(
            f"release source does not match the exact tracked Git tree: {relative}"
        )
    if identity is not None:
        st_mode = int(identity[2])
        executable = bool(st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if executable != (mode == "100755"):
            raise SourceFreezeError(f"{GIT_METADATA_DRIFT}: {relative}")


def _require_production_git_inputs(
    tree: _GitTreeState | None,
    payloads: tuple[tuple[str, bytes], ...],
    aliases: tuple[tuple[str, str], ...],
    roots: Iterable[str],
    identities: tuple[tuple[str, tuple[int, ...]], ...] = (),
) -> None:
    if tree is None:
        return
    selected = dict(payloads)
    identity_by_path = dict(identities)
    porcelain = _porcelain_by_path(tree)
    explained: set[str] = set()
    root_list = tuple(roots)
    allowlist = frozenset(INTENTIONALLY_UNTRACKED_SOURCE)
    alias_paths = {alias for alias, _target in aliases}
    for relative, payload in selected.items():
        explained.add(relative)
        xy = porcelain.get(relative, "")
        flag = tree.flags.get(relative, "")
        if flag and flag not in {"H", "C"}:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        in_head = relative in tree.blobs
        in_index = relative in tree.index
        if relative in allowlist:
            if in_head or in_index:
                raise SourceFreezeError(
                    f"intentionally untracked source is tracked: {relative}"
                )
            if xy not in {"??", ""}:
                raise SourceFreezeError(f"{GIT_UNTRACKED_INPUT}: {relative}")
            continue
        if not in_head:
            if xy[:1] == "A" or (in_index and not in_head):
                raise SourceFreezeError(f"{GIT_STAGED_ONLY_INPUT}: {relative}")
            raise SourceFreezeError(f"{GIT_UNTRACKED_INPUT}: {relative}")
        head_record = tree.blobs[relative]
        index_record = tree.index.get(relative)
        if index_record is None:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        if index_record != head_record:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        _require_blob_matches_worktree(
            relative,
            payload,
            identity_by_path.get(relative),
            head_record,
            tree.object_format,
        )
        if xy and (xy[0] in "MTDARC" or xy[1] in "MTD"):
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
    for alias, target in aliases:
        explained.add(alias)
        record = tree.blobs.get(alias)
        if record is None:
            xy = porcelain.get(alias, "")
            if xy[:1] == "A":
                raise SourceFreezeError(f"{GIT_STAGED_ONLY_INPUT}: {alias}")
            raise SourceFreezeError(f"{GIT_UNTRACKED_INPUT}: {alias}")
        mode, kind, oid = record
        if mode != "120000" or kind != "blob":
            raise SourceFreezeError(f"{GIT_SYMLINK_INPUT}: {alias}")
        expected = _git_blob_oid(target.encode("utf-8"), tree.object_format)
        if oid != expected:
            raise SourceFreezeError(
                f"release source does not match the exact tracked Git tree: {alias}"
            )
        index_record = tree.index.get(alias)
        if index_record != record:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {alias}")
        resolved = _normalized_symlink_target(alias, target)
        target_record = tree.blobs.get(resolved)
        if (
            target_record is None
            or target_record[0] not in {"100644", "100755"}
            or target_record[1] != "blob"
        ):
            raise SourceFreezeError(
                f"symlink alias target is not in the exact tracked Git tree: {alias}"
            )
    for relative, record in tree.blobs.items():
        if relative in explained or relative in alias_paths:
            continue
        if not _path_in_roots(relative, root_list):
            continue
        if _excluded_from_git_denominator(relative):
            continue
        if record[0] == "120000":
            continue
        raise SourceFreezeError(
            f"tracked Git source is missing from the freeze denominator: {relative}"
        )
    for relative in allowlist:
        if relative not in selected:
            raise SourceFreezeError(
                f"intentionally untracked source is missing: {relative}"
            )
        explained.add(relative)
    leftover = [path for _xy, path in tree.porcelain if path not in explained]
    if leftover:
        raise SourceFreezeError(f"{GIT_DIRTY_SOURCE}: {leftover[0]}")


def _executing_control_paths() -> tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    tools_dir = pathlib.Path(__file__).resolve().parent
    controller = tools_dir / CONTROLLER_NAME
    test_path = tools_dir / TEST_NAME
    manifest = tools_dir / TOOLCHAIN_PIN_NAME
    if controller.name != CONTROLLER_NAME or pathlib.Path(__file__).resolve() != controller:
        raise SourceFreezeError(PRODUCER_INJECTION)
    return controller, test_path, manifest


def _stable_hash_control_file(path: pathlib.Path, label: str) -> tuple[str, bytes]:
    owners = _allowed_owners(path.parent)
    payload, _identity, info = _stable_read_regular_file(path, owners)
    if not stat.S_ISREG(info.st_mode):
        raise SourceFreezeError(label)
    return hashlib.sha256(payload).hexdigest(), payload


def _require_reviewed_python(manifest_payload: bytes) -> None:
    record = _load_json_object(manifest_payload, "toolchain pin manifest")
    tools = record.get("tools")
    if type(tools) is not dict:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    python = tools.get("python")
    if type(python) is not dict:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    version = python.get("version")
    if type(version) is not str or not version:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    parts = version.split(".")
    if len(parts) < 2:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except ValueError as suc:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE) from suc
    if (major, minor) != REVIEWED_PYTHON_MAJOR_MINOR:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    if sys.version_info[:2] != REVIEWED_PYTHON_MAJOR_MINOR:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)


def _require_executing_toolchain_closure(
    issuance: _IssuanceBinding,
) -> dict[str, bytes]:
    controller, test_path, manifest = _executing_control_paths()
    try:
        controller_digest, controller_payload = _stable_hash_control_file(
            controller, PRODUCER_INJECTION
        )
        test_digest, test_payload = _stable_hash_control_file(test_path, TEST_INJECTION)
        manifest_digest, manifest_payload = _stable_hash_control_file(
            manifest, TOOLCHAIN_CLOSURE
        )
    except SourceFreezeError:
        raise
    except OSError as suc:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE) from suc
    if controller_digest != issuance.controller_sha256:
        raise SourceFreezeError(PRODUCER_INJECTION)
    if test_digest != issuance.test_sha256:
        raise SourceFreezeError(TEST_INJECTION)
    if manifest_digest != issuance.manifest_sha256:
        raise SourceFreezeError(TOOLCHAIN_CLOSURE)
    _require_reviewed_python(manifest_payload)
    return {
        f"tools/{CONTROLLER_NAME}": controller_payload,
        f"tools/{TEST_NAME}": test_payload,
        TOOLCHAIN_PIN_PATH: manifest_payload,
    }


def _require_candidate_control_closure(
    tree: _GitTreeState | None,
    files: dict[str, bytes],
) -> None:
    if tree is None:
        return
    for relative, payload in files.items():
        record = tree.blobs.get(relative)
        if record is None:
            raise SourceFreezeError(f"{TOOLCHAIN_CLOSURE}: {relative}")
        index_record = tree.index.get(relative)
        if index_record != record:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        flag = tree.flags.get(relative, "")
        if flag and flag not in {"H", "C"}:
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")
        _require_blob_matches_worktree(
            relative, payload, None, record, tree.object_format
        )
        xy = _porcelain_by_path(tree).get(relative, "")
        if xy and (xy[0] in "MTDARC" or xy[1] in "MTD"):
            raise SourceFreezeError(f"{GIT_INDEX_WORKTREE_SPLIT}: {relative}")


def _require_freeze_dir_membership(
    freeze_dir_fd: int,
    freeze_relative: str,
    *,
    website_changed: bool,
) -> None:
    names = set(_list_directory_names(freeze_dir_fd, freeze_relative))
    required = {FREEZE_LOCK_NAME, FREEZE_SCOPE_NAME}
    if website_changed:
        required.add(FREEZE_STAGE_NAME)
    if names != required:
        raise SourceFreezeError(PARTIAL_PUBLICATION)


def _bind_freeze_dir(
    repo_fd: int,
    freeze_relative: str,
    allowed_owners: frozenset[int],
    missing_message: str,
) -> tuple[int, os.stat_result]:
    try:
        return _walk_open_dir(repo_fd, freeze_relative, allowed_owners)
    except SourceFreezeError as suc:
        message = str(suc)
        if (
            "could not be inspected" in message
            or "could not be opened" in message
            or "Required release source root is missing" in message
        ):
            raise SourceFreezeError(missing_message) from suc
        raise


def _rebind_held_directory(
    repo_fd: int,
    relative: str,
    held_fd: int,
    opened: os.stat_result,
    allowed_owners: frozenset[int],
    label: str,
) -> os.stat_result:
    try:
        rebound = os.fstat(held_fd)
    except OSError as suc:
        raise SourceFreezeError(RECEIPT_REBIND_CHANGED) from suc
    if _identity(rebound) != _identity(opened):
        raise SourceFreezeError(
            f"{label} identity changed before freeze verification returned"
        )
    path_fd, path_info = _walk_open_dir(repo_fd, relative, allowed_owners)
    try:
        if (path_info.st_dev, path_info.st_ino) != (rebound.st_dev, rebound.st_ino):
            raise SourceFreezeError(
                f"{label} identity changed before freeze verification returned"
            )
        if _identity(path_info) != _identity(rebound):
            raise SourceFreezeError(
                f"{label} identity changed before freeze verification returned"
            )
    finally:
        os.close(path_fd)
    return rebound


def _read_named_json(
    parent_fd: int,
    name: str,
    relative: str,
    allowed_owners: frozenset[int],
    label: str,
    *,
    missing_message: str | None = None,
) -> _BoundDocument:
    try:
        payload, identity, _info = _stable_read_regular_file_at(
            parent_fd,
            name,
            relative,
            allowed_owners,
            max_bytes=MAX_SOURCE_JSON_BYTES,
        )
    except SourceFreezeError as suc:
        message = str(suc)
        if missing_message and (
            "could not be inspected" in message
            or "could not be opened" in message
            or "must be a regular non-symlink file" in message
        ):
            raise SourceFreezeError(missing_message) from suc
        raise
    return _BoundDocument(
        relative=relative,
        record=_load_json_object(payload, label),
        digest=hashlib.sha256(payload).hexdigest(),
        identity=identity,
    )


def _rebind_named_json(
    parent_fd: int,
    expected: _BoundDocument,
    allowed_owners: frozenset[int],
    label: str,
) -> _BoundDocument:
    actual = _read_named_json(
        parent_fd,
        pathlib.PurePosixPath(expected.relative).name,
        expected.relative,
        allowed_owners,
        label,
    )
    if actual.digest != expected.digest or actual.identity != expected.identity:
        raise SourceFreezeError(
            f"{label} identity changed before freeze verification returned"
        )
    return actual


def verified_release_source_state(repo: pathlib.Path) -> ReleaseSourceState:
    repo = _canonical_repo(pathlib.Path(repo))
    allowed_owners = _allowed_owners(repo)
    issuance = _bind_external_issuance(repo)
    control_files = _require_executing_toolchain_closure(issuance)
    repo_fd, opened = _open_repo_dir(repo, allowed_owners)
    freeze_dir_fd: int | None = None
    try:
        opened = _require_repo_path_identity(repo, repo_fd, opened)
        _require_app_source_roots_at(repo_fd, allowed_owners)
        version, build = _release_identity_at(repo_fd, allowed_owners)
        release = f"{version}+{build}"
        if issuance.release != release:
            raise SourceFreezeError(
                f"{TRUST_PIN_LABEL} release {issuance.release} does not match "
                f"pubspec.yaml release {release}; {TRUST_PIN_HOW_TO}"
            )
        freeze_relative = f".artifacts/release-freeze-{release}"
        scope_relative = f"{freeze_relative}/SCOPE_FREEZE.json"
        lock_relative = f"{freeze_relative}/APP_SOURCE_LOCK.json"
        scopes = _capture_release_scopes_at(repo_fd, allowed_owners)
        opened = _require_repo_path_identity(repo, repo_fd, opened)
        first_git = _bind_production_git_tree(repo)
        _require_production_git_inputs(
            first_git,
            scopes.payloads,
            scopes.aliases,
            SOURCE_PATHS_COMBINED,
            scopes.identities,
        )
        _require_candidate_control_closure(first_git, control_files)
        app = scopes.app
        website = scopes.website
        immutable_website = scopes.immutable_website
        missing_lock = (
            "No immutable APP_SOURCE_LOCK.json exists for the current release."
        )
        freeze_dir_fd, freeze_info = _bind_freeze_dir(
            repo_fd, freeze_relative, allowed_owners, missing_lock
        )
        lock_doc = _read_named_json(
            freeze_dir_fd,
            "APP_SOURCE_LOCK.json",
            lock_relative,
            allowed_owners,
            "APP_SOURCE_LOCK.json",
            missing_message=missing_lock,
        )
        if lock_doc.digest != issuance.app_source_lock_sha256:
            raise SourceFreezeError(
                "APP_SOURCE_LOCK.json does not match the app_source_lock_sha256 pin: "
                f"pinned={issuance.app_source_lock_sha256} current={lock_doc.digest}"
            )
        parsed_lock = _parse_lock(lock_doc.record, release, issuance)
        scope_doc = _read_named_json(
            freeze_dir_fd,
            "SCOPE_FREEZE.json",
            scope_relative,
            allowed_owners,
            "SCOPE_FREEZE.json",
            missing_message=(
                "App source lock is not bound to the exact scope-freeze manifest."
            ),
        )
        if scope_doc.digest != issuance.scope_freeze_sha256:
            raise SourceFreezeError(
                "SCOPE_FREEZE.json does not match the scope_freeze_sha256 pin: "
                f"pinned={issuance.scope_freeze_sha256} current={scope_doc.digest}"
            )
        if parsed_lock["scope_freeze_sha256"] != scope_doc.digest:
            raise SourceFreezeError(
                "App source lock is not bound to the exact scope-freeze manifest."
            )
        frozen_fingerprint = str(
            parsed_lock["frozen_combined_source_fingerprint_sha256"]
        )
        frozen_count = _require_source_count(
            parsed_lock["frozen_combined_source_file_count"],
            "APP_SOURCE_LOCK.json frozen_combined_source_file_count",
        )
        _parse_scope(scope_doc.record, release, frozen_fingerprint, issuance)
        if app.sha256 != parsed_lock["app_source_fingerprint_sha256"]:
            raise SourceFreezeError(
                "Frozen app/runtime/installer source fingerprint changed."
            )
        if app.file_count != parsed_lock["app_source_file_count"]:
            raise SourceFreezeError(
                "Frozen app/runtime/installer source file count changed."
            )
        if immutable_website.sha256 != parsed_lock[
            "immutable_website_source_fingerprint_sha256_at_freeze"
        ]:
            raise SourceFreezeError("Immutable website source changed after scope freeze.")
        if immutable_website.file_count != parsed_lock[
            "immutable_website_source_file_count_at_freeze"
        ]:
            raise SourceFreezeError(
                "Immutable website source file count changed after scope freeze."
            )

        website_changed = (
            website.sha256
            != parsed_lock["website_source_fingerprint_sha256_at_freeze"]
            or website.file_count
            != parsed_lock["website_source_file_count_at_freeze"]
        )
        stage_relative = ""
        stage_doc: _BoundDocument | None = None
        if website_changed:
            stage_path_relative = f"{freeze_relative}/WEBSITE_STAGE.json"
            try:
                stage_doc = _read_named_json(
                    freeze_dir_fd,
                    "WEBSITE_STAGE.json",
                    stage_path_relative,
                    allowed_owners,
                    "WEBSITE_STAGE.json",
                    missing_message=(
                        "Changed website source lacks a valid WEBSITE_STAGE.json attestation."
                    ),
                )
            except SourceFreezeError as suc:
                message = str(suc)
                if "WEBSITE_STAGE.json" in message or "schema fields" in message:
                    raise
                raise SourceFreezeError(
                    "Changed website source lacks a valid WEBSITE_STAGE.json attestation."
                ) from suc
            if issuance.website_stage_sha256 is None:
                raise SourceFreezeError(
                    f"{TRUST_PIN_MISSING} has website_stage_sha256 null but the "
                    "website source changed after the freeze; record the sha256 of "
                    f"{stage_path_relative} as website_stage_sha256"
                )
            if stage_doc.digest != issuance.website_stage_sha256:
                raise SourceFreezeError(
                    "WEBSITE_STAGE.json does not match the website_stage_sha256 pin: "
                    f"pinned={issuance.website_stage_sha256} current={stage_doc.digest}"
                )
            expected_stage = {
                "schema_version": 1,
                "contract": WEBSITE_STAGE_CONTRACT,
                "release": release,
                "boundary_lock_sha256": lock_doc.digest,
                "app_source_fingerprint_sha256": app.sha256,
                "app_source_file_count": app.file_count,
                "immutable_website_source_fingerprint_sha256": immutable_website.sha256,
                "immutable_website_source_file_count": immutable_website.file_count,
                "website_index_sha256_before": parsed_lock[
                    "website_index_sha256_at_freeze"
                ],
                "website_index_sha256_after": _sha256_relative(
                    repo_fd, "web/index.html", allowed_owners
                ),
                "staged_website_source_fingerprint_sha256": website.sha256,
                "staged_website_source_file_count": website.file_count,
                "mutated_paths": ["web/index.html"],
                "publication_authorized": False,
                "issuance_id": issuance.issuance_id,
                "created_utc": issuance.created_utc,
            }
            _parse_stage(stage_doc.record, expected_stage, issuance)
            stage_relative = stage_path_relative
        elif issuance.website_stage_sha256 is not None:
            raise SourceFreezeError(
                f"{TRUST_PIN_LABEL} pins website_stage_sha256 but the website source "
                "is unchanged since the freeze; set website_stage_sha256 to null"
            )
        _require_freeze_dir_membership(
            freeze_dir_fd,
            freeze_relative,
            website_changed=website_changed,
        )

        freeze_info = _rebind_held_directory(
            repo_fd,
            freeze_relative,
            freeze_dir_fd,
            freeze_info,
            allowed_owners,
            "freeze receipt directory",
        )
        opened = _revalidate_release_scopes_at(
            repo, repo_fd, opened, allowed_owners, scopes
        )
        hook = _POST_FINAL_CAPTURE_HOOK
        if callable(hook):
            hook()
        opened = _rebind_requested_path(
            repo,
            repo_fd,
            opened,
            kind="release repository",
            directory=True,
        )
        _rebind_external_issuance(issuance)
        freeze_info = _rebind_held_directory(
            repo_fd,
            freeze_relative,
            freeze_dir_fd,
            freeze_info,
            allowed_owners,
            "freeze receipt directory",
        )
        lock_doc = _rebind_named_json(
            freeze_dir_fd, lock_doc, allowed_owners, "APP_SOURCE_LOCK.json"
        )
        scope_doc = _rebind_named_json(
            freeze_dir_fd, scope_doc, allowed_owners, "SCOPE_FREEZE.json"
        )
        if stage_doc is not None:
            stage_doc = _rebind_named_json(
                freeze_dir_fd, stage_doc, allowed_owners, "WEBSITE_STAGE.json"
            )
        opened = _revalidate_release_scopes_at(
            repo, repo_fd, opened, allowed_owners, scopes
        )
        _require_freeze_dir_membership(
            freeze_dir_fd,
            freeze_relative,
            website_changed=website_changed,
        )
        _rebind_external_issuance(issuance)
        control_files = _require_executing_toolchain_closure(issuance)
        second_git = _bind_production_git_tree(repo)
        if first_git != second_git:
            raise SourceFreezeError(GIT_DIRTY_SOURCE)
        _require_production_git_inputs(
            second_git,
            scopes.payloads,
            scopes.aliases,
            SOURCE_PATHS_COMBINED,
            scopes.identities,
        )
        _require_candidate_control_closure(second_git, control_files)
        return ReleaseSourceState(
            source_fingerprint_sha256=frozen_fingerprint,
            source_file_count=frozen_count,
            latest_write_utc=app.latest_write_utc,
            app_source_fingerprint_sha256=app.sha256,
            app_source_file_count=app.file_count,
            website_source_fingerprint_sha256=website.sha256,
            website_source_file_count=website.file_count,
            immutable_website_source_fingerprint_sha256=immutable_website.sha256,
            immutable_website_source_file_count=immutable_website.file_count,
            website_changed_from_freeze=website_changed,
            lock_path=lock_relative,
            website_stage_path=stage_relative,
        )
    finally:
        _close_quietly(freeze_dir_fd)
        os.close(repo_fd)


def _json_record(state: ReleaseSourceState) -> dict[str, object]:
    return {
        "source_fingerprint_sha256": state.source_fingerprint_sha256,
        "source_file_count": state.source_file_count,
        "latest_write_utc": state.latest_write_utc.isoformat().replace("+00:00", "Z"),
        "app_source_fingerprint_sha256": state.app_source_fingerprint_sha256,
        "app_source_file_count": state.app_source_file_count,
        "website_source_fingerprint_sha256": state.website_source_fingerprint_sha256,
        "website_source_file_count": state.website_source_file_count,
        "immutable_website_source_fingerprint_sha256": state.immutable_website_source_fingerprint_sha256,
        "immutable_website_source_file_count": state.immutable_website_source_file_count,
        "website_changed_from_freeze": state.website_changed_from_freeze,
        "lock_path": state.lock_path,
        "website_stage_path": state.website_stage_path,
    }


def _website_json_record(state: WebsiteSourceState) -> dict[str, object]:
    return {
        "website_source_fingerprint_sha256": state.website_source_fingerprint_sha256,
        "website_source_file_count": state.website_source_file_count,
        "website_latest_write_utc": state.website_latest_write_utc.isoformat().replace(
            "+00:00", "Z"
        ),
        "immutable_website_source_fingerprint_sha256": state.immutable_website_source_fingerprint_sha256,
        "immutable_website_source_file_count": state.immutable_website_source_file_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--website-only",
        action="store_true",
        help="Fingerprint current website staging without verifying the legacy app lock.",
    )
    args = parser.parse_args()
    global _PRODUCTION_REQUIRED
    if isolated_fixture_mode_active():
        print(f"RELEASE SOURCE FREEZE: FAIL: {FIXTURE_CANNOT_AUTHORIZE}")
        return 1
    previous_production = _PRODUCTION_REQUIRED
    _PRODUCTION_REQUIRED = True
    try:
        try:
            if args.website_only:
                website_state = current_website_source_state(pathlib.Path(args.repo))
            else:
                state = verified_release_source_state(pathlib.Path(args.repo))
        except SourceFreezeError as exc:
            print(f"RELEASE SOURCE FREEZE: FAIL: {exc}")
            return 1
    finally:
        _PRODUCTION_REQUIRED = previous_production
    if args.website_only:
        if args.json:
            print(json.dumps(_website_json_record(website_state), sort_keys=True))
        else:
            print(
                "WEBSITE SOURCE FINGERPRINT: PASS "
                f"website={website_state.website_source_fingerprint_sha256}"
            )
        return 0
    if args.json:
        print(json.dumps(_json_record(state), sort_keys=True))
    else:
        print(
            "RELEASE SOURCE FREEZE: PASS "
            f"fingerprint={state.source_fingerprint_sha256} "
            f"app={state.app_source_fingerprint_sha256} "
            f"website={state.website_source_fingerprint_sha256}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
