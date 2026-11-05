#!/usr/bin/env python3
"""Exact known-server-secret matching, encodings, archives, and redaction.

This lane module composes with the shared release-artifact privacy scanner
(validate_release_artifact_privacy) and hardens one produced-artifact gap that
the shared scanner does not close: an archive member NAME that leaks a local
user-home or source-tree build path.  The shared scanner rejects those path
leaks only when they appear in member content; a member whose name embeds such
a path (for example the builder's local checkout path) with otherwise clean
content is a false green.

The full scanner API is re-exported here so a consumer may import this module
as the canonical exact-secret surface.  An import-time completeness guard makes
a partially aggregated surface fail loudly instead of silently passing.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
import tarfile
import types
import zipfile
from typing import Iterable, Mapping

import release_secret_inventory as inventory
import validate_release_artifact_privacy as _base

PrivacyError = _base.PrivacyError
InventoryError = _base.InventoryError

# Aggregate the entire shared scanner surface so the lane module is a drop-in
# canonical import for exact-secret scanning and redaction.
for _name in dir(_base):
    if _name.startswith("__"):
        continue
    globals()[_name] = getattr(_base, _name)


MAX_SECRET_STDIN_BYTES = 64 * 1024
MAX_SECRET_STDIN_FIELDS = 128


# A member NAME in a produced archive is normally relative.  The shared scanner
# rejects absolute user-home/source-tree paths in member data, but it never
# inspects member names and the archive-path validators allow relative names.
# These patterns catch a relative builder-checkout leak embedded in a name that
# the archive-path validator would otherwise permit.  Matching is case-folded
# and slash-normalized.
_RELATIVE_USER_HOME_NAME_RE = re.compile(
    r"(?i)(?:^|/)(?:users|home|documents and settings)/[^/\x00\r\n]{1,128}/"
)
_RELATIVE_SOURCE_TREE_NAME_RE = re.compile(
    r"(?i)(?:^|/)(?:wins_vpn|wins-vpn)"
    r"(?:[-_.]?[a-z0-9][a-z0-9._-]{0,31})?"
    r"(?:/[^/\x00\r\n]{1,128}){0,12}"
    r"/(?:android|apple|build|ios|lib|linux|macos|tools|windows)/"
)


def member_name_leak_category(name: str) -> str | None:
    """Return the leaked build-path category in an archive member NAME, or None.

    The shared scanner scans member data but not member names for these path
    leaks.  A name that leaks a local user-home or source-tree path is a
    produced-artifact privacy failure even when the member payload is clean.
    """
    if not name:
        return None
    folded = name.replace("\\", "/")
    if LOCAL_USER_HOME_PATH_RE.search(folded):
        return "local-user-home-path"
    if SOURCE_TREE_PATH_RE.search(folded):
        return "local-source-tree-path"
    if _RELATIVE_USER_HOME_NAME_RE.search(folded):
        return "local-user-home-path"
    if _RELATIVE_SOURCE_TREE_NAME_RE.search(folded):
        return "local-source-tree-path"
    return None


def reject_unsafe_archive_member_name(name: str) -> None:
    """Raise PrivacyError when an archive member name leaks a build path."""
    category = member_name_leak_category(name)
    if category is not None:
        raise PrivacyError(
            f"{PUBLIC_MEMBER_LABEL} name contains {category} build-path material."
        )


def reject_unsafe_archive_member_names(names: list[str]) -> None:
    """Reject any archive member name that leaks a build path."""
    for name in names:
        reject_unsafe_archive_member_name(name)


def _absolute_artifact_path(path: pathlib.Path) -> pathlib.Path:
    if not isinstance(path, pathlib.Path):
        path = pathlib.Path(path)
    if not path.is_absolute():
        path = pathlib.Path(os.path.abspath(path))
    return path


def _path_custody_token(path: pathlib.Path) -> tuple[tuple[object, ...], ...]:
    """Capture every lexical path component around a descriptor-bound read."""
    absolute = _absolute_artifact_path(path)
    current = pathlib.Path(absolute.anchor)
    components = [current]
    for part in absolute.parts[1:]:
        current = current / part
        components.append(current)
    token: list[tuple[object, ...]] = []
    for component in components:
        try:
            info = os.lstat(component)
        except OSError:
            raise PrivacyError("release artifact path was replaced") from None
        token.append(
            (
                os.fspath(component),
                _pathname_identity(info),
                stat.S_ISLNK(info.st_mode),
            )
        )
    return tuple(token)


def _assert_snapshot_still_current(
    path: pathlib.Path,
    snapshot: ArtifactSnapshot,
    path_token: tuple[tuple[object, ...], ...],
) -> None:
    """Refuse a PASS if the live path or any ancestor changed after scanning."""
    absolute = _absolute_artifact_path(path)
    try:
        current = os.lstat(absolute)
    except OSError:
        raise PrivacyError("release artifact was replaced after its privacy scan") from None
    if _stat_identity(current) != snapshot.identity:
        raise PrivacyError("release artifact was replaced after its privacy scan")
    if _path_custody_token(absolute) != path_token:
        raise PrivacyError("release artifact path was replaced after its privacy scan")


def _directory_custody_token(path: pathlib.Path) -> tuple[tuple[object, ...], ...]:
    """Capture a bounded directory tree without rereading candidate bytes."""
    absolute = _absolute_artifact_path(path)
    try:
        root_info = os.lstat(absolute)
    except OSError:
        raise PrivacyError("release artifact directory was replaced") from None
    _reject_artifact_stat(root_info, directory_ok=True)
    records: list[tuple[object, ...]] = [(".", _stat_identity(root_info))]
    count = 0
    for root, dirnames, filenames in os.walk(absolute, followlinks=False):
        dirnames[:] = sorted(dirnames)
        for name in dirnames:
            child = pathlib.Path(root) / name
            try:
                info = os.lstat(child)
            except OSError:
                raise PrivacyError("release artifact directory was replaced") from None
            _reject_artifact_stat(info, directory_ok=True)
            count += 1
            if count > MAX_ARCHIVE_MEMBER_COUNT:
                raise PrivacyError("release archive exceeds the member-count limit")
            records.append(
                (child.relative_to(absolute).as_posix() + "/", _stat_identity(info))
            )
        for name in sorted(filenames):
            child = pathlib.Path(root) / name
            try:
                info = os.lstat(child)
            except OSError:
                raise PrivacyError("release artifact directory was replaced") from None
            _reject_artifact_stat(info)
            count += 1
            if count > MAX_ARCHIVE_MEMBER_COUNT:
                raise PrivacyError("release archive exceeds the member-count limit")
            records.append(
                (child.relative_to(absolute).as_posix(), _stat_identity(info))
            )
    return tuple(records)


def _reject_nonfinite_json(value: str) -> object:
    raise PrivacyError(f"Secret scan input contains non-finite JSON value {value}.")


def _strict_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise PrivacyError("Secret scan input contains a non-finite JSON number.")
    return parsed


def read_secrets_stdin() -> dict[str, str]:
    """Read a bounded, duplicate-free, finite JSON secret map from stdin."""
    raw = sys.stdin.buffer.read(MAX_SECRET_STDIN_BYTES + 1)
    if not raw or len(raw) > MAX_SECRET_STDIN_BYTES:
        raise PrivacyError("Secret scan input size is outside the accepted bound.")
    try:
        payload = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
            parse_float=_strict_json_float,
        )
    except PrivacyError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise PrivacyError(
            "Secret scan input must be one strict UTF-8 JSON object on stdin."
        ) from None
    if type(payload) is not dict or not payload:
        raise PrivacyError("Secret scan input must be a non-empty JSON object.")
    if len(payload) > MAX_SECRET_STDIN_FIELDS:
        raise PrivacyError("Secret scan input contains too many fields.")
    result: dict[str, str] = {}
    for key, value in payload.items():
        if type(key) is not str or re.fullmatch(r"[A-Z][A-Z0-9_]{2,80}", key) is None:
            raise PrivacyError("Secret scan input contains an invalid field label.")
        if type(value) is not str or len(value) < 12:
            raise PrivacyError(
                f"Secret scan input {key} must contain at least 12 characters."
            )
        result[key] = value
    return result


def _inspect_member(
    member_name: str,
    data: bytes,
    secrets: Mapping[str, str],
    compiled: Mapping[str, tuple[bytes, ...]],
    matches: set[str],
) -> None:
    """Inspect a member and reject any build-path leak embedded in its NAME.

    The shared scanner inspects member data and secret-labels in member names,
    but it never rejects a relative user-home or source-tree path that appears
    only in the member NAME.  A member whose name leaks such a path with clean
    content is a produced-artifact false green, so this lane composes the base
    inspection with the exact member-name check before delegating.
    """
    reject_unsafe_archive_member_name(member_name)
    _base._inspect_member(member_name, data, secrets, compiled, matches)


def _scan_artifacts(
    paths: Iterable[pathlib.Path],
    secrets: Mapping[str, str],
    *,
    target_id: str = "",
    exact_target: bool = False,
) -> tuple[int, tuple[str, ...], tuple[str, ...]]:
    """Mirror the shared scanner's archive scan with the exact member-name check.

    The shared scanner resolves its member inspector from its own module globals,
    so re-exporting it would bypass this lane's NAME-path rejection.  This lane
    owns the scan loop and composes the exact-secret member inspector instead.
    """
    paths = tuple(paths)
    if target_id and len(paths) != 1:
        raise PrivacyError("exact target privacy scanning requires one artifact candidate")
    compiled = compile_exact_secret_forms(secrets) if secrets else {}
    blobs = 0
    matches: set[str] = set()
    identities: list[str] = []
    for path in paths:
        path = _absolute_artifact_path(path)
        try:
            info = os.lstat(path)
        except OSError:
            raise PrivacyError("Required release artifact does not exist") from None
        if stat.S_ISLNK(info.st_mode):
            raise PrivacyError("release artifact must be a regular non-symlink file")
        try:
            if stat.S_ISDIR(info.st_mode):
                _reject_artifact_stat(info, directory_ok=True)
                if target_id:
                    raise PrivacyError("target identity does not match the artifact type")
                path_token = _path_custody_token(path)
                directory_token = _directory_custody_token(path)
                directory_digest = hashlib.sha256()
                iterator = _iter_directory(path)
            else:
                _reject_artifact_stat(info)
                path_token = _path_custody_token(path)
                snapshot = _snapshot_regular_file(path)
                _assert_target_artifact_type(
                    target_id, path, snapshot, exact_target=exact_target
                )
                identities.append(snapshot.digest)
                iterator = _iter_snapshot(snapshot)
            if service_account_member_name(path.name):
                raise PrivacyError(
                    f"{PUBLIC_MEMBER_LABEL} contains reusable secret category "
                    "google_service_account_json. Obfuscation or stripping is not "
                    "remediation; remove the credential from the distributable before "
                    "rebuilding."
                )
            for member_name, data in iterator:
                _inspect_member(member_name, data, secrets, compiled, matches)
                if stat.S_ISDIR(info.st_mode):
                    encoded_name = member_name.encode(
                        "utf-8", errors="surrogateescape"
                    )
                    directory_digest.update(len(encoded_name).to_bytes(8, "big"))
                    directory_digest.update(encoded_name)
                    directory_digest.update(len(data).to_bytes(8, "big"))
                    directory_digest.update(data)
                blobs += 1
            if stat.S_ISDIR(info.st_mode):
                if _path_custody_token(path) != path_token:
                    raise PrivacyError(
                        "release artifact path was replaced after its privacy scan"
                    )
                if _directory_custody_token(path) != directory_token:
                    raise PrivacyError(
                        "release artifact directory changed after its privacy scan"
                    )
                identities.append(directory_digest.hexdigest())
            else:
                _assert_snapshot_still_current(path, snapshot, path_token)
        except PrivacyError as exc:
            raise PrivacyError(redact_diagnostic(str(exc), compiled)) from None
        except Exception as exc:
            raise PrivacyError(redact_diagnostic("archive is not inspectable", compiled)) from None
    if blobs == 0:
        raise PrivacyError("Artifact privacy scan inspected no files.")
    return blobs, tuple(sorted(matches)), tuple(identities)


def validate_artifacts(paths: Iterable[pathlib.Path], secrets: dict[str, str]) -> int:
    """Validate artifacts with the exact member-NAME build-path rejection."""
    blobs, matched, _identities = _scan_artifacts(paths, secrets)
    if matched:
        raise PrivacyError(
            "artifact contains exact known-server-secret label(s) "
            + ", ".join(matched)
            + "."
        )
    return blobs


def scan_release_artifacts(
    paths: Iterable[pathlib.Path],
    inventory: SecretInventory,
    *,
    target_id: str = "",
    require_target: bool = False,
) -> ArtifactPrivacyScanResult:
    """Scan release artifacts with the exact member-NAME build-path rejection."""
    if require_target and not target_id:
        raise PrivacyError("authenticated release artifact scan requires an exact target identity")
    if target_id and TARGET_ID_RE.fullmatch(target_id) is None:
        raise PrivacyError("target identity is not a validated ASCII label")
    if target_id and target_id not in KNOWN_PRIVACY_TARGET_IDS:
        raise PrivacyError("target identity is not a known release target")
    try:
        secrets = dict(release_secret_values(inventory))
    except InventoryError as exc:
        raise PrivacyError(str(exc)) from None
    try:
        blobs, matched, identities = _scan_artifacts(
            paths, secrets, target_id=target_id, exact_target=require_target
        )
    finally:
        secrets.clear()
    return ArtifactPrivacyScanResult(
        passed=not matched,
        revision=inventory.revision,
        labels=inventory.labels,
        label_count=inventory.label_count,
        unique_value_count=inventory.unique_value_count,
        target_id=target_id,
        artifact_identity=",".join(identities),
        matched_labels=matched,
        blob_count=blobs,
    )


def _rebind_scan_entrypoints() -> None:
    """Route re-exported scan entry points through this module's exact inspector.

    A re-exported base function keeps the shared scanner's module globals, so it
    would resolve scan_release_artifacts and _inspect_member in the base module
    and silently skip the exact member-name build-path rejection. Rebinding the
    scan-performing entry points to this module's globals makes them honor the
    lane hardening instead of returning a false green on a produced artifact.
    """
    global main, canonical_extension_gate_verify
    main = types.FunctionType(
        _base.main.__code__,
        globals(),
        _base.main.__name__,
        _base.main.__defaults__,
        _base.main.__closure__,
    )
    canonical_extension_gate_verify = types.FunctionType(
        _base.canonical_extension_gate_verify.__code__,
        globals(),
        _base.canonical_extension_gate_verify.__name__,
        _base.canonical_extension_gate_verify.__defaults__,
        _base.canonical_extension_gate_verify.__closure__,
    )


_rebind_scan_entrypoints()


def _assert_complete_scanner_api() -> None:
    required = (
        "PrivacyError",
        "scan_release_artifacts",
        "validate_artifacts",
        "format_inventory_scan_report",
        "encoded_forms",
        "exact_secret_labels",
        "redact_diagnostic",
        "compile_exact_secret_forms",
        "_inspect_member",
        "is_approved_vendor_debug_metadata",
        "javascript_concatenated_blobs",
        "javascript_array_join_blobs",
        "apple_default_artifacts",
        "main",
        "MAX_ENCODED_SECRET_FORMS",
        "MAX_ARCHIVE_PATH_DEPTH",
        "MAX_ARCHIVE_MEMBER_COUNT",
        "MAX_ARCHIVE_MEMBER_EXPANDED_BYTES",
        "MAX_ARCHIVE_COMPRESSION_RATIO",
        "MAX_ARCHIVE_INPUT_BYTES",
        "MAX_ARCHIVE_NEST_DEPTH",
        "_POST_PARENT_BIND_HOOK",
    )
    missing = [name for name in required if not hasattr(_base, name)]
    if missing:
        raise PrivacyError(
            "release-artifact exact-secret scanner surface is incomplete: "
            + ", ".join(missing)
        )


_assert_complete_scanner_api()


if __name__ == "__main__":
    _assert_complete_scanner_api()
    print("RELEASE ARTIFACT EXACT SECRETS MODULE: SURFACE COMPLETE")
