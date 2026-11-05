#!/usr/bin/env python3
"""Reproduced P1 bypass audit for release-artifact privacy scanning.

This lane module composes with the shared release-artifact privacy scanner
(validate_release_artifact_privacy) and provides a narrow, explicitly-owned P1
entrypoint that audits the exact canonical filename and path-marker binding for
a release target.  It reuses the shared scanner's verified canonical filename
and target tables so that produced-artifact cross-target swaps and parent-path
substitutions fail closed.

The full scanner API is re-exported here so a consumer may import this module
as the canonical P1 bypass surface.  An import-time completeness guard makes a
partially aggregated surface fail loudly instead of silently passing.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import stat
import tarfile
import zipfile

import release_secret_inventory as inventory
import validate_release_artifact_privacy as _base

PrivacyError = _base.PrivacyError
InventoryError = _base.InventoryError

# Aggregate the entire shared scanner surface so the lane module is a drop-in
# canonical import for P1 bypass auditing.
for _name in dir(_base):
    if _name.startswith("__"):
        continue
    globals()[_name] = getattr(_base, _name)


class P1CanonicalBindingVerdict:
    __slots__ = ("passed", "target_id", "reason")

    def __init__(self, passed: bool, target_id: str, reason: str) -> None:
        self.passed = passed
        self.target_id = target_id
        self.reason = reason


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
    """Refuse a verdict if the live artifact or an ancestor changed."""
    try:
        current = os.lstat(path)
    except OSError:
        raise PrivacyError("release artifact was replaced after binding") from None
    if _stat_identity(current) != snapshot.identity:
        raise PrivacyError("release artifact was replaced after binding")
    if _path_custody_token(path) != path_token:
        raise PrivacyError("release artifact path was replaced after binding")


def audit_canonical_binding(
    target_id: str,
    path: pathlib.Path,
    *,
    exact_target: bool = False,
) -> P1CanonicalBindingVerdict:
    """Audit that path binds to target_id through exact canonical filename and markers.

    Mirrors the shared scanner's exact-target assertion so the lane owns a P1
    entrypoint that fails closed on reproduced canonical-filename swaps without
    requiring the caller to catch PrivacyError.

    The shared assertion assumes a validated target identity key, so this lane
    validates the target itself.  An empty or unknown identity is a false green
    otherwise: the shared table lookup raises KeyError out of this API instead
    of returning a clean fail-closed verdict.  A missing, symlink, or
    non-regular artifact is also a fail-closed verdict, matching the shared
    scanner which refuses a produced artifact that is not present and regular.

    The verdict is only a pass when the produced bytes also match the target's
    artifact type (suffix and leading magic).  The shared exact-target path
    checks type through _assert_target_artifact_type, which composes the
    canonical-filename assertion with the suffix and magic binding; a wrong
    container that merely borrows a canonical filename (for example a ZIP that
    is named like the Windows installer) must not receive a clean verdict.
    """
    if not target_id:
        return P1CanonicalBindingVerdict(
            False, target_id, "authenticated P1 audit requires an exact target identity"
        )
    if target_id not in KNOWN_PRIVACY_TARGET_IDS:
        return P1CanonicalBindingVerdict(
            False, target_id, "target identity is not a known release target"
        )
    if path is None:
        return P1CanonicalBindingVerdict(
            False, target_id, "release artifact does not exist"
        )
    path = _absolute_artifact_path(path)
    try:
        artifact_info = path.lstat() if path is not None else None
    except OSError:
        artifact_info = None
    if artifact_info is None:
        return P1CanonicalBindingVerdict(
            False,
            target_id,
            "release artifact does not exist",
        )
    if stat.S_ISLNK(artifact_info.st_mode):
        return P1CanonicalBindingVerdict(
            False,
            target_id,
            "release artifact must be a regular non-symlink file",
        )
    if not stat.S_ISREG(artifact_info.st_mode):
        return P1CanonicalBindingVerdict(
            False,
            target_id,
            "release artifact must be a regular non-symlink file",
        )
    try:
        path_token = _path_custody_token(path)
        snapshot = _snapshot_regular_file(path)
        _assert_target_artifact_type(
            target_id, path, snapshot, exact_target=exact_target
        )
        _assert_canonical_filename_tables()
        _assert_snapshot_still_current(path, snapshot, path_token)
    except PrivacyError as exc:
        return P1CanonicalBindingVerdict(False, target_id, str(exc))
    return P1CanonicalBindingVerdict(True, target_id, "exact canonical binding holds")


def assert_no_cross_target_collision() -> None:
    """Fail when canonical filenames do not bind their own targets exactly."""
    _assert_canonical_filename_tables()
    if set(TARGET_CANONICAL_FILENAMES) != set(KNOWN_PRIVACY_TARGET_IDS):
        raise PrivacyError(
            "canonical privacy filenames are not exact for all release targets"
        )
    if TARGET_ARTIFACT_SUFFIXES["macos-developer-id-app"] != (".app.zip",):
        raise PrivacyError("macos-developer-id-app suffix is not the exact P1 contract")


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
        "_assert_canonical_artifact_filename",
        "_assert_canonical_filename_tables",
        "_path_markers_match",
        "apple_default_artifacts",
        "main",
        "REQUIRED_PRIVACY_TARGET_IDS",
        "OPTIONAL_PRIVACY_TARGET_IDS",
        "KNOWN_PRIVACY_TARGET_IDS",
        "DEFAULT_TARGET_RELATIVE_PATHS",
        "TARGET_ARTIFACT_SUFFIXES",
        "TARGET_CANONICAL_FILENAMES",
        "EXTENSION_CROSS_STORE_TARGETS",
        "MAX_ARCHIVE_NEST_DEPTH",
        "_POST_PARENT_BIND_HOOK",
    )
    missing = [name for name in required if not hasattr(_base, name)]
    if missing:
        raise PrivacyError(
            "release-artifact P1 bypass scanner surface is incomplete: "
            + ", ".join(missing)
        )


_assert_complete_scanner_api()


if __name__ == "__main__":
    _assert_complete_scanner_api()
    assert_no_cross_target_collision()
    print("RELEASE ARTIFACT PRIVACY P1 MODULE: SURFACE COMPLETE")
