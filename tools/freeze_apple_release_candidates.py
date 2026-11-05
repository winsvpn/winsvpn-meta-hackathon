#!/usr/bin/env python3
"""Atomically freeze the exact verified local Apple App Store candidates."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from apple_final_evidence_collector import (
    REQUIRED_MACOS_ARCHITECTURES,
    CollectorError,
    _require_safe_ipa_members,
    embedded_watch_identity_from_ipa,
    validate_macos_architecture_inventory,
)
from release_freeze_client import verify_build_receipt

from validate_apple_submission_package import (
    ARTIFACT_MANIFEST,
    ARTIFACT_SOURCE_FINGERPRINT_CONTRACT,
    CURRENT_APPLE_BUNDLE_IDS,
    IOS_COMPILED_ICON_VERIFICATION_CONTRACT,
    IOS_COMPILED_ICON_VERIFICATION_MARKER,
    PRIVACY_LABEL_MANIFEST,
    ROOT,
    VERIFICATION_LOG_MARKERS,
    _artifact_bundle_ids,
    _artifact_runtime_source_files,
    _artifact_source_fingerprint,
    _assert_payload_has_no_forbidden_map_markers,
    _validate_archive_privacy_report,
    pubspec_version,
    read_json,
    sha256_file,
    validate_artifact_manifest,
)


class FreezeError(RuntimeError):
    pass


DEFAULT_IOS = Path("build/apple/exports/ios-app-store-local/Win's VPN.ipa")
DEFAULT_MACOS = Path("build/apple/exports/macos-app-store-local/Win's VPN.pkg")
PKGUTIL_TIMEOUT_SECONDS = 300
LIPO_TIMEOUT_SECONDS = 60
GIT_TIMEOUT_SECONDS = 60
# apple_runtime_smoke.sh apple_privacy_archive_report names the archives and records each
# PrivacyInfo.xcprivacy path relative to the archive root.
ARCHIVE_PRIVACY_ARCHIVES = {"ios": "wins-vpn-ios.xcarchive", "macos": "wins-vpn-macos.xcarchive"}
ARCHIVE_APPLICATIONS_PREFIX = "Products/Applications/"
PRIVACY_MANIFEST_NAME = "PrivacyInfo.xcprivacy"


def require_repo_file(relative: Path, suffix: str, label: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts or relative.suffix.lower() != suffix:
        raise FreezeError(f"{label} must be a repository-relative {suffix} path")
    path = ROOT / relative
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise FreezeError(f"{label} is missing, empty, or symbolic")
    try:
        path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise FreezeError(f"{label} escapes the repository") from exc
    return path


def require_owner_only_artifacts_path(value: str, label: str, *, directory: bool) -> Path:
    raw = Path(value)
    if not raw.is_absolute() or ".." in raw.parts:
        raise FreezeError(f"{label} must be an absolute repository .artifacts path")
    try:
        relative = raw.relative_to(ROOT)
    except ValueError as exc:
        raise FreezeError(f"{label} must stay under repository .artifacts") from exc
    if len(relative.parts) < 2 or relative.parts[0] != ".artifacts":
        raise FreezeError(f"{label} must stay under repository .artifacts")

    current = ROOT
    expected_uid = os.getuid() if hasattr(os, "getuid") else None
    if expected_uid is None:
        raise FreezeError(f"{label} owner verification requires a Unix host")
    for index, part in enumerate(relative.parts):
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError as exc:
            raise FreezeError(f"{label} does not exist: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise FreezeError(f"{label} must not traverse a symbolic link: {current}")
        is_final = index == len(relative.parts) - 1
        if is_final:
            expected_type = stat.S_ISDIR if directory else stat.S_ISREG
            if not expected_type(metadata.st_mode):
                kind = "directory" if directory else "regular file"
                raise FreezeError(f"{label} must be a {kind}: {current}")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise FreezeError(f"{label} parent is not a directory: {current}")
        if metadata.st_uid != expected_uid:
            raise FreezeError(f"{label} is not owned by the current user: {current}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise FreezeError(f"{label} path is not owner-only: {current}")

    artifacts_root = (ROOT / ".artifacts").resolve(strict=True)
    try:
        current.resolve(strict=True).relative_to(artifacts_root)
    except ValueError as exc:
        raise FreezeError(f"{label} escapes repository .artifacts") from exc
    return current


def require_receipt_log(value: str, receipt_directory: Path, label: str) -> Path:
    path = require_owner_only_artifacts_path(value, label, directory=False)
    if path.parent != receipt_directory:
        raise FreezeError(f"{label} must be directly inside the new receipt directory")
    if path.stat().st_size <= 0:
        raise FreezeError(f"{label} must not be empty")
    return path


def require_receipt_file(value: str, receipt_directory: Path, label: str) -> Path:
    path = require_owner_only_artifacts_path(value, label, directory=False)
    if path.parent != receipt_directory:
        raise FreezeError(f"{label} must be directly inside the new receipt directory")
    if path.stat().st_size <= 0:
        raise FreezeError(f"{label} must not be empty")
    return path


def require_anchored_file(value: str, label: str) -> tuple[Path, Path]:
    path = require_owner_only_artifacts_path(value, label, directory=False)
    anchor = require_owner_only_artifacts_path(
        str(path.with_name(path.name + ".sha256")),
        f"{label} SHA-256 anchor",
        directory=False,
    )
    if anchor.parent != path.parent or anchor.stat().st_size <= 0:
        raise FreezeError(f"{label} SHA-256 anchor is invalid")
    return path, anchor


def require_build_receipt(
    value: str,
    receipt_directory: Path,
    release_input_index: Path,
    platform: str,
    artifact_path: Path,
) -> tuple[Path, Path, dict[str, object]]:
    label = f"{platform} build receipt"
    receipt = require_receipt_file(value, receipt_directory, label)
    anchor = require_owner_only_artifacts_path(
        str(receipt.with_name(receipt.name + ".sha256")),
        f"{label} SHA-256 anchor",
        directory=False,
    )
    if anchor.parent != receipt_directory or anchor.stat().st_size <= 0:
        raise FreezeError(f"{label} SHA-256 anchor is invalid")
    result = verify_build_receipt(
        ROOT,
        release_input_index,
        platform,
        receipt,
        artifact_path,
    )
    if (
        result.get("platform") != platform
        or result.get("artifact_sha256") != sha256_file(artifact_path)
        or result.get("artifact_size_bytes") != artifact_path.stat().st_size
        or result.get("receipt_sha256") != sha256_file(receipt)
    ):
        raise FreezeError(f"{label} does not bind the exact candidate artifact")
    return receipt, anchor, result


def artifact_reference(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def require_verification_markers(platform: str, log_path: Path) -> None:
    key = (platform, "app_store_local", "ipa" if platform == "ios" else "pkg")
    text = log_path.read_text(encoding="utf-8", errors="replace")
    missing = [marker for marker in VERIFICATION_LOG_MARKERS[key] if marker not in text]
    if platform == "ios" and IOS_COMPILED_ICON_VERIFICATION_MARKER not in text:
        missing.append(IOS_COMPILED_ICON_VERIFICATION_MARKER)
    if missing:
        raise FreezeError(
            f"{platform} verification log lacks {len(missing)} required proof marker(s)"
        )


def require_archive_export_markers(log_path: Path) -> None:
    text = log_path.read_text(encoding="utf-8", errors="replace")
    required = [
        "Exported iOS App Store local IPA: build/apple/exports/ios-app-store-local/Win's VPN.ipa",
        "Exported macOS App Store local package: build/apple/exports/macos-app-store-local/Win's VPN.pkg",
    ]
    missing = [marker for marker in required if marker not in text]
    if text.count("** ARCHIVE SUCCEEDED **") < 2:
        missing.append("two successful Xcode archives")
    if text.count("** EXPORT SUCCEEDED **") < 2:
        missing.append("two successful App Store exports")
    if missing:
        raise FreezeError(
            f"archive/export log lacks {len(missing)} required rebuild proof marker(s)"
        )


def source_commit() -> str:
    """The commit the candidates were built from (R22 Y3 D2).

    The Watch companion smoke runs on a simulator build of the release commit;
    the validators bind its receipt to this value.
    """
    try:
        completed = subprocess.run(
            ["/usr/bin/git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD^{commit}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise FreezeError("release candidate source commit could not be read") from exc
    commit = completed.stdout.strip()
    if completed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise FreezeError("release candidate source commit could not be read from git")
    return commit


def runtime_sources_changed_since(platform: str, artifact_mtime: float) -> list[str]:
    """Runtime sources newer than the candidate that are not the committed bytes.

    The producer's second pass (pod install, Flutter gen-l10n) rewrites tracked
    files such as the Xcode projects, macos/Podfile.lock and lib/l10n with
    identical bytes, so a newer modification time alone is not a change. A
    newer file passes only when git reports it unmodified against HEAD; an
    edited or untracked one is still refused. The build receipts and the
    post-build verify-index bind the exact input contents separately.
    """
    newer = sorted(
        path.relative_to(ROOT).as_posix()
        for path in _artifact_runtime_source_files(platform)
        if path.stat().st_mtime > artifact_mtime
    )
    if not newer:
        return []
    def git(*args: str) -> bytes:
        try:
            completed = subprocess.run(
                ["/usr/bin/git", "-C", str(ROOT), *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=GIT_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FreezeError("runtime source status could not be read from git") from exc
        if completed.returncode != 0:
            raise FreezeError("runtime source status could not be read from git")
        return completed.stdout

    status = git("status", "--porcelain=v1", "-z", "--untracked-files=all", "--", *newer)
    changed = {
        entry[3:].decode("utf-8", errors="replace")
        for entry in status.split(b"\0")
        if len(entry) > 3
    }
    tracked = git("ls-files", "-z", "--", *newer)
    known = {item.decode("utf-8") for item in tracked.split(b"\0") if item}
    return sorted(changed | (set(newer) - known))


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def artifact_entry(
    platform: str,
    relative_path: Path,
    artifact_path: Path,
    archive_log: Path,
    verification_log: Path,
    release_input_index: Path,
    build_receipt: Path,
    build_receipt_anchor: Path,
    build_receipt_result: dict[str, object],
) -> dict[str, object]:
    artifact_type = "ipa" if platform == "ios" else "pkg"
    require_verification_markers(platform, verification_log)
    actual_bundle_ids = _artifact_bundle_ids(platform, artifact_path)
    expected_bundle_ids = CURRENT_APPLE_BUNDLE_IDS[platform]
    if actual_bundle_ids != expected_bundle_ids:
        raise FreezeError(
            f"{platform} bundle IDs are {actual_bundle_ids!r}, expected {expected_bundle_ids!r}"
        )
    _assert_payload_has_no_forbidden_map_markers(platform, artifact_path)
    source_hash, source_count, source_mtime, latest_source = _artifact_source_fingerprint(
        platform
    )
    artifact_mtime = artifact_path.stat().st_mtime
    if artifact_mtime < source_mtime:
        changed = runtime_sources_changed_since(platform, artifact_mtime)
        if changed:
            raise FreezeError(
                f"{platform} candidate predates changed runtime source {changed[0]}"
            )
    if archive_log.stat().st_mtime < artifact_mtime:
        raise FreezeError(f"{platform} archive/export log predates the candidate")
    if verification_log.stat().st_mtime < artifact_mtime:
        raise FreezeError(f"{platform} verification log predates the candidate")
    entry: dict[str, object] = {
        "platform": platform,
        "lane": "app_store_local",
        "type": artifact_type,
        "path": relative_path.as_posix(),
        "size_bytes": artifact_path.stat().st_size,
        "sha256": sha256_file(artifact_path),
        "bundle_id": actual_bundle_ids[0],
        "packet_tunnel_bundle_id": actual_bundle_ids[1],
        "expected_current_bundle_id": expected_bundle_ids[0],
        "expected_current_packet_tunnel_bundle_id": expected_bundle_ids[1],
        "artifact_status": "current_candidate",
        "upload_status": "not_uploaded",
        "archive_export_log": artifact_reference(archive_log),
        "archive_export_log_sha256": sha256_file(archive_log),
        "verification_log": artifact_reference(verification_log),
        "verification_log_sha256": sha256_file(verification_log),
        "release_input_index": artifact_reference(release_input_index),
        "release_input_index_sha256": sha256_file(release_input_index),
        "build_receipt": artifact_reference(build_receipt),
        "build_receipt_sha256": str(build_receipt_result["receipt_sha256"]),
        "build_receipt_anchor": artifact_reference(build_receipt_anchor),
        "build_receipt_anchor_sha256": sha256_file(build_receipt_anchor),
        "artifact_input_fingerprint_sha256": str(
            build_receipt_result["artifact_input_fingerprint_sha256"]
        ),
        "platform_manifest_sha256": str(
            build_receipt_result["platform_manifest_sha256"]
        ),
        "source_fingerprint_contract": ARTIFACT_SOURCE_FINGERPRINT_CONTRACT,
        "source_fingerprint_sha256": source_hash,
        "source_file_count": source_count,
        "signing": {
            "status": "current_candidate",
            "contract": "apple-distribution",
            "authority": "Authority=Apple Distribution:",
            "team_id": "5YT8H4U72M",
        },
    }
    if platform == "ios":
        entry["verification_contract"] = IOS_COMPILED_ICON_VERIFICATION_CONTRACT
        entry["embedded_watchos_companion"] = {
            "status": "current_candidate",
            **embedded_watch_identity_from_ipa(artifact_path),
        }
    elif platform == "macos":
        entry["shipped_architecture_inventory"] = _macos_shipped_architecture_inventory(
            artifact_path
        )
    return entry


def _reject_symlinked_components(
    expanded: Path, candidate: Path, artifact_path: Path, purpose: str
) -> None:
    """pkgutil --expand-full restores payload symlinks, so a plain final name is not
    enough: neither the expansion root nor any component below it on the way to the
    measured file may be a link, or the measurement leaves the expanded package."""
    try:
        parts = candidate.relative_to(expanded).parts
    except ValueError as exc:
        raise FreezeError(f"{artifact_path} {purpose} path is outside the expansion") from exc
    current = expanded
    for part in ("", *parts):
        current = current / part if part else current
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise FreezeError(f"{artifact_path} {purpose} path is missing: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise FreezeError(f"{artifact_path} {purpose} path crosses a symlink: {current}")


def _macos_shipped_architecture_inventory(artifact_path: Path) -> dict[str, object]:
    pkgutil = Path("/usr/sbin/pkgutil")
    lipo = Path("/usr/bin/lipo")
    with tempfile.TemporaryDirectory(prefix="wins-apple-pkg-arch-") as tmp_dir:
        expanded = Path(tmp_dir) / "expanded"
        try:
            completed = subprocess.run(
                [str(pkgutil), "--expand-full", str(artifact_path), str(expanded)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=PKGUTIL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise FreezeError(
                f"pkgutil --expand-full timed out on {artifact_path}"
            ) from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise FreezeError(
                f"could not expand {artifact_path} for architecture inventory: {stderr}"
            )
        host_plists = [
            path
            for path in expanded.rglob("Info.plist")
            if path.parent.name == "Contents" and path.parent.parent.suffix == ".app"
        ]
        if len(host_plists) != 1:
            raise FreezeError(
                f"{artifact_path} must contain exactly one macOS app payload plist"
            )
        host_plist = host_plists[0]
        host_app = host_plist.parent.parent
        _reject_symlinked_components(expanded, host_plist, artifact_path, "architecture inventory")
        plist_data = plistlib.loads(host_plist.read_bytes())
        executable = str(plist_data.get("CFBundleExecutable") or "").strip()
        if not executable:
            raise FreezeError(f"{artifact_path} host Info.plist missing CFBundleExecutable")
        # The plist value is joined to a path: an absolute name or a separator
        # would let the inventory measure a binary outside Contents/MacOS.
        if (
            "/" in executable
            or "\\" in executable
            or "\0" in executable
            or executable in {".", ".."}
        ):
            raise FreezeError(
                f"{artifact_path} host Info.plist CFBundleExecutable is not a plain file name"
            )
        exec_path = host_app / "Contents" / "MacOS" / executable
        if exec_path.is_symlink() or not exec_path.is_file():
            raise FreezeError(f"{artifact_path} missing macOS executable {executable}")
        _reject_symlinked_components(expanded, exec_path, artifact_path, "architecture inventory")
        try:
            archs_proc = subprocess.run(
                [str(lipo), "-archs", str(exec_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=LIPO_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise FreezeError(f"lipo -archs timed out on {exec_path}") from exc
        if archs_proc.returncode != 0:
            raise FreezeError(f"lipo -archs failed on {exec_path}")
        archs = archs_proc.stdout.decode("utf-8", errors="replace").split()
        inventory = {
            "required_architectures": list(REQUIRED_MACOS_ARCHITECTURES),
            "shipped": [
                {
                    "path": f"{host_app.name}/Contents/MacOS/{executable}",
                    "sha256": sha256_file(exec_path),
                    "size_bytes": exec_path.stat().st_size,
                    "architectures": archs,
                }
            ],
        }
        return validate_macos_architecture_inventory(inventory, require_complete=True)


def _archive_privacy_hashes(report: dict[str, object], archive_name: str) -> dict[str, str]:
    entries = [
        entry
        for entry in report.get("archives") or []
        if isinstance(entry, dict) and entry.get("archive") == archive_name
    ]
    if len(entries) != 1:
        raise FreezeError(f"archive privacy inventory must describe {archive_name} exactly once")
    hashes: dict[str, str] = {}
    for item in entries[0].get("privacy_manifests") or []:
        path = str(item.get("path") or "") if isinstance(item, dict) else ""
        if not path.startswith(ARCHIVE_APPLICATIONS_PREFIX):
            raise FreezeError(
                f"{archive_name} privacy manifest path is outside Products/Applications: {path!r}"
            )
        relative = path[len(ARCHIVE_APPLICATIONS_PREFIX):]
        if relative in hashes:
            raise FreezeError(f"{archive_name} lists privacy manifest {relative!r} twice")
        hashes[relative] = str(item.get("sha256") or "")
    return hashes


def _ipa_privacy_hashes(artifact_path: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    try:
        with zipfile.ZipFile(artifact_path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise FreezeError(f"{artifact_path} has duplicate zip members")
            # The member policy of the embedded Watch identity read: no links,
            # special or encrypted members, no case-colliding names, bounded sizes.
            try:
                _require_safe_ipa_members(archive, f"{artifact_path}")
            except CollectorError as exc:
                raise FreezeError(str(exc)) from exc
            for name in names:
                # PurePosixPath drops "." and empty segments, so two raw names
                # could otherwise measure as one manifest; refuse them raw.
                if any(part in {"", ".", ".."} for part in name.rstrip("/").split("/")):
                    raise FreezeError(f"{artifact_path} has an unsafe zip member path: {name!r}")
                member = PurePosixPath(name)
                if name.endswith("/") or member.name != PRIVACY_MANIFEST_NAME:
                    continue
                if member.is_absolute() or ".." in member.parts or member.parts[0] != "Payload":
                    raise FreezeError(f"{artifact_path} privacy manifest outside Payload: {name!r}")
                hashes["/".join(member.parts[1:])] = hashlib.sha256(archive.read(name)).hexdigest()
    except zipfile.BadZipFile as exc:
        raise FreezeError(f"{artifact_path} is not a readable IPA") from exc
    return hashes


def _pkg_privacy_hashes(artifact_path: Path) -> dict[str, str]:
    pkgutil = Path("/usr/sbin/pkgutil")
    with tempfile.TemporaryDirectory(prefix="wins-apple-pkg-privacy-") as tmp_dir:
        expanded = Path(tmp_dir) / "expanded"
        try:
            completed = subprocess.run(
                [str(pkgutil), "--expand-full", str(artifact_path), str(expanded)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=PKGUTIL_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as exc:
            raise FreezeError(f"pkgutil --expand-full timed out on {artifact_path}") from exc
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise FreezeError(
                f"could not expand {artifact_path} for the privacy manifest binding: {stderr}"
            )
        host_apps = [
            path.parent.parent
            for path in expanded.rglob("Info.plist")
            if path.parent.name == "Contents" and path.parent.parent.suffix == ".app"
        ]
        if len(host_apps) != 1:
            raise FreezeError(f"{artifact_path} must contain exactly one macOS app payload")
        host_app = host_apps[0]
        # The walk starts at host_app: no component on the way to it may be a link.
        _reject_symlinked_components(
            expanded, host_app / "Contents" / "Info.plist", artifact_path, "privacy manifest"
        )
        hashes: dict[str, str] = {}
        # Versioned framework links (Resources -> Versions/Current/Resources) are not
        # followed, as the archive report's glob does not follow them either.
        for directory, _subdirectories, names in os.walk(host_app, followlinks=False):
            if PRIVACY_MANIFEST_NAME not in names:
                continue
            path = Path(directory) / PRIVACY_MANIFEST_NAME
            # A linked manifest is either measured outside the package or skipped,
            # and a skipped one ships unbound: refuse it rather than pass it unseen.
            _reject_symlinked_components(expanded, path, artifact_path, "privacy manifest")
            if not path.is_file():
                continue
            relative = f"{host_app.name}/{path.relative_to(host_app).as_posix()}"
            hashes[relative] = sha256_file(path)
        return hashes


def bind_archive_privacy_inventory(inventory: Path, ios_path: Path, macos_path: Path) -> None:
    """The archive report must describe the privacy manifests inside the exact candidates."""
    try:
        report = json.loads(inventory.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezeError("archive privacy inventory is not valid JSON") from exc
    if not isinstance(report, dict):
        raise FreezeError("archive privacy inventory must contain a JSON object")
    label = read_json(PRIVACY_LABEL_MANIFEST)
    evidence = label.get("binary_evidence") if isinstance(label, dict) else None
    expected = evidence.get("expected_archives") if isinstance(evidence, dict) else None
    _validate_archive_privacy_report(report, expected)
    for platform, measured in (
        ("ios", _ipa_privacy_hashes(ios_path)),
        ("macos", _pkg_privacy_hashes(macos_path)),
    ):
        recorded = _archive_privacy_hashes(report, ARCHIVE_PRIVACY_ARCHIVES[platform])
        if recorded != measured:
            differing = sorted(
                key
                for key in set(recorded) | set(measured)
                if recorded.get(key) != measured.get(key)
            )
            raise FreezeError(
                f"{platform} candidate privacy manifests differ from the archive privacy "
                f"inventory: {differing}"
            )


def freeze(args: argparse.Namespace) -> None:
    ios_relative = Path(args.ios_artifact)
    macos_relative = Path(args.macos_artifact)
    ios_path = require_repo_file(ios_relative, ".ipa", "iOS candidate")
    macos_path = require_repo_file(macos_relative, ".pkg", "macOS candidate")
    receipt_directory = require_owner_only_artifacts_path(
        args.receipt_directory,
        "receipt directory",
        directory=True,
    )
    release_input_index, release_input_index_anchor = require_anchored_file(
        args.release_input_index,
        "release input index",
    )
    archive_log = require_receipt_log(
        args.archive_export_log,
        receipt_directory,
        "archive/export log",
    )
    verification_log = require_receipt_log(
        args.verification_log,
        receipt_directory,
        "verification log",
    )
    archive_privacy_inventory = require_receipt_file(
        args.archive_privacy_inventory,
        receipt_directory,
        "archive privacy inventory",
    )
    require_archive_export_markers(archive_log)
    ios_receipt, ios_receipt_anchor, ios_receipt_result = require_build_receipt(
        args.ios_build_receipt,
        receipt_directory,
        release_input_index,
        "ios",
        ios_path,
    )
    macos_receipt, macos_receipt_anchor, macos_receipt_result = require_build_receipt(
        args.macos_build_receipt,
        receipt_directory,
        release_input_index,
        "macos",
        macos_path,
    )
    bind_archive_privacy_inventory(archive_privacy_inventory, ios_path, macos_path)
    commit = source_commit()
    version, build = pubspec_version()
    artifacts = [
        artifact_entry(
            "ios",
            ios_relative,
            ios_path,
            archive_log,
            verification_log,
            release_input_index,
            ios_receipt,
            ios_receipt_anchor,
            ios_receipt_result,
        ),
        artifact_entry(
            "macos",
            macos_relative,
            macos_path,
            archive_log,
            verification_log,
            release_input_index,
            macos_receipt,
            macos_receipt_anchor,
            macos_receipt_result,
        ),
    ]
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    manifest = {
        "schema_version": 1,
        "generated_at_utc": generated,
        "app_version": version,
        "build_number": build,
        "candidate_set_status": "complete_local_candidates",
        "upload_status": "not_uploaded",
        "submission_package_validation_status": "pending_current_runtime_and_owner_evidence",
        "submission_package_validation_log": artifact_reference(verification_log),
        "submission_package_validation_log_sha256": sha256_file(verification_log),
        "release_input_index": artifact_reference(release_input_index),
        "release_input_index_sha256": sha256_file(release_input_index),
        "release_input_index_anchor": artifact_reference(release_input_index_anchor),
        "release_input_index_anchor_sha256": sha256_file(release_input_index_anchor),
        "archive_privacy_inventory": artifact_reference(archive_privacy_inventory),
        "archive_privacy_inventory_sha256": sha256_file(archive_privacy_inventory),
        "source_commit": commit,
        "notes": (
            f"Paired source-current {version}+{build} App Store-local candidates were "
            "rebuilt, independently re-verified, and atomically hash-frozen. No upload "
            "or App Review mutation occurred."
        ),
        "artifacts": artifacts,
    }

    manifest_path = ROOT / ARTIFACT_MANIFEST.relative_to(ROOT)
    previous = manifest_path.read_bytes() if manifest_path.exists() else None
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=manifest_path.parent,
            prefix=".release_candidate.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            json.dump(manifest, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, manifest_path)
        fsync_directory(manifest_path.parent)
        temp_path = None
        messages = validate_artifact_manifest(
            verified_receipts={"ios": ios_receipt_result, "macos": macos_receipt_result}
        )
    except Exception:
        if previous is None:
            manifest_path.unlink(missing_ok=True)
        else:
            restore = manifest_path.with_name(".release_candidate.restore.tmp")
            restore.write_bytes(previous)
            os.chmod(restore, 0o600)
            os.replace(restore, manifest_path)
        fsync_directory(manifest_path.parent)
        raise
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    for message in messages:
        print(message)
    for entry in artifacts:
        print(
            f"FROZEN {entry['platform']} sha256={entry['sha256']} "
            f"size={entry['size_bytes']}"
        )
    print("Apple release-candidate manifest atomically refreshed and validated.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ios-artifact", default=str(DEFAULT_IOS))
    parser.add_argument("--macos-artifact", default=str(DEFAULT_MACOS))
    parser.add_argument("--receipt-directory", required=True)
    parser.add_argument("--release-input-index", required=True)
    parser.add_argument("--ios-build-receipt", required=True)
    parser.add_argument("--macos-build-receipt", required=True)
    parser.add_argument("--archive-export-log", required=True)
    parser.add_argument("--verification-log", required=True)
    parser.add_argument("--archive-privacy-inventory", required=True)
    return parser.parse_args()


def main() -> int:
    try:
        freeze(parse_args())
        return 0
    except (FreezeError, AssertionError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
