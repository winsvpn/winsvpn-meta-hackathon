#!/usr/bin/env python3
"""Produce immutable local receipts for exact cross-store release artifacts.

This tool verifies an existing artifact and build receipt against an existing
release-input freeze, executes the target's signing and hardening gates, and
then writes one local custody receipt. It never builds, signs, uploads,
deploys, or authorizes publication.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import tempfile
from collections.abc import Callable

import cross_store_gate_runner as gate_runner
import cross_store_upload_readiness as readiness
import release_dependency_freeze as freeze


class TargetReceiptError(RuntimeError):
    """Raised when an exact target receipt cannot be produced safely."""


def _canonical_json(record: dict[str, object]) -> bytes:
    return (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short receipt write")
        view = view[written:]


def _fsync_directory(path: pathlib.Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_private_directory(path: pathlib.Path, label: str) -> None:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or (hasattr(os, "getuid") and info.st_uid != os.getuid())
    ):
        raise TargetReceiptError(f"{label} must be an owner-controlled 0700 directory.")


def _unlink_matching_inode(path: pathlib.Path, identity: tuple[int, int]) -> bool:
    """Remove only the named inode, preserving a raced replacement.

    POSIX has no portable compare-and-unlink operation.  Quarantining the leaf
    with renameat first makes the namespace change atomic.  A replacement that
    wins before the rename is moved aside, identified, and restored without
    ever being unlinked.  The unguessable quarantine name and owner-only 0700
    parent bound the remaining same-owner interference surface.
    """

    parent = path.parent
    _require_private_directory(parent, "Cleanup parent")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_before = parent.lstat()
    directory = os.open(parent, flags)
    try:
        parent_open = os.fstat(directory)
        if (
            (parent_before.st_dev, parent_before.st_ino)
            != (parent_open.st_dev, parent_open.st_ino)
            or not stat.S_ISDIR(parent_open.st_mode)
            or stat.S_IMODE(parent_open.st_mode) != 0o700
            or (hasattr(os, "getuid") and parent_open.st_uid != os.getuid())
        ):
            raise TargetReceiptError("Cleanup parent identity or custody changed.")

        name = path.name
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != identity:
            return False

        quarantine = f".{name}.cleanup-{secrets.token_hex(16)}"
        try:
            os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise TargetReceiptError("Cleanup quarantine unexpectedly exists.")

        os.rename(
            name,
            quarantine,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        moved = os.stat(quarantine, dir_fd=directory, follow_symlinks=False)
        if (moved.st_dev, moved.st_ino) != identity:
            try:
                os.link(
                    quarantine,
                    name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                    follow_symlinks=False,
                )
            except FileExistsError:
                # Preserve both names.  Deleting either could delete a raced
                # replacement selected by another same-owner process.
                return False
            os.unlink(quarantine, dir_fd=directory)
            os.fsync(directory)
            return False

        os.unlink(quarantine, dir_fd=directory)
        os.fsync(directory)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(directory)


def _publish_immutable_json(
    repo: pathlib.Path,
    output: pathlib.Path,
    record: dict[str, object],
) -> pathlib.Path:
    """Atomically publish one owner-only receipt without replacing a prior file."""

    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json", output.name) is None:
        raise TargetReceiptError("Receipt output must use a safe .json filename.")
    output = freeze.secure_repo_path(
        repo,
        output,
        "Upload target receipt output",
        must_exist=False,
        allow_missing_leaf=True,
    )
    relative = output.relative_to(repo)
    if not relative.parts or relative.parts[0] != ".artifacts":
        raise TargetReceiptError("Receipt output must stay under .artifacts/.")
    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _require_private_directory(output.parent, "Receipt output parent")
    output = freeze.secure_repo_path(
        repo,
        output,
        "Upload target receipt output",
        must_exist=False,
        allow_missing_leaf=True,
    )
    if output.exists() or output.is_symlink():
        raise TargetReceiptError("Refusing to overwrite an immutable target receipt.")

    descriptor = -1
    temporary_name: str | None = None
    published = False
    published_identity: tuple[int, int] | None = None
    temporary_identity: tuple[int, int] | None = None
    publication_complete = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, _canonical_json(record))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        temporary = pathlib.Path(temporary_name)
        temp_info = temporary.lstat()
        temporary_identity = (temp_info.st_dev, temp_info.st_ino)
        if not stat.S_ISREG(temp_info.st_mode) or stat.S_IMODE(temp_info.st_mode) != 0o600:
            raise TargetReceiptError("Temporary receipt custody is not owner-only.")

        # link() gives same-filesystem atomic visibility plus O_EXCL semantics:
        # an existing destination is never replaced, even if it appears after
        # the preflight check.
        os.link(temporary, output)
        published = True
        output_info = output.lstat()
        published_identity = (output_info.st_dev, output_info.st_ino)
        if (
            not stat.S_ISREG(output_info.st_mode)
            or stat.S_IMODE(output_info.st_mode) != 0o600
            or (output_info.st_dev, output_info.st_ino)
            != (temp_info.st_dev, temp_info.st_ino)
        ):
            raise TargetReceiptError("Published receipt custody is invalid.")
        _fsync_directory(output.parent)
        if not _unlink_matching_inode(temporary, temporary_identity):
            raise TargetReceiptError("Temporary receipt identity changed before cleanup.")
        temporary_name = None
        _fsync_directory(output.parent)
        publication_complete = True
        return output
    except FileExistsError as exc:
        raise TargetReceiptError(
            "Refusing to overwrite an immutable target receipt."
        ) from exc
    except (OSError, freeze.DependencyFreezeError) as exc:
        raise TargetReceiptError(f"Unable to publish target receipt atomically: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if published and not publication_complete and published_identity is not None:
            try:
                if _unlink_matching_inode(output, published_identity):
                    _fsync_directory(output.parent)
            except (OSError, TargetReceiptError):
                pass
        if temporary_name is not None and temporary_identity is not None:
            try:
                _unlink_matching_inode(pathlib.Path(temporary_name), temporary_identity)
            except (OSError, TargetReceiptError):
                pass


def _gate_command(
    repo: pathlib.Path,
    target: readiness.UploadTarget,
    gate_id: str,
    artifact_path: pathlib.Path,
) -> tuple[str, ...]:
    producer_id = readiness.GATE_PRODUCER_IDS[gate_id][0]
    producer = freeze.secure_repo_path(
        repo,
        pathlib.Path(producer_id),
        f"{target.target_id} {gate_id} producer",
        must_exist=True,
    )
    relative_artifact = freeze._relative_repo_path(repo, artifact_path)
    suffix = ("--verify", target.target_id, relative_artifact)
    if producer.suffix.lower() == ".py":
        return (str(pathlib.Path(sys.executable).resolve(strict=True)), producer_id, *suffix)
    if producer.suffix.lower() == ".sh":
        return ("/bin/bash", "--noprofile", "--norc", producer_id, *suffix)
    if os.access(producer, os.X_OK):
        return (producer_id, *suffix)
    raise TargetReceiptError(
        f"{target.target_id} {gate_id} producer has no exact supported launcher."
    )


def _source_binding(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    target: readiness.UploadTarget,
) -> dict[str, object]:
    verified_index = freeze.verify_release_index(repo, index_path, target.platform)
    index_record = readiness._load_json(index_path, "Release input index")
    platform_refs = index_record.get("platform_manifests")
    if not isinstance(platform_refs, dict):
        raise TargetReceiptError("Release input index platform set is malformed.")
    platform_ref = readiness._exact(
        platform_refs.get(target.platform),
        {"path", "sha256", "artifact_input_fingerprint_sha256"},
        f"Indexed {target.platform} manifest",
    )
    platform_manifest = freeze.secure_repo_path(
        repo,
        index_path.parent / str(platform_ref["path"]),
        f"Indexed {target.platform} manifest",
        must_exist=True,
    )
    return {
        "index_path": freeze._relative_repo_path(repo, index_path),
        "index_sha256": freeze._sha256_file(index_path),
        "platform_manifest_path": freeze._relative_repo_path(repo, platform_manifest),
        "platform_manifest_sha256": platform_ref["sha256"],
        "artifact_input_fingerprint_sha256": platform_ref[
            "artifact_input_fingerprint_sha256"
        ],
        "shared_revision": verified_index["shared_revision"],
    }


def _build_binding(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    target: readiness.UploadTarget,
    artifact_path: pathlib.Path,
    build_receipt_path: pathlib.Path,
) -> tuple[dict[str, object], str]:
    if target.manifest_verifier_path is not None:
        result = readiness._verify_manifest_build_receipt(
            repo, target, build_receipt_path, artifact_path
        )
        producer_value = result.get("producer")
        build_target = result.get("target")
    else:
        result = freeze.verify_build_receipt(
            repo, index_path, target.platform, build_receipt_path, artifact_path
        )
        build_record = readiness._load_json(
            build_receipt_path, f"{target.target_id} build receipt"
        )
        toolchain = readiness._exact(
            build_record.get("toolchain"),
            {"name", "version", "revision", "target"},
            f"{target.target_id} build receipt toolchain",
        )
        producer_value = readiness._exact(
            build_record.get("producer"),
            {"path", "sha256"},
            f"{target.target_id} build receipt producer",
        )
        build_target = toolchain.get("target")
    if not isinstance(producer_value, dict):
        raise TargetReceiptError(f"{target.target_id} build producer is malformed.")
    producer_id = producer_value.get("path")
    if (
        not isinstance(producer_id, str)
        or producer_id not in target.producer_ids
        or build_target != target.build_receipt_target
    ):
        raise TargetReceiptError(
            f"{target.target_id} build receipt target or producer was substituted."
        )
    producer_path = freeze.secure_repo_path(
        repo,
        pathlib.Path(producer_id),
        f"{target.target_id} build producer",
        must_exist=True,
    )
    producer_sha = freeze._sha256_file(producer_path)
    if producer_value.get("sha256") != producer_sha:
        raise TargetReceiptError(f"{target.target_id} build producer hash changed.")
    return (
        {
            "path": freeze._relative_repo_path(repo, build_receipt_path),
            "sha256": result["receipt_sha256"],
            "target": target.build_receipt_target,
        },
        producer_id,
    )


def produce_target_receipt(
    repo: pathlib.Path,
    index_path: pathlib.Path,
    target_id: str,
    artifact_path: pathlib.Path,
    build_receipt_path: pathlib.Path,
    output: pathlib.Path,
    evidence_dir: pathlib.Path,
    *,
    runner: gate_runner.ExplicitArgvRunner | None = None,
    clock: Callable[[], dt.datetime] | None = None,
) -> dict[str, object]:
    """Verify and atomically publish one immutable local target receipt."""

    repo = freeze.secure_repo_path(repo, pathlib.Path("."), "Repository root", must_exist=True)
    readiness._assert_target_contract()
    if target_id not in readiness.KNOWN_TARGET_IDS:
        raise TargetReceiptError(f"Unexpected upload target: {target_id}")
    target = readiness.TARGET_BY_ID[target_id]
    output = freeze.secure_repo_path(
        repo,
        output,
        "Upload target receipt output",
        must_exist=False,
        allow_missing_leaf=True,
    )
    if (
        not output.relative_to(repo).parts
        or output.relative_to(repo).parts[0] != ".artifacts"
    ):
        raise TargetReceiptError("Receipt output must stay under .artifacts/.")
    if output.exists() or output.is_symlink():
        raise TargetReceiptError("Refusing to overwrite an immutable target receipt.")
    index_path = freeze.secure_repo_path(
        repo, index_path, "Release input index", must_exist=True
    )
    artifact_path = freeze.secure_repo_path(
        repo, artifact_path, f"{target_id} artifact", must_exist=True
    )
    build_receipt_path = freeze.secure_repo_path(
        repo, build_receipt_path, f"{target_id} build receipt", must_exist=True
    )
    if not any(
        artifact_path.name.lower().endswith(suffix)
        for suffix in target.artifact_suffixes
    ):
        raise TargetReceiptError(f"{target_id} artifact type is not allowed.")

    artifact_bytes, artifact_mtime_ns, artifact_sha = readiness._stable_identity(
        artifact_path, f"{target_id} artifact"
    )
    now = clock or (lambda: dt.datetime.now(tz=dt.timezone.utc))
    preflight_at = now()
    if preflight_at.tzinfo is None or preflight_at.utcoffset() is None:
        raise TargetReceiptError("Receipt clock must return a timezone-aware timestamp.")
    artifact_time = dt.datetime.fromtimestamp(
        artifact_mtime_ns / 1_000_000_000, tz=dt.timezone.utc
    )
    if (
        artifact_time > preflight_at + readiness.MAX_CLOCK_SKEW
        or preflight_at - artifact_time > readiness.MAX_RECEIPT_AGE
    ):
        raise TargetReceiptError(f"{target_id} artifact freshness is invalid.")
    artifact = {
        "path": freeze._relative_repo_path(repo, artifact_path),
        "sha256": artifact_sha,
        "bytes": artifact_bytes,
    }
    build_receipt, producer_id = _build_binding(
        repo, index_path, target, artifact_path, build_receipt_path
    )
    source = _source_binding(repo, index_path, target)
    producer_path = freeze.secure_repo_path(
        repo, pathlib.Path(producer_id), f"{target_id} producer", must_exist=True
    )
    extension_zip: dict[str, object] | None = None
    if target.platform == "extension":
        try:
            extension_zip = readiness.verify_extension_zip_artifact(
                repo, target_id, artifact_path
            )
        except readiness.UploadReadinessError as exc:
            raise TargetReceiptError(str(exc)) from exc
    commands = {
        gate_id: _gate_command(repo, target, gate_id, artifact_path)
        for gate_id in (target.signing_gate_id, target.hardening_gate_id)
    }
    gate_references = readiness.execute_target_gate_transaction(
        repo,
        target_id,
        artifact_path,
        commands,
        evidence_dir,
        runner=runner,
        clock=clock,
    )
    verified_at = now()
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise TargetReceiptError("Receipt clock must return a timezone-aware timestamp.")
    if verified_at < preflight_at:
        raise TargetReceiptError("Receipt clock moved backwards during verification.")
    verified_utc = readiness._utc_timestamp(verified_at)
    receipt = {
        "ok": True,
        "schema_version": readiness.TARGET_RECEIPT_SCHEMA_VERSION,
        "contract": readiness.TARGET_RECEIPT_CONTRACT,
        "release": freeze._release_identity(repo),
        "target_id": target_id,
        "platform": target.platform,
        "verified_utc": verified_utc,
        "build_receipt": build_receipt,
        "artifact": artifact,
        "producer": {
            "id": producer_id,
            "path": producer_id,
            "sha256": freeze._sha256_file(producer_path),
        },
        "signing_verification_gate": gate_references[target.signing_gate_id],
        "obfuscation_privacy_gate": gate_references[target.hardening_gate_id],
        "dependency_source_freeze": source,
        "publication_authorized": False,
        "upload_attempted": False,
    }
    if extension_zip is not None:
        receipt["verifier_source_closure"] = extension_zip["verifier_source_closure"]

    output.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    _require_private_directory(output.parent, "Receipt output parent")
    descriptor, candidate_name = tempfile.mkstemp(
        prefix=f".{output.name}.preflight.", suffix=".json", dir=output.parent
    )
    candidate = pathlib.Path(candidate_name)
    candidate_info = os.fstat(descriptor)
    candidate_identity = (candidate_info.st_dev, candidate_info.st_ino)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, _canonical_json(receipt))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        readiness._verify_target_receipt(
            repo,
            index_path,
            target_id,
            candidate,
            now=verified_at,
        )
        # Recheck the exact bytes immediately before publication. Any changed
        # artifact, build receipt, producer, freeze, or gate evidence fails closed.
        if readiness._stable_identity(artifact_path, f"{target_id} artifact") != (
            artifact_bytes,
            artifact_mtime_ns,
            artifact_sha,
        ):
            raise TargetReceiptError(f"{target_id} artifact changed before publication.")
        readiness._verify_target_receipt(
            repo, index_path, target_id, candidate, now=verified_at
        )
        published = _publish_immutable_json(repo, output, receipt)
        published_info = published.lstat()
        published_identity = (published_info.st_dev, published_info.st_ino)
        try:
            verified = readiness._verify_target_receipt(
                repo, index_path, target_id, published, now=verified_at
            )
        except Exception:
            _unlink_matching_inode(published, published_identity)
            try:
                _fsync_directory(published.parent)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise TargetReceiptError(
            f"Unable to stage or verify the immutable target receipt: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            _unlink_matching_inode(candidate, candidate_identity)
        except (OSError, TargetReceiptError):
            pass
    return {
        "ok": True,
        "target_id": target_id,
        "receipt_path": verified["receipt_path"],
        "receipt_sha256": verified["receipt_sha256"],
        "artifact": verified["artifact"],
        "publication_authorized": False,
        "upload_attempted": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list-targets")
    produce = subparsers.add_parser("produce")
    produce.add_argument("--repo", default=".")
    produce.add_argument("--index", required=True)
    produce.add_argument("--target", required=True, choices=sorted(readiness.KNOWN_TARGET_IDS))
    produce.add_argument("--artifact", required=True)
    produce.add_argument("--build-receipt", required=True)
    produce.add_argument("--output", required=True)
    produce.add_argument("--evidence-dir", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "list-targets":
            result = {
                "ok": True,
                "required_targets": sorted(readiness.REQUIRED_TARGET_IDS),
                "optional_targets": sorted(readiness.OPTIONAL_TARGET_IDS),
                "targets": sorted(readiness.KNOWN_TARGET_IDS),
            }
        else:
            result = produce_target_receipt(
                pathlib.Path(args.repo),
                pathlib.Path(args.index),
                args.target,
                pathlib.Path(args.artifact),
                pathlib.Path(args.build_receipt),
                pathlib.Path(args.output),
                pathlib.Path(args.evidence_dir),
            )
    except (TargetReceiptError, readiness.UploadReadinessError, freeze.DependencyFreezeError) as exc:
        print(f"CROSS-STORE TARGET RECEIPT: FAIL: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
