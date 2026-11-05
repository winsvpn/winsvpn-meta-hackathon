#!/usr/bin/env python3
"""Remote-host half of a Mac-orchestrated (remote-attested) release build.

The authenticated dependency-freeze worker runs only on the macOS release host.
For a Windows or Linux build the Mac runs begin-build --remote-host, which
writes a deterministic tar of the frozen revision and binds its digest in the
begin record, and writes REMOTE_INPUT.json (see tools/release_remote_build.py).
On the remote native host this stdlib-only tool replaces the producer's direct
controller calls:

  extract-source  check the shipped tar against REMOTE_INPUT.json (digest, size,
                  Git blob listing) and extract it into a new directory
  verify-inputs   check the shipped index and manifests against the digests the
                  Mac recorded, then every shared, native and producer manifest
                  file in the tree (path, size, sha256); a forged or edited
                  manifest or input file is refused
  record-run      write REMOTE_RUN.json binding the produced artifact bytes to
                  the begin record; the Mac's finish-build compares it with the
                  copied-back artifact and the begin record

Nothing here grants authority. finish-build on the Mac validates the artifact
bytes and refuses any run record that differs from its begin record.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform as host_platform
import posixpath
import re
import shutil
import stat
import sys
import tarfile

INPUT_CONTRACT = "winsvpn-remote-attestation-input-v1"
SOURCE_ARCHIVE_CONTRACT = "winsvpn-remote-source-archive-v1"
RUN_RECORD_CONTRACT = "winsvpn-remote-producer-run-v1"
# A Windows build host cannot load the authenticated secret inventory, so its run record
# says finish-build on the release host runs the exact scan (tools/release_remote_build.py).
SECRET_SCAN_DEFERRED = "deferred-to-release-host"
REMOTE_PRODUCERS = {
    ("linux", "linux"): "tools/build_linux_release.sh",
    ("windows", "windows"): "installer/windows/build_installer.ps1",
}
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_EXPANDED_BYTES = 16 * 1024 * 1024 * 1024
# Windows build hosts get each symbolic link as a copy of its target; see
# extract_source.
MATERIALIZE_SYMLINKS = os.name == "nt"
HEX64 = re.compile(r"[0-9a-f]{64}")
INPUT_KEYS = {
    "contract",
    "release",
    "platform",
    "remote_host",
    "build_begin_sha256",
    "release_input_index",
    "shared_manifest",
    "platform_manifest",
    "source_archive",
    "producer",
}
ARCHIVE_KEYS = {
    "contract",
    "path",
    "sha256",
    "size_bytes",
    "revision",
    "object_format",
    "file_count",
    "listing_sha256",
    "mtime",
}


class RemoteAttestationError(Exception):
    """A remote attestation check refused."""


def _fail(message: str) -> None:
    raise RemoteAttestationError(message)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    _fail(f"non-finite JSON number: {value}")
    return None


def _read_regular(path: pathlib.Path, label: str, limit: int | None = None) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise RemoteAttestationError(f"{label} is unavailable: {path}") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail(f"{label} is not a single-link regular file: {path}")
    if limit is not None and before.st_size > limit:
        _fail(f"{label} exceeds its size bound: {path}")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            _fail(f"{label} changed while it was opened: {path}")
        chunks = []
        remaining = opened.st_size
        while remaining:
            block = os.read(descriptor, min(4 * 1024 * 1024, remaining))
            if not block:
                _fail(f"{label} was truncated while read: {path}")
            chunks.append(block)
            remaining -= len(block)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _sha256_file(path: pathlib.Path, label: str) -> tuple[str, int]:
    # The custody of _read_regular: one link, no symbolic link at open, and the
    # descriptor hashed is the inode that was checked (R24 V2 finding 2).
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        _fail(f"{label} is not a single-link regular file: {path}")
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            _fail(f"{label} changed while it was opened: {path}")
        while True:
            block = os.read(descriptor, 4 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
            size += len(block)
    finally:
        os.close(descriptor)
    if size != before.st_size:
        _fail(f"{label} changed while it was hashed: {path}")
    return digest.hexdigest(), size


def _load_json(payload: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RemoteAttestationError(f"{label} is not strict JSON: {exc}") from exc
    if type(value) is not dict:
        _fail(f"{label} is not a JSON object")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        _fail(f"{label} fields are not exact")
    return value  # type: ignore[return-value]


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or HEX64.fullmatch(value) is None:
        _fail(f"{label} is not a SHA-256 digest")
    return value  # type: ignore[return-value]


def _relative(value: object, label: str) -> str:
    if type(value) is not str or not value or "\\" in value or "\x00" in value:
        _fail(f"{label} path is unsafe")
    pure = pathlib.PurePosixPath(value)  # type: ignore[arg-type]
    if pure.is_absolute() or ".." in pure.parts or any(not part for part in pure.parts):
        _fail(f"{label} path escapes the repository")
    return value  # type: ignore[return-value]


def load_input(path: pathlib.Path) -> dict[str, object]:
    record = _exact(
        _load_json(_read_regular(path, "Remote input record", MAX_JSON_BYTES), "Remote input record"),
        INPUT_KEYS,
        "Remote input record",
    )
    if record.get("contract") != INPUT_CONTRACT:
        _fail("Remote input record contract is invalid")
    platform = record.get("platform")
    remote_host = record.get("remote_host")
    producer = _exact(record.get("producer"), {"path", "sha256"}, "Remote producer")
    if REMOTE_PRODUCERS.get((platform, remote_host)) != producer.get("path"):  # type: ignore[arg-type]
        _fail("Remote input record names an unreviewed producer")
    _hex64(producer.get("sha256"), "Remote producer digest")
    _hex64(record.get("build_begin_sha256"), "Build begin digest")
    for key in ("release_input_index", "shared_manifest", "platform_manifest"):
        reference = _exact(record.get(key), {"path", "sha256"}, key)
        _relative(reference.get("path"), key)
        _hex64(reference.get("sha256"), key)
        if pathlib.PurePosixPath(reference["path"]).parts[0] != ".artifacts":  # type: ignore[arg-type]
            _fail(f"{key} must stay under .artifacts/")
    archive = _exact(record.get("source_archive"), ARCHIVE_KEYS, "Source archive")
    if archive.get("contract") != SOURCE_ARCHIVE_CONTRACT or archive.get("object_format") not in {
        "sha1",
        "sha256",
    }:
        _fail("Source archive record is invalid")
    _hex64(archive.get("sha256"), "Source archive digest")
    _hex64(archive.get("listing_sha256"), "Source listing digest")
    for key in ("size_bytes", "file_count", "mtime"):
        if type(archive.get(key)) is not int or archive[key] < 1:  # type: ignore[operator]
            _fail(f"Source archive {key} is invalid")
    return record


def _blob_oid(payload: bytes, object_format: str) -> str:
    body = f"blob {len(payload)}\0".encode("ascii") + payload
    if object_format == "sha1":
        return hashlib.sha1(body, usedforsecurity=False).hexdigest()
    return hashlib.sha256(body).hexdigest()


def _symlink_blobs(block: dict[str, object], label: str) -> list[tuple[str, str, str]]:
    """Return (path, object format, blob id) for each symbolic link a section binds."""

    audit = block.get("git_audit")
    if audit is None:
        return []
    if type(audit) is not dict:
        _fail(f"{label} Git audit is malformed")
    object_format = audit.get("object_format")  # type: ignore[union-attr]
    if object_format not in {"sha1", "sha256"}:
        _fail(f"{label} Git object format is not reviewed")
    blobs = audit.get("selected_blobs")  # type: ignore[union-attr]
    if type(blobs) is not list:
        _fail(f"{label} Git selected blobs are malformed")
    width = 40 if object_format == "sha1" else 64
    links: list[tuple[str, str, str]] = []
    for blob in blobs:  # type: ignore[union-attr]
        if type(blob) is not dict:
            _fail(f"{label} Git selected blob is malformed")
        if blob.get("mode") != "120000":
            continue
        blob = _exact(blob, {"path", "mode", "oid"}, f"{label} symbolic link")
        relative = _relative(blob.get("path"), f"{label} symbolic link")
        oid = blob.get("oid")
        if type(oid) is not str or re.fullmatch(f"[0-9a-f]{{{width}}}", oid) is None:
            _fail(f"{label} symbolic link blob id is invalid: {relative}")
        links.append((relative, object_format, oid))  # type: ignore[arg-type]
    return links


def extract_source(input_path: pathlib.Path, archive_path: pathlib.Path, destination: pathlib.Path) -> dict[str, object]:
    record = load_input(input_path)
    expected = record["source_archive"]  # type: ignore[index]
    if _sha256_file(archive_path, "Source archive") != (expected["sha256"], expected["size_bytes"]):  # type: ignore[index]
        _fail("Source archive digest or size differs from the begin record")
    if os.path.lexists(destination):
        _fail(f"extraction destination must be a new path: {destination}")
    destination.mkdir(mode=0o700, parents=False)
    created = os.lstat(destination)
    try:
        return _extract_source_into(expected, archive_path, destination)
    except BaseException:
        # A refused or partial extraction must not leave a tree at the
        # operator's path that looks like the frozen revision. Only the
        # directory created just above is removed: if the path was replaced
        # while extracting, what is there now is not ours to delete.
        try:
            current = os.lstat(destination)
        except OSError:
            current = None
        if (
            current is not None
            and stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)
        ):
            shutil.rmtree(destination, ignore_errors=True)
        raise


def _extract_source_into(
    expected: dict[str, object], archive_path: pathlib.Path, destination: pathlib.Path
) -> dict[str, object]:
    root = destination.resolve(strict=True)
    listing = hashlib.sha256()
    count = 0
    expanded = 0
    previous = None
    with tarfile.open(archive_path, mode="r:") as archive:
        for member in archive:
            count += 1
            if count > MAX_MEMBERS:
                _fail("Source archive has too many members")
            name = _relative(member.name, "Source archive member")
            encoded = name.encode("utf-8")
            if previous is not None and encoded <= previous:
                _fail("Source archive members are not in reviewed order")
            previous = encoded
            target = root.joinpath(*pathlib.PurePosixPath(name).parts)
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            if target.parent.resolve(strict=True) != root.joinpath(
                *pathlib.PurePosixPath(name).parent.parts
            ):
                _fail(f"Source archive member parent escapes the tree: {name}")
            if member.issym():
                link = member.linkname
                resolved = os.path.normpath(
                    str(pathlib.PurePosixPath(name).parent / link)
                ).replace("\\", "/")
                if (
                    not link
                    or pathlib.PurePosixPath(link).is_absolute()
                    or resolved.startswith("../")
                    or resolved == ".."
                ):
                    _fail(f"Source archive symbolic link escapes the tree: {name}")
                payload = link.encode("utf-8")
                if MATERIALIZE_SYMLINKS:
                    # A Windows symbolic link needs a privilege or Developer
                    # Mode, and a core.symlinks=false text file holding the
                    # target breaks the build (dart compile exe parses
                    # tools/native_messaging/host/lib as Dart). Write the
                    # target's bytes instead. The reviewed member order has
                    # already extracted the target, the listing below binds
                    # it, and the Mac freeze binds the link itself (mode
                    # 120000 and its exact target text).
                    source_path = root.joinpath(*pathlib.PurePosixPath(resolved).parts)
                    if source_path.is_symlink() or not source_path.is_file():
                        _fail(
                            "Source archive symbolic link target is not an extracted "
                            f"regular file: {name}"
                        )
                    copied = source_path.read_bytes()
                    expanded += len(copied)
                    if expanded > MAX_EXPANDED_BYTES:
                        _fail("Source archive expands beyond its bound")
                    with open(target, "xb") as handle:
                        handle.write(copied)
                else:
                    os.symlink(link, target)
                mode = "120000"
            elif member.isfile():
                if member.mode & 0o7777 not in {0o644, 0o755}:
                    _fail(f"Source archive member mode is not reviewed: {name}")
                # The producer stamps every member with the revision's commit time
                # and records it. The listing below binds content, mode and order
                # but not the time that os.utime applies to the tree; bind it here
                # so the archive bytes hashed before the open are all that shapes it.
                if member.mtime != expected["mtime"]:  # type: ignore[index]
                    _fail(f"Source archive member time differs from the begin record: {name}")
                expanded += member.size
                if expanded > MAX_EXPANDED_BYTES:
                    _fail("Source archive expands beyond its bound")
                source = archive.extractfile(member)
                if source is None:
                    _fail(f"Source archive member is unreadable: {name}")
                payload = source.read(member.size + 1)  # type: ignore[union-attr]
                if len(payload) != member.size:
                    _fail(f"Source archive member size changed: {name}")
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    0o755 if member.mode & 0o111 else 0o644,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
                os.utime(target, (member.mtime, member.mtime))
                mode = "100755" if member.mode & 0o111 else "100644"
            else:
                _fail(f"Source archive member type is not reviewed: {name}")
            listing.update(
                f"{mode} {_blob_oid(payload, expected['object_format'])} {name}\n".encode("utf-8")  # type: ignore[index]
            )
    if count != expected["file_count"] or listing.hexdigest() != expected["listing_sha256"]:  # type: ignore[index]
        _fail("Extracted source tree differs from the frozen revision listing")
    return {"ok": True, "files": count, "destination": str(root)}


def verify_inputs(repo: pathlib.Path, input_path: pathlib.Path, index: pathlib.Path | None) -> dict[str, object]:
    record = load_input(input_path)
    root = repo.resolve(strict=True)
    if index is not None:
        expected_index = root.joinpath(*pathlib.PurePosixPath(record["release_input_index"]["path"]).parts)  # type: ignore[index]
        if index.resolve(strict=True) != expected_index.resolve(strict=True):
            _fail("Release input index differs from the one the Mac verified")
    manifests: dict[str, dict[str, object]] = {}
    for key in ("release_input_index", "shared_manifest", "platform_manifest"):
        reference = record[key]  # type: ignore[index]
        path = root.joinpath(*pathlib.PurePosixPath(reference["path"]).parts)
        payload = _read_regular(path, key, MAX_JSON_BYTES)
        if hashlib.sha256(payload).hexdigest() != reference["sha256"]:
            _fail(f"{key} differs from the digest the Mac recorded (forged or edited manifest)")
        manifests[key] = _load_json(payload, key)
    index_record = manifests["release_input_index"]
    platform = record["platform"]
    platform_reference = (index_record.get("platform_manifests") or {}).get(platform)  # type: ignore[union-attr]
    shared_reference = index_record.get("shared_manifest")
    if (
        index_record.get("release") != record["release"]
        or type(platform_reference) is not dict
        or platform_reference.get("sha256") != record["platform_manifest"]["sha256"]  # type: ignore[index]
        or type(shared_reference) is not dict
        or shared_reference.get("sha256") != record["shared_manifest"]["sha256"]  # type: ignore[index]
        or manifests["platform_manifest"].get("platform") != platform
    ):
        _fail("Release input index does not bind the shipped manifests")
    checked = 0
    verified_files: dict[str, tuple[str, int]] = {}
    symlink_blobs: list[tuple[str, str, str]] = []
    for key, sections in (
        ("shared_manifest", ("inputs",)),
        ("platform_manifest", ("native_inputs", "producer_inputs")),
    ):
        for section in sections:
            block = manifests[key].get(section)
            files = block.get("files") if type(block) is dict else None
            if type(files) is not list or not files:
                _fail(f"{key} {section} file list is missing")
            for entry in files:  # type: ignore[union-attr]
                entry = _exact(entry, {"path", "sha256", "size"}, f"{section} file")
                relative = _relative(entry.get("path"), f"{section} file")
                expected = (_hex64(entry.get("sha256"), relative), entry.get("size"))
                if _sha256_file(root.joinpath(*pathlib.PurePosixPath(relative).parts), relative) != expected:
                    _fail(f"native input differs from the frozen manifest: {relative}")
                verified_files[relative] = expected  # type: ignore[assignment]
                checked += 1
            symlink_blobs.extend(_symlink_blobs(block, f"{key} {section}"))  # type: ignore[arg-type]
    # A symbolic link input (the Windows native host's lib/*.dart aliases) is
    # bound by the Mac freeze only as a Git blob of its target text, never in a
    # files list, so it is checked here against that blob: a link must still
    # carry the frozen target text, and a Windows copy made by extract-source
    # must still hold the bytes of the input it names. Either way the target
    # must be an input whose bytes were verified above.
    for relative, object_format, oid in symlink_blobs:
        alias = root.joinpath(*pathlib.PurePosixPath(relative).parts)
        alias_dir = pathlib.PurePosixPath(relative).parent
        if MATERIALIZE_SYMLINKS:
            targets = [
                path
                for path in verified_files
                if _blob_oid(
                    posixpath.relpath("/" + path, "/" + str(alias_dir)).encode("utf-8"),
                    object_format,
                )
                == oid
            ]
            if len(targets) != 1:
                _fail(f"symbolic link input names no verified input: {relative}")
            if _sha256_file(alias, relative) != verified_files[targets[0]]:
                _fail(f"materialized symbolic link input differs from its target: {relative}")
        else:
            try:
                info = os.lstat(alias)
            except OSError as exc:
                raise RemoteAttestationError(
                    f"symbolic link input is unavailable: {relative}"
                ) from exc
            if not stat.S_ISLNK(info.st_mode):
                _fail(f"symbolic link input is not a symbolic link: {relative}")
            link = os.readlink(alias)
            if _blob_oid(link.encode("utf-8"), object_format) != oid:
                _fail(f"symbolic link input target differs from the frozen revision: {relative}")
            target = posixpath.normpath(str(alias_dir / link))
            if target not in verified_files:
                _fail(f"symbolic link input names no verified input: {relative}")
        checked += 1
    producer = record["producer"]  # type: ignore[index]
    if _sha256_file(root.joinpath(*pathlib.PurePosixPath(producer["path"]).parts), "producer")[0] != producer["sha256"]:
        _fail("remote producer differs from the producer the Mac shipped")
    return {"ok": True, "files_checked": checked}


def record_run(
    repo: pathlib.Path,
    input_path: pathlib.Path,
    artifact: pathlib.Path,
    toolchain: dict[str, str],
    output: pathlib.Path,
    signing: str = "unsigned",
    secret_scan: str | None = None,
) -> dict[str, object]:
    if signing not in {"unsigned", "producer", "orchestrator"}:
        _fail("signing mode is not reviewed")
    if secret_scan not in {None, SECRET_SCAN_DEFERRED}:
        _fail("secret scan mode is not reviewed")
    verify_inputs(repo, input_path, None)
    record = load_input(input_path)
    if (secret_scan is not None) != (record["platform"] == "windows"):
        _fail("only a Windows run defers its secret scan, and a Windows run must")
    if os.path.lexists(output):
        _fail(f"remote run record must be a new path: {output}")
    artifact_sha256, artifact_size = _sha256_file(artifact, "artifact")
    run = {
        "contract": RUN_RECORD_CONTRACT,
        "release": record["release"],
        "platform": record["platform"],
        "remote_host": record["remote_host"],
        "build_begin_sha256": record["build_begin_sha256"],
        "source_archive_sha256": record["source_archive"]["sha256"],  # type: ignore[index]
        "release_input_index_sha256": record["release_input_index"]["sha256"],  # type: ignore[index]
        "platform_manifest_sha256": record["platform_manifest"]["sha256"],  # type: ignore[index]
        "producer": record["producer"],
        "toolchain": toolchain,
        "artifact": {"name": artifact.name, "size_bytes": artifact_size, "sha256": artifact_sha256},
        "signing": signing,
        "remote_system": {"system": host_platform.system(), "machine": host_platform.machine()},
        "finished_utc": dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if secret_scan is not None:
        run["secret_scan"] = secret_scan
    payload = (json.dumps(run, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
    return {"ok": True, "run_record": str(output), "artifact_sha256": artifact_sha256}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    extract = commands.add_parser("extract-source")
    extract.add_argument("--input", required=True)
    extract.add_argument("--archive", required=True)
    extract.add_argument("--dest", required=True)
    verify = commands.add_parser("verify-inputs")
    verify.add_argument("--repo", required=True)
    verify.add_argument("--input", required=True)
    verify.add_argument("--index")
    run = commands.add_parser("record-run")
    run.add_argument("--repo", required=True)
    run.add_argument("--input", required=True)
    run.add_argument("--artifact", required=True)
    run.add_argument("--toolchain-name", required=True)
    run.add_argument("--toolchain-version", required=True)
    run.add_argument("--toolchain-revision", default="")
    run.add_argument("--target", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--signing", choices=("unsigned", "producer", "orchestrator"), required=True)
    run.add_argument(
        "--secret-scan",
        choices=(SECRET_SCAN_DEFERRED,),
        help="a Windows run records that finish-build on the release host runs its secret scan",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "extract-source":
            result = extract_source(pathlib.Path(args.input), pathlib.Path(args.archive), pathlib.Path(args.dest))
        elif args.command == "verify-inputs":
            result = verify_inputs(
                pathlib.Path(args.repo),
                pathlib.Path(args.input),
                None if args.index is None else pathlib.Path(args.index),
            )
        else:
            result = record_run(
                pathlib.Path(args.repo),
                pathlib.Path(args.input),
                pathlib.Path(args.artifact),
                {
                    "name": args.toolchain_name,
                    "version": args.toolchain_version,
                    "revision": args.toolchain_revision,
                    "target": args.target,
                },
                pathlib.Path(args.output),
                args.signing,
                args.secret_scan,
            )
    except (RemoteAttestationError, OSError, tarfile.TarError) as exc:
        print(f"REMOTE ATTESTATION CHECK: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"REMOTE ATTESTATION CHECK: PASS {args.command} {json.dumps(result, sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
