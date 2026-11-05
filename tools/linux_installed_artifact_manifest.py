#!/usr/bin/env python3
"""Prove that /opt/wins-vpn is the exact payload from one Linux archive.

The public-release lane must not treat a successful installer exit or a typed
SHA-256 as proof of what is running.  This tool hashes every regular archive
member, verifies its normalized mode against the installed tree, rejects
missing/extra/symlink content, and emits a sanitized machine report that can be
bound into the native smoke transcript.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import tarfile
import tempfile
from typing import Any


CONTRACT = "winsvpn-linux-installed-payload-v1"
EXECUTABLES = {
    "amneziawg-go",
    "awg",
    "awg-quick",
    "install.sh",
    "winn-datapath",
    "wins_vpn",
    "winsvpn-bypass-bpf",
    "xray",
}


class ManifestError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_digest(entries: list[dict[str, Any]]) -> str:
    encoded = json.dumps(
        entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_installed_ownership(uid: int, gid: int, relative: str) -> None:
    if uid != 0 or gid != 0:
        raise ManifestError(
            f"installed payload object is not root-owned: {relative}"
        )


def archive_entries(archive: pathlib.Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            normalized = member.name.removeprefix("./").rstrip("/")
            if normalized in {"", "."}:
                continue
            relative = pathlib.PurePosixPath(normalized)
            if relative.is_absolute() or ".." in relative.parts:
                raise ManifestError(f"unsafe archive member: {member.name!r}")
            name = relative.as_posix()
            if name in seen:
                raise ManifestError(f"duplicate archive member: {name}")
            seen.add(name)
            if member.isdir():
                expected_mode = 0o755
                kind = "directory"
                member_sha256 = None
            elif member.isfile():
                expected_mode = 0o755 if name in EXECUTABLES else 0o644
                kind = "file"
                extracted = bundle.extractfile(member)
                if extracted is None:
                    raise ManifestError(f"could not read archive member: {name}")
                digest = hashlib.sha256()
                for block in iter(lambda: extracted.read(1024 * 1024), b""):
                    digest.update(block)
                member_sha256 = digest.hexdigest()
            else:
                raise ManifestError(f"unsupported archive member type: {name}")
            if member.mode != expected_mode or member.uid != 0 or member.gid != 0:
                raise ManifestError(f"unsafe archive metadata: {name}")
            entry: dict[str, Any] = {
                "kind": kind,
                "mode": f"{expected_mode:04o}",
                "path": name,
            }
            if member_sha256 is not None:
                entry["sha256"] = member_sha256
            entries.append(entry)
    if not entries:
        raise ManifestError("Linux archive is empty")
    return sorted(entries, key=lambda item: item["path"])


def installed_entries(
    root: pathlib.Path, *, verify_modes: bool = True, verify_ownership: bool = True
) -> list[dict[str, Any]]:
    if not root.is_dir() or root.is_symlink():
        raise ManifestError("installed root must be a real directory")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if verify_ownership:
            validate_installed_ownership(info.st_uid, info.st_gid, relative)
        if stat.S_ISLNK(info.st_mode):
            raise ManifestError(f"installed payload contains a symlink: {relative}")
        if stat.S_ISDIR(info.st_mode):
            entry = {"kind": "directory", "mode": "0755", "path": relative}
        elif stat.S_ISREG(info.st_mode):
            expected_mode = 0o755 if relative in EXECUTABLES else 0o644
            entry = {
                "kind": "file",
                "mode": f"{expected_mode:04o}",
                "path": relative,
                "sha256": sha256_file(path),
            }
        else:
            raise ManifestError(
                f"installed payload contains an unsupported object: {relative}"
            )
        if verify_modes and stat.S_IMODE(info.st_mode) != int(entry["mode"], 8):
            raise ManifestError(f"installed payload mode mismatch: {relative}")
        entries.append(entry)
    if not entries:
        raise ManifestError("installed payload is empty")
    return entries


def build_report(
    archive: pathlib.Path,
    installed_root: pathlib.Path,
    *,
    verify_modes: bool = True,
    verify_ownership: bool = True,
) -> dict[str, Any]:
    expected = archive_entries(archive)
    observed = installed_entries(
        installed_root,
        verify_modes=verify_modes,
        verify_ownership=verify_ownership,
    )
    if observed != expected:
        expected_by_path = {entry["path"]: entry for entry in expected}
        observed_by_path = {entry["path"]: entry for entry in observed}
        missing = sorted(expected_by_path.keys() - observed_by_path.keys())
        extra = sorted(observed_by_path.keys() - expected_by_path.keys())
        changed = sorted(
            path
            for path in expected_by_path.keys() & observed_by_path.keys()
            if expected_by_path[path] != observed_by_path[path]
        )
        detail = ", ".join(
            part
            for part in (
                f"missing={len(missing)}" if missing else "",
                f"extra={len(extra)}" if extra else "",
                f"changed={len(changed)}" if changed else "",
            )
            if part
        )
        raise ManifestError(f"installed payload differs from archive ({detail})")
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "platform": "linux",
        "artifact_sha256": sha256_file(archive),
        "installed_payload_manifest_sha256": canonical_digest(observed),
        "member_count": len(observed),
        "exact_archive_payload_installed": True,
        "secret_material_redacted": True,
    }


def atomic_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, indent=2) + "\n")
    os.replace(temporary, path)


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="wins-linux-installed-manifest-") as name:
        root = pathlib.Path(name)
        payload = root / "payload"
        (payload / "share").mkdir(parents=True)
        (payload / "wins_vpn").write_bytes(b"binary\n")
        (payload / "share" / "notice.txt").write_text("notice\n", encoding="utf-8")
        (payload / "wins_vpn").chmod(0o755)
        (payload / "share").chmod(0o755)
        (payload / "share" / "notice.txt").chmod(0o644)
        archive = root / "wins-vpn-linux-x64.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for relative in ("wins_vpn", "share", "share/notice.txt"):
                source = payload / relative
                info = bundle.gettarinfo(str(source), arcname=f"./{relative}")
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o755 if source.is_dir() or relative == "wins_vpn" else 0o644
                if source.is_dir():
                    bundle.addfile(info)
                else:
                    with source.open("rb") as handle:
                        bundle.addfile(info, handle)
        report = build_report(
            archive,
            payload,
            verify_modes=os.name != "nt",
            verify_ownership=(
                not hasattr(os, "geteuid") or os.geteuid() == 0
            ),
        )
        if not report["exact_archive_payload_installed"] or report["member_count"] != 3:
            raise ManifestError("positive installed-payload self-test failed")
        (payload / "share" / "notice.txt").write_text("changed\n", encoding="utf-8")
        try:
            build_report(
                archive,
                payload,
                verify_modes=os.name != "nt",
                verify_ownership=(
                    not hasattr(os, "geteuid") or os.geteuid() == 0
                ),
            )
        except ManifestError:
            pass
        else:
            raise ManifestError("changed installed payload was accepted")
        try:
            validate_installed_ownership(1000, 1000, "wins_vpn")
        except ManifestError:
            pass
        else:
            raise ManifestError("non-root-owned installed payload was accepted")
    print("LINUX INSTALLED ARTIFACT MANIFEST SELF-TEST: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact")
    parser.add_argument("--installed-root", default="/opt/wins-vpn")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.artifact or not args.output:
        parser.error("--artifact and --output are required")
    artifact = pathlib.Path(args.artifact).expanduser().resolve()
    installed_root = pathlib.Path(args.installed_root).expanduser().resolve()
    if not artifact.is_file():
        raise ManifestError("Linux release artifact is missing")
    report = build_report(artifact, installed_root)
    atomic_json(pathlib.Path(args.output).expanduser().resolve(), report)
    print("LINUX INSTALLED ARTIFACT MANIFEST: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestError as error:
        print(f"LINUX INSTALLED ARTIFACT MANIFEST: FAIL: {error}", file=os.sys.stderr)
        raise SystemExit(1)
