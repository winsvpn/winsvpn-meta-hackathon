#!/usr/bin/env python3
"""Sealed, reproducible, signed release builds of the Winn Protocol engines.

This replaces the retained-producer gate (owner decision, 2026-10-09). That
gate could never complete: no tool created its root-owned authority files, an
approval lasted 15 minutes while it had to cover 30 targets, and every output
needed a signed single-use ledger entry naming an inode the builder had only
just created, while the builder never paused to wait for it.

What a release still has to prove, and how this tool proves it:

  * Pinned toolchains, verified by checksum. Go is extracted from the official
    archive named in tools/toolchain-pins.json; the archive SHA-256, the
    normalized install-tree SHA-256 and the bin/go SHA-256 must all equal the
    pins (same extraction and tree-hash code as tools/release_go_archive_custody.py).
    The Android NDK must carry the pinned Pkg.Revision and the pinned tree
    digest. Xcode must report the pinned version and build.
  * A read-only source snapshot tied to a git commit. The commit must be HEAD,
    the Winn module and the release tools must be clean (tracked and
    untracked), and the snapshot is taken with `git archive <commit>`, so
    uncommitted bytes cannot reach the compiler. Every snapshot file and
    directory is made non-writable before its digest is taken.
  * Two independent builds per target. Each target is built twice, from two
    separate snapshot copies, into two separate output trees, with two Go
    build caches, one per variant: every A build shares cache A and every B
    build shares cache B, so A and B never share compiled objects. Build B of
    a target starts only after its build A has finished and at least two
    seconds later. The two outputs (and generated headers) must be byte-
    identical or nothing is released.
  * A manifest of every output's SHA-256 plus the source digest and toolchain
    digests, written as canonical JSON.
  * An Ed25519 signature over the manifest by the owner's release authority
    key. `sign` reads the key file itself and never prints, logs or copies it.
    `verify` checks the signature against the pinned public key in
    tools/winn_release_authority.json and re-hashes every artifact.

Usage:
  winn_release.py targets --set {android,apple,windows,linux,app,all}
  winn_release.py build --out DIR (--set NAME | --targets T1,T2) --source-commit SHA
        [--source-export DIR] [--go-archive PATH] [--ndk DIR] [--developer-dir DIR]
        [--module-proxy URL] [--jobs N] [--skip-unavailable] [--keep-work]
  winn_release.py sign --release DIR --key PATH [--allow-unpinned-key]
        [--allow-export-source] [--allow-partial]
  winn_release.py verify --release DIR [--trust-public-key HEX] [--allow-unsigned]
        [--print-manifest] [--print-artifact TARGET]
  winn_release.py verify-android-stamp --stamp PATH --artifact PATH --target TARGET
  winn_release.py prepare-go --out DIR [--go-archive PATH]
  winn_release.py build-one TARGET OUTPUT
  winn_release.py digest --kind {sealed,platform,go-tree} PATH

`verify` reads manifest.json and manifest.sig.json exactly once each, checks
the signature over those held bytes, and takes every digest from the same held
bytes. --print-manifest prints those exact verified manifest bytes (one
canonical JSON line) before any --print-artifact lines, so a consumer takes
its expected digests from what was verified and never rereads the release
directory's manifest.

Exit codes: 0 success, 1 refusal or failure, 2 usage, 3 a required toolchain
is not installed (stderr line starts with "TOOLCHAIN-MISSING:").
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
MODULE_RELATIVE = "winn_protocol_experimental"
# The Windows Wintun relay is its own Go module that replaces
# winsvpn.local/winnprotocol with ../../winn_protocol_experimental, so a
# snapshot keeps both directories at their repository-relative places.
RELAY_RELATIVE = "windows/winn3_engine"
BUILDER = TOOLS / "build_winn_protocol_engine.sh"
PINS = TOOLS / "toolchain-pins.json"
# Its own file, so the reviewed records that bind toolchain-pins.json stay valid.
GARBLE_PIN = TOOLS / "winn_garble_pin.json"
AUTHORITY = TOOLS / "winn_release_authority.json"
GO_CUSTODY = TOOLS / "release_go_archive_custody.py"
PRODUCER_FILES = (BUILDER, Path(__file__).resolve(), PINS, GO_CUSTODY, AUTHORITY)

MANIFEST_CONTRACT = "winsvpn-winn-release-manifest-v1"
SIGNATURE_CONTRACT = "winsvpn-winn-release-signature-v1"
AUTHORITY_CONTRACT = "winsvpn-winn-release-authority-v1"
SIGNATURE_DOMAIN = b"WINSVPN-WINN-RELEASE-MANIFEST-V1\0"
RECEIPT_PREFIX = "WINN_BUILD_RECEIPT "
RECEIPT_CONTRACT = "winsvpn-winn-core-build-v4"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{7,64}\Z")
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
EXIT_FAIL, EXIT_USAGE, EXIT_TOOLCHAIN = 1, 2, 3
# Minimum gap between the end of a target's build A and the start of its
# build B (see build_release).
B_SEPARATION_SECONDS = 2.0
# The files a commit-bound release must not have local edits in.
CLEAN_PATHS = (
    MODULE_RELATIVE,
    RELAY_RELATIVE,
    "tools/build_winn_protocol_engine.sh",
    "tools/winn_release.py",
    "tools/toolchain-pins.json",
    "tools/winn_garble_pin.json",
    "tools/release_go_archive_custody.py",
    "tools/winn_release_authority.json",
)


class ReleaseError(RuntimeError):
    """A fail-closed refusal."""


class ToolchainMissing(ReleaseError):
    """A required toolchain is not installed on this host."""


# ---------------------------------------------------------------------------
# Targets. Names and compile recipes live in the builder; this table adds the
# artifact file name and the external toolchain each target needs.
# ---------------------------------------------------------------------------

def _target_table() -> dict[str, tuple[str, Optional[str]]]:
    table: dict[str, tuple[str, Optional[str]]] = {}
    for goos, arches in (("windows", ("amd64", "arm64")), ("darwin", ("amd64", "arm64")),
                         ("linux", ("amd64", "arm64")), ("android", ("arm64", "arm", "amd64"))):
        for arch in arches:
            exe = ".exe" if goos == "windows" else ""
            need = "ndk" if goos == "android" else None
            table[f"{goos}-{arch}"] = (f"winn-clientinfo{exe}", need)
            datapath = "libwinnengine.so" if goos == "android" else f"winn-datapath{exe}"
            table[f"datapath-{goos}-{arch}"] = (datapath, need)
    table["ios-arm64"] = ("libwinn-clientinfo.a", "xcode")
    for target in ("datapath-ios-arm64", "datapath-iossimulator-arm64",
                   "datapath-iossimulator-amd64", "datapath-archive-darwin-arm64",
                   "datapath-archive-darwin-amd64"):
        table[target] = ("libwinn-datapath.a", "xcode")
    for arch in ("amd64", "arm64"):
        table[f"server-linux-{arch}"] = ("winn-server", None)
        table[f"carrier-linux-{arch}"] = ("winn-carrier-server", None)
        table[f"winn3-gateway-linux-{arch}"] = ("winn3-gateway", None)
        # windows/winn3_engine: the Wintun inner-packet relay that
        # windows/runner/winn3_supervisor.cpp starts beside the service.
        table[f"winn3-relay-windows-{arch}"] = ("winsvpn_winn3_engine.exe", None)
    return table


TARGETS = _target_table()
SETS: dict[str, tuple[str, ...]] = {
    "android": ("datapath-android-arm64", "datapath-android-arm", "datapath-android-amd64"),
    "apple": ("datapath-ios-arm64", "datapath-iossimulator-arm64", "datapath-iossimulator-amd64",
              "datapath-archive-darwin-arm64", "datapath-archive-darwin-amd64"),
    "windows": ("datapath-windows-amd64", "datapath-windows-arm64",
                "winn3-relay-windows-amd64", "winn3-relay-windows-arm64"),
    "linux": ("datapath-linux-amd64", "datapath-linux-arm64",
              "winn3-gateway-linux-amd64", "winn3-gateway-linux-arm64"),
}
SETS["app"] = SETS["android"] + SETS["apple"] + SETS["windows"] + SETS["linux"]
SETS["all"] = tuple(sorted(TARGETS))


def select_targets(set_name: Optional[str], targets: Optional[str]) -> list[str]:
    if bool(set_name) == bool(targets):
        raise ReleaseError("give exactly one of --set or --targets")
    if set_name:
        if set_name not in SETS:
            raise ReleaseError(f"unknown target set {set_name!r}; known: {', '.join(sorted(SETS))}")
        return list(SETS[set_name])
    chosen = [item.strip() for item in str(targets).split(",")]
    if not chosen or any(not item for item in chosen):
        raise ReleaseError("--targets must be a comma list of target names")
    if len(set(chosen)) != len(chosen):
        raise ReleaseError("--targets repeats a target")
    unknown = sorted(set(chosen) - set(TARGETS))
    if unknown:
        raise ReleaseError(f"unknown targets: {', '.join(unknown)}")
    return chosen


# ---------------------------------------------------------------------------
# Hashing and canonical JSON.
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError(f"not a regular file: {path}")
    digest = hashlib.sha256()
    # O_BINARY: on Windows a plain os.open is text mode (CRLF folding, stop at
    # Ctrl-Z), which hashed winn-datapath.exe wrong and refused a good release.
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_json(path: Path, limit: int = 4 * 1024 * 1024) -> Any:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ReleaseError(f"not a bounded regular JSON file: {path}")
    return json.loads(path.read_bytes().decode("utf-8"), object_pairs_hook=_no_duplicates)


def read_held_bytes(path: Path, limit: int) -> bytes:
    """Read a bounded regular file once, without following a final symlink.

    The returned bytes are the only copy a decision is taken on: a caller that
    verifies them must also take every value it needs from them, never from a
    second read of the same path.
    """
    fd = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ReleaseError(f"not a bounded regular file: {path}")
        chunks = []
        remaining = limit + 1
        while remaining > 0:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
    finally:
        os.close(fd)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise ReleaseError(f"{path} grew past {limit} bytes while it was read")
    return payload


# ---------------------------------------------------------------------------
# Exclusive publication. Every file this tool publishes is created with
# O_CREAT|O_EXCL|O_NOFOLLOW (or linked into place, which also fails on an
# existing name), so a destination that exists, or that another writer creates
# while a build runs, is refused and never overwritten or written through.
# ---------------------------------------------------------------------------

# O_BINARY for the same reason as sha256_file: Windows text mode rewrites bytes.
_EXCLUSIVE_WRITE = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_BINARY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _open_exclusive(path: Path) -> int:
    try:
        return os.open(path, _EXCLUSIVE_WRITE, 0o600)
    except FileExistsError as exc:
        raise ReleaseError(f"refusing to overwrite an existing path: {path}") from exc


def write_exclusive(path: Path, payload: bytes, mode: int) -> None:
    """Create a new file holding exactly payload; an existing path is refused."""
    fd = _open_exclusive(path)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ReleaseError(f"short write to {path}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def copy_exclusive(source: Path, destination: Path, mode: int) -> str:
    """Copy a regular file to a new destination; returns the SHA-256 written.

    The destination is created exclusively, so an existing or racing path is
    refused rather than replaced, and the source is read through one
    O_NOFOLLOW descriptor.
    """
    src = os.open(
        source,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(src).st_mode):
            raise ReleaseError(f"not a regular file: {source}")
        digest = hashlib.sha256()
        dst = _open_exclusive(destination)
        try:
            while True:
                block = os.read(src, 1024 * 1024)
                if not block:
                    break
                digest.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(dst, view)
                    if written <= 0:
                        raise ReleaseError(f"short write to {destination}")
                    view = view[written:]
            os.fchmod(dst, mode)
            os.fsync(dst)
        finally:
            os.close(dst)
    finally:
        os.close(src)
    return digest.hexdigest()


def sealed_tree_digest(root: Path) -> str:
    """Content digest of a sealed (non-writable, regular-files-only) tree.

    Same member encoding as the builder has always used for the source and the
    module cache: sorted "file <size> <sha256> <relpath>" lines. The root and
    every member must belong to this user and carry no write bit at all, so a
    tree that can still be edited is refused rather than measured.
    """
    root_text = str(root)
    info = os.lstat(root_text)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(f"sealed tree root is not a directory: {root}")
    uid = os.getuid()
    prefix = len(root_text.rstrip(os.sep)) + 1
    # Each file is opened once without following links (O_NONBLOCK so a FIFO
    # cannot stall the walk) and checked with fstat on that descriptor, so
    # the file whose mode, owner and link count are checked is the file that
    # is hashed, with two lstat calls fewer per file than before.
    flags = (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    members: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_text, followlinks=False):
        dinfo = os.lstat(dirpath)
        if dinfo.st_uid != uid or dinfo.st_mode & 0o222:
            raise ReleaseError(f"sealed tree directory is writable or foreign: {dirpath}")
        dirnames.sort()
        for name in dirnames:
            child = os.lstat(os.path.join(dirpath, name))
            if stat.S_ISLNK(child.st_mode) or not stat.S_ISDIR(child.st_mode):
                raise ReleaseError(f"sealed tree holds a non-directory link: {os.path.join(dirpath, name)}")
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            try:
                fd = os.open(path, flags)
            except OSError as exc:
                raise ReleaseError(f"sealed tree holds a non-regular file: {path}") from exc
            try:
                finfo = os.fstat(fd)
                if not stat.S_ISREG(finfo.st_mode):
                    raise ReleaseError(f"sealed tree holds a non-regular file: {path}")
                if finfo.st_uid != uid or finfo.st_mode & 0o222 or finfo.st_nlink != 1:
                    raise ReleaseError(f"sealed tree file is writable, foreign or hard-linked: {path}")
                digest = hashlib.sha256()
                while True:
                    block = os.read(fd, 1024 * 1024)
                    if not block:
                        break
                    digest.update(block)
            finally:
                os.close(fd)
            relative = path[prefix:].replace(os.sep, "/")
            members.append(f"file {finfo.st_size} {digest.hexdigest()} {relative}\n")
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def platform_tree_digest(root: Path) -> str:
    """Content digest of an installed toolchain tree (NDK).

    Same encoding as winn_conformance_verify._external_platform_tree_sha256:
    files by size and SHA-256, in-tree symlinks by target text. Links that
    escape the root and group- or world-writable members are refused.
    """
    root_text = os.path.abspath(str(root))
    if os.path.islink(root_text) or not os.path.isdir(root_text):
        raise ReleaseError(f"toolchain root is not a directory: {root}")
    root_real = os.path.realpath(root_text)
    owners = {0, os.getuid()}
    members: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root_text, followlinks=False):
        dinfo = os.lstat(dirpath)
        if dinfo.st_uid not in owners or dinfo.st_mode & 0o022:
            raise ReleaseError(f"toolchain directory is writable by others or foreign: {dirpath}")
        relative_dir = os.path.relpath(dirpath, root_text).replace(os.sep, "/")
        members.append(f"dir {dinfo.st_mode} {dinfo.st_uid} {relative_dir}\n")
        dirnames.sort()
        for name in list(dirnames):
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                if os.path.commonpath((root_real, os.path.realpath(path))) != root_real:
                    raise ReleaseError(f"toolchain directory link escapes its root: {path}")
                members.append(f"symlink {os.readlink(path)} {os.path.relpath(path, root_text)}\n")
                dirnames.remove(name)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            finfo = os.lstat(path)
            relative = os.path.relpath(path, root_text).replace(os.sep, "/")
            if stat.S_ISLNK(finfo.st_mode):
                if os.path.commonpath((root_real, os.path.realpath(path))) != root_real:
                    raise ReleaseError(f"toolchain file link escapes its root: {path}")
                members.append(f"symlink {os.readlink(path)} {relative}\n")
                continue
            if not stat.S_ISREG(finfo.st_mode):
                raise ReleaseError(f"toolchain holds a special file: {path}")
            if finfo.st_uid not in owners or finfo.st_mode & 0o022:
                raise ReleaseError(f"toolchain file is writable by others or foreign: {path}")
            members.append(f"file {finfo.st_size} {sha256_file(Path(path))} {relative}\n")
    members.sort()
    return hashlib.sha256("".join(members).encode("utf-8")).hexdigest()


def seal_tree(root: Path) -> None:
    """Remove every write bit, deepest first, so the tree can be measured."""
    for dirpath, dirnames, filenames in os.walk(str(root), topdown=False, followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                os.chmod(path, stat.S_IMODE(info.st_mode) & ~0o222)
        os.chmod(dirpath, stat.S_IMODE(os.lstat(dirpath).st_mode) & ~0o222 | 0o500)


def remove_tree(root: Path) -> None:
    if not root.exists() and not root.is_symlink():
        return
    if root.is_symlink():
        root.unlink()
        return
    for dirpath, _dirnames, _filenames in os.walk(str(root), followlinks=False):
        os.chmod(dirpath, 0o700)
    shutil.rmtree(root)


# ---------------------------------------------------------------------------
# Pins.
# ---------------------------------------------------------------------------

def host_key() -> str:
    system = {"darwin": "darwin", "linux": "linux"}.get(sys.platform)
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(
        os.uname().machine.lower())
    if system is None or machine is None:
        raise ReleaseError(f"unsupported build host {sys.platform}/{os.uname().machine}")
    return f"{system}_{machine}"


def load_pins() -> dict[str, Any]:
    pins = load_json(PINS)
    tools = pins.get("tools") if isinstance(pins, dict) else None
    if not isinstance(tools, dict):
        raise ReleaseError("toolchain-pins.json has no tools object")
    return tools


def go_pins(tools: Mapping[str, Any]) -> dict[str, str]:
    go = tools.get("go")
    if not isinstance(go, dict):
        raise ReleaseError("toolchain-pins.json has no go entry")
    host = host_key()
    executable_pins = go.get("executable_sha256_by_platform", {})
    if not isinstance(executable_pins, dict):
        raise ReleaseError("go executable_sha256_by_platform must be an object")
    executable_sha256 = executable_pins.get(host)
    if host == "darwin_arm64" and host not in executable_pins:
        executable_sha256 = go.get("executable_sha256")
    values = {
        "version": go.get("version"),
        "executable_sha256": executable_sha256,
        "archive_sha256": (go.get("archive_sha256") or {}).get(host),
        "install_tree_sha256": (go.get("install_tree_sha256") or {}).get(host),
    }
    if not isinstance(values["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", values["version"]):
        raise ReleaseError("go pin has no exact version")
    for key in ("executable_sha256", "archive_sha256", "install_tree_sha256"):
        if not isinstance(values[key], str) or not HEX64.fullmatch(values[key]):
            raise ReleaseError(f"go pin {key} is missing for {host}; refusing an unpinned Go")
    archive_paths = go.get("archive_path") or {}
    values["archive_path"] = archive_paths.get(host) if isinstance(archive_paths, dict) else None
    return values  # type: ignore[return-value]


# Owner ruling 2026-10-27: only the client engines that ship from
# winsvpn.org may be obfuscated. Store (Apple), server and gateway targets
# always build plain, also inside a garble release (the Linux producer needs
# the plain winn3-gateway beside the garbled datapath in one manifest).
OBFUSCATABLE_PREFIXES = ("datapath-android-", "datapath-linux-", "datapath-windows-", "winn3-relay-windows-")


def load_garble_pin() -> dict[str, Any]:
    try:
        tools = json.loads(GARBLE_PIN.read_text(encoding="utf-8")).get("tools")
    except (OSError, ValueError) as exc:
        raise ReleaseError(f"{GARBLE_PIN.name} is unreadable: {exc}") from exc
    if not isinstance(tools, dict):
        raise ReleaseError(f"{GARBLE_PIN.name} has no tools object")
    return tools


def garble_pins(tools: Mapping[str, Any]) -> dict[str, str]:
    garble = tools.get("garble")
    if not isinstance(garble, dict):
        raise ReleaseError("toolchain-pins.json has no garble entry; refusing an unpinned obfuscator")
    host = host_key()
    values = {
        "version": garble.get("version"),
        "executable_sha256": (garble.get("executable_sha256_by_platform") or {}).get(host),
        "install_path": (garble.get("install_path") or {}).get(host),
    }
    if not isinstance(values["version"], str) or not re.fullmatch(r"v\d+\.\d+\.\d+", values["version"]):
        raise ReleaseError("garble pin has no exact version")
    if not isinstance(values["executable_sha256"], str) or not HEX64.fullmatch(values["executable_sha256"]):
        raise ReleaseError(f"garble executable pin is missing for {host}")
    if not isinstance(values["install_path"], str) or not values["install_path"].startswith("/"):
        raise ReleaseError(f"garble install path is missing for {host}")
    return values  # type: ignore[return-value]


def prepare_garble(tools: Mapping[str, Any], seed_file: Optional[str]) -> tuple[Path, Path]:
    pins = garble_pins(tools)
    binary = Path(pins["install_path"])
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ToolchainMissing(f"TOOLCHAIN-MISSING: garble {pins['version']} is not installed at {binary}")
    if sha256_file(binary) != pins["executable_sha256"]:
        raise ReleaseError(f"{binary} is not the pinned garble {pins['version']} executable")
    if not seed_file or not os.path.isabs(seed_file):
        raise ReleaseError("--obfuscate garble needs an absolute --garble-seed-file")
    # The builder reads and checks the seed itself; it is never read here.
    return binary, Path(seed_file)


def ndk_pins(tools: Mapping[str, Any]) -> dict[str, str]:
    ndk = tools.get("android_ndk")
    if not isinstance(ndk, dict) or not isinstance(ndk.get("version"), str):
        raise ReleaseError("toolchain-pins.json has no android_ndk version")
    tree = (ndk.get("install_tree_sha256") or {}).get(host_key())
    if not isinstance(tree, str) or not HEX64.fullmatch(tree):
        raise ReleaseError(f"android_ndk install_tree_sha256 is not pinned for {host_key()}; refusing an unpinned NDK")
    return {"version": ndk["version"], "install_tree_sha256": tree}


def xcode_pins(tools: Mapping[str, Any]) -> dict[str, str]:
    xcode = tools.get("xcode")
    if not isinstance(xcode, dict) or not isinstance(xcode.get("version"), str) or not isinstance(xcode.get("build"), str):
        raise ReleaseError("toolchain-pins.json has no xcode version and build; refusing an unpinned Xcode")
    return {"version": xcode["version"], "build": xcode["build"]}


# ---------------------------------------------------------------------------
# Toolchains.
# ---------------------------------------------------------------------------

def _go_custody_module() -> Any:
    sys.path.insert(0, str(TOOLS))
    try:
        import release_go_archive_custody as custody  # type: ignore[import-not-found]
    finally:
        sys.path.pop(0)
    return custody


def prepare_go(archive: Optional[str], work: Path, pins: Mapping[str, str]) -> tuple[Path, dict[str, str]]:
    path_text = archive or pins.get("archive_path")
    if not path_text:
        raise ToolchainMissing("TOOLCHAIN-MISSING: no Go archive; pass --go-archive with the pinned go"
                               f"{pins['version']} archive")
    path = Path(os.path.expanduser(path_text))
    if not path.is_file():
        raise ToolchainMissing(f"TOOLCHAIN-MISSING: Go archive not found: {path}")
    archive_sha = sha256_file(path)
    if archive_sha != pins["archive_sha256"]:
        raise ReleaseError(f"Go archive SHA-256 {archive_sha} is not the pinned {pins['archive_sha256']}")
    custody = _go_custody_module()
    destination = work / "toolchain" / "go-extract"
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        go_root = custody.safe_extract(path, destination, "go")
        tree_sha = custody.tree_hash(go_root)
        executable_sha = custody.digest_file(go_root / "bin" / "go")
    except custody.Refused as exc:
        raise ReleaseError(f"Go archive extraction refused: {exc}") from exc
    if tree_sha != pins["install_tree_sha256"]:
        raise ReleaseError(f"Go install tree {tree_sha} is not the pinned {pins['install_tree_sha256']}")
    if executable_sha != pins["executable_sha256"]:
        raise ReleaseError(f"bin/go {executable_sha} is not the pinned {pins['executable_sha256']}")
    return go_root, {
        "version": pins["version"],
        "archive_sha256": archive_sha,
        "install_tree_sha256": tree_sha,
        "executable_sha256": executable_sha,
    }


def recheck_go(go_root: Path, identity: Mapping[str, str]) -> None:
    custody = _go_custody_module()
    if custody.tree_hash(go_root) != identity["install_tree_sha256"]:
        raise ReleaseError("Go install tree changed during the release build")


def prepare_ndk(ndk: Optional[str], pins: Mapping[str, str]) -> tuple[Path, dict[str, str]]:
    root = Path(os.path.expanduser(ndk or f"~/.local/android-sdk/ndk/{pins['version']}"))
    properties = root / "source.properties"
    if not properties.is_file():
        raise ToolchainMissing(f"TOOLCHAIN-MISSING: Android NDK {pins['version']} not found at {root}")
    revision = None
    for line in properties.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"\s*Pkg\.Revision\s*=\s*(\S+)\s*", line)
        if match:
            revision = match.group(1)
    if revision != pins["version"]:
        raise ReleaseError(f"NDK at {root} is {revision}, not the pinned {pins['version']}")
    root = Path(os.path.realpath(root))
    tree = platform_tree_digest(root)
    if tree != pins["install_tree_sha256"]:
        raise ReleaseError(f"NDK tree digest {tree} is not the pinned {pins['install_tree_sha256']}")
    return root, {"version": revision, "tree_sha256": tree, "root": str(root)}


def _run_text(argv: Sequence[str], env: Optional[Mapping[str, str]] = None, cwd: Optional[Path] = None) -> str:
    result = subprocess.run(list(argv), env=dict(env) if env is not None else None, cwd=cwd,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise ReleaseError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()[:2000]}")
    return result.stdout


def prepare_xcode(developer_dir: Optional[str], pins: Mapping[str, str]) -> tuple[Path, dict[str, Any]]:
    if developer_dir is None:
        try:
            developer_dir = _run_text(["/usr/bin/xcode-select", "-p"]).strip()
        except (OSError, ReleaseError) as exc:
            raise ToolchainMissing(f"TOOLCHAIN-MISSING: Xcode developer directory unavailable: {exc}") from exc
    root = Path(os.path.realpath(developer_dir))
    if not (root / "usr" / "bin" / "xcodebuild").exists():
        raise ToolchainMissing(f"TOOLCHAIN-MISSING: no Xcode at {root}")
    env = {"PATH": SAFE_PATH, "DEVELOPER_DIR": str(root), "HOME": os.environ.get("HOME", "/tmp")}
    lines = _run_text([str(root / "usr" / "bin" / "xcodebuild"), "-version"], env).split("\n")
    version = lines[0].removeprefix("Xcode ").strip()
    build = lines[1].removeprefix("Build version ").strip() if len(lines) > 1 else ""
    if (version, build) != (pins["version"], pins["build"]):
        raise ReleaseError(f"Xcode {version} ({build}) is not the pinned {pins['version']} ({pins['build']})")
    clang = Path(os.path.realpath(_run_text(["/usr/bin/xcrun", "-f", "clang"], env).strip()))
    sdks: dict[str, Any] = {}
    for sdk in ("iphoneos", "iphonesimulator", "macosx"):
        sdk_path = Path(_run_text(["/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-path"], env).strip())
        settings = sdk_path / "SDKSettings.json"
        sdks[sdk] = {
            "version": _run_text(["/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-version"], env).strip(),
            "build": _run_text(["/usr/bin/xcrun", "--sdk", sdk, "--show-sdk-build-version"], env).strip(),
            "settings_sha256": sha256_file(settings) if settings.is_file() else None,
        }
    return root, {
        "xcode_version": version,
        "xcode_build": build,
        "clang_sha256": sha256_file(clang),
        "sdks": sdks,
    }


# ---------------------------------------------------------------------------
# Source snapshot.
# ---------------------------------------------------------------------------

def git_binary() -> str:
    # Test hook: tests point this at a stub. A real release uses /usr/bin/git.
    return os.environ.get("WINS_WINN_RELEASE_GIT", "/usr/bin/git")


def _git(*args: str) -> bytes:
    result = subprocess.run([git_binary(), "-C", str(ROOT), *args], stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=600,
                            env={"PATH": SAFE_PATH, "HOME": os.environ.get("HOME", "/tmp"),
                                 "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C"})
    if result.returncode != 0:
        raise ReleaseError(f"git {' '.join(args[:2])} failed: {result.stderr.decode(errors='replace').strip()[:1000]}")
    return result.stdout


def resolve_commit_and_require_clean(commit: str) -> str:
    if not COMMIT_RE.fullmatch(commit):
        raise ReleaseError("--source-commit must be a hex commit id")
    if not (ROOT / ".git").exists():
        raise ReleaseError(f"{ROOT} is not a git checkout; a commit-bound release needs one "
                           "(or pass --source-export for an unverified export)")
    resolved = _git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}").decode().strip()
    head = _git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if resolved != head:
        raise ReleaseError(f"--source-commit {resolved} is not HEAD {head}; check out the commit first so "
                           "the build tools and the source come from the same commit")
    dirty = _git("status", "--porcelain=v1", "--untracked-files=all", "--", *CLEAN_PATHS).decode()
    if dirty.strip():
        raise ReleaseError("refusing a dirty tree; uncommitted or untracked changes in:\n" + dirty.rstrip())
    return resolved


def _extract_tar_bytes(payload: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            if not (member.isreg() or member.isdir()) or member.name.startswith("/") \
                    or ".." in Path(member.name).parts or "\\" in member.name or member.linkname:
                raise ReleaseError(f"refusing source archive member {member.name!r}")
        if hasattr(tarfile, "data_filter"):
            archive.extractall(destination, filter="data")
        else:  # /usr/bin/python3 3.9 predates extraction filters; members were vetted above
            archive.extractall(destination)


def snapshot_source(work: Path, commit: str, export: Optional[str]) -> tuple[list[Path], dict[str, Any]]:
    copies = [work / "source-a", work / "source-b"]
    if export:
        export_root = Path(os.path.realpath(os.path.expanduser(export)))
        relay_export: Optional[Path] = None
        if (export_root / MODULE_RELATIVE / "go.mod").is_file():
            if (export_root / RELAY_RELATIVE / "go.mod").is_file():
                relay_export = export_root / RELAY_RELATIVE
            export_root = export_root / MODULE_RELATIVE
        if not (export_root / "go.mod").is_file():
            raise ReleaseError(f"--source-export {export_root} holds no Winn module (go.mod)")
        if not COMMIT_RE.fullmatch(commit):
            raise ReleaseError("--source-commit must be a hex commit id")
        for copy in copies:
            shutil.copytree(export_root, copy / MODULE_RELATIVE, symlinks=True)
            if relay_export is not None:
                shutil.copytree(relay_export, copy / RELAY_RELATIVE, symlinks=True)
        binding = "export"
        resolved = commit
    else:
        resolved = resolve_commit_and_require_clean(commit)
        payload = _git("archive", "--format=tar", resolved, "--", MODULE_RELATIVE, RELAY_RELATIVE)
        for copy in copies:
            copy.mkdir(parents=True)
            _extract_tar_bytes(payload, copy)
        binding = "git-archive"
    roots = [copy / MODULE_RELATIVE for copy in copies]
    digests = []
    relay_digests = []
    for root in roots:
        if not (root / "go.mod").is_file() or not (root / "go.sum").is_file():
            raise ReleaseError("source snapshot has no go.mod and go.sum")
        seal_tree(root.parent)
        digests.append(sealed_tree_digest(root))
        relay = root.parent / RELAY_RELATIVE
        relay_digests.append(sealed_tree_digest(relay) if (relay / "go.mod").is_file() else None)
    if digests[0] != digests[1] or relay_digests[0] != relay_digests[1]:
        raise ReleaseError("the two source snapshot copies differ")
    return roots, {"commit": resolved, "binding": binding, "path": MODULE_RELATIVE, "tree_sha256": digests[0],
                   "relay_path": RELAY_RELATIVE if relay_digests[0] else None,
                   "relay_tree_sha256": relay_digests[0]}


def go_env(go_root: Path, extra: Mapping[str, str]) -> dict[str, str]:
    env = {
        "PATH": f"{go_root / 'bin'}:{SAFE_PATH}",
        "HOME": os.environ.get("HOME", "/tmp"),
        "LC_ALL": "C",
        "GOTOOLCHAIN": "local",
        "GOENV": "off",
        "GOTELEMETRY": "off",
        "GOFLAGS": "-mod=readonly",
        "GOSUMDB": "off",
        "GOWORK": "off",
        "CGO_ENABLED": "0",
    }
    env.update(extra)
    return env


def seed_module_cache(go_root: Path, source: Path, work: Path, proxy: str) -> tuple[Path, str]:
    cache = work / "gomodcache"
    scratch = work / "tmp" / "seed"
    scratch.mkdir(parents=True)
    env = go_env(go_root, {"GOMODCACHE": str(cache), "GOPROXY": proxy,
                           "GOCACHE": str(scratch / "gocache"), "TMPDIR": str(scratch)})
    modules = [source]
    if (source.parent / RELAY_RELATIVE / "go.mod").is_file():
        modules.append(source.parent / RELAY_RELATIVE)
    for module in modules:
        for argv in (["go", "mod", "download"], ["go", "mod", "verify"]):
            result = subprocess.run([str(go_root / "bin" / "go"), *argv[1:]], cwd=module, env=env,
                                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                raise ReleaseError(f"{' '.join(argv)} in {module.name} with GOPROXY={proxy} failed: "
                                   f"{result.stderr.strip()[:3000]}")
    for lock in cache.glob("cache/download/**/*.lock"):
        lock.unlink()
    seal_tree(cache)
    return cache, sealed_tree_digest(cache)


# ---------------------------------------------------------------------------
# Building.
# ---------------------------------------------------------------------------

def run_builder(target: str, output: Path, env: Mapping[str, str], log: Path) -> dict[str, Any]:
    result = subprocess.run(["/bin/bash", str(BUILDER), target, str(output)], env=dict(env), cwd=ROOT,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3600)
    write_exclusive(log, (f"$ build {target} -> {output}\nexit {result.returncode}\n--- stdout\n{result.stdout}"
                          f"--- stderr\n{result.stderr}").encode("utf-8"), 0o644)
    if result.returncode != 0:
        tail = "\n".join(result.stderr.strip().splitlines()[-15:])
        raise ReleaseError(f"build[{target}] exited {result.returncode} (log {log}):\n{tail}")
    receipts = [line[len(RECEIPT_PREFIX):] for line in result.stdout.splitlines() if line.startswith(RECEIPT_PREFIX)]
    if len(receipts) != 1:
        raise ReleaseError(f"build[{target}] printed {len(receipts)} receipts, expected 1 (log {log})")
    receipt = json.loads(receipts[0], object_pairs_hook=_no_duplicates)
    if receipt.get("contract") != RECEIPT_CONTRACT or receipt.get("target", {}).get("id") != target:
        raise ReleaseError(f"build[{target}] receipt has the wrong contract or target")
    return receipt


def header_for(path: Path) -> Optional[Path]:
    return path.with_suffix(".h") if path.suffix == ".a" else None


def _normalized(receipt: Mapping[str, Any]) -> bytes:
    copy = json.loads(json.dumps(receipt))
    copy["artifact"]["output_path"] = "<output>"
    return canonical_json(copy)


def build_release(args: argparse.Namespace) -> int:
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        raise ReleaseError(f"--out {out} already exists; a release directory is created fresh")
    targets = select_targets(args.set, args.targets)
    tools = load_pins()
    gopin = go_pins(tools)
    garble: Optional[tuple[Path, Path]] = None
    if getattr(args, "obfuscate", "none") == "garble":
        if not any(target.startswith(OBFUSCATABLE_PREFIXES) for target in targets):
            raise ReleaseError("--obfuscate garble needs at least one website client engine target")
        garble = prepare_garble(load_garble_pin(), args.garble_seed_file)
    elif getattr(args, "garble_seed_file", None):
        raise ReleaseError("--garble-seed-file is only valid with --obfuscate garble")
    needs = {TARGETS[target][1] for target in targets} - {None}
    out.mkdir(parents=True)
    work = out / "work"
    work.mkdir()
    logs = out / "logs"
    logs.mkdir()
    skipped: dict[str, str] = {}
    try:
        producer = {f"{path.name}": sha256_file(path) for path in PRODUCER_FILES}
        if garble is not None:
            producer[GARBLE_PIN.name] = sha256_file(GARBLE_PIN)
        go_root, go_identity = prepare_go(args.go_archive, work, gopin)
        print(f"Go {go_identity['version']}: archive, install tree and bin/go match the pins", file=sys.stderr)
        ndk_root: Optional[Path] = None
        ndk_identity: Optional[dict[str, str]] = None
        xcode_root: Optional[Path] = None
        xcode_identity: Optional[dict[str, Any]] = None
        if "ndk" in needs:
            try:
                ndk_root, ndk_identity = prepare_ndk(args.ndk, ndk_pins(tools))
                print(f"NDK {ndk_identity['version']}: tree {ndk_identity['tree_sha256']} matches the pin", file=sys.stderr)
            except ToolchainMissing as exc:
                if not args.skip_unavailable:
                    raise
                for target in targets:
                    if TARGETS[target][1] == "ndk":
                        skipped[target] = str(exc)
        if "xcode" in needs:
            try:
                xcode_root, xcode_identity = prepare_xcode(args.developer_dir, xcode_pins(tools))
                print(f"Xcode {xcode_identity['xcode_version']} ({xcode_identity['xcode_build']}) matches the pin", file=sys.stderr)
            except ToolchainMissing as exc:
                if not args.skip_unavailable:
                    raise
                for target in targets:
                    if TARGETS[target][1] == "xcode":
                        skipped[target] = str(exc)
        build_targets = [target for target in targets if target not in skipped]
        if not build_targets:
            raise ToolchainMissing("TOOLCHAIN-MISSING: no selected target has its toolchain installed")
        sources, source_identity = snapshot_source(work, args.source_commit, args.source_export)
        if any(target.startswith("winn3-relay-") for target in build_targets) \
                and not source_identity.get("relay_tree_sha256"):
            raise ReleaseError(f"the source snapshot has no {RELAY_RELATIVE} module for the Windows relay targets")
        print(f"Source {source_identity['binding']} {source_identity['commit']}: tree {source_identity['tree_sha256']}", file=sys.stderr)
        cache, cache_digest = seed_module_cache(go_root, sources[0], work, args.module_proxy)
        print(f"Module cache sealed: {cache_digest}", file=sys.stderr)

        # One Go build cache per variant: every A build shares cache A and
        # every B build shares cache B, so the standard library is compiled
        # once per platform and variant, while A and B never share compiled
        # objects and the two-build comparison still sets two independently
        # compiled outputs against each other.
        variant_caches = []
        garble_caches = []
        for name in "ab":
            variant_cache = work / "gocache" / name
            variant_cache.mkdir(parents=True, mode=0o700)
            variant_caches.append(variant_cache)
            garble_cache = work / "garblecache" / name
            garble_cache.mkdir(parents=True, mode=0o700)
            garble_caches.append(garble_cache)
        a_finished: dict[str, float] = {}
        a_failed: set[str] = set()
        a_done = {target: threading.Event() for target in build_targets}

        def job(target: str, variant: int) -> tuple[str, int, Path, dict[str, Any]]:
            name = "ab"[variant]
            if variant:
                # Build B starts only after its build A has finished, and at
                # least B_SEPARATION_SECONDS later, so every wall-clock stamp B
                # can leak lies in a later second than any stamp A can leak
                # and shows up as a mismatch. Every A build is queued before
                # any B build (the pool is FIFO), so A is running or done when
                # B is taken, and B usually finds it long finished.
                a_done[target].wait()
                if target in a_failed:
                    raise ReleaseError(f"build[{target}] (b) not started: build A failed")
                wait = a_finished[target] + B_SEPARATION_SECONDS - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
            try:
                return _job_body(target, variant, name)
            except BaseException:
                if not variant:
                    a_failed.add(target)
                raise
            finally:
                if not variant:
                    a_finished[target] = time.monotonic()
                    a_done[target].set()

        def _job_body(target: str, variant: int, name: str) -> tuple[str, int, Path, dict[str, Any]]:
            build_dir = work / "builds" / name / target
            tmp = work / "tmp" / f"{name}-{target}"
            build_dir.mkdir(parents=True)
            tmp.mkdir(parents=True)
            env = {
                "PATH": SAFE_PATH,
                "HOME": os.environ.get("HOME", "/tmp"),
                "LC_ALL": "C",
                "TMPDIR": str(tmp),
                "WINS_WINN_SOURCE_ROOT": str(sources[variant]),
                "WINS_WINN_SOURCE_TREE_SHA256": source_identity["tree_sha256"],
                "WINS_STORE_GOMODCACHE": str(cache),
                "WINS_STORE_GOMODCACHE_TREE_SHA256": cache_digest,
                "WINS_RELEASE_GO_ROOT": str(go_root),
                "WINS_WINN_VARIANT_GOCACHE": str(variant_caches[variant]),
            }
            if source_identity.get("relay_tree_sha256"):
                env["WINS_WINN_RELAY_SOURCE_ROOT"] = str(sources[variant].parent / RELAY_RELATIVE)
                env["WINS_WINN_RELAY_SOURCE_TREE_SHA256"] = source_identity["relay_tree_sha256"]
            if ndk_root is not None:
                env["WINS_ANDROID_NDK_ROOT"] = str(ndk_root)
            if xcode_root is not None:
                env["WINS_APPLE_DEVELOPER_DIR"] = str(xcode_root)
            if garble is not None and target.startswith(OBFUSCATABLE_PREFIXES):
                env["WINS_WINN_OBFUSCATION"] = "garble"
                env["WINS_GARBLE_BIN"] = str(garble[0])
                env["WINS_GARBLE_SEED_FILE"] = str(garble[1])
                env["WINS_WINN_VARIANT_GARBLE_CACHE"] = str(garble_caches[variant])
            output = build_dir / TARGETS[target][0]
            receipt = run_builder(target, output, env, logs / f"{target}.{name}.log")
            return target, variant, output, receipt

        results: dict[tuple[str, int], tuple[Path, dict[str, Any]]] = {}
        failures: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            futures = [pool.submit(job, target, variant) for variant in (0, 1) for target in build_targets]
            for future in concurrent.futures.as_completed(futures):
                try:
                    target, variant, output, receipt = future.result()
                    results[(target, variant)] = (output, receipt)
                    print(f"built {target} ({'ab'[variant]})", file=sys.stderr)
                except ReleaseError as exc:
                    failures.append(str(exc))
        if failures:
            raise ReleaseError("\n".join(sorted(failures)))

        artifacts = []
        for target in build_targets:
            (out_a, receipt_a), (out_b, receipt_b) = results[(target, 0)], results[(target, 1)]
            sha_a, sha_b = sha256_file(out_a), sha256_file(out_b)
            if sha_a != sha_b:
                raise ReleaseError(f"build[{target}] is not reproducible: {sha_a} != {sha_b}")
            if sha_a != receipt_a["artifact"]["sha256"] or sha_b != receipt_b["artifact"]["sha256"]:
                raise ReleaseError(f"build[{target}] output does not match its own receipt")
            header_a, header_b = header_for(out_a), header_for(out_b)
            header_sha = None
            if header_a is not None and header_b is not None:
                header_sha = sha256_file(header_a)
                if header_sha != sha256_file(header_b):
                    raise ReleaseError(f"build[{target}] generated headers differ")
            if _normalized(receipt_a) != _normalized(receipt_b):
                raise ReleaseError(f"build[{target}] receipts differ beyond the output path")
            final_dir = out / "artifacts" / target
            final_dir.mkdir(parents=True)
            final = final_dir / out_a.name
            copied = copy_exclusive(out_a, final, 0o555 if receipt_a["archive_mode"] is False else 0o444)
            if copied != sha_a:
                raise ReleaseError(f"build[{target}] output changed while it was published")
            entry: dict[str, Any] = {
                "target": target,
                "path": final.relative_to(out).as_posix(),
                "sha256": sha256_file(final),
                "size": final.stat().st_size,
                "header_path": None,
                "header_sha256": None,
                "build_a_sha256": sha_a,
                "build_b_sha256": sha_b,
                "package": receipt_a["package"],
                "role": receipt_a["role"],
                "goos": receipt_a["target"]["goos"],
                "goarch": receipt_a["target"]["goarch"],
                "cgo_enabled": receipt_a["target"]["cgo_enabled"],
                "platform": receipt_a["platform"],
            }
            garbled = garble is not None and target.startswith(OBFUSCATABLE_PREFIXES)
            if garbled != ("obfuscation" in receipt_a):
                raise ReleaseError(f"build[{target}] obfuscation does not match the request")
            if garbled:
                entry["obfuscation"] = receipt_a["obfuscation"]
                if "v3_packages_linked" in receipt_a:
                    entry["v3_packages_linked"] = receipt_a["v3_packages_linked"]
            if header_a is not None:
                final_header = final_dir / header_a.name
                copy_exclusive(header_a, final_header, 0o444)
                entry["header_path"] = final_header.relative_to(out).as_posix()
                entry["header_sha256"] = sha256_file(final_header)
                if entry["header_sha256"] != header_sha:
                    raise ReleaseError(f"build[{target}] header copy changed")
            if entry["sha256"] != sha_a:
                raise ReleaseError(f"build[{target}] artifact copy changed")
            artifacts.append(entry)

        # The inputs must still be what was measured before the builds.
        recheck_go(go_root, go_identity)
        if sealed_tree_digest(cache) != cache_digest:
            raise ReleaseError("module cache changed during the release build")
        for root in sources:
            if sealed_tree_digest(root) != source_identity["tree_sha256"]:
                raise ReleaseError("source snapshot changed during the release build")
            if source_identity.get("relay_tree_sha256") and \
                    sealed_tree_digest(root.parent / RELAY_RELATIVE) != source_identity["relay_tree_sha256"]:
                raise ReleaseError("relay source snapshot changed during the release build")
        if ndk_root is not None and ndk_identity is not None:
            if platform_tree_digest(ndk_root) != ndk_identity["tree_sha256"]:
                raise ReleaseError("Android NDK changed during the release build")

        obfuscation = None
        if garble is not None:
            garbled_entries = [entry for entry in artifacts if "obfuscation" in entry]
            records = {canonical_json(entry["obfuscation"]) for entry in garbled_entries}
            if len(records) != 1:
                raise ReleaseError("obfuscated artifacts disagree on the garble tool, flags or seed")
            obfuscation = garbled_entries[0]["obfuscation"]
        manifest = {
            "contract": MANIFEST_CONTRACT,
            "created_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source": source_identity,
            "producer": producer,
            "toolchains": {
                "go": go_identity,
                "gomodcache_tree_sha256": cache_digest,
                "module_proxy_for_seeding": args.module_proxy,
                "android_ndk": None if ndk_identity is None else
                {"version": ndk_identity["version"], "tree_sha256": ndk_identity["tree_sha256"]},
                "apple": xcode_identity,
            },
            "reproducibility": {"independent_builds": 2, "result": "byte-identical"},
            "requested_targets": targets,
            "skipped_targets": skipped,
            "artifacts": sorted(artifacts, key=lambda item: item["target"]),
        }
        if obfuscation is not None:
            # Plain manifests keep their exact shape; only obfuscated ones add this.
            manifest["obfuscation"] = obfuscation
        manifest_path = out / "manifest.json"
        write_exclusive(manifest_path, canonical_json(manifest), 0o444)
        print(f"MANIFEST {manifest_path} sha256 {sha256_file(manifest_path)}")
        for entry in manifest["artifacts"]:
            print(f"ARTIFACT {entry['target']} {entry['sha256']} a={entry['build_a_sha256']} b={entry['build_b_sha256']}")
        for target, reason in sorted(skipped.items()):
            print(f"SKIPPED {target}: {reason}")
        return 0
    finally:
        if not args.keep_work:
            remove_tree(work)


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032), pure Python so signing needs nothing beyond the
# standard library. Verification is cross-checked in the tests against the
# independent verifier in winn_conformance_verify.py and RFC 8032 vectors.
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = x * _I % _P
    if (x * x - xx) % _P or (x == 0 and sign):
        return None
    return _P - x if x & 1 != sign else x


_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
assert _BX is not None
_B = (_BX, _BY, 1, _BX * _BY % _P)
_ZERO = (0, 1, 1, 0)


def _add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = _ZERO
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = point
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(data: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, value >> 255)
    return None if x is None else (x, y, 1, x * y % _P)


def _secret_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_public(seed: bytes) -> bytes:
    scalar, _prefix = _secret_scalar(seed)
    return _encode(_mul(scalar, _B))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ReleaseError("Ed25519 seed must be 32 bytes")
    scalar, prefix = _secret_scalar(seed)
    public = _encode(_mul(scalar, _B))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    big_r = _encode(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % _L
    return big_r + ((r + k * scalar) % _L).to_bytes(32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    point_a = _decode(public)
    point_r = _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if point_a is None or point_r is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _encode(_mul(s, _B)) == _encode(_add(point_r, _mul(k, point_a)))


_PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def load_private_seed(path: Path) -> bytes:
    """Read a PKCS#8 PEM Ed25519 private key. Never prints or returns text."""
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReleaseError("release key must be a regular file, not a link")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ReleaseError("release key must be owned by you and not readable by group or others (chmod 600)")
    if info.st_size > 4096:
        raise ReleaseError("release key file is too large to be one Ed25519 key")
    lines = path.read_text(encoding="ascii").strip().splitlines()
    if not lines or lines[0] != "-----BEGIN PRIVATE KEY-----" or lines[-1] != "-----END PRIVATE KEY-----":
        raise ReleaseError("release key is not a PKCS#8 PEM private key")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    if len(der) != 48 or not der.startswith(_PKCS8_ED25519_PREFIX):
        raise ReleaseError("release key is not an Ed25519 PKCS#8 key")
    return der[16:]


def pinned_public_key() -> bytes:
    document = load_json(AUTHORITY, 64 * 1024)
    if not isinstance(document, dict) or document.get("contract") != AUTHORITY_CONTRACT \
            or document.get("algorithm") != "ed25519":
        raise ReleaseError("tools/winn_release_authority.json is malformed")
    key = document.get("public_key")
    if not isinstance(key, str) or not HEX64.fullmatch(key):
        raise ReleaseError("tools/winn_release_authority.json has no Ed25519 public key")
    return bytes.fromhex(key)


def sign_release(args: argparse.Namespace) -> int:
    release = Path(os.path.abspath(args.release))
    manifest_path = release / "manifest.json"
    signature_path = release / "manifest.sig.json"
    if signature_path.exists() or signature_path.is_symlink():
        raise ReleaseError(f"{signature_path} already exists; refusing to re-sign")
    payload = manifest_path.read_bytes()
    manifest = json.loads(payload, object_pairs_hook=_no_duplicates)
    if manifest.get("contract") != MANIFEST_CONTRACT or canonical_json(manifest) != payload:
        raise ReleaseError("manifest.json is not a canonical release manifest")
    if manifest["source"]["binding"] != "git-archive" and not args.allow_export_source:
        raise ReleaseError("manifest source is an unverified export, not a git commit; refusing to sign "
                           "(--allow-export-source exists for offline proofs only)")
    if manifest.get("skipped_targets") and not args.allow_partial:
        raise ReleaseError("manifest skipped targets: " + ", ".join(sorted(manifest["skipped_targets"]))
                           + "; refusing to sign a partial release (--allow-partial to override)")
    verify_artifacts(release, manifest)
    key_path = Path(os.path.expanduser(args.key or os.environ.get("WINS_WINN_RELEASE_KEY", "")))
    if not str(key_path) or str(key_path) == ".":
        raise ReleaseError("pass --key PATH (or WINS_WINN_RELEASE_KEY)")
    seed = load_private_seed(key_path)
    try:
        public = ed25519_public(seed)
        if public != pinned_public_key() and not args.allow_unpinned_key:
            raise ReleaseError("this key is not the pinned release authority in tools/winn_release_authority.json "
                               "(--allow-unpinned-key exists for test keys only)")
        signature = ed25519_sign(seed, SIGNATURE_DOMAIN + payload)
    finally:
        seed = b"\0" * 32
        del seed
    if not ed25519_verify(public, SIGNATURE_DOMAIN + payload, signature):
        raise ReleaseError("fresh signature failed self-verification")
    document = {
        "contract": SIGNATURE_CONTRACT,
        "algorithm": "ed25519",
        "public_key": public.hex(),
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": signature.hex(),
    }
    # Staged under a fresh name, then linked into place: the link fails if a
    # signature appeared while this one was made, so another signer's record
    # is refused, never replaced, and a reader never sees a partial file.
    descriptor, temporary_text = tempfile.mkstemp(prefix=".manifest.sig.json.", dir=release)
    temporary = Path(temporary_text)
    try:
        try:
            view = memoryview(canonical_json(document))
            while view:
                view = view[os.write(descriptor, view):]
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, signature_path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ReleaseError(f"{signature_path} appeared while signing; refusing to replace it") from exc
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    print(f"SIGNED {manifest_path} sha256 {document['manifest_sha256']} public_key {public.hex()}")
    return 0


def _inside(release: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or relative.startswith("/") or ".." in Path(relative).parts:
        raise ReleaseError(f"manifest path is not release-relative: {relative!r}")
    return release / relative


def verify_artifacts(release: Path, manifest: Mapping[str, Any]) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ReleaseError("manifest lists no artifacts")
    seen = set()
    for entry in artifacts:
        target = entry.get("target")
        if target not in TARGETS or target in seen:
            raise ReleaseError(f"manifest artifact target is unknown or repeated: {target!r}")
        seen.add(target)
        if not (entry.get("sha256") == entry.get("build_a_sha256") == entry.get("build_b_sha256")):
            raise ReleaseError(f"{target}: the two independent builds are not recorded as identical")
        if "obfuscation" in entry and (not target.startswith(OBFUSCATABLE_PREFIXES)
                                       or entry["obfuscation"] != manifest.get("obfuscation")):
            raise ReleaseError(f"{target}: obfuscation record is not allowed or disagrees with the manifest")
        path = _inside(release, entry.get("path"))
        if sha256_file(path) != entry["sha256"] or path.stat().st_size != entry.get("size"):
            raise ReleaseError(f"{target}: {path} does not match the manifest")
        if entry.get("header_path") is not None:
            if sha256_file(_inside(release, entry["header_path"])) != entry.get("header_sha256"):
                raise ReleaseError(f"{target}: header does not match the manifest")
        elif TARGETS[target][0].endswith(".a"):
            raise ReleaseError(f"{target}: archive has no generated header in the manifest")


MANIFEST_LIMIT = 4 * 1024 * 1024
SIGNATURE_LIMIT = 64 * 1024


def verify_manifest_payload(payload: bytes, signature_document: Optional[bytes],
                            trusted: Optional[bytes]) -> dict[str, Any]:
    """Authenticate held manifest bytes and return the manifest parsed from them.

    signature_document None means the caller chose the unsigned dev path. With
    a document, trusted is the Ed25519 public key the signature must verify
    under. Nothing here touches the filesystem, so the caller decides once
    which bytes are the release and every later value comes from them.
    """
    manifest = json.loads(payload, object_pairs_hook=_no_duplicates)
    if not isinstance(manifest, dict) or manifest.get("contract") != MANIFEST_CONTRACT \
            or canonical_json(manifest) != payload:
        raise ReleaseError("manifest.json is not a canonical release manifest")
    if signature_document is None:
        return manifest
    if trusted is None or len(trusted) != 32:
        raise ReleaseError("no trusted Ed25519 release key")
    document = json.loads(signature_document, object_pairs_hook=_no_duplicates)
    if not isinstance(document, dict) or document.get("contract") != SIGNATURE_CONTRACT \
            or document.get("algorithm") != "ed25519":
        raise ReleaseError("manifest.sig.json is malformed")
    if document.get("public_key") != trusted.hex():
        raise ReleaseError("manifest was signed by a key that is not the trusted release authority")
    if document.get("manifest_sha256") != hashlib.sha256(payload).hexdigest():
        raise ReleaseError("manifest.sig.json names a different manifest")
    signature_hex = document.get("signature")
    if not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        raise ReleaseError("manifest.sig.json signature is malformed")
    if not ed25519_verify(trusted, SIGNATURE_DOMAIN + payload, bytes.fromhex(signature_hex)):
        raise ReleaseError("manifest signature does not verify")
    return manifest


def verify_release(args: argparse.Namespace) -> int:
    release = Path(os.path.abspath(args.release))
    # Each file is read exactly once. The signature is checked over these held
    # bytes and every digest below comes from the manifest parsed out of them.
    payload = read_held_bytes(release / "manifest.json", MANIFEST_LIMIT)
    signature_path = release / "manifest.sig.json"
    if args.allow_unsigned:
        print("UNSIGNED: dev use only; the signature was not checked", file=sys.stderr)
        manifest = verify_manifest_payload(payload, None, None)
    else:
        if not signature_path.is_file():
            raise ReleaseError("manifest.sig.json is missing; the release is unsigned")
        document = read_held_bytes(signature_path, SIGNATURE_LIMIT)
        trusted = bytes.fromhex(args.trust_public_key) if args.trust_public_key else pinned_public_key()
        manifest = verify_manifest_payload(payload, document, trusted)
    verify_artifacts(release, manifest)
    if getattr(args, "print_manifest", False):
        # The exact bytes the signature was verified over: one canonical JSON
        # line. Consumers take expected digests from this, never from a second
        # read of manifest.json.
        sys.stdout.write(payload.decode("ascii"))
        sys.stdout.flush()
    if args.print_artifact:
        for entry in manifest["artifacts"]:
            if entry["target"] == args.print_artifact:
                print(_inside(release, entry["path"]))
                if entry.get("header_path"):
                    print(_inside(release, entry["header_path"]))
                break
        else:
            raise ReleaseError(f"release holds no artifact for {args.print_artifact}")
    else:
        state = "unsigned" if args.allow_unsigned else "signature valid"
        print(f"VERIFIED {release}: {len(manifest['artifacts'])} artifacts, {state}, "
              f"source {manifest['source']['binding']} {manifest['source']['commit']}", file=sys.stderr)
    return 0


ANDROID_STAMP_CONTRACT = "winsvpn-winn-release-android-stage-v1"
ANDROID_STAMP_TARGETS = ("datapath-android-arm64", "datapath-android-arm", "datapath-android-amd64")


def verify_android_stamp(args: argparse.Namespace) -> int:
    """Release gate for an Android winn-release.json stamp.

    The stamp carries the signed manifest bytes and their detached signature.
    It passes only if that signature verifies under the pinned release
    authority key (no override), and the staged engine's sha256 and size equal
    the signed manifest's reproducible entry for TARGET. Hex-shaped fields in
    the stamp itself are never trusted.
    """
    stamp = load_json(Path(args.stamp))
    if not isinstance(stamp, dict) or stamp.get("contract") != ANDROID_STAMP_CONTRACT:
        raise ReleaseError("invalid Android release stamp")
    encoded = stamp.get("manifest_b64")
    signature_hex = stamp.get("manifest_signature")
    if not isinstance(encoded, str) or not isinstance(signature_hex, str) \
            or not re.fullmatch(r"[0-9a-f]{128}", signature_hex):
        raise ReleaseError("Android stamp lacks signed manifest bytes")
    payload = base64.b64decode(encoded, validate=True)
    manifest = json.loads(payload, object_pairs_hook=_no_duplicates)
    if not isinstance(manifest, dict) or manifest.get("contract") != MANIFEST_CONTRACT \
            or canonical_json(manifest) != payload:
        raise ReleaseError("Android stamp manifest is not canonical")
    if not ed25519_verify(pinned_public_key(), SIGNATURE_DOMAIN + payload, bytes.fromhex(signature_hex)):
        raise ReleaseError("Android stamp signature does not verify")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ReleaseError("Android stamp manifest has no artifacts")
    rows = [row for row in artifacts if isinstance(row, dict) and row.get("target") == args.target]
    if len(rows) != 1:
        raise ReleaseError("Android stamp must contain exactly one matching target")
    row = rows[0]
    path = Path(args.artifact)
    digest = sha256_file(path)
    if not (digest == row.get("sha256") == row.get("build_a_sha256") == row.get("build_b_sha256")):
        raise ReleaseError("staged Android engine differs from the signed manifest")
    if type(row.get("size")) is not int or path.stat().st_size != row["size"]:
        raise ReleaseError("staged Android engine size differs from the signed manifest")
    print(f"ANDROID STAMP OK {args.target} sha256 {digest} manifest {hashlib.sha256(payload).hexdigest()}")
    return 0


def prepare_go_command(args: argparse.Namespace) -> int:
    """Extract the pinned Go archive into a new directory and print its identity.

    The archive SHA-256, the normalized install-tree SHA-256 and the bin/go
    SHA-256 must all equal tools/toolchain-pins.json for this host. This is the
    same check `build` uses; other producers (AWG, Xray) take Go from it.
    """
    out = Path(os.path.abspath(args.out))
    if out.exists() or out.is_symlink():
        raise ReleaseError(f"--out {out} already exists; prepare-go extracts into a new directory")
    out.mkdir(parents=True, mode=0o700)
    try:
        go_root, identity = prepare_go(args.go_archive, out, go_pins(load_pins()))
    except BaseException:
        # A refused archive, tree or bin/go leaves nothing behind that a
        # caller ignoring the exit status could pick up as a Go root.
        remove_tree(out)
        raise
    print(json.dumps({"go_root": str(go_root), **identity}, sort_keys=True))
    return 0


def build_one(args: argparse.Namespace) -> int:
    """Direct builder invocation: commit-bound two-build release of one target."""
    output = Path(os.path.abspath(args.output))
    receipt_path = Path(str(output) + ".receipt.json")
    archive_mode = TARGETS[args.target][0].endswith(".a")
    if archive_mode and output.suffix != ".a":
        raise ReleaseError(f"archive target {args.target} requires an output path ending in .a")
    expected_header = output.with_suffix(".h") if archive_mode else None
    for destination in (output, receipt_path, expected_header):
        if destination is not None and (destination.exists() or destination.is_symlink()):
            raise ReleaseError(f"output must be fresh: {destination}")
    head = _git("rev-parse", "--verify", "HEAD^{commit}").decode().strip() if (ROOT / ".git").exists() else ""
    if not head:
        raise ReleaseError("direct builds need a git checkout to bind the source to a commit; "
                           "use tools/winn_release.py build --source-export DIR --source-commit SHA instead")
    output.parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=".winn-build-one.", dir=output.parent))
    try:
        namespace = argparse.Namespace(
            out=str(scratch / "release"), set=None, targets=args.target, source_commit=head,
            source_export=None, go_archive=os.environ.get("WINS_WINN_GO_ARCHIVE"),
            ndk=os.environ.get("WINS_ANDROID_NDK_ROOT"), developer_dir=os.environ.get("WINS_APPLE_DEVELOPER_DIR"),
            module_proxy=default_module_proxy(), jobs=2, skip_unavailable=False, keep_work=False)
        build_release(namespace)
        manifest = load_json(scratch / "release" / "manifest.json")
        entry = manifest["artifacts"][0]
        log = scratch / "release" / "logs" / f"{args.target}.a.log"
        receipt_lines = [
            line[len(RECEIPT_PREFIX):]
            for line in log.read_text(encoding="utf-8").splitlines()
            if line.startswith(RECEIPT_PREFIX)
        ]
        if len(receipt_lines) != 1:
            raise ReleaseError("direct build must retain exactly one build A receipt")
        receipt = json.loads(receipt_lines[0], object_pairs_hook=_no_duplicates)
        if receipt.get("contract") != RECEIPT_CONTRACT or receipt.get("target", {}).get("id") != args.target:
            raise ReleaseError("direct build receipt has the wrong contract or target")
        receipt["artifact"]["output_path"] = str(output)
        payload = canonical_json(receipt)
        staged_receipt = scratch / "direct.receipt.json"
        with staged_receipt.open("xb") as handle:
            handle.write(payload)
        os.chmod(staged_receipt, 0o444)
        publications = [(scratch / "release" / entry["path"], output, entry["sha256"])]
        if entry.get("header_path"):
            publications.append((
                scratch / "release" / entry["header_path"],
                expected_header,
                entry["header_sha256"],
            ))
        publications.append((
            staged_receipt, receipt_path, hashlib.sha256(payload).hexdigest(),
        ))
        installed: list[tuple[Path, int, int]] = []
        try:
            for source, destination, expected in publications:
                if sha256_file(source) != expected:
                    raise ReleaseError(f"staged output changed before publication: {source}")
                info = os.lstat(source)
                os.link(source, destination, follow_symlinks=False)
                installed.append((destination, info.st_dev, info.st_ino))
            for _source, destination, expected in publications:
                if sha256_file(destination) != expected:
                    raise ReleaseError(f"installed output changed during publication: {destination}")
        except BaseException:
            for destination, device, inode in reversed(installed):
                try:
                    info = os.lstat(destination)
                except FileNotFoundError:
                    continue
                if (info.st_dev, info.st_ino) == (device, inode):
                    destination.unlink()
            raise
        print(RECEIPT_PREFIX + payload.decode("ascii").rstrip("\n"))
        print(f"Built Winn Protocol {entry['role']}: {output} ({args.target}, sha256 {entry['sha256']})")
        return 0
    finally:
        remove_tree(scratch)


def default_module_proxy() -> str:
    local = Path(os.path.expanduser("~/go/pkg/mod/cache/download"))
    return f"file://{local}" if local.is_dir() else "off"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    targets = sub.add_parser("targets")
    targets.add_argument("--set", required=True, choices=sorted(SETS))
    build = sub.add_parser("build")
    build.add_argument("--out", required=True)
    build.add_argument("--set", choices=sorted(SETS))
    build.add_argument("--targets")
    build.add_argument("--source-commit", required=True)
    build.add_argument("--source-export")
    build.add_argument("--go-archive")
    build.add_argument("--ndk")
    build.add_argument("--developer-dir")
    build.add_argument("--module-proxy", default=default_module_proxy(),
                       help="GOPROXY used only to fill the private module cache; go.sum pins the bytes")
    build.add_argument("--jobs", type=int, default=4)
    build.add_argument("--skip-unavailable", action="store_true",
                       help="build what this host can; missing toolchains are listed in the manifest")
    build.add_argument("--keep-work", action="store_true")
    build.add_argument("--obfuscate", choices=("none", "garble"), default="none",
                       help="garble the website client engines (owner ruling 2026-10-27)")
    build.add_argument("--garble-seed-file",
                       help="owner-only file holding the private garble seed; only its SHA-256 is recorded")
    sign = sub.add_parser("sign")
    sign.add_argument("--release", required=True)
    sign.add_argument("--key")
    sign.add_argument("--allow-unpinned-key", action="store_true")
    sign.add_argument("--allow-export-source", action="store_true")
    sign.add_argument("--allow-partial", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("--release", required=True)
    verify.add_argument("--trust-public-key")
    verify.add_argument("--allow-unsigned", action="store_true")
    verify.add_argument("--print-artifact")
    verify.add_argument("--print-manifest", action="store_true",
                        help="print the exact verified manifest bytes (one line) before any artifact path")
    android_stamp = sub.add_parser("verify-android-stamp")
    android_stamp.add_argument("--stamp", required=True)
    android_stamp.add_argument("--artifact", required=True)
    android_stamp.add_argument("--target", required=True, choices=ANDROID_STAMP_TARGETS)
    go_root = sub.add_parser("prepare-go")
    go_root.add_argument("--out", required=True)
    go_root.add_argument("--go-archive")
    one = sub.add_parser("build-one")
    one.add_argument("target")
    one.add_argument("output")
    digest = sub.add_parser("digest")
    digest.add_argument("--kind", required=True, choices=("sealed", "platform", "go-tree"))
    digest.add_argument("path")
    args = parser.parse_args(argv)
    try:
        if args.command == "targets":
            print("\n".join(SETS[args.set]))
            return 0
        if args.command == "build":
            return build_release(args)
        if args.command == "sign":
            return sign_release(args)
        if args.command == "verify":
            return verify_release(args)
        if args.command == "verify-android-stamp":
            return verify_android_stamp(args)
        if args.command == "prepare-go":
            return prepare_go_command(args)
        if args.command == "build-one":
            if args.target not in TARGETS:
                raise ReleaseError(f"unknown target {args.target!r}")
            args.targets = args.target
            return build_one(args)
        if args.command == "digest":
            path = Path(os.path.abspath(args.path))
            if args.kind == "sealed":
                print(sealed_tree_digest(path))
            elif args.kind == "platform":
                print(platform_tree_digest(path))
            else:
                # The normalized Go install-tree digest the go pins name.
                print(_go_custody_module().tree_hash(path))
            return 0
    except ToolchainMissing as exc:
        message = str(exc)
        print(message if message.startswith("TOOLCHAIN-MISSING:") else f"TOOLCHAIN-MISSING: {message}", file=sys.stderr)
        return EXIT_TOOLCHAIN
    except (ReleaseError, OSError, ValueError, KeyError) as exc:
        print(f"WINN RELEASE REFUSED: {exc}", file=sys.stderr)
        return EXIT_FAIL
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
