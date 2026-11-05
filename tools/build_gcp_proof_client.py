#!/usr/bin/env python3
"""Build an explicit GOOS/GOARCH GCP proof client with exact provenance.

The caller must name the exact target. The builder labels that target in the
artifact name, receipt, and compiled identity, and refuses to produce or treat
as executable a binary that cannot run on the observed host.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import importlib.util
import json
import marshal
import os
import pathlib
import platform
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import types
from collections.abc import Iterator, Mapping, Sequence
from typing import Any


TOOLS = pathlib.Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

freeze: types.ModuleType | None = None
gcloud_custody: types.ModuleType | None = None
gcloud_pin_generator: types.ModuleType | None = None
go_custody: types.ModuleType | None = None


SCHEMA_VERSION = 3
RECEIPT_CONTRACT = "winsvpn-gcp-proof-client-build-receipt-v3"
IDENTITY_CONTRACT = "winsvpn-gcp-proof-client-identity-v1"
BUILD_CONTRACT = "winsvpn-gcp-proof-client-build-contract-v5"
SOURCE_CONTRACT = "winsvpn-gcp-proof-client-source-v4"
TOOLCHAIN_CONTRACT = "winsvpn-reviewed-go-runtime-custody-v1"
SOURCE_SNAPSHOT_CONTRACT = "winsvpn-root-immutable-proof-source-v1"
ALLOWED_GOOS = frozenset({"darwin", "linux"})
ALLOWED_GOARCH = frozenset({"amd64", "arm64"})
ALLOWED_TARGETS = frozenset(
    (goos, goarch) for goos in ALLOWED_GOOS for goarch in ALLOWED_GOARCH
)
RELEASE_TARGET = {"cgo_enabled": False, "goarch": "amd64", "goos": "linux"}
HOST_OS = {"Darwin": "darwin", "Linux": "linux"}
HOST_ARCH = {
    "amd64": "amd64",
    "arm64": "arm64",
    "aarch64": "arm64",
    "x86_64": "amd64",
}
RELEASE_INDEX_PLATFORM = "linux"
TARGET_KEYS = frozenset({"cgo_enabled", "goarch", "goos"})
ARTIFACT_NAME_PREFIX = "winsvpn-gcp-proof-client"
BUNDLE_SUFFIX = ".bundle"
IDENTITY_PROBE_NAME = "build_identity_probe_test.go"
PACKAGE_COMPILER_INPUTS = (
    "tools/gcp_proof_client/go.mod",
    "tools/gcp_proof_client/gcloud_custody.go",
    "tools/gcp_proof_client/gcloud_custody_test.go",
    "tools/gcp_proof_client/gcloud_pin_generated.go",
    "tools/gcp_proof_client/main.go",
    "tools/gcp_proof_client/main_test.go",
)
REVIEWED_SUPPORT_INPUTS = (
    "tools/release_dependency_freeze.py",
    "tools/generate_gcloud_go_pin.py",
    "tools/gcloud_custody.py",
    "tools/create_gcloud_custody_receipt.py",
    "tools/gcp_proof_attempt_broker.py",
    "tools/release_go_archive_custody.py",
    "tools/release_go_archive_custody.sh",
    "tools/release_go_archive_custody.trust.json",
    "tools/provision_macos_release_go_runtime.sh",
    "tools/release_source_freeze.py",
)
SOURCE_PATHS = PACKAGE_COMPILER_INPUTS + REVIEWED_SUPPORT_INPUTS
BUILDER_PATH = "tools/build_gcp_proof_client.py"
PIN_PATH = "tools/toolchain-pins.json"
PROOF_PACKAGE = "tools/gcp_proof_client"
BUILD_FLAGS = (
    "build",
    "-trimpath",
    "-buildvcs=false",
    "-mod=readonly",
)
LD_FLAGS = ("-s", "-w", "-buildid=")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GO_EMBED_RE = re.compile(rb"(?m)^[\t ]*//go:embed(?:[\t ]|$)")
GO_COMPILER_SUFFIXES = frozenset(
    {
        ".F",
        ".S",
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".f",
        ".f90",
        ".for",
        ".go",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".m",
        ".mm",
        ".s",
        ".swig",
        ".swigcxx",
        ".sx",
        ".syso",
    }
)
GO_MODULE_INPUT_NAMES = frozenset({"go.mod", "go.sum", "go.work", "go.work.sum"})
EXPECTED_GO_MOD_BYTES = b"module winsvpn.local/gcpproofclient\n\ngo 1.27.1\n"
OWNER_BLOCKED_GO = (
    "OWNER-BLOCKED: a complete root-owned immutable reviewed Go runtime custody "
    "identity is required"
)
LOCAL_HELPER_PATHS = (
    ("release_dependency_freeze", "tools/release_dependency_freeze.py"),
    ("gcloud_custody", "tools/gcloud_custody.py"),
    ("generate_gcloud_go_pin", "tools/generate_gcloud_go_pin.py"),
    ("release_go_archive_custody", "tools/release_go_archive_custody.py"),
    ("release_source_freeze", "tools/release_source_freeze.py"),
)
IDENTITY_DEFINE_NAMES = (
    ("attempt_broker_sha256", "expectedAttemptBrokerSHA256"),
    ("release", "releaseValue"),
    ("shared_revision", "sharedRevision"),
    ("source_sha256", "sourceSHA256"),
    ("build_contract_sha256", "buildContractSHA256"),
    ("toolchain_version", "toolchainVersion"),
    ("target", "targetValue"),
    ("build_identity", "buildIdentity"),
)
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
ELF_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
MACHO64_HEADER = struct.Struct("<IiiIIIII")
MACHO64_MAGIC = 0xFEEDFACF
MACHO_ARM64_CPU = 0x0100000C
IDENTITY_MARKER = b"WINSVPN_BUILD_IDENTITY="
SOURCE_SNAPSHOT_BLOCKER = (
    "OWNER-BLOCKED: the exact private proof source snapshot must be separately "
    "root-provisioned with SF_IMMUTABLE"
)
SOURCE_SNAPSHOT_ROOT = pathlib.Path(
    "/Library/WinsVPN/GcpProofSourceSnapshots/v1"
)
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
IDENTITY_PROBE_BYTES = b'''package main

import (
\t"encoding/json"
\t"fmt"
\t"os"
\t"testing"
)

func TestMain(m *testing.M) {
\tif len(os.Args) != 2 || os.Args[1] != "--winsvpn-build-identity-readback" {
\t\tos.Exit(m.Run())
\t}
\tidentity := map[string]string{
\t\t"attempt_broker_sha256": expectedAttemptBrokerSHA256,
\t\t"build_contract_sha256": buildContractSHA256,
\t\t"build_identity": buildIdentity,
\t\t"release": releaseValue,
\t\t"shared_revision": sharedRevision,
\t\t"source_sha256": sourceSHA256,
\t\t"target": targetValue,
\t\t"toolchain_version": toolchainVersion,
\t}
\tencoded, err := json.Marshal(identity)
\tif err != nil {
\t\tfmt.Fprintln(os.Stderr, err)
\t\tos.Exit(2)
\t}
\tfmt.Printf("WINSVPN_BUILD_IDENTITY=%s\\n", encoded)
\tos.Exit(0)
}
'''


class ProofBuildError(RuntimeError):
    """The dedicated GCP proof artifact cannot be produced safely."""


def canonical_target(raw: object) -> dict[str, Any]:
    """Return the exact labeled GOOS/GOARCH object, or refuse."""

    if raw is None:
        raise ProofBuildError("Proof client GOOS/GOARCH target must be explicit.")
    if not isinstance(raw, Mapping):
        raise ProofBuildError("Proof client target must be an exact GOOS/GOARCH object.")
    if set(raw) != TARGET_KEYS:
        raise ProofBuildError("Proof client target has missing or unknown keys.")
    cgo = raw.get("cgo_enabled")
    goos = raw.get("goos")
    goarch = raw.get("goarch")
    if cgo is not False:
        raise ProofBuildError("Proof client target must disable cgo.")
    if (
        not isinstance(goos, str)
        or not isinstance(goarch, str)
        or (goos, goarch) not in ALLOWED_TARGETS
    ):
        raise ProofBuildError("Proof client GOOS/GOARCH target is not allowed.")
    return {"cgo_enabled": False, "goarch": goarch, "goos": goos}


def explicit_target(goos: object, goarch: object) -> dict[str, Any]:
    """Build the exact target object from explicit GOOS and GOARCH names."""

    if not isinstance(goos, str) or not isinstance(goarch, str) or not goos or not goarch:
        raise ProofBuildError("Proof client GOOS/GOARCH target must be explicit.")
    return canonical_target({"cgo_enabled": False, "goarch": goarch, "goos": goos})


def target_value(target: Mapping[str, Any]) -> str:
    selected = canonical_target(target)
    return f"{selected['goos']}/{selected['goarch']}"


def labeled_artifact_name(target: Mapping[str, Any]) -> str:
    selected = canonical_target(target)
    return f"{ARTIFACT_NAME_PREFIX}-{selected['goos']}-{selected['goarch']}"


def require_labeled_artifact_path(
    path: pathlib.Path, target: Mapping[str, Any], label: str
) -> None:
    expected = labeled_artifact_name(target)
    if path.name != expected:
        raise ProofBuildError(f"{label} must be named {expected}.")


def host_go_target() -> dict[str, Any]:
    """Observe the host GOOS/GOARCH. Environment GOOS/GOARCH cannot select it."""

    system = platform.system()
    machine = platform.machine()
    goos = HOST_OS.get(system)
    goarch = HOST_ARCH.get(machine)
    if goos is None or goarch is None:
        raise ProofBuildError(
            f"Proof client host platform {system}/{machine} is not a supported GOOS/GOARCH."
        )
    return explicit_target(goos, goarch)


def require_reviewed_builder_host() -> dict[str, Any]:
    """Require the platform covered by the current owner Go custody design."""

    host = host_go_target()
    if target_value(host) != "darwin/arm64":
        raise ProofBuildError(
            f"{OWNER_BLOCKED_GO}: the reviewed proof builder host must be "
            f"darwin/arm64, not {target_value(host)}."
        )
    return host


def _require_artifact_metadata(
    metadata: bytes,
    target: Mapping[str, Any],
    toolchain_version: str,
    *,
    expected_path: str = "winsvpn.local/gcpproofclient",
) -> dict[str, str]:
    """Require exact structured metadata emitted by the held reviewed Go tool."""

    selected = canonical_target(target)
    record = _strict_json_bytes(metadata, "Proof artifact build metadata")
    allowed_top = {"Deps", "GoVersion", "Main", "Path", "Settings"}
    if set(record) - allowed_top or not {
        "GoVersion",
        "Main",
        "Path",
        "Settings",
    }.issubset(record):
        raise ProofBuildError("Proof artifact build metadata keys are not exact.")
    if record.get("Deps") not in (None, []):
        raise ProofBuildError("Proof artifact unexpectedly embeds a dependency module.")
    if record.get("GoVersion") != toolchain_version:
        raise ProofBuildError("Proof artifact Go version is not the reviewed toolchain.")
    if record.get("Path") != expected_path:
        raise ProofBuildError("Proof artifact package path is not exact.")
    main = record.get("Main")
    if main != {
        "Path": "winsvpn.local/gcpproofclient",
        "Version": "(devel)",
    }:
        raise ProofBuildError("Proof artifact main-module identity is not exact.")
    raw_settings = record.get("Settings")
    if not isinstance(raw_settings, list):
        raise ProofBuildError("Proof artifact build settings are not an exact list.")
    settings: dict[str, str] = {}
    for item in raw_settings:
        if (
            not isinstance(item, dict)
            or set(item) != {"Key", "Value"}
            or type(item["Key"]) is not str
            or type(item["Value"]) is not str
            or item["Key"] in settings
        ):
            raise ProofBuildError("Proof artifact build settings are ambiguous.")
        settings[item["Key"]] = item["Value"]
    required = {
        "-buildmode": "exe",
        "-compiler": "gc",
        "-trimpath": "true",
        "CGO_ENABLED": "0",
        "GOARCH": selected["goarch"],
        "GOOS": selected["goos"],
    }
    architecture_key = "GOAMD64" if selected["goarch"] == "amd64" else "GOARM64"
    architecture_value = "v1" if selected["goarch"] == "amd64" else "v8.0"
    required[architecture_key] = architecture_value
    if settings != required:
        raise ProofBuildError("Proof artifact build settings are not the exact reviewed set.")
    for key, value in required.items():
        if settings.get(key) != value:
            raise ProofBuildError(
                f"Proof artifact metadata does not bind exact {key}={value}."
            )
    return settings


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ProofBuildError("Proof build record is not JSON-safe.") from exc
    return (encoded + "\n").encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProofBuildError(f"Duplicate JSON key {key!r} is forbidden.")
        result[key] = value
    return result


def _strict_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ProofBuildError(f"{label} is not strict UTF-8 JSON.") from exc
    return _strict_json_bytes(data, label)


def _strict_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except ProofBuildError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProofBuildError(f"{label} is not strict UTF-8 JSON.") from exc
    if not isinstance(value, dict):
        raise ProofBuildError(f"{label} must be a JSON object.")
    return value


def _canonical_repo(raw: pathlib.Path) -> pathlib.Path:
    text = os.fspath(raw)
    if not raw.is_absolute() or os.path.normpath(text) != text:
        raise ProofBuildError("Repository root must be an absolute canonical path.")
    try:
        resolved = raw.resolve(strict=True)
        info = raw.lstat()
    except OSError as exc:
        raise ProofBuildError("Repository root is not readable.") from exc
    if resolved != raw or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ProofBuildError("Repository root must be a canonical non-symlink directory.")
    return raw


def _repo_path(
    repo: pathlib.Path,
    raw: pathlib.Path,
    label: str,
    *,
    must_exist: bool,
) -> pathlib.Path:
    text = os.fspath(raw)
    if not raw.is_absolute() or os.path.normpath(text) != text or "\\" in text:
        raise ProofBuildError(f"{label} must be an absolute canonical path.")
    try:
        relative = raw.relative_to(repo)
    except ValueError as exc:
        raise ProofBuildError(f"{label} must stay safely inside the repository.") from exc
    current = repo
    try:
        for index, part in enumerate(relative.parts):
            current /= part
            leaf = index == len(relative.parts) - 1
            try:
                info = current.lstat()
            except FileNotFoundError:
                if not must_exist:
                    break
                raise
            if stat.S_ISLNK(info.st_mode) or (not leaf and not stat.S_ISDIR(info.st_mode)):
                raise ProofBuildError(
                    f"{label} must stay safely inside the repository."
                )
    except ProofBuildError:
        raise
    except OSError as exc:
        raise ProofBuildError(f"{label} must stay safely inside the repository.") from exc
    if must_exist and raw.resolve() != raw:
        raise ProofBuildError(f"{label} path is not canonical.")
    return raw


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
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


def _read_descriptor(descriptor: int, size: int, label: str) -> bytes:
    chunks: list[bytes] = []
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            raise ProofBuildError(f"{label} was truncated while held.")
        chunks.append(block)
        offset += len(block)
    if os.pread(descriptor, 1, offset):
        raise ProofBuildError(f"{label} grew while held.")
    return b"".join(chunks)


class _DescriptorRepoInputs:
    """Hold exact repository leaves and their parent chain through the build."""

    def __init__(self, repo: pathlib.Path, paths: Sequence[str]) -> None:
        self.repo = repo
        self._parent_fd = -1
        self._ancestor_fds: list[tuple[int, tuple[int, ...], int, str]] = []
        self._directory_fds: dict[str, tuple[int, tuple[int, ...], str, str]] = {}
        self._files: dict[
            str, tuple[int, bytes, tuple[int, ...], str, str]
        ] = {}
        self._module_state: list[tuple[str, types.ModuleType | None]] = []
        self._loaded_modules: dict[str, types.ModuleType] = {}
        self._module_fingerprints: dict[str, object] = {}
        try:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            root_ancestor = os.open(pathlib.Path(repo.anchor), directory_flags)
            root_ancestor_info = os.fstat(root_ancestor)
            self._ancestor_fds.append(
                (
                    root_ancestor,
                    _containment_identity(root_ancestor_info),
                    -1,
                    repo.anchor,
                )
            )
            current_fd = root_ancestor
            for part in repo.parent.parts[1:]:
                descriptor = os.open(part, directory_flags, dir_fd=current_fd)
                opened = os.fstat(descriptor)
                named = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _containment_identity(opened)
                    != _containment_identity(named)
                ):
                    os.close(descriptor)
                    raise ProofBuildError(
                        "Repository ancestor changed while it was bound."
                    )
                self._ancestor_fds.append(
                    (
                        descriptor,
                        _containment_identity(opened),
                        len(self._ancestor_fds) - 1,
                        part,
                    )
                )
                current_fd = descriptor
            self._parent_fd = current_fd
            root_fd = os.open(repo.name, directory_flags, dir_fd=self._parent_fd)
            root_info = os.fstat(root_fd)
            named_root = os.stat(
                repo.name, dir_fd=self._parent_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISDIR(root_info.st_mode)
                or _containment_identity(root_info)
                != _containment_identity(named_root)
            ):
                os.close(root_fd)
                raise ProofBuildError("Repository root changed while it was bound.")
            self._root_identity = _containment_identity(root_info)
            self._directory_fds["."] = (
                root_fd,
                self._root_identity,
                "",
                repo.name,
            )
            for relative in dict.fromkeys(paths):
                self._hold_file(relative)
            self.verify(validate_modules=False)
            _validate_runtime_module_origins(self)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _parts(relative: str) -> tuple[str, ...]:
        pure = pathlib.PurePosixPath(relative)
        if (
            not relative
            or pure.is_absolute()
            or pure.as_posix() != relative
            or any(part in {"", ".", ".."} for part in pure.parts)
            or "\\" in relative
        ):
            raise ProofBuildError("A held repository path is not exact and relative.")
        return pure.parts

    def _open_directory(self, relative: str) -> int:
        if relative in {"", "."}:
            return self._directory_fds["."][0]
        if relative in self._directory_fds:
            return self._directory_fds[relative][0]
        parts = self._parts(relative)
        parent_relative = pathlib.PurePosixPath(*parts[:-1]).as_posix()
        if parent_relative == ".":
            parent_relative = "."
        parent_fd = self._open_directory(parent_relative)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        name = parts[-1]
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ProofBuildError(
                f"Held repository directory is unsafe: {relative}."
            ) from exc
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _containment_identity(opened) != _containment_identity(named)
        ):
            os.close(descriptor)
            raise ProofBuildError(
                f"Held repository directory changed while opened: {relative}."
            )
        self._directory_fds[relative] = (
            descriptor,
            _containment_identity(opened),
            parent_relative,
            name,
        )
        return descriptor

    def directory_fd(self, relative: str) -> int:
        return self._open_directory(relative)

    def _hold_file(self, relative: str) -> None:
        if relative in self._files:
            return
        parts = self._parts(relative)
        parent_relative = pathlib.PurePosixPath(*parts[:-1]).as_posix()
        if parent_relative == ".":
            parent_relative = "."
        parent_fd = self._open_directory(parent_relative)
        name = parts[-1]
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            named_before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size <= 0
                or _file_identity(opened) != _file_identity(named_before)
            ):
                raise ProofBuildError(
                    f"Held repository input is not one stable file: {relative}."
                )
            data = _read_descriptor(descriptor, opened.st_size, relative)
            finished = os.fstat(descriptor)
            named_after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not (
                _file_identity(opened)
                == _file_identity(finished)
                == _file_identity(named_after)
            ):
                raise ProofBuildError(
                    f"Held repository input changed while read: {relative}."
                )
        except BaseException:
            if "descriptor" in locals():
                os.close(descriptor)
            raise
        self._files[relative] = (
            descriptor,
            data,
            _file_identity(opened),
            parent_relative,
            name,
        )

    def bytes(self, relative: str) -> bytes:
        try:
            return self._files[relative][1]
        except KeyError as exc:
            raise ProofBuildError(
                f"Repository input was not descriptor-bound: {relative}."
            ) from exc

    def ref(self, relative: str) -> dict[str, Any]:
        data = self.bytes(relative)
        return {"bytes": len(data), "path": relative, "sha256": sha256_bytes(data)}

    def verify(self, *, validate_modules: bool = True) -> None:
        if self._parent_fd < 0 or "." not in self._directory_fds:
            raise ProofBuildError("Repository descriptor custody is closed.")
        try:
            root_fd, root_identity, _parent, _name = self._directory_fds["."]
            for index, (descriptor, identity, parent_index, name) in enumerate(
                self._ancestor_fds
            ):
                opened = os.fstat(descriptor)
                if _containment_identity(opened) != identity:
                    raise ProofBuildError("Repository ancestor descriptor changed.")
                if index == 0:
                    continue
                parent_fd = self._ancestor_fds[parent_index][0]
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _containment_identity(named) != identity:
                    raise ProofBuildError("Repository ancestor pathname changed.")
            root_opened = os.fstat(root_fd)
            root_named = os.stat(
                self.repo.name, dir_fd=self._parent_fd, follow_symlinks=False
            )
            if not (
                _containment_identity(root_opened)
                == _containment_identity(root_named)
                == root_identity
            ):
                raise ProofBuildError("Repository root escaped its held parent.")
            for relative, (descriptor, identity, parent_relative, name) in sorted(
                self._directory_fds.items(), key=lambda item: item[0].count("/")
            ):
                if relative == ".":
                    continue
                parent_fd = self._directory_fds[parent_relative][0]
                opened = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not (
                    stat.S_ISDIR(opened.st_mode)
                    and _containment_identity(opened)
                    == _containment_identity(named)
                    == identity
                ):
                    raise ProofBuildError(
                        f"Repository input parent changed while held: {relative}."
                    )
            for relative, (
                descriptor,
                expected,
                identity,
                parent_relative,
                name,
            ) in self._files.items():
                parent_fd = self._directory_fds[parent_relative][0]
                opened = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if not (
                    stat.S_ISREG(opened.st_mode)
                    and opened.st_nlink == 1
                    and _file_identity(opened) == _file_identity(named) == identity
                    and _read_descriptor(descriptor, len(expected), relative) == expected
                ):
                    raise ProofBuildError(
                        f"Repository input changed while held: {relative}."
                    )
        except ProofBuildError:
            raise
        except OSError as exc:
            raise ProofBuildError(
                "Repository descriptor custody could not be revalidated."
            ) from exc
        if validate_modules:
            _validate_runtime_module_origins(self)

    def close(self) -> None:
        global freeze, gcloud_custody, gcloud_pin_generator, go_custody
        for name, previous in reversed(self._module_state):
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        self._module_state.clear()
        self._loaded_modules.clear()
        self._module_fingerprints.clear()
        freeze = None
        gcloud_custody = None
        gcloud_pin_generator = None
        go_custody = None
        for descriptor, _data, _identity, _parent, _name in self._files.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._files.clear()
        directories = sorted(
            self._directory_fds.items(), key=lambda item: item[0].count("/"), reverse=True
        )
        for _relative, (descriptor, _identity, _parent, _name) in directories:
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._directory_fds.clear()
        for descriptor, _identity, _parent, _name in reversed(self._ancestor_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._ancestor_fds.clear()
        self._parent_fd = -1

    def __enter__(self) -> "_DescriptorRepoInputs":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _code_fingerprint(code: types.CodeType) -> object:
    constants: list[object] = []
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            constants.append(("code", _code_fingerprint(value)))
        elif type(value) in {type(None), bool, int, float, complex, str, bytes}:
            constants.append((type(value).__name__, value))
        elif isinstance(value, tuple):
            constants.append(("tuple", tuple(repr(item) for item in value)))
        elif isinstance(value, frozenset):
            constants.append(("frozenset", tuple(sorted(map(repr, value)))))
        else:
            constants.append((type(value).__name__, repr(value)))
    return (
        code.co_argcount,
        code.co_posonlyargcount,
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        tuple(constants),
        code.co_names,
        code.co_varnames,
        code.co_filename,
        code.co_name,
        code.co_qualname,
        code.co_firstlineno,
        code.co_linetable,
        code.co_exceptiontable,
        code.co_freevars,
        code.co_cellvars,
    )


def _builder_code_map(namespace: Mapping[str, Any], filename: str) -> dict[str, str]:
    result: dict[str, str] = {}

    def add(name: str, value: object) -> None:
        if isinstance(value, (staticmethod, classmethod)):
            value = value.__func__
        if isinstance(value, property):
            for suffix, function in (
                (".fget", value.fget),
                (".fset", value.fset),
                (".fdel", value.fdel),
            ):
                if function is not None:
                    add(name + suffix, function)
            return
        wrapped = getattr(value, "__wrapped__", None)
        if wrapped is not None:
            value = wrapped
        if isinstance(value, types.FunctionType):
            if value.__code__.co_filename == filename:
                result[name] = hashlib.sha256(
                    repr(_code_fingerprint(value.__code__)).encode("utf-8")
                ).hexdigest()
            return
        if isinstance(value, type):
            for child_name, child in vars(value).items():
                add(f"{name}.{child_name}", child)

    for name, value in namespace.items():
        add(name, value)
    return result


def _security_global(value: object) -> object:
    if value is None or type(value) in {bool, int, str, bytes}:
        return value
    if isinstance(value, pathlib.PurePath):
        return ("path", os.fspath(value))
    if isinstance(value, re.Pattern):
        return ("regex", value.pattern, value.flags)
    if isinstance(value, struct.Struct):
        return ("struct", value.format)
    if isinstance(value, (tuple, list)):
        return tuple(_security_global(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_security_global(item) for item in value), key=repr))
    if isinstance(value, dict):
        return tuple(
            sorted(
                (
                    (_security_global(key), _security_global(item))
                    for key, item in value.items()
                ),
                key=repr,
            )
        )
    raise TypeError


def _validate_executing_builder(inputs: _DescriptorRepoInputs) -> None:
    expected = inputs.repo / BUILDER_PATH
    runtime_file = globals().get("__file__")
    if type(runtime_file) is not str or pathlib.Path(runtime_file) != expected:
        raise ProofBuildError("Executing proof builder is outside repo_root.")
    if (
        not expected.is_absolute()
        or expected.suffix != ".py"
        or "__pycache__" in expected.parts
        or _file_identity(expected.lstat()) != inputs._files[BUILDER_PATH][2]
    ):
        raise ProofBuildError("Executing proof builder is not the held source FileRef.")
    source = inputs.bytes(BUILDER_PATH)
    try:
        exact_code = compile(
            source,
            os.fspath(expected),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (SyntaxError, ValueError) as exc:
        raise ProofBuildError("Held proof builder source cannot be compiled.") from exc
    spec = globals().get("__spec__")
    loader = globals().get("__loader__")
    if spec is not None:
        if getattr(spec, "origin", None) != runtime_file or loader is None:
            raise ProofBuildError("Imported proof builder origin is not exact source.")
        get_code = getattr(loader, "get_code", None)
        if not callable(get_code):
            raise ProofBuildError("Imported proof builder loader cannot prove source bytes.")
        try:
            loaded_code = get_code(getattr(spec, "name", ""))
        except (ImportError, OSError) as exc:
            raise ProofBuildError("Imported proof builder code cannot be authenticated.") from exc
        if not isinstance(loaded_code, types.CodeType) or _code_fingerprint(
            loaded_code
        ) != _code_fingerprint(exact_code):
            raise ProofBuildError("Imported proof builder executed alternate pycache bytes.")
    elif globals().get("__name__") != "__main__":
        raise ProofBuildError("Proof builder has no authenticated import or script origin.")
    reference: dict[str, Any] = {
        "__name__": "_winsvpn_exact_builder_reference",
        "__file__": os.fspath(expected),
        "__spec__": None,
        "__loader__": None,
        "__builtins__": __builtins__,
    }
    exec(exact_code, reference)
    runtime_codes = _builder_code_map(globals(), os.fspath(expected))
    reference_codes = _builder_code_map(reference, os.fspath(expected))
    if not runtime_codes or runtime_codes != reference_codes:
        raise ProofBuildError("Executing proof builder code differs from held source.")
    runtime_constants: dict[str, object] = {}
    reference_constants: dict[str, object] = {}
    try:
        for name, value in globals().items():
            if name.isupper() and name != "TOOLS":
                runtime_constants[name] = _security_global(value)
        for name, value in reference.items():
            if name.isupper() and name != "TOOLS":
                reference_constants[name] = _security_global(value)
    except TypeError as exc:
        raise ProofBuildError("Proof builder security globals are not exact constants.") from exc
    if runtime_constants != reference_constants:
        raise ProofBuildError("Proof builder security constants differ from held source.")


def _load_exact_module(
    inputs: _DescriptorRepoInputs, name: str, relative: str
) -> types.ModuleType:
    path = inputs.repo / relative
    try:
        code = compile(
            inputs.bytes(relative),
            os.fspath(path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (SyntaxError, ValueError) as exc:
        raise ProofBuildError(f"Held helper source cannot be compiled: {name}.") from exc
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__loader__ = None
    module.__package__ = ""
    module.__spec__ = importlib.util.spec_from_loader(
        name, loader=None, origin=os.fspath(path)
    )
    module.__dict__["__winsvpn_file_ref__"] = inputs.ref(relative)
    previous = sys.modules.get(name)
    inputs._module_state.append((name, previous))
    sys.modules[name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        inputs._module_state.pop()
        raise
    return module


def _module_fingerprint(module: types.ModuleType, filename: str) -> object:
    constants: dict[str, object] = {}
    for name, value in vars(module).items():
        if name.isupper():
            try:
                constants[name] = _security_global(value)
            except TypeError:
                constants[name] = (
                    "runtime-object",
                    type(value).__module__,
                    type(value).__qualname__,
                    id(value),
                )
    return (_builder_code_map(vars(module), filename), constants)


def _validate_runtime_module_origins(inputs: _DescriptorRepoInputs) -> None:
    global freeze, gcloud_custody, gcloud_pin_generator, go_custody
    _validate_executing_builder(inputs)
    if inputs._loaded_modules:
        expected = {
            name: inputs.ref(relative) for name, relative in LOCAL_HELPER_PATHS
        }
        global_modules = {
            "release_dependency_freeze": freeze,
            "gcloud_custody": gcloud_custody,
            "generate_gcloud_go_pin": gcloud_pin_generator,
            "release_go_archive_custody": go_custody,
            "release_source_freeze": getattr(freeze, "_SOURCE_FREEZE_MODULE", None),
        }
        for name, module in inputs._loaded_modules.items():
            relative = dict(LOCAL_HELPER_PATHS)[name]
            expected_path = os.fspath(inputs.repo / relative)
            if (
                global_modules.get(name) is not module
                or
                sys.modules.get(name) is not module
                or getattr(module, "__winsvpn_file_ref__", None) != expected[name]
                or getattr(module, "__file__", None) != expected_path
                or getattr(getattr(module, "__spec__", None), "origin", None)
                != expected_path
                or "__pycache__" in pathlib.Path(expected_path).parts
                or _module_fingerprint(module, expected_path)
                != inputs._module_fingerprints.get(name)
            ):
                raise ProofBuildError(f"Held helper module was substituted: {name}.")
        if getattr(gcloud_pin_generator, "gcloud_custody", None) is not gcloud_custody:
            raise ProofBuildError(
                "generate_gcloud_go_pin imported alternate gcloud_custody."
            )
        if getattr(freeze, "_SOURCE_FREEZE_MODULE", None) is not inputs._loaded_modules[
            "release_source_freeze"
        ]:
            raise ProofBuildError("release_dependency_freeze helper was substituted.")
        return
    source_freeze = _load_exact_module(
        inputs, "release_source_freeze", "tools/release_source_freeze.py"
    )
    gcloud_custody = _load_exact_module(
        inputs, "gcloud_custody", "tools/gcloud_custody.py"
    )
    go_custody = _load_exact_module(
        inputs,
        "release_go_archive_custody",
        "tools/release_go_archive_custody.py",
    )
    freeze = _load_exact_module(
        inputs, "release_dependency_freeze", "tools/release_dependency_freeze.py"
    )
    setattr(freeze, "_SOURCE_FREEZE_MODULE", source_freeze)
    gcloud_pin_generator = _load_exact_module(
        inputs, "generate_gcloud_go_pin", "tools/generate_gcloud_go_pin.py"
    )
    inputs._loaded_modules = {
        "release_source_freeze": source_freeze,
        "gcloud_custody": gcloud_custody,
        "release_go_archive_custody": go_custody,
        "release_dependency_freeze": freeze,
        "generate_gcloud_go_pin": gcloud_pin_generator,
    }
    inputs._module_fingerprints = {
        name: _module_fingerprint(
            module,
            os.fspath(inputs.repo / dict(LOCAL_HELPER_PATHS)[name]),
        )
        for name, module in inputs._loaded_modules.items()
    }
    if getattr(gcloud_pin_generator, "gcloud_custody", None) is not gcloud_custody:
        raise ProofBuildError("generate_gcloud_go_pin imported alternate gcloud_custody.")


def _stable_repo_file(repo: pathlib.Path, relative: str) -> bytes:
    path = _repo_path(repo, repo / relative, relative, must_exist=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
        ):
            raise ProofBuildError(
                f"{relative} is not a stable single-link source file."
            )
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _file_identity(before) != _file_identity(opened):
                raise ProofBuildError(f"{relative} changed before it was opened.")
            chunks: list[bytes] = []
            while block := os.read(descriptor, 1024 * 1024):
                chunks.append(block)
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except ProofBuildError:
        raise
    except OSError as exc:
        raise ProofBuildError(f"Unable to snapshot {relative}.") from exc
    if not (
        _file_identity(opened)
        == _file_identity(finished)
        == _file_identity(after)
    ):
        raise ProofBuildError(f"{relative} changed while it was read.")
    data = b"".join(chunks)
    if not data:
        raise ProofBuildError(f"{relative} must not be empty.")
    return data


def _file_ref(repo: pathlib.Path, relative: str) -> dict[str, Any]:
    data = _stable_repo_file(repo, relative)
    return {"bytes": len(data), "path": relative, "sha256": sha256_bytes(data)}


def _is_possible_go_input(name: str) -> bool:
    return name in GO_MODULE_INPUT_NAMES or pathlib.PurePath(name).suffix in GO_COMPILER_SUFFIXES


def _reject_unreviewed_compiler_inputs(
    repo: pathlib.Path, inputs: _DescriptorRepoInputs | None = None
) -> None:
    package = _repo_path(
        repo, repo / PROOF_PACKAGE, "Proof client package", must_exist=True
    )
    allowed = {
        pathlib.PurePosixPath(relative).relative_to(PROOF_PACKAGE).as_posix()
        for relative in PACKAGE_COMPILER_INPUTS
    }
    observed: set[str] = set()
    try:
        for base, directories, files in os.walk(package, topdown=True, followlinks=False):
            base_path = pathlib.Path(base)
            for name in list(directories):
                path = base_path / name
                relative = path.relative_to(package).as_posix()
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise ProofBuildError(
                        f"Proof client package contains an unsafe directory: {relative}."
                    )
                if name == "vendor":
                    raise ProofBuildError(
                        "Proof client package contains an unreviewed vendor compiler input tree."
                    )
            for name in files:
                path = base_path / name
                relative = path.relative_to(package).as_posix()
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise ProofBuildError(
                        f"Proof client package contains an unsafe file: {relative}."
                    )
                if _is_possible_go_input(name):
                    observed.add(relative)
                    if relative not in allowed:
                        raise ProofBuildError(
                            "Proof client package contains an unreviewed compiler input: "
                            f"{relative}."
                        )
    except ProofBuildError:
        raise
    except OSError as exc:
        raise ProofBuildError("Proof client compiler-input inventory is unreadable.") from exc
    if observed != allowed:
        missing = sorted(allowed - observed)
        detail = missing[0] if missing else "unknown"
        raise ProofBuildError(
            f"Proof client compiler-input inventory is incomplete: {detail}."
        )
    for relative in PACKAGE_COMPILER_INPUTS:
        data = inputs.bytes(relative) if inputs is not None else _stable_repo_file(repo, relative)
        if relative.endswith(".go") and GO_EMBED_RE.search(data):
            raise ProofBuildError(
                f"Proof client compiler input {relative} uses an unreviewed go:embed input."
            )
    go_mod = (
        inputs.bytes("tools/gcp_proof_client/go.mod")
        if inputs is not None
        else _stable_repo_file(repo, "tools/gcp_proof_client/go.mod")
    )
    if go_mod != EXPECTED_GO_MOD_BYTES:
        raise ProofBuildError(
            "Proof client go.mod must be the exact dependency-free reviewed module."
        )


def _compiler_input_bytes(
    repo: pathlib.Path, inputs: _DescriptorRepoInputs | None = None
) -> dict[str, bytes]:
    _reject_unreviewed_compiler_inputs(repo, inputs)
    result = {
        relative: (
            inputs.bytes(relative)
            if inputs is not None
            else _stable_repo_file(repo, relative)
        )
        for relative in PACKAGE_COMPILER_INPUTS
    }
    return result


def _reviewed_go(
    repo: pathlib.Path,
    target: Mapping[str, Any],
    inputs: _DescriptorRepoInputs | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selected = canonical_target(target)
    pins = (
        _strict_json_bytes(inputs.bytes(PIN_PATH), "Toolchain pin manifest")
        if inputs is not None
        else _strict_json(repo / PIN_PATH, "Toolchain pin manifest")
    )
    try:
        go = pins["tools"]["go"]
        version = go["version"]
        archives = go["archive_sha256"]
        trees = go["install_tree_sha256"]
        executable = go["executable"]
        executable_hashes = go["executable_sha256"]
        declared_platform = go["platform"]
    except (KeyError, TypeError) as exc:
        raise ProofBuildError(f"{OWNER_BLOCKED_GO}: pin fields are incomplete.") from exc
    platform_key = f"{selected['goos']}_{selected['goarch']}"
    platform_value = target_value(selected)
    executable_sha256: object = None
    if isinstance(executable_hashes, dict):
        executable_sha256 = executable_hashes.get(platform_key)
    elif (
        isinstance(executable_hashes, str)
        and isinstance(declared_platform, str)
        and declared_platform.replace("-", "_") == platform_key
    ):
        executable_sha256 = executable_hashes
    if (
        not isinstance(version, str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
        or not isinstance(archives, dict)
        or not isinstance(archives.get(platform_key), str)
        or SHA256_RE.fullmatch(archives[platform_key]) is None
        or not isinstance(trees, dict)
        or not isinstance(trees.get(platform_key), str)
        or SHA256_RE.fullmatch(trees[platform_key]) is None
        or executable != "bin/go"
        or not isinstance(executable_sha256, str)
        or SHA256_RE.fullmatch(executable_sha256) is None
    ):
        raise ProofBuildError(
            f"{OWNER_BLOCKED_GO} for {platform_value}; archive, install tree, "
            "and executable pins must all be exact."
        )
    return (
        {
            "archive_sha256": archives[platform_key],
            "contract": TOOLCHAIN_CONTRACT,
            "custody": "root-owned-immutable-runtime",
            "executable": executable,
            "executable_sha256": executable_sha256,
            "install_tree_sha256": trees[platform_key],
            "name": "Go",
            "owner_authority_contract": go_custody.AUTHORITY_CONTRACT,
            "platform": platform_value,
            "runtime_contract": go_custody.OWNER_RECEIPT_CONTRACT,
            "schema_version": 1,
            "version": version,
        },
        inputs.ref(PIN_PATH) if inputs is not None else _file_ref(repo, PIN_PATH),
    )


def _verify_generated_gcloud_pin(
    repo: pathlib.Path, inputs: _DescriptorRepoInputs | None = None
) -> None:
    generated = repo / "tools/gcp_proof_client/gcloud_pin_generated.go"
    try:
        observed = (
            inputs.bytes("tools/gcp_proof_client/gcloud_pin_generated.go").decode(
                "utf-8"
            )
            if inputs is not None
            else generated.read_text(encoding="utf-8")
        )
        if inputs is None:
            expected = gcloud_pin_generator.render(repo / PIN_PATH)
        else:
            pin = gcloud_custody.parse_google_cloud_cli_pin_document(
                inputs.bytes(PIN_PATH)
            )
            platform_key = "linux_amd64"
            expected = f'''// Code generated from tools/toolchain-pins.json by generate_gcloud_go_pin.py. DO NOT EDIT.
package main

const (
\treviewedGcloudVersion       = "{pin['version']}"
\treviewedGcloudPlatform      = "{platform_key}"
\treviewedGcloudArchiveName   = "{pin['archive_name'][platform_key]}"
\treviewedGcloudArchiveSHA256 = "{pin['archive_sha256'][platform_key]}"
\tgcloudReceiptName           = ".winsvpn-gcloud-custody-v1.json"
\tgcloudCustodyArchiveName    = ".winsvpn-gcloud-official-archive"
\tgcloudReceiptContract       = "winsvpn-gcloud-install-custody-v1"
)
'''
    except gcloud_custody.GcloudCustodyError as exc:
        raise ProofBuildError(
            "Authenticated Google Cloud CLI pin generation is owner-blocked or unauthorized."
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ProofBuildError("Reviewed Google Cloud CLI pin is unreadable.") from exc
    if observed != expected:
        raise ProofBuildError(
            "Generated Go Google Cloud CLI pin does not match the independent platform pin."
        )
    if inputs is not None:
        inputs.verify()


def expected_provenance(
    repo_root: pathlib.Path,
    release_input_index: pathlib.Path,
    target: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Recompute every pre-artifact field that the build receipt must carry."""

    selected = canonical_target(target)
    repo = _canonical_repo(repo_root)
    index = _repo_path(
        repo, release_input_index, "Release input index", must_exist=True
    )
    index_relative = index.relative_to(repo).as_posix()
    held_paths = (*SOURCE_PATHS, BUILDER_PATH, PIN_PATH, index_relative)
    with _DescriptorRepoInputs(repo, held_paths) as inputs:
        return _expected_provenance(repo, index, selected, inputs)


def _expected_provenance(
    repo: pathlib.Path,
    index: pathlib.Path,
    selected: Mapping[str, Any],
    inputs: _DescriptorRepoInputs,
) -> dict[str, Any]:
    builder_host = require_reviewed_builder_host()
    selected = canonical_target(selected)
    if selected != RELEASE_TARGET:
        raise ProofBuildError("Proof release build target must be exact linux/amd64.")
    index_relative = index.relative_to(repo).as_posix()
    inputs.verify()
    try:
        verified = freeze.verify_release_index(repo, index, RELEASE_INDEX_PLATFORM)
    except freeze.DependencyFreezeError as exc:
        raise ProofBuildError(str(exc)) from exc
    inputs.verify()
    index_record = _strict_json_bytes(
        inputs.bytes(index_relative), "Release input index"
    )
    if (
        index_record.get("release") != verified.get("release")
        or index_record.get("shared_revision") != verified.get("shared_revision")
    ):
        raise ProofBuildError("Release input index identity disagrees with verification.")
    # verify_release_index accepts a platform-scoped index for an in-scope
    # platform, but the proof fleet binds only the complete index
    # (gcp_client_release_binding), so refuse before any build work.
    if (
        index_record.get("contract") != freeze.INDEX_CONTRACT
        or index_record.get("manifest_set_complete") is not True
    ):
        raise ProofBuildError(
            "Proof client build requires the complete release input index, "
            "not a platform-scoped one."
        )
    _verify_generated_gcloud_pin(repo, inputs)
    _reject_unreviewed_compiler_inputs(repo, inputs)
    inputs.verify()
    compiler_inputs = [inputs.ref(path) for path in PACKAGE_COMPILER_INPUTS]
    reviewed_support = [inputs.ref(path) for path in REVIEWED_SUPPORT_INPUTS]
    source_record = {
        "compiler_inputs": compiler_inputs,
        "contract": SOURCE_CONTRACT,
        "package": PROOF_PACKAGE,
        "reviewed_support": reviewed_support,
        "schema_version": SCHEMA_VERSION,
    }
    source_record["sha256"] = sha256_bytes(canonical_bytes(source_record))
    toolchain, pin_ref = _reviewed_go(repo, builder_host, inputs)
    build_statement: dict[str, Any] = {
        "argv": [
            "<reviewed-go>",
            *BUILD_FLAGS,
            "-ldflags=<exact-release-defines>",
            "-o",
            "<new-output>",
            ".",
        ],
        "contract": BUILD_CONTRACT,
        "environment": {
            "CGO_ENABLED": "0",
            "GOENV": "off",
            "GOARCH": selected["goarch"],
            "GOAMD64": "v1",
            "GOFIPS140": "off",
            "GOOS": selected["goos"],
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        },
        "test_environment": {
            "CGO_ENABLED": "0",
            "GOENV": "off",
            "GOARCH": builder_host["goarch"],
            "GOARM64": "v8.0",
            "GOFIPS140": "off",
            "GOOS": builder_host["goos"],
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        },
        "ldflags": list(LD_FLAGS),
        "native_identity_probe": {
            "build_argv": [
                "<reviewed-go>",
                "test",
                "-c",
                "-trimpath",
                "-buildvcs=false",
                "-mod=readonly",
                "-ldflags=<exact-release-defines>",
                "-o",
                "<native-test-output>",
                ".",
            ],
            "execute_argv": [
                "<descriptor-held-native-test-output>",
                "--winsvpn-build-identity-readback",
            ],
            "identity_keys": [name for name, _variable in IDENTITY_DEFINE_NAMES],
            "source": {
                "bytes": len(IDENTITY_PROBE_BYTES),
                "path": IDENTITY_PROBE_NAME,
                "sha256": sha256_bytes(IDENTITY_PROBE_BYTES),
            },
        },
        "package": PROOF_PACKAGE,
        "schema_version": SCHEMA_VERSION,
        "source_snapshot": {
            "contract": SOURCE_SNAPSHOT_CONTRACT,
            "custody": "root-owned-sf-immutable",
            "location": "owner-provisioned-fixed-root",
        },
    }
    build_statement["sha256"] = sha256_bytes(canonical_bytes(build_statement))
    attempt_broker_sha256 = next(
        item["sha256"]
        for item in reviewed_support
        if item["path"] == "tools/gcp_proof_attempt_broker.py"
    )
    defines = {
        "attempt_broker_sha256": attempt_broker_sha256,
        "build_contract_sha256": build_statement["sha256"],
        "release": str(verified["release"]),
        "shared_revision": str(verified["shared_revision"]),
        "source_sha256": source_record["sha256"],
        "target": target_value(selected),
        "toolchain_version": f"go{toolchain['version']}",
    }
    builder_ref = inputs.ref(BUILDER_PATH)
    release_input_ref = {
        "path": index_relative,
        "sha256": sha256_bytes(inputs.bytes(index_relative)),
    }
    identity_input = {
        "build_contract": build_statement,
        "builder": builder_ref,
        "defines": defines,
        "identity_contract": IDENTITY_CONTRACT,
        "release_input_index": release_input_ref,
        "source": source_record,
        "target": selected,
        "toolchain": toolchain,
        "toolchain_pin_manifest": pin_ref,
    }
    identity = sha256_bytes(canonical_bytes(identity_input))
    defines["build_identity"] = identity
    return {
        "build_contract": build_statement,
        "build_identity": identity,
        "builder": builder_ref,
        "defines": defines,
        "release": str(verified["release"]),
        "release_input_index": release_input_ref,
        "shared_revision": str(verified["shared_revision"]),
        "source": source_record,
        "target": dict(selected),
        "toolchain": toolchain,
        "toolchain_pin_manifest": pin_ref,
    }


def _ldflags(defines: Mapping[str, str]) -> str:
    if set(defines) != {name for name, _variable in IDENTITY_DEFINE_NAMES}:
        raise ProofBuildError("Proof release define keys are not exact.")
    pairs = tuple((variable, defines[name]) for name, variable in IDENTITY_DEFINE_NAMES)
    if not all(re.fullmatch(r"[A-Za-z0-9._/+:-]+", value) for _, value in pairs):
        raise ProofBuildError("A proof release define contains unsafe characters.")
    return " ".join([*LD_FLAGS, *(f"-X=main.{name}={value}" for name, value in pairs)])


def _parse_native_identity(output: bytes, expected: Mapping[str, str]) -> None:
    expected_output = (
        IDENTITY_MARKER
        + json.dumps(
            dict(expected),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )
    if output != expected_output:
        raise ProofBuildError("Native proof identity readback marker is not exact.")
    observed = _strict_json_bytes(
        output[len(IDENTITY_MARKER) : -1], "Native proof identity readback"
    )
    if observed != dict(expected):
        raise ProofBuildError("Native proof identity readback differs from release defines.")


def _require_native_probe_macho(data: bytes) -> None:
    if len(data) < MACHO64_HEADER.size:
        raise ProofBuildError("Native identity probe is not a complete Mach-O executable.")
    magic, cpu, _subtype, filetype, commands, command_bytes, _flags, reserved = (
        MACHO64_HEADER.unpack_from(data)
    )
    if (
        magic != MACHO64_MAGIC
        or cpu != MACHO_ARM64_CPU
        or filetype != 2
        or reserved != 0
        or not 1 <= commands <= 256
        or command_bytes < commands * 8
        or MACHO64_HEADER.size + command_bytes > len(data)
    ):
        raise ProofBuildError("Native identity probe Mach-O header is not exact.")
    offset = MACHO64_HEADER.size
    end = offset + command_bytes
    executable_text = False
    linkedit = False
    for _index in range(commands):
        if offset + 8 > end:
            raise ProofBuildError("Native identity probe load commands are truncated.")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 8 or offset + size > end:
            raise ProofBuildError("Native identity probe load command is malformed.")
        if command == 0x19:
            if size < 72:
                raise ProofBuildError("Native identity probe segment command is truncated.")
            (
                _cmd,
                _size,
                raw_name,
                _vmaddr,
                _vmsize,
                file_offset,
                file_size,
                _maximum,
                initial,
                _sections,
                _segment_flags,
            ) = struct.unpack_from("<II16sQQQQiiII", data, offset)
            if file_offset + file_size > len(data):
                raise ProofBuildError("Native identity probe segment escapes the file.")
            name = raw_name.split(b"\0", 1)[0]
            if name == b"__TEXT" and initial & 0x4 and file_size:
                executable_text = True
            if name == b"__LINKEDIT" and file_size:
                linkedit = True
        offset += size
    if offset != end or not executable_text or not linkedit:
        raise ProofBuildError("Native identity probe Mach-O structure is incomplete.")


def _power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _require_linux_amd64_elf(data: bytes, expected: Mapping[str, str]) -> None:
    """Validate the complete ELF layout plus every exact release identity witness."""

    if len(data) < ELF_HEADER.size:
        raise ProofBuildError("Proof artifact is not a complete ELF64 executable.")
    (
        ident,
        elf_type,
        machine,
        version,
        entry,
        program_offset,
        section_offset,
        _flags,
        header_size,
        program_size,
        program_count,
        section_size,
        section_count,
        string_index,
    ) = ELF_HEADER.unpack_from(data)
    if (
        ident[:7] != b"\x7fELF\x02\x01\x01"
        or ident[7] != 0
        or any(ident[8:])
        or elf_type != 2
        or machine != 62
        or version != 1
        or header_size != ELF_HEADER.size
        or program_size != ELF_PROGRAM_HEADER.size
        or section_size != ELF_SECTION_HEADER.size
        or not 1 <= program_count <= 256
        or not 2 <= section_count <= 4096
        or not 1 <= string_index < section_count
        or program_offset < header_size
        or program_offset + program_size * program_count > len(data)
        or section_offset < header_size
        or section_offset + section_size * section_count > len(data)
        or entry == 0
    ):
        raise ProofBuildError("Proof artifact ELF64 header is not exact Linux/amd64.")
    program_table = (program_offset, program_offset + program_size * program_count)
    section_table = (section_offset, section_offset + section_size * section_count)
    if max(program_table[0], section_table[0]) < min(
        program_table[1], section_table[1]
    ):
        raise ProofBuildError("Proof artifact ELF metadata tables overlap.")
    entry_is_executable = False
    load_count = 0
    load_segments: list[tuple[int, int, int, int, int]] = []
    for index in range(program_count):
        fields = ELF_PROGRAM_HEADER.unpack_from(
            data, program_offset + index * program_size
        )
        kind, flags, file_offset, virtual, _physical, file_size, memory_size, align = fields
        if file_size > memory_size or file_offset + file_size > len(data):
            raise ProofBuildError("Proof artifact ELF program segment is malformed.")
        if align not in (0, 1):
            if not _power_of_two(align) or file_offset % align != virtual % align:
                raise ProofBuildError("Proof artifact ELF segment alignment is invalid.")
        if kind == 1:
            load_count += 1
            load_segments.append((flags, file_offset, virtual, file_size, memory_size))
            if flags & 0x1 and virtual <= entry < virtual + file_size:
                entry_is_executable = True
        elif kind in {2, 3}:
            raise ProofBuildError("Proof artifact ELF is dynamically linked.")
    if load_count < 2 or not entry_is_executable:
        raise ProofBuildError("Proof artifact ELF entry point is not executable.")
    raw_sections = [
        ELF_SECTION_HEADER.unpack_from(data, section_offset + index * section_size)
        for index in range(section_count)
    ]
    if any(raw_sections[0]):
        raise ProofBuildError("Proof artifact ELF null section is malformed.")
    string_section = raw_sections[string_index]
    string_offset, string_size = string_section[4], string_section[5]
    if (
        string_section[1] != 3
        or not string_size
        or string_offset + string_size > len(data)
    ):
        raise ProofBuildError("Proof artifact ELF section-name table is malformed.")
    names_blob = data[string_offset : string_offset + string_size]
    if not names_blob.startswith(b"\0") or not names_blob.endswith(b"\0"):
        raise ProofBuildError("Proof artifact ELF section names are not terminated.")
    sections: dict[str, tuple[int, ...]] = {}
    occupied: list[tuple[int, int, str]] = []
    for index, section in enumerate(raw_sections):
        name_offset, kind, flags, _address, file_offset, size, _link, _info, align, _entry = section
        if name_offset >= len(names_blob):
            raise ProofBuildError("Proof artifact ELF section name escapes its table.")
        terminator = names_blob.find(b"\0", name_offset)
        if terminator < 0:
            raise ProofBuildError("Proof artifact ELF section name is unterminated.")
        try:
            name = names_blob[name_offset:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProofBuildError("Proof artifact ELF section name is not ASCII.") from exc
        if index and (not name or name in sections):
            raise ProofBuildError("Proof artifact ELF section inventory is ambiguous.")
        if kind != 8 and file_offset + size > len(data):
            raise ProofBuildError("Proof artifact ELF section escapes the file.")
        if section[6] >= section_count and section[6] != 0:
            raise ProofBuildError("Proof artifact ELF section link is invalid.")
        if align not in (0, 1) and not _power_of_two(align):
            raise ProofBuildError("Proof artifact ELF section alignment is invalid.")
        if kind in {2, 18}:
            raise ProofBuildError("Proof artifact carries a forbidden symbol table.")
        if (
            name.startswith((".debug", ".zdebug", ".stab"))
            or name in {".symtab", ".gnu_debugdata", ".gdb_index"}
        ):
            raise ProofBuildError("Proof artifact carries forbidden debug metadata.")
        if index and kind != 8 and size:
            for start, finish, other in occupied:
                if max(start, file_offset) < min(finish, file_offset + size):
                    raise ProofBuildError(
                        f"Proof artifact ELF sections overlap: {other} and {name}."
                    )
            occupied.append((file_offset, file_offset + size, name))
        if index and flags & 0x2 and kind != 8 and size:
            mapped = any(
                segment_offset <= file_offset
                and file_offset + size <= segment_offset + segment_file_size
                and virtual <= section[3]
                and section[3] + size <= virtual + memory_size
                and section[3] - virtual == file_offset - segment_offset
                for _segment_flags, segment_offset, virtual, segment_file_size, memory_size
                in load_segments
            )
            if not mapped:
                raise ProofBuildError(
                    f"Proof artifact allocated section is not load-mapped: {name}."
                )
        sections[name] = section
    for name in (".text", ".rodata", ".go.buildinfo", ".gopclntab", ".shstrtab"):
        if name not in sections or sections[name][5] <= 0:
            raise ProofBuildError(f"Proof artifact ELF omits required {name} section.")
    if sections[".text"][1] != 1 or not sections[".text"][2] & 0x4:
        raise ProofBuildError("Proof artifact ELF .text section is not executable code.")
    if sections[".go.buildinfo"][1] != 1:
        raise ProofBuildError("Proof artifact ELF Go build-info section is invalid.")
    buildinfo = sections[".go.buildinfo"]
    buildinfo_bytes = data[buildinfo[4] : buildinfo[4] + buildinfo[5]]
    if not buildinfo_bytes.startswith(b"\xff Go buildinf:"):
        raise ProofBuildError("Proof artifact Go build-info magic is not exact.")
    if ".note.go.buildid" in sections:
        raise ProofBuildError("Proof artifact unexpectedly carries a Go build ID.")
    if set(expected) != {name for name, _variable in IDENTITY_DEFINE_NAMES}:
        raise ProofBuildError("Proof artifact identity expectation is incomplete.")
    for key, value in expected.items():
        encoded = value.encode("ascii")
        if not encoded or encoded not in data:
            raise ProofBuildError(
                f"Proof artifact omits exact embedded release identity {key}."
            )


def _run_held_native_probe(
    path: pathlib.Path,
    expected_bytes: bytes,
    *,
    cwd: pathlib.Path,
    cwd_fd: int,
    env: Mapping[str, str],
) -> bytes:
    """Execute the exact descriptor-held native binary, never its pathname bytes."""

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(path.parent, directory_flags)
        parent_identity = _file_identity(os.fstat(parent_fd))
        named_before = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(path.name, file_flags, dir_fd=parent_fd)
        opened = os.fstat(descriptor)
        opened_identity = _file_identity(opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not stat.S_IMODE(opened.st_mode) & 0o111
            or _file_identity(opened) != _file_identity(named_before)
            or _read_descriptor(descriptor, len(expected_bytes), "Native identity probe")
            != expected_bytes
        ):
            raise ProofBuildError("Native identity probe executable changed before readback.")
        executable = f"/dev/fd/{descriptor}"
        with _scoped_process_state(cwd, cwd_fd, env):
            completed = subprocess.run(
                [executable, "--winsvpn-build-identity-readback"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=dict(env),
                close_fds=True,
                pass_fds=(descriptor,),
                timeout=60,
                check=False,
            )
        named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            completed.returncode != 0
            or completed.stderr
            or _file_identity(os.fstat(parent_fd)) != parent_identity
            or not (
                _file_identity(os.fstat(descriptor))
                == _file_identity(named_after)
                == opened_identity
            )
            or _read_descriptor(descriptor, len(expected_bytes), "Native identity probe")
            != expected_bytes
        ):
            detail = completed.stderr[:1000].decode("utf-8", errors="replace")
            raise ProofBuildError(f"Native identity probe execution failed: {detail}")
        return completed.stdout
    except ProofBuildError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProofBuildError("Native identity probe could not be executed safely.") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _write_exclusive_file(path: pathlib.Path, data: bytes, mode: int) -> None:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, mode)
    try:
        _write_all(descriptor, data)
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _containment_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
    )


def _ensure_repo_directory(repo: pathlib.Path, relative: str) -> None:
    """Create a non-sensitive container through held, non-symlink descriptors."""

    parts = _DescriptorRepoInputs._parts(relative)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptors: list[int] = []
    try:
        current = os.open(repo, flags)
        descriptors.append(current)
        for part in parts:
            try:
                nxt = os.open(part, flags, dir_fd=current)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=current)
                os.fsync(current)
                nxt = os.open(part, flags, dir_fd=current)
            opened = os.fstat(nxt)
            named = os.stat(part, dir_fd=current, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _file_identity(opened) != _file_identity(named)
                or opened.st_uid != os.getuid()
                or stat.S_IMODE(opened.st_mode) & 0o022
            ):
                os.close(nxt)
                raise ProofBuildError(
                    f"Proof private container is unsafe: {relative}."
                )
            descriptors.append(nxt)
            current = nxt
    except ProofBuildError:
        raise
    except OSError as exc:
        raise ProofBuildError(
            f"Proof private container cannot be prepared: {relative}."
        ) from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _open_mutable_directory_chain(
    root_fd: int, relative: str
) -> list[tuple[int, tuple[int, ...], int, str]]:
    parts = () if relative == "." else _DescriptorRepoInputs._parts(relative)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    chain: list[tuple[int, tuple[int, ...], int, str]] = []
    current = os.dup(root_fd)
    chain.append((current, _containment_identity(os.fstat(current)), -1, "."))
    try:
        for part in parts:
            parent_index = len(chain) - 1
            descriptor = os.open(part, flags, dir_fd=current)
            opened = os.fstat(descriptor)
            named = os.stat(part, dir_fd=current, follow_symlinks=False)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _containment_identity(opened) != _containment_identity(named)
            ):
                os.close(descriptor)
                raise ProofBuildError("Proof bundle parent changed while opened.")
            chain.append(
                (descriptor, _containment_identity(opened), parent_index, part)
            )
            current = descriptor
        return chain
    except BaseException:
        for descriptor, _identity, _parent, _name in reversed(chain):
            os.close(descriptor)
        raise


def _verify_mutable_directory_chain(
    chain: Sequence[tuple[int, tuple[int, ...], int, str]],
) -> None:
    for index, (descriptor, identity, parent_index, name) in enumerate(chain):
        opened = os.fstat(descriptor)
        if _containment_identity(opened) != identity:
            raise ProofBuildError("Proof bundle parent descriptor changed.")
        if index:
            named = os.stat(
                name, dir_fd=chain[parent_index][0], follow_symlinks=False
            )
            if _containment_identity(named) != identity:
                raise ProofBuildError("Proof bundle parent pathname changed.")


def _write_exclusive_at(
    parent_fd: int, name: str, data: bytes, mode: int
) -> tuple[int, tuple[int, ...]]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
    try:
        _write_all(descriptor, data)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        identity = _file_identity(os.fstat(descriptor))
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _file_identity(named) != identity:
            raise ProofBuildError("Proof bundle leaf changed while written.")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _rename_noreplace(
    source_fd: int,
    source_name: str,
    destination_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    encoded_source = os.fsencode(source_name)
    encoded_destination = os.fsencode(destination_name)
    if sys.platform == "darwin":
        renameatx = getattr(libc, "renameatx_np", None)
        if renameatx is None:
            raise ProofBuildError("Descriptor-relative no-replace publication is unavailable.")
        renameatx.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameatx.restype = ctypes.c_int
        result = renameatx(
            source_fd,
            encoded_source,
            destination_fd,
            encoded_destination,
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise ProofBuildError("Descriptor-relative no-replace publication is unavailable.")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_fd,
            encoded_source,
            destination_fd,
            encoded_destination,
            0x00000001,
        )
    else:
        raise ProofBuildError("Descriptor-relative no-replace publication is unavailable.")
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise ProofBuildError("Proof bundle destination already exists.")
        raise ProofBuildError(
            f"Descriptor-relative no-replace publication failed: errno {code}."
        )


def _publish_bundle(
    inputs: _DescriptorRepoInputs,
    bundle_relative: str,
    leaves: Sequence[tuple[str, bytes, int]],
) -> None:
    bundle = pathlib.PurePosixPath(bundle_relative)
    parent_relative = bundle.parent.as_posix()
    if parent_relative == ".":
        parent_relative = "."
    root_fd = inputs._directory_fds["."][0]
    chain = _open_mutable_directory_chain(root_fd, parent_relative)
    parent_fd = chain[-1][0]
    stage_name = f".gcp-proof-stage-{secrets.token_hex(16)}"
    stage_fd = -1
    published = False
    file_records: list[tuple[str, int, bytes, int, tuple[int, ...]]] = []
    try:
        _verify_mutable_directory_chain(chain)
        try:
            os.stat(bundle.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ProofBuildError("Proof bundle must be a new path.")
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_fd = os.open(
            stage_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_fd,
        )
        stage_identity = _containment_identity(os.fstat(stage_fd))
        if len(leaves) != 3 or len({name for name, _data, _mode in leaves}) != 3:
            raise ProofBuildError("Proof bundle inventory is not exact.")
        for name, data, mode in leaves:
            if (
                not name
                or pathlib.PurePosixPath(name).name != name
                or mode not in {0o444, 0o555}
                or not data
            ):
                raise ProofBuildError("Proof bundle leaf contract is invalid.")
            descriptor, identity = _write_exclusive_at(stage_fd, name, data, mode)
            file_records.append((name, descriptor, data, mode, identity))
        if {entry.name for entry in os.scandir(stage_fd)} != {
            name for name, _data, _mode in leaves
        }:
            raise ProofBuildError("Proof bundle staged inventory changed.")
        for name, descriptor, data, mode, identity in file_records:
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if (
                not (_file_identity(opened) == _file_identity(named) == identity)
                or stat.S_IMODE(opened.st_mode) != mode
                or opened.st_nlink != 1
                or _read_descriptor(descriptor, len(data), name) != data
            ):
                raise ProofBuildError("Proof bundle staged leaf changed.")
        os.fchmod(stage_fd, 0o500)
        stage_identity = _containment_identity(os.fstat(stage_fd))
        os.fsync(stage_fd)
        _verify_mutable_directory_chain(chain)
        inputs.verify()
        _rename_noreplace(parent_fd, stage_name, parent_fd, bundle.name)
        published = True
        os.fsync(parent_fd)
        named_bundle = os.stat(
            bundle.name, dir_fd=parent_fd, follow_symlinks=False
        )
        if _containment_identity(named_bundle) != stage_identity:
            raise ProofBuildError("Published proof bundle is not the held staging directory.")
        _verify_mutable_directory_chain(chain)
        inputs.verify()
        if {entry.name for entry in os.scandir(stage_fd)} != {
            name for name, _data, _mode in leaves
        }:
            raise ProofBuildError("Published proof bundle inventory changed.")
        for name, descriptor, data, mode, identity in file_records:
            opened = os.fstat(descriptor)
            named = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if (
                not (_file_identity(opened) == _file_identity(named) == identity)
                or stat.S_IMODE(opened.st_mode) != mode
                or _read_descriptor(descriptor, len(data), name) != data
            ):
                raise ProofBuildError("Published proof bundle leaf changed.")
    except OSError as exc:
        raise ProofBuildError("Proof bundle could not be published safely.") from exc
    finally:
        for _name, descriptor, _data, _mode, _identity in reversed(file_records):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not published and stage_fd >= 0:
            try:
                os.fchmod(stage_fd, 0o700)
            except OSError:
                pass
            for name, _data, _mode in reversed(leaves):
                try:
                    os.unlink(name, dir_fd=stage_fd)
                except OSError:
                    pass
        if stage_fd >= 0:
            try:
                os.close(stage_fd)
            except OSError:
                pass
        if not published:
            try:
                os.rmdir(stage_name, dir_fd=parent_fd)
            except OSError:
                pass
        for descriptor, _identity, _parent, _name in reversed(chain):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _stable_private_bytes(path: pathlib.Path, label: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
        ):
            raise ProofBuildError(f"{label} is not one stable private file.")
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            chunks: list[bytes] = []
            while block := os.read(descriptor, 1024 * 1024):
                chunks.append(block)
            finished = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except ProofBuildError:
        raise
    except OSError as exc:
        raise ProofBuildError(f"{label} is unreadable.") from exc
    if not (
        _file_identity(before)
        == _file_identity(opened)
        == _file_identity(finished)
        == _file_identity(after)
    ):
        raise ProofBuildError(f"{label} changed while it was read.")
    return b"".join(chunks)


def _snapshot_files(source: Mapping[str, bytes]) -> dict[str, bytes]:
    if set(source) != set(PACKAGE_COMPILER_INPUTS):
        raise ProofBuildError("Proof source snapshot input inventory is not exact.")
    result: dict[str, bytes] = {}
    for relative in PACKAGE_COMPILER_INPUTS:
        if (
            pathlib.PurePosixPath(relative).parent.as_posix() != PROOF_PACKAGE
            or not source[relative]
        ):
            raise ProofBuildError("Proof source snapshot input is invalid.")
        name = pathlib.PurePosixPath(relative).name
        if name in result:
            raise ProofBuildError("Proof source snapshot has a duplicate leaf name.")
        result[name] = source[relative]
    result[IDENTITY_PROBE_NAME] = IDENTITY_PROBE_BYTES
    return result


def _source_snapshot_id(source: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name, data in sorted(_snapshot_files(source).items()):
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(len(data)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _require_system_immutable_source(info: os.stat_result, label: str) -> None:
    if sys.platform != "darwin":
        raise ProofBuildError(f"{SOURCE_SNAPSHOT_BLOCKER}: {label}.")


def _require_trusted_source_ancestor(info: os.stat_result, label: str) -> None:
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ProofBuildError(f"{SOURCE_SNAPSHOT_BLOCKER}: writable ancestor {label}.")
    if info.st_uid != 0 or not SF_IMMUTABLE or not int(
        getattr(info, "st_flags", 0)
    ) & SF_IMMUTABLE:
        raise ProofBuildError(f"{SOURCE_SNAPSHOT_BLOCKER}: {label}.")


class _HeldSourceSnapshot:
    """Bind a separately provisioned root-owned immutable source snapshot."""

    def __init__(self, source: Mapping[str, bytes]) -> None:
        self._expected = _snapshot_files(source)
        self.path = SOURCE_SNAPSHOT_ROOT / _source_snapshot_id(source)
        self._directory_fd = -1
        self._ancestors: list[tuple[int, tuple[int, ...], int, str]] = []
        self._files: dict[str, tuple[int, bytes, tuple[int, ...]]] = {}
        try:
            directory_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            current = os.open(self.path.anchor, directory_flags)
            self._ancestors.append(
                (
                    current,
                    _containment_identity(os.fstat(current)),
                    -1,
                    self.path.anchor,
                )
            )
            for part in self.path.parts[1:]:
                parent_index = len(self._ancestors) - 1
                descriptor = os.open(part, directory_flags, dir_fd=current)
                opened = os.fstat(descriptor)
                named = os.stat(part, dir_fd=current, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _containment_identity(opened)
                    != _containment_identity(named)
                ):
                    os.close(descriptor)
                    raise ProofBuildError("Proof source snapshot ancestor changed.")
                if part == self.path.name:
                    _require_system_immutable_source(opened, "snapshot directory")
                    if stat.S_IMODE(opened.st_mode) & 0o222:
                        raise ProofBuildError("Proof source snapshot directory is writable.")
                else:
                    _require_trusted_source_ancestor(opened, part)
                self._ancestors.append(
                    (
                        descriptor,
                        _containment_identity(opened),
                        parent_index,
                        part,
                    )
                )
                current = descriptor
            self._directory_fd = current
            file_flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            for name, expected in sorted(self._expected.items()):
                named = os.stat(name, dir_fd=self._directory_fd, follow_symlinks=False)
                descriptor = os.open(name, file_flags, dir_fd=self._directory_fd)
                opened = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) & 0o222
                    or _file_identity(opened) != _file_identity(named)
                    or _read_descriptor(descriptor, len(expected), name) != expected
                ):
                    os.close(descriptor)
                    raise ProofBuildError(f"Proof source snapshot file is not exact: {name}.")
                _require_system_immutable_source(opened, name)
                self._files[name] = (
                    descriptor,
                    expected,
                    _file_identity(opened),
                )
            self.verify()
        except BaseException as exc:
            self.close()
            if isinstance(exc, ProofBuildError):
                raise
            raise ProofBuildError(SOURCE_SNAPSHOT_BLOCKER) from exc

    def verify(self) -> None:
        if self._directory_fd < 0:
            raise ProofBuildError("Held proof source directory is not bound.")
        try:
            for index, (descriptor, identity, parent_index, name) in enumerate(
                self._ancestors
            ):
                opened = os.fstat(descriptor)
                if _containment_identity(opened) != identity:
                    raise ProofBuildError("Proof source snapshot ancestor changed.")
                if index:
                    parent_fd = self._ancestors[parent_index][0]
                    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    if _containment_identity(named) != identity:
                        raise ProofBuildError(
                            "Proof source snapshot escaped its held parent."
                        )
            directory = os.fstat(self._directory_fd)
            _require_system_immutable_source(directory, "snapshot directory")
            if stat.S_IMODE(directory.st_mode) & 0o222:
                raise ProofBuildError("Proof source snapshot directory became writable.")
            observed = {entry.name for entry in os.scandir(self._directory_fd)}
            if observed != set(self._files):
                raise ProofBuildError("Held proof source inventory changed.")
            for name, (descriptor, expected, identity) in self._files.items():
                opened = os.fstat(descriptor)
                named = os.stat(
                    name, dir_fd=self._directory_fd, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) & 0o222
                    or not (
                        _file_identity(opened)
                        == _file_identity(named)
                        == identity
                    )
                    or _read_descriptor(descriptor, len(expected), name) != expected
                ):
                    raise ProofBuildError(f"Held proof source changed: {name}.")
                _require_system_immutable_source(opened, name)
        except ProofBuildError:
            raise
        except OSError as exc:
            raise ProofBuildError("Held proof source could not be revalidated.") from exc

    @property
    def directory_fd(self) -> int:
        if self._directory_fd < 0:
            raise ProofBuildError("Held proof source directory is not bound.")
        return self._directory_fd

    def close(self) -> None:
        for descriptor, _expected, _identity in getattr(self, "_files", {}).values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        if hasattr(self, "_files"):
            self._files.clear()
        for descriptor, _identity, _parent, _name in reversed(
            getattr(self, "_ancestors", [])
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if hasattr(self, "_ancestors"):
            self._ancestors.clear()
        self._directory_fd = -1

    def __enter__(self) -> "_HeldSourceSnapshot":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@contextlib.contextmanager
def _scoped_process_state(
    cwd: pathlib.Path,
    cwd_fd: int,
    environment: Mapping[str, str],
) -> Iterator[None]:
    previous_cwd_fd = os.open(
        ".",
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    previous_environment = dict(os.environ)
    try:
        opened = os.fstat(cwd_fd)
        if not stat.S_ISDIR(opened.st_mode):
            raise ProofBuildError("Held proof source descriptor is not a directory.")
        os.environ.clear()
        os.environ.update(environment)
        os.fchdir(cwd_fd)
        entered = os.stat(".")
        if _file_identity(opened) != _file_identity(entered):
            raise ProofBuildError(
                f"Held proof source descriptor did not bind the requested cwd {cwd}."
            )
        yield
    finally:
        try:
            os.fchdir(previous_cwd_fd)
        finally:
            os.close(previous_cwd_fd)
            os.environ.clear()
            os.environ.update(previous_environment)


class _OwnedGoRuntime:
    """Execute only through the reviewed root-owned immutable Go custody."""

    def __init__(
        self,
        repo: pathlib.Path,
        target: Mapping[str, Any],
        expected: Mapping[str, Any],
    ) -> None:
        self.repo = repo
        self.target = canonical_target(target)
        self.expected = dict(expected)
        self.runtime: pathlib.Path | None = None
        self.runtime_id = ""
        try:
            if target_value(self.target) != "darwin/arm64":
                raise ProofBuildError(
                    f"{OWNER_BLOCKED_GO} for {target_value(self.target)}; the reviewed "
                    "root-owned custody currently covers darwin/arm64 only."
                )
            authorized = go_custody.authorize_repo(repo)
            issuance = go_custody._bind_external_issuance(repo)
            pin = go_custody.parse_pin_bytes(authorized[2])
            owner = go_custody.verify_owner_runtime(
                repo, pin, authorized, issuance
            )
            expected_owner = {
                "BINARY_SHA256": expected["executable_sha256"],
                "TREE_SHA256": expected["install_tree_sha256"],
            }
            for key, value in expected_owner.items():
                if owner.get(key) != value:
                    raise ProofBuildError(
                        f"{OWNER_BLOCKED_GO}: owner runtime {key} does not match the pin."
                    )
            state = go_custody._create_private_execution_state()
            self.runtime = pathlib.Path(state["RUNTIME"])
            self.runtime_id = state["RUNTIME_ID"]
            self.root = pathlib.Path(owner["ROOT"])
            self.binary = pathlib.Path(owner["BINARY"])
            self.binary_sha256 = owner["BINARY_SHA256"]
            self.tree_sha256 = owner["TREE_SHA256"]
            go_custody.check_go_identity(
                self.binary,
                self.runtime,
                self.root,
                str(expected["version"]),
                self.target["goarch"],
                self.binary_sha256,
                self.tree_sha256,
            )
            self.verify()
        except ProofBuildError:
            self.close()
            raise
        except (go_custody.Refused, OSError, KeyError, subprocess.SubprocessError) as exc:
            self.close()
            raise ProofBuildError(f"{OWNER_BLOCKED_GO}: {exc}") from exc

    def _verification_arguments(self) -> list[str]:
        if self.runtime is None:
            raise ProofBuildError(f"{OWNER_BLOCKED_GO}: runtime is not prepared.")
        return [
            str(self.runtime),
            self.runtime_id,
            str(self.root),
            self.tree_sha256,
            str(self.binary),
            self.binary_sha256,
            str(self.repo),
            str(self.repo / PIN_PATH),
        ]

    def verify(self) -> None:
        try:
            go_custody.verify_runtime(self._verification_arguments())
        except (go_custody.Refused, OSError, KeyError, subprocess.SubprocessError) as exc:
            raise ProofBuildError(f"{OWNER_BLOCKED_GO}: {exc}") from exc

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: pathlib.Path,
        cwd_fd: int,
        env: Mapping[str, str],
    ) -> bytes:
        if self.runtime is None:
            raise ProofBuildError(f"{OWNER_BLOCKED_GO}: runtime is not prepared.")
        forwarded = {
            key: value
            for key, value in env.items()
            if key not in {"GOENV", "GOTOOLCHAIN"}
        }
        try:
            with _scoped_process_state(cwd, cwd_fd, forwarded):
                completed = go_custody._run_go(
                    self.binary,
                    self.runtime,
                    self.root,
                    self.binary_sha256,
                    [str(value) for value in arguments],
                    timeout=300,
                    capture=True,
                    expected_tree=self.tree_sha256,
                )
        except (go_custody.Refused, OSError, subprocess.SubprocessError) as exc:
            raise ProofBuildError(f"Proof build command execution failed: {exc}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip()
            raise ProofBuildError(
                f"Proof build command exited {completed.returncode}: {detail[:1000]}"
            )
        return completed.stdout.encode("utf-8")

    def close(self) -> None:
        if self.runtime is None:
            return
        runtime = self.runtime
        runtime_id = self.runtime_id
        self.runtime = None
        try:
            go_custody.cleanup(str(runtime), runtime_id)
        except (go_custody.Refused, OSError) as exc:
            raise ProofBuildError(
                f"Reviewed Go private-state cleanup failed: {exc}"
            ) from exc

    def __enter__(self) -> "_OwnedGoRuntime":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _open_reviewed_go(
    repo: pathlib.Path,
    target: Mapping[str, Any],
    expected: Mapping[str, Any],
) -> _OwnedGoRuntime:
    return _OwnedGoRuntime(repo, target, expected)


def build(
    repo_root: pathlib.Path,
    release_input_index: pathlib.Path,
    output: pathlib.Path,
    receipt: pathlib.Path,
    *,
    goos: str,
    goarch: str,
) -> dict[str, Any]:
    selected = explicit_target(goos, goarch)
    if selected != RELEASE_TARGET:
        raise ProofBuildError("Proof release build target must be exact linux/amd64.")
    builder_host = require_reviewed_builder_host()
    repo = _canonical_repo(repo_root)
    output = _repo_path(repo, output, "Proof executable output", must_exist=False)
    require_labeled_artifact_path(output, selected, "Proof executable output")
    receipt = _repo_path(repo, receipt, "Proof build receipt", must_exist=False)
    artifact_name = labeled_artifact_name(selected)
    if (
        output.parent != receipt.parent
        or output.parent.name != artifact_name + BUNDLE_SUFFIX
        or receipt.name != artifact_name + ".receipt.json"
    ):
        raise ProofBuildError(
            "Proof output and receipt must be exact leaves of one new labeled .bundle."
        )
    anchor = receipt.with_name(receipt.name + ".sha256")
    if output.parent.exists() or output.parent.is_symlink():
        raise ProofBuildError("Proof bundle must be a new path.")
    index = _repo_path(
        repo, release_input_index, "Release input index", must_exist=True
    )
    index_relative = index.relative_to(repo).as_posix()
    scratch_relative = ".artifacts/gcp-proof-client-scratch"
    bundle_parent_relative = output.parent.parent.relative_to(repo).as_posix()
    _ensure_repo_directory(repo, scratch_relative)
    if bundle_parent_relative != ".":
        _ensure_repo_directory(repo, bundle_parent_relative)
    build_root = repo / scratch_relative
    held_paths = (*SOURCE_PATHS, BUILDER_PATH, PIN_PATH, index_relative)
    with _DescriptorRepoInputs(repo, held_paths) as inputs:
        provenance = _expected_provenance(repo, index, selected, inputs)
        if provenance["target"] != selected:
            raise ProofBuildError(
                "Proof build provenance target drifted from the explicit target."
            )
        compiler_source = _compiler_input_bytes(repo, inputs)
        recorded_compiler_inputs = {
            item["path"]: (item["bytes"], item["sha256"])
            for item in provenance["source"]["compiler_inputs"]
        }
        measured_compiler_inputs = {
            relative: (len(data), sha256_bytes(data))
            for relative, data in compiler_source.items()
        }
        if recorded_compiler_inputs != measured_compiler_inputs:
            raise ProofBuildError(
                "Proof compiler-input bytes differ from the held provenance."
            )
        environment = dict(provenance["build_contract"]["environment"])
        test_environment = dict(provenance["build_contract"]["test_environment"])
        if environment != {
            "CGO_ENABLED": "0",
            "GOARCH": "amd64",
            "GOAMD64": "v1",
            "GOENV": "off",
            "GOFIPS140": "off",
            "GOOS": "linux",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        }:
            raise ProofBuildError("Proof build environment is not exact linux/amd64.")
        if test_environment != {
            "CGO_ENABLED": "0",
            "GOARCH": "arm64",
            "GOARM64": "v8.0",
            "GOENV": "off",
            "GOFIPS140": "off",
            "GOOS": "darwin",
            "GOPROXY": "off",
            "GOSUMDB": "off",
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
        } or provenance["toolchain"].get("platform") != target_value(builder_host):
            raise ProofBuildError("Proof native environment is not exact darwin/arm64.")
        with (
            _HeldSourceSnapshot(compiler_source) as source_snapshot,
            _open_reviewed_go(
                repo, builder_host, provenance["toolchain"]
            ) as reviewed_go,
            tempfile.TemporaryDirectory(prefix="test-", dir=build_root) as test_root,
            tempfile.TemporaryDirectory(prefix="native-", dir=build_root) as native_root,
            tempfile.TemporaryDirectory(prefix="build-a-", dir=build_root) as first,
            tempfile.TemporaryDirectory(prefix="build-b-", dir=build_root) as second,
        ):
            reviewed_go.verify()
            version_output = reviewed_go.run(
                ["version"],
                cwd=source_snapshot.path,
                cwd_fd=source_snapshot.directory_fd,
                env=test_environment,
            )
            expected_version = f"go{provenance['toolchain']['version']}"
            expected_platform = target_value(builder_host)
            match = re.fullmatch(
                rb"go version (go[0-9]+\.[0-9]+\.[0-9]+) ([a-z0-9]+/[a-z0-9]+)\n?",
                version_output,
            )
            if (
                match is None
                or match.group(1).decode("ascii") != expected_version
                or match.group(2).decode("ascii") != expected_platform
            ):
                raise ProofBuildError(
                    f"Proof release build requires exact {expected_version} "
                    f"{expected_platform}."
                )
            source_snapshot.verify()
            inputs.verify()
            reviewed_go.verify()

            test_cache = pathlib.Path(test_root) / "gocache"
            test_cache.mkdir(mode=0o700)
            current_test_environment = dict(test_environment)
            current_test_environment["GOCACHE"] = str(test_cache)
            reviewed_go.run(
                ["test", "-trimpath", "-buildvcs=false", "-mod=readonly", "."],
                cwd=source_snapshot.path,
                cwd_fd=source_snapshot.directory_fd,
                env=current_test_environment,
            )
            source_snapshot.verify()
            inputs.verify()
            reviewed_go.verify()

            native_cache = pathlib.Path(native_root) / "gocache"
            native_cache.mkdir(mode=0o700)
            native_environment = dict(test_environment)
            native_environment["GOCACHE"] = str(native_cache)
            native_binary = pathlib.Path(native_root) / "proof-identity.test"
            exact_ldflags = _ldflags(provenance["defines"])
            reviewed_go.run(
                [
                    "test",
                    "-c",
                    "-trimpath",
                    "-buildvcs=false",
                    "-mod=readonly",
                    "-ldflags=" + exact_ldflags,
                    "-o",
                    str(native_binary),
                    ".",
                ],
                cwd=source_snapshot.path,
                cwd_fd=source_snapshot.directory_fd,
                env=native_environment,
            )
            native_bytes = _stable_private_bytes(
                native_binary, "Native proof identity probe"
            )
            _require_native_probe_macho(native_bytes)
            native_metadata = reviewed_go.run(
                ["version", "-m", "-json", str(native_binary)],
                cwd=source_snapshot.path,
                cwd_fd=source_snapshot.directory_fd,
                env=native_environment,
            )
            _require_artifact_metadata(
                native_metadata, builder_host, expected_version
            )
            native_output = _run_held_native_probe(
                native_binary,
                native_bytes,
                cwd=source_snapshot.path,
                cwd_fd=source_snapshot.directory_fd,
                env=native_environment,
            )
            _parse_native_identity(native_output, provenance["defines"])
            source_snapshot.verify()
            inputs.verify()
            reviewed_go.verify()

            binaries: list[pathlib.Path] = []
            artifact_bytes: list[bytes] = []
            metadata_bytes: list[bytes] = []
            for ordinal, scratch_text in enumerate((first, second), start=1):
                scratch = pathlib.Path(scratch_text)
                cache = scratch / "gocache"
                cache.mkdir(mode=0o700)
                current_env = dict(environment)
                current_env["GOCACHE"] = str(cache)
                artifact = scratch / artifact_name
                reviewed_go.run(
                    [
                        *BUILD_FLAGS,
                        "-ldflags=" + exact_ldflags,
                        "-o",
                        str(artifact),
                        ".",
                    ],
                    cwd=source_snapshot.path,
                    cwd_fd=source_snapshot.directory_fd,
                    env=current_env,
                )
                data = _stable_private_bytes(
                    artifact, f"Proof artifact build {ordinal}"
                )
                _require_linux_amd64_elf(data, provenance["defines"])
                metadata = reviewed_go.run(
                    ["version", "-m", "-json", str(artifact)],
                    cwd=source_snapshot.path,
                    cwd_fd=source_snapshot.directory_fd,
                    env=current_env,
                )
                _require_artifact_metadata(metadata, selected, expected_version)
                binaries.append(artifact)
                artifact_bytes.append(data)
                metadata_bytes.append(metadata)
                source_snapshot.verify()
                inputs.verify()
                reviewed_go.verify()
            if artifact_bytes[0] != artifact_bytes[1]:
                raise ProofBuildError(
                    "Proof client is not byte-reproducible across scratch paths."
                )
            if metadata_bytes[0] != metadata_bytes[1]:
                raise ProofBuildError(
                    "Proof artifact metadata is not reproducible across scratch paths."
                )
            first_bytes = artifact_bytes[0]
            source_snapshot.verify()
            inputs.verify()
            reviewed_go.verify()

            receipt_record = {
                "artifact": {
                    "bytes": len(first_bytes),
                    "mode": "0555",
                    "path": output.relative_to(repo).as_posix(),
                    "sha256": sha256_bytes(first_bytes),
                },
                "build_contract": provenance["build_contract"],
                "build_identity": provenance["build_identity"],
                "builder": provenance["builder"],
                "contract": RECEIPT_CONTRACT,
                "defines": provenance["defines"],
                "publication_authorized": False,
                "release": provenance["release"],
                "release_input_index": provenance["release_input_index"],
                "schema_version": SCHEMA_VERSION,
                "shared_revision": provenance["shared_revision"],
                "source": provenance["source"],
                "target": provenance["target"],
                "toolchain": provenance["toolchain"],
                "toolchain_pin_manifest": provenance["toolchain_pin_manifest"],
            }
            receipt_bytes = canonical_bytes(receipt_record)
            anchor_bytes = (
                f"{sha256_bytes(receipt_bytes)}  {receipt.name}\n".encode("ascii")
            )
            _publish_bundle(
                inputs,
                output.parent.relative_to(repo).as_posix(),
                (
                    (output.name, first_bytes, 0o555),
                    (receipt.name, receipt_bytes, 0o444),
                    (anchor.name, anchor_bytes, 0o444),
                ),
            )
            source_snapshot.verify()
            inputs.verify()
            reviewed_go.verify()
            return receipt_record


class _NoColorHelpFormatter(argparse.HelpFormatter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if sys.version_info >= (3, 14):
            kwargs["color"] = False
        super().__init__(*args, **kwargs)


def parser() -> argparse.ArgumentParser:
    options: dict[str, Any] = {
        "description": __doc__,
        "formatter_class": _NoColorHelpFormatter,
    }
    if sys.version_info >= (3, 14):
        options["color"] = False
    result = argparse.ArgumentParser(**options)
    result.add_argument("--repo-root", required=True, type=pathlib.Path)
    result.add_argument("--release-input-index", required=True, type=pathlib.Path)
    result.add_argument("--output", required=True, type=pathlib.Path)
    result.add_argument("--receipt", required=True, type=pathlib.Path)
    result.add_argument("--goos", required=True)
    result.add_argument("--goarch", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        result = build(
            args.repo_root,
            args.release_input_index,
            args.output,
            args.receipt,
            goos=args.goos,
            goarch=args.goarch,
        )
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except ProofBuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
