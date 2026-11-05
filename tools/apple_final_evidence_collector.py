#!/usr/bin/env python3
"""Compile trusted Apple machine observations into hash-bound release evidence.

This collector deliberately does not accept a pass transcript.  A physical
Apple UI harness must implement the fixed Driver protocol and return one exact,
redacted observation per action.  The collector owns receipt creation, route
coverage, producer binding, and the final bundle.  Production wrappers must
bind the harness source into their producer closure before using it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Callable
from typing import Any, Protocol

from public_release_live_smoke_common import (
    build_receipt_binding,
    producer_contract_hash,
    release_input_binding,
)
from apple_cross_store_artifact_gate import (
    AppleArtifactGateError,
    held_reviewed_watch_verifier_source,
    verify_signature,
    verify_watch_artifact_snapshot,
)
import apple_watch_artifact_verifier as watch_artifact_schema
import verify_ios_release_artifact as ios_release_verifier


CONTRACT = "winsvpn-apple-final-evidence-driver-v1"
MACHINE_CONTRACT = "winsvpn-linux-apple-release-machine-evidence-v1"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
INVALID_OBSERVATION_DIGESTS = {EMPTY_SHA256, "0" * 64}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
APPLE_SPLIT_SCOPE = "destination-consumer-mdm-per-app-only"
INSTALLED_DRIVER = pathlib.Path("/usr/local/libexec/winsvpn-apple-release-ui-driver.py")
INSTALLED_MAP_OBSERVER = pathlib.Path("/usr/local/libexec/winsvpn-apple-map-observer")
INSTALLED_ROUTE_CONTROLLER = pathlib.Path("/usr/local/libexec/winsvpn-apple-route-controller.py")
INSTALLED_MANIFEST = pathlib.Path("/usr/local/libexec/winsvpn-apple-release-tools.json")
APPLE_PUBLIC_PRODUCER = "tools/apple_public_release_live_smoke.sh"
OWNER_AUTHORIZATION_CONTRACT = "winsvpn-apple-owner-authorization-v2"
CANONICAL_RELEASE = "1.0.17+34"
CANONICAL_APP_VERSION = "1.0.17"
CANONICAL_BUILD_NUMBER = "34"
NO_CURRENT_CANDIDATE = "no_current_candidate"
COMPLETE_LOCAL_CANDIDATES = "complete_local_candidates"
HOST_BUNDLE_ID = "org.winsvpn.app"
PACKET_TUNNEL_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
WATCH_EXECUTABLE = "WinsWatch"
IOS_RELEASE_VERIFICATION_CONTRACT = "winsvpn-ios-release-final-evidence-v1"
IOS_RELEASE_VERIFICATION_SCHEMA_VERSION = 1
PROCESS_TIMEOUT_SECONDS = 600
PROCESS_OUTPUT_LIMIT_BYTES = 1024 * 1024
XCODE_DEVELOPER_DIR = pathlib.Path("/Applications/Xcode.app/Contents/Developer")
TOOLS_ROOT = pathlib.Path(__file__).resolve().parent
IOS_RELEASE_VERIFIER_PATH = TOOLS_ROOT / "verify_ios_release_artifact.py"
WATCH_ARTIFACT_VERIFIER_PATH = TOOLS_ROOT / "apple_watch_artifact_verifier.py"
WATCH_ARTIFACT_VERIFIER_SHA256 = (
    "9282c14eb209d3639ba6f50f6d884e6ea809ec62ad04dacdd4225343637baeb2"
)
REQUIRED_OWNER_SURFACES = ("ios", "embedded_watchos_companion", "macos")
REQUIRED_MACOS_ARCHITECTURES = ("arm64", "x86_64")
STALE_BUILD_29_SHA256 = frozenset(
    {
        "1f92c7e291f68ebbdc93586f8db49157fb35067971c3da569af9095cbd81d4a9",
        "b4c4ce430c61931306b3d151d4a19809285fa28266b38f233cdab48d90d46eec",
        "41acc41a2f2d767e3dd09d569ab6f933a20499e94cba5536b7246c13b3ed3ca4",
        "944adac41b0f786fe356367f2892ae2c43ab55f5332a302289481adf38135e51",
    }
)
OWNER_EVIDENCE_SET_KEYS = (
    "contract",
    "release",
    "app_version",
    "build_number",
    "required_surfaces",
    "release_input_index_sha256",
    "ios_artifact_sha256",
    "ios_artifact_size_bytes",
    "ios_bundle_id",
    "ios_packet_tunnel_bundle_id",
    "watch_bundle_id",
    "watch_companion_bundle_id",
    "watch_version",
    "watch_build",
    "watch_executable",
    "watch_executable_sha256",
    "watch_privacy_info_sha256",
    "macos_artifact_sha256",
    "macos_artifact_size_bytes",
    "macos_bundle_id",
    "macos_packet_tunnel_bundle_id",
    "macos_architecture_inventory",
    "runtime_evidence_sha256",
    "watch_companion_smoke_sha256",
    "archive_privacy_inventory_sha256",
    "app_store_privacy_snapshot_sha256",
    "final_receipt_sha256",
)
WATCH_COMPANION_IDENTITY_KEYS = (
    "bundle_id",
    "companion_bundle_id",
    "version",
    "build",
    "executable",
    "executable_sha256",
    "privacy_info_sha256",
)
OWNER_SIGNED_TARGET_IDS = {
    "ios": "ios-app-store-ipa",
    "macos": "macos-app-store-pkg",
}
MAX_IPA_MEMBERS = 200_000
MAX_IPA_MEMBER_BYTES = 4 * 1024**3
MAX_IPA_EXPANDED_BYTES = 16 * 1024**3
IOS_RELEASE_VERIFICATION_KEYS = {
    "schema_version",
    "contract",
    "artifact_contract",
    "verifier_source_sha256",
    "ipa_sha256",
    "ipa_bytes",
    "xcarchive_inventory_sha256",
    "obfuscation_receipt_sha256",
    "symbol_custody_receipt_sha256",
    "host_version",
    "host_build_number",
    "watch_artifact_verification",
    "watch_profile_verified",
    "watch_signature_verified",
    "watch_distribution_identity_verified",
    "watch_platform",
    "watch_minimum_os",
    "watch_uuids",
    "watch_uuid_parity_verified",
    "watch_dsym_coverage_verified",
}

IOSReleaseEvidenceVerifier = Callable[
    [pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path], dict[str, Any]
]


class CollectorError(RuntimeError):
    pass


def _require_authoritative_verifier_origins() -> None:
    origins = (
        (ios_release_verifier, IOS_RELEASE_VERIFIER_PATH, "iOS release verifier"),
        (watch_artifact_schema, WATCH_ARTIFACT_VERIFIER_PATH, "Watch artifact verifier"),
    )
    for module, expected, label in origins:
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str) or pathlib.Path(origin).resolve() != expected:
            raise CollectorError(f"{label} module origin is not authoritative")
        info = expected.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CollectorError(f"{label} source identity is unsafe")


class Driver(Protocol):
    def call(self, action: str, **values: str) -> dict[str, Any]: ...


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except Exception:
        pass


def _bounded_command(
    command: list[str],
    *,
    label: str,
    pass_fds: tuple[int, ...] = (),
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not command
        or any(type(item) is not str or not item for item in command)
        or type(timeout) is not int
        or timeout <= 0
    ):
        raise CollectorError(f"{label} process contract is invalid")
    process: subprocess.Popen[bytes] | None = None
    streams: dict[int, tuple[object, bytearray, str]] = {}
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            command,
            cwd="/",
            env=dict(env or {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            shell=False,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
        )
        for stream, stream_label in (
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ):
            assert stream is not None
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            streams[descriptor] = (stream, captured[stream_label], stream_label)
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CollectorError(f"{label} exceeded the time bound")
            readable, _writable, _exceptional = select.select(
                list(streams), [], [], min(0.1, remaining)
            )
            for descriptor in readable:
                stream, payload, stream_label = streams[descriptor]
                try:
                    chunk = os.read(
                        descriptor,
                        min(65536, PROCESS_OUTPUT_LIMIT_BYTES + 1 - len(payload)),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                payload.extend(chunk)
                if len(payload) > PROCESS_OUTPUT_LIMIT_BYTES:
                    raise CollectorError(
                        f"{label} exceeded the {stream_label} output bound"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CollectorError(f"{label} exceeded the time bound")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise CollectorError(f"{label} exceeded the time bound") from exc
        return subprocess.CompletedProcess(
            command,
            returncode,
            bytes(captured["stdout"]),
            bytes(captured["stderr"]),
        )
    except CollectorError:
        if process is not None:
            _kill_process_group(process)
        raise
    except OSError as exc:
        if process is not None:
            _kill_process_group(process)
        raise CollectorError(f"{label} could not execute") from exc
    finally:
        if process is not None:
            _kill_process_group(process)
        for stream, _payload, _stream_label in list(streams.values()):
            try:
                stream.close()
            except OSError:
                pass


class SubprocessDriver:
    def __init__(self, executable: pathlib.Path) -> None:
        self.executable = executable

    def call(self, action: str, **values: str) -> dict[str, Any]:
        command = [str(self.executable), action]
        for key, value in values.items():
            command.extend([f"--{key.replace('_', '-')}", str(value)])
        pass_fds: tuple[int, ...] = ()
        artifact = values.get("artifact")
        if isinstance(artifact, str):
            artifact_path = pathlib.Path(artifact)
            if (
                artifact_path.parent.as_posix() in {"/dev/fd", "/proc/self/fd"}
                and artifact_path.name.isdigit()
            ):
                pass_fds = (int(artifact_path.name),)
        completed = _bounded_command(
            command,
            label="Apple physical evidence driver",
            pass_fds=pass_fds,
        )
        try:
            output = completed.stdout.decode("utf-8", "strict")
            failure = completed.stderr.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CollectorError("Apple physical driver returned invalid UTF-8") from exc
        if completed.returncode != 0:
            summary = (failure or output).strip().splitlines()[-1:] or ["driver failed"]
            raise CollectorError(f"Apple physical driver failed: {summary[0][:300]}")
        try:
            value = json.loads(output)
        except json.JSONDecodeError as exc:
            raise CollectorError("Apple physical driver did not return one JSON object") from exc
        if not isinstance(value, dict):
            raise CollectorError("Apple physical driver did not return one JSON object")
        return value


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_regular_file_binding(path: pathlib.Path, label: str) -> tuple[int, str]:
    path = reject_link_components(path, label, must_exist=True)
    descriptor = -1
    try:
        descriptor = os.open(path, _open_nofollow_flags())
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
        ):
            raise CollectorError(f"{label} must be one non-empty single-link file")
        digest = hashlib.sha256()
        remaining = before.st_size
        offset = 0
        while remaining:
            block = os.pread(
                descriptor, min(1024 * 1024, remaining), offset
            )
            if not block:
                raise CollectorError(f"{label} changed while it was read")
            digest.update(block)
            offset += len(block)
            remaining -= len(block)
        if os.pread(descriptor, 1, offset):
            raise CollectorError(f"{label} grew while it was read")
        after = os.fstat(descriptor)
        if (
            path.parent.as_posix() in {"/dev/fd", "/proc/self/fd"}
            and path.name.isdigit()
        ):
            named = after
        else:
            named = path.lstat()
        stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable) or any(
            getattr(before, field) != getattr(named, field) for field in stable
        ):
            raise CollectorError(f"{label} was substituted while it was read")
        return before.st_size, digest.hexdigest()
    except OSError as exc:
        raise CollectorError(f"{label} could not be bound") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def xcarchive_inventory_sha256(archive: pathlib.Path) -> str:
    archive = reject_directory_components(archive, "iOS xcarchive")
    info = archive.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise CollectorError("iOS xcarchive must be one non-symlink directory")
    records: list[dict[str, object]] = []
    for path in sorted(archive.rglob("*")):
        relative = path.relative_to(archive).as_posix()
        item = path.lstat()
        if stat.S_ISLNK(item.st_mode) or is_reparse_point(item):
            raise CollectorError("iOS xcarchive contains a link or reparse point")
        if stat.S_ISDIR(item.st_mode):
            records.append({"path": relative, "type": "directory"})
            continue
        if not stat.S_ISREG(item.st_mode):
            raise CollectorError("iOS xcarchive contains a special filesystem object")
        size, digest = _stable_regular_file_binding(path, f"iOS xcarchive file {relative}")
        records.append(
            {"path": relative, "type": "file", "size": size, "sha256": digest}
        )
    if not any(record["type"] == "file" for record in records):
        raise CollectorError("iOS xcarchive contains no files")
    encoded = json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _ios_release_input_bindings(
    ipa: pathlib.Path,
    archive: pathlib.Path,
    obfuscation_receipt: pathlib.Path,
    symbol_custody_receipt: pathlib.Path,
) -> dict[str, object]:
    ipa_size, ipa_sha256 = _stable_regular_file_binding(ipa, "held iOS IPA")
    _, obfuscation_sha256 = _stable_regular_file_binding(
        obfuscation_receipt, "iOS obfuscation receipt"
    )
    _, symbol_sha256 = _stable_regular_file_binding(
        symbol_custody_receipt, "iOS symbol-custody receipt"
    )
    return {
        "ipa_sha256": ipa_sha256,
        "ipa_bytes": ipa_size,
        "xcarchive_inventory_sha256": xcarchive_inventory_sha256(archive),
        "obfuscation_receipt_sha256": obfuscation_sha256,
        "symbol_custody_receipt_sha256": symbol_sha256,
    }


def _verify_watch_release_snapshot(
    ipa: pathlib.Path, *, artifact_sha256: str, artifact_size: int
) -> dict[str, object]:
    with held_reviewed_watch_verifier_source(
        expected_sha256=WATCH_ARTIFACT_VERIFIER_SHA256
    ) as watch_verifier_source:
        return verify_watch_artifact_snapshot(
            ipa,
            artifact_sha256=artifact_sha256,
            artifact_size=artifact_size,
            verifier_source=watch_verifier_source,
            expected_verifier_sha256=WATCH_ARTIFACT_VERIFIER_SHA256,
        )


class _AuthenticatedXcodeSelection:
    def __init__(self) -> None:
        self._records: list[tuple[int | None, str, int, tuple[int, ...]]] = []
        self._watch: object | None = None
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            current = os.open(os.sep, flags)
            self._records.append(
                (None, "", current, _retained_directory_identity(os.fstat(current)))
            )
            for component in XCODE_DEVELOPER_DIR.parts[1:]:
                child = os.open(component, flags, dir_fd=current)
                self._records.append(
                    (
                        current,
                        component,
                        child,
                        _retained_directory_identity(os.fstat(child)),
                    )
                )
                current = child
            self.descriptor = current
            if hasattr(select, "kqueue"):
                watch = select.kqueue()
                flags_value = (
                    getattr(select, "KQ_NOTE_DELETE", 0)
                    | getattr(select, "KQ_NOTE_RENAME", 0)
                    | getattr(select, "KQ_NOTE_REVOKE", 0)
                    | getattr(select, "KQ_NOTE_ATTRIB", 0)
                    | getattr(select, "KQ_NOTE_WRITE", 0)
                )
                watch.control(
                    [
                        select.kevent(
                            descriptor,
                            filter=select.KQ_FILTER_VNODE,
                            flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                            fflags=flags_value,
                        )
                        for _parent, _name, descriptor, _identity in self._records
                    ],
                    0,
                    0,
                )
                self._watch = watch
            self.verify()
        except Exception:
            self.close()
            raise

    @property
    def descriptor_path(self) -> str:
        root = "/dev/fd" if sys.platform == "darwin" else "/proc/self/fd"
        return f"{root}/{self.descriptor}"

    def verify(self) -> None:
        if not self._records:
            raise CollectorError("authenticated Xcode custody is closed")
        if self._watch is not None and self._watch.control(
            None, max(1, len(self._records) * 2), 0
        ):
            raise CollectorError("authenticated Xcode selection changed")
        for parent_fd, name, descriptor, expected in self._records:
            if _retained_directory_identity(os.fstat(descriptor)) != expected:
                raise CollectorError("authenticated Xcode directory identity changed")
            if parent_fd is not None:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _retained_directory_identity(named) != expected:
                    raise CollectorError("authenticated Xcode directory was substituted")

    def close(self) -> None:
        if self._watch is not None:
            try:
                self._watch.close()
            except OSError:
                pass
            self._watch = None
        for _parent, _name, descriptor, _identity in reversed(self._records):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._records.clear()

    def __enter__(self) -> "_AuthenticatedXcodeSelection":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()


def _authenticate_fixed_apple_tools() -> None:
    for path in (
        pathlib.Path("/usr/bin/codesign"),
        pathlib.Path("/usr/bin/security"),
        pathlib.Path("/usr/bin/xcrun"),
    ):
        try:
            named = path.lstat()
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise CollectorError(f"OWNER-BLOCKED: fixed Apple tool is unavailable: {path}") from exc
        try:
            opened = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            stat.S_ISLNK(named.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != 0
            or opened.st_mode & 0o022
            or not opened.st_mode & stat.S_IXUSR
            or _retained_file_identity(named) != _retained_file_identity(opened)
        ):
            raise CollectorError(f"OWNER-BLOCKED: fixed Apple tool custody is unsafe: {path}")
    return None


def _authoritative_ios_command_runner(
    arguments: list[str] | tuple[str, ...],
    xcode: _AuthenticatedXcodeSelection,
) -> subprocess.CompletedProcess[bytes]:
    command = list(arguments)
    allowed = {
        "/usr/bin/codesign",
        "/usr/bin/security",
        "/usr/bin/xcrun",
        sys.executable,
    }
    if not command or command[0] not in allowed:
        raise CollectorError("iOS release verifier requested an unauthenticated tool")
    xcode.verify()
    return _bounded_command(
        command,
        label="authoritative iOS release verifier",
        env={
            "DEVELOPER_DIR": xcode.descriptor_path,
            "HOME": "/var/empty",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": "/private/tmp",
        },
        pass_fds=(xcode.descriptor,),
    )


def authoritative_ios_release_verification(
    ipa: pathlib.Path,
    archive: pathlib.Path,
    obfuscation_receipt: pathlib.Path,
    symbol_custody_receipt: pathlib.Path,
) -> dict[str, Any]:
    _require_authoritative_verifier_origins()
    _authenticate_fixed_apple_tools()
    before = _ios_release_input_bindings(
        ipa, archive, obfuscation_receipt, symbol_custody_receipt
    )
    try:
        with _AuthenticatedXcodeSelection() as xcode:
            runner = lambda arguments: _authoritative_ios_command_runner(
                arguments, xcode
            )
            ios_release_verifier.verify_release_pair(
                ipa,
                archive,
                obfuscation_receipt,
                symbol_custody_receipt,
                runner=runner,
            )
            archive_app = ios_release_verifier._archive_app(archive)
            bundle = ios_release_verifier.verify_app_bundle(
                archive_app,
                "final-evidence xcarchive",
                runner,
                distribution=False,
            )
            dsym_uuids = ios_release_verifier._archive_dsym_uuids(
                archive, runner
            )
            watch_snapshot = _verify_watch_release_snapshot(
                ipa,
                artifact_sha256=str(before["ipa_sha256"]),
                artifact_size=int(before["ipa_bytes"]),
            )
            xcode.verify()
    except ios_release_verifier.BlockedError as exc:
        raise CollectorError(f"OWNER-BLOCKED: {exc}") from exc
    except ios_release_verifier.VerificationError as exc:
        raise CollectorError(
            f"OWNER-BLOCKED: current iOS release evidence is missing, stale, or invalid: {exc}"
        ) from exc
    except AppleArtifactGateError as exc:
        raise CollectorError(f"iOS Watch verifier rejected current evidence: {exc}") from exc
    after = _ios_release_input_bindings(
        ipa, archive, obfuscation_receipt, symbol_custody_receipt
    )
    if before != after:
        raise CollectorError("iOS release candidate inputs changed during verification")
    if not bundle.watch_uuids or not bundle.watch_uuids.issubset(dsym_uuids):
        raise CollectorError("iOS release verifier did not cover Watch dSYM UUIDs")
    return {
        "schema_version": IOS_RELEASE_VERIFICATION_SCHEMA_VERSION,
        "contract": IOS_RELEASE_VERIFICATION_CONTRACT,
        "artifact_contract": ios_release_verifier.ARTIFACT_CONTRACT,
        "verifier_source_sha256": sha256_file(IOS_RELEASE_VERIFIER_PATH),
        **before,
        "host_version": bundle.app_version,
        "host_build_number": bundle.build_number,
        "watch_artifact_verification": watch_snapshot,
        "watch_profile_verified": True,
        "watch_signature_verified": True,
        "watch_distribution_identity_verified": True,
        "watch_platform": "WATCHOS",
        "watch_minimum_os": ios_release_verifier.EXPECTED_MINIMUM_WATCHOS,
        "watch_uuids": sorted(bundle.watch_uuids),
        "watch_uuid_parity_verified": True,
        "watch_dsym_coverage_verified": True,
    }


def _retained_directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
    )


def _retained_file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class HeldExactArtifact:
    """Keep exact snapshot bytes, their name, and every ancestor retained."""

    def __init__(
        self,
        path: pathlib.Path,
        descriptor: int,
        *,
        digest: str,
        size: int,
    ) -> None:
        self.path = path.resolve(strict=True)
        self.descriptor = descriptor
        self.digest = digest
        self.size = size
        self.identity = _retained_file_identity(os.fstat(descriptor))
        self._ancestors: list[tuple[int | None, str, int, tuple[int, ...]]] = []
        self._watch: object | None = None
        self._closed = False
        try:
            parts = self.path.parent.parts
            if not parts or parts[0] != os.sep:
                raise CollectorError("held Apple artifact path is not absolute")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_DIRECTORY", 0)
            )
            current = os.open(os.sep, flags)
            self._ancestors.append(
                (None, "", current, _retained_directory_identity(os.fstat(current)))
            )
            for component in parts[1:]:
                child = os.open(component, flags, dir_fd=current)
                self._ancestors.append(
                    (
                        current,
                        component,
                        child,
                        _retained_directory_identity(os.fstat(child)),
                    )
                )
                current = child
            self.parent_descriptor = current
            os.set_inheritable(self.descriptor, False)
            self._start_watch()
            self.verify(rehash=True)
        except Exception:
            self.close(verify=False)
            raise

    def __iter__(self):
        yield self.digest
        yield self.size

    @property
    def descriptor_path(self) -> pathlib.Path:
        self.verify()
        root = pathlib.Path("/dev/fd") if sys.platform == "darwin" else pathlib.Path("/proc/self/fd")
        path = root / str(self.descriptor)
        duplicate = -1
        try:
            duplicate = os.open(path, _open_nofollow_flags())
            named = os.fstat(duplicate)
            held = os.fstat(self.descriptor)
        except OSError as exc:
            raise CollectorError("held Apple artifact descriptor is not addressable") from exc
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        if _retained_file_identity(named) != _retained_file_identity(held):
            raise CollectorError("held Apple artifact descriptor path is not exact")
        return path

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            return
        watch = select.kqueue()
        directory_flags = (
            getattr(select, "KQ_NOTE_DELETE", 0)
            | getattr(select, "KQ_NOTE_RENAME", 0)
            | getattr(select, "KQ_NOTE_REVOKE", 0)
            | getattr(select, "KQ_NOTE_ATTRIB", 0)
        )
        file_flags = (
            directory_flags
            | getattr(select, "KQ_NOTE_WRITE", 0)
            | getattr(select, "KQ_NOTE_EXTEND", 0)
            | getattr(select, "KQ_NOTE_LINK", 0)
        )
        events = [
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=directory_flags,
            )
            for _parent, _name, descriptor, _identity in self._ancestors
        ]
        events.append(
            select.kevent(
                self.descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=file_flags,
            )
        )
        watch.control(events, 0, 0)
        self._watch = watch

    def _reject_events(self) -> None:
        if self._watch is not None and self._watch.control(
            None, len(self._ancestors) + 1, 0
        ):
            raise CollectorError(
                "held Apple artifact or an ancestor changed while retained"
            )

    def verify(self, *, rehash: bool = False) -> None:
        if self._closed or self.descriptor < 0:
            raise CollectorError("held Apple artifact custody is closed")
        self._reject_events()
        for parent_fd, name, descriptor, expected in self._ancestors:
            current = os.fstat(descriptor)
            if _retained_directory_identity(current) != expected:
                raise CollectorError("held Apple artifact ancestor changed")
            if parent_fd is not None:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _retained_directory_identity(named) != expected:
                    raise CollectorError("held Apple artifact ancestor was substituted")
        current = os.fstat(self.descriptor)
        named = os.stat(
            self.path.name,
            dir_fd=self.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_size != self.size
            or _retained_file_identity(current) != self.identity
            or _retained_file_identity(named) != self.identity
        ):
            raise CollectorError("held Apple artifact was substituted")
        if rehash:
            digest = hashlib.sha256()
            offset = 0
            while offset < self.size:
                block = os.pread(
                    self.descriptor, min(1024 * 1024, self.size - offset), offset
                )
                if not block:
                    raise CollectorError("held Apple artifact read was truncated")
                digest.update(block)
                offset += len(block)
            if os.pread(self.descriptor, 1, offset) or digest.hexdigest() != self.digest:
                raise CollectorError("held Apple artifact digest changed")
        self._reject_events()

    def rehash(self) -> str:
        self.verify(rehash=True)
        return self.digest

    def close(self, *, verify: bool = True) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if verify:
            try:
                self.verify(rehash=True)
            except BaseException as exc:
                error = exc
        self._closed = True
        if self._watch is not None:
            try:
                self._watch.close()
            except OSError:
                pass
            self._watch = None
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        for _parent, _name, descriptor, _identity in reversed(self._ancestors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._ancestors.clear()
        if error is not None:
            raise error

    def __del__(self) -> None:
        try:
            self.close(verify=False)
        except Exception:
            pass


class HeldArchiveCustody:
    """Retain an xcarchive root, every directory/file, and its exact inventory."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = path.resolve(strict=True)
        self.inventory_sha256 = xcarchive_inventory_sha256(self.path)
        self._records: list[tuple[pathlib.Path, int, tuple[int, ...]]] = []
        self._files: list[
            tuple[int, str, int, tuple[int, ...], str, int]
        ] = []
        self._watch: object | None = None
        self._closed = False
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            current = pathlib.Path(os.sep)
            root_descriptor = os.open(current, flags)
            self._records.append(
                (
                    current,
                    root_descriptor,
                    _retained_directory_identity(os.fstat(root_descriptor)),
                )
            )
            for component in self.path.parent.parts[1:]:
                current = current / component
                descriptor = os.open(current, flags)
                info = os.fstat(descriptor)
                self._records.append(
                    (current, descriptor, _retained_directory_identity(info))
                )
            for root, directory_names, file_names in os.walk(
                self.path, followlinks=False
            ):
                root_path = pathlib.Path(root)
                descriptor = os.open(root_path, flags)
                info = os.fstat(descriptor)
                if not stat.S_ISDIR(info.st_mode):
                    os.close(descriptor)
                    raise CollectorError("iOS xcarchive directory custody is invalid")
                self._records.append(
                    (root_path, descriptor, _retained_directory_identity(info))
                )
                for name in directory_names:
                    child = root_path / name
                    child_info = child.lstat()
                    if stat.S_ISLNK(child_info.st_mode) or is_reparse_point(child_info):
                        raise CollectorError("iOS xcarchive contains a linked directory")
                for name in file_names:
                    child = root_path / name
                    file_descriptor = os.open(child, _open_nofollow_flags())
                    file_info = os.fstat(file_descriptor)
                    named_info = os.stat(
                        name, dir_fd=descriptor, follow_symlinks=False
                    )
                    if (
                        not stat.S_ISREG(file_info.st_mode)
                        or file_info.st_nlink != 1
                        or _retained_file_identity(file_info)
                        != _retained_file_identity(named_info)
                    ):
                        os.close(file_descriptor)
                        raise CollectorError(
                            "iOS xcarchive contains a linked or substituted file"
                        )
                    digest = hashlib.sha256()
                    offset = 0
                    while offset < file_info.st_size:
                        block = os.pread(
                            file_descriptor,
                            min(1024 * 1024, file_info.st_size - offset),
                            offset,
                        )
                        if not block:
                            os.close(file_descriptor)
                            raise CollectorError(
                                "iOS xcarchive file read was truncated"
                            )
                        digest.update(block)
                        offset += len(block)
                    if os.pread(file_descriptor, 1, offset):
                        os.close(file_descriptor)
                        raise CollectorError("iOS xcarchive file grew while retained")
                    self._files.append(
                        (
                            descriptor,
                            name,
                            file_descriptor,
                            _retained_file_identity(file_info),
                            digest.hexdigest(),
                            file_info.st_size,
                        )
                    )
            if not self._records:
                raise CollectorError("iOS xcarchive custody is empty")
            self._start_watch()
            self.verify()
        except Exception:
            self.close(verify=False)
            raise

    def _start_watch(self) -> None:
        if not hasattr(select, "kqueue"):
            return
        watch = select.kqueue()
        flags = (
            getattr(select, "KQ_NOTE_DELETE", 0)
            | getattr(select, "KQ_NOTE_RENAME", 0)
            | getattr(select, "KQ_NOTE_REVOKE", 0)
            | getattr(select, "KQ_NOTE_ATTRIB", 0)
            | getattr(select, "KQ_NOTE_WRITE", 0)
        )
        events = [
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=flags,
            )
            for _path, descriptor, _identity in self._records
        ]
        events.extend(
            select.kevent(
                descriptor,
                filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                fflags=(
                    flags
                    | getattr(select, "KQ_NOTE_EXTEND", 0)
                    | getattr(select, "KQ_NOTE_LINK", 0)
                ),
            )
            for _parent, _name, descriptor, _identity, _digest, _size in self._files
        )
        watch.control(events, 0, 0)
        self._watch = watch

    def _reject_events(self) -> None:
        if self._watch is not None and self._watch.control(
            None, len(self._records) + len(self._files), 0
        ):
            raise CollectorError("iOS xcarchive changed while retained")

    def verify(self) -> None:
        if self._closed:
            raise CollectorError("iOS xcarchive custody is closed")
        self._reject_events()
        for path, descriptor, expected in self._records:
            current = os.fstat(descriptor)
            named = path.lstat()
            if (
                _retained_directory_identity(current) != expected
                or _retained_directory_identity(named) != expected
            ):
                raise CollectorError("iOS xcarchive directory was substituted")
        for parent_fd, name, descriptor, expected, expected_digest, size in self._files:
            current = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _retained_file_identity(current) != expected
                or _retained_file_identity(named) != expected
            ):
                raise CollectorError("iOS xcarchive file was substituted")
            digest = hashlib.sha256()
            offset = 0
            while offset < size:
                block = os.pread(
                    descriptor, min(1024 * 1024, size - offset), offset
                )
                if not block:
                    raise CollectorError("iOS xcarchive file read was truncated")
                digest.update(block)
                offset += len(block)
            if os.pread(descriptor, 1, offset) or digest.hexdigest() != expected_digest:
                raise CollectorError("iOS xcarchive file digest changed")
        if xcarchive_inventory_sha256(self.path) != self.inventory_sha256:
            raise CollectorError("iOS xcarchive inventory changed while retained")
        self._reject_events()

    def relocate(self, destination: pathlib.Path) -> None:
        if self._closed:
            raise CollectorError("directory custody is closed")
        old_root = self.path
        destination = destination.resolve(strict=True)
        relocated: list[tuple[pathlib.Path, int, tuple[int, ...]]] = []
        for path, descriptor, identity in self._records:
            try:
                relative = path.relative_to(old_root)
            except ValueError:
                relocated.append((path, descriptor, identity))
            else:
                relocated.append((destination / relative, descriptor, identity))
        self.path = destination
        self._records = relocated
        self._start_watch()
        if self._watch is not None:
            self._watch.control(
                None, max(1, len(self._records) + len(self._files)), 0
            )
        self.verify()

    def prepare_atomic_relocate(self) -> None:
        self.verify()
        if self._watch is not None:
            self._watch.close()
            self._watch = None

    def close(self, *, verify: bool = True) -> None:
        if self._closed:
            return
        error: BaseException | None = None
        if verify:
            try:
                self.verify()
            except BaseException as exc:
                error = exc
        self._closed = True
        if self._watch is not None:
            try:
                self._watch.close()
            except OSError:
                pass
            self._watch = None
        for _parent, _name, descriptor, _identity, _digest, _size in reversed(
            self._files
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._files.clear()
        for _path, descriptor, _identity in reversed(self._records):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._records.clear()
        if error is not None:
            raise error


def hold_exact_artifact(
    source: pathlib.Path,
    destination: pathlib.Path,
    *,
    expected_sha256: str | None = None,
) -> HeldExactArtifact:
    """Copy one source inode once and retain a private single-link candidate."""

    source_fd = destination_fd = retained_fd = -1
    destination_created = False
    expected_held_size = 0
    try:
        source_fd = os.open(source, _open_nofollow_flags())
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
            raise CollectorError("Apple artifact must be a non-empty single-link file")
        expected_held_size = before.st_size
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        destination_created = True
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(source_fd, min(1024 * 1024, remaining))
            if not block:
                raise CollectorError("Apple artifact changed while it was held")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise CollectorError("held Apple artifact write was truncated")
                view = view[written:]
            remaining -= len(block)
        if os.read(source_fd, 1):
            raise CollectorError("Apple artifact grew while it was held")
        after = os.fstat(source_fd)
        named = source.lstat()
        held = os.fstat(destination_fd)
        held_digest = digest.hexdigest()
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (before.st_dev, before.st_ino, before.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
            or not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or held.st_size != before.st_size
            or (expected_sha256 is not None and held_digest != expected_sha256)
        ):
            raise CollectorError("Apple artifact was substituted while it was held")
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
        dir_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
        dir_fd = os.open(destination.parent, dir_flags)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        retained_fd = os.open(destination, _open_nofollow_flags())
        owned_descriptor = retained_fd
        retained_fd = -1
        custody = HeldExactArtifact(
            destination,
            owned_descriptor,
            digest=held_digest,
            size=before.st_size,
        )
        return custody
    except OSError as exc:
        raise CollectorError("Apple artifact could not be held safely") from exc
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)
        if source_fd >= 0:
            os.close(source_fd)
        if retained_fd >= 0:
            os.close(retained_fd)
        if destination_created:
            try:
                held_info = destination.lstat()
            except OSError:
                held_info = None
            if held_info is None or (
                stat.S_ISLNK(held_info.st_mode)
                or not stat.S_ISREG(held_info.st_mode)
                or held_info.st_nlink != 1
                or expected_held_size <= 0
                or held_info.st_size != expected_held_size
            ):
                try:
                    destination.unlink()
                except OSError:
                    pass


def _effective_uid() -> int:
    return int(getattr(os, "geteuid", lambda: 0)())


def _open_nofollow_flags(*, writable: bool = False) -> int:
    access = os.O_RDWR if writable else os.O_RDONLY
    return (
        access
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _mode_matches(info: os.stat_result, expected_mode: int) -> bool:
    # Windows' compatibility stat reports directory/file modes as 0777/0666;
    # production collection and the release wrapper are macOS-only.
    return os.name == "nt" or stat.S_IMODE(info.st_mode) == expected_mode


def _enforce_fd_mode(descriptor: int, path: pathlib.Path, mode: int) -> None:
    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, mode)
    else:  # pragma: no cover - Windows-only compatibility for protocol tests.
        os.chmod(path, mode)


def read_owner_file_bytes(
    path: pathlib.Path,
    *,
    expected_uid: int,
    expected_mode: int = 0o600,
    label: str,
) -> bytes:
    """Read one trusted regular file once, using the same descriptor for validation and bytes."""
    try:
        link_info = path.lstat()
    except FileNotFoundError as exc:
        raise CollectorError(f"{label} does not exist") from exc
    if stat.S_ISLNK(link_info.st_mode) or is_reparse_point(link_info):
        raise CollectorError(f"{label} must not be a symlink/reparse point")
    try:
        descriptor = os.open(path, _open_nofollow_flags())
    except OSError as exc:
        raise CollectorError(f"{label} could not be opened safely") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or not _mode_matches(info, expected_mode)
        ):
            raise CollectorError(f"{label} ownership/type/mode is invalid")
        chunks: list[bytes] = []
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(descriptor)
        if (info.st_dev, info.st_ino, info.st_size) != (after.st_dev, after.st_ino, after.st_size):
            raise CollectorError(f"{label} changed while it was read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _harden_owner_file(path: pathlib.Path, *, expected_uid: int, label: str) -> bytes:
    try:
        link_info = path.lstat()
    except FileNotFoundError as exc:
        raise CollectorError(f"{label} does not exist") from exc
    if stat.S_ISLNK(link_info.st_mode) or is_reparse_point(link_info):
        raise CollectorError(f"{label} must not be a symlink/reparse point")
    try:
        descriptor = os.open(path, _open_nofollow_flags(writable=True))
    except OSError as exc:
        raise CollectorError(f"{label} could not be opened safely") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid:
            raise CollectorError(f"{label} ownership/type is invalid")
        _enforce_fd_mode(descriptor, path, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return read_owner_file_bytes(
        path, expected_uid=expected_uid, expected_mode=0o600, label=label
    )


def _exclusive_bytes(path: pathlib.Path, data: bytes, *, expected_uid: int) -> str:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise CollectorError(f"refusing to overwrite Apple evidence file: {path.name}") from exc
    except OSError as exc:
        raise CollectorError(f"Apple evidence file could not be created safely: {path.name}") from exc
    try:
        _enforce_fd_mode(descriptor, path, 0o600)
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or not _mode_matches(info, 0o600)
        ):
            raise CollectorError(f"Apple evidence file ownership/type/mode is invalid: {path.name}")
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def reject_link_components(path: pathlib.Path, label: str, *, must_exist: bool) -> pathlib.Path:
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else pathlib.Path.cwd() / expanded
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if must_exist:
                raise CollectorError(f"{label} does not exist")
            continue
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or is_reparse_point(info):
            raise CollectorError(f"{label} must not traverse a symlink/reparse point")
    if must_exist and (not absolute.is_file() or absolute.is_symlink()):
        raise CollectorError(f"{label} must be a regular file")
    return absolute.resolve(strict=must_exist)


def reject_directory_components(path: pathlib.Path, label: str) -> pathlib.Path:
    expanded = path.expanduser()
    absolute = expanded if expanded.is_absolute() else pathlib.Path.cwd() / expanded
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            raise CollectorError(f"{label} does not exist")
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or is_reparse_point(info):
            raise CollectorError(f"{label} must not traverse a symlink/reparse point")
    if not absolute.is_dir() or absolute.is_symlink():
        raise CollectorError(f"{label} must be a directory")
    return absolute.resolve(strict=True)


def validate_installed_tools(repo: pathlib.Path) -> pathlib.Path:
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise CollectorError("Apple final evidence collection must run as root on macOS")
    driver = reject_link_components(INSTALLED_DRIVER, "Apple UI driver", must_exist=True)
    observer = reject_link_components(INSTALLED_MAP_OBSERVER, "Apple map observer", must_exist=True)
    route_controller = reject_link_components(
        INSTALLED_ROUTE_CONTROLLER, "Apple route controller", must_exist=True
    )
    manifest_path = reject_link_components(INSTALLED_MANIFEST, "Apple tool manifest", must_exist=True)
    source_driver = reject_link_components(repo / "tools/apple_release_ui_driver.py", "Apple UI driver source", must_exist=True)
    source_observer = reject_link_components(repo / "tools/apple_map_semantic_observer.swift", "Apple map observer source", must_exist=True)
    source_route_controller = reject_link_components(
        repo / "tools/android_remote_route_control.py",
        "Apple route controller source",
        must_exist=True,
    )
    for path, mode, label in (
        (driver, 0o755, "Apple UI driver"),
        (observer, 0o755, "Apple map observer"),
        (route_controller, 0o755, "Apple route controller"),
        (manifest_path, 0o600, "Apple tool manifest"),
    ):
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            raise CollectorError(f"{label} ownership/mode is invalid")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("Apple installed-tool manifest is invalid") from exc
    expected_fields = {
        "schema_version", "contract", "driver_source_sha256", "driver_installed_sha256",
        "map_observer_source_sha256", "map_observer_installed_sha256", "secret_material_redacted",
        "route_controller_source_sha256", "route_controller_installed_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_fields or manifest["schema_version"] != 1 or manifest["contract"] != "winsvpn-apple-release-tools-v1" or manifest["secret_material_redacted"] is not True:
        raise CollectorError("Apple installed-tool manifest contract is invalid")
    comparisons = (
        ("driver_source_sha256", sha256_file(source_driver)),
        ("driver_installed_sha256", sha256_file(driver)),
        ("map_observer_source_sha256", sha256_file(source_observer)),
        ("map_observer_installed_sha256", sha256_file(observer)),
        ("route_controller_source_sha256", sha256_file(source_route_controller)),
        ("route_controller_installed_sha256", sha256_file(route_controller)),
    )
    for field, current in comparisons:
        if require_sha(manifest[field], field) != current:
            raise CollectorError(f"Apple installed tool does not match frozen source: {field}")
    if sha256_file(driver) != sha256_file(source_driver):
        raise CollectorError("Installed Apple UI driver differs from repository source")
    if sha256_file(route_controller) != sha256_file(source_route_controller):
        raise CollectorError("Installed Apple route controller differs from repository source")
    return driver


def require_sha(value: Any, label: str) -> str:
    text = str(value)
    if not SHA256_RE.fullmatch(text):
        raise CollectorError(f"{label} must be a lowercase SHA-256 digest")
    return text


def reject_mutable_tmp_authority(value: Any, label: str) -> None:
    text = str(value or "").replace("\\", "/")
    lowered = text.lower()
    if lowered.startswith("/tmp/") or "/tmp/" in lowered or lowered.startswith("/var/folders/"):
        raise CollectorError(f"{label} must not use mutable /tmp logs as final authority")


def reject_stale_build_29_digest(value: Any, label: str) -> None:
    text = str(value or "")
    if text in STALE_BUILD_29_SHA256:
        raise CollectorError(f"{label} binds stale build 29 bytes as current evidence")


def _optional_sha(value: Any, label: str, *, required: bool) -> str:
    if value in ("", None):
        if required:
            raise CollectorError(f"{label} must be a lowercase SHA-256 digest")
        return ""
    digest = require_sha(value, label)
    reject_stale_build_29_digest(digest, label)
    return digest


def validate_macos_architecture_inventory(
    inventory: Any, *, require_complete: bool
) -> dict[str, Any]:
    required = list(REQUIRED_MACOS_ARCHITECTURES)
    if not isinstance(inventory, dict):
        raise CollectorError("macOS architecture inventory must be an object")
    if inventory.get("required_architectures") != required:
        raise CollectorError(
            "macOS architecture inventory must require every shipped architecture: arm64, x86_64"
        )
    shipped = inventory.get("shipped")
    if not isinstance(shipped, list):
        raise CollectorError("macOS architecture inventory shipped list is invalid")
    if not require_complete:
        if shipped:
            raise CollectorError(
                "pending macOS architecture inventory must not claim shipped binaries"
            )
        return {
            "required_architectures": required,
            "shipped": [],
        }
    if not shipped:
        raise CollectorError("macOS architecture inventory is missing shipped binaries")
    seen_paths: set[str] = set()
    found_archs: set[str] = set()
    canonical_shipped: list[dict[str, Any]] = []
    for index, raw in enumerate(shipped):
        item = exact(
            raw,
            {"path", "sha256", "size_bytes", "architectures"},
            f"macOS shipped binary {index}",
        )
        path = str(item["path"] or "")
        reject_mutable_tmp_authority(path, f"macOS shipped binary {index} path")
        if not path or path.startswith("/") or ".." in pathlib.Path(path).parts:
            raise CollectorError(f"macOS shipped binary {index} path is invalid")
        if path in seen_paths:
            raise CollectorError(f"macOS shipped binary path is duplicated: {path}")
        seen_paths.add(path)
        digest = require_sha(item["sha256"], f"macOS shipped binary {path} sha256")
        reject_stale_build_29_digest(digest, f"macOS shipped binary {path} sha256")
        size = item["size_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise CollectorError(f"macOS shipped binary {path} size is invalid")
        architectures = item["architectures"]
        if not isinstance(architectures, list) or not architectures:
            raise CollectorError(f"macOS shipped binary {path} architectures are missing")
        normalized: list[str] = []
        for architecture in architectures:
            if architecture not in REQUIRED_MACOS_ARCHITECTURES:
                raise CollectorError(
                    f"macOS shipped binary {path} has unsupported architecture {architecture!r}"
                )
            if architecture in normalized:
                raise CollectorError(
                    f"macOS shipped binary {path} has a duplicate architecture"
                )
            normalized.append(str(architecture))
            found_archs.add(str(architecture))
        canonical_shipped.append(
            {
                "path": path,
                "sha256": digest,
                "size_bytes": size,
                "architectures": normalized,
            }
        )
    missing = [architecture for architecture in required if architecture not in found_archs]
    if missing:
        raise CollectorError(
            "missing shipped macOS architecture: " + ", ".join(missing)
        )
    canonical_shipped.sort(key=lambda item: item["path"])
    return {
        "required_architectures": required,
        "shipped": canonical_shipped,
    }


def canonical_owner_evidence_set(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict) or set(record) != set(OWNER_EVIDENCE_SET_KEYS):
        actual = sorted(record) if isinstance(record, dict) else type(record).__name__
        raise CollectorError(f"Apple owner evidence set fields are invalid: {actual}")
    if record["contract"] != OWNER_AUTHORIZATION_CONTRACT:
        raise CollectorError("Apple owner evidence contract is invalid")
    if record["release"] != CANONICAL_RELEASE:
        raise CollectorError("Apple owner evidence release must be 1.0.17+34")
    if record["app_version"] != CANONICAL_APP_VERSION:
        raise CollectorError("Apple owner evidence app_version must be 1.0.17")
    if str(record["build_number"]) != CANONICAL_BUILD_NUMBER:
        raise CollectorError("Apple owner evidence build_number must be 33")
    if list(record["required_surfaces"]) != list(REQUIRED_OWNER_SURFACES):
        raise CollectorError(
            "Apple owner evidence must cover ios, embedded watchos companion, and macos"
        )
    complete = evidence_set_is_complete(record, validate=False)
    canonical = {
        "contract": OWNER_AUTHORIZATION_CONTRACT,
        "release": CANONICAL_RELEASE,
        "app_version": CANONICAL_APP_VERSION,
        "build_number": CANONICAL_BUILD_NUMBER,
        "required_surfaces": list(REQUIRED_OWNER_SURFACES),
        "release_input_index_sha256": _optional_sha(
            record["release_input_index_sha256"],
            "release_input_index_sha256",
            required=complete,
        ),
        "ios_artifact_sha256": _optional_sha(
            record["ios_artifact_sha256"], "ios_artifact_sha256", required=complete
        ),
        "ios_artifact_size_bytes": record["ios_artifact_size_bytes"],
        "ios_bundle_id": record["ios_bundle_id"],
        "ios_packet_tunnel_bundle_id": record["ios_packet_tunnel_bundle_id"],
        "watch_bundle_id": record["watch_bundle_id"],
        "watch_companion_bundle_id": record["watch_companion_bundle_id"],
        "watch_version": record["watch_version"],
        "watch_build": record["watch_build"],
        "watch_executable": record["watch_executable"],
        "watch_executable_sha256": _optional_sha(
            record["watch_executable_sha256"],
            "watch_executable_sha256",
            required=complete,
        ),
        "watch_privacy_info_sha256": _optional_sha(
            record["watch_privacy_info_sha256"],
            "watch_privacy_info_sha256",
            required=complete,
        ),
        "macos_artifact_sha256": _optional_sha(
            record["macos_artifact_sha256"], "macos_artifact_sha256", required=complete
        ),
        "macos_artifact_size_bytes": record["macos_artifact_size_bytes"],
        "macos_bundle_id": record["macos_bundle_id"],
        "macos_packet_tunnel_bundle_id": record["macos_packet_tunnel_bundle_id"],
        "macos_architecture_inventory": validate_macos_architecture_inventory(
            record["macos_architecture_inventory"], require_complete=complete
        ),
        "runtime_evidence_sha256": _optional_sha(
            record["runtime_evidence_sha256"],
            "runtime_evidence_sha256",
            required=complete,
        ),
        "watch_companion_smoke_sha256": _optional_sha(
            record["watch_companion_smoke_sha256"],
            "watch_companion_smoke_sha256",
            required=complete,
        ),
        "archive_privacy_inventory_sha256": _optional_sha(
            record["archive_privacy_inventory_sha256"],
            "archive_privacy_inventory_sha256",
            required=complete,
        ),
        "app_store_privacy_snapshot_sha256": require_sha(
            record["app_store_privacy_snapshot_sha256"],
            "app_store_privacy_snapshot_sha256",
        ),
        "final_receipt_sha256": record["final_receipt_sha256"],
    }
    for label in (
        "ios_bundle_id",
        "macos_bundle_id",
        "watch_companion_bundle_id",
    ):
        if canonical[label] != HOST_BUNDLE_ID:
            raise CollectorError(f"{label} must be {HOST_BUNDLE_ID}")
    for label in ("ios_packet_tunnel_bundle_id", "macos_packet_tunnel_bundle_id"):
        if canonical[label] != PACKET_TUNNEL_BUNDLE_ID:
            raise CollectorError(f"{label} must be {PACKET_TUNNEL_BUNDLE_ID}")
    if canonical["watch_bundle_id"] != WATCH_BUNDLE_ID:
        raise CollectorError("watch_bundle_id must be org.winsvpn.app.watchkitapp")
    if canonical["watch_version"] != CANONICAL_APP_VERSION:
        raise CollectorError("embedded watch version must be 1.0.17")
    if str(canonical["watch_build"]) != CANONICAL_BUILD_NUMBER:
        raise CollectorError("embedded watch build must be 33")
    if canonical["watch_executable"] != WATCH_EXECUTABLE:
        raise CollectorError("embedded watch executable must be WinsWatch")
    for label in ("ios_artifact_size_bytes", "macos_artifact_size_bytes"):
        size = canonical[label]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise CollectorError(f"{label} must be a non-negative integer")
        if complete and size <= 0:
            raise CollectorError(f"{label} must bind the exact artifact size")
        if not complete and size != 0:
            raise CollectorError(f"pending {label} must be 0")
    receipts = canonical["final_receipt_sha256"]
    if not isinstance(receipts, dict):
        raise CollectorError("final_receipt_sha256 must be an object")
    canonical_receipts: dict[str, str] = {}
    for raw_name, raw_digest in receipts.items():
        name = str(raw_name)
        relative = pathlib.Path(name)
        reject_mutable_tmp_authority(name, f"final receipt {name}")
        if relative.is_absolute() or ".." in relative.parts or relative.name != name:
            raise CollectorError(f"final receipt name is invalid: {name}")
        canonical_receipts[name] = _optional_sha(
            raw_digest, f"final receipt {name}", required=complete
        )
    if complete and not canonical_receipts:
        raise CollectorError("final receipt hashes are missing")
    if not complete and canonical_receipts:
        raise CollectorError("pending owner evidence must not bind final receipt hashes")
    canonical["final_receipt_sha256"] = dict(sorted(canonical_receipts.items()))
    reject_stale_build_29_digest(
        canonical["app_store_privacy_snapshot_sha256"],
        "app_store_privacy_snapshot_sha256",
    )
    return canonical


def evidence_set_is_complete(record: Any, *, validate: bool = True) -> bool:
    if not isinstance(record, dict):
        return False
    sha_fields = (
        "release_input_index_sha256",
        "ios_artifact_sha256",
        "watch_executable_sha256",
        "watch_privacy_info_sha256",
        "macos_artifact_sha256",
        "runtime_evidence_sha256",
        "watch_companion_smoke_sha256",
        "archive_privacy_inventory_sha256",
        "app_store_privacy_snapshot_sha256",
    )
    complete = all(SHA256_RE.fullmatch(str(record.get(field) or "")) for field in sha_fields)
    if validate and complete:
        canonical_owner_evidence_set(record)
    return complete


def owner_evidence_set_sha256(record: Any) -> str:
    canonical = canonical_owner_evidence_set(record)
    if not evidence_set_is_complete(canonical, validate=False):
        raise CollectorError(
            "owner approval cannot hash an incomplete post-build evidence set"
        )
    payload = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def pending_owner_evidence_set(*, app_store_privacy_snapshot_sha256: str) -> dict[str, Any]:
    return canonical_owner_evidence_set(
        {
            "contract": OWNER_AUTHORIZATION_CONTRACT,
            "release": CANONICAL_RELEASE,
            "app_version": CANONICAL_APP_VERSION,
            "build_number": CANONICAL_BUILD_NUMBER,
            "required_surfaces": list(REQUIRED_OWNER_SURFACES),
            "release_input_index_sha256": "",
            "ios_artifact_sha256": "",
            "ios_artifact_size_bytes": 0,
            "ios_bundle_id": HOST_BUNDLE_ID,
            "ios_packet_tunnel_bundle_id": PACKET_TUNNEL_BUNDLE_ID,
            "watch_bundle_id": WATCH_BUNDLE_ID,
            "watch_companion_bundle_id": HOST_BUNDLE_ID,
            "watch_version": CANONICAL_APP_VERSION,
            "watch_build": CANONICAL_BUILD_NUMBER,
            "watch_executable": WATCH_EXECUTABLE,
            "watch_executable_sha256": "",
            "watch_privacy_info_sha256": "",
            "macos_artifact_sha256": "",
            "macos_artifact_size_bytes": 0,
            "macos_bundle_id": HOST_BUNDLE_ID,
            "macos_packet_tunnel_bundle_id": PACKET_TUNNEL_BUNDLE_ID,
            "macos_architecture_inventory": {
                "required_architectures": list(REQUIRED_MACOS_ARCHITECTURES),
                "shipped": [],
            },
            "runtime_evidence_sha256": "",
            "watch_companion_smoke_sha256": "",
            "archive_privacy_inventory_sha256": "",
            "app_store_privacy_snapshot_sha256": app_store_privacy_snapshot_sha256,
            "final_receipt_sha256": {},
        }
    )


def _require_safe_ipa_members(archive: zipfile.ZipFile, label: str) -> None:
    members = archive.infolist()
    if not members or len(members) > MAX_IPA_MEMBERS:
        raise CollectorError(f"{label} ZIP member count is invalid")
    names: set[str] = set()
    expanded = 0
    for member in members:
        raw_name = member.filename
        pure = pathlib.PurePosixPath(raw_name)
        if (
            not raw_name
            or "\\" in raw_name
            or "\x00" in raw_name
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise CollectorError(f"{label} contains an unsafe zip path")
        folded = raw_name.rstrip("/").casefold()
        if not folded or folded in names:
            raise CollectorError(f"{label} contains duplicate or empty zip paths")
        names.add(folded)
        if member.flag_bits & 0x1:
            raise CollectorError(f"{label} contains encrypted zip content")
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise CollectorError(f"{label} must not contain symbolic-link members")
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise CollectorError(f"{label} contains a special filesystem zip entry")
        if member.file_size < 0 or member.file_size > MAX_IPA_MEMBER_BYTES:
            raise CollectorError(f"{label} zip member size is invalid")
        expanded += member.file_size
        if expanded > MAX_IPA_EXPANDED_BYTES:
            raise CollectorError(f"{label} zip expansion limit exceeded")


def embedded_watch_identity_from_ipa(ipa: pathlib.Path) -> dict[str, str]:
    ipa = reject_link_components(ipa, "iOS IPA", must_exist=True)
    if not zipfile.is_zipfile(ipa):
        raise CollectorError("iOS artifact is not a valid IPA ZIP")
    with zipfile.ZipFile(ipa) as archive:
        _require_safe_ipa_members(archive, "iOS IPA")
        names = archive.namelist()
        if any(
            re.search(r"(?:^|/)WinsWatch Extension\.appex(?:/|$)", name) for name in names
        ):
            raise CollectorError("iOS IPA contains legacy WinsWatch Extension.appex")
        host_plists = [
            name
            for name in names
            if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
        ]
        if len(host_plists) != 1:
            raise CollectorError("iOS IPA must contain exactly one top-level app plist")
        app_prefix = host_plists[0][: -len("/Info.plist")]
        watch_apps = sorted(
            {
                match.group(1)
                for name in names
                if (
                    match := re.fullmatch(
                        rf"({re.escape(app_prefix)}/Watch/[^/]+\.app)/Info\.plist",
                        name,
                    )
                )
            }
        )
        if len(watch_apps) != 1:
            raise CollectorError("iOS IPA omitted the embedded watchOS companion")
        watch_prefix = watch_apps[0]
        try:
            watch_info = plistlib.loads(archive.read(f"{watch_prefix}/Info.plist"))
        except Exception as exc:
            raise CollectorError("embedded Watch Info.plist is invalid") from exc
        if not isinstance(watch_info, dict):
            raise CollectorError("embedded Watch Info.plist must be a dictionary")
        bundle_id = str(watch_info.get("CFBundleIdentifier") or "")
        companion = str(watch_info.get("WKCompanionAppBundleIdentifier") or "")
        version = str(watch_info.get("CFBundleShortVersionString") or "")
        build = str(watch_info.get("CFBundleVersion") or "")
        executable = str(watch_info.get("CFBundleExecutable") or "").strip()
        if bundle_id != WATCH_BUNDLE_ID:
            raise CollectorError("embedded Watch bundle ID is invalid")
        if companion != HOST_BUNDLE_ID:
            raise CollectorError("embedded Watch companion bundle ID is invalid")
        if version != CANONICAL_APP_VERSION or build != CANONICAL_BUILD_NUMBER:
            raise CollectorError("embedded Watch version/build must be 1.0.17+34")
        if executable != WATCH_EXECUTABLE:
            raise CollectorError("embedded Watch executable must be WinsWatch")
        executable_path = f"{watch_prefix}/{executable}"
        try:
            executable_bytes = archive.read(executable_path)
        except KeyError as exc:
            raise CollectorError("embedded Watch executable is missing") from exc
        if not executable_bytes:
            raise CollectorError("embedded Watch executable is empty")
        try:
            privacy_bytes = archive.read(f"{watch_prefix}/PrivacyInfo.xcprivacy")
        except KeyError as exc:
            raise CollectorError("embedded Watch PrivacyInfo.xcprivacy is missing") from exc
        identity = {
            "bundle_id": bundle_id,
            "companion_bundle_id": companion,
            "version": version,
            "build": build,
            "executable": executable,
            "executable_sha256": hashlib.sha256(executable_bytes).hexdigest(),
            "privacy_info_sha256": hashlib.sha256(privacy_bytes).hexdigest(),
        }
        if set(identity) != set(WATCH_COMPANION_IDENTITY_KEYS):
            raise CollectorError("embedded Watch identity fields are invalid")
        return identity


def canonical_ios_release_verification(
    value: Any,
    *,
    expected_bindings: dict[str, object],
) -> dict[str, Any]:
    _require_authoritative_verifier_origins()
    record = exact(value, IOS_RELEASE_VERIFICATION_KEYS, "iOS release verification")
    if (
        record["schema_version"] != IOS_RELEASE_VERIFICATION_SCHEMA_VERSION
        or record["contract"] != IOS_RELEASE_VERIFICATION_CONTRACT
        or record["artifact_contract"] != ios_release_verifier.ARTIFACT_CONTRACT
        or record["verifier_source_sha256"] != sha256_file(IOS_RELEASE_VERIFIER_PATH)
    ):
        raise CollectorError("iOS release verifier schema or source is stale")
    for field, expected in expected_bindings.items():
        if record[field] != expected:
            raise CollectorError(
                f"iOS release verification is bound to a different candidate: {field}"
            )
    if (
        record["host_version"] != CANONICAL_APP_VERSION
        or str(record["host_build_number"]) != CANONICAL_BUILD_NUMBER
        or record["watch_profile_verified"] is not True
        or record["watch_signature_verified"] is not True
        or record["watch_distribution_identity_verified"] is not True
        or record["watch_platform"] != "WATCHOS"
        or record["watch_minimum_os"] != ios_release_verifier.EXPECTED_MINIMUM_WATCHOS
        or record["watch_uuid_parity_verified"] is not True
        or record["watch_dsym_coverage_verified"] is not True
    ):
        raise CollectorError("iOS release verification omitted required Watch evidence")
    watch_uuids = record["watch_uuids"]
    if (
        type(watch_uuids) is not list
        or not watch_uuids
        or watch_uuids != sorted(set(watch_uuids))
        or any(
            type(value) is not str
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value)
            is None
            for value in watch_uuids
        )
    ):
        raise CollectorError("iOS release verification Watch UUID evidence is invalid")
    snapshot = exact(
        record["watch_artifact_verification"],
        {"contract", "artifact_sha256", "verifier", "result", "result_sha256"},
        "Watch artifact verification snapshot",
    )
    if (
        snapshot["contract"] != "winsvpn-watch-artifact-verification-v1"
        or snapshot["artifact_sha256"] != expected_bindings["ipa_sha256"]
    ):
        raise CollectorError("Watch artifact verification is bound to another IPA")
    verifier = exact(snapshot["verifier"], {"path", "sha256"}, "Watch verifier")
    if (
        verifier["path"] != "tools/apple_watch_artifact_verifier.py"
        or verifier["sha256"] != sha256_file(WATCH_ARTIFACT_VERIFIER_PATH)
    ):
        raise CollectorError("Watch artifact verifier source is stale")
    result_keys = {
        "schema_version",
        "bundle_id",
        "companion_bundle_id",
        "version",
        "build_number",
        "parent_version",
        "parent_build_number",
        "ipa_sha256",
        "ipa_bytes",
        "executable",
        "executable_sha256",
        "architectures",
        "watch_connectivity_dependency",
        "wc_session_import",
        "required_selectors",
        "privacy_manifest_sha256",
        "debug_sections",
    }
    result = exact(snapshot["result"], result_keys, "Watch verifier result")
    architectures = result["architectures"]
    if (
        result["schema_version"] != 1
        or result["bundle_id"] != WATCH_BUNDLE_ID
        or result["companion_bundle_id"] != HOST_BUNDLE_ID
        or result["version"] != CANONICAL_APP_VERSION
        or str(result["build_number"]) != CANONICAL_BUILD_NUMBER
        or result["parent_version"] != record["host_version"]
        or str(result["parent_build_number"]) != str(record["host_build_number"])
        or result["ipa_sha256"] != expected_bindings["ipa_sha256"]
        or result["ipa_bytes"] != expected_bindings["ipa_bytes"]
        or result["executable"] != WATCH_EXECUTABLE
        or type(architectures) is not list
        or not architectures
        or len(architectures) != len(set(architectures))
        or not set(architectures).issubset({"arm64", "arm64_32"})
        or result["watch_connectivity_dependency"]
        != watch_artifact_schema.WATCHCONNECTIVITY_DYLIB
        or result["wc_session_import"] != "_OBJC_CLASS_$_WCSession"
        or result["required_selectors"]
        != sorted(watch_artifact_schema.REQUIRED_SELECTORS)
        or result["debug_sections"] is not False
    ):
        raise CollectorError("Watch verifier result is incomplete or stale")
    require_sha(result["executable_sha256"], "Watch executable")
    require_sha(result["privacy_manifest_sha256"], "Watch privacy manifest")
    expected_result_sha256 = hashlib.sha256(
        json.dumps(
            result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    if snapshot["result_sha256"] != expected_result_sha256:
        raise CollectorError("Watch verifier result digest is stale")
    return dict(record)


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise CollectorError(f"{label} fields are invalid: {actual}")
    return value


def driver_result(value: Any, action: str, fields: set[str]) -> dict[str, Any]:
    result = exact(
        value,
        {
            "schema_version",
            "contract",
            "action",
            "passed",
            "secret_material_redacted",
            *fields,
        },
        f"{action} driver result",
    )
    if (
        result["schema_version"] != 1
        or result["contract"] != CONTRACT
        or result["action"] != action
        or result["passed"] is not True
        or result["secret_material_redacted"] is not True
    ):
        raise CollectorError(f"{action} driver result failed closed")
    raw = json.dumps(result, sort_keys=True).lower()
    if any(token in raw for token in ("privatekey", "presharedkey", "endpoint =", "http://", "https://")):
        raise CollectorError(f"{action} driver result contains forbidden raw material")
    return result


def exclusive_json(path: pathlib.Path, value: dict[str, Any], *, expected_uid: int) -> str:
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return _exclusive_bytes(path, data, expected_uid=expected_uid)


def validate_owner_only_bundle(
    bundle: pathlib.Path,
    *,
    platform: str,
    repo: pathlib.Path,
    expected_uid: int = 0,
) -> tuple[pathlib.Path, pathlib.Path, str]:
    """Validate and hash/parse a collector bundle without reopening trusted bytes."""
    if platform not in {"ios", "macos"}:
        raise CollectorError("Apple collector bundle platform is invalid")
    bundle = reject_link_components(bundle, "Apple collector bundle", must_exist=False)
    try:
        bundle_info = bundle.lstat()
    except FileNotFoundError as exc:
        raise CollectorError("Apple collector bundle does not exist") from exc
    if (
        not stat.S_ISDIR(bundle_info.st_mode)
        or stat.S_ISLNK(bundle_info.st_mode)
        or is_reparse_point(bundle_info)
        or bundle_info.st_uid != expected_uid
        or not _mode_matches(bundle_info, 0o700)
    ):
        raise CollectorError("Apple collector bundle must be a root-owned 0700 directory")

    index_path = bundle / "EVIDENCE_INDEX.json"
    index_bytes = read_owner_file_bytes(
        index_path, expected_uid=expected_uid, label="Apple collector index"
    )
    try:
        index = json.loads(index_bytes.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectorError("Apple collector index must be UTF-8 JSON") from exc
    fields = {
        "schema_version", "contract", "platform", "machine_evidence_sha256",
        "map_screenshot_sha256", "receipt_sha256", "producer_contract_sha256",
        "secret_material_redacted",
    }
    if not isinstance(index, dict) or set(index) != fields:
        raise CollectorError("Apple collector index fields are invalid")
    if (
        index["schema_version"] != 1
        or index["contract"] != "winsvpn-apple-final-evidence-index-v1"
        or index["platform"] != platform
        or index["secret_material_redacted"] is not True
    ):
        raise CollectorError("Apple collector index contract is invalid")

    machine_path = bundle / f"{platform}-machine-evidence.json"
    map_path = bundle / "map.png"
    machine_bytes = read_owner_file_bytes(
        machine_path, expected_uid=expected_uid, label="Apple machine evidence"
    )
    map_bytes = read_owner_file_bytes(
        map_path, expected_uid=expected_uid, label="Apple map screenshot"
    )
    if require_sha(index["machine_evidence_sha256"], "machine_evidence_sha256") != hashlib.sha256(machine_bytes).hexdigest():
        raise CollectorError("Apple machine evidence does not match collector index")
    if require_sha(index["map_screenshot_sha256"], "map_screenshot_sha256") != hashlib.sha256(map_bytes).hexdigest():
        raise CollectorError("Apple map screenshot does not match collector index")
    if require_sha(index["producer_contract_sha256"], "producer_contract_sha256") != producer_contract_hash(repo, APPLE_PUBLIC_PRODUCER):
        raise CollectorError("Apple collector index was produced under a stale producer closure")

    receipts = index["receipt_sha256"]
    if not isinstance(receipts, dict) or not receipts:
        raise CollectorError("Apple collector index does not bind receipt files")
    expected_names = {"EVIDENCE_INDEX.json", machine_path.name, map_path.name}
    for raw_name, expected_hash in receipts.items():
        name = str(raw_name)
        relative = pathlib.Path(name)
        if relative.is_absolute() or ".." in relative.parts or relative.name != name:
            raise CollectorError("Apple collector receipt name is invalid")
        receipt_bytes = read_owner_file_bytes(
            bundle / name, expected_uid=expected_uid, label=f"Apple collector receipt {name}"
        )
        if require_sha(expected_hash, f"receipt_sha256.{name}") != hashlib.sha256(receipt_bytes).hexdigest():
            raise CollectorError(f"Apple collector receipt is missing or changed: {name}")
        expected_names.add(name)
    actual_names = {item.name for item in bundle.iterdir()}
    if actual_names != expected_names:
        raise CollectorError("Apple collector bundle contains unindexed files")
    return machine_path, map_path, hashlib.sha256(index_bytes).hexdigest()


class Collector:
    def __init__(
        self,
        *,
        driver: Driver,
        platform: str,
        artifact: pathlib.Path,
        output_dir: pathlib.Path,
        binding: dict[str, str],
        ios_route_inventory: pathlib.Path | None = None,
        ios_ssh_config: pathlib.Path | None = None,
        ios_archive: pathlib.Path | None = None,
        ios_obfuscation_receipt: pathlib.Path | None = None,
        ios_symbol_custody_receipt: pathlib.Path | None = None,
        ios_release_evidence_verifier: IOSReleaseEvidenceVerifier = (
            authoritative_ios_release_verification
        ),
        require_owner_signed: bool = True,
    ) -> None:
        if platform not in {"macos", "ios"}:
            raise CollectorError("Apple platform must be macos or ios")
        self.driver = driver
        self.platform = platform
        self.artifact = reject_link_components(artifact, "Apple artifact", must_exist=True)
        requested_output_dir = reject_link_components(
            output_dir, "Apple evidence output", must_exist=False
        )
        self.owner_uid = _effective_uid()
        self.binding = dict(binding)
        self.ios_route_inventory = (
            reject_link_components(ios_route_inventory, "iOS route inventory", must_exist=True)
            if ios_route_inventory is not None else None
        )
        self.ios_ssh_config = (
            reject_link_components(ios_ssh_config, "iOS release SSH config", must_exist=True)
            if ios_ssh_config is not None else None
        )
        ios_release_inputs = (
            ios_archive,
            ios_obfuscation_receipt,
            ios_symbol_custody_receipt,
        )
        if self.platform == "ios" and None in (
            self.ios_route_inventory,
            self.ios_ssh_config,
            *ios_release_inputs,
        ):
            raise CollectorError(
                "OWNER-BLOCKED: physical iOS collection requires the exact xcarchive, "
                "obfuscation receipt, symbol-custody receipt, route inventory, and pinned SSH config"
            )
        if self.platform == "macos" and any(
            value is not None
            for value in (
                self.ios_route_inventory,
                self.ios_ssh_config,
                *ios_release_inputs,
            )
        ):
            raise CollectorError("macOS collection must not receive iOS release inputs")
        for path, label in (
            (ios_archive, "iOS xcarchive"),
            (ios_obfuscation_receipt, "iOS obfuscation receipt"),
            (ios_symbol_custody_receipt, "iOS symbol-custody receipt"),
        ):
            if self.platform == "ios" and (
                path is None or not path.exists() or path.is_symlink()
            ):
                raise CollectorError(f"OWNER-BLOCKED: current {label} is missing or unsafe")
        self.ios_archive = (
            reject_directory_components(ios_archive, "iOS xcarchive")
            if ios_archive is not None
            else None
        )
        self.ios_obfuscation_receipt = (
            reject_link_components(
                ios_obfuscation_receipt, "iOS obfuscation receipt", must_exist=True
            )
            if ios_obfuscation_receipt is not None
            else None
        )
        self.ios_symbol_custody_receipt = (
            reject_link_components(
                ios_symbol_custody_receipt,
                "iOS symbol-custody receipt",
                must_exist=True,
            )
            if ios_symbol_custody_receipt is not None
            else None
        )
        self.ios_release_evidence_verifier = ios_release_evidence_verifier
        if (
            require_owner_signed
            and ios_release_evidence_verifier is not authoritative_ios_release_verification
        ):
            raise CollectorError(
                "owner-signed collection cannot substitute the authoritative iOS release verifier"
            )
        required = {
            "release_input_index_sha256",
            "platform_manifest_sha256",
            "artifact_input_fingerprint_sha256",
            "build_receipt_sha256",
            "producer_contract_sha256",
        }
        if set(self.binding) != required:
            raise CollectorError("Apple release binding fields are invalid")
        for field, value in self.binding.items():
            require_sha(value, field)
        if requested_output_dir.exists() or requested_output_dir.is_symlink():
            raise CollectorError("Apple evidence output directory must not already exist")
        os.umask(0o077)
        requested_output_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        output_parent = reject_directory_components(
            requested_output_dir.parent, "Apple evidence output parent"
        )
        anchor_path = output_parent / f".wins-evidence-parent-{uuid.uuid4().hex}"
        anchor_fd = os.open(
            anchor_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        try:
            anchor_bytes = os.urandom(32)
            if os.write(anchor_fd, anchor_bytes) != len(anchor_bytes):
                raise CollectorError("Apple evidence parent anchor write was truncated")
            os.fchmod(anchor_fd, 0o400)
            os.fsync(anchor_fd)
        finally:
            os.close(anchor_fd)
        retained_anchor_fd = os.open(anchor_path, _open_nofollow_flags())
        self._output_parent_custody = HeldExactArtifact(
            anchor_path,
            retained_anchor_fd,
            digest=hashlib.sha256(anchor_bytes).hexdigest(),
            size=len(anchor_bytes),
        )
        self.final_output_dir = requested_output_dir
        staging_name = f".{requested_output_dir.name}.staging-{uuid.uuid4().hex}"
        os.mkdir(
            staging_name,
            0o700,
            dir_fd=self._output_parent_custody.parent_descriptor,
        )
        self.output_dir = output_parent / staging_name
        os.chmod(self.output_dir, 0o700)
        output_info = self.output_dir.lstat()
        if (
            not stat.S_ISDIR(output_info.st_mode)
            or stat.S_ISLNK(output_info.st_mode)
            or is_reparse_point(output_info)
            or output_info.st_uid != self.owner_uid
            or not _mode_matches(output_info, 0o700)
        ):
            raise CollectorError("Apple evidence output must be an owner-only directory")
        self.receipts: list[pathlib.Path] = []
        self.receipt_hashes: dict[str, str] = {}
        self._driver_finalized = False
        self._output_committed = False
        self._output_bundle_custody: HeldArchiveCustody | None = None
        self._held_directory = tempfile.TemporaryDirectory(
            prefix=f".wins-apple-final-{self.platform}-",
            dir=str(self.artifact.parent),
        )
        held_artifact = pathlib.Path(self._held_directory.name) / self.artifact.name
        self._held_artifact = hold_exact_artifact(self.artifact, held_artifact)
        held_digest, held_size = self._held_artifact
        if held_size <= 0:
            self._held_directory.cleanup()
            raise CollectorError("held Apple artifact is empty")
        self.artifact = held_artifact
        self._held_ios_archive: HeldArchiveCustody | None = None
        self._held_ios_receipts: list[HeldExactArtifact] = []
        if self.platform == "ios":
            assert self.ios_archive is not None
            assert self.ios_obfuscation_receipt is not None
            assert self.ios_symbol_custody_receipt is not None
            self._held_ios_archive = HeldArchiveCustody(self.ios_archive)
            held_inputs: list[HeldExactArtifact] = []
            for source, name in (
                (self.ios_obfuscation_receipt, "held-obfuscation-receipt.json"),
                (self.ios_symbol_custody_receipt, "held-symbol-custody-receipt.json"),
            ):
                held_inputs.append(
                    hold_exact_artifact(
                        source, pathlib.Path(self._held_directory.name) / name
                    )
                )
            self._held_ios_receipts = held_inputs
            self.ios_archive = self._held_ios_archive.path
            self.ios_obfuscation_receipt = held_inputs[0].descriptor_path
            self.ios_symbol_custody_receipt = held_inputs[1].descriptor_path
        if require_owner_signed:
            try:
                verify_signature(OWNER_SIGNED_TARGET_IDS[self.platform], held_artifact)
            except AppleArtifactGateError as exc:
                self.close()
                raise CollectorError(
                    "Apple artifact is not an owner-signed Apple Distribution candidate"
                ) from exc
            if held_digest != self._held_artifact.rehash():
                self.close()
                raise CollectorError(
                    "owner-signed Apple artifact changed after signature verification"
                )

    def close(self) -> None:
        bundle_custody = getattr(self, "_output_bundle_custody", None)
        if bundle_custody is not None:
            bundle_custody.close(verify=True)
            self._output_bundle_custody = None
        archive = getattr(self, "_held_ios_archive", None)
        if archive is not None:
            archive.close(verify=True)
            self._held_ios_archive = None
        receipts = getattr(self, "_held_ios_receipts", [])
        for receipt in reversed(receipts):
            receipt.close(verify=True)
        self._held_ios_receipts = []
        custody = getattr(self, "_held_artifact", None)
        if custody is not None:
            custody.close(verify=True)
            self._held_artifact = None
        held = getattr(self, "_held_directory", None)
        if held is not None:
            held.cleanup()
            self._held_directory = None
        parent_custody = getattr(self, "_output_parent_custody", None)
        if parent_custody is not None:
            if not getattr(self, "_output_committed", False):
                try:
                    info = self.output_dir.lstat()
                    if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                        shutil.rmtree(self.output_dir)
                except FileNotFoundError:
                    pass
            parent_custody.verify(rehash=True)
            os.unlink(
                parent_custody.path.name,
                dir_fd=parent_custody.parent_descriptor,
            )
            parent_custody.close(verify=False)
            self._output_parent_custody = None

    def _finalize_driver(self) -> None:
        if self._driver_finalized:
            return
        finalized = driver_result(
            self.driver.call("finalize", platform=self.platform),
            "finalize",
            {"restored", "baseline_state_removed"},
        )
        if (
            finalized["restored"] is not True
            or finalized["baseline_state_removed"] is not True
        ):
            raise CollectorError("Apple driver finalization was incomplete")
        self._driver_finalized = True

    def _commit_output(self) -> None:
        if self._output_committed:
            raise CollectorError("Apple evidence output was already committed")
        self._output_parent_custody.verify(rehash=True)
        self._output_bundle_custody = HeldArchiveCustody(self.output_dir)
        self._output_bundle_custody.verify()
        parent_fd = self._output_parent_custody.parent_descriptor
        staging_name = self.output_dir.name
        final_name = self.final_output_dir.name
        try:
            os.stat(final_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise CollectorError("Apple evidence output appeared before commit")
        os.fsync(parent_fd)
        self._output_bundle_custody.prepare_atomic_relocate()
        os.rename(
            staging_name,
            final_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
        self.output_dir = self.final_output_dir
        self._output_bundle_custody.relocate(self.final_output_dir)
        self._output_parent_custody.verify(rehash=True)
        self._output_bundle_custody.verify()
        self._output_committed = True

    def __del__(self) -> None:  # pragma: no cover - process-exit safety net.
        try:
            self.close()
        except Exception:
            pass

    def receipt(self, name: str, contract: str, fields: dict[str, Any]) -> dict[str, str]:
        path = self.output_dir / f"{name}.json"
        value = {
            "schema_version": 1,
            "contract": contract,
            **fields,
            "captured_at_utc": now_utc(),
            "secret_material_redacted": True,
        }
        receipt_hash = exclusive_json(path, value, expected_uid=self.owner_uid)
        self.receipts.append(path)
        self.receipt_hashes[path.name] = receipt_hash
        return {"receipt_path": path.name, "receipt_sha256": receipt_hash}

    def collect(self) -> tuple[pathlib.Path, pathlib.Path]:
        custody = getattr(self, "_held_artifact", None)
        if custody is None:
            raise CollectorError("held Apple artifact custody is unavailable")
        artifact_hash = custody.rehash()
        artifact_read_path = custody.descriptor_path
        if self._held_ios_archive is not None:
            self._held_ios_archive.verify()
        for receipt in self._held_ios_receipts:
            receipt.verify(rehash=True)

        install_call = {"platform": self.platform, "artifact": str(artifact_read_path)}
        if self.ios_route_inventory is not None:
            install_call["route_inventory"] = str(self.ios_route_inventory)
            install_call["ssh_config"] = str(self.ios_ssh_config)
        install = driver_result(
            self.driver.call("clean_install", **install_call),
            "clean_install",
            {
                "source_artifact_sha256",
                "clean_remove_passed",
                "install_passed",
                "installed_identity_sha256",
                "exact_install_source_verified",
                "app_version",
                "build_number",
                "install_method",
                "installed_bundle_id",
                "installed_team_id",
                "installed_designated_requirement_sha256",
                "install_session_sha256",
            },
        )
        expected_method = "macos-signed-package" if self.platform == "macos" else "xcode-devicectl-exact-ipa"
        if (
            install["source_artifact_sha256"] != artifact_hash
            or install["clean_remove_passed"] is not True
            or install["install_passed"] is not True
            or install["exact_install_source_verified"] is not True
            or install["install_method"] != expected_method
            or install["installed_bundle_id"] != "org.winsvpn.app"
            or not re.fullmatch(r"[A-Z0-9]{10}", str(install["installed_team_id"]))
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(install["app_version"]))
            or not str(install["build_number"]).isdigit()
        ):
            raise CollectorError("exact Apple installation was not machine verified")
        for field in (
            "installed_identity_sha256",
            "installed_designated_requirement_sha256",
            "install_session_sha256",
        ):
            require_sha(install[field], field)
        install_fields = {
            "platform": self.platform,
            **{
                key: install[key]
                for key in (
                    "source_artifact_sha256",
                    "installed_identity_sha256",
                    "app_version",
                    "build_number",
                    "exact_install_source_verified",
                    "install_method",
                    "installed_bundle_id",
                    "installed_team_id",
                    "installed_designated_requirement_sha256",
                    "install_session_sha256",
                )
            },
        }
        install_observation = {
            "source_artifact_sha256": artifact_hash,
            "clean_remove_passed": True,
            "install_passed": True,
            "installed_identity_sha256": install["installed_identity_sha256"],
            "exact_install_source_verified": True,
            **self.receipt("install", "winsvpn-install-receipt-v1", install_fields),
        }
        if self.platform == "ios":
            if not zipfile.is_zipfile(artifact_read_path):
                raise CollectorError("OWNER-BLOCKED: current iOS IPA is missing or invalid")
            watch_identity = embedded_watch_identity_from_ipa(artifact_read_path)
            assert self.ios_archive is not None
            assert self.ios_obfuscation_receipt is not None
            assert self.ios_symbol_custody_receipt is not None
            expected_bindings = _ios_release_input_bindings(
                artifact_read_path,
                self.ios_archive,
                self.ios_obfuscation_receipt,
                self.ios_symbol_custody_receipt,
            )
            raw_verification = self.ios_release_evidence_verifier(
                artifact_read_path,
                self.ios_archive,
                self.ios_obfuscation_receipt,
                self.ios_symbol_custody_receipt,
            )
            release_verification = canonical_ios_release_verification(
                raw_verification, expected_bindings=expected_bindings
            )
            watch_verification = release_verification["watch_artifact_verification"]
            if (
                watch_verification["result"]["executable_sha256"]
                != watch_identity["executable_sha256"]
                or watch_verification["result"]["privacy_manifest_sha256"]
                != watch_identity["privacy_info_sha256"]
            ):
                raise CollectorError("Watch verifier output does not bind the embedded executable")
            self.receipt(
                "watch-companion",
                "winsvpn-watch-companion-identity-v2",
                {
                    "platform": self.platform,
                    **watch_identity,
                    "source_artifact_sha256": artifact_hash,
                    "artifact_verification": watch_verification,
                    "release_artifact_verification": release_verification,
                },
            )

        lanes: list[dict[str, Any]] = []
        egresses: set[str] = set()

        def normalize_routes(value: Any, label: str) -> list[dict[str, Any]]:
            if not isinstance(value, list) or not value:
                raise CollectorError(f"{label} is empty")
            result: list[dict[str, Any]] = []
            seen: set[tuple[int, str]] = set()
            for raw in value:
                route = exact(raw, {"protocol", "port", "security"}, label)
                port = route["port"]
                security = route["security"]
                if route["protocol"] != "tcp" or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or security not in {"none", "tls"} or (port, security) in seen:
                    raise CollectorError(f"{label} contains an invalid/duplicate route")
                seen.add((port, security)); result.append(dict(route))
            return sorted(result, key=lambda item: (item["port"], item["security"]))

        def collect_lane(
            lane_id: str,
            kind: str,
            expected_port: int | None = None,
            expected_security: str | None = None,
            expected_direct_port: int | None = None,
            expected_routes: list[dict[str, Any]] | None = None,
        ) -> tuple[dict[str, Any], int, list[dict[str, Any]]]:
            call_values = {"platform": self.platform, "lane_id": lane_id, "kind": kind}
            if expected_port is not None:
                call_values.update({"port": str(expected_port), "security": str(expected_security), "direct_port": str(expected_direct_port)})
            observed = driver_result(
                self.driver.call("lane", **call_values),
                "lane",
                {
                    "lane_id", "kind", "protocol", "port", "security",
                    "actual_direct_port", "advertised_xray_routes",
                    "forcing_blocked_udp_port",
                    "ui_connect_invoked", "ui_disconnect_invoked", "connected_observed",
                    "double_vpn_active", "rx_delta_bytes", "tx_delta_bytes",
                    "protected_egress_sha256", "provider_executable_sha256",
                    "control_state_before_sha256", "control_state_after_sha256",
                    "forcing_applied", "forcing_restored",
                    "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256",
                },
            )
            is_xray = kind in {"xray", "double_vpn_xray"}
            is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
            protocol = "tcp" if is_xray else "udp"
            actual_direct_port = observed["actual_direct_port"]
            if isinstance(actual_direct_port, bool) or not isinstance(actual_direct_port, int) or not 1 <= actual_direct_port <= 65535:
                raise CollectorError(f"{lane_id} runtime direct port is invalid")
            mode_routes = normalize_routes(observed["advertised_xray_routes"], f"{lane_id} advertised routes")
            if is_xray and (actual_direct_port != expected_direct_port or mode_routes != expected_routes):
                raise CollectorError(f"{lane_id} changed its mode-specific baseline config")
            port = expected_port if is_xray else actual_direct_port
            security = expected_security if is_xray else "none"
            if any(observed[key] is not True for key in ("ui_connect_invoked", "ui_disconnect_invoked", "connected_observed")):
                raise CollectorError(f"{lane_id} was not UI driven and machine observed")
            if observed["lane_id"] != lane_id or observed["kind"] != kind or observed["protocol"] != protocol or observed["port"] != port or observed["security"] != security:
                raise CollectorError(f"{lane_id} observation does not match requested route")
            if observed["double_vpn_active"] is not is_double:
                raise CollectorError(f"{lane_id} Double VPN state is wrong")
            if observed["forcing_applied"] is not is_xray or observed["forcing_restored"] is not True:
                raise CollectorError(f"{lane_id} forcing state was not restored")
            if is_xray and observed["forcing_blocked_udp_port"] != actual_direct_port:
                raise CollectorError(f"{lane_id} forcing did not block its mode direct port")
            if not is_xray and observed["forcing_blocked_udp_port"] is not None:
                raise CollectorError(f"{lane_id} unexpectedly reports UDP forcing")
            if observed["control_state_before_sha256"] != observed["control_state_after_sha256"]:
                raise CollectorError(f"{lane_id} control state was not restored")
            for field in ("rx_delta_bytes", "tx_delta_bytes"):
                if not isinstance(observed[field], int) or isinstance(observed[field], bool) or observed[field] < 96:
                    raise CollectorError(f"{lane_id} lacks bidirectional traffic")
            for field in ("protected_egress_sha256", "provider_executable_sha256", "control_state_before_sha256", "control_state_after_sha256", "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256"):
                require_sha(observed[field], f"{lane_id} {field}")
            for field in ("protected_egress_sha256", "provider_executable_sha256"):
                if observed[field] in INVALID_OBSERVATION_DIGESTS:
                    raise CollectorError(f"{lane_id} {field} is an empty/sentinel observation")
            if is_double:
                if observed["double_vpn_core_id_sha256"] in INVALID_OBSERVATION_DIGESTS or observed["double_vpn_exit_slug_sha256"] in INVALID_OBSERVATION_DIGESTS:
                    raise CollectorError(f"{lane_id} lacks real Double VPN identity")
            elif observed["double_vpn_core_id_sha256"] != EMPTY_SHA256 or observed["double_vpn_exit_slug_sha256"] != EMPTY_SHA256:
                raise CollectorError(f"{lane_id} unexpectedly reports Double VPN identity")
            egresses.add(observed["protected_egress_sha256"])
            routes_hash = hashlib.sha256(
                json.dumps(
                    mode_routes, separators=(",", ":"), sort_keys=True
                ).encode()
            ).hexdigest()
            receipt_fields = {
                "platform": self.platform,
                **{key: observed[key] for key in (
                    "lane_id", "kind", "protocol", "port", "security", "double_vpn_active",
                    "provider_executable_sha256", "connected_observed", "rx_delta_bytes", "tx_delta_bytes",
                    "protected_egress_sha256", "control_state_before_sha256", "control_state_after_sha256",
                    "forcing_applied", "forcing_restored", "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256",
                )},
                "runtime_direct_port": actual_direct_port,
                "advertised_xray_routes_sha256": routes_hash,
                "forcing_blocked_udp_port": observed["forcing_blocked_udp_port"],
            }
            lanes.append({
                **{key: observed[key] for key in (
                    "lane_id", "kind", "protocol", "port", "security", "double_vpn_active",
                    "rx_delta_bytes", "tx_delta_bytes", "protected_egress_sha256", "provider_executable_sha256",
                    "control_state_before_sha256", "control_state_after_sha256", "forcing_applied", "forcing_restored",
                    "double_vpn_core_id_sha256", "double_vpn_exit_slug_sha256",
                )},
                "runtime_direct_port": actual_direct_port,
                "advertised_xray_routes_sha256": routes_hash,
                "forcing_blocked_udp_port": observed["forcing_blocked_udp_port"],
                "connected_passed": True,
                **self.receipt(lane_id, "winsvpn-route-observation-v1", receipt_fields),
            })
            return lanes[-1], actual_direct_port, mode_routes

        _, direct_awg_port, normalized_routes = collect_lane("direct-awg", "direct_awg")
        for route in normalized_routes:
            collect_lane(
                f"xray-{route['port']}-{route['security']}", "xray",
                route["port"], route["security"], direct_awg_port, normalized_routes,
            )
        _, double_vpn_direct_port, double_routes = collect_lane(
            "double-direct", "double_vpn_direct"
        )
        for route in double_routes:
            collect_lane(
                f"double-xray-{route['port']}-{route['security']}", "double_vpn_xray",
                route["port"], route["security"], double_vpn_direct_port, double_routes,
            )
        if len(egresses) != 1:
            raise CollectorError("Apple route lanes did not use one selected exit")

        checks: dict[str, Any] = {}
        check_specs = {
            "split": ("winsvpn-split-observation-v1", {"scope", "consumer_per_app_available", "mdm_per_app_only", "selection_applied_by_harness", "selected_scope_bypassed", "ordinary_scope_protected"}),
            "leak": ("winsvpn-leak-observation-v1", {"dns_protected", "ipv4_protected", "ipv6_escape_blocked", "public_canaries_agree"}),
            "network_change": ("winsvpn-network-change-observation-v1", {"change_triggered_by_harness", "pre_change_protected", "post_change_recovered", "post_change_protected"}),
            "teardown": ("winsvpn-teardown-observation-v1", {"disconnect_requested_by_harness", "provider_absent", "protected_routes_absent", "transient_state_absent"}),
            "rollback": ("winsvpn-rollback-observation-v1", {"failure_injected_by_harness", "prior_state_sha256", "restored_state_sha256", "recovery_connect_passed"}),
        }
        for action, (contract, fields) in check_specs.items():
            result = driver_result(self.driver.call(action, platform=self.platform), action, fields)
            values = {key: result[key] for key in fields}
            if action == "split":
                if values != {
                    "scope": APPLE_SPLIT_SCOPE,
                    "consumer_per_app_available": False,
                    "mdm_per_app_only": True,
                    "selection_applied_by_harness": True,
                    "selected_scope_bypassed": True,
                    "ordinary_scope_protected": True,
                }:
                    raise CollectorError("Apple split scope is not truthful destination split")
            elif action == "rollback":
                require_sha(values["prior_state_sha256"], "rollback prior state")
                require_sha(values["restored_state_sha256"], "rollback restored state")
                if values["prior_state_sha256"] != values["restored_state_sha256"] or values["failure_injected_by_harness"] is not True or values["recovery_connect_passed"] is not True:
                    raise CollectorError("rollback did not restore the exact prior state")
            elif any(value is not True for value in values.values()):
                raise CollectorError(f"{action} machine observation failed")
            checks[action] = {**values, **self.receipt(action, contract, values)}

        screenshot = self.output_dir / "map.png"
        map_result = driver_result(
            self.driver.call("capture_map", platform=self.platform, output=str(screenshot)),
            "capture_map",
            {"capture_method", "screenshot_sha256", "radius_label_50_miles_detected", "surrounding_city_labels", "target_marker_detected", "viewport_not_world_zoom"},
        )
        screenshot_bytes = _harden_owner_file(
            screenshot, expected_uid=self.owner_uid, label="Apple map screenshot"
        )
        screenshot_hash = hashlib.sha256(screenshot_bytes).hexdigest()
        if map_result["screenshot_sha256"] != screenshot_hash:
            raise CollectorError("map capture digest does not match the owner-only screenshot")
        if screenshot.is_symlink() or not screenshot.is_file() or sha256_file(screenshot) != map_result["screenshot_sha256"]:
            raise CollectorError("machine map capture is missing or changed")
        expected_capture = "macos-window-capture" if self.platform == "macos" else "xcode-device-ui-capture"
        cities = map_result["surrounding_city_labels"]
        if map_result["capture_method"] != expected_capture or not isinstance(cities, list) or len({str(city).strip().casefold() for city in cities if str(city).strip()}) < 2:
            raise CollectorError("map capture lacks local city semantics")
        for field in ("radius_label_50_miles_detected", "target_marker_detected", "viewport_not_world_zoom"):
            if map_result[field] is not True:
                raise CollectorError(f"map {field} was not detected")
        map_fields = {
            "platform": self.platform,
            "screenshot_sha256": map_result["screenshot_sha256"],
            "capture_method": map_result["capture_method"],
            "radius_label_50_miles_detected": True,
            "surrounding_city_label_count": len({str(city).strip().casefold() for city in cities if str(city).strip()}),
            "target_marker_detected": True,
            "viewport_not_world_zoom": True,
        }
        map_visual = {
            **{key: value for key, value in map_fields.items() if key != "platform"},
            **self.receipt("map", "winsvpn-map-capture-observation-v1", map_fields),
        }

        self._finalize_driver()
        if self._held_ios_archive is not None:
            self._held_ios_archive.verify()
        for receipt in self._held_ios_receipts:
            receipt.verify(rehash=True)
        custody.verify(rehash=True)

        machine = {
            "schema_version": 1,
            "contract": MACHINE_CONTRACT,
            "platform": self.platform,
            "app_version": install["app_version"],
            "build_number": str(install["build_number"]),
            "artifact_sha256": artifact_hash,
            "artifact_size_bytes": custody.size,
            **self.binding,
            "run_id": str(uuid.uuid4()),
            "captured_at_utc": now_utc(),
            "secret_material_redacted": True,
            "install": install_observation,
            "advertised_xray_routes": sorted(normalized_routes, key=lambda item: (item["port"], item["security"])),
            "double_vpn_advertised_xray_routes": double_routes,
            "direct_awg_port": direct_awg_port,
            "double_vpn_direct_port": double_vpn_direct_port,
            "lanes": lanes,
            "split_scope": checks["split"],
            "leak": checks["leak"],
            "network_change": checks["network_change"],
            "teardown": checks["teardown"],
            "rollback": checks["rollback"],
            "map_visual": map_visual,
        }
        machine_path = self.output_dir / f"{self.platform}-machine-evidence.json"
        machine_hash = exclusive_json(
            machine_path, machine, expected_uid=self.owner_uid
        )
        index = {
            "schema_version": 1,
            "contract": "winsvpn-apple-final-evidence-index-v1",
            "platform": self.platform,
            "machine_evidence_sha256": machine_hash,
            "map_screenshot_sha256": screenshot_hash,
            "receipt_sha256": dict(sorted(self.receipt_hashes.items())),
            "producer_contract_sha256": self.binding["producer_contract_sha256"],
            "secret_material_redacted": True,
        }
        exclusive_json(
            self.output_dir / "EVIDENCE_INDEX.json",
            index,
            expected_uid=self.owner_uid,
        )
        validate_owner_only_bundle(
            self.output_dir,
            platform=self.platform,
            repo=pathlib.Path(__file__).resolve().parent.parent,
            expected_uid=self.owner_uid,
        )
        if self._held_ios_archive is not None:
            self._held_ios_archive.verify()
        for receipt in self._held_ios_receipts:
            receipt.verify(rehash=True)
        custody.verify(rehash=True)
        self._commit_output()
        machine_path = self.output_dir / machine_path.name
        screenshot = self.output_dir / screenshot.name
        validate_owner_only_bundle(
            self.output_dir,
            platform=self.platform,
            repo=pathlib.Path(__file__).resolve().parent.parent,
            expected_uid=self.owner_uid,
        )
        return machine_path, screenshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--platform", choices=["macos", "ios"])
    parser.add_argument("--artifact")
    parser.add_argument("--output-dir")
    parser.add_argument("--release-input-index")
    parser.add_argument("--build-receipt")
    parser.add_argument("--ios-route-inventory")
    parser.add_argument("--ios-ssh-config")
    parser.add_argument("--ios-xcarchive")
    parser.add_argument("--ios-obfuscation-receipt")
    parser.add_argument("--ios-symbol-custody-receipt")
    args = parser.parse_args()
    if args.self_test:
        print("APPLE FINAL EVIDENCE COLLECTOR SELF-TEST: protocol module loaded")
        return 0
    if not all((args.platform, args.artifact, args.output_dir, args.release_input_index, args.build_receipt)):
        parser.error("platform, artifact, output directory, release index, and build receipt are required")
    repo = pathlib.Path(__file__).resolve().parent.parent
    driver_path = validate_installed_tools(repo)
    artifact = reject_link_components(pathlib.Path(args.artifact), "Apple artifact", must_exist=True)
    output_dir = reject_link_components(pathlib.Path(args.output_dir), "Apple evidence output", must_exist=False)
    artifacts_root = (repo / ".artifacts").resolve()
    try:
        output_dir.relative_to(artifacts_root)
    except ValueError as exc:
        raise CollectorError("Apple evidence output must stay under repository .artifacts") from exc
    input_binding = release_input_binding(repo, args.platform, args.release_input_index)
    build_binding = build_receipt_binding(repo, args.platform, args.release_input_index, args.build_receipt, artifact)
    ios_route_inventory = (
        reject_link_components(pathlib.Path(args.ios_route_inventory), "iOS route inventory", must_exist=True)
        if args.ios_route_inventory else None
    )
    ios_ssh_config = (
        reject_link_components(pathlib.Path(args.ios_ssh_config), "iOS release SSH config", must_exist=True)
        if args.ios_ssh_config else None
    )
    ios_archive = pathlib.Path(args.ios_xcarchive) if args.ios_xcarchive else None
    ios_obfuscation_receipt = (
        pathlib.Path(args.ios_obfuscation_receipt)
        if args.ios_obfuscation_receipt
        else None
    )
    ios_symbol_custody_receipt = (
        pathlib.Path(args.ios_symbol_custody_receipt)
        if args.ios_symbol_custody_receipt
        else None
    )
    ios_inputs = (
        ios_route_inventory,
        ios_ssh_config,
        ios_archive,
        ios_obfuscation_receipt,
        ios_symbol_custody_receipt,
    )
    if args.platform == "ios" and None in ios_inputs:
        parser.error(
            "physical iOS collection requires route inventory, SSH config, xcarchive, "
            "obfuscation receipt, and symbol-custody receipt"
        )
    if args.platform == "macos" and any(value is not None for value in ios_inputs):
        parser.error("iOS route-control arguments are valid only for iOS")
    binding = {
        "release_input_index_sha256": input_binding.index_sha256,
        "platform_manifest_sha256": input_binding.platform_manifest_sha256,
        "artifact_input_fingerprint_sha256": input_binding.artifact_input_fingerprint_sha256,
        "build_receipt_sha256": build_binding.sha256,
        "producer_contract_sha256": producer_contract_hash(repo, APPLE_PUBLIC_PRODUCER),
    }
    collector = Collector(
        driver=SubprocessDriver(driver_path), platform=args.platform,
        artifact=artifact, output_dir=output_dir, binding=binding,
        ios_route_inventory=ios_route_inventory,
        ios_ssh_config=ios_ssh_config,
        ios_archive=ios_archive,
        ios_obfuscation_receipt=ios_obfuscation_receipt,
        ios_symbol_custody_receipt=ios_symbol_custody_receipt,
    )
    try:
        machine, screenshot = collector.collect()
    except Exception as original:
        try:
            collector._finalize_driver()
        except Exception as cleanup_error:
            collector.close()
            raise CollectorError("Apple evidence failure also failed secure finalization") from cleanup_error
        collector.close()
        raise original
    collector.close()
    print(json.dumps({
        "platform": args.platform,
        "machine_evidence": machine.relative_to(repo).as_posix(),
        "map_screenshot": screenshot.relative_to(repo).as_posix(),
        "secret_material_redacted": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CollectorError as error:
        print(f"APPLE FINAL EVIDENCE COLLECTOR: FAIL: {error}", file=os.sys.stderr)
        raise SystemExit(1)
