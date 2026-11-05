#!/usr/bin/env python3
"""Upload only the hash-pinned Apple release candidates after every release gate passes."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import plistlib
import re
import select
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

from apple_app_store_connect_auth_probe import (
    ProbeError,
    probe as probe_app_store_connect,
    require_issuer_id,
    require_key_id,
    require_private_external_key,
)
from validate_apple_owner_signoff import validate_owner_signoff
import apple_store_listing_metadata as listing
from apple_release_contamination_gate import (
    AppleReleaseContaminationError,
    verify_artifact as verify_release_contamination,
)
from apple_cross_store_artifact_gate import (
    AppleArtifactGateError,
    held_reviewed_watch_verifier_source,
    verify_signature,
    verify_watch_artifact_snapshot,
)


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_APPLE_ID = "6789417002"
EXPECTED_BUNDLE_ID = "org.winsvpn.app"
EXPECTED_PACKET_TUNNEL_BUNDLE_ID = "org.winsvpn.app.PacketTunnel"
EXPECTED_WATCH_BUNDLE_ID = "org.winsvpn.app.watchkitapp"
MANIFEST_PATH = Path("app_store/apple/artifacts/release_candidate.json")
ROLLOUT_PATH = Path("app_store/apple/review/rollout_readiness.json")
SUBMISSION_VALIDATOR = Path("tools/validate_apple_submission_package.py")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
OWNER_SIGNED_TARGET_IDS = {
    "ios": "ios-app-store-ipa",
    "macos": "macos-app-store-pkg",
}
REQUIRED_MACOS_ARCHITECTURES = ("arm64", "x86_64")
MAX_IPA_MEMBERS = 200_000
MAX_IPA_MEMBER_BYTES = 4 * 1024**3
MAX_IPA_EXPANDED_BYTES = 16 * 1024**3
WATCH_ARTIFACT_VERIFIER_SHA256 = (
    "9282c14eb209d3639ba6f50f6d884e6ea809ec62ad04dacdd4225343637baeb2"
)
FIXED_XCRUN = Path("/usr/bin/xcrun")
FIXED_CODESIGN = Path("/usr/bin/codesign")
FIXED_XCODE_ALTOOL = Path(
    "/Applications/Xcode.app/Contents/SharedFrameworks/"
    "ContentDelivery.framework/Versions/A/Resources/altoolShim"
)
PROCESS_TIMEOUT_SECONDS = 300
PROCESS_OUTPUT_LIMIT_BYTES = 1024 * 1024


class UploadGateError(RuntimeError):
    pass


def _descriptor_path(descriptor: int) -> Path:
    root = Path("/dev/fd") if sys.platform == "darwin" else Path("/proc/self/fd")
    path = root / str(descriptor)
    duplicate = -1
    try:
        duplicate = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        named = os.fstat(duplicate)
        held = os.fstat(descriptor)
    except OSError as exc:
        raise UploadGateError("retained Apple descriptor is not addressable") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    if _file_identity(named) != _file_identity(held):
        raise UploadGateError("retained Apple descriptor path is not exact")
    return path


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except Exception:
        pass


def _bounded_process(
    command: list[str],
    *,
    label: str,
    cwd: Path,
    env: dict[str, str],
    pass_fds: tuple[int, ...] = (),
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    output_limit: int = PROCESS_OUTPUT_LIMIT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    if (
        not command
        or any(not isinstance(item, str) or not item for item in command)
        or timeout <= 0
        or output_limit <= 0
    ):
        raise UploadGateError(f"{label} process contract is invalid")
    process: subprocess.Popen[bytes] | None = None
    streams: dict[int, tuple[object, bytearray]] = {}
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout
    alarm_state: tuple[object, tuple[float, float]] | None = None
    try:
        if threading.current_thread() is not threading.main_thread():
            raise UploadGateError(
                f"{label} requires main-thread process-start deadline custody"
            )

        def process_start_timeout(_signum, _frame):
            raise UploadGateError(f"{label} exceeded the process-start time bound")

        alarm_state = (
            signal.getsignal(signal.SIGALRM),
            signal.getitimer(signal.ITIMER_REAL),
        )
        signal.signal(signal.SIGALRM, process_start_timeout)
        signal.setitimer(
            signal.ITIMER_REAL,
            max(0.001, deadline - time.monotonic()),
        )
        try:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                text=False,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
            )
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, alarm_state[0])
            signal.setitimer(signal.ITIMER_REAL, *alarm_state[1])
            alarm_state = None
        assert process.stdout is not None
        assert process.stderr is not None
        for stream, payload in ((process.stdout, stdout), (process.stderr, stderr)):
            descriptor = stream.fileno()
            os.set_blocking(descriptor, False)
            streams[descriptor] = (stream, payload)
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UploadGateError(f"{label} exceeded the time bound")
            readable, _writable, _exceptional = select.select(
                list(streams), [], [], min(0.1, remaining)
            )
            for descriptor in readable:
                stream, payload = streams[descriptor]
                try:
                    chunk = os.read(
                        descriptor,
                        min(65536, output_limit + 1 - len(payload)),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    stream.close()
                    del streams[descriptor]
                    continue
                payload.extend(chunk)
                if len(payload) > output_limit:
                    raise UploadGateError(f"{label} exceeded the output bound")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise UploadGateError(f"{label} exceeded the time bound")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise UploadGateError(f"{label} exceeded the time bound") from exc
        return subprocess.CompletedProcess(
            command, returncode, bytes(stdout), bytes(stderr)
        )
    except UploadGateError:
        if process is not None:
            _kill_process_group(process)
        raise
    except OSError as exc:
        if process is not None:
            _kill_process_group(process)
        raise UploadGateError(f"{label} could not execute") from exc
    finally:
        if alarm_state is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, alarm_state[0])
            signal.setitimer(signal.ITIMER_REAL, *alarm_state[1])
        if process is not None:
            _kill_process_group(process)
        for stream, _payload in list(streams.values()):
            try:
                stream.close()
            except OSError:
                pass


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
    )


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
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


def _authenticate_fixed_executable(path: Path, label: str) -> os.stat_result:
    if not path.is_absolute():
        raise UploadGateError(f"{label} path must be absolute")
    try:
        named = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise UploadGateError(f"{label} is unavailable or symbolic") from exc
    try:
        held = os.fstat(descriptor)
        if (
            not stat.S_ISREG(held.st_mode)
            or named.st_uid != 0
            or held.st_uid != 0
            or named.st_mode & 0o022
            or held.st_mode & 0o022
            or not held.st_mode & stat.S_IXUSR
            or held.st_nlink != 1
            or _file_identity(named) != _file_identity(held)
        ):
            raise UploadGateError(f"{label} executable custody is invalid")
        return held
    finally:
        os.close(descriptor)


def _descriptor_number(path: Path) -> int | None:
    parent = path.parent.as_posix()
    if parent not in {"/dev/fd", "/proc/self/fd"} or not path.name.isdigit():
        return None
    descriptor = int(path.name)
    duplicate = -1
    try:
        held = os.fstat(descriptor)
        duplicate = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        named = os.fstat(duplicate)
    except OSError as exc:
        raise UploadGateError("Apple descriptor path is no longer valid") from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    if _file_identity(held) != _file_identity(named):
        raise UploadGateError("Apple descriptor path changed identity")
    return descriptor


@contextlib.contextmanager
def _authenticated_altool() -> object:
    _authenticate_fixed_executable(FIXED_XCRUN, "fixed xcrun")
    resolved = _bounded_process(
        [str(FIXED_XCRUN), "--find", "altool"],
        label="xcrun altool resolution",
        cwd=Path("/"),
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        timeout=30,
        output_limit=4096,
    )
    if resolved.returncode != 0:
        raise UploadGateError("fixed xcrun could not resolve altool")
    try:
        output = resolved.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise UploadGateError("fixed xcrun returned a non-ASCII altool path") from exc
    if "\n" in output or "\r" in output:
        raise UploadGateError("fixed xcrun returned an ambiguous altool path")
    advertised = Path(output)
    try:
        actual = advertised.resolve(strict=True)
    except OSError as exc:
        raise UploadGateError("resolved altool is unavailable") from exc
    if actual != FIXED_XCODE_ALTOOL:
        raise UploadGateError("xcrun resolved an unreviewed Xcode altool")
    info = _authenticate_fixed_executable(actual, "fixed Xcode altool")
    descriptor = os.open(actual, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    custody = HeldCandidate(
        actual,
        descriptor,
        expected_sha256=file_sha256(actual),
        expected_size=info.st_size,
    )
    try:
        custody.verify(rehash=True)
        _authenticate_fixed_executable(FIXED_CODESIGN, "fixed codesign")
        signature = _bounded_process(
            [
                str(FIXED_CODESIGN),
                "--verify",
                "--strict",
                "--verbose=2",
                str(custody.path),
            ],
            label="Xcode altool signature authentication",
            cwd=Path("/"),
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
            timeout=30,
            output_limit=64 * 1024,
        )
        if signature.returncode != 0:
            raise UploadGateError("fixed Xcode altool signature is invalid")
        custody.verify(rehash=True)
        yield custody
        custody.verify(rehash=True)
    finally:
        custody.close(verify=True)


class HeldCandidate:
    """Retain exact candidate bytes, their name, and every lexical ancestor."""

    def __init__(
        self,
        path: Path,
        descriptor: int,
        *,
        expected_sha256: str,
        expected_size: int,
    ) -> None:
        self.path = path.resolve(strict=True)
        self.descriptor = descriptor
        self.expected_sha256 = expected_sha256
        self.expected_size = expected_size
        self._ancestors: list[tuple[int | None, str, int, tuple[int, ...]]] = []
        self._watch: object | None = None
        self._closed = False
        try:
            parts = self.path.parent.parts
            if not parts or parts[0] != os.sep:
                raise UploadGateError("held Apple candidate path is not absolute")
            directory_flags = (
                os.O_RDONLY
                | os.O_CLOEXEC
                | os.O_NOFOLLOW
                | getattr(os, "O_DIRECTORY", 0)
            )
            current = os.open(os.sep, directory_flags)
            self._ancestors.append(
                (None, "", current, _directory_identity(os.fstat(current)))
            )
            for component in parts[1:]:
                child = os.open(component, directory_flags, dir_fd=current)
                self._ancestors.append(
                    (current, component, child, _directory_identity(os.fstat(child)))
                )
                current = child
            self.parent_descriptor = current
            self.identity = _file_identity(os.fstat(self.descriptor))
            os.set_inheritable(self.descriptor, False)
            self._start_watch()
            self.verify(rehash=True)
        except Exception:
            self.close(verify=False)
            raise

    def __fspath__(self) -> str:
        return os.fspath(self.path)

    def read_bytes(self) -> bytes:
        self.verify(rehash=True)
        payload = bytearray()
        offset = 0
        while offset < self.expected_size:
            block = os.pread(
                self.descriptor, min(1024 * 1024, self.expected_size - offset), offset
            )
            if not block:
                raise UploadGateError("held Apple candidate read was truncated")
            payload.extend(block)
            offset += len(block)
        self.verify(rehash=True)
        return bytes(payload)

    @property
    def descriptor_path(self) -> Path:
        self.verify()
        return _descriptor_path(self.descriptor)

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
        if self._watch is None:
            return
        events = self._watch.control(None, len(self._ancestors) + 1, 0)
        if events:
            raise UploadGateError(
                "held Apple candidate or an ancestor changed while retained"
            )

    def verify(self, *, rehash: bool = False) -> None:
        if self._closed or self.descriptor < 0:
            raise UploadGateError("held Apple candidate custody is closed")
        self._reject_events()
        for parent_fd, name, descriptor, expected in self._ancestors:
            current = os.fstat(descriptor)
            if not stat.S_ISDIR(current.st_mode) or _directory_identity(current) != expected:
                raise UploadGateError("held Apple candidate ancestor changed")
            if parent_fd is not None:
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if _directory_identity(named) != expected:
                    raise UploadGateError("held Apple candidate ancestor was substituted")
        current = os.fstat(self.descriptor)
        named = os.stat(
            self.path.name,
            dir_fd=self.parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_size != self.expected_size
            or _file_identity(current) != self.identity
            or _file_identity(named) != self.identity
        ):
            raise UploadGateError("held Apple candidate was substituted")
        if rehash:
            digest = hashlib.sha256()
            offset = 0
            while offset < self.expected_size:
                block = os.pread(
                    self.descriptor,
                    min(1024 * 1024, self.expected_size - offset),
                    offset,
                )
                if not block:
                    raise UploadGateError("held Apple candidate hash was truncated")
                digest.update(block)
                offset += len(block)
            if os.pread(self.descriptor, 1, offset):
                raise UploadGateError("held Apple candidate grew while retained")
            if digest.hexdigest() != self.expected_sha256:
                raise UploadGateError("held Apple candidate digest changed")
        self._reject_events()

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

    def __enter__(self) -> "HeldCandidate":
        self.verify(rehash=True)
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close(verify=True)

    def __del__(self) -> None:
        try:
            self.close(verify=False)
        except Exception:
            pass


@dataclass(frozen=True)
class Candidate:
    platform: str
    artifact_type: str
    path: Path
    relative_path: str
    size_bytes: int
    sha256: str
    app_version: str
    build_number: str
    custody: HeldCandidate | None = None


@dataclass(frozen=True)
class ArtifactIdentity:
    host_bundle_id: str
    packet_tunnel_bundle_id: str
    host_version: str
    packet_tunnel_version: str
    host_build: str
    packet_tunnel_build: str
    watch_bundle_id: str | None = None
    watch_version: str | None = None
    watch_build: str | None = None


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UploadGateError(f"could not read release file {path.name}") from exc
    if not isinstance(value, dict):
        raise UploadGateError(f"release file {path.name} must contain a JSON object")
    return value


def _verify_watch_manifest_binding(
    verifier_result: dict[str, object], watch_manifest: dict[str, object]
) -> None:
    if (
        verifier_result.get("executable_sha256")
        != watch_manifest.get("executable_sha256")
        or verifier_result.get("privacy_manifest_sha256")
        != watch_manifest.get("privacy_info_sha256")
    ):
        raise UploadGateError(
            "Watch verifier output does not bind the embedded executable/privacy manifest"
        )


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    dir_fd = os.open(path, flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def require_exact_candidate_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise UploadGateError(f"{label} owner-signed artifact is missing") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size <= 0
    ):
        raise UploadGateError(
            f"{label} owner-signed artifact must be a non-empty single-link regular file"
        )
    return info


def require_owner_signed_packaging(
    path: Path,
    platform: str,
    *,
    signature_verifier: Callable[[str, Path], object] = verify_signature,
    gate_path: Path | None = None,
) -> None:
    if platform not in OWNER_SIGNED_TARGET_IDS:
        raise UploadGateError(f"unsupported Apple artifact platform {platform!r}")
    require_exact_candidate_file(path, platform)
    if gate_path is not None and gate_path.is_absolute():
        raise UploadGateError(
            f"{platform} owner-signed artifact gate path must be repository-relative"
        )
    try:
        signature_verifier(
            OWNER_SIGNED_TARGET_IDS[platform], path if gate_path is None else gate_path
        )
    except AppleArtifactGateError as exc:
        raise UploadGateError(
            f"{platform} candidate is not an owner-signed Apple Distribution artifact: {exc}"
        ) from exc


def verify_exported_owner_signed_candidates(
    ios_value: str,
    macos_value: str,
    *,
    root: Path = ROOT,
    signature_verifier: Callable[[str, Path], object] = verify_signature,
) -> None:
    resolved_root = root.resolve()
    candidates: list[tuple[str, str, str]] = (
        ("ios", ios_value, ".ipa"),
        ("macos", macos_value, ".pkg"),
    )
    for platform, value, suffix in candidates:
        raw = Path(value)
        candidate = raw if raw.is_absolute() else root / raw
        require_exact_candidate_file(candidate, platform)
        try:
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(resolved_root)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise UploadGateError(
                f"{platform} owner-signed artifact is missing or outside the project"
            ) from exc
        if resolved.suffix.lower() != suffix:
            raise UploadGateError(f"{platform} owner-signed artifact has the wrong type")
        # The cross-store gate binds artifacts only by repository-relative path.
        require_owner_signed_packaging(
            resolved,
            platform,
            signature_verifier=signature_verifier,
            gate_path=relative,
        )


def _require_safe_ipa_members(archive: zipfile.ZipFile, label: str) -> None:
    members = archive.infolist()
    if not members or len(members) > MAX_IPA_MEMBERS:
        raise UploadGateError(f"{label} ZIP member count is invalid")
    names: set[str] = set()
    expanded = 0
    for member in members:
        raw_name = member.filename
        pure = PurePosixPath(raw_name)
        if (
            not raw_name
            or "\\" in raw_name
            or "\x00" in raw_name
            or pure.is_absolute()
            or any(part in {"", ".", ".."} for part in pure.parts)
        ):
            raise UploadGateError(f"{label} contains an unsafe zip path")
        folded = raw_name.rstrip("/").casefold()
        if not folded or folded in names:
            raise UploadGateError(f"{label} contains duplicate or empty zip paths")
        names.add(folded)
        if member.flag_bits & 0x1:
            raise UploadGateError(f"{label} contains encrypted zip content")
        mode = member.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise UploadGateError(f"{label} must not contain symbolic-link members")
        file_type = stat.S_IFMT(mode)
        if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise UploadGateError(f"{label} contains a special filesystem zip entry")
        if member.file_size < 0 or member.file_size > MAX_IPA_MEMBER_BYTES:
            raise UploadGateError(f"{label} zip member size is invalid")
        expanded += member.file_size
        if expanded > MAX_IPA_EXPANDED_BYTES:
            raise UploadGateError(f"{label} zip expansion limit exceeded")


def _require_manifest_signing(entry: dict[str, object], platform: str) -> None:
    try:
        listing.require_recorded_app_store_signing(entry, platform, required=True)
    except listing.AppleListingGateError as exc:
        raise UploadGateError(str(exc)) from exc


def _require_manifest_watch_companion(entry: dict[str, object]) -> dict[str, object]:
    watch = entry.get("embedded_watchos_companion")
    if not isinstance(watch, dict):
        raise UploadGateError("ios candidate omitted the embedded watchOS companion identity")
    if watch.get("status") != "current_candidate":
        raise UploadGateError(
            "ios embedded watchOS companion is not a current signed candidate"
        )
    if (
        watch.get("bundle_id") != EXPECTED_WATCH_BUNDLE_ID
        or watch.get("companion_bundle_id") != EXPECTED_BUNDLE_ID
        or watch.get("executable") != "WinsWatch"
    ):
        raise UploadGateError("ios embedded watchOS companion identity is not current")
    for key in ("executable_sha256", "privacy_info_sha256"):
        digest = watch.get(key)
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise UploadGateError(
                "ios embedded watchOS companion omitted real signed artifact hashes"
            )
    return watch


def _require_manifest_macos_architecture(entry: dict[str, object]) -> None:
    inventory = entry.get("shipped_architecture_inventory")
    if not isinstance(inventory, dict):
        raise UploadGateError("macos candidate omitted the shipped architecture inventory")
    if inventory.get("required_architectures") != list(REQUIRED_MACOS_ARCHITECTURES):
        raise UploadGateError(
            "macos architecture inventory must require every shipped architecture: arm64, x86_64"
        )
    shipped = inventory.get("shipped")
    if not isinstance(shipped, list) or not shipped:
        raise UploadGateError(
            "macos current candidate must inventory arm64 and x86_64 binaries"
        )
    found: set[str] = set()
    seen_paths: set[str] = set()
    for item in shipped:
        if not isinstance(item, dict):
            raise UploadGateError("macos shipped binary inventory is invalid")
        path = str(item.get("path") or "")
        if not path or path.startswith("/") or ".." in Path(path).parts:
            raise UploadGateError("macos shipped binary path is invalid")
        if path in seen_paths:
            raise UploadGateError(f"macos shipped binary path is duplicated: {path}")
        seen_paths.add(path)
        digest = item.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise UploadGateError(f"macos shipped binary {path} sha256 is invalid")
        size = item.get("size_bytes")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise UploadGateError(f"macos shipped binary {path} size is invalid")
        architectures = item.get("architectures")
        if not isinstance(architectures, list) or not architectures:
            raise UploadGateError(f"macos shipped binary {path} architectures are missing")
        for architecture in architectures:
            if architecture not in REQUIRED_MACOS_ARCHITECTURES:
                raise UploadGateError(
                    f"macos shipped binary {path} has unsupported architecture {architecture!r}"
                )
            found.add(str(architecture))
    missing = [arch for arch in REQUIRED_MACOS_ARCHITECTURES if arch not in found]
    if missing:
        raise UploadGateError("missing shipped macOS architecture: " + ", ".join(missing))


def hold_candidate(
    source: Path, destination: Path, *, expected_sha256: str, expected_size: int
) -> HeldCandidate:
    source_fd = destination_fd = retained_fd = -1
    destination_created = False
    custody: HeldCandidate | None = None
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_size
        ):
            raise UploadGateError("Apple candidate cannot be held as one exact inode")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
        )
        destination_created = True
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(source_fd, min(1024 * 1024, remaining))
            if not block:
                raise UploadGateError("Apple candidate changed while it was held")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise UploadGateError("held Apple candidate write was truncated")
                view = view[written:]
            remaining -= len(block)
        if os.read(source_fd, 1):
            raise UploadGateError("Apple candidate grew while it was held")
        after = os.fstat(source_fd)
        named = source.lstat()
        held = os.fstat(destination_fd)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (before.st_dev, before.st_ino, before.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
            or not stat.S_ISREG(held.st_mode)
            or held.st_nlink != 1
            or held.st_size != expected_size
            or digest.hexdigest() != expected_sha256
        ):
            raise UploadGateError("Apple candidate was stale or substituted while held")
        os.fchmod(destination_fd, 0o400)
        os.fsync(destination_fd)
        _fsync_directory(destination.parent)
        retained_fd = os.open(
            destination, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        owned_descriptor = retained_fd
        retained_fd = -1
        custody = HeldCandidate(
            destination,
            owned_descriptor,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )
        return custody
    except OSError as exc:
        raise UploadGateError("Apple candidate could not be held safely") from exc
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
                or held_info.st_size != expected_size
            ):
                try:
                    os.unlink(destination)
                except OSError:
                    pass


def _plist_identity(payload: bytes, label: str) -> tuple[str, str, str]:
    try:
        value = plistlib.loads(payload)
    except Exception as exc:
        raise UploadGateError(f"{label} is not a valid plist") from exc
    if not isinstance(value, dict):
        raise UploadGateError(f"{label} must contain a plist dictionary")
    fields: list[str] = []
    for key in ("CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"):
        field = value.get(key)
        if not isinstance(field, str) or not field.strip():
            raise UploadGateError(f"{label} is missing {key}")
        fields.append(field.strip())
    return fields[0], fields[1], fields[2]


def _privacy_manifest(
    payload: bytes,
    label: str,
    *,
    require_empty_collection: bool,
) -> None:
    try:
        value = plistlib.loads(payload)
    except Exception as exc:
        raise UploadGateError(f"{label} is not a valid plist") from exc
    if not isinstance(value, dict):
        raise UploadGateError(f"{label} must contain a plist dictionary")
    expected_types = {
        "NSPrivacyTracking": bool,
        "NSPrivacyTrackingDomains": list,
        "NSPrivacyCollectedDataTypes": list,
        "NSPrivacyAccessedAPITypes": list,
    }
    for key, expected_type in expected_types.items():
        if not isinstance(value.get(key), expected_type):
            raise UploadGateError(f"{label} has invalid {key}")
    if value["NSPrivacyTracking"] is not False:
        raise UploadGateError(f"{label} must disable tracking")
    if value["NSPrivacyTrackingDomains"]:
        raise UploadGateError(f"{label} must not list tracking domains")
    if require_empty_collection and value["NSPrivacyCollectedDataTypes"]:
        raise UploadGateError(f"{label} must not declare collected data")


def _zip_member(archive: zipfile.ZipFile, name: str, label: str) -> bytes:
    try:
        return archive.read(name)
    except KeyError as exc:
        raise UploadGateError(f"{label} is missing from the release artifact") from exc


def _ios_archive_identity(artifact_path: Path) -> ArtifactIdentity:
    expected_supported_platform = "iPhoneOS"
    try:
        with zipfile.ZipFile(artifact_path) as archive:
            _require_safe_ipa_members(archive, str(artifact_path))
            archive_names = archive.namelist()
            host_plists = [
                name
                for name in archive_names
                if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", name)
            ]
            if len(host_plists) != 1:
                raise UploadGateError(
                    f"{artifact_path} must contain exactly one top-level app plist"
                )
            host_plist = host_plists[0]
            app_prefix = host_plist[: -len("/Info.plist")]
            packet_prefix = f"{app_prefix}/PlugIns/PacketTunnel.appex"
            host_payload = _zip_member(
                archive, host_plist, f"{artifact_path} host Info.plist"
            )
            packet_payload = _zip_member(
                archive,
                f"{packet_prefix}/Info.plist",
                f"{artifact_path} PacketTunnel Info.plist",
            )
            _privacy_manifest(
                _zip_member(
                    archive,
                    f"{app_prefix}/PrivacyInfo.xcprivacy",
                    f"{artifact_path} host PrivacyInfo.xcprivacy",
                ),
                f"{artifact_path} host PrivacyInfo.xcprivacy",
                require_empty_collection=False,
            )
            _privacy_manifest(
                _zip_member(
                    archive,
                    f"{packet_prefix}/PrivacyInfo.xcprivacy",
                    f"{artifact_path} PacketTunnel PrivacyInfo.xcprivacy",
                ),
                f"{artifact_path} PacketTunnel PrivacyInfo.xcprivacy",
                require_empty_collection=True,
            )

            try:
                host_info = plistlib.loads(host_payload)
            except Exception as exc:
                raise UploadGateError(
                    f"{artifact_path} host Info.plist is not a valid plist"
                ) from exc
            supported = (
                host_info.get("CFBundleSupportedPlatforms")
                if isinstance(host_info, dict)
                else None
            )
            if not isinstance(supported, list) or supported != [expected_supported_platform]:
                raise UploadGateError(
                    f"{artifact_path} host CFBundleSupportedPlatforms must be "
                    f"[{expected_supported_platform!r}]"
                )

            identity = _artifact_identity_from_plists(
                host_payload, packet_payload, artifact_path
            )
            if any(
                re.search(r"(?:^|/)WinsWatch Extension\.appex(?:/|$)", name)
                for name in archive_names
            ):
                raise UploadGateError(
                    f"{artifact_path} contains legacy WinsWatch Extension.appex"
                )
            watch_apps = sorted(
                {
                    match.group(1)
                    for name in archive_names
                    if (
                        match := re.fullmatch(
                            rf"({re.escape(app_prefix)}/Watch/[^/]+\.app)/Info\.plist",
                            name,
                        )
                    )
                }
            )
            if len(watch_apps) != 1:
                raise UploadGateError(
                    f"{artifact_path} must contain exactly one embedded Watch app"
                )
            watch_prefix = watch_apps[0]
            watch_payload = _zip_member(
                archive,
                f"{watch_prefix}/Info.plist",
                f"{artifact_path} Watch Info.plist",
            )
            _privacy_manifest(
                _zip_member(
                    archive,
                    f"{watch_prefix}/PrivacyInfo.xcprivacy",
                    f"{artifact_path} Watch PrivacyInfo.xcprivacy",
                ),
                f"{artifact_path} Watch PrivacyInfo.xcprivacy",
                require_empty_collection=True,
            )
            try:
                watch_info = plistlib.loads(watch_payload)
            except Exception as exc:
                raise UploadGateError(
                    f"{artifact_path} Watch Info.plist is not a valid plist"
                ) from exc
            if not isinstance(watch_info, dict):
                raise UploadGateError(
                    f"{artifact_path} Watch Info.plist must contain a plist dictionary"
                )
            watch_executable = watch_info.get("CFBundleExecutable")
            if not isinstance(watch_executable, str) or not watch_executable.strip():
                raise UploadGateError(
                    f"{artifact_path} Watch Info.plist is missing CFBundleExecutable"
                )
            executable_path = f"{watch_prefix}/{watch_executable.strip()}"
            try:
                executable_info = archive.getinfo(executable_path)
            except KeyError as exc:
                raise UploadGateError(
                    f"{artifact_path} is missing declared Watch executable {executable_path}"
                ) from exc
            if executable_info.is_dir() or executable_info.file_size <= 0:
                raise UploadGateError(
                    f"{artifact_path} declared Watch executable is empty"
                )
    except zipfile.BadZipFile as exc:
        raise UploadGateError(f"{artifact_path} is not a valid iOS IPA ZIP") from exc

    watch_bundle_id, watch_version, watch_build = _plist_identity(
        watch_payload, f"{artifact_path} Watch Info.plist"
    )
    return ArtifactIdentity(
        host_bundle_id=identity.host_bundle_id,
        packet_tunnel_bundle_id=identity.packet_tunnel_bundle_id,
        host_version=identity.host_version,
        packet_tunnel_version=identity.packet_tunnel_version,
        host_build=identity.host_build,
        packet_tunnel_build=identity.packet_tunnel_build,
        watch_bundle_id=watch_bundle_id,
        watch_version=watch_version,
        watch_build=watch_build,
    )


def _artifact_identity_from_plists(
    host_payload: bytes,
    packet_tunnel_payload: bytes,
    artifact_path: Path,
) -> ArtifactIdentity:
    host_bundle_id, host_version, host_build = _plist_identity(
        host_payload, f"{artifact_path} host Info.plist"
    )
    packet_bundle_id, packet_version, packet_build = _plist_identity(
        packet_tunnel_payload, f"{artifact_path} PacketTunnel Info.plist"
    )
    return ArtifactIdentity(
        host_bundle_id=host_bundle_id,
        packet_tunnel_bundle_id=packet_bundle_id,
        host_version=host_version,
        packet_tunnel_version=packet_version,
        host_build=host_build,
        packet_tunnel_build=packet_build,
    )


def _ios_artifact_identity(artifact_path: Path) -> ArtifactIdentity:
    return _ios_archive_identity(artifact_path)


def _macos_artifact_identity(artifact_path: Path) -> ArtifactIdentity:
    pkgutil = Path("/usr/sbin/pkgutil")
    _authenticate_fixed_executable(pkgutil, "fixed pkgutil")
    with tempfile.TemporaryDirectory(prefix="wins-apple-candidate-pkg-") as temp_dir:
        inspect_root = Path(temp_dir)
        expanded = inspect_root / "expanded"
        artifact_descriptor = _descriptor_number(artifact_path)
        completed = _bounded_process(
            [str(pkgutil), "--expand-full", str(artifact_path), str(expanded)],
            label="Apple PKG identity inspection",
            cwd=inspect_root,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
            pass_fds=(() if artifact_descriptor is None else (artifact_descriptor,)),
            timeout=120,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise UploadGateError(
                f"could not expand {artifact_path} for embedded identity audit: {stderr}"
            )
        if expanded.is_symlink() or not expanded.is_dir():
            raise UploadGateError(
                f"{artifact_path} package payload is missing or symbolic"
            )
        try:
            expanded.resolve(strict=True).relative_to(inspect_root.resolve(strict=True))
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise UploadGateError(
                f"{artifact_path} package payload escaped the inspection directory"
            ) from exc
        host_plists: list[Path] = []
        for root, dir_names, file_names in os.walk(expanded, followlinks=False):
            root_path = Path(root)
            if root_path.is_symlink():
                raise UploadGateError(
                    f"{artifact_path} package payload must not contain symbolic links"
                )
            for name in (*dir_names, *file_names):
                child = root_path / name
                if child.is_symlink():
                    raise UploadGateError(
                        f"{artifact_path} package payload must not contain symbolic links"
                    )
            for name in file_names:
                path = root_path / name
                if (
                    path.name == "Info.plist"
                    and path.parent.name == "Contents"
                    and path.parent.parent.suffix == ".app"
                ):
                    host_plists.append(path)
        if len(host_plists) != 1:
            raise UploadGateError(
                f"{artifact_path} must contain exactly one macOS app payload plist"
            )
        host_plist = host_plists[0]
        packet_tunnel_plist = (
            host_plist.parent.parent
            / "Contents"
            / "PlugIns"
            / "PacketTunnel.appex"
            / "Contents"
            / "Info.plist"
        )
        if packet_tunnel_plist.is_symlink() or not packet_tunnel_plist.is_file():
            raise UploadGateError(
                f"{artifact_path} is missing embedded PacketTunnel Info.plist"
            )
        return _artifact_identity_from_plists(
            host_plist.read_bytes(),
            packet_tunnel_plist.read_bytes(),
            artifact_path,
        )


def artifact_identity(platform: str, artifact_path: Path) -> ArtifactIdentity:
    if platform == "ios":
        return _ios_artifact_identity(artifact_path)
    if platform == "macos":
        return _macos_artifact_identity(artifact_path)
    raise UploadGateError(f"unsupported Apple artifact platform {platform!r}")


def verify_embedded_watch_candidate(
    artifact_path: Path, *, artifact_sha256: str, artifact_size: int
) -> dict[str, object]:
    with held_reviewed_watch_verifier_source(
        expected_sha256=WATCH_ARTIFACT_VERIFIER_SHA256
    ) as watch_verifier_source:
        return verify_watch_artifact_snapshot(
            artifact_path,
            artifact_sha256=artifact_sha256,
            artifact_size=artifact_size,
            verifier_source=watch_verifier_source,
            expected_verifier_sha256=WATCH_ARTIFACT_VERIFIER_SHA256,
        )


def candidate_map(
    root: Path = ROOT,
    *,
    allowed_upload_statuses: frozenset[str] = frozenset({"not_uploaded"}),
    identity_reader: Callable[[str, Path], ArtifactIdentity] | None = None,
    contamination_reader: Callable[[Path, str], None] = verify_release_contamination,
    signature_reader: Callable[[Path, str], None] | None = None,
    snapshot_root: Path | None = None,
) -> dict[str, Candidate]:
    manifest = read_json(root / MANIFEST_PATH)
    if manifest.get("schema_version") != 1:
        raise UploadGateError("release candidate manifest must use schema_version 1")
    app_version = manifest.get("app_version")
    build_number_value = manifest.get("build_number")
    if not isinstance(app_version, str) or not app_version.strip():
        raise UploadGateError("release candidate app_version is missing")
    build_number = str(build_number_value or "").strip()
    if not build_number:
        raise UploadGateError("release candidate build_number is missing")
    verify_packaging = identity_reader is None
    verify_watch = identity_reader is None
    if identity_reader is None:
        identity_reader = artifact_identity
    upload_status = manifest.get("upload_status")
    expected_candidate_set_status = {
        "not_uploaded": "complete_local_candidates",
        "uploaded_processed_and_attached": "uploaded_processed_and_attached",
    }.get(upload_status)
    if upload_status not in allowed_upload_statuses:
        allowed = ", ".join(sorted(allowed_upload_statuses))
        raise UploadGateError(
            f"release candidate upload status {upload_status!r} is not allowed; "
            f"expected one of: {allowed}"
        )
    candidate_set_status = manifest.get("candidate_set_status")
    if candidate_set_status != expected_candidate_set_status:
        # The refusal is unchanged -- what changes is that it says WHY. This
        # message used to be "release candidate set status does not match its
        # upload state", which reads like a corrupted or hand-edited manifest.
        # The state it fires on in practice is neither: it is the manifest
        # correctly recording that its own candidates have been invalidated
        # (`preliminary_local_candidates_invalidated_by_shared_revision`) and
        # must be rebuilt. A gate whose message misdescribes the cause sends
        # whoever reads it looking in the wrong place.
        detail = ""
        if candidate_set_status == (
            "preliminary_local_candidates_invalidated_by_shared_revision"
        ):
            detail = (
                " -- the frozen candidates were invalidated by a later shared "
                "revision and must be rebuilt before any upload; this is the "
                "manifest reporting its own staleness, not a corrupt manifest"
            )
        elif candidate_set_status == "no_current_candidate":
            detail = (
                " -- there is no current signed iOS IPA with embedded watchOS "
                "or macOS App Store PKG; both artifacts must be rebuilt with "
                "real Apple Distribution identities before any upload"
            )
        notes = manifest.get("notes")
        raise UploadGateError(
            f"release candidate set status {candidate_set_status!r} does not "
            f"match upload status {upload_status!r} "
            f"(expected {expected_candidate_set_status!r}){detail}."
            + (f" Manifest notes: {notes}" if isinstance(notes, str) else "")
        )

    entries = manifest.get("artifacts")
    if not isinstance(entries, list) or len(entries) != 2:
        raise UploadGateError(
            "release manifest must contain exactly two Apple candidates: "
            "iOS (including watchOS) and macOS"
        )

    expected = {
        "ios": ("ipa", ".ipa"),
        "macos": ("pkg", ".pkg"),
    }
    candidates: dict[str, Candidate] = {}
    resolved_root = root.resolve()
    for entry in entries:
        if not isinstance(entry, dict):
            raise UploadGateError("release candidate entries must be JSON objects")
        platform = entry.get("platform")
        if platform not in expected or platform in candidates:
            raise UploadGateError("release manifest has an unexpected or duplicate platform")
        artifact_type, suffix = expected[platform]
        if entry.get("lane") != "app_store_local" or entry.get("type") != artifact_type:
            raise UploadGateError(f"{platform} candidate is not the frozen App Store-local artifact")
        artifact_status = entry.get("artifact_status")
        if artifact_status != "current_candidate":
            raise UploadGateError(
                f"{platform} candidate is non-final or invalidated "
                f"(artifact_status={artifact_status!r}); rebuild before upload"
            )
        if entry.get("upload_status") != upload_status:
            raise UploadGateError(f"{platform} candidate upload status does not match the set")
        recorded_bundle_ids = (
            entry.get("bundle_id"),
            entry.get("packet_tunnel_bundle_id"),
        )
        expected_bundle_ids = (
            EXPECTED_BUNDLE_ID,
            EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
        )
        if recorded_bundle_ids != expected_bundle_ids:
            raise UploadGateError(
                f"{platform} candidate bundle IDs are not the current universal app IDs"
            )
        recorded_current_bundle_ids = (
            entry.get("expected_current_bundle_id"),
            entry.get("expected_current_packet_tunnel_bundle_id"),
        )
        if recorded_current_bundle_ids != expected_bundle_ids:
            raise UploadGateError(
                f"{platform} candidate expected-current bundle IDs are stale"
            )
        _require_manifest_signing(entry, platform)
        watch_manifest = None
        if platform == "ios":
            watch_manifest = _require_manifest_watch_companion(entry)
        else:
            if "embedded_watchos_companion" in entry:
                raise UploadGateError("macos must not embed a watchOS companion")
            _require_manifest_macos_architecture(entry)

        relative_path = entry.get("path")
        expected_sha = entry.get("sha256")
        expected_size = entry.get("size_bytes")
        if not isinstance(relative_path, str) or Path(relative_path).is_absolute():
            raise UploadGateError(f"{platform} candidate path must be repository-relative")
        if not isinstance(expected_sha, str) or not SHA256_RE.fullmatch(expected_sha):
            raise UploadGateError(f"{platform} candidate SHA-256 is invalid")
        if not isinstance(expected_size, int) or expected_size <= 0:
            raise UploadGateError(f"{platform} candidate size is invalid")

        unresolved_path = root / relative_path
        require_exact_candidate_file(unresolved_path, platform)
        try:
            artifact_path = unresolved_path.resolve(strict=True)
            repository_relative = artifact_path.relative_to(resolved_root)
        except (FileNotFoundError, OSError, ValueError) as exc:
            raise UploadGateError(f"{platform} candidate is missing or outside the project") from exc
        project_artifact = artifact_path
        if not artifact_path.is_file() or artifact_path.suffix.lower() != suffix:
            raise UploadGateError(f"{platform} candidate has the wrong artifact type")
        if artifact_path.stat().st_size != expected_size:
            raise UploadGateError(f"{platform} candidate size no longer matches the manifest")
        if file_sha256(artifact_path) != expected_sha:
            raise UploadGateError(f"{platform} candidate SHA-256 no longer matches the manifest")
        custody: HeldCandidate | None = None
        if snapshot_root is not None:
            snapshot_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            held_path = snapshot_root / f"held-{platform}{suffix}"
            custody = hold_candidate(
                artifact_path,
                held_path,
                expected_sha256=expected_sha,
                expected_size=expected_size,
            )
            artifact_path = custody.path
        if signature_reader is not None:
            signature_reader(artifact_path, platform)
        elif verify_packaging:
            # The cross-store gate binds artifacts only by repository-relative
            # path, so it reads the project file; that file must still carry the
            # manifest digest the held snapshot was taken from.
            require_owner_signed_packaging(
                artifact_path, platform, gate_path=repository_relative
            )
            if file_sha256(project_artifact) != expected_sha:
                raise UploadGateError(
                    f"{platform} candidate SHA-256 changed during the Apple artifact gate"
                )
        if custody is not None:
            custody.verify(rehash=True)
        try:
            contamination_reader(artifact_path, platform)
        except AppleReleaseContaminationError as exc:
            raise UploadGateError(
                f"{platform} candidate failed the Apple release contamination gate: {exc}"
            ) from exc
        if custody is not None:
            custody.verify(rehash=True)

        identity_path = (
            custody.descriptor_path if custody is not None else artifact_path
        )
        identity = identity_reader(platform, identity_path)
        if custody is not None:
            custody.verify(rehash=True)
        actual_bundle_ids = (
            identity.host_bundle_id,
            identity.packet_tunnel_bundle_id,
        )
        if actual_bundle_ids != recorded_bundle_ids:
            raise UploadGateError(
                f"{platform} embedded bundle IDs {actual_bundle_ids!r} do not match "
                f"the manifest {recorded_bundle_ids!r}"
            )
        embedded_versions = {
            identity.host_version,
            identity.packet_tunnel_version,
        }
        if embedded_versions != {app_version}:
            raise UploadGateError(
                f"{platform} embedded versions {sorted(embedded_versions)!r} do not "
                f"match manifest app_version {app_version!r}"
            )
        embedded_builds = {identity.host_build, identity.packet_tunnel_build}
        if embedded_builds != {build_number}:
            raise UploadGateError(
                f"{platform} embedded build numbers {sorted(embedded_builds)!r} do not "
                f"match manifest build_number {build_number!r}"
            )
        if platform == "ios":
            if identity.watch_bundle_id != EXPECTED_WATCH_BUNDLE_ID:
                raise UploadGateError(
                    f"ios embedded Watch bundle ID {identity.watch_bundle_id!r} does not "
                    f"match {EXPECTED_WATCH_BUNDLE_ID!r}"
                )
            if identity.watch_version != app_version:
                raise UploadGateError(
                    f"ios embedded Watch version {identity.watch_version!r} does not "
                    f"match manifest app_version {app_version!r}"
                )
            if identity.watch_build != build_number:
                raise UploadGateError(
                    f"ios embedded Watch build {identity.watch_build!r} does not "
                    f"match manifest build_number {build_number!r}"
                )
            if verify_watch:
                try:
                    verification = verify_embedded_watch_candidate(
                        identity_path,
                        artifact_sha256=expected_sha,
                        artifact_size=expected_size,
                    )
                except AppleArtifactGateError as exc:
                    raise UploadGateError(str(exc)) from exc
                if verification["result"]["executable_sha256"] is None:
                    raise UploadGateError("Watch verifier result is incomplete")
                if watch_manifest is not None:
                    _verify_watch_manifest_binding(
                        verification["result"], watch_manifest
                    )

        candidates[platform] = Candidate(
            platform=platform,
            artifact_type=artifact_type,
            path=artifact_path,
            relative_path=relative_path,
            size_bytes=expected_size,
            sha256=expected_sha,
            app_version=app_version,
            build_number=build_number,
            custody=custody,
        )

    if set(candidates) != set(expected):
        raise UploadGateError(
            "release manifest must contain iOS and macOS candidates"
        )
    return candidates


def close_candidates(
    candidates: dict[str, Candidate], *, verify: bool = True
) -> None:
    error: BaseException | None = None
    for candidate in reversed(list(candidates.values())):
        if candidate.custody is None:
            continue
        try:
            candidate.custody.close(verify=verify)
        except BaseException as exc:
            if error is None:
                error = exc
    if error is not None:
        raise error


@contextlib.contextmanager
def isolated_private_key(key_path: Path, key_id: str):
    key_info = require_exact_candidate_file(key_path, "Apple API key")
    if key_info.st_uid != os.getuid() or key_info.st_mode & 0o077:
        raise UploadGateError("Apple API key must be owner-only")
    expected_sha256 = file_sha256(key_path)
    with tempfile.TemporaryDirectory(
        prefix="wins-apple-upload-key-"
    ) as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        held = hold_candidate(
            key_path,
            root / f"AuthKey_{key_id}.p8",
            expected_sha256=expected_sha256,
            expected_size=key_info.st_size,
        )
        try:
            held.verify(rehash=True)
            yield held, root
            held.verify(rehash=True)
        finally:
            held.close(verify=True)


def require_clean_macos_install(candidates: dict[str, Candidate], root: Path = ROOT) -> None:
    rollout = read_json(root / ROLLOUT_PATH)
    completed = rollout.get("completed_gates")
    blockers = rollout.get("remaining_blockers")
    if not isinstance(completed, dict) or not isinstance(blockers, dict):
        raise UploadGateError("rollout readiness gates are malformed")
    gate = completed.get("macos_pkg_clean_install")
    if not isinstance(gate, dict) or gate.get("status") != "passed":
        raise UploadGateError("the exact macOS PKG clean system-install rehearsal has not passed")
    if gate.get("artifact_sha256") != candidates["macos"].sha256:
        raise UploadGateError("macOS clean-install evidence belongs to a different PKG")
    if "macos_pkg_clean_install" in blockers:
        raise UploadGateError("macOS clean-install blocker is still active")


def run_release_gates(candidates: dict[str, Candidate]) -> tuple[Path, str, str]:
    completed = _bounded_process(
        [sys.executable, str(ROOT / SUBMISSION_VALIDATOR), "--release-ready"],
        label="Apple submission package validation",
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
        timeout=600,
        output_limit=PROCESS_OUTPUT_LIMIT_BYTES,
    )
    if completed.returncode != 0:
        raise UploadGateError("Apple submission package validation failed")
    try:
        validate_owner_signoff(ROOT, require_approved=True)
    except AssertionError as exc:
        raise UploadGateError(str(exc)) from exc
    require_clean_macos_install(candidates)

    key_path = require_private_external_key(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_PATH", "")
    )
    key_id = require_key_id(os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ID", ""))
    issuer_id = require_issuer_id(
        os.environ.get("WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID", "")
    )
    if key_path.name != f"AuthKey_{key_id}.p8":
        raise UploadGateError("authentication key filename does not match its key ID")
    probe_app_store_connect()
    return key_path, key_id, issuer_id


def require_confirmation(label: str, supplied: str | None, expected: str) -> None:
    if supplied != expected:
        raise UploadGateError(f"{label} confirmation does not match the frozen release manifest")


def redacted_output(value: str, secrets: list[str]) -> str:
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise UploadGateError(f"Apple uploader response duplicated key {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> object:
    raise UploadGateError(f"Apple uploader response contains {value}")


def upload_candidate(
    candidate: Candidate,
    key_path: Path,
    key_id: str,
    issuer_id: str,
) -> dict[str, object]:
    if candidate.custody is None:
        raise UploadGateError("Apple upload requires retained candidate custody")
    candidate.custody.verify(rehash=True)
    with isolated_private_key(key_path, key_id) as (held_key, isolated_key_dir):
        env = {
            "API_PRIVATE_KEYS_DIR": str(isolated_key_dir),
            "HOME": "/var/empty",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR": "/private/tmp",
        }
        with _authenticated_altool() as altool:
            assert isinstance(altool, HeldCandidate)
            candidate_path = candidate.custody.descriptor_path
            command = [
                str(altool.descriptor_path),
                "--upload-app",
                "-f",
                str(candidate_path),
                "--api-key",
                key_id,
                "--api-issuer",
                issuer_id,
                "--output-format",
                "json",
            ]
            completed = _bounded_process(
                command,
                label=f"Apple {candidate.platform} candidate upload",
                cwd=ROOT,
                env=env,
                pass_fds=(altool.descriptor, candidate.custody.descriptor),
            )
            altool.verify(rehash=True)
            held_key.verify(rehash=True)
    candidate.custody.verify(rehash=True)
    output_bytes = completed.stdout
    failure_bytes = completed.stderr
    try:
        output = output_bytes.decode("utf-8", "strict")
        failure = failure_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise UploadGateError("Apple uploader returned invalid UTF-8") from exc
    safe_output = redacted_output(
        "\n".join(part for part in (output, failure) if part),
        [str(key_path), str(key_path.parent), key_id, issuer_id],
    ).strip()
    if safe_output:
        print(safe_output)
    if completed.returncode != 0:
        raise UploadGateError(f"Apple rejected the exact {candidate.platform} upload")
    try:
        response = json.loads(
            output,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except json.JSONDecodeError as exc:
        raise UploadGateError("Apple uploader did not return exact JSON") from exc
    if not isinstance(response, dict) or response.get("product-errors") != []:
        raise UploadGateError("Apple uploader response did not confirm a clean transfer")
    response_sha256 = hashlib.sha256(output_bytes).hexdigest()
    candidate.custody.verify(rehash=True)
    transfer_receipt: dict[str, object] = {
        "schema_version": 1,
        "contract": "winsvpn-apple-upload-transfer-receipt-v1",
        "platform": candidate.platform,
        "artifact_type": candidate.artifact_type,
        "candidate_sha256": candidate.sha256,
        "candidate_size_bytes": candidate.size_bytes,
        "app_version": candidate.app_version,
        "build_number": candidate.build_number,
        "response_sha256": response_sha256,
        "product_errors": [],
        "processing_status": "unverified_pending_app_store_connect",
    }
    print(
        f"PASS: Apple upload transfer completed for exact {candidate.platform} candidate "
        f"sha256={candidate.sha256} response_sha256={response_sha256} "
        "processing_status=unverified_pending_app_store_connect"
    )
    return transfer_receipt


def selected_platforms(value: str) -> list[str]:
    if value == "both":
        return ["ios", "macos"]
    return [value]


def run_selftest() -> None:
    with tempfile.TemporaryDirectory(prefix="wins-exact-apple-upload-") as temp_dir:
        root = Path(temp_dir)
        ios_path = root / "build/ios/test.ipa"
        mac_path = root / "build/macos/test.pkg"
        ios_path.parent.mkdir(parents=True)
        mac_path.parent.mkdir(parents=True)
        ios_path.write_bytes(b"exact-ios-candidate")
        mac_path.write_bytes(b"exact-macos-candidate")
        manifest_path = root / MANIFEST_PATH
        manifest_path.parent.mkdir(parents=True)
        entries = []
        version = "1.2.3"
        build = "45"
        for platform, artifact_type, path in (
            ("ios", "ipa", ios_path),
            ("macos", "pkg", mac_path),
        ):
            extra: dict[str, object] = {
                "signing": {
                    "status": "current_candidate",
                    "contract": "apple-distribution",
                    "authority": "Authority=Apple Distribution:",
                    "team_id": listing.TEAM_ID,
                }
            }
            if platform == "ios":
                extra["embedded_watchos_companion"] = {
                    "status": "current_candidate",
                    "bundle_id": EXPECTED_WATCH_BUNDLE_ID,
                    "companion_bundle_id": EXPECTED_BUNDLE_ID,
                    "version": version,
                    "build": build,
                    "executable": "WinsWatch",
                    "executable_sha256": file_sha256(path),
                    "privacy_info_sha256": file_sha256(path),
                }
            else:
                extra["shipped_architecture_inventory"] = {
                    "required_architectures": list(REQUIRED_MACOS_ARCHITECTURES),
                    "shipped": [
                        {
                            "path": "WinsVPN.app/Contents/MacOS/WinsVPN",
                            "sha256": file_sha256(path),
                            "size_bytes": path.stat().st_size,
                            "architectures": list(REQUIRED_MACOS_ARCHITECTURES),
                        }
                    ],
                }
            entries.append(
                {
                    "platform": platform,
                    "lane": "app_store_local",
                    "type": artifact_type,
                    "path": str(path.relative_to(root)),
                    "size_bytes": path.stat().st_size,
                    "sha256": file_sha256(path),
                    "bundle_id": EXPECTED_BUNDLE_ID,
                    "packet_tunnel_bundle_id": EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
                    "expected_current_bundle_id": EXPECTED_BUNDLE_ID,
                    "expected_current_packet_tunnel_bundle_id": (
                        EXPECTED_PACKET_TUNNEL_BUNDLE_ID
                    ),
                    "artifact_status": "current_candidate",
                    "upload_status": "not_uploaded",
                    **extra,
                }
            )
        expected_identity = ArtifactIdentity(
            host_bundle_id=EXPECTED_BUNDLE_ID,
            packet_tunnel_bundle_id=EXPECTED_PACKET_TUNNEL_BUNDLE_ID,
            host_version=version,
            packet_tunnel_version=version,
            host_build=build,
            packet_tunnel_build=build,
            watch_bundle_id=EXPECTED_WATCH_BUNDLE_ID,
            watch_version=version,
            watch_build=build,
        )

        def selftest_identity_reader(
            platform: str, artifact_path: Path
        ) -> ArtifactIdentity:
            if platform not in {"ios", "macos"} or not artifact_path.is_file():
                raise UploadGateError("self-test identity reader received bad input")
            return expected_identity

        def selftest_contamination_reader(
            artifact_path: Path, platform: str
        ) -> None:
            if platform not in {"ios", "macos"} or not artifact_path.is_file():
                raise UploadGateError("self-test contamination reader received bad input")

        manifest_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "app_version": version,
                    "build_number": build,
                    "upload_status": "not_uploaded",
                    "candidate_set_status": "complete_local_candidates",
                    "artifacts": entries,
                }
            ),
            encoding="utf-8",
        )
        candidates = candidate_map(
            root,
            identity_reader=selftest_identity_reader,
            contamination_reader=selftest_contamination_reader,
        )
        if set(candidates) != {"ios", "macos"}:
            raise UploadGateError("self-test did not load all exact candidates")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["upload_status"] = "uploaded_processed_and_attached"
        manifest["candidate_set_status"] = "uploaded_processed_and_attached"
        for entry in manifest["artifacts"]:
            entry["upload_status"] = "uploaded_processed_and_attached"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        candidate_map(
            root,
            allowed_upload_statuses=frozenset(
                {"not_uploaded", "uploaded_processed_and_attached"}
            ),
            identity_reader=selftest_identity_reader,
            contamination_reader=selftest_contamination_reader,
        )
        try:
            candidate_map(
                root,
                identity_reader=selftest_identity_reader,
                contamination_reader=selftest_contamination_reader,
            )
        except UploadGateError as exc:
            if "not allowed" not in str(exc):
                raise
        else:
            raise UploadGateError("self-test allowed uploader reuse after upload")
        ios_path.write_bytes(b"changed-ios-candidate")
        try:
            candidate_map(
                root,
                allowed_upload_statuses=frozenset(
                    {"not_uploaded", "uploaded_processed_and_attached"}
                ),
                identity_reader=selftest_identity_reader,
                contamination_reader=selftest_contamination_reader,
            )
        except UploadGateError as exc:
            if "size" not in str(exc) and "SHA-256" not in str(exc):
                raise
        else:
            raise UploadGateError("self-test accepted a changed release candidate")
        try:
            verify_exported_owner_signed_candidates(
                str(ios_path), str(mac_path), root=root
            )
        except UploadGateError:
            pass
        else:
            raise UploadGateError(
                "self-test accepted unsigned IPA/PKG bytes as owner-signed packaging"
            )
        if redacted_output("key ABC path /secret", ["ABC", "/secret"]) != (
            "key <redacted> path <redacted>"
        ):
            raise UploadGateError("self-test failed to redact authentication values")
    print("PASS: exact Apple candidate uploader self-test")
    print("SUMMARY: 1/1 checks passing")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--platform",
        choices=("both", "ios", "macos"),
        default="both",
    )
    parser.add_argument("--preflight", action="store_true", help="Require every upload gate without uploading.")
    parser.add_argument("--upload", action="store_true", help="Upload the exact selected candidate artifacts.")
    parser.add_argument("--confirm-apple-id")
    parser.add_argument("--confirm-ios-sha256")
    parser.add_argument("--confirm-macos-sha256")
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--print-validated-upload-status",
        action="store_true",
        help="Validate exact local candidate bytes and embedded identity, then print upload_status.",
    )
    parser.add_argument(
        "--verify-owner-signed-packaging",
        nargs=2,
        metavar=("IOS_IPA", "MACOS_PKG"),
        help="Fail closed unless both artifacts are present, exact, and Apple Distribution signed.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.selftest:
            if (
                args.preflight
                or args.upload
                or args.print_validated_upload_status
                or args.verify_owner_signed_packaging
            ):
                raise UploadGateError("--selftest cannot be combined with release actions")
            run_selftest()
            return 0

        if args.verify_owner_signed_packaging:
            if args.preflight or args.upload or args.print_validated_upload_status:
                raise UploadGateError(
                    "--verify-owner-signed-packaging cannot be combined with release actions"
                )
            ios_artifact, macos_artifact = args.verify_owner_signed_packaging
            verify_exported_owner_signed_candidates(ios_artifact, macos_artifact)
            print("PASS: owner-signed iOS IPA and macOS PKG packaging preflight")
            return 0

        try:
            listing.review_current_apple_store_metadata(
                release_ready=bool(
                    args.preflight
                    or args.upload
                    or args.print_validated_upload_status
                )
            )
        except listing.AppleListingGateError as exc:
            raise UploadGateError(str(exc)) from exc

        if args.print_validated_upload_status:
            if args.preflight or args.upload:
                raise UploadGateError(
                    "--print-validated-upload-status cannot be combined with release actions"
                )
            candidate_map(
                allowed_upload_statuses=frozenset(
                    {"not_uploaded", "uploaded_processed_and_attached"}
                )
            )
            manifest = read_json(ROOT / MANIFEST_PATH)
            print(str(manifest["upload_status"]))
            return 0

        with tempfile.TemporaryDirectory(
            prefix="wins-exact-apple-candidates-"
        ) as held, contextlib.ExitStack() as held_stack:
            candidates = candidate_map(snapshot_root=Path(held))
            held_stack.callback(close_candidates, candidates, verify=True)
            platforms = selected_platforms(args.platform)
            for platform in platforms:
                candidate = candidates[platform]
                print(
                    f"PASS: frozen {platform} candidate verified "
                    f"sha256={candidate.sha256} size={candidate.size_bytes}"
                )

            if not args.preflight and not args.upload:
                print("DRY RUN: no Apple release gates were changed and no artifact was uploaded")
                return 0

            require_confirmation("Apple ID", args.confirm_apple_id, EXPECTED_APPLE_ID)
            if "ios" in platforms:
                require_confirmation(
                    "iOS SHA-256", args.confirm_ios_sha256, candidates["ios"].sha256
                )
            if "macos" in platforms:
                require_confirmation(
                    "macOS SHA-256", args.confirm_macos_sha256, candidates["macos"].sha256
                )
            key_path, key_id, issuer_id = run_release_gates(candidates)
            print("PASS: owner, package, clean-install, and App Store Connect gates passed")
            if not args.upload:
                print("PREFLIGHT ONLY: no artifact was uploaded")
                return 0
            for platform in platforms:
                custody = candidates[platform].custody
                if custody is None:
                    raise UploadGateError(
                        f"held {platform} candidate custody is unavailable"
                    )
                custody.verify(rehash=True)
                if custody.expected_sha256 != candidates[platform].sha256:
                    raise UploadGateError(
                        f"held {platform} candidate changed after release preflight"
                    )
                upload_candidate(candidates[platform], key_path, key_id, issuer_id)
        return 0
    except (UploadGateError, ProbeError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
