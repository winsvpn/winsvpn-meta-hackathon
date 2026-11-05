#!/usr/bin/env python3
"""Execute the fixed local proof-driver protocol and capture immutable evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gcp_deployment_inputs as deployment_inputs
import gcp_proof_fleet as fleet
import gcp_proof_live_probe as probe
import gcloud_custody


B64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{32,}={0,2}")
B64URL_BLOB_RE = re.compile(rb"[A-Za-z0-9_-]{32,}={0,2}")
HEX_BLOB_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")
MAX_SECRET_DECODE_DEPTH = 3
MAX_SECRET_CANDIDATES = 64
COLLECTOR_CREDENTIAL_ENV = (
    probe.CREDENTIAL_KIND_ENV,
    probe.CREDENTIAL_PATH_ENV,
    probe.CREDENTIAL_ACCOUNT_ENV,
    probe.CREDENTIAL_PROJECT_ENV,
    deployment_inputs.PYTHON_RUNTIME_RECEIPT_ENV,
    deployment_inputs.REMOTE_PYTHON_RUNTIME_RECEIPT_ENV,
)
COLLECTOR_SOURCE = TOOLS / "gcp_proof_evidence.py"
PROBE_SOURCE = TOOLS / "gcp_proof_live_probe.py"
AUTHENTICATED_PROBE_SHA256 = "ec03a251a383cef6b912365214103d94662f52e152b2c6c3d0c1fd1998ab6580"
MAX_AUTHENTICATED_SOURCE_BYTES = 4 * 1024 * 1024
_PROBE_DESCRIPTOR_BOOTSTRAP = (
    "import hashlib,os,stat,sys;"
    "fd=int(sys.argv[1]);path=sys.argv[2];expected=sys.argv[3];"
    "identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,"
    "s.st_size,s.st_mtime_ns,s.st_ctime_ns);"
    "before=os.fstat(fd);os.lseek(fd,0,os.SEEK_SET);"
    "data=b''.join(iter(lambda:os.read(fd,1048576),b''));after=os.fstat(fd);"
    "assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and "
    "identity(before)==identity(after) and len(data)<=4194304 and "
    "hashlib.sha256(data).hexdigest()==expected;"
    "sys.argv=[path,*sys.argv[4:]];"
    "exec(compile(data,path,'exec'),{'__name__':'__main__','__file__':path})"
)


def _custody_identity(info: os.stat_result) -> tuple[int, ...]:
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


def _effective_user_can_write(info: os.stat_result) -> bool:
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid == os.geteuid():
        return bool(mode & stat.S_IWUSR)
    if info.st_gid in {os.getegid(), *os.getgroups()}:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


@dataclass
class HeldPath:
    path: Path
    descriptor: int
    identity: tuple[int, ...]
    sha256: str
    ancestors: list[tuple[Path, int, tuple[int, ...]]]

    def read_bytes(self) -> bytes:
        position = os.lseek(self.descriptor, 0, os.SEEK_CUR)
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            data = b"".join(iter(lambda: os.read(self.descriptor, 1024 * 1024), b""))
        finally:
            os.lseek(self.descriptor, position, os.SEEK_SET)
        return data

    def assert_current(self) -> None:
        try:
            for path, descriptor, expected in self.ancestors:
                if (
                    _custody_identity(os.fstat(descriptor)) != expected
                    or _custody_identity(path.lstat()) != expected
                ):
                    raise fleet.FleetRefused(
                        f"authenticated execution ancestor changed: {path}"
                    )
            held = os.fstat(self.descriptor)
            current = self.path.lstat()
            data = self.read_bytes()
        except OSError as exc:
            raise fleet.FleetRefused(
                "authenticated execution descriptor or path disappeared"
            ) from exc
        if (
            _custody_identity(held) != self.identity
            or _custody_identity(current) != self.identity
            or hashlib.sha256(data).hexdigest() != self.sha256
        ):
            raise fleet.FleetRefused(
                f"authenticated execution path or bytes changed: {self.path}"
            )

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        for _path, descriptor, _identity in reversed(self.ancestors):
            os.close(descriptor)
        self.ancestors.clear()


def hold_path(
    path: Path,
    *,
    expected_sha256: str,
    label: str,
    executable: bool = False,
    reject_effective_write: bool = False,
) -> HeldPath:
    lexical = Path(os.path.abspath(os.fspath(path)))
    if (
        not lexical.is_absolute()
        or os.path.normpath(os.fspath(lexical)) != os.fspath(lexical)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        raise fleet.FleetRefused(f"{label} custody input is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    ancestors: list[tuple[Path, int, tuple[int, ...]]] = []
    descriptor = -1
    current_path = Path(lexical.anchor)
    current_fd = -1
    try:
        current_fd = os.open(current_path, directory_flags)
        root_info = os.fstat(current_fd)
        if not stat.S_ISDIR(root_info.st_mode):
            raise fleet.FleetRefused(f"{label} root ancestor is unsafe")
        root_identity = _custody_identity(root_info)
        if _custody_identity(current_path.lstat()) != root_identity:
            raise fleet.FleetRefused(f"{label} root ancestor changed during open")
        if reject_effective_write and _effective_user_can_write(root_info):
            raise fleet.FleetRefused(f"{label} has an owner-writable execution ancestor")
        ancestors.append((current_path, current_fd, root_identity))
        for component in lexical.parts[1:-1]:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise fleet.FleetRefused(f"{label} traverses an unsafe ancestor")
            child_fd = os.open(component, directory_flags, dir_fd=current_fd)
            opened = os.fstat(child_fd)
            after = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if not (
                _custody_identity(before)
                == _custody_identity(opened)
                == _custody_identity(after)
            ):
                os.close(child_fd)
                raise fleet.FleetRefused(f"{label} ancestor changed during open")
            current_path /= component
            if reject_effective_write and _effective_user_can_write(opened):
                os.close(child_fd)
                raise fleet.FleetRefused(f"{label} has an owner-writable execution ancestor")
            ancestors.append((current_path, child_fd, _custody_identity(opened)))
            current_fd = child_fd
        leaf = lexical.name
        before = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_AUTHENTICATED_SOURCE_BYTES
            or executable and not before.st_mode & 0o111
            or reject_effective_write and _effective_user_can_write(before)
        ):
            raise fleet.FleetRefused(f"{label} is not one safe retained file")
        descriptor = os.open(leaf, file_flags, dir_fd=current_fd)
        opened = os.fstat(descriptor)
        data = b"".join(iter(lambda: os.read(descriptor, 1024 * 1024), b""))
        os.lseek(descriptor, 0, os.SEEK_SET)
        finished = os.fstat(descriptor)
        after = os.stat(leaf, dir_fd=current_fd, follow_symlinks=False)
        if not (
            _custody_identity(before)
            == _custody_identity(opened)
            == _custody_identity(finished)
            == _custody_identity(after)
        ):
            raise fleet.FleetRefused(f"{label} changed while retained")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected_sha256:
            raise fleet.FleetRefused(f"{label} digest is not authority-authenticated")
        held = HeldPath(
            path=lexical,
            descriptor=descriptor,
            identity=_custody_identity(opened),
            sha256=digest,
            ancestors=ancestors,
        )
        held.assert_current()
        return held
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        for _path, ancestor_fd, _identity in reversed(ancestors):
            os.close(ancestor_fd)
        raise


@dataclass
class AuthenticatedRuntimeClosure:
    collector: HeldPath
    probe: HeldPath
    runtime: HeldPath

    def assert_current(self) -> None:
        self.collector.assert_current()
        self.probe.assert_current()
        self.runtime.assert_current()

    def close(self) -> None:
        self.runtime.close()
        self.probe.close()
        self.collector.close()


def authenticate_runtime_closure(
    runtime_record: Mapping[str, object],
    *,
    collector_expected_sha256: str | None = None,
    probe_loaded_sha256: str | None = None,
) -> AuthenticatedRuntimeClosure:
    expected_collector = collector_expected_sha256
    if expected_collector is None:
        expected_collector = globals().get(
            "__wins_gcp_authenticated_collector_sha256__"
        )
    loaded_probe = probe_loaded_sha256
    if loaded_probe is None:
        loaded_probe = globals().get("__wins_gcp_authenticated_probe_sha256__")
    if (
        type(expected_collector) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_collector) is None
        or loaded_probe != AUTHENTICATED_PROBE_SHA256
    ):
        raise fleet.FleetRefused(
            "owner blocker: authenticated collector/probe descriptor handoff is absent"
        )
    runtime_path = runtime_record.get("executable_path")
    runtime_sha256 = runtime_record.get("executable_sha256")
    if (
        type(runtime_path) is not str
        or type(runtime_sha256) is not str
        or Path(runtime_path).resolve(strict=True) != Path(sys.executable).resolve(strict=True)
    ):
        raise fleet.FleetRefused("authenticated CPython executable is substituted")
    holds: list[HeldPath] = []
    try:
        collector_hold = hold_path(
            COLLECTOR_SOURCE,
            expected_sha256=expected_collector,
            label="GCP evidence collector",
        )
        holds.append(collector_hold)
        probe_hold = hold_path(
            PROBE_SOURCE,
            expected_sha256=AUTHENTICATED_PROBE_SHA256,
            label="GCP live probe",
        )
        holds.append(probe_hold)
        runtime_hold = hold_path(
            Path(runtime_path),
            expected_sha256=runtime_sha256,
            label="authenticated CPython 3.14 executable",
            executable=True,
            reject_effective_write=True,
        )
        holds.append(runtime_hold)
        closure = AuthenticatedRuntimeClosure(
            collector=collector_hold,
            probe=probe_hold,
            runtime=runtime_hold,
        )
        closure.assert_current()
        return closure
    except BaseException:
        for hold in reversed(holds):
            hold.close()
        raise


@dataclass(frozen=True)
class RunResult:
    stdout: bytes
    stderr: bytes
    exit_code: int


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> RunResult: ...


def sanitized_collector_environment() -> dict[str, str]:
    environment = probe.sanitized_child_environment()
    for name in COLLECTOR_CREDENTIAL_ENV:
        value = os.environ.get(name)
        if type(value) is str and value:
            environment[name] = value
    for name in probe.CREDENTIAL_ENV_NAMES:
        if name not in COLLECTOR_CREDENTIAL_ENV:
            environment.pop(name, None)
    return environment


def _try_base64(data: bytes) -> bytes | None:
    text = data.strip()
    if len(text) < 32:
        return None
    padded = text + b"=" * ((4 - len(text) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except ValueError:
        decoded = None
    if decoded:
        return decoded
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except ValueError:
        return None
    return decoded if decoded and decoded != data else None


def _try_hex(data: bytes) -> bytes | None:
    text = data.strip()
    if len(text) < 32 or len(text) % 2:
        return None
    try:
        decoded = bytes.fromhex(text.decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return None
    return decoded if decoded and decoded != data else None


def _json_string_blobs(value: object, blobs: list[bytes]) -> None:
    if len(blobs) >= MAX_SECRET_CANDIDATES:
        return
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if encoded:
            blobs.append(encoded)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                blobs.append(key.encode("utf-8"))
            _json_string_blobs(item, blobs)
        return
    if isinstance(value, list):
        for item in value:
            _json_string_blobs(item, blobs)


def _secret_candidates(data: bytes) -> list[bytes]:
    blobs = [data, data.strip()]
    for encoding in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        encoded = text.encode("utf-8")
        if encoded not in blobs:
            blobs.append(encoded)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            continue
        _json_string_blobs(parsed, blobs)
    for pattern in (B64_BLOB_RE, B64URL_BLOB_RE, HEX_BLOB_RE):
        for match in pattern.findall(data):
            blobs.append(match)
            if len(blobs) >= MAX_SECRET_CANDIDATES:
                return blobs
    return blobs


def contains_reversible_secret(data: bytes) -> bool:
    """Detect plaintext and reversible encodings of credential material. Never emit secrets."""
    pending: list[tuple[bytes, int]] = [(data, 0)]
    seen: set[bytes] = set()
    while pending:
        chunk, depth = pending.pop()
        if chunk in seen or len(chunk) == 0:
            continue
        seen.add(chunk)
        for encoding in ("utf-8", "utf-16-le", "utf-16-be", "latin-1"):
            try:
                text = chunk.decode(encoding)
            except UnicodeDecodeError:
                continue
            if fleet.SECRET_RE.search(text):
                return True
        if depth >= MAX_SECRET_DECODE_DEPTH:
            continue
        for candidate in _secret_candidates(chunk):
            decoded = _try_base64(candidate)
            if decoded is not None:
                pending.append((decoded, depth + 1))
            decoded_hex = _try_hex(candidate)
            if decoded_hex is not None:
                pending.append((decoded_hex, depth + 1))
    return False


_LIVE_RUNTIME_CLOSURE: AuthenticatedRuntimeClosure | None = None


def require_live_collection_custody() -> AuthenticatedRuntimeClosure:
    global _LIVE_RUNTIME_CLOSURE
    probe.require_authenticated_gcloud_credential()
    runtime_record = probe.require_local_python_runtime()
    if _LIVE_RUNTIME_CLOSURE is None:
        _LIVE_RUNTIME_CLOSURE = authenticate_runtime_closure(runtime_record)
    _LIVE_RUNTIME_CLOSURE.assert_current()
    return _LIVE_RUNTIME_CLOSURE


def _is_test_only_runner(runner: Runner) -> bool:
    if type(runner) is SubprocessRunner:
        return False
    if getattr(type(runner), "TEST_ONLY", False) is True:
        return True
    return getattr(runner, "TEST_ONLY", False) is True


class SubprocessRunner:
    """Production runner. It executes an argv vector directly, never a shell."""

    def __init__(self) -> None:
        self._runtime_closure: AuthenticatedRuntimeClosure | None = None

    def bind_authenticated_probe(
        self, closure: AuthenticatedRuntimeClosure
    ) -> None:
        if self._runtime_closure is not None and self._runtime_closure is not closure:
            raise fleet.FleetRefused("collector runner custody is already bound")
        closure.assert_current()
        self._runtime_closure = closure

    def _execution_argv(
        self, argv: Sequence[str]
    ) -> tuple[list[str], tuple[int, ...]]:
        closure = self._runtime_closure
        if closure is None:
            return list(argv), ()
        closure.assert_current()
        if argv[0] != str(PROBE_SOURCE):
            raise fleet.FleetRefused(
                "collector child is not the authority-authenticated live probe"
            )
        return (
            [
                str(closure.runtime.path),
                "-I",
                "-S",
                "-c",
                _PROBE_DESCRIPTOR_BOOTSTRAP,
                str(closure.probe.descriptor),
                str(closure.probe.path),
                closure.probe.sha256,
                *argv[1:],
            ],
            (closure.probe.descriptor,),
        )

    def run(self, argv: Sequence[str], *, timeout_seconds: int) -> RunResult:
        if (
            isinstance(argv, (str, bytes))
            or not argv
            or not all(isinstance(item, str) and item for item in argv)
        ):
            raise fleet.FleetRefused(
                "collector runner requires a non-empty explicit argv vector"
            )
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        streams: dict[str, object] = {}
        succeeded = False
        try:
            execution_argv, pass_fds = self._execution_argv(argv)
            process = subprocess.Popen(
                execution_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=sanitized_collector_environment(),
                bufsize=0,
                close_fds=True,
                pass_fds=pass_fds,
                start_new_session=True,
            )
            if process.stdout is None or process.stderr is None:
                raise fleet.FleetRefused("collector command could not be executed")
            streams = {"stdout": process.stdout, "stderr": process.stderr}
            chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
            totals = {"stdout": 0, "stderr": 0}
            for label, stream in streams.items():
                descriptor = stream.fileno()  # type: ignore[attr-defined]
                os.set_blocking(descriptor, False)
                selector.register(stream, selectors.EVENT_READ, label)

            deadline = time.monotonic() + timeout_seconds
            open_streams = len(streams)
            while open_streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(list(argv), timeout_seconds)
                for key, _mask in selector.select(min(remaining, 0.25)):
                    label = str(key.data)
                    try:
                        chunk = os.read(
                            key.fd,
                            min(
                                65536,
                                fleet.MAX_CAPTURE_BYTES + 1 - totals[label],
                            ),
                        )
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        open_streams -= 1
                        continue
                    chunks[label].append(chunk)
                    totals[label] += len(chunk)
                    if totals[label] > fleet.MAX_CAPTURE_BYTES:
                        raise fleet.FleetRefused(
                            f"collector {label} exceeds the size limit"
                        )

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(list(argv), timeout_seconds)
            exit_code = process.wait(timeout=remaining)
            result = RunResult(
                stdout=b"".join(chunks["stdout"]),
                stderr=b"".join(chunks["stderr"]),
                exit_code=int(exit_code),
            )
            if self._runtime_closure is not None:
                self._runtime_closure.assert_current()
            succeeded = True
            return result
        except subprocess.TimeoutExpired as exc:
            raise fleet.FleetRefused("collector command timed out") from exc
        except OSError as exc:
            raise fleet.FleetRefused("collector command could not be executed") from exc
        finally:
            selector.close()
            for stream in streams.values():
                try:
                    stream.close()  # type: ignore[attr-defined]
                except OSError:
                    pass
            if process is not None and not succeeded:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    try:
                        process.kill()
                    except (OSError, ProcessLookupError):
                        pass
                try:
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if self._runtime_closure is not None:
                self._runtime_closure.assert_current()


def now() -> datetime:
    return datetime.now(timezone.utc)


def private_new_output(path: Path) -> Path:
    output = path.expanduser()
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise fleet.FleetRefused(
            "evidence output must be a new absolute non-symlink path"
        )
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise fleet.FleetRefused(
            "evidence output parent must be an existing non-symlink directory"
        )
    if stat.S_IMODE(output.parent.stat().st_mode) != 0o700:
        raise fleet.FleetRefused("evidence output parent must already be mode 0700")
    return output


def require_executable(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise fleet.FleetRefused("probe driver path must be absolute")
    fleet.executable_ref(candidate, label="probe driver")
    return candidate


def capture_stream(data: bytes, label: str) -> dict[str, object]:
    if not isinstance(data, bytes):
        raise fleet.FleetRefused(f"collector {label} must be raw bytes")
    if len(data) > fleet.MAX_CAPTURE_BYTES:
        raise fleet.FleetRefused(f"collector {label} exceeds the size limit")
    if contains_reversible_secret(data):
        raise fleet.FleetRefused(
            f"collector {label} appears to contain secret material"
        )
    return {
        "encoding": "base64",
        "data": base64.b64encode(data).decode("ascii"),
        "bytes": len(data),
        "sha256": fleet.sha256_bytes(data),
    }


def command_record(
    *,
    command: dict[str, object],
    result: RunResult,
    started: datetime,
    ended: datetime,
    bindings: dict[str, object],
    previous_sha256: str,
) -> dict[str, object]:
    if (
        started.tzinfo is None
        or ended.tzinfo is None
        or started.utcoffset() is None
        or ended.utcoffset() is None
    ):
        raise fleet.FleetRefused(
            "collector clock must return timezone-aware UTC instants"
        )
    if (
        started.utcoffset().total_seconds() != 0
        or ended.utcoffset().total_seconds() != 0
        or ended < started
    ):
        raise fleet.FleetRefused("collector command timestamps are invalid")
    if type(result.exit_code) is not int:
        raise fleet.FleetRefused("collector exit code must be an integer")
    record: dict[str, object] = {
        "kind": fleet.KIND_COMMAND,
        "index": command["index"],
        "action": command["action"],
        "identity": command["identity"],
        "argv": command["argv"],
        "started_utc": fleet.format_utc(started),
        "ended_utc": fleet.format_utc(ended),
        "exit_code": result.exit_code,
        "stdout": capture_stream(result.stdout, "stdout"),
        "stderr": capture_stream(result.stderr, "stderr"),
        "bindings": bindings,
        "previous_sha256": previous_sha256,
    }
    record["record_sha256"] = fleet.command_record_digest(record)
    return record


CONTROL_MUTATIONS = frozenset(
    {"inject-awg-block", "inject-winn3-block", "withdraw-cover"}
)
PROOF_RECEIPT_KINDS = frozenset(
    {
        fleet.KIND_APPLY,
        fleet.KIND_EVIDENCE,
        fleet.KIND_EXECUTION,
        fleet.KIND_PLAN,
        fleet.KIND_RECEIPT,
    }
)


def _cleanup_actions(completed: set[str]) -> list[str]:
    result: list[str] = []
    if "withdraw-cover" in completed and "restore-cover" not in completed:
        result.append("restore-cover")
    if "inject-winn3-block" in completed and "restore-winn3" not in completed:
        result.append("restore-winn3")
    if "inject-awg-block" in completed and "restore-awg" not in completed:
        result.append("restore-awg")
    return result


def require_utc_clock(value: datetime, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        or value.utcoffset().total_seconds() != 0
    ):
        raise fleet.FleetRefused(
            f"{label} must return timezone-aware UTC instants"
        )
    return value


def restore_observation_data(action: str, spec: fleet.FleetSpec) -> dict[str, object]:
    cover = spec.by_role["data-cover"].name
    if action == "restore-awg":
        return {
            "control_id": "negative-awg-block",
            "protocol": "awg",
            "state": "restored",
        }
    if action == "restore-winn3":
        return {
            "control_id": "negative-winn3-block",
            "protocol": "winn3",
            "state": "restored",
        }
    if action == "restore-cover":
        return {
            "control_id": "negative-cover-withdrawn",
            "node": cover,
            "state": "restored",
        }
    raise fleet.FleetRefused(f"collector cleanup action {action} is not a restore")


def require_fresh_three_vm_binding(
    spec: fleet.FleetSpec,
    execution: Mapping[str, object],
) -> None:
    if tuple(item.role for item in spec.instances) != fleet.ROLES:
        raise fleet.FleetRefused(
            "collector proof binding must be the exact three-VM topology"
        )
    if len(set(spec.names)) != 3:
        raise fleet.FleetRefused(
            "control, Winn v3 data, and cover data names must be distinct"
        )
    preflight = execution.get("preflight")
    if not isinstance(preflight, dict):
        raise fleet.FleetRefused("deployment execution preflight is missing")
    instances = preflight.get("instances")
    if not isinstance(instances, dict) or set(instances) != set(fleet.ROLES):
        raise fleet.FleetRefused(
            "deployment execution is not bound to the exact three proof VMs"
        )
    seen_ids: set[str] = set()
    ended = fleet.parse_utc("deployment execution end", execution.get("ended_utc"))
    for role in fleet.ROLES:
        identity = instances[role]
        instance = spec.by_role[role]
        if not isinstance(identity, dict):
            raise fleet.FleetRefused(f"{role} preflight identity is malformed")
        if (
            identity.get("name") != instance.name
            or identity.get("zone") != instance.zone
            or identity.get("machine_type") != instance.machine_type
            or identity.get("project") != spec.project
            or identity.get("role") != role
        ):
            raise fleet.FleetRefused(
                f"{role} inventory is not bound to the fresh proof VM"
            )
        transaction = identity.get("creation_transaction")
        if not isinstance(transaction, dict):
            raise fleet.FleetRefused(
                f"{role} inventory is not bound to a creation transaction"
            )
        created = fleet.parse_creation_timestamp(
            f"{role} inventory creation timestamp",
            transaction.get("creation_timestamp"),
        )
        ident = transaction.get("id")
        if not isinstance(ident, str) or ident in seen_ids:
            raise fleet.FleetRefused(f"{role} creation identity is duplicated")
        seen_ids.add(ident)
        if created > ended + fleet.MAX_CLOCK_SKEW:
            raise fleet.FleetRefused(
                f"{role} creation transaction is not bound to this execution"
            )


def require_candidate_identity(
    execution: Mapping[str, object],
    deploy_refs: Mapping[str, object],
    plan: Mapping[str, object],
) -> None:
    inputs = plan.get("deployment_inputs")
    if not isinstance(inputs, dict):
        raise fleet.FleetRefused("collector plan is missing deployment inputs")
    plan_candidate = inputs.get("candidate_id")
    execution_candidate = execution.get("candidate_id")
    bound_candidate = deploy_refs.get("deployment_candidate_id")
    if (
        not isinstance(plan_candidate, str)
        or execution_candidate != plan_candidate
        or bound_candidate != plan_candidate
    ):
        raise fleet.FleetRefused("collector deployment candidate identity mismatch")
    markers = execution.get("markers")
    if not isinstance(markers, dict) or set(markers) != set(fleet.ROLES):
        raise fleet.FleetRefused("deployment markers are missing or mixed")
    for role in fleet.ROLES:
        marker = markers[role]
        if not isinstance(marker, dict) or marker.get("candidate_id") != plan_candidate:
            raise fleet.FleetRefused(
                f"{role} installation marker is not bound to the candidate"
            )


def require_unique_proof_receipts(
    state_dir: Path,
    *,
    execution_path: Path,
    output: Path,
) -> None:
    canonical = {
        fleet.KIND_PLAN: fleet.PLAN_NAME,
        fleet.KIND_APPLY: fleet.APPLY_NAME,
        fleet.KIND_EXECUTION: fleet.EXECUTION_NAME,
    }
    try:
        names = os.listdir(state_dir)
    except OSError as exc:
        raise fleet.FleetRefused(
            "collector state directory is not readable"
        ) from exc
    for name in names:
        if name.endswith(".sha256") or name.endswith(".tmp"):
            continue
        path = state_dir / name
        try:
            info = path.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            continue
        try:
            payload = json.loads(path.read_bytes().decode("ascii"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        kind = payload.get("kind")
        if kind not in PROOF_RECEIPT_KINDS:
            continue
        if kind == fleet.KIND_EVIDENCE:
            try:
                same_output = path.resolve() == output.expanduser().resolve()
            except OSError:
                same_output = False
            if not same_output:
                raise fleet.FleetRefused(
                    "duplicate or mixed collector evidence receipt"
                )
            continue
        if kind == fleet.KIND_RECEIPT:
            raise fleet.FleetRefused("duplicate or mixed acceptance receipt")
        expected_name = canonical.get(str(kind))
        if expected_name is None:
            raise fleet.FleetRefused("duplicate or mixed proof receipts")
        if name != expected_name:
            raise fleet.FleetRefused("duplicate or mixed proof receipts")
        if kind == fleet.KIND_EXECUTION and path != execution_path:
            raise fleet.FleetRefused("duplicate or mixed deployment execution receipt")


def _marker_only_observation(data: Mapping[str, object]) -> bool:
    if data.get("kind") == fleet.KIND_MARKER:
        return True
    if set(data) <= {"marker", "markers", "marker_updated"}:
        return True
    roles = data.get("roles")
    if isinstance(roles, list) and roles:
        return all(
            isinstance(row, dict)
            and "marker" in row
            and "candidate" not in row
            for row in roles
        )
    return False


def decode_collector_observation(
    *,
    action: str,
    stdout: bytes,
    bindings: Mapping[str, object],
) -> dict[str, object]:
    if contains_reversible_secret(stdout):
        raise fleet.FleetRefused(
            f"collector {action} appears to contain secret material"
        )
    parsed = fleet.strict_json_bytes(f"collector {action} stdout", stdout)
    if not isinstance(parsed, dict):
        raise fleet.FleetRefused("collector command stdout must be one JSON object")
    if parsed.get("kind") == fleet.KIND_MARKER:
        raise fleet.FleetRefused("marker-only collector observation is not proof")
    data = parsed.get("data")
    if not isinstance(data, dict):
        raise fleet.FleetRefused("collector command stdout must be one JSON object")
    if _marker_only_observation(data):
        raise fleet.FleetRefused("marker-only collector observation is not proof")
    expected = fleet.observation_envelope(action, bindings, data)
    if parsed != expected:
        raise fleet.FleetRefused("collector observation identity binding mismatch")
    fleet._assert_no_pass_tokens(data)
    return parsed


def require_command_observation(
    action: str,
    observations: Sequence[Mapping[str, object]],
    *,
    spec: fleet.FleetSpec,
    execution: Mapping[str, object],
    bindings: Mapping[str, object],
    action_windows: Mapping[str, tuple[datetime, datetime]],
) -> None:
    by_action = {str(item["action"]): item["data"] for item in observations}
    if action not in by_action or action not in fleet.COLLECTOR_ACTIONS:
        raise fleet.FleetRefused("collector commands are missing or duplicated")
    data = by_action[action]
    if not isinstance(data, dict):
        raise fleet.FleetRefused(f"collector {action} observation is malformed")
    winn3 = spec.by_role["data-winn3"].name
    cover = spec.by_role["data-cover"].name
    if action == "inventory":
        expected_inventory = fleet.expected_inventory_data(spec)
        expected_names = {item["name"] for item in expected_inventory["instances"]}
        observed_instances = data.get("instances")
        if not isinstance(observed_instances, list) or {
            item.get("name") for item in observed_instances if isinstance(item, dict)
        } != expected_names:
            raise fleet.FleetRefused("collector inventory instance scope mismatch")
        if len(observed_instances) != len(fleet.ROLES):
            raise fleet.FleetRefused(
                "collector inventory is not bound to the exact three proof VMs"
            )
        normalized_instances = []
        seen_roles: list[str] = []
        for observed in observed_instances:
            if not isinstance(observed, dict):
                raise fleet.FleetRefused("collector inventory instance is malformed")
            image_name = observed.get("image_name")
            image_id = observed.get("image_id")
            if (
                not isinstance(image_name, str)
                or not re.fullmatch(r"ubuntu-(minimal-)?2404-[a-z0-9-]+", image_name)
                or not isinstance(image_id, str)
                or not re.fullmatch(r"[0-9]{6,32}", image_id)
            ):
                raise fleet.FleetRefused(
                    "collector inventory boot image identity is invalid"
                )
            role = observed.get("role")
            if role not in fleet.ROLES or role in seen_roles:
                raise fleet.FleetRefused(
                    "collector inventory instance scope mismatch"
                )
            seen_roles.append(str(role))
            identity = execution.get("preflight")
            if not isinstance(identity, dict):
                raise fleet.FleetRefused("deployment execution preflight is missing")
            preflight_instances = identity.get("instances")
            if not isinstance(preflight_instances, dict):
                raise fleet.FleetRefused(
                    "deployment-to-evidence transaction continuity is missing"
                )
            bound = preflight_instances.get(role)
            if not isinstance(bound, dict):
                raise fleet.FleetRefused(
                    "deployment-to-evidence transaction continuity is missing"
                )
            fleet.exact_equal(
                f"{role} inventory name", observed.get("name"), bound.get("name")
            )
            fleet.exact_equal(
                f"{role} inventory zone", observed.get("zone"), bound.get("zone")
            )
            fleet.exact_equal(
                f"{role} inventory machine",
                observed.get("machine_type"),
                bound.get("machine_type"),
            )
            normalized = dict(observed)
            normalized["image_name"] = None
            normalized["image_id"] = None
            normalized_instances.append(normalized)
        if tuple(seen_roles) != fleet.ROLES:
            raise fleet.FleetRefused(
                "collector inventory is not bound to the exact three proof VMs"
            )
        normalized_inventory = dict(data)
        normalized_inventory["instances"] = normalized_instances
        fleet._expect_exact_data("inventory", normalized_inventory, expected_inventory)
        return
    if action == "deployment":
        fleet.validate_deployment_observation(
            spec, data, execution=execution, bindings=bindings
        )
        return
    if action == "route-decision":
        fleet.assert_exact_keys(
            "route-decision observation",
            data,
            {
                "served_carrier",
                "descriptor_node",
                "selected_node",
                "descriptor_sha256",
                "signature_state",
                "canary_state",
            },
        )
        if (
            data
            != {
                "served_carrier": "winn3",
                "descriptor_node": winn3,
                "selected_node": winn3,
                "descriptor_sha256": data.get("descriptor_sha256"),
                "signature_state": "verified",
                "canary_state": "reachable",
            }
            or not isinstance(data.get("descriptor_sha256"), str)
            or not fleet.SHA256_RE.fullmatch(str(data.get("descriptor_sha256")))
        ):
            raise fleet.FleetRefused(
                "collector route-decision does not prove signed Winn v3 node binding"
            )
        return
    if action == "connect-primary":
        fleet.assert_exact_keys(
            "connect-primary observation",
            data,
            {"attempts", "bytes_rx", "bytes_tx", "interface", "status_delta"},
        )
        status_delta = data.get("status_delta")
        if not isinstance(status_delta, dict):
            raise fleet.FleetRefused(
                "collector primary Winn v3 status delta is malformed"
            )
        if (
            data.get("attempts")
            != [{"protocol": "winn3", "node": winn3, "result": "connected"}]
            or type(data.get("bytes_rx")) is not int
            or type(data.get("bytes_tx")) is not int
            or data.get("interface") != "winn3gw0"
            or type(status_delta.get("inner_packets_delivered")) is not int
            or type(status_delta.get("rx_device_writes")) is not int
            or int(data["bytes_rx"]) <= 0
            or int(data["bytes_tx"]) <= 0
            or int(status_delta["inner_packets_delivered"]) <= 0
            or int(status_delta["rx_device_writes"]) <= 0
        ):
            raise fleet.FleetRefused(
                "collector primary observation does not prove Winn v3 carried traffic"
            )
        return
    if action == "connect-cover-awg":
        fleet.assert_exact_keys(
            "connect-cover-awg observation",
            data,
            {"protocol", "node", "result", "latest_handshake_utc"},
        )
        if (data.get("protocol"), data.get("node"), data.get("result")) != (
            "awg",
            cover,
            "connected",
        ):
            raise fleet.FleetRefused(
                "collector AWG observation does not prove cover-node connection"
            )
        handshake = fleet.parse_utc(
            "AWG latest handshake UTC", data.get("latest_handshake_utc")
        )
        window = action_windows[action]
        if not window[0] <= handshake <= window[1]:
            raise fleet.FleetRefused(
                "collector AWG handshake is outside the command window"
            )
        return
    if action == "connect-cover-xray":
        fleet._expect_exact_data(
            action, data, {"protocol": "xray", "node": cover, "result": "connected"}
        )
        return
    if action == "inject-awg-block":
        fleet._expect_exact_data(
            action,
            data,
            {"control_id": "negative-awg-block", "protocol": "awg", "state": "blocked"},
        )
        return
    if action == "probe-awg-block":
        fleet.assert_exact_keys(
            "probe-awg-block observation",
            data,
            {
                "control_id",
                "attempts",
                "attempt_events",
                "awg_interface",
                "xray_bytes_rx",
                "xray_bytes_tx",
            },
        )
        if (
            data.get("control_id") != "negative-awg-block"
            or data.get("attempts")
            != [
                {"protocol": "awg", "node": cover, "result": "blocked"},
                {"protocol": "xray", "node": cover, "result": "connected"},
            ]
            or data.get("awg_interface") != "awg0"
            or type(data.get("xray_bytes_rx")) is not int
            or type(data.get("xray_bytes_tx")) is not int
            or int(data["xray_bytes_rx"]) <= 0
            or int(data["xray_bytes_tx"]) <= 0
        ):
            raise fleet.FleetRefused(
                "AWG negative control did not prove Xray fallback traffic"
            )
        fleet._expect_attempt_events(
            action,
            data["attempt_events"],
            (
                ("awg", cover, "started", "pending"),
                ("awg", cover, "finished", "failed"),
                ("xray", cover, "started", "pending"),
                ("xray", cover, "finished", "connected"),
            ),
            bindings=bindings,
            window=action_windows[action],
        )
        return
    if action == "restore-awg":
        fleet._expect_exact_data(action, data, restore_observation_data(action, spec))
        return
    if action == "inject-winn3-block":
        fleet._expect_exact_data(
            action,
            data,
            {
                "control_id": "negative-winn3-block",
                "protocol": "winn3",
                "state": "blocked",
            },
        )
        return
    if action == "probe-winn3-block":
        fleet._expect_attempts(
            action,
            data,
            [
                {"protocol": "winn3", "node": winn3, "result": "blocked"},
                {"protocol": "awg", "node": cover, "result": "connected"},
            ],
        )
        if data.get("control_id") != "negative-winn3-block":
            raise fleet.FleetRefused("Winn v3 negative-control identity mismatch")
        fleet._expect_attempt_events(
            action,
            data["attempt_events"],
            (
                ("winn3", winn3, "started", "pending"),
                ("winn3", winn3, "finished", "failed"),
                ("awg", cover, "started", "pending"),
                ("awg", cover, "finished", "connected"),
            ),
            bindings=bindings,
            window=action_windows[action],
        )
        return
    if action == "withdraw-cover":
        fleet._expect_exact_data(
            action,
            data,
            {
                "control_id": "negative-cover-withdrawn",
                "node": cover,
                "state": "withdrawn",
            },
        )
        return
    if action == "probe-cover-withdrawn":
        fleet.assert_exact_keys(
            "probe-cover-withdrawn observation",
            data,
            {
                "attempt_events",
                "attempts",
                "control_id",
                "refusal_code",
                "same_node_downgrade_attempts",
            },
        )
        if type(data.get("same_node_downgrade_attempts")) is not int or {
            key: value for key, value in data.items() if key != "attempt_events"
        } != {
            "control_id": "negative-cover-withdrawn",
            "attempts": [{"protocol": "winn3", "node": winn3, "result": "blocked"}],
            "refusal_code": "same_node_downgrade_refused",
            "same_node_downgrade_attempts": 0,
        }:
            raise fleet.FleetRefused(
                "cover-withdrawn observation does not prove fail-closed downgrade refusal"
            )
        fleet._expect_attempt_events(
            action,
            data["attempt_events"],
            (
                ("winn3", winn3, "started", "pending"),
                ("winn3", winn3, "finished", "failed"),
            ),
            bindings=bindings,
            window=action_windows[action],
        )
        fleet._expect_authorized_winn_v1_fallback(spec, by_action)
        return
    if action in {"restore-cover", "restore-winn3"}:
        fleet._expect_exact_data(action, data, restore_observation_data(action, spec))
        return
    if action == "teardown-check":
        fleet._expect_exact_data(
            action,
            data,
            {
                "expected_resources": fleet.resource_identity(spec),
                "observed_resources": fleet.resource_identity(spec),
                "unexpected_targets": [],
                "foreign_resource_ids": [],
                "credential_files_read": [],
                "production_resources_touched": [],
            },
        )
        return
    raise fleet.FleetRefused("collector command is not in the exact proof protocol")


def cleanup_postcondition_error(
    *,
    action: str,
    result: RunResult,
    bindings: Mapping[str, object],
    spec: fleet.FleetSpec,
) -> str | None:
    if type(result.exit_code) is not int or result.exit_code != 0:
        return f"{action}: exited {result.exit_code}"
    try:
        if contains_reversible_secret(result.stdout) or contains_reversible_secret(
            result.stderr
        ):
            raise fleet.FleetRefused(
                "collector cleanup appears to contain secret material"
            )
        observation = decode_collector_observation(
            action=action,
            stdout=result.stdout,
            bindings=bindings,
        )
        fleet._expect_exact_data(
            action, observation["data"], restore_observation_data(action, spec)
        )
    except fleet.FleetRefused as exc:
        return f"{action}: {exc}"
    return None


def _reload_deployment_binding(
    *,
    apply_path: Path,
    spec: fleet.FleetSpec,
    plan_digest: str,
    apply_digest: str,
    plan: Mapping[str, object],
    deploy_refs: Mapping[str, object],
) -> dict[str, object]:
    state_dir = fleet.prepare_state_dir(apply_path.parent, create=False)
    execution_path = fleet.state_paths(state_dir)["execution"]
    execution, execution_digest = fleet.load_deployment_execution(
        execution_path,
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        plan=plan,
        state_dir=state_dir,
        require_passed=True,
    )
    current = fleet.deployment_binding(
        execution_path=execution_path,
        execution=execution,
        execution_digest=execution_digest,
    )
    if current != deploy_refs:
        raise fleet.FleetRefused("collector deployment candidate identity changed")
    require_fresh_three_vm_binding(spec, execution)
    require_candidate_identity(execution, deploy_refs, plan)
    return execution


def collect(
    *,
    plan_path: Path,
    apply_path: Path,
    probe_driver: Path,
    run_id: str,
    session_id: str,
    correlation_id: str,
    output: Path,
    runner: Runner,
    clock: Callable[[], datetime] = now,
    timeout_seconds: int = 600,
) -> tuple[Path, str]:
    output = private_new_output(output)
    probe_driver = require_executable(probe_driver)
    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise fleet.FleetRefused("collector timeout must be between 1 and 3600 seconds")
    plan_path = plan_path.expanduser().absolute()
    apply_path = apply_path.expanduser().absolute()
    if (
        plan_path != fleet.state_paths(apply_path.parent)["plan"].absolute()
        or apply_path.name != fleet.APPLY_NAME
    ):
        raise fleet.FleetRefused(
            "collector plan/apply paths must be the exact shared state pair"
        )
    plan, plan_digest = fleet.load_json_document(plan_path, require_immutable=True)
    spec = fleet.spec_from_plan(plan)
    runner_type = type(runner)
    if runner_type is SubprocessRunner:
        runtime_closure = require_live_collection_custody()
        runner.bind_authenticated_probe(runtime_closure)
        credential = probe.require_authenticated_gcloud_credential(
            expected_project=spec.project
        )
        try:
            gcloud_custody.require_bound_project(credential, spec.project)
        except gcloud_custody.GcloudCustodyError as suc:
            raise fleet.FleetRefused(str(suc)) from suc
    elif _is_test_only_runner(runner):
        pass
    else:
        raise fleet.FleetRefused(gcloud_custody.ARBITRARY_RUNNER)
    _, apply_digest = fleet.load_immutable_apply(
        apply_path, spec, plan_digest, plan
    )
    state_dir = fleet.prepare_state_dir(apply_path.parent, create=False)
    execution_path = fleet.state_paths(state_dir)["execution"]
    execution, execution_digest = fleet.load_deployment_execution(
        execution_path,
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        plan=plan,
        state_dir=state_dir,
        require_passed=True,
    )
    deploy_refs = fleet.deployment_binding(
        execution_path=execution_path,
        execution=execution,
        execution_digest=execution_digest,
    )
    client_release_reference = fleet.verify_client_release_binding_reference(
        plan["client_release_binding"]
    )
    client_ref = client_release_reference["binding"]["artifact"]
    driver_ref = fleet.executable_ref(probe_driver, label="reviewed probe driver")
    bindings = fleet.collector_record_bindings(
        spec=spec,
        plan_digest=plan_digest,
        apply_digest=apply_digest,
        client_release_binding=client_release_reference,
        probe_driver=driver_ref,
        run_id=run_id,
        session_id=session_id,
        correlation_id=correlation_id,
        deployment_execution=deploy_refs["deployment_execution"],
        deployment_candidate_id=deploy_refs["deployment_candidate_id"],
        deployment_manifest_sha256=deploy_refs["deployment_manifest_sha256"],
        deployment_record_chain_sha256=deploy_refs["deployment_record_chain_sha256"],
    )
    commands = fleet.collector_command_specs(probe_driver, spec, bindings)
    if [str(item["action"]) for item in commands] != list(fleet.COLLECTOR_ACTIONS):
        raise fleet.FleetRefused("collector commands are missing or duplicated")
    require_fresh_three_vm_binding(spec, execution)
    require_candidate_identity(execution, deploy_refs, plan)
    require_unique_proof_receipts(
        state_dir, execution_path=execution_path, output=output
    )
    records: list[dict[str, object]] = []
    observations: list[dict[str, object]] = []
    action_windows: dict[str, tuple[datetime, datetime]] = {}
    completed: set[str] = set()
    attempted_controls: set[str] = set()
    previous = "0" * 64
    last_end: datetime | None = None
    window_start: datetime | None = None
    try:
        for command in commands:
            action = str(command["action"])
            if action in CONTROL_MUTATIONS:
                attempted_controls.add(action)
            require_unique_proof_receipts(
                state_dir, execution_path=execution_path, output=output
            )
            execution_now = _reload_deployment_binding(
                apply_path=apply_path,
                spec=spec,
                plan_digest=plan_digest,
                apply_digest=apply_digest,
                plan=plan,
                deploy_refs=deploy_refs,
            )
            if (
                fleet.executable_ref(probe_driver, label="probe driver before command")
                != driver_ref
                or fleet.verify_client_release_binding_reference(
                    client_release_reference
                )
                != client_release_reference
            ):
                raise fleet.FleetRefused(
                    "probe driver or client release binding changed before command execution"
                )
            started = require_utc_clock(clock(), "collector command start")
            if last_end is not None and started < last_end:
                raise fleet.FleetRefused(
                    "collector command timestamps are invalid or reordered"
                )
            if (
                action in CONTROL_MUTATIONS
                and window_start is not None
                and started <= window_start
            ):
                raise fleet.FleetRefused(
                    "collector timestamps are frozen; refusing control mutation"
                )
            result = runner.run(command["argv"], timeout_seconds=timeout_seconds)
            ended = require_utc_clock(clock(), "collector command end")
            if (
                fleet.executable_ref(probe_driver, label="probe driver after command")
                != driver_ref
                or fleet.verify_client_release_binding_reference(
                    client_release_reference
                )
                != client_release_reference
            ):
                raise fleet.FleetRefused(
                    "probe driver or client release binding changed during command execution"
                )
            record = command_record(
                command=command,
                result=result,
                started=started,
                ended=ended,
                bindings=bindings,
                previous_sha256=previous,
            )
            records.append(record)
            if result.exit_code != 0:
                raise fleet.FleetRefused(
                    f"collector command {command['action']} exited {result.exit_code}"
                )
            observation = decode_collector_observation(
                action=action,
                stdout=result.stdout,
                bindings=bindings,
            )
            observations.append(observation)
            action_windows[action] = (started, ended)
            require_command_observation(
                action,
                observations,
                spec=spec,
                execution=execution_now,
                bindings=bindings,
                action_windows=action_windows,
            )
            completed.add(action)
            previous = str(record["record_sha256"])
            last_end = ended
            if window_start is None:
                window_start = started
    except BaseException as original:
        by_action = {str(item["action"]): item for item in commands}
        cleanup_errors: list[str] = []
        for action in _cleanup_actions(completed | attempted_controls):
            try:
                if (
                    fleet.executable_ref(
                        probe_driver, label="probe driver before cleanup"
                    )
                    != driver_ref
                    or fleet.verify_client_release_binding_reference(
                        client_release_reference
                    )
                    != client_release_reference
                ):
                    cleanup_errors.append(
                        f"{action}: driver or client integrity mismatch"
                    )
                    continue
                cleanup_result = runner.run(
                    by_action[action]["argv"], timeout_seconds=timeout_seconds
                )
                error = cleanup_postcondition_error(
                    action=action,
                    result=cleanup_result,
                    bindings=bindings,
                    spec=spec,
                )
                if error:
                    cleanup_errors.append(error)
                if (
                    fleet.executable_ref(
                        probe_driver, label="probe driver after cleanup"
                    )
                    != driver_ref
                    or fleet.verify_client_release_binding_reference(
                        client_release_reference
                    )
                    != client_release_reference
                ):
                    cleanup_errors.append(
                        f"{action}: driver or client changed during cleanup"
                    )
            except BaseException as cleanup_error:
                cleanup_errors.append(f"{action}: {cleanup_error}")
        if cleanup_errors:
            raise fleet.FleetRefused(
                "collector cleanup failed: " + "; ".join(cleanup_errors)
            ) from original
        raise
    generated = require_utc_clock(clock(), "collector generated")
    if not records:
        raise fleet.FleetRefused("collector produced no command records")
    if last_end is not None and generated < last_end:
        raise fleet.FleetRefused("collector command timestamps are invalid")
    payload: dict[str, object] = {
        "kind": fleet.KIND_EVIDENCE,
        "schema_version": fleet.EVIDENCE_SCHEMA_VERSION,
        "generated_utc": fleet.format_utc(generated),
        "fleet_id": fleet.fleet_id_for(spec),
        "plan": fleet.file_ref(plan_path, label="collector plan"),
        "apply": fleet.file_ref(apply_path, label="collector apply"),
        "run_id": bindings["run_id"],
        "session_id": bindings["session_id"],
        "correlation_id": bindings["correlation_id"],
        "window": {
            "started_utc": records[0]["started_utc"],
            "ended_utc": records[-1]["ended_utc"],
        },
        "collector_closure": fleet.collector_closure_ref(),
        "probe_driver": driver_ref,
        "client_release_binding": client_release_reference,
        "client_artifact": client_ref,
        "client_build_identity": client_release_reference["binding"][
            "build_identity"
        ],
        "deployment_execution": deploy_refs["deployment_execution"],
        "deployment_candidate_id": deploy_refs["deployment_candidate_id"],
        "deployment_manifest_sha256": deploy_refs["deployment_manifest_sha256"],
        "deployment_record_chain_sha256": deploy_refs["deployment_record_chain_sha256"],
        "records": records,
        "record_chain_sha256": fleet.record_chain_digest(records),
    }
    fleet.verify_evidence_payload(
        spec,
        plan_digest,
        plan,
        payload,
        expected_apply=apply_path,
        expected_probe_driver=probe_driver,
        expected_run_id=run_id,
        expected_session_id=session_id,
        expected_correlation_id=correlation_id,
    )
    digest = fleet.write_json_document(output, payload, immutable=True)
    return output, digest


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "apply", "probe-driver", "output"):
        result.add_argument(f"--{name}", required=True, type=Path)
    for name in ("run-id", "session-id", "correlation-id"):
        result.add_argument(f"--{name}", required=True)
    result.add_argument("--timeout-seconds", type=int, default=600)
    result.add_argument("--confirm-live-collection", action="store_true")
    return result


def main(argv: list[str] | None = None, *, runner: Runner | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if not args.confirm_live_collection:
            raise fleet.FleetRefused(
                "collector execution requires --confirm-live-collection"
            )
        active_runner: Runner = runner or SubprocessRunner()
        if type(active_runner) is SubprocessRunner:
            require_live_collection_custody()
        elif _is_test_only_runner(active_runner):
            pass
        else:
            raise fleet.FleetRefused(gcloud_custody.ARBITRARY_RUNNER)
        output, digest = collect(
            plan_path=args.plan,
            apply_path=args.apply,
            probe_driver=args.probe_driver,
            run_id=args.run_id,
            session_id=args.session_id,
            correlation_id=args.correlation_id,
            output=args.output,
            runner=active_runner,
            timeout_seconds=args.timeout_seconds,
        )
    except fleet.FleetRefused as exc:
        print(str(exc), file=sys.stderr)
        return fleet.REFUSAL_EXIT
    json.dump(
        {"collected": True, "evidence": str(output), "evidence_sha256": digest},
        sys.stdout,
        sort_keys=True,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
