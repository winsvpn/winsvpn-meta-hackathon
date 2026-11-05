#!/usr/bin/env python3
"""Fail-closed delegator for the local dashboard evidence refresh path.

This module does not reimplement tools/sync_progress.sh. That script already
owns cache refresh, snapshot materialization, the snapshot lock, and the
fail-closed dashboard failure snapshot. Duplicating those steps here would
drift from the owned sync path and weaken it. The coordinator only complements
that script:

- require explicit local repo/config/evidence/snapshot/cache paths
- invoke the owned sync executable one-shot per cycle, with no shell
- keep a coordinator lock distinct from the sync snapshot lock so a bounded
  watch cannot interleave with another coordinator
- bound watch mode with an explicit cycle cap (the shell watch is unbounded)
- on a nonzero sync, invoke dashboard/server.py --failure-snapshot and
  propagate the nonzero status
- keep store_upload_authorized hard-off
- refuse Git, GitHub, network, sign, upload, and deploy actions

It never fabricates receipts or success snapshots.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SYNC_EXECUTABLE = ROOT / "tools" / "sync_progress.sh"
DEFAULT_DASHBOARD_SERVER = ROOT / "dashboard" / "server.py"
STORE_UPLOAD_AUTHORIZED = False
EX_USAGE = 64
EX_TEMPFAIL = 75
EX_NOEXEC = 127
MIN_WATCH_SECONDS = 2
MAX_WATCH_SECONDS = 60
MAX_CYCLES = 60
LOCK_SUFFIX = ".coordinator.lock"
PID_NAME = "pid"
STORE_UPLOAD_KEY = "store_upload_authorized"
AUTHORIZED_ENV = "WINSVPN_STORE_UPLOAD_AUTHORIZED"
FORBIDDEN_COMMANDS = frozenset(
    {
        "aws",
        "codesign",
        "curl",
        "gcloud",
        "gh",
        "git",
        "gpg",
        "gsutil",
        "rsync",
        "scp",
        "signtool",
        "ssh",
        "wget",
        "xcrun",
    }
)
FORBIDDEN_FLAG_PREFIXES = (
    "--deploy",
    "--github",
    "--network",
    "--sign",
    "--upload",
)
TRUTHY = frozenset({"1", "on", "true", "yes"})


class CoordinatorUsageError(ValueError):
    """Caller arguments cannot be executed fail-closed."""


def local_sync_argv(sync_executable: Path) -> list[str]:
    """Return the one-shot argv for the owned local sync executable.

    tools/sync_progress.sh rejects unexpected flags and reads explicit paths
    from WINSVPN_DASHBOARD_* environment variables. Extra argv here would break
    that owned path, so the child argv is the executable only.
    """

    return [str(sync_executable)]


def failure_snapshot_argv(
    python_bin: Path, dashboard_server: Path, snapshot: Path
) -> list[str]:
    return [
        str(python_bin),
        str(dashboard_server),
        "--failure-snapshot",
        str(snapshot),
    ]


def dashboard_environment(
    repo_root: Path,
    config: Path,
    evidence_root: Path,
    snapshot: Path,
    cache: Path,
    python_bin: Path,
    source_env: dict[str, str] | None = None,
) -> dict[str, str]:
    env = dict(source_env if source_env is not None else os.environ)
    env["WINSVPN_DASHBOARD_REPO_ROOT"] = str(repo_root)
    env["WINSVPN_DASHBOARD_CONFIG"] = str(config)
    env["WINSVPN_DASHBOARD_EVIDENCE_DIR"] = str(evidence_root)
    env["WINSVPN_DASHBOARD_SNAPSHOT"] = str(snapshot)
    env["WINSVPN_DASHBOARD_CROSS_STORE_CACHE"] = str(cache)
    env["WINSVPN_DASHBOARD_PYTHON"] = str(python_bin)
    env[AUTHORIZED_ENV] = "false"
    return env


def coordinator_lock_dir(snapshot: Path) -> Path:
    return Path(str(snapshot) + LOCK_SUFFIX)


def _command_name(token: str) -> str:
    return Path(token).name.lower()


def reject_forbidden_argv(argv: list[str]) -> None:
    if not argv:
        raise CoordinatorUsageError("child argv is empty")
    for token in argv:
        name = _command_name(token)
        if name in FORBIDDEN_COMMANDS or name.replace(".exe", "") in FORBIDDEN_COMMANDS:
            raise CoordinatorUsageError(
                f"refused external command {token!r}"
            )
        lowered = token.lower()
        for prefix in FORBIDDEN_FLAG_PREFIXES:
            if lowered == prefix or lowered.startswith(prefix + "="):
                raise CoordinatorUsageError(
                    f"refused external action flag {token!r}"
                )


def _explicit_local_path(value: str, label: str) -> Path:
    path = Path(value)
    rendered = path.as_posix()
    if not path.is_absolute() or rendered.startswith("//") or "://" in rendered:
        raise CoordinatorUsageError(f"{label} must be an absolute local path")
    if any(part == "" or part == "." or part == ".." for part in path.parts[1:]):
        raise CoordinatorUsageError(f"{label} must be an explicit local path")
    return path


def _reject_symlink(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CoordinatorUsageError(f"{label} is not usable: {exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise CoordinatorUsageError(f"{label} must not be a symlink")


def _require_directory(path: Path, label: str) -> Path:
    _reject_symlink(path, label)
    if not path.is_dir():
        raise CoordinatorUsageError(f"{label} must be an existing directory")
    return path


def _require_regular_file(
    path: Path, label: str, *, executable: bool, allow_symlink: bool = False
) -> Path:
    if not allow_symlink:
        _reject_symlink(path, label)
    elif path.is_symlink():
        try:
            target = path.resolve()
        except OSError as exc:
            raise CoordinatorUsageError(f"{label} is not usable: {exc}") from exc
        if not target.is_file():
            raise CoordinatorUsageError(f"{label} must be an existing regular file")
    if not path.is_file():
        raise CoordinatorUsageError(f"{label} must be an existing regular file")
    if executable and not os.access(path, os.X_OK):
        raise CoordinatorUsageError(f"{label} must be executable")
    return path


def _authorization_requested(env: dict[str, str]) -> bool:
    return env.get(AUTHORIZED_ENV, "").strip().lower() in TRUTHY


def _upload_authorized_values(payload: object) -> list[object]:
    found: list[object] = []
    if isinstance(payload, dict):
        if STORE_UPLOAD_KEY in payload:
            found.append(payload[STORE_UPLOAD_KEY])
        for value in payload.values():
            found.extend(_upload_authorized_values(value))
    elif isinstance(payload, list):
        for item in payload:
            found.extend(_upload_authorized_values(item))
    return found


def reject_authorized_snapshot(snapshot: Path) -> None:
    if not snapshot.is_file() or snapshot.is_symlink():
        return
    try:
        payload = json.loads(snapshot.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoordinatorUsageError(
            f"snapshot is not usable after sync: {exc}"
        ) from exc
    values = _upload_authorized_values(payload)
    if not values or any(item is not False for item in values):
        raise CoordinatorUsageError(
            "store_upload_authorized stays hard-off"
        )


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CoordinatorUsageError(message)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = _ArgumentParser(
        description=(
            "Fail-closed delegator for tools/sync_progress.sh. "
            "It does not reimplement dashboard snapshot materialization."
        )
    )
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--evidence-root", required=True)
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument(
        "--sync-executable",
        default=str(DEFAULT_SYNC_EXECUTABLE),
    )
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument(
        "--dashboard-server",
        default=str(DEFAULT_DASHBOARD_SERVER),
    )
    parser.add_argument(
        "--watch",
        nargs="?",
        const=5,
        default=0,
    )
    parser.add_argument("--cycles", default=None)
    args, unknown = parser.parse_known_args(argv)
    if unknown:
        raise CoordinatorUsageError(
            "unexpected arguments: " + " ".join(unknown)
        )
    return args


def load_request(
    argv: list[str] | None,
    source_env: dict[str, str] | None = None,
) -> argparse.Namespace:
    env = dict(source_env if source_env is not None else os.environ)
    if STORE_UPLOAD_AUTHORIZED is not False or _authorization_requested(env):
        raise CoordinatorUsageError("store_upload_authorized stays hard-off")
    raw = parse_args(argv)
    repo_root = _require_directory(
        _explicit_local_path(str(raw.repo_root), "--repo-root"),
        "--repo-root",
    )
    config = _require_regular_file(
        _explicit_local_path(str(raw.config), "--config"),
        "--config",
        executable=False,
    )
    evidence_root = _require_directory(
        _explicit_local_path(str(raw.evidence_root), "--evidence-root"),
        "--evidence-root",
    )
    snapshot = _explicit_local_path(str(raw.snapshot), "--snapshot")
    cache = _explicit_local_path(str(raw.cache), "--cache")
    if snapshot.exists():
        _reject_symlink(snapshot, "--snapshot")
        if snapshot.is_dir():
            raise CoordinatorUsageError("--snapshot must not be a directory")
    if cache.exists():
        _reject_symlink(cache, "--cache")
        if cache.is_dir():
            raise CoordinatorUsageError("--cache must not be a directory")
    sync_executable = _require_regular_file(
        _explicit_local_path(str(raw.sync_executable), "--sync-executable"),
        "--sync-executable",
        executable=True,
    )
    python_bin = _require_regular_file(
        _explicit_local_path(str(raw.python), "--python"),
        "--python",
        executable=True,
        allow_symlink=True,
    )
    dashboard_server = _require_regular_file(
        _explicit_local_path(str(raw.dashboard_server), "--dashboard-server"),
        "--dashboard-server",
        executable=False,
    )
    try:
        watch_seconds = int(raw.watch)
        cycles = 1 if raw.cycles is None else int(raw.cycles)
    except (TypeError, ValueError) as exc:
        raise CoordinatorUsageError(
            "watch interval must be 2 through 60 seconds"
        ) from exc
    if raw.cycles is None and watch_seconds != 0:
        raise CoordinatorUsageError(
            "watch mode requires --cycles 1 through 60"
        )
    if raw.cycles is not None and watch_seconds == 0 and cycles != 1:
        raise CoordinatorUsageError("one-shot mode allows only --cycles 1")
    if watch_seconds != 0 and (
        watch_seconds < MIN_WATCH_SECONDS or watch_seconds > MAX_WATCH_SECONDS
    ):
        raise CoordinatorUsageError(
            "watch interval must be 2 through 60 seconds"
        )
    if cycles < 1 or cycles > MAX_CYCLES:
        raise CoordinatorUsageError("cycles must be 1 through 60")
    reject_forbidden_argv(local_sync_argv(sync_executable))
    reject_forbidden_argv(
        failure_snapshot_argv(python_bin, dashboard_server, snapshot)
    )
    raw.repo_root = repo_root
    raw.config = config
    raw.evidence_root = evidence_root
    raw.snapshot = snapshot
    raw.cache = cache
    raw.sync_executable = sync_executable
    raw.python = python_bin
    raw.dashboard_server = dashboard_server
    raw.watch = watch_seconds
    raw.cycles = cycles
    raw.environment = dashboard_environment(
        repo_root,
        config,
        evidence_root,
        snapshot,
        cache,
        python_bin,
        source_env=env,
    )
    return raw


def _run_local(argv: list[str], cwd: Path, env: dict[str, str]) -> int:
    reject_forbidden_argv(argv)
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            shell=False,
            check=False,
            close_fds=True,
        )
    except OSError:
        return EX_NOEXEC
    return int(completed.returncode)


def _prepare_output_parents(snapshot: Path, cache: Path) -> None:
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    cache.parent.mkdir(parents=True, exist_ok=True)


def _write_pid(lock_dir: Path) -> None:
    pid_path = lock_dir / PID_NAME
    fd = os.open(
        pid_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
    finally:
        os.close(fd)


def _release_lock(lock_dir: Path) -> None:
    pid_path = lock_dir / PID_NAME
    try:
        os.unlink(pid_path)
    except OSError:
        pass
    try:
        os.rmdir(lock_dir)
    except OSError:
        pass


def _acquire_lock(lock_dir: Path) -> bool:
    try:
        os.mkdir(lock_dir, 0o700)
    except FileExistsError:
        return False
    except OSError:
        return False
    try:
        _write_pid(lock_dir)
    except OSError:
        _release_lock(lock_dir)
        return False
    return True


def write_failure_snapshot(request: argparse.Namespace) -> int:
    return _run_local(
        failure_snapshot_argv(
            request.python, request.dashboard_server, request.snapshot
        ),
        request.repo_root,
        request.environment,
    )


def invoke_local_sync(request: argparse.Namespace) -> int:
    return _run_local(
        local_sync_argv(request.sync_executable),
        request.repo_root,
        request.environment,
    )


def _fail_closed(request: argparse.Namespace, sync_status: int) -> int:
    failure_status = write_failure_snapshot(request)
    if failure_status != 0:
        return failure_status
    return sync_status


def run_coordinator(request: argparse.Namespace) -> int:
    _prepare_output_parents(request.snapshot, request.cache)
    lock_dir = coordinator_lock_dir(request.snapshot)
    if not _acquire_lock(lock_dir):
        sys.stderr.write(
            f"dashboard coordinator refused: another coordinator owns {lock_dir}\n"
        )
        return EX_TEMPFAIL
    try:
        for index in range(request.cycles):
            status = invoke_local_sync(request)
            if status != 0:
                return _fail_closed(request, status)
            try:
                reject_authorized_snapshot(request.snapshot)
            except CoordinatorUsageError as exc:
                sys.stderr.write(f"dashboard coordinator refused: {exc}\n")
                return _fail_closed(request, EX_USAGE)
            if index + 1 < request.cycles:
                time.sleep(request.watch)
        return 0
    finally:
        _release_lock(lock_dir)


def main(argv: list[str] | None = None) -> int:
    previous_umask = os.umask(0o077)
    try:
        try:
            request = load_request(argv)
        except CoordinatorUsageError as exc:
            sys.stderr.write(f"dashboard coordinator refused: {exc}\n")
            return EX_USAGE
        return run_coordinator(request)
    finally:
        os.umask(previous_umask)


if __name__ == "__main__":
    raise SystemExit(main())
