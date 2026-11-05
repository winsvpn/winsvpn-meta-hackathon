#!/usr/bin/python3
"""Root-installed Linux UI/runtime driver for final Win's VPN evidence.

The driver performs actions; it never writes release receipts.  Results are
derived from the installed Flutter accessibility tree, owner-only app runtime,
kernel state, and the captured application window.  Secret configuration and
raw Double VPN identities are never emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Callable, Iterator

try:  # Imported lazily on non-POSIX hosts so the pure self-test can run there.
    import pwd  # type: ignore
except ImportError:  # pragma: no cover - exercised by Windows self-test hosts.
    pwd = None  # type: ignore[assignment]


CONTRACT = "winsvpn-linux-final-evidence-collector-v1"
STATE_ROOT = pathlib.Path("/run/winsvpn-release-driver")
STATE_FILE = STATE_ROOT / "state.json"
APP_ROOT = pathlib.Path("/opt/wins-vpn")
APP_BINARY = APP_ROOT / "wins_vpn"
AWG_BINARY = APP_ROOT / "awg"
FORCING_COMMENT = "winsvpn-release-route-force"
CANARY_DESKTOP_NAME = "winsvpn-release-split-canary.desktop"
CANARY_LABEL = "Win's VPN Release Split Canary"
CANARY_EXECUTABLE = pathlib.Path("/usr/local/libexec/winsvpn-release-split-canary.sh")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_JSON_BYTES = 1024 * 1024
SAFE_DESKTOP_ENV_KEYS = (
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "XDG_CONFIG_DIRS",
    "XDG_CURRENT_DESKTOP",
    "XDG_DATA_DIRS",
    "XDG_SESSION_TYPE",
)


class DriverError(RuntimeError):
    pass


def is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def minimal_desktop_environment(
    source: dict[str, str],
    *,
    user: str,
    uid: int,
    home: pathlib.Path,
    display: str,
    wayland_display: str,
    xauthority: str,
) -> dict[str, str]:
    """Build a desktop environment without forwarding root release secrets."""
    env = {
        key: source[key]
        for key in SAFE_DESKTOP_ENV_KEYS
        if source.get(key)
    }
    env.update(
        {
            "HOME": str(home),
            "USER": user,
            "LOGNAME": user,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
            "GTK_MODULES": "atk-bridge",
        }
    )
    if display:
        env["DISPLAY"] = display
    if wayland_display:
        env["WAYLAND_DISPLAY"] = wayland_display
    if xauthority:
        env["XAUTHORITY"] = xauthority
    return env


def minimal_installer_environment(source: dict[str, str]) -> dict[str, str]:
    """Do not expose unrelated operator credentials to the tested installer."""
    env = {
        key: source[key]
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "TZ")
        if source.get(key)
    }
    env.update(
        {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "USER": "root",
            "LOGNAME": "root",
            "DEBIAN_FRONTEND": "noninteractive",
            "NEEDRESTART_MODE": "a",
        }
    )
    return env


def run(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 180,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
        check=False,
    )
    if check and result.returncode != 0:
        raise DriverError(f"Required command failed: {pathlib.Path(argv[0]).name} exit {result.returncode}")
    return result


def run_as_user(
    argv: list[str],
    *,
    entry: Any,
    env: dict[str, str],
    check: bool = True,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    def drop_privileges() -> None:
        os.umask(0o077)
        os.setgroups([entry.pw_gid])
        os.setgid(entry.pw_gid)
        os.setuid(entry.pw_uid)

    result = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
        check=False,
        preexec_fn=drop_privileges,
    )
    if check and result.returncode != 0:
        raise DriverError("Desktop-user helper failed")
    return result


def response(action: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": CONTRACT,
        "action": action,
        "passed": True,
        "secret_material_redacted": True,
        **fields,
    }


def atomic_json(path: pathlib.Path, value: dict[str, Any], mode: int = 0o600) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, separators=(",", ":"), sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_json_file(path: pathlib.Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_JSON_BYTES:
        raise DriverError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DriverError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise DriverError(f"{label} is not a JSON object")
    return value


def ensure_root() -> None:
    if (
        os.name != "posix"
        or not hasattr(os, "geteuid")
        or os.geteuid() != 0
        or not pathlib.Path("/proc").is_dir()
        or pwd is None
    ):
        raise DriverError("Linux release UI driver must run as root on Linux")


def reject_symlink_components(
    path: pathlib.Path, label: str, *, must_exist: bool
) -> pathlib.Path:
    """Reject symlink traversal before a root process reads or writes a path."""
    absolute = path if path.is_absolute() else pathlib.Path.cwd() / path
    current = pathlib.Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if must_exist:
                raise DriverError(f"{label} does not exist")
            continue
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or is_reparse_point(info):
            raise DriverError(f"{label} must not traverse a symlink/reparse point")
    if must_exist and not absolute.is_file():
        raise DriverError(f"{label} must be a regular file")
    return absolute.resolve(strict=must_exist)


def secure_state_root() -> None:
    if STATE_ROOT.exists() or STATE_ROOT.is_symlink():
        info = STATE_ROOT.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise DriverError("Linux release driver state directory is unsafe")
    else:
        STATE_ROOT.mkdir(mode=0o700, parents=False)
    os.chown(STATE_ROOT, 0, 0)
    os.chmod(STATE_ROOT, 0o700)


def load_state() -> dict[str, Any]:
    if STATE_ROOT.exists() or STATE_ROOT.is_symlink():
        secure_state_root()
    if not STATE_FILE.exists():
        return {}
    info = STATE_FILE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise DriverError("Linux release driver state is unsafe")
    return load_json_file(STATE_FILE, "release driver state")


def save_state(state: dict[str, Any]) -> None:
    secure_state_root()
    atomic_json(STATE_FILE, state)


def discover_desktop_user(state: dict[str, Any]) -> tuple[str, int, pathlib.Path]:
    candidates = [
        str(state.get("desktop_user", "")),
        os.environ.get("WINS_RELEASE_DESKTOP_USER", ""),
        os.environ.get("SUDO_USER", ""),
    ]
    sessions = run(
        ["loginctl", "list-sessions", "--no-legend"], check=False, timeout=10
    ).stdout.splitlines()
    for line in sessions:
        parts = line.split()
        if len(parts) >= 3:
            candidates.append(parts[2])
    for name in candidates:
        name = name.strip()
        if not name or name == "root":
            continue
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        runtime = pathlib.Path(f"/run/user/{entry.pw_uid}")
        if runtime.is_dir() and (runtime / "bus").exists():
            return entry.pw_name, entry.pw_uid, pathlib.Path(entry.pw_dir)
    raise DriverError("No active non-root graphical desktop user was found")


def desktop_environment(user: str, uid: int, home: pathlib.Path) -> dict[str, str]:
    display = ""
    wayland_display = ""
    xauthority = ""
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != uid:
                continue
            raw = (proc / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        values = {}
        for item in raw:
            if b"=" in item:
                key, value = item.split(b"=", 1)
                values[key.decode(errors="ignore")] = value.decode(errors="ignore")
        display = display or values.get("DISPLAY", "")
        wayland_display = wayland_display or values.get("WAYLAND_DISPLAY", "")
        xauthority = xauthority or values.get("XAUTHORITY", "")
        if display:
            break
    display = display or os.environ.get("DISPLAY", "")
    wayland_display = wayland_display or os.environ.get("WAYLAND_DISPLAY", "")
    xauthority = xauthority or os.environ.get("XAUTHORITY", "")
    return minimal_desktop_environment(
        os.environ,
        user=user,
        uid=uid,
        home=home,
        display=display,
        wayland_display=wayland_display,
        xauthority=xauthority,
    )


def activate_accessibility_bus(
    state: dict[str, Any], env: dict[str, str]
) -> dict[str, str]:
    if not shutil.which("gdbus"):
        raise DriverError("gdbus is required to activate the desktop accessibility bus")
    entry = pwd.getpwnam(str(state["desktop_user"]))
    result = run_as_user(
        [
            "gdbus", "call", "--session", "--dest", "org.a11y.Bus",
            "--object-path", "/org/a11y/bus",
            "--method", "org.a11y.Bus.GetAddress",
        ],
        entry=entry,
        env=env,
        timeout=20,
    )
    address_match = re.search(r"(unix:[^'\"),]+)", result.stdout)
    if not address_match:
        raise DriverError("Desktop accessibility bus did not return an address")
    result_env = dict(env)
    result_env["AT_SPI_BUS_ADDRESS"] = address_match.group(1)
    result_env["NO_AT_BRIDGE"] = "0"
    return result_env


def initialize_state() -> tuple[dict[str, Any], dict[str, str]]:
    state = load_state()
    user, uid, home = discover_desktop_user(state)
    if not state:
        state = {
            "schema_version": 1,
            "desktop_user": user,
            "desktop_uid": uid,
            "desktop_home": str(home),
            "original_app_running": app_pids(uid) != [],
            "backups": {},
            "forcing_rules": [],
        }
        save_state(state)
    elif (
        state.get("desktop_user") != user
        or state.get("desktop_uid") != uid
        or state.get("desktop_home") != str(home)
    ):
        raise DriverError("Release driver desktop identity changed during the run")
    return state, desktop_environment(user, uid, home)


def app_pids(uid: int) -> list[int]:
    result: list[int] = []
    expected = APP_BINARY.resolve() if APP_BINARY.exists() else APP_BINARY
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdigit():
            continue
        try:
            if proc.stat().st_uid != uid or (proc / "exe").resolve(strict=True) != expected:
                continue
            result.append(int(proc.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return sorted(result)


def stop_app(uid: int) -> None:
    pids = app_pids(uid)
    for pid in pids:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and app_pids(uid):
        time.sleep(0.25)
    for pid in app_pids(uid):
        os.kill(pid, signal.SIGKILL)
    if app_pids(uid):
        raise DriverError("Installed Win's VPN process could not be stopped")


def backup_user_runtime(state: dict[str, Any]) -> None:
    home = pathlib.Path(str(state["desktop_home"]))
    data = home / ".local/share/wins_vpn"
    for name in ("vpn_settings.txt", "vpn_config.txt"):
        path = data / name
        if name in state["backups"]:
            continue
        reject_symlink_components(
            path,
            f"Win's VPN runtime file {name}",
            must_exist=path.exists(),
        )
        record: dict[str, Any] = {"path": str(path), "existed": path.exists()}
        if path.exists():
            if not path.is_file() or path.is_symlink():
                raise DriverError(f"Win's VPN runtime file is unsafe: {name}")
            info = path.stat()
            if info.st_uid != state["desktop_uid"] or path.stat().st_size > MAX_JSON_BYTES:
                raise DriverError(f"Win's VPN runtime file ownership/size is unsafe: {name}")
            backup = STATE_ROOT / f"original-{name}"
            shutil.copyfile(path, backup)
            os.chown(backup, 0, 0)
            os.chmod(backup, 0o600)
            record.update(
                {
                    "backup": str(backup),
                    "sha256": sha256_file(backup),
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                }
            )
        state["backups"][name] = record
    save_state(state)


def prepare_visible_runtime(state: dict[str, Any]) -> None:
    backup_user_runtime(state)
    home = pathlib.Path(str(state["desktop_home"]))
    path = home / ".local/share/wins_vpn/vpn_settings.txt"
    reject_symlink_components(
        path, "Win's VPN settings path", must_exist=False
    )
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    reject_symlink_components(
        path, "Win's VPN settings path", must_exist=path.exists()
    )
    os.chown(path.parent, state["desktop_uid"], pwd.getpwnam(state["desktop_user"]).pw_gid)
    value = load_json_file(path, "VPN settings") if path.exists() else {}
    value["launcher_unlocked"] = True
    value["double_vpn_requested"] = False
    atomic_json(path, value, 0o600)
    os.chown(path, state["desktop_uid"], pwd.getpwnam(state["desktop_user"]).pw_gid)
    config = config_path(state)
    if config.exists():
        if not config.is_file() or config.is_symlink():
            raise DriverError("Win's VPN configuration path is unsafe")
        os.chown(config, state["desktop_uid"], pwd.getpwnam(state["desktop_user"]).pw_gid)
        os.chmod(config, 0o600)


def launch_app(state: dict[str, Any], env: dict[str, str]) -> int:
    pids = app_pids(int(state["desktop_uid"]))
    if pids:
        return pids[0]
    env.update(activate_accessibility_bus(state, env))
    if not APP_BINARY.is_file() or APP_BINARY.is_symlink() or not os.access(APP_BINARY, os.X_OK):
        raise DriverError("Installed Win's VPN executable is missing or unsafe")
    entry = pwd.getpwnam(str(state["desktop_user"]))

    def drop_privileges() -> None:
        os.umask(0o077)
        os.setgroups([entry.pw_gid])
        os.setgid(entry.pw_gid)
        os.setuid(entry.pw_uid)

    process = subprocess.Popen(
        [str(APP_BINARY)],
        cwd=str(entry.pw_dir),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        preexec_fn=drop_privileges,
    )
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        pids = app_pids(entry.pw_uid)
        if pids:
            state["app_pid"] = pids[0]
            save_state(state)
            return pids[0]
        if process.poll() is not None:
            break
        time.sleep(0.25)
    raise DriverError("Installed Win's VPN UI did not start")


class AccessibilityWorker:
    def __init__(self, pid: int, env: dict[str, str]) -> None:
        if pid <= 1:
            raise DriverError("Accessibility worker process identity is invalid")
        proc = pathlib.Path(f"/proc/{pid}")
        if not proc.is_dir() or proc.stat().st_uid != os.geteuid():
            raise DriverError("Accessibility worker may only inspect its own user process")
        os.environ.update({key: value for key, value in env.items() if key in {
            "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
            "AT_SPI_BUS_ADDRESS", "NO_AT_BRIDGE", "GTK_MODULES",
            "HOME", "USER", "LOGNAME"
        }})
        try:
            import pyatspi  # type: ignore
        except ImportError as exc:
            raise DriverError("python3-pyatspi is required for Linux UI evidence") from exc
        self.pyatspi = pyatspi
        self.pid = pid

    def walk(self, node: Any) -> Iterator[Any]:
        yield node
        try:
            count = node.childCount
        except Exception:
            return
        for index in range(min(int(count), 4096)):
            try:
                child = node.getChildAtIndex(index)
            except Exception:
                continue
            if child is not None:
                yield from self.walk(child)

    def app_root(self) -> Any:
        desktop = self.pyatspi.Registry.getDesktop(0)
        for node in self.walk(desktop):
            try:
                if int(node.get_process_id()) == self.pid:
                    return node
            except Exception:
                continue
        raise DriverError("Win's VPN accessibility root is unavailable")

    def find(self, name: str, *, contains: bool = False, timeout: int = 20) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                root = self.app_root()
                for node in self.walk(root):
                    candidate = str(getattr(node, "name", "") or "").strip()
                    if (candidate == name) or (contains and name.casefold() in candidate.casefold()):
                        return node
            except DriverError:
                pass
            time.sleep(0.4)
        raise DriverError(f"Installed Win's VPN accessibility control was not found: {name}")

    def names(self) -> list[str]:
        return [
            str(getattr(node, "name", "") or "").strip()
            for node in self.walk(self.app_root())
            if str(getattr(node, "name", "") or "").strip()
        ]

    def click(self, node: Any) -> None:
        try:
            actions = node.queryAction()
            count = int(actions.nActions)
            for index in range(count):
                name = str(actions.getName(index)).casefold()
                if name in {"click", "press", "activate", "toggle", "tap"} or index == 0:
                    if actions.doAction(index):
                        return
        except Exception as exc:
            raise DriverError("Win's VPN accessibility action failed") from exc
        raise DriverError("Win's VPN accessibility control has no callable action")

    def checked(self, node: Any) -> bool:
        try:
            return bool(node.getState().contains(self.pyatspi.STATE_CHECKED))
        except Exception as exc:
            raise DriverError("Win's VPN accessibility checked state is unavailable") from exc

    def set_checked(self, name: str, expected: bool) -> None:
        node = self.find(name, contains=True)
        if self.checked(node) != expected:
            self.click(node)
            time.sleep(1)
            node = self.find(name, contains=True)
        if self.checked(node) != expected:
            raise DriverError(f"Win's VPN control did not reach requested checked state: {name}")

    def set_text(self, name: str, value: str) -> None:
        node = self.find(name, contains=True)
        try:
            editable = node.queryEditableText()
            editable.setTextContents(value)
        except Exception as exc:
            raise DriverError(f"Win's VPN editable control could not be set: {name}") from exc


def ui_worker(
    operation: str,
    pid: int,
    name: str,
    contains: bool,
    expected: str,
    value: str,
) -> int:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise DriverError("Accessibility worker must run as the non-root desktop user")
    env = dict(os.environ)
    worker = AccessibilityWorker(pid, env)
    result: dict[str, Any] = {"ok": True}
    if operation == "click":
        worker.click(worker.find(name, contains=contains))
    elif operation == "require":
        worker.find(name, contains=contains)
    elif operation == "set_checked":
        if expected not in {"true", "false"}:
            raise DriverError("Accessibility checked-state request is invalid")
        worker.set_checked(name, expected == "true")
    elif operation == "set_text":
        worker.set_text(name, value)
    elif operation == "names":
        result["names"] = worker.names()
    else:
        raise DriverError("Accessibility worker operation is invalid")
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


class Accessibility:
    """Root-side proxy; all AT-SPI calls execute as the desktop session user."""

    def __init__(self, state: dict[str, Any], env: dict[str, str]) -> None:
        self.state = state
        self.env = activate_accessibility_bus(state, env)
        env.update(self.env)
        self.entry = pwd.getpwnam(str(state["desktop_user"]))
        self.pid = launch_app(state, self.env)

    def call(
        self,
        operation: str,
        *,
        name: str = "",
        contains: bool = False,
        expected: str = "",
        value: str = "",
    ) -> dict[str, Any]:
        argv = [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--internal-ui",
            operation,
            "--pid",
            str(self.pid),
        ]
        if name:
            argv.extend(("--name", name))
        if contains:
            argv.append("--contains")
        if expected:
            argv.extend(("--expected", expected))
        if value:
            argv.extend(("--value", value))
        result = run_as_user(
            argv,
            entry=self.entry,
            env=self.env,
            timeout=45,
        )
        try:
            parsed = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise DriverError("Accessibility worker returned invalid JSON") from exc
        if not isinstance(parsed, dict) or parsed.get("ok") is not True:
            raise DriverError("Accessibility worker did not confirm the UI operation")
        return parsed

    def click_name(self, name: str, *, contains: bool = False) -> None:
        self.call("click", name=name, contains=contains)

    def require_name(self, name: str, *, contains: bool = False) -> None:
        self.call("require", name=name, contains=contains)

    def set_checked(self, name: str, expected: bool) -> None:
        self.call(
            "set_checked",
            name=name,
            contains=True,
            expected="true" if expected else "false",
        )

    def set_text(self, name: str, value: str) -> None:
        self.call("set_text", name=name, contains=True, value=value)

    def names(self) -> list[str]:
        result = self.call("names")
        names = result.get("names")
        if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
            raise DriverError("Accessibility worker names result is invalid")
        return names


def config_path(state: dict[str, Any]) -> pathlib.Path:
    return pathlib.Path(str(state["desktop_home"])) / ".local/share/wins_vpn/vpn_config.txt"


def settings_path(state: dict[str, Any]) -> pathlib.Path:
    return pathlib.Path(str(state["desktop_home"])) / ".local/share/wins_vpn/vpn_settings.txt"


def load_user_json_file(
    state: dict[str, Any], path: pathlib.Path, label: str
) -> dict[str, Any]:
    path = reject_symlink_components(path, label, must_exist=True)
    if not path.exists() or path.is_symlink():
        raise DriverError(f"{label} is missing or unsafe")
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != int(state["desktop_uid"])
        or stat.S_IMODE(info.st_mode) & 0o077
        or info.st_size > MAX_JSON_BYTES
    ):
        raise DriverError(f"{label} ownership, permissions, or size is unsafe")
    return load_json_file(path, label)


def runtime_config(state: dict[str, Any], timeout: int = 20) -> dict[str, Any]:
    path = config_path(state)
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        try:
            last = load_user_json_file(
                state, path, "installed app VPN configuration"
            )
            if last:
                return last
        except DriverError:
            pass
        time.sleep(0.4)
    raise DriverError("Installed app did not expose a current owner-only VPN configuration")


def advertised_routes(config: dict[str, Any]) -> list[dict[str, Any]]:
    xray = config.get("xray")
    if not isinstance(xray, dict):
        raise DriverError("Installed app configuration has no Xray transport object")
    raw = xray.get("transports") or xray.get("stealth_transports") or []
    if not isinstance(raw, list):
        raise DriverError("Installed app advertised Xray route list is invalid")
    routes: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise DriverError("Installed app advertised Xray route is invalid")
        port = item.get("port")
        security = str(item.get("security", "")).strip().lower()
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or security not in {"none", "tls"}:
            raise DriverError("Installed app advertised Xray route port/security is invalid")
        routes.append({"protocol": "tcp", "port": port, "security": security})
    if not routes:
        port = xray.get("port")
        security = str(xray.get("security", "")).strip().lower()
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 and security in {"none", "tls"}:
            routes.append({"protocol": "tcp", "port": port, "security": security})
    keys = {(item["port"], item["security"]) for item in routes}
    if not routes or len(keys) != len(routes) or len(routes) > 32:
        raise DriverError("Installed app advertised Xray route set is empty or duplicated")
    return sorted(routes, key=lambda item: (item["port"], item["security"]))


def baseline_key(is_double: bool) -> str:
    return "double" if is_double else "node"


def save_mode_baseline(
    state: dict[str, Any], is_double: bool, config: dict[str, Any]
) -> tuple[int, list[dict[str, Any]]]:
    direct_port = runtime_direct_port(config)
    routes = advertised_routes(config)
    direct_addresses, xray_addresses = forcing_endpoint_addresses(config)
    baselines = state.setdefault("mode_baselines", {})
    if not isinstance(baselines, dict):
        raise DriverError("Linux release mode baseline state is invalid")
    baselines[baseline_key(is_double)] = {
        "schema_version": 1,
        "direct_port": direct_port,
        "advertised_xray_routes": routes,
        "direct_addresses": [list(item) for item in direct_addresses],
        "xray_addresses": [list(item) for item in xray_addresses],
    }
    save_state(state)
    return direct_port, routes


def load_mode_baseline(
    state: dict[str, Any], is_double: bool
) -> tuple[int, list[dict[str, Any]], list[tuple[int, str]], list[tuple[int, str]]]:
    baselines = state.get("mode_baselines")
    value = baselines.get(baseline_key(is_double)) if isinstance(baselines, dict) else None
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "direct_port", "advertised_xray_routes",
        "direct_addresses", "xray_addresses"
    } or value.get("schema_version") != 1:
        raise DriverError("A machine-observed direct baseline is required before Xray testing")
    direct_port = value.get("direct_port")
    if isinstance(direct_port, bool) or not isinstance(direct_port, int) or not 1 <= direct_port <= 65535:
        raise DriverError("Stored Linux release direct baseline port is invalid")
    routes = value.get("advertised_xray_routes")
    if not isinstance(routes, list):
        raise DriverError("Stored Linux release advertised route baseline is invalid")
    normalized = advertised_routes({"xray": {"transports": routes}})
    if normalized != routes:
        raise DriverError("Stored Linux release advertised route baseline is non-canonical")
    def addresses(field: str) -> list[tuple[int, str]]:
        raw = value.get(field)
        if not isinstance(raw, list) or not raw or len(raw) > 64:
            raise DriverError("Stored Linux release forcing address baseline is invalid")
        result: set[tuple[int, str]] = set()
        for item in raw:
            if not isinstance(item, list) or len(item) != 2 or item[0] not in {4, 6}:
                raise DriverError("Stored Linux release forcing address baseline is invalid")
            try:
                parsed = ipaddress.ip_address(str(item[1]))
            except ValueError as exc:
                raise DriverError("Stored Linux release forcing address baseline is invalid") from exc
            if parsed.version != item[0]:
                raise DriverError("Stored Linux release forcing address family is inconsistent")
            result.add((parsed.version, str(parsed)))
        if len(result) != len(raw):
            raise DriverError("Stored Linux release forcing address baseline is duplicated")
        return sorted(result)
    return direct_port, normalized, addresses("direct_addresses"), addresses("xray_addresses")


def validate_route_forcing_capability(
    routes: list[dict[str, Any]], port: int, security: str
) -> None:
    """Require the requested transport to be unique at the kernel-visible port."""
    same_port = [item for item in routes if item.get("port") == port]
    if len(same_port) != 1 or same_port[0].get("security") != security:
        raise DriverError(
            "Requested Xray port/security cannot be uniquely forced by kernel port isolation"
        )


def firewall_rule(binary: str, action: str, rule: list[str]) -> None:
    if binary not in {"iptables", "ip6tables"}:
        raise DriverError("Release forcing firewall family is invalid")
    run([binary, "-w", "5", action, "OUTPUT", *rule])


def endpoint_host(endpoint: str) -> str:
    value = endpoint.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::[0-9]{1,5})?", value)
        return match.group(1) if match else ""
    if ":" in value:
        return value.rsplit(":", 1)[0].strip()
    return value


def resolve_endpoint_addresses(hosts: list[str]) -> list[tuple[int, str]]:
    addresses: set[tuple[int, str]] = set()
    for raw in hosts:
        host = endpoint_host(raw)
        if not host:
            continue
        try:
            parsed = ipaddress.ip_address(host)
            addresses.add((parsed.version, str(parsed)))
            continue
        except ValueError:
            pass
        try:
            records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DriverError("Release forcing could not resolve a configured transport host") from exc
        for family, _, _, _, sockaddr in records:
            if family in {socket.AF_INET, socket.AF_INET6}:
                parsed = ipaddress.ip_address(sockaddr[0])
                addresses.add((parsed.version, str(parsed)))
    if not addresses or len(addresses) > 64:
        raise DriverError("Release forcing transport address set is empty or excessive")
    return sorted(addresses)


def forcing_endpoint_addresses(
    config: dict[str, Any]
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    direct = resolve_endpoint_addresses(
        [str(config.get("server_endpoint") or config.get("serverendpoint") or "")]
    )
    xray = config.get("xray") if isinstance(config.get("xray"), dict) else {}
    hosts = [
        str(xray.get("host") or ""),
        str(xray.get("server_name") or xray.get("servername") or ""),
    ]
    for value in (
        xray.get("fallback_hosts"), xray.get("fallbackhosts"),
        config.get("regional_aliases"), config.get("regionalaliases"),
    ):
        if isinstance(value, list):
            hosts.extend(str(item) for item in value)
    return direct, resolve_endpoint_addresses(hosts)


def forcing_rule_records(
    config: dict[str, Any],
    routes: list[dict[str, Any]],
    selected_port: int,
    direct_port: int,
) -> list[tuple[str, list[str]]]:
    direct_addresses, xray_addresses = forcing_endpoint_addresses(config)
    return forcing_rule_records_from_addresses(
        direct_addresses, xray_addresses, routes, selected_port, direct_port
    )


def forcing_rule_records_from_addresses(
    direct_addresses: list[tuple[int, str]],
    xray_addresses: list[tuple[int, str]],
    routes: list[dict[str, Any]],
    selected_port: int,
    direct_port: int,
) -> list[tuple[str, list[str]]]:
    records: list[tuple[str, list[str]]] = []
    for version, address in direct_addresses:
        records.append((
            "ip6tables" if version == 6 else "iptables",
            ["!", "-o", "lo", "-d", address, "-p", "udp", "--dport", str(direct_port),
             "-m", "comment", "--comment", FORCING_COMMENT, "-j", "REJECT"],
        ))
    for other_port in sorted({item["port"] for item in routes if item["port"] != selected_port}):
        for version, address in xray_addresses:
            records.append((
                "ip6tables" if version == 6 else "iptables",
                ["!", "-o", "lo", "-d", address, "-p", "tcp", "--dport", str(other_port),
                 "-m", "comment", "--comment", FORCING_COMMENT, "-j", "REJECT"],
            ))
    return records


def remove_forcing(state: dict[str, Any]) -> None:
    for record in reversed(state.get("forcing_rules", [])):
        if not isinstance(record, dict):
            continue
        binary = record.get("binary")
        rule = record.get("rule")
        if (
            binary in {"iptables", "ip6tables"}
            and isinstance(rule, list)
            and all(isinstance(item, str) for item in rule)
        ):
            run(
                [binary, "-w", "5", "-D", "OUTPUT", *rule],
                check=False,
            )
    state["forcing_rules"] = []
    state.pop("forcing_token", None)
    save_state(state)


def install_forcing(
    state: dict[str, Any],
    kind: str,
    port: int,
    security: str,
    direct_port: int,
    routes: list[dict[str, Any]],
    direct_addresses: list[tuple[int, str]],
    xray_addresses: list[tuple[int, str]],
) -> None:
    remove_forcing(state)
    if kind not in {"xray", "double_vpn_xray"}:
        return
    validate_route_forcing_capability(routes, port, security)
    rules = forcing_rule_records_from_addresses(
        direct_addresses, xray_addresses, routes, port, direct_port
    )
    for binary in ("iptables", "ip6tables"):
        if not shutil.which(binary):
            raise DriverError(f"Required route-forcing firewall is unavailable: {binary}")
    state["forcing_token"] = uuid.uuid4().hex
    save_state(state)
    spawn_watchdog("forcing", 300)
    try:
        for binary, rule in rules:
            firewall_rule(binary, "-I", rule)
            state.setdefault("forcing_rules", []).append(
                {"binary": binary, "rule": rule}
            )
            save_state(state)
    except Exception:
        remove_forcing(state)
        raise


def spawn_watchdog(kind: str, seconds: int) -> None:
    token = str(load_state().get(f"{kind}_token", ""))
    subprocess.Popen(
        [sys.executable, str(pathlib.Path(__file__).resolve()), "--internal-watchdog", kind, token, str(seconds)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def wait_interface(active: bool, timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        present = run(["ip", "link", "show", "winsvpn"], check=False, timeout=5).returncode == 0
        if present == active:
            return
        time.sleep(0.5)
    raise DriverError(f"Win's VPN interface did not become {'active' if active else 'inactive'}")


def runtime_direct_port(config: dict[str, Any]) -> int:
    endpoint = str(config.get("server_endpoint") or config.get("serverendpoint") or "").strip()
    match = re.search(r":([0-9]{1,5})$", endpoint)
    if not match:
        raise DriverError("Live runtime AWG endpoint has no explicit port")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise DriverError("Live runtime AWG endpoint port is invalid")
    xray = config.get("xray") if isinstance(config.get("xray"), dict) else {}
    remote = xray.get("remote_awg_port") or xray.get("remoteawgport")
    if remote is not None and int(remote) != port:
        raise DriverError("Live direct port disagrees with Xray remote AWG port")
    return port


def validate_live_xray_route(config: dict[str, Any], port: int, security: str) -> int:
    """Require every live Xray edge to use the exact selected route.

    Production configs may advertise more than one same-route edge behind an
    Xray balancer.  Treating that valid redundancy as a second route made the
    release driver reject the current application even though every edge used
    the requested port and security.  This validator accepts bounded redundant
    edges, but still rejects mixed transports, malformed VLESS entries, and
    host-header divergence.
    """
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list) or not 1 <= len(outbounds) <= 16:
        raise DriverError("Live Xray client has an invalid edge count")
    tags: list[str] = []
    for outbound in outbounds:
        if not isinstance(outbound, dict) or outbound.get("protocol") != "vless":
            raise DriverError("Live Xray client contains a non-VLESS edge")
        settings = outbound.get("settings")
        stream = outbound.get("streamSettings")
        if not isinstance(settings, dict) or not isinstance(stream, dict):
            raise DriverError("Live Xray client route is malformed")
        vnext = settings.get("vnext")
        ws = stream.get("wsSettings")
        if (
            not isinstance(vnext, list)
            or len(vnext) != 1
            or not isinstance(vnext[0], dict)
            or not isinstance(ws, dict)
        ):
            raise DriverError("Live Xray client route is malformed")
        host = ws.get("host")
        headers = ws.get("headers")
        if (
            vnext[0].get("port") != port
            or stream.get("security") != security
            or not isinstance(host, str)
            or not host
            or not isinstance(headers, dict)
            or headers.get("Host") != host
        ):
            raise DriverError(
                "Live Xray client does not match the forced port/security route"
            )
        tag = outbound.get("tag")
        if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", tag):
            raise DriverError("Live Xray client edge tag is invalid")
        tags.append(tag)
    if len(set(tags)) != len(tags):
        raise DriverError("Live Xray client edge tags are duplicated")
    return len(outbounds)


def verify_connected_transport(kind: str, port: int, security: str, direct_port: int) -> None:
    is_xray = kind in {"xray", "double_vpn_xray"}
    if is_xray:
        config = load_json_file(pathlib.Path("/run/wins-vpn-xray/client.json"), "live Xray client")
        validate_live_xray_route(config, port, security)
    else:
        if pathlib.Path("/run/wins-vpn-xray/xray.pid").exists():
            raise DriverError("Direct AWG lane unexpectedly started Xray")
        endpoint = run([str(AWG_BINARY), "show", "winsvpn", "endpoints"]).stdout.strip().split()
        if not endpoint or not endpoint[-1].endswith(f":{direct_port}"):
            raise DriverError("Live direct AWG endpoint does not match runtime config")


def wait_connected_transport(
    kind: str,
    port: int,
    security: str,
    direct_port: int,
    timeout: int = 150,
) -> None:
    """Wait through the app's direct-to-Xray transition before attesting it.

    The AWG interface is intentionally created before the direct route has
    proven usable.  On a censored path the same connection attempt can then
    replace that peer with the requested Xray carrier.  Observing interface
    presence alone is therefore too early for an Xray lane.
    """
    deadline = time.monotonic() + timeout
    last_error = "requested provider did not become observable"
    stable_observations = 0
    while time.monotonic() < deadline:
        try:
            verify_connected_transport(kind, port, security, direct_port)
            handshake = run(
                [str(AWG_BINARY), "show", "winsvpn", "latest-handshakes"],
                check=False,
                timeout=10,
            ).stdout.strip().split()
            transfer = run(
                [str(AWG_BINARY), "show", "winsvpn", "transfer"],
                check=False,
                timeout=10,
            ).stdout.strip().split()
            if (
                not handshake
                or not handshake[-1].isdigit()
                or int(handshake[-1]) <= 0
                or int(time.time()) - int(handshake[-1]) > 180
                or len(transfer) < 3
                or not transfer[-2].isdigit()
                or not transfer[-1].isdigit()
                or int(transfer[-2]) <= 0
                or int(transfer[-1]) <= 0
            ):
                raise DriverError("Requested Linux transport lacks a recent handshake and traffic")
            stable_observations += 1
            if stable_observations >= 5:
                return
        except (DriverError, FileNotFoundError, OSError) as exc:
            last_error = str(exc)
            stable_observations = 0
        time.sleep(1)
    raise DriverError(f"Requested Linux transport did not become active: {last_error}")


def action_routes(state: dict[str, Any], env: dict[str, str], _: argparse.Namespace) -> dict[str, Any]:
    launch_app(state, env)
    return response("routes", advertised_xray_routes=advertised_routes(runtime_config(state)))


def safe_extract(artifact: pathlib.Path, destination: pathlib.Path) -> None:
    with tarfile.open(artifact, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise DriverError("Linux release archive is empty")
        for member in members:
            name = member.name.removeprefix("./").rstrip("/")
            if name in {"", "."}:
                continue
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
                raise DriverError("Linux release archive contains an unsafe member")
            expected_mode = 0o755 if member.isdir() or path.name in {
                "wins_vpn", "winsvpn-bypass-bpf", "xray", "awg", "awg-quick", "amneziawg-go", "install.sh"
            } else 0o644
            if member.uid != 0 or member.gid != 0 or member.mode != expected_mode:
                raise DriverError("Linux release archive metadata is unsafe")
        for member in members:
            name = member.name.removeprefix("./").rstrip("/")
            if name in {"", "."}:
                continue
            target = destination / pathlib.PurePosixPath(name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise DriverError("Linux release archive member could not be read")
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, member.mode)
            with os.fdopen(descriptor, "wb") as handle:
                shutil.copyfileobj(source, handle, 1024 * 1024)
            os.chmod(target, member.mode)


def installed_version(root: pathlib.Path) -> str:
    path = root / "share/metainfo/org.winsvpn.app.metainfo.xml"
    if not path.is_file() or path.is_symlink():
        raise DriverError("Installed AppStream metadata is missing")
    try:
        releases = ET.parse(path).getroot().find("releases")
    except ET.ParseError as exc:
        raise DriverError("Installed AppStream metadata is invalid") from exc
    if releases is None or len(releases) == 0:
        raise DriverError("Installed AppStream metadata has no release version")
    version = str(releases[0].attrib.get("version", ""))
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise DriverError("Installed AppStream release version is invalid")
    return version


def rollback_install_root(
    app_root: pathlib.Path, previous: pathlib.Path, *, had_previous: bool
) -> None:
    """Remove a failed new install and atomically restore the prior app root."""
    if app_root.exists() or app_root.is_symlink():
        info = app_root.lstat()
        if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            shutil.rmtree(app_root)
        else:
            app_root.unlink()
    if had_previous:
        if not previous.is_dir() or previous.is_symlink():
            raise DriverError("Prior Linux application root is unavailable for rollback")
        os.rename(previous, app_root)


def action_clean_install(state: dict[str, Any], env: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    raw_artifact = pathlib.Path(args.artifact or "")
    if not raw_artifact.is_absolute():
        raise DriverError("Exact Linux artifact must be an absolute regular file")
    artifact = reject_symlink_components(
        raw_artifact, "Exact Linux artifact", must_exist=True
    )
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.app_version or "") or not str(args.build_number or "").isdigit():
        raise DriverError("Expected release version/build arguments are invalid")
    backup_user_runtime(state)
    remove_forcing(state)
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        ui = Accessibility(state, env)
        ui.click_name("Disconnect VPN")
        wait_interface(False)
    stop_app(int(state["desktop_uid"]))
    extraction = pathlib.Path(tempfile.mkdtemp(prefix="extract-", dir=STATE_ROOT))
    previous = pathlib.Path(f"/opt/.wins-vpn.release-previous.{uuid.uuid4().hex}")
    moved_previous = False
    install_attempted = False
    try:
        safe_extract(artifact, extraction)
        if installed_version(extraction) != args.app_version:
            raise DriverError("Archive AppStream version does not match the frozen release")
        if APP_ROOT.exists():
            if not APP_ROOT.is_dir() or APP_ROOT.is_symlink():
                raise DriverError("Existing /opt/wins-vpn is unsafe")
            os.rename(APP_ROOT, previous)
            moved_previous = True
        if APP_ROOT.exists():
            raise DriverError("Clean removal did not make /opt/wins-vpn absent")
        install_attempted = True
        result = run(
            ["bash", str(extraction / "install.sh")],
            env=minimal_installer_environment(os.environ),
            check=False,
            timeout=900,
        )
        if result.returncode != 0 or not APP_ROOT.is_dir() or APP_ROOT.is_symlink():
            raise DriverError("Exact Linux release installer failed")
        if installed_version(APP_ROOT) != args.app_version:
            raise DriverError("Installed AppStream version does not match the frozen release")
        if moved_previous:
            shutil.rmtree(previous)
            moved_previous = False
    except Exception:
        if install_attempted:
            rollback_install_root(
                APP_ROOT, previous, had_previous=moved_previous
            )
            moved_previous = False
        raise
    finally:
        shutil.rmtree(extraction, ignore_errors=True)
        if moved_previous and not APP_ROOT.exists() and previous.exists():
            os.rename(previous, APP_ROOT)
    prepare_visible_runtime(state)
    launch_app(state, env)
    return response(
        "clean_install",
        source_artifact_sha256=sha256_file(artifact),
        app_version=args.app_version,
        build_number=args.build_number,
        clean_remove_passed=True,
        install_passed=True,
    )


def set_double_vpn(state: dict[str, Any], env: dict[str, str], expected: bool) -> None:
    ui = Accessibility(state, env)
    ui.set_checked("Double VPN", expected)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        settings = load_user_json_file(state, settings_path(state), "VPN settings")
        if settings.get("double_vpn_requested") is expected:
            return
        time.sleep(0.3)
    raise DriverError("Installed app did not persist the requested Double VPN state")


def double_identity_fields(
    is_double: bool, core: str, exit_slug: str
) -> dict[str, str]:
    core = core.strip()
    exit_slug = exit_slug.strip()
    if is_double and (not core or not exit_slug):
        raise DriverError("Installed app live Double VPN identities are missing")
    if not is_double and (core or exit_slug):
        raise DriverError("Non-Double route unexpectedly exposed Double VPN identities")
    return {
        "double_vpn_core_id_sha256": sha256_bytes(core.encode()),
        "double_vpn_exit_slug_sha256": sha256_bytes(exit_slug.encode()),
    }


def action_connect(state: dict[str, Any], env: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    kind = args.kind or ""
    if kind not in {"direct_awg", "xray", "double_vpn_direct", "double_vpn_xray"}:
        raise DriverError("Requested Linux route kind is invalid")
    is_xray = kind in {"xray", "double_vpn_xray"}
    is_double = kind in {"double_vpn_direct", "double_vpn_xray"}
    if is_xray:
        try:
            port = int(args.port)
            expected_direct_port = int(args.direct_port)
        except (TypeError, ValueError) as exc:
            raise DriverError("Requested Linux Xray route/direct port is invalid") from exc
        security = (args.security or "").lower()
        if (
            not 1 <= port <= 65535
            or not 1 <= expected_direct_port <= 65535
            or security not in {"none", "tls"}
        ):
            raise DriverError("Requested Linux Xray route/direct port is invalid")
        (
            baseline_direct_port,
            baseline_routes,
            direct_addresses,
            xray_addresses,
        ) = load_mode_baseline(state, is_double)
        if expected_direct_port != baseline_direct_port:
            raise DriverError("Requested direct port does not match the machine-observed mode baseline")
        validate_route_forcing_capability(baseline_routes, port, security)
    else:
        if args.port is not None or args.security is not None or args.direct_port is not None:
            raise DriverError("Direct Linux baseline must discover its port from live runtime config")
        port = None
        security = "none"
        baseline_direct_port = None
        baseline_routes = []
        direct_addresses, xray_addresses = [], []
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        raise DriverError("Connect action requires a disconnected tunnel")
    set_double_vpn(state, env, is_double)
    if is_xray:
        install_forcing(
            state,
            kind,
            int(port),
            security,
            int(baseline_direct_port),
            baseline_routes,
            direct_addresses,
            xray_addresses,
        )
    else:
        remove_forcing(state)
    try:
        ui = Accessibility(state, env)
        ui.click_name("Connect VPN")
        wait_interface(True, 150)
        config = runtime_config(state)
        actual_direct_port = runtime_direct_port(config)
        active_routes = advertised_routes(config)
        if is_xray:
            if actual_direct_port != baseline_direct_port or active_routes != baseline_routes:
                raise DriverError("Live Linux Xray config differs from its direct mode baseline")
        else:
            actual_direct_port, active_routes = save_mode_baseline(state, is_double, config)
            port = actual_direct_port
        wait_connected_transport(kind, int(port), security, actual_direct_port)
        double_active = config.get("double_vpn_active") is True
        core = str(config.get("double_vpn_core_id", "")).strip()
        exit_slug = str(config.get("double_vpn_exit_slug", "")).strip()
        if double_active is not is_double:
            raise DriverError("Installed app live Double VPN state contradicts the requested route")
        identity_fields = double_identity_fields(is_double, core, exit_slug)
        return response(
            "connect",
            kind=kind,
            port=port,
            security=security,
            actual_direct_port=actual_direct_port,
            advertised_xray_routes=active_routes,
            forcing_blocked_udp_port=actual_direct_port if is_xray else None,
            forced_route=is_xray,
            double_vpn_active=is_double,
            **identity_fields,
        )
    except Exception as original:
        try:
            action_disconnect(state, env, argparse.Namespace())
        except Exception as cleanup_error:
            raise DriverError(
                "Failed Linux connection also failed its deterministic cleanup"
            ) from cleanup_error
        raise original


def action_disconnect(state: dict[str, Any], env: dict[str, str], _: argparse.Namespace) -> dict[str, Any]:
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        ui = Accessibility(state, env)
        try:
            ui.click_name("Disconnect VPN")
        except DriverError:
            # During direct-to-Xray failover the semantic power control is a
            # cancellation action, not yet a disconnect action.
            ui.click_name("Cancel VPN connection")
        wait_interface(False, 150)
    remove_forcing(state)
    canary = pathlib.Path(f"/run/user/{state['desktop_uid']}/winsvpn-split-canary.json")
    if canary.exists() or canary.is_symlink():
        pid = validated_split_canary(state, require_running=False)
        try:
            if pid is not None:
                os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        canary.unlink(missing_ok=True)
    return response("disconnect")


def canary_desktop_path(state: dict[str, Any]) -> pathlib.Path:
    return pathlib.Path(str(state["desktop_home"])) / ".local/share/applications" / CANARY_DESKTOP_NAME


def validate_split_canary_metadata(
    value: dict[str, Any],
    *,
    desktop_uid: int,
    file_uid: int,
    file_mode: int,
    process_uid: int,
    process_cmdline: bytes,
    process_cgroup: str,
) -> int:
    """Validate a user-written canary before root trusts or signals its PID."""
    if set(value) != {"schema_version", "socket_mark", "cgroup", "pid"}:
        raise DriverError("Split canary fields are invalid")
    pid = value.get("pid")
    socket_mark = value.get("socket_mark")
    claimed_cgroup = value.get("cgroup")
    if (
        value.get("schema_version") != 1
        or isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 1
        or isinstance(socket_mark, bool)
        or not isinstance(socket_mark, int)
        or socket_mark <= 0
        or not isinstance(claimed_cgroup, str)
        or "winsvpn-bypass.slice" not in claimed_cgroup
    ):
        raise DriverError("Split canary values are invalid")
    if file_uid != desktop_uid or file_mode != 0o600 or process_uid != desktop_uid:
        raise DriverError("Split canary ownership or permissions are invalid")
    if process_cgroup != claimed_cgroup:
        raise DriverError("Split canary process cgroup contradicts its claim")
    expected = os.fsencode(str(CANARY_EXECUTABLE))
    if expected not in process_cmdline.split(b"\0"):
        raise DriverError("Split canary PID does not belong to the installed canary")
    return pid


def validated_split_canary(
    state: dict[str, Any], *, require_running: bool
) -> int | None:
    canary = pathlib.Path(
        f"/run/user/{state['desktop_uid']}/winsvpn-split-canary.json"
    )
    path = reject_symlink_components(canary, "split canary", must_exist=True)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_size > MAX_JSON_BYTES
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise DriverError("Split canary file metadata is unsafe")
    value = load_json_file(path, "split canary")
    pid = value.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise DriverError("Split canary PID is invalid")
    proc = pathlib.Path(f"/proc/{pid}")
    if not proc.exists():
        if require_running:
            raise DriverError("Split canary process is no longer running")
        return None
    try:
        process_uid = proc.stat().st_uid
        cmdline = (proc / "cmdline").read_bytes()
        cgroup_lines = (proc / "cgroup").read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, ProcessLookupError) as exc:
        if require_running:
            raise DriverError("Split canary process disappeared during validation") from exc
        return None
    unified = [line.split(":", 2)[2] for line in cgroup_lines if line.startswith("0::")]
    if len(unified) != 1:
        raise DriverError("Split canary unified cgroup is unavailable")
    return validate_split_canary_metadata(
        value,
        desktop_uid=int(state["desktop_uid"]),
        file_uid=info.st_uid,
        file_mode=stat.S_IMODE(info.st_mode),
        process_uid=process_uid,
        process_cmdline=cmdline,
        process_cgroup=unified[0],
    )


def action_select_split(state: dict[str, Any], env: dict[str, str], _: argparse.Namespace) -> dict[str, Any]:
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        raise DriverError("Split selection must occur while disconnected")
    if not CANARY_EXECUTABLE.is_file() or CANARY_EXECUTABLE.is_symlink() or not os.access(CANARY_EXECUTABLE, os.X_OK):
        raise DriverError("Installed Linux split evidence canary is unavailable")
    desktop = canary_desktop_path(state)
    reject_symlink_components(
        desktop, "Linux split canary desktop entry", must_exist=False
    )
    desktop.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(
        desktop, "Linux split canary desktop entry", must_exist=desktop.exists()
    )
    entry = pwd.getpwnam(str(state["desktop_user"]))
    os.chown(desktop.parent, entry.pw_uid, entry.pw_gid)
    if desktop.exists() and not state.get("canary_desktop_backup"):
        if not desktop.is_file() or desktop.is_symlink():
            raise DriverError("Existing split canary desktop entry is unsafe")
        backup = STATE_ROOT / "original-canary.desktop"
        shutil.copyfile(desktop, backup)
        os.chmod(backup, 0o600)
        state["canary_desktop_backup"] = str(backup)
    state["canary_desktop_existed"] = desktop.exists()
    content = (
        "[Desktop Entry]\nType=Application\n"
        f"Name={CANARY_LABEL}\nExec={CANARY_EXECUTABLE}\n"
        "NoDisplay=false\nTerminal=false\n"
    )
    desktop.write_text(content, encoding="utf-8")
    os.chown(desktop, entry.pw_uid, entry.pw_gid)
    os.chmod(desktop, 0o644)
    save_state(state)
    stop_app(entry.pw_uid)
    launch_app(state, env)
    ui = Accessibility(state, env)
    ui.click_name("Split Tunneling", contains=True)
    ui.set_text("Search Linux apps to exclude", CANARY_LABEL)
    ui.set_checked(CANARY_LABEL, True)
    settings = load_user_json_file(state, settings_path(state), "VPN settings")
    exclusions = settings.get("excluded_vpn_packages")
    if not isinstance(exclusions, list) or str(desktop.resolve()) not in exclusions:
        raise DriverError("Installed app did not persist the release canary split selection")
    return response("select_split", selection_applied=True)


def action_launch_split(state: dict[str, Any], env: dict[str, str], _: argparse.Namespace) -> dict[str, Any]:
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode != 0:
        raise DriverError("Split canary launch requires an active tunnel")
    ui = Accessibility(state, env)
    # A successful connection returns the application to its dashboard.  Open
    # the split panel again and narrow it to the already-selected release
    # canary before invoking the launcher action.
    ui.click_name("Split Tunneling", contains=True)
    ui.set_text("Search Linux apps to exclude", CANARY_LABEL)
    ui.click_name("Launch outside VPN", contains=True)
    canary = pathlib.Path(f"/run/user/{state['desktop_uid']}/winsvpn-split-canary.json")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if canary.exists() or canary.is_symlink():
            validated_split_canary(state, require_running=True)
            return response("launch_split", launched=True)
        time.sleep(0.3)
    raise DriverError("Installed app did not launch the selected canary in the bypass cgroup")


def network_state_path() -> pathlib.Path:
    return STATE_ROOT / "network-transition.json"


def restore_network_transition() -> None:
    path = network_state_path()
    if not path.exists():
        return
    value = load_json_file(path, "network transition")
    interface = str(value.get("interface", ""))
    method = str(value.get("method", ""))
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface):
        raise DriverError("Stored network interface is invalid")
    if method == "nmcli":
        connection_uuid = str(value.get("connection_uuid", ""))
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            connection_uuid,
        ):
            raise DriverError("Stored NetworkManager connection identity is invalid")
        result = run(
            [
                "nmcli", "connection", "up", "uuid", connection_uuid,
                "ifname", interface,
            ],
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            raise DriverError("NetworkManager could not restore the original connection")
    else:
        run(["ip", "link", "set", "dev", interface, "up"], timeout=20)
    path.unlink(missing_ok=True)
    state = load_state()
    if state:
        state.pop("network_token", None)
        save_state(state)


def action_network_begin(state: dict[str, Any], _: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    interface = args.interface or ""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", interface) or interface in {"lo", "winsvpn"}:
        raise DriverError("Named network-change interface is invalid")
    if run(["ip", "link", "show", "dev", interface], check=False).returncode != 0:
        raise DriverError("Named network-change interface does not exist")
    restore_network_transition()
    method = "nmcli" if shutil.which("nmcli") else "ip"
    token = uuid.uuid4().hex
    metadata = {"interface": interface, "method": method, "token": token}
    if method == "nmcli":
        connection_uuid = run(
            ["nmcli", "-g", "GENERAL.CON-UUID", "device", "show", interface],
            timeout=15,
        ).stdout.strip()
        if not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            connection_uuid,
        ):
            raise DriverError("Named interface has no active NetworkManager connection")
        metadata["connection_uuid"] = connection_uuid
    atomic_json(network_state_path(), metadata)
    state["network_token"] = token
    save_state(state)
    spawn_watchdog("network", 45)
    if method == "nmcli":
        run(["nmcli", "device", "disconnect", interface], timeout=30)
    else:
        run(["ip", "link", "set", "dev", interface, "down"], timeout=20)
    return response("network_change_begin", change_triggered_by_harness=True)


def action_network_restore(_: dict[str, Any], __: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    value = load_json_file(network_state_path(), "network transition")
    if value.get("interface") != args.interface:
        raise DriverError("Network restore interface does not match the transition")
    restore_network_transition()
    return response("network_change_restore", restored=True)


def rollback_metadata_path() -> pathlib.Path:
    return STATE_ROOT / "rollback.json"


def restore_rollback() -> None:
    metadata = rollback_metadata_path()
    if not metadata.exists():
        return
    value = load_json_file(metadata, "rollback metadata")
    backup = pathlib.Path(str(value.get("backup", "")))
    target = pathlib.Path(str(value.get("target", "")))
    if target != AWG_BINARY or not backup.is_file() or backup.is_symlink():
        raise DriverError("Rollback restoration metadata is unsafe")
    temporary = target.with_name(f".{target.name}.restore.{uuid.uuid4().hex}")
    shutil.copyfile(backup, temporary)
    os.chown(temporary, int(value["uid"]), int(value["gid"]))
    os.chmod(temporary, int(value["mode"]))
    os.replace(temporary, target)
    restored_info = target.stat()
    if (
        sha256_file(target) != value["sha256"]
        or stat.S_IMODE(restored_info.st_mode) != value["mode"]
        or restored_info.st_uid != value["uid"]
        or restored_info.st_gid != value["gid"]
    ):
        raise DriverError("Rollback byte-exact restoration verification failed")
    backup.unlink()
    metadata.unlink()
    state = load_state()
    if state:
        state.pop("rollback_token", None)
        save_state(state)


def action_rollback_inject(state: dict[str, Any], _: dict[str, str], __: argparse.Namespace) -> dict[str, Any]:
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        raise DriverError("Rollback injection requires a disconnected tunnel")
    restore_rollback()
    if not AWG_BINARY.is_file() or AWG_BINARY.is_symlink():
        raise DriverError("Installed AWG executable is unsafe")
    info = AWG_BINARY.stat()
    if (
        info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o755
        or info.st_size <= 0
    ):
        raise DriverError("Installed AWG executable metadata is unsafe")
    backup = STATE_ROOT / "rollback-awg.original"
    shutil.copyfile(AWG_BINARY, backup)
    os.chown(backup, 0, 0)
    os.chmod(backup, 0o600)
    value = {
        "target": str(AWG_BINARY),
        "backup": str(backup),
        "sha256": sha256_file(backup),
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "token": uuid.uuid4().hex,
    }
    atomic_json(rollback_metadata_path(), value)
    state["rollback_token"] = value["token"]
    save_state(state)
    spawn_watchdog("rollback", 60)
    replacement = AWG_BINARY.with_name(f".{AWG_BINARY.name}.failure.{uuid.uuid4().hex}")
    replacement.write_bytes(b"#!/bin/sh\nexit 70\n")
    os.chown(replacement, 0, 0)
    os.chmod(replacement, 0o755)
    os.replace(replacement, AWG_BINARY)
    if sha256_file(AWG_BINARY) == value["sha256"]:
        raise DriverError("Rollback injection did not change the AWG executable bytes")
    return response("rollback_inject", failure_injected_by_harness=True)


def action_rollback_restore(_: dict[str, Any], __: dict[str, str], ___: argparse.Namespace) -> dict[str, Any]:
    restore_rollback()
    return response("rollback_restore", restored=True)


def capture_window(pid: int, output: pathlib.Path, env: dict[str, str], state: dict[str, Any]) -> tuple[int, int]:
    if not env.get("DISPLAY"):
        raise DriverError("Deterministic Linux window capture requires an X11/Xorg test session")
    search = run(["xdotool", "search", "--onlyvisible", "--pid", str(pid)], env=env)
    windows = [line.strip() for line in search.stdout.splitlines() if line.strip().isdigit()]
    if len(windows) != 1:
        raise DriverError("Expected exactly one visible Win's VPN X11 window")
    window = windows[0]
    geometry = run(["xdotool", "getwindowgeometry", "--shell", window], env=env).stdout
    width_match = re.search(r"(?m)^WIDTH=(\d+)$", geometry)
    height_match = re.search(r"(?m)^HEIGHT=(\d+)$", geometry)
    if not width_match or not height_match:
        raise DriverError("Win's VPN window geometry is unavailable")
    width, height = int(width_match.group(1)), int(height_match.group(1))
    if width < 640 or height < 480:
        raise DriverError("Win's VPN map window is too small for semantic evidence")
    entry = pwd.getpwnam(str(state["desktop_user"]))
    temp = pathlib.Path(f"/run/user/{entry.pw_uid}/winsvpn-map-{uuid.uuid4().hex}.png")
    result = run(["import", "-window", window, str(temp)], env=env, check=False, timeout=30)
    if result.returncode != 0 or not temp.is_file():
        raise DriverError("ImageMagick could not capture the actual Win's VPN X11 window")
    shutil.copyfile(temp, output)
    temp.unlink()
    os.chown(output, 0, 0)
    os.chmod(output, 0o600)
    return width, height


def parse_tesseract_tsv(tsv: str, width: int, height: int) -> list[str]:
    rows = tsv.splitlines()
    if not rows:
        raise DriverError("Tesseract produced no map semantics")
    header = rows[0].split("\t")
    required = {"left", "top", "width", "height", "conf", "text", "block_num", "par_num", "line_num"}
    if not required.issubset(header):
        raise DriverError("Tesseract TSV schema is incomplete")
    index = {name: header.index(name) for name in required}
    grouped: dict[tuple[str, str, str], list[tuple[int, str]]] = {}
    for raw in rows[1:]:
        values = raw.split("\t")
        if len(values) < len(header):
            continue
        try:
            confidence = float(values[index["conf"]])
            left = int(values[index["left"]])
            top = int(values[index["top"]])
            token_width = int(values[index["width"]])
            token_height = int(values[index["height"]])
        except ValueError:
            continue
        text = values[index["text"]].strip()
        if confidence < 45 or not text or top < height * 0.06 or top + token_height > height * 0.82:
            continue
        if left < 0 or left + token_width > width:
            continue
        key = (values[index["block_num"]], values[index["par_num"]], values[index["line_num"]])
        grouped.setdefault(key, []).append((left, text))
    excluded = {
        "wins vpn", "explore map", "close map", "approximate ip area", "mi radius",
        "openstreetmap", "contributors", "copyright", "maptiler",
    }
    candidates: list[str] = []
    for tokens in grouped.values():
        line = " ".join(text for _, text in sorted(tokens)).strip(" -|•")
        normalized = re.sub(r"[^A-Za-z .'-]", "", line).strip()
        if (
            2 <= len(normalized) <= 64
            and re.search(r"[A-Za-z]{2}", normalized)
            and not any(value in normalized.casefold() for value in excluded)
        ):
            candidates.append(normalized)
    return sorted(set(candidates), key=str.casefold)


def ocr_city_candidates(image: pathlib.Path, width: int, height: int) -> list[str]:
    result = run(
        ["tesseract", str(image), "stdout", "--psm", "11", "tsv"],
        timeout=60,
    )
    return parse_tesseract_tsv(result.stdout, width, height)


def action_capture_map(state: dict[str, Any], env: dict[str, str], args: argparse.Namespace) -> dict[str, Any]:
    raw_output = pathlib.Path(args.output or "")
    if not raw_output.is_absolute() or raw_output.exists():
        raise DriverError("Map output must be a new absolute path")
    output = reject_symlink_components(raw_output, "Map output", must_exist=False)
    if not output.parent.is_dir():
        raise DriverError("Map output parent directory does not exist")
    if run(["ip", "link", "show", "winsvpn"], check=False).returncode == 0:
        raise DriverError("Map capture requires a disconnected app")
    ui = Accessibility(state, env)
    ui.click_name("Explore map")
    ui.require_name("Your approximate network location")
    names = ui.names()
    radius = any("50 mi radius" in name.casefold() for name in names)
    marker = any("your approximate network location" == name.casefold() for name in names)
    if not radius or not marker:
        raise DriverError("Actual app map accessibility lacks the 50-mile label or target marker")
    width, height = capture_window(ui.pid, output, env, state)
    cities = ocr_city_candidates(output, width, height)
    if len(cities) < 2:
        raise DriverError("Actual app map OCR found fewer than two surrounding place labels")
    return response(
        "capture_map",
        capture_method="linux-window-capture",
        screenshot_sha256=sha256_file(output),
        radius_label_50_miles_detected=True,
        surrounding_city_labels=cities[:32],
        target_marker_detected=True,
        viewport_not_world_zoom=True,
    )


def restore_user_runtime(state: dict[str, Any]) -> None:
    for record in state.get("backups", {}).values():
        if not isinstance(record, dict):
            raise DriverError("Stored runtime backup metadata is invalid")
        path = pathlib.Path(str(record.get("path", "")))
        reject_symlink_components(
            path, "Stored runtime restore path", must_exist=path.exists()
        )
        if record.get("existed"):
            backup = pathlib.Path(str(record.get("backup", "")))
            if not backup.is_file() or backup.is_symlink() or sha256_file(backup) != record.get("sha256"):
                raise DriverError("Stored runtime backup changed before restoration")
            temporary = path.with_name(f".{path.name}.restore.{uuid.uuid4().hex}")
            shutil.copyfile(backup, temporary)
            os.chown(temporary, int(record["uid"]), int(record["gid"]))
            os.chmod(temporary, int(record["mode"]))
            os.replace(temporary, path)
            if sha256_file(path) != record["sha256"]:
                raise DriverError("Runtime backup byte restoration failed")
        else:
            if path.exists():
                if not path.is_file() or path.is_symlink():
                    raise DriverError("New runtime path became unsafe before cleanup")
                path.unlink()


def action_finalize(state: dict[str, Any], env: dict[str, str], _: argparse.Namespace) -> dict[str, Any]:
    errors: list[str] = []
    try:
        action_disconnect(state, env, argparse.Namespace())
    except Exception as exc:
        errors.append(str(exc))
    for operation in (restore_network_transition, restore_rollback):
        try:
            operation()
        except Exception as exc:
            errors.append(str(exc))
    try:
        stop_app(int(state["desktop_uid"]))
        restore_user_runtime(state)
        desktop = canary_desktop_path(state)
        if state.get("canary_desktop_existed"):
            backup = pathlib.Path(str(state.get("canary_desktop_backup", "")))
            if not backup.is_file() or backup.is_symlink():
                raise DriverError("Original canary desktop backup is unavailable")
            shutil.copyfile(backup, desktop)
            entry = pwd.getpwnam(str(state["desktop_user"]))
            os.chown(desktop, entry.pw_uid, entry.pw_gid)
            os.chmod(desktop, 0o644)
        elif desktop.exists():
            desktop.unlink()
        if state.get("original_app_running"):
            launch_app(state, env)
    except Exception as exc:
        errors.append(str(exc))
    if errors:
        raise DriverError("Linux release driver restoration failed")
    shutil.rmtree(STATE_ROOT)
    return response("finalize", restored=True)


def watchdog(kind: str, token: str, seconds: int) -> int:
    ensure_root()
    time.sleep(seconds)
    state = load_state()
    if not state or state.get(f"{kind}_token") != token:
        return 0
    if kind == "forcing":
        remove_forcing(state)
    elif kind == "network":
        restore_network_transition()
    elif kind == "rollback":
        restore_rollback()
    return 0


def self_test() -> None:
    config = {
        "xray": {
            "transports": [
                {"port": 443, "security": "tls", "host": "secret.example"},
                {"port": 80, "security": "none", "uuid": "secret"},
            ]
        }
    }
    routes = advertised_routes(config)
    if routes != [
        {"protocol": "tcp", "port": 80, "security": "none"},
        {"protocol": "tcp", "port": 443, "security": "tls"},
    ] or "secret" in json.dumps(routes):
        raise DriverError("Driver self-test leaked route secrets")
    try:
        advertised_routes({"xray": {"transports": [{"port": 80, "security": "none"}] * 2}})
    except DriverError:
        pass
    else:
        raise DriverError("Driver self-test accepted duplicate routes")
    if not response("routes", advertised_xray_routes=routes)["secret_material_redacted"]:
        raise DriverError("Driver self-test response redaction failed")
    print("LINUX RELEASE UI DRIVER SELF-TEST: PASS")


ACTIONS: dict[str, Callable[[dict[str, Any], dict[str, str], argparse.Namespace], dict[str, Any]]] = {
    "routes": action_routes,
    "clean_install": action_clean_install,
    "connect": action_connect,
    "disconnect": action_disconnect,
    "select_split": action_select_split,
    "launch_split": action_launch_split,
    "network_change_begin": action_network_begin,
    "network_change_restore": action_network_restore,
    "rollback_inject": action_rollback_inject,
    "rollback_restore": action_rollback_restore,
    "capture_map": action_capture_map,
    "finalize": action_finalize,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=sorted(ACTIONS))
    parser.add_argument("--artifact")
    parser.add_argument("--app-version")
    parser.add_argument("--build-number")
    parser.add_argument("--kind")
    parser.add_argument("--port")
    parser.add_argument("--security")
    parser.add_argument("--direct-port")
    parser.add_argument("--interface")
    parser.add_argument("--output")
    parser.add_argument(
        "--internal-ui",
        choices=("click", "require", "set_checked", "set_text", "names"),
    )
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--name", default="")
    parser.add_argument("--contains", action="store_true")
    parser.add_argument("--expected", default="")
    parser.add_argument("--value", default="")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--internal-watchdog", nargs=3, metavar=("KIND", "TOKEN", "SECONDS"))
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.internal_ui:
        return ui_worker(
            args.internal_ui,
            args.pid,
            args.name,
            args.contains,
            args.expected,
            args.value,
        )
    if args.internal_watchdog:
        kind, token, seconds = args.internal_watchdog
        return watchdog(kind, token, int(seconds))
    ensure_root()
    if not args.action:
        parser.error("--action is required")
    state, env = initialize_state()
    result = ACTIONS[args.action](state, env, args)
    encoded = json.dumps(result, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode()) > MAX_JSON_BYTES:
        raise DriverError("Sanitized driver response is unexpectedly large")
    print(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DriverError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"LINUX RELEASE UI DRIVER: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
