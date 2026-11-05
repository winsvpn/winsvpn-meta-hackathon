#!/usr/bin/env python3
"""Unit tests for the browser-agnostic core, run in a real JavaScript engine.

    python3 tools/core_tests.py

There is no Node.js dependency and no test framework. The modules under test are
imported into the extension's own options page inside a headless Chromium, and
the assertions run there. That is worth the small amount of plumbing for two
reasons:

  1. The code is executed by the same engine that will execute it in the field,
     including the generated PAC script -- which is not merely inspected for the
     absence of a DIRECT fallback but CALLED, for a list of hosts, with its
     answers checked.

  2. src/core/ is shared by all three targets. Firefox could not be run on this
     machine, so its adapter is unproven -- but the routing decisions, the rule
     matching, the state machine and the message parsing are the same code, and
     this exercises them. It does not make the Firefox adapter tested. It makes
     the part of Firefox's behaviour that lives in the core tested.
"""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import cdp  # noqa: E402

_CLONE_NOFOLLOW = 0x0001
_POSIX_SPAWN_SETSID = 0x0400
_POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
_POSIX_SPAWN_SETEXEC = 0x0040
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_EXEC = getattr(os, "O_EXEC", 0x40000000)
_UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
CHROME_PRODUCT = "Google Chrome for Testing"
CHROME_APP_NAME = "Google Chrome for Testing.app"
CHROME_EXECUTABLE_REL = Path("Contents/MacOS") / CHROME_PRODUCT
CHROME_ROOT_NAME = "chrome-mac-arm64"
PRIVATE_TMP = Path("/private/tmp")
EXEC_PREFIX = "wins-browser-exec."
REQUEST_NAME = "spawn-request.json"
CODESIGN = Path("/usr/bin/codesign")
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
EXACT_EXEC_BLOCKER = (
    "exact-byte browser execution is unavailable on this owner/environment: "
    "macOS rejects /dev/fd exec (EACCES) and has no fexecve; posix_spawn "
    "re-resolves a path, and a deny-write Seatbelt profile is per-process so "
    "it cannot stop same-UID replacement of the sealed snapshot before exec"
)
_LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
_LIBC.fclonefileat.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
_LIBC.fclonefileat.restype = ctypes.c_int
_LIBC.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32]
_LIBC.clonefile.restype = ctypes.c_int
_LIBC.posix_spawn.restype = ctypes.c_int
_LIBC.posix_spawnattr_init.restype = ctypes.c_int
_LIBC.posix_spawnattr_setflags.restype = ctypes.c_int
_LIBC.posix_spawnattr_destroy.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_init.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_adddup2.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_addopen.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_addinherit_np.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_addfchdir_np.restype = ctypes.c_int
_LIBC.posix_spawn_file_actions_destroy.restype = ctypes.c_int
_LIBC.fchflags.argtypes = [ctypes.c_int, ctypes.c_ulong]
_LIBC.fchflags.restype = ctypes.c_int
_LIBC.proc_pidinfo.argtypes = [
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_int,
]
_LIBC.proc_pidinfo.restype = ctypes.c_int
_PROC_PIDUNIQIDENTIFIERINFO = 17
HELPER_MODULE_NAMES = ("core_tests.py", "cdp.py")
BROWSER_ARCHIVE_TRUST = "release_browser_archive_custody.trust.json"
BROWSER_ARCHIVE_MANIFEST = "toolchain-pins.json"
BROWSER_ARCHIVE_TRUST_CONTRACT = "winsvpn-browser-archive-custody-trust-v1"

FORBIDDEN_BROWSER_ENV_PREFIXES = (
    "PYTHON",
    "DYLD",
    "JAVA",
    "JDK_",
    "OPENSSL",
    "SSL_",
    "WINS_ANDROID",
    "WINS_RELEASE_",
)
FORBIDDEN_BROWSER_ENV_NAMES = frozenset(
    {
        "JAVA_HOME",
        "JDK_HOME",
        "OPENSSL_CONF",
        "OPENSSL_ENGINES",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONEXECUTABLE",
        "PYTHONSTARTUP",
        "PYTHONSAFEPATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "BROWSER_BIN",
    }
)
FORBIDDEN_CREDENTIAL_MARKERS = (
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    "AUTHORIZATION",
    "BEARER",
    "COOKIE",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "SESSION_KEY",
)

_EXACT_EXEC_PROBED: bool | None = None


class ProcessTreeCleanupError(RuntimeError):
    """Descendant cleanup could not prove every child exited."""


class ExactExecutionUnavailable(RuntimeError):
    """This owner/environment cannot bind posix_spawn to authenticated bytes."""


def resolve_browser_bin(
    env: dict[str, str] | os._Environ[str] | None = None,
) -> str:
    environment = os.environ if env is None else env
    explicit = environment.get("BROWSER_BIN", "")
    if not explicit or explicit.strip() != explicit:
        raise FileNotFoundError("BROWSER_BIN must explicitly name the release browser")
    path = Path(explicit)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or not os.access(path, os.X_OK)
    ):
        raise FileNotFoundError(
            "BROWSER_BIN must be one absolute executable regular non-symlink file"
        )
    return str(path)


def env_is_forbidden(name: str) -> bool:
    upper = name.upper()
    if upper in FORBIDDEN_BROWSER_ENV_NAMES:
        return True
    if any(marker in upper for marker in FORBIDDEN_CREDENTIAL_MARKERS):
        return True
    return any(upper.startswith(prefix) for prefix in FORBIDDEN_BROWSER_ENV_PREFIXES)


def browser_child_env(
    home: str, tmpdir: str, extra: dict[str, str] | None = None
) -> dict[str, str]:
    env = {
        "HOME": home,
        "TMPDIR": tmpdir,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
    }
    if extra:
        for name, value in extra.items():
            if env_is_forbidden(name):
                raise ValueError(f"refusing to pass {name} into the browser environment")
            if "\x00" in name or "\x00" in value:
                raise ValueError("browser environment values must not contain NUL")
            env[name] = value
    leaked = [name for name in env if env_is_forbidden(name)]
    if leaked:
        raise ValueError(f"browser environment contains forbidden names: {leaked}")
    return env


def _posix_errno(rc: int, what: str) -> OSError:
    return OSError(rc, f"{what}: {os.strerror(rc)}")


def _must(rc: int, what: str) -> None:
    if rc:
        raise _posix_errno(rc if rc > 0 else ctypes.get_errno() or rc, what)


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_nofollow(path: str, flags: int = os.O_RDONLY) -> int:
    return os.open(path, flags | _O_CLOEXEC | _O_NOFOLLOW)


def _inode(info: os.stat_result) -> tuple[int, int]:
    return (info.st_dev, info.st_ino)


def _close_fd(fd: int | None) -> None:
    if fd is None or fd < 0:
        return
    try:
        os.close(fd)
    except OSError:
        pass


def _file_identity(path: Path) -> dict[str, object]:
    fd = _open_nofollow(str(path))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"regular file required: {path}")
        return {
            "digest": _sha256_fd(fd),
            "dev": info.st_dev,
            "ino": info.st_ino,
            "size": info.st_size,
            "mode": stat.S_IMODE(info.st_mode),
        }
    finally:
        os.close(fd)


def _verify_file_identity(path: Path, expected: dict[str, object], label: str) -> None:
    current = _file_identity(path)
    if current != expected:
        raise RuntimeError(f"{label} identity changed")


def _sha256_path(path: str) -> str:
    fd = _open_nofollow(path)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"regular file required to hash: {path}")
        return _sha256_fd(fd)
    finally:
        os.close(fd)


def _require_hex64(value: str, label: str) -> str:
    if HEX_RE.fullmatch(value) is None:
        raise RuntimeError(f"{label} is not an exact SHA-256 receipt digest")
    return value


def _check_path_components(path: Path) -> None:
    if not path.is_absolute():
        raise RuntimeError(f"path is not absolute: {path}")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in {"", ".", ".."}:
            raise RuntimeError(f"unsafe path component: {path}")
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError(f"symbolic path component rejected: {current}")
        if info.st_uid not in {0, os.getuid()}:
            raise RuntimeError(f"foreign-owned path component rejected: {current}")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 and not (
            stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and mode & stat.S_ISVTX
        ):
            raise RuntimeError(f"group/world-writable path component rejected: {current}")


def _require_system_tool(path: Path) -> None:
    _check_path_components(path)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise RuntimeError(f"required system tool is unavailable: {path}")


def app_bundle_for_executable(path: Path) -> Path | None:
    macos = path.parent
    contents = macos.parent
    app = contents.parent
    if macos.name == "MacOS" and contents.name == "Contents" and app.name.endswith(".app"):
        return app
    return None


def _feed_digest(digest: hashlib._Hash, *parts: object) -> None:
    for part in parts:
        if isinstance(part, int):
            digest.update(part.to_bytes(8, "big", signed=False))
            continue
        if isinstance(part, bytes):
            value = part
        else:
            value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


@dataclass(frozen=True)
class TreeEntry:
    relative: str
    kind: str
    mode: int
    size: int
    link: str
    digest: str


def tree_binding_digest(entries: list[TreeEntry]) -> str:
    digest = hashlib.sha256()
    for entry in sorted(entries, key=lambda item: os.fsencode(item.relative)):
        _feed_digest(
            digest,
            entry.kind,
            entry.relative,
            entry.mode,
            entry.size,
            entry.link,
            entry.digest,
        )
    return digest.hexdigest()


def _frozen_file_mode(mode: int) -> int:
    return 0o500 if mode & 0o111 else 0o400


def _archive_tree_feed(digest: hashlib._Hash, *parts: object) -> None:
    # Must match tools/release_browser_archive_custody.py tree_hash(): every
    # part is length-prefixed UTF-8 of str(part), including integer modes/sizes.
    for part in parts:
        value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def archive_tree_digest(root: Path) -> str:
    if root.is_symlink():
        raise RuntimeError("Chrome root symbolic link rejected")
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o500:
        raise RuntimeError("Chrome root is not owner-controlled and frozen")
    digest = hashlib.sha256()

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != os.getuid():
                raise RuntimeError(f"unsafe Chrome tree ownership or mode: {relative}")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _reject_escaping_link(root, path, target)
                _archive_tree_feed(digest, "L", relative, target)
            elif mode & 0o022:
                raise RuntimeError(f"unsafe Chrome tree ownership or mode: {relative}")
            elif stat.S_ISDIR(info.st_mode):
                if mode != 0o500:
                    raise RuntimeError(f"Chrome directory is not frozen: {relative}")
                _archive_tree_feed(digest, "D", relative, mode)
                walk(path)
            elif stat.S_ISREG(info.st_mode):
                expected_mode = (
                    0o500
                    if relative == str(Path(CHROME_APP_NAME) / CHROME_EXECUTABLE_REL) or mode == 0o500
                    else 0o400
                )
                if info.st_nlink != 1 or mode != expected_mode:
                    raise RuntimeError(f"Chrome file mode or hardlink rejected: {relative}")
                _archive_tree_feed(
                    digest, "F", relative, mode, info.st_size, _sha256_path(str(path))
                )
            else:
                raise RuntimeError(f"unsupported Chrome tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def _reject_escaping_link(root: Path, link: Path, target: str) -> None:
    if not target or target.startswith("/") or "\\" in target or any(ord(ch) < 32 for ch in target):
        raise RuntimeError(f"unsafe symbolic-link target rejected: {link}")
    try:
        resolved = link.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (FileNotFoundError, RuntimeError, ValueError, OSError) as exc:
        raise RuntimeError(f"escaping or broken symbolic link rejected: {link}") from exc


def _clone_or_copy_regular(src_fd: int, dest_dirfd: int, name: str, mode: int) -> tuple[str, int]:
    encoded = os.fsencode(name)
    rc = _LIBC.fclonefileat(src_fd, dest_dirfd, encoded, 0)
    if rc != 0:
        dest_fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_CLOEXEC | _O_NOFOLLOW,
            0o400,
            dir_fd=dest_dirfd,
        )
        try:
            os.lseek(src_fd, 0, os.SEEK_SET)
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(dest_fd, view)
                    if written <= 0:
                        raise RuntimeError("short write while snapshotting a regular file")
                    view = view[written:]
        finally:
            os.close(dest_fd)
    copied = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=dest_dirfd)
    try:
        info = os.fstat(copied)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("snapshot member is not a regular file")
        os.fchmod(copied, mode)
        digest = _sha256_fd(copied)
        source_digest = _sha256_fd(src_fd)
        if digest != source_digest:
            raise RuntimeError("descriptor snapshot digest mismatch")
        return digest, info.st_size
    finally:
        os.close(copied)


def _snapshot_tree(source: Path, destination: Path) -> list[TreeEntry]:
    _check_path_components(source)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("snapshot destination already exists")
    destination.mkdir(mode=0o700)
    src_root_fd = os.open(str(source), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    dest_root_fd = os.open(str(destination), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    entries: list[TreeEntry] = []
    try:
        src_info = os.fstat(src_root_fd)
        if not stat.S_ISDIR(src_info.st_mode):
            raise RuntimeError("snapshot source is not a directory")
        entries.extend(_walk_snapshot(src_root_fd, dest_root_fd, source, destination, ""))
    finally:
        os.close(src_root_fd)
        os.close(dest_root_fd)
    _freeze_snapshot_dirs(destination, entries)
    return entries


def _freeze_snapshot_dirs(root: Path, entries: list[TreeEntry]) -> None:
    for entry in sorted(entries, key=lambda item: item.relative.count("/"), reverse=True):
        if entry.kind != "D":
            continue
        os.chmod(root / entry.relative, 0o500, follow_symlinks=False)
    os.chmod(root, 0o500, follow_symlinks=False)


def _walk_snapshot(
    src_dirfd: int,
    dest_dirfd: int,
    src_root: Path,
    dest_root: Path,
    prefix: str,
) -> list[TreeEntry]:
    collected: list[TreeEntry] = []
    names = sorted(os.listdir(src_dirfd), key=os.fsencode)
    for name in names:
        if name in {".", ".."}:
            continue
        relative = name if not prefix else f"{prefix}/{name}"
        info = os.lstat(name, dir_fd=src_dirfd)
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(name, dir_fd=src_dirfd)
            _reject_escaping_link(src_root, src_root / relative, target)
            os.symlink(target, name, dir_fd=dest_dirfd)
            collected.append(TreeEntry(relative, "L", mode, 0, target, ""))
            continue
        if stat.S_ISDIR(info.st_mode):
            os.mkdir(name, 0o700, dir_fd=dest_dirfd)
            child_src = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=src_dirfd)
            child_dest = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=dest_dirfd)
            try:
                collected.append(TreeEntry(relative, "D", 0o500, 0, "", ""))
                collected.extend(
                    _walk_snapshot(child_src, child_dest, src_root, dest_root, relative)
                )
            finally:
                os.close(child_src)
                os.close(child_dest)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"unsupported snapshot member: {relative}")
        if info.st_nlink != 1:
            raise RuntimeError(f"hardlinked snapshot member rejected: {relative}")
        frozen = _frozen_file_mode(mode)
        src_fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=src_dirfd)
        try:
            digest, size = _clone_or_copy_regular(src_fd, dest_dirfd, name, frozen)
        finally:
            os.close(src_fd)
        collected.append(TreeEntry(relative, "F", frozen, size, "", digest))
    return collected


def _snapshot_regular_file(source: Path, destination_dir: Path) -> list[TreeEntry]:
    _check_path_components(source)
    destination_dir.mkdir(mode=0o700)
    src_fd = _open_nofollow(str(source))
    dest_dirfd = os.open(str(destination_dir), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        info = os.fstat(src_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError("source is not one regular non-hardlinked file")
        mode = 0o500 if stat.S_IMODE(info.st_mode) & 0o111 else 0o400
        digest, size = _clone_or_copy_regular(src_fd, dest_dirfd, "executable", mode)
        return [TreeEntry("executable", "F", mode, size, "", digest)]
    finally:
        os.close(src_fd)
        os.close(dest_dirfd)


def inspect_source_tree(source: Path) -> list[TreeEntry]:
    if source.is_symlink():
        raise RuntimeError("snapshot source may not be a symbolic link")
    if source.is_file():
        fd = _open_nofollow(str(source))
        try:
            info = os.fstat(fd)
            mode = 0o500 if stat.S_IMODE(info.st_mode) & 0o111 else 0o400
            return [TreeEntry("executable", "F", mode, info.st_size, "", _sha256_fd(fd))]
        finally:
            os.close(fd)
    if not source.is_dir():
        raise RuntimeError("snapshot source must be a directory or regular file")
    root_fd = os.open(str(source), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        return _inspect_walk(root_fd, source, "")
    finally:
        os.close(root_fd)


def _inspect_walk(dirfd: int, src_root: Path, prefix: str) -> list[TreeEntry]:
    collected: list[TreeEntry] = []
    for name in sorted(os.listdir(dirfd), key=os.fsencode):
        if name in {".", ".."}:
            continue
        relative = name if not prefix else f"{prefix}/{name}"
        info = os.lstat(name, dir_fd=dirfd)
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(name, dir_fd=dirfd)
            _reject_escaping_link(src_root, src_root / relative, target)
            collected.append(TreeEntry(relative, "L", mode, 0, target, ""))
            continue
        if stat.S_ISDIR(info.st_mode):
            collected.append(TreeEntry(relative, "D", 0o500, 0, "", ""))
            child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=dirfd)
            try:
                collected.extend(_inspect_walk(child, src_root, relative))
            finally:
                os.close(child)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"unsupported source member: {relative}")
        if info.st_nlink != 1:
            raise RuntimeError(f"hardlinked source member rejected: {relative}")
        fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=dirfd)
        try:
            collected.append(
                TreeEntry(relative, "F", _frozen_file_mode(mode), info.st_size, "", _sha256_fd(fd))
            )
        finally:
            os.close(fd)
    return collected


_CODESIGN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
_NO_RESOURCES = "code has no resources but signature indicates they must be present"


def _signed_macho(app: Path) -> Path:
    if app.is_file() and not app.is_symlink():
        return app
    macos = app / "Contents" / "MacOS"
    chrome = macos / CHROME_PRODUCT
    if chrome.is_file() and not chrome.is_symlink():
        return chrome
    if macos.is_dir():
        files = [path for path in macos.iterdir() if path.is_file() and not path.is_symlink()]
        if len(files) == 1:
            return files[0]
    return app


def _run_codesign(*args: str) -> subprocess.CompletedProcess[str]:
    _require_system_tool(CODESIGN)
    return subprocess.run(
        [str(CODESIGN), *args],
        check=False,
        capture_output=True,
        text=True,
        env=_CODESIGN_ENV,
    )


def _layout_safe_verify_dir(app: Path) -> Path:
    current = app.resolve()
    while current != current.parent:
        if current.parent == PRIVATE_TMP and current.name.startswith(EXEC_PREFIX):
            return current
        current = current.parent
    return PRIVATE_TMP


def _codesign_verify_layout_safe(
    app: Path, extra: list[str], *, allow_immutable: bool
) -> None:
    completed = _run_codesign("--verify", "--deep", "--strict", *extra, str(app))
    if completed.returncode == 0:
        return
    text = f"{completed.stdout}\n{completed.stderr}"
    if _NO_RESOURCES not in text:
        raise RuntimeError(
            f"Chrome code signature failed strict verification: {text.strip()[:800]}"
        )
    binary = _signed_macho(app)
    if not binary.is_file() or binary.is_symlink():
        raise RuntimeError("signed Mach-O is absent for strict verification")
    link_dir = _layout_safe_verify_dir(app)
    link = link_dir / f".macho-verify.{os.getpid()}"
    if link.exists() or link.is_symlink():
        raise RuntimeError("Chrome macho verification path already exists")
    try:
        os.link(binary, link)
    except PermissionError:
        if allow_immutable:
            return
        raise RuntimeError("Chrome macho verification link could not be created")
    try:
        linked = link.lstat()
        source = binary.lstat()
        if (linked.st_dev, linked.st_ino) != (source.st_dev, source.st_ino):
            raise RuntimeError("Chrome macho verification link is not the frozen executable")
        completed = _run_codesign("--verify", "--deep", "--strict", *extra, str(link))
        if completed.returncode != 0:
            err = f"{completed.stdout}\n{completed.stderr}".strip()[:800]
            raise RuntimeError(f"Chrome code signature failed strict verification: {err}")
    finally:
        try:
            link.unlink()
        except FileNotFoundError:
            pass


def _codesign_verify(app: Path, *, allow_immutable: bool = False) -> None:
    _codesign_verify_layout_safe(app, [], allow_immutable=allow_immutable)


def _codesign_display(app: Path) -> tuple[str, str]:
    _require_system_tool(CODESIGN)
    displayed = subprocess.run(
        [str(CODESIGN), "--display", "--verbose=2", str(app)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if displayed.returncode != 0:
        raise RuntimeError("code signature identity could not be read")
    text = f"{displayed.stdout}\n{displayed.stderr}"
    authorities: list[str] = []
    signature = ""
    identifier = ""
    for line in text.splitlines():
        if line.startswith("Authority="):
            authorities.append(line.split("=", 1)[1])
        elif line.startswith("Signature="):
            signature = line.split("=", 1)[1]
        elif line.startswith("Identifier="):
            identifier = line.split("=", 1)[1]
    identity = authorities[0] if authorities else ("adhoc" if signature == "adhoc" else "")
    if not identity:
        raise RuntimeError("code signature identity is absent")
    requirement = subprocess.run(
        [str(CODESIGN), "-d", "-r", "-", str(app)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    designated = ""
    blob = f"{requirement.stdout}\n{requirement.stderr}"
    for line in blob.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped.startswith("designated =>"):
            designated = stripped
            break
    if not designated:
        raise RuntimeError("designated requirement is absent")
    return identity, designated


def _codesign_verify_requirement(
    app: Path, designated: str, *, allow_immutable: bool = False
) -> None:
    requirement = designated
    if requirement.startswith("designated =>"):
        requirement = requirement.split("=>", 1)[1].strip()
    _codesign_verify_layout_safe(
        app,
        ["--requirements", f"={requirement}"],
        allow_immutable=allow_immutable,
    )


def _probe_dev_fd_exec() -> bool:
    if sys.platform != "darwin":
        return False
    probe_dir = Path(tempfile.mkdtemp(prefix="wins-fd-exec-probe.", dir=str(PRIVATE_TMP)))
    source = probe_dir / "probe.c"
    binary = probe_dir / "probe"
    try:
        source.write_text("int main(void) { return 7; }\n", encoding="utf-8")
        compiled = subprocess.run(
            ["/usr/bin/clang", "-Os", "-o", str(binary), str(source)],
            check=False,
            capture_output=True,
            text=True,
        )
        if compiled.returncode != 0 or not binary.is_file():
            return False
        fd = os.open(str(binary), os.O_RDONLY)
        try:
            os.set_inheritable(fd, True)
            pid = os.fork()
            if pid == 0:
                try:
                    os.execve(f"/dev/fd/{fd}", [str(binary)], {})
                except OSError:
                    os._exit(91)
            _, status = os.waitpid(pid, 0)
            if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 7:
                return True
        finally:
            os.close(fd)
        return False
    except OSError:
        return False
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)


def _load_json_regular(path: Path) -> tuple[object, str]:
    _check_path_components(path)
    fd = _open_nofollow(str(path))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"regular JSON file required: {path}")
        digest = _sha256_fd(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    try:
        return json.loads(b"".join(chunks).decode("utf-8")), digest
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"authenticated JSON could not be parsed: {path}") from exc


def _text_field(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value or value.strip() != value:
        raise RuntimeError(f"browser archive receipt field is not exact text: {key}")
    return value


def external_browser_archive_receipt() -> dict[str, str]:
    tools = HERE.parents[1] / "tools"
    trust_path = tools / BROWSER_ARCHIVE_TRUST
    manifest_path = tools / BROWSER_ARCHIVE_MANIFEST
    trust_document, _trust_digest = _load_json_regular(trust_path)
    if type(trust_document) is not dict:
        raise RuntimeError("browser archive trust document is not an object")
    if trust_document.get("contract") != BROWSER_ARCHIVE_TRUST_CONTRACT:
        raise RuntimeError("browser archive trust contract is not authentic")
    if trust_document.get("manifest") != f"tools/{BROWSER_ARCHIVE_MANIFEST}":
        raise RuntimeError("browser archive trust manifest path mismatch")
    expected_manifest = trust_document.get("manifest_sha256")
    if type(expected_manifest) is not str or HEX_RE.fullmatch(expected_manifest) is None:
        raise RuntimeError("browser archive trust is missing the manifest digest")
    manifest, manifest_digest = _load_json_regular(manifest_path)
    if manifest_digest != expected_manifest:
        raise RuntimeError(
            "browser archive receipt is not the externally authenticated manifest digest"
        )
    if type(manifest) is not dict:
        raise RuntimeError("browser archive pin manifest is not an object")
    tools_map = manifest.get("tools")
    if type(tools_map) is not dict:
        raise RuntimeError("browser archive pin tools object is absent")
    browser = tools_map.get("browser")
    if type(browser) is not dict:
        raise RuntimeError("browser archive pin browser object is absent")
    archive_hashes = browser.get("archive_sha256")
    tree_hashes = browser.get("install_tree_sha256")
    if type(archive_hashes) is not dict or type(tree_hashes) is not dict:
        raise RuntimeError("browser archive pin digest maps are absent")
    pin = {
        "product": _text_field(browser, "product"),
        "version": _text_field(browser, "version"),
        "tree_sha": _text_field(tree_hashes, "darwin_arm64"),
        "executable_sha": _text_field(browser, "executable_sha256"),
        "signing_identity": _text_field(browser, "signing_identity"),
        "root": _text_field(browser, "top_level_root"),
        "executable": _text_field(browser, "executable"),
        "archive_sha": _text_field(archive_hashes, "darwin_arm64"),
    }
    if pin["product"] != CHROME_PRODUCT:
        raise RuntimeError("browser archive receipt product is not Google Chrome for Testing")
    if pin["root"] != CHROME_ROOT_NAME:
        raise RuntimeError("browser archive receipt root is not chrome-mac-arm64")
    if pin["executable"] != str(Path(CHROME_APP_NAME) / CHROME_EXECUTABLE_REL):
        raise RuntimeError("browser archive receipt executable layout mismatch")
    for key in ("tree_sha", "executable_sha", "archive_sha"):
        _require_hex64(pin[key], f"browser archive {key}")
    return pin


def _mkdirat_exclusive(dirfd: int, name: str, mode: int = 0o700) -> int:
    try:
        existing = os.lstat(name, dir_fd=dirfd)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise RuntimeError(f"symbolic {name} directory rejected")
        raise RuntimeError(f"{name} residue remains")
    os.mkdir(name, mode, dir_fd=dirfd)
    child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=dirfd)
    try:
        info = os.fstat(child)
        if not stat.S_ISDIR(info.st_mode):
            os.close(child)
            raise RuntimeError(f"{name} is not a directory")
        return child
    except Exception:
        _close_fd(child)
        raise


def create_browser_state_dirs(work: Path) -> tuple[Path, Path, Path]:
    _check_path_components(work)
    work_fd = os.open(str(work), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    created: list[int] = []
    try:
        work_info = os.fstat(work_fd)
        path_info = work.lstat()
        if stat.S_ISLNK(path_info.st_mode) or _inode(work_info) != _inode(path_info):
            raise RuntimeError("browser work directory inode was replaced")
        for name in ("profile", "home", "tmp"):
            created.append(_mkdirat_exclusive(work_fd, name))
        return work / "profile", work / "home", work / "tmp"
    finally:
        for fd in created:
            _close_fd(fd)
        _close_fd(work_fd)


def exact_execution_defended() -> bool:
    global _EXACT_EXEC_PROBED
    if _EXACT_EXEC_PROBED is None:
        _EXACT_EXEC_PROBED = _probe_dev_fd_exec()
    return _EXACT_EXEC_PROBED


@dataclass
class BrowserReceipt:
    executable: Path
    executable_sha256: str
    tree_sha256: str
    app: Path
    root: Path
    runtime: Path
    signing_identity: str
    product: str
    version: str


def require_release_browser_identity(
    env: dict[str, str] | os._Environ[str] | None = None,
) -> BrowserReceipt:
    pin = external_browser_archive_receipt()
    environment = os.environ if env is None else env
    required = {
        "WINS_RELEASE_BROWSER": environment.get("WINS_RELEASE_BROWSER", ""),
        "WINS_RELEASE_BROWSER_SHA256": environment.get("WINS_RELEASE_BROWSER_SHA256", ""),
        "WINS_RELEASE_BROWSER_TREE_SHA256": environment.get("WINS_RELEASE_BROWSER_TREE_SHA256", ""),
        "WINS_RELEASE_BROWSER_APP": environment.get("WINS_RELEASE_BROWSER_APP", ""),
        "WINS_RELEASE_BROWSER_ROOT": environment.get("WINS_RELEASE_BROWSER_ROOT", ""),
        "WINS_RELEASE_BROWSER_RUNTIME": environment.get("WINS_RELEASE_BROWSER_RUNTIME", ""),
        "WINS_RELEASE_BROWSER_SIGNING_IDENTITY": environment.get(
            "WINS_RELEASE_BROWSER_SIGNING_IDENTITY", ""
        ),
        "WINS_RELEASE_BROWSER_PRODUCT": environment.get("WINS_RELEASE_BROWSER_PRODUCT", CHROME_PRODUCT),
        "WINS_RELEASE_BROWSER_VERSION": environment.get("WINS_RELEASE_BROWSER_VERSION", ""),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(
            "authenticated browser receipt identities are absent: " + ", ".join(missing)
        )
    if required["WINS_RELEASE_BROWSER_SHA256"] != pin["executable_sha"]:
        raise RuntimeError(
            "runtime identity is not the externally authenticated browser archive receipt"
        )
    if required["WINS_RELEASE_BROWSER_TREE_SHA256"] != pin["tree_sha"]:
        raise RuntimeError(
            "runtime identity is not the externally authenticated browser archive receipt"
        )
    if required["WINS_RELEASE_BROWSER_SIGNING_IDENTITY"] != pin["signing_identity"]:
        raise RuntimeError(
            "runtime identity is not the externally authenticated browser archive receipt"
        )
    if required["WINS_RELEASE_BROWSER_PRODUCT"] != pin["product"]:
        raise RuntimeError("WINS_RELEASE_BROWSER_PRODUCT is not Google Chrome for Testing")
    if required["WINS_RELEASE_BROWSER_VERSION"] != pin["version"]:
        raise RuntimeError(
            "runtime identity is not the externally authenticated browser archive receipt"
        )
    executable = Path(required["WINS_RELEASE_BROWSER"])
    app = Path(required["WINS_RELEASE_BROWSER_APP"])
    root = Path(required["WINS_RELEASE_BROWSER_ROOT"])
    runtime = Path(required["WINS_RELEASE_BROWSER_RUNTIME"])
    for path in (runtime, root, app, executable):
        _check_path_components(path)
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith("wins-release-browser."):
        raise RuntimeError("WINS_RELEASE_BROWSER_RUNTIME escaped its private prefix")
    if root != runtime / "extracted" / CHROME_ROOT_NAME:
        raise RuntimeError("WINS_RELEASE_BROWSER_ROOT is not the receipt extracted Chrome root")
    if app != root / CHROME_APP_NAME:
        raise RuntimeError("WINS_RELEASE_BROWSER_APP is not the receipt Chrome bundle")
    if executable != app / CHROME_EXECUTABLE_REL:
        raise RuntimeError("WINS_RELEASE_BROWSER is not the receipt Chrome executable")
    browser_bin = environment.get("BROWSER_BIN", "")
    if browser_bin and browser_bin != str(executable):
        raise RuntimeError("BROWSER_BIN is not the receipt-bound Chrome executable")
    measured_executable = _sha256_path(str(executable))
    if measured_executable != pin["executable_sha"]:
        raise RuntimeError("live Chrome executable is not the externally authenticated digest")
    measured_tree = archive_tree_digest(root)
    if measured_tree != pin["tree_sha"]:
        raise RuntimeError("live Chrome tree is not the externally authenticated digest")
    return BrowserReceipt(
        executable=executable,
        executable_sha256=pin["executable_sha"],
        tree_sha256=pin["tree_sha"],
        app=app,
        root=root,
        runtime=runtime,
        signing_identity=pin["signing_identity"],
        product=pin["product"],
        version=pin["version"],
    )


class ExecutionImage:
    def __init__(
        self,
        root: Path,
        path: str,
        executable_digest: str,
        tree_digest: str,
        source: str,
        entries: list[TreeEntry],
        archive_tree: bool,
        signing_identity: str | None,
        designated_requirement: str | None,
        sealed_root: Path,
        exec_fd: int,
        root_fd: int,
        sealed_fd: int,
    ):
        self.root = root
        self.path = path
        self.digest = executable_digest
        self.tree_digest = tree_digest
        self.source = source
        self.entries = entries
        self.archive_tree = archive_tree
        self.signing_identity = signing_identity
        self.designated_requirement = designated_requirement
        self.sealed_root = sealed_root
        self._exec_fd = exec_fd
        self._root_fd = root_fd
        self._sealed_fd = sealed_fd
        self._exec_id = _inode(os.fstat(exec_fd))
        self._root_id = _inode(os.fstat(root_fd))
        self._sealed_id = _inode(os.fstat(sealed_fd))
        self._cleaned = False
        self._sealed = False

    def assert_bound_identity(self) -> None:
        if self._cleaned:
            raise RuntimeError("execution image was already cleaned up")
        if self._exec_fd < 0 or self._root_fd < 0 or self._sealed_fd < 0:
            raise RuntimeError("execution image descriptors were closed")
        exec_info = os.fstat(self._exec_fd)
        if _inode(exec_info) != self._exec_id:
            raise RuntimeError("execution image executable inode was replaced")
        try:
            path_info = os.lstat(self.path)
        except OSError as exc:
            raise RuntimeError("execution image executable inode was replaced") from exc
        if stat.S_ISLNK(path_info.st_mode) or _inode(path_info) != self._exec_id:
            raise RuntimeError("execution image executable inode was replaced")
        if _sha256_fd(self._exec_fd) != self.digest:
            raise RuntimeError("execution image digest changed before posix_spawn")
        root_info = os.fstat(self._root_fd)
        if _inode(root_info) != self._root_id:
            raise RuntimeError("execution image root inode was replaced")
        try:
            root_path = os.lstat(self.root)
        except OSError as exc:
            raise RuntimeError("execution image root inode was replaced") from exc
        if stat.S_ISLNK(root_path.st_mode) or _inode(root_path) != self._root_id:
            raise RuntimeError("execution image root inode was replaced")
        sealed_info = os.fstat(self._sealed_fd)
        if _inode(sealed_info) != self._sealed_id:
            raise RuntimeError("execution image sealed root inode was replaced")
        try:
            sealed_path = os.lstat(self.sealed_root)
        except OSError as exc:
            raise RuntimeError("execution image sealed root inode was replaced") from exc
        if stat.S_ISLNK(sealed_path.st_mode) or _inode(sealed_path) != self._sealed_id:
            raise RuntimeError("execution image sealed root inode was replaced")

    def verify(self) -> None:
        self.assert_bound_identity()
        current = inspect_source_tree(self.sealed_root)
        if tree_binding_digest(current) != tree_binding_digest(self.entries):
            raise RuntimeError("execution image tree changed before posix_spawn")
        if self.archive_tree:
            if archive_tree_digest(self.sealed_root) != self.tree_digest:
                raise RuntimeError("execution image archive tree digest changed before posix_spawn")
        elif tree_binding_digest(current) != self.tree_digest:
            raise RuntimeError("execution image tree digest changed before posix_spawn")
        if self.signing_identity is not None:
            app = app_bundle_for_executable(Path(self.path))
            target = app if app is not None else Path(self.path)
            _codesign_verify(target, allow_immutable=self._sealed)
            identity, designated = _codesign_display(target)
            if identity != self.signing_identity:
                raise RuntimeError("execution image signing identity changed")
            if self.designated_requirement and designated != self.designated_requirement:
                raise RuntimeError("execution image designated requirement changed")
            if self.designated_requirement:
                _codesign_verify_requirement(
                    target, self.designated_requirement, allow_immutable=self._sealed
                )
        self.assert_bound_identity()

    def seal(self) -> None:
        if self._sealed:
            return
        self.assert_bound_identity()
        _seal_tree_from_dirfd(self._sealed_fd)
        if self._sealed_fd != self._root_fd:
            _seal_dirfd(self._root_fd)
        self._sealed = True
        self.assert_bound_identity()

    def cleanup(self) -> None:
        if self._cleaned:
            if self.root.exists() or self.root.is_symlink():
                raise RuntimeError("snapshot residue remains")
            return
        errors: list[str] = []
        self._cleaned = True
        try:
            if self._exec_fd >= 0:
                _close_fd(self._exec_fd)
                self._exec_fd = -1
            if self._sealed_fd >= 0 and self._sealed_fd != self._root_fd:
                try:
                    _destroy_tree_from_dirfd(self._sealed_fd)
                except (RuntimeError, OSError) as exc:
                    errors.append(str(exc))
                _close_fd(self._sealed_fd)
                self._sealed_fd = -1
            if self._root_fd >= 0:
                try:
                    _destroy_tree_from_dirfd(self._root_fd)
                except (RuntimeError, OSError) as exc:
                    errors.append(str(exc))
                try:
                    _unlink_dir_if_same_inode(self.root, self._root_id, self._root_fd)
                except (RuntimeError, OSError) as exc:
                    errors.append(str(exc))
                _close_fd(self._root_fd)
                self._root_fd = -1
            if self.root.exists() or self.root.is_symlink():
                errors.append("snapshot residue remains")
        finally:
            _close_fd(self._exec_fd)
            _close_fd(self._sealed_fd)
            _close_fd(self._root_fd)
            self._exec_fd = self._sealed_fd = self._root_fd = -1
        if errors:
            raise RuntimeError("snapshot cleanup failed: " + "; ".join(errors))


def _fchflags(fd: int, flags: int) -> None:
    if not _UF_IMMUTABLE:
        return
    rc = _LIBC.fchflags(fd, flags)
    if rc != 0:
        err = ctypes.get_errno()
        if err not in {
            errno.EOPNOTSUPP,
            errno.ENOTSUP,
            errno.EINVAL,
            errno.EPERM,
            errno.ENOENT,
        }:
            raise OSError(err, f"fchflags: {os.strerror(err)}")


def _seal_dirfd(dirfd: int) -> None:
    _fchflags(dirfd, 0)
    os.fchmod(dirfd, 0o500)
    _fchflags(dirfd, _UF_IMMUTABLE)


def _seal_tree_from_dirfd(dirfd: int) -> None:
    names = os.listdir(dirfd)
    for name in names:
        if name in {".", ".."}:
            continue
        info = os.lstat(name, dir_fd=dirfd)
        if stat.S_ISLNK(info.st_mode):
            continue
        flags = os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW
        if stat.S_ISDIR(info.st_mode):
            flags |= _O_DIRECTORY
        try:
            child = os.open(name, flags, dir_fd=dirfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise RuntimeError("substituted symlink during seal") from exc
            raise
        try:
            child_info = os.fstat(child)
            if stat.S_ISDIR(child_info.st_mode):
                _seal_tree_from_dirfd(child)
            elif stat.S_ISREG(child_info.st_mode):
                os.fchmod(child, stat.S_IMODE(child_info.st_mode) & ~0o222)
                _fchflags(child, _UF_IMMUTABLE)
            else:
                raise RuntimeError("unsupported snapshot member during seal")
        finally:
            os.close(child)
    _seal_dirfd(dirfd)


def _destroy_tree_from_dirfd(dirfd: int) -> None:
    for _attempt in range(8):
        _fchflags(dirfd, 0)
        try:
            os.fchmod(dirfd, 0o700)
        except OSError as exc:
            raise RuntimeError(f"cleanup could not unfreeze snapshot directory: {exc}") from exc
        try:
            names = [name for name in os.listdir(dirfd) if name not in {".", ".."}]
        except OSError as exc:
            raise RuntimeError(f"cleanup could not list snapshot: {exc}") from exc
        if not names:
            return
        for name in names:
            try:
                info = os.lstat(name, dir_fd=dirfd)
            except OSError as exc:
                raise RuntimeError(f"cleanup lstat failed: {name}") from exc
            if stat.S_ISLNK(info.st_mode):
                os.unlink(name, dir_fd=dirfd)
                continue
            flags = os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW
            if stat.S_ISDIR(info.st_mode):
                flags |= _O_DIRECTORY
            try:
                child = os.open(name, flags, dir_fd=dirfd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    os.unlink(name, dir_fd=dirfd)
                    continue
                raise RuntimeError(f"cleanup open failed: {name}") from exc
            try:
                child_info = os.fstat(child)
                if stat.S_ISDIR(child_info.st_mode):
                    _destroy_tree_from_dirfd(child)
                elif stat.S_ISREG(child_info.st_mode):
                    _fchflags(child, 0)
                    os.fchmod(child, 0o600)
                else:
                    raise RuntimeError(f"unsupported cleanup member: {name}")
            finally:
                os.close(child)
            if stat.S_ISDIR(info.st_mode):
                os.rmdir(name, dir_fd=dirfd)
            else:
                os.unlink(name, dir_fd=dirfd)
    leftover = [name for name in os.listdir(dirfd) if name not in {".", ".."}]
    if leftover:
        raise RuntimeError("snapshot residue remains: " + ", ".join(leftover[:8]))


def _unlink_dir_if_same_inode(path: Path, expected: tuple[int, int], dirfd: int) -> None:
    parent = path.parent
    parent_fd = os.open(str(parent), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode) or _inode(info) != expected:
            raise RuntimeError("snapshot path was substituted; residue remains")
        held = os.fstat(dirfd)
        if _inode(held) != expected:
            raise RuntimeError("snapshot path was substituted; residue remains")
        os.rmdir(path.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _unfreeze_tree_from_dirfd(dirfd: int) -> None:
    _fchflags(dirfd, 0)
    try:
        os.fchmod(dirfd, 0o700)
    except OSError:
        pass
    for name in os.listdir(dirfd):
        if name in {".", ".."}:
            continue
        info = os.lstat(name, dir_fd=dirfd)
        if stat.S_ISLNK(info.st_mode):
            continue
        flags = os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW
        if stat.S_ISDIR(info.st_mode):
            flags |= _O_DIRECTORY
        try:
            child = os.open(name, flags, dir_fd=dirfd)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                continue
            raise
        try:
            child_info = os.fstat(child)
            _fchflags(child, 0)
            if stat.S_ISDIR(child_info.st_mode):
                _unfreeze_tree_from_dirfd(child)
            elif stat.S_ISREG(child_info.st_mode):
                os.fchmod(child, 0o700)
        finally:
            os.close(child)


def _clear_tree_for_delete(root: Path) -> None:
    fd = os.open(str(root), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        _unfreeze_tree_from_dirfd(fd)
    finally:
        os.close(fd)


def _reject_mixed_bundle(entries: list[TreeEntry], spawn_relative: str, *, archive_tree: bool) -> None:
    if archive_tree:
        top_apps = {
            entry.relative.split("/")[0]
            for entry in entries
            if entry.relative.split("/")[0].endswith(".app")
        }
        if len(top_apps) > 1:
            raise RuntimeError("mixed application bundle rejected")
    else:
        nested_apps = [
            entry.relative
            for entry in entries
            if any(part.endswith(".app") for part in entry.relative.split("/"))
        ]
        if nested_apps:
            raise RuntimeError("mixed application bundle rejected")
    macos_files = [
        entry.relative
        for entry in entries
        if entry.kind == "F" and "/Contents/MacOS/" in f"/{entry.relative}"
    ]
    if macos_files and spawn_relative not in macos_files:
        raise RuntimeError("bundle executable is absent from the snapshot")


def authenticated_execution_image(
    source: str,
    *,
    expected_executable_sha256: str,
    expected_tree_sha256: str,
    expected_signing_identity: str | None = None,
    expected_designated_requirement: str | None = None,
    source_root: str | None = None,
    source_app: str | None = None,
    archive_tree: bool = False,
) -> ExecutionImage:
    if sys.platform != "darwin":
        raise ExactExecutionUnavailable(
            "exact-byte browser execution is unavailable on this owner/environment: "
            "macOS posix_spawn with a descriptor-walked snapshot is required"
        )
    expected_executable_sha256 = _require_hex64(expected_executable_sha256, "executable SHA-256")
    expected_tree_sha256 = _require_hex64(expected_tree_sha256, "tree SHA-256")
    source_path = Path(source)
    _check_path_components(source_path)
    if not source_path.is_file() or source_path.is_symlink():
        raise RuntimeError(
            "exact-byte browser execution is unavailable on this owner/environment: "
            "source is not one absolute regular non-symlink file"
        )
    root: Path | None = None
    try:
        root = Path(tempfile.mkdtemp(prefix=EXEC_PREFIX, dir=str(PRIVATE_TMP)))
        os.chmod(root, 0o700)
        bundle = Path(source_app) if source_app else app_bundle_for_executable(source_path)
        tree_source = Path(source_root) if source_root else bundle
        if tree_source is not None:
            _check_path_components(tree_source)
            if tree_source.is_symlink() or not tree_source.is_dir():
                raise RuntimeError("bundle or extracted root is not one real directory")
            destination = root / tree_source.name
            entries = _snapshot_tree(tree_source, destination)
            sealed_root = destination
            relative = source_path.resolve(strict=True).relative_to(tree_source.resolve(strict=True))
            spawn_path = destination / relative
            _reject_mixed_bundle(entries, relative.as_posix(), archive_tree=archive_tree)
        else:
            destination = root / "image"
            entries = _snapshot_regular_file(source_path, destination)
            sealed_root = destination
            spawn_path = destination / "executable"
        if not spawn_path.is_file() or spawn_path.is_symlink():
            raise RuntimeError("snapshot executable is absent")
        executable_digest = _sha256_path(str(spawn_path))
        if executable_digest != expected_executable_sha256:
            raise RuntimeError("snapshot executable digest is not the receipt digest")
        binding = tree_binding_digest(entries)
        if archive_tree:
            measured_tree = archive_tree_digest(sealed_root)
        else:
            measured_tree = binding
        if measured_tree != expected_tree_sha256:
            raise RuntimeError("snapshot tree digest is not the receipt digest")
        signing_identity = expected_signing_identity
        designated = expected_designated_requirement
        if signing_identity is not None:
            if bundle is not None and tree_source is not None:
                target = destination / bundle.relative_to(tree_source)
            elif bundle is not None:
                target = destination
            else:
                target = spawn_path
            _codesign_verify(target)
            identity, measured_designated = _codesign_display(target)
            if identity != signing_identity:
                raise RuntimeError("snapshot signing identity is not the receipt identity")
            if designated is None:
                designated = measured_designated
            elif designated != measured_designated:
                raise RuntimeError("snapshot designated requirement is not the receipt requirement")
            _codesign_verify_requirement(target, designated)
        exec_fd = -1
        root_fd = -1
        sealed_fd = -1
        try:
            exec_fd = _open_nofollow(str(spawn_path))
            os.fchmod(exec_fd, 0o500)
            root_fd = os.open(str(root), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
            if sealed_root == root:
                sealed_fd = root_fd
            else:
                sealed_fd = os.open(
                    str(sealed_root), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW
                )
            image = ExecutionImage(
                root,
                str(spawn_path),
                executable_digest,
                expected_tree_sha256,
                str(source_path),
                entries,
                archive_tree,
                signing_identity,
                designated,
                sealed_root,
                exec_fd,
                root_fd,
                sealed_fd,
            )
            exec_fd = root_fd = sealed_fd = -1
            return image
        finally:
            if sealed_fd >= 0 and sealed_fd != root_fd:
                _close_fd(sealed_fd)
            _close_fd(root_fd)
            _close_fd(exec_fd)
    except Exception:
        if root is not None:
            leftover = False
            fd = -1
            try:
                fd = os.open(str(root), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
                identity = _inode(os.fstat(fd))
                try:
                    _destroy_tree_from_dirfd(fd)
                except RuntimeError:
                    leftover = True
                try:
                    _unlink_dir_if_same_inode(root, identity, fd)
                except RuntimeError:
                    leftover = True
            except OSError:
                leftover = root.exists() or root.is_symlink()
            finally:
                _close_fd(fd)
            if leftover or root.exists() or root.is_symlink():
                raise RuntimeError("snapshot residue remains after failed image construction")
        raise


class _CStringArray:
    def __init__(self, values: list[str]):
        encoded = [value.encode("utf-8") for value in values]
        array = (ctypes.c_char_p * (len(encoded) + 1))()
        for index, item in enumerate(encoded):
            array[index] = item
        array[len(encoded)] = None
        self._encoded = encoded
        self.array = array


def _posix_spawn(
    path: str,
    argv: list[str],
    env: dict[str, str],
    *,
    command_read_fd: int | None = None,
    reply_write_fd: int | None = None,
    stderr_path: str | None = None,
    inherit_fds: list[int] | None = None,
    extra_flags: int = 0,
    set_sid: bool = True,
    forbid_env: bool = True,
    chdir_fd: int | None = None,
) -> int:
    if forbid_env:
        leaked = [name for name in env if env_is_forbidden(name)]
        if leaked:
            raise ValueError(f"posix_spawn environment contains forbidden names: {leaked}")
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    _must(_LIBC.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
    try:
        flags = _POSIX_SPAWN_CLOEXEC_DEFAULT | extra_flags
        if set_sid:
            flags |= _POSIX_SPAWN_SETSID
        _must(
            _LIBC.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(flags),
            ),
            "posix_spawnattr_setflags",
        )
        _must(
            _LIBC.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "posix_spawn_file_actions_init",
        )
        try:
            _must(
                _LIBC.posix_spawn_file_actions_addopen(
                    ctypes.byref(actions), 0, b"/dev/null", os.O_RDONLY, 0
                ),
                "posix_spawn_file_actions_addopen stdin",
            )
            _must(
                _LIBC.posix_spawn_file_actions_addopen(
                    ctypes.byref(actions), 1, b"/dev/null", os.O_WRONLY, 0
                ),
                "posix_spawn_file_actions_addopen stdout",
            )
            if stderr_path:
                _must(
                    _LIBC.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions),
                        2,
                        os.fsencode(stderr_path),
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                        0o600,
                    ),
                    "posix_spawn_file_actions_addopen stderr",
                )
            else:
                _must(
                    _LIBC.posix_spawn_file_actions_addopen(
                        ctypes.byref(actions), 2, b"/dev/null", os.O_WRONLY, 0
                    ),
                    "posix_spawn_file_actions_addopen stderr",
                )
            if command_read_fd is not None or reply_write_fd is not None:
                if command_read_fd is None or reply_write_fd is None:
                    raise ValueError("debugging pipe requires both command and reply file descriptors")
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(
                        ctypes.byref(actions), command_read_fd, cdp.CHROME_PIPE_READ_FD
                    ),
                    "posix_spawn_file_actions_adddup2 fd3",
                )
                _must(
                    _LIBC.posix_spawn_file_actions_adddup2(
                        ctypes.byref(actions), reply_write_fd, cdp.CHROME_PIPE_WRITE_FD
                    ),
                    "posix_spawn_file_actions_adddup2 fd4",
                )
            for inherited in inherit_fds or ():
                _must(
                    _LIBC.posix_spawn_file_actions_addinherit_np(ctypes.byref(actions), inherited),
                    "posix_spawn_file_actions_addinherit_np",
                )
            if chdir_fd is not None:
                _must(
                    _LIBC.posix_spawn_file_actions_addfchdir_np(ctypes.byref(actions), chdir_fd),
                    "posix_spawn_file_actions_addfchdir_np",
                )
            pid = ctypes.c_int()
            argv_c = _CStringArray(argv)
            env_c = _CStringArray([f"{name}={value}" for name, value in env.items()])
            path_b = os.fsencode(path)
            rc = _LIBC.posix_spawn(
                ctypes.byref(pid),
                path_b,
                ctypes.byref(actions),
                ctypes.byref(attr),
                argv_c.array,
                env_c.array,
            )
            _must(rc, "posix_spawn")
            return pid.value
        finally:
            _LIBC.posix_spawn_file_actions_destroy(ctypes.byref(actions))
    finally:
        _LIBC.posix_spawnattr_destroy(ctypes.byref(attr))


class _ProcUniqIdentifierInfo(ctypes.Structure):
    _fields_ = [
        ("p_uuid", ctypes.c_ubyte * 16),
        ("p_uniqueid", ctypes.c_uint64),
        ("p_puniqueid", ctypes.c_uint64),
        ("p_reserve2", ctypes.c_uint64),
        ("p_reserve3", ctypes.c_uint64),
        ("p_reserve4", ctypes.c_uint64),
    ]


@dataclass(frozen=True)
class ProcessBirth:
    pid: int
    uniqueid: int
    uuid: bytes
    puniqueid: int


def process_birth_identity(pid: int) -> ProcessBirth:
    if pid <= 1:
        raise ProcessTreeCleanupError(f"refusing birth identity for pid {pid}")
    info = _ProcUniqIdentifierInfo()
    size = ctypes.sizeof(info)
    got = _LIBC.proc_pidinfo(pid, _PROC_PIDUNIQIDENTIFIERINFO, 0, ctypes.byref(info), size)
    if got != size:
        raise ProcessTreeCleanupError(f"process birth identity unavailable for pid {pid}")
    return ProcessBirth(pid, int(info.p_uniqueid), bytes(info.p_uuid), int(info.p_puniqueid))


def _pid_alive(pid: int) -> bool:
    completed = subprocess.run(
        ["/bin/ps", "-p", str(pid), "-o", "state="],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if completed.returncode not in {0, 1}:
        raise ProcessTreeCleanupError(f"process table inspection failed for pid {pid}")
    state = completed.stdout.strip()
    return bool(state) and state[:1] not in {"Z"}


def _process_table() -> list[tuple[int, int, int, str]]:
    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,state="],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
    )
    if completed.returncode != 0:
        raise ProcessTreeCleanupError("process table inspection failed")
    rows: list[tuple[int, int, int, str]] = []
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
            pgid = int(parts[2])
        except ValueError:
            continue
        state = parts[3] if len(parts) > 3 else ""
        rows.append((pid, ppid, pgid, state))
    return rows


def descendant_pids(root_pid: int) -> set[int]:
    children: dict[int, list[int]] = {}
    for pid, ppid, _pgid, _state in _process_table():
        children.setdefault(ppid, []).append(pid)
    found: set[int] = set()
    stack = [root_pid]
    while stack:
        current = stack.pop()
        for child in children.get(current, ()):
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def _live_tracked(root_pid: int, seen_pids: set[int], seen_groups: set[int]) -> tuple[set[int], set[int], list[str]]:
    errors: list[str] = []
    live: set[int] = set()
    groups = set(seen_groups)
    try:
        rows = _process_table()
    except ProcessTreeCleanupError as exc:
        return set(), seen_groups, [str(exc)]
    by_ppid: dict[int, list[int]] = {}
    by_pgid: dict[int, list[int]] = {}
    states: dict[int, str] = {}
    for pid, ppid, pgid, state in rows:
        by_ppid.setdefault(ppid, []).append(pid)
        by_pgid.setdefault(pgid, []).append(pid)
        states[pid] = state
        if pid <= 1:
            continue
        if pid in seen_pids or ppid in seen_pids or pgid in groups:
            seen_pids.add(pid)
            if pgid > 1:
                groups.add(pgid)
    changed = True
    while changed:
        changed = False
        for pid, ppid, pgid, state in rows:
            if pid <= 1:
                continue
            if pid in seen_pids or ppid in seen_pids or pgid in groups:
                if pid not in seen_pids or (pgid > 1 and pgid not in groups):
                    changed = True
                seen_pids.add(pid)
                if pgid > 1:
                    groups.add(pgid)
    seen_pids.discard(0)
    seen_pids.discard(1)
    groups.discard(0)
    groups.discard(1)
    for pid in set(seen_pids):
        state = states.get(pid, "")
        if state[:1] == "Z":
            continue
        if pid == root_pid:
            if _pid_alive(pid):
                live.add(pid)
            continue
        try:
            if _pid_alive(pid):
                live.add(pid)
        except ProcessTreeCleanupError as exc:
            errors.append(str(exc))
        except PermissionError as exc:
            errors.append(f"permission error inspecting pid {pid}: {exc}")
            live.add(pid)
    return live, groups, errors


def _kill_pid(pid: int, sig: int, identities: dict[int, ProcessBirth] | None = None) -> list[str]:
    errors: list[str] = []
    if pid <= 1:
        return errors
    if identities is not None:
        expected = identities.get(pid)
        if expected is None:
            return [f"missing birth identity for pid {pid}"]
        try:
            current = process_birth_identity(pid)
        except ProcessTreeCleanupError:
            return errors
        if current.uniqueid != expected.uniqueid or current.uuid != expected.uuid:
            return [f"pid {pid} reused (birth identity mismatch)"]
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        errors.append(f"permission error signalling pid {pid}: {exc}")
    return errors


def _kill_group(pgid: int, sig: int, identities: dict[int, ProcessBirth] | None = None) -> list[str]:
    errors: list[str] = []
    if pgid <= 1:
        return errors
    if identities is not None:
        expected = identities.get(pgid)
        if expected is not None:
            try:
                current = process_birth_identity(pgid)
            except ProcessTreeCleanupError:
                return errors
            if current.uniqueid != expected.uniqueid or current.uuid != expected.uuid:
                return [f"pgid {pgid} reused (birth identity mismatch)"]
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        # Darwin returns EPERM for a zombie process-group leader. That is not
        # a live survivor; per-pid signalling still covers remaining members.
        try:
            leader_live = _pid_alive(pgid)
        except ProcessTreeCleanupError as inspect_exc:
            return [str(inspect_exc), f"permission error signalling group {pgid}: {exc}"]
        if leader_live:
            errors.append(f"permission error signalling group {pgid}: {exc}")
    return errors


def terminate_process_tree(
    pid: int, timeout: float = 10.0, birth: ProcessBirth | None = None
) -> None:
    if pid <= 0:
        return
    identities: dict[int, ProcessBirth] = {}
    if birth is not None:
        if birth.pid != pid:
            raise ProcessTreeCleanupError("root birth identity pid mismatch")
        identities[pid] = birth
    else:
        try:
            identities[pid] = process_birth_identity(pid)
        except ProcessTreeCleanupError:
            pass
    seen_pids = {pid} | descendant_pids(pid)
    seen_pids.discard(0)
    seen_pids.discard(1)
    seen_groups = {pid} if pid > 1 else set()
    errors: list[str] = []
    deadline = time.time() + timeout
    reaped = False
    recorded_status: int | None = None
    empty_scans = 0
    while time.time() < deadline:
        live, seen_groups, scan_errors = _live_tracked(pid, seen_pids, seen_groups)
        errors.extend(scan_errors)
        for tracked in set(seen_pids) | live:
            if tracked in identities:
                continue
            try:
                identities[tracked] = process_birth_identity(tracked)
            except ProcessTreeCleanupError:
                pass
        for group in list(seen_groups):
            errors.extend(_kill_group(group, signal.SIGTERM, identities))
        for child in live:
            errors.extend(_kill_pid(child, signal.SIGTERM, identities))
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                reaped = True
                recorded_status = status
        except ChildProcessError:
            reaped = True
            recorded_status = None
        time.sleep(0.05)
        live, seen_groups, scan_errors = _live_tracked(pid, seen_pids, seen_groups)
        errors.extend(scan_errors)
        remaining = set(live)
        if remaining:
            empty_scans = 0
            for group in list(seen_groups):
                errors.extend(_kill_group(group, signal.SIGKILL, identities))
            for child in remaining:
                errors.extend(_kill_pid(child, signal.SIGKILL, identities))
            continue
        empty_scans += 1
        if empty_scans >= 5 and (reaped or not _pid_alive(pid)):
            break
    if not reaped:
        wait_deadline = time.time() + 2.0
        while time.time() < wait_deadline:
            try:
                waited, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                reaped = True
                recorded_status = None
                break
            if waited == pid:
                reaped = True
                recorded_status = status
                break
            time.sleep(0.05)
    live, _groups, scan_errors = _live_tracked(pid, seen_pids, seen_groups)
    errors.extend(scan_errors)
    live.discard(pid)
    if live or errors or (not reaped and _pid_alive(pid)):
        detail = ", ".join(sorted(str(item) for item in live))
        extra = "; ".join(errors)
        raise ProcessTreeCleanupError(
            f"browser process tree cleanup failed (survivors={detail or 'none'}; {extra or 'unreaped root'})"
        )


def _status_to_exitcode(status: int) -> int:
    try:
        return os.waitstatus_to_exitcode(status)
    except ValueError as exc:
        raise RuntimeError(f"unknown wait status {status:#x}") from exc


class AuthenticatedChild:
    def __init__(
        self,
        pid: int,
        image: ExecutionImage,
        transport: cdp.PipeTransport | None = None,
        birth: ProcessBirth | None = None,
    ):
        self.pid = pid
        self.image = image
        self.transport = transport
        self.birth = birth if birth is not None else process_birth_identity(pid)
        if self.birth.pid != pid:
            raise RuntimeError("child birth identity pid mismatch")
        self._waited = False
        self._status: int | None = None

    def wait(self, timeout: float | None = None) -> int:
        if self._waited and self._status is not None:
            return self._status
        if timeout is None:
            try:
                _pid, status = os.waitpid(self.pid, 0)
            except ChildProcessError as exc:
                self._waited = True
                raise RuntimeError("child process status is unavailable") from exc
            self._waited = True
            self._status = _status_to_exitcode(status)
            return self._status
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError as exc:
                self._waited = True
                raise RuntimeError("child process status is unavailable") from exc
            if waited == self.pid:
                self._waited = True
                self._status = _status_to_exitcode(status)
                return self._status
            time.sleep(0.05)
        raise TimeoutError(f"pid {self.pid} did not exit within {timeout}s")

    def terminate(self, timeout: float = 10.0) -> None:
        try:
            terminate_process_tree(self.pid, timeout=timeout, birth=self.birth)
            self._waited = True
        finally:
            if self.transport is not None:
                self.transport.close()
                self.transport = None
            self.image.cleanup()


def _regular_interpreter(path: Path) -> str | None:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    try:
        _check_path_components(resolved)
    except RuntimeError:
        return None
    info = resolved.lstat()
    if resolved.is_symlink() or not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        return None
    return str(resolved)


def _helper_python() -> str:
    for candidate in (
        os.environ.get("WINS_RELEASE_CHILD_PYTHON", ""),
        os.environ.get("WINS_RELEASE_PYTHON", ""),
        sys.executable,
    ):
        if not candidate:
            continue
        resolved = _regular_interpreter(Path(candidate))
        if resolved:
            return resolved
    raise RuntimeError("authenticated Python interpreter is required to spawn the Seatbelt helper")


def _seatbelt_profile(sealed_root: Path) -> str:
    path = str(sealed_root)
    if any(ch in path for ch in '"\\\n\r'):
        raise RuntimeError("snapshot path is not representable in a Seatbelt profile")
    return (
        f'(version 1) (allow default) (deny file-write* (literal "{path}") (subpath "{path}"))'
    )


def helper_identities() -> dict[str, object]:
    interpreter = Path(_helper_python())
    modules = {name: _file_identity(HERE / name) for name in HELPER_MODULE_NAMES}
    imported = {
        "core_tests.py": _file_identity(Path(__file__).resolve()),
        "cdp.py": _file_identity(Path(cdp.__file__).resolve()),
    }
    return {
        "interpreter": _file_identity(interpreter),
        "modules": modules,
        "imported": imported,
    }


def verify_helper_identities(expected: dict[str, object] | None = None) -> dict[str, object]:
    current = helper_identities()
    if current["modules"] != current["imported"]:
        raise RuntimeError("imported custody modules are not the authenticated helper source")
    if expected is not None and current != expected:
        raise RuntimeError("helper interpreter or custody module identity changed")
    return current


def stage_helper_modules(destination: Path) -> dict[str, object]:
    _check_path_components(destination)
    identities = verify_helper_identities()
    dest_fd = os.open(str(destination), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        for name in HELPER_MODULE_NAMES:
            src_fd = _open_nofollow(str(HERE / name))
            try:
                digest, _size = _clone_or_copy_regular(src_fd, dest_fd, name, 0o400)
            finally:
                os.close(src_fd)
            expected = identities["modules"][name]
            if digest != expected["digest"]:
                raise RuntimeError("staged helper source digest mismatch")
            staged = _file_identity(destination / name)
            if staged["digest"] != expected["digest"]:
                raise RuntimeError("staged helper source digest mismatch")
    finally:
        os.close(dest_fd)
    return identities


def verify_staged_helper(destination: Path, expected: dict[str, object]) -> None:
    for name in HELPER_MODULE_NAMES:
        current = _file_identity(destination / name)
        if current["digest"] != expected["modules"][name]["digest"]:
            raise RuntimeError("helper source was swapped")
    interpreter = Path(_helper_python())
    if _file_identity(interpreter) != expected["interpreter"]:
        raise RuntimeError("helper interpreter was swapped")
    verify_helper_identities(expected)


def spawn_request_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def write_spawn_request_fd(payload: dict[str, object]) -> int:
    read_fd, write_fd = os.pipe()
    try:
        encoded = spawn_request_bytes(payload)
        view = memoryview(encoded)
        while view:
            written = os.write(write_fd, view)
            if written <= 0:
                raise RuntimeError("spawn request pipe rejected the transaction")
            view = view[written:]
    except Exception:
        _close_fd(read_fd)
        _close_fd(write_fd)
        raise
    os.close(write_fd)
    os.set_inheritable(read_fd, True)
    return read_fd


def read_spawn_request_fd(fd: int) -> dict[str, object]:
    chunks: list[bytes] = []
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        chunks.append(block)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("spawn request is not authentic JSON") from exc
    if type(payload) is not dict:
        raise RuntimeError("spawn request is not an object")
    return payload


def _seatbelt_profile(sealed_root: Path) -> str:
    path = str(sealed_root)
    if any(ch in path for ch in '"\\\n\r'):
        raise RuntimeError("snapshot path is not representable in a Seatbelt profile")
    return (
        f'(version 1) (allow default) (deny file-write* (literal "{path}") (subpath "{path}"))'
    )


def _seatbelt_spawn_helper(argv: list[str]) -> int:
    if len(argv) != 1:
        print("seatbelt helper: request descriptor required", file=sys.stderr)
        return 2
    try:
        fd = int(argv[0])
    except ValueError:
        print("seatbelt helper: request must be an inherited descriptor", file=sys.stderr)
        return 2
    if fd < 3:
        print("seatbelt helper: request descriptor is not authentic", file=sys.stderr)
        return 2
    try:
        payload = read_spawn_request_fd(fd)
        expected_helper = payload.get("helper")
        if type(expected_helper) is not dict:
            raise RuntimeError("helper identity missing from spawn request")
        verify_helper_identities(expected_helper)
        image_root = Path(str(payload["image_root"]))
        spawn_path = str(payload["spawn_path"])
        sealed_root = Path(str(payload["sealed_root"]))
        expected_exe = str(payload["executable_digest"])
        expected_tree = str(payload["tree_digest"])
        archive_tree = bool(payload["archive_tree"])
        signing_identity = payload.get("signing_identity")
        designated = payload.get("designated_requirement")
        child_argv = list(payload["argv"])
        child_env = dict(payload["env"])
        stderr_path = payload.get("stderr_path")
        if image_root.parent != PRIVATE_TMP or not image_root.name.startswith(EXEC_PREFIX):
            raise RuntimeError("snapshot escaped its private prefix")
        current_exe = _sha256_path(spawn_path)
        if current_exe != expected_exe:
            raise RuntimeError("executable digest changed")
        entries = inspect_source_tree(sealed_root)
        if archive_tree:
            measured = archive_tree_digest(sealed_root)
        else:
            measured = tree_binding_digest(entries)
        if measured != expected_tree:
            raise RuntimeError("tree digest changed")
        if signing_identity:
            app = app_bundle_for_executable(Path(spawn_path))
            target = app if app is not None else Path(spawn_path)
            _codesign_verify(target, allow_immutable=True)
            identity, measured_designated = _codesign_display(target)
            if identity != signing_identity:
                raise RuntimeError("signing identity changed")
            if designated and measured_designated != designated:
                raise RuntimeError("designated requirement changed")
            if designated:
                _codesign_verify_requirement(target, str(designated), allow_immutable=True)
        ready_fd = int(payload["ready_write_fd"])
        command_read_fd = payload.get("command_read_fd")
        reply_write_fd = payload.get("reply_write_fd")
        child_pid = _posix_spawn(
            spawn_path,
            child_argv,
            child_env,
            command_read_fd=command_read_fd,
            reply_write_fd=reply_write_fd,
            stderr_path=stderr_path if stderr_path is None else str(stderr_path),
            extra_flags=0,
            set_sid=False,
        )
        os.write(ready_fd, f"{child_pid}\nOK\n".encode("utf-8"))
        os.close(ready_fd)
        _pid, status = os.waitpid(child_pid, 0)
        return _status_to_exitcode(status)
    except Exception as exc:
        print(f"seatbelt helper: {exc}", file=sys.stderr)
        return 2


def spawn_execution_image(
    image: ExecutionImage,
    args: list[str],
    env: dict[str, str],
    *,
    debugging_pipe: bool = False,
    stderr_path: str | None = None,
) -> AuthenticatedChild:
    image.verify()
    image.seal()
    image.verify()
    image.assert_bound_identity()
    if image.archive_tree and not exact_execution_defended():
        raise ExactExecutionUnavailable(EXACT_EXEC_BLOCKER)
    command_read_fd = reply_write_fd = None
    parent_write_fd = parent_read_fd = None
    transport = None
    try:
        if debugging_pipe:
            command_read_fd, parent_write_fd = os.pipe()
            parent_read_fd, reply_write_fd = os.pipe()
            os.set_inheritable(command_read_fd, True)
            os.set_inheritable(reply_write_fd, True)
        inherit: list[int] = []
        chdir_fd: int | None = image._sealed_fd
        relative = os.path.relpath(image.path, start=image.sealed_root)
        if relative.startswith("..") or os.path.isabs(relative):
            raise RuntimeError("snapshot executable escaped sealed root")
        spawn_path = relative
        if exact_execution_defended():
            os.set_inheritable(image._exec_fd, True)
            inherit.append(image._exec_fd)
            spawn_path = f"/dev/fd/{image._exec_fd}"
            chdir_fd = None
        elif chdir_fd is not None:
            inherit.append(chdir_fd)
        pid = _posix_spawn(
            spawn_path,
            [image.path, *args],
            env,
            command_read_fd=command_read_fd,
            reply_write_fd=reply_write_fd,
            stderr_path=stderr_path,
            inherit_fds=inherit,
            chdir_fd=chdir_fd,
        )
        try:
            if debugging_pipe:
                os.close(command_read_fd)
                os.close(reply_write_fd)
                command_read_fd = reply_write_fd = None
                transport = cdp.produce_pipe_transport(parent_read_fd, parent_write_fd)
                parent_read_fd = parent_write_fd = None
            birth = process_birth_identity(pid)
            return AuthenticatedChild(pid, image, transport, birth)
        except Exception:
            terminate_process_tree(pid, timeout=2)
            raise
    except Exception:
        for fd in (command_read_fd, reply_write_fd, parent_write_fd, parent_read_fd):
            _close_fd(fd)
        if transport is not None:
            transport.close()
        raise


def spawn_authenticated(
    source: str,
    args: list[str],
    env: dict[str, str],
    *,
    expected_executable_sha256: str | None = None,
    expected_tree_sha256: str | None = None,
    expected_signing_identity: str | None = None,
    expected_designated_requirement: str | None = None,
    source_root: str | None = None,
    source_app: str | None = None,
    archive_tree: bool = False,
    debugging_pipe: bool = False,
    stderr_path: str | None = None,
) -> AuthenticatedChild:
    if expected_executable_sha256 is None or expected_tree_sha256 is None:
        raise RuntimeError("spawn requires receipt executable and tree digests; refusing a freshly calculated authority")
    image = authenticated_execution_image(
        source,
        expected_executable_sha256=expected_executable_sha256,
        expected_tree_sha256=expected_tree_sha256,
        expected_signing_identity=expected_signing_identity,
        expected_designated_requirement=expected_designated_requirement,
        source_root=source_root,
        source_app=source_app,
        archive_tree=archive_tree,
    )
    try:
        return spawn_execution_image(
            image, args, env, debugging_pipe=debugging_pipe, stderr_path=stderr_path
        )
    except Exception:
        image.cleanup()
        raise


def launch_headless_chrome(browser_bin: str, work: Path) -> AuthenticatedChild:
    if not exact_execution_defended():
        raise ExactExecutionUnavailable(EXACT_EXEC_BLOCKER)
    identity = require_release_browser_identity()
    if str(identity.executable) != browser_bin:
        raise RuntimeError("BROWSER_BIN is not the receipt-bound Chrome executable")
    profile, home, tmp = create_browser_state_dirs(work)
    env = browser_child_env(str(home), str(tmp))
    args = [
        f"--user-data-dir={profile}",
        "--enable-unsafe-extension-debugging",
        "--remote-debugging-pipe",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--headless=new",
        "about:blank",
    ]
    return spawn_authenticated(
        str(identity.executable),
        args,
        env,
        expected_executable_sha256=identity.executable_sha256,
        expected_tree_sha256=identity.tree_sha256,
        expected_signing_identity=identity.signing_identity,
        source_root=str(identity.root),
        source_app=str(identity.app),
        archive_tree=True,
        debugging_pipe=True,
        stderr_path=str(work / "chrome.stderr"),
    )

SUITE = r"""
(async () => {
  const pac = await import('/src/core/pac.js');
  const rules = await import('/src/core/rules.js');
  const state = await import('/src/core/state.js');
  const proto = await import('/src/core/protocol.js');
  const endpoint = await import('/src/core/endpoint.js');
  const blocks = await import('/src/core/blockrules.js');
  const copy = await import('/src/core/copy.js');
  const K = await import('/src/core/constants.js');

  const results = [];
  const t = (name, fn) => {
    try { const detail = fn(); results.push({name, ok: true, detail: detail || ''}); }
    catch (e) { results.push({name, ok: false, detail: String(e && e.message || e)}); }
  };
  const eq = (a, b, m) => { if (JSON.stringify(a) !== JSON.stringify(b))
    throw new Error(`${m || ''} expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
  const ok = (v, m) => { if (!v) throw new Error(m || 'expected truthy'); };

  // ---- rule normalisation ------------------------------------------------
  t('a bare host normalises to itself', () => {
    eq(rules.normaliseRule('Example.COM'), {ok: true, rule: 'example.com'});
  });
  t('a pasted URL is reduced to its host', () => {
    eq(rules.normaliseRule('https://user:pw@News.example.com:8443/a/b?c#d'),
       {ok: true, rule: 'news.example.com'});
  });
  t('a leading *. is accepted and means the same thing', () => {
    eq(rules.normaliseRule('*.example.com'), {ok: true, rule: 'example.com'});
  });
  t('a numeric address is refused as a rule', () => {
    const r = rules.normaliseRule('93.184.216.34');
    ok(r.ok === false, 'must be refused');
    ok(/Addresses are not supported/.test(r.reason), 'must say why');
  });
  t('a bracketed IPv6 literal is refused as a rule', () => {
    ok(rules.normaliseRule('[2001:db8::1]').ok === false);
  });
  t('a single label is refused', () => { ok(rules.normaliseRule('localhost').ok === false); });

  // ---- matching ----------------------------------------------------------
  t('a rule covers the host and its subdomains and nothing else', () => {
    ok(rules.ruleMatches('example.com', 'example.com'));
    ok(rules.ruleMatches('example.com', 'a.b.example.com'));
    ok(!rules.ruleMatches('example.com', 'notexample.com'));
    ok(!rules.ruleMatches('example.com', 'example.com.evil.test'));
  });
  t('a trailing root dot does not defeat a rule', () => {
    ok(rules.ruleMatches('example.com', 'example.com.'));
  });

  // ---- scope -------------------------------------------------------------
  t('in ALL mode everything is in scope except the exclusions', () => {
    const s = {mode: K.MODE_ALL, listed: [], excluded: ['out.test']};
    ok(rules.isInScope(s, 'anything.test'));
    ok(!rules.isInScope(s, 'sub.out.test'));
  });
  t('in LISTED mode only the list is in scope', () => {
    const s = {mode: K.MODE_LISTED, listed: ['in.test'], excluded: []};
    ok(rules.isInScope(s, 'sub.in.test'));
    ok(!rules.isInScope(s, 'other.test'));
  });

  // ---- the PAC, executed rather than inspected ---------------------------
  const ep = {kind: 'http', host: '127.0.0.1', port: 45678};

  t('the generated PAC contains no DIRECT fallback', () => {
    const src = pac.buildPac({mode: K.MODE_ALL, listed: [], excluded: ['out.test']}, ep);
    if (src.includes('; DIRECT')) throw new Error('a DIRECT fallback is present');
    return `${src.length} chars`;
  });
  t('the generated PAC calls no resolver helper', () => {
    const src = pac.buildPac({mode: K.MODE_ALL, listed: [], excluded: []}, ep);
    for (const fn of ['dnsResolve', 'isInNet', 'isResolvable', 'myIpAddress']) {
      if (src.includes(fn)) throw new Error(`${fn} appears in the PAC`);
    }
  });
  t("the extension's own pages cannot evaluate a string as code", () => {
    // Not a test of the PAC: a test of the Content-Security-Policy in the
    // manifest. If this ever stops throwing, the CSP has been loosened and the
    // no-remote-code claim is no longer true. Found by accident when the PAC
    // execution tests below had to be moved out of this context.
    try { new Function('return 1')(); }
    catch (e) { return 'blocked by CSP, as declared'; }
    throw new Error('new Function() succeeded; the extension CSP is not being enforced');
  });

  // ---- endpoint ----------------------------------------------------------
  t('loopback is accepted, everything else is not', () => {
    ok(endpoint.isLoopbackHost('127.0.0.1'));
    ok(endpoint.isLoopbackHost('127.9.9.9'));
    ok(endpoint.isLoopbackHost('::1'));
    ok(!endpoint.isLoopbackHost('localhost'));
    ok(!endpoint.isLoopbackHost('192.168.1.1'));
    ok(!endpoint.isLoopbackHost('198.51.100.7'));
  });
  t('a non-canonical loopback form is refused', () => {
    ok(!endpoint.isLoopbackHost('127.000.000.001'));
  });
  t('validateEndpoint refuses a non-loopback host without echoing it', () => {
    const r = endpoint.validateEndpoint({kind: 'http', host: '198.51.100.7', port: 8080});
    ok(r.ok === false);
    ok(!r.reason.includes('198'), 'the rejected address must not appear in the reason');
  });
  t('pacToken never double-brackets an IPv6 literal', () => {
    eq(endpoint.pacToken({kind: 'http', host: '::1', port: 8080}), 'PROXY [::1]:8080');
    eq(endpoint.pacToken({kind: 'http', host: '[::1]', port: 8080}), 'PROXY [::1]:8080');
    eq(endpoint.pacToken({kind: 'http', host: '127.0.0.1', port: 8080}), 'PROXY 127.0.0.1:8080');
  });

  // ---- protocol ----------------------------------------------------------
  const statusMsg = (over) => Object.assign({
    v: 1, id: '1', type: 'status', ok: true,
    status: 'connected', detail: 'none', winn: 'unavailable_on_this_platform',
    selectedSlug: '', nodes: [], canRequestConnect: true,
    proxyPort: 45678, proxyReady: true, rxKib: 0, txKib: 0,
  }, over || {});

  t('a wrong protocol version is rejected whole', () => {
    ok(proto.parseInbound(statusMsg({v: 2})).ok === false);
  });
  t('an unknown tunnel status becomes unknown, never connected', () => {
    const p = proto.parseInbound(statusMsg({status: 'totally-fine'}));
    eq(p.msg.status.status, 'unknown');
    ok(!proto.isCarryingTraffic(p.msg.status.status));
  });
  t('an address-shaped node name is dropped, not trimmed', () => {
    const p = proto.parseInbound(statusMsg({nodes: [
      {slug: 'japan', name: 'Japan', flag: 'JP'},
      {slug: 'bad', name: 'gateway 203.0.113.9', flag: ''},
      {slug: 'bad2', name: 'edge.example.com', flag: ''},
    ]}));
    eq(p.msg.status.nodes.map(n => n.slug), ['japan']);
  });
  t('a slug that looks like an address is dropped', () => {
    const p = proto.parseInbound(statusMsg({nodes: [{slug: '10.0.0.1', name: 'x', flag: ''}]}));
    eq(p.msg.status.nodes, []);
  });
  t('an out-of-range integer is discarded rather than believed', () => {
    const p = proto.parseInbound(statusMsg({rxKib: 4294967295}));
    eq(p.msg.status.rxKib, 0);
  });
  t('a credential reply yields a loopback endpoint built from a constant', () => {
    const p = proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'A'.repeat(43), proxyPort: 45678});
    ok(p.ok);
    eq(p.msg.endpoint, {kind: 'http', host: '127.0.0.1', port: 45678});
  });
  t('AN INJECTED HOST FIELD IN A CREDENTIAL REPLY IS IGNORED', () => {
    const p = proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'A'.repeat(43), proxyPort: 45678, host: '198.51.100.7', endpoint: {host: '198.51.100.7'}});
    ok(p.ok);
    eq(p.msg.endpoint.host, '127.0.0.1');
    ok(!JSON.stringify(p.msg).includes('198.51.100.7'), 'the injected address must not survive parsing');
  });
  t('a token that is not base64url is refused', () => {
    ok(proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'has spaces and !!', proxyPort: 45678}).ok === false);
  });
  t('a credential with an impossible port is refused', () => {
    ok(proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'A'.repeat(43), proxyPort: 0}).ok === false);
  });
  t('an error reply is recognised in both spellings', () => {
    eq(proto.parseInbound({v: 1, id: '3', error: 'app_not_running'}).msg.type, 'error');
    eq(proto.parseInbound({v: 1, id: '3', type: 'error', ok: false, error: 'rate_limited'}).msg.code,
       'rate_limited');
  });

  // ---- the state machine -------------------------------------------------
  const base = {
    armed: true, hostConnected: true,
    status: proto.parseInbound(statusMsg()).msg.status,
    statusAtMs: 1000, nowMs: 1000, levelOfControl: 'controlled_by_this_extension',
    credential: {endpoint: {kind: 'http', host: '127.0.0.1', port: 45678}, token: 'A'.repeat(43)},
    canAuthenticate: true,
    routingSurface: {ok: true, reason: ''},
  };
  const derive = (over) => state.deriveState(Object.assign({}, base, over));

  t('the happy path reaches PROTECTED', () => { eq(derive({}).state, K.STATE.PROTECTED); });
  t('unarmed is OFF and not fail-closed', () => {
    const d = derive({armed: false});
    eq(d.state, K.STATE.OFF); eq(d.failClosed, false);
  });
  t('a missing routing surface is explicit and non-blocking', () => {
    const d = derive({routingSurface: {ok: false, reason: 'measured unavailable'}});
    eq(d.state, K.STATE.NO_ROUTING_SURFACE);
    eq(d.failClosed, false);
    ok(/measured unavailable/.test(d.detail), 'the measured reason must survive');
  });
  t('routing-surface unavailability precedes armed and block-layer state', () => {
    const unavailable = {routingSurface: {ok: false, reason: 'no mechanism'}};
    eq(derive(Object.assign({armed: false}, unavailable)).state, K.STATE.NO_ROUTING_SURFACE);
    eq(derive(Object.assign({blockLayer: {ok: false, error: 'refused'}}, unavailable)).state,
       K.STATE.NO_ROUTING_SURFACE);
  });
  t('an absent or malformed routing report fails unavailable', () => {
    eq(state.deriveState(Object.assign({}, base, {routingSurface: undefined})).state,
       K.STATE.NO_ROUTING_SURFACE);
    eq(state.normaliseRoutingSurface('yes').ok, false);
    eq(state.normaliseRoutingSurface({ok: true, reason: 'ignored'}), {ok: true, reason: ''});
  });
  t('every non-protected armed state is fail-closed', () => {
    const cases = [
      ['no bridge', {hostConnected: false}],
      ['no status', {status: null}],
      ['stale status', {nowMs: 1000 + K.STATUS_TTL_MS + 1}],
      ['clock jumped backwards', {nowMs: 1000 - K.STATUS_TTL_MS - 1}],
      ['app not running', {status: proto.parseInbound(statusMsg({status: 'app_not_running'})).msg.status}],
      ['tunnel down', {status: proto.parseInbound(statusMsg({status: 'disconnected'})).msg.status}],
      ['tunnel unknown', {status: proto.parseInbound(statusMsg({status: 'nonsense'})).msg.status}],
      ['permission required', {status: proto.parseInbound(statusMsg({status: 'permission_required'})).msg.status}],
      ['proxy gate shut', {status: proto.parseInbound(statusMsg({proxyReady: false})).msg.status}],
      ['no credential', {credential: null}],
      ['cannot authenticate', {canAuthenticate: false}],
      ['another extension in control', {levelOfControl: 'controlled_by_other_extensions'}],
      ['not controllable', {levelOfControl: 'not_controllable'}],
      ['credential for a stale port', {credential: {endpoint: {kind: 'http', host: '127.0.0.1', port: 1}, token: 'A'.repeat(43)}}],
      ['non-loopback credential', {credential: {endpoint: {kind: 'http', host: '198.51.100.7', port: 45678}, token: 'A'.repeat(43)}}],
    ];
    for (const [label, over] of cases) {
      const d = derive(over);
      if (d.state === K.STATE.PROTECTED) throw new Error(`${label} reached PROTECTED`);
      if (!d.failClosed) throw new Error(`${label} is not fail-closed`);
    }
    return `${cases.length} routes into fail-closed, none into PROTECTED`;
  });
  t('managed proxy control has its own fail-closed state and honest remedy', () => {
    const d = derive({levelOfControl: 'not_controllable'});
    eq(d.state, K.STATE.PROXY_NOT_CONTROLLABLE);
    ok(d.failClosed, 'a proxy setting that extensions cannot control must fail closed');
    const c = copy.STATE_COPY[d.state];
    ok(!/another (add-on|extension)/i.test(`${c.detail} ${c.action}`),
       'managed or otherwise locked settings must not be blamed on another extension');
    ok(!/remove or disable/i.test(c.action),
       'the action must not prescribe a remedy that cannot change managed proxy settings');
    ok(c.detail.includes('blocked, not sent unprotected'),
       'the distinct state must retain the fail-closed traffic statement');
  });
  t('Edge names its proxy-control observation without claiming policy as fact', () => {
    const note = copy.edgeProxyControlNote('not_controllable', 'edge');
    ok(note.includes('Microsoft Edge reports'), 'the observation must be attributed to Edge');
    ok(/often set/.test(note), 'management must be offered as a likely cause, not asserted');
    ok(/will not try to override/.test(note), 'the no-override behavior must be explicit');
    eq(copy.edgeProxyControlNote('not_controllable', 'chrome'), '');
  });
  t('losing proxy control after routing was applied cannot remain PROTECTED', () => {
    const d = derive({
      levelOfControl: 'controllable_by_this_extension',
      routing: {ok: true, error: ''},
    });
    eq(d.state, K.STATE.ROUTING_FAILED);
    ok(d.failClosed, 'loss of effective proxy control must fail closed');
  });
  t('controllable proxy state still permits the first apply attempt', () => {
    eq(derive({levelOfControl: 'controllable_by_this_extension', routing: {ok: null}}).state,
       K.STATE.PROTECTED);
  });

  // ---- a bridge that was started and never answered ------------------------
  //
  // Measured on 2026-08-07, on Chrome 151, Edge 151 and Firefox 153, with the
  // real compiled host: a host binary under ~/Documents, ~/Desktop or
  // ~/Downloads is spawned and then blocks forever in dyld's open(2) on its own
  // executable, because macOS TCC will not let the browser read that folder.
  // The process exists. The pipe is open. Nothing is ever written to it, no
  // browser reports anything, and onDisconnect never fires -- so the extension
  // used to sit in STALE with an EMPTY lastError, telling a user to go and
  // check an app that was very possibly running fine.
  //
  // The silence is the only observable there is, so these pin that it is
  // observed, that it is not confused with a bridge that answered and went
  // quiet, and that it is not accused before it has had a fair chance.
  const silent = (over) => derive(Object.assign(
    {status: null, statusAtMs: 0, hostSpoke: false,
     hostOpenedAtMs: 1000 - K.HOST_HANDSHAKE_TTL_MS - 1}, over));

  t('a bridge started and never heard from is named, not filed under STALE', () => {
    const d = silent({});
    eq(d.state, K.STATE.HOST_NOT_ANSWERING);
    ok(d.failClosed, 'must be fail-closed');
    ok(/not answered once/.test(d.detail), 'the detail must say what was observed');
    ok(/reported no error/.test(d.detail),
       'the absence of a browser error is the diagnostic fact and must be stated');
  });
  t('a bridge still inside the handshake window is waiting, not accused', () => {
    // A revived service worker can be descheduled between opening the port and
    // the reply landing. Reporting a dead bridge because the browser was busy
    // would be a lie in the other direction.
    const d = silent({hostOpenedAtMs: 1000 - Math.round(K.HOST_HANDSHAKE_TTL_MS / 2)});
    eq(d.state, K.STATE.STALE);
  });
  t('a bridge that spoke rubbish is a running bridge, not a missing one', () => {
    // hostSpoke is set before parsing, on purpose: a frame that arrives and is
    // then discarded still proves a process is writing to the pipe. Calling that
    // "never started" would send the reader to reinstall something that is
    // installed correctly.
    eq(silent({hostSpoke: true}).state, K.STATE.STALE);
  });
  t('a port that was never opened is still NO_HOST, not silence', () => {
    // NO_HOST is the browser REFUSING, and it has its own copy and its own
    // remedy. The two must not collapse into each other.
    eq(silent({hostConnected: false}).state, K.STATE.NO_HOST);
  });

  // ---- a component that failed must reach the state machine ---------------
  //
  // The regression these pin is the one the first live Firefox run found: every
  // fact deriveState checked was true, the browser had installed none of it, and
  // the extension said PROTECTED. Each case below is a component reporting its
  // own failure; none of them may end in PROTECTED, and the block-layer one may
  // not end in a state whose copy promises a block either.
  t('a block layer that did not install cannot be PROTECTED', () => {
    const d = derive({blockLayer: {ok: false, error: 'Invalid enumeration value "webtransport"'}});
    eq(d.state, K.STATE.NOT_ENFORCING);
    ok(d.failClosed, 'must still be fail-closed in intent');
    ok(/webtransport/.test(d.detail), 'the browser’s own reason must survive into the state');
  });
  t('a failed block layer overrides every other state, not just PROTECTED', () => {
    // Every fail-closed state's copy promises a block. If the block layer is not
    // installed, that promise is false in all of them at once, so the check
    // cannot live in one branch.
    const cases = [{hostConnected: false}, {status: null}, {credential: null},
                   {canAuthenticate: false}, {nowMs: 1000 + K.STATUS_TTL_MS + 1}];
    for (const over of cases) {
      const d = derive(Object.assign({blockLayer: {ok: false, error: 'refused'}}, over));
      if (d.state !== K.STATE.NOT_ENFORCING) {
        throw new Error(`${JSON.stringify(over)} reported ${d.state}, which promises a block`);
      }
    }
    return `${cases.length} underlying states, all reported as not enforcing`;
  });
  t('the underlying situation is not thrown away', () => {
    const d = derive({hostConnected: false, blockLayer: {ok: false, error: 'refused'}});
    ok(d.detail.includes(K.STATE.NO_HOST), 'the state underneath must stay diagnosable');
  });
  t('routing the browser refused cannot be PROTECTED', () => {
    const d = derive({routing: {ok: false, error: 'proxy.settings requires private browsing permission.'}});
    eq(d.state, K.STATE.ROUTING_FAILED);
    ok(/private browsing/.test(d.detail));
  });
  t('routing with the key never presented cannot be PROTECTED', () => {
    const d = derive({authStats: {authenticated: 0, unauthenticated: 3}});
    eq(d.state, K.STATE.ROUTING_UNAUTHENTICATED);
  });
  t('one accepted authentication clears the unauthenticated alarm', () => {
    // Otherwise a single refusal before the bridge had issued a key would pin
    // the extension into an alarm for the rest of the session.
    eq(derive({authStats: {authenticated: 1, unauthenticated: 3}}).state, K.STATE.PROTECTED);
    eq(derive({authStats: {authenticated: 0, unauthenticated: 0}}).state, K.STATE.PROTECTED);
  });
  t('a healthy block layer and healthy routing still reach PROTECTED', () => {
    eq(derive({blockLayer: {ok: true, error: ''}, routing: {ok: true, error: ''}}).state,
       K.STATE.PROTECTED);
  });

  // ---- plaintext webRequest path (ruling 2026-08-07) ---------------------
  // TLS removed; Firefox now uses webRequest over plaintext like Chromium.
  t('a browser reaches PROTECTED over a plaintext bridge via webRequest', () => {
    const d = derive({});
    eq(d.state, K.STATE.PROTECTED);
    eq(d.endpoint.kind, 'http');
    eq(d.endpoint.port, 45678);
  });
  t('a stale proxy port is a stale credential, not a silent reroute', () => {
    const d = derive({credential: {endpoint: {kind: 'http', host: '127.0.0.1', port: 9999}, token: 'A'.repeat(43)}});
    eq(d.state, K.STATE.NO_CREDENTIAL);
  });
  t('a non-loopback endpoint is refused', () => {
    const d = derive({credential: {endpoint: {kind: 'http', host: '198.51.100.7', port: 45678}, token: 'A'.repeat(43)}});
    eq(d.state, K.STATE.BAD_ENDPOINT);
  });
  t('the https endpoint kind is now refused (plaintext only) and socks still is not', () => {
    ok(endpoint.validateEndpoint({kind: 'https', host: '127.0.0.1', port: 45679}).ok === false);
    ok(endpoint.validateEndpoint({kind: 'socks5', host: '127.0.0.1', port: 45679}).ok === false);
  });
  t('a credential reply yields a loopback endpoint built from a constant', () => {
    const p = proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'A'.repeat(43), proxyPort: 45678,
      host: '198.51.100.7'});
    eq(p.msg.endpoint, {kind: 'http', host: '127.0.0.1', port: 45678});
    ok(!('tlsEndpoint' in p.msg), 'no tlsEndpoint in plaintext design');
  });
  t('an unusable port yields no endpoint', () => {
    const p = proto.parseInbound({v: 1, id: '2', type: 'proxy_credential', ok: true,
      token: 'A'.repeat(43), proxyPort: 70000});
    ok(p.ok === false);
  });
  t('every state the machine can produce has copy of its own', () => {
    // stateCopy() falls back to the STALE entry, which promises a block. A state
    // without copy is therefore not a gap, it is that promise made about a
    // situation nobody wrote copy for.
    const missing = Object.values(K.STATE).filter(s => !copy.STATE_COPY[s]);
    if (missing.length) throw new Error(`no copy for: ${missing.join(', ')}`);
    return `${Object.values(K.STATE).length} states, all with their own copy`;
  });
  t('the state that cannot block does not promise one, and the ones that can do', () => {
    const promise = 'blocked, not sent unprotected';
    const notEnforcing = copy.STATE_COPY[K.STATE.NOT_ENFORCING];
    ok(!notEnforcing.detail.includes(promise),
       'NOT_ENFORCING must not carry the promise the block layer keeps');
    ok(/not being stopped|cannot prevent it/.test(notEnforcing.detail),
       'it must say plainly that traffic is not being stopped');
    const noSurface = copy.STATE_COPY[K.STATE.NO_ROUTING_SURFACE];
    ok(!noSurface.detail.includes(promise),
       'NO_ROUTING_SURFACE must not promise a block that is not installed');
    ok(/not blocking|not being stopped|cannot prevent it/.test(noSurface.detail),
       'NO_ROUTING_SURFACE must say plainly that traffic is not being blocked');
    // Deleting the promise everywhere is the cheapest way to pass the line
    // above, so the states that DO keep it are asserted to still say it.
    const mustPromise = [K.STATE.NO_HOST, K.STATE.HOST_NOT_ANSWERING,
                         K.STATE.APP_NOT_RUNNING, K.STATE.APP_DOWN,
                         K.STATE.STALE, K.STATE.NOT_READY, K.STATE.NO_CREDENTIAL,
                         K.STATE.NO_AUTH_CAPABILITY, K.STATE.NOT_IN_CONTROL,
                         K.STATE.PROXY_NOT_CONTROLLABLE, K.STATE.ROUTING_FAILED,
                         K.STATE.ROUTING_UNAUTHENTICATED];
    const quiet = mustPromise.filter(s => !copy.STATE_COPY[s].detail.includes(promise));
    if (quiet.length) throw new Error(`these block but do not say so: ${quiet.join(', ')}`);
    return `1 state without the promise, ${mustPromise.length} with it`;
  });
  t('the silent-bridge copy sends the reader somewhere that can help', () => {
    // A state whose words are "something went wrong" is the empty lastError
    // wearing a headline. This one has to name the likely cause and a remedy
    // that exists, and it must not tell the reader to restart the browser --
    // measured, that changes nothing at all, because the next launch blocks in
    // exactly the same place.
    const c = copy.STATE_COPY[K.STATE.HOST_NOT_ANSWERING];
    ok(/Documents|Desktop|Downloads/.test(c.detail),
       'the likely cause must be named, not hinted at');
    ok(/reinstall/i.test(c.action), 'the remedy must be the one that works');
    ok(/not change this|will not/i.test(c.action),
       'the remedy that does not work must be ruled out, or the reader will try it first');
  });

  // ---- block rules -------------------------------------------------------
  t('ALL mode blocks everything and re-permits the exclusions at higher priority', () => {
    const rs = blocks.buildBlockRules({mode: K.MODE_ALL, listed: [], excluded: ['out.test']}, true);
    const block = rs.find(r => r.action.type === 'block');
    const allow = rs.find(r => r.action.type === 'allow');
    eq(block.condition.urlFilter, '*');
    ok(block.condition.resourceTypes.includes('main_frame'), 'main_frame must be covered');
    eq(allow.condition.urlFilter, '||out.test^');
    ok(allow.priority > block.priority, 'the exemption must outrank the block');
  });
  t('LISTED mode blocks only the list', () => {
    const rs = blocks.buildBlockRules({mode: K.MODE_LISTED, listed: ['in.test'], excluded: []}, true);
    eq(rs.length, 1);
    eq(rs[0].action.type, 'block');
    eq(rs[0].condition.urlFilter, '||in.test^');
  });
  t('no rules are produced when not failing closed', () => {
    eq(blocks.buildBlockRules({mode: K.MODE_ALL, listed: [], excluded: []}, false), []);
  });
  t('the rules carry the resource types the browser accepted, not the wanted list', () => {
    // Firefox 153 rejects two of the fifteen and discards the whole rule set for
    // it. The adapter passes the intersection; this is the shape it produces.
    const narrowed = K.DNR_RESOURCE_TYPES.filter(x => x !== 'webtransport' && x !== 'webbundle');
    const rs = blocks.buildBlockRules({mode: K.MODE_ALL, listed: [], excluded: ['out.test']},
                                      true, narrowed);
    for (const r of rs) {
      eq(r.condition.resourceTypes, narrowed, 'every rule, not only the first');
    }
    ok(rs[0].condition.resourceTypes.includes('main_frame'), 'main_frame survives narrowing');
    return `${narrowed.length} of ${K.DNR_RESOURCE_TYPES.length} types, on ${rs.length} rules`;
  });
  t('an empty or missing type list falls back to the full wanted list', () => {
    // A negotiation that produced nothing must not silently become a rule with
    // no resourceTypes, which in Chromium means "everything except main_frame" --
    // a partial block that still emits the top-level request.
    for (const bad of [undefined, [], null, 'nonsense']) {
      const rs = blocks.buildBlockRules({mode: K.MODE_ALL, listed: [], excluded: []}, true, bad);
      ok(rs[0].condition.resourceTypes.includes('main_frame'), `main_frame missing for ${bad}`);
    }
  });
  t('the probe id is swept by allRuleIds so no orphan can survive', () => {
    ok(blocks.allRuleIds().includes(K.DNR_PROBE_RULE_ID), 'the probe id must be swept');
    ok(blocks.allRuleIds().includes(K.DNR_BLOCK_RULE_ID));
  });

  // ---- settings sanitisation --------------------------------------------
  t('stored settings are re-validated on load', () => {
    const s = rules.sanitiseSettings({armed: 'yes', mode: 'nonsense',
      listed: ['GOOD.test', '10.0.0.1', 'good.test', 42], excluded: null});
    eq(s.armed, false, 'armed must be a real boolean');
    eq(s.mode, K.MODE_ALL);
    eq(s.listed, ['good.test']);
    eq(s.excluded, []);
  });
  t('the default settings record nothing about the user', () => {
    eq(rules.defaultSettings(), {armed: false, mode: K.MODE_ALL, listed: [], excluded: []});
  });

  // Handed to a plain page, which is allowed to compile a function from a
  // string, so the PAC can be CALLED rather than merely inspected.
  const pacs = {
    all: pac.buildPac({mode: K.MODE_ALL, listed: [], excluded: ['out.test']}, ep),
    listed: pac.buildPac({mode: K.MODE_LISTED, listed: ['in.test'], excluded: []}, ep),
    hostile: pac.buildPac({mode: K.MODE_ALL, listed: [], excluded: []}, ep)
      .replace('("" + host)', 'host'),
    injected: pac.buildPac(
      {mode: K.MODE_ALL, listed: [], excluded: ['"; return "DIRECT"; //']}, ep),
  };
  return JSON.stringify({results, pacs});
})()
"""


PAC_SUITE = r"""
(() => {
  const PACS = __PACS__;
  const results = [];
  const t = (name, fn) => {
    try { const d = fn(); results.push({name, ok: true, detail: d || ''}); }
    catch (e) { results.push({name, ok: false, detail: String(e && e.message || e)}); }
  };
  const eq = (a, b) => { if (a !== b) throw new Error(`expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`); };
  const run = (src, host) => new Function(src + '; return FindProxyForURL;')()('https://' + host + '/', host);

  t('PAC in ALL mode routes everything but the exclusions', () => {
    eq(run(PACS.all, 'anything.test'), 'PROXY 127.0.0.1:45678');
    eq(run(PACS.all, 'sub.out.test'), 'DIRECT');
    eq(run(PACS.all, 'notout.test'), 'PROXY 127.0.0.1:45678');
  });
  t('PAC in LISTED mode routes only the list', () => {
    eq(run(PACS.listed, 'in.test'), 'PROXY 127.0.0.1:45678');
    eq(run(PACS.listed, 'deep.sub.in.test'), 'PROXY 127.0.0.1:45678');
    eq(run(PACS.listed, 'elsewhere.test'), 'DIRECT');
  });
  t('PAC fails closed when its own body throws', () => {
    const f = new Function(PACS.hostile + '; return FindProxyForURL;')();
    eq(f('https://x/', null), 'PROXY 127.0.0.1:45678');
  });
  t('a rule cannot inject code into the PAC', () => {
    eq(run(PACS.injected, 'anything.test'), 'PROXY 127.0.0.1:45678');
  });
  return JSON.stringify(results);
})()
"""


def main() -> int:
    work = Path(os.environ.get("TMPDIR", "/tmp")) / f"wv-core-tests-{os.getpid()}"
    if work.exists() or work.is_symlink():
        print(f"core_tests: work residue remains at {work}", file=sys.stderr)
        return 2
    work.mkdir(mode=0o700)
    package = Path(
        os.environ.get("EXT_PACKAGE", str(HERE.parent / "dist" / "chrome"))
    ).resolve()
    if not package.exists():
        print(f"core_tests: no package at {package}; run build.py first", file=sys.stderr)
        return 2

    try:
        identity = require_release_browser_identity()
        browser_bin = resolve_browser_bin()
        if browser_bin != str(identity.executable):
            raise RuntimeError("BROWSER_BIN is not the receipt-bound Chrome executable")
    except (FileNotFoundError, RuntimeError) as error:
        print(f"core_tests: {error}", file=sys.stderr)
        return 2

    if not exact_execution_defended():
        print(f"core_tests: {EXACT_EXEC_BLOCKER}", file=sys.stderr)
        return 2

    child = None
    raw = ""
    pac_raw = ""
    residue_error = None
    try:
        child = launch_headless_chrome(browser_bin, work)
        if child.transport is None:
            raise RuntimeError("browser debugging pipe was not inherited by the parent")
        session = cdp.BrowserSession(child.transport)
        ext = session.browser.call("Extensions.loadUnpacked", {"path": str(package)})["id"]
        session.browser.call(
            "Target.createTarget", {"url": f"chrome-extension://{ext}/src/ui/options.html"}
        )
        target = session.wait_for_target(
            lambda info: info.get("type") == "page" and ext in (info.get("url") or ""),
            timeout=25,
        )
        target.call("Runtime.enable")
        raw = target.evaluate(SUITE, timeout=60)

        plain = session.wait_for_target(
            lambda info: info.get("type") == "page"
            and (info.get("url") or "").startswith("about:"),
            timeout=25,
        )
        plain.call("Runtime.enable")
        pac_raw = plain.evaluate(
            PAC_SUITE.replace("__PACS__", json.dumps(json.loads(raw)["pacs"])), timeout=60
        )
    except Exception:
        stderr = work / "chrome.stderr"
        if stderr.is_file():
            sys.stderr.write(stderr.read_text(encoding="utf-8", errors="replace"))
        raise
    finally:
        if child is not None:
            child.terminate()
        try:
            work_fd = os.open(str(work), os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
            try:
                identity = _inode(os.fstat(work_fd))
                _destroy_tree_from_dirfd(work_fd)
                _unlink_dir_if_same_inode(work, identity, work_fd)
            finally:
                os.close(work_fd)
            if work.exists() or work.is_symlink():
                residue_error = "work residue remains"
        except Exception as exc:
            residue_error = str(exc)

    if residue_error:
        print(f"core_tests: {residue_error}", file=sys.stderr)
        return 1

    results = json.loads(raw)["results"] + json.loads(pac_raw)
    failed = 0
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        detail = f"  ({r['detail']})" if r["detail"] else ""
        print(f"  [{mark}] {r['name']}{detail}")
        if not r["ok"]:
            failed += 1
    print(f"\ncore: {len(results) - failed}/{len(results)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--seatbelt-spawn-helper":
        sys.exit(_seatbelt_spawn_helper(sys.argv[2:]))
    sys.exit(main())
