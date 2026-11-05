#!/usr/bin/env python3
"""Trusted CPython launcher for Android macOS toolchain provisioning.

Root of trust: CPython reads this entire file into memory and compiles it
before any statement runs. Same-user post-start writes to this inode cannot
change the already-loaded bytecode. This launcher does not hash or
authenticate itself; doing so would be a circular self-auth claim.

The loaded launcher authenticates tools/provision_macos_release_android_toolchains.sh
against the reviewed digest below using a held O_NOFOLLOW snapshot, copies
those exact bytes into a root-owned private execution object, and extracts
the bootstrap from the held image. Bash never parses the user-writable
original.

Root never executes this user-writable pathname. The printed owner command
is a one-shot authenticated loader on the sealed root-owned CPython 3.14.7
wrapper. That loader holds these bytes through O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK,
checks before/opened/finished/after identity, and compiles only the reviewed digest
from tools/release_obfuscation_contract.py. The sealed wrapper uses env -i,
so the loader restores validated numeric SUDO_UID/SUDO_GID.

Owner command shape:

  /usr/bin/sudo -H -- /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I -S \\
    -c '<authenticated one-shot loader with the reviewed launcher SHA-256 literal>' \\
    /ABS/PATH/tools/launch_macos_release_android_toolchains.py \\
    /ABS/PATH/tools/toolchain-pins.json \\
    INVOKING_UID INVOKING_GID

This helper never invokes sudo, never reads a password, and never uses
askpass.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import tempfile


REVIEWED_PROVISIONER_SHA256 = (
    "dd75985ceb4f32b7e8fe42c1ad9e560f7c3f6666c5651e675ae21788c5ffb45a"
)
PROVISIONER_NAME = "provision_macos_release_android_toolchains.sh"
HELPER_NAME = "release_android_toolchain_archive_custody.sh"
CONTRACT_NAME = "android-toolchain-custody.json"
MANIFEST_NAME = "toolchain-pins.json"
LAUNCHER_NAME = "launch_macos_release_android_toolchains.py"
OBFUSCATION_NAME = "release_obfuscation_contract.py"
SEALED_CPYTHON_314 = Path(
    "/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14"
)
SEALED_SUDO = Path("/usr/bin/sudo")
OWNER_LIBRARY_ROOT = Path("/Library/WinsVPN")
OWNER_BOOTSTRAP = Path("/Library/WinsVPN/ReleaseAndroidToolchainBootstrap")
OWNER_FLUTTER = Path("/Library/WinsVPN/ReleaseAndroidToolchains/flutter-3.47.6")
OWNER_JAVA = Path("/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1")
LAUNCHER_STAGING_PREFIX = str(OWNER_LIBRARY_ROOT) + "/.ReleaseAndroidLauncherExecution."
BOOTSTRAP_BEGIN = "# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_BEGIN\n"
BOOTSTRAP_END = "\n# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_END"
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Android toolchain "
    "tree immutable against same-user path replacement through execution"
)
CHUNK = 1024 * 1024
MAX_PROVISIONER_BYTES = 2 * 1024 * 1024
MAX_LAUNCHER_BYTES = 2 * 1024 * 1024
SHA_RE_CHARS = "0123456789abcdef"
LAUNCHER_SHA_PLACEHOLDER = "__LAUNCHER_SHA256_LITERAL__"
LAUNCHER_SHA_MARKER = 'ANDROID_TOOLCHAIN_LAUNCHER_SHA256 = (\n    "'
# Compact one-shot loader executed by sealed CPython via -c. No single quotes:
# printers wrap it in shell single quotes. The reviewed SHA-256 is substituted
# at print time from the external obfuscation pin, never from hashing this file.
ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE = """import hashlib,os,stat,sys,fcntl
if len(sys.argv)!=5:
 raise SystemExit("authenticated launcher loader arguments are malformed")
p=sys.argv[1]
m=sys.argv[2]
uid=sys.argv[3]
gid=sys.argv[4]
expected="__LAUNCHER_SHA256_LITERAL__"
if len(expected)!=64 or expected.strip("0123456789abcdef") or expected=="0"*64:
 raise SystemExit("reviewed launcher digest is malformed")
if not uid.isdigit() or int(uid)<=0:
 raise SystemExit("root preflight refused: SUDO_UID is missing")
if not gid.isdigit() or int(gid)<=0:
 raise SystemExit("root preflight refused: SUDO_GID is missing")
os.environ["SUDO_UID"]=uid
os.environ["SUDO_GID"]=gid
if p[:1]!="/" or m[:1]!="/" or ".." in p.split("/") or ".." in m.split("/"):
 raise SystemExit("absolute launcher and manifest paths are required")
nofollow=getattr(os,"O_NOFOLLOW",0)
cloexec=getattr(os,"O_CLOEXEC",0)
nonblock=getattr(os,"O_NONBLOCK",0)
if not nofollow or not cloexec or not nonblock:
 raise SystemExit("O_NOFOLLOW, O_CLOEXEC, and O_NONBLOCK are required")
if not hasattr(fcntl,"F_GETFL") or not hasattr(fcntl,"F_SETFL"):
 raise SystemExit("F_GETFL and F_SETFL are required")
flags=os.O_RDONLY|cloexec|nofollow|nonblock
def ident(v):
 return (v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,v.st_nlink,stat.S_IFMT(v.st_mode),stat.S_IMODE(v.st_mode)&0o022)
def unsafe(v):
 return (not stat.S_ISREG(v.st_mode)) or v.st_nlink!=1 or (stat.S_IMODE(v.st_mode)&0o022)!=0
try:
 before=os.lstat(p)
except OSError:
 raise SystemExit("launcher is absent")
if unsafe(before) or before.st_size<=0 or before.st_size>2097152:
 raise SystemExit("launcher identity is unsafe")
try:
 fd=os.open(p,flags)
except OSError:
 raise SystemExit("launcher path is not a readable regular file")
try:
 opened=os.fstat(fd)
 if ident(before)!=ident(opened) or unsafe(opened):
  raise SystemExit("launcher was replaced before it was opened")
 cur=fcntl.fcntl(fd,fcntl.F_GETFL)
 if cur&nonblock:
  fcntl.fcntl(fd,fcntl.F_SETFL,cur&~nonblock)
 chunks=[]
 total=0
 while True:
  chunk=os.read(fd,1048576)
  if not chunk:
   break
  total+=len(chunk)
  if total>2097152:
   raise SystemExit("launcher exceeds the custody bound")
  chunks.append(chunk)
 finished=os.fstat(fd)
 if ident(opened)!=ident(finished) or unsafe(finished):
  raise SystemExit("launcher changed while it was read")
finally:
 os.close(fd)
after=os.lstat(p)
if ident(finished)!=ident(after) or unsafe(after):
 raise SystemExit("launcher was replaced after it was opened")
data=b"".join(chunks)
if not data or len(data)!=finished.st_size:
 raise SystemExit("launcher current bytes could not be held")
if hashlib.sha256(data).hexdigest()!=expected:
 raise SystemExit("stale or substituted Android toolchain launcher rejected")
sys.argv=[p,m]
ns={"__name__":"__main__","__file__":p,"__package__":None,"__cached__":None}
exec(compile(data,p,"exec"),ns,ns)
"""


class Refused(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


def _hex64(value: str, label: str) -> str:
    if len(value) != 64 or value.strip(SHA_RE_CHARS) or value == "0" * 64:
        fail(f"{label} must be an exact lowercase non-zero SHA-256")
    return value


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required for Android toolchain custody")
    return flag


def _cloexec() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _nonblock() -> int:
    flag = getattr(os, "O_NONBLOCK", 0)
    if not flag:
        fail("O_NONBLOCK is required for Android toolchain custody")
    return flag


def _clear_nonblock_if_needed(fd: int) -> None:
    if not hasattr(fcntl, "F_GETFL") or not hasattr(fcntl, "F_SETFL"):
        fail("F_GETFL and F_SETFL are required for Android toolchain custody")
    nonblock = _nonblock()
    current = fcntl.fcntl(fd, fcntl.F_GETFL)
    if current & nonblock:
        fcntl.fcntl(fd, fcntl.F_SETFL, current & ~nonblock)


def _open_flags() -> int:
    return os.O_RDONLY | _cloexec() | _nofollow() | _nonblock()


def android_toolchain_launcher_loader(expected: str) -> str:
    digest = _hex64(expected, "reviewed launcher digest")
    if ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE.count(LAUNCHER_SHA_PLACEHOLDER) != 1:
        fail("authenticated launcher loader placeholder is malformed")
    return ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE.replace(
        LAUNCHER_SHA_PLACEHOLDER, digest
    )


def reviewed_launcher_sha256(*, tools_dir: Path | None = None) -> str:
    directory = tools_dir if tools_dir is not None else tools_dir_from_loaded_path()
    path = directory / OBFUSCATION_NAME
    walk_components(path, "Android toolchain launcher digest pin")
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail("Android toolchain launcher digest pin is absent")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail(
            "Android toolchain launcher digest pin must be one regular "
            "non-symlink single-link file"
        )
    if stat.S_IMODE(info.st_mode) & 0o022:
        fail("Android toolchain launcher digest pin is group/world-writable")
    try:
        text = path.read_text(encoding="ascii")
    except UnicodeDecodeError:
        fail("Android toolchain launcher digest pin is not ASCII")
    if text.count(LAUNCHER_SHA_MARKER) != 1:
        fail("Android toolchain launcher digest pin is malformed")
    start = text.index(LAUNCHER_SHA_MARKER) + len(LAUNCHER_SHA_MARKER)
    digest = text[start : start + 64]
    if start + 64 >= len(text) or text[start + 64] != '"':
        fail("Android toolchain launcher digest pin is malformed")
    return _hex64(digest, "reviewed launcher digest")


def owner_command(
    manifest: Path,
    *,
    tools_dir: Path | None = None,
    launcher_sha256: str | None = None,
    invoking_uid: int | None = None,
    invoking_gid: int | None = None,
) -> str:
    resolved_tools = tools_dir if tools_dir is not None else tools_dir_from_loaded_path()
    launcher = resolved_tools / LAUNCHER_NAME
    if not launcher.is_absolute() or not Path(manifest).is_absolute():
        fail("owner command paths must be absolute")
    if ".." in launcher.parts or ".." in Path(manifest).parts:
        fail("owner command paths must be absolute")
    uid = os.getuid() if invoking_uid is None else invoking_uid
    gid = os.getgid() if invoking_gid is None else invoking_gid
    if uid <= 0 or gid <= 0:
        fail("root preflight refused: SUDO_UID is missing")
    expected = (
        _hex64(launcher_sha256, "reviewed launcher digest")
        if launcher_sha256 is not None
        else reviewed_launcher_sha256(tools_dir=resolved_tools)
    )
    loader = android_toolchain_launcher_loader(expected)
    return (
        f"{SEALED_SUDO} -H -- {SEALED_CPYTHON_314} -I -S -c {shlex.quote(loader)} "
        f"{shlex.quote(str(launcher))} {shlex.quote(str(manifest))} {uid} {gid}"
    )


def require_loaded_cpython_314_identity() -> None:
    if not sys.argv or sys.argv[0] in {"-", "-c"}:
        fail("CPython launcher must be loaded from a regular file, not stdin or -c")
    if not sys.flags.isolated or not sys.flags.no_site:
        fail("CPython 3.14 launcher requires isolated -I -S")
    if Path(sys.executable).name != "python3.14":
        fail("CPython 3.14 launcher identity is required")


def tools_dir_from_loaded_path() -> Path:
    raw = Path(__file__)
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    parent = raw.parent
    if parent.name != "tools":
        fail("Android toolchain launcher must live in tools/")
    return parent


def walk_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in {"", ".", ".."} or "/" in part or "\\" in part or "\x00" in part:
            fail(f"{label} contains an unsafe path component")
        current = current / part
        try:
            info = current.lstat()
        except OSError as suc:
            fail(f"{label} path is not readable: {suc}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} traverses a symbolic link")


def hold_regular_file(path: Path, *, max_size: int, label: str) -> tuple[bytes, str]:
    walk_components(path, label)
    try:
        before = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is absent")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be one regular non-symlink single-link file")
    if before.st_size <= 0 or before.st_size > max_size:
        fail(f"{label} size is outside the custody bound")
    try:
        fd = os.open(path, _open_flags())
    except OSError:
        fail(f"{label} path is not a readable regular file")
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail(f"{label} must be one regular non-symlink single-link file")
        if (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_size,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
            opened.st_size,
        ):
            fail(f"{label} was replaced before it was opened")
        _clear_nonblock_if_needed(fd)
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            chunks.append(block)
            if sum(len(item) for item in chunks) > max_size:
                fail(f"{label} exceeds the custody bound")
        after = os.fstat(fd)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
            opened.st_size,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_size,
        ):
            fail(f"{label} changed while it was read")
        data = b"".join(chunks)
        if not data:
            fail(f"{label} snapshot is empty")
        return data, _digest(data)
    finally:
        os.close(fd)


def authenticate_held_provisioner(data: bytes) -> str:
    digest = _digest(data)
    expected = _hex64(REVIEWED_PROVISIONER_SHA256, "reviewed provisioner digest")
    if digest != expected:
        fail("stale or substituted Android toolchain provisioner rejected")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("Android toolchain provisioner is not ASCII")
    if text.count(BOOTSTRAP_BEGIN) != 1 or text.count(BOOTSTRAP_END) != 1:
        fail("Android toolchain provisioner bootstrap markers are malformed")
    return digest


def extract_bootstrap_source(data: bytes) -> str:
    authenticate_held_provisioner(data)
    text = data.decode("ascii")
    begin = text.index(BOOTSTRAP_BEGIN) + len(BOOTSTRAP_BEGIN)
    end = text.index(BOOTSTRAP_END)
    source = text[begin:end]
    if "def bootstrap_and_provision(" not in source:
        fail("held provisioner bootstrap is missing bootstrap_and_provision")
    return source


def load_bootstrap_namespace(data: bytes) -> dict[str, object]:
    source = extract_bootstrap_source(data)
    namespace: dict[str, object] = {"__name__": "wins_android_root_trust_bootstrap"}
    exec(compile(source, "wins_android_root_trust_bootstrap", "exec"), namespace)
    return namespace


def _ensure_library_root() -> None:
    if OWNER_LIBRARY_ROOT.exists() or OWNER_LIBRARY_ROOT.is_symlink():
        info = OWNER_LIBRARY_ROOT.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail("owner library root is not a real directory")
        if info.st_uid != 0:
            fail("owner library root is not root-owned")
        if stat.S_IMODE(info.st_mode) & 0o022:
            fail("owner library root is group/world-writable")
        return
    OWNER_LIBRARY_ROOT.mkdir(mode=0o755)
    os.chown(OWNER_LIBRARY_ROOT, 0, 0)
    OWNER_LIBRARY_ROOT.chmod(0o755)


def _destroy_launcher_staging(staging: Path) -> None:
    if not str(staging).startswith(LAUNCHER_STAGING_PREFIX) and not str(staging).startswith(
        "/private/tmp/wins-android-launcher-exec."
    ):
        fail("refusing cleanup of a foreign launcher staging path")
    if staging.exists() or staging.is_symlink():
        for base, directories, files in os.walk(staging, topdown=False, followlinks=False):
            base_path = Path(base)
            for name in files + directories:
                path = base_path / name
                if path.is_symlink():
                    continue
                try:
                    os.chflags(path, 0)
                except OSError:
                    pass
            try:
                os.chflags(base_path, 0)
            except OSError:
                pass
        shutil.rmtree(staging, ignore_errors=True)


def materialize_private_execution_object(
    data: bytes,
    expected: str,
    *,
    dest_parent: Path | None = None,
    chown_root: bool | None = None,
) -> Path:
    expected = _hex64(expected, "reviewed provisioner digest")
    if _digest(data) != expected:
        fail("stale or substituted Android toolchain provisioner rejected")
    authenticate_held_provisioner(data)
    if chown_root is None:
        chown_root = os.geteuid() == 0 and os.getuid() == 0
    if dest_parent is None:
        if chown_root:
            _ensure_library_root()
            dest_parent = Path(f"{LAUNCHER_STAGING_PREFIX}{os.getpid()}")
        else:
            dest_parent = Path(
                tempfile.mkdtemp(
                    prefix="wins-android-launcher-exec.",
                    dir="/private/tmp",
                )
            )
            dest_parent.chmod(0o700)
            return _write_private_provisioner(
                dest_parent, data, expected, chown_root=False
            )
    if dest_parent.exists() or dest_parent.is_symlink():
        if chown_root and str(dest_parent).startswith(LAUNCHER_STAGING_PREFIX):
            _destroy_launcher_staging(dest_parent)
        elif not chown_root:
            fail("launcher private execution directory already exists")
        else:
            fail("launcher private execution directory already exists")
    dest_parent.mkdir(mode=0o700)
    if chown_root:
        os.chown(dest_parent, 0, 0)
        dest_parent.chmod(0o700)
    try:
        return _write_private_provisioner(
            dest_parent, data, expected, chown_root=chown_root
        )
    except BaseException:
        _destroy_launcher_staging(dest_parent)
        raise


def _write_private_provisioner(
    dest_parent: Path, data: bytes, expected: str, *, chown_root: bool
) -> Path:
    destination = dest_parent / PROVISIONER_NAME
    dest_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec() | _nofollow()
    dest_fd = os.open(destination, dest_flags, 0o600)
    copied = hashlib.sha256()
    try:
        view = memoryview(data)
        while view:
            written = os.write(dest_fd, view)
            if written <= 0:
                fail("short write while copying held provisioner")
            copied.update(view[:written])
            view = view[written:]
        os.fsync(dest_fd)
        if chown_root:
            os.fchown(dest_fd, 0, 0)
        os.fchmod(dest_fd, 0o500 if chown_root else 0o700)
    finally:
        os.close(dest_fd)
    if copied.hexdigest() != expected:
        fail("held provisioner copy digest mismatch")
    return destination


def emit_owner_boundary(manifest: Path) -> None:
    print(
        f"release-android-toolchain provision: {EXECUTION_BLOCKER}; "
        "owner-provisioned root-owned Flutter 3.47.6/JDK 17.0.20.1 trees are unavailable",
        file=sys.stderr,
    )
    print(
        f"release-android-toolchain provision: sealed trees: {OWNER_FLUTTER} "
        f"{OWNER_JAVA}",
        file=sys.stderr,
    )
    print(
        f"release-android-toolchain provision: owner action: {owner_command(manifest)}",
        file=sys.stderr,
    )
    print(
        "release-android-toolchain provision: owner action must run in a visible "
        "interactive macOS Terminal with a controlling TTY; this helper never invokes sudo",
        file=sys.stderr,
    )


def launch_authenticated_provisioner(
    manifest: Path,
    *,
    require_root: bool = True,
    dest: Path | None = None,
    execute_provision: bool | None = None,
    tools_dir: Path | None = None,
) -> str:
    _hex64(REVIEWED_PROVISIONER_SHA256, "reviewed provisioner digest")
    resolved_tools = tools_dir if tools_dir is not None else tools_dir_from_loaded_path()
    provisioner = resolved_tools / PROVISIONER_NAME
    helper = resolved_tools / HELPER_NAME
    contract = resolved_tools / CONTRACT_NAME
    if manifest != resolved_tools / MANIFEST_NAME:
        fail("replacement Android pin manifest cannot self-authorize")
    held, digest = hold_regular_file(
        provisioner, max_size=MAX_PROVISIONER_BYTES, label="Android toolchain provisioner"
    )
    authenticate_held_provisioner(held)
    if digest != REVIEWED_PROVISIONER_SHA256:
        fail("stale or substituted Android toolchain provisioner rejected")
    namespace = load_bootstrap_namespace(held)
    pins = namespace["provisioner_embedded_pins"](held)  # type: ignore[operator]
    private = materialize_private_execution_object(
        held,
        REVIEWED_PROVISIONER_SHA256,
        chown_root=require_root,
    )
    staging = private.parent
    try:
        result = namespace["bootstrap_and_provision"](  # type: ignore[operator]
            private,
            helper,
            contract,
            manifest,
            pins["helper"],
            pins["contract"],
            pins["manifest"],
            REVIEWED_PROVISIONER_SHA256,
            OWNER_BOOTSTRAP if dest is None else dest,
            apply_kernel_seal=require_root,
            require_root=require_root,
            execute_provision=(
                require_root if execute_provision is None else execute_provision
            ),
        )
        return str(result)
    finally:
        _destroy_launcher_staging(staging)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(
            "release-android-toolchain provision: usage: "
            "launch_macos_release_android_toolchains.py ABSOLUTE_PIN_MANIFEST",
            file=sys.stderr,
        )
        return 1
    try:
        if os.environ.get("SUDO_ASKPASS"):
            fail("SUDO_ASKPASS is refused; this helper never reads a password")
        if os.uname().sysname != "Darwin":
            fail("macOS is required")
        if os.uname().machine != "arm64":
            fail("darwin_arm64 custody requires an arm64 host")
        manifest = Path(args[0])
        if not manifest.is_absolute() or " " in str(manifest):
            fail("regular absolute pin manifest required")
        walk_components(manifest, "Android pin manifest")
        info = manifest.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail("regular absolute pin manifest required")
        if os.geteuid() != 0 or os.getuid() != 0:
            emit_owner_boundary(manifest)
            return 1
        require_loaded_cpython_314_identity()
        raw = os.environ.get("SUDO_UID")
        if raw is None or not raw.isdigit() or int(raw) <= 0:
            fail(
                "root preflight refused: SUDO_UID is missing; rerun via "
                "the printed /usr/bin/sudo -H -- authenticated CPython 3.14.7 "
                "loader so the owner identity is preserved. "
                "Do not use a login root shell"
            )
        launch_authenticated_provisioner(manifest, require_root=True)
        return 0
    except Refused as suc:
        print(f"release-android-toolchain provision: {suc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, UnicodeDecodeError) as suc:
        print(
            f"release-android-toolchain provision: fail-closed error: {suc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
