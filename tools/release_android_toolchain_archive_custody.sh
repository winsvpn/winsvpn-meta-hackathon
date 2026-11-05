#!/bin/bash
# Sourceable macOS Flutter/JDK release-toolchain archive custody.
# Authenticated Python custody is required. Callers cannot self-author
# archives plus matching pins: only the in-repo helper, contract, and
# exact pin manifest may bind Flutter 3.47.6 and Temurin 17.0.20.1.
# Candidate Flutter/Dart/Java execution binds a one-time owner-provisioned
# root-owned 0555/0444 + SF_IMMUTABLE tree under
# /Library/WinsVPN/ReleaseAndroidToolchains, then runs as the original
# non-root uid. Unprivileged SF_IMMUTABLE on /private/tmp fails with EPERM.
# UF_IMMUTABLE is insufficient because the owner can clear it. This helper
# never invokes sudo, never reads a password, and never runs Flutter, Gradle,
# or signing as root. The owner provisions with a one-shot authenticated
# loader on the sealed CPython 3.14.7 wrapper:
#   /usr/bin/sudo -H -- /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I -S \
#     -c '<authenticated one-shot loader with the reviewed launcher SHA-256 literal>' \
#     /ABS/PATH/tools/launch_macos_release_android_toolchains.py \
#     /ABS/PATH/tools/toolchain-pins.json \
#     INVOKING_UID INVOKING_GID
# The loader holds the user-writable launcher bytes; root never executes that
# pathname. System python/uname/lipo/env are never reopened by mutable pathname after
# verification.

readonly WINS_RELEASE_ANDROID_TOOLCHAIN_CUSTODY_LOADED=1
readonly WINS_RELEASE_ANDROID_OWNER_LIBRARY=/Library/WinsVPN
readonly WINS_RELEASE_ANDROID_OWNER_PREFIX=/Library/WinsVPN/ReleaseAndroidToolchains
readonly WINS_RELEASE_ANDROID_OWNER_FLUTTER=/Library/WinsVPN/ReleaseAndroidToolchains/flutter-3.47.6
readonly WINS_RELEASE_ANDROID_OWNER_JAVA=/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1
readonly WINS_RELEASE_ANDROID_OWNER_BOOTSTRAP=/Library/WinsVPN/ReleaseAndroidToolchainBootstrap

_wins_rat_error() {
  printf 'release-android-toolchain custody: %s\n' "$*" >&2
  return 1
}

_wins_rat_helper_path() {
  local src="${BASH_SOURCE[0]}"
  local dir
  [[ -n "$src" ]] || return 1
  dir="$(cd "$(dirname "$src")" && pwd)" || return 1
  printf '%s\n' "$dir/$(basename "$src")"
}

_wins_rat_require_authenticated_python() {
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rat_error 'authenticated release Python custody is required' || return 1
}

_wins_rat_bind_exact_inputs() {
  local helper manifest tools_dir
  helper="$(_wins_rat_helper_path)" ||
    _wins_rat_error 'Android toolchain helper path could not be resolved' || return 1
  tools_dir="$(cd "$(dirname "$helper")" && pwd)" || return 1
  [[ "$helper" == "$tools_dir/release_android_toolchain_archive_custody.sh" ]] ||
    _wins_rat_error 'malicious or substituted Android toolchain helper rejected' || return 1
  [[ $# -eq 1 ]] || return 0
  manifest="$1"
  [[ "$manifest" == "$tools_dir/toolchain-pins.json" ]] ||
    _wins_rat_error 'replacement Android pin manifest cannot self-authorize' || return 1
}

_wins_rat_python() {
  local helper
  _wins_rat_require_authenticated_python || return 1
  helper="$(_wins_rat_helper_path)" ||
    _wins_rat_error 'Android toolchain helper path could not be resolved' || return 1
  wins_release_python_run - --helper "$helper" "$@" <<'WINS_ANDROID_TOOLCHAIN_PYTHON'
# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN
from __future__ import annotations

import ctypes
import datetime as dt
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import struct
import sys
import tarfile
import tempfile
import time
import unicodedata
import zipfile
import zlib


PLATFORM = "darwin_arm64"
FLUTTER_VERSION = "3.47.6"
FLUTTER_REVISION = "5fc346839b5d0eef006ed8404392afb4dfae428d"
DART_VERSION = "3.13.5"
FLUTTER_ARCHIVE = "flutter_macos_arm64_3.47.6-stable.zip"
FLUTTER_REPOSITORY = "https://github.com/flutter/flutter.git"

JAVA_VERSION = "17.0.20.1"
JAVA_RELEASE = "jdk-17.0.20.1+1"
JAVA_ARCHIVE = "OpenJDK17U-jdk_aarch64_mac_hotspot_17.0.20.1_1.tar.gz"
JAVA_VENDOR = "Eclipse Adoptium"

PUB_CACHE_ROOT_NAME = "pub-cache"
PUB_CACHE_PAYLOAD_DIRS = ("hosted", "hosted-hashes")
PUB_CACHE_METADATA_NAME = "active_roots"
PUB_CACHE_TEMP_NAME = "_temp"
FLUTTER_TOOLS_REL = Path("packages") / "flutter_tools"
FLUTTER_TOOLS_PACKAGE_CONFIG = (
    '{"configVersion":2,"generator":"pub","packages":['
    '{"languageVersion":"3.11","name":"flutter_tools","packageUri":"lib/","rootUri":"../"}'
    "]}\n"
)

SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_MEMBER_COUNT = 500_000
MAX_MEMBER_BYTES = 8 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 32 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 4096
MAX_PATH_BYTES = 4096
MAX_PATH_DEPTH = 128
CHUNK = 1024 * 1024
HELPER_NAME = "release_android_toolchain_archive_custody.sh"
CONTRACT_NAME = "android-toolchain-custody.json"
MANIFEST_NAME = "toolchain-pins.json"
WINDOWS_HELPER_NAME = "android_toolchain_custody.ps1"
CONTRACT_ID = "winsvpn-android-toolchain-custody-v1"
RUNTIME_PREFIX = "wins-release-android-toolchains."
PRIVATE_TMP = Path("/private/tmp")
ISSUANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
ISO_UTC = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REVIEWED_ISSUANCE_UTC = dt.datetime(2026, 8, 19, 0, 0, 0, tzinfo=dt.timezone.utc)
MAX_CONTRACT_BYTES = 64 * 1024
MAX_HELPER_BYTES = 2 * 1024 * 1024
ARM64_CPU_TYPE = 0x0100000C
CLONE_NOFOLLOW = 0x0001
POSIX_SPAWN_SETSID = 0x0400
POSIX_SPAWN_CLOEXEC_DEFAULT = 0x4000
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
UF_IMMUTABLE = getattr(stat, "UF_IMMUTABLE", 0x00000002)
PROVISIONER_NAME = "provision_macos_release_android_toolchains.sh"
LAUNCHER_NAME = "launch_macos_release_android_toolchains.py"
OWNER_LIBRARY_ROOT = Path("/Library/WinsVPN")
OWNER_PREFIX = OWNER_LIBRARY_ROOT / "ReleaseAndroidToolchains"
OWNER_BOOTSTRAP = OWNER_LIBRARY_ROOT / "ReleaseAndroidToolchainBootstrap"
OWNER_FLUTTER_NAME = f"flutter-{FLUTTER_VERSION}"
OWNER_JAVA_NAME = f"jdk-{JAVA_VERSION}"
OWNER_FLUTTER = OWNER_PREFIX / OWNER_FLUTTER_NAME
OWNER_JAVA = OWNER_PREFIX / OWNER_JAVA_NAME
PYTHON_BEGIN = "# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n"
PYTHON_END = "\n# WINS_ANDROID_TOOLCHAIN_PYTHON_END"
BOOTSTRAP_STAGING_PREFIX = str(OWNER_LIBRARY_ROOT) + "/.ReleaseAndroidToolchainBootstrap.staging."
OWNER_SHELL_PREFIX = "sudo /bin/bash -p"
SEALED_CPYTHON_314 = (
    "/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14"
)
SEALED_SUDO = "/usr/bin/sudo"
OBFUSCATION_NAME = "release_obfuscation_contract.py"
LAUNCHER_SHA_PLACEHOLDER = "__LAUNCHER_SHA256_LITERAL__"
LAUNCHER_SHA_MARKER = 'ANDROID_TOOLCHAIN_LAUNCHER_SHA256 = (\n    "'
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
LIVE_HELPER: Path | None = None
EXECUTION_BLOCKER = (
    "owner/environment blocker: this host cannot make the Android toolchain "
    "tree immutable against same-user path replacement through execution"
)
MACOS_BLOCKER = (
    "owner/environment blocker: macOS kernel-bound Android toolchain execution "
    "is required"
)
SELF_AUTHORIZE = "replacement Android pin manifest cannot self-authorize"
HELPER_SUBSTITUTED = "malicious or substituted Android toolchain helper rejected"
MANIFEST_SUBSTITUTED = "malicious or substituted Android pin manifest rejected"
CONTRACT_KEYS = (
    "schema_version",
    "contract",
    "issuance_id",
    "created_utc",
    "helper",
    "helper_sha256",
    "provisioner",
    "manifest",
    "manifest_sha256",
    "windows_helper",
    "windows_helper_sha256",
    "platforms",
)
BOOTSTRAP_BUNDLE = (
    ("provisioner", PROVISIONER_NAME, 0o555, MAX_HELPER_BYTES),
    ("helper", HELPER_NAME, 0o555, MAX_HELPER_BYTES),
    ("contract", CONTRACT_NAME, 0o444, MAX_CONTRACT_BYTES),
    ("manifest", MANIFEST_NAME, 0o444, MAX_MANIFEST_BYTES),
)
PLATFORM_KEYS = ("darwin_arm64", "windows_amd64")
DARWIN_KEYS = ("status", "flutter", "java", "flutter_pub_cache")
DARWIN_FLUTTER_KEYS = (
    "version",
    "revision",
    "dart_version",
    "archive_name",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
)
DARWIN_JAVA_KEYS = (
    "version",
    "distribution",
    "release_name",
    "vendor",
    "jvm",
    "architecture",
    "image_type",
    "release_type",
    "archive_name",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
)
DARWIN_PUB_KEYS = (
    "top_level_root",
    "archive_name",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
    "package_count",
)
WINDOWS_PLATFORM_KEYS = ("status", "owner_action", "tools")
WINDOWS_TOOL_NAMES = ("python", "flutter", "jdk")
WINDOWS_TOOL_KEYS = (
    "version",
    "revision",
    "vendor",
    "architecture",
    "version_source",
    "revision_source",
    "vendor_source",
    "architecture_source",
    "archive_environment",
    "archive_sha256",
    "install_tree_sha256",
)
PIN_FLUTTER_KEYS = (
    "version",
    "revision",
    "dart_version",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
    "channel_note",
    "review_status",
    "review_note",
    "host_provisioning",
)
PIN_JAVA_KEYS = (
    "version",
    "distribution",
    "release_name",
    "vendor",
    "jvm",
    "architecture",
    "image_type",
    "release_type",
    "license",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
    "note",
)
PIN_PUB_KEYS = (
    "top_level_root",
    "archive_path",
    "archive_sha256",
    "install_tree_sha256",
    "package_count",
    "note",
)
PIN_PLATFORM_KEYS = ("darwin_arm64",)
ALLOWED_RUN_ENV = (
    "ANDROID_SDK_ROOT",
    "ANDROID_HOME",
    "WINS_ANDROID_KEYSTORE",
    "WINS_ANDROID_KEY_ALIAS",
    "WINS_ANDROID_KEY_PASSWORD",
    "WINS_ANDROID_STORE_PASSWORD",
)
if sys.platform == "darwin":
    _LIBC = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    _LIBC.fclonefileat.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    _LIBC.fclonefileat.restype = ctypes.c_int
    _LIBC.posix_spawn.restype = ctypes.c_int
    _LIBC.posix_spawnattr_init.restype = ctypes.c_int
    _LIBC.posix_spawnattr_setflags.restype = ctypes.c_int
    _LIBC.posix_spawnattr_destroy.restype = ctypes.c_int
    _LIBC.posix_spawn_file_actions_init.restype = ctypes.c_int
    _LIBC.posix_spawn_file_actions_adddup2.restype = ctypes.c_int
    _LIBC.posix_spawn_file_actions_addopen.restype = ctypes.c_int
    _LIBC.posix_spawn_file_actions_destroy.restype = ctypes.c_int
else:
    _LIBC = None


class Refused(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


def _sudo_invoking_uid() -> int | None:
    if os.geteuid() != 0:
        return None
    raw = os.environ.get("SUDO_UID")
    if raw is None or not raw.isdigit():
        return None
    uid = int(raw)
    if uid <= 0:
        return None
    return uid


def _allowed_source_uids() -> set[int]:
    allowed = {0, os.getuid()}
    invoking = _sudo_invoking_uid()
    if invoking is not None:
        allowed.add(invoking)
    return allowed


def _shell_quote(value: Path | str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def android_toolchain_launcher_loader(expected: str) -> str:
    if SHA_RE.fullmatch(expected) is None or expected == "0" * 64:
        fail("reviewed launcher digest must be an exact lowercase non-zero SHA-256")
    if ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE.count(LAUNCHER_SHA_PLACEHOLDER) != 1:
        fail("authenticated launcher loader placeholder is malformed")
    return ANDROID_TOOLCHAIN_LAUNCHER_LOADER_TEMPLATE.replace(
        LAUNCHER_SHA_PLACEHOLDER, expected
    )


def reviewed_launcher_sha256(tools_dir: Path) -> str:
    path = tools_dir / OBFUSCATION_NAME
    if not path.is_absolute() or ".." in path.parts:
        fail("owner command paths must be absolute")
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
    if SHA_RE.fullmatch(digest) is None or digest == "0" * 64:
        fail("reviewed launcher digest must be an exact lowercase non-zero SHA-256")
    return digest


def owner_provision_command(helper: Path | None = None) -> str:
    resolved = helper if helper is not None else LIVE_HELPER
    if resolved is None:
        fail("Android toolchain helper path is required to print the owner command")
    tools_dir = resolved.resolve(strict=False).parent
    if tools_dir == OWNER_BOOTSTRAP:
        fail(
            "owner command cannot use a cwd-relative launcher; rerun the "
            "repository provisioner as the original non-root user"
        )
    launcher = tools_dir / LAUNCHER_NAME
    manifest = tools_dir / MANIFEST_NAME
    if not launcher.is_absolute() or not manifest.is_absolute():
        fail("owner command paths must be absolute")
    if ".." in launcher.parts or ".." in manifest.parts:
        fail("owner command paths must be absolute")
    try:
        info = launcher.lstat()
    except FileNotFoundError:
        fail("Android toolchain CPython launcher is missing or symbolic")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("Android toolchain CPython launcher is missing or symbolic")
    uid = os.getuid()
    gid = os.getgid()
    if uid <= 0 or gid <= 0:
        fail("root preflight refused: SUDO_UID is missing")
    loader = android_toolchain_launcher_loader(reviewed_launcher_sha256(tools_dir))
    return (
        f"{SEALED_SUDO} -H -- {_shell_quote(SEALED_CPYTHON_314)} -I -S -c "
        f"{_shell_quote(loader)} {_shell_quote(launcher)} {_shell_quote(manifest)} "
        f"{uid} {gid}"
    )


def _owner_unavailable(detail: str, helper: Path | None = None) -> None:
    fail(
        f"{EXECUTION_BLOCKER}: owner-provisioned root-owned Flutter {FLUTTER_VERSION}/"
        f"JDK {JAVA_VERSION} trees are unavailable ({detail}); owner action: "
        f"{owner_provision_command(helper)}"
    )


def _is_foreign_protected_path(tree: Path) -> bool:
    text = str(tree)
    if text == "/Library" or text.startswith("/Library/"):
        return True
    prefix = str(OWNER_PREFIX)
    return text == prefix or text.startswith(prefix + "/")


def _refuse_root_execution() -> None:
    if os.geteuid() == 0 or os.getuid() == 0:
        fail(
            "owner-blocked: Android toolchain execution must drop to the original "
            "non-root uid; Flutter/JDK/Gradle/signing are never run as root"
        )


def duplicate_safe_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _nofollow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required for Android toolchain custody")
    return flag


def _cloexec_flag() -> int:
    return getattr(os, "O_CLOEXEC", 0)


def _nonblock_flag() -> int:
    flag = getattr(os, "O_NONBLOCK", 0)
    if not flag:
        fail("O_NONBLOCK is required for Android toolchain custody")
    return flag


def _clear_nonblock_if_needed(fd: int) -> None:
    if not hasattr(fcntl, "F_GETFL") or not hasattr(fcntl, "F_SETFL"):
        fail("F_GETFL and F_SETFL are required for Android toolchain custody")
    nonblock = _nonblock_flag()
    current = fcntl.fcntl(fd, fcntl.F_GETFL)
    if current & nonblock:
        fcntl.fcntl(fd, fcntl.F_SETFL, current & ~nonblock)


def _open_flags() -> int:
    return os.O_RDONLY | _cloexec_flag() | _nofollow_flag()


def _posix_errno(rc: int, what: str) -> OSError:
    return OSError(rc, f"{what}: {os.strerror(rc)}")


def _must(rc: int, what: str) -> None:
    if rc:
        raise _posix_errno(rc if rc > 0 else ctypes.get_errno(), what)


def _json_object(pairs):
    return duplicate_safe_object(pairs)


def _mapping(value, label: str) -> dict:
    if type(value) is not dict:
        fail(f"{label} must be one JSON object")
    return value


def _text(mapping: dict, key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        fail(f"{key} must be one non-empty string")
    if any(ord(character) < 32 for character in value) or value.strip() != value:
        fail(f"{key} contains a control character")
    return value


def _exact_int(value, label: str) -> int:
    if type(value) is bool:
        fail(f"{label} must be an integer, not bool-as-int")
    if type(value) is not int:
        fail(f"{label} has the wrong type")
    return value


def _null(mapping: dict, key: str) -> None:
    if mapping.get(key) is not None:
        fail(f"{key} must be JSON null")


def _require_keys(mapping: dict, required: tuple[str, ...], label: str) -> None:
    missing = [key for key in required if key not in mapping]
    if missing:
        fail(f"{label} field is absent: {missing[0]}")
    extra = [key for key in mapping if key not in required]
    if extra:
        fail(f"unexpected extra field rejected: {label}.{extra[0]}")


def _hex64(mapping: dict, key: str) -> str:
    value = _text(mapping, key)
    if SHA_RE.fullmatch(value) is None or value == "0" * 64:
        fail(f"{key} must be an exact lowercase non-zero SHA-256")
    return value


def _utc(mapping: dict, key: str) -> dt.datetime:
    value = _text(mapping, key)
    if ISO_UTC.fullmatch(value) is None:
        fail(f"{key} must be exact ISO UTC")
    parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )
    now = dt.datetime.now(dt.timezone.utc)
    if parsed < REVIEWED_ISSUANCE_UTC:
        fail(f"{key} is stale")
    if parsed > now + dt.timedelta(minutes=5):
        fail(f"{key} is future-dated")
    return parsed


def _issuance(mapping: dict, key: str) -> str:
    value = _text(mapping, key)
    if ISSUANCE_RE.fullmatch(value) is None:
        fail(f"{key} must be a 32-hex issuance identity")
    return value


def bind_regular_file(path: Path, *, max_size: int, label: str) -> bytes:
    reject_symlink_components(path, label)
    try:
        before = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is absent")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be one regular non-symlink single-link file")
    if before.st_uid not in _allowed_source_uids():
        fail(f"{label} has an untrusted owner")
    if before.st_size <= 0 or before.st_size > max_size:
        fail(f"{label} size is outside the custody bound")
    fd = os.open(path, _open_flags())
    try:
        opened = os.fstat(fd)
        if identity(before) != identity(opened):
            fail(f"{label} was replaced before it was opened")
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            chunks.append(block)
            if sum(len(item) for item in chunks) > max_size:
                fail(f"{label} exceeds the custody bound")
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            fail(f"{label} changed while it was read")
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if not data:
        fail(f"{label} snapshot is empty")
    return data


def hold_regular_file(path: Path, *, max_size: int, label: str) -> tuple[int, bytes, str]:
    """Open path with O_NOFOLLOW/O_NONBLOCK, fstat, then read the held fd.

    Callers must close the returned fd. The path is never reopened.
    """
    reject_symlink_components(path, label)
    try:
        before = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is absent")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be one regular non-symlink single-link file")
    if before.st_uid not in _allowed_source_uids():
        fail(f"{label} has an untrusted owner")
    if before.st_size <= 0 or before.st_size > max_size:
        fail(f"{label} size is outside the custody bound")
    try:
        fd = os.open(path, _open_flags() | _nonblock_flag())
    except OSError:
        fail(f"{label} path is not a readable regular file")
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail(f"{label} must be one regular non-symlink single-link file")
        if identity(before) != identity(opened):
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
        if identity(opened) != identity(after):
            fail(f"{label} changed while it was read")
        data = b"".join(chunks)
        if not data:
            fail(f"{label} snapshot is empty")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, data, _digest_bytes(data)
    except BaseException:
        os.close(fd)
        raise


def copy_held_fd(
    fd: int, data: bytes, destination: Path, expected: str, *, mode: int, label: str
) -> None:
    os.fstat(fd)
    if _digest_bytes(data) != expected:
        fail(f"{label} SHA-256 mismatch during held-fd copy")
    dest_flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec_flag() | _nofollow_flag()
    )
    dest_fd = os.open(destination, dest_flags, 0o600)
    digest = hashlib.sha256()
    try:
        view = memoryview(data)
        while view:
            written = os.write(dest_fd, view)
            if written <= 0:
                fail(f"short write while copying {label}")
            digest.update(view[:written])
            view = view[written:]
        os.fsync(dest_fd)
        os.fchmod(dest_fd, mode)
    finally:
        os.close(dest_fd)
    if digest.hexdigest() != expected:
        fail(f"{label} SHA-256 mismatch during held-fd copy")
    _, copied_digest = stable_file_digest(destination)
    if copied_digest != expected:
        fail(f"copied {label} SHA-256 mismatch")


def extract_helper_python(data: bytes | str) -> str:
    text = data.decode("ascii") if isinstance(data, bytes) else data
    try:
        begin = text.index(PYTHON_BEGIN) + len(PYTHON_BEGIN)
        end = text.index(PYTHON_END)
    except ValueError:
        fail("sealed helper Python markers are absent")
    source = text[begin:end]
    if "def main(" not in source or "def provision_owner_toolchains(" not in source:
        fail("sealed helper Python does not define provision entrypoints")
    if "\nif __name__ == \"__main__\":\n" not in source or "raise SystemExit(main())" not in source:
        fail("sealed helper Python does not invoke main")
    return source


def require_exact_provisioned_result(output: str) -> None:
    expected = {
        f"provisioned {OWNER_FLUTTER} and {OWNER_JAVA}",
        f"already provisioned at {OWNER_FLUTTER} and {OWNER_JAVA}",
    }
    lines = [line.rstrip("\r") for line in output.split("\n") if line.strip()]
    if not any(line in expected for line in lines):
        fail("owner command produced no exact provisioned result")


def invoke_provision_main(source: str, helper_path: Path, manifest_path: Path) -> str:
    from contextlib import redirect_stdout

    guard = '\nif __name__ == "__main__":\n'
    index = source.rfind(guard)
    if index < 0:
        fail("sealed helper Python does not invoke main")
    body = source[:index]
    namespace: dict = {"__name__": "android_toolchain_sealed_exec"}
    exec(compile(body, str(helper_path), "exec"), namespace)
    previous = sys.argv
    sys.argv = [
        "release_android_toolchain_archive_custody",
        "--helper",
        str(helper_path),
        "provision",
        str(manifest_path),
    ]
    captured = io.StringIO()
    try:
        with redirect_stdout(captured):
            rc = namespace["main"]()
    finally:
        sys.argv = previous
    if rc not in (0, None):
        fail("sealed helper provision returned a non-zero status")
    output = captured.getvalue()
    sys.stdout.write(output)
    require_exact_provisioned_result(output)
    return output


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dev_ino(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return (int(info.st_dev), int(info.st_ino))


def provisioner_embedded_pins(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("Android toolchain provisioner is not ASCII")
    pins: dict[str, str] = {}
    for kind in ("HELPER", "CONTRACT", "MANIFEST"):
        marker = f"readonly _WINS_PRAT_{kind}_SHA256='"
        if text.count(marker) != 1:
            fail("Android toolchain provisioner pin markers are malformed")
        start = text.index(marker) + len(marker)
        digest = text[start : start + 64]
        if SHA_RE.fullmatch(digest) is None or digest == "0" * 64:
            fail(f"Android toolchain provisioner {kind.lower()} digest is malformed")
        if start + 64 >= len(text) or text[start + 64] != "'":
            fail("Android toolchain provisioner pin markers are malformed")
        pins[kind.lower()] = digest
    return pins


def authenticate_bootstrap_payloads(payloads: dict[str, bytes]) -> None:
    required = ("provisioner", "helper", "contract", "manifest")
    if set(payloads) != set(required):
        fail("sealed bootstrap payload set is not exact")
    pins = provisioner_embedded_pins(payloads["provisioner"])
    helper_digest = _digest_bytes(payloads["helper"])
    contract_digest = _digest_bytes(payloads["contract"])
    manifest_digest = _digest_bytes(payloads["manifest"])
    if helper_digest != pins["helper"]:
        fail(HELPER_SUBSTITUTED)
    if contract_digest != pins["contract"]:
        fail("stale or substituted Android toolchain contract rejected")
    if manifest_digest != pins["manifest"]:
        fail(MANIFEST_SUBSTITUTED)
    contract = parse_contract_bytes(payloads["contract"])
    if helper_digest != contract["helper_sha256"]:
        fail(HELPER_SUBSTITUTED)
    if manifest_digest != contract["manifest_sha256"]:
        fail(MANIFEST_SUBSTITUTED)


def parse_contract_bytes(data: bytes) -> dict:
    if b"\0" in data:
        fail("Android toolchain contract contains a NUL")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"Android toolchain contract is not strict UTF-8 JSON: {exc}")
    root = _mapping(document, "contract")
    _require_keys(root, CONTRACT_KEYS, "contract")
    if _exact_int(root.get("schema_version"), "schema_version") != 1:
        fail("schema_version must be exactly 1")
    if _text(root, "contract") != CONTRACT_ID:
        fail("Android toolchain custody contract mismatch")
    _issuance(root, "issuance_id")
    _utc(root, "created_utc")
    if _text(root, "helper") != f"tools/{HELPER_NAME}":
        fail("helper path mismatch")
    if _text(root, "provisioner") != f"tools/{PROVISIONER_NAME}":
        fail("provisioner path mismatch")
    if _text(root, "manifest") != f"tools/{MANIFEST_NAME}":
        fail("manifest path mismatch")
    if _text(root, "windows_helper") != f"tools/{WINDOWS_HELPER_NAME}":
        fail("windows helper path mismatch")
    _hex64(root, "helper_sha256")
    _hex64(root, "manifest_sha256")
    _hex64(root, "windows_helper_sha256")
    platforms = _mapping(root.get("platforms"), "platforms")
    _require_keys(platforms, PLATFORM_KEYS, "platforms")
    darwin = _mapping(platforms.get("darwin_arm64"), "darwin_arm64")
    _require_keys(darwin, DARWIN_KEYS, "darwin_arm64")
    if _text(darwin, "status") != "pinned":
        fail("darwin_arm64 status must be pinned")
    flutter = _mapping(darwin.get("flutter"), "darwin_arm64.flutter")
    java = _mapping(darwin.get("java"), "darwin_arm64.java")
    pub = _mapping(darwin.get("flutter_pub_cache"), "darwin_arm64.flutter_pub_cache")
    _require_keys(flutter, DARWIN_FLUTTER_KEYS, "darwin_arm64.flutter")
    _require_keys(java, DARWIN_JAVA_KEYS, "darwin_arm64.java")
    _require_keys(pub, DARWIN_PUB_KEYS, "darwin_arm64.flutter_pub_cache")
    if _text(flutter, "version") != FLUTTER_VERSION:
        fail(f"flutter version must be exactly {FLUTTER_VERSION}")
    if _text(flutter, "revision") != FLUTTER_REVISION:
        fail(f"flutter revision must be exactly {FLUTTER_REVISION}")
    if _text(flutter, "dart_version") != DART_VERSION:
        fail(f"flutter dart_version must be exactly {DART_VERSION}")
    if _text(flutter, "archive_name") != FLUTTER_ARCHIVE:
        fail(f"flutter archive_name must be exactly {FLUTTER_ARCHIVE}")
    _hex64(flutter, "archive_sha256")
    _hex64(flutter, "install_tree_sha256")
    if flutter["archive_sha256"] == flutter["install_tree_sha256"]:
        fail("flutter archive and tree hashes must be independent")
    if _text(java, "version") != JAVA_VERSION:
        fail(f"java version must be exactly {JAVA_VERSION}")
    if _text(java, "distribution") != "eclipse-temurin":
        fail("java distribution must be exactly eclipse-temurin")
    if _text(java, "release_name") != JAVA_RELEASE:
        fail(f"java release_name must be exactly {JAVA_RELEASE}")
    if _text(java, "vendor") != JAVA_VENDOR:
        fail(f"java vendor must be exactly {JAVA_VENDOR}")
    if _text(java, "jvm") != "hotspot":
        fail("java jvm must be exactly hotspot")
    if _text(java, "architecture") != "aarch64":
        fail("java architecture must be exactly aarch64")
    if _text(java, "image_type") != "jdk":
        fail("java image_type must be exactly jdk")
    if _text(java, "release_type") != "ga":
        fail("java release_type must be exactly ga")
    if _text(java, "archive_name") != JAVA_ARCHIVE:
        fail(f"java archive_name must be exactly {JAVA_ARCHIVE}")
    _hex64(java, "archive_sha256")
    _hex64(java, "install_tree_sha256")
    if java["archive_sha256"] == java["install_tree_sha256"]:
        fail("java archive and tree hashes must be independent")
    if _text(pub, "top_level_root") != PUB_CACHE_ROOT_NAME:
        fail("flutter_pub_cache top_level_root must be exactly pub-cache")
    _hex64(pub, "archive_sha256")
    _hex64(pub, "install_tree_sha256")
    if pub["archive_sha256"] == pub["install_tree_sha256"]:
        fail("flutter_pub_cache archive and tree hashes must be independent")
    _exact_int(pub.get("package_count"), "flutter_pub_cache.package_count")
    windows = _mapping(platforms.get("windows_amd64"), "windows_amd64")
    _require_keys(windows, WINDOWS_PLATFORM_KEYS, "windows_amd64")
    if _text(windows, "status") != "owner_inputs_required":
        fail("windows_amd64 must remain owner_inputs_required")
    _text(windows, "owner_action")
    tools = _mapping(windows.get("tools"), "windows_amd64.tools")
    _require_keys(tools, WINDOWS_TOOL_NAMES, "windows_amd64.tools")
    for name in WINDOWS_TOOL_NAMES:
        record = _mapping(tools.get(name), f"windows_amd64.tools.{name}")
        _require_keys(record, WINDOWS_TOOL_KEYS, f"windows_amd64.tools.{name}")
        for field in (
            "version",
            "revision",
            "vendor",
            "architecture",
            "archive_sha256",
            "install_tree_sha256",
        ):
            _null(record, field)
        _text(record, "version_source")
        _text(record, "revision_source")
        _text(record, "vendor_source")
        _text(record, "architecture_source")
        _text(record, "archive_environment")
    return root


def parse_pin_tools_bytes(data: bytes, contract: dict) -> dict:
    if b"\0" in data:
        fail("pin manifest contains a NUL")
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as suc:
        fail(f"pin manifest is not strict UTF-8 JSON: {suc}")
    root = _mapping(document, "pin manifest")
    tools = _mapping(root.get("tools"), "tools")
    flutter = _mapping(tools.get("flutter"), "tools.flutter")
    java = _mapping(tools.get("java"), "tools.java")
    pub = _mapping(tools.get("flutter_pub_cache"), "tools.flutter_pub_cache")
    darwin = _mapping(contract["platforms"].get("darwin_arm64"), "darwin_arm64")
    expected_flutter = _mapping(darwin.get("flutter"), "darwin_arm64.flutter")
    expected_java = _mapping(darwin.get("java"), "darwin_arm64.java")
    expected_pub = _mapping(darwin.get("flutter_pub_cache"), "darwin_arm64.flutter_pub_cache")
    for key in ("version", "revision", "dart_version"):
        if _text(flutter, key) != expected_flutter[key]:
            fail(f"tools.flutter.{key} does not match the authenticated contract")
    flutter_paths = _mapping(flutter.get("archive_path"), "tools.flutter.archive_path")
    flutter_archives = _mapping(flutter.get("archive_sha256"), "tools.flutter.archive_sha256")
    flutter_trees = _mapping(flutter.get("install_tree_sha256"), "tools.flutter.install_tree_sha256")
    _require_keys(flutter_paths, PIN_PLATFORM_KEYS, "tools.flutter.archive_path")
    _require_keys(flutter_archives, PIN_PLATFORM_KEYS, "tools.flutter.archive_sha256")
    _require_keys(flutter_trees, PIN_PLATFORM_KEYS, "tools.flutter.install_tree_sha256")
    archive_path = Path(_text(flutter_paths, PLATFORM))
    if archive_path.name != expected_flutter["archive_name"]:
        fail("tools.flutter archive basename does not match the authenticated contract")
    if _text(flutter_paths, PLATFORM) != _text(expected_flutter, "archive_path"):
        fail("tools.flutter archive_path does not match the authenticated contract")
    if _text(flutter_archives, PLATFORM) != expected_flutter["archive_sha256"]:
        fail("tools.flutter archive_sha256 does not match the authenticated contract")
    if _text(flutter_trees, PLATFORM) != expected_flutter["install_tree_sha256"]:
        fail("tools.flutter install_tree_sha256 does not match the authenticated contract")
    for key in (
        "version",
        "distribution",
        "release_name",
        "vendor",
        "jvm",
        "architecture",
        "image_type",
        "release_type",
    ):
        if _text(java, key) != expected_java[key]:
            fail(f"tools.java.{key} does not match the authenticated contract")
    java_paths = _mapping(java.get("archive_path"), "tools.java.archive_path")
    java_archives = _mapping(java.get("archive_sha256"), "tools.java.archive_sha256")
    java_trees = _mapping(java.get("install_tree_sha256"), "tools.java.install_tree_sha256")
    _require_keys(java_paths, PIN_PLATFORM_KEYS, "tools.java.archive_path")
    _require_keys(java_archives, PIN_PLATFORM_KEYS, "tools.java.archive_sha256")
    _require_keys(java_trees, PIN_PLATFORM_KEYS, "tools.java.install_tree_sha256")
    java_archive = Path(_text(java_paths, PLATFORM))
    if java_archive.name != expected_java["archive_name"]:
        fail("tools.java archive basename does not match the authenticated contract")
    if _text(java_paths, PLATFORM) != _text(expected_java, "archive_path"):
        fail("tools.java archive_path does not match the authenticated contract")
    if _text(java_archives, PLATFORM) != expected_java["archive_sha256"]:
        fail("tools.java archive_sha256 does not match the authenticated contract")
    if _text(java_trees, PLATFORM) != expected_java["install_tree_sha256"]:
        fail("tools.java install_tree_sha256 does not match the authenticated contract")
    if _text(pub, "top_level_root") != expected_pub["top_level_root"]:
        fail("tools.flutter_pub_cache.top_level_root does not match the authenticated contract")
    pub_paths = _mapping(pub.get("archive_path"), "tools.flutter_pub_cache.archive_path")
    pub_archives = _mapping(pub.get("archive_sha256"), "tools.flutter_pub_cache.archive_sha256")
    pub_trees = _mapping(
        pub.get("install_tree_sha256"), "tools.flutter_pub_cache.install_tree_sha256"
    )
    _require_keys(pub_paths, PIN_PLATFORM_KEYS, "tools.flutter_pub_cache.archive_path")
    _require_keys(pub_archives, PIN_PLATFORM_KEYS, "tools.flutter_pub_cache.archive_sha256")
    _require_keys(pub_trees, PIN_PLATFORM_KEYS, "tools.flutter_pub_cache.install_tree_sha256")
    if Path(_text(pub_paths, PLATFORM)).name != _text(expected_pub, "archive_name"):
        fail("tools.flutter_pub_cache archive basename does not match the authenticated contract")
    if _text(pub_paths, PLATFORM) != _text(expected_pub, "archive_path"):
        fail("tools.flutter_pub_cache archive_path does not match the authenticated contract")
    if _text(pub_archives, PLATFORM) != expected_pub["archive_sha256"]:
        fail("tools.flutter_pub_cache archive_sha256 does not match the authenticated contract")
    if _text(pub_trees, PLATFORM) != expected_pub["install_tree_sha256"]:
        fail("tools.flutter_pub_cache install_tree_sha256 does not match the authenticated contract")
    if _exact_int(pub.get("package_count"), "tools.flutter_pub_cache.package_count") != _exact_int(
        expected_pub.get("package_count"), "contract flutter_pub_cache.package_count"
    ):
        fail("tools.flutter_pub_cache.package_count does not match the authenticated contract")
    return {
        "flutter": {
            "path": archive_path,
            "archive_sha": expected_flutter["archive_sha256"],
            "tree_sha": expected_flutter["install_tree_sha256"],
        },
        "java": {
            "path": java_archive,
            "archive_sha": expected_java["archive_sha256"],
            "tree_sha": expected_java["install_tree_sha256"],
        },
        "pub": {
            "path": Path(_text(pub_paths, PLATFORM)),
            "archive_sha": expected_pub["archive_sha256"],
            "tree_sha": expected_pub["install_tree_sha256"],
            "top_level_root": expected_pub["top_level_root"],
        },
    }


def authorize_custody_inputs(helper: Path, manifest: Path) -> dict:
    if helper.name != HELPER_NAME:
        fail(HELPER_SUBSTITUTED)
    if helper.parent == OWNER_BOOTSTRAP:
        if helper != OWNER_BOOTSTRAP / HELPER_NAME:
            fail(HELPER_SUBSTITUTED)
        if manifest != OWNER_BOOTSTRAP / MANIFEST_NAME:
            fail(MANIFEST_SUBSTITUTED)
        helper_data = bind_regular_file(
            helper, max_size=MAX_HELPER_BYTES, label="sealed Android toolchain helper"
        )
        contract_data = bind_regular_file(
            OWNER_BOOTSTRAP / CONTRACT_NAME,
            max_size=MAX_CONTRACT_BYTES,
            label="sealed Android toolchain contract",
        )
        manifest_data = bind_regular_file(
            manifest, max_size=MAX_MANIFEST_BYTES, label="sealed Android pin manifest"
        )
        provisioner_data = bind_regular_file(
            OWNER_BOOTSTRAP / PROVISIONER_NAME,
            max_size=MAX_HELPER_BYTES,
            label="sealed Android toolchain provisioner",
        )
        authenticate_bootstrap_payloads(
            {
                "provisioner": provisioner_data,
                "helper": helper_data,
                "contract": contract_data,
                "manifest": manifest_data,
            }
        )
        contract = parse_contract_bytes(contract_data)
        pins = parse_pin_tools_bytes(manifest_data, contract)
        return {
            "contract": contract,
            "pins": pins,
            "manifest_sha": _digest_bytes(manifest_data),
            "helper": helper,
            "manifest": manifest,
        }
    tools_dir = helper.resolve(strict=False).parent
    if tools_dir.name != "tools":
        fail(HELPER_SUBSTITUTED)
    expected_helper = tools_dir / HELPER_NAME
    expected_contract = tools_dir / CONTRACT_NAME
    expected_manifest = tools_dir / MANIFEST_NAME
    expected_windows = tools_dir / WINDOWS_HELPER_NAME
    if helper != expected_helper:
        fail(HELPER_SUBSTITUTED)
    if manifest != expected_manifest:
        fail(SELF_AUTHORIZE)
    helper_data = bind_regular_file(
        expected_helper, max_size=MAX_HELPER_BYTES, label="Android toolchain helper"
    )
    contract_data = bind_regular_file(
        expected_contract, max_size=MAX_CONTRACT_BYTES, label="Android toolchain contract"
    )
    manifest_data = bind_regular_file(
        expected_manifest, max_size=MAX_MANIFEST_BYTES, label="Android pin manifest"
    )
    windows_data = bind_regular_file(
        expected_windows, max_size=MAX_HELPER_BYTES, label="Android Windows helper"
    )
    contract = parse_contract_bytes(contract_data)
    if _digest_bytes(helper_data) != contract["helper_sha256"]:
        fail(HELPER_SUBSTITUTED)
    if _digest_bytes(manifest_data) != contract["manifest_sha256"]:
        fail(MANIFEST_SUBSTITUTED)
    if _digest_bytes(windows_data) != contract["windows_helper_sha256"]:
        fail("malicious or substituted Android Windows helper rejected")
    pins = parse_pin_tools_bytes(manifest_data, contract)
    return {
        "contract": contract,
        "pins": pins,
        "manifest_sha": _digest_bytes(manifest_data),
        "helper": expected_helper,
        "manifest": expected_manifest,
    }


def stable_bytes(path: Path, label: str, *, require_read_only: bool, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be a regular non-symlink single-link file")
    if before.st_uid not in _allowed_source_uids():
        fail(f"{label} has an untrusted owner")
    if require_read_only and stat.S_IMODE(before.st_mode) & 0o222:
        fail(f"{label} must be read-only")
    if before.st_size <= 0 or before.st_size > max_bytes:
        fail(f"{label} size is outside the custody bound")
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        data = bytearray()
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            data.extend(block)
            if len(data) > max_bytes:
                fail(f"{label} exceeds the custody bound")
        finished = os.fstat(fd)
    finally:
        os.close(fd)
    after = path.lstat()
    if not (identity(before) == identity(opened) == identity(finished) == identity(after)):
        fail(f"{label} changed while it was read")
    return bytes(data)


def reject_symlink_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        if part in {"", ".", ".."}:
            fail(f"{label} contains an unsafe path component")
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            fail(f"{label} is absent")
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} must not traverse a symlink")


def read_manifest(path_text: str) -> tuple[dict, str]:
    path = Path(path_text)
    reject_symlink_components(path, "pin manifest")
    raw = stable_bytes(
        path,
        "pin manifest",
        require_read_only=False,
        max_bytes=MAX_MANIFEST_BYTES,
    )
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_safe_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"pin manifest is not strict UTF-8 JSON: {exc}")
    root = _mapping(manifest, "pin manifest")
    if _exact_int(root.get("schema_version"), "schema_version") != 1:
        fail("pin manifest schema_version must be exactly 1")
    return root, hashlib.sha256(raw).hexdigest()


def required_string(value, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        fail(f"{label} must be one non-empty control-free string")
    return value


def platform_pin(tool: dict, key: str, label: str) -> str:
    mapping = tool.get(key)
    if not isinstance(mapping, dict):
        fail(f"{label}.{key} must be a platform map")
    return required_string(mapping.get(PLATFORM), f"{label}.{key}.{PLATFORM}")


def validate_pub_cache_pin(tool: dict) -> dict:
    archive_path = Path(platform_pin(tool, "archive_path", "flutter_pub_cache"))
    archive_sha = platform_pin(tool, "archive_sha256", "flutter_pub_cache")
    tree_sha = platform_pin(tool, "install_tree_sha256", "flutter_pub_cache")
    top_level_root = required_string(
        tool.get("top_level_root"), "flutter_pub_cache.top_level_root"
    )
    if top_level_root != PUB_CACHE_ROOT_NAME:
        fail("flutter_pub_cache top_level_root must be exactly pub-cache")
    if archive_path.suffix.lower() != ".zip":
        fail("flutter_pub_cache archive must be a ZIP file")
    if not SHA_RE.fullmatch(archive_sha) or archive_sha == "0" * 64:
        fail("flutter_pub_cache archive SHA-256 pin is malformed")
    if not SHA_RE.fullmatch(tree_sha) or tree_sha == "0" * 64:
        fail("flutter_pub_cache tree SHA-256 pin is malformed")
    if archive_sha == tree_sha:
        fail("flutter_pub_cache archive and tree hashes must be independent")
    return {
        "path": archive_path,
        "archive_sha": archive_sha,
        "tree_sha": tree_sha,
        "top_level_root": top_level_root,
    }


def validate_exact_pins(manifest: dict) -> tuple[dict, dict, dict | None]:
    tools = manifest.get("tools")
    if not isinstance(tools, dict):
        fail("pin manifest tools object is missing")
    flutter = tools.get("flutter")
    java = tools.get("java")
    if not isinstance(flutter, dict) or not isinstance(java, dict):
        fail("exact flutter and java pin objects are required")
    pub_cache = tools.get("flutter_pub_cache")
    if "flutter_pub_cache" in tools and not isinstance(pub_cache, dict):
        fail("exact flutter_pub_cache pin object is required")

    exact_flutter = {
        "version": FLUTTER_VERSION,
        "revision": FLUTTER_REVISION,
        "dart_version": DART_VERSION,
    }
    for key, expected in exact_flutter.items():
        if flutter.get(key) != expected:
            fail(f"flutter {key} must be exactly {expected}")

    exact_java = {
        "version": JAVA_VERSION,
        "distribution": "eclipse-temurin",
        "release_name": JAVA_RELEASE,
        "vendor": JAVA_VENDOR,
        "jvm": "hotspot",
        "architecture": "aarch64",
        "image_type": "jdk",
        "release_type": "ga",
    }
    for key, expected in exact_java.items():
        if java.get(key) != expected:
            fail(f"java {key} must be exactly {expected}")

    result = {}
    for label, tool, expected_name in (
        ("flutter", flutter, FLUTTER_ARCHIVE),
        ("java", java, JAVA_ARCHIVE),
    ):
        archive_path = Path(platform_pin(tool, "archive_path", label))
        archive_sha = platform_pin(tool, "archive_sha256", label)
        tree_sha = platform_pin(tool, "install_tree_sha256", label)
        if archive_path.name != expected_name:
            fail(f"{label} archive basename must be exactly {expected_name}")
        if not SHA_RE.fullmatch(archive_sha) or archive_sha == "0" * 64:
            fail(f"{label} archive SHA-256 pin is malformed")
        if not SHA_RE.fullmatch(tree_sha) or tree_sha == "0" * 64:
            fail(f"{label} tree SHA-256 pin is malformed")
        if archive_sha == tree_sha:
            fail(f"{label} archive and tree hashes must be independent")
        result[label] = {
            "path": archive_path,
            "archive_sha": archive_sha,
            "tree_sha": tree_sha,
        }
    pub_pin = validate_pub_cache_pin(pub_cache) if isinstance(pub_cache, dict) else None
    return result["flutter"], result["java"], pub_pin


def copy_authenticated(source: Path, expected: str, destination: Path, label: str) -> None:
    reject_symlink_components(source, f"{label} archive")
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} archive must be a regular non-symlink single-link file")
    if before.st_uid not in _allowed_source_uids():
        fail(f"{label} archive has an untrusted owner")
    if stat.S_IMODE(before.st_mode) & 0o222:
        fail(f"{label} archive must be read-only")
    if before.st_size <= 0 or before.st_size > MAX_ARCHIVE_BYTES:
        fail(f"{label} archive size is outside the custody bound")

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_NOFOLLOW", 0):
        fail("O_NOFOLLOW is required for Android toolchain custody")
    source_fd = os.open(source, source_flags)
    destination_fd = os.open(destination, destination_flags, 0o600)
    digest = hashlib.sha256()
    copied = 0
    try:
        opened = os.fstat(source_fd)
        while True:
            block = os.read(source_fd, CHUNK)
            if not block:
                break
            copied += len(block)
            if copied > MAX_ARCHIVE_BYTES:
                fail(f"{label} archive exceeds the custody bound")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    fail(f"short write while copying {label} archive")
                view = view[written:]
        os.fsync(destination_fd)
        finished = os.fstat(source_fd)
    finally:
        os.close(destination_fd)
        os.close(source_fd)
    after = source.lstat()
    if not (identity(before) == identity(opened) == identity(finished) == identity(after)):
        fail(f"{label} archive changed during authenticated copy")
    if digest.hexdigest() != expected:
        fail(f"{label} archive SHA-256 mismatch")
    _, copied_digest = stable_file_digest(destination)
    if copied_digest != expected:
        fail(f"private {label} archive copy SHA-256 mismatch")
    destination.chmod(0o400)


def normalized_member_name(name: str, *, directory: bool) -> str:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        fail("archive member has an unsafe name")
    raw = name[:-1] if directory and name.endswith("/") else name
    if not raw or raw.startswith("/"):
        fail(f"archive member path is unsafe: {name!r}")
    if len(raw.encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES:
        fail("archive member path exceeds the custody bound")
    parts = raw.split("/")
    if len(parts) > MAX_PATH_DEPTH or any(part in {"", ".", ".."} for part in parts):
        fail(f"archive member path is unsafe: {name!r}")
    normalized = PurePosixPath(*parts).as_posix()
    if normalized != raw:
        fail(f"archive member path is not canonical: {name!r}")
    return normalized


def validate_name_set(entries: list[dict], expected_root: str) -> None:
    exact = set()
    folded = {}
    kinds = {}
    for entry in entries:
        name = entry["name"]
        if name in exact:
            fail(f"duplicate archive member rejected: {name}")
        exact.add(name)
        folded_name = unicodedata.normalize("NFC", name).casefold()
        prior = folded.get(folded_name)
        if prior is not None and prior != name:
            fail(f"case or Unicode-colliding archive members rejected: {prior}, {name}")
        folded[folded_name] = name
        kinds[name] = entry["kind"]
        if name.split("/", 1)[0] != expected_root:
            fail(f"archive member escapes its exact top-level root: {name}")
    for entry in entries:
        parts = entry["name"].split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if kinds.get(parent) in {"file", "symlink"}:
                fail(f"archive member is nested below a non-directory: {entry['name']}")


def safe_link_target(name: str, target: str) -> None:
    if not target or "\x00" in target or "\\" in target or target.startswith("/"):
        fail(f"archive symlink target is unsafe: {name}")
    if len(target.encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES:
        fail(f"archive symlink target exceeds the custody bound: {name}")
    if len(target.split("/")) > MAX_PATH_DEPTH:
        fail(f"archive symlink target depth exceeds the custody bound: {name}")
    target_parts = name.split("/")[:-1] + target.split("/")
    resolved = []
    for part in target_parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not resolved:
                fail(f"archive symlink escapes its root: {name}")
            resolved.pop()
        else:
            resolved.append(part)
    expected_root = name.split("/", 1)[0]
    if not resolved or resolved[0] != expected_root:
        fail(f"archive symlink escapes its root: {name}")


def validate_extracted_symlinks(destination: Path, entries: list[dict]) -> None:
    root = destination.resolve(strict=True)
    for entry in entries:
        if entry["kind"] != "symlink":
            continue
        link = destination / entry["name"]
        try:
            resolved = link.resolve(strict=True)
            resolved.relative_to(root)
        except (FileNotFoundError, RuntimeError, ValueError):
            fail(f"extracted symlink is broken, cyclic, or escaping: {entry['name']}")


def ensure_bounds(entries: list[dict], compressed_bytes: int) -> None:
    if not entries or len(entries) > MAX_MEMBER_COUNT:
        fail("archive member count is outside the custody bound")
    total = 0
    for entry in entries:
        size = entry.get("size", 0)
        if not isinstance(size, int) or size < 0 or size > MAX_MEMBER_BYTES:
            fail(f"archive member size is outside the custody bound: {entry['name']}")
        total += size
        if total > MAX_EXPANDED_BYTES:
            fail("archive cumulative expansion exceeds the custody bound")
        compressed = entry.get("compressed", size)
        if entry["kind"] == "file" and size > 0:
            if compressed <= 0 or size > max(compressed, 1) * MAX_COMPRESSION_RATIO:
                fail(f"archive member compression ratio exceeds the custody bound: {entry['name']}")
    if total > max(compressed_bytes, 1) * MAX_COMPRESSION_RATIO:
        fail("archive cumulative compression ratio exceeds the custody bound")


def create_parent(path: Path, root: Path) -> None:
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists():
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                fail(f"extraction parent is not a real directory: {current}")
        else:
            current.mkdir(mode=0o700)


def write_stream(stream, destination: Path, expected_size: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    total = 0
    try:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            total += len(block)
            if total > expected_size or total > MAX_MEMBER_BYTES:
                fail(f"archive member expanded beyond metadata: {destination.name}")
            view = memoryview(block)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    fail("short archive member write")
                view = view[written:]
        if total != expected_size:
            fail(f"archive member size did not match metadata: {destination.name}")
    finally:
        os.close(fd)


def normalize_modes(root: Path, *, flutter_tree: bool = False) -> None:
    directories = []
    for base_text, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(base_text)
        directories.append(base)
        dirnames.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        for filename in filenames:
            path = base / filename
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail(f"extracted tree contains an unsupported or hardlinked file: {path}")
            relative = path.relative_to(root).as_posix()
            if flutter_tree and relative == "bin/cache/lockfile":
                path.chmod(0o600)
            else:
                path.chmod(0o500 if mode_was_executable(info.st_mode) else 0o400)
    for directory in reversed(directories):
        if directory != root and directory.is_symlink():
            fail(f"extracted tree contains a symlink directory: {directory}")
        directory.chmod(0o500)


def verify_canonical_zip_container(
    archive: Path, bundle: zipfile.ZipFile, entries: list[dict]
) -> None:
    ordered = sorted(entries, key=lambda entry: entry["item"].header_offset)
    if not ordered or ordered[0]["item"].header_offset != 0:
        fail("ZIP archive contains a noncanonical prefix")
    with archive.open("rb") as stream:
        for index, entry in enumerate(ordered):
            item = entry["item"]
            stream.seek(item.header_offset)
            header = stream.read(30)
            if len(header) != 30 or header[:4] != b"PK\x03\x04":
                fail(f"invalid ZIP local header: {entry['name']}")
            filename_size, extra_size = struct.unpack_from("<HH", header, 26)
            member_end = (
                item.header_offset
                + 30
                + filename_size
                + extra_size
                + item.compress_size
            )
            next_offset = (
                ordered[index + 1]["item"].header_offset
                if index + 1 < len(ordered)
                else bundle.start_dir
            )
            if member_end != next_offset:
                fail("ZIP archive contains an unexplained interior gap")
        size = archive.stat().st_size
        tail_size = min(size, 22 + 65_535)
        stream.seek(size - tail_size)
        tail = stream.read(tail_size)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(tail):
        fail("ZIP end-of-central-directory record is absent")
    values = struct.unpack_from("<4s4H2LH", tail, eocd)
    _, disk, central_disk, disk_entries, total_entries, central_size, central_offset, comment_size = values
    eocd_offset = size - tail_size + eocd
    if (
        disk != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries != len(entries)
        or central_offset != bundle.start_dir
        or central_offset + central_size != eocd_offset
        or eocd_offset + 22 + comment_size != size
    ):
        fail("ZIP central directory or trailer is noncanonical")


def verify_single_gzip_container(archive: Path) -> None:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    expanded = 0
    with archive.open("rb") as stream:
        while True:
            block = stream.read(CHUNK)
            if not block:
                break
            output = decoder.decompress(block)
            expanded += len(output)
            if expanded > MAX_EXPANDED_BYTES:
                fail("gzip TAR cumulative expansion exceeds the custody bound")
            if decoder.eof:
                if decoder.unused_data or stream.read(1):
                    fail("gzip TAR contains trailing or concatenated container bytes")
                break
    if not decoder.eof:
        fail("gzip TAR container is truncated")


def extract_zip(
    archive: Path,
    destination: Path,
    expected_root: str,
    *,
    allow_symlinks: bool = True,
) -> None:
    entries = []
    with zipfile.ZipFile(archive) as bundle:
        for item in bundle.infolist():
            if len(entries) >= MAX_MEMBER_COUNT:
                fail("ZIP member count exceeds the custody bound")
            if item.flag_bits & 0x1:
                fail("encrypted ZIP member rejected")
            if item.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                fail("unsupported ZIP compression method rejected")
            unix_mode = (item.external_attr >> 16) & 0xFFFF
            is_directory = item.is_dir() or stat.S_ISDIR(unix_mode)
            name = normalized_member_name(item.filename, directory=is_directory)
            if is_directory:
                kind = "dir"
            elif stat.S_ISLNK(unix_mode):
                if not allow_symlinks:
                    fail(f"archive symlink rejected: {name}")
                kind = "symlink"
            elif unix_mode == 0 or stat.S_ISREG(unix_mode):
                kind = "file"
            else:
                fail(f"unsupported ZIP member type rejected: {name}")
            entry = {
                "name": name,
                "kind": kind,
                "size": item.file_size,
                "compressed": item.compress_size,
                "mode": unix_mode,
                "item": item,
            }
            if kind == "dir" and item.file_size != 0:
                fail(f"ZIP directory carries unexpected data: {name}")
            if kind == "symlink":
                if item.file_size > MAX_PATH_BYTES:
                    fail(f"ZIP symlink target exceeds the custody bound: {name}")
                with bundle.open(item) as stream:
                    try:
                        entry["target"] = stream.read(MAX_PATH_BYTES + 1).decode("utf-8")
                    except UnicodeDecodeError:
                        fail(f"ZIP symlink target is not UTF-8: {name}")
            entries.append(entry)
        validate_name_set(entries, expected_root)
        ensure_bounds(entries, archive.stat().st_size)
        verify_canonical_zip_container(archive, bundle, entries)
        for entry in entries:
            if entry["kind"] == "symlink":
                safe_link_target(entry["name"], entry["target"])

        destination.mkdir(mode=0o700)
        for entry in entries:
            if entry["kind"] == "dir":
                create_parent(destination / entry["name"], destination)
        for entry in entries:
            if entry["kind"] != "file":
                continue
            target = destination / entry["name"]
            create_parent(target.parent, destination)
            with bundle.open(entry["item"]) as stream:
                write_stream(stream, target, entry["size"])
            target.chmod(0o700 if entry["mode"] & 0o111 else 0o600)
        for entry in entries:
            if entry["kind"] != "symlink":
                continue
            target = destination / entry["name"]
            create_parent(target.parent, destination)
            os.symlink(entry["target"], target)
        validate_extracted_symlinks(destination, entries)


def extract_tar(archive: Path, destination: Path, expected_root: str) -> None:
    entries = []
    verify_single_gzip_container(archive)
    with tarfile.open(archive, mode="r:gz") as bundle:
        for item in bundle:
            if len(entries) >= MAX_MEMBER_COUNT:
                fail("TAR member count exceeds the custody bound")
            if item.isdir():
                kind = "dir"
            elif item.isfile():
                kind = "file"
            elif item.issym():
                kind = "symlink"
            elif item.islnk():
                fail(f"TAR hardlink rejected: {item.name}")
            else:
                fail(f"unsupported TAR member type rejected: {item.name}")
            if getattr(item, "sparse", None):
                fail(f"sparse TAR member rejected: {item.name}")
            name = normalized_member_name(item.name, directory=kind == "dir")
            entry = {
                "name": name,
                "kind": kind,
                "size": item.size,
                "compressed": item.size,
                "mode": item.mode,
                "item": item,
            }
            if kind in {"dir", "symlink"} and item.size != 0:
                fail(f"TAR metadata member carries unexpected data: {name}")
            if kind == "symlink":
                entry["target"] = item.linkname
            entries.append(entry)
        validate_name_set(entries, expected_root)
        ensure_bounds(entries, archive.stat().st_size)
        for entry in entries:
            if entry["kind"] == "symlink":
                safe_link_target(entry["name"], entry["target"])

        destination.mkdir(mode=0o700)
        for entry in entries:
            if entry["kind"] == "dir":
                create_parent(destination / entry["name"], destination)
        for entry in entries:
            if entry["kind"] != "file":
                continue
            target = destination / entry["name"]
            create_parent(target.parent, destination)
            stream = bundle.extractfile(entry["item"])
            if stream is None:
                fail(f"TAR member cannot be read: {entry['name']}")
            with stream:
                write_stream(stream, target, entry["size"])
            target.chmod(0o700 if entry["mode"] & 0o111 else 0o600)
        for entry in entries:
            if entry["kind"] != "symlink":
                continue
            target = destination / entry["name"]
            create_parent(target.parent, destination)
            os.symlink(entry["target"], target)
        validate_extracted_symlinks(destination, entries)


def stable_file_digest(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        before = os.fstat(fd)
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if identity(before) != identity(after):
            fail(f"tree file changed while it was hashed: {path}")
        size = before.st_size
        digest_hex = digest.hexdigest()
    finally:
        os.close(fd)
    return size, digest_hex


def tree_hash(root: Path, *, require_frozen: bool, flutter_tree: bool = False) -> str:
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        fail("toolchain root must be one real directory")
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o500:
        fail("toolchain root has unsafe ownership or mode")
    digest = hashlib.sha256()

    def feed(*parts) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != os.getuid() or mode & 0o022:
                fail(f"toolchain entry has unsafe ownership or mode: {relative}")
            if stat.S_ISDIR(info.st_mode):
                if require_frozen and mode != 0o500:
                    fail(f"toolchain directory is not frozen: {relative}")
                feed("D", relative, mode)
                walk(path)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                if os.path.isabs(target):
                    fail(f"toolchain symlink target is absolute: {relative}")
                resolved = (path.parent / target).resolve(strict=True)
                try:
                    resolved.relative_to(root)
                except ValueError:
                    fail(f"toolchain symlink escapes its root: {relative}")
                feed("L", relative, target)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    fail(f"toolchain hardlink rejected: {relative}")
                expected_modes = {0o400, 0o500}
                if flutter_tree and relative == "bin/cache/lockfile":
                    expected_modes = {0o600}
                if require_frozen and mode not in expected_modes:
                    fail(f"toolchain file is not frozen: {relative}")
                size, content = stable_file_digest(path)
                feed("F", relative, mode, size, content)
            else:
                fail(f"unsupported toolchain tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def copy_directory_tree(source: Path, destination: Path) -> None:
    source_info = source.lstat()
    if not stat.S_ISDIR(source_info.st_mode) or stat.S_ISLNK(source_info.st_mode):
        fail("pub-cache copy source must be one real directory")
    destination.mkdir(mode=0o700)
    with os.scandir(source) as scan:
        entries = list(scan)
    for entry in entries:
        src = Path(entry.path)
        dst = destination / entry.name
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode):
            fail(f"pub-cache copy rejected a symlink: {src}")
        if stat.S_ISDIR(info.st_mode):
            copy_directory_tree(src, dst)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                fail(f"pub-cache copy rejected a hardlink: {src}")
            source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            destination_flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            )
            source_fd = os.open(src, source_flags)
            destination_fd = os.open(dst, destination_flags, 0o600)
            try:
                while True:
                    block = os.read(source_fd, CHUNK)
                    if not block:
                        break
                    view = memoryview(block)
                    while view:
                        written = os.write(destination_fd, view)
                        if written <= 0:
                            fail("short write while copying pub-cache payload")
                        view = view[written:]
            finally:
                os.close(destination_fd)
                os.close(source_fd)
            dst.chmod(0o700 if mode_was_executable(info.st_mode) else 0o600)
        else:
            fail(f"pub-cache copy rejected a special file: {src}")


def remove_ephemeral_tree(path: Path, label: str) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        fail(f"{label} must not be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a real directory")
    if info.st_uid != os.getuid():
        fail(f"{label} has an untrusted owner")
    for base_text, dirnames, filenames in os.walk(path, topdown=False, followlinks=False):
        base = Path(base_text)
        base.chmod(0o700)
        dirnames.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        for filename in filenames:
            child = base / filename
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode):
                fail(f"{label} contains a symlink")
            if not stat.S_ISREG(child_info.st_mode) or child_info.st_nlink != 1:
                fail(f"{label} contains a link or special file")
            if child_info.st_uid != os.getuid():
                fail(f"{label} has an untrusted owner")
            child.chmod(0o600)
            child.unlink()
        for dirname in dirnames:
            child = base / dirname
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode):
                fail(f"{label} contains a symlink")
            if not stat.S_ISDIR(child_info.st_mode):
                fail(f"{label} contains a special file")
            if child_info.st_uid != os.getuid():
                fail(f"{label} has an untrusted owner")
            child.chmod(0o700)
            child.rmdir()
    path.chmod(0o700)
    path.rmdir()


def make_hosted_hashes_writable(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("pub-cache hosted-hashes must be one real directory")
    if info.st_uid != os.getuid():
        fail("pub-cache hosted-hashes has an untrusted owner")
    path.chmod(0o700)
    for base_text, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        base = Path(base_text)
        dirnames.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        for dirname in list(dirnames):
            child = base / dirname
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(child_info.st_mode):
                fail("pub-cache hosted-hashes contains an unsafe directory")
            if child_info.st_uid != os.getuid():
                fail("pub-cache hosted-hashes has an untrusted owner")
            child.chmod(0o700)
        for filename in filenames:
            child = base / filename
            child_info = child.lstat()
            if (
                stat.S_ISLNK(child_info.st_mode)
                or not stat.S_ISREG(child_info.st_mode)
                or child_info.st_nlink != 1
            ):
                fail("pub-cache hosted-hashes contains a link or special file")
            if child_info.st_uid != os.getuid():
                fail("pub-cache hosted-hashes has an untrusted owner")
            child.chmod(0o600)


def restore_hosted_hashes(destination_root: Path, golden_root: Path) -> None:
    dest = destination_root / "hosted-hashes"
    src = golden_root / "hosted-hashes"
    src_info = src.lstat()
    if stat.S_ISLNK(src_info.st_mode) or not stat.S_ISDIR(src_info.st_mode):
        fail("authenticated hosted-hashes snapshot must be one real directory")
    try:
        dest.lstat()
    except FileNotFoundError:
        pass
    else:
        remove_ephemeral_tree(dest, "pub-cache hosted-hashes")
    copy_directory_tree(src, dest)
    normalize_modes(dest)


def golden_pub_cache_root(runtime_path: Path) -> Path:
    golden = runtime_path / "extracted" / "pub-cache-archive" / PUB_CACHE_ROOT_NAME
    try:
        golden.resolve(strict=True).relative_to(runtime_path.resolve(strict=True))
    except ValueError:
        fail("authenticated pub-cache snapshot escaped the private runtime")
    info = golden.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("authenticated pub-cache snapshot must be one real directory")
    return golden


def sanitize_pub_cache_runtime(
    runtime_pub: Path, golden_root: Path, expected_sha: str
) -> None:
    golden_sha = pub_cache_payload_hash(
        golden_root, require_frozen=True, permit_active_roots=False
    )
    if golden_sha != expected_sha:
        fail("authenticated pub-cache snapshot changed")
    runtime_pub = runtime_pub.resolve(strict=True)
    info = runtime_pub.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("pub-cache root must be one real directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        fail("pub-cache root has unsafe ownership or mode")
    with os.scandir(runtime_pub) as scan:
        entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
    allowed = set(PUB_CACHE_PAYLOAD_DIRS)
    allowed.add(PUB_CACHE_METADATA_NAME)
    allowed.add(PUB_CACHE_TEMP_NAME)
    for entry in entries:
        if entry.name not in allowed:
            fail(f"pub-cache contains unsupported metadata: {entry.name}")
        entry_info = entry.stat(follow_symlinks=False)
        if entry.name == PUB_CACHE_TEMP_NAME:
            if stat.S_ISLNK(entry_info.st_mode) or not stat.S_ISDIR(entry_info.st_mode):
                fail("pub-cache _temp must be one real directory")
            remove_ephemeral_tree(Path(entry.path), "pub-cache _temp")
    hosted = runtime_pub / "hosted"
    hosted_info = hosted.lstat()
    if stat.S_ISLNK(hosted_info.st_mode) or not stat.S_ISDIR(hosted_info.st_mode):
        fail("pub-cache hosted must be one real directory")
    restore_hosted_hashes(runtime_pub, golden_root)
    observed = pub_cache_payload_hash(
        runtime_pub, require_frozen=True, permit_active_roots=True
    )
    if observed != expected_sha:
        fail("private pub-cache payload changed")
    make_hosted_hashes_writable(runtime_pub / "hosted-hashes")


def flutter_tools_root(flutter_root: Path) -> Path | None:
    tools = flutter_root / FLUTTER_TOOLS_REL
    try:
        info = tools.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("Flutter tools directory must be one real directory")
    if info.st_uid != os.getuid():
        fail("Flutter tools directory has an untrusted owner")
    try:
        tools.resolve(strict=True).relative_to(flutter_root.resolve(strict=True))
    except ValueError:
        fail("Flutter tools directory escaped the Flutter tree")
    return tools


def remove_flutter_tools_pub_stamp(flutter_root: Path) -> None:
    tools = flutter_tools_root(flutter_root)
    if tools is None:
        return
    dart_tool = tools / ".dart_tool"
    try:
        info = dart_tool.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        fail("Flutter tools .dart_tool must not be a symlink")
    if not stat.S_ISDIR(info.st_mode):
        fail("Flutter tools .dart_tool must be one real directory")
    if info.st_uid != os.getuid():
        fail("Flutter tools .dart_tool has an untrusted owner")
    with os.scandir(dart_tool) as scan:
        entries = list(scan)
    for entry in entries:
        if entry.name != "package_config.json":
            fail(f"Flutter tools .dart_tool contains unsupported metadata: {entry.name}")
        entry_info = entry.stat(follow_symlinks=False)
        if (
            stat.S_ISLNK(entry_info.st_mode)
            or not stat.S_ISREG(entry_info.st_mode)
            or entry_info.st_nlink != 1
            or entry_info.st_uid != os.getuid()
        ):
            fail("Flutter tools package_config must be one regular file")
    tools.chmod(0o700)
    remove_ephemeral_tree(dart_tool, "Flutter tools .dart_tool")
    tools.chmod(0o500)


def install_flutter_tools_pub_stamp(flutter_root: Path) -> None:
    tools = flutter_tools_root(flutter_root)
    if tools is None:
        return
    remove_flutter_tools_pub_stamp(flutter_root)
    info = tools.lstat()
    if stat.S_IMODE(info.st_mode) != 0o500:
        fail("Flutter tools directory is not frozen")
    tools.chmod(0o700)
    dart_tool = tools / ".dart_tool"
    dart_tool.mkdir(mode=0o700)
    destination = dart_tool / "package_config.json"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.open(destination, flags, 0o400)
    try:
        payload = FLUTTER_TOOLS_PACKAGE_CONFIG.encode("ascii")
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short Flutter tools package_config write")
            view = view[written:]
    finally:
        os.close(fd)
    destination.chmod(0o400)
    dart_tool.chmod(0o500)
    tools.chmod(0o500)


def validate_active_roots(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("pub-cache active_roots must be one real directory")
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
        fail("pub-cache active_roots has unsafe ownership or mode")
    for base_text, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        base = Path(base_text)
        dirnames.sort(key=os.fsencode)
        filenames.sort(key=os.fsencode)
        for dirname in list(dirnames):
            child = base / dirname
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode) or not stat.S_ISDIR(child_info.st_mode):
                fail("pub-cache active_roots contains an unsafe directory")
            if child_info.st_uid != os.getuid() or stat.S_IMODE(child_info.st_mode) & 0o022:
                fail("pub-cache active_roots has unsafe ownership or mode")
        for filename in filenames:
            child = base / filename
            child_info = child.lstat()
            if (
                stat.S_ISLNK(child_info.st_mode)
                or not stat.S_ISREG(child_info.st_mode)
                or child_info.st_nlink != 1
            ):
                fail("pub-cache active_roots contains a link or special file")
            if child_info.st_uid != os.getuid() or stat.S_IMODE(child_info.st_mode) & 0o022:
                fail("pub-cache active_roots has unsafe ownership or mode")


def pub_cache_payload_hash(
    root: Path, *, require_frozen: bool, permit_active_roots: bool
) -> str:
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        fail("pub-cache root must be one real directory")
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) & 0o022:
        fail("pub-cache root has unsafe ownership or mode")
    digest = hashlib.sha256()

    def feed(*parts) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid != os.getuid() or mode & 0o022:
                fail(f"pub-cache payload has unsafe ownership or mode: {relative}")
            if stat.S_ISDIR(info.st_mode):
                if require_frozen and mode != 0o500:
                    fail(f"pub-cache payload directory is not frozen: {relative}")
                feed("D", relative, mode)
                walk(path)
            elif stat.S_ISLNK(info.st_mode):
                fail(f"pub-cache payload symlink rejected: {relative}")
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    fail(f"pub-cache payload hardlink rejected: {relative}")
                if require_frozen and mode not in {0o400, 0o500}:
                    fail(f"pub-cache payload file is not frozen: {relative}")
                size, content = stable_file_digest(path)
                feed("F", relative, mode, size, content)
            else:
                fail(f"unsupported pub-cache payload entry: {relative}")

    with os.scandir(root) as scan:
        entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
    seen = [entry.name for entry in entries]
    allowed = set(PUB_CACHE_PAYLOAD_DIRS)
    if permit_active_roots:
        allowed.add(PUB_CACHE_METADATA_NAME)
    for name in seen:
        if name not in allowed:
            fail(f"pub-cache contains unsupported metadata: {name}")
    for required in PUB_CACHE_PAYLOAD_DIRS:
        if required not in seen:
            fail(f"pub-cache payload directory missing: {required}")
    for entry in entries:
        if entry.name == PUB_CACHE_METADATA_NAME:
            validate_active_roots(Path(entry.path))
            continue
        path = Path(entry.path)
        info = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"pub-cache payload must be a directory: {entry.name}")
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid != os.getuid() or mode & 0o022:
            fail(f"pub-cache payload has unsafe ownership or mode: {entry.name}")
        if require_frozen and mode != 0o500:
            fail(f"pub-cache payload directory is not frozen: {entry.name}")
        feed("D", entry.name, mode)
        walk(path)
    return digest.hexdigest()


def install_pub_cache_runtime(extracted_root: Path, runtime: Path, expected_sha: str) -> tuple[Path, str]:
    hosted = extracted_root / "hosted"
    hosted_hashes = extracted_root / "hosted-hashes"
    if (
        not hosted.is_dir()
        or hosted.is_symlink()
        or not hosted_hashes.is_dir()
        or hosted_hashes.is_symlink()
    ):
        fail("pub-cache archive lacks exact hosted/ and hosted-hashes/ payload directories")
    normalize_modes(hosted)
    normalize_modes(hosted_hashes)
    observed = pub_cache_payload_hash(
        extracted_root, require_frozen=True, permit_active_roots=False
    )
    if observed != expected_sha:
        fail(
            "archive-derived tree SHA-256 mismatch: "
            f"Flutter pub-cache observed={observed} expected={expected_sha}"
        )
    destination = runtime / "pub-cache"
    destination.mkdir(mode=0o700)
    copy_directory_tree(hosted, destination / "hosted")
    copy_directory_tree(hosted_hashes, destination / "hosted-hashes")
    normalize_modes(destination / "hosted")
    normalize_modes(destination / "hosted-hashes")
    (destination / PUB_CACHE_METADATA_NAME).mkdir(mode=0o700)
    copied = pub_cache_payload_hash(
        destination, require_frozen=True, permit_active_roots=True
    )
    if copied != observed:
        fail("private pub-cache payload changed during copy")
    make_hosted_hashes_writable(destination / "hosted-hashes")
    return destination, observed


def _macho_architectures_from_header(header: bytes) -> set[str]:
    if len(header) < 8:
        fail("executable is too small to be Mach-O")
    magic = header[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu_type = struct.unpack_from("<I", header, 4)[0]
        return {"arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}"}
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64 = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", header, 4)[0]
        entry_size = 32 if is_64 else 20
        if count == 0 or count > 32 or 8 + count * entry_size > len(header):
            fail("universal Mach-O header is malformed")
        result = set()
        for index in range(count):
            cpu_type = struct.unpack_from(">I", header, 8 + index * entry_size)[0]
            result.add("arm64" if cpu_type == ARM64_CPU_TYPE else f"cpu-{cpu_type}")
        return result
    fail("executable is not a supported Mach-O binary")


def require_direct_executable(path: Path, label: str) -> None:
    fd = os.open(path, _open_flags())
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail(f"{label} must be a direct single-link regular file")
        if not mode_was_executable(opened.st_mode):
            fail(f"{label} is not executable")
        header = os.read(fd, 4096)
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            fail(f"{label} changed while Mach-O identity was read")
    finally:
        os.close(fd)
    if _macho_architectures_from_header(header) != {"arm64"}:
        fail(f"{label} must be an exact arm64 Mach-O executable")


def mode_was_executable(mode: int) -> bool:
    return bool(stat.S_IMODE(mode) & 0o111)


def validate_flutter_static(root: Path) -> None:
    flutter = root / "bin" / "flutter"
    dart = root / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
    snapshot = root / "bin" / "cache" / "flutter_tools.snapshot"
    lockfile = root / "bin" / "cache" / "lockfile"
    flutter_info = flutter.lstat()
    if not stat.S_ISREG(flutter_info.st_mode) or stat.S_ISLNK(flutter_info.st_mode) or flutter_info.st_nlink != 1:
        fail("Flutter launcher must be a direct single-link regular file")
    if not mode_was_executable(flutter_info.st_mode):
        fail("Flutter launcher is not executable")
    require_direct_executable(dart, "Flutter Dart runtime")
    for path, label in ((snapshot, "Flutter tool snapshot"), (lockfile, "Flutter lockfile")):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_nlink != 1:
            fail(f"{label} must be a direct single-link regular file")


def parse_release_file(path: Path) -> dict[str, str]:
    raw = bind_regular_file(path, max_size=256 * 1024, label="JDK release metadata")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("JDK release metadata is not UTF-8")
    result = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or len(value) < 2 or value[0] != '"' or value[-1] != '"':
            fail("JDK release metadata contains a malformed field")
        if key in result:
            fail(f"duplicate JDK release metadata field: {key}")
        result[key] = value[1:-1]
    return result


def validate_java_static(java_home: Path) -> None:
    for name in ("java", "keytool", "jarsigner"):
        path = java_home / "bin" / name
        require_direct_executable(path, f"JDK {name}")
    release = parse_release_file(java_home / "release")
    expected = {
        "IMPLEMENTOR": JAVA_VENDOR,
        "JAVA_VERSION": JAVA_VERSION,
        "JAVA_RUNTIME_VERSION": "17.0.20.1+1",
        "OS_ARCH": "aarch64",
        "JVM_VARIANT": "Hotspot",
        "IMAGE_TYPE": "JDK",
    }
    for key, value in expected.items():
        if release.get(key) != value:
            fail(f"JDK release metadata {key} mismatch")


def runtime_id_from_info(info: os.stat_result) -> str:
    return ":".join(
        str(value)
        for value in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            format(stat.S_IMODE(info.st_mode), "o"),
        )
    )


def root_identity_from_stat(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
    )


def root_identity(path: Path) -> tuple[int, ...]:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("toolchain root must be one real directory")
    return root_identity_from_stat(info)


def encode_root_identity(path: Path) -> str:
    return ":".join(str(part) for part in root_identity(path))


def decode_root_identity(value: str) -> tuple[int, ...]:
    parts = value.split(":")
    if len(parts) != 6:
        fail("toolchain root identity is malformed")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        fail("toolchain root identity is malformed")


def _destroy_clone_tree(tree: Path) -> None:
    if _is_foreign_protected_path(tree):
        fail("refusing cleanup of an owner-provisioned or foreign sealed toolchain")
    allowed_clone = (
        tree.name in {"flutter", "java"}
        and tree.parent.name == "exec"
        and tree.parent.parent.name.startswith(RUNTIME_PREFIX)
        and tree.parent.parent.parent == PRIVATE_TMP
    )
    if not allowed_clone:
        fail("refusing cleanup of a foreign clone path")
    if not (tree.exists() or tree.is_symlink()):
        return
    info = tree.lstat()
    if stat.S_ISLNK(info.st_mode):
        tree.unlink()
        return
    if not stat.S_ISDIR(info.st_mode):
        fail("execution clone slot is not a disposable tree")
    for base, directories, files in os.walk(tree, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            try:
                if not path.is_symlink():
                    os.chflags(path, 0)
            except OSError:
                pass
            try:
                if not path.is_symlink():
                    os.chmod(path, 0o700 if path.is_dir() else 0o600)
            except OSError:
                pass
        try:
            if not base_path.is_symlink():
                os.chflags(base_path, 0)
                os.chmod(base_path, 0o700)
        except OSError:
            pass
    shutil.rmtree(tree, ignore_errors=True)


def _flutter_tools_dart_tool_relative() -> str:
    return (FLUTTER_TOOLS_REL / ".dart_tool").as_posix()


def _skip_sealed_relative(relative: str) -> bool:
    dart_tool = _flutter_tools_dart_tool_relative()
    return relative == dart_tool or relative.startswith(dart_tool + "/")


def _canonical_pin_mode(relative: str, info: os.stat_result, *, flutter_tree: bool) -> int:
    if stat.S_ISDIR(info.st_mode):
        return 0o500
    if flutter_tree and relative == "bin/cache/lockfile":
        return 0o600
    if stat.S_IMODE(info.st_mode) & 0o111:
        return 0o500
    return 0o400


def _sealed_entry_mode_ok(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        return mode == 0o555
    if not stat.S_ISREG(info.st_mode):
        return False
    return mode in {0o444, 0o555}


def _require_sf_immutable(info: os.stat_result, label: str) -> None:
    flags = int(getattr(info, "st_flags", 0))
    if flags & UF_IMMUTABLE and not (flags & SF_IMMUTABLE):
        fail(f"UF_IMMUTABLE is insufficient: {label}")
    if not (flags & SF_IMMUTABLE):
        fail(f"SF_IMMUTABLE is required: {label}")


def _same_user_cannot_replace(path: Path) -> bool:
    """UF_IMMUTABLE is insufficient: the owner can clear it and replace the path."""
    try:
        info = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return False
    if info.st_uid == os.getuid():
        return False
    flags = int(getattr(info, "st_flags", 0))
    if flags & UF_IMMUTABLE and not (flags & SF_IMMUTABLE):
        return False
    if sys.platform == "darwin":
        try:
            os.chflags(path, 0)
        except OSError:
            pass
        else:
            return False
    try:
        os.chmod(path, 0o700 if stat.S_ISDIR(info.st_mode) else 0o600)
    except OSError:
        pass
    else:
        return False
    if stat.S_ISREG(info.st_mode):
        try:
            fd = os.open(path, os.O_WRONLY | _cloexec_flag() | _nofollow_flag())
        except OSError:
            pass
        else:
            os.close(fd)
            return False
        try:
            os.unlink(path)
        except OSError:
            pass
        else:
            return False
    else:
        try:
            os.rmdir(path)
        except OSError:
            pass
        else:
            return False
    return True


def live_darwin_uf_vs_sf_probe(path: Path) -> tuple[bool, int | None]:
    """Return (UF_IMMUTABLE owner-clearable, SF_IMMUTABLE errno or None)."""
    os.chflags(path, UF_IMMUTABLE)
    os.chflags(path, 0)
    sf_errno: int | None = None
    try:
        os.chflags(path, SF_IMMUTABLE)
    except OSError as suc:
        sf_errno = suc.errno
    return True, sf_errno


def _require_owner_parent_chain(root: Path) -> None:
    reject_symlink_components(root, "owner-sealed toolchain")
    current = Path(root.anchor)
    for part in root.parts[1:]:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"{EXECUTION_BLOCKER}: owner-sealed ancestor is not a real directory: {current}")
        if info.st_uid != 0:
            fail(f"{EXECUTION_BLOCKER}: owner-sealed path is not root-owned: {current}")
        if stat.S_IMODE(info.st_mode) & 0o022:
            fail(f"{EXECUTION_BLOCKER}: owner-sealed path is group/world-writable: {current}")


def sealed_tree_hash(root: Path, *, flutter_tree: bool = False) -> str:
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        fail("toolchain root must be one real directory")
    if root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o555:
        fail("owner-sealed toolchain root has unsafe ownership or mode")
    digest = hashlib.sha256()

    def feed(*parts) -> None:
        for part in parts:
            value = str(part).encode("utf-8", "surrogateescape")
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)

    def walk(directory: Path) -> None:
        with os.scandir(directory) as scan:
            entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if _skip_sealed_relative(relative):
                continue
            info = entry.stat(follow_symlinks=False)
            if info.st_uid != 0:
                fail(f"owner-sealed toolchain entry has an untrusted owner: {relative}")
            if stat.S_ISDIR(info.st_mode):
                if not _sealed_entry_mode_ok(info):
                    fail(f"owner-sealed toolchain directory is not 0555: {relative}")
                feed("D", relative, _canonical_pin_mode(relative, info, flutter_tree=flutter_tree))
                walk(path)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                if os.path.isabs(target):
                    fail(f"toolchain symlink target is absolute: {relative}")
                resolved = (path.parent / target).resolve(strict=True)
                try:
                    resolved.relative_to(root)
                except ValueError:
                    fail(f"toolchain symlink escapes its root: {relative}")
                feed("L", relative, target)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    fail(f"toolchain hardlink rejected: {relative}")
                if not _sealed_entry_mode_ok(info):
                    fail(f"owner-sealed toolchain file is not 0444/0555: {relative}")
                size, content = stable_file_digest(path)
                feed(
                    "F",
                    relative,
                    _canonical_pin_mode(relative, info, flutter_tree=flutter_tree),
                    size,
                    content,
                )
            else:
                fail(f"unsupported toolchain tree entry: {relative}")

    walk(root)
    return digest.hexdigest()


def _kernel_seal_tree(root: Path, *, prove_unprivileged: bool = True) -> None:
    """Prove a root-owned sealed tree. Never set SF_IMMUTABLE unprivileged.

    Unprivileged chflags(SF_IMMUTABLE) fails with EPERM on /private/tmp.
    UF_IMMUTABLE is insufficient because the owner can clear it. Only a
    one-time root-owned 0555/0444 tree with SF_IMMUTABLE counts, and the
    proof is that the same user cannot clear the flag or replace a path.
    """
    if sys.platform != "darwin" or not SF_IMMUTABLE:
        fail(MACOS_BLOCKER)
    if prove_unprivileged:
        _refuse_root_execution()
    _require_owner_parent_chain(root)
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail(EXECUTION_BLOCKER)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o555:
        fail(EXECUTION_BLOCKER)
    _require_sf_immutable(info, str(root))
    if prove_unprivileged and not _same_user_cannot_replace(root):
        fail(EXECUTION_BLOCKER)
    probe = None
    for base, directories, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        relative_base = "" if base_path == root else base_path.relative_to(root).as_posix()
        if _skip_sealed_relative(relative_base):
            directories[:] = []
            continue
        for name in list(directories):
            path = base_path / name
            rel = path.relative_to(root).as_posix()
            if _skip_sealed_relative(rel):
                continue
            if path.is_symlink():
                continue
            entry = path.lstat()
            _require_sf_immutable(entry, rel)
            if not _sealed_entry_mode_ok(entry) or entry.st_uid != 0:
                fail(EXECUTION_BLOCKER)
            if prove_unprivileged and not _same_user_cannot_replace(path):
                fail(EXECUTION_BLOCKER)
        for name in files:
            path = base_path / name
            rel = path.relative_to(root).as_posix()
            if _skip_sealed_relative(rel) or path.is_symlink():
                continue
            entry = path.lstat()
            _require_sf_immutable(entry, rel)
            if not _sealed_entry_mode_ok(entry) or entry.st_uid != 0:
                fail(EXECUTION_BLOCKER)
            if prove_unprivileged and not _same_user_cannot_replace(path):
                fail(EXECUTION_BLOCKER)
            if probe is None and rel in {
                "bin/cache/dart-sdk/bin/dart",
                "bin/java",
            }:
                probe = path
    if probe is None:
        fail(EXECUTION_BLOCKER)
    if prove_unprivileged and not _same_user_cannot_replace(probe):
        fail(EXECUTION_BLOCKER)
    try:
        os.chflags(probe, 0)
    except OSError:
        pass
    else:
        fail(EXECUTION_BLOCKER)
    try:
        fd = os.open(probe, os.O_WRONLY | _cloexec_flag() | _nofollow_flag())
    except OSError:
        pass
    else:
        os.close(fd)
        fail(EXECUTION_BLOCKER)
    try:
        os.unlink(probe)
    except OSError:
        pass
    else:
        fail(EXECUTION_BLOCKER)


def clone_execution_tree(root: Path, slot: Path, expected: tuple[int, ...]) -> Path:
    if slot.exists() or slot.is_symlink():
        _destroy_clone_tree(slot)
        if slot.exists() or slot.is_symlink():
            fail("execution clone slot is not a disposable tree")
    parent = slot.parent
    parent.mkdir(mode=0o700, exist_ok=True)
    if sys.platform != "darwin" or _LIBC is None:
        fail(MACOS_BLOCKER)
    root_fd = os.open(
        root, os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag()
    )
    try:
        root_info = os.fstat(root_fd)
        if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
            fail("extracted root is not an owner-controlled directory")
        if root_identity_from_stat(root_info) != expected:
            fail("extracted root was replaced before it was cloned")
        dirfd = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
        )
        try:
            rc = _LIBC.fclonefileat(
                root_fd, dirfd, os.fsencode(slot.name), CLONE_NOFOLLOW
            )
            if rc != 0:
                fail(
                    "owner/environment blocker: macOS fclonefileat of the authenticated "
                    f"Android toolchain tree failed: {os.strerror(ctypes.get_errno())}"
                )
        finally:
            os.close(dirfd)
    finally:
        os.close(root_fd)
    return slot


class _CStringArray:
    def __init__(self, values: list[str]):
        encoded = [value.encode("utf-8") for value in values]
        array = (ctypes.c_char_p * (len(encoded) + 1))()
        for index, item in enumerate(encoded):
            array[index] = item
        array[len(encoded)] = None
        self._encoded = encoded
        self.array = array


def _posix_spawn(path: str, argv: list[str], env: dict[str, str]) -> int:
    if _LIBC is None:
        fail(MACOS_BLOCKER)
    attr = ctypes.c_void_p()
    actions = ctypes.c_void_p()
    _must(_LIBC.posix_spawnattr_init(ctypes.byref(attr)), "posix_spawnattr_init")
    try:
        _must(
            _LIBC.posix_spawnattr_setflags(
                ctypes.byref(attr),
                ctypes.c_short(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT),
            ),
            "posix_spawnattr_setflags",
        )
        _must(
            _LIBC.posix_spawn_file_actions_init(ctypes.byref(actions)),
            "posix_spawn_file_actions_init",
        )
        try:
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 0, 0),
                "posix_spawn stdin",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 1, 1),
                "posix_spawn stdout",
            )
            _must(
                _LIBC.posix_spawn_file_actions_adddup2(ctypes.byref(actions), 2, 2),
                "posix_spawn stderr",
            )
            pid = ctypes.c_int()
            argv_c = _CStringArray(argv)
            env_c = _CStringArray([f"{name}={value}" for name, value in env.items()])
            rc = _LIBC.posix_spawn(
                ctypes.byref(pid),
                os.fsencode(path),
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


def _wait_pid(pid: int, timeout: float) -> int:
    deadline = time.time() + timeout
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return os.waitstatus_to_exitcode(status)
        if time.time() >= deadline:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
            fail("Android toolchain execution timed out")
        time.sleep(0.02)


def cloned_environment(
    runtime: Path,
    flutter_root: Path,
    java_home: Path,
    extra: dict[str, str] | None = None,
    pub_cache: Path | None = None,
) -> dict[str, str]:
    env = {
        "HOME": str(runtime / "state" / "home"),
        "TMPDIR": str(runtime / "state" / "tmp"),
        "PATH": f"{flutter_root}/bin:{java_home}/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "CI": "true",
        "FLUTTER_ROOT": str(flutter_root),
        "FLUTTER_SUPPRESS_ANALYTICS": "true",
        "FLUTTER_ALREADY_LOCKED": "true",
        "JAVA_HOME": str(java_home),
    }
    if pub_cache is not None:
        env["PUB_CACHE"] = str(pub_cache)
    if extra:
        for key, value in extra.items():
            if key not in ALLOWED_RUN_ENV:
                fail(f"unapproved execution environment rejected: {key}")
            env[key] = value
    return env


def bind_owner_sealed_tree(
    root: Path,
    expected_sha: str,
    *,
    flutter_tree: bool,
    prove_unprivileged: bool = True,
) -> Path:
    if root != (OWNER_FLUTTER if flutter_tree else OWNER_JAVA):
        fail(EXECUTION_BLOCKER)
    if not (root.exists() or root.is_symlink()):
        _owner_unavailable(f"missing {root}")
    _kernel_seal_tree(root, prove_unprivileged=prove_unprivileged)
    observed = sealed_tree_hash(root, flutter_tree=flutter_tree)
    if observed != expected_sha:
        fail(
            f"owner-provisioned {'Flutter' if flutter_tree else 'Java'} tree does not "
            f"match the authenticated pin: observed={observed} expected={expected_sha}"
        )
    return root


def sealed_execution_trees(
    flutter_root: Path,
    java_home: Path,
    flutter_expected: tuple[int, ...],
    java_expected: tuple[int, ...],
    flutter_sha: str,
    java_sha: str,
) -> tuple[Path, Path]:
    _refuse_root_execution()
    if root_identity(flutter_root) != flutter_expected:
        fail("Flutter root identity changed after custody preparation")
    if root_identity(java_home) != java_expected:
        fail("Java Home identity changed after custody preparation")
    flutter = bind_owner_sealed_tree(OWNER_FLUTTER, flutter_sha, flutter_tree=True)
    java = bind_owner_sealed_tree(OWNER_JAVA, java_sha, flutter_tree=False)
    return flutter, java


def sealed_clones(
    runtime: Path,
    flutter_root: Path,
    java_home: Path,
    flutter_expected: tuple[int, ...],
    java_expected: tuple[int, ...],
    flutter_sha: str,
    java_sha: str,
) -> tuple[Path, Path]:
    del runtime
    return sealed_execution_trees(
        flutter_root,
        java_home,
        flutter_expected,
        java_expected,
        flutter_sha,
        java_sha,
    )


def spawn_cloned(
    executable: Path,
    argv: list[str],
    env: dict[str, str],
    timeout: float,
) -> int:
    fd = os.open(executable, _open_flags())
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            fail("cloned executable must be one regular non-hardlinked file")
    finally:
        os.close(fd)
    pid = _posix_spawn(str(executable), argv, env)
    return _wait_pid(pid, timeout)


def install_extracted_runtime(
    flutter_pin: dict,
    java_pin: dict,
    pub_pin: dict | None,
    *,
    manifest_path: str,
    manifest_sha: str,
) -> dict[str, str]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        fail("exact darwin_arm64 host required")
    runtime = Path(
        tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir=str(PRIVATE_TMP))
    )
    runtime.chmod(0o700)
    try:
        incoming = runtime / "incoming"
        extracted = runtime / "extracted"
        state = runtime / "state"
        exec_dir = runtime / "exec"
        for directory in (
            incoming,
            extracted,
            state,
            state / "home",
            state / "tmp",
            exec_dir,
        ):
            directory.mkdir(mode=0o700)
        flutter_archive = incoming / FLUTTER_ARCHIVE
        java_archive = incoming / JAVA_ARCHIVE
        copy_authenticated(
            flutter_pin["path"], flutter_pin["archive_sha"], flutter_archive, "Flutter"
        )
        copy_authenticated(
            java_pin["path"], java_pin["archive_sha"], java_archive, "Java"
        )
        pub_archive = None
        if pub_pin is not None:
            pub_archive = incoming / Path(pub_pin["path"]).name
            copy_authenticated(
                pub_pin["path"],
                pub_pin["archive_sha"],
                pub_archive,
                "Flutter pub-cache",
            )
        flutter_extract = extracted / "flutter-archive"
        java_extract = extracted / "java-archive"
        extract_zip(flutter_archive, flutter_extract, "flutter")
        extract_tar(java_archive, java_extract, JAVA_RELEASE)
        flutter_root = flutter_extract / "flutter"
        java_home = java_extract / JAVA_RELEASE / "Contents" / "Home"
        if not flutter_root.is_dir() or flutter_root.is_symlink():
            fail("Flutter archive lacks its exact flutter root")
        if not java_home.is_dir() or java_home.is_symlink():
            fail("Temurin archive lacks its exact Contents/Home root")
        pub_extracted_root = None
        if pub_pin is not None:
            pub_extract = extracted / "pub-cache-archive"
            extract_zip(
                pub_archive,
                pub_extract,
                pub_pin["top_level_root"],
                allow_symlinks=False,
            )
            pub_extracted_root = pub_extract / pub_pin["top_level_root"]
            if not pub_extracted_root.is_dir() or pub_extracted_root.is_symlink():
                fail("pub-cache archive lacks its exact pub-cache root")
        validate_flutter_static(flutter_root)
        validate_java_static(java_home)
        normalize_modes(flutter_root, flutter_tree=True)
        normalize_modes(java_home)
        observed_flutter = tree_hash(flutter_root, require_frozen=True, flutter_tree=True)
        observed_java = tree_hash(java_home, require_frozen=True)
        mismatches = []
        if observed_flutter != flutter_pin["tree_sha"]:
            mismatches.append(
                f"Flutter observed={observed_flutter} expected={flutter_pin['tree_sha']}"
            )
        if observed_java != java_pin["tree_sha"]:
            mismatches.append(
                f"Java observed={observed_java} expected={java_pin['tree_sha']}"
            )
        if mismatches:
            fail("archive-derived tree SHA-256 mismatch: " + "; ".join(mismatches))
        pub_cache_runtime = None
        observed_pub = None
        if pub_pin is not None:
            pub_cache_runtime, observed_pub = install_pub_cache_runtime(
                pub_extracted_root, runtime, pub_pin["tree_sha"]
            )
        install_flutter_tools_pub_stamp(flutter_root)
        runtime_identity = runtime.lstat()
        fields = {
            "RUNTIME": str(runtime),
            "RUNTIME_ID": runtime_id_from_info(runtime_identity),
            "MANIFEST": str(Path(manifest_path)),
            "MANIFEST_SHA256": manifest_sha,
            "FLUTTER_ROOT": str(flutter_root),
            "FLUTTER_SHA256": observed_flutter,
            "JAVA_HOME": str(java_home),
            "JAVA_SHA256": observed_java,
            "STATE": str(state),
            "FLUTTER_ID": encode_root_identity(flutter_root),
            "JAVA_ID": encode_root_identity(java_home),
        }
        if pub_cache_runtime is not None:
            fields["PUB_CACHE"] = str(pub_cache_runtime)
            fields["PUB_CACHE_SHA256"] = observed_pub
        return fields
    except BaseException:
        try:
            _destroy_runtime(runtime)
        except Refused as residue:
            fail(str(residue))
        except OSError as residue:
            fail(f"cleanup residue: {residue}")
        raise


def _require_root_provision_identity() -> int:
    if os.geteuid() != 0 or os.getuid() != 0:
        _owner_unavailable("provision helper is not running as root")
    if os.environ.get("SUDO_ASKPASS"):
        fail("SUDO_ASKPASS is refused; this helper never reads a password")
    invoking = _sudo_invoking_uid()
    if invoking is None:
        fail(
            "root preflight refused: SUDO_UID is missing; rerun via "
            "the printed /usr/bin/sudo -H -- authenticated CPython 3.14.7 "
            "loader so the owner identity is preserved. "
            "Do not use a login root shell"
        )
    return invoking


def _drop_privileges() -> None:
    invoking = _require_root_provision_identity()
    gid_raw = os.environ.get("SUDO_GID")
    gid = (
        int(gid_raw)
        if gid_raw is not None and gid_raw.isdigit() and int(gid_raw) > 0
        else invoking
    )
    os.setgid(gid)
    if hasattr(os, "setgroups"):
        try:
            os.setgroups([])
        except OSError:
            pass
    os.setuid(invoking)
    if os.geteuid() == 0 or os.getuid() == 0:
        fail("failed to drop root privileges before leaving the provision helper")


def _apply_owner_sealed_modes(root: Path) -> None:
    directories = []
    for base_text, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(base_text)
        directories.append(base)
        for filename in filenames:
            path = base / filename
            if path.is_symlink():
                continue
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                fail(f"unsupported provision file: {path}")
            path.chmod(0o555 if mode_was_executable(info.st_mode) else 0o444)
    for directory in reversed(directories):
        directory.chmod(0o555)


def _apply_sf_immutable_tree(root: Path) -> None:
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            if path.is_symlink():
                continue
            os.chflags(path, SF_IMMUTABLE)
        os.chflags(base_path, SF_IMMUTABLE)


def _rollback_published_owner_tree(root: Path, identity: tuple[int, int]) -> None:
    if root not in {OWNER_FLUTTER, OWNER_JAVA}:
        fail("refusing rollback of a foreign toolchain occupant")
    if root.is_symlink():
        fail("refusing rollback of a foreign toolchain occupant")
    if not root.exists():
        return
    info = root.lstat()
    if (int(info.st_dev), int(info.st_ino)) != identity:
        fail("refusing rollback of a foreign toolchain occupant")
    if not stat.S_ISDIR(info.st_mode):
        fail("refusing rollback of a foreign toolchain occupant")
    expected_uid = 0 if os.geteuid() == 0 else os.getuid()
    if info.st_uid != expected_uid:
        fail("refusing rollback of a foreign toolchain occupant")
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            if path.is_symlink():
                continue
            try:
                entry = path.lstat()
            except FileNotFoundError:
                continue
            if entry.st_uid != expected_uid:
                fail("refusing rollback of a foreign toolchain occupant")
            try:
                os.chflags(path, 0)
            except OSError:
                pass
            try:
                os.chmod(path, 0o700 if stat.S_ISDIR(entry.st_mode) else 0o600)
            except OSError:
                pass
        try:
            os.chflags(base_path, 0)
        except OSError:
            pass
        try:
            os.chmod(base_path, 0o700)
        except OSError:
            pass
    shutil.rmtree(root)


def _commit_owner_live_trees(flutter_src: Path, java_src: Path) -> None:
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        flutter_src.rename(OWNER_FLUTTER)
        published.append((OWNER_FLUTTER, _dev_ino(OWNER_FLUTTER)))
        java_src.rename(OWNER_JAVA)
        published.append((OWNER_JAVA, _dev_ino(OWNER_JAVA)))
        _apply_sf_immutable_tree(OWNER_FLUTTER)
        _apply_sf_immutable_tree(OWNER_JAVA)
    except BaseException:
        for tree, identity in reversed(published):
            _rollback_published_owner_tree(tree, identity)
        raise


def _clear_sf_immutable_tree(root: Path) -> None:
    if not (root.exists() or root.is_symlink()):
        return
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
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


def _ensure_owner_parents() -> None:
    for path, mode in ((OWNER_LIBRARY_ROOT, 0o755), (OWNER_PREFIX, 0o755)):
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail(f"owner prefix is not a real directory: {path}")
            if info.st_uid != 0:
                fail(f"owner prefix is not root-owned: {path}")
            if stat.S_IMODE(info.st_mode) & 0o022:
                fail(f"owner prefix is group/world-writable: {path}")
            continue
        path.mkdir(mode=mode)
        os.chown(path, 0, 0)
        path.chmod(mode)


def _owner_live_present() -> bool:
    return any(
        path.exists() or path.is_symlink()
        for path in (OWNER_FLUTTER, OWNER_JAVA)
    )


def _owner_trees_match(flutter_sha: str, java_sha: str) -> bool:
    try:
        prove = os.geteuid() != 0
        bind_owner_sealed_tree(
            OWNER_FLUTTER, flutter_sha, flutter_tree=True, prove_unprivileged=prove
        )
        bind_owner_sealed_tree(
            OWNER_JAVA, java_sha, flutter_tree=False, prove_unprivileged=prove
        )
    except Refused:
        return False
    return True


def _destroy_staging(staging: Path) -> None:
    prefix = str(OWNER_PREFIX) + "/.staging."
    if not str(staging).startswith(prefix):
        fail("refusing cleanup of a foreign staging path")
    _clear_sf_immutable_tree(staging)
    shutil.rmtree(staging, ignore_errors=True)


def _materialize_unsealed_toolchains(
    staging: Path, flutter_pin: dict, java_pin: dict
) -> tuple[Path, Path, str, str]:
    incoming = staging / "incoming"
    extracted = staging / "extracted"
    incoming.mkdir(mode=0o700)
    extracted.mkdir(mode=0o700)
    flutter_archive = incoming / FLUTTER_ARCHIVE
    java_archive = incoming / JAVA_ARCHIVE
    copy_authenticated(
        flutter_pin["path"], flutter_pin["archive_sha"], flutter_archive, "Flutter"
    )
    copy_authenticated(java_pin["path"], java_pin["archive_sha"], java_archive, "Java")
    flutter_extract = extracted / "flutter-archive"
    java_extract = extracted / "java-archive"
    extract_zip(flutter_archive, flutter_extract, "flutter")
    extract_tar(java_archive, java_extract, JAVA_RELEASE)
    flutter_root = flutter_extract / "flutter"
    java_home = java_extract / JAVA_RELEASE / "Contents" / "Home"
    if not flutter_root.is_dir() or flutter_root.is_symlink():
        fail("Flutter archive lacks its exact flutter root")
    if not java_home.is_dir() or java_home.is_symlink():
        fail("Temurin archive lacks its exact Contents/Home root")
    validate_flutter_static(flutter_root)
    validate_java_static(java_home)
    normalize_modes(flutter_root, flutter_tree=True)
    normalize_modes(java_home)
    observed_flutter = tree_hash(flutter_root, require_frozen=True, flutter_tree=True)
    observed_java = tree_hash(java_home, require_frozen=True)
    if observed_flutter != flutter_pin["tree_sha"]:
        fail(
            f"Flutter observed={observed_flutter} expected={flutter_pin['tree_sha']}"
        )
    if observed_java != java_pin["tree_sha"]:
        fail(f"Java observed={observed_java} expected={java_pin['tree_sha']}")
    install_flutter_tools_pub_stamp(flutter_root)
    return flutter_root, java_home, observed_flutter, observed_java


def provision_owner_toolchains(manifest_path: str, helper_path: Path) -> None:
    if os.geteuid() != 0:
        _owner_unavailable("provision helper is not running as root", helper_path)
    _require_root_provision_identity()
    bound = authorize_custody_inputs(helper_path, Path(manifest_path))
    pins = bound["pins"]
    flutter_sha = pins["flutter"]["tree_sha"]
    java_sha = pins["java"]["tree_sha"]
    _ensure_owner_parents()
    if _owner_trees_match(flutter_sha, java_sha):
        _drop_privileges()
        bind_owner_sealed_tree(OWNER_FLUTTER, flutter_sha, flutter_tree=True)
        bind_owner_sealed_tree(OWNER_JAVA, java_sha, flutter_tree=False)
        print(f"already provisioned at {OWNER_FLUTTER} and {OWNER_JAVA}")
        return
    if _owner_live_present():
        fail(
            "refusing to replace live owner Android toolchain trees; owner recovery "
            f"after review: {OWNER_SHELL_PREFIX} chflags -R noschg "
            f"{OWNER_FLUTTER} {OWNER_JAVA} && {OWNER_SHELL_PREFIX} rm -rf "
            f"{OWNER_FLUTTER} {OWNER_JAVA}; owner action: "
            f"{owner_provision_command(helper_path)}"
        )
    staging = OWNER_PREFIX / f".staging.{os.getpid()}"
    if staging.exists() or staging.is_symlink():
        _destroy_staging(staging)
    staging.mkdir(mode=0o700)
    os.chown(staging, 0, 0)
    try:
        flutter_root, java_home, _, _ = _materialize_unsealed_toolchains(
            staging, pins["flutter"], pins["java"]
        )
        publish = staging / "publish"
        publish.mkdir(mode=0o700)
        flutter_dest = publish / OWNER_FLUTTER_NAME
        java_dest = publish / OWNER_JAVA_NAME
        flutter_root.rename(flutter_dest)
        java_home.rename(java_dest)
        _apply_owner_sealed_modes(flutter_dest)
        _apply_owner_sealed_modes(java_dest)
        _commit_owner_live_trees(flutter_dest, java_dest)
    except BaseException:
        _destroy_staging(staging)
        raise
    _destroy_staging(staging)
    _drop_privileges()
    bind_owner_sealed_tree(OWNER_FLUTTER, flutter_sha, flutter_tree=True)
    bind_owner_sealed_tree(OWNER_JAVA, java_sha, flutter_tree=False)
    print(f"provisioned {OWNER_FLUTTER} and {OWNER_JAVA}")


def require_sealed_execution(argv: list[str]) -> None:
    verify_runtime(argv)
    sealed_execution_trees(
        Path(argv[4]),
        Path(argv[6]),
        decode_root_identity(argv[8]),
        decode_root_identity(argv[9]),
        argv[5],
        argv[7],
    )


def prepare(manifest_path: str, helper_path: str | None) -> None:
    _refuse_root_execution()
    if helper_path is None:
        fail(HELPER_SUBSTITUTED)
    bound = authorize_custody_inputs(Path(helper_path), Path(manifest_path))
    pins = bound["pins"]
    fields = install_extracted_runtime(
        pins["flutter"],
        pins["java"],
        pins["pub"],
        manifest_path=str(bound["manifest"]),
        manifest_sha=bound["manifest_sha"],
    )
    for key, value in fields.items():
        if "|" in value or "\n" in value or "\r" in value:
            fail("custody result contains an unsafe path")
        print(f"{key}|{value}")


def _open_parent_dir(path: Path) -> int:
    parent = path.parent
    dirfd = os.open(
        parent, os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag()
    )
    opened = os.fstat(dirfd)
    if not stat.S_ISDIR(opened.st_mode):
        os.close(dirfd)
        fail("cleanup parent must be one real directory")
    return dirfd


def _plan_cleanup(runtime: Path) -> list[tuple[str, Path, tuple[int, ...]]]:
    runtime_info = runtime.lstat()
    if runtime.is_symlink() or not stat.S_ISDIR(runtime_info.st_mode):
        fail("refusing cleanup of a substituted private runtime")
    if runtime_info.st_uid != os.getuid():
        fail("refusing cleanup of a foreign-owned private runtime")
    plan: list[tuple[str, Path, tuple[int, ...]]] = []
    for base, directories, files in os.walk(runtime, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, identity(info)))
                continue
            if not stat.S_ISREG(info.st_mode):
                fail(f"refusing cleanup of unsupported runtime entry: {path}")
            if info.st_nlink != 1:
                fail("refusing cleanup of a hardlinked runtime file")
            plan.append(("file", path, identity(info)))
        for name in directories:
            path = base_path / name
            info = path.lstat()
            if info.st_dev != runtime_info.st_dev:
                fail("refusing cleanup of an external runtime inode")
            if stat.S_ISLNK(info.st_mode):
                plan.append(("symlink", path, identity(info)))
                continue
            if not stat.S_ISDIR(info.st_mode):
                fail(f"refusing cleanup of unsupported runtime entry: {path}")
            plan.append(("dir", path, identity(info)))
    plan.append(("dir", runtime, identity(runtime_info)))
    return plan


def _destroy_runtime(runtime: Path) -> None:
    if _is_foreign_protected_path(runtime):
        fail("refusing cleanup of an owner-provisioned or foreign sealed toolchain")
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing cleanup outside the private runtime prefix")
    plan = _plan_cleanup(runtime)
    residues: list[str] = []
    for kind, path, expected in plan:
        try:
            current = path.lstat()
        except FileNotFoundError:
            residues.append(str(path))
            continue
        if identity(current) != expected:
            fail("runtime changed after cleanup validation")
        if kind == "file":
            if current.st_nlink != 1:
                fail("refusing cleanup of a hardlinked runtime file")
            fd = os.open(path, os.O_RDONLY | _cloexec_flag() | _nofollow_flag())
            try:
                opened = os.fstat(fd)
                if opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (
                    expected[0],
                    expected[1],
                ):
                    fail("refusing cleanup of a hardlinked or external runtime file")
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        elif kind == "dir":
            fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | _cloexec_flag() | _nofollow_flag(),
            )
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino) != (expected[0], expected[1]):
                    fail("cleanup directory was replaced")
                os.fchmod(fd, 0o700)
                if hasattr(os, "chflags"):
                    try:
                        os.chflags(path, 0)
                    except OSError:
                        pass
            finally:
                os.close(fd)
        elif kind == "symlink":
            pass
    for kind, path, expected in plan:
        try:
            current = path.lstat()
        except FileNotFoundError:
            residues.append(str(path))
            continue
        try:
            dirfd = _open_parent_dir(path)
            try:
                if kind == "file":
                    if current.st_nlink != 1 or (current.st_dev, current.st_ino) != (
                        expected[0],
                        expected[1],
                    ):
                        fail("refusing unlink of a hardlinked or external runtime file")
                    os.unlink(path.name, dir_fd=dirfd)
                elif kind == "symlink":
                    if not stat.S_ISLNK(current.st_mode):
                        fail("refusing unlink of a substituted runtime symlink")
                    os.unlink(path.name, dir_fd=dirfd)
                elif kind == "dir":
                    os.rmdir(path.name, dir_fd=dirfd)
            finally:
                os.close(dirfd)
        except OSError as suc:
            residues.append(f"{path}: {suc}")
    if runtime.exists() or runtime.is_symlink():
        residues.append(str(runtime))
    if residues:
        fail("cleanup residue: " + "; ".join(residues))


def verify_runtime(argv: list[str]) -> None:
    if len(argv) not in {10, 12}:
        fail("internal runtime verification arguments are malformed")
    (
        runtime,
        runtime_id,
        manifest_path,
        manifest_sha,
        flutter_root,
        flutter_sha,
        java_home,
        java_sha,
        flutter_id_text,
        java_id_text,
    ) = argv[:10]
    runtime_path = Path(runtime)
    info = runtime_path.lstat()
    observed_id = runtime_id_from_info(info)
    if (
        observed_id != runtime_id
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        fail("private runtime identity changed")
    if runtime_path.parent != PRIVATE_TMP or not runtime_path.name.startswith(
        RUNTIME_PREFIX
    ):
        fail("runtime pointer escaped its private prefix")
    flutter = Path(flutter_root)
    java = Path(java_home)
    expected_flutter_id = decode_root_identity(flutter_id_text)
    expected_java_id = decode_root_identity(java_id_text)
    flutter_live = root_identity(flutter)
    java_live = root_identity(java)
    if flutter_live != expected_flutter_id:
        fail("Flutter root identity changed after custody preparation")
    if java_live != expected_java_id:
        fail("Java Home identity changed after custody preparation")
    manifest, observed_manifest_sha = read_manifest(manifest_path)
    flutter_pin, java_pin, pub_pin = validate_exact_pins(manifest)
    if observed_manifest_sha != manifest_sha:
        fail("pin manifest changed after custody preparation")
    if pub_pin is None:
        if len(argv) != 10:
            fail("unexpected pub-cache custody fields")
    elif len(argv) != 12:
        fail("pub-cache custody fields are missing")
    expected_flutter = runtime_path / "extracted" / "flutter-archive" / "flutter"
    expected_java = (
        runtime_path / "extracted" / "java-archive" / JAVA_RELEASE / "Contents" / "Home"
    )
    if flutter != expected_flutter or java != expected_java:
        fail("toolchain root pointers changed after custody preparation")
    if flutter_sha != flutter_pin["tree_sha"] or java_sha != java_pin["tree_sha"]:
        fail("caller-provided tree digest differs from the authoritative manifest pin")
    for root in (flutter, java):
        try:
            root.resolve(strict=True).relative_to(runtime_path.resolve(strict=True))
        except ValueError:
            fail("toolchain root escaped the private runtime")
    remove_flutter_tools_pub_stamp(flutter)
    if tree_hash(flutter, require_frozen=True, flutter_tree=True) != flutter_sha:
        fail("private Flutter tree changed")
    if tree_hash(java, require_frozen=True) != java_sha:
        fail("private Java tree changed")
    if root_identity(flutter) != expected_flutter_id:
        fail("Flutter root identity changed during verification")
    if root_identity(java) != expected_java_id:
        fail("Java Home identity changed during verification")
    if pub_pin is not None:
        pub_cache = Path(argv[10])
        pub_sha = argv[11]
        expected_pub = runtime_path / "pub-cache"
        if pub_cache != expected_pub:
            fail("pub-cache root pointer changed after custody preparation")
        if pub_sha != pub_pin["tree_sha"]:
            fail("caller-provided tree digest differs from the authoritative manifest pin")
        try:
            pub_cache.resolve(strict=True).relative_to(runtime_path.resolve(strict=True))
        except ValueError:
            fail("pub-cache root escaped the private runtime")
        sanitize_pub_cache_runtime(
            pub_cache, golden_pub_cache_root(runtime_path), pub_sha
        )
    install_flutter_tools_pub_stamp(flutter)
    for directory in (runtime_path / "state" / "home", runtime_path / "state" / "tmp"):
        state_info = directory.lstat()
        if stat.S_ISLNK(state_info.st_mode) or not stat.S_ISDIR(state_info.st_mode):
            fail("state directory must be one real directory")


def cleanup_runtime(argv: list[str]) -> None:
    if len(argv) != 2:
        fail("internal cleanup arguments are malformed")
    runtime_text, expected_id = argv
    runtime = Path(runtime_text)
    if _is_foreign_protected_path(runtime):
        fail("refusing cleanup of an owner-provisioned or foreign sealed toolchain")
    if runtime.parent != PRIVATE_TMP or not runtime.name.startswith(RUNTIME_PREFIX):
        fail("refusing cleanup outside the private runtime prefix")
    info = runtime.lstat()
    observed_id = runtime_id_from_info(info)
    if (
        observed_id != expected_id
        or not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
    ):
        fail("refusing cleanup of a substituted private runtime")
    _destroy_runtime(runtime)


def run_from_verified(
    argv: list[str],
    *,
    kind: str,
    extra_env: dict[str, str] | None = None,
) -> int:
    try:
        separator = argv.index("--")
    except ValueError:
        fail("run action requires an argument separator")
    verification = argv[:separator]
    command = argv[separator + 1 :]
    verify_runtime(verification)
    runtime = Path(verification[0])
    flutter = Path(verification[4])
    java = Path(verification[6])
    flutter_expected = decode_root_identity(verification[8])
    java_expected = decode_root_identity(verification[9])
    pub_cache = Path(verification[10]) if len(verification) >= 12 else None
    try:
        flutter_exec, java_exec = sealed_clones(
            runtime,
            flutter,
            java,
            flutter_expected,
            java_expected,
            verification[5],
            verification[7],
        )
        env = cloned_environment(
            runtime, flutter_exec, java_exec, extra_env, pub_cache
        )
        if kind == "flutter":
            executable = (
                flutter_exec / "bin" / "cache" / "dart-sdk" / "bin" / "dart"
            )
            snapshot = flutter_exec / "bin" / "cache" / "flutter_tools.snapshot"
            spawn_argv = [str(executable), str(snapshot), *command]
        elif kind in {"java", "keytool", "jarsigner"}:
            executable = java_exec / "bin" / kind
            spawn_argv = [str(executable), *command]
        else:
            fail(f"unapproved JDK tool rejected: {kind}")
        return spawn_cloned(executable, spawn_argv, env, 300)
    finally:
        verify_runtime(verification)


def parse_argv(argv: list[str]) -> tuple[str | None, list[str]]:
    if argv[:1] == ["--helper"] and len(argv) >= 2:
        return argv[1], argv[2:]
    return None, argv


def bind_live_helper(helper_path: str | None) -> Path:
    global LIVE_HELPER
    if helper_path is None:
        fail(HELPER_SUBSTITUTED)
    helper = Path(helper_path)
    if helper.name != HELPER_NAME:
        fail(HELPER_SUBSTITUTED)
    if helper.parent == OWNER_BOOTSTRAP:
        LIVE_HELPER = _bind_sealed_bootstrap_helper(helper)
        return LIVE_HELPER
    tools_dir = helper.resolve(strict=False).parent
    if tools_dir.name != "tools" or helper != tools_dir / HELPER_NAME:
        fail(HELPER_SUBSTITUTED)
    helper_data = bind_regular_file(
        tools_dir / HELPER_NAME, max_size=MAX_HELPER_BYTES, label="Android toolchain helper"
    )
    contract_data = bind_regular_file(
        tools_dir / CONTRACT_NAME,
        max_size=MAX_CONTRACT_BYTES,
        label="Android toolchain contract",
    )
    windows_data = bind_regular_file(
        tools_dir / WINDOWS_HELPER_NAME,
        max_size=MAX_HELPER_BYTES,
        label="Android Windows helper",
    )
    contract = parse_contract_bytes(contract_data)
    if _digest_bytes(helper_data) != contract["helper_sha256"]:
        fail(HELPER_SUBSTITUTED)
    if _digest_bytes(windows_data) != contract["windows_helper_sha256"]:
        fail("malicious or substituted Android Windows helper rejected")
    LIVE_HELPER = helper
    return helper


def _bind_sealed_bootstrap_helper(helper: Path) -> Path:
    if helper != OWNER_BOOTSTRAP / HELPER_NAME:
        fail(HELPER_SUBSTITUTED)
    dirinfo = OWNER_BOOTSTRAP.lstat()
    if stat.S_ISLNK(dirinfo.st_mode) or not stat.S_ISDIR(dirinfo.st_mode):
        fail("sealed bootstrap is not one real directory")
    if dirinfo.st_uid != 0 or stat.S_IMODE(dirinfo.st_mode) != 0o555:
        fail("sealed bootstrap directory is not root-owned 0555")
    _require_sf_immutable(dirinfo, "sealed bootstrap")
    payloads: dict[str, bytes] = {}
    for label, name, mode, max_size in BOOTSTRAP_BUNDLE:
        path = OWNER_BOOTSTRAP / name
        payload = bind_regular_file(path, max_size=max_size, label=f"sealed {label}")
        info = path.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            fail(f"sealed {label} is not root-owned mode {oct(mode)}")
        _require_sf_immutable(info, f"sealed {label}")
        payloads[label] = payload
    authenticate_bootstrap_payloads(payloads)
    return helper


def main() -> int:
    helper, rest = parse_argv(sys.argv[1:])
    bound_helper = bind_live_helper(helper)
    if not rest:
        fail("internal action is missing")
    action = rest[0]
    if action == "provision" and len(rest) == 2:
        provision_owner_toolchains(rest[1], bound_helper)
        return 0
    _refuse_root_execution()
    if action == "prepare" and len(rest) == 2:
        prepare(rest[1], helper)
        return 0
    if action == "verify":
        verify_runtime(rest[1:])
        return 0
    if action == "require-seal":
        require_sealed_execution(rest[1:])
        return 0
    if action == "cleanup" and len(rest) == 3:
        cleanup_runtime(rest[1:])
        return 0
    if action in {"run-flutter", "run-java", "run-keytool", "run-jarsigner"}:
        kind = "flutter" if action == "run-flutter" else action[len("run-") :]
        extra = {}
        if kind == "keytool":
            password = os.environ.get("WINS_ANDROID_STORE_PASSWORD")
            if password:
                extra["WINS_ANDROID_STORE_PASSWORD"] = password
        for name in ALLOWED_RUN_ENV:
            value = os.environ.get(name)
            if value:
                extra[name] = value
        return run_from_verified(rest[1:], kind=kind, extra_env=extra or None)
    fail("unknown or malformed internal action")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refused as suc:
        print(f"release-android-toolchain custody: {suc}", file=sys.stderr)
        raise SystemExit(1)
    except (OSError, EOFError, ValueError, KeyError, tarfile.TarError, zipfile.BadZipFile) as suc:
        print(f"release-android-toolchain custody: fail-closed error: {suc}", file=sys.stderr)
        raise SystemExit(1)


# WINS_ANDROID_TOOLCHAIN_PYTHON_END
WINS_ANDROID_TOOLCHAIN_PYTHON
}

wins_release_android_toolchains_cleanup() {
  if [[ -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" ]]; then
    return 0
  fi
  local runtime="${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME}" expected
  expected="${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID:-}"
  case "$runtime" in
    /private/tmp/wins-release-android-toolchains.*) ;;
    /Library|/Library/*)
      _wins_rat_error 'refusing cleanup of an owner-provisioned or foreign sealed toolchain'
      return 1
      ;;
    *) _wins_rat_error 'refusing cleanup outside the private runtime prefix'; return 1 ;;
  esac
  _wins_rat_python cleanup "$runtime" "$expected" || return 1
  unset WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME
  unset WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID
  unset WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST
  unset WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256
  unset WINS_RELEASE_FLUTTER_ROOT WINS_RELEASE_FLUTTER_BIN
  unset WINS_RELEASE_FLUTTER_TREE_SHA256
  unset WINS_RELEASE_JAVA_HOME WINS_RELEASE_JAVA_BIN
  unset WINS_RELEASE_JAVA_TREE_SHA256
  unset WINS_RELEASE_ANDROID_TOOLCHAIN_STATE
  unset WINS_RELEASE_PUB_CACHE
  unset WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256
  unset WINS_RELEASE_FLUTTER_ROOT_ID WINS_RELEASE_JAVA_HOME_ID
}

wins_release_android_toolchains_prepare() {
  [[ $# -eq 1 ]] ||
    _wins_rat_error 'usage: wins_release_android_toolchains_prepare ABSOLUTE_PIN_MANIFEST' || return 1
  [[ -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" ]] ||
    _wins_rat_error 'Android toolchain custody is already active' || return 1
  _wins_rat_require_authenticated_python || return 1
  _wins_rat_bind_exact_inputs "$1" || return 1
  local result key value
  result="$(_wins_rat_python prepare "$1")" || return 1
  while IFS='|' read -r key value; do
    case "$key" in
      RUNTIME) WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME="$value" ;;
      RUNTIME_ID) WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID="$value" ;;
      MANIFEST) WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST="$value" ;;
      MANIFEST_SHA256) WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256="$value" ;;
      FLUTTER_ROOT) WINS_RELEASE_FLUTTER_ROOT="$value" ;;
      FLUTTER_SHA256) WINS_RELEASE_FLUTTER_TREE_SHA256="$value" ;;
      JAVA_HOME) WINS_RELEASE_JAVA_HOME="$value" ;;
      JAVA_SHA256) WINS_RELEASE_JAVA_TREE_SHA256="$value" ;;
      STATE) WINS_RELEASE_ANDROID_TOOLCHAIN_STATE="$value" ;;
      PUB_CACHE) WINS_RELEASE_PUB_CACHE="$value" ;;
      PUB_CACHE_SHA256) WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256="$value" ;;
      FLUTTER_ID) WINS_RELEASE_FLUTTER_ROOT_ID="$value" ;;
      JAVA_ID) WINS_RELEASE_JAVA_HOME_ID="$value" ;;
      *)
        wins_release_android_toolchains_cleanup
        _wins_rat_error 'unexpected custody result field'
        return 1
        ;;
    esac
  done <<< "$result"
  if [[ -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" ||
        -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID:-}" ||
        -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST:-}" ||
        -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256:-}" ||
        -z "${WINS_RELEASE_FLUTTER_ROOT:-}" ||
        -z "${WINS_RELEASE_FLUTTER_TREE_SHA256:-}" ||
        -z "${WINS_RELEASE_JAVA_HOME:-}" ||
        -z "${WINS_RELEASE_JAVA_TREE_SHA256:-}" ||
        -z "${WINS_RELEASE_ANDROID_TOOLCHAIN_STATE:-}" ||
        -z "${WINS_RELEASE_FLUTTER_ROOT_ID:-}" ||
        -z "${WINS_RELEASE_JAVA_HOME_ID:-}" ]]; then
    wins_release_android_toolchains_cleanup
    _wins_rat_error 'incomplete custody result rejected'
    return 1
  fi
  WINS_RELEASE_FLUTTER_BIN="${WINS_RELEASE_FLUTTER_ROOT}/bin/flutter"
  WINS_RELEASE_JAVA_BIN="${WINS_RELEASE_JAVA_HOME}/bin/java"
  export WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME
  export WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID
  export WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST
  export WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256
  export WINS_RELEASE_FLUTTER_ROOT WINS_RELEASE_FLUTTER_BIN
  export WINS_RELEASE_FLUTTER_TREE_SHA256
  export WINS_RELEASE_JAVA_HOME WINS_RELEASE_JAVA_BIN
  export WINS_RELEASE_JAVA_TREE_SHA256
  export WINS_RELEASE_ANDROID_TOOLCHAIN_STATE
  export WINS_RELEASE_FLUTTER_ROOT_ID WINS_RELEASE_JAVA_HOME_ID
  if [[ -n "${WINS_RELEASE_PUB_CACHE:-}" || -n "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]]; then
    if [[ -z "${WINS_RELEASE_PUB_CACHE:-}" || -z "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]]; then
      wins_release_android_toolchains_cleanup
      _wins_rat_error 'incomplete pub-cache custody result rejected'
      return 1
    fi
    export WINS_RELEASE_PUB_CACHE
    export WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256
  fi
}

# The public verifier intentionally accepts no arguments.
# shellcheck disable=SC2120
_wins_rat_verification_python() {
  local action="$1"
  [[ -n "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" &&
     -n "${WINS_RELEASE_FLUTTER_ROOT_ID:-}" &&
     -n "${WINS_RELEASE_JAVA_HOME_ID:-}" ]] ||
    _wins_rat_error 'Android toolchain custody is not active' || return 1
  if [[ -n "${WINS_RELEASE_PUB_CACHE:-}" || -n "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]]; then
    [[ -n "${WINS_RELEASE_PUB_CACHE:-}" && -n "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]] ||
      _wins_rat_error 'incomplete pub-cache custody state' || return 1
    _wins_rat_python "$action" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT" \
      "$WINS_RELEASE_FLUTTER_TREE_SHA256" \
      "$WINS_RELEASE_JAVA_HOME" \
      "$WINS_RELEASE_JAVA_TREE_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT_ID" \
      "$WINS_RELEASE_JAVA_HOME_ID" \
      "$WINS_RELEASE_PUB_CACHE" \
      "$WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256"
  else
    _wins_rat_python "$action" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT" \
      "$WINS_RELEASE_FLUTTER_TREE_SHA256" \
      "$WINS_RELEASE_JAVA_HOME" \
      "$WINS_RELEASE_JAVA_TREE_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT_ID" \
      "$WINS_RELEASE_JAVA_HOME_ID"
  fi
}

wins_release_android_toolchains_verify() {
  [[ $# -eq 0 ]] || _wins_rat_error 'usage: wins_release_android_toolchains_verify' || return 1
  _wins_rat_verification_python verify
}

wins_release_android_toolchains_require_sealed_execution() {
  [[ $# -eq 0 ]] ||
    _wins_rat_error 'usage: wins_release_android_toolchains_require_sealed_execution' ||
    return 1
  _wins_rat_verification_python require-seal
}

_wins_rat_run_kind() {
  local kind="$1"
  shift
  [[ -n "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" &&
     -n "${WINS_RELEASE_FLUTTER_ROOT_ID:-}" &&
     -n "${WINS_RELEASE_JAVA_HOME_ID:-}" ]] ||
    _wins_rat_error 'Android toolchain custody is not active' || return 1
  if [[ -n "${WINS_RELEASE_PUB_CACHE:-}" || -n "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]]; then
    [[ -n "${WINS_RELEASE_PUB_CACHE:-}" && -n "${WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256:-}" ]] ||
      _wins_rat_error 'incomplete pub-cache custody state' || return 1
    _wins_rat_python "run-${kind}" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT" \
      "$WINS_RELEASE_FLUTTER_TREE_SHA256" \
      "$WINS_RELEASE_JAVA_HOME" \
      "$WINS_RELEASE_JAVA_TREE_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT_ID" \
      "$WINS_RELEASE_JAVA_HOME_ID" \
      "$WINS_RELEASE_PUB_CACHE" \
      "$WINS_RELEASE_PUB_CACHE_PAYLOAD_SHA256" \
      -- "$@"
  else
    _wins_rat_python "run-${kind}" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME_ID" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST" \
      "$WINS_RELEASE_ANDROID_TOOLCHAIN_MANIFEST_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT" \
      "$WINS_RELEASE_FLUTTER_TREE_SHA256" \
      "$WINS_RELEASE_JAVA_HOME" \
      "$WINS_RELEASE_JAVA_TREE_SHA256" \
      "$WINS_RELEASE_FLUTTER_ROOT_ID" \
      "$WINS_RELEASE_JAVA_HOME_ID" \
      -- "$@"
  fi
}

wins_release_android_flutter() {
  [[ -n "${WINS_RELEASE_FLUTTER_ROOT:-}" ]] ||
    _wins_rat_error 'Android toolchain custody is not active' || return 1
  _wins_rat_run_kind flutter "$@"
}

wins_release_android_flutter_build() {
  [[ $# -ge 1 && "$1" == build ]] ||
    _wins_rat_error 'usage: wins_release_android_flutter_build build [ARGS...]' || return 1
  if [[ -n "${WINS_RELEASE_PUB_CACHE:-}" ]]; then
    local _wins_rat_no_pub=0 _wins_rat_arg
    for _wins_rat_arg in "$@"; do
      if [[ "$_wins_rat_arg" == "--no-pub" ]]; then
        _wins_rat_no_pub=$((_wins_rat_no_pub + 1))
      fi
    done
    [[ "$_wins_rat_no_pub" -eq 1 ]] ||
      _wins_rat_error 'build wrapper requires exactly one --no-pub' || return 1
  fi
  [[ -n "${ANDROID_SDK_ROOT:-}" && "${ANDROID_SDK_ROOT}" == "${ANDROID_HOME:-}" &&
     "${ANDROID_SDK_ROOT}" == /* && -d "${ANDROID_SDK_ROOT}" && ! -L "${ANDROID_SDK_ROOT}" ]] ||
    _wins_rat_error 'one absolute non-symlink Android SDK root is required' || return 1
  local name value
  for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
    value="${!name:-}"
    [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] ||
      _wins_rat_error "required Android signing input is absent or malformed: $name" || return 1
  done
  _wins_rat_run_kind flutter "$@"
}

wins_release_android_keytool_with_store_password() {
  [[ -n "${WINS_ANDROID_STORE_PASSWORD:-}" &&
     "${WINS_ANDROID_STORE_PASSWORD}" != *$'\n'* &&
     "${WINS_ANDROID_STORE_PASSWORD}" != *$'\r'* ]] ||
    _wins_rat_error 'WINS_ANDROID_STORE_PASSWORD is absent or malformed' || return 1
  _wins_rat_run_kind keytool "$@"
}

wins_release_android_jdk_tool() {
  [[ $# -ge 1 ]] ||
    _wins_rat_error 'usage: wins_release_android_jdk_tool java|keytool|jarsigner [ARGS...]' || return 1
  local tool="$1"
  shift
  case "$tool" in
    java|keytool|jarsigner) ;;
    *) _wins_rat_error "unapproved JDK tool rejected: $tool"; return 1 ;;
  esac
  [[ -n "${WINS_RELEASE_JAVA_HOME:-}" ]] ||
    _wins_rat_error 'Android toolchain custody is not active' || return 1
  _wins_rat_run_kind "$tool" "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  _wins_rat_error 'this helper must be sourced, not executed'
  exit 64
fi
