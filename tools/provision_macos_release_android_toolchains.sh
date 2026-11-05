#!/bin/bash
# Owner-provisioned macOS Flutter 3.47.6 / Temurin 17.0.20.1 execution helper.
#
# This helper never invokes sudo, never downloads, never reads a password, and
# never logs a password. It never runs Flutter, Gradle, signing, or arbitrary
# repo code as root. The owner runs it as root from a visible interactive
# macOS Terminal that has a controlling TTY on stdin, stdout, and stderr:
#
#   /usr/bin/sudo -H -- /Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14 -I -S \
#     -c '<authenticated one-shot loader with the reviewed launcher SHA-256 literal>' \
#     /ABS/PATH/tools/launch_macos_release_android_toolchains.py \
#     /ABS/PATH/tools/toolchain-pins.json \
#     INVOKING_UID INVOKING_GID
#
# A Cursor/agent session, pipe, or TERM=dumb capture cannot display a usable
# sudo password prompt. /dev/tty existing is not a controlling TTY. The
# helper therefore stops at the owner sudo boundary with an explicit prompt
# diagnosis and the exact owner command. Installation is atomic, fail-closed,
# and idempotent. Matching live root-owned 0555/0444 + SF_IMMUTABLE trees are
# left untouched. A mismatch is refused instead of replacing the live trees.
#
# Root never execs mutable repo Python or user-writable Bash. The printed
# owner command is a one-shot authenticated loader on the sealed CPython 3.14.7
# wrapper. That loader holds the launcher bytes through O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK,
# checks before/opened/finished/after identity, and compiles only the reviewed
# digest from tools/release_obfuscation_contract.py. The CPython launcher
# authenticates this provisioner against an embedded reviewed digest, copies
# those exact bytes into a root-owned private execution object, then runs the
# independent root-trust bootstrap from that held image. This Bash file is not
# the owner entry point: Bash lazy-parse of a user-writable original is refused.
# Do not pin this provisioner's own hash here (cycle with the launcher).
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
hash -r 2>/dev/null || true

readonly _WINS_PRAT_ID=/usr/bin/id
readonly _WINS_PRAT_UNAME=/usr/bin/uname
readonly _WINS_PRAT_STAT=/usr/bin/stat
readonly _WINS_PRAT_DIRNAME=/usr/bin/dirname
readonly _WINS_PRAT_PLUTIL=/usr/bin/plutil
readonly _WINS_PRAT_SHASUM=/usr/bin/shasum
readonly _WINS_PRAT_CPYTHON314=/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14
readonly _WINS_PRAT_FLUTTER=/Library/WinsVPN/ReleaseAndroidToolchains/flutter-3.47.6
readonly _WINS_PRAT_JAVA=/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1
readonly _WINS_PRAT_PREFIX=/Library/WinsVPN/ReleaseAndroidToolchains
readonly _WINS_PRAT_BOOTSTRAP=/Library/WinsVPN/ReleaseAndroidToolchainBootstrap
readonly _WINS_PRAT_EXECUTION_BLOCKER='owner/environment blocker: this host cannot make the Android toolchain tree immutable against same-user path replacement through execution'
# Authenticated digests of the user-writable repo inputs. Do not pin this
# provisioner's own hash here (cycle with the launcher/contract). The CPython
# launcher authenticates this file against its embedded reviewed digest.
readonly _WINS_PRAT_HELPER_SHA256='5b9b2f3cb7018adbf2b55ca8409a5317678e93c6622c17becaacee3cbbc341e8'
readonly _WINS_PRAT_CONTRACT_SHA256='7517705b3fd340dde17eb493267999a89fea23e6aa8f88f6f21cc49155203d08'
readonly _WINS_PRAT_MANIFEST_SHA256='3615ddbd9cb8602c610e6c3bfed4804749b3d5de29f7c7436434f0da5c28e365'

_wins_prat_error() {
  printf 'release-android-toolchain provision: %s\n' "$*" >&2
  return 1
}

_wins_prat_note() {
  printf 'release-android-toolchain provision: %s\n' "$*" >&2
}

_WINS_PRAT_SELF="${BASH_SOURCE[0]:-}"
[[ -n "$_WINS_PRAT_SELF" && ! -L "$_WINS_PRAT_SELF" ]] ||
  _wins_prat_error "provision helper must be one regular file" || exit 1
_WINS_PRAT_DIR="$(cd "$("$_WINS_PRAT_DIRNAME" "$_WINS_PRAT_SELF")" && pwd -P)" || exit 1
_WINS_PRAT_SELF="$_WINS_PRAT_DIR/provision_macos_release_android_toolchains.sh"
[[ -f "$_WINS_PRAT_SELF" && ! -L "$_WINS_PRAT_SELF" ]] || exit 1
readonly _WINS_PRAT_HELPER="$_WINS_PRAT_DIR/release_android_toolchain_archive_custody.sh"
readonly _WINS_PRAT_CONTRACT="$_WINS_PRAT_DIR/android-toolchain-custody.json"

_wins_prat_launcher_sha256() {
  local obfuscation="$_WINS_PRAT_DIR/release_obfuscation_contract.py" digest="" seen=0 line
  [[ "$obfuscation" == /* && -f "$obfuscation" && ! -L "$obfuscation" ]] ||
    _wins_prat_error "Android toolchain launcher digest pin is absent" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$seen" == 1 ]]; then
      if [[ "$line" =~ ^[[:space:]]*\"([0-9a-f]{64})\"[[:space:]]*$ ]]; then
        digest="${BASH_REMATCH[1]}"
        break
      fi
      _wins_prat_error "Android toolchain launcher digest pin is malformed" || return 1
    fi
    if [[ "$line" == "ANDROID_TOOLCHAIN_LAUNCHER_SHA256 = (" ]]; then
      seen=1
    fi
  done < "$obfuscation"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$digest" != 0000000000000000000000000000000000000000000000000000000000000000 ]] ||
    _wins_prat_error "Android toolchain launcher digest pin is malformed" || return 1
  printf '%s\n' "$digest"
}

_wins_prat_owner_command() {
  local manifest="$1" launcher digest uid gid loader
  launcher="$_WINS_PRAT_DIR/launch_macos_release_android_toolchains.py"
  [[ "$launcher" == /* && -f "$launcher" && ! -L "$launcher" ]] ||
    _wins_prat_error "Android toolchain CPython launcher is missing or symbolic" || return 1
  [[ "$manifest" == /* ]] ||
    _wins_prat_error "owner command paths must be absolute" || return 1
  digest="$(_wins_prat_launcher_sha256)" || return 1
  uid="$("$_WINS_PRAT_ID" -u)"
  gid="$("$_WINS_PRAT_ID" -g)"
  [[ "$uid" =~ ^[1-9][0-9]*$ && "$gid" =~ ^[1-9][0-9]*$ ]] ||
    _wins_prat_error "root preflight refused: SUDO_UID is missing" || return 1
  loader=$(cat <<'WINS_ANDROID_LAUNCHER_LOADER'
import hashlib,os,stat,sys,fcntl
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
WINS_ANDROID_LAUNCHER_LOADER
printf x)
  loader="${loader%x}"
  loader="${loader/__LAUNCHER_SHA256_LITERAL__/${digest}}"
  printf '/usr/bin/sudo -H -- %q -I -S -c %q %q %q %q %q\n' \
    "$_WINS_PRAT_CPYTHON314" "$loader" "$launcher" "$manifest" "$uid" "$gid"
}

_wins_prat_prompt_visible() {
  [[ -t 0 && -t 1 && -t 2 ]] || return 1
  [[ -n "${TERM:-}" && "${TERM}" != dumb ]] || return 1
  [[ -z "${CURSOR_AGENT:-}" ]] || return 1
  [[ -z "${SUDO_ASKPASS:-}" ]] || return 1
  return 0
}

_wins_prat_report_prompt_visibility() {
  if _wins_prat_prompt_visible; then
    _wins_prat_note "visible sudo password prompt: available on this controlling TTY"
    _wins_prat_note "owner action: paste the owner command into this same visible terminal; do not pipe, background, or wrap it"
    return 0
  fi
  _wins_prat_note "visible sudo password prompt: unavailable"
  if [[ ! -t 0 ]]; then
    _wins_prat_note "prompt reason: stdin is not a controlling TTY"
  fi
  if [[ ! -t 1 ]]; then
    _wins_prat_note "prompt reason: stdout is not a controlling TTY"
  fi
  if [[ ! -t 2 ]]; then
    _wins_prat_note "prompt reason: stderr is not a controlling TTY"
  fi
  if [[ -z "${TERM:-}" || "${TERM}" == dumb ]]; then
    _wins_prat_note "prompt reason: TERM is missing or dumb, so this session is not an interactive terminal"
  fi
  if [[ -n "${CURSOR_AGENT:-}" ]]; then
    _wins_prat_note "prompt reason: CURSOR_AGENT is set; agent-captured sessions cannot display a sudo password prompt or install results"
  fi
  if [[ -n "${SUDO_ASKPASS:-}" ]]; then
    _wins_prat_note "prompt reason: SUDO_ASKPASS is set; this helper never uses askpass and never reads a password"
  fi
  _wins_prat_note "prompt reason: /dev/tty existing is not a controlling TTY"
  _wins_prat_note "this session cannot collect a sudo password or show usable install results; do not run sudo from here"
  return 1
}

_wins_prat_emit_owner_boundary() {
  local manifest="$1"
  _wins_prat_note "${_WINS_PRAT_EXECUTION_BLOCKER}; owner-provisioned root-owned Flutter 3.47.6/JDK 17.0.20.1 trees are unavailable"
  _wins_prat_note "sealed trees: ${_WINS_PRAT_FLUTTER} ${_WINS_PRAT_JAVA} under ${_WINS_PRAT_PREFIX}"
  _wins_prat_report_prompt_visibility || true
  _wins_prat_note "owner action: $(_wins_prat_owner_command "$manifest")"
  _wins_prat_note "owner action must run in a visible interactive macOS Terminal with a controlling TTY; this helper never invokes sudo"
  return 1
}

_wins_prat_sha256() {
  local path="$1" actual
  actual="$("$_WINS_PRAT_SHASUM" -a 256 "$path")" ||
    _wins_prat_error "could not hash $path" || return 1
  printf '%s\n' "${actual%% *}"
}

_wins_prat_verify_helper_pin() {
  local expected actual
  [[ -f "$_WINS_PRAT_HELPER" && ! -L "$_WINS_PRAT_HELPER" ]] ||
    _wins_prat_error "Android toolchain helper is missing or symbolic" || return 1
  [[ -f "$_WINS_PRAT_CONTRACT" && ! -L "$_WINS_PRAT_CONTRACT" ]] ||
    _wins_prat_error "Android toolchain contract is missing or symbolic" || return 1
  [[ "${1:-}" == /* && -f "$1" && ! -L "$1" ]] ||
    _wins_prat_error "regular absolute pin manifest required" || return 1
  expected="$("$_WINS_PRAT_PLUTIL" -extract helper_sha256 raw -o - "$_WINS_PRAT_CONTRACT")" ||
    _wins_prat_error "Android toolchain helper digest pin is unreadable" || return 1
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" == "$_WINS_PRAT_HELPER_SHA256" ]] ||
    _wins_prat_error "Android toolchain helper digest pin is malformed or disagrees with the provisioner" || return 1
  actual="$(_wins_prat_sha256 "$_WINS_PRAT_HELPER")" || return 1
  [[ "$actual" == "$expected" ]] ||
    _wins_prat_error "stale or substituted Android toolchain helper rejected" || return 1
  actual="$(_wins_prat_sha256 "$_WINS_PRAT_CONTRACT")" || return 1
  [[ "$actual" == "$_WINS_PRAT_CONTRACT_SHA256" ]] ||
    _wins_prat_error "stale or substituted Android toolchain contract rejected" || return 1
  expected="$("$_WINS_PRAT_PLUTIL" -extract manifest_sha256 raw -o - "$_WINS_PRAT_CONTRACT")" ||
    _wins_prat_error "Android pin manifest digest pin is unreadable" || return 1
  [[ "$expected" == "$_WINS_PRAT_MANIFEST_SHA256" ]] ||
    _wins_prat_error "Android pin manifest digest pin disagrees with the provisioner" || return 1
  actual="$(_wins_prat_sha256 "$1")" || return 1
  [[ "$actual" == "$expected" ]] ||
    _wins_prat_error "stale or substituted Android pin manifest rejected" || return 1
}

_wins_prat_refuse_user_writable_root() {
  local manifest="${1:-tools/toolchain-pins.json}"
  _wins_prat_error "refusing to parse this user-writable provisioner as root; invoke the CPython 3.14 launcher" || true
  _wins_prat_note "owner action: $(_wins_prat_owner_command "$manifest")"
  return 1
}

_wins_prat_user_writable_owner_entry() {
  local manifest="${1:-}"
  [[ $# -eq 1 ]] ||
    _wins_prat_error "usage: provision_macos_release_android_toolchains.sh ABSOLUTE_PIN_MANIFEST" ||
    return 1
  [[ "$("$_WINS_PRAT_UNAME" -s)" == Darwin ]] ||
    _wins_prat_error "macOS is required" || return 1
  [[ "$("$_WINS_PRAT_UNAME" -m)" == arm64 ]] ||
    _wins_prat_error "darwin_arm64 custody requires an arm64 host" || return 1
  [[ "$manifest" == /* && -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_prat_error "regular absolute pin manifest required" || return 1
  [[ "$manifest" != *[[:space:]]* && "$_WINS_PRAT_SELF" != *[[:space:]]* ]] ||
    _wins_prat_error "owner command paths must not contain whitespace" || return 1
  [[ -z "${SUDO_ASKPASS:-}" ]] ||
    _wins_prat_error "SUDO_ASKPASS is refused; this helper never reads a password" || return 1
  [[ "$manifest" == "$_WINS_PRAT_DIR/toolchain-pins.json" ]] ||
    _wins_prat_error "replacement Android pin manifest cannot self-authorize" || return 1
  [[ "$_WINS_PRAT_HELPER_SHA256" =~ ^[0-9a-f]{64}$ &&
     "$_WINS_PRAT_CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ &&
     "$_WINS_PRAT_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    _wins_prat_error "authenticated bootstrap digests are malformed" || return 1
  _wins_prat_verify_helper_pin "$manifest" || return 1
  _wins_prat_emit_owner_boundary "$manifest"
  return 1
}

# Exit before Bash lazy-parses the bootstrap payload from a user-writable
# original. A same-user same-inode overwrite after this process started cannot
# redefine a heredoc this shell will never read.
if [[ "$_WINS_PRAT_DIR" != "$_WINS_PRAT_BOOTSTRAP" ]]; then
  if [[ "$("$_WINS_PRAT_ID" -u)" == 0 ]]; then
    _wins_prat_refuse_user_writable_root "${1:-}"
    exit 1
  fi
  _wins_prat_user_writable_owner_entry "${1:-}"
  exit 1
fi

_wins_prat_run_root_trust_bootstrap() {
  _wins_prat_error "refusing to feed this provisioner to Python stdin; invoke the CPython 3.14 launcher" || return 1
}

# Payload data for the already-loaded CPython launcher. Bash never executes it
# as a program. The launcher authenticates these exact bytes once and compiles
# them in-process from the held image.
: <<'PY'
# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_BEGIN
from __future__ import annotations

import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from contextlib import redirect_stdout

CHUNK = 1024 * 1024
SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
SF_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000)
PYTHON_BEGIN = "# WINS_ANDROID_TOOLCHAIN_PYTHON_BEGIN\n"
PYTHON_END = "\n# WINS_ANDROID_TOOLCHAIN_PYTHON_END"
OWNER_LIBRARY_ROOT = Path("/Library/WinsVPN")
OWNER_BOOTSTRAP = Path("/Library/WinsVPN/ReleaseAndroidToolchainBootstrap")
OWNER_FLUTTER = Path("/Library/WinsVPN/ReleaseAndroidToolchains/flutter-3.47.6")
OWNER_JAVA = Path("/Library/WinsVPN/ReleaseAndroidToolchains/jdk-17.0.20.1")
BOOTSTRAP_STAGING_PREFIX = str(OWNER_LIBRARY_ROOT) + "/.ReleaseAndroidToolchainBootstrap.staging."
HELPER_NAME = "release_android_toolchain_archive_custody.sh"
PROVISIONER_NAME = "provision_macos_release_android_toolchains.sh"
CONTRACT_NAME = "android-toolchain-custody.json"
MANIFEST_NAME = "toolchain-pins.json"
class Refused(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


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


def _hex64(value: str, label: str) -> str:
    if SHA_RE.fullmatch(value) is None or value == "0" * 64:
        fail(f"{label} must be an exact lowercase non-zero SHA-256")
    return value


def _digest(data: bytes) -> str:
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


def authenticate_bootstrap_payloads(
    payloads: dict[str, bytes], expected: dict[str, str]
) -> None:
    required = ("provisioner", "helper", "contract", "manifest")
    if set(payloads) != set(required) or set(expected) != set(required):
        fail("sealed bootstrap payload set is not exact")
    observed = {label: _digest(payloads[label]) for label in required}
    for label in required:
        if observed[label] != expected[label]:
            fail(f"stale or substituted Android toolchain {label} rejected")
    pins = provisioner_embedded_pins(payloads["provisioner"])
    if observed["helper"] != pins["helper"]:
        fail("stale or substituted Android toolchain helper rejected")
    if observed["contract"] != pins["contract"]:
        fail("stale or substituted Android toolchain contract rejected")
    if observed["manifest"] != pins["manifest"]:
        fail("stale or substituted Android pin manifest rejected")
    try:
        document = json.loads(payloads["contract"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Android toolchain contract is not strict UTF-8 JSON")
    if type(document) is not dict:
        fail("Android toolchain contract is not strict UTF-8 JSON")
    if document.get("helper_sha256") != expected["helper"]:
        fail("contract helper digest disagrees with the authenticated provisioner pin")
    if document.get("manifest_sha256") != expected["manifest"]:
        fail("contract manifest digest disagrees with the authenticated provisioner pin")


def _thaw_private_inode(path: Path, *, expected_uid: int) -> None:
    if path.is_symlink():
        fail("refusing rollback of a foreign bootstrap occupant")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if info.st_uid != expected_uid:
        fail("refusing rollback of a foreign bootstrap occupant")
    try:
        os.chflags(path, 0)
    except OSError:
        pass
    mode = 0o700 if stat.S_ISDIR(info.st_mode) else 0o600
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _rollback_published_dest(
    dest: Path,
    identity: tuple[int, int] | None,
    names: dict[str, tuple[str, int]],
    *,
    chown_root: bool,
) -> None:
    if identity is None:
        return
    if dest.is_symlink():
        fail("refusing rollback of a foreign bootstrap occupant")
    if not dest.exists():
        return
    if dest in {Path("/Library"), OWNER_LIBRARY_ROOT, OWNER_FLUTTER, OWNER_JAVA} or (
        dest != OWNER_BOOTSTRAP and str(dest).startswith("/Library/")
    ):
        fail("refusing rollback of a foreign bootstrap occupant")
    info = dest.lstat()
    if (int(info.st_dev), int(info.st_ino)) != identity:
        fail("refusing rollback of a foreign bootstrap occupant")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("refusing rollback of a foreign bootstrap occupant")
    expected_uid = 0 if chown_root else os.getuid()
    if info.st_uid != expected_uid:
        fail("refusing rollback of a foreign bootstrap occupant")
    expected_names = {name for name, _mode in names.values()}
    observed: list[str] = []
    with os.scandir(dest) as scan:
        for entry in scan:
            observed.append(entry.name)
            if entry.is_symlink() or entry.name not in expected_names:
                fail("refusing rollback of a foreign bootstrap occupant")
    if set(observed) != expected_names:
        fail("refusing rollback of a foreign bootstrap occupant")
    for name in expected_names:
        _thaw_private_inode(dest / name, expected_uid=expected_uid)
    _thaw_private_inode(dest, expected_uid=expected_uid)
    shutil.rmtree(dest)


def hold_regular_file(path: Path, *, max_size: int, label: str) -> tuple[int, bytes, str]:
    if not path.is_absolute():
        fail(f"{label} path must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} traverses a symbolic link")
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
            (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns, before.st_size)
            != (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_size)
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
            (opened.st_dev, opened.st_ino, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_size)
            != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, after.st_size)
        ):
            fail(f"{label} changed while it was read")
        data = b"".join(chunks)
        if not data:
            fail(f"{label} snapshot is empty")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd, data, _digest(data)
    except BaseException:
        os.close(fd)
        raise


def copy_held_fd(
    fd: int,
    data: bytes,
    destination: Path,
    expected: str,
    *,
    mode: int,
    label: str,
    chown_root: bool,
) -> None:
    os.fstat(fd)
    if _digest(data) != expected:
        fail(f"{label} SHA-256 mismatch during held-fd copy")
    dest_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _cloexec() | _nofollow()
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
        if chown_root:
            os.fchown(dest_fd, 0, 0)
        os.fchmod(dest_fd, mode)
    finally:
        os.close(dest_fd)
    if digest.hexdigest() != expected:
        fail(f"{label} SHA-256 mismatch during held-fd copy")


def extract_helper_python(data: bytes) -> str:
    text = data.decode("ascii")
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


def _require_sf_immutable(info: os.stat_result, label: str) -> None:
    flags = int(getattr(info, "st_flags", 0))
    if not (flags & SF_IMMUTABLE):
        fail(f"SF_IMMUTABLE is required: {label}")


def _destroy_staging(staging: Path, dest: Path) -> None:
    if dest == OWNER_BOOTSTRAP:
        if not str(staging).startswith(BOOTSTRAP_STAGING_PREFIX):
            fail("refusing cleanup of a foreign bootstrap staging path")
    elif (
        staging.parent != dest.parent
        or not staging.name.startswith(".ReleaseAndroidToolchainBootstrap.staging.")
    ):
        fail("refusing cleanup of a foreign bootstrap staging path")
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


def _staging_path(dest: Path) -> Path:
    if dest == OWNER_BOOTSTRAP:
        staging = OWNER_LIBRARY_ROOT / f".ReleaseAndroidToolchainBootstrap.staging.{os.getpid()}"
        if not str(staging).startswith(BOOTSTRAP_STAGING_PREFIX):
            fail("refusing cleanup of a foreign bootstrap staging path")
        return staging
    return dest.parent / f".ReleaseAndroidToolchainBootstrap.staging.{os.getpid()}"


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


def _reverify_sealed(dest: Path, expected: dict[str, str]) -> dict[str, bytes]:
    dirinfo = dest.lstat()
    if stat.S_ISLNK(dirinfo.st_mode) or not stat.S_ISDIR(dirinfo.st_mode):
        fail("sealed bootstrap is not one real directory")
    if dirinfo.st_uid != 0 or stat.S_IMODE(dirinfo.st_mode) != 0o555:
        fail("sealed bootstrap directory is not root-owned 0555")
    _require_sf_immutable(dirinfo, "sealed bootstrap")
    payloads: dict[str, bytes] = {}
    files = (
        ("provisioner", dest / PROVISIONER_NAME, 0o555),
        ("helper", dest / HELPER_NAME, 0o555),
        ("contract", dest / CONTRACT_NAME, 0o444),
        ("manifest", dest / MANIFEST_NAME, 0o444),
    )
    for label, path, mode in files:
        fd, data, digest = hold_regular_file(path, max_size=2 * 1024 * 1024, label=f"sealed {label}")
        os.close(fd)
        info = path.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
            fail(f"sealed {label} is not root-owned mode {oct(mode)}")
        _require_sf_immutable(info, f"sealed {label}")
        payloads[label] = data
    authenticate_bootstrap_payloads(payloads, expected)
    return payloads


def publish_sealed_bundle(
    held: dict[str, tuple[int, bytes, str]],
    dest: Path,
    *,
    apply_kernel_seal: bool,
    chown_root: bool,
) -> dict[str, bytes]:
    expected = {label: digest for label, (_fd, _data, digest) in held.items()}
    if dest.exists() or dest.is_symlink():
        try:
            return _reverify_sealed(dest, expected)
        except Refused as suc:
            fail(
                "refusing to replace live sealed Android toolchain bootstrap "
                f"({suc}); owner recovery after review: sudo /bin/bash -p chflags "
                f"-R noschg {dest} && sudo /bin/bash -p rm -rf {dest}"
            )
    if dest == OWNER_BOOTSTRAP:
        _ensure_library_root()
    staging = _staging_path(dest)
    _destroy_staging(staging, dest)
    staging.mkdir(mode=0o700)
    if chown_root:
        os.chown(staging, 0, 0)
    staging.chmod(0o700)
    names = {
        "provisioner": (PROVISIONER_NAME, 0o555),
        "helper": (HELPER_NAME, 0o555),
        "contract": (CONTRACT_NAME, 0o444),
        "manifest": (MANIFEST_NAME, 0o444),
    }
    try:
        for label, (name, mode) in names.items():
            fd, data, digest = held[label]
            copy_held_fd(
                fd,
                data,
                staging / name,
                digest,
                mode=mode,
                label=label,
                chown_root=chown_root,
            )
        staging.chmod(0o555)
        if chown_root:
            os.chown(staging, 0, 0)
        os.rename(staging, dest)
        published_identity = _dev_ino(dest)
    except BaseException:
        _destroy_staging(staging, dest)
        raise
    if apply_kernel_seal:
        try:
            if not SF_IMMUTABLE:
                fail("SF_IMMUTABLE is required")
            for _label, (name, _mode) in names.items():
                os.chflags(dest / name, SF_IMMUTABLE)
            os.chflags(dest, SF_IMMUTABLE)
            return _reverify_sealed(dest, expected)
        except BaseException:
            _rollback_published_dest(
                dest, published_identity, names, chown_root=chown_root
            )
            _destroy_staging(staging, dest)
            raise
    payloads = {}
    for label, (name, _mode) in names.items():
        payloads[label] = (dest / name).read_bytes()
        if hashlib.sha256(payloads[label]).hexdigest() != expected[label]:
            fail(f"published {label} digest mismatch")
    authenticate_bootstrap_payloads(payloads, expected)
    return payloads


def invoke_sealed_provision(helper_data: bytes, helper_path: Path, manifest_path: Path) -> str:
    source = extract_helper_python(helper_data)
    namespace: dict = {"__name__": "android_toolchain_sealed_exec"}
    guard = '\nif __name__ == "__main__":\n'
    index = source.rfind(guard)
    if index < 0:
        fail("sealed helper Python does not invoke main")
    body = source[:index]
    exec(compile(body, str(helper_path), "exec"), namespace)
    if "main" not in namespace or "provision_owner_toolchains" not in namespace:
        fail("sealed helper Python did not define main")
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


def bootstrap_and_provision(
    provisioner: Path,
    helper: Path,
    contract: Path,
    manifest: Path,
    expected_helper: str,
    expected_contract: str,
    expected_manifest: str,
    expected_provisioner: str,
    dest: Path,
    *,
    apply_kernel_seal: bool = True,
    require_root: bool = True,
    execute_provision: bool = True,
) -> str:
    if require_root and (os.geteuid() != 0 or os.getuid() != 0):
        fail("root-trust bootstrap must run as root")
    if os.environ.get("SUDO_ASKPASS"):
        fail("SUDO_ASKPASS is refused; this helper never reads a password")
    if require_root:
        raw = os.environ.get("SUDO_UID")
        if raw is None or not raw.isdigit() or int(raw) <= 0:
            fail(
                "root preflight refused: SUDO_UID is missing; rerun via "
                "the printed /usr/bin/sudo -H -- authenticated CPython 3.14.7 "
                "loader so the owner identity is preserved. "
                "Do not use a login root shell"
            )
    expected_helper = _hex64(expected_helper, "helper digest")
    expected_contract = _hex64(expected_contract, "contract digest")
    expected_manifest = _hex64(expected_manifest, "manifest digest")
    expected_provisioner = _hex64(expected_provisioner, "provisioner digest")
    held: dict[str, tuple[int, bytes, str]] = {}
    try:
        held["provisioner"] = hold_regular_file(
            provisioner, max_size=2 * 1024 * 1024, label="Android toolchain provisioner"
        )
        held["helper"] = hold_regular_file(
            helper, max_size=2 * 1024 * 1024, label="Android toolchain helper"
        )
        held["contract"] = hold_regular_file(
            contract, max_size=64 * 1024, label="Android toolchain contract"
        )
        held["manifest"] = hold_regular_file(
            manifest, max_size=2 * 1024 * 1024, label="Android pin manifest"
        )
        _pfd, provisioner_data, provisioner_digest = held["provisioner"]
        _hfd, helper_data, helper_digest = held["helper"]
        _cfd, contract_data, contract_digest = held["contract"]
        _mfd, manifest_data, manifest_digest = held["manifest"]
        del _pfd, _hfd, _cfd, _mfd
        authenticate_bootstrap_payloads(
            {
                "provisioner": provisioner_data,
                "helper": helper_data,
                "contract": contract_data,
                "manifest": manifest_data,
            },
            {
                "provisioner": expected_provisioner,
                "helper": expected_helper,
                "contract": expected_contract,
                "manifest": expected_manifest,
            },
        )
        if provisioner_digest != expected_provisioner:
            fail("stale or substituted Android toolchain provisioner rejected")
        helper_text = helper_data.decode("ascii")
        if helper_text.count(PYTHON_BEGIN) != 1 or helper_text.count(PYTHON_END) != 1:
            fail("Android toolchain helper Python markers are malformed")
        payloads = publish_sealed_bundle(
            held,
            dest,
            apply_kernel_seal=apply_kernel_seal,
            chown_root=require_root,
        )
        if not execute_provision:
            return helper_digest
        sealed_helper = dest / HELPER_NAME
        sealed_manifest = dest / MANIFEST_NAME
        return invoke_sealed_provision(payloads["helper"], sealed_helper, sealed_manifest)
    finally:
        for fd, _data, _digest in held.values():
            try:
                os.close(fd)
            except OSError:
                pass


def bootstrap_main(argv: list[str]) -> int:
    if len(argv) != 9:
        fail("root-trust bootstrap arguments are malformed")
    (
        provisioner,
        helper,
        contract,
        manifest,
        helper_sha,
        contract_sha,
        manifest_sha,
        provisioner_sha,
        dest,
    ) = argv
    try:
        bootstrap_and_provision(
            Path(provisioner),
            Path(helper),
            Path(contract),
            Path(manifest),
            helper_sha,
            contract_sha,
            manifest_sha,
            provisioner_sha,
            Path(dest),
            apply_kernel_seal=True,
            require_root=True,
        )
        return 0
    except Refused as suc:
        print(f"release-android-toolchain provision: {suc}", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as suc:
        print(f"release-android-toolchain provision: fail-closed error: {suc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(bootstrap_main(sys.argv[1:]))
# WINS_ANDROID_ROOT_TRUST_BOOTSTRAP_END
PY

wins_release_android_toolchains_provision_owner_trees() {
  local manifest="$1" uid
  [[ $# -eq 1 ]] ||
    _wins_prat_error "usage: provision_macos_release_android_toolchains.sh ABSOLUTE_PIN_MANIFEST" ||
    return 1
  [[ "$("$_WINS_PRAT_UNAME" -s)" == Darwin ]] ||
    _wins_prat_error "macOS is required" || return 1
  [[ "$("$_WINS_PRAT_UNAME" -m)" == arm64 ]] ||
    _wins_prat_error "darwin_arm64 custody requires an arm64 host" || return 1
  [[ "$manifest" == /* && -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_prat_error "regular absolute pin manifest required" || return 1
  [[ "$manifest" != *[[:space:]]* && "$_WINS_PRAT_SELF" != *[[:space:]]* ]] ||
    _wins_prat_error "owner command paths must not contain whitespace" || return 1
  [[ -z "${SUDO_ASKPASS:-}" ]] ||
    _wins_prat_error "SUDO_ASKPASS is refused; this helper never reads a password" || return 1
  [[ "$manifest" == "$_WINS_PRAT_DIR/toolchain-pins.json" ]] ||
    _wins_prat_error "replacement Android pin manifest cannot self-authorize" || return 1
  [[ "$_WINS_PRAT_HELPER_SHA256" =~ ^[0-9a-f]{64}$ &&
     "$_WINS_PRAT_CONTRACT_SHA256" =~ ^[0-9a-f]{64}$ &&
     "$_WINS_PRAT_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
    _wins_prat_error "authenticated bootstrap digests are malformed" || return 1

  uid="$("$_WINS_PRAT_ID" -u)"
  if [[ "$uid" == 0 ]]; then
    _wins_prat_error "refusing to parse this provisioner as root; invoke the CPython 3.14 launcher" || true
    _wins_prat_note "owner action: $(_wins_prat_owner_command "$manifest")"
    return 1
  fi
  _wins_prat_verify_helper_pin "$manifest" || return 1
  _wins_prat_emit_owner_boundary "$manifest"
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  wins_release_android_toolchains_provision_owner_trees "${1:-}"
fi
