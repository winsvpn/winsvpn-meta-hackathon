#!/bin/bash
# One-time owner provisioner for the authenticated macOS arm64 Go runtime.
#
# This helper never invokes sudo, downloads, uses ambient Go, reads a password,
# or executes this user-writable Bash file as root. After the external issuance
# has been refreshed, run it once as the non-root owner. It prints the exact
# command to paste into a visible macOS Terminal:
#
#   WINS_GO_CUSTODY_ISSUANCE=/ABS/issuance.json \
#     /bin/bash tools/provision_macos_release_go_runtime.sh \
#     /ABS/PATH/tools/toolchain-pins.json
#
# It first copies descriptor-bound, externally issued inputs and the exact Go
# archive from the digest-addressed, root-owned ReleaseGoInputs mirror into a
# root-owned SF_IMMUTABLE bootstrap. The manifest archive path remains the
# reviewed acquisition record; production never trusts that user-owned path.
# The runtime controller is executed only from the sealed bootstrap. Existing
# mismatched bootstrap or runtime paths are never replaced automatically.
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE PYTHONPATH PYTHONHOME
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
hash -r 2>/dev/null || true

readonly _WINS_GO_ID=/usr/bin/id
readonly _WINS_GO_UNAME=/usr/bin/uname
readonly _WINS_GO_DIRNAME=/usr/bin/dirname
readonly _WINS_GO_PLUTIL=/usr/bin/plutil
readonly _WINS_GO_SHASUM=/usr/bin/shasum
readonly _WINS_GO_SED=/usr/bin/sed
readonly _WINS_GO_STAT=/usr/bin/stat
readonly _WINS_GO_RELEASE_PYTHON=/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14
readonly _WINS_GO_RELEASE_PYTHON_BIN=/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/bin/python3.14

_wins_go_error() {
  printf 'release-go provision: %s\n' "$*" >&2
  return 1
}

_wins_go_verify_python_component() {
  [[ $# -eq 2 ]] || return 1
  local path="$1" require_schg="$2" identity uid gid mode flags type
  [[ "$path" == /* && ! -L "$path" ]] || return 1
  identity="$("$_WINS_GO_STAT" -f '%u:%g:%OLp:%Sf:%HT' "$path")" || return 1
  IFS=: read -r uid gid mode flags type <<<"$identity"
  [[ "$uid" == 0 && "$gid" == 0 && "$mode" =~ ^[0-7]+$ &&
     $((8#$mode & 8#022)) -eq 0 ]] || return 1
  if [[ "$type" == "Regular File" ]]; then
    [[ $((8#$mode & 8#111)) -ne 0 ]] || return 1
  else
    [[ "$type" == "Directory" ]] || return 1
  fi
  [[ "$require_schg" != 1 || ",${flags}," == *,schg,* || "$flags" == schg ]] || return 1
}

_wins_go_verify_release_python() {
  local path
  for path in /Library /Library/WinsVPN /Library/WinsVPN/ReleasePython; do
    _wins_go_verify_python_component "$path" 0 || return 1
  done
  for path in \
    /Library/WinsVPN/ReleasePython/3.14.7 \
    /Library/WinsVPN/ReleasePython/3.14.7/launcher \
    "$_WINS_GO_RELEASE_PYTHON" \
    /Library/WinsVPN/ReleasePython/3.14.7/Python.framework \
    /Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions \
    /Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14 \
    /Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/bin \
    "$_WINS_GO_RELEASE_PYTHON_BIN"; do
    _wins_go_verify_python_component "$path" 1 || return 1
  done
}

_WINS_GO_SELF="${BASH_SOURCE[0]:-}"
[[ -n "$_WINS_GO_SELF" && ! -L "$_WINS_GO_SELF" ]] ||
  _wins_go_error 'provisioner must be one regular non-symbolic file' || exit 1
_WINS_GO_DIR="$(cd "$("$_WINS_GO_DIRNAME" "$_WINS_GO_SELF")" && pwd -P)" || exit 1
_WINS_GO_SELF="$_WINS_GO_DIR/provision_macos_release_go_runtime.sh"
readonly _WINS_GO_SELF _WINS_GO_DIR

[[ $# -eq 1 && "$1" == /* ]] ||
  _wins_go_error 'usage: provision_macos_release_go_runtime.sh ABSOLUTE_PIN_MANIFEST' || exit 1
readonly _WINS_GO_MANIFEST="$1"
readonly _WINS_GO_REPO="${_WINS_GO_DIR%/tools}"
[[ "$_WINS_GO_DIR" == "$_WINS_GO_REPO/tools" &&
   "$_WINS_GO_MANIFEST" == "$_WINS_GO_DIR/toolchain-pins.json" ]] ||
  _wins_go_error 'replacement repository or Go pin manifest cannot self-authorize' || exit 1

[[ "$("$_WINS_GO_ID" -u)" != 0 && "$("$_WINS_GO_ID" -ru)" != 0 ]] ||
  _wins_go_error 'refusing to execute this user-writable provisioner as root' || exit 1
[[ "$("$_WINS_GO_UNAME" -s)" == Darwin && "$("$_WINS_GO_UNAME" -m)" == arm64 ]] ||
  _wins_go_error 'owner runtime provisioning requires macOS arm64' || exit 1
[[ -z "${SUDO_ASKPASS:-}" ]] ||
  _wins_go_error 'SUDO_ASKPASS is refused; this helper never reads a password' || exit 1
[[ "${WINS_GO_CUSTODY_ISSUANCE:-}" == /* ]] ||
  _wins_go_error 'WINS_GO_CUSTODY_ISSUANCE must name the external reviewed issuance' || exit 1
_wins_go_verify_release_python ||
  _wins_go_error 'release Python executable or ancestor custody is not root-owned, non-writable, non-symbolic, and SF_IMMUTABLE where required' || exit 1
[[ -f "$WINS_GO_CUSTODY_ISSUANCE" && ! -L "$WINS_GO_CUSTODY_ISSUANCE" ]] ||
  _wins_go_error 'external reviewed issuance must be one regular non-symbolic file' || exit 1
readonly _WINS_GO_EXPECTED_SELF_SHA="$("$_WINS_GO_PLUTIL" -extract provisioner_sha256 raw -o - "$WINS_GO_CUSTODY_ISSUANCE")"
readonly _WINS_GO_OBSERVED_SELF_SHA="$("$_WINS_GO_SHASUM" -a 256 "$_WINS_GO_SELF")"
[[ "$_WINS_GO_EXPECTED_SELF_SHA" =~ ^[0-9a-f]{64}$ &&
   "${_WINS_GO_OBSERVED_SELF_SHA%% *}" == "$_WINS_GO_EXPECTED_SELF_SHA" ]] ||
  _wins_go_error 'stale or substituted Go provisioner rejected by the external issuance' || exit 1
readonly _WINS_GO_OWNER_UID="$("$_WINS_GO_ID" -u)"
readonly _WINS_GO_OWNER_GID="$("$_WINS_GO_ID" -g)"
readonly _WINS_GO_LOADER="$("$_WINS_GO_SED" -n \
  '/^# WINS_GO_ROOT_LOADER_BEGIN$/,/^# WINS_GO_ROOT_LOADER_END$/p' "$_WINS_GO_SELF" | \
  "$_WINS_GO_SED" '1d;$d')"
[[ -n "$_WINS_GO_LOADER" ]] ||
  _wins_go_error 'authenticated inline root loader is absent' || exit 1
"$_WINS_GO_RELEASE_PYTHON" -I -S -c "$_WINS_GO_LOADER" \
  "$_WINS_GO_REPO" "$_WINS_GO_MANIFEST" "$_WINS_GO_SELF" \
  "$WINS_GO_CUSTODY_ISSUANCE" "$_WINS_GO_OWNER_UID" "$_WINS_GO_OWNER_GID" \
  preflight >/dev/null ||
  _wins_go_error 'signed Go provisioning preflight failed' || exit 1
printf '/usr/bin/sudo -H -- %q -I -S -c %q %q %q %q %q %q %q %q\n' \
  "$_WINS_GO_RELEASE_PYTHON" "$_WINS_GO_LOADER" \
  "$_WINS_GO_REPO" "$_WINS_GO_MANIFEST" "$_WINS_GO_SELF" \
  "$WINS_GO_CUSTODY_ISSUANCE" "$_WINS_GO_OWNER_UID" "$_WINS_GO_OWNER_GID" provision
exit 0

: <<'PY'
# WINS_GO_ROOT_LOADER_BEGIN
from __future__ import annotations

import ctypes
import datetime as dt
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


repo = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
provisioner_path = Path(sys.argv[3])
issuance_path = Path(sys.argv[4])
owner_uid = int(sys.argv[5])
owner_gid = int(sys.argv[6])
mode = sys.argv[7]
if mode not in {"preflight", "provision"}:
    raise SystemExit("release-go provision: inline loader mode is invalid")
if mode == "provision" and (os.getuid() != 0 or os.geteuid() != 0):
    raise SystemExit("release-go provision: inline loader must run as root")
if mode == "preflight" and (os.getuid() != owner_uid or os.geteuid() != owner_uid):
    raise SystemExit("release-go provision: preflight identity mismatch")
if owner_uid <= 0 or owner_gid <= 0:
    raise SystemExit("release-go provision: invoking owner identity is invalid")
tools = repo / "tools"
controller_name = "release_go_archive_custody.py"
wrapper_name = "release_go_archive_custody.sh"
provisioner_name = "provision_macos_release_go_runtime.sh"
manifest_name = "toolchain-pins.json"
trust_name = "release_go_archive_custody.trust.json"
freeze_name = "release_source_freeze.py"
bootstrap_parent = Path("/Library/WinsVPN/ReleaseGoBootstrap")
authority_prefix = Path("/Library/WinsVPN/ReleaseGoAuthority/v1")
authority_path = authority_prefix / "authority.json"
release_python = Path("/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14")
release_python_bin = Path("/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/bin/python3.14")
sf_immutable = getattr(stat, "SF_IMMUTABLE", 0x00020000)
hex_re = re.compile(r"[0-9a-f]{64}\Z")
issuance_id_re = re.compile(r"[0-9a-f]{32}\Z")
iso_utc_re = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
signature_algorithm = "ecdsa-p256-sha256-x962"


class Refused(RuntimeError):
    pass


def fail(message: str) -> None:
    raise Refused(message)


def json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def canonical(document: dict[str, object]) -> bytes:
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def identity(info: os.stat_result) -> tuple[int, ...]:
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


def bind(path: Path, limit: int, label: str, allowed_uids: set[int]) -> bytes:
    if not path.is_absolute():
        fail(f"{label} must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        parent_info = current.lstat()
        parent_mode = stat.S_IMODE(parent_info.st_mode)
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            fail(f"{label} symbolic or non-directory ancestor rejected")
        if parent_info.st_uid not in allowed_uids:
            fail(f"{label} foreign-owned ancestor rejected")
        if parent_mode & 0o022 and not (
            parent_info.st_uid == 0 and parent_mode & stat.S_ISVTX
        ):
            fail(f"{label} writable ancestor rejected")
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(f"{label} must be one regular non-hardlinked file")
    if before.st_uid not in allowed_uids or before.st_gid not in {0, owner_gid}:
        fail(f"{label} ownership is not reviewed")
    if before.st_size <= 0 or before.st_size > limit:
        fail(f"{label} size is outside the accepted range")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if identity(before) != identity(opened):
            fail(f"{label} changed before open")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(fd, min(1024 * 1024, limit + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > limit:
                fail(f"{label} exceeds its size limit")
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            fail(f"{label} changed while read")
    finally:
        os.close(fd)
    if identity(after) != identity(path.lstat()):
        fail(f"{label} changed after read")
    return b"".join(chunks)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if type(value) is not str or not value:
        fail(f"invalid string field: {key}")
    return value


def exact_int(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int:
        fail(f"invalid integer field: {key}")
    return value


def decode_base64(value: str, label: str, maximum: int) -> bytes:
    try:
        data = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        fail(f"invalid base64 for {label}: {exc}")
    if not data or len(data) > maximum:
        fail(f"decoded {label} size is outside the accepted range")
    return data


def verify_signature(authority: dict[str, object], issuance: dict[str, object]) -> None:
    openssl = Path("/usr/bin/openssl")
    for candidate in (Path("/usr"), Path("/usr/bin"), openssl):
        info = candidate.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or (
                candidate == openssl
                and (not stat.S_ISREG(info.st_mode) or not stat.S_IMODE(info.st_mode) & 0o111)
            )
            or (candidate != openssl and not stat.S_ISDIR(info.st_mode))
        ):
            fail("platform signature verifier custody mismatch")
    public_key = decode_base64(text(authority, "public_key_pem_base64"), "authority public key", 16 * 1024)
    signature = decode_base64(text(issuance, "signature_base64"), "issuance signature", 1024)
    signed = dict(issuance)
    signed.pop("signature_base64", None)
    message = canonical(signed)
    with tempfile.TemporaryFile(dir="/private/tmp") as key_file, tempfile.TemporaryFile(dir="/private/tmp") as signature_file:
        key_file.write(public_key)
        signature_file.write(signature)
        key_file.flush()
        signature_file.flush()
        os.lseek(key_file.fileno(), 0, os.SEEK_SET)
        os.lseek(signature_file.fileno(), 0, os.SEEK_SET)
        completed = subprocess.run(
            [
                "/usr/bin/openssl", "dgst", "-sha256", "-verify",
                f"/dev/fd/{key_file.fileno()}", "-signature",
                f"/dev/fd/{signature_file.fileno()}",
            ],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": "/var/root", "TMPDIR": "/private/tmp",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null",
            },
            pass_fds=(key_file.fileno(), signature_file.fileno()),
            close_fds=True,
            timeout=10,
            check=False,
        )
    if completed.returncode != 0 or completed.stdout.strip() != b"Verified OK":
        fail("Go custody issuance signature verification failed")


def verify_release_python() -> None:
    protected_root = Path("/Library/WinsVPN/ReleasePython/3.14.7")
    for candidate in (release_python, release_python_bin):
        info = candidate.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or not stat.S_IMODE(info.st_mode) & 0o111
            or not int(getattr(info, "st_flags", 0)) & sf_immutable
        ):
            fail("release Python executable custody mismatch")
        current = candidate.parent
        while current != protected_root.parent:
            parent_info = current.lstat()
            if (
                stat.S_ISLNK(parent_info.st_mode)
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0
                or parent_info.st_gid != 0
                or stat.S_IMODE(parent_info.st_mode) & 0o022
                or not int(getattr(parent_info, "st_flags", 0)) & sf_immutable
            ):
                fail(f"release Python protected ancestor custody mismatch: {current}")
            current = current.parent
    for current in (Path("/Library"), Path("/Library/WinsVPN"), protected_root.parent):
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            fail(f"release Python outer ancestor custody mismatch: {current}")


def safe_parent(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"unsafe bootstrap ancestor: {current}")
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            fail(f"writable or foreign bootstrap ancestor: {current}")


def verify_authority() -> dict[str, object]:
    for current in (authority_prefix.parent, authority_prefix):
        info = current.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or not int(getattr(info, "st_flags", 0)) & sf_immutable
        ):
            fail(f"Go custody authority ancestor mismatch: {current}")
    info = authority_path.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) != 0o444
        or not int(getattr(info, "st_flags", 0)) & sf_immutable
    ):
        fail("Go custody authority file custody mismatch")
    data = bind(authority_path, 64 * 1024, "Go custody authority", {0})
    authority = json.loads(data, object_pairs_hook=json_object)
    if type(authority) is not dict or data != canonical(authority):
        fail("Go custody authority must be one canonical JSON object")
    expected = {
        "contract", "schema_version", "key_id", "signature_algorithm",
        "public_key_pem_base64", "active_issuance_id", "active_sequence",
        "not_before_utc",
    }
    if set(authority) != expected:
        fail("Go custody authority field set mismatch")
    if authority.get("contract") != "winsvpn-go-archive-custody-authority-v1" or authority.get("schema_version") != 1:
        fail("Go custody authority contract mismatch")
    if authority.get("signature_algorithm") != signature_algorithm:
        fail("Go custody authority signature algorithm mismatch")
    public_key = decode_base64(text(authority, "public_key_pem_base64"), "authority public key", 16 * 1024)
    if not public_key.startswith(b"-----BEGIN PUBLIC KEY-----\n") or not public_key.endswith(b"-----END PUBLIC KEY-----\n") or b"PRIVATE KEY" in public_key:
        fail("Go custody authority must contain one PEM public key")
    if text(authority, "key_id") != sha(public_key):
        fail("Go custody authority key_id mismatch")
    active_id = text(authority, "active_issuance_id")
    if issuance_id_re.fullmatch(active_id) is None or active_id == "0" * 32:
        fail("Go custody authority active issuance identity is invalid")
    if exact_int(authority, "active_sequence") <= 0:
        fail("Go custody authority active sequence is invalid")
    if iso_utc_re.fullmatch(text(authority, "not_before_utc")) is None:
        fail("Go custody authority not_before_utc is invalid")
    return authority


def write_bound(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short bootstrap write")
            view = view[written:]
        os.fsync(fd)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)


def publish_exclusive(staging: Path, destination: Path) -> None:
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.renameatx_np.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.renameatx_np.restype = ctypes.c_int
    if libc.renameatx_np(-2, os.fsencode(staging), -2, os.fsencode(destination), 0x00000004) != 0:
        error = ctypes.get_errno()
        fail(f"exclusive sealed-bootstrap publication failed: {os.strerror(error)}")


def seal_tree(root: Path) -> None:
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            path = base_path / name
            if path.is_symlink():
                fail("sealed bootstrap symbolic link rejected")
            os.chflags(path, sf_immutable, follow_symlinks=False)
        os.chflags(base_path, sf_immutable, follow_symlinks=False)


def xattr_names(path: Path, label: str) -> list[bytes]:
    if hasattr(os, "listxattr"):
        names = [os.fsencode(name) for name in os.listxattr(path, follow_symlinks=False)]
    else:
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.listxattr.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_int,
        ]
        libc.listxattr.restype = ctypes.c_ssize_t
        encoded = os.fsencode(path)
        size = libc.listxattr(encoded, None, 0, 0x0001)
        if size < 0:
            error = ctypes.get_errno()
            fail(f"sealed bootstrap xattr inspection failed: {label}: {os.strerror(error)}")
        if size == 0:
            names = []
        else:
            buffer = ctypes.create_string_buffer(size)
            observed = libc.listxattr(encoded, buffer, size, 0x0001)
            if observed < 0 or observed != size:
                error = ctypes.get_errno()
                fail(f"sealed bootstrap xattr inspection changed: {label}: {os.strerror(error)}")
            names = [name for name in buffer.raw[:observed].split(b"\0") if name]
    return names


def clear_injected_provenance(root: Path) -> None:
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.removexattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    libc.removexattr.restype = ctypes.c_int
    paths = [root]
    for base, directories, files in os.walk(root, topdown=False, followlinks=False):
        base_path = Path(base)
        for name in files + directories:
            paths.append(base_path / name)
    for path in paths:
        if path.is_symlink():
            fail("sealed bootstrap symbolic link rejected before metadata normalization")
        label = str(path.relative_to(root)) if path != root else "."
        names = xattr_names(path, label)
        unexpected = [name for name in names if name != b"com.apple.provenance"]
        if unexpected:
            fail(f"sealed bootstrap extended attributes rejected: {label}")
        if b"com.apple.provenance" in names:
            if libc.removexattr(os.fsencode(path), b"com.apple.provenance", 0x0001) != 0:
                error = ctypes.get_errno()
                if error not in (errno.EPERM, errno.EACCES):
                    fail(f"sealed bootstrap provenance normalization failed: {label}: {os.strerror(error)}")
        remaining = xattr_names(path, label)
        if any(name != b"com.apple.provenance" for name in remaining):
            fail(f"sealed bootstrap extended attributes remain after normalization: {label}")


def reject_metadata(path: Path, label: str) -> None:
    if any(name != b"com.apple.provenance" for name in xattr_names(path, label)):
        fail(f"sealed bootstrap extended attributes rejected: {label}")
    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
    libc.acl_get_link_np.restype = ctypes.c_void_p
    libc.acl_free.argtypes = [ctypes.c_void_p]
    libc.acl_free.restype = ctypes.c_int
    acl = libc.acl_get_link_np(os.fsencode(path), 0x00000100)
    if acl:
        libc.acl_free(acl)
        fail(f"sealed bootstrap ACL rejected: {label}")


def verify_sealed_bootstrap(
    destination: Path,
    expected: dict[str, bytes],
    receipt_data: bytes,
) -> None:
    safe_parent(destination / "placeholder")
    root_info = destination.lstat()
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        fail("sealed bootstrap directory type mismatch")
    if (
        root_info.st_uid != 0
        or root_info.st_gid != 0
        or stat.S_IMODE(root_info.st_mode) != 0o555
        or not int(getattr(root_info, "st_flags", 0)) & sf_immutable
    ):
        fail("sealed bootstrap directory ownership, mode, or SF_IMMUTABLE mismatch")
    reject_metadata(destination, ".")
    names = set(expected) | {"bootstrap-receipt.json"}
    if {entry.name for entry in os.scandir(destination)} != names:
        fail("sealed bootstrap entry set mismatch")
    for name in sorted(expected):
        path = destination / name
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_dev != root_info.st_dev
            or stat.S_IMODE(info.st_mode) != 0o444
            or not int(getattr(info, "st_flags", 0)) & sf_immutable
        ):
            fail(f"sealed bootstrap file custody mismatch: {name}")
        reject_metadata(path, name)
        if bind(path, 128 * 1024 * 1024, name, {0}) != expected[name]:
            fail(f"sealed bootstrap file bytes mismatch: {name}")
    receipt_path = destination / "bootstrap-receipt.json"
    receipt_info = receipt_path.lstat()
    if (
        stat.S_ISLNK(receipt_info.st_mode)
        or not stat.S_ISREG(receipt_info.st_mode)
        or receipt_info.st_nlink != 1
        or receipt_info.st_uid != 0
        or receipt_info.st_gid != 0
        or receipt_info.st_dev != root_info.st_dev
        or stat.S_IMODE(receipt_info.st_mode) != 0o444
        or not int(getattr(receipt_info, "st_flags", 0)) & sf_immutable
    ):
        fail("sealed bootstrap receipt custody mismatch")
    reject_metadata(receipt_path, "bootstrap receipt")
    if bind(receipt_path, 64 * 1024, "bootstrap receipt", {0}) != receipt_data:
        fail("sealed bootstrap receipt bytes mismatch")


def remove_staging(staging: Path) -> None:
    if not staging.exists():
        return
    if staging.parent != bootstrap_parent or not staging.name.startswith(".bootstrap."):
        fail("refusing bootstrap cleanup outside staging prefix")
    for base, directories, files in os.walk(staging, topdown=False, followlinks=False):
        base_path = Path(base)
        base_path.chmod(0o700)
        for name in files:
            path = base_path / name
            path.chmod(0o600)
            path.unlink()
        for name in directories:
            path = base_path / name
            path.chmod(0o700)
            path.rmdir()
    staging.rmdir()


try:
    verify_release_python()
    if manifest_path != tools / manifest_name or provisioner_path != tools / provisioner_name:
        fail("replacement provisioning input cannot self-authorize")
    try:
        issuance_path.resolve(strict=False).relative_to(repo.resolve(strict=False))
    except ValueError:
        pass
    else:
        fail("external issuance must not be inside the candidate repository")
    issuance_info = issuance_path.lstat()
    if stat.S_IMODE(issuance_info.st_mode) != 0o444:
        fail("external issuance must be mode 0444")
    authority = verify_authority()
    issuance_data = bind(issuance_path, 64 * 1024, "Go custody issuance", {0, owner_uid})
    issuance = json.loads(issuance_data, object_pairs_hook=json_object)
    if type(issuance) is not dict or issuance_data != canonical(issuance):
        fail("Go custody issuance must be one canonical JSON object")
    expected_issuance = {
        "contract", "schema_version", "issuance_id", "sequence", "created_utc",
        "expires_utc", "issuer", "authority_key_id", "signature_algorithm",
        "controller", "wrapper", "provisioner", "manifest", "trust_anchor",
        "source_freeze_producer", "controller_sha256", "wrapper_sha256",
        "provisioner_sha256", "manifest_sha256", "trust_anchor_sha256",
        "source_freeze_producer_sha256", "signature_base64",
    }
    if set(issuance) != expected_issuance:
        fail("Go custody issuance field set mismatch")
    if issuance.get("contract") != "winsvpn-go-archive-custody-issuance-v2":
        fail("Go custody issuance contract mismatch")
    if issuance.get("schema_version") != 2:
        fail("Go custody issuance schema mismatch")
    if issuance.get("issuer") != "winsvpn-go-archive-custody":
        fail("Go custody issuance issuer mismatch")
    issuance_id = text(issuance, "issuance_id")
    if issuance_id_re.fullmatch(issuance_id) is None or issuance_id == "0" * 32:
        fail("Go custody issuance identity is invalid")
    if issuance_id != text(authority, "active_issuance_id") or exact_int(issuance, "sequence") != exact_int(authority, "active_sequence"):
        fail("Go custody issuance is replayed or inactive")
    if text(issuance, "authority_key_id") != text(authority, "key_id") or issuance.get("signature_algorithm") != signature_algorithm:
        fail("Go custody issuance authority mismatch")
    created_text = text(issuance, "created_utc")
    expires_text = text(issuance, "expires_utc")
    if iso_utc_re.fullmatch(created_text) is None or iso_utc_re.fullmatch(expires_text) is None:
        fail("Go custody issuance timestamp format is invalid")
    created = dt.datetime.strptime(created_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    expires = dt.datetime.strptime(expires_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    not_before = dt.datetime.strptime(text(authority, "not_before_utc"), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    now = dt.datetime.now(dt.timezone.utc)
    if created < not_before or created > now + dt.timedelta(minutes=5) or now - created > dt.timedelta(hours=72) or expires <= now:
        fail("Go custody issuance is stale or future-dated")
    if expires <= created or expires - created > dt.timedelta(hours=72):
        fail("Go custody issuance validity interval is invalid")
    verify_signature(authority, issuance)
    paths = {
        "controller": (controller_name, 2 * 1024 * 1024),
        "wrapper": (wrapper_name, 2 * 1024 * 1024),
        "provisioner": (provisioner_name, 2 * 1024 * 1024),
        "manifest": (manifest_name, 1024 * 1024),
        "trust_anchor": (trust_name, 64 * 1024),
        "source_freeze_producer": (freeze_name, 4 * 1024 * 1024),
    }
    bound: dict[str, bytes] = {}
    for key, (name, limit) in paths.items():
        if issuance.get(key) != f"tools/{name}":
            fail(f"Go custody issuance path mismatch: {key}")
        data = bind(tools / name, limit, f"Go custody {key}", {0, owner_uid})
        expected_sha = text(issuance, f"{key}_sha256")
        if hex_re.fullmatch(expected_sha) is None or sha(data) != expected_sha:
            fail(f"Go custody issuance digest mismatch: {key}")
        bound[name] = data
    manifest = json.loads(bound[manifest_name], object_pairs_hook=json_object)
    if type(manifest) is not dict or type(manifest.get("tools")) is not dict:
        fail("Go pin manifest structure is invalid")
    go = manifest["tools"].get("go")
    if type(go) is not dict:
        fail("Go pin manifest tools.go is invalid")
    version = text(go, "version")
    if re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is None:
        fail("Go version is not an exact stable dotted release")
    if go.get("platform") != "darwin-arm64" or go.get("architecture") != "arm64" or go.get("archive_format") != "tar.gz":
        fail("Go platform pin is not the reviewed macOS arm64 archive")
    if go.get("top_level_root") != "go" or go.get("executable") != "bin/go":
        fail("Go root or executable pin mismatch")
    archive_paths = go.get("archive_path")
    archive_hashes = go.get("archive_sha256")
    tree_hashes = go.get("install_tree_sha256")
    if type(archive_paths) is not dict or type(archive_hashes) is not dict or type(tree_hashes) is not dict:
        fail("Go platform mappings are invalid")
    declared_archive_path = Path(text(archive_paths, "darwin_arm64"))
    archive_name = f"go{version}.darwin-arm64.tar.gz"
    if not declared_archive_path.is_absolute() or declared_archive_path.name != archive_name:
        fail("Go archive basename does not match the exact version")
    archive_sha = text(archive_hashes, "darwin_arm64")
    tree_sha = text(tree_hashes, "darwin_arm64")
    executable_sha = text(go, "executable_sha256")
    for label, digest in (("archive", archive_sha), ("tree", tree_sha), ("executable", executable_sha)):
        if hex_re.fullmatch(digest) is None:
            fail(f"invalid Go {label} digest")
    archive_path = (
        Path("/Library/WinsVPN/ReleaseGoInputs/sha256")
        / archive_sha
        / archive_name
    )
    archive_info = archive_path.lstat()
    if (
        stat.S_IMODE(archive_info.st_mode) != 0o444
        or archive_info.st_uid != 0
        or archive_info.st_gid != 0
        or not int(getattr(archive_info, "st_flags", 0)) & sf_immutable
    ):
        fail("Go archive must be root-owned mode 0444 and SF_IMMUTABLE before owner provisioning")
    archive_data = bind(archive_path, 128 * 1024 * 1024, "Go archive", {0})
    if sha(archive_data) != archive_sha:
        fail("Go archive digest mismatch")
    if mode == "preflight":
        print("release-go provision: signed preflight accepted")
        raise SystemExit(0)
    materials = {
        "controller_sha256": sha(bound[controller_name]),
        "wrapper_sha256": sha(bound[wrapper_name]),
        "provisioner_sha256": sha(bound[provisioner_name]),
        "manifest_sha256": sha(bound[manifest_name]),
        "trust_anchor_sha256": sha(bound[trust_name]),
        "source_freeze_producer_sha256": sha(bound[freeze_name]),
    }
    payload = "".join(f"{key}={materials[key]}\n" for key in sorted(materials))
    payload += "".join(
        f"{key}={value}\n"
        for key, value in (
            ("version", version),
            ("archive_sha", archive_sha),
            ("tree_sha", tree_sha),
            ("executable_sha", executable_sha),
        )
    )
    bootstrap_identity = hashlib.sha256(payload.encode("ascii")).hexdigest()
    destination = bootstrap_parent / bootstrap_identity
    receipt: dict[str, object] = {
        "contract": "winsvpn-go-sealed-bootstrap-v1",
        "schema_version": 1,
        "identity": bootstrap_identity,
        "path": str(destination),
        "version": version,
        "archive_name": archive_name,
        "archive_size": len(archive_data),
        "archive_sha256": archive_sha,
        "tree_sha256": tree_sha,
        "executable": "bin/go",
        "executable_sha256": executable_sha,
        **materials,
    }
    receipt_data = canonical(receipt)
    expected_bootstrap = {**bound, archive_name: archive_data}
    if not bootstrap_parent.exists():
        parent = bootstrap_parent.parent
        safe_parent(parent / "placeholder")
        bootstrap_parent.mkdir(mode=0o755)
        os.chown(bootstrap_parent, 0, 0)
        bootstrap_parent.chmod(0o755)
    safe_parent(destination)
    if destination.exists() or destination.is_symlink():
        verify_sealed_bootstrap(destination, expected_bootstrap, receipt_data)
    else:
        staging = Path(tempfile.mkdtemp(prefix=".bootstrap.", dir=str(bootstrap_parent)))
        published = False
        try:
            os.chown(staging, 0, 0)
            staging.chmod(0o700)
            for name, data in bound.items():
                write_bound(staging / name, data)
            write_bound(staging / archive_name, archive_data)
            write_bound(staging / "bootstrap-receipt.json", receipt_data)
            staging.chmod(0o555)
            publish_exclusive(staging, destination)
            published = True
            clear_injected_provenance(destination)
            seal_tree(destination)
            verify_sealed_bootstrap(destination, expected_bootstrap, receipt_data)
        finally:
            if not published:
                remove_staging(staging)
    sealed_controller = destination / controller_name
    source = bind(
        sealed_controller,
        2 * 1024 * 1024,
        "sealed Go controller",
        {0},
    )
    if sha(source) != materials["controller_sha256"]:
        fail("sealed Go controller digest mismatch before execution")
    os.environ.clear()
    os.environ.update(
        {
            "HOME": "/var/root",
            "TMPDIR": "/private/tmp",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "WINS_GO_CUSTODY_ISSUANCE": str(issuance_path),
            "SUDO_UID": str(owner_uid),
            "SUDO_GID": str(owner_gid),
        }
    )
    sys.argv = [str(sealed_controller), "provision", str(repo), str(manifest_path), str(provisioner_path)]
    namespace = {"__name__": "__main__", "__file__": str(sealed_controller)}
    exec(compile(source, str(sealed_controller), "exec"), namespace)
except (OSError, ValueError, KeyError, json.JSONDecodeError, Refused) as exc:
    print(f"release-go provision: {exc}", file=sys.stderr)
    raise SystemExit(1)
# WINS_GO_ROOT_LOADER_END
PY
