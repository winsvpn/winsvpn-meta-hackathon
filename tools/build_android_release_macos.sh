#!/bin/bash -p
case "$-" in
  *p*) ;;
  *) printf 'ANDROID MACOS RELEASE BUILD ERROR: invoke with /bin/bash -p\n' >&2; exit 126 ;;
esac
unset BASH_ENV ENV CDPATH GLOBIGNORE
export -n WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS \
  WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD 2>/dev/null || true
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
set -Eeuo pipefail
# A caller may invoke this producer with `bash -x` or inherit xtrace through
# SHELLOPTS. Disable it before the first signing variable is inspected, loaded,
# exported, or passed to a subprocess. Release passwords must never become an
# execution transcript.
case "$-" in *x*) set +x ;; esac
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

die() {
  printf 'ANDROID MACOS RELEASE BUILD ERROR: %s\n' "$*" >&2
  exit 65
}

readonly REQUIRED_OPEN_FILES=131072
SOFT_OPEN_FILES="$(ulimit -Sn)" ||
  die "cannot read the open-file soft limit"
readonly SOFT_OPEN_FILES
[[ "${SOFT_OPEN_FILES}" == unlimited || "${SOFT_OPEN_FILES}" =~ ^[0-9]+$ ]] ||
  die "unexpected open-file soft limit: ${SOFT_OPEN_FILES}"
if [[ "${SOFT_OPEN_FILES}" != unlimited ]] && (( SOFT_OPEN_FILES < REQUIRED_OPEN_FILES )); then
  ulimit -Sn "${REQUIRED_OPEN_FILES}" 2>/dev/null ||
    die "cannot raise the open-file soft limit to ${REQUIRED_OPEN_FILES} (soft ${SOFT_OPEN_FILES}, hard $(ulimit -Hn))"
fi

PIN_PYTHON_BIN="/usr/bin/python3"
# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this producer from every other build. Also makes the
# default managed-toolchain path follow the pin rather than embedding the
# version in a path. Fail loudly so a missing pin file or parser never
# selects an unreviewed toolchain silently.
read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  local pin_python_bin="${PIN_PYTHON_BIN:-/usr/bin/python3}"
  [[ -f "${pin_python_bin}" && -x "${pin_python_bin}" && ! -L "${pin_python_bin}" ]] || {
    printf 'TOOLCHAIN PIN ERROR: %s is required to read %s.\n' \
      "${pin_python_bin}" \
      "${ROOT}/tools/toolchain-pins.json" >&2
    exit 65
  }
  [[ -f "${ROOT}/tools/toolchain-pins.json" ]] || {
    printf 'TOOLCHAIN PIN ERROR: %s does not exist; cannot resolve %s.\n' \
      "${ROOT}/tools/toolchain-pins.json" "${pin_key}" >&2
    exit 65
  }
  "${pin_python_bin}" - "${ROOT}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"
REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"
REQUIRED_DART_VERSION="$(read_wins_toolchain_pin tools.flutter.dart_version)"
REQUIRED_PYTHON_VERSION="$(read_wins_toolchain_pin tools.python.version)"
REQUIRED_PYTHON_IMPLEMENTATION="$(read_wins_toolchain_pin tools.python.implementation)"
REQUIRED_GO_VERSION="$(read_wins_toolchain_pin tools.go.version)"

RELEASE_PYTHON_WORK=""
RELEASE_PYTHON_WORK_PARENT=""
RELEASE_PYTHON_VENDOR=""
RELEASE_PYTHON_EXECUTABLE_PIN_SHA256=""

read_pinned_release_python_executable() {
  "${PIN_PYTHON_BIN}" -I -S - "${ROOT}/tools/toolchain-pins.json" "${1:?read_pinned_release_python_executable: missing platform key}" <<'PY'
import json
import re
import sys


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


platform_key = sys.argv[2]
try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        python = json.load(handle, object_pairs_hook=reject_duplicates)["tools"]["python"]
    path = python["reviewed_executable_path"][platform_key]
    digest = python["executable_sha256"][platform_key]
except (OSError, KeyError, TypeError, ValueError) as error:
    raise SystemExit(
        f"tools/toolchain-pins.json lacks the {platform_key} release Python path or SHA-256: {error}"
    )
if not isinstance(path, str) or not path.startswith("/") or "|" in path or "\n" in path:
    raise SystemExit("reviewed release Python executable path pin is malformed")
if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
    raise SystemExit("reviewed release Python executable SHA-256 pin is malformed")
print(path, digest, sep="|")
PY
}

# Pinned release Python. tools/toolchain-pins.json names this host's reviewed
# interpreter with its SHA-256 and the runtime wheels with theirs. The
# interpreter must be that exact regular file and report the pinned
# implementation and version. Each runtime wheel is read once into memory,
# compared with its pin, and only those held bytes are extracted into a private
# vendor directory that is then made read-only. wins_release_python_run runs
# the pinned interpreter with that vendor directory as its only import root.
prepare_pinned_release_python() {
  local platform_key pins python_path python_sha256 observed identity parent
  [[ -z "${RELEASE_PYTHON_WORK}" ]] || die 'Pinned release Python was already prepared.'
  platform_key="$(toolchain_platform_key)"
  pins="$(read_pinned_release_python_executable "${platform_key}")" \
    || die 'tools/toolchain-pins.json does not pin a release Python executable for this host.'
  IFS='|' read -r python_path python_sha256 <<<"${pins}"
  [[ -f "${python_path}" && -x "${python_path}" && ! -L "${python_path}" ]] \
    || die "Pinned release Python must be a regular non-symlink executable: ${python_path}"
  observed="$(custody_regular_file_sha256 "${python_path}")" \
    || die "Pinned release Python executable could not be hashed: ${python_path}"
  [[ "${observed}" == "${python_sha256}" ]] \
    || die "Pinned release Python executable does not match tools/toolchain-pins.json: observed=${observed} pin=${python_sha256}."
  identity="$(/usr/bin/env -i HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" PATH="${PATH}" \
    "${python_path}" -I -S -c 'import platform,sys; print(f"{platform.python_implementation().lower()}|{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')" \
    || die 'Pinned release Python did not report its identity.'
  [[ "${identity}" == "${REQUIRED_PYTHON_IMPLEMENTATION}|${REQUIRED_PYTHON_VERSION}" ]] \
    || die "Pinned release Python identity mismatch: observed=${identity} pin=${REQUIRED_PYTHON_IMPLEMENTATION}|${REQUIRED_PYTHON_VERSION}."
  parent="${TMPDIR:-/private/tmp}"
  parent="$(cd "${parent}" && pwd -P)" || die 'TMPDIR is not a usable directory.'
  RELEASE_PYTHON_WORK_PARENT="${parent}"
  RELEASE_PYTHON_WORK="$(/usr/bin/mktemp -d "${parent}/wins-android-release-python.XXXXXX")" \
    || die 'Could not create a private release Python work directory.'
  /bin/chmod 0700 "${RELEASE_PYTHON_WORK}"
  "${PIN_PYTHON_BIN}" -I -S - "${ROOT}/tools/toolchain-pins.json" "${platform_key}" \
    "${RELEASE_PYTHON_WORK}/vendor" <<'PY' || die 'Pinned release Python runtime wheels could not be authenticated and extracted.'
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile

pins_path, platform_key, vendor = sys.argv[1:4]
HOST_PLATFORM_ARCHES = dict(
    darwin_arm64=("arm64", "universal2"),
    darwin_amd64=("x86_64", "intel", "universal2"),
)
STARTUP_HOOKS = ("sitecustomize.py", "usercustomize.py")


def fail(message):
    raise SystemExit(f"release Python wheel refused: {message}")


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def platform_tag_runs_here(tag):
    for single in tag.split("."):
        if single == "any":
            return True
        match = re.fullmatch(r"macosx_\d+_\d+_([a-z0-9_]+)", single)
        if match and match.group(1) in HOST_PLATFORM_ARCHES[platform_key]:
            return True
    return False


def hold_wheel(path, expected):
    if (
        not isinstance(path, str)
        or not path.startswith("/")
        or path.startswith("//")
        or path != os.path.normpath(path)
        or "\x00" in path
    ):
        fail(f"unsafe wheel path: {path!r}")
    parts = path.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        fail(f"unsafe wheel path: {path!r}")
    common_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    directory_flags = common_flags | os.O_DIRECTORY
    file_flags = common_flags | getattr(os, "O_NONBLOCK", 0)

    def identity(info, leaf):
        value = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)
        if leaf:
            value += (
                info.st_nlink,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
            )
        return value

    descriptors = []
    identities = []
    try:
        descriptors.append(os.open("/", directory_flags))
        for index, part in enumerate(parts):
            leaf = index == len(parts) - 1
            descriptors.append(
                os.open(
                    part,
                    file_flags if leaf else directory_flags,
                    dir_fd=descriptors[-1],
                )
            )
        for index, descriptor in enumerate(descriptors):
            leaf = index == len(descriptors) - 1
            info = os.fstat(descriptor)
            mode = stat.S_IMODE(info.st_mode)
            if info.st_uid not in (0, os.getuid()):
                fail(f"untrusted wheel path owner: {path}")
            if leaf:
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or mode & 0o022
                ):
                    fail(f"unsafe wheel file type, link count or permissions: {path}")
            elif (
                not stat.S_ISDIR(info.st_mode)
                or (
                    mode & 0o022
                    and not (info.st_uid == 0 and mode & stat.S_ISVTX)
                )
            ):
                fail(f"unsafe wheel ancestor: {path}")
            identities.append(identity(info, leaf))
        chunks = []
        while True:
            chunk = os.read(descriptors[-1], 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        for index, descriptor in enumerate(descriptors):
            leaf = index == len(descriptors) - 1
            named = (
                os.lstat("/")
                if index == 0
                else os.stat(
                    parts[index - 1],
                    dir_fd=descriptors[index - 1],
                    follow_symlinks=False,
                )
            )
            if (
                identity(os.fstat(descriptor), leaf) != identities[index]
                or identity(named, leaf) != identities[index]
            ):
                fail(f"wheel path or file changed while read: {path}")
        data = b"".join(chunks)
        observed = hashlib.sha256(data).hexdigest()
        if observed != expected:
            fail(f"SHA-256 mismatch for {path}: observed={observed} pin={expected}")
        return data
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def member_parts(info):
    name = info.filename
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        fail(f"unsafe member name {name!r}")
    stripped = name[:-1] if info.is_dir() else name
    parts = stripped.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"traversal member name {name!r}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        fail(f"symlink member {name!r}")
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
        fail(f"special member {name!r}")
    lowered = parts[-1].lower()
    if not info.is_dir() and (lowered.endswith(".pth") or lowered in STARTUP_HOOKS):
        fail(f"Python startup hook member {name!r}")
    return parts, mode


try:
    with open(pins_path, encoding="utf-8") as handle:
        custody = json.load(handle, object_pairs_hook=reject_duplicates)["tools"]["python"][
            "archive_custody"
        ][platform_key]
    count = custody["runtime_wheel_count"]
    wheels = custody["wheels"]
except (OSError, KeyError, TypeError, ValueError) as error:
    fail(f"tools/toolchain-pins.json lacks {platform_key} runtime wheel pins: {error}")
if platform_key not in HOST_PLATFORM_ARCHES:
    fail(f"unsupported host platform {platform_key}")
if not isinstance(count, int) or isinstance(count, bool) or count < 1 or not isinstance(wheels, dict):
    fail("runtime_wheel_count or wheels pin is malformed")
os.mkdir(vendor, 0o700)
for index in range(count):
    try:
        pin = wheels[str(index)]
        path = pin["path"]
        expected = pin["sha256"]
    except (KeyError, TypeError) as error:
        fail(f"wheel {index} pin is missing: {error}")
    if not isinstance(path, str) or not path.startswith("/"):
        fail(f"wheel {index} path pin is malformed")
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        fail(f"wheel {index} SHA-256 pin is malformed")
    leaf = os.path.basename(path)
    fields = leaf[:-4].split("-") if leaf.endswith(".whl") else []
    if len(fields) not in (5, 6):
        fail(f"wheel {index} file name is not a wheel name: {leaf}")
    if not platform_tag_runs_here(fields[-1]):
        fail(f"wheel {index} platform tag {fields[-1]} cannot run on {platform_key}")
    data = hold_wheel(path, expected)
    seen = set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if not members:
            fail(f"empty wheel {leaf}")
        planned = []
        for info in members:
            if info.filename in seen:
                fail(f"duplicate member {info.filename!r} in {leaf}")
            seen.add(info.filename)
            planned.append((info,) + member_parts(info))
        for info, parts, mode in planned:
            destination = os.path.join(vendor, *parts)
            if info.is_dir():
                os.makedirs(destination, 0o700, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(destination), 0o700, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(destination, flags, 0o600)
            except FileExistsError:
                fail(f"wheel file collision {info.filename!r} from {leaf}")
            with os.fdopen(fd, "wb") as handle:
                handle.write(archive.read(info))
            if mode & 0o111:
                os.chmod(destination, 0o700)
for current, directories, files in os.walk(vendor, topdown=False):
    for name in files:
        path = os.path.join(current, name)
        os.chmod(path, 0o555 if os.lstat(path).st_mode & 0o100 else 0o444)
    for name in directories:
        os.chmod(os.path.join(current, name), 0o555)
os.chmod(vendor, 0o555)
PY
  RELEASE_PYTHON_VENDOR="${RELEASE_PYTHON_WORK}/vendor"
  RELEASE_PYTHON_EXECUTABLE_PIN_SHA256="${python_sha256}"
  PYTHON_BIN="${python_path}"
  export PYTHON_BIN
}

# Runs a command in an environment of exactly the NAME=value assignments that
# precede the first "--" argument and nothing else, as `env -i NAME=value command`
# does, but without ever putting a value on a command line: env would show the
# values to any process observer for as long as it runs. A bash builtin cannot give
# that guarantee on macOS bash 3.2: bash adds SHLVL, PWD and _ back at exec, a
# local variable shadows an inherited export instead of removing it, and a name
# that is not a valid identifier cannot be unexported. So env -i starts the
# bootstrap interpreter in an empty environment; the interpreter reads the
# NUL-separated assignments from a pipe and execs the command with an explicit
# environment dictionary. The pipe is its own descriptor, so standard input stays
# the caller's, and the interpreter closes it before the exec.
run_with_exact_environment() {
  local -a assignments
  local interpreter="${PIN_PYTHON_BIN:-/usr/bin/python3}"
  assignments=()
  while (( $# > 0 )) && [[ "$1" != -- ]]; do
    [[ "$1" == *=* && "${1%%=*}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || return 64
    assignments+=("$1")
    shift
  done
  [[ "${1:-}" == -- && $# -ge 2 ]] || return 64
  shift
  [[ -f "${interpreter}" && -x "${interpreter}" && ! -L "${interpreter}" ]] || {
    printf 'EXACT ENVIRONMENT ERROR: %s is required to start a command.\n' "${interpreter}" >&2
    return 69
  }
  /usr/bin/env -i "${interpreter}" -I -S -c 'import os
import sys

transport = sys.argv[1]
if not transport.startswith("/dev/fd/"):
    print("exact-environment: the assignments did not arrive on a descriptor", file=sys.stderr)
    raise SystemExit(70)
try:
    with os.fdopen(int(transport[len("/dev/fd/"):]), "rb") as pipe:
        data = pipe.read()
except (OSError, ValueError):
    print("exact-environment: the assignments could not be read", file=sys.stderr)
    raise SystemExit(70)
records = data.split(b"\0")
if records[-1] != b"" or len(records) - 1 != int(sys.argv[2]):
    print("exact-environment: the assignments arrived incomplete", file=sys.stderr)
    raise SystemExit(70)
environment = {}
for record in records[:-1]:
    name, separator, value = record.partition(b"=")
    if not separator or not name:
        print("exact-environment: an assignment is malformed", file=sys.stderr)
        raise SystemExit(70)
    environment[name] = value
arguments = [os.fsencode(argument) for argument in sys.argv[3:]]
try:
    os.execvpe(arguments[0], arguments, environment)
except OSError as error:
    print("exact-environment: " + os.fsdecode(arguments[0]) + ": " + error.strerror, file=sys.stderr)
    raise SystemExit(127 if isinstance(error, FileNotFoundError) else 126)
' <(
    if (( ${#assignments[@]} > 0 )); then
      builtin printf '%s\0' "${assignments[@]}"
    fi
  ) "${#assignments[@]}" "$@"
}

# Runs the pinned interpreter in a clean environment: only HOME, TMPDIR, the
# producer's PATH, the read-only vendor directory, and the no-user-site and
# no-bytecode switches cross the boundary. The two Android signing passwords
# cross only through wins_release_python_run_with_android_privacy_secrets. The
# signer verifier keeps the isolated (-I) startup it checks for itself.
_wins_android_release_python_exec() {
  local mode="$1"
  local -a startup_flags verifier_env
  shift
  [[ -n "${RELEASE_PYTHON_VENDOR}" && -d "${RELEASE_PYTHON_VENDOR}" && -n "${PYTHON_BIN:-}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned release Python was not prepared.\n' >&2
    return 1
  }
  startup_flags=(-S)
  verifier_env=()
  # The exact release secret scan reads the inventory this path names; only
  # the path crosses, never the inventory contents.
  [[ -z "${WINS_RELEASE_SECRET_INVENTORY:-}" ]] || verifier_env+=("WINS_RELEASE_SECRET_INVENTORY=${WINS_RELEASE_SECRET_INVENTORY}")
  case "${1:-}" in
    tools/verify_android_aab_signers.py|./tools/verify_android_aab_signers.py|/*/tools/verify_android_aab_signers.py)
      startup_flags=(-I -S)
      # The signer verifier binds the pinned home JDK, the pinned bundletool
      # jar and build-tools apksigner itself; only their locations cross.
      [[ -z "${WINS_RELEASE_JAVA_HOME:-}" ]] || verifier_env+=("WINS_RELEASE_JAVA_HOME=${WINS_RELEASE_JAVA_HOME}")
      [[ -z "${WINS_BUNDLETOOL_JAR:-}" ]] || verifier_env+=("WINS_BUNDLETOOL_JAR=${WINS_BUNDLETOOL_JAR}")
      [[ -z "${ANDROID_SDK_ROOT:-}" ]] || verifier_env+=("ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}")
      ;;
  esac
  if [[ "${mode}" == android-privacy ]]; then
    [[ -n "${WINS_ANDROID_KEY_PASSWORD:-}" && -n "${WINS_ANDROID_STORE_PASSWORD:-}" ]] || {
      printf 'ANDROID MACOS RELEASE BUILD ERROR: Android privacy scan requires both signing passwords.\n' >&2
      return 1
    }
    run_with_exact_environment \
      HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" PATH="${PATH}" \
      PYTHONPATH="${RELEASE_PYTHON_VENDOR}" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
      ${verifier_env[@]+"${verifier_env[@]}"} \
      WINS_ANDROID_KEY_PASSWORD="${WINS_ANDROID_KEY_PASSWORD}" \
      WINS_ANDROID_STORE_PASSWORD="${WINS_ANDROID_STORE_PASSWORD}" \
      -- "${PYTHON_BIN}" "${startup_flags[@]}" "$@"
    return
  fi
  /usr/bin/env -i \
    HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" PATH="${PATH}" \
    PYTHONPATH="${RELEASE_PYTHON_VENDOR}" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    ${verifier_env[@]+"${verifier_env[@]}"} \
    "${PYTHON_BIN}" "${startup_flags[@]}" "$@"
}

wins_release_python_run() {
  _wins_android_release_python_exec clean "$@"
}

wins_release_python_run_with_android_privacy_secrets() {
  _wins_android_release_python_exec android-privacy "$@"
}

# Removes only the private release Python work directory this run created. The
# vendor tree is read-only, so owner write permission is restored inside that
# mktemp-owned directory before removal.
release_python_cleanup() {
  [[ -n "${RELEASE_PYTHON_WORK}" ]] || return 0
  case "${RELEASE_PYTHON_WORK}" in
    "${RELEASE_PYTHON_WORK_PARENT:-/nonexistent}"/wins-android-release-python.*)
      if [[ -d "${RELEASE_PYTHON_WORK}" && ! -L "${RELEASE_PYTHON_WORK}" ]]; then
        /bin/chmod -R u+w "${RELEASE_PYTHON_WORK}" 2>/dev/null || true
        /bin/rm -rf -- "${RELEASE_PYTHON_WORK}" || return 1
      fi
      ;;
    *)
      printf 'ANDROID MACOS RELEASE BUILD ERROR: refusing to remove an unexpected release Python work path: %s\n' \
        "${RELEASE_PYTHON_WORK}" >&2
      return 1
      ;;
  esac
  RELEASE_PYTHON_WORK=""
  RELEASE_PYTHON_VENDOR=""
}

select_reviewed_flutter() {
  local candidate explicit=''
  local -a candidates
  candidates=()
  if [[ -n "${FLUTTER_BIN+x}" ]]; then
    [[ -n "${FLUTTER_BIN}" ]] || die 'FLUTTER_BIN is set but empty.'
    explicit="${FLUTTER_BIN}"
  fi
  if [[ -n "${explicit}" ]]; then
    candidates=("${explicit}")
  else
    candidates=(
      "${HOME}/.local/toolchains/flutter-${REQUIRED_FLUTTER_VERSION}/bin/flutter"
      "${HOME}/Library/Application Support/WinsVPN/toolchains/flutter-${REQUIRED_FLUTTER_VERSION}-git/bin/flutter"
      "${HOME}/.local/flutter/bin/flutter"
    )
    candidate="$(command -v flutter 2>/dev/null || true)"
    [[ -z "${candidate}" ]] || candidates+=("${candidate}")
  fi
  for candidate in "${candidates[@]}"; do
    if [[ -f "${candidate}" && -x "${candidate}" && ! -L "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  die "Flutter ${REQUIRED_FLUTTER_VERSION} is unavailable; set FLUTTER_BIN to its regular executable."
}

select_reviewed_java_home() {
  local candidate explicit=''
  local -a candidates
  candidates=()
  if [[ -n "${JAVA_HOME+x}" ]]; then
    [[ -n "${JAVA_HOME}" ]] || die 'JAVA_HOME is set but empty.'
    explicit="${JAVA_HOME}"
  fi
  if [[ -n "${explicit}" ]]; then
    candidates=("${explicit}")
  else
    candidates=(
      "${HOME}"/.local/jdk17/jdk-17*/Contents/Home
      "${HOME}/Library/Application Support/WinsVPN/toolchains/temurin-17/Contents/Home"
    )
    if [[ -x /usr/libexec/java_home ]]; then
      candidate="$(/usr/libexec/java_home -v 17 2>/dev/null || true)"
      [[ -z "${candidate}" ]] || candidates+=("${candidate}")
    fi
  fi
  for candidate in "${candidates[@]}"; do
    if [[ -d "${candidate}" && ! -L "${candidate}" && -f "${candidate}/bin/java" \
       && -x "${candidate}/bin/java" && ! -L "${candidate}/bin/java" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  die 'Android releases require JDK 17; set JAVA_HOME to its regular current-user or system installation.'
}

toolchain_platform_key() {
  case "$(uname -m)" in
    arm64) printf 'darwin_arm64\n' ;;
    x86_64) printf 'darwin_amd64\n' ;;
    *) die "Android macOS release toolchain custody does not support architecture $(uname -m)." ;;
  esac
}

custody_regular_file_sha256() {
  "${PIN_PYTHON_BIN}" - "${1:?custody_regular_file_sha256: missing path}" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

path = pathlib.Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(path, flags)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SystemExit(f"custody file must be a single-link regular file: {path}")
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(fd)
finally:
    os.close(fd)
latest = path.lstat()
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    value.st_mode,
    value.st_nlink,
    value.st_uid,
    value.st_size,
    value.st_mtime_ns,
)
if identity(before) != identity(after) or identity(after) != identity(latest):
    raise SystemExit(f"custody file changed while it was hashed: {path}")
print(digest.hexdigest())
PY
}

normalized_toolchain_tree_sha256() {
  "${PIN_PYTHON_BIN}" - "${1:?normalized_toolchain_tree_sha256: missing root}" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
if not root.is_absolute() or root.is_symlink():
    raise SystemExit(f"toolchain root must be one absolute non-symlink directory: {root}")
root = root.resolve(strict=True)
root_info = root.lstat()
if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid not in {0, os.getuid()}:
    raise SystemExit(f"toolchain root must be a current-user or root-owned directory: {root}")
if stat.S_IMODE(root_info.st_mode) & 0o022:
    raise SystemExit(f"toolchain root must not be writable by group or other: {root}")

digest = hashlib.sha256()

def feed(*parts):
    for part in parts:
        value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

def walk(directory):
    with os.scandir(directory) as scan:
        entries = sorted(scan, key=lambda item: os.fsencode(item.name))
    for entry in entries:
        path = pathlib.Path(entry.path)
        relative = path.relative_to(root).as_posix()
        info = entry.stat(follow_symlinks=False)
        mode = stat.S_IMODE(info.st_mode)
        if info.st_uid not in {0, os.getuid()} or mode & 0o022:
            raise SystemExit(f"toolchain entry has unsafe ownership or write mode: {path}")
        if stat.S_ISDIR(info.st_mode):
            feed("D", relative, mode)
            walk(path)
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if os.path.isabs(target):
                raise SystemExit(f"toolchain symlink must remain relative: {path}")
            resolved = (path.parent / target).resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError:
                raise SystemExit(f"toolchain symlink escapes its root: {path}")
            feed("L", relative, mode, target)
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                raise SystemExit(f"toolchain file must not be hard-linked: {path}")
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(path, flags)
            try:
                before = os.fstat(fd)
                content = hashlib.sha256()
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    content.update(chunk)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            latest = path.lstat()
            identity = lambda value: (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_nlink,
                value.st_uid,
                value.st_size,
                value.st_mtime_ns,
            )
            if identity(before) != identity(after) or identity(after) != identity(latest):
                raise SystemExit(f"toolchain file changed while it was hashed: {path}")
            feed("F", relative, mode, before.st_size, content.hexdigest())
        else:
            raise SystemExit(f"toolchain tree contains an unsupported entry: {path}")

walk(root)
print(digest.hexdigest())
PY
}

read_reproducible_toolchain_custody_pin() {
  local tool_key="${1:?read_reproducible_toolchain_custody_pin: missing tool key}"
  local platform_key="${2:?read_reproducible_toolchain_custody_pin: missing platform key}"
  "${PIN_PYTHON_BIN}" - "${ROOT}/tools/toolchain-pins.json" "${tool_key}" "${platform_key}" <<'PY'
import json
import pathlib
import re
import sys

def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

path = pathlib.Path(sys.argv[1])
tool_key = sys.argv[2]
platform_key = sys.argv[3]
try:
    root = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    tool = root["tools"][tool_key]
    version = tool["version"]
    archive = tool["archive_sha256"][platform_key]
    installed = tool["install_tree_sha256"][platform_key]
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(
        f"{tool_key} custody blocker: tools/toolchain-pins.json lacks exact version, "
        f"official archive_sha256.{platform_key}, or independently reproducible "
        f"install_tree_sha256.{platform_key}: {error}"
    )
if not isinstance(version, str) or not version:
    raise SystemExit(f"{tool_key} custody blocker: version pin must be a non-empty string")
for name, value in (("archive", archive), ("installed tree", installed)):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(f"{tool_key} custody blocker: {name} SHA-256 pin is malformed")
if archive == installed:
    raise SystemExit(
        f"{tool_key} custody blocker: a receipt-declared tree hash cannot stand in "
        "for independently derived archive and installed-tree identities"
    )
print(version, archive, installed, sep="|")
PY
}

capture_one_toolchain_custody() {
  local label="$1" tool_key="$2" root="$3" runtime_version="$4"
  local pins pinned_version archive_sha256 installed_sha256 observed
  pins="$(read_reproducible_toolchain_custody_pin "${tool_key}" "${TOOLCHAIN_PLATFORM_KEY}")" \
    || die "${label} lacks independently reproducible archive-to-installed-tree custody."
  IFS='|' read -r pinned_version archive_sha256 installed_sha256 <<<"${pins}"
  [[ "${runtime_version}" == "${pinned_version}" ]] \
    || die "${label} custody version mismatch: runtime=${runtime_version:-unreported} pin=${pinned_version:-missing}."
  observed="$(normalized_toolchain_tree_sha256 "${root}")" \
    || die "${label} installed tree could not be hashed safely."
  [[ "${observed}" == "${installed_sha256}" ]] \
    || die "${label} installed tree mismatch: observed=${observed:-unreported} pin=${installed_sha256}."
  printf '%s\n' "${observed}"
}

# Pinned home Flutter and JDK (owner ruling 2026-10-09). The release Flutter
# and JDK are the current user's installs at
#   ${HOME}/.local/flutter-<tools.flutter.version>
#   ${HOME}/.local/toolchains/jdk-<tools.java.version>
# bound by version metadata and by a canonical tree digest pinned in
# tools/toolchain-pins.json: tools.java.install_tree_sha256 for the JDK and
# tools.flutter.installed_tree_sha256 for Flutter. The digest feeds, in sorted
# byte-name order, length-prefixed parts: ("D", path, 0o500) per directory,
# ("L", path, target) per symlink and ("F", path, mode, size, sha256) per file,
# with mode 0o500 when any execute bit is set and 0o400 otherwise. Flutter's
# digest skips only the runtime-mutable state listed in
# HOME_FLUTTER_RUNTIME_STATE below. Every root, ancestor and entry must be
# owned by the current user or root and must not be group or world writable
# (a root-owned sticky ancestor such as /private/tmp is allowed), files must
# not be hard-linked, and symlinks must be relative and stay inside the root.
# Flutter and the JDK tools then run directly from the verified roots with a
# scrubbed environment.
verify_home_toolchain_tree() {
  local kind="${1:?verify_home_toolchain_tree: missing kind}"
  local root="${2:?verify_home_toolchain_tree: missing root}"
  local platform_key
  platform_key="$(toolchain_platform_key)" || return 1
  "${PIN_PYTHON_BIN}" -I -S - "${ROOT}/tools/toolchain-pins.json" "${platform_key}" "${kind}" "${root}" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

pins_path, platform_key, kind, root_text = sys.argv[1:5]
HOME_FLUTTER_RUNTIME_STATE = (
    ".git",
    "bin/cache/lockfile",
    "bin/cache/flutter_version_check.stamp",
    "packages/flutter_tools/.dart_tool",
    "packages/flutter_tools/gradle/.gradle",
    "packages/flutter_tools/gradle/build",
    "packages/flutter_tools/gradle/.kotlin",
)
SHA256 = re.compile(r"[0-9a-f]{64}")


def fail(message):
    raise SystemExit(f"pinned home {kind} toolchain refused: {message}")


def reject_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def pinned_text(mapping, key, label):
    value = mapping.get(key) if isinstance(mapping, dict) else None
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        fail(f"tools/toolchain-pins.json {label} is missing or malformed")
    return value


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_size,
        info.st_mtime_ns,
    )


def hold_file(path, max_size=None):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {path}: {error}")
    chunks = []
    content = hashlib.sha256()
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            fail(f"not a single-link regular file: {path}")
        if max_size is not None and before.st_size > max_size:
            fail(f"metadata file is too large: {path}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            content.update(chunk)
            if max_size is not None:
                chunks.append(chunk)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if identity(before) != identity(after) or identity(after) != identity(os.lstat(path)):
        fail(f"file changed while it was hashed: {path}")
    return before, content.hexdigest(), b"".join(chunks)


def owner_ok(info):
    return info.st_uid in (0, os.getuid())


try:
    with open(pins_path, encoding="utf-8") as handle:
        tools = json.load(handle, object_pairs_hook=reject_duplicates)["tools"]
    if kind == "java":
        tool = tools["java"]
        version = pinned_text(tool, "version", "tools.java.version")
        expected_tree = pinned_text(
            tool["install_tree_sha256"], platform_key, f"tools.java.install_tree_sha256.{platform_key}"
        )
    elif kind == "flutter":
        tool = tools["flutter"]
        version = pinned_text(tool, "version", "tools.flutter.version")
        expected_tree = pinned_text(
            tool["installed_tree_sha256"],
            platform_key,
            f"tools.flutter.installed_tree_sha256.{platform_key}",
        )
    else:
        fail("unknown toolchain kind")
except (OSError, KeyError, TypeError, ValueError) as error:
    fail(f"tools/toolchain-pins.json lacks the {kind} pins for {platform_key}: {error}")
if SHA256.fullmatch(expected_tree) is None or expected_tree == "0" * 64:
    fail("tree SHA-256 pin is malformed")
if re.fullmatch(r"[0-9][0-9A-Za-z.+_-]*", version) is None:
    fail("version pin is not a plain version string")
expected_name = f"jdk-{version}" if kind == "java" else f"flutter-{version}"

if not os.path.isabs(root_text) or root_text != os.path.normpath(root_text):
    fail(f"toolchain root must be one normalized absolute path: {root_text}")
if os.path.basename(root_text) != expected_name:
    fail(f"toolchain root {root_text} does not name the pinned version {expected_name}")
try:
    real_root = os.path.realpath(root_text)
    root_info = os.lstat(root_text)
except OSError as error:
    fail(f"toolchain root is missing: {root_text}: {error}")
if real_root != root_text or stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
    fail(f"toolchain root must be a real directory reached without symlinks: {root_text}")
if not owner_ok(root_info) or stat.S_IMODE(root_info.st_mode) & 0o022:
    fail(f"toolchain root must be current-user or root owned and not group/world writable: {root_text}")
ancestor = os.path.dirname(root_text)
while True:
    info = os.lstat(ancestor)
    mode = stat.S_IMODE(info.st_mode)
    writable = mode & 0o022
    sticky_root = info.st_uid == 0 and mode & stat.S_ISVTX
    if not stat.S_ISDIR(info.st_mode) or not owner_ok(info) or (writable and not sticky_root):
        fail(f"toolchain ancestor is not a safe current-user or root directory: {ancestor}")
    if ancestor == "/":
        break
    ancestor = os.path.dirname(ancestor)
root = root_text

if kind == "java":
    _info, _digest, raw = hold_file(os.path.join(root, "release"), max_size=256 * 1024)
    fields = {}
    for line in raw.decode("utf-8").splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        if (
            not separator
            or re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None
            or len(value) < 2
            or value[0] != '"'
            or value[-1] != '"'
        ):
            fail("JDK release file contains a malformed field")
        if key in fields:
            fail(f"JDK release file repeats {key}")
        fields[key] = value[1:-1]
    release_name = pinned_text(tool, "release_name", "tools.java.release_name")
    if not release_name.startswith("jdk-"):
        fail("tools.java.release_name must start with jdk-")
    expected_fields = {
        "IMPLEMENTOR": pinned_text(tool, "vendor", "tools.java.vendor"),
        "JAVA_VERSION": version,
        "JAVA_RUNTIME_VERSION": release_name[len("jdk-"):],
        "OS_ARCH": pinned_text(tool, "architecture", "tools.java.architecture"),
        "IMAGE_TYPE": pinned_text(tool, "image_type", "tools.java.image_type").upper(),
    }
    for key, expected in expected_fields.items():
        if fields.get(key) != expected:
            fail(f"JDK release {key} mismatch: observed={fields.get(key)!r} pin={expected!r}")
    if fields.get("JVM_VARIANT", "").lower() != pinned_text(tool, "jvm", "tools.java.jvm").lower():
        fail("JDK release JVM_VARIANT mismatch")
    executables = ("bin/java", "bin/jarsigner", "bin/keytool")
else:
    _info, _digest, raw = hold_file(
        os.path.join(root, "bin", "cache", "flutter.version.json"), max_size=64 * 1024
    )
    try:
        metadata = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except ValueError as error:
        fail(f"bin/cache/flutter.version.json is not strict JSON: {error}")
    expected_fields = {
        "frameworkVersion": version,
        "frameworkRevision": pinned_text(tool, "revision", "tools.flutter.revision"),
        "dartSdkVersion": pinned_text(tool, "dart_version", "tools.flutter.dart_version"),
    }
    for key, expected in expected_fields.items():
        if not isinstance(metadata, dict) or metadata.get(key) != expected:
            observed = metadata.get(key) if isinstance(metadata, dict) else None
            fail(f"bin/cache/flutter.version.json {key} mismatch: observed={observed!r} pin={expected!r}")
    _info, _digest, raw = hold_file(
        os.path.join(root, "bin", "cache", "dart-sdk", "version"), max_size=4096
    )
    if raw.decode("utf-8").strip() != expected_fields["dartSdkVersion"]:
        fail("bin/cache/dart-sdk/version does not match tools.flutter.dart_version")
    executables = ("bin/flutter", "bin/cache/dart-sdk/bin/dart")
    hold_file(os.path.join(root, "bin", "cache", "flutter_tools.snapshot"))
for relative in executables:
    info = os.lstat(os.path.join(root, relative))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not stat.S_IMODE(info.st_mode) & 0o100:
        fail(f"{relative} must be a single-link regular executable file")

digest = hashlib.sha256()


def feed(*parts):
    for part in parts:
        value = str(part).encode("utf-8", "surrogateescape")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)


def skipped(relative):
    if kind != "flutter":
        return False
    return any(relative == item or relative.startswith(item + "/") for item in HOME_FLUTTER_RUNTIME_STATE)


def walk(directory):
    with os.scandir(directory) as scan:
        entries = sorted(scan, key=lambda entry: os.fsencode(entry.name))
    for entry in entries:
        path = entry.path
        relative = os.path.relpath(path, root)
        if skipped(relative):
            continue
        info = os.lstat(path)
        if not owner_ok(info):
            fail(f"entry is not owned by the current user or root: {relative}")
        if stat.S_ISDIR(info.st_mode):
            if stat.S_IMODE(info.st_mode) & 0o022:
                fail(f"entry is group or world writable: {relative}")
            feed("D", relative, 0o500)
            walk(path)
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if os.path.isabs(target):
                fail(f"symlink target is absolute: {relative}")
            resolved = os.path.realpath(os.path.join(os.path.dirname(path), target))
            if not os.path.exists(resolved) or not (resolved + "/").startswith(root + "/"):
                fail(f"symlink escapes the toolchain root or dangles: {relative}")
            feed("L", relative, target)
        elif stat.S_ISREG(info.st_mode):
            if stat.S_IMODE(info.st_mode) & 0o022:
                fail(f"entry is group or world writable: {relative}")
            if info.st_nlink != 1:
                fail(f"file is hard-linked: {relative}")
            held, content, _raw = hold_file(path)
            mode = 0o500 if stat.S_IMODE(held.st_mode) & 0o111 else 0o400
            feed("F", relative, mode, held.st_size, content)
        else:
            fail(f"unsupported entry type: {relative}")


walk(root)
observed = digest.hexdigest()
if observed != expected_tree:
    fail(f"installed tree digest mismatch: observed={observed} pin={expected_tree}")
print(observed)
PY
}

# Same calling conventions as the retired sourced custody helper, so the call
# sites below stay unchanged. Binds the pinned home roots, checks the JDK's own
# identity report, and selects the default Pub cache Flutter uses on macOS.
wins_release_android_toolchains_prepare() {
  local java_version java_release java_home flutter_root identity pub_cache
  [[ $# -eq 1 && "$1" == "${ROOT}/tools/toolchain-pins.json" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned toolchains bind only %s\n' "${ROOT}/tools/toolchain-pins.json" >&2
    return 1
  }
  [[ -z "${WINS_RELEASE_FLUTTER_ROOT:-}" && -z "${WINS_RELEASE_JAVA_HOME:-}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned Flutter/JDK were already prepared.\n' >&2
    return 1
  }
  [[ "${HOME}" == /* && "${HOME}" != *$'\n'* ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: HOME must be an absolute path.\n' >&2
    return 1
  }
  java_version="$(read_wins_toolchain_pin tools.java.version)" || return 1
  java_release="$(read_wins_toolchain_pin tools.java.release_name)" || return 1
  [[ "${java_version}" =~ ^[0-9][0-9A-Za-z.+_-]*$ && "${REQUIRED_FLUTTER_VERSION}" =~ ^[0-9][0-9A-Za-z.+_-]*$ ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: Flutter/JDK version pins are malformed.\n' >&2
    return 1
  }
  java_home="${HOME}/.local/toolchains/jdk-${java_version}"
  flutter_root="${HOME}/.local/flutter-${REQUIRED_FLUTTER_VERSION}"
  WINS_RELEASE_JAVA_TREE_SHA256="$(verify_home_toolchain_tree java "${java_home}")" || return 1
  WINS_RELEASE_FLUTTER_TREE_SHA256="$(verify_home_toolchain_tree flutter "${flutter_root}")" || return 1
  pub_cache="${HOME}/.pub-cache"
  [[ -d "${pub_cache}" && ! -L "${pub_cache}" \
     && "$(/usr/bin/stat -f '%u' "${pub_cache}")" == "$(id -u)" \
     && $(( 8#$(/usr/bin/stat -f '%Lp' "${pub_cache}") & 8#022 )) -eq 0 ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: Pub cache must be a current-user directory that is not group/world writable: %s\n' "${pub_cache}" >&2
    return 1
  }
  WINS_RELEASE_JAVA_HOME="${java_home}"
  WINS_RELEASE_FLUTTER_ROOT="${flutter_root}"
  WINS_RELEASE_FLUTTER_BIN="${flutter_root}/bin/flutter"
  WINS_RELEASE_PUB_CACHE="${pub_cache}"
  identity="$(wins_release_android_jdk_tool java -version 2>&1)" || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned JDK did not report its identity.\n' >&2
    return 1
  }
  [[ "${identity}" == *"version \"${java_version}\""* && "${identity}" == *"(build ${java_release#jdk-})"* ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned JDK identity mismatch: %s\n' "${identity}" >&2
    return 1
  }
}

# Recomputes both tree digests and compares them with the values bound by
# wins_release_android_toolchains_prepare.
wins_release_android_toolchains_verify() {
  local java_tree flutter_tree
  [[ -n "${WINS_RELEASE_JAVA_HOME:-}" && -n "${WINS_RELEASE_FLUTTER_ROOT:-}" \
     && -n "${WINS_RELEASE_JAVA_TREE_SHA256:-}" && -n "${WINS_RELEASE_FLUTTER_TREE_SHA256:-}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned Flutter/JDK were not prepared.\n' >&2
    return 1
  }
  java_tree="$(verify_home_toolchain_tree java "${WINS_RELEASE_JAVA_HOME}")" || return 1
  flutter_tree="$(verify_home_toolchain_tree flutter "${WINS_RELEASE_FLUTTER_ROOT}")" || return 1
  [[ "${java_tree}" == "${WINS_RELEASE_JAVA_TREE_SHA256}" && "${flutter_tree}" == "${WINS_RELEASE_FLUTTER_TREE_SHA256}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned Flutter/JDK tree changed after it was verified.\n' >&2
    return 1
  }
}

# Runs Flutter (the pinned Dart VM on the pinned flutter_tools snapshot, never
# the bin/flutter updater script) or one JDK tool from the verified roots. Only
# HOME, TMPDIR, a fixed PATH with the pinned JDK first, the C locale, JAVA_HOME
# and, for Flutter, its root, the Pub cache, the Android SDK root and the
# non-interactive switches cross the env -i boundary. Signing values cross only
# for `flutter build` (all four) and keytool with the store password (one).
_wins_release_android_toolchain_exec() {
  local mode="$1" flutter_root="${WINS_RELEASE_FLUTTER_ROOT:-}" java_home="${WINS_RELEASE_JAVA_HOME:-}" name
  local -a toolchain_env
  shift
  [[ -n "${flutter_root}" && -n "${java_home}" && -n "${WINS_RELEASE_PUB_CACHE:-}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: pinned Flutter/JDK were not prepared.\n' >&2
    return 1
  }
  toolchain_env=(
    "HOME=${HOME}"
    "TMPDIR=${TMPDIR:-/private/tmp}"
    "PATH=${java_home}/bin:${flutter_root}/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    "LANG=C"
    "LC_ALL=C"
    "JAVA_HOME=${java_home}"
  )
  case "${mode}" in
    flutter|flutter-build)
      toolchain_env+=(
        "CI=true"
        "FLUTTER_ROOT=${flutter_root}"
        "FLUTTER_SUPPRESS_ANALYTICS=true"
        "FLUTTER_ALREADY_LOCKED=true"
        "PUB_CACHE=${WINS_RELEASE_PUB_CACHE}"
      )
      [[ -z "${ANDROID_SDK_ROOT:-}" ]] || toolchain_env+=("ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}")
      [[ -z "${ANDROID_HOME:-}" ]] || toolchain_env+=("ANDROID_HOME=${ANDROID_HOME}")
      if [[ "${mode}" == flutter-build ]]; then
        for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
          toolchain_env+=("${name}=${!name}")
        done
      fi
      run_with_exact_environment "${toolchain_env[@]}" -- \
        "${flutter_root}/bin/cache/dart-sdk/bin/dart" \
        "${flutter_root}/bin/cache/flutter_tools.snapshot" "$@"
      ;;
    java|jarsigner|keytool)
      /usr/bin/env -i "${toolchain_env[@]}" "${java_home}/bin/${mode}" "$@"
      ;;
    keytool-store-password)
      run_with_exact_environment "${toolchain_env[@]}" \
        "WINS_ANDROID_STORE_PASSWORD=${WINS_ANDROID_STORE_PASSWORD}" -- \
        "${java_home}/bin/keytool" "$@"
      ;;
    *)
      printf 'ANDROID MACOS RELEASE BUILD ERROR: unapproved toolchain command: %s\n' "${mode}" >&2
      return 1
      ;;
  esac
}

wins_release_android_flutter() {
  _wins_release_android_toolchain_exec flutter "$@"
}

wins_release_android_flutter_build() {
  local no_pub=0 argument name value
  [[ $# -ge 1 && "$1" == build ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: usage: wins_release_android_flutter_build build [ARGS...]\n' >&2
    return 1
  }
  for argument in "$@"; do
    [[ "${argument}" != --no-pub ]] || no_pub=$((no_pub + 1))
  done
  [[ "${no_pub}" -eq 1 ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: release Flutter builds require exactly one --no-pub.\n' >&2
    return 1
  }
  [[ -n "${ANDROID_SDK_ROOT:-}" && "${ANDROID_SDK_ROOT}" == "${ANDROID_HOME:-}" \
     && "${ANDROID_SDK_ROOT}" == /* && -d "${ANDROID_SDK_ROOT}" && ! -L "${ANDROID_SDK_ROOT}" ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: one absolute non-symlink Android SDK root is required.\n' >&2
    return 1
  }
  for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
    value="${!name:-}"
    [[ -n "${value}" && "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || {
      printf 'ANDROID MACOS RELEASE BUILD ERROR: required Android signing input is absent or malformed: %s\n' "${name}" >&2
      return 1
    }
  done
  _wins_release_android_toolchain_exec flutter-build "$@"
}

wins_release_android_keytool_with_store_password() {
  [[ -n "${WINS_ANDROID_STORE_PASSWORD:-}" && "${WINS_ANDROID_STORE_PASSWORD}" != *$'\n'* \
     && "${WINS_ANDROID_STORE_PASSWORD}" != *$'\r'* ]] || {
    printf 'ANDROID MACOS RELEASE BUILD ERROR: WINS_ANDROID_STORE_PASSWORD is absent or malformed.\n' >&2
    return 1
  }
  _wins_release_android_toolchain_exec keytool-store-password "$@"
}

wins_release_android_jdk_tool() {
  local tool="${1:-}"
  case "${tool}" in
    java|keytool|jarsigner) ;;
    *)
      printf 'ANDROID MACOS RELEASE BUILD ERROR: unapproved JDK tool rejected: %s\n' "${tool}" >&2
      return 1
      ;;
  esac
  shift
  _wins_release_android_toolchain_exec "${tool}" "$@"
}

assert_reviewed_toolchain_custody() {
  local current_pin_manifest current_python
  current_python="$(custody_regular_file_sha256 "${PYTHON_BIN}")" \
    || die 'Pinned release Python executable could not be rechecked.'
  [[ -n "${RELEASE_PYTHON_EXECUTABLE_PIN_SHA256}" \
     && "${current_python}" == "${RELEASE_PYTHON_EXECUTABLE_PIN_SHA256}" ]] \
    || die 'Pinned release Python executable no longer matches tools/toolchain-pins.json.'
  wins_release_android_toolchains_verify \
    || die 'Pinned home Flutter/JDK recheck failed.'
  current_pin_manifest="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")" \
    || die 'Toolchain pin manifest custody could not be rechecked.'
  [[ "${current_pin_manifest}" == "${TOOLCHAIN_PINS_CUSTODY_SHA256}" ]] \
    || die 'Toolchain pin manifest changed after custody was established.'
}

assert_private_android_signing_env_file() {
  local path="$1" file_uid file_mode file_links current_uid parent parent_uid parent_mode
  [[ -f "${path}" && -r "${path}" && ! -L "${path}" ]] \
    || die "Android signing environment must be a readable regular non-symlink file: ${path}"
  parent="$(dirname "${path}")"
  [[ -d "${parent}" && ! -L "${parent}" ]] \
    || die "Android signing environment parent must be a regular non-symlink directory: ${parent}"
  current_uid="$(id -u)"
  file_uid="$(/usr/bin/stat -f '%u' "${path}")" \
    || die 'Could not inspect Android signing environment ownership.'
  file_mode="$(/usr/bin/stat -f '%Lp' "${path}")" \
    || die 'Could not inspect Android signing environment permissions.'
  file_links="$(/usr/bin/stat -f '%l' "${path}")" \
    || die 'Could not inspect Android signing environment link count.'
  parent_uid="$(/usr/bin/stat -f '%u' "${parent}")" \
    || die 'Could not inspect Android signing environment parent ownership.'
  parent_mode="$(/usr/bin/stat -f '%Lp' "${parent}")" \
    || die 'Could not inspect Android signing environment parent permissions.'
  [[ "${file_uid}" == "${current_uid}" ]] \
    || die 'Android signing environment must be owned by the current user.'
  [[ "${file_links}" == "1" ]] \
    || die 'Android signing environment must not be hard-linked.'
  (( (8#${file_mode} & 8#177) == 0 )) \
    || die 'Android signing environment must use mode 0600 or stricter without execute bits.'
  [[ "${parent_uid}" == "${current_uid}" ]] \
    || die 'Android signing environment parent must be owned by the current user.'
  (( (8#${parent_mode} & 8#022) == 0 )) \
    || die 'Android signing environment parent must not be writable by group or other.'
}

ANDROID_SIGNING_ENV_AUTOLOADED=0

load_android_signing_env_if_unset() {
  local name set_count=0 path line assignment key value seen='|' line_number=0
  for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
    [[ -z "${!name+x}" ]] || set_count=$((set_count + 1))
  done
  (( set_count == 0 )) || return 0
  path="${HOME}/.winsvpn/android-release.env"
  [[ -e "${path}" || -L "${path}" ]] || return 0
  assert_private_android_signing_env_file "${path}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_number=$((line_number + 1))
    [[ "${#line}" -le 8192 ]] \
      || die "Android signing environment line ${line_number} is too long."
    [[ "${line}" != *$'\r'* ]] \
      || die "Android signing environment line ${line_number} contains a carriage return."
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    case "${line}" in
      export\ *) assignment="${line#export }" ;;
      *) assignment="${line}" ;;
    esac
    [[ "${assignment}" == *=* ]] \
      || die "Android signing environment line ${line_number} is not KEY=VALUE."
    key="${assignment%%=*}"
    value="${assignment#*=}"
    case "${key}" in
      WINS_ANDROID_KEYSTORE|WINS_ANDROID_KEY_ALIAS|WINS_ANDROID_KEY_PASSWORD|WINS_ANDROID_STORE_PASSWORD) ;;
      *) die "Android signing environment line ${line_number} uses an unsupported key." ;;
    esac
    case "${seen}" in *"|${key}|"*) die "Android signing environment repeats ${key}." ;; esac
    seen="${seen}${key}|"
    if [[ "${value}" == \"* || "${value}" == *\" ]]; then
      [[ "${#value}" -ge 2 && "${value}" == \"*\" ]] \
        || die "Android signing environment line ${line_number} has malformed quotes."
      value="${value:1:${#value}-2}"
      [[ "${value}" != *\"* ]] \
        || die "Android signing environment line ${line_number} contains an unsupported embedded quote."
    else
      [[ "${value}" != *[[:space:]]* ]] \
        || die "Android signing environment line ${line_number} has unquoted whitespace."
    fi
    case "${key}" in
      WINS_ANDROID_KEYSTORE) WINS_ANDROID_KEYSTORE="${value}" ;;
      WINS_ANDROID_KEY_ALIAS) WINS_ANDROID_KEY_ALIAS="${value}" ;;
      WINS_ANDROID_KEY_PASSWORD) WINS_ANDROID_KEY_PASSWORD="${value}" ;;
      WINS_ANDROID_STORE_PASSWORD) WINS_ANDROID_STORE_PASSWORD="${value}" ;;
    esac
  done < "${path}"
  ANDROID_SIGNING_ENV_AUTOLOADED=1
}

assert_complete_android_signing_env() {
  local name
  for name in WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD; do
    [[ -n "${!name:-}" ]] \
      || die "OWNER-BLOCKED: ${name} is required; missing owner keystore remains blocked."
    [[ "${!name}" != *$'\n'* && "${!name}" != *$'\r'* ]] \
      || die "${name} must be a single-line value."
  done
  [[ "${WINS_ANDROID_KEY_ALIAS}" =~ ^[A-Za-z0-9._-]+$ ]] \
    || die 'WINS_ANDROID_KEY_ALIAS contains unsupported characters.'
}

assert_owner_keystore_present() {
  [[ "${WINS_ANDROID_KEYSTORE}" == /* ]] \
    || die 'OWNER-BLOCKED: WINS_ANDROID_KEYSTORE must be an absolute external path.'
  [[ -f "${WINS_ANDROID_KEYSTORE}" && ! -L "${WINS_ANDROID_KEYSTORE}" && -s "${WINS_ANDROID_KEYSTORE}" ]] \
    || die 'OWNER-BLOCKED: missing Android upload keystore'
}

# Winn3 descriptor verification key - CLIENT side (PUBLIC material).
# Client: --dart-define=WINS_WINN3_DESCRIPTOR_PUBKEY_G1 (WITH prefix)
# Hub:    WINN3_DESCRIPTOR_PUBKEY_G1 (NO prefix) - same value, two names.
collect_winn3_descriptor_pubkey_defines() {
  local slot var file_var raw value defines
  defines=()
  for slot in G1 G2 G3; do
    var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"
    file_var="${var}_FILE"
    raw=""; value=""
    if [[ -n "${!file_var:-}" ]]; then
      if [[ ! -f "${!file_var}" || -L "${!file_var}" ]]; then
        printf 'Winn3 descriptor pubkey file missing or symbolic: %s=%s\n' "${file_var}" "${!file_var}" >&2; return 65
      fi
      raw="$(tr -d '\r\n' < "${!file_var}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
      if [[ "${raw}" == --dart-define=* || "${raw}" == WINS_WINN3_DESCRIPTOR_PUBKEY_* || "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then
        printf 'Refusing %s that looks like a dart-define or hub key name: %.60s\n' "${file_var}" "${raw}" >&2; return 65
      fi
      value="${raw}"
    elif [[ -n "${!var:-}" ]]; then
      raw="${!var}"
      if [[ "${raw}" == --dart-define=* ]]; then printf 'Refusing %s that already contains --dart-define\n' "${var}" >&2; return 65; fi
      if [[ "${raw}" == WINN3_DESCRIPTOR_PUBKEY_* ]]; then printf 'Refusing %s that looks like a hub key name: %.60s\n' "${var}" "${raw}" >&2; return 65; fi
      value="$(printf '%s' "${raw}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    else continue; fi
    if [[ -z "${value}" ]]; then continue; fi
    if ! printf '%s' "${value}" | wins_release_python_run -c 'import base64,sys; d=base64.b64decode(sys.stdin.read().strip(),validate=True); assert len(d)==32' 2>/dev/null; then
      printf 'Winn3 descriptor pubkey %s is not valid base64 of 32 bytes: %.20s...\n' "${var}" "${value}" >&2; return 65
    fi
    defines+=("--dart-define=${var}=${value}")
  done
  if [[ "${#defines[@]}" -gt 0 ]]; then
    printf '%s\n' "${defines[@]}"
  fi
}
log_winn3_descriptor_pubkey_status() {
  local count="$1"
  if [[ "${count}" -gt 0 ]]; then
    printf 'ANDROID RELEASE: Winn3 descriptor verification ring PRESENT (%s slot(s) compiled in)\n' "${count}"
  else
    printf 'ANDROID RELEASE WARNING: Winn3 descriptor verification ring ABSENT - no WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3 supplied.\n' >&2
    printf 'ANDROID RELEASE WARNING: This build will report descriptor-no-verification-keys-compiled and standalone is unavailable.\n' >&2
    printf 'ANDROID RELEASE WARNING: Set WINS_WINN3_DESCRIPTOR_PUBKEY_G1 from tools/winn3_sign_descriptor.py pubkey to produce a complete build.\n' >&2
    printf 'ANDROID RELEASE ERROR: standalone v3 release requires at least one descriptor verification key.\n' >&2
    return 65
  fi
}

# Where the ring itself comes from. tools/winn3_descriptor_ring_defines.py is
# the single place the Track B ceremony public keys live; it recomputes the ring
# identity from those keys through tools/winn3_descriptor_ring_identity.py and
# emits nothing at all when the recomputation disagrees with its reviewed pin,
# so the keys and the digest cannot drift apart in an operator's shell history.
# Until this call existed nothing supplied WINS_WINN3_DESCRIPTOR_PUBKEY_G1..G3
# or WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256, so a release either refused to
# build or shipped with an ABSENT ring and no standalone v3 on any handset.
# An operator-supplied ring always wins: if any _G1..G3 or _FILE variable is
# already set this defers completely, so a key rotation can still be driven
# from the environment without editing a producer. Must run with the working
# directory inside the neutral stage so the keys come from the snapshotted copy.
load_reviewed_winn3_descriptor_ring_defines() {
  local tool slot var file_var exports
  tool='tools/winn3_descriptor_ring_defines.py'
  for slot in G1 G2 G3; do
    var="WINS_WINN3_DESCRIPTOR_PUBKEY_${slot}"
    file_var="${var}_FILE"
    if [[ -n "${!var:-}" || -n "${!file_var:-}" ]]; then
      printf 'ANDROID RELEASE: Winn3 descriptor ring supplied by the environment; %s not consulted.\n' "${tool}"
      return 0
    fi
  done
  [[ -f "${tool}" && ! -L "${tool}" ]] \
    || die "Reviewed Winn3 descriptor ring source is missing from the neutral stage: ${tool}"
  # `sh` emits nothing but `export NAME='value'` lines, and the tool has already
  # constrained every value to ^[A-Za-z0-9+/]{43}=$ or ^[0-9a-f]{64}$ -- no
  # quote, backslash or metacharacter can reach this eval.
  exports="$(wins_release_python_run "${tool}" sh)" \
    || die 'The reviewed Winn3 descriptor ring could not be resolved; refusing to build a ringless release.'
  eval "${exports}"
  printf 'ANDROID RELEASE: %s\n' "$(wins_release_python_run "${tool}" verify)"
}

DEPENDENCY_FREEZE="${ROOT}/tools/release_dependency_freeze.py"
# The freeze worker runs only through its launcher, which checks the pinned
# interpreter sha256 and hands it the controller on a retained descriptor.
DEPENDENCY_FREEZE_PARENT="${ROOT}/tools/run_release_dependency_freeze.sh"
WINN_ENGINE_SOURCE_GATE="${ROOT}/android/tools/prepare_android_winn_assets.sh"
OBFUSCATION_CONTRACT="${ROOT}/tools/release_obfuscation_contract.py"
PRIVACY_VALIDATOR="${ROOT}/tools/validate_release_artifact_privacy.py"
CUSTODY_TOOL="${ROOT}/tools/private_release_symbol_custody.py"
PUBLICATION_TOOL="${ROOT}/tools/android_release_publication.py"
PUBLICATION_STATE="${ROOT}/.artifacts/android-release-publication.state.json"
EXPECTED_UPLOAD_CERTIFICATE_SHA256="4ebbff15a1274e7b072767fa37f00e8ffbeafab80cb61b51a5ab598af6dbe6ee"
EXPECTED_PHONE_APPLICATION_ID="org.winsvpn.app"
EXPECTED_TV_APPLICATION_ID="org.winsvpn.app"
BUNDLETOOL_VERSION="1.18.3"
BUNDLETOOL_ALL_SHA256="a099cfa1543f55593bc2ed16a70a7c67fe54b1747bb7301f37fdfd6d91028e29"
REVIEWED_BUILD_TOOLS_VERSION="36.0.0"
REVIEWED_APKSIGNER_JAR_RELATIVE="build-tools/37.0.0/lib/apksigner.jar"
REVIEWED_APKSIGNER_JAR_SHA256="2defad215d7ff52968a409cde528cdaef7918b115e276b8e3378ca7a178e4180"
BUILD_LOCK_DIR="${ROOT}/.dart_tool/winsvpn-release-build.lock"
BUILD_LOCK_OWNER="${BUILD_LOCK_DIR}/owner.txt"
BUILD_LOCK_ACQUIRED=0
STAGE=""
RELEASE_INDEX=""
REQUESTED_RECEIPT_DIR=""
PUBLICATION_ACTIVE=0
PREPARED_PATHS=()

release_build_lock() {
  local released
  [[ "${BUILD_LOCK_ACQUIRED}" == "1" ]] || return 0
  released="${BUILD_LOCK_DIR}.released.$$-${RANDOM}"
  [[ ! -e "${released}" && ! -L "${released}" ]] || return 1
  mv "${BUILD_LOCK_DIR}" "${released}" || return 1
  BUILD_LOCK_ACQUIRED=0
  rm -rf "${released}"
}

cleanup() {
  local status=$?
  trap - EXIT
  if [[ "${PUBLICATION_ACTIVE}" == "1" && -f "${PUBLICATION_STATE}" ]]; then
    if ! wins_release_python_run "${PUBLICATION_TOOL}" recover --state "${PUBLICATION_STATE}"; then
      printf 'ANDROID MACOS RELEASE BUILD ERROR: publication recovery failed; preserve %s\n' "${PUBLICATION_STATE}" >&2
      status=74
    fi
  fi
  local prepared
  # macOS ships Bash 3.2, where expanding an empty array under `set -u`
  # raises an unbound-variable error. Guard the expansion so early failures
  # retain their original status and diagnostics.
  if (( ${#PREPARED_PATHS[@]} > 0 )); then
    for prepared in "${PREPARED_PATHS[@]}"; do
      case "${prepared}" in
        "${ROOT}"/.artifacts/private-release-symbols/*/.winsvpn-android-publication-prepared-*|\
        "${ROOT}"/build/app/outputs/*/.winsvpn-android-publication-prepared-*)
          chmod -R u+w "${prepared}" 2>/dev/null || true
          rm -rf "${prepared}" || status=74
          ;;
        '') ;;
        *)
          printf 'ANDROID MACOS RELEASE BUILD ERROR: refusing to clean unexpected prepared path: %s\n' "${prepared}" >&2
          status=74
          ;;
      esac
    done
  fi
  if ! release_build_lock; then status=74; fi
  if [[ -n "${STAGE}" && "${STAGE}" == /private/tmp/winsvpn-android-neutral.* && -d "${STAGE}" ]]; then
    chmod -R u+w "${STAGE}" 2>/dev/null || true
    rm -rf "${STAGE}" || status=74
  fi
  release_python_cleanup || status=74
  unset WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD
  exit "${status}"
}
trap cleanup EXIT

resolve_repo_index() {
  local requested="$1" candidate parent resolved
  [[ -n "${requested}" ]] || die '--release-input-index is required.'
  if [[ "${requested}" == /* ]]; then candidate="${requested}"; else candidate="${ROOT}/${requested}"; fi
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || die 'Release input index is missing or symbolic.'
  parent="$(cd "$(dirname "${candidate}")" && pwd -P)"
  resolved="${parent}/$(basename "${candidate}")"
  case "${resolved}" in
    "${ROOT}"/.artifacts/*/RELEASE_INPUT_INDEX.json) ;;
    *) die 'Release input index must be a repository .artifacts RELEASE_INPUT_INDEX.json.' ;;
  esac
  printf '%s\n' "${resolved}"
}

while (( $# > 0 )); do
  case "$1" in
    --release-input-index)
      (( $# >= 2 )) || die '--release-input-index requires a value.'
      RELEASE_INDEX="$2"
      shift 2
      ;;
    --build-receipt-directory)
      (( $# >= 2 )) || die '--build-receipt-directory requires a value.'
      REQUESTED_RECEIPT_DIR="$2"
      shift 2
      ;;
    *) die "Unknown argument: $1" ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || die 'This producer must run on macOS.'
[[ "$(id -u)" != "0" ]] \
  || die 'Android macOS release production must run as the current non-root user. Flutter, Gradle, and signing are never run as root.'
[[ "${WINS_ANDROID_MACOS_PS_ENTRYPOINT:-0}" == "1" ]] \
  || die 'Invoke tools/build_android_release.ps1 with PowerShell so the frozen formal producer owns this build.'
for ambient_toolchain_override in PYTHON_BIN WINS_RELEASE_PYTHON; do
  [[ -z "${!ambient_toolchain_override+x}" ]] \
    || die "Caller toolchain override is forbidden; tools/toolchain-pins.json owns the release Python interpreter (${ambient_toolchain_override})."
done
for ambient_toolchain_override in FLUTTER_BIN JAVA_HOME; do
  [[ -z "${!ambient_toolchain_override+x}" ]] \
    || die "Caller toolchain override is forbidden; tools/toolchain-pins.json owns ${ambient_toolchain_override}."
done
load_android_signing_env_if_unset
assert_complete_android_signing_env
assert_owner_keystore_present
[[ "${ANDROID_SIGNING_ENV_AUTOLOADED}" != "1" ]] \
  || printf 'ANDROID MACOS RELEASE: loaded four signing variables from the private current-user environment file.\n'
RELEASE_INDEX="$(resolve_repo_index "${RELEASE_INDEX}")"
prepare_pinned_release_python
wins_release_android_toolchains_prepare "${ROOT}/tools/toolchain-pins.json" \
  || die 'Pinned home Flutter/JDK verification failed; tools/toolchain-pins.json names the required versions and tree digests.'
FLUTTER_BIN="${WINS_RELEASE_FLUTTER_BIN}"
ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-${HOME}/Library/Android/sdk}}"
ANDROID_HOME="${ANDROID_SDK_ROOT}"
export ANDROID_SDK_ROOT ANDROID_HOME
export PYTHON_BIN FLUTTER_BIN
export PATH
[[ -x "${PYTHON_BIN}" ]] || die "Python is unavailable at ${PYTHON_BIN}."

# Native SDK binaries only. Java SDK tools must use the pinned, digest-verified
# JDK through wins_release_android_jdk_tool.
run_android_sdk_native_tool() {
  /usr/bin/env -i \
    HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" \
    ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT}" ANDROID_HOME="${ANDROID_HOME}" \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$@"
}

run_android_apksigner() {
  [[ $# -ge 1 ]] || die 'run_android_apksigner requires apksigner arguments.'
  [[ -n "${SEALED_JAVA}" && -n "${WINS_RELEASE_JAVA_HOME:-}" \
     && "${SEALED_JAVA}" == "${WINS_RELEASE_JAVA_HOME}/bin/java" ]] \
    || die 'apksigner must bind the pinned, digest-verified JDK java executable.'
  [[ -f "${SEALED_JAVA}" && -x "${SEALED_JAVA}" && ! -L "${SEALED_JAVA}" ]] \
    || die 'pinned JDK java is missing or symbolic.'
  wins_release_python_run - \
    "${SEALED_JAVA}" \
    "${ANDROID_SDK_ROOT}" \
    "${REVIEWED_APKSIGNER_JAR_RELATIVE}" \
    "${REVIEWED_APKSIGNER_JAR_SHA256}" \
    "$@" <<'PY'
# WINS_ANDROID_APKSIGNER_HOLD_BEGIN
from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

CHUNK = 1024 * 1024
HOSTILE_JAVA_ENV = (
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "JAVA_OPTS",
    "CLASSPATH",
    "JAVA_HOME",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def _nofollow() -> int:
    flag = getattr(os, "O_NOFOLLOW", 0)
    if not flag:
        fail("O_NOFOLLOW is required to hold apksigner.jar")
    return flag


def _nonblock() -> int:
    flag = getattr(os, "O_NONBLOCK", 0)
    if not flag:
        fail("O_NONBLOCK is required to hold apksigner.jar")
    return flag


def _clear_nonblock_if_needed(fd: int) -> None:
    if not hasattr(fcntl, "F_GETFL") or not hasattr(fcntl, "F_SETFL"):
        fail("F_GETFL and F_SETFL are required to hold apksigner.jar")
    nonblock = _nonblock()
    current = fcntl.fcntl(fd, fcntl.F_GETFL)
    if current & nonblock:
        fcntl.fcntl(fd, fcntl.F_SETFL, current & ~nonblock)


def walk_regular_file(path: Path, label: str) -> None:
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
            fail(f"{label} path is not a readable regular file: {suc}")
        if stat.S_ISLNK(info.st_mode):
            fail(f"{label} traverses a symbolic link")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_size,
    )


def hold_bytes(sdk_root: str, relative: str, expected: str) -> bytes:
    if relative != "build-tools/37.0.0/lib/apksigner.jar":
        fail("reviewed apksigner.jar relative path is not exact")
    if len(expected) != 64 or expected.strip("0123456789abcdef") or expected == "0" * 64:
        fail("reviewed apksigner.jar digest is malformed")
    root = Path(sdk_root)
    source = root / Path(*relative.split("/"))
    walk_regular_file(root, "Android SDK root")
    walk_regular_file(source, "apksigner.jar")
    try:
        before = source.lstat()
    except FileNotFoundError:
        fail("apksigner.jar is absent")
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0:
        fail("apksigner.jar must be one regular non-symlink single-link file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _nofollow() | _nonblock()
    try:
        fd = os.open(source, flags)
    except OSError:
        fail("apksigner.jar path is not a readable regular file")
    try:
        opened = os.fstat(fd)
        if _identity(before) != _identity(opened):
            fail("apksigner.jar was replaced before it was opened")
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened.st_size <= 0:
            fail("apksigner.jar must be one regular non-symlink single-link file")
        _clear_nonblock_if_needed(fd)
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, CHUNK)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(fd)
        if _identity(opened) != _identity(after):
            fail("apksigner.jar changed while it was read")
        data = b"".join(chunks)
        if len(data) != opened.st_size:
            fail("apksigner.jar current bytes could not be held")
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            fail("apksigner.jar SHA-256 does not match the reviewed pin")
        return data
    finally:
        os.close(fd)


def bind_reviewed_java(path: str) -> str:
    java = Path(path)
    walk_regular_file(java, "reviewed java")
    info = java.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail("reviewed java must be one regular non-symlink single-link file")
    if java.name != "java":
        fail("reviewed java executable name is not exact")
    if not os.access(java, os.X_OK):
        fail("reviewed java is not executable")
    return str(java)


def java_exec_env() -> dict[str, str]:
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "C",
        "LC_ALL": "C",
        "TMPDIR": os.environ.get("TMPDIR") or "/private/tmp",
    }
    home = os.environ.get("HOME")
    if home:
        env["HOME"] = home
    for name in HOSTILE_JAVA_ENV:
        env.pop(name, None)
    return env


def anonymous_held_fd(data: bytes, expected: str) -> int:
    if len(expected) != 64 or expected.strip("0123456789abcdef") or expected == "0" * 64:
        fail("reviewed apksigner.jar digest is malformed")
    if hashlib.sha256(data).hexdigest() != expected:
        fail("apksigner.jar SHA-256 does not match the reviewed pin")
    fd, name = tempfile.mkstemp(prefix="winsvpn-apksigner-anon.", dir="/private/tmp")
    try:
        os.unlink(name)
    except OSError:
        os.close(fd)
        try:
            os.unlink(name)
        except OSError:
            pass
        raise
    copied = hashlib.sha256()
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                fail("short write while holding apksigner.jar")
            copied.update(view[:written])
            view = view[written:]
        os.fsync(fd)
        if copied.hexdigest() != expected:
            fail("held apksigner.jar copy digest mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def descriptor_jar_path(fd: int) -> str:
    path = f"/dev/fd/{fd}"
    probe = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        probed = os.fstat(probe)
        if (opened.st_dev, opened.st_ino) != (probed.st_dev, probed.st_ino):
            fail("apksigner descriptor path does not match the held inode")
        if not stat.S_ISREG(opened.st_mode):
            fail("held apksigner.jar descriptor is not a regular file")
    finally:
        os.close(probe)
    return path


def snapshot_jar(fd: int, expected: str) -> tuple[str, str]:
    """Copy the held bytes to a private 0o400 file alone in a 0o500 directory.

    The JVM cannot load classes from a /dev/fd/N jar on macOS (the finding
    tools/verify_android_aab_signers.py _HeldApksigner records), so java -jar
    receives this snapshot, re-hashed before and after it runs.
    """
    directory = tempfile.mkdtemp(prefix="winsvpn-apksigner-snapshot.", dir="/private/tmp")
    path = os.path.join(directory, "apksigner.jar")
    try:
        # Read the held bytes through the descriptor path, which checks that it
        # still names the held inode, never through the SDK pathname.
        os.lseek(fd, 0, os.SEEK_SET)
        with open(descriptor_jar_path(fd), "rb") as stream:
            data = stream.read()
        if hashlib.sha256(data).hexdigest() != expected:
            fail("held apksigner.jar copy digest mismatch")
        out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        try:
            view = memoryview(data)
            while view:
                written = os.write(out, view)
                if written <= 0:
                    fail("short write while snapshotting apksigner.jar")
                view = view[written:]
            os.fsync(out)
        finally:
            os.close(out)
        os.chmod(directory, 0o500)
    except BaseException:
        remove_snapshot(directory)
        raise
    return directory, path


def snapshot_digest(path: str) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o400:
            fail("apksigner.jar snapshot is not one private regular file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def remove_snapshot(directory: str) -> None:
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    shutil.rmtree(directory, ignore_errors=True)


def run_held_apksigner(
    java_path: str,
    sdk_root: str,
    relative: str,
    expected: str,
    argv: list[str],
) -> int:
    java = bind_reviewed_java(java_path)
    data = hold_bytes(sdk_root, relative, expected)
    fd = anonymous_held_fd(data, expected)
    try:
        directory, jar = snapshot_jar(fd, expected)
        try:
            if snapshot_digest(jar) != expected:
                fail("apksigner.jar snapshot digest mismatch")
            env = java_exec_env()
            for name in HOSTILE_JAVA_ENV:
                if name in env:
                    fail(f"hostile Java environment leaked: {name}")
            completed = subprocess.run(
                [java, "-jar", jar, *argv],
                env=env,
                check=False,
            )
            if snapshot_digest(jar) != expected:
                fail("apksigner.jar snapshot changed while apksigner ran")
            return int(completed.returncode)
        finally:
            remove_snapshot(directory)
    finally:
        os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) < 5:
        fail("run_held_apksigner arguments are malformed")
    raise SystemExit(
        run_held_apksigner(
            sys.argv[1],
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
            sys.argv[5:],
        )
    )
# WINS_ANDROID_APKSIGNER_HOLD_END
PY
}

# macOS /bin/realpath does not support GNU's -e option. Resolve strictly with
# the already-required Python runtime so this producer works on its declared
# host while retaining the regular-file and final-component symlink checks
# below.
resolve_existing_path() {
  wins_release_python_run - "${1:?resolve_existing_path: missing path}" <<'PY'
import pathlib
import sys

try:
    print(pathlib.Path(sys.argv[1]).resolve(strict=True))
except (OSError, RuntimeError):
    raise SystemExit(1)
PY
}

# FLUTTER_BIN is overridable via env var and its default is just a fixed
# path string, neither of which by itself proves the file there is real:
# resolving through realpath and rejecting symlinks means the later exact
# version+revision check below is actually binding to one concrete file on
# disk, not to whatever a compromised or substituted flutter reports.
FLUTTER_BIN_RESOLVED="$(resolve_existing_path "${FLUTTER_BIN}" 2>/dev/null || true)"
[[ -n "${FLUTTER_BIN_RESOLVED}" && -f "${FLUTTER_BIN_RESOLVED}" \
   && -x "${FLUTTER_BIN_RESOLVED}" && ! -L "${FLUTTER_BIN_RESOLVED}" ]] \
  || die "Flutter must resolve to one real regular executable file, not a symlink: ${FLUTTER_BIN}"
FLUTTER_BIN="${FLUTTER_BIN_RESOLVED}"
# Existence+executable alone doesn't prove this is a real, on-disk JDK
# binary rather than a symlink/alias standing in for it -- the same
# reasoning already applied to Flutter above, now applied here because R8/D8
# (the code that actually optimizes and dexes the shipped release bytecode)
# runs inside this exact JVM. The pinned JDK tree is digest-verified; every
# Java invocation uses it through the reviewed runner.
JAVA_BIN_RESOLVED="$(resolve_existing_path "${WINS_RELEASE_JAVA_HOME}/bin/java" 2>/dev/null || true)"
[[ -n "${JAVA_BIN_RESOLVED}" && -f "${JAVA_BIN_RESOLVED}" \
   && -x "${JAVA_BIN_RESOLVED}" && ! -L "${JAVA_BIN_RESOLVED}" ]] \
  || die "JDK 17 must resolve to one real regular executable file, not a symlink: ${WINS_RELEASE_JAVA_HOME}/bin/java"
SEALED_JAVA="$(resolve_existing_path "${WINS_RELEASE_JAVA_HOME}/bin/java" 2>/dev/null || true)"
SEALED_JARSIGNER="$(resolve_existing_path "${WINS_RELEASE_JAVA_HOME}/bin/jarsigner" 2>/dev/null || true)"
SEALED_KEYTOOL="$(resolve_existing_path "${WINS_RELEASE_JAVA_HOME}/bin/keytool" 2>/dev/null || true)"
[[ "${SEALED_JAVA}" == "${WINS_RELEASE_JAVA_HOME}/bin/java" && -f "${SEALED_JAVA}" && -x "${SEALED_JAVA}" && ! -L "${SEALED_JAVA}" ]] \
  || die "pinned JDK java must resolve to one real regular executable file: ${WINS_RELEASE_JAVA_HOME}/bin/java"
[[ "${SEALED_JARSIGNER}" == "${WINS_RELEASE_JAVA_HOME}/bin/jarsigner" && -f "${SEALED_JARSIGNER}" && -x "${SEALED_JARSIGNER}" && ! -L "${SEALED_JARSIGNER}" ]] \
  || die "pinned JDK jarsigner must resolve to one real regular executable file: ${WINS_RELEASE_JAVA_HOME}/bin/jarsigner"
[[ "${SEALED_KEYTOOL}" == "${WINS_RELEASE_JAVA_HOME}/bin/keytool" && -f "${SEALED_KEYTOOL}" && -x "${SEALED_KEYTOOL}" && ! -L "${SEALED_KEYTOOL}" ]] \
  || die "pinned JDK keytool must resolve to one real regular executable file: ${WINS_RELEASE_JAVA_HOME}/bin/keytool"
JAVA_VERSION="17.0.20.1"
[[ "${JAVA_VERSION}" == "$(read_wins_toolchain_pin tools.java.version)" ]] \
  || die "JAVA_VERSION ${JAVA_VERSION} disagrees with tools/toolchain-pins.json tools.java.version."

assert_private_external_keystore() {
  local path="$1"
  wins_release_python_run - "${ROOT}" "${path}" <<'PY'
import os
import pathlib
import stat
import sys

repo = pathlib.Path(sys.argv[1]).resolve(strict=True)
candidate = pathlib.Path(sys.argv[2]).expanduser()
if not candidate.is_absolute():
    raise SystemExit('WINS_ANDROID_KEYSTORE must be an absolute external path.')
cursor = pathlib.Path(candidate.anchor)
for part in candidate.parts[1:]:
    cursor /= part
    try:
        info = cursor.lstat()
    except FileNotFoundError:
        raise SystemExit('OWNER-BLOCKED: missing Android upload keystore')
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f'Android signing keystore path traverses a symbolic link: {cursor}')
try:
    resolved = candidate.resolve(strict=True)
except FileNotFoundError:
    raise SystemExit('OWNER-BLOCKED: missing Android upload keystore')
if repo == resolved or repo in resolved.parents:
    raise SystemExit('Android signing keystore must remain outside the repository.')
info = resolved.stat()
if not stat.S_ISREG(info.st_mode):
    raise SystemExit('Android signing keystore must be a regular file.')
if info.st_nlink != 1:
    raise SystemExit('Android signing keystore must not be hard-linked.')
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit('Android signing keystore must be current-user-owned with mode 0600 or stricter.')
print(resolved)
PY
}

WINS_ANDROID_KEYSTORE="$(assert_private_external_keystore "${WINS_ANDROID_KEYSTORE}")"

TOOLCHAIN_PLATFORM_KEY="$(toolchain_platform_key)"
FLUTTER_TOOLCHAIN_ROOT="${WINS_RELEASE_FLUTTER_ROOT}"
JAVA_TOOLCHAIN_ROOT="${WINS_RELEASE_JAVA_HOME}"
TOOLCHAIN_PINS_CUSTODY_SHA256="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")" \
  || die 'Toolchain pin manifest custody could not be established.'
FLUTTER_TOOLCHAIN_TREE_SHA256="${WINS_RELEASE_FLUTTER_TREE_SHA256}"
JAVA_TOOLCHAIN_TREE_SHA256="${WINS_RELEASE_JAVA_TREE_SHA256}"
assert_reviewed_toolchain_custody

prepare_reviewed_go_for_engine_freshness() {
  local expected_binary actual_binary identity
  REVIEWED_GO_FRESHNESS_ROOT="${HOME}/.local/toolchains/go${REQUIRED_GO_VERSION}"
  REVIEWED_GO_FRESHNESS_BIN="${REVIEWED_GO_FRESHNESS_ROOT}/bin/go"
  [[ -d "${REVIEWED_GO_FRESHNESS_ROOT}" && ! -L "${REVIEWED_GO_FRESHNESS_ROOT}" ]] \
    || die "Android native-engine freshness requires the reviewed Go ${REQUIRED_GO_VERSION} tree."
  [[ -f "${REVIEWED_GO_FRESHNESS_BIN}" && -x "${REVIEWED_GO_FRESHNESS_BIN}" \
     && ! -L "${REVIEWED_GO_FRESHNESS_BIN}" ]] \
    || die "Android native-engine freshness requires a regular reviewed Go ${REQUIRED_GO_VERSION} executable."
  expected_binary="$(read_wins_toolchain_pin tools.go.executable_sha256)"
  [[ "${expected_binary}" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Reviewed Go freshness executable pin is missing or malformed.'
  actual_binary="$(custody_regular_file_sha256 "${REVIEWED_GO_FRESHNESS_BIN}")" \
    || die 'Reviewed Go freshness executable could not be authenticated.'
  [[ "${actual_binary}" == "${expected_binary}" ]] \
    || die 'Reviewed Go freshness executable does not match tools/toolchain-pins.json.'
  identity="$(/usr/bin/env -i HOME="${HOME}" PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    GOROOT="${REVIEWED_GO_FRESHNESS_ROOT}" GOENV=off GOTOOLCHAIN=local \
    "${REVIEWED_GO_FRESHNESS_BIN}" version)" \
    || die 'Reviewed Go freshness executable did not report its identity.'
  [[ "${identity}" == "go version go${REQUIRED_GO_VERSION} darwin/arm64" ]] \
    || die "Reviewed Go freshness identity mismatch: ${identity}"
  REVIEWED_GO_FRESHNESS_BINARY_SHA256="${actual_binary}"
}

run_reviewed_android_engine_freshness_gate() {
  local after_binary
  [[ -n "${REVIEWED_GO_FRESHNESS_ROOT:-}" && -n "${REVIEWED_GO_FRESHNESS_BIN:-}" ]] \
    || die 'Reviewed Go freshness custody was not prepared.'
  /usr/bin/env -i \
    HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" \
    PATH="${REVIEWED_GO_FRESHNESS_ROOT}/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
    GOROOT="${REVIEWED_GO_FRESHNESS_ROOT}" GOENV=off GOTOOLCHAIN=local GOPROXY=off \
    /bin/bash "${WINN_ENGINE_SOURCE_GATE}" --verify \
    || die 'Android staged native engines are stale, incomplete, or unverifiable.'
  after_binary="$(custody_regular_file_sha256 "${REVIEWED_GO_FRESHNESS_BIN}")" \
    || die 'Reviewed Go freshness executable changed during validation.'
  [[ "${after_binary}" == "${REVIEWED_GO_FRESHNESS_BINARY_SHA256}" ]] \
    || die 'Reviewed Go freshness custody changed while native engines were validated.'
}

prepare_reviewed_go_for_engine_freshness

acquire_release_build_lock() {
  local owner='owner metadata is not available'
  mkdir -p -- "$(dirname "${BUILD_LOCK_DIR}")"
  if ! mkdir -- "${BUILD_LOCK_DIR}" 2>/dev/null; then
    [[ -s "${BUILD_LOCK_OWNER}" ]] && owner="$(tr '\n' ' ' <"${BUILD_LOCK_OWNER}")"
    printf 'Another platform release build owns %s. %s. Wait for it to finish; never delete an active lock.\n' \
      "${BUILD_LOCK_DIR}" "${owner}" >&2
    exit 73
  fi
  BUILD_LOCK_ACQUIRED=1
  printf 'platform=android-macos\npid=%s\nstarted_utc=%s\n' \
    "$$" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >"${BUILD_LOCK_OWNER}"
}

initialize_receipts() {
  local requested parent
  requested="${REQUESTED_RECEIPT_DIR}"
  if [[ -z "${requested}" ]]; then
    requested="$(dirname "${RELEASE_INDEX}")/android-macos-build-$(date -u +'%Y%m%dT%H%M%SZ')-$$"
  elif [[ "${requested}" != /* ]]; then
    requested="${ROOT}/${requested}"
  fi
  [[ ! -e "${requested}" && ! -L "${requested}" ]] || die 'Android build receipt directory must be a new immutable path.'
  parent="$(cd "$(dirname "${requested}")" && pwd -P)"
  RECEIPT_DIR="${parent}/$(basename "${requested}")"
  case "${RECEIPT_DIR}" in "${ROOT}"/.artifacts/*) ;; *) die 'Build receipt directory must stay under repository .artifacts.' ;; esac
  # M-1: fail before any Android APK/AAB is accepted if a committed
  # Xray/AmneziaWG binary embeds a Go runtime with known-fixed stdlib CVEs.
  wins_release_python_run "${ROOT}/tools/verify_embedded_engine_runtime_versions.py"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" verify-index --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android
  # Validate every staged Winn v3 and Xray slice that exists. The Gradle
  # release-graph gate below independently requires the complete three-ABI
  # inventory, so absence and wrong-ABI substitution are separate failures.
  run_reviewed_android_engine_freshness_gate
  mkdir -m 0700 -- "${RECEIPT_DIR}"
  APK_BEGIN="${RECEIPT_DIR}/ANDROID_APK_BUILD_BEGIN.json"
  AAB_BEGIN="${RECEIPT_DIR}/ANDROID_AAB_BUILD_BEGIN.json"
  TV_APK_BEGIN="${RECEIPT_DIR}/ANDROID_TV_APK_BUILD_BEGIN.json"
  TV_AAB_BEGIN="${RECEIPT_DIR}/ANDROID_TV_AAB_BUILD_BEGIN.json"
  APK_RECEIPT="${RECEIPT_DIR}/ANDROID_APK_BUILD_RECEIPT.json"
  AAB_RECEIPT="${RECEIPT_DIR}/ANDROID_AAB_BUILD_RECEIPT.json"
  TV_APK_RECEIPT="${RECEIPT_DIR}/ANDROID_TV_APK_BUILD_RECEIPT.json"
  TV_AAB_RECEIPT="${RECEIPT_DIR}/ANDROID_TV_AAB_BUILD_RECEIPT.json"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" begin-build --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android --output "${APK_BEGIN}"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" begin-build --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android --output "${AAB_BEGIN}"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" begin-build --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android --output "${TV_APK_BEGIN}"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" begin-build --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android --output "${TV_AAB_BEGIN}"
}

snapshot_inputs() {
  local root="$1" output="$2"
  wins_release_python_run - "${root}" "${output}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
output = pathlib.Path(sys.argv[2])
files = [
    '.metadata', 'analysis_options.yaml', 'pubspec.yaml', 'pubspec.lock',
    'tools/build_android_release.ps1', 'tools/build_android_release_macos.sh',
    'tools/release_android_toolchain_archive_custody.sh',
    'tools/provision_macos_release_android_toolchains.sh',
    'tools/launch_macos_release_android_toolchains.py',
    'tools/validate_flutter_package_config.py',
    'tools/toolchain-pins.json',
    'tools/android_release_publication.py',
    'tools/release_obfuscation_contract.py',
    'tools/validate_release_artifact_privacy.py',
    # Imported at module level by the two tools above.
    'tools/release_secret_scan_policy.py',
    'tools/release_secret_inventory.py',
    # release_obfuscation_contract.py validate_static, run by record and verify
    # inside the stage, reads these repository files and extension/src below.
    'tools/local_release_gate.ps1',
    'installer/windows/build_installer.ps1',
    'tools/build_linux_release.sh',
    'tools/apple_runtime_smoke.sh',
    'extension/build.py',
    'extension/tools/store_js_minifier.py',
    'ios/Runner.xcodeproj/project.pbxproj',
    'macos/Runner.xcodeproj/project.pbxproj',
    'wear_os/app/build.gradle.kts',
    'tools/verify_android_aab_page_alignment.py',
    'tools/verify_android_aab_signers.py',
    'tools/private_release_symbol_custody.py',
    # Run from INSIDE the neutral stage -- the first three by relative path
    # from the staged working directory, the fourth through ${STAGE_REPO}.
    # Omitting one is not a provenance nicety: the interpreter cannot open a
    # file that was never copied, and the producer dies under `set -Eeuo
    # pipefail` at the first descriptor-ring step, before any APK exists.
    'tools/winn3_descriptor_ring_defines.py',
    'tools/winn3_descriptor_ring_identity.py',
    'tools/verify_winn3_ring_artifact.py',
    'tools/verify_standalone_v3_artifact.py',
    # S14A, run through ${STAGE_REPO} against the four staged artifacts.
    'tools/android_play_redemption_gate.py',
    # The Gradle stamp check verifyWinnReleaseStamp reads ../tools/winn_release_authority.json
    # from the staged project to check every engine stamp's signature.
    'tools/winn_release_authority.json',
    # Run from ${ROOT}, never from the stage, so these two are not needed for
    # the build to execute. They are listed because the before/after snapshot
    # comparison is the only thing that would notice one of the two gates
    # deciding whether this build may proceed being rewritten mid-build.
    'tools/release_dependency_freeze.py',
    'tools/run_release_dependency_freeze.sh',
    'tools/verify_embedded_engine_runtime_versions.py',
]
excluded_dirs = {'.gradle', '.cxx', 'build'}
for directory in ('lib', 'assets', 'android', 'app_store/android', 'extension/src'):
    base = root / directory
    if base.is_symlink() or not base.is_dir():
        raise SystemExit(f'Required Android release directory is unsafe or missing: {directory}')
    for current, names, children in os.walk(base, followlinks=False):
        names[:] = sorted(name for name in names if name not in excluded_dirs)
        current_path = pathlib.Path(current)
        for name in list(names):
            if (current_path / name).is_symlink():
                raise SystemExit(f'Android release source contains a symbolic directory: {current_path / name}')
        for name in sorted(children):
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            if name == 'local.properties':
                continue
            if path.is_symlink() or not path.is_file():
                raise SystemExit(f'Android release source contains an unsafe file: {relative}')
            files.append(relative)
records = []
for relative in sorted(set(files)):
    path = root / relative
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise SystemExit(f'Required Android release input is unsafe or missing: {relative}')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    records.append({'path': relative, 'bytes': info.st_size, 'sha256': digest})
output.write_text(json.dumps(records, separators=(',', ':'), sort_keys=True) + '\n', encoding='utf-8')
PY
}

copy_snapshot() {
  local source="$1" destination="$2" snapshot="$3"
  wins_release_python_run - "${source}" "${destination}" "${snapshot}" <<'PY'
import json
import pathlib
import shutil
import stat
import sys
source, destination, manifest = map(pathlib.Path, sys.argv[1:])
for record in json.loads(manifest.read_text(encoding='utf-8')):
    relative = pathlib.PurePosixPath(record['path'])
    target = destination.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    source_path = source.joinpath(*relative.parts)
    shutil.copyfile(source_path, target)
    target.chmod(0o700 if source_path.stat().st_mode & stat.S_IXUSR else 0o600)
PY
}

assert_safe_repo_destination() {
  local path="$1"
  wins_release_python_run - "${ROOT}" "${path}" <<'PY'
import pathlib
import stat
import sys
repo = pathlib.Path(sys.argv[1]).resolve(strict=True)
path = pathlib.Path(sys.argv[2])
try:
    relative = path.relative_to(repo)
except ValueError:
    raise SystemExit(f'Android publication path escaped the repository: {path}')
cursor = repo
for part in relative.parts:
    cursor /= part
    try:
        info = cursor.lstat()
    except FileNotFoundError:
        continue
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f'Android publication path traverses a symbolic link: {cursor}')
PY
}

verify_expected_signer() {
  local report digest
  report="$(wins_release_android_keytool_with_store_password -list -v -keystore "${WINS_ANDROID_KEYSTORE}" -alias "${WINS_ANDROID_KEY_ALIAS}" '-storepass:env' WINS_ANDROID_STORE_PASSWORD 2>&1)" \
    || die 'OWNER-BLOCKED: The configured Android upload certificate could not be read.'
  digest="$(printf '%s\n' "${report}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | head -n 1 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
  unset report
  [[ "${digest}" == "${EXPECTED_UPLOAD_CERTIFICATE_SHA256}" ]] \
    || die "Unexpected Android upload signer: sha256=${digest:-unreported}"
}

verify_exact_android_identity_and_r8() {
  local script_root="$1"
  local phone_apk="$2"
  local phone_aab="$3"
  local tv_apk="$4"
  local tv_aab="$5"
  local phone_apk_map="$6"
  local phone_aab_map="$7"
  local tv_apk_map="$8"
  local tv_aab_map="$9"
  local signer="${script_root}/tools/verify_android_aab_signers.py"
  wins_release_python_run "${signer}" --verify android-phone-tablet-aab "${phone_aab}" --java "${SEALED_JAVA}" --jarsigner "${SEALED_JARSIGNER}" --keytool "${SEALED_KEYTOOL}"
  wins_release_python_run "${signer}" --verify android-tv-aab "${tv_aab}" --java "${SEALED_JAVA}" --jarsigner "${SEALED_JARSIGNER}" --keytool "${SEALED_KEYTOOL}"
  wins_release_python_run "${signer}" --verify-apk android-phone-tablet-apk "${phone_apk}" --java "${SEALED_JAVA}" --jarsigner "${SEALED_JARSIGNER}" --keytool "${SEALED_KEYTOOL}"
  wins_release_python_run "${signer}" --verify-apk android-tv-apk "${tv_apk}" --java "${SEALED_JAVA}" --jarsigner "${SEALED_JARSIGNER}" --keytool "${SEALED_KEYTOOL}"
  wins_release_python_run "${signer}" --bind-r8 android-phone-tablet-aab "${phone_aab}" "${phone_aab_map}"
  wins_release_python_run "${signer}" --bind-r8 android-phone-tablet-apk "${phone_apk}" "${phone_apk_map}"
  wins_release_python_run "${signer}" --bind-r8 android-tv-aab "${tv_aab}" "${tv_aab_map}"
  wins_release_python_run "${signer}" --bind-r8 android-tv-apk "${tv_apk}" "${tv_apk_map}"
}

find_android_tool() {
  local name="$1" result
  # Plain lexicographic sort would rank "9.0.0" above "34.0.0" and return the
  # stale tool when multiple SDK build-tools/cmdline-tools versions are
  # installed side by side. Version-sort so the numerically newest wins.
  result="$(find "${ANDROID_SDK_ROOT}" -type f -name "${name}" -perm -u+x 2>/dev/null | sort -V | tail -n 1)"
  [[ -n "${result}" ]] || die "Android SDK ${name} was not found under ${ANDROID_SDK_ROOT}."
  printf '%s\n' "${result}"
}

prepare_file() {
  local source="$1" destination="$2" temporary source_hash copy_hash extension
  if [[ ! -s "${source}" || -L "${source}" ]]; then
    die "OWNER-BLOCKED: produced Android AAB/APK bytes are absent: ${source}"
  fi
  assert_safe_repo_destination "${destination}"
  mkdir -p -- "$(dirname "${destination}")"
  extension=".${destination##*.}"
  temporary="$(dirname "${destination}")/.winsvpn-android-publication-prepared-$$-${RANDOM}${extension}"
  [[ ! -e "${temporary}" && ! -L "${temporary}" ]] || die "Prepared Android publication path already exists: ${temporary}"
  cp "${source}" "${temporary}" || {
    rm -f "${temporary}"
    die "Android release output could not be prepared: ${source}"
  }
  source_hash="$(shasum -a 256 "${source}" | awk '{print $1}')"
  copy_hash="$(shasum -a 256 "${temporary}" | awk '{print $1}')"
  if [[ "${source_hash}" != "${copy_hash}" ]]; then
    rm -f "${temporary}"
    die "Android release output changed while preparing publication: ${source}"
  fi
  printf '%s\n' "${temporary}"
}

prepare_symbols() {
  local source="$1" destination="$2" temporary parent
  [[ -d "${source}" && ! -L "${source}" ]] || die "Staged Android private-symbol directory is unsafe or missing: ${source}"
  assert_safe_repo_destination "${destination}"
  parent="$(dirname "${destination}")"
  mkdir -p -- "${parent}"
  chmod 0700 "${parent}"
  temporary="${parent}/.winsvpn-android-publication-prepared-$$-${RANDOM}"
  [[ ! -e "${temporary}" && ! -L "${temporary}" ]] || die "Prepared Android symbol path already exists: ${temporary}"
  mkdir -m 0700 -- "${temporary}"
  cp -R "${source}/." "${temporary}/" || {
    rm -rf "${temporary}"
    die "Android private symbols could not be prepared: ${source}"
  }
  find "${temporary}" -type d -exec chmod 0700 {} +
  find "${temporary}" -type f -exec chmod 0600 {} +
  printf '%s\n' "${temporary}"
}

acquire_release_build_lock
mkdir -p -- "$(dirname "${PUBLICATION_STATE}")"
wins_release_python_run "${PUBLICATION_TOOL}" recover --state "${PUBLICATION_STATE}"
initialize_receipts

read -r FLUTTER_VERSION FLUTTER_REVISION < <(
  wins_release_android_flutter --version --machine | wins_release_python_run -c '
import json, sys
raw = sys.stdin.read(); start = raw.find("{"); end = raw.rfind("}")
if start < 0 or end < start: raise SystemExit("Flutter version JSON was not found")
value = json.loads(raw[start:end + 1])
print(value.get("frameworkVersion", ""), value.get("frameworkRevision", ""))
'
)
[[ "${FLUTTER_VERSION}" == "${REQUIRED_FLUTTER_VERSION}" && "${FLUTTER_REVISION}" == "${REQUIRED_FLUTTER_REVISION}" ]] \
  || die "Android releases require Flutter ${REQUIRED_FLUTTER_VERSION} (${REQUIRED_FLUTTER_REVISION}); found ${FLUTTER_VERSION} (${FLUTTER_REVISION})."
assert_reviewed_toolchain_custody
verify_expected_signer

VERSION_IDENTITY="$(sed -nE 's/^version:[[:space:]]*([^+[:space:]]+)\+([0-9]+)[[:space:]]*$/\1+\2/p' "${ROOT}/pubspec.yaml" | head -n 1)"
[[ -n "${VERSION_IDENTITY}" ]] || die 'Unable to read version: <semver>+<build> from pubspec.yaml.'
BUILD_NUMBER="${VERSION_IDENTITY##*+}"
[[ "${BUILD_NUMBER}" =~ ^[0-9]+$ ]] \
  || die "Unable to derive numeric Android build number from ${VERSION_IDENTITY}."
STAGE="$(mktemp -d /private/tmp/winsvpn-android-neutral.XXXXXX)"
chmod 0700 "${STAGE}"
[[ "$(cd "${STAGE}" && pwd -P)" == "${STAGE}" && "$(stat -f '%u' "${STAGE}")" == "$(id -u)" ]] \
  || die 'The producer-owned neutral stage failed ownership or symbolic-path validation.'
SOURCE_SNAPSHOT="${STAGE}/source-inputs.json"
STAGE_SNAPSHOT="${STAGE}/stage-inputs.json"
ROOT_AFTER_SNAPSHOT="${STAGE}/root-after-inputs.json"
STAGE_REPO="${STAGE}/source"
mkdir -m 0700 -- "${STAGE_REPO}"
snapshot_inputs "${ROOT}" "${SOURCE_SNAPSHOT}"
copy_snapshot "${ROOT}" "${STAGE_REPO}" "${SOURCE_SNAPSHOT}"
snapshot_inputs "${STAGE_REPO}" "${STAGE_SNAPSHOT}"
cmp -s "${SOURCE_SNAPSHOT}" "${STAGE_SNAPSHOT}" || die 'Neutral-stage Android release inputs do not match the source snapshot.'

STAGE_APK_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-apk/${VERSION_IDENTITY}"
STAGE_AAB_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-aab/${VERSION_IDENTITY}"
STAGE_TV_APK_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-tv-apk/${VERSION_IDENTITY}"
STAGE_TV_AAB_SYMBOLS="${STAGE_REPO}/.artifacts/private-release-symbols/android-tv-aab/${VERSION_IDENTITY}"
mkdir -p -- "${STAGE_APK_SYMBOLS}" "${STAGE_AAB_SYMBOLS}" "${STAGE_TV_APK_SYMBOLS}" "${STAGE_TV_AAB_SYMBOLS}"
chmod 0700 "${STAGE_APK_SYMBOLS}" "${STAGE_AAB_SYMBOLS}" "${STAGE_TV_APK_SYMBOLS}" "${STAGE_TV_AAB_SYMBOLS}"
(
  cd "${STAGE_REPO}"
  wins_release_android_flutter pub get --offline --enforce-lockfile --no-precompile
  validate_flutter_package_config() {
    wins_release_python_run tools/validate_flutter_package_config.py \
      --package-config "${STAGE_REPO}/.dart_tool/package_config.json" \
      --lockfile "${STAGE_REPO}/pubspec.lock" \
      --project-root "${STAGE_REPO}" \
      --flutter-root "${WINS_RELEASE_FLUTTER_ROOT}" \
      --pub-cache "${WINS_RELEASE_PUB_CACHE}" \
      --flutter-version "${REQUIRED_FLUTTER_VERSION}" \
      --dart-version "${REQUIRED_DART_VERSION}" \
      "$@"
  }
  PACKAGE_CONFIG_SHA256="$(validate_flutter_package_config)"
  [[ "${PACKAGE_CONFIG_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
    || die 'Flutter package configuration did not produce a valid release digest.'
  run_flutter_release_build() {
    validate_flutter_package_config --expected-digest "${PACKAGE_CONFIG_SHA256}" >/dev/null
    wins_release_android_flutter_build "$@"
    validate_flutter_package_config --expected-digest "${PACKAGE_CONFIG_SHA256}" >/dev/null
  }
  load_reviewed_winn3_descriptor_ring_defines
  # Not `mapfile`: tools/build_android_release.ps1 launches this producer with
  # `/bin/bash`, which on macOS is 3.2.57 and has no `mapfile` builtin at all,
  # so this line aborted the build with exit 127 before a single define was
  # collected. A plain command substitution also propagates the collector's own
  # exit status, which the process substitution behind `mapfile` discarded --
  # an unsupplied ring used to surface as "ring is empty" from the identity
  # tool instead of the collector's diagnostic naming the missing variable.
  WINN3_DEFINE_LINES="$(collect_winn3_descriptor_pubkey_defines)"
  WINN3_PUBKEY_DEFINES=()
  while IFS= read -r winn3_define_line; do
    if [[ -n "${winn3_define_line}" ]]; then
      WINN3_PUBKEY_DEFINES+=("${winn3_define_line}")
    fi
  done <<<"${WINN3_DEFINE_LINES}"
  # Returns 65 on an empty ring, so every later expansion of the array below is
  # reached only with at least one element -- which is what keeps `set -u` from
  # tripping over an empty array expansion on Bash 3.2.
  log_winn3_descriptor_pubkey_status "${#WINN3_PUBKEY_DEFINES[@]}"
  WINN3_RING_SHA256="$(wins_release_python_run tools/winn3_descriptor_ring_identity.py "${WINN3_PUBKEY_DEFINES[@]}")"
  # `tr`, not `${var,,}`: case-modifying expansion is Bash 4 syntax and is a
  # hard parse error on the Bash 3.2 that actually runs this file.
  EXPECTED_WINN3_RING_SHA256="$(printf '%s' "${WINS_EXPECTED_WINN3_DESCRIPTOR_RING_SHA256:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "${EXPECTED_WINN3_RING_SHA256}" =~ ^[0-9a-f]{64}$ &&
     "${EXPECTED_WINN3_RING_SHA256}" == "${WINN3_RING_SHA256}" ]] || die "Reviewed Winn3 descriptor ring identity mismatch. Computed=${WINN3_RING_SHA256}"
  WINN3_PUBKEY_DEFINES+=("--dart-define=WINS_WINN3_DESCRIPTOR_RING_SHA256=${WINN3_RING_SHA256}")
  # phone/tv product flavors removed Flutter's unflavored app-release.apk
  # finder. --flavor phone makes Flutter look for app-phone-release.apk/aab.
  # TV is still assembled so assembleTvRelease engine/signing gates cannot
  # disappear from this producer.
  run_flutter_release_build build apk --no-pub --release --flavor phone --obfuscate --split-debug-info="${STAGE_APK_SYMBOLS}" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android --dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android "${WINN3_PUBKEY_DEFINES[@]}"
  run_flutter_release_build build appbundle --no-pub --release --flavor phone --obfuscate --split-debug-info="${STAGE_AAB_SYMBOLS}" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android --dart-define=WINS_WINN3_RELAY_ENABLED_PLATFORMS=android "${WINN3_PUBKEY_DEFINES[@]}"
  run_flutter_release_build build apk --no-pub --release --flavor tv --obfuscate --split-debug-info="${STAGE_TV_APK_SYMBOLS}" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android "${WINN3_PUBKEY_DEFINES[@]}"
  run_flutter_release_build build appbundle --no-pub --release --flavor tv --obfuscate --split-debug-info="${STAGE_TV_AAB_SYMBOLS}" --dart-define=WINS_GOOGLE_PLAY_BUILD=true --dart-define=WINS_WINN3_ENABLED_PLATFORMS=android "${WINN3_PUBKEY_DEFINES[@]}"
  wins_release_python_run tools/verify_winn3_ring_artifact.py "${WINN3_RING_SHA256}" build/app/outputs/flutter-apk/app-phone-release.apk build/app/outputs/bundle/phoneRelease/app-phone-release.aab build/app/outputs/flutter-apk/app-tv-release.apk build/app/outputs/bundle/tvRelease/app-tv-release.aab
)
assert_reviewed_toolchain_custody

STAGE_APK="${STAGE_REPO}/build/app/outputs/flutter-apk/app-phone-release.apk"
STAGE_AAB="${STAGE_REPO}/build/app/outputs/bundle/phoneRelease/app-phone-release.aab"
STAGE_TV_APK="${STAGE_REPO}/build/app/outputs/flutter-apk/app-tv-release.apk"
STAGE_TV_AAB="${STAGE_REPO}/build/app/outputs/bundle/tvRelease/app-tv-release.aab"
R8_MAPPING="${STAGE_REPO}/build/app/outputs/mapping/phoneRelease/mapping.txt"
STAGE_TV_MAPPING="${STAGE_REPO}/build/app/outputs/mapping/tvRelease/mapping.txt"
NATIVE_SYMBOLS="${STAGE_REPO}/build/app/outputs/native-debug-symbols/phoneRelease/native-debug-symbols.zip"
STAGE_TV_NATIVE_SYMBOLS="${STAGE_REPO}/build/app/outputs/native-debug-symbols/tvRelease/native-debug-symbols.zip"
UNFLAVORED_APK="${STAGE_REPO}/build/app/outputs/flutter-apk/app-release.apk"
UNFLAVORED_AAB="${STAGE_REPO}/build/app/outputs/bundle/release/app-release.aab"
if [[ -e "${UNFLAVORED_APK}" || -L "${UNFLAVORED_APK}" || -e "${UNFLAVORED_AAB}" || -L "${UNFLAVORED_AAB}" ]]; then
  die 'Flutter searched for or produced unflavored app-release.apk/aab; pass --flavor so Flutter does not look for those names.'
fi
for output in "${STAGE_APK}" "${STAGE_AAB}" "${STAGE_TV_APK}" "${STAGE_TV_AAB}"; do
  [[ -s "${output}" && ! -L "${output}" ]] \
    || die "OWNER-BLOCKED: produced Android AAB/APK bytes are absent: ${output}"
done
for output in "${R8_MAPPING}" "${STAGE_TV_MAPPING}" "${NATIVE_SYMBOLS}" "${STAGE_TV_NATIVE_SYMBOLS}"; do
  [[ -s "${output}" && ! -L "${output}" ]] \
    || die "Required Android release output is unsafe, missing, or empty: ${output}"
done
wins_release_python_run "${STAGE_REPO}/tools/verify_standalone_v3_artifact.py" "${STAGE_APK}" "${STAGE_AAB}" "${STAGE_TV_APK}" "${STAGE_TV_AAB}"
# S14A (Play-policy artifact gate): all four artifacts above are built with
# --dart-define=WINS_GOOGLE_PLAY_BUILD=true, so none of them may carry R2
# prepaid, promo or referral redemption text. The gate derives its needles from
# the source it is pointed at, so it must read the staged tree, not ${ROOT}.
wins_release_python_run "${STAGE_REPO}/tools/android_play_redemption_gate.py" --repo "${STAGE_REPO}" "${STAGE_APK}" "${STAGE_AAB}" "${STAGE_TV_APK}" "${STAGE_TV_AAB}"
cp "${R8_MAPPING}" "${STAGE_APK_SYMBOLS}/proguard-mapping.txt"
cp "${R8_MAPPING}" "${STAGE_AAB_SYMBOLS}/proguard-mapping.txt"
cp "${NATIVE_SYMBOLS}" "${STAGE_AAB_SYMBOLS}/native-debug-symbols.zip"
cp "${STAGE_TV_MAPPING}" "${STAGE_TV_APK_SYMBOLS}/proguard-mapping.txt"
cp "${STAGE_TV_MAPPING}" "${STAGE_TV_AAB_SYMBOLS}/proguard-mapping.txt"
cp "${STAGE_TV_NATIVE_SYMBOLS}" "${STAGE_TV_AAB_SYMBOLS}/native-debug-symbols.zip"
PHONE_MAP_SHA256="$(shasum -a 256 "${R8_MAPPING}" | awk '{print $1}')"
TV_MAP_SHA256="$(shasum -a 256 "${STAGE_TV_MAPPING}" | awk '{print $1}')"
[[ "${PHONE_MAP_SHA256}" != "${TV_MAP_SHA256}" ]] \
  || die 'Android TV R8 mapping exactly reuses the phone/tablet mapping bytes.'

for spec in "android-apk:${STAGE_APK_SYMBOLS}:${STAGE_APK}" "android-aab:${STAGE_AAB_SYMBOLS}:${STAGE_AAB}" "android-apk:${STAGE_TV_APK_SYMBOLS}:${STAGE_TV_APK}" "android-aab:${STAGE_TV_AAB_SYMBOLS}:${STAGE_TV_AAB}"; do
  IFS=: read -r platform symbols artifact <<<"${spec}"
  wins_release_python_run "${STAGE_REPO}/tools/release_obfuscation_contract.py" record --platform "${platform}" --symbols-dir "${symbols}" --manifest "${symbols}/manifest.json" --artifact "${artifact}"
  wins_release_python_run "${STAGE_REPO}/tools/release_obfuscation_contract.py" verify --platform "${platform}" --symbols-dir "${symbols}" --manifest "${symbols}/manifest.json" --artifact "${artifact}"
  wins_release_python_run "${STAGE_REPO}/tools/private_release_symbol_custody.py" record --platform "${platform}" --symbols-dir "${symbols}" --artifact "${artifact}"
  wins_release_python_run "${STAGE_REPO}/tools/private_release_symbol_custody.py" verify --platform "${platform}" --symbols-dir "${symbols}" --artifact "${artifact}"
done
for privacy_spec in \
  "android-phone-tablet-apk:${STAGE_APK}" \
  "android-phone-tablet-aab:${STAGE_AAB}" \
  "android-tv-apk:${STAGE_TV_APK}" \
  "android-tv-aab:${STAGE_TV_AAB}"; do
  IFS=: read -r privacy_target privacy_artifact <<<"${privacy_spec}"
  wins_release_python_run_with_android_privacy_secrets \
    "${STAGE_REPO}/tools/validate_release_artifact_privacy.py" --artifacts \
    --target "${privacy_target}" --artifact "${privacy_artifact}" \
    --secret-env WINS_ANDROID_KEY_PASSWORD \
    --secret-env WINS_ANDROID_STORE_PASSWORD
done

ZIPALIGN="$(find_android_tool zipalign)"
run_android_sdk_native_tool "${ZIPALIGN}" -c -P 16 -v 4 "${STAGE_APK}" >/dev/null || die 'Android phone APK is not 16 KiB ZIP-aligned.'
run_android_sdk_native_tool "${ZIPALIGN}" -c -P 16 -v 4 "${STAGE_TV_APK}" >/dev/null || die 'Android TV APK is not 16 KiB ZIP-aligned.'
wins_release_python_run "${STAGE_REPO}/tools/verify_android_aab_page_alignment.py" "${STAGE_AAB}"
wins_release_python_run "${STAGE_REPO}/tools/verify_android_aab_page_alignment.py" "${STAGE_TV_AAB}"
export WINS_BUNDLETOOL_JAR="${WINS_BUNDLETOOL_JAR:-${ROOT}/.artifacts/tool-cache/bundletool/bundletool-all-${BUNDLETOOL_VERSION}.jar}"
[[ -f "${WINS_BUNDLETOOL_JAR}" && ! -L "${WINS_BUNDLETOOL_JAR}" ]] \
  || die "missing pinned bundletool-all-${BUNDLETOOL_VERSION}.jar; set WINS_BUNDLETOOL_JAR"
[[ "$(shasum -a 256 "${WINS_BUNDLETOOL_JAR}" | awk '{print $1}')" == "${BUNDLETOOL_ALL_SHA256}" ]] \
  || die "bundletool-all-${BUNDLETOOL_VERSION}.jar SHA-256 does not match the reviewed pin"
PHONE_APK_BEFORE="$(shasum -a 256 "${STAGE_APK}" | awk '{print $1}')"
PHONE_AAB_BEFORE="$(shasum -a 256 "${STAGE_AAB}" | awk '{print $1}')"
TV_APK_BEFORE="$(shasum -a 256 "${STAGE_TV_APK}" | awk '{print $1}')"
TV_AAB_BEFORE="$(shasum -a 256 "${STAGE_TV_AAB}" | awk '{print $1}')"
verify_exact_android_identity_and_r8 \
  "${STAGE_REPO}" \
  "build/app/outputs/flutter-apk/app-phone-release.apk" \
  "build/app/outputs/bundle/phoneRelease/app-phone-release.aab" \
  "build/app/outputs/flutter-apk/app-tv-release.apk" \
  "build/app/outputs/bundle/tvRelease/app-tv-release.aab" \
  ".artifacts/private-release-symbols/android-apk/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-aab/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-tv-apk/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-tv-aab/${VERSION_IDENTITY}/proguard-mapping.txt"
PHONE_APK_AFTER="$(shasum -a 256 "${STAGE_APK}" | awk '{print $1}')"
PHONE_AAB_AFTER="$(shasum -a 256 "${STAGE_AAB}" | awk '{print $1}')"
TV_APK_AFTER="$(shasum -a 256 "${STAGE_TV_APK}" | awk '{print $1}')"
TV_AAB_AFTER="$(shasum -a 256 "${STAGE_TV_AAB}" | awk '{print $1}')"
[[ "${PHONE_APK_BEFORE}" == "${PHONE_APK_AFTER}" ]] \
  || die 'Android phone APK current bytes changed during identity inspection.'
[[ "${PHONE_AAB_BEFORE}" == "${PHONE_AAB_AFTER}" ]] \
  || die 'Android phone/tablet AAB current bytes changed during identity inspection.'
[[ "${TV_APK_BEFORE}" == "${TV_APK_AFTER}" ]] \
  || die 'Android TV APK current bytes changed during identity inspection.'
[[ "${TV_AAB_BEFORE}" == "${TV_AAB_AFTER}" ]] \
  || die 'Android TV AAB current bytes changed during identity inspection.'
if cmp -s "${STAGE_AAB}" "${STAGE_TV_AAB}"; then
  die 'Android TV AAB exactly reuses the phone/tablet AAB bytes.'
fi
APK_SIGNATURE="$(run_android_apksigner verify -Werr --verbose --print-certs "${STAGE_APK}")" || die 'Android APK signature verification failed.'
APK_DIGEST="$(printf '%s\n' "${APK_SIGNATURE}" | sed -nE 's/.*certificate SHA-256 digest:[[:space:]]*([0-9A-Fa-f:]+).*/\1/p' | tr -d ':' | tr '[:upper:]' '[:lower:]' | sort -u)"
unset APK_SIGNATURE
AAB_JAR_VERIFICATION="$(wins_release_android_jdk_tool jarsigner -verify "${STAGE_AAB}" 2>&1)" || die 'Android AAB cryptographic signature verification failed.'
[[ "${AAB_JAR_VERIFICATION}" =~ jar[[:space:]]verified ]] || die 'Android AAB was not reported as cryptographically verified.'
[[ ! "${AAB_JAR_VERIFICATION}" =~ jar[[:space:]]is[[:space:]]unsigned ]] || die 'Android AAB was reported as unsigned.'
unset AAB_JAR_VERIFICATION
AAB_CERTIFICATE="$(wins_release_android_jdk_tool keytool -printcert -jarfile "${STAGE_AAB}" 2>&1)" || die 'Android AAB signer certificate could not be read.'
AAB_DIGEST="$(printf '%s\n' "${AAB_CERTIFICATE}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | tr -d ':' | tr '[:upper:]' '[:lower:]' | sort -u)"
unset AAB_CERTIFICATE
TV_AAB_JAR_VERIFICATION="$(wins_release_android_jdk_tool jarsigner -verify "${STAGE_TV_AAB}" 2>&1)" || die 'Android TV AAB cryptographic signature verification failed.'
[[ "${TV_AAB_JAR_VERIFICATION}" =~ jar[[:space:]]verified ]] || die 'Android TV AAB was not reported as cryptographically verified.'
[[ ! "${TV_AAB_JAR_VERIFICATION}" =~ jar[[:space:]]is[[:space:]]unsigned ]] || die 'Android TV AAB was reported as unsigned.'
unset TV_AAB_JAR_VERIFICATION
TV_AAB_CERTIFICATE="$(wins_release_android_jdk_tool keytool -printcert -jarfile "${STAGE_TV_AAB}" 2>&1)" || die 'Android TV AAB signer certificate could not be read.'
TV_AAB_DIGEST="$(printf '%s\n' "${TV_AAB_CERTIFICATE}" | sed -nE 's/^[[:space:]]*SHA256:[[:space:]]*([0-9A-Fa-f:]+)[[:space:]]*$/\1/p' | tr -d ':' | tr '[:upper:]' '[:lower:]' | sort -u)"
unset TV_AAB_CERTIFICATE
TV_APK_SIGNATURE="$(run_android_apksigner verify -Werr --verbose --print-certs "${STAGE_TV_APK}")" || die 'Android TV APK signature verification failed.'
TV_APK_DIGEST="$(printf '%s\n' "${TV_APK_SIGNATURE}" | sed -nE 's/.*certificate SHA-256 digest:[[:space:]]*([0-9A-Fa-f:]+).*/\1/p' | tr -d ':' | tr '[:upper:]' '[:lower:]' | sort -u)"
unset TV_APK_SIGNATURE
[[ -n "${APK_DIGEST}" && "${APK_DIGEST}" == "${AAB_DIGEST}" ]] \
  || die 'Android APK and AAB signer certificates differ or were not reported.'
[[ "$(printf '%s\n' "${AAB_DIGEST}" | wc -l | tr -d ' ')" == "1" ]] \
  || die 'Android AAB must report exactly one signer certificate fingerprint.'
[[ "$(printf '%s\n' "${TV_AAB_DIGEST}" | wc -l | tr -d ' ')" == "1" ]] \
  || die 'Android TV AAB must report exactly one signer certificate fingerprint.'
[[ -n "${TV_APK_DIGEST}" && "${APK_DIGEST}" == "${TV_APK_DIGEST}" ]] \
  || die 'Android phone APK and TV APK signer certificates differ or were not reported.'
[[ -n "${TV_AAB_DIGEST}" && "${APK_DIGEST}" == "${TV_AAB_DIGEST}" ]] \
  || die 'Android phone APK and TV AAB signer certificates differ or were not reported.'
[[ "${APK_DIGEST}" == "${EXPECTED_UPLOAD_CERTIFICATE_SHA256}" ]] || die "Android release artifacts use an unexpected upload signer: sha256=${APK_DIGEST}"
printf 'ANDROID RELEASE SIGNER: PASS sha256=%s\n' "${APK_DIGEST}"

snapshot_inputs "${ROOT}" "${ROOT_AFTER_SNAPSHOT}"
cmp -s "${SOURCE_SNAPSHOT}" "${ROOT_AFTER_SNAPSHOT}" || die 'Android release source inputs changed during the isolated build.'
/bin/bash "${DEPENDENCY_FREEZE_PARENT}" verify-index --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android
ROOT_APK_SYMBOLS="${ROOT}/.artifacts/private-release-symbols/android-apk/${VERSION_IDENTITY}"
ROOT_AAB_SYMBOLS="${ROOT}/.artifacts/private-release-symbols/android-aab/${VERSION_IDENTITY}"
ROOT_TV_APK_SYMBOLS="${ROOT}/.artifacts/private-release-symbols/android-tv-apk/${VERSION_IDENTITY}"
ROOT_TV_AAB_SYMBOLS="${ROOT}/.artifacts/private-release-symbols/android-tv-aab/${VERSION_IDENTITY}"
ROOT_APK="${ROOT}/build/app/outputs/flutter-apk/app-release.apk"
ROOT_AAB="${ROOT}/build/app/outputs/bundle/release/app-release.aab"
ROOT_TV_APK="${ROOT}/build/app/outputs/flutter-apk/app-tv-release.apk"
ROOT_TV_AAB="${ROOT}/build/app/outputs/bundle/tvRelease/app-tv-release.aab"
PREPARED_APK_SYMBOLS="$(prepare_symbols "${STAGE_APK_SYMBOLS}" "${ROOT_APK_SYMBOLS}")"
PREPARED_PATHS+=("${PREPARED_APK_SYMBOLS}")
PREPARED_AAB_SYMBOLS="$(prepare_symbols "${STAGE_AAB_SYMBOLS}" "${ROOT_AAB_SYMBOLS}")"
PREPARED_PATHS+=("${PREPARED_AAB_SYMBOLS}")
PREPARED_TV_APK_SYMBOLS="$(prepare_symbols "${STAGE_TV_APK_SYMBOLS}" "${ROOT_TV_APK_SYMBOLS}")"
PREPARED_PATHS+=("${PREPARED_TV_APK_SYMBOLS}")
PREPARED_TV_AAB_SYMBOLS="$(prepare_symbols "${STAGE_TV_AAB_SYMBOLS}" "${ROOT_TV_AAB_SYMBOLS}")"
PREPARED_PATHS+=("${PREPARED_TV_AAB_SYMBOLS}")
PREPARED_APK="$(prepare_file "${STAGE_APK}" "${ROOT_APK}")"
PREPARED_PATHS+=("${PREPARED_APK}")
PREPARED_AAB="$(prepare_file "${STAGE_AAB}" "${ROOT_AAB}")"
PREPARED_PATHS+=("${PREPARED_AAB}")
PREPARED_TV_APK="$(prepare_file "${STAGE_TV_APK}" "${ROOT_TV_APK}")"
PREPARED_PATHS+=("${PREPARED_TV_APK}")
PREPARED_TV_AAB="$(prepare_file "${STAGE_TV_AAB}" "${ROOT_TV_AAB}")"
PREPARED_PATHS+=("${PREPARED_TV_AAB}")

for pair in "${STAGE_APK}:${PREPARED_APK}" "${STAGE_AAB}:${PREPARED_AAB}" "${STAGE_TV_APK}:${PREPARED_TV_APK}" "${STAGE_TV_AAB}:${PREPARED_TV_AAB}"; do
  IFS=: read -r source_artifact prepared_artifact <<<"${pair}"
  [[ "$(shasum -a 256 "${source_artifact}" | awk '{print $1}')" == "$(shasum -a 256 "${prepared_artifact}" | awk '{print $1}')" ]] \
    || die 'Prepared Android artifact bytes differ from the fully verified staged artifact.'
done

for spec in "android-apk:${PREPARED_APK_SYMBOLS}:${PREPARED_APK}" "android-aab:${PREPARED_AAB_SYMBOLS}:${PREPARED_AAB}" "android-apk:${PREPARED_TV_APK_SYMBOLS}:${PREPARED_TV_APK}" "android-aab:${PREPARED_TV_AAB_SYMBOLS}:${PREPARED_TV_AAB}"; do
  IFS=: read -r platform symbols artifact <<<"${spec}"
  wins_release_python_run "${OBFUSCATION_CONTRACT}" verify --platform "${platform}" --symbols-dir "${symbols}" --manifest "${symbols}/manifest.json" --artifact "${artifact}"
  wins_release_python_run "${CUSTODY_TOOL}" verify --platform "${platform}" --symbols-dir "${symbols}" --artifact "${artifact}"
done
# No exact-target privacy scan of the prepared copies: the exact target binds
# the canonical artifact filename, and a prepared copy is a sibling temporary
# (android_release_publication.py renames within one parent only). Its bytes
# equal the staged artifact scanned above under its canonical name, and the
# canonical published paths are scanned again right after the commit.

wins_release_python_run "${PUBLICATION_TOOL}" commit --state "${PUBLICATION_STATE}" \
  --pair "${PREPARED_APK_SYMBOLS}" "${ROOT_APK_SYMBOLS}" \
  --pair "${PREPARED_AAB_SYMBOLS}" "${ROOT_AAB_SYMBOLS}" \
  --pair "${PREPARED_TV_APK_SYMBOLS}" "${ROOT_TV_APK_SYMBOLS}" \
  --pair "${PREPARED_TV_AAB_SYMBOLS}" "${ROOT_TV_AAB_SYMBOLS}" \
  --pair "${PREPARED_APK}" "${ROOT_APK}" \
  --pair "${PREPARED_AAB}" "${ROOT_AAB}" \
  --pair "${PREPARED_TV_APK}" "${ROOT_TV_APK}" \
  --pair "${PREPARED_TV_AAB}" "${ROOT_TV_AAB}"
PUBLICATION_ACTIVE=1

for spec in "android-apk:${ROOT_APK_SYMBOLS}:${ROOT_APK}" "android-aab:${ROOT_AAB_SYMBOLS}:${ROOT_AAB}" "android-apk:${ROOT_TV_APK_SYMBOLS}:${ROOT_TV_APK}" "android-aab:${ROOT_TV_AAB_SYMBOLS}:${ROOT_TV_AAB}"; do
  IFS=: read -r platform symbols artifact <<<"${spec}"
  wins_release_python_run "${OBFUSCATION_CONTRACT}" verify --platform "${platform}" --symbols-dir "${symbols}" --manifest "${symbols}/manifest.json" --artifact "${artifact}"
  wins_release_python_run "${CUSTODY_TOOL}" verify --platform "${platform}" --symbols-dir "${symbols}" --artifact "${artifact}"
done
for privacy_spec in \
  "android-phone-tablet-apk:${ROOT_APK}" \
  "android-phone-tablet-aab:${ROOT_AAB}" \
  "android-tv-apk:${ROOT_TV_APK}" \
  "android-tv-aab:${ROOT_TV_AAB}"; do
  IFS=: read -r privacy_target privacy_artifact <<<"${privacy_spec}"
  wins_release_python_run_with_android_privacy_secrets \
    "${PRIVACY_VALIDATOR}" --artifacts \
    --target "${privacy_target}" --artifact "${privacy_artifact}" \
    --secret-env WINS_ANDROID_KEY_PASSWORD \
    --secret-env WINS_ANDROID_STORE_PASSWORD
done
for pair in "${STAGE_APK}:${ROOT_APK}" "${STAGE_AAB}:${ROOT_AAB}" "${STAGE_TV_APK}:${ROOT_TV_APK}" "${STAGE_TV_AAB}:${ROOT_TV_AAB}"; do
  IFS=: read -r source_artifact root_artifact <<<"${pair}"
  [[ "$(shasum -a 256 "${source_artifact}" | awk '{print $1}')" == "$(shasum -a 256 "${root_artifact}" | awk '{print $1}')" ]] \
    || die 'Canonical Android artifact bytes differ from the fully verified staged artifact.'
done
verify_exact_android_identity_and_r8 \
  "${ROOT}" \
  "build/app/outputs/flutter-apk/app-release.apk" \
  "build/app/outputs/bundle/release/app-release.aab" \
  "build/app/outputs/flutter-apk/app-tv-release.apk" \
  "build/app/outputs/bundle/tvRelease/app-tv-release.aab" \
  ".artifacts/private-release-symbols/android-apk/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-aab/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-tv-apk/${VERSION_IDENTITY}/proguard-mapping.txt" \
  ".artifacts/private-release-symbols/android-tv-aab/${VERSION_IDENTITY}/proguard-mapping.txt"
/bin/bash "${DEPENDENCY_FREEZE_PARENT}" verify-index --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android
wins_release_python_run "${PUBLICATION_TOOL}" finalize --state "${PUBLICATION_STATE}"
PUBLICATION_ACTIVE=0

finish_receipt() {
  local begin="$1" artifact="$2" target="$3" receipt="$4"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" finish-build --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android \
    --begin "${begin}" --artifact "${artifact}" --producer tools/build_android_release_macos.sh \
    --toolchain-name Flutter --toolchain-version "${FLUTTER_VERSION}" --toolchain-revision "${FLUTTER_REVISION}" \
    --target "${target}" --output "${receipt}"
  /bin/bash "${DEPENDENCY_FREEZE_PARENT}" verify-receipt --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform android --receipt "${receipt}" --artifact "${artifact}"
}
finish_receipt "${APK_BEGIN}" "${ROOT_APK}" android-release-apk "${APK_RECEIPT}"
finish_receipt "${AAB_BEGIN}" "${ROOT_AAB}" android-release-aab "${AAB_RECEIPT}"
finish_receipt "${TV_APK_BEGIN}" "${ROOT_TV_APK}" android-tv-release-apk "${TV_APK_RECEIPT}"
finish_receipt "${TV_AAB_BEGIN}" "${ROOT_TV_AAB}" android-tv-release-aab "${TV_AAB_RECEIPT}"

printf 'ANDROID MACOS RELEASE BUILD: PASS version=%s\n' "${VERSION_IDENTITY}"
printf 'APK: %s sha256=%s\n' "${ROOT_APK}" "$(shasum -a 256 "${ROOT_APK}" | awk '{print $1}')"
printf 'AAB: %s sha256=%s\n' "${ROOT_AAB}" "$(shasum -a 256 "${ROOT_AAB}" | awk '{print $1}')"
printf 'TV APK: %s sha256=%s\n' "${ROOT_TV_APK}" "$(shasum -a 256 "${ROOT_TV_APK}" | awk '{print $1}')"
printf 'TV AAB: %s bytes=%s sha256=%s\n' "${ROOT_TV_AAB}" "$(stat -f '%z' "${ROOT_TV_AAB}")" "$(shasum -a 256 "${ROOT_TV_AAB}" | awk '{print $1}')"
printf 'APK receipt: %s\nAAB receipt: %s\nTV APK receipt: %s\nTV AAB receipt: %s\n' "${APK_RECEIPT}" "${AAB_RECEIPT}" "${TV_APK_RECEIPT}" "${TV_AAB_RECEIPT}"
printf 'No Play Console upload or publication occurred.\n'
