#!/bin/bash -p
# Independent Wear OS signed-AAB producer.
#
# Writes a permission-frozen signed-AAB receipt. Loads the same owner-only
# ${HOME}/.winsvpn/android-release.env and external keystore contract as phone/TV.
# Verifies the release Python, the JDK, the Android SDK root and the exact
# latest-stable bundletool against tools/toolchain-pins.json and
# wear_os/tools/external_tool_pins.json, using the same current-user pinned home
# toolchain model as the Android phone producer (no root-owned custody trees).
# Never accepts ambient signing variables, debug fallback, PATH discovery, a
# leftover AAB, or a downloaded bundletool. This script never uploads to Play and
# never invokes the phone/TV Android producer.
case "$-" in
  *p*) ;;
  *) printf 'WEAR OS RELEASE: FAIL: invoke with /bin/bash -p\n' >&2; exit 126 ;;
esac
unset BASH_ENV ENV CDPATH GLOBIGNORE
unset WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS \
  WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
set -Eeuo pipefail
case "$-" in *x*) set +x ;; esac
umask 077

WEAR="$(cd "$(/usr/bin/dirname "$0")/.." && pwd -P)"
ROOT="$(cd "${WEAR}/.." && pwd -P)"

PIN_PYTHON_BIN="/usr/bin/python3"
PIN_MANIFEST="${WEAR}/tools/external_tool_pins.json"
RECEIPT_TOOL="${WEAR}/tools/create_signed_aab_receipt.py"
ASSERT_AAB="${WEAR}/tools/assert_release_aab.py"
SIGNER_TOOL="${ROOT}/tools/verify_android_aab_signers.py"
CUSTODY_TOOL="${ROOT}/tools/private_release_symbol_custody.py"
PRIVACY_TOOL="${ROOT}/tools/validate_release_artifact_privacy.py"
SOURCE_FREEZE="${ROOT}/tools/release_source_freeze.py"
DEPENDENCY_FREEZE="${ROOT}/tools/run_release_dependency_freeze.sh"
GRADLEW="${WEAR}/gradlew"
CANONICAL_AAB="${WEAR}/app/build/outputs/bundle/release/app-release.aab"
MAPPING_SRC="${WEAR}/app/build/outputs/mapping/release"
OWNER_SIGNING_ENV="${HOME}/.winsvpn/android-release.env"
RELEASE_INDEX=""

die() {
  printf 'WEAR OS RELEASE: FAIL: %s\n' "$*" >&2
  exit 1
}

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "Wear OS release producer must run on macOS"
[[ "$(/usr/bin/id -u)" != "0" ]] \
  || die "Wear OS release production must run as the current non-root user; Gradle and signing are never run as root"
[[ -f "${PIN_PYTHON_BIN}" && -x "${PIN_PYTHON_BIN}" && ! -L "${PIN_PYTHON_BIN}" ]] \
  || die "OWNER-BLOCKED: bootstrap /usr/bin/python3 is unavailable"
[[ -f "${PIN_MANIFEST}" && ! -L "${PIN_MANIFEST}" ]] \
  || die "OWNER-BLOCKED: Wear external-tool pin manifest is absent"
[[ -x "${GRADLEW}" ]] || die "wear_os/gradlew is missing or not executable"
[[ -f "${RECEIPT_TOOL}" ]] || die "Wear signed-AAB receipt tool is missing"
[[ -f "${ASSERT_AAB}" ]] || die "Wear AAB form-factor inspector is missing"
[[ -f "${SIGNER_TOOL}" ]] || die "AAB signer verifier is missing"
[[ -f "${CUSTODY_TOOL}" ]] || die "private symbol custody tool is missing"
[[ -f "${PRIVACY_TOOL}" ]] || die "release artifact privacy validator is missing"
[[ -f "${SOURCE_FREEZE}" ]] || die "source freeze tool is missing"
[[ -f "${DEPENDENCY_FREEZE}" ]] || die "dependency freeze tool is missing"

for ambient_toolchain_override in PYTHON_BIN WINS_RELEASE_PYTHON JAVA_HOME \
  WINS_BUNDLETOOL_JAR ANDROID_SDK_ROOT ANDROID_HOME \
  WINS_RELEASE_OPENSSL WINS_RELEASE_KEYTOOL WINS_RELEASE_JARSIGNER; do
  [[ -z "${!ambient_toolchain_override+x}" ]] \
    || die "ambient ${ambient_toolchain_override} is forbidden; tools/toolchain-pins.json and wear_os/tools/external_tool_pins.json own Wear tools"
done

assert_private_android_signing_env_file() {
  local path="$1" file_uid file_mode file_links current_uid parent parent_uid parent_mode
  [[ -f "${path}" && -r "${path}" && ! -L "${path}" ]] \
    || die "Android signing environment must be a readable regular non-symlink file: ${path}"
  parent="$(/usr/bin/dirname "${path}")"
  [[ -d "${parent}" && ! -L "${parent}" ]] \
    || die "Android signing environment parent must be a regular non-symlink directory: ${parent}"
  current_uid="$(/usr/bin/id -u)"
  file_uid="$(/usr/bin/stat -f '%u' "${path}")" \
    || die "Could not inspect Android signing environment ownership."
  file_mode="$(/usr/bin/stat -f '%Lp' "${path}")" \
    || die "Could not inspect Android signing environment permissions."
  file_links="$(/usr/bin/stat -f '%l' "${path}")" \
    || die "Could not inspect Android signing environment link count."
  parent_uid="$(/usr/bin/stat -f '%u' "${parent}")" \
    || die "Could not inspect Android signing environment parent ownership."
  parent_mode="$(/usr/bin/stat -f '%Lp' "${parent}")" \
    || die "Could not inspect Android signing environment parent permissions."
  [[ "${file_uid}" == "${current_uid}" ]] \
    || die "Android signing environment must be owned by the current user."
  [[ "${file_links}" == "1" ]] \
    || die "Android signing environment must not be hard-linked."
  (( (8#${file_mode} & 8#177) == 0 )) \
    || die "Android signing environment must use mode 0600 or stricter without execute bits."
  [[ "${parent_uid}" == "${current_uid}" ]] \
    || die "Android signing environment parent must be owned by the current user."
  (( (8#${parent_mode} & 8#022) == 0 )) \
    || die "Android signing environment parent must not be writable by group or other."
}

load_owner_android_signing_env() {
  local path line assignment key value seen='|' line_number=0
  path="${OWNER_SIGNING_ENV}"
  [[ -e "${path}" || -L "${path}" ]] \
    || die "OWNER-BLOCKED: owner-only ${HOME}/.winsvpn/android-release.env is absent"
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
    || die "WINS_ANDROID_KEY_ALIAS contains unsupported characters."
  [[ "${WINS_ANDROID_KEY_ALIAS}" != *[Dd][Ee][Bb][Uu][Gg]* ]] \
    || die "OWNER-BLOCKED: Wear release must not use a debug or test key"
  [[ "${WINS_ANDROID_KEY_ALIAS}" != *[Tt][Ee][Ss][Tt]* ]] \
    || die "OWNER-BLOCKED: Wear release must not use a debug or test key"
  local keystore_name
  keystore_name="$(/usr/bin/basename "${WINS_ANDROID_KEYSTORE}")"
  [[ "${keystore_name}" != *[Dd][Ee][Bb][Uu][Gg]* ]] \
    || die "OWNER-BLOCKED: Wear release must not use a debug or test key"
  [[ "${keystore_name}" != *[Tt][Ee][Ss][Tt]* ]] \
    || die "OWNER-BLOCKED: Wear release must not use a debug or test key"
}

assert_owner_keystore_present() {
  [[ "${WINS_ANDROID_KEYSTORE}" == /* ]] \
    || die "OWNER-BLOCKED: WINS_ANDROID_KEYSTORE must be an absolute external path."
  [[ -f "${WINS_ANDROID_KEYSTORE}" && ! -L "${WINS_ANDROID_KEYSTORE}" && -s "${WINS_ANDROID_KEYSTORE}" ]] \
    || die "OWNER-BLOCKED: missing Android upload keystore"
}

assert_private_external_keystore() {
  local path="$1"
  "${PIN_PYTHON_BIN}" - "${ROOT}" "${path}" <<'PY'
import os
import pathlib
import stat
import sys

repo = pathlib.Path(sys.argv[1]).resolve(strict=True)
candidate = pathlib.Path(sys.argv[2]).expanduser()
if not candidate.is_absolute():
    raise SystemExit("WINS_ANDROID_KEYSTORE must be an absolute external path.")
cursor = pathlib.Path(candidate.anchor)
for part in candidate.parts[1:]:
    cursor /= part
    info = cursor.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"Android signing keystore path traverses a symbolic link: {cursor}")
resolved = candidate.resolve(strict=True)
if repo == resolved or repo in resolved.parents:
    raise SystemExit("Android signing keystore must remain outside the repository.")
info = resolved.stat()
if not stat.S_ISREG(info.st_mode):
    raise SystemExit("Android signing keystore must be a regular file.")
if info.st_nlink != 1:
    raise SystemExit("Android signing keystore must not be hard-linked.")
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit("Android signing keystore must be current-user-owned with mode 0600 or stricter.")
print(resolved)
PY
}

resolve_repo_index() {
  local requested="$1" candidate parent resolved
  [[ -n "${requested}" ]] || die "OWNER-BLOCKED: --release-input-index is required"
  if [[ "${requested}" == /* ]]; then candidate="${requested}"; else candidate="${ROOT}/${requested}"; fi
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || die "OWNER-BLOCKED: Wear dependency freeze index is missing or symbolic"
  parent="$(cd "$(/usr/bin/dirname "${candidate}")" && pwd -P)"
  resolved="${parent}/$(/usr/bin/basename "${candidate}")"
  case "${resolved}" in
    "${ROOT}"/.artifacts/*/RELEASE_INPUT_INDEX.json) ;;
    *) die "OWNER-BLOCKED: release input index must be a repository .artifacts RELEASE_INPUT_INDEX.json" ;;
  esac
  printf '%s\n' "${resolved}"
}

load_owner_android_signing_env
assert_complete_android_signing_env
assert_owner_keystore_present
WINS_ANDROID_KEYSTORE="$(assert_private_external_keystore "${WINS_ANDROID_KEYSTORE}")" \
  || die "OWNER-BLOCKED: missing Android upload keystore"

if [[ -e "${CANONICAL_AAB}" || -L "${CANONICAL_AAB}" ]]; then
  die "stale Wear AAB already exists; refusing to accept a leftover artifact: ${CANONICAL_AAB}"
fi

while (( $# > 0 )); do
  case "$1" in
    --release-input-index)
      (( $# >= 2 )) || die "--release-input-index requires a value."
      RELEASE_INDEX="$2"
      shift 2
      ;;
    *) die "Unknown argument: $1" ;;
  esac
done
RELEASE_INDEX="$(resolve_repo_index "${RELEASE_INDEX}")"

BUNDLETOOL_ARCHIVE="$("${PIN_PYTHON_BIN}" - "${PIN_MANIFEST}" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_bytes().decode("ascii"))
bundletool = payload["bundletool"]
version = bundletool["version"]
artifact = bundletool["artifact"]
source = bundletool["source_url"]
expected = f"https://github.com/google/bundletool/releases/download/{version}/{artifact}"
if source != expected or not re.fullmatch(r"[0-9a-f]{64}", bundletool["sha256"]):
    raise SystemExit("bundletool source/hash pin is not the reviewed latest-stable Google release")
if bundletool.get("latest_stable") is not True or payload.get("latest_stable") is not True:
    raise SystemExit("Wear bundletool pin is not marked latest-stable")
print(bundletool["archive_path"])
print(bundletool["sha256"])
print(payload["android_sdk"]["root"])
PY
)" || die "OWNER-BLOCKED: Wear external-tool pin could not be parsed"
BUNDLETOOL_PATH="$(printf '%s\n' "${BUNDLETOOL_ARCHIVE}" | /usr/bin/sed -n '1p')"
BUNDLETOOL_SHA256="$(printf '%s\n' "${BUNDLETOOL_ARCHIVE}" | /usr/bin/sed -n '2p')"
PINNED_SDK_ROOT="$(printf '%s\n' "${BUNDLETOOL_ARCHIVE}" | /usr/bin/sed -n '3p')"
[[ -n "${BUNDLETOOL_PATH}" && -n "${BUNDLETOOL_SHA256}" && -n "${PINNED_SDK_ROOT}" ]] \
  || die "OWNER-BLOCKED: Wear external-tool pin is incomplete"
[[ -L "${BUNDLETOOL_PATH}" ]] && die "bundletool CLI jar must not be a symlink"
[[ -f "${BUNDLETOOL_PATH}" ]] \
  || die "OWNER-BLOCKED: exact latest-stable bundletool archive is absent at ${BUNDLETOOL_PATH}"

OBSERVED_BUNDLETOOL_SHA256="$("${PIN_PYTHON_BIN}" - "${BUNDLETOOL_PATH}" <<'PY'
from pathlib import Path
import hashlib
import sys

digest = hashlib.sha256()
with Path(sys.argv[1]).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
)"
[[ "${OBSERVED_BUNDLETOOL_SHA256}" == "${BUNDLETOOL_SHA256}" ]] \
  || die "bundletool-all jar SHA-256 does not match the reviewed pin"

[[ -d "${PINNED_SDK_ROOT}" && ! -L "${PINNED_SDK_ROOT}" && "${PINNED_SDK_ROOT}" == /* ]] \
  || die "OWNER-BLOCKED: authenticated Android SDK tree is absent at ${PINNED_SDK_ROOT}"

# Pinned home toolchains (owner ruling 2026-10-21, "AI ports the Wear build").
#
# Python and the JDK used to be authenticated through root-owned custody trees,
# which need a root-granted release Python authority that expires by design. They
# are now the current user's installs, verified exactly as the Android phone
# producer verifies them, against the digests in tools/toolchain-pins.json: the
# release Python executable (path, SHA-256, implementation and version) with its
# authenticated runtime wheels, and the home JDK tree (release file, tool
# identities, canonical tree digest). Nothing here needs root.
#
# The eight functions between the BEGIN and END markers are byte-identical copies
# of the phone producer's functions of the same names. The last of them,
# run_with_exact_environment, runs a command in an environment of exactly the
# given NAME=value assignments without ever putting a value on a command line
# (env -i NAME=value would show signing passwords to any process observer). The
# phone producer cannot be sourced (it runs the release build when it is read) and
# the phone tests parse its text, so the copies are held in step by
# test_pinned_toolchain_functions_match_the_phone_producer in
# wear_os/tools/test_prepare_release_build_receipt.py. Change both sides together.
# BEGIN functions shared verbatim with the phone producer
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
# END functions shared verbatim with the phone producer

RELEASE_PYTHON_WORK=""
RELEASE_PYTHON_WORK_PARENT=""
RELEASE_PYTHON_VENDOR=""
RELEASE_PYTHON_EXECUTABLE_PIN_SHA256=""
WINS_RELEASE_JAVA_HOME=""
WINS_RELEASE_JAVA_TREE_SHA256=""
TOOLCHAIN_PINS_CUSTODY_SHA256=""

# Binds the pinned release Python (executable bytes, identity, authenticated
# runtime wheels) and the pinned home JDK (tree digest, identity), and records the
# pin manifest digest, so assert_reviewed_wear_toolchains can detect any change.
prepare_wear_toolchains() {
  local java_version java_release identity
  [[ -z "${RELEASE_PYTHON_WORK}" && -z "${WINS_RELEASE_JAVA_HOME}" ]] \
    || die "pinned Wear toolchains were already prepared"
  [[ "${HOME}" == /* && "${HOME}" != *$'\n'* ]] \
    || die "OWNER-BLOCKED: HOME must be an absolute path"
  REQUIRED_PYTHON_VERSION="$(read_wins_toolchain_pin tools.python.version)" \
    || die "OWNER-BLOCKED: tools/toolchain-pins.json does not pin the release Python version"
  REQUIRED_PYTHON_IMPLEMENTATION="$(read_wins_toolchain_pin tools.python.implementation)" \
    || die "OWNER-BLOCKED: tools/toolchain-pins.json does not pin the release Python implementation"
  prepare_pinned_release_python
  java_version="$(read_wins_toolchain_pin tools.java.version)" \
    || die "OWNER-BLOCKED: tools/toolchain-pins.json does not pin the JDK version"
  java_release="$(read_wins_toolchain_pin tools.java.release_name)" \
    || die "OWNER-BLOCKED: tools/toolchain-pins.json does not pin the JDK release name"
  [[ "${java_version}" =~ ^[0-9][0-9A-Za-z.+_-]*$ ]] \
    || die "OWNER-BLOCKED: the JDK version pin is malformed"
  WINS_RELEASE_JAVA_HOME="${HOME}/.local/toolchains/jdk-${java_version}"
  WINS_RELEASE_JAVA_TREE_SHA256="$(verify_home_toolchain_tree java "${WINS_RELEASE_JAVA_HOME}")" \
    || die "OWNER-BLOCKED: pinned home JDK failed verification at ${WINS_RELEASE_JAVA_HOME}"
  identity="$(/usr/bin/env -i HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" \
    PATH="${WINS_RELEASE_JAVA_HOME}/bin:/usr/bin:/bin:/usr/sbin:/sbin" LANG=C LC_ALL=C \
    JAVA_HOME="${WINS_RELEASE_JAVA_HOME}" "${WINS_RELEASE_JAVA_HOME}/bin/java" -version 2>&1)" \
    || die "OWNER-BLOCKED: pinned home JDK did not report its identity"
  [[ "${identity}" == *"version \"${java_version}\""* && "${identity}" == *"(build ${java_release#jdk-})"* ]] \
    || die "OWNER-BLOCKED: pinned home JDK identity mismatch: ${identity}"
  TOOLCHAIN_PINS_CUSTODY_SHA256="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")" \
    || die "toolchain pin manifest custody could not be established"
}

# Rechecks everything prepare_wear_toolchains and the bundletool pin check bound.
# Runs before Gradle starts, after it returns, and before the build is attested.
assert_reviewed_wear_toolchains() {
  local current_python current_java current_pins current_bundletool
  current_python="$(custody_regular_file_sha256 "${PYTHON_BIN}")" \
    || die "pinned release Python executable could not be rechecked"
  [[ -n "${RELEASE_PYTHON_EXECUTABLE_PIN_SHA256}" \
     && "${current_python}" == "${RELEASE_PYTHON_EXECUTABLE_PIN_SHA256}" ]] \
    || die "pinned release Python executable no longer matches tools/toolchain-pins.json"
  current_java="$(verify_home_toolchain_tree java "${WINS_RELEASE_JAVA_HOME}")" \
    || die "pinned home JDK recheck failed"
  [[ -n "${WINS_RELEASE_JAVA_TREE_SHA256}" && "${current_java}" == "${WINS_RELEASE_JAVA_TREE_SHA256}" ]] \
    || die "pinned home JDK tree changed after it was verified"
  current_pins="$(custody_regular_file_sha256 "${ROOT}/tools/toolchain-pins.json")" \
    || die "toolchain pin manifest custody could not be rechecked"
  [[ -n "${TOOLCHAIN_PINS_CUSTODY_SHA256}" && "${current_pins}" == "${TOOLCHAIN_PINS_CUSTODY_SHA256}" ]] \
    || die "toolchain pin manifest changed after custody was established"
  current_bundletool="$(custody_regular_file_sha256 "${BUNDLETOOL_PATH}")" \
    || die "bundletool CLI jar could not be rechecked"
  [[ "${current_bundletool}" == "${BUNDLETOOL_SHA256}" ]] \
    || die "bundletool-all jar no longer matches the reviewed pin"
}

# The Gradle build also writes HTML reports (the R8 config analyzer, the problems
# report, lint) into the generated trees under the frozen wear_os source root, and
# the release source freeze refuses shipping-source file types there. Once the
# mapping symbols are in private custody, remove every generated tree except the
# directory that holds the signed AAB. The AAB, its bytes and every frozen input
# stay as they are; only Gradle's own residue goes.
prune_generated_wear_outputs() {
  (
    local generated
    cd "${WEAR}" || die "Wear source root could not be opened for pruning"
    [[ "$(pwd -P)" == "${WEAR}" ]] \
      || die "Wear source root changed before pruning"
    for generated in .gradle .kotlin build app app/build; do
      [[ ! -L "${generated}" ]] \
        || die "generated Wear output must not be a symbolic link: ${generated}"
    done
    /bin/rm -rf -- .gradle .kotlin build \
      || die "generated Wear caches could not be pruned"
    [[ -d app/build ]] || exit 0
    cd app/build || die "Wear app build directory could not be opened for pruning"
    [[ "$(pwd -P)" == "${WEAR}/app/build" ]] \
      || die "Wear app build directory escaped the Wear source root"
    /usr/bin/find . -mindepth 1 \
      ! -path ./outputs ! -path ./outputs/bundle \
      ! -path ./outputs/bundle/release ! -path './outputs/bundle/release/*' \
      -delete
  ) || die "generated Wear outputs could not be pruned"
}

# Runs the pinned interpreter in a clean environment: only HOME, TMPDIR, the
# producer's PATH, the read-only vendor directory, the no-user-site and no-bytecode
# switches, and the tool locations the named gate verifies for itself cross the
# boundary. Startup flags match the phone producer: -S, and -I -S for the signer
# verifier. The two Android signing passwords cross only into the privacy
# validator and only when its arguments name them with --secret-env, exactly as
# the phone producer passes them; no other gate ever receives them.
wins_release_python_run() {
  local -a startup_flags tool_env
  local previous_argument="" argument
  [[ -n "${RELEASE_PYTHON_VENDOR}" && -d "${RELEASE_PYTHON_VENDOR}" && -n "${PYTHON_BIN:-}" ]] || {
    printf 'WEAR OS RELEASE: FAIL: pinned release Python was not prepared\n' >&2
    return 1
  }
  startup_flags=(-S)
  tool_env=()
  # The exact release secret scan reads the inventory this path names; only the
  # path crosses, never the inventory contents.
  [[ -z "${WINS_RELEASE_SECRET_INVENTORY:-}" ]] \
    || tool_env+=("WINS_RELEASE_SECRET_INVENTORY=${WINS_RELEASE_SECRET_INVENTORY}")
  case "${1:-}" in
    "${SIGNER_TOOL}")
      startup_flags=(-I -S)
      tool_env+=(
        "WINS_RELEASE_JAVA_HOME=${WINS_RELEASE_JAVA_HOME}"
        "WINS_BUNDLETOOL_JAR=${BUNDLETOOL_PATH}"
        "ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}"
      )
      ;;
    "${PRIVACY_TOOL}")
      for argument in "$@"; do
        if [[ "${previous_argument}" == "--secret-env" ]]; then
          case "${argument}" in
            WINS_ANDROID_KEY_PASSWORD|WINS_ANDROID_STORE_PASSWORD)
              [[ -n "${!argument:-}" && "${!argument}" != *$'\n'* && "${!argument}" != *$'\r'* ]] || {
                printf 'WEAR OS RELEASE: FAIL: the privacy scan needs %s\n' "${argument}" >&2
                return 1
              }
              tool_env+=("${argument}=${!argument}")
              ;;
          esac
        fi
        previous_argument="${argument}"
      done
      ;;
    "${ASSERT_AAB}")
      # The Wear inspector refuses an ambient bundletool path and finds its own
      # reviewed jar; it needs only the JDK location.
      tool_env+=("WINS_RELEASE_JAVA_HOME=${WINS_RELEASE_JAVA_HOME}")
      ;;
    "${RECEIPT_TOOL}")
      # The receipt tool runs the Wear inspector and the signer verifier in its
      # own process, so it needs the JDK and SDK locations as well as its three
      # exact release tools. It must not receive an ambient bundletool path.
      tool_env+=(
        "WINS_RELEASE_JAVA_HOME=${WINS_RELEASE_JAVA_HOME}"
        "ANDROID_SDK_ROOT=${ANDROID_SDK_ROOT}"
        "WINS_RELEASE_OPENSSL=${WINS_RELEASE_OPENSSL}"
        "WINS_RELEASE_KEYTOOL=${WINS_RELEASE_KEYTOOL}"
        "WINS_RELEASE_JARSIGNER=${WINS_RELEASE_JARSIGNER}"
      )
      ;;
  esac
  run_with_exact_environment \
    HOME="${HOME}" TMPDIR="${TMPDIR:-/private/tmp}" PATH="${PATH}" \
    PYTHONPATH="${RELEASE_PYTHON_VENDOR}" PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
    ${tool_env[@]+"${tool_env[@]}"} \
    -- "${PYTHON_BIN}" "${startup_flags[@]}" "$@"
}

cleanup() {
  local status=$?
  trap - EXIT
  release_python_cleanup || status=74
  unset WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD
  exit "${status}"
}
trap cleanup EXIT

prepare_wear_toolchains

JAVA_HOME="${WINS_RELEASE_JAVA_HOME}"
ANDROID_SDK_ROOT="${PINNED_SDK_ROOT}"
ANDROID_HOME="${ANDROID_SDK_ROOT}"
export JAVA_HOME ANDROID_SDK_ROOT ANDROID_HOME
export WINS_RELEASE_JAVA_HOME
export WINS_RELEASE_KEYTOOL="${JAVA_HOME}/bin/keytool"
export WINS_RELEASE_JARSIGNER="${JAVA_HOME}/bin/jarsigner"
export WINS_RELEASE_OPENSSL="/usr/bin/openssl"
PATH="${JAVA_HOME}/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
[[ -x "${JAVA_HOME}/bin/java" && ! -L "${JAVA_HOME}/bin/java" ]] \
  || die "OWNER-BLOCKED: authenticated JDK java is absent"
[[ -x "${WINS_RELEASE_KEYTOOL}" && ! -L "${WINS_RELEASE_KEYTOOL}" ]] \
  || die "OWNER-BLOCKED: authenticated keytool is absent"
[[ -x "${WINS_RELEASE_JARSIGNER}" && ! -L "${WINS_RELEASE_JARSIGNER}" ]] \
  || die "OWNER-BLOCKED: authenticated jarsigner is absent"
[[ -x "${WINS_RELEASE_OPENSSL}" && ! -L "${WINS_RELEASE_OPENSSL}" ]] \
  || die "OWNER-BLOCKED: authenticated OpenSSL is absent"

wins_release_python_run "${SOURCE_FREEZE}" --repo "${ROOT}" \
  || die "OWNER-BLOCKED: current source freeze is unavailable"
/bin/bash "${DEPENDENCY_FREEZE}" verify-index \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform wear_os \
  || die "OWNER-BLOCKED: Wear dependency freeze index failed"

VERSION_NAME="$(wins_release_python_run - "${ROOT}" <<'PY'
from pathlib import Path
import re
import sys
text = Path(sys.argv[1], "pubspec.yaml").read_text(encoding="utf-8")
match = re.search(r"^version:\s*([^+\s]+)\+(\d+)\s*$", text, re.MULTILINE)
if match is None:
    raise SystemExit("pubspec.yaml is missing version: <name>+<build>")
print(match.group(1))
PY
)"
VERSION_CODE="$(wins_release_python_run - "${ROOT}" <<'PY'
from pathlib import Path
import re
import sys
text = Path(sys.argv[1], "pubspec.yaml").read_text(encoding="utf-8")
match = re.search(r"^version:\s*([^+\s]+)\+(\d+)\s*$", text, re.MULTILINE)
if match is None:
    raise SystemExit("pubspec.yaml is missing version: <name>+<build>")
print(int(match.group(2)) * 100 + 1)
PY
)"
[[ "${VERSION_NAME}" == "1.0.16" ]] \
  || die "Wear versionName is not the canonical 1.0.16 identity"
[[ "${VERSION_CODE}" == "3301" ]] \
  || die "Wear versionCode is not the canonical 3301 watch identity"

# The dependency-freeze build receipt names the Gradle distribution the wrapper
# runs: its version and the distributionSha256Sum the wrapper verifies.
GRADLE_IDENTITY="$(wins_release_python_run - "${WEAR}/gradle/wrapper/gradle-wrapper.properties" <<'PY'
from pathlib import Path
import re
import sys
text = Path(sys.argv[1]).read_text(encoding="ascii")
url = re.search(r"^distributionUrl=https\\://services\.gradle\.org/distributions/gradle-([0-9]+(?:\.[0-9]+){1,2})-(?:all|bin)\.zip$", text, re.MULTILINE)
digest = re.search(r"^distributionSha256Sum=([0-9a-f]{64})$", text, re.MULTILINE)
if url is None or digest is None:
    raise SystemExit("Wear Gradle wrapper does not pin an official distribution and SHA-256")
print(url.group(1))
print(digest.group(1))
PY
)" || die "Wear Gradle wrapper identity could not be read"
GRADLE_VERSION="$(printf '%s\n' "${GRADLE_IDENTITY}" | /usr/bin/sed -n '1p')"
GRADLE_DISTRIBUTION_SHA256="$(printf '%s\n' "${GRADLE_IDENTITY}" | /usr/bin/sed -n '2p')"
[[ -n "${GRADLE_VERSION}" && -n "${GRADLE_DISTRIBUTION_SHA256}" ]] \
  || die "Wear Gradle wrapper identity is incomplete"

RECEIPT_ROOT="${ROOT}/.artifacts/release-build-receipts/wear-os"
SYMBOLS="${ROOT}/.artifacts/private-release-symbols/wear-os/${VERSION_NAME}+${VERSION_CODE}"
RECEIPT_DIR="${RECEIPT_ROOT}/$(/bin/date -u +'%Y%m%dT%H%M%SZ')-$$"
# The dependency-freeze begin and build receipts live beside, not inside, the
# permission-frozen signed-AAB receipt directory, which must be a new path.
FREEZE_RECEIPT_DIR="${RECEIPT_DIR}-dependency-freeze"
WEAR_AAB_BEGIN="${FREEZE_RECEIPT_DIR}/WEAR_OS_AAB_BUILD_BEGIN.json"
WEAR_AAB_RECEIPT="${FREEZE_RECEIPT_DIR}/WEAR_OS_AAB_BUILD_RECEIPT.json"

mkdir -p "${RECEIPT_ROOT}" "${ROOT}/.artifacts/private-release-symbols/wear-os"
[[ -e "${RECEIPT_DIR}" || -L "${RECEIPT_DIR}" ]] && die "Wear receipt path already exists: ${RECEIPT_DIR}"
[[ -e "${FREEZE_RECEIPT_DIR}" || -L "${FREEZE_RECEIPT_DIR}" ]] && die "Wear dependency-freeze receipt path already exists: ${FREEZE_RECEIPT_DIR}"
[[ -e "${SYMBOLS}" || -L "${SYMBOLS}" ]] && die "Wear symbol custody path already exists: ${SYMBOLS}"
mkdir -p "${SYMBOLS}"
/bin/mkdir -m 0700 -- "${FREEZE_RECEIPT_DIR}"
# Producer-attested on darwin (tools/release_dependency_freeze.py): the single-use
# begin receipt precedes the Gradle build, so only an AAB written after it can
# be attested by finish-build below.
/bin/bash "${DEPENDENCY_FREEZE}" begin-build \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform wear_os --output "${WEAR_AAB_BEGIN}" \
  || die "OWNER-BLOCKED: Wear dependency-freeze begin-build was refused"
assert_reviewed_wear_toolchains

(
  cd "${WEAR}"
  for exported_name in $(compgen -e); do
    case "${exported_name}" in
      HOME|TMPDIR|JAVA_HOME|ANDROID_SDK_ROOT|ANDROID_HOME|PATH) ;;
      *) unset "${exported_name}" 2>/dev/null || true ;;
    esac
  done
  TMPDIR="${TMPDIR:-/private/tmp}"
  PATH="${JAVA_HOME}/bin:/usr/bin:/bin:/usr/sbin:/sbin"
  export TMPDIR PATH WINS_ANDROID_KEYSTORE WINS_ANDROID_KEY_ALIAS \
    WINS_ANDROID_KEY_PASSWORD WINS_ANDROID_STORE_PASSWORD
  exec /bin/bash "${GRADLEW}" --no-daemon --no-build-cache \
    --dependency-verification=strict :app:bundleRelease
)
assert_reviewed_wear_toolchains

[[ -L "${CANONICAL_AAB}" ]] && die "Wear AAB must not be a symlink"
[[ -f "${CANONICAL_AAB}" ]] || die "OWNER-BLOCKED: missing Wear signed AAB"
[[ -f "${MAPPING_SRC}/mapping.txt" ]] || die "missing Wear R8 mapping symbol"
/bin/chmod 0444 "${CANONICAL_AAB}" \
  || die "Wear signed AAB could not be held as immutable bytes"

cp -R "${MAPPING_SRC}/." "${SYMBOLS}/"
if /usr/bin/find "${SYMBOLS}" -type l | /usr/bin/grep -q .; then
  die "Wear symbol custody refuses symbolic links"
fi
[[ -f "${SYMBOLS}/mapping.txt" ]] || die "missing Wear R8 mapping symbol"
prune_generated_wear_outputs
[[ -f "${CANONICAL_AAB}" && ! -L "${CANONICAL_AAB}" ]] \
  || die "Wear signed AAB did not survive pruning of generated outputs"

wins_release_python_run "${ASSERT_AAB}" "${CANONICAL_AAB}" >/dev/null
wins_release_python_run "${SIGNER_TOOL}" "${CANONICAL_AAB}"
wins_release_python_run "${PRIVACY_TOOL}" --artifacts --target wear-os-aab --artifact "${CANONICAL_AAB}" \
  --secret-env WINS_ANDROID_KEY_PASSWORD \
  --secret-env WINS_ANDROID_STORE_PASSWORD
wins_release_python_run "${CUSTODY_TOOL}" record --platform wear-os --symbols-dir "${SYMBOLS}" --artifact "${CANONICAL_AAB}"
wins_release_python_run "${CUSTODY_TOOL}" verify --platform wear-os --symbols-dir "${SYMBOLS}" --artifact "${CANONICAL_AAB}"
wins_release_python_run "${RECEIPT_TOOL}" record \
  --aab "${CANONICAL_AAB}" \
  --mapping "${SYMBOLS}/mapping.txt" \
  --receipt-dir "${RECEIPT_DIR}" \
  --release-input-index "${RELEASE_INDEX}"
wins_release_python_run "${RECEIPT_TOOL}" verify \
  --aab "${CANONICAL_AAB}" \
  --mapping "${SYMBOLS}/mapping.txt" \
  --receipt-dir "${RECEIPT_DIR}" \
  --release-input-index "${RELEASE_INDEX}"
assert_reviewed_wear_toolchains
/bin/bash "${DEPENDENCY_FREEZE}" finish-build \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform wear_os \
  --begin "${WEAR_AAB_BEGIN}" --artifact "${CANONICAL_AAB}" \
  --producer wear_os/tools/prepare_release.sh \
  --toolchain-name Gradle --toolchain-version "${GRADLE_VERSION}" \
  --toolchain-revision "${GRADLE_DISTRIBUTION_SHA256}" \
  --target wear-os-release-aab --output "${WEAR_AAB_RECEIPT}" \
  || die "Wear dependency-freeze finish-build was refused"
/bin/bash "${DEPENDENCY_FREEZE}" verify-receipt \
  --repo "${ROOT}" --index "${RELEASE_INDEX}" --platform wear_os \
  --receipt "${WEAR_AAB_RECEIPT}" --artifact "${CANONICAL_AAB}" \
  || die "Wear dependency-freeze build receipt did not verify"

printf 'WEAR OS RELEASE: PASS permission-frozen signed AAB receipt recorded\n'
printf 'AAB: %s\n' "${CANONICAL_AAB}"
printf 'Permission-frozen receipt: %s\n' "${RECEIPT_DIR}/WEAR_OS_SIGNED_AAB_RECEIPT.json"
printf 'Dependency-freeze build receipt: %s\n' "${WEAR_AAB_RECEIPT}"
printf 'Custody: %s\n' "${SYMBOLS}"
printf 'Publication remains unauthorized. No Play Console upload or publication occurred.\n'
