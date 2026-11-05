#!/bin/bash
# Build the reviewed static linux/amd64 gcloud runtime provisioner and helper.
# Go is executed only through authenticated, fd-bound release custody.
set -euo pipefail
umask 077

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
unset CDPATH ENV BASH_ENV
hash -r 2>/dev/null || true

die() {
  printf 'gcloud-runtime-provisioner: %s\n' "$*" >&2
  exit 1
}

SCRIPT_PATH="${BASH_SOURCE[0]}"
[[ "${SCRIPT_PATH}" == /* ]] || SCRIPT_PATH="$(pwd -P)/${SCRIPT_PATH}"
[[ -f "${SCRIPT_PATH}" && ! -L "${SCRIPT_PATH}" ]] || \
  die "build script must be one regular non-symbolic file"
SCRIPT_DIR="$(cd -P "$(/usr/bin/dirname "${SCRIPT_PATH}")" && pwd -P)"
ROOT="$(cd -P "${SCRIPT_DIR}/.." && pwd -P)"

SRC="${ROOT}/tools/gcloud_runtime_provisioner.go"
TEST_SRC="${ROOT}/tools/gcloud_runtime_provisioner_test.go"
HELPER_SRC="${ROOT}/tools/gcloud_immutable_helper.go"
HELPER_TEST_SRC="${ROOT}/tools/gcloud_immutable_helper_test.go"
PIN_MANIFEST="${ROOT}/tools/toolchain-pins.json"
PYTHON_CUSTODY_WRAPPER="${ROOT}/tools/release_python_archive_custody.sh"
PYTHON_CUSTODY_RECEIPT="${ROOT}/tools/macos_release_python_runtime_receipt.py"
GO_CUSTODY_WRAPPER="${ROOT}/tools/release_go_archive_custody.sh"
GO_CUSTODY_CONTROLLER="${ROOT}/tools/release_go_archive_custody.py"
GO_CUSTODY_TRUST="${ROOT}/tools/release_go_archive_custody.trust.json"
GO_CUSTODY_PROVISIONER="${ROOT}/tools/provision_macos_release_go_runtime.sh"
SOURCE_FREEZE_PRODUCER="${ROOT}/tools/release_source_freeze.py"
ART="${ROOT}/build/gcloud_runtime_provisioner"
OUT="${ART}/gcloud_runtime_provisioner_linux_amd64"
HELPER_OUT="${ART}/gcloud_immutable_helper_linux_amd64"
RECEIPT_NAME="gcloud_runtime_provisioner_linux_amd64.receipt.json"
RECEIPT="${ART}/${RECEIPT_NAME}"
RECEIPT_SHA256="${RECEIPT}.sha256"

CUSTODY_CONTROL_PATHS=(
  "${PYTHON_CUSTODY_WRAPPER}"
  "${PYTHON_CUSTODY_RECEIPT}"
  "${GO_CUSTODY_WRAPPER}"
  "${GO_CUSTODY_CONTROLLER}"
  "${GO_CUSTODY_TRUST}"
  "${GO_CUSTODY_PROVISIONER}"
  "${SOURCE_FREEZE_PRODUCER}"
  "${PIN_MANIFEST}"
)
CUSTODY_CONTROL_SHA256=(
  "a83405a84f140c3fa8bdfc804bbb48fbe03ebcfcefd0e871a366dd74a7b76066"
  "a1af6cb00410e9f9a73e231f30033dd316a5ffc383f89bf89d658038a5eb2f11"
  "29feac49552e79bdb77c90584e1cae0e2fe60708fd1333d002d28ae9237465e3"
  "88e5fd47ff1bdd98655f5e36b1a1a1a060176389c3c6e4d9dfc6cbcdcd2120c8"
  "7ddec86dbdc6982395beb49678bebfc44cae4d28ba45c4d89a5ce8120c7a8327"
  "43d96b91bba315e2022e3d69d90d1dda9c10cbac0734c883db2e1a5981b20619"
  "8a587a45c5afe9c89f6ec6b88242099087a8ccbf4634f23d8901e0610eebdb2a"
  "67399ed6bf2768ba72c095bc946d6867411d60efb28979744899dece840cdd05"
)

# These are the complete Go inputs reviewed for this producer. A source or
# test change requires an explicit builder review and digest update before an
# artifact can be published.
INPUT_PATHS=(
  "${SRC}"
  "${TEST_SRC}"
  "${HELPER_SRC}"
  "${HELPER_TEST_SRC}"
)
INPUT_NAMES=(
  "gcloud_runtime_provisioner.go"
  "gcloud_runtime_provisioner_test.go"
  "gcloud_immutable_helper.go"
  "gcloud_immutable_helper_test.go"
)
INPUT_LABELS=(
  "tools/gcloud_runtime_provisioner.go"
  "tools/gcloud_runtime_provisioner_test.go"
  "tools/gcloud_immutable_helper.go"
  "tools/gcloud_immutable_helper_test.go"
)
INPUT_KINDS=(
  "source"
  "test"
  "source"
  "test"
)
INPUT_EXPECTED_SHA256=(
  "6f0939d3063f7583eb39719111bf8b1104182669fd83cb3bc587c62166b2789a"
  "5098ac5c5ac7937fc1029acd91b9b7ab46ae0302f1d9391d8ca1ad4db24287aa"
  "f353861155e7e072bf65752f8abe73ee341989c638d947d897c124930b98c122"
  "31c4d3098fb142cfa339fafa3e356acc4eeb62ff794b8e53edef6021cdd9d4a1"
)
INPUT_IDENTITIES=()

for required_file in \
  "${PIN_MANIFEST}" \
  "${PYTHON_CUSTODY_WRAPPER}" \
  "${PYTHON_CUSTODY_RECEIPT}" \
  "${GO_CUSTODY_WRAPPER}" \
  "${GO_CUSTODY_CONTROLLER}" \
  "${GO_CUSTODY_TRUST}" \
  "${GO_CUSTODY_PROVISIONER}" \
  "${SOURCE_FREEZE_PRODUCER}"; do
  [[ -f "${required_file}" && ! -L "${required_file}" ]] || \
    die "required custody input is missing or symbolic: ${required_file}"
done

verify_custody_control_bytes() {
  local index measured
  for ((index=0; index<${#CUSTODY_CONTROL_PATHS[@]}; index++)); do
    measured="$(/usr/bin/shasum -a 256 "${CUSTODY_CONTROL_PATHS[$index]}")" || return 1
    measured="${measured%% *}"
    [[ "${measured}" == "${CUSTODY_CONTROL_SHA256[$index]}" ]] || {
      printf 'gcloud-runtime-provisioner: reviewed custody control digest mismatch: %s\n' \
        "${CUSTODY_CONTROL_PATHS[$index]}" >&2
      return 1
    }
  done
}
verify_custody_control_bytes || \
  die "owner-blocked: reviewed custody control bytes are unavailable"
[[ "$#" -eq 0 ]] || \
  die "caller-supplied build or receipt fields are refused"
for input_path in "${INPUT_PATHS[@]}"; do
  [[ -f "${input_path}" && ! -L "${input_path}" ]] || \
    die "reviewed source/test input is missing or symbolic: ${input_path}"
done
for fixed_tool in \
  /usr/bin/shasum /usr/bin/file /usr/bin/cmp /usr/bin/mktemp \
  /usr/bin/dirname /usr/bin/id \
  /bin/mkdir /bin/rm /bin/chmod; do
  [[ -f "${fixed_tool}" && -x "${fixed_tool}" && ! -L "${fixed_tool}" ]] || \
    die "required fixed system tool is unavailable: ${fixed_tool}"
done

[[ -z "${WINS_RELEASE_GO:-}" ]] || \
  die "WINS_RELEASE_GO executable path export is refused; use wins_release_go_run"
[[ "${WINS_GO_CUSTODY_ISSUANCE:-}" == /* ]] || \
  die "owner-blocked: current reviewed Go custody issuance identity is unavailable"

# Refuse inherited Go state. The authenticated controller supplies GOROOT,
# GOENV=off, GOTOOLCHAIN=local, a private HOME/TMPDIR, and a fixed PATH.
for name in \
  GOOS GOARCH GOARM GOAMD64 CGO_ENABLED CC CXX \
  CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS \
  GOROOT GOPATH GOBIN GOTOOLDIR GOHOSTOS GOHOSTARCH GOVERSION GOMOD \
  GOENV GOTOOLCHAIN GO111MODULE GOAUTH GOINSECURE GOVCS \
  GOMODCACHE GOPROXY GOFLAGS GOCACHE GOTMPDIR GOWORK GOPRIVATE \
  GONOPROXY GONOSUMDB GOSUMDB GODEBUG GOEXPERIMENT GOTELEMETRY \
  SDKROOT MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET \
  TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET PKG_CONFIG_PATH \
  WINS_RELEASE_GO_RUNTIME WINS_RELEASE_GO_RUNTIME_ID \
  WINS_RELEASE_GO_ROOT WINS_RELEASE_GO_TREE_SHA256 \
  WINS_RELEASE_GO_SHA256 WINS_GO_CUSTODY_TOOL; do
  unset "${name}"
done
unset -f go wins_release_go_prepare wins_release_go_verify \
  wins_release_go_run wins_release_go_cleanup \
  wins_release_python_prepare wins_release_python_run \
  wins_release_python_cleanup 2>/dev/null || true

# The absolute, digest-bound path is computed above.
# shellcheck disable=SC1090
source "${PYTHON_CUSTODY_WRAPPER}" || \
  die "owner-blocked: authenticated release Python custody could not be loaded"
# The absolute, digest-bound path is computed above.
# shellcheck disable=SC1090
source "${GO_CUSTODY_WRAPPER}" || \
  die "owner-blocked: authenticated release Go custody could not be loaded"
verify_custody_control_bytes || \
  die "owner-blocked: custody control changed while functions were loaded"
for custody_function in \
  wins_release_python_prepare wins_release_python_run wins_release_python_cleanup \
  wins_release_go_prepare wins_release_go_verify wins_release_go_run \
  wins_release_go_cleanup; do
  declare -F "${custody_function}" >/dev/null 2>&1 || \
    die "owner-blocked: required custody function is absent: ${custody_function}"
done

PYTHON_CUSTODY_ACTIVE=0
GO_CUSTODY_ACTIVE=0
WORK=""
PUBLICATION_CREATED=0
cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if [[ "${rc}" -ne 0 && "${PUBLICATION_CREATED:-0}" == 1 ]]; then
    rollback_published_receipt_bundle >/dev/null 2>&1 || rc=1
  fi
  if [[ -n "${WORK}" ]]; then
    case "${WORK}" in
      "${ART}"/.native-build.*)
        if [[ -d "${WORK}" && ! -L "${WORK}" ]]; then
          /bin/rm -rf -- "${WORK}" || rc=1
        fi
        ;;
      *)
        printf 'gcloud-runtime-provisioner: refusing cleanup outside private build prefix: %s\n' \
          "${WORK}" >&2
        rc=1
        ;;
    esac
  fi
  if [[ "${GO_CUSTODY_ACTIVE}" == 1 ]]; then
    wins_release_go_cleanup || rc=1
  fi
  if [[ "${PYTHON_CUSTODY_ACTIVE}" == 1 ]]; then
    wins_release_python_cleanup || rc=1
  fi
  exit "${rc}"
}
trap cleanup EXIT HUP INT TERM

wins_release_python_prepare "${PIN_MANIFEST}" || \
  die "owner-blocked: authenticated release Python runtime is unavailable"
PYTHON_CUSTODY_ACTIVE=1

wins_release_go_prepare "${GO_CUSTODY_CONTROLLER}" "${PIN_MANIFEST}" || \
  die "owner-blocked: authenticated reviewed Go owner custody is unavailable"
GO_CUSTODY_ACTIVE=1
wins_release_go_verify || \
  die "owner-blocked: authenticated reviewed Go owner runtime verification failed"

pin_fields="$(wins_release_python_run -c '
import json, re, sys

def reject(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit("duplicate JSON key rejected: " + key)
        result[key] = value
    return result

with open(sys.argv[1], "r", encoding="utf-8") as stream:
    document = json.load(stream, object_pairs_hook=reject)
go = document.get("tools", {}).get("go", {})
values = (
    go.get("version"),
    go.get("archive_sha256", {}).get("darwin_arm64"),
    go.get("install_tree_sha256", {}).get("darwin_arm64"),
    go.get("executable_sha256"),
)
if not isinstance(values[0], str) or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values[0]) is None:
    raise SystemExit("tools.go.version is not an exact stable dotted release")
if any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in values[1:]):
    raise SystemExit("reviewed Go archive, tree, or executable digest is invalid")
sys.stdout.write("|".join(values))
' "${PIN_MANIFEST}")" || die "authenticated Go pin resolution failed"
IFS='|' read -r REVIEWED_GO_VERSION REVIEWED_GO_ARCHIVE_SHA256 \
  REVIEWED_GO_TREE_SHA256 REVIEWED_GO_EXECUTABLE_SHA256 <<<"${pin_fields}"

EXPECTED_GO_ROOT="/Library/WinsVPN/ReleaseGo/${REVIEWED_GO_VERSION}/extracted/go"
[[ "${WINS_RELEASE_GO_ROOT:-}" == "${EXPECTED_GO_ROOT}" ]] || \
  die "owner-blocked: Go custody did not bind the exact reviewed owner runtime"
[[ "${WINS_RELEASE_GO_TREE_SHA256:-}" == "${REVIEWED_GO_TREE_SHA256}" ]] || \
  die "owner-blocked: Go owner-runtime tree digest is not the reviewed digest"
[[ "${WINS_RELEASE_GO_SHA256:-}" == "${REVIEWED_GO_EXECUTABLE_SHA256}" ]] || \
  die "owner-blocked: Go executable digest is not the reviewed digest"
case "${WINS_RELEASE_GO_RUNTIME:-}" in
  /private/tmp/wins-release-go.*|/tmp/wins-release-go.*) ;;
  *) die "owner-blocked: Go execution state escaped the custody prefix" ;;
esac
[[ -d "${WINS_RELEASE_GO_RUNTIME}" && ! -L "${WINS_RELEASE_GO_RUNTIME}" &&
   -n "${WINS_RELEASE_GO_RUNTIME_ID:-}" ]] || \
  die "owner-blocked: Go execution state is absent or substituted"

go_identity="$(wins_release_go_run version)" || \
  die "fd-bound wins_release_go_run could not report the reviewed Go identity"
expected_go_identity="go version go${REVIEWED_GO_VERSION} darwin/arm64"
[[ "${go_identity}" == "${expected_go_identity}" ]] || \
  die "reviewed Go identity mismatch: expected ${expected_go_identity}; got ${go_identity}"
wins_release_go_verify || \
  die "reviewed Go owner runtime changed during identity verification"

BUILD_ROOT="${ROOT}/build"
if [[ -e "${BUILD_ROOT}" || -L "${BUILD_ROOT}" ]]; then
  [[ -d "${BUILD_ROOT}" && ! -L "${BUILD_ROOT}" ]] || \
    die "build root is not one regular directory: ${BUILD_ROOT}"
else
  /bin/mkdir -m 0700 "${BUILD_ROOT}"
fi
if [[ -e "${ART}" || -L "${ART}" ]]; then
  [[ -d "${ART}" && ! -L "${ART}" ]] || \
    die "artifact root is not one regular directory: ${ART}"
else
  /bin/mkdir -m 0700 "${ART}"
fi
WORK="$(/usr/bin/mktemp -d "${ART}/.native-build.XXXXXX")" || \
  die "could not create private build workspace"
/bin/chmod 0700 "${WORK}"
SNAPSHOT_DIR="${WORK}/source"
/bin/mkdir -m 0700 "${SNAPSHOT_DIR}"

snapshot_arguments=()
for ((index=0; index<${#INPUT_PATHS[@]}; index++)); do
  snapshot_arguments+=(
    "${INPUT_PATHS[$index]}"
    "${INPUT_NAMES[$index]}"
    "${INPUT_EXPECTED_SHA256[$index]}"
  )
done
snapshot_records="$(wins_release_python_run -c '
import hashlib, os, pathlib, stat, sys

def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )

def write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise SystemExit("short snapshot write")
        offset += written

destination = pathlib.Path(sys.argv[1])
payload = sys.argv[2:]
if len(payload) == 0 or len(payload) % 3:
    raise SystemExit("source/test snapshot arguments are malformed")
dest_info = destination.lstat()
if destination.is_symlink() or not stat.S_ISDIR(dest_info.st_mode):
    raise SystemExit("source/test snapshot directory is unsafe")
directory_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
records = []
try:
    for offset in range(0, len(payload), 3):
        source = pathlib.Path(payload[offset])
        name = payload[offset + 1]
        expected = payload[offset + 2]
        if name != source.name or "/" in name or name in {"", ".", ".."}:
            raise SystemExit("source/test snapshot name is invalid")
        before = source.lstat()
        if source.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SystemExit("source/test input must be one regular non-hardlinked file: " + str(source))
        if before.st_size <= 0 or before.st_size > 4 * 1024 * 1024:
            raise SystemExit("source/test input size is outside the accepted range: " + str(source))
        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(source_fd)
            if identity(before) != identity(opened):
                raise SystemExit("source/test input was replaced before open: " + str(source))
            blocks = []
            digest = hashlib.sha256()
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                blocks.append(block)
                digest.update(block)
            after = os.fstat(source_fd)
        finally:
            os.close(source_fd)
        latest = source.lstat()
        if identity(opened) != identity(after) or identity(after) != identity(latest):
            raise SystemExit("source/test input changed while bound: " + str(source))
        measured = digest.hexdigest()
        if measured != expected:
            raise SystemExit("reviewed source/test digest mismatch: " + str(source))
        output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400, dir_fd=directory_fd)
        try:
            write_all(output_fd, b"".join(blocks))
            os.fsync(output_fd)
            os.fchmod(output_fd, 0o400)
            copied = os.fstat(output_fd)
        finally:
            os.close(output_fd)
        if not stat.S_ISREG(copied.st_mode) or copied.st_nlink != 1:
            raise SystemExit("source/test snapshot is not one regular file")
        records.append(measured + "|" + ",".join(str(item) for item in identity(after)))
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
sys.stdout.write("\n".join(records))
' "${SNAPSHOT_DIR}" "${snapshot_arguments[@]}")" || \
  die "reviewed source/test snapshot failed"

record_count=0
while IFS='|' read -r measured_digest measured_identity; do
  [[ "${record_count}" -lt "${#INPUT_PATHS[@]}" &&
     "${measured_digest}" == "${INPUT_EXPECTED_SHA256[$record_count]}" &&
     -n "${measured_identity}" ]] || die "source/test snapshot result is malformed"
  INPUT_IDENTITIES[record_count]="${measured_identity}"
  record_count=$((record_count + 1))
done <<<"${snapshot_records}"
[[ "${record_count}" -eq "${#INPUT_PATHS[@]}" ]] || \
  die "source/test snapshot did not bind every explicit input"

verify_inputs_unchanged() {
  local -a arguments=()
  local index
  for ((index=0; index<${#INPUT_PATHS[@]}; index++)); do
    arguments+=(
      "${INPUT_PATHS[$index]}"
      "${INPUT_NAMES[$index]}"
      "${INPUT_EXPECTED_SHA256[$index]}"
      "${INPUT_IDENTITIES[$index]}"
    )
  done
  wins_release_python_run -c '
import hashlib, os, pathlib, stat, sys

def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )

def digest_fd(fd):
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()

snapshot = pathlib.Path(sys.argv[1])
payload = sys.argv[2:]
if len(payload) == 0 or len(payload) % 4:
    raise SystemExit("source/test revalidation arguments are malformed")
for offset in range(0, len(payload), 4):
    source = pathlib.Path(payload[offset])
    name = payload[offset + 1]
    expected_digest = payload[offset + 2]
    expected_identity = tuple(int(item) for item in payload[offset + 3].split(","))
    before = source.lstat()
    if source.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or identity(before) != expected_identity:
        raise SystemExit("source/test input drift: " + str(source))
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        measured = digest_fd(fd)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if identity(opened) != expected_identity or identity(after) != expected_identity or measured != expected_digest or identity(source.lstat()) != expected_identity:
        raise SystemExit("source/test input drift: " + str(source))
    copied = snapshot / name
    copied_info = copied.lstat()
    if copied.is_symlink() or not stat.S_ISREG(copied_info.st_mode) or copied_info.st_nlink != 1:
        raise SystemExit("source/test snapshot substitution: " + str(copied))
    copied_fd = os.open(copied, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        copied_digest = digest_fd(copied_fd)
    finally:
        os.close(copied_fd)
    if copied_digest != expected_digest:
        raise SystemExit("source/test snapshot drift: " + str(copied))
' "${SNAPSHOT_DIR}" "${arguments[@]}"
}

RECEIPT_HELPER_SOURCE=""
IFS= read -r -d '' RECEIPT_HELPER_SOURCE <<'PY' || true
import hashlib
import json
import os
import pathlib
import re
import stat
import struct
import sys


class ReceiptError(Exception):
    pass


SHA_RE = re.compile(r"[0-9a-f]{64}\Z")
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
UID = os.getuid()
GID = os.getgid()
MAX_ARTIFACT = 256 * 1024 * 1024
MAX_RECEIPT = 512 * 1024
DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
CONTROL_PATHS = (
    "tools/release_python_archive_custody.sh",
    "tools/macos_release_python_runtime_receipt.py",
    "tools/release_go_archive_custody.sh",
    "tools/release_go_archive_custody.py",
    "tools/release_go_archive_custody.trust.json",
    "tools/provision_macos_release_go_runtime.sh",
    "tools/release_source_freeze.py",
    "tools/toolchain-pins.json",
)
SOURCE_PATHS = {
    "provisioner": (
        ("tools/gcloud_runtime_provisioner.go", "source"),
        ("tools/gcloud_runtime_provisioner_test.go", "test"),
        ("tools/gcloud_immutable_helper.go", "source"),
        ("tools/gcloud_immutable_helper_test.go", "test"),
    ),
}


def fail(message):
    raise ReceiptError(message)


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key: " + key)
        result[key] = value
    return result


def canonical(value, newline=False):
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        fail("canonical ASCII JSON encoding failed: " + str(exc))
    return encoded + (b"\n" if newline else b"")


def parse_canonical(raw, label):
    if not isinstance(raw, str):
        fail(label + " is not text")
    try:
        data = raw.encode("ascii")
        value = json.loads(data.decode("ascii"), object_pairs_hook=reject_duplicates)
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError) as exc:
        fail(label + " is not canonical ASCII JSON: " + str(exc))
    if canonical(value) != data:
        fail(label + " is not canonical ASCII JSON")
    return value


def inode(info):
    return (int(info.st_dev), int(info.st_ino))


def stable_identity(info):
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def require_name(name, label):
    if (
        not isinstance(name, str)
        or not name.isascii()
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
    ):
        fail("unsafe " + label + " name")


def relative_under(root, path, label):
    try:
        relative = path.relative_to(root)
    except ValueError:
        fail(label + " escaped the repository root")
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        fail("unsafe " + label + " path")
    text = relative.as_posix()
    if not text.isascii():
        fail("non-ASCII " + label + " path")
    return text


def repo_file(root, relative, label):
    if (
        not isinstance(relative, str)
        or not relative.isascii()
        or not relative
        or relative.startswith("/")
        or "\\" in relative
    ):
        fail("unsafe " + label + " path")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        fail("unsafe " + label + " path")
    return root.joinpath(*parts)


def read_descriptor(descriptor, maximum, label):
    data = bytearray()
    while len(data) <= maximum:
        chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > maximum:
        fail(label + " exceeds the accepted size")
    return bytes(data)


def bound_record(root, path, expected_sha, expected_identity, label, kind=None, executable=False):
    relative = relative_under(root, path, label)
    try:
        before = path.lstat()
    except OSError as exc:
        fail(label + " is unavailable: " + str(exc))
    mode = stat.S_IMODE(before.st_mode)
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != UID
        or before.st_gid != GID
        or mode & 0o022
        or before.st_size <= 0
        or before.st_size > MAX_ARTIFACT
        or (executable and not mode & stat.S_IXUSR)
    ):
        fail("unsafe " + label)
    if expected_identity is not None and stable_identity(before) != expected_identity:
        fail(label + " identity drift")
    try:
        descriptor = os.open(path, READ_FLAGS)
    except OSError as exc:
        fail(label + " could not be opened: " + str(exc))
    try:
        opened = os.fstat(descriptor)
        if stable_identity(opened) != stable_identity(before):
            fail(label + " changed before descriptor binding")
        data = read_descriptor(descriptor, MAX_ARTIFACT, label)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = path.lstat()
    except OSError as exc:
        fail(label + " changed while descriptor-bound: " + str(exc))
    if (
        stable_identity(opened) != stable_identity(after)
        or stable_identity(after) != stable_identity(current)
        or len(data) != after.st_size
    ):
        fail(label + " changed while descriptor-bound")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha is not None and digest != expected_sha:
        fail(label + " digest drift")
    record = {
        "_identity": list(stable_identity(after)),
        "bytes": len(data),
        "mode": format(stat.S_IMODE(after.st_mode), "04o"),
        "path": relative,
        "sha256": digest,
    }
    if kind is not None:
        record["kind"] = kind
    return record


def parse_identity(value, label):
    if not isinstance(value, str):
        fail(label + " identity is malformed")
    parts = value.split(",")
    if len(parts) != 9 or any(not part.isdecimal() for part in parts):
        fail(label + " identity is malformed")
    return tuple(int(part) for part in parts)


def require_count(value, label):
    if not isinstance(value, str) or not value.isdecimal() or not value:
        fail(label + " count is malformed")
    count = int(value)
    if count < 1 or count > 64:
        fail(label + " count is outside the accepted range")
    return count


def require_hash(value, label):
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        fail(label + " is not one lowercase SHA-256 digest")
    return value


def material_shape(materials, producer_kind):
    if type(materials) is not dict or set(materials) != {
        "custody_controls",
        "producer",
        "source_tests",
    }:
        fail("receipt material schema is not exact")
    if producer_kind not in SOURCE_PATHS:
        fail("receipt producer kind is not recognized")
    expected_sources = SOURCE_PATHS[producer_kind]
    sources = materials["source_tests"]
    controls = materials["custody_controls"]
    producer = materials["producer"]
    if (
        type(sources) is not list
        or type(controls) is not list
        or len(sources) != len(expected_sources)
        or len(controls) != len(CONTROL_PATHS)
    ):
        fail("receipt material inventory is incomplete")
    if [item.get("path") for item in sources] != [item[0] for item in expected_sources]:
        fail("receipt source/test inventory is incomplete")
    if [item.get("kind") for item in sources] != [item[1] for item in expected_sources]:
        fail("receipt source/test kinds are incomplete")
    if [item.get("path") for item in controls] != list(CONTROL_PATHS):
        fail("receipt custody-control inventory is incomplete")
    return producer, sources, controls


def record_path(root, record, label, has_kind):
    expected = {"_identity", "bytes", "mode", "path", "sha256"}
    if has_kind:
        expected.add("kind")
    if type(record) is not dict or set(record) != expected:
        fail(label + " record schema is not exact")
    path_text = record["path"]
    path = repo_file(root, path_text, label)
    digest = require_hash(record["sha256"], label + " digest")
    if type(record["bytes"]) is not int or isinstance(record["bytes"], bool) or record["bytes"] <= 0:
        fail(label + " byte count is malformed")
    if not isinstance(record["mode"], str) or re.fullmatch(r"0[0-7]{3}", record["mode"]) is None:
        fail(label + " mode is malformed")
    identity_value = record["_identity"]
    if (
        type(identity_value) is not list
        or len(identity_value) != 9
        or any(type(item) is not int or item < 0 for item in identity_value)
    ):
        fail(label + " identity is malformed")
    kind = record.get("kind")
    if has_kind and kind not in {"source", "test"}:
        fail(label + " kind is malformed")
    bound = bound_record(
        root,
        path,
        digest,
        tuple(identity_value),
        label,
        kind=kind,
        executable=(label == "producer script"),
    )
    if bound != record:
        fail(label + " changed after the reviewed snapshot")


def verify_materials(root, materials, producer_kind):
    producer, sources, controls = material_shape(materials, producer_kind)
    record_path(root, producer, "producer script", False)
    for item in sources:
        record_path(root, item, "source/test input", True)
    for item in controls:
        record_path(root, item, "custody control", False)


def public_record(record):
    return {key: value for key, value in record.items() if key != "_identity"}


def open_directory(path, label):
    try:
        before = path.lstat()
    except OSError as exc:
        fail(label + " is unavailable: " + str(exc))
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != UID
        or before.st_gid != GID
        or stat.S_IMODE(before.st_mode) != 0o700
    ):
        fail("unsafe " + label)
    try:
        descriptor = os.open(path, DIRECTORY_FLAGS)
    except OSError as exc:
        fail(label + " could not be descriptor-bound: " + str(exc))
    held = os.fstat(descriptor)
    try:
        current = path.lstat()
    except OSError as exc:
        os.close(descriptor)
        fail(label + " changed during descriptor binding: " + str(exc))
    if (
        not stat.S_ISDIR(held.st_mode)
        or inode(before) != inode(held)
        or inode(current) != inode(held)
        or held.st_uid != UID
        or held.st_gid != GID
        or stat.S_IMODE(held.st_mode) != 0o700
    ):
        os.close(descriptor)
        fail(label + " changed during descriptor binding")
    return descriptor, inode(held)


def verify_directory(path, descriptor, expected, label):
    held = os.fstat(descriptor)
    current = path.lstat()
    if (
        not stat.S_ISDIR(held.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or inode(held) != expected
        or inode(current) != expected
        or held.st_uid != UID
        or held.st_gid != GID
        or current.st_uid != UID
        or current.st_gid != GID
        or stat.S_IMODE(held.st_mode) != 0o700
        or stat.S_IMODE(current.st_mode) != 0o700
    ):
        fail(label + " changed during descriptor-relative publication")


def read_leaf(directory, name, maximum, label):
    require_name(name, label)
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        fail(label + " is missing")
    except OSError as exc:
        fail(label + " cannot be inspected: " + str(exc))
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != UID
        or before.st_gid != GID
        or before.st_size <= 0
        or before.st_size > maximum
    ):
        fail("unsafe " + label)
    try:
        descriptor = os.open(name, READ_FLAGS, dir_fd=directory)
    except OSError as exc:
        fail(label + " could not be descriptor-bound: " + str(exc))
    try:
        opened = os.fstat(descriptor)
        if inode(opened) != inode(before) or not stat.S_ISREG(opened.st_mode):
            fail(label + " changed before descriptor binding")
        data = read_descriptor(descriptor, maximum, label)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        fail(label + " changed while descriptor-bound: " + str(exc))
    if (
        stable_identity(opened) != stable_identity(after)
        or stable_identity(after) != stable_identity(current)
        or len(data) != after.st_size
    ):
        fail(label + " changed while descriptor-bound")
    return after, data


def validate_linux_static_stripped(data, label):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:7] != b"\x02\x01\x01":
        fail(label + " is not ELF64 little-endian")
    try:
        machine = struct.unpack_from("<H", data, 18)[0]
        program_offset = struct.unpack_from("<Q", data, 32)[0]
        section_offset = struct.unpack_from("<Q", data, 40)[0]
        program_size = struct.unpack_from("<H", data, 54)[0]
        program_count = struct.unpack_from("<H", data, 56)[0]
        section_size = struct.unpack_from("<H", data, 58)[0]
        section_count = struct.unpack_from("<H", data, 60)[0]
    except struct.error as exc:
        fail(label + " ELF header is truncated: " + str(exc))
    if machine != 62 or program_size < 56 or section_size < 64:
        fail(label + " is not linux/amd64")
    if program_offset + program_size * program_count > len(data):
        fail(label + " program table is truncated")
    for index in range(program_count):
        program_type = struct.unpack_from("<I", data, program_offset + index * program_size)[0]
        if program_type in {2, 3}:
            fail(label + " is dynamically linked")
    if section_count:
        if section_offset + section_size * section_count > len(data):
            fail(label + " section table is truncated")
        for index in range(section_count):
            section_type = struct.unpack_from("<I", data, section_offset + index * section_size + 4)[0]
            if section_type == 2:
                fail(label + " is not stripped")


def exact_final(directory, name, expected, mode, label):
    info, data = read_leaf(directory, name, MAX_ARTIFACT, label)
    if (
        data != expected
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != mode
        or hashlib.sha256(data).hexdigest() != hashlib.sha256(expected).hexdigest()
    ):
        fail(label + " bytes or metadata are not exact")
    return info


def seal_stage(directory, name, expected, mode, label):
    require_name(name, label)
    try:
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except OSError as exc:
        fail(label + " is unavailable: " + str(exc))
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != UID
        or before.st_gid != GID
    ):
        fail("unsafe " + label)
    try:
        descriptor = os.open(
            name,
            os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
    except OSError as exc:
        fail(label + " could not be sealed: " + str(exc))
    try:
        opened = os.fstat(descriptor)
        if inode(opened) != inode(before):
            fail(label + " changed before sealing")
        data = read_descriptor(descriptor, MAX_ARTIFACT, label)
        if data != expected:
            fail(label + " bytes changed before sealing")
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        inode(after) != inode(before)
        or inode(current) != inode(before)
        or after.st_nlink != 1
        or stat.S_IMODE(after.st_mode) != mode
        or stat.S_IMODE(current.st_mode) != mode
        or after.st_size != len(expected)
    ):
        fail(label + " sealing metadata is invalid")
    os.fsync(directory)
    return after


def unlink_if_inode(directory, name, expected, label):
    current = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or inode(current) != expected
    ):
        fail(label + " changed before cleanup")
    os.unlink(name, dir_fd=directory)
    os.fsync(directory)


def write_stage(directory, name, data, mode, label):
    require_name(name, label)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    except FileExistsError:
        fail("staged " + label + " already exists")
    except OSError as exc:
        fail("staged " + label + " could not be created: " + str(exc))
    created = inode(os.fstat(descriptor))
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("short write for staged " + label)
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        if (
            final.st_nlink != 1
            or final.st_size != len(data)
            or stat.S_IMODE(final.st_mode) != mode
            or final.st_uid != UID
            or final.st_gid != GID
        ):
            fail("staged " + label + " metadata is invalid")
    except Exception:
        os.close(descriptor)
        try:
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if inode(current) == created and stat.S_ISREG(current.st_mode):
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
        except OSError:
            pass
        raise
    os.close(descriptor)
    os.fsync(directory)


def publish_stage(work_directory, artifact_directory, stage_name, final_name, expected, mode, label, created):
    stage = seal_stage(work_directory, stage_name, expected, mode, label + " stage")
    try:
        os.link(
            stage_name,
            final_name,
            src_dir_fd=work_directory,
            dst_dir_fd=artifact_directory,
            follow_symlinks=False,
        )
    except FileExistsError:
        fail("exclusive no-replace publication raced for " + label)
    except OSError as exc:
        fail("exclusive no-replace publication failed for " + label + ": " + str(exc))
    os.fsync(artifact_directory)
    final, final_data = read_leaf(artifact_directory, final_name, MAX_ARTIFACT, label)
    linked = os.stat(stage_name, dir_fd=work_directory, follow_symlinks=False)
    if (
        final_data != expected
        or inode(final) != inode(stage)
        or inode(linked) != inode(stage)
        or final.st_nlink != 2
        or linked.st_nlink != 2
        or stat.S_IMODE(final.st_mode) != mode
    ):
        fail("published " + label + " identity is invalid")
    created.append((final_name, expected, mode, inode(final), label))
    unlink_if_inode(work_directory, stage_name, inode(stage), label + " stage")
    exact_final(artifact_directory, final_name, expected, mode, label)
    os.fsync(artifact_directory)


def rollback_created(directory, created):
    for name, expected, mode, expected_inode, _label in reversed(created):
        try:
            current, data = read_leaf(directory, name, MAX_ARTIFACT, "rollback " + name)
            if (
                inode(current) == expected_inode
                and data == expected
                and current.st_nlink == 1
                and stat.S_IMODE(current.st_mode) == mode
            ):
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
        except Exception:
            pass


def component_spec(producer_kind):
    if producer_kind == "provisioner":
        return (
            (
                "gcloud_immutable_helper_linux_amd64",
                "gcloud_immutable_helper_linux_amd64.a",
                "gcloud_immutable_helper_linux_amd64.b",
            ),
            (
                "gcloud_runtime_provisioner_linux_amd64",
                "gcloud_runtime_provisioner_linux_amd64.a",
                "gcloud_runtime_provisioner_linux_amd64.b",
            ),
        )
    fail("receipt producer kind is not recognized")

def receipt_name_for(producer_kind):
    if producer_kind == "provisioner":
        return "gcloud_runtime_provisioner_linux_amd64.receipt.json"
    fail("receipt producer kind is not recognized")

def environment_policy(slot, target):
    result = {
        "CGO_ENABLED": "0",
        "GOCACHE": "WORK/" + slot + "/gocache",
        "GOMODCACHE": "WORK/" + slot + "/gomodcache",
        "GOENV": "off",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTELEMETRY": "off",
        "GOTOOLCHAIN": "local",
        "GOWORK": "off",
        "HOME": "WORK/" + slot + "/home",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": "WORK/" + slot + "/tmp",
    }
    if target:
        result.update({"GOAMD64": "v1", "GOARCH": "amd64", "GOOS": "linux"})
    else:
        result.update({"GOAMD64": "unset", "GOARCH": "unset", "GOOS": "unset"})
    return result


def build_policy(producer_kind, artifacts):
    if (
        producer_kind != "provisioner"
        or len(artifacts) != 2
        or [item["name"] for item in artifacts]
        != [
            "gcloud_immutable_helper_linux_amd64",
            "gcloud_runtime_provisioner_linux_amd64",
        ]
    ):
        fail("receipt build policy cannot bind an optional component")
    helper_hash = artifacts[0]["sha256"]
    return {
        "host_tests": [
            {
                "argv": [
                    "test",
                    "-count=1",
                    "-timeout=120s",
                    "gcloud_runtime_provisioner.go",
                    "gcloud_runtime_provisioner_test.go",
                ],
                "environment": environment_policy("host-test-provisioner", False),
            },
            {
                "argv": [
                    "test",
                    "-count=1",
                    "-timeout=120s",
                    "gcloud_immutable_helper.go",
                    "gcloud_immutable_helper_test.go",
                ],
                "environment": environment_policy("host-test-helper", False),
            },
        ],
        "linux_builds": [
            {
                "argv": [
                    "build",
                    "-a",
                    "-buildmode=exe",
                    "-pgo=off",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags=-s -w -buildid=",
                    "-o",
                    "WORK/gcloud_immutable_helper_linux_amd64.a",
                    "gcloud_immutable_helper.go",
                ],
                "environment": environment_policy("helper-build-a", True),
            },
            {
                "argv": [
                    "build",
                    "-a",
                    "-buildmode=exe",
                    "-pgo=off",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags=-s -w -buildid=",
                    "-o",
                    "WORK/gcloud_immutable_helper_linux_amd64.b",
                    "gcloud_immutable_helper.go",
                ],
                "environment": environment_policy("helper-build-b", True),
            },
            {
                "argv": [
                    "build",
                    "-a",
                    "-buildmode=exe",
                    "-pgo=off",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags=-s -w -buildid= -X main.compiledHelperSHA256=" + helper_hash,
                    "-o",
                    "WORK/gcloud_runtime_provisioner_linux_amd64.a",
                    "gcloud_runtime_provisioner.go",
                ],
                "environment": environment_policy("provisioner-build-a", True),
            },
            {
                "argv": [
                    "build",
                    "-a",
                    "-buildmode=exe",
                    "-pgo=off",
                    "-trimpath",
                    "-buildvcs=false",
                    "-ldflags=-s -w -buildid= -X main.compiledHelperSHA256=" + helper_hash,
                    "-o",
                    "WORK/gcloud_runtime_provisioner_linux_amd64.b",
                    "gcloud_runtime_provisioner.go",
                ],
                "environment": environment_policy("provisioner-build-b", True),
            },
        ],
    }

def receipt_record(root, artifact_root, work_directory, producer_kind, materials, version, archive, tree, executable):
    if VERSION_RE.fullmatch(version) is None:
        fail("reviewed Go version is malformed")
    for value, label in ((archive, "archive"), (tree, "tree"), (executable, "executable")):
        require_hash(value, "reviewed Go " + label + " digest")
    verify_materials(root, materials, producer_kind)
    artifact_relative = relative_under(root, artifact_root, "artifact directory")
    artifacts = []
    staged = []
    for final_name, first_name, second_name in component_spec(producer_kind):
        first_info, first = read_leaf(work_directory, first_name, MAX_ARTIFACT, "first build " + final_name)
        second_info, second = read_leaf(work_directory, second_name, MAX_ARTIFACT, "second build " + final_name)
        if first_info.st_nlink != 1 or second_info.st_nlink != 1:
            fail("double-build stage is hardlinked")
        validate_linux_static_stripped(first, "first build " + final_name)
        validate_linux_static_stripped(second, "second build " + final_name)
        first_hash = hashlib.sha256(first).hexdigest()
        second_hash = hashlib.sha256(second).hexdigest()
        if first_hash != second_hash or first != second:
            fail("double-build output is not byte-identical for " + final_name)
        artifacts.append(
            {
                "bytes": len(first),
                "double_build": {
                    "first": {"bytes": len(first), "sha256": first_hash},
                    "second": {"bytes": len(second), "sha256": second_hash},
                },
                "mode": "0500",
                "name": final_name,
                "path": artifact_relative + "/" + final_name,
                "sha256": first_hash,
            }
        )
        staged.append((final_name, first_name, first, "native artifact " + final_name))
    record = {
        "artifacts": artifacts,
        "build_policy": build_policy(producer_kind, artifacts),
        "contract": "winsvpn-gcloud-native-double-build-receipt-v1",
        "custody_controls": [public_record(item) for item in materials["custody_controls"]],
        "producer": public_record(materials["producer"]),
        "schema_version": 1,
        "source_tests": [public_record(item) for item in materials["source_tests"]],
        "target": {
            "cgo_enabled": "0",
            "goamd64": "v1",
            "goarch": "amd64",
            "goos": "linux",
        },
        "toolchain": {
            "archive_platform": "darwin_arm64",
            "archive_sha256": archive,
            "custody_wrapper": "tools/release_go_archive_custody.sh",
            "executable": "bin/go",
            "executable_sha256": executable,
            "install_tree_sha256": tree,
            "root": "/Library/WinsVPN/ReleaseGo/" + version + "/extracted/go",
            "version": version,
        },
    }
    record["build_identity"] = hashlib.sha256(canonical(record)).hexdigest()
    return record, canonical(record, newline=True), staged


def bundle_expected(root, artifact_root, work_directory, producer_kind, materials, version, archive, tree, executable):
    record, receipt, staged = receipt_record(
        root,
        artifact_root,
        work_directory,
        producer_kind,
        materials,
        version,
        archive,
        tree,
        executable,
    )
    receipt_name = receipt_name_for(producer_kind)
    sidecar = (
        hashlib.sha256(receipt).hexdigest() + "  " + receipt_name + "\n"
    ).encode("ascii")
    return record, receipt, sidecar, staged


def verify_bundle(root, artifact_root, artifact_directory, producer_kind, materials, record, receipt, sidecar, staged):
    for artifact, (name, _stage, expected, label) in zip(record["artifacts"], staged):
        final = exact_final(artifact_directory, name, expected, 0o500, label)
        validate_linux_static_stripped(expected, label)
        if (
            artifact["path"] != relative_under(root, artifact_root, "artifact directory") + "/" + name
            or artifact["name"] != name
            or artifact["bytes"] != len(expected)
            or artifact["sha256"] != hashlib.sha256(expected).hexdigest()
            or artifact["mode"] != "0500"
            or final.st_nlink != 1
        ):
            fail("receipt artifact binding is not exact")
    receipt_name = receipt_name_for(producer_kind)
    exact_final(artifact_directory, receipt_name, receipt, 0o444, "native build receipt")
    exact_final(
        artifact_directory,
        receipt_name + ".sha256",
        sidecar,
        0o444,
        "native build receipt sidecar",
    )
    verify_materials(root, materials, producer_kind)


def publish(root, artifact_root, work_root, producer_kind, requested_receipt_name, materials, version, archive, tree, executable):
    if requested_receipt_name != receipt_name_for(producer_kind):
        fail("receipt name is not the producer-fixed name")
    artifact_directory, artifact_identity = open_directory(artifact_root, "artifact directory")
    work_directory, work_identity = open_directory(work_root, "private build workspace")
    created = []
    try:
        record, receipt, sidecar, staged = bundle_expected(
            root,
            artifact_root,
            work_directory,
            producer_kind,
            materials,
            version,
            archive,
            tree,
            executable,
        )
        receipt_name = receipt_name_for(producer_kind)
        target_names = [name for name, _stage, _data, _label in staged] + [
            receipt_name,
            receipt_name + ".sha256",
        ]
        present = []
        for name in target_names:
            try:
                os.stat(name, dir_fd=artifact_directory, follow_symlinks=False)
            except FileNotFoundError:
                present.append(False)
            except OSError as exc:
                fail("publication target cannot be inspected: " + str(exc))
            else:
                present.append(True)
        if any(present) and not all(present):
            fail("partial or substituted publication bundle already exists")
        verify_directory(artifact_root, artifact_directory, artifact_identity, "artifact directory")
        verify_directory(work_root, work_directory, work_identity, "private build workspace")
        if all(present):
            verify_bundle(
                root,
                artifact_root,
                artifact_directory,
                producer_kind,
                materials,
                record,
                receipt,
                sidecar,
                staged,
            )
            verify_directory(artifact_root, artifact_directory, artifact_identity, "artifact directory")
            return "idempotent"
        try:
            for final_name, stage_name, data, label in staged:
                publish_stage(
                    work_directory,
                    artifact_directory,
                    stage_name,
                    final_name,
                    data,
                    0o500,
                    label,
                    created,
                )
            verify_directory(artifact_root, artifact_directory, artifact_identity, "artifact directory")
            write_stage(work_directory, ".native-receipt.stage", receipt, 0o600, "native build receipt")
            publish_stage(
                work_directory,
                artifact_directory,
                ".native-receipt.stage",
                receipt_name,
                receipt,
                0o444,
                "native build receipt",
                created,
            )
            write_stage(
                work_directory,
                ".native-receipt-sidecar.stage",
                sidecar,
                0o600,
                "native build receipt sidecar",
            )
            publish_stage(
                work_directory,
                artifact_directory,
                ".native-receipt-sidecar.stage",
                receipt_name + ".sha256",
                sidecar,
                0o444,
                "native build receipt sidecar",
                created,
            )
            verify_bundle(
                root,
                artifact_root,
                artifact_directory,
                producer_kind,
                materials,
                record,
                receipt,
                sidecar,
                staged,
            )
            verify_directory(artifact_root, artifact_directory, artifact_identity, "artifact directory")
            verify_directory(work_root, work_directory, work_identity, "private build workspace")
        except Exception:
            rollback_created(artifact_directory, created)
            raise
        return "created"
    finally:
        os.close(work_directory)
        os.close(artifact_directory)


def rollback_receipt(artifact_root, producer_kind):
    receipt_name = receipt_name_for(producer_kind)
    directory, identity_value = open_directory(artifact_root, "artifact directory")
    try:
        receipt_data = None
        try:
            receipt_info, receipt_data = read_leaf(directory, receipt_name, MAX_RECEIPT, "native build receipt")
            parsed = json.loads(receipt_data.decode("ascii"), object_pairs_hook=reject_duplicates)
            if (
                canonical(parsed, newline=True) != receipt_data
                or type(parsed) is not dict
                or parsed.get("contract") != "winsvpn-gcloud-native-double-build-receipt-v1"
                or receipt_info.st_nlink != 1
                or stat.S_IMODE(receipt_info.st_mode) != 0o444
            ):
                receipt_data = None
        except (ReceiptError, UnicodeDecodeError, ValueError):
            receipt_data = None
        sidecar_name = receipt_name + ".sha256"
        if receipt_data is not None:
            expected_sidecar = (
                hashlib.sha256(receipt_data).hexdigest() + "  " + receipt_name + "\n"
            ).encode("ascii")
            try:
                sidecar_info, sidecar_data = read_leaf(directory, sidecar_name, MAX_RECEIPT, "native build receipt sidecar")
                if (
                    sidecar_data == expected_sidecar
                    and sidecar_info.st_nlink == 1
                    and stat.S_IMODE(sidecar_info.st_mode) == 0o444
                ):
                    os.unlink(sidecar_name, dir_fd=directory)
                    os.fsync(directory)
            except ReceiptError:
                pass
            try:
                current, current_data = read_leaf(directory, receipt_name, MAX_RECEIPT, "native build receipt")
                if (
                    current_data == receipt_data
                    and current.st_nlink == 1
                    and stat.S_IMODE(current.st_mode) == 0o444
                ):
                    os.unlink(receipt_name, dir_fd=directory)
                    os.fsync(directory)
            except ReceiptError:
                pass
        verify_directory(artifact_root, directory, identity_value, "artifact directory")
    finally:
        os.close(directory)


def capture(arguments):
    if len(arguments) < 5:
        fail("receipt capture arguments are incomplete")
    root = pathlib.Path(arguments[0]).resolve(strict=True)
    script = pathlib.Path(arguments[1]).resolve(strict=True)
    producer_label = arguments[2]
    source_count = require_count(arguments[3], "source/test")
    control_count = require_count(arguments[4], "custody-control")
    cursor = 5
    if len(arguments) != cursor + source_count * 5 + control_count * 2:
        fail("receipt capture arguments are malformed")
    producer = bound_record(root, script, None, None, "producer script", executable=True)
    if producer["path"] != producer_label:
        fail("producer script path is not fixed")
    sources = []
    for _index in range(source_count):
        path = pathlib.Path(arguments[cursor])
        label = arguments[cursor + 1]
        kind = arguments[cursor + 2]
        digest = require_hash(arguments[cursor + 3], "source/test digest")
        identity_value = parse_identity(arguments[cursor + 4], "source/test")
        cursor += 5
        if kind not in {"source", "test"}:
            fail("source/test kind is malformed")
        record = bound_record(root, path, digest, identity_value, "source/test input", kind=kind)
        if record["path"] != label:
            fail("source/test path is not fixed")
        sources.append(record)
    controls = []
    for _index in range(control_count):
        path = pathlib.Path(arguments[cursor])
        digest = require_hash(arguments[cursor + 1], "custody-control digest")
        cursor += 2
        controls.append(bound_record(root, path, digest, None, "custody control"))
    materials = {
        "custody_controls": controls,
        "producer": producer,
        "source_tests": sources,
    }
    verify_materials(root, materials, "provisioner")
    sys.stdout.buffer.write(canonical(materials))


def main():
    if len(sys.argv) < 2:
        fail("receipt operation is missing")
    operation = sys.argv[1]
    arguments = sys.argv[2:]
    if operation == "capture":
        capture(arguments)
        return
    if operation == "verify":
        if len(arguments) != 3:
            fail("receipt verification arguments are malformed")
        root = pathlib.Path(arguments[0]).resolve(strict=True)
        producer_kind = arguments[1]
        materials = parse_canonical(arguments[2], "receipt materials")
        verify_materials(root, materials, producer_kind)
        return
    if operation == "publish":
        if len(arguments) != 10:
            fail("receipt publication arguments are malformed")
        root = pathlib.Path(arguments[0]).resolve(strict=True)
        result = publish(
            root,
            pathlib.Path(arguments[1]),
            pathlib.Path(arguments[2]),
            arguments[3],
            arguments[4],
            parse_canonical(arguments[5], "receipt materials"),
            arguments[6],
            arguments[7],
            arguments[8],
            arguments[9],
        )
        sys.stdout.write(result)
        return
    if operation == "rollback":
        if len(arguments) != 2:
            fail("receipt rollback arguments are malformed")
        rollback_receipt(pathlib.Path(arguments[0]), arguments[1])
        return
    fail("receipt operation is not recognized")


try:
    main()
except ReceiptError as exc:
    print("native receipt: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
except (OSError, ValueError, struct.error) as exc:
    print("native receipt: " + str(exc), file=sys.stderr)
    raise SystemExit(1)
PY

receipt_python() {
  wins_release_python_run -c "${RECEIPT_HELPER_SOURCE}" "$@"
}

capture_receipt_materials() {
  local -a arguments=()
  local index
  arguments=(
    capture
    "${ROOT}"
    "${SCRIPT_PATH}"
    "tools/build_gcloud_runtime_provisioner.sh"
    "${#INPUT_PATHS[@]}"
    "${#CUSTODY_CONTROL_PATHS[@]}"
  )
  for ((index=0; index<${#INPUT_PATHS[@]}; index++)); do
    arguments+=(
      "${INPUT_PATHS[$index]}"
      "${INPUT_LABELS[$index]}"
      "${INPUT_KINDS[$index]}"
      "${INPUT_EXPECTED_SHA256[$index]}"
      "${INPUT_IDENTITIES[$index]}"
    )
  done
  for ((index=0; index<${#CUSTODY_CONTROL_PATHS[@]}; index++)); do
    arguments+=(
      "${CUSTODY_CONTROL_PATHS[$index]}"
      "${CUSTODY_CONTROL_SHA256[$index]}"
    )
  done
  receipt_python "${arguments[@]}"
}

verify_receipt_materials() {
  receipt_python verify "${ROOT}" provisioner "${RECEIPT_MATERIALS}"
}

rollback_published_receipt_bundle() {
  receipt_python rollback "${ART}" provisioner
}

publish_receipt_bundle() {
  receipt_python publish \
    "${ROOT}" "${ART}" "${WORK}" provisioner "${RECEIPT_NAME}" \
    "${RECEIPT_MATERIALS}" \
    "${REVIEWED_GO_VERSION}" "${REVIEWED_GO_ARCHIVE_SHA256}" \
    "${REVIEWED_GO_TREE_SHA256}" "${REVIEWED_GO_EXECUTABLE_SHA256}"
}

run_custody_go() (
  local target_os="$1" target_arch="$2" state_root="$3" cgo_enabled="$4"
  shift 4
  case "${state_root}" in
    "${WORK}"/*) ;;
    *) return 125 ;;
  esac
  [[ ! -e "${state_root}" && ! -L "${state_root}" ]] || return 125
  /bin/mkdir -m 0700 "${state_root}" || return 125
  /bin/mkdir -m 0700 \
    "${state_root}/home" "${state_root}/tmp" "${state_root}/gocache" \
    "${state_root}/gomodcache" || return 125
  unset GOOS GOARCH GOARM GOAMD64 CGO_ENABLED CC CXX
  unset CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS
  unset GOROOT GOPATH GOBIN GOTOOLDIR GOHOSTOS GOHOSTARCH GOVERSION GOMOD
  unset GOENV GOTOOLCHAIN GO111MODULE GOAUTH GOINSECURE GOVCS GOFLAGS
  unset GODEBUG GOEXPERIMENT GOPRIVATE GONOPROXY GONOSUMDB
  export HOME="${state_root}/home"
  export TMPDIR="${state_root}/tmp"
  export PATH=/usr/bin:/bin:/usr/sbin:/sbin
  export LANG=C LC_ALL=C
  export GOCACHE="${state_root}/gocache"
  export GOMODCACHE="${state_root}/gomodcache"
  export GOENV=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOTELEMETRY=off
  [[ "${cgo_enabled}" == 0 || "${cgo_enabled}" == 1 ]] || return 125
  export CGO_ENABLED="${cgo_enabled}"
  if [[ "${target_os}" != host ]]; then
    export GOOS="${target_os}" GOARCH="${target_arch}"
    if [[ "${target_arch}" == amd64 ]]; then
      export GOAMD64=v1
    fi
  fi
  cd "${SNAPSHOT_DIR}"
  wins_release_go_verify || return 126
  local rc=0
  wins_release_go_run "$@" || rc=$?
  wins_release_go_verify || return 126
  return "${rc}"
)

run_go_checked() {
  verify_inputs_unchanged || die "source/test input drift detected before fd-bound Go execution"
  run_custody_go "$@" || die "fd-bound reviewed Go command failed"
  verify_inputs_unchanged || die "source/test input drift detected after fd-bound Go execution"
}

capture_go_checked() {
  local result
  verify_inputs_unchanged || die "source/test input drift detected before fd-bound Go execution"
  result="$(run_custody_go "$@")" || die "fd-bound reviewed Go command failed"
  verify_inputs_unchanged || die "source/test input drift detected after fd-bound Go execution"
  printf '%s\n' "${result}"
}

hash_file() {
  local digest
  digest="$(/usr/bin/shasum -a 256 "$1")" || return 1
  digest="${digest%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "${digest}"
}

artifact_is_valid() {
  local path="$1" description
  [[ -s "${path}" && -f "${path}" && ! -L "${path}" ]] || return 1
  description="$(/usr/bin/file -b "${path}")" || return 1
  [[ "${description}" == *"ELF 64-bit LSB executable"* ]] || return 1
  [[ "${description}" == *"x86-64"* ]] || return 1
  [[ "${description}" == *"statically linked"* &&
     "${description}" != *"dynamically linked"* ]] || return 1
  [[ "${description}" == *"stripped"* && "${description}" != *"not stripped"* ]]
}

validate_artifact() {
  artifact_is_valid "$1" || die "artifact is not static stripped linux/amd64: $1"
}

for ((index=0; index<${#INPUT_PATHS[@]}; index++)); do
  printf 'gcloud-runtime-provisioner input sha256 %s %s\n' \
    "${INPUT_EXPECTED_SHA256[$index]}" "${INPUT_LABELS[$index]}"
done
printf 'gcloud-runtime-provisioner: %s\n' "${go_identity}"

RECEIPT_MATERIALS="$(capture_receipt_materials)" || \
  die "reviewed receipt materials could not be captured"
verify_receipt_materials || die "reviewed receipt materials changed before build"

host_go_env="$(capture_go_checked host host "${WORK}/host-env" 0 env GOOS GOARCH CGO_ENABLED)"
[[ "${host_go_env}" == $'darwin\narm64\n0' ]] || \
  die "reviewed Go host identity is not exactly darwin/arm64 with CGO disabled"
target_go_env="$(capture_go_checked linux amd64 "${WORK}/target-env" 0 env GOOS GOARCH CGO_ENABLED)"
[[ "${target_go_env}" == $'linux\namd64\n0' ]] || \
  die "reviewed Go target identity is not exactly linux/amd64 with CGO disabled"

run_go_checked host host "${WORK}/host-test-provisioner" 0 test -vet=all -count=1 -timeout=120s \
  "${INPUT_NAMES[0]}" "${INPUT_NAMES[1]}"
run_go_checked host host "${WORK}/host-test-helper" 0 test -vet=all -count=1 -timeout=120s \
  "${INPUT_NAMES[2]}" "${INPUT_NAMES[3]}"
run_go_checked host host "${WORK}/host-race-provisioner" 1 test -race -vet=all -count=1 -timeout=240s \
  "${INPUT_NAMES[0]}" "${INPUT_NAMES[1]}"
run_go_checked host host "${WORK}/host-race-helper" 1 test -race -vet=all -count=1 -timeout=240s \
  "${INPUT_NAMES[2]}" "${INPUT_NAMES[3]}"

helper1="${WORK}/gcloud_immutable_helper_linux_amd64.a"
helper2="${WORK}/gcloud_immutable_helper_linux_amd64.b"
run_go_checked linux amd64 "${WORK}/helper-build-a" 0 build -a -buildmode=exe -pgo=off -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o "${helper1}" "${INPUT_NAMES[2]}"
run_go_checked linux amd64 "${WORK}/helper-build-b" 0 build -a -buildmode=exe -pgo=off -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid=' -o "${helper2}" "${INPUT_NAMES[2]}"

validate_artifact "${helper1}"
validate_artifact "${helper2}"
helper_hash1="$(hash_file "${helper1}")" || die "first helper build digest failed"
helper_hash2="$(hash_file "${helper2}")" || die "second helper build digest failed"
[[ "${helper_hash1}" == "${helper_hash2}" ]] || \
  die "independently built helper is not deterministic: ${helper_hash1} vs ${helper_hash2}"
/usr/bin/cmp -s "${helper1}" "${helper2}" || \
  die "independently built helper double-build is not byte-identical"

out1="${WORK}/gcloud_runtime_provisioner_linux_amd64.a"
out2="${WORK}/gcloud_runtime_provisioner_linux_amd64.b"
LDFLAGS="-s -w -buildid= -X main.compiledHelperSHA256=${helper_hash1}"
run_go_checked linux amd64 "${WORK}/provisioner-build-a" 0 build -a -buildmode=exe -pgo=off -trimpath -buildvcs=false \
  -ldflags="${LDFLAGS}" -o "${out1}" "${INPUT_NAMES[0]}"
run_go_checked linux amd64 "${WORK}/provisioner-build-b" 0 build -a -buildmode=exe -pgo=off -trimpath -buildvcs=false \
  -ldflags="${LDFLAGS}" -o "${out2}" "${INPUT_NAMES[0]}"

validate_artifact "${out1}"
validate_artifact "${out2}"
hash1="$(hash_file "${out1}")" || die "first provisioner build digest failed"
hash2="$(hash_file "${out2}")" || die "second provisioner build digest failed"
[[ "${hash1}" == "${hash2}" ]] || \
  die "linux/amd64 provisioner is not deterministic: ${hash1} vs ${hash2}"
/usr/bin/cmp -s "${out1}" "${out2}" || \
  die "linux/amd64 provisioner double-build is not byte-identical"
verify_inputs_unchanged || die "source/test input drift detected before receipt publication"
verify_receipt_materials || die "reviewed receipt materials changed before publication"
verify_custody_control_bytes || die "custody-control bytes changed before publication"
wins_release_go_verify || die "reviewed Go owner runtime changed before receipt publication"

publication_result="$(publish_receipt_bundle)" || die "receipt bundle publication failed"
[[ "${publication_result}" == created || "${publication_result}" == idempotent ]] || \
  die "receipt bundle publication result is malformed"
[[ "${publication_result}" != created ]] || PUBLICATION_CREATED=1
validate_artifact "${HELPER_OUT}"
validate_artifact "${OUT}"
verify_inputs_unchanged || die "source/test input drift detected after publication"
verify_receipt_materials || die "reviewed receipt materials changed after publication"
verify_custody_control_bytes || die "custody-control bytes changed after publication"
wins_release_go_verify || die "reviewed Go owner runtime changed after publication"
PUBLICATION_CREATED=0
printf 'gcloud-immutable-helper linux/amd64 %s %s\n' "${helper_hash1}" "${HELPER_OUT}"
printf 'gcloud-runtime-provisioner linux/amd64 %s %s receipt %s sidecar %s\n' \
  "${hash1}" "${OUT}" "${RECEIPT}" "${RECEIPT_SHA256}"
