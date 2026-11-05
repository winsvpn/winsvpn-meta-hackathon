#!/usr/bin/env bash
# Deterministic linux-arm64 AmneziaWG CLI (awg) plus the architecture-independent
# awg-quick script, built from official amneziawg-tools source.
#
# This producer consumes amneziawg-tools, not amneziawg-go. Live official GitHub
# metadata on 2026-08-24 freezes two distinct latest identities:
#   amneziawg-tools  v3.1.20260812  ee0f0a9aa34ff0a0da4b3433b9512781cfe02843
#                    latest stable GitHub Release
#   amneziawg-go     v3.1.20260828  b5928efb6ca19f0153958460c3d141f04abc5c2e
#                    latest upstream tag; stability designation unavailable
# The Ubuntu amd64 zip is a third identity. Do not copy any of those hashes onto
# another artifact. The Go engine for linux-arm64 is built from the Go pin by
# tools/build_linux_release.sh / server/build_amneziawg_go_server_image.sh, not here.
#
# Upstream has never published an arm64 Linux zip. The C `awg` binary is therefore
# compiled here from that pinned source with the Debian 12 clang already recorded
# in tools/linux_apt_pins.json. Two isolated builds of this recipe were compared
# byte-for-byte on 2026-08-23 and produced AWG_BINARY_SHA256.
#
# Fail-closed: this script only runs natively on Linux aarch64. A cross-compile
# from linux/amd64 or Darwin would be a different toolchain and is refused rather
# than silently emitting a binary the release hash would reject.
#
# Usage:
#   tools/build_linux_arm64_awg.sh <awg-output> [awg-quick-output]
#   tools/build_linux_arm64_awg.sh --self-test-pins
#   WINS_LINUX_ARM64_AWG_REPRODUCE=1 tools/build_linux_arm64_awg.sh <awg> [awg-quick]
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LINUX_SYSTEM_PYTHON="/usr/bin/python3"
unset -f python3 2>/dev/null || true
python3() {
  "${LINUX_SYSTEM_PYTHON}" -I "$@"
}
readonly -f python3

AWG_TOOLS_VERSION="v3.1.20260812"
AWG_TOOLS_COMMIT="ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
# GitHub archive/refs/tags/${AWG_TOOLS_VERSION}.tar.gz -- not the Ubuntu zip.
AWG_TOOLS_SOURCE_SHA256="dbd8ce0748d835d18f30bb76720246b7bfc80bd09cd17c379b1c59f683a18493"
# ubuntu-22.04-amneziawg-tools.zip from the same tools tag. Not consumed here.
AWG_TOOLS_UBUNTU_ZIP_SHA256="919e9d0a367c7c72f9c16b7d0a9e4840b943628353b2210a33cb4b582785ba56"
# Companion latest upstream Go engine tag. Stability designation unavailable.
# This script does not download or build it.
AWG_GO_TAG="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"
AWG_GO_SOURCE_SHA256="10bf7458e090bf52f87df27adcd3904a60e4d17fab844d9415e46379147f1ab4"
AWG_GO_BINARY_SHA256_AMD64="5e8e2e656d77f9f66102660234fa08d8c2ddb99bf32961db8c02ad19c32e872f"
# Same value as AWG_GO_BINARY_SHA256_ARM64 in tools/build_linux_release.sh and
# AWG_GO_LINUX_ARM64_SHA256 in tools/test_linux_arm64_fallback_elf.py. The
# userspace-only awg-quick embeds both engine digests, so AWG_QUICK_SHA256
# depends on this exact value.
AWG_GO_BINARY_SHA256_ARM64="9083c92dbd16422cd590df8fcf2ebae2c604b43539bdd58dddaede74efd0642a"
AWG_BINARY_SHA256="bbf94b3753fb7660897d102918de797a55d675bd66c12bda63a9887400e1876d"
AWG_QUICK_SOURCE_SHA256="f4bb0f5d63665ade87f0cb9f2185c43515cff09868637eb311f98f65a318722c"
AWG_QUICK_SHA256="89dca7788242e542cec249af5d062764fbcb3a6a3ef66999c400d5bbe2f446db"
REVIEWED_CLANG_PACKAGE="1:14.0-55.7~deb12u1"
REVIEWED_CLANG_VERSION="14.0.6"
REVIEWED_BINUTILS_PACKAGE="2.40-2"
SOURCE_DATE_EPOCH_PINNED=""
CALLER_CLANG_SHA256="${WINS_LINUX_ARM64_CLANG_SHA256:-}"
REVIEWED_CLANG_SHA256=""

die() {
  printf 'BUILD LINUX ARM64 AWG ERROR: %s\n' "$*" >&2
  exit 1
}

refuse() {
  printf 'BUILD LINUX ARM64 AWG ERROR: %s\n' "$*" >&2
  exit 65
}

# Prints tools.linux.arm64.clang_executable_sha256 from tools/toolchain-pins.json,
# or nothing when the pin is absent. The pin file must be one strict JSON
# document in a single-link regular file.
read_reviewed_clang_pin() {
  python3 -I - "${SCRIPT_DIR}/toolchain-pins.json" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate toolchain pin key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite toolchain pin number: {value}")

pins_path = pathlib.Path(sys.argv[1])
before = pins_path.lstat()
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
    raise SystemExit("tools/toolchain-pins.json is not a single-link regular file")
fd = os.open(pins_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
try:
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("tools/toolchain-pins.json changed while opened")
    if opened.st_size > 16 * 1024 * 1024:
        raise SystemExit("tools/toolchain-pins.json is oversized")
    payload = os.pread(fd, opened.st_size, 0)
    if len(payload) != opened.st_size:
        raise SystemExit("tools/toolchain-pins.json is truncated")
finally:
    os.close(fd)
document = json.loads(
    payload.decode("utf-8"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
try:
    value = document["tools"]["linux"]["arm64"]["clang_executable_sha256"]
except (KeyError, TypeError):
    value = ""
if not isinstance(value, str):
    raise SystemExit("tools.linux.arm64.clang_executable_sha256 is not a string")
if value and re.fullmatch(r"[0-9a-f]{64}", value) is None:
    raise SystemExit("tools.linux.arm64.clang_executable_sha256 is not 64 lowercase hex")
print(value)
PY
}

# Prints the one SOURCE_DATE_EPOCH for this release: the whole seconds since
# 1970-01-01T00:00:00Z of the release input index created_utc, which must be
# an ISO-8601 UTC timestamp ending in Z. The index must be one strict JSON
# document in a single-link regular file, not group/other-writable, with the
# exact release-index schema. This matches resolve_linux_release_controls in
# tools/build_linux_release.sh, which passes the same value in.
derive_release_source_date_epoch() {
  python3 -I - "$1" <<'PY'
import datetime as dt
import json
import os
import pathlib
import stat
import sys

def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate release index key: {key}")
        result[key] = value
    return result

def reject_nonfinite(value):
    raise SystemExit(f"non-finite release index number: {value}")

index_path = pathlib.Path(sys.argv[1])
before = index_path.lstat()
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
    raise SystemExit("release input index is not a single-link regular file")
if before.st_mode & 0o022:
    raise SystemExit("release input index is group/other-writable")
fd = os.open(index_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
try:
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
        raise SystemExit("release input index changed while opened")
    if opened.st_size > 16 * 1024 * 1024:
        raise SystemExit("release input index is oversized")
    payload = os.pread(fd, opened.st_size, 0)
    if len(payload) != opened.st_size:
        raise SystemExit("release input index is truncated")
finally:
    os.close(fd)
index = json.loads(
    payload.decode("utf-8"),
    object_pairs_hook=reject_duplicate_keys,
    parse_constant=reject_nonfinite,
)
if (
    not isinstance(index, dict)
    or set(index) != {
        "contract", "created_utc", "manifest_set_complete", "platform_manifests",
        "publication_authorized", "release", "schema_version", "sha256_anchor",
        "shared_manifest", "shared_revision",
    }
    or type(index.get("schema_version")) is not int
    or index.get("schema_version") != 1
    or index.get("contract") != "winsvpn-release-input-index-v1"
):
    raise SystemExit("release input index fields are not exact")
created = index["created_utc"]
if not isinstance(created, str) or not created.endswith("Z"):
    raise SystemExit("release input index created_utc is not a UTC timestamp")
try:
    moment = dt.datetime.fromisoformat(created[:-1] + "+00:00")
except ValueError as exc:
    raise SystemExit("release input index created_utc is invalid") from exc
epoch = (moment - dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)) // dt.timedelta(seconds=1)
if not 0 < epoch <= 253402300799:
    raise SystemExit("release input index created_utc is outside the SOURCE_DATE_EPOCH range")
print(epoch)
PY
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

tree_sha256() {
  python3 -I - "$1" <<'PY'
import hashlib, os, pathlib, stat, sys

root = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix().encode("utf-8")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"source tree contains a symbolic link: {path}")
    kind = b"d" if stat.S_ISDIR(info.st_mode) else b"f" if stat.S_ISREG(info.st_mode) else b"?"
    if kind == b"?":
        raise SystemExit(f"source tree contains an unsupported file type: {path}")
    digest.update(kind + b"\0" + relative + b"\0")
    if kind == b"f":
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
print(digest.hexdigest())
PY
}

write_userspace_only_awg_quick() {
  python3 -I - "$1" "$2" "${AWG_GO_BINARY_SHA256_AMD64}" "${AWG_GO_BINARY_SHA256_ARM64}" <<'PY'
import hashlib, pathlib, sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
amd64_sha256 = sys.argv[3]
arm64_sha256 = sys.argv[4]
raw = source.read_bytes()
marker = b"# ~~ function override insertion point ~~\n"
override = f'''# Wins VPN release override: HPK requires the exact in-bundle reviewed userspace engine.
add_if() {{
\tlocal implementation="${{SELF%/*}}/amneziawg-go"
\tlocal expected_engine_sha256 actual_engine_sha256
\tcase "$(/usr/bin/uname -m)" in
\t\tx86_64|amd64) expected_engine_sha256="{amd64_sha256}" ;;
\t\taarch64|arm64) expected_engine_sha256="{arm64_sha256}" ;;
\t\t*) die "unsupported architecture for the reviewed AmneziaWG userspace engine" ;;
\tesac
\t[[ -f "$implementation" && ! -L "$implementation" && -x "$implementation" ]] || die "reviewed in-bundle AmneziaWG userspace implementation is unavailable"
\tactual_engine_sha256="$(/usr/bin/sha256sum -- "$implementation")" || die "could not hash the reviewed AmneziaWG userspace implementation"
\tactual_engine_sha256="${{actual_engine_sha256%% *}}"
\t[[ "$actual_engine_sha256" == "$expected_engine_sha256" ]] || die "AmneziaWG userspace implementation is not owner-authorized for this architecture"
\techo "[!] HeaderProtectionKey requires the exact reviewed userspace AmneziaWG engine; kernel fast path is disabled until exact kernel proof is pinned." >&2
\tcmd "$implementation" "$INTERFACE"
}}
'''.encode("ascii")
if raw.count(marker) != 1:
    raise SystemExit("awg-quick userspace override insertion point is missing or duplicated")
payload = raw.replace(marker, override)
destination.write_bytes(payload)
print(hashlib.sha256(payload).hexdigest())
PY
}

abs_path() {
  local candidate="$1"
  case "${candidate}" in
    /*) printf '%s\n' "${candidate}" ;;
    *) printf '%s\n' "$(pwd -P)/${candidate}" ;;
  esac
}

print_pins() {
  cat <<EOF
AWG_TOOLS_VERSION=${AWG_TOOLS_VERSION}
AWG_TOOLS_COMMIT=${AWG_TOOLS_COMMIT}
AWG_TOOLS_SOURCE_SHA256=${AWG_TOOLS_SOURCE_SHA256}
AWG_TOOLS_UBUNTU_ZIP_SHA256=${AWG_TOOLS_UBUNTU_ZIP_SHA256}
AWG_GO_TAG=${AWG_GO_TAG}
AWG_GO_COMMIT=${AWG_GO_COMMIT}
AWG_GO_SOURCE_SHA256=${AWG_GO_SOURCE_SHA256}
AWG_GO_BINARY_SHA256_AMD64=${AWG_GO_BINARY_SHA256_AMD64}
AWG_GO_BINARY_SHA256_ARM64=${AWG_GO_BINARY_SHA256_ARM64}
AWG_BINARY_SHA256=${AWG_BINARY_SHA256}
AWG_QUICK_SOURCE_SHA256=${AWG_QUICK_SOURCE_SHA256}
AWG_QUICK_SHA256=${AWG_QUICK_SHA256}
REVIEWED_CLANG_PACKAGE=${REVIEWED_CLANG_PACKAGE}
REVIEWED_CLANG_VERSION=${REVIEWED_CLANG_VERSION}
REVIEWED_BINUTILS_PACKAGE=${REVIEWED_BINUTILS_PACKAGE}
REVIEWED_CLANG_SHA256=${REVIEWED_CLANG_SHA256:-MISSING}
EOF
}

if [[ "${1:-}" == "--self-test-pins" ]]; then
  REVIEWED_CLANG_SHA256="$(read_reviewed_clang_pin)" \
    || refuse "tools/toolchain-pins.json is not a strict reviewed pin document"
  print_pins
  [[ "${AWG_BINARY_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_BINARY_SHA256 is malformed"
  [[ "${AWG_QUICK_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_QUICK_SOURCE_SHA256 is malformed"
  [[ "${AWG_QUICK_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_QUICK_SHA256 is malformed"
  [[ "${AWG_TOOLS_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_TOOLS_SOURCE_SHA256 is malformed"
  [[ "${AWG_TOOLS_UBUNTU_ZIP_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_TOOLS_UBUNTU_ZIP_SHA256 is malformed"
  [[ "${AWG_GO_SOURCE_SHA256}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_GO_SOURCE_SHA256 is malformed"
  [[ "${AWG_GO_BINARY_SHA256_AMD64}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_GO_BINARY_SHA256_AMD64 is malformed"
  [[ "${AWG_GO_BINARY_SHA256_ARM64}" =~ ^[0-9a-f]{64}$ ]] || die "AWG_GO_BINARY_SHA256_ARM64 is malformed"
  [[ "${AWG_GO_BINARY_SHA256_AMD64}" != "${AWG_GO_BINARY_SHA256_ARM64}" ]] \
    || die "amd64 and arm64 amneziawg-go output pins must differ."
  [[ "${AWG_GO_COMMIT}" =~ ^[0-9a-f]{40}$ ]] || die "AWG_GO_COMMIT is malformed"
  [[ "${AWG_TOOLS_VERSION}" != "${AWG_GO_TAG}" ]] \
    || die "tools tag must remain distinct from the Go engine tag."
  [[ "${AWG_TOOLS_COMMIT}" != "${AWG_GO_COMMIT}" ]] \
    || die "tools commit must remain distinct from the Go engine commit."
  [[ "${AWG_TOOLS_SOURCE_SHA256}" != "${AWG_TOOLS_UBUNTU_ZIP_SHA256}" ]] \
    || die "tools source tarball hash must not be the Ubuntu zip hash."
  [[ "${AWG_TOOLS_SOURCE_SHA256}" != "${AWG_GO_SOURCE_SHA256}" ]] \
    || die "tools source tarball hash must not be the Go engine archive hash."
  [[ "${AWG_TOOLS_UBUNTU_ZIP_SHA256}" != "${AWG_GO_SOURCE_SHA256}" ]] \
    || die "Ubuntu tools zip hash must not be the Go engine archive hash."
  [[ "${AWG_GO_TAG}" == "v3.1.20260828" ]] \
    || die "Go engine companion tag is not the frozen latest upstream tag."
  [[ "${AWG_GO_COMMIT}" == "b5928efb6ca19f0153958460c3d141f04abc5c2e" ]] \
    || die "Go engine companion commit is not the frozen latest upstream tag."
  [[ "${REVIEWED_CLANG_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
    || refuse "missing pin: tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json; it must pin the exact Debian clang ${REVIEWED_CLANG_VERSION} executable SHA-256."
  [[ -z "${CALLER_CLANG_SHA256}" || "${CALLER_CLANG_SHA256}" == "${REVIEWED_CLANG_SHA256}" ]] \
    || refuse "WINS_LINUX_ARM64_CLANG_SHA256 does not match tools.linux.arm64.clang_executable_sha256."
  printf 'LINUX ARM64 AWG PINS: PASS\n'
  exit 0
fi

OUTPUT="${1:-}"
QUICK_OUTPUT="${2:-}"
[[ -n "${OUTPUT}" ]] || die "Usage: $0 <awg-output> [awg-quick-output]"
[[ -n "${WINS_RELEASE_INPUT_INDEX:-}" ]] \
  || refuse "WINS_RELEASE_INPUT_INDEX is required to derive SOURCE_DATE_EPOCH"
SOURCE_DATE_EPOCH_PINNED="$(derive_release_source_date_epoch "${WINS_RELEASE_INPUT_INDEX}")" \
  || refuse "could not derive SOURCE_DATE_EPOCH from the release input index"
[[ "${SOURCE_DATE_EPOCH_PINNED}" =~ ^[1-9][0-9]*$ ]] \
  || refuse "release input index did not derive one exact SOURCE_DATE_EPOCH"
# One reproducible epoch per release: a caller value is accepted only when it
# is exactly the value derived from the release input index.
if [[ -n "${SOURCE_DATE_EPOCH+x}" && "${SOURCE_DATE_EPOCH}" != "${SOURCE_DATE_EPOCH_PINNED}" ]]; then
  refuse "caller SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} differs from ${SOURCE_DATE_EPOCH_PINNED} derived from the release input index created_utc"
fi
REVIEWED_CLANG_SHA256="$(read_reviewed_clang_pin)" \
  || refuse "tools/toolchain-pins.json is not a strict reviewed pin document"
[[ "${REVIEWED_CLANG_SHA256}" =~ ^[0-9a-f]{64}$ ]] \
  || refuse "missing pin: tools.linux.arm64.clang_executable_sha256 is absent from tools/toolchain-pins.json; it must pin the exact Debian clang ${REVIEWED_CLANG_VERSION} executable SHA-256."
[[ -z "${CALLER_CLANG_SHA256}" || "${CALLER_CLANG_SHA256}" == "${REVIEWED_CLANG_SHA256}" ]] \
  || refuse "WINS_LINUX_ARM64_CLANG_SHA256 does not match tools.linux.arm64.clang_executable_sha256."
OUTPUT="$(abs_path "${OUTPUT}")"
if [[ -n "${QUICK_OUTPUT}" ]]; then
  QUICK_OUTPUT="$(abs_path "${QUICK_OUTPUT}")"
fi

[[ "$(uname -s)" == "Linux" ]] || refuse "linux-arm64 awg must be compiled on Linux, not $(uname -s)."
case "$(uname -m)" in
  aarch64|arm64) ;;
  *)
    refuse "linux-arm64 awg must be compiled natively on aarch64 (found $(uname -m)). Cross-compiling would change the pinned bytes; refusing rather than emitting a binary the release hash would reject."
    ;;
esac

command -v clang >/dev/null 2>&1 || refuse "clang ${REVIEWED_CLANG_VERSION} is required."
command -v make >/dev/null 2>&1 || refuse "make is required."
command -v curl >/dev/null 2>&1 || refuse "curl is required."
command -v python3 >/dev/null 2>&1 || refuse "python3 is required to verify the ELF output."

clang_version="$(clang --version | head -n 1 || true)"
[[ "${clang_version}" == *"clang version ${REVIEWED_CLANG_VERSION}"* ]] \
  || refuse "reviewed clang is Debian ${REVIEWED_CLANG_VERSION}; found: ${clang_version:-unknown}."
if command -v dpkg-query >/dev/null 2>&1; then
  clang_pkg="$(dpkg-query -W -f='${Version}' clang 2>/dev/null || true)"
  [[ "${clang_pkg}" == "${REVIEWED_CLANG_PACKAGE}" ]] \
    || refuse "reviewed clang package is ${REVIEWED_CLANG_PACKAGE}; dpkg reports ${clang_pkg:-missing}."
  binutils_pkg="$(dpkg-query -W -f='${Version}' binutils 2>/dev/null || true)"
  [[ "${binutils_pkg}" == "${REVIEWED_BINUTILS_PACKAGE}" ]] \
    || refuse "reviewed binutils package is ${REVIEWED_BINUTILS_PACKAGE}; dpkg reports ${binutils_pkg:-missing}."
fi
clang_path="$(realpath -e -- "$(command -v clang)")"
[[ -f "${clang_path}" && ! -L "${clang_path}" ]] \
  || refuse "reviewed clang must resolve to one regular non-symlink executable."
[[ "$(sha256_file "${clang_path}")" == "${REVIEWED_CLANG_SHA256}" ]] \
  || refuse "reviewed clang executable SHA-256 verification failed."
exec {CLANG_FD}<"${clang_path}"
CLANG_HELD_PATH="/proc/$$/fd/${CLANG_FD}"
[[ -r "${CLANG_HELD_PATH}" ]] \
  || refuse "Linux /proc descriptor binding is required for the reviewed clang executable."

WORK_ROOT=""
cleanup() {
  if [[ -n "${WORK_ROOT}" ]]; then
    case "${WORK_ROOT}" in
      "${TMPDIR:-/tmp}"/wins-linux-arm64-awg.*)
        rm -rf -- "${WORK_ROOT}"
        ;;
      *)
        die "Refusing to remove an unsafe awg build work root."
        ;;
    esac
  fi
}
trap cleanup EXIT

WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wins-linux-arm64-awg.XXXXXX")"
chmod 700 "${WORK_ROOT}"

archive="${WORK_ROOT}/amneziawg-tools-${AWG_TOOLS_VERSION}.tar.gz"
curl --proto '=https' --tlsv1.2 -fsSL --retry 4 --retry-all-errors \
  "https://github.com/amnezia-vpn/amneziawg-tools/archive/refs/tags/${AWG_TOOLS_VERSION}.tar.gz" \
  -o "${archive}"
[[ "$(sha256_file "${archive}")" == "${AWG_TOOLS_SOURCE_SHA256}" ]] \
  || die "Pinned amneziawg-tools ${AWG_TOOLS_VERSION} source SHA-256 verification failed."

tar -xzf "${archive}" -C "${WORK_ROOT}"
src="${WORK_ROOT}/amneziawg-tools-${AWG_TOOLS_VERSION#v}/src"
[[ -f "${src}/version.h" ]] || die "amneziawg-tools source is missing src/version.h."
[[ -f "${src}/uapi/linux/linux/wireguard.h" ]] || die "amneziawg-tools source is missing the bundled linux uapi."
[[ -f "${src}/wg-quick/linux.bash" ]] || die "amneziawg-tools source is missing wg-quick/linux.bash."
[[ ! -e "${WORK_ROOT}/amneziawg-tools-${AWG_TOOLS_VERSION#v}/.git" ]] \
  || die "Refusing a git checkout; git describe would inject a non-reproducible version string."
grep -Fq 'WIREGUARD_TOOLS_VERSION "3.1.20260812"' "${src}/version.h" \
  || die "Pinned amneziawg-tools source has an unexpected version.h."
[[ "$(sha256_file "${src}/wg-quick/linux.bash")" == "${AWG_QUICK_SOURCE_SHA256}" ]] \
  || die "Source awg-quick is not the already-pinned architecture-independent script."
userspace_quick="${WORK_ROOT}/awg-quick-userspace"
[[ "$(write_userspace_only_awg_quick "${src}/wg-quick/linux.bash" "${userspace_quick}")" == "${AWG_QUICK_SHA256}" ]] \
  || die "Userspace-only awg-quick transformed SHA-256 verification failed."
chmod 0755 "${userspace_quick}"
source_tree_sha256="$(tree_sha256 "${src}")"

build_one() {
  local dest_dir="$1"
  local build="${dest_dir}/src"
  mkdir -p "${build}"
  cp -a "${src}/." "${build}/"
  (
    cd "${build}"
    export LC_ALL=C LANG=C TZ=UTC
    export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH_PINNED}"
    # Environment CFLAGS so Makefile CFLAGS += still adds -I uapi/linux and RUNSTATEDIR.
    # Command-line CFLAGS= would suppress those and compile against distro wireguard.h.
    export CFLAGS="-O3 -ffile-prefix-map=${build}=. -fno-ident -g0 -fPIE"
    export LDFLAGS="-pie -Wl,--build-id=none -Wl,-z,relro,-z,now"
    [[ "$(tree_sha256 "${build}")" == "${source_tree_sha256}" ]] \
      || die "Compiler-consumed amneziawg-tools source does not match the authenticated source tree."
    make PLATFORM=linux WITH_WGQUICK=no WITH_BASHCOMPLETION=no \
      WITH_SYSTEMDUNITS=no CC="${CLANG_HELD_PATH}"
    [[ -x wg ]] || die "make did not produce src/wg."
    install -m 0755 wg "${dest_dir}/awg"
    install -m 0755 "${userspace_quick}" "${dest_dir}/awg-quick"
  )
}

build_one "${WORK_ROOT}/build1"
[[ "$(sha256_file "${WORK_ROOT}/build1/awg")" == "${AWG_BINARY_SHA256}" ]] \
  || die "Reproducible linux-arm64 awg SHA-256 verification failed."
[[ "$(sha256_file "${WORK_ROOT}/build1/awg-quick")" == "${AWG_QUICK_SHA256}" ]] \
  || die "linux-arm64 awg-quick SHA-256 verification failed."

if [[ "${WINS_LINUX_ARM64_AWG_REPRODUCE:-0}" == "1" ]]; then
  build_one "${WORK_ROOT}/build2"
  cmp -s "${WORK_ROOT}/build1/awg" "${WORK_ROOT}/build2/awg" \
    || die "Two clean linux-arm64 awg builds were not byte-identical."
  cmp -s "${WORK_ROOT}/build1/awg-quick" "${WORK_ROOT}/build2/awg-quick" \
    || die "Two clean linux-arm64 awg-quick builds were not byte-identical."
  printf 'LINUX ARM64 AWG REPRODUCE: PASS\n'
fi

python3 "${SCRIPT_DIR}/test_linux_arm64_fallback_elf.py" verify awg \
  "${WORK_ROOT}/build1/awg" --sha256 "${AWG_BINARY_SHA256}"
python3 "${SCRIPT_DIR}/test_linux_arm64_fallback_elf.py" verify awg-quick \
  "${WORK_ROOT}/build1/awg-quick" --shape-only

mkdir -p "$(dirname "${OUTPUT}")"
install -m 0755 "${WORK_ROOT}/build1/awg" "${OUTPUT}"
if [[ -n "${QUICK_OUTPUT}" ]]; then
  mkdir -p "$(dirname "${QUICK_OUTPUT}")"
  install -m 0755 "${WORK_ROOT}/build1/awg-quick" "${QUICK_OUTPUT}"
fi

printf 'Built %s\n' "${OUTPUT}"
printf '  awg-tools: %s (%s)\n' "${AWG_TOOLS_VERSION}" "${AWG_TOOLS_COMMIT}"
printf '  clang:     %s\n' "${clang_version}"
printf '  sha256:    %s\n' "$(sha256_file "${OUTPUT}")"
if [[ -n "${QUICK_OUTPUT}" ]]; then
  printf '  awg-quick: %s\n' "$(sha256_file "${QUICK_OUTPUT}")"
fi
