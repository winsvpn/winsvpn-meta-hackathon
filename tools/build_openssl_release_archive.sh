#!/bin/bash
# Deterministic, fail-closed OpenSSL 4.0.2 source-to-binary producer for
# darwin64-arm64-cc no-shared no-tests no-docs. Authenticates the exact Apple
# clang/Xcode identity, isolates source/build/install trees, refuses ambient
# package substitution, strips the release CLI, and emits a stable ZIP.
# This producer never writes an owner build receipt and never overwrites an
# existing official output.
set -euo pipefail

die() {
  printf 'build-openssl-release-archive: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 0 ]] || die 'usage: tools/build_openssl_release_archive.sh'

SELF_SRC="${BASH_SOURCE[0]}"
[[ -n "$SELF_SRC" && ! -L "$SELF_SRC" ]] || die 'producer path must be a regular file'
SELF_DIR="$(cd "$(/usr/bin/dirname "$SELF_SRC")" && pwd)" || die 'producer directory could not be resolved'
SELF="$SELF_DIR/$(/usr/bin/basename "$SELF_SRC")"
CUSTODY="$SELF_DIR/release_openssl_archive_custody.py"
[[ "$SELF" == "$SELF_DIR/build_openssl_release_archive.sh" && -f "$SELF" && ! -L "$SELF" ]] ||
  die 'malicious or substituted OpenSSL producer rejected'
[[ -f "$CUSTODY" && ! -L "$CUSTODY" ]] ||
  die 'malicious or substituted OpenSSL custody controller rejected'

PYTHON=/usr/bin/python3
PERL=/usr/bin/perl
MAKE=/usr/bin/make
CURL=/usr/bin/curl
UNAME=/usr/bin/uname
MKTEMP=/usr/bin/mktemp
SYSCTL=/usr/sbin/sysctl
XCODEBUILD=/usr/bin/xcodebuild
XCRUN=/usr/bin/xcrun
STAT=/usr/bin/stat

OFFICIAL_VERSION=4.0.2
OFFICIAL_SOURCE_NAME=openssl-4.0.2.tar.gz
OFFICIAL_SOURCE_SHA256=736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8
OFFICIAL_SOURCE_URL='https://www.openssl.org/source/openssl-4.0.2.tar.gz'
OFFICIAL_ARCHIVE_NAME=wins-openssl-4.0.2-darwin-arm64.zip
OFFICIAL_SOURCE_PATH="/Users/owner/Downloads/${OFFICIAL_SOURCE_NAME}"
OFFICIAL_OUTPUT_PATH="/Users/owner/Downloads/${OFFICIAL_ARCHIVE_NAME}"
SOURCE_DATE_EPOCH=1787658262
ZIP_DATE_TIME='2026,8,25,11,44,22'
MAX_SOURCE=83886080
MAX_SOURCE_EXPANDED=536870912
MAX_ARCHIVE=10485760
TOOLCHAIN='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin'
DEVELOPER_DIR='/Applications/Xcode.app/Contents/Developer'
CLANG="${TOOLCHAIN}/clang"
FROZEN_CLANG_SHA256=7def90dd8829726686213a747fc5bff1583df933dae5edc55d755479e0bfe00a
FROZEN_CLANG_VERSION_LINE='Apple clang version 21.0.0 (clang-2100.1.1.101)'
FROZEN_CLANG_TARGET='arm64-apple-darwin25.6.0'
FROZEN_XCODE_VERSION=26.6
FROZEN_XCODE_BUILD=17F113
MACOSX_DEPLOYMENT_TARGET=26.0

[[ "$("$UNAME" -s)" == Darwin ]] || die 'OpenSSL producer requires Darwin'
[[ "$("$UNAME" -m)" == arm64 ]] || die 'OpenSSL producer requires arm64'
[[ -x "$PYTHON" && ! -L "$PYTHON" ]] || die 'system python3 is required'
[[ -x "$PERL" ]] || die 'system perl is required'
[[ -x "$MAKE" ]] || die 'system make is required'

SOURCE_PATH="${WINS_OPENSSL_SOURCE_ARCHIVE:-$OFFICIAL_SOURCE_PATH}"
OUTPUT_PATH="${WINS_OPENSSL_OUTPUT_ARCHIVE:-$OFFICIAL_OUTPUT_PATH}"

[[ "$SOURCE_PATH" == /* ]] || die 'source archive path must be absolute'
[[ "$(/usr/bin/basename "$SOURCE_PATH")" == "$OFFICIAL_SOURCE_NAME" ]] ||
  die "source archive basename must be ${OFFICIAL_SOURCE_NAME}"
[[ "$SOURCE_PATH" != *..* ]] || die 'source archive path is unsafe'

case "$OUTPUT_PATH" in
  "$OFFICIAL_OUTPUT_PATH") ;;
  /private/tmp/wins-openssl-build.*/"$OFFICIAL_ARCHIVE_NAME") ;;
  *) die "output archive path is not an owner-approved location: ${OUTPUT_PATH}" ;;
esac
[[ "$OUTPUT_PATH" != *..* ]] || die 'output archive path is unsafe'

WORK=""
cleanup() {
  if [[ -n "${WORK:-}" ]]; then
    case "$WORK" in
      /private/tmp/wins-openssl-build.*)
        /bin/chmod -R u+w "$WORK" 2>/dev/null || true
        /bin/rm -rf -- "$WORK"
        ;;
      *) die "refusing to remove an unsafe OpenSSL work root: ${WORK}" ;;
    esac
  fi
}
trap cleanup EXIT

run_py() {
  "$PYTHON" - "$CUSTODY" "$SELF" "$@" <<'PY'
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import zipfile

custody_path = Path(sys.argv[1])
producer_path = Path(sys.argv[2])
action = sys.argv[3]
args = sys.argv[4:]

def die(message: str) -> None:
    print(f"build-openssl-release-archive: {message}", file=sys.stderr)
    raise SystemExit(1)

def identity(info: os.stat_result) -> tuple[object, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_size, info.st_mtime_ns)

def bind_bytes(path: Path, max_size: int, label: str) -> bytes:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        die(f"{label} must be one absolute regular file")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        die(f"{label} must be one regular non-hardlinked file")
    if info.st_size <= 0 or info.st_size > max_size:
        die(f"{label} exceeds the size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    chunks: list[bytes] = []
    try:
        opened = os.fstat(fd)
        if identity(info) != identity(opened):
            die(f"{label} was replaced before it was opened")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            die(f"{label} changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    if identity(after) != identity(latest):
        die(f"{label} was replaced after it was opened")
    data = b"".join(chunks)
    if not data:
        die(f"{label} snapshot is empty")
    return data

def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def load_custody():
    spec = importlib.util.spec_from_file_location("release_openssl_archive_custody", custody_path)
    if spec is None or spec.loader is None:
        die("OpenSSL custody controller could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def require_ascii_text(path: Path, label: str, max_size: int) -> bytes:
    data = bind_bytes(path, max_size, label)
    if b"\0" in data:
        die(f"{label} contains a NUL")
    try:
        data.decode("ascii")
    except UnicodeDecodeError as exc:
        die(f"{label} is not ASCII: {exc}")
    return data

module = load_custody()
if module.OFFICIAL_VERSION != "4.0.2":
    die("custody controller is not the OpenSSL 4.0.2 identity")
if module.OFFICIAL_SOURCE_NAME != "openssl-4.0.2.tar.gz":
    die("custody source archive identity mismatch")
if module.OFFICIAL_SOURCE_SHA256 != "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8":
    die("custody source digest is not the official OpenSSL 4.0.2 digest")
if module.OFFICIAL_ARCHIVE_NAME != "wins-openssl-4.0.2-darwin-arm64.zip":
    die("custody archive identity mismatch")
if module.OFFICIAL_CONFIGURATION != "darwin64-arm64-cc no-shared no-tests no-docs":
    die("custody configuration flags mismatch")
if module.OFFICIAL_PLATFORM != "darwin64-arm64-cc":
    die("custody platform mismatch")

if action == "snapshot_controllers":
    producer = require_ascii_text(producer_path, "OpenSSL producer", 256 * 1024)
    custody = require_ascii_text(custody_path, "OpenSSL custody controller", module.MAX_CONTROLLER)
    print(digest_bytes(producer))
    print(digest_bytes(custody))
    raise SystemExit(0)

if action == "verify_controllers":
    expected_producer, expected_custody = args
    producer = require_ascii_text(producer_path, "OpenSSL producer", 256 * 1024)
    custody = require_ascii_text(custody_path, "OpenSSL custody controller", module.MAX_CONTROLLER)
    if digest_bytes(producer) != expected_producer:
        die("OpenSSL producer mutated during the build")
    if digest_bytes(custody) != expected_custody:
        die("OpenSSL custody controller mutated during the build")
    raise SystemExit(0)

if action == "compiler":
    clang, sha, version_line, target, xcode_version, xcode_build = args
    path = Path(clang)
    if path.is_symlink():
        die("OpenSSL compiler/toolchain identity must not be a symbolic link")
    digest = digest_bytes(bind_bytes(path, 256 * 1024 * 1024, "OpenSSL compiler"))
    if digest != sha:
        die("OpenSSL compiler/toolchain identity mismatch")
    frozen = dict(module.FROZEN_COMPILER_IDENTITY)
    if frozen["path"] != clang or frozen["sha256"] != sha:
        die("OpenSSL compiler/toolchain identity pin mismatch")
    if frozen["version_line"] != version_line or frozen["target"] != target:
        die("OpenSSL compiler/toolchain identity mismatch")
    if frozen["xcode_version"] != xcode_version or frozen["xcode_build"] != xcode_build:
        die("OpenSSL compiler/toolchain identity mismatch")
    print(digest)
    raise SystemExit(0)

if action == "source":
    source_text, expected, max_source_text = args
    source = Path(source_text)
    if source.is_symlink():
        die("OpenSSL source archive symbolic link rejected")
    digest = digest_bytes(bind_bytes(source, int(max_source_text), "OpenSSL source archive"))
    if digest != expected or digest != module.OFFICIAL_SOURCE_SHA256:
        die("OpenSSL source archive digest is not the official OpenSSL 4.0.2 digest")
    print(digest)
    raise SystemExit(0)

if action == "extract":
    source_text, destination_text, expected, max_source_text, max_expanded_text = args
    source = Path(source_text)
    destination = Path(destination_text)
    max_source = int(max_source_text)
    max_expanded = int(max_expanded_text)
    data = bind_bytes(source, max_source, "OpenSSL source archive")
    if digest_bytes(data) != expected:
        die("OpenSSL source archive digest is not the official OpenSSL 4.0.2 digest")
    if destination.exists() or destination.is_symlink():
        die("OpenSSL source extract directory must not already exist")
    destination.mkdir(mode=0o700)
    tmp_archive = destination / "openssl-4.0.2.tar.gz"
    fd = os.open(tmp_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    if module.digest_file(tmp_archive) != expected:
        die("OpenSSL source archive changed during authenticated copying")
    total = 0
    with tarfile.open(tmp_archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            die("OpenSSL source archive is empty")
        for member in members:
            name = member.name
            parts = Path(name).parts
            if name.startswith("/") or name.startswith("\\") or ".." in parts:
                die("OpenSSL source archive contains an unsafe path")
            if not (name == "openssl-4.0.2" or name.startswith("openssl-4.0.2/")):
                die(f"unexpected OpenSSL source member: {name}")
            if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                die(f"OpenSSL source archive contains a non-regular member: {name}")
            if member.isfile():
                total += member.size
                if total > max_expanded or member.size > max_expanded:
                    die("OpenSSL source expanded size exceeds the limit")
        bundle.extractall(path=destination, numeric_owner=True)
    extracted = destination / "openssl-4.0.2"
    if not extracted.is_dir() or extracted.is_symlink():
        die("OpenSSL source root is absent")
    for relative, label in (("Configure", "Configure"), ("LICENSE.txt", "LICENSE.txt"), ("VERSION.dat", "VERSION.dat")):
        path = extracted / relative
        if path.is_symlink() or not path.is_file():
            die(f"OpenSSL {label} is absent")
    version_text = (extracted / "VERSION.dat").read_text(encoding="ascii")
    if "PATCH=2" not in version_text or 'RELEASE_DATE="25 Aug 2026"' not in version_text:
        die("OpenSSL VERSION.dat is not the official 4.0.2 release")
    print(extracted)
    raise SystemExit(0)

if action == "pack":
    binary_text, license_text, zip_text, date_text, max_archive_text = args
    binary = Path(binary_text)
    license_path = Path(license_text)
    archive = Path(zip_text)
    year, month, day, hour, minute, second = (int(part) for part in date_text.split(","))
    date_time = (year, month, day, hour, minute, second)
    if archive.exists() or archive.is_symlink():
        die("OpenSSL ZIP must not already exist")
    binary_data = bind_bytes(binary, 32 * 1024 * 1024, "OpenSSL executable")
    license_data = bind_bytes(license_path, 1024 * 1024, "OpenSSL LICENSE.txt")
    try:
        license_data.decode("ascii")
    except UnicodeDecodeError as exc:
        die(f"OpenSSL LICENSE.txt is not ASCII: {exc}")
    members = [
        ("openssl/", "dir", b"", 0o40755),
        ("openssl/bin/", "dir", b"", 0o40700),
        ("openssl/bin/openssl", "file", binary_data, 0o100500),
        ("openssl/share/", "dir", b"", 0o40700),
        ("openssl/share/LICENSE.txt", "file", license_data, 0o100400),
    ]
    if [name for name, _, _, _ in members] != list(module.EXPECTED_MEMBERS):
        die("OpenSSL ZIP member order mismatch")
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with zipfile.ZipFile(archive, "w") as bundle:
        for name, kind, payload, unix_mode in members:
            info = zipfile.ZipInfo(name, date_time)
            info.create_system = 3
            info.create_version = 30
            info.extra = b""
            info.comment = b""
            if kind == "dir":
                info.compress_type = zipfile.ZIP_STORED
                info.extract_version = 10
                info.external_attr = (unix_mode << 16) | 0x10
                bundle.writestr(info, b"")
            else:
                info.compress_type = zipfile.ZIP_DEFLATED
                info.extract_version = 20
                info.external_attr = (unix_mode << 16) | 0x01
                bundle.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED)
    raw = bind_bytes(archive, int(max_archive_text), "OpenSSL ZIP")
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(raw):
        die("OpenSSL ZIP end record is absent")
    comment_length = int.from_bytes(raw[eocd + 20 : eocd + 22], "little")
    if eocd + 22 + comment_length != len(raw) or comment_length:
        die("OpenSSL ZIP comments or trailing bytes are forbidden")
    print(digest_bytes(raw))
    raise SystemExit(0)

if action == "tree_from_zip":
    archive_text, extracted_text, expected_archive, max_archive_text = args
    archive = Path(archive_text)
    extracted = Path(extracted_text)
    if digest_bytes(bind_bytes(archive, int(max_archive_text), "OpenSSL ZIP")) != expected_archive:
        die("OpenSSL ZIP digest mismatch")
    if extracted.exists() or extracted.is_symlink():
        die("OpenSSL extract directory must not already exist")
    module.safe_extract(archive, extracted)
    root = extracted / "openssl"
    binary = root / "bin" / "openssl"
    print(module.tree_hash(root))
    print(module.digest_file(binary))
    print(binary)
    raise SystemExit(0)

if action == "capabilities":
    binary_text, state_text, expected_executable = args
    binary = Path(binary_text)
    state = Path(state_text)
    if module.digest_file(binary) != expected_executable:
        die("OpenSSL executable digest mismatch before capability validation")
    module.check_capabilities(binary, state, module.OFFICIAL_VERSION, module.OFFICIAL_PLATFORM)
    if module.digest_file(binary) != expected_executable:
        die("OpenSSL executable changed during capability validation")
    raise SystemExit(0)

if action == "transaction":
    archive_sha, tree_sha, executable_sha = args
    pin = {
        "archive_sha": archive_sha,
        "build_configuration": module.OFFICIAL_CONFIGURATION,
        "compiler_identity": dict(module.FROZEN_COMPILER_IDENTITY),
        "executable_sha": executable_sha,
        "tree_sha": tree_sha,
        "source_name": module.OFFICIAL_SOURCE_NAME,
        "source_sha": module.OFFICIAL_SOURCE_SHA256,
        "version": module.OFFICIAL_VERSION,
    }
    transaction = module.canonical_build_transaction(pin)
    frozen = getattr(module, "OFFICIAL_BUILD_TRANSACTION", "")
    if frozen and transaction != frozen:
        die("OpenSSL build transaction is not the frozen 4.0.2 transaction")
    archive_freeze = getattr(module, "OFFICIAL_ARCHIVE_SHA256", "")
    tree_freeze = getattr(module, "OFFICIAL_TREE_SHA256", "")
    executable_freeze = getattr(module, "OFFICIAL_EXECUTABLE_SHA256", "")
    if archive_freeze and archive_sha != archive_freeze:
        die("OpenSSL archive digest is not the frozen 4.0.2 digest")
    if tree_freeze and tree_sha != tree_freeze:
        die("OpenSSL install tree digest is not the frozen 4.0.2 digest")
    if executable_freeze and executable_sha != executable_freeze:
        die("OpenSSL executable digest is not the frozen 4.0.2 digest")
    print(transaction)
    raise SystemExit(0)

if action == "install_excl":
    source_text, destination_text, expected, max_size_text = args
    source = Path(source_text)
    destination = Path(destination_text)
    if destination.exists() or destination.is_symlink():
        die(f"refusing to overwrite existing OpenSSL output: {destination}")
    data = bind_bytes(source, int(max_size_text), "OpenSSL payload")
    if digest_bytes(data) != expected:
        die("OpenSSL payload digest mismatch during install")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    latest = destination.lstat()
    if identity(after) != identity(latest):
        die("OpenSSL output mutated after exclusive create")
    if stat.S_IMODE(latest.st_mode) != 0o444:
        die("OpenSSL output must be immutable mode 0444")
    if digest_bytes(bind_bytes(destination, int(max_size_text), "installed OpenSSL payload")) != expected:
        die("OpenSSL output digest mismatch after exclusive create")
    print(expected)
    raise SystemExit(0)

if action == "match_existing":
    path_text, expected, max_size_text = args
    path = Path(path_text)
    if path.is_symlink() or not path.is_file():
        die("existing OpenSSL output must be one regular file")
    info = path.lstat()
    if stat.S_IMODE(info.st_mode) != 0o444:
        die("existing OpenSSL output must be immutable mode 0444")
    digest = digest_bytes(bind_bytes(path, int(max_size_text), "existing OpenSSL ZIP"))
    if digest != expected:
        die("existing OpenSSL output does not match this identity-proven build")
    print(digest)
    raise SystemExit(0)

if action == "candidate_record":
    archive_sha, tree_sha, executable_sha, transaction, producer_sha, custody_sha = args
    record = {
        "contract": "winsvpn-openssl-source-to-binary-candidate-record-v1",
        "authenticated": False,
        "issuer": "candidate-producer",
        "version": module.OFFICIAL_VERSION,
        "source_archive_name": module.OFFICIAL_SOURCE_NAME,
        "source_archive_sha256": module.OFFICIAL_SOURCE_SHA256,
        "build_configuration": module.OFFICIAL_CONFIGURATION,
        "compiler_identity": dict(module.FROZEN_COMPILER_IDENTITY),
        "build_transaction": transaction,
        "archive_sha256": archive_sha,
        "install_tree_sha256": tree_sha,
        "executable_sha256": executable_sha,
        "producer": "tools/build_openssl_release_archive.sh",
        "producer_sha256": producer_sha,
        "controller": module.CONTROLLER_RELATIVE,
        "controller_sha256": custody_sha,
        "note": "Not an owner build receipt. Candidate self-auth remains owner-blocked.",
    }
    if record["authenticated"] is not False:
        die("candidate record must not claim authentication")
    if record["issuer"] == module.RECEIPT_ISSUER:
        die("candidate record must not use the owner receipt issuer")
    print(json.dumps(record, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0)

die(f"unknown OpenSSL producer action: {action}")
PY
}

[[ ! -L "$OUTPUT_PATH" ]] || die 'output archive symbolic link rejected'
OUTPUT_PARENT="$(/usr/bin/dirname "$OUTPUT_PATH")"
[[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" ]] || die "output parent is not a directory: ${OUTPUT_PARENT}"
if [[ -e "$OUTPUT_PATH" ]]; then
  [[ -f "$OUTPUT_PATH" ]] || die "existing OpenSSL output is not a regular file: ${OUTPUT_PATH}"
  [[ "$("$STAT" -f %Lp "$OUTPUT_PATH")" == 444 ]] || die 'existing OpenSSL output must be immutable mode 0444'
  [[ "$("$STAT" -f %z "$OUTPUT_PATH")" -gt 1000 ]] || die 'refusing to overwrite an incomplete OpenSSL output'
fi

CONTROLLER_HASHES="$(run_py snapshot_controllers)" || die 'controller snapshot failed'
PRODUCER_SHA256="$(printf '%s\n' "$CONTROLLER_HASHES" | /usr/bin/sed -n '1p')"
CUSTODY_SHA256="$(printf '%s\n' "$CONTROLLER_HASHES" | /usr/bin/sed -n '2p')"
[[ "$PRODUCER_SHA256" =~ ^[0-9a-f]{64}$ && "$CUSTODY_SHA256" =~ ^[0-9a-f]{64}$ ]] ||
  die 'controller snapshot is malformed'

if [[ -e "$SOURCE_PATH" ]]; then
  [[ ! -L "$SOURCE_PATH" ]] || die 'OpenSSL source archive symbolic link rejected'
  [[ -f "$SOURCE_PATH" ]] || die 'OpenSSL source archive must be one regular file'
  run_py source "$SOURCE_PATH" "$OFFICIAL_SOURCE_SHA256" "$MAX_SOURCE" >/dev/null
elif [[ "$SOURCE_PATH" == "$OFFICIAL_SOURCE_PATH" ]]; then
  FETCH_TMP="$("$MKTEMP" /private/tmp/openssl-4.0.2.tar.gz.XXXXXX)"
  "$CURL" --fail --location --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
    --output "$FETCH_TMP" "$OFFICIAL_SOURCE_URL" || {
    /bin/rm -f -- "$FETCH_TMP"
    die 'official OpenSSL 4.0.2 source download failed'
  }
  run_py source "$FETCH_TMP" "$OFFICIAL_SOURCE_SHA256" "$MAX_SOURCE" >/dev/null || {
    /bin/rm -f -- "$FETCH_TMP"
    die 'downloaded OpenSSL source digest is not official 4.0.2'
  }
  run_py install_excl "$FETCH_TMP" "$SOURCE_PATH" "$OFFICIAL_SOURCE_SHA256" "$MAX_SOURCE" >/dev/null || {
    /bin/rm -f -- "$FETCH_TMP"
    die 'exclusive install of the official OpenSSL source failed'
  }
  /bin/rm -f -- "$FETCH_TMP"
else
  die "OpenSSL source archive is absent: ${SOURCE_PATH}"
fi

[[ -x "$CLANG" && ! -L "$CLANG" ]] || die 'frozen Apple clang path is absent'
[[ -d "$DEVELOPER_DIR" && ! -L "$DEVELOPER_DIR" ]] || die 'frozen Xcode Developer directory is absent'
[[ "$("$XCRUN" -f clang)" == "$CLANG" ]] || die 'xcrun clang is not the frozen Apple clang'
XCODE_OUT="$("$XCODEBUILD" -version)"
printf '%s\n' "$XCODE_OUT" | /usr/bin/grep -qx "Xcode ${FROZEN_XCODE_VERSION}" ||
  die "Xcode version is not ${FROZEN_XCODE_VERSION}"
printf '%s\n' "$XCODE_OUT" | /usr/bin/grep -qx "Build version ${FROZEN_XCODE_BUILD}" ||
  die "Xcode build is not ${FROZEN_XCODE_BUILD}"
CLANG_VERSION_OUT="$("$CLANG" --version)"
CLANG_VERSION_LINE="$(printf '%s\n' "$CLANG_VERSION_OUT" | /usr/bin/sed -n '1p')"
CLANG_TARGET_LINE="$(printf '%s\n' "$CLANG_VERSION_OUT" | /usr/bin/sed -n '2p')"
[[ "$CLANG_VERSION_LINE" == "$FROZEN_CLANG_VERSION_LINE" ]] ||
  die 'Apple clang version line mismatch'
[[ "$CLANG_TARGET_LINE" == "Target: ${FROZEN_CLANG_TARGET}" ]] ||
  die 'Apple clang target mismatch'
run_py compiler "$CLANG" "$FROZEN_CLANG_SHA256" "$FROZEN_CLANG_VERSION_LINE" \
  "$FROZEN_CLANG_TARGET" "$FROZEN_XCODE_VERSION" "$FROZEN_XCODE_BUILD" >/dev/null

SDK_LINK="$("$XCRUN" --sdk macosx --show-sdk-path)"
[[ "$SDK_LINK" == "$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/"* ]] ||
  die 'macOS SDK is not the frozen Xcode SDK'
if [[ -L "$SDK_LINK" ]]; then
  SDK_TARGET="$(/usr/bin/readlink "$SDK_LINK")"
  [[ "$SDK_TARGET" == MacOSX.sdk ]] || die "macOS SDK symlink target is not MacOSX.sdk: ${SDK_TARGET}"
  SDKROOT="$(/usr/bin/dirname "$SDK_LINK")/MacOSX.sdk"
else
  SDKROOT="$SDK_LINK"
fi
[[ -d "$SDKROOT" && ! -L "$SDKROOT" ]] || die 'macOS SDK path is absent'
[[ "$SDKROOT" == "$DEVELOPER_DIR/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk" ]] ||
  die 'macOS SDK is not the frozen Xcode MacOSX.sdk'
JOBS="$("$SYSCTL" -n hw.ncpu)"
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die 'CPU count is malformed'

WORK="$("$MKTEMP" -d /private/tmp/wins-openssl-build.XXXXXX)"
/bin/chmod 700 "$WORK"
HOME_DIR="$WORK/home"
TMP_DIR="$WORK/tmp"
/bin/mkdir -m 700 "$HOME_DIR" "$TMP_DIR"
BUILD_PATH="${TOOLCHAIN}:/usr/bin:/bin"
STRIP="${TOOLCHAIN}/strip"
AR="${TOOLCHAIN}/ar"
RANLIB="${TOOLCHAIN}/ranlib"
[[ -x "$STRIP" && -x "$AR" && -x "$RANLIB" ]] || die 'frozen Apple strip/ar/ranlib are absent'

run_isolated() {
  local cwd="$1"
  local log="$2"
  shift 2
  (
    cd "$cwd" || exit 1
    /usr/bin/env -i \
      HOME="$HOME_DIR" \
      TMPDIR="$TMP_DIR" \
      PATH="$BUILD_PATH" \
      PWD="$cwd" \
      CC="$CLANG" \
      CXX="${TOOLCHAIN}/clang++" \
      AR="$AR" \
      RANLIB="$RANLIB" \
      STRIP="$STRIP" \
      SDKROOT="$SDKROOT" \
      DEVELOPER_DIR="$DEVELOPER_DIR" \
      MACOSX_DEPLOYMENT_TARGET="$MACOSX_DEPLOYMENT_TARGET" \
      SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
      ZERO_AR_DATE=1 \
      LDFLAGS="-Wl,-reproducible" \
      LANG=C \
      LC_ALL=C \
      TZ=UTC \
      OPENSSL_CONF=/dev/null \
      "$@"
  ) >"$log" 2>&1 || {
    /usr/bin/tail -n 80 "$log" >&2
    return 1
  }
}

build_one() {
  local root="$1"
  local src_root zip_path extracted tree_out archive_sha tree_sha executable_sha binary_path
  /bin/mkdir -m 700 "$root" "$root/build" "$root/install" "$root/state"
  /bin/mkdir -m 700 "$root/state/home" "$root/state/tmp"
  src_root="$(run_py extract "$SOURCE_PATH" "$root/extract" "$OFFICIAL_SOURCE_SHA256" "$MAX_SOURCE" "$MAX_SOURCE_EXPANDED")"
  [[ -d "$src_root" ]] || die 'OpenSSL source extract failed'
  run_isolated "$root/build" "$root/configure.log" "$PERL" "$src_root/Configure" \
    darwin64-arm64-cc no-shared no-tests no-docs \
    --prefix="$root/install" \
    --openssldir="$root/install/ssl" || die 'OpenSSL Configure failed'
  run_isolated "$root/build" "$root/make.log" "$MAKE" "-j${JOBS}" || die 'OpenSSL make failed'
  run_isolated "$root/build" "$root/install.log" "$MAKE" install_sw || die 'OpenSSL make install_sw failed'
  [[ -f "$root/install/bin/openssl" && ! -L "$root/install/bin/openssl" ]] ||
    die 'OpenSSL executable was not installed'
  run_isolated "$root/install/bin" "$root/strip.log" "$STRIP" -S "$root/install/bin/openssl" ||
    die 'OpenSSL strip failed'
  zip_path="$root/${OFFICIAL_ARCHIVE_NAME}"
  archive_sha="$(run_py pack "$root/install/bin/openssl" "$src_root/LICENSE.txt" "$zip_path" "$ZIP_DATE_TIME" "$MAX_ARCHIVE")"
  extracted="$root/extracted"
  tree_out="$(run_py tree_from_zip "$zip_path" "$extracted" "$archive_sha" "$MAX_ARCHIVE")"
  tree_sha="$(printf '%s\n' "$tree_out" | /usr/bin/sed -n '1p')"
  executable_sha="$(printf '%s\n' "$tree_out" | /usr/bin/sed -n '2p')"
  binary_path="$(printf '%s\n' "$tree_out" | /usr/bin/sed -n '3p')"
  run_py capabilities "$binary_path" "$root/state" "$executable_sha"
  printf 'ARCHIVE|%s\nTREE|%s\nEXEC|%s\nZIP|%s\n' "$archive_sha" "$tree_sha" "$executable_sha" "$zip_path"
}

run_py verify_controllers "$PRODUCER_SHA256" "$CUSTODY_SHA256"
field() {
  printf '%s\n' "$1" | /usr/bin/awk -F'|' -v key="$2" '$1==key {print $2; found=1} END {if (!found) exit 1}'
}
STAGE="$WORK/stage"
PASS1_DIR="$WORK/pass1"
PASS2_DIR="$WORK/pass2"
/bin/mkdir -m 700 "$PASS1_DIR" "$PASS2_DIR"
FIRST_OUT="$(build_one "$STAGE")"
FIRST_ARCHIVE_SHA="$(field "$FIRST_OUT" ARCHIVE)" || die 'first OpenSSL archive digest is absent'
FIRST_TREE_SHA="$(field "$FIRST_OUT" TREE)" || die 'first OpenSSL tree digest is absent'
FIRST_EXEC_SHA="$(field "$FIRST_OUT" EXEC)" || die 'first OpenSSL executable digest is absent'
FIRST_ZIP="$(field "$FIRST_OUT" ZIP)" || die 'first OpenSSL ZIP path is absent'
/bin/cp "$FIRST_ZIP" "$PASS1_DIR/${OFFICIAL_ARCHIVE_NAME}"
/bin/cp "$STAGE/install/bin/openssl" "$PASS1_DIR/openssl"
/bin/chmod -R u+w "$STAGE"
/bin/rm -rf -- "$STAGE"
FIRST_ZIP="$PASS1_DIR/${OFFICIAL_ARCHIVE_NAME}"
SECOND_OUT="$(build_one "$STAGE")"
SECOND_ARCHIVE_SHA="$(field "$SECOND_OUT" ARCHIVE)" || die 'second OpenSSL archive digest is absent'
SECOND_TREE_SHA="$(field "$SECOND_OUT" TREE)" || die 'second OpenSSL tree digest is absent'
SECOND_EXEC_SHA="$(field "$SECOND_OUT" EXEC)" || die 'second OpenSSL executable digest is absent'
SECOND_ZIP="$(field "$SECOND_OUT" ZIP)" || die 'second OpenSSL ZIP path is absent'
/bin/cp "$SECOND_ZIP" "$PASS2_DIR/${OFFICIAL_ARCHIVE_NAME}"
[[ "$FIRST_ARCHIVE_SHA" =~ ^[0-9a-f]{64}$ &&
   "$FIRST_TREE_SHA" =~ ^[0-9a-f]{64}$ &&
   "$FIRST_EXEC_SHA" =~ ^[0-9a-f]{64}$ ]] || die 'OpenSSL identity output is malformed'
[[ "$FIRST_ARCHIVE_SHA" == "$SECOND_ARCHIVE_SHA" &&
   "$FIRST_TREE_SHA" == "$SECOND_TREE_SHA" &&
   "$FIRST_EXEC_SHA" == "$SECOND_EXEC_SHA" ]] || {
  printf 'first archive=%s tree=%s exec=%s\n' "$FIRST_ARCHIVE_SHA" "$FIRST_TREE_SHA" "$FIRST_EXEC_SHA" >&2
  printf 'second archive=%s tree=%s exec=%s\n' "$SECOND_ARCHIVE_SHA" "$SECOND_TREE_SHA" "$SECOND_EXEC_SHA" >&2
  /bin/cp "$PASS1_DIR/openssl" /private/tmp/wins-openssl-diag-a
  /bin/cp "$STAGE/install/bin/openssl" /private/tmp/wins-openssl-diag-b
  /bin/cp "$PASS1_DIR/${OFFICIAL_ARCHIVE_NAME}" /private/tmp/wins-openssl-diag-a.zip
  /bin/cp "$PASS2_DIR/${OFFICIAL_ARCHIVE_NAME}" /private/tmp/wins-openssl-diag-b.zip
  die 'OpenSSL identity-proven rebuild mismatch'
}

run_py verify_controllers "$PRODUCER_SHA256" "$CUSTODY_SHA256"
TRANSACTION="$(run_py transaction "$FIRST_ARCHIVE_SHA" "$FIRST_TREE_SHA" "$FIRST_EXEC_SHA")"

if [[ -e "$OUTPUT_PATH" ]]; then
  run_py match_existing "$OUTPUT_PATH" "$FIRST_ARCHIVE_SHA" "$MAX_ARCHIVE" >/dev/null
  printf 'build-openssl-release-archive: existing output already matches identity-proven bytes\n' >&2
else
  run_py install_excl "$FIRST_ZIP" "$OUTPUT_PATH" "$FIRST_ARCHIVE_SHA" "$MAX_ARCHIVE" >/dev/null
fi

RECORD="$(run_py candidate_record "$FIRST_ARCHIVE_SHA" "$FIRST_TREE_SHA" "$FIRST_EXEC_SHA" "$TRANSACTION" "$PRODUCER_SHA256" "$CUSTODY_SHA256")"
printf 'SOURCE_SHA256|%s\n' "$OFFICIAL_SOURCE_SHA256"
printf 'ARCHIVE_SHA256|%s\n' "$FIRST_ARCHIVE_SHA"
printf 'TREE_SHA256|%s\n' "$FIRST_TREE_SHA"
printf 'EXECUTABLE_SHA256|%s\n' "$FIRST_EXEC_SHA"
printf 'BUILD_TRANSACTION|%s\n' "$TRANSACTION"
printf 'OUTPUT|%s\n' "$OUTPUT_PATH"
printf 'IDENTITY|byte-identical\n'
printf 'CANDIDATE_RECORD|%s\n' "$RECORD"
