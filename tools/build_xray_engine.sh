#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# M-1 remediation: rebuild the exact already-reviewed Xray-core source commit
# with a pinned, independently-verified-current Go toolchain, instead of
# trusting whatever Go version XTLS's own release CI happened to use when it
# built the upstream binary we used to just download
# (tools/prepare_android_xray_assets.sh, installer/windows/build_installer.ps1,
# tools/build_linux_release.sh all pinned the same v26.3.27 release, which
# embeds go1.26.1 -- see docs/RELEASE_ENGINE_BINARY_REFRESH.md for the CVEs
# that predates).
#
# Version policy: the M-1 fix itself only changed the Go toolchain. On
# 2026-10-06 the owner then directed that Xray follow the newest upstream tag
# (v26.9.30, which upstream flags GitHub pre-release); see
# docs/RELEASE_ENGINE_BINARY_REFRESH.md. The output hashes pinned by the
# callers (Windows/Android/Linux) must be refilled from a fresh build of the
# pinned commit before a release can pass its gates.
#
# The core build recipe below preserves XTLS/Xray-core's release flags at this
# commit (.github/workflows/release.yml). Pinned NDK r28 emits 16 KiB-aligned
# 64-bit Android images by default, but its 32-bit ARM linker still emitted
# 4 KiB LOAD segments in a measured build. That target receives explicit
# alignment flags. Every Android output is then verified before acceptance.
#
# Usage:
#   tools/build_xray_engine.sh <target> <output-path> [license-output-path]
#     target: linux-amd64 | linux-arm64 | windows-amd64 | windows-arm64 | android-arm64 | android-arm | android-amd64
#
# linux-arm64 is a first-class target: Xray-core is pure Go with CGO_ENABLED=0
# on Linux, so linux/arm64 needs only GOOS/GOARCH plus a pinned host Go SDK.
# The host archive hash for linux-arm64 was fetched from go.dev (mode=json
# include=all) and independently re-hashed from the downloaded tarball. The
# linux-arm64 *output* hash is pinned by tools/build_linux_release.sh after two
# clean byte-identical builds; this script verifies ELF shape and the reviewed
# Go runtime, not that output digest.
#
# Requires network access (clones Xray-core unless XRAY_SOURCE_DIR is set,
# and downloads the pinned Go toolchain unless WINS_WINN_GO_ARCHIVE names a
# local copy of the official archive) and, for the three Android targets, an
# installed Android NDK (set ANDROID_NDK_HOME/ANDROID_HOME, or rely on the
# usual SDK layout under ~/Library/Android/sdk, ~/Android/Sdk, or
# ~/.local/android-sdk).
#
# Go comes from one of two places, both bound to the pinned archive SHA-256:
#   - a caller-defined wins_release_go_run (the Linux producer defines a local
#     pinned-checksum wrapper), or
#   - the official go<version>.<os>-<arch>.tar.gz, read from
#     WINS_WINN_GO_ARCHIVE when set (offline) or else downloaded from go.dev,
#     verified against GO_HOST_SHA256_* below and extracted privately.

die() {
  printf 'BUILD XRAY ENGINE ERROR: %s\n' "$*" >&2
  exit 1
}

TARGET="${1:-}"
OUTPUT="${2:-}"
LICENSE_OUTPUT="${3:-}"
[[ -n "${TARGET}" && -n "${OUTPUT}" ]] \
  || die "Usage: $0 <linux-amd64|linux-arm64|windows-amd64|windows-arm64|android-arm64|android-arm|android-amd64> <output-path> [license-output-path]"
# Resolve to absolute paths up front: the build step below cds into a
# freshly cloned source tree, which would otherwise silently reinterpret a
# relative OUTPUT/LICENSE_OUTPUT relative to that temp directory instead of
# the caller's cwd.
case "${OUTPUT}" in
  /*) ;;
  *) OUTPUT="$(pwd -P)/${OUTPUT}" ;;
esac
if [[ -n "${LICENSE_OUTPUT}" ]]; then
  case "${LICENSE_OUTPUT}" in
    /*) ;;
    *) LICENSE_OUTPUT="$(pwd -P)/${LICENSE_OUTPUT}" ;;
  esac
fi

# Same already-reviewed upstream source every other Xray-acquiring script in
# this repo pins today (XRAY_VERSION="26.9.30" in tools/build_linux_release.sh
# and installer/windows/build_installer.ps1). The commit below was fetched
# directly from `git ls-remote --tags` / the GitHub tags API against
# https://github.com/XTLS/Xray-core, not copied from any report, and must
# keep resolving to tag v26.9.30 (verified again below).
XRAY_REPO="https://github.com/XTLS/Xray-core.git"
XRAY_TAG="v26.9.30"
XRAY_COMMIT="b26a91de4f3294e26a0ad0a970b81a386a41f789"
XRAY_IDENTITY_SHA256="6b501c995a8347b43b586e763cae272f9a02b13d065e3d14c2b2a5421544df10"
XRAY_LICENSE_SHA256="1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5"

# Bump all three together after independently re-verifying against
# https://go.dev/dl/?mode=json against the new release -- never trust a
# hash you did not fetch and check yourself.
REVIEWED_GO_VERSION="1.27.1"
GO_HOST_SHA256_DARWIN_ARM64="ee215d57e0ec269c60cc9ceca68e6bda321ba9ee5afe24f4b0988703c2d87d12"
GO_HOST_SHA256_DARWIN_AMD64="8f8f52c6649542cf027bbc9b9c68d1ec042f9f34808a40413f0b8b3f66f3caa4"
GO_HOST_SHA256_LINUX_AMD64="63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445"
GO_HOST_SHA256_LINUX_ARM64="3450b45a3f9ee8568792736a5c5e70a1f2e9b36c35a8f74958c03e51d7d92bec"

NDK_CLANG_API_LEVEL=24
REVIEWED_NDK_VERSION="30.0.16248370"
ANDROID_ELF_PAGE_SIZE=16384

resolve_host_go_archive() {
  local host_os host_arch
  case "$(uname -s)" in
    Darwin) host_os=darwin ;;
    Linux) host_os=linux ;;
    *) die "Unsupported build host OS: $(uname -s). This script builds ON macOS or Linux (any target)." ;;
  esac
  case "$(uname -m)" in
    arm64|aarch64) host_arch=arm64 ;;
    x86_64) host_arch=amd64 ;;
    *) die "Unsupported build host architecture: $(uname -m)" ;;
  esac
  case "${host_os}-${host_arch}" in
    darwin-arm64) printf 'darwin arm64 %s\n' "${GO_HOST_SHA256_DARWIN_ARM64}" ;;
    darwin-amd64) printf 'darwin amd64 %s\n' "${GO_HOST_SHA256_DARWIN_AMD64}" ;;
    linux-amd64) printf 'linux amd64 %s\n' "${GO_HOST_SHA256_LINUX_AMD64}" ;;
    linux-arm64) printf 'linux arm64 %s\n' "${GO_HOST_SHA256_LINUX_ARM64}" ;;
    *) die "No pinned Go host archive for ${host_os}-${host_arch}. Add and independently verify one." ;;
  esac
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

WORK_ROOT=""
cleanup() {
  if [[ -n "${WORK_ROOT}" ]]; then
    case "${WORK_ROOT}" in
      "${TMPDIR:-/tmp}"/wins-xray-engine-build.*)
        # Go module caches intentionally contain read-only source files.
        # Restore owner write permission only inside this mktemp-owned tree
        # before removing it, so successful builds do not report cleanup as a
        # producer failure or leave hundreds of megabytes behind.
        chmod -R u+w "${WORK_ROOT}" 2>/dev/null || true
        rm -rf -- "${WORK_ROOT}"
        ;;
      *)
        die "Refusing to remove an unsafe Xray engine build work root."
        ;;
    esac
  fi
}
trap cleanup EXIT

prepare_reviewed_go() {
  local host_os host_arch archive_sha archive go_bin snapshot
  if declare -F wins_release_go_run >/dev/null 2>&1; then
    if [[ -n "${LINUX_REVIEWED_GO_BIN:-}" && -x "${LINUX_REVIEWED_GO_BIN}" && ! -L "${LINUX_REVIEWED_GO_BIN}" ]]; then
      printf '%s\n' "${LINUX_REVIEWED_GO_BIN}"
      return 0
    fi
    printf '\n'
    return 0
  fi
  local local_archive="${WINS_WINN_GO_ARCHIVE:-}"
  if [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" && -z "${local_archive}" ]]; then
    die "declared Go SDK must be archive-bound before Xray build (set WINS_WINN_GO_ARCHIVE to the pinned Go archive)."
  fi
  read -r host_os host_arch archive_sha < <(resolve_host_go_archive)
  if [[ -n "${local_archive}" ]]; then
    [[ "${local_archive}" == /* && -f "${local_archive}" && ! -L "${local_archive}" ]] \
      || die "WINS_WINN_GO_ARCHIVE must be an absolute path to a regular file (the official go${REVIEWED_GO_VERSION}.${host_os}-${host_arch}.tar.gz)."
  else
    command -v curl >/dev/null 2>&1 || die "curl is required (or set WINS_WINN_GO_ARCHIVE to a local pinned Go archive)."
  fi
  command -v python3 >/dev/null 2>&1 || die "python3 is required to bind the Go archive."
  archive="${WORK_ROOT}/go-host.tar.gz"
  snapshot="${WORK_ROOT}/go-host.tar.gz.snap"
  python3 -I - "https://go.dev/dl/go${REVIEWED_GO_VERSION}.${host_os}-${host_arch}.tar.gz" \
    "${archive_sha}" "${archive}" "${snapshot}" "${WORK_ROOT}" "${local_archive}" <<'PY' \
    || die "Pinned Go host toolchain archive was refused."
import hashlib, os, stat, subprocess, sys, tarfile
url, expected, download, snapshot, dest, local_archive = sys.argv[1:7]
flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
snap_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
if os.path.exists(download) or os.path.lexists(download) or os.path.exists(snapshot) or os.path.lexists(snapshot):
    raise SystemExit("Go archive path already exists")
fd = os.open(download, flags, 0o600)
try:
    if local_archive:
        # Offline: copy the caller's archive into this private file. The same
        # pinned SHA-256 check below is the only thing that admits it.
        source_fd = os.open(local_archive, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(source_fd).st_mode):
                raise SystemExit("WINS_WINN_GO_ARCHIVE is not a regular file")
            while True:
                block = os.read(source_fd, 1024 * 1024)
                if not block:
                    break
                view = memoryview(block)
                while view:
                    view = view[os.write(fd, view):]
        finally:
            os.close(source_fd)
    else:
        subprocess.run(
            ["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--retry", "4", "--retry-all-errors", url],
            stdout=fd,
            stdin=subprocess.DEVNULL,
            check=True,
        )
    info = os.fstat(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    remaining = info.st_size
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            raise SystemExit("Go archive ended before its declared size")
        hasher.update(block)
        remaining -= len(block)
    if hasher.hexdigest() != expected:
        raise SystemExit("Pinned Go host toolchain SHA-256 verification failed.")
    os.lseek(fd, 0, os.SEEK_SET)
    snap_fd = os.open(snapshot, snap_flags, 0o400)
    try:
        remaining = info.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise SystemExit("Go archive ended while snapshotting")
            written = os.write(snap_fd, block)
            if written != len(block):
                raise SystemExit("Go archive snapshot write truncated")
            remaining -= len(block)
        os.fchmod(snap_fd, 0o400)
    finally:
        os.close(snap_fd)
finally:
    os.close(fd)
    try:
        os.unlink(download)
    except OSError:
        pass
before = os.lstat(snapshot)
if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
    raise SystemExit("Go archive snapshot must be a regular file")
snap_fd = os.open(snapshot, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW)
try:
    opened = os.fstat(snap_fd)
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        before.st_dev, before.st_ino, before.st_size
    ):
        raise SystemExit("Go archive snapshot changed while opened")
    handle = os.fdopen(snap_fd, "rb")
    snap_fd = -1
    with tarfile.open(fileobj=handle, mode="r:gz") as archive:
        if not hasattr(tarfile, "data_filter") or not callable(tarfile.data_filter):
            raise SystemExit("tar extraction requires an explicit data filter")
        for member in archive.getmembers():
            name = member.name.replace("\\", "/")
            parts = [part for part in name.split("/") if part]
            if name.startswith("/") or any(part == ".." for part in parts):
                raise SystemExit(f"Go archive member path is unsafe: {member.name}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise SystemExit(f"Go archive member type is unsafe: {member.name}")
            if member.linkname:
                raise SystemExit(f"Go archive link target is not allowed: {member.name}")
        try:
            archive.extractall(dest, filter="data")
        except (tarfile.TarError, OSError) as suc:
            sys.stderr.write(f"Go archive extraction failed: {suc}\n")
            raise SystemExit(65) from suc
    handle.close()
finally:
    if snap_fd >= 0:
        os.close(snap_fd)
PY
  go_bin="${WORK_ROOT}/go/bin/go"
  [[ -x "${go_bin}" && ! -L "${go_bin}" ]] || die "Go host toolchain archive did not produce an executable go binary."
  [[ "$("${go_bin}" version)" == "go version go${REVIEWED_GO_VERSION} ${host_os}/${host_arch}" ]] \
    || die "Reviewed Go host toolchain identity mismatch."
  printf '%s\n' "${go_bin}"
}

resolve_real_ndk_tool() {
  local candidate="$1" resolved
  [[ -f "${candidate}" && -x "${candidate}" && ! -L "${candidate}" ]] || return 1
  resolved="$(realpath -- "${candidate}" 2>/dev/null || true)"
  [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] || return 1
  printf '%s\n' "${resolved}"
}

resolve_ndk_home() {
  local ndk_home candidate props revision
  ndk_home="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  if [[ -z "${ndk_home}" ]]; then
    for candidate in \
      "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}/ndk"/* \
      "${HOME}/Library/Android/sdk/ndk"/* \
      "${HOME}/Android/Sdk/ndk"/* \
      "${HOME}/.local/android-sdk/ndk"/*
    do
      [[ -d "${candidate}" ]] && ndk_home="${candidate}"
    done
  fi
  [[ -n "${ndk_home}" && -d "${ndk_home}" ]] \
    || die "Android NDK not found. Set ANDROID_NDK_HOME, or install reviewed NDK ${REVIEWED_NDK_VERSION} under the standard SDK ndk/ directory."
  props="${ndk_home}/source.properties"
  [[ -f "${props}" ]] \
    || die "NDK source.properties is missing under ${ndk_home}; cannot verify its version."
  revision="$(sed -n 's/^Pkg\.Revision[[:space:]]*=[[:space:]]*//p' "${props}" | head -n 1)"
  [[ "${revision}" == "${REVIEWED_NDK_VERSION}" ]] \
    || die "Reviewed Android NDK is ${REVIEWED_NDK_VERSION}; found ${revision:-unknown} at ${ndk_home}."
  printf '%s\n' "${ndk_home}"
}

resolve_ndk_clang() {
  local goarch="$1" ndk_home candidate resolved prebuilt triple
  case "${goarch}" in
    arm64) triple="aarch64-linux-android" ;;
    arm) triple="armv7a-linux-androideabi" ;;
    amd64) triple="x86_64-linux-android" ;;
    *) die "Unsupported android goarch: ${goarch}" ;;
  esac
  ndk_home="$(resolve_ndk_home)"
  for prebuilt in darwin-x86_64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/${triple}${NDK_CLANG_API_LEVEL}-clang"
    resolved="$(resolve_real_ndk_tool "${candidate}" || true)"
    if [[ -n "${resolved}" ]]; then
      printf '%s\n' "${resolved}"
      return 0
    fi
  done
  die "No ${triple}${NDK_CLANG_API_LEVEL}-clang found under ${ndk_home}/toolchains/llvm/prebuilt/{darwin,linux}-x86_64/bin."
}

verify_android_elf() {
  local path="$1" goarch="$2" build_marker="$3"
  command -v python3 >/dev/null 2>&1 || die "python3 is required to verify Android ELF output."
  python3 "${SCRIPT_DIR}/verify_android_xray_binary.py" "${path}" \
    --goarch "${goarch}" \
    --go-version "${REVIEWED_GO_VERSION}" \
    --build-marker "${build_marker}" \
    --page-size "${ANDROID_ELF_PAGE_SIZE}"
}

main() {
  WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wins-xray-engine-build.XXXXXX")"
  chmod 700 "${WORK_ROOT}"

  local go_bin goos goarch cc="" android_target=0 use_release_go=0
  if declare -F wins_release_go_run >/dev/null 2>&1; then
    use_release_go=1
  fi
  go_bin="$(prepare_reviewed_go)"

  case "${TARGET}" in
    linux-amd64) goos=linux; goarch=amd64 ;;
    linux-arm64) goos=linux; goarch=arm64 ;;
    windows-amd64) goos=windows; goarch=amd64 ;;
    windows-arm64) goos=windows; goarch=arm64 ;;
    android-arm64) goos=android; goarch=arm64; android_target=1; cc="$(resolve_ndk_clang arm64)" ;;
    android-arm) goos=android; goarch=arm; android_target=1; cc="$(resolve_ndk_clang arm)" ;;
    android-amd64) goos=android; goarch=amd64; android_target=1; cc="$(resolve_ndk_clang amd64)" ;;
    *) die "Unknown target '${TARGET}'. Expected linux-amd64, linux-arm64, windows-amd64, windows-arm64, android-arm64, android-arm, or android-amd64." ;;
  esac

  local src commid identity
  if [[ -n "${XRAY_SOURCE_DIR:-}" ]]; then
    src="${XRAY_SOURCE_DIR}"
    [[ -d "${src}" && ! -L "${src}" ]] || die "XRAY_SOURCE_DIR must be a regular directory."
    identity="${src}/.winsvpn-xray-identity"
    [[ -f "${src}/LICENSE" && ! -L "${src}/LICENSE" ]] \
      || die "Xray LICENSE is required."
    [[ "$(sha256_file "${src}/LICENSE")" == "${XRAY_LICENSE_SHA256}" ]] \
      || die "Xray LICENSE is not the authenticated source."
    if [[ -n "${WINS_ENGINE_SOURCE_ROOT:-}" || -n "${XRAY_SOURCE_TREE_SHA256:-}" ]]; then
      [[ "${XRAY_SOURCE_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] \
        || die "XRAY_SOURCE_TREE_SHA256 must bind the complete Xray source tree."
      python3 -I - "${SCRIPT_DIR}/../linux/packaging/store_engine_bind.py" "${src}" "${XRAY_SOURCE_TREE_SHA256}" <<'PY'
import importlib.util
import pathlib
import sys

origin = pathlib.Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("_winsvpn_xray_tree_bind", origin)
if spec is None or spec.loader is None:
    sys.stderr.write("unable to load store engine binder\n")
    raise SystemExit(65)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    digest = module.hash_regular_tree(pathlib.Path(sys.argv[2]), "Xray source")
except module.StoreEngineBindError as suc:
    sys.stderr.write(f"Xray source tree bind failed: {suc}\n")
    raise SystemExit(65) from suc
if digest != sys.argv[3]:
    sys.stderr.write("Xray source tree does not match the authenticated identity\n")
    raise SystemExit(65)
PY
    fi
    if [[ -f "${identity}" && ! -L "${identity}" ]]; then
      [[ "$(sha256_file "${identity}")" == "${XRAY_IDENTITY_SHA256}" ]] \
        || die "Xray identity file SHA-256 does not bind commit ${XRAY_COMMIT} and tag ${XRAY_TAG}."
      grep -qx "commit=${XRAY_COMMIT}" "${identity}" \
        || die "Xray identity file does not bind commit ${XRAY_COMMIT}."
      grep -qx "tag=${XRAY_TAG}" "${identity}" \
        || die "Xray identity file does not bind tag ${XRAY_TAG}."
      commid="${XRAY_BUILD_COMMID:-${XRAY_TAG}}"
    else
      command -v git >/dev/null 2>&1 || die "git is required."
      [[ -d "${src}/.git" && ! -L "${src}/.git" ]] \
        || die "declared Xray source must retain git identity or a commit/tag identity file."
      [[ "$(git -C "${src}" rev-parse HEAD)" == "${XRAY_COMMIT}" ]] \
        || die "Xray-core checkout did not land on the pinned commit."
      git -C "${src}" tag --points-at HEAD | grep -qx "${XRAY_TAG}" \
        || die "Pinned commit ${XRAY_COMMIT} no longer carries tag ${XRAY_TAG}; upstream history changed underneath us."
      commid="$(git -C "${src}" describe --always --dirty)"
    fi
  else
    command -v git >/dev/null 2>&1 || die "git is required."
    src="${WORK_ROOT}/Xray-core"
    git clone --quiet "${XRAY_REPO}" "${src}"
    git -C "${src}" checkout --quiet "${XRAY_COMMIT}"
    [[ "$(git -C "${src}" rev-parse HEAD)" == "${XRAY_COMMIT}" ]] \
      || die "Xray-core checkout did not land on the pinned commit."
    # Upstream tags this same commit twice: the CalVer release tag (v26.9.30)
    # and an auto-generated Go-module-compatible SemVer mirror (v1.260327.0,
    # per XTLS/libXray's release-go-mirror.yml). `git describe --exact-match`
    # only ever returns one of several tags on the same commit, so check
    # membership instead of a single expected string.
    git -C "${src}" tag --points-at HEAD | grep -qx "${XRAY_TAG}" \
      || die "Pinned commit ${XRAY_COMMIT} no longer carries tag ${XRAY_TAG}; upstream history changed underneath us."
    commid="$(git -C "${src}" describe --always --dirty)"
  fi

  mkdir -p "$(dirname "${OUTPUT}")"
  (
    cd "${src}"
    local go_dir go_root
    if [[ -n "${go_bin}" ]]; then
      go_dir="$(dirname "${go_bin}")"
      go_root="$(cd -- "${go_dir}/.." && pwd -P)"
      export GOROOT="${go_root}"
      export PATH="${go_dir}:${PATH}"
    else
      unset GOROOT
    fi
    export GOENV=off
    export GOTOOLCHAIN=local
    export GOFLAGS=-mod=readonly
    if [[ -n "${WINS_STORE_GOMODCACHE:-}" ]]; then
      [[ -d "${WINS_STORE_GOMODCACHE}" && ! -L "${WINS_STORE_GOMODCACHE}" ]] \
        || die "WINS_STORE_GOMODCACHE must be a regular directory."
      if [[ "${WINS_STORE_GOMODCACHE}" == "${HOME}/go/pkg/mod" ]]; then
        die "refusing dirty host Go module cache"
      fi
      export GOMODCACHE="${WINS_STORE_GOMODCACHE}"
      export GOPROXY=off
      export GOSUMDB=off
    else
      export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"
      export GOSUMDB="${GOSUMDB:-sum.golang.org}"
      export GOMODCACHE="${WORK_ROOT}/go-mod-cache"
    fi
    export GOPRIVATE="" GONOPROXY="" GONOSUMDB=""
    if [[ -n "${WINS_STORE_GOCACHE:-}" ]]; then
      [[ -d "${WINS_STORE_GOCACHE}" && ! -L "${WINS_STORE_GOCACHE}" ]] \
        || die "WINS_STORE_GOCACHE must be a regular directory."
      host_gocache_darwin="${HOME}/Library/Caches/go-build"
      host_gocache_linux="${HOME}/.cache/go-build"
      if [[ "${WINS_STORE_GOCACHE}" == "${host_gocache_darwin}" || "${WINS_STORE_GOCACHE}" == "${host_gocache_linux}" ]]; then
        die "refusing host Go build cache"
      fi
      export GOCACHE="${WINS_STORE_GOCACHE}"
    else
      export GOCACHE="${WORK_ROOT}/go-build-cache"
    fi
    export GOOS="${goos}" GOARCH="${goarch}"
    if [[ "${goarch}" == "arm" ]]; then
      export GOARM=7
    fi
    if [[ -n "${cc}" ]]; then
      export CGO_ENABLED=1 CC="${cc}"
    else
      export CGO_ENABLED=0
    fi
    local ldflags
    ldflags="-X github.com/xtls/xray-core/core.build=${commid} -s -w -buildid="
    if [[ "${android_target}" == "1" ]]; then
      # Upstream's own Android recipe at v26.9.30 (.github/workflows/release.yml,
      # "Building Xray for Android...") links with -checklinkname=0 because
      # github.com/wlynxg/anet v0.0.5 reaches net.zoneCache by go:linkname,
      # which Go 1.23 and later refuse at link time ("invalid reference to
      # net.zoneCache"). Measured failing without it on go1.27.1 on 2026-10-07.
      ldflags+=" -checklinkname=0"
    fi
    if [[ "${android_target}" == "1" && "${goarch}" == "arm" ]]; then
      ldflags+=" -extldflags=-Wl,-z,max-page-size=${ANDROID_ELF_PAGE_SIZE},-z,common-page-size=${ANDROID_ELF_PAGE_SIZE}"
    fi
    if [[ "${use_release_go}" == "1" ]]; then
      wins_release_go_run build -o "${OUTPUT}" -trimpath -buildvcs=false -gcflags="all=-l=4" \
        -ldflags="${ldflags}" -v ./main
    else
      "${go_bin}" build -o "${OUTPUT}" -trimpath -buildvcs=false -gcflags="all=-l=4" \
        -ldflags="${ldflags}" -v ./main
    fi
  )

  if [[ -n "${LICENSE_OUTPUT}" ]]; then
    [[ -f "${src}/LICENSE" ]] || die "Xray-core checkout is missing its LICENSE file."
    mkdir -p "$(dirname "${LICENSE_OUTPUT}")"
    cp "${src}/LICENSE" "${LICENSE_OUTPUT}"
  fi

  [[ -f "${OUTPUT}" ]] || die "Build did not produce ${OUTPUT}."
  if [[ "${android_target}" == "1" ]]; then
    verify_android_elf "${OUTPUT}" "${goarch}" "${commid}"
  fi
  local version_check
  if [[ "${use_release_go}" == "1" ]]; then
    version_check="$(wins_release_go_run version -m "${OUTPUT}" 2>/dev/null | head -1 || true)"
  else
    version_check="$("${go_bin}" version -m "${OUTPUT}" 2>/dev/null | head -1 || true)"
  fi
  case "${version_check}" in
    *"go${REVIEWED_GO_VERSION}"*) ;;
    *) die "Built ${OUTPUT} but it does not report go${REVIEWED_GO_VERSION}: ${version_check}" ;;
  esac
  if [[ "${goos}" == "linux" && "${goarch}" == "arm64" ]]; then
    python3 "${SCRIPT_DIR}/test_linux_arm64_fallback_elf.py" verify xray "${OUTPUT}" --shape-only \
      || die "linux-arm64 Xray failed ELF/runtime shape verification."
  fi
  if [[ "${goos}" == "windows" ]]; then
    command -v python3 >/dev/null 2>&1 || die "python3 is required to verify Windows PE output."
    python3 - "${OUTPUT}" "${goarch}" <<'PY'
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
expected = {"amd64": 0x8664, "arm64": 0xAA64}[sys.argv[2]]
data = path.read_bytes()
if len(data) < 64 or data[:2] != b"MZ":
    raise SystemExit(f"{path} is not a DOS/PE image")
pe = struct.unpack_from("<I", data, 0x3C)[0]
if pe + 26 > len(data) or data[pe:pe + 4] != b"PE\0\0":
    raise SystemExit(f"{path} has an invalid PE header")
machine = struct.unpack_from("<H", data, pe + 4)[0]
magic = struct.unpack_from("<H", data, pe + 24)[0]
if machine != expected or magic != 0x20B:
    raise SystemExit(
        f"{path} has PE machine 0x{machine:04x}/magic 0x{magic:04x}; "
        f"expected PE32+ {sys.argv[2]}"
    )
PY
  fi

  printf 'Built %s\n' "${OUTPUT}"
  printf '  xray tag:    %s (%s)\n' "${XRAY_TAG}" "${XRAY_COMMIT}"
  printf '  go version:  %s\n' "${version_check}"
  printf '  sha256:      %s\n' "$(sha256_file "${OUTPUT}")"
}

main "$@"
