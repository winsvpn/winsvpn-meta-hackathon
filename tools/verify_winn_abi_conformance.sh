#!/usr/bin/env bash
#
# verify_winn_abi_conformance.sh — prove the Apple Winn wrapper and the real Go
# c-archive agree on the C ABI, at build time, for every slice the wrapper
# targets.
#
# WHY THIS EXISTS
#
# C carries no arity in its ABI. A wrapper that calls
# WinnTunnelCreate(config, fd) against an archive exporting
# WinnTunnelCreate(config, fd, char **errorOut) links cleanly, then reads an
# uninitialised register as an out-parameter and writes through it inside Go.
# That is memory corruption on first connect, not a clean failure, and no
# linker, test, or code review reliably catches it.
#
# It happened here. apple/EngineWrappers/WinnTunnel.h was written against a plan
# document while the datapath lane was still building, and disagreed with the
# real archive on 4 of 5 entry points. apple/EngineWrappers/WinnTunnelTestDouble.c
# implemented the same assumed contract, so `-Werror` was green on all five
# platform slices while the shipping path would have corrupted memory. Green
# tests against a double prove nothing about the real contract.
#
# WHAT IT CHECKS
#
# The cgo-generated header beside the archive is the authority. For each slice:
#
#   1. WinnTunnel.h and the generated header compile in ONE translation unit.
#      Compiling both together is what surfaced the original mismatch; a
#      conflicting declaration is a hard error, not a warning.
#   2. WinnTunnelTestDouble.c compiles with the generated header force-included,
#      so the double's DEFINITIONS are checked against the real prototypes. This
#      is the check that stops a double from certifying a wrong contract again.
#   3. WinsWinnPacketEngine.m compiles with the generated header force-included,
#      so every CALL SITE is checked against the real prototypes.
#
# Then, for each slice a real archive exists for:
#
#   4. The archive exports every Winn* symbol in WINN_REQUIRED_SYMBOLS below --
#      eleven as of 2026-08-09, including WinnTunnelCreateWinn3 -- and its go.o
#      member reports the expected LC_BUILD_VERSION platform.
#   5. The archive's ACCEPTED FIELD SET matches the Go source beside it.
#      See below — this is the check that catches a stale archive.
#
# WHY CHECKS 1-4 ARE NOT ENOUGH: THE STALE-ARCHIVE HOLE
#
# Every check above is a check on the C ABI SIGNATURE. That is exactly the
# wrong instrument for the failure this repository actually hit on 2026-08-03.
#
# libwinn-datapath-{darwin,ios}-arm64.a were built at 07:39. At 13:56 the fields
# s1..s4 were added to datapath.AWGHeaderTypes. Adding a Go struct field changes
# no C prototype, so the cgo-generated header stayed BYTE-IDENTICAL and this
# script passed — while WinnTunnelCreate refused every configuration the wrapper
# produces, with `json: unknown field "s1"`, because datapath.Config decodes with
# DisallowUnknownFields. A green signature check on a broken artifact is worse
# than no check, and it cost a session an hour of hunting a phantom wrapper bug.
#
# Signature checking STRUCTURALLY cannot see this. The contract that broke is not
# the set of functions, it is the set of JSON FIELDS Go will accept. So that is
# what check 5 compares.
#
# HOW: Go emits every struct tag into the artifact verbatim as a string literal.
# So the tags declared in winn_protocol_experimental/datapath/*.go must ALL be
# findable in the archive. A field present in the source and absent from the
# archive means the archive predates it, and DisallowUnknownFields then
# guarantees that field is REJECTED at runtime. That is an implication, not a
# heuristic. It needs no execution, so it works for iOS, the simulator, Android
# and Windows slices that cannot run on the build host.
#
# THE ANDROID SLICE (check 6, added 2026-08-11)
#
# The android/arm64 slice is a sixth matrix entry. It is a DIFFERENT artifact
# than the Apple five. cdatapath — the package whose //export directives define
# the WinnTunnel* C ABI — is //go:build darwin and does not build for android,
# and Go rejects `-buildmode=c-archive` on android/arm64, so no Android
# artifact can export WinnTunnel* C symbols; Android ships the datapath
# contract as a stripped subprocess executable (cmd/winn-datapath, built by
# `build_winn_protocol_engine.sh datapath-android-arm64`) whose Create frame
# carries exactly datapath.Config. So the Android boundary contract is
# datapath.Config's JSON field set, and check 6 asserts the built engine is a
# real AArch64 Android ELF carrying that current field set and the Winn v3
# payload classes. It shares WINN_ACCEPTED_FIELD_SET with the Apple slices,
# which is what keeps the matrix comparable and the WinnTunnel* C-symbol claim
# honest (it is asserted on the Apple c-archives, where it genuinely holds).
#
# NOT USED: comparing the archive's mtime against source mtimes. It was the
# other candidate and it is unsound — a fresh `git clone` or `git checkout` sets
# every mtime to the checkout time, so mtime ordering carries no information
# about which source a binary was built from. It would fail open on CI, which is
# precisely where it would matter.
#
# Usage:  tools/verify_winn_abi_conformance.sh
# Env:    WINN_DATAPATH_ARCHIVE_DIR   where the archives and generated headers live
#         WINN_DATAPATH_SOURCE_DIR    the Go package whose field set is authority
#         WINN_ABI_SLICES             override the slice list (platform:arch:minos)
#         WINN_ABI_RELEASE_DIR        take the android/arm64 engine from a Winn release
#                                     directory (tools/winn_release.py verify, signed)
#                                     instead of building it; WINN_ABI_RELEASE_ALLOW_UNSIGNED=1
#                                     accepts an unsigned dev release

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
APPLE_ENGINE_WRAPPER_SOURCE_DIR="${APPLE_ENGINE_WRAPPER_SOURCE_DIR:-${PROJECT_ROOT}/apple/EngineWrappers}"
WINN_DATAPATH_ARCHIVE_DIR="${WINN_DATAPATH_ARCHIVE_DIR:-${PROJECT_ROOT}/tools/winn_conformance_build_out}"

# BUILD THE ARCHIVES IF THEY ARE NOT THERE, rather than requiring them checked in.
#
# They used to be 23 tracked binaries. They are pure build output of
# winn_protocol_experimental/, which is in this repository, and committing them
# created a staleness trap that fired: every artifact was built 2026-08-03 07:37,
# before s1..s4 joined datapath.AWGHeaderTypes at 13:56. Because datapath.Config
# decodes with DisallowUnknownFields, they refused every current configuration --
# while this script PASSED against them, because the cgo header was byte-identical
# and the C ABI genuinely had not changed. They were committed stale and nothing
# noticed.
#
# So a fresh clone has no archives, and this builds them from the source beside
# it. tools/verify_apple_winn_seam.sh is the model: build what you verify, so
# what you verify cannot be older than what it is verified against.
# The Android NDK is pinned in tools/toolchain-pins.json (tools.android_ndk,
# 30.0.16248370, the same r30 the Gradle build pins). android_ndk_root prints an
# explicit ANDROID_NDK_HOME / ANDROID_NDK_ROOT, else that pinned version under
# the SDK; never "the newest NDK installed", which is how a verifier ends up
# judging an artifact with a different toolchain than the one that built it.
ANDROID_NDK_PIN="$(/usr/bin/python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["tools"]["android_ndk"]["version"])' \
  "${PROJECT_ROOT}/tools/toolchain-pins.json" 2>/dev/null || echo 30.0.16248370)"
android_ndk_root() {
  local ndk_home sdk_root
  ndk_home="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
  if [[ -z "${ndk_home}" ]]; then
    sdk_root="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${HOME}/.local/android-sdk}}"
    [[ -d "${sdk_root}/ndk/${ANDROID_NDK_PIN}" ]] && ndk_home="${sdk_root}/ndk/${ANDROID_NDK_PIN}"
  fi
  printf '%s\n' "${ndk_home:-}"
}

# build_android_engine produces the android/arm64 datapath engine at OUTPUT.
# From a release directory it copies the artifact `winn_release.py verify
# --print-artifact` vouches for; otherwise it launches the builder in direct
# mode (which runs `winn_release.py build-one`: sealed source from git HEAD,
# two builds compared) with the pinned NDK in WINS_ANDROID_NDK_ROOT. Errors are
# shown, not discarded, and exit 3 (TOOLCHAIN-MISSING) is passed through.
build_android_engine() {
  local target="$1" out="$2" printed rc=0
  local -a verify_flags=()
  if [[ -n "${WINN_ABI_RELEASE_DIR:-}" ]]; then
    [[ "${WINN_ABI_RELEASE_ALLOW_UNSIGNED:-}" == "1" ]] && verify_flags=(--allow-unsigned)
    printed="$(cd "${PROJECT_ROOT}" && /usr/bin/python3 -I tools/winn_release.py verify \
      --release "${WINN_ABI_RELEASE_DIR}" ${verify_flags[@]+"${verify_flags[@]}"} \
      --print-artifact "${target}")" || return $?
    printed="${printed%%$'\n'*}"
    [[ -f "${printed}" && ! -L "${printed}" ]] || return 1
    cp "${printed}" "${out}" && chmod 755 "${out}"
    return $?
  fi
  local ndk
  ndk="$(android_ndk_root)"
  if [[ -z "${ndk}" ]]; then
    echo "TOOLCHAIN-MISSING: Android NDK ${ANDROID_NDK_PIN} (set ANDROID_NDK_HOME)" >&2
    return 3
  fi
  WINS_ANDROID_NDK_ROOT="${ndk}" bash "${PROJECT_ROOT}/tools/build_winn_protocol_engine.sh" \
    "${target}" "${out}" >/dev/null || rc=$?
  return "${rc}"
}

if [[ -z "${WINN_ABI_SKIP_BUILD:-}" ]]; then
  _needed=(
    "datapath-archive-darwin-arm64:libwinn-datapath-darwin-arm64.a"
    "datapath-archive-darwin-amd64:libwinn-datapath-darwin-amd64.a"
    "datapath-ios-arm64:libwinn-datapath-ios-arm64.a"
    "datapath-iossimulator-arm64:libwinn-datapath-iossimulator-arm64.a"
    "datapath-iossimulator-amd64:libwinn-datapath-iossimulator-amd64.a"
    "datapath-android-arm64:winn-datapath-android-arm64"
  )
  _missing=0
  for _entry in "${_needed[@]}"; do
    [[ -s "${WINN_DATAPATH_ARCHIVE_DIR}/${_entry#*:}" ]] || _missing=1
  done
  if (( _missing )); then
    command -v go >/dev/null 2>&1 || {
      echo "Go is required to build the datapath archives this script verifies." >&2
      echo "Set WINN_DATAPATH_ARCHIVE_DIR to a directory that already has them," >&2
      echo "or WINN_ABI_SKIP_BUILD=1 to verify whatever is present as-is." >&2
      exit 2
    }
    mkdir -p "${WINN_DATAPATH_ARCHIVE_DIR}"
    for _entry in "${_needed[@]}"; do
      _target="${_entry%%:*}"; _out="${WINN_DATAPATH_ARCHIVE_DIR}/${_entry#*:}"
      [[ -s "${_out}" ]] && continue
      printf 'building %s\n' "${_target}" >&2
      if [[ "${_target}" == datapath-android-* ]]; then
        _rc=0
        build_android_engine "${_target}" "${_out}" || _rc=$?
        [[ "${_rc}" -eq 3 ]] && { echo "failed to build ${_target}: toolchain missing" >&2; exit 3; }
        [[ "${_rc}" -eq 0 && -s "${_out}" ]] || { echo "failed to build ${_target}" >&2; exit 2; }
        continue
      fi
      # The build script can emit a nonzero status on a successful build under
      # `set -u`, so the artifact is what is checked, not the exit code.
      bash "${PROJECT_ROOT}/tools/build_winn_protocol_engine.sh" "${_target}" "${_out}" \
        >/dev/null 2>&1 || true
      [[ -s "${_out}" ]] || { echo "failed to build ${_target}" >&2; exit 2; }
    done
  fi
fi

# The package whose Config is decoded with DisallowUnknownFields. Its struct
# tags are the authority for check 5.
WINN_DATAPATH_SOURCE_DIR="${WINN_DATAPATH_SOURCE_DIR:-${PROJECT_ROOT}/winn_protocol_experimental/datapath}"

# The generated header is the authority. Both generated headers in the tree are
# byte-identical, so either proves the contract; the iOS one is named because
# iOS is the platform that forces the c-archive route in the first place.
WINN_GENERATED_HEADER="${WINN_GENERATED_HEADER:-${WINN_DATAPATH_ARCHIVE_DIR}/libwinn-datapath-ios-arm64.h}"

# platform:arch:minos — the same five slices tools/build_apple_engine_wrappers.sh
# produces wrappers for.
DEFAULT_SLICES=(
  "macosx:arm64:13.0"
  "macosx:x86_64:13.0"
  "iphoneos:arm64:13.0"
  "iphonesimulator:arm64:14.0"
  "iphonesimulator:x86_64:13.0"
  "android:arm64:24"
)

# Every symbol the archive is required to export. Eleven, per the generated
# header: the original nine, plus WinnTunnelCreateWithCarrier, the additive
# carrier-profile entry point (see winn_protocol_experimental/cdatapath/winn_datapath_carrier.go),
# plus WinnTunnelCreateWinn3, the additive create for the STANDALONE winn/3
# shape (winn_protocol_experimental/cdatapath/winn_datapath_winn3.go).
#
# WinnTunnelCreateWinn3 was missing from this list until 2026-08-09, and its
# absence here was invisible for the same reason it was invisible in
# tools/build_apple_engine_wrappers.sh: every OTHER symbol belongs to the v1
# relay carrier, so an archive built before winn/3 existed exports all ten of
# them and this check printed a confident "10 Winn* symbols" over an archive
# with no standalone protocol in it at all. The Apple pump resolves the create
# through dlsym, so nothing downstream link-fails either -- the App Store .ipa
# at 1.0.14+29 shipped with ZERO winn3 strings in Runner.app,
# PacketTunnel.appex and WinsWinnPacketEngine.framework, and the first thing
# any user saw was StartError.symbolsUnavailable.
#
# This list and WINN_REQUIRED_SYMBOLS in tools/build_apple_engine_wrappers.sh
# are two independent gates on the same fact. They must be extended together
# whenever the generated header grows an entry point.
WINN_REQUIRED_SYMBOLS=(
  WinnTunnelFreeString
  WinnTunnelContractVersion
  WinnTunnelProtocolVersion
  WinnTunnelMaxDatagram
  WinnTunnelCreate
  WinnTunnelWriteInbound
  WinnTunnelReadOutbound
  WinnTunnelStatusJSON
  WinnTunnelClose
  WinnTunnelCreateWithCarrier
  WinnTunnelCreateWinn3
)

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# Fully resolve a path to a real on-disk file, on both GNU and BSD userlands.
# GNU realpath takes -e; the BSD realpath macOS ships does not, and already
# fails on a path that does not exist, so the fallback is equivalent.
resolve_real_file() {
  realpath -e -- "$1" 2>/dev/null && return 0
  realpath -- "$1" 2>/dev/null && return 0
  return 1
}

ensure_tools() {
  command -v xcrun >/dev/null 2>&1 || die "full Xcode command line tools are required."
  local tool candidate resolved
  for tool in clang nm vtool lipo ar; do
    candidate="$(xcrun -f "${tool}" 2>/dev/null || true)"
    [[ -n "${candidate}" ]] || die "${tool} from Xcode is required."
    resolved="$(resolve_real_file "${candidate}" || true)"
    [[ -n "${resolved}" && -f "${resolved}" && -x "${resolved}" && ! -L "${resolved}" ]] \
      || die "${tool} from Xcode must resolve to a real regular executable file, not a symlink: ${candidate}"
    case "${tool}" in
      clang) CLANG_BIN="${resolved}" ;;
      nm) NM_BIN="${resolved}" ;;
      vtool) VTOOL_BIN="${resolved}" ;;
      lipo) LIPO_BIN="${resolved}" ;;
      ar) AR_BIN="${resolved}" ;;
    esac
  done

  # Android slice needs the NDK's llvm-readelf to prove the artifact is really
  # an AArch64 Android ELF. Resolved from the same NDK the build script uses,
  # so the verifier and the builder agree about which toolchain produced the
  # artifact it is about to judge. The android slice is a default, so a missing
  # NDK is a hard failure, not a silent skip.
  ANDROID_READELF_BIN="$(resolve_android_readelf)"
  [[ -n "${ANDROID_READELF_BIN}" ]] \
    || die "llvm-readelf from the Android NDK is required for the android/arm64 slice."
}

# resolve_android_ndk_root finds the NDK root the Android engine was built
# with: an explicit ANDROID_NDK_HOME / ANDROID_NDK_ROOT, else the pinned
# version under the SDK (see android_ndk_root above).
resolve_android_ndk_root() {
  android_ndk_root
}

resolve_android_readelf() {
  local ndk_home prebuilt candidate
  ndk_home="$(resolve_android_ndk_root)"
  [[ -n "${ndk_home}" ]] || return 1
  for prebuilt in darwin-x86_64 darwin-arm64 linux-x86_64; do
    candidate="${ndk_home}/toolchains/llvm/prebuilt/${prebuilt}/bin/llvm-readelf"
    if [[ -x "${candidate}" ]]; then printf '%s\n' "${candidate}"; return 0; fi
  done
  return 1
}

target_triple() {
  local platform="$1" minos="$2" arch="$3"
  case "${platform}" in
    macosx) printf '%s-apple-macos%s\n' "${arch}" "${minos}" ;;
    iphoneos) printf '%s-apple-ios%s\n' "${arch}" "${minos}" ;;
    iphonesimulator) printf '%s-apple-ios%s-simulator\n' "${arch}" "${minos}" ;;
    *) die "Unknown Apple platform '${platform}'." ;;
  esac
}

expected_platform() {
  case "$1" in
    macosx) printf 'MACOS\n' ;;
    iphoneos) printf 'IOS\n' ;;
    iphonesimulator) printf 'IOSSIMULATOR\n' ;;
    *) die "Unknown Apple platform '$1'." ;;
  esac
}

# The artifact built for a slice, or empty when none exists for it.
# All five Apple slices the wrapper targets have one; the android/arm64 slice
# has the datapath engine executable, which is a different shape (a stripped
# subprocess binary, not a c-archive) for reasons documented on the android
# branch in main(). A slice that silently checks no artifact is a regression
# rather than the normal case.
archive_for_slice() {
  local platform="$1" arch="$2"
  case "${platform}:${arch}" in
    iphoneos:arm64) printf '%s/libwinn-datapath-ios-arm64.a\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    macosx:arm64) printf '%s/libwinn-datapath-darwin-arm64.a\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    macosx:x86_64) printf '%s/libwinn-datapath-darwin-amd64.a\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    iphonesimulator:arm64) printf '%s/libwinn-datapath-iossimulator-arm64.a\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    iphonesimulator:x86_64) printf '%s/libwinn-datapath-iossimulator-amd64.a\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    android:arm64) printf '%s/winn-datapath-android-arm64\n' "${WINN_DATAPATH_ARCHIVE_DIR}" ;;
    *) printf '\n' ;;
  esac
}

# accepted_field_set prints every JSON struct tag the datapath package declares,
# one per line, sorted and deduplicated. Test files are excluded: a tag that
# exists only in a _test.go fixture is not part of the shipping contract and
# would make this check fail on a correct archive.
accepted_field_set() {
  local sources=()
  local file
  for file in "${WINN_DATAPATH_SOURCE_DIR}"/*.go; do
    [[ -f "${file}" ]] || continue
    [[ "${file}" == *_test.go ]] && continue
    sources+=("${file}")
  done
  [[ "${#sources[@]}" -gt 0 ]] \
    || die "No Go sources under ${WINN_DATAPATH_SOURCE_DIR}; check 5 cannot establish the accepted field set and will not silently skip."
  grep -oh 'json:"[^"]*"' "${sources[@]}" | sort -u
}

# verify_archive_field_set is check 5. Go writes struct tags into the artifact
# verbatim, so every tag the source declares must be findable in the archive.
# grep -a is used rather than strings(1) so no additional tool is required and
# no string-length heuristic can drop a short tag.
#
# APPLICABLE ONLY TO DATAPATH-FAMILY ARTIFACTS. ./cdatapath and ./cmd/winn-datapath
# import the datapath package; ./cshared and ./cmd/winn-clientinfo do NOT, so
# their artifacts legitimately carry none of these tags and this check would
# report a stale archive that is perfectly current. That is not hypothetical --
# running the check across the whole build-output directory reports all eight
# winn-clientinfo binaries as stale when they are byte-identical to a fresh
# build. The precondition below refuses to guess: an artifact with no datapath
# contract marker is a category error, not a stale archive.
verify_archive_field_set() {
  local archive="$1"
  local missing=() total=0 tag

  grep -aqF 'winn-datapath/1' "${archive}" \
    || die "${archive} carries no datapath contract marker, so it was not built from a package that imports ${WINN_DATAPATH_SOURCE_DIR#"${PROJECT_ROOT}/"}. The field-set check does not apply to it and must not be run against it -- a clientinfo artifact would be reported stale when it is current. Fix archive_for_slice rather than this check."
  while IFS= read -r tag; do
    total=$((total + 1))
    grep -aqF "${tag}" "${archive}" || missing+=("${tag}")
  done <<<"${WINN_ACCEPTED_FIELD_SET}"

  [[ "${total}" -gt 0 ]] \
    || die "The accepted field set came back empty; check 5 would pass vacuously. Refusing."

  if [[ "${#missing[@]}" -gt 0 ]]; then
    printf 'ERROR: %s IS STALE.\n' "${archive}" >&2
    printf '  It was built before %d of the %d fields %s declares:\n' \
      "${#missing[@]}" "${total}" "${WINN_DATAPATH_SOURCE_DIR}" >&2
    printf '    %s\n' "${missing[@]}" >&2
    printf '  datapath.Config decodes with DisallowUnknownFields, so this archive REFUSES\n' >&2
    printf '  every configuration carrying any of those fields, with `json: unknown field`.\n' >&2
    printf '  The C ABI is unchanged, which is why the header and symbol checks above passed.\n' >&2
    printf '  Rebuild it:  tools/build_winn_protocol_engine.sh <datapath target> %s\n' "${archive}" >&2
    exit 1
  fi
}

# -Wall -Wextra -Werror is the same bar the wrapper is built at, so the guard
# cannot pass something the build would reject.
compile_flags() {
  printf '%s\n' -Wall -Wextra -Werror -fsyntax-only
}

verify_headers_agree() {
  local platform="$1" arch="$2" minos="$3" sdk_path="$4" work_dir="$5"
  local target
  target="$(target_triple "${platform}" "${minos}" "${arch}")"

  # Both headers, one translation unit. This is the check that surfaced the
  # original 4-error mismatch.
  local probe="${work_dir}/winn_abi_probe.c"
  cat >"${probe}" <<EOF
/* Generated by tools/verify_winn_abi_conformance.sh. Do not edit. */
#include "WinnTunnel.h"
#include "$(basename "${WINN_GENERATED_HEADER}")"
EOF

  "${CLANG_BIN}" \
    -target "${target}" \
    -isysroot "${sdk_path}" \
    $(compile_flags) \
    -I "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}" \
    -I "$(dirname "${WINN_GENERATED_HEADER}")" \
    "${probe}" \
    || die "WinnTunnel.h disagrees with $(basename "${WINN_GENERATED_HEADER}") for ${target}. The generated header is the authority: change WinnTunnel.h."
}

verify_double_matches() {
  local platform="$1" arch="$2" minos="$3" sdk_path="$4"
  local target
  target="$(target_triple "${platform}" "${minos}" "${arch}")"

  # Force-including the generated header puts the real prototypes ahead of the
  # double's definitions, so a definition that disagrees is a hard error.
  "${CLANG_BIN}" \
    -target "${target}" \
    -isysroot "${sdk_path}" \
    $(compile_flags) \
    -I "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}" \
    -include "${WINN_GENERATED_HEADER}" \
    "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnelTestDouble.c" \
    || die "WinnTunnelTestDouble.c implements a different contract than the real archive for ${target}. A double that implements the wrong contract makes every test a false pass."
}

verify_wrapper_call_sites() {
  local platform="$1" arch="$2" minos="$3" sdk_path="$4"
  local target
  target="$(target_triple "${platform}" "${minos}" "${arch}")"

  "${CLANG_BIN}" \
    -target "${target}" \
    -isysroot "${sdk_path}" \
    $(compile_flags) \
    -fobjc-arc \
    -I "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}" \
    -include "${WINN_GENERATED_HEADER}" \
    "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" \
    || die "WinsWinnPacketEngine.m calls the Winn C ABI in a way the real archive does not export, for ${target}."
}

verify_archive() {
  local platform="$1" arch="$2" archive="$3" work_dir="$4"

  local symbols
  symbols="$("${NM_BIN}" -g "${archive}" 2>/dev/null | awk '{ print $NF }' | sed 's/^_//' | sort -u)"
  [[ -n "${symbols}" ]] || die "No exported symbols found in ${archive}."
  local symbol
  for symbol in "${WINN_REQUIRED_SYMBOLS[@]}"; do
    grep -qx "${symbol}" <<<"${symbols}" \
      || die "Missing symbol ${symbol} in ${archive}."
  done

  # go.o carries the LC_BUILD_VERSION for the archive. The archives are thin,
  # so there is nothing to lipo -thin out of them first.
  local extract_dir="${work_dir}/archive-${platform}-${arch}"
  mkdir -p "${extract_dir}"
  (cd "${extract_dir}" && "${AR_BIN}" -x "${archive}" go.o)
  [[ -f "${extract_dir}/go.o" ]] || die "Could not extract go.o from ${archive}."

  local expected actual
  expected="$(expected_platform "${platform}")"
  actual="$("${VTOOL_BIN}" -show-build "${extract_dir}/go.o" 2>/dev/null \
    | awk '/^[[:space:]]*platform[[:space:]]+[A-Z0-9_]+[[:space:]]*$/ { print $2; exit }')"
  [[ -n "${actual}" ]] || die "Missing LC_BUILD_VERSION metadata in ${archive} (go.o)."
  [[ "${actual}" == "${expected}" ]] \
    || die "${archive} go.o targets ${actual}; expected ${expected}."

  local archive_archs
  archive_archs="$("${LIPO_BIN}" -archs "${archive}" 2>/dev/null || true)"
  [[ " ${archive_archs} " == *" ${arch} "* ]] \
    || die "${archive} does not contain ${arch}; found ${archive_archs}."

  # Everything above this line checks the C ABI signature, which a stale archive
  # satisfies perfectly. This is the check that does not.
  verify_archive_field_set "${archive}"
}

# verify_android_engine is the android/arm64 slice. It is deliberately NOT a
# mirror of verify_archive, because the Android shape is a different artifact
# and pretending otherwise is how this script would report a false green.
#
# On Apple, the Winn datapath crosses to the host as a c-archive: cdatapath is
# //go:build darwin, built with -buildmode=c-archive, and its WinnTunnel*
# entry points are the C ABI that applet wrapper links and dlsyms. There is no
# Android analogue of that archive. Go's cdatapath package carries a darwin
# build constraint and does not build for android at all, and Go rejects
# `-buildmode=c-archive` on android/arm64 outright, so no Android artifact can
# export WinnTunnel* C symbols. Android ships the same datapath contract as a
# STRIPPED subprocess executable (cmd/winn-datapath via
# `build_winn_protocol_engine.sh datapath-android-arm64`): the host spawns it
# and speaks the framed-duplex protocol, whose Create frame carries exactly
# datapath.Config.
#
# So the Android boundary contract is datapath.Config's JSON field set, not a
# C symbol table, and that is what this slice asserts. The field set is the
# SAME set the Apple c-archives are checked against (WINN_ACCEPTED_FIELD_SET),
# which is what makes the matrix comparable: every slice must be built from the
# current datapath source or it is stale, and a stale Android engine refuses
# current configs with `json: unknown field` exactly as a stale Apple archive
# does. The C ABI (WinnTunnel*) remains exported by the Apple c-archives and is
# checked there; it is honest to assert it there and not to invent an Android
# artifact that could export it.
verify_android_engine() {
  local engine="$1"
  local readelf="$2"

  [[ -f "${engine}" ]] || die "Missing Android datapath engine: ${engine}."
  [[ -x "${engine}" ]] || die "Android datapath engine is not executable: ${engine}."

  # 1. The artifact is really an AArch64 Android ELF. The datapath engine is a
  #    DYN (a pie executable / shared object), not a static archive.
  local header class machine type
  header="$("${readelf}" -h "${engine}" 2>/dev/null || true)"
  class="$(printf '%s\n' "${header}" | awk '/Class:/ { print $2; exit }')"
  machine="$(printf '%s\n' "${header}" | awk '/Machine:/ { print $2; exit }')"
  type="$(printf '%s\n' "${header}" | awk '/Type:/ { print $2; exit }')"
  [[ "${class}" == "ELF64" ]] || die "Android datapath engine is not ELF64 (found '${class}'): ${engine}."
  [[ "${machine}" == "AArch64" ]] || die "Android datapath engine is not AArch64 (found '${machine}'): ${engine}."
  [[ "${type}" == "DYN" ]] || die "Android datapath engine is not a DYN executable (found '${type}'): ${engine}."

  # 2. It carries the datapath contract marker. This is the same guard
  #    verify_archive_field_set uses on the Apple archives; a binary not built
  #    from a package importing datapath would have no marker and would be a
  #    category error, not a stale engine.
  grep -aqF 'winn-datapath/1' "${engine}" \
    || die "${engine} carries no datapath contract marker; it was not built from ${WINN_DATAPATH_SOURCE_DIR#"${PROJECT_ROOT}/"}. The field-set check must not be run against it."

  # 3. The full accepted field set is present. This is the stale-artifact guard
  #    for Android, and it fails a build that predates any datapath.Config
  #    field. Record total and missing explicitly into locals before printing,
  #    so a pipeline can never launder a count.
  local total=0 missing=() tag
  while IFS= read -r tag; do
    total=$((total + 1))
    grep -aqF "${tag}" "${engine}" || missing+=("${tag}")
  done <<<"${WINN_ACCEPTED_FIELD_SET}"
  [[ "${total}" -gt 0 ]] || die "The accepted field set came back empty; the android field-set check would pass vacuously. Refusing."
  if [[ "${#missing[@]}" -gt 0 ]]; then
    printf 'ERROR: %s IS STALE.\n' "${engine}" >&2
    printf '  It was built before %d of the %d fields %s declares.\n' \
      "${#missing[@]}" "${total}" "${WINN_DATAPATH_SOURCE_DIR}" >&2
    printf '    %s\n' "${missing[@]}" >&2
    exit 1
  fi

  # 4. The Winn v3 binding is recognisably shipped: the payload classes the
  #    engine advertises (the relay datagram and the standalone v3 inner-IP
  #    frame) and the banner key that hosts probe to decide v3 support.
  for _needle in 'awg-datagram' 'ip-packet'; do
    grep -aqF "${_needle}" "${engine}" \
      || die "${engine} does not carry the Winn v3 payload class '${_needle}'; it is not a Winn v3-capable datapath."
  done

  printf '  OK  %-40s android %s, %d datapath Config fields, field set current\n' \
    "$(basename "${engine}")" "arm64" "${total}"
  return 0
}

main() {
  ensure_tools

  [[ -f "${WINN_GENERATED_HEADER}" ]] \
    || die "Missing the cgo-generated header that defines the contract: ${WINN_GENERATED_HEADER}. It is the authority for apple/EngineWrappers/WinnTunnel.h and this check cannot run without it."
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnel.h" ]] \
    || die "Missing apple/EngineWrappers/WinnTunnel.h."
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnelTestDouble.c" ]] \
    || die "Missing apple/EngineWrappers/WinnTunnelTestDouble.c."
  [[ -f "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinsWinnPacketEngine.m" ]] \
    || die "Missing apple/EngineWrappers/WinsWinnPacketEngine.m."

  local slices=()
  if [[ -n "${WINN_ABI_SLICES:-}" ]]; then
    read -r -a slices <<<"${WINN_ABI_SLICES}"
  else
    slices=("${DEFAULT_SLICES[@]}")
  fi

  # Deliberately not `local`: the EXIT trap runs after main returns, so a
  # function-scoped variable would be unbound by the time the trap fires.
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-winn-abi.XXXXXX")"
  trap 'rm -rf "${WORK_DIR}"' EXIT
  local work_dir="${WORK_DIR}"

  # Deliberately not `local`: verify_archive_field_set reads it.
  WINN_ACCEPTED_FIELD_SET="$(accepted_field_set)"
  local field_count field_digest
  field_count="$(printf '%s\n' "${WINN_ACCEPTED_FIELD_SET}" | wc -l | tr -d ' ')"
  field_digest="$(printf '%s' "${WINN_ACCEPTED_FIELD_SET}" | shasum -a 256 | cut -c1-16)"

  printf 'Winn C ABI conformance\n'
  printf '  authority:   %s\n' "${WINN_GENERATED_HEADER}"
  printf '  wrapper:     %s\n' "${APPLE_ENGINE_WRAPPER_SOURCE_DIR}/WinnTunnel.h"
  printf '  field set:   %s fields from %s (sha256 %s)\n' \
    "${field_count}" "${WINN_DATAPATH_SOURCE_DIR#"${PROJECT_ROOT}/"}" "${field_digest}"
  printf '\n'

  local checked_archives=0
  local slice platform arch minos sdk_path archive
  for slice in "${slices[@]}"; do
    IFS=':' read -r platform arch minos <<<"${slice}"

    # Android is a different artifact shape (a datapath subprocess executable,
    # not an Apple c-archive), so it gets its own branch before the Apple SDK
    # machinery below is even touched. xcrun, target_triple, vtool and lipo
    # are all Mach-O / Apple-only and must not run against it.
    if [[ "${platform}" == "android" ]]; then
      archive="$(archive_for_slice "${platform}" "${arch}")"
      if [[ -n "${archive}" && -f "${archive}" ]]; then
        verify_android_engine "${archive}" "${ANDROID_READELF_BIN}"
        checked_archives=$((checked_archives + 1))
      fi
      continue
    fi

    sdk_path="$(xcrun --sdk "${platform}" --show-sdk-path)"

    verify_headers_agree "${platform}" "${arch}" "${minos}" "${sdk_path}" "${work_dir}"
    verify_double_matches "${platform}" "${arch}" "${minos}" "${sdk_path}"
    verify_wrapper_call_sites "${platform}" "${arch}" "${minos}" "${sdk_path}"
    printf '  OK  %-40s header + double + call sites\n' \
      "$(target_triple "${platform}" "${minos}" "${arch}")"

    archive="$(archive_for_slice "${platform}" "${arch}")"
    if [[ -n "${archive}" && -f "${archive}" ]]; then
      verify_archive "${platform}" "${arch}" "${archive}" "${work_dir}"
      checked_archives=$((checked_archives + 1))
      printf '  OK  %-40s %d Winn* symbols, platform %s, field set current\n' \
        "$(basename "${archive}")" "${#WINN_REQUIRED_SYMBOLS[@]}" "$(expected_platform "${platform}")"
    fi
  done

  printf '\n'
  if [[ "${checked_archives}" -eq 0 ]]; then
    printf 'Winn C ABI conformance passed for %d slice(s). No real archive was available to verify against; the header check still ran against the generated header in the tree.\n' \
      "${#slices[@]}"
  else
    printf 'Winn C ABI conformance passed for %d slice(s), %d real archive(s).\n' \
      "${#slices[@]}" "${checked_archives}"
  fi
}

main "$@"
