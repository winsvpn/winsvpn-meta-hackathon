#!/usr/bin/env bash
#
# verify_native_standalone_tests.sh — build and RUN every standalone C++17 test
# program in linux/runner/ and windows/runner/.
#
# WHY THIS EXISTS
#
# There are eleven of these files. Every one of them has its own `main`, every
# one of them is deliberately NOT in its platform's CMakeLists.txt (both CMake
# targets list their sources explicitly, so a test file cannot reach a shipped
# binary), and every one of them carries a header comment with a `c++ -std=c++17`
# line and the sentence "a test that only <platform> can execute is a test that
# does not get run".
#
# WHAT IT DOES
#
#   1. Binds an exact authenticated CXX executable and its compiler runtime
#      (bytes + support tree) from existing toolchain custody. Arbitrary CXX,
#      PATH compilers, Apple trampolines, and copies of /usr/bin/true fail
#      closed. Compiler --version / identity probes never have their exit
#      status masked.
#   2. Builds each test with the compiler flags its own header comment
#      specifies, plus whatever extra translation units and pkg-config packages
#      it genuinely needs (the TESTS table below).
#   3. RUNS it.
#   4. Applies a SHRINK-ONLY known-red ratchet. The index lookup is a numeric
#      walk of KNOWN_RED_COUNT so Bash 3.2 cannot miss index 0.
#   5. Emits a HOST-SCOPED verdict. Portable/macOS coverage may pass on Darwin
#      while Linux libsecret/BPF and Windows production-host coverage remain
#      explicit required receipts/blockers. One executed test never satisfies
#      universal release coverage.
#
# THE COMPLETENESS RULE
#
# Every `*_test.cc` under linux/runner and windows/runner MUST appear in TESTS.
# The inventory is exactly eleven entries.
#
# THE RATCHET RULES (tools/native_standalone_tests_known_red.txt)
#
#   * red   + listed    -> KNOWN-RED, reported loudly, does not fail the run
#   * red   + unlisted  -> FAIL. This is the case the gate exists for.
#   * green + listed    -> FAIL, "delete the entry". Shrink-only: an entry that
#                          has been fixed may not linger and re-open the hole.
#   * listed + no such test -> FAIL. A stale entry is a lie about coverage.
#   * an empty list is FINE and is the goal state.
#
# Usage:  tools/verify_native_standalone_tests.sh
#         tools/verify_native_standalone_tests.sh --self-test
# Env:    CXX  must be unset or the exact authenticated compiler path.

set -Eeuo pipefail

PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "${PROJECT_ROOT}"

STAT_BIN="/usr/bin/stat"
FIND_BIN="/usr/bin/find"
SORT_BIN="/usr/bin/sort"
SHASUM_BIN="/usr/bin/shasum"
AWK_BIN="/usr/bin/awk"
READLINK_BIN="/usr/bin/readlink"
UNAME_BIN="/usr/bin/uname"
PLUTIL_BIN="/usr/bin/plutil"
HEAD_BIN="/usr/bin/head"
TRUE_BIN="/usr/bin/true"
CP_BIN="/bin/cp"
CHMOD_BIN="/bin/chmod"
MKDIR_BIN="/bin/mkdir"
PIN_MANIFEST="${PROJECT_ROOT}/tools/toolchain-pins.json"
APPLE_SEAM_HARNESS="${PROJECT_ROOT}/tools/verify_apple_winn_seam_harness.swift"
DETERMINISTIC_WG_KEY="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

# test source | extra TUs | pkg-config packages | coverage class
#
# Coverage classes are host-scoped. portable and portable_windows_source may
# execute on Darwin. linux_libsecret and linux_bpf require a Linux host with
# the named runtime. Windows production-host coverage is NEVER satisfied by
# compiling the portable Windows sources on another OS.
TESTS=(
  "linux/runner/linux_winn_gate_test.cc|||portable"
  "linux/runner/winn3_posture_test.cc|||portable"
  "windows/runner/windows_winn_gate_test.cc|||portable_windows_source"
  "windows/runner/windows_tunnel_service_client_test.cc|||portable_windows_source"
  "windows/runner/winn3_supervisor_test.cc|||portable_windows_source"
  "windows/runner/winn_frame_selftest_test.cc|||portable_windows_source"
  "linux/runner/linux_winn3_host_test.cc|linux/runner/linux_winn3_host.cc||portable"
  "linux/runner/linux_winn_carrier_profile_test.cc|linux/runner/linux_winn_host.cc||portable"
  "linux/runner/linux_secure_store_test.cc|linux/runner/linux_secure_store.cc linux/runner/linux_secure_store_async.cc|gio-2.0 glib-2.0 gobject-2.0 libsecret-1|linux_libsecret"
  "linux/runner/winsvpn_bypass_bpf_test.cc|||linux_bpf"
  "linux/runner/my_application_launch_wiring_test.cc|||portable"
)

EXPECTED_TEST_COUNT=11

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_system_tool() {
  local tool="$1"
  [[ -e "${tool}" ]] || die "required system tool is missing: ${tool}"
  [[ -L "${tool}" ]] && die "required system tool must not be a symlink: ${tool}"
  [[ -f "${tool}" && -x "${tool}" ]] || die "required system tool is not a regular executable: ${tool}"
  [[ -w "${tool}" ]] && die "owner/environment blocker: same-user substitution cannot be prevented for ${tool}"
  local uid
  uid="$("${STAT_BIN}" -f '%u' "${tool}")" || die "stat failed for ${tool}"
  [[ "${uid}" == "0" ]] || die "required system tool is not uid 0: ${tool}"
}

host_os() {
  "${UNAME_BIN}" -s
}

authenticated_cxx_path() {
  local os
  os="$(host_os)"
  case "${os}" in
    Darwin)
      printf '%s' "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++"
      ;;
    *)
      die "owner/environment blocker: toolchain custody has no authenticated CXX executable for ${os}; PATH compilers are refused"
      ;;
  esac
}

authenticated_toolchain_root() {
  printf '%s' "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
}

authenticated_sdk_path() {
  printf '%s' "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
}

# ---------------------------------------------------------------------------
# Known-red list
# ---------------------------------------------------------------------------
declare -a KNOWN_RED_NAMES=()
declare -a KNOWN_RED_REASONS=()
KNOWN_RED_COUNT=0
load_known_red() {
  KNOWN_RED_NAMES=()
  KNOWN_RED_REASONS=()
  KNOWN_RED_COUNT=0
  [[ -f "${KNOWN_RED_FILE}" ]] || return 0
  local line name reason
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%$'\r'}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    name="${line%%[[:space:]]*}"
    reason="${line#"${name}"}"
    reason="${reason#"${reason%%[![:space:]]*}"}"
    [[ -n "${reason}" ]] || die "${KNOWN_RED_FILE}: entry '${name}' has no reason. Every entry must say why."
    KNOWN_RED_NAMES+=("${name}")
    KNOWN_RED_REASONS+=("${reason}")
    KNOWN_RED_COUNT=$((KNOWN_RED_COUNT + 1))
  done < "${KNOWN_RED_FILE}"

  local i known_name test_entry found
  i=0
  while [[ ${i} -lt ${KNOWN_RED_COUNT} ]]; do
    known_name="${KNOWN_RED_NAMES[$i]}"
    found=0
    for test_entry in "${TESTS[@]}"; do
      [[ "$(basename "${test_entry%%|*}" .cc)" == "${known_name}" ]] && {
        found=1
        break
      }
    done
    [[ ${found} -eq 1 ]] ||
      die "${KNOWN_RED_FILE}: entry '${known_name}' names no standalone test in TESTS. Remove the entry."
    i=$((i + 1))
  done
}

# Numeric walk. Bash 3.2 (and the ${!array[@]+...} idiom on every Bash this
# host has) expands the index list to an empty word, so a listed green test
# was treated as unlisted and the shrink-only ratchet never fired.
known_red_index() {
  local wanted="$1"
  local i=0
  while [[ ${i} -lt ${KNOWN_RED_COUNT} ]]; do
    if [[ "${KNOWN_RED_NAMES[$i]}" == "${wanted}" ]]; then
      printf '%s' "${i}"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# ---------------------------------------------------------------------------
# Completeness: no test file may exist without a TESTS entry
# ---------------------------------------------------------------------------
check_completeness() {
  local declared=() entry found path missing=0
  [[ ${#TESTS[@]} -eq ${EXPECTED_TEST_COUNT} ]] ||
    die "TESTS inventory is ${#TESTS[@]} entries; exactly ${EXPECTED_TEST_COUNT} are required."
  for entry in "${TESTS[@]}"; do declared+=("${entry%%|*}"); done
  while IFS= read -r path; do
    [[ "$(basename "${path}")" == ._* ]] && continue
    found=0
    for e in "${declared[@]}"; do [[ "${e}" == "${path}" ]] && found=1 && break; done
    if [[ ${found} -eq 0 ]]; then
      printf 'UNCOVERED: %s exists but has no entry in TESTS in %s\n' \
        "${path}" "$(basename "${BASH_SOURCE[0]}")" >&2
      missing=1
    fi
  done < <("${FIND_BIN}" linux/runner windows/runner -maxdepth 1 -name '*_test.cc' ! -name '*.bak*' | "${SORT_BIN}")
  [[ ${missing} -eq 0 ]] || die "a standalone test exists that this gate does not run. Add it to TESTS."
  for e in "${declared[@]}"; do
    [[ -f "${e}" ]] || die "TESTS names ${e}, which does not exist. Remove the entry."
  done
}

file_sha256() {
  local path="$1" sum
  sum="$("${SHASUM_BIN}" -a 256 "${path}")" || die "shasum failed for ${path}"
  printf '%s' "${sum%% *}"
}

file_identity() {
  local path="$1"
  "${STAT_BIN}" -f '%d:%i:%u:%g:%Lp:%l:%z:%m' "${path}" || die "stat failed for ${path}"
}

support_tree_fingerprint() {
  local root="$1" log="$2"
  [[ -d "${root}" ]] || die "compiler support tree is not a directory: ${root}"
  : > "${log}"
  "${FIND_BIN}" -P "${root}" -print0 | "${SORT_BIN}" -z | while IFS= read -r -d '' path; do
    "${STAT_BIN}" -f '%N|%HT|%u|%g|%Lp|%l|%z|%m|%i|%d' "${path}" >> "${log}" || exit 1
  done
  file_sha256 "${log}"
}

# Run BIN --version into LOG. Never pipe the compiler, never || true, never
# 2>/dev/null. Status is checked before any identity text is consumed.
probe_compiler_version() {
  local bin="$1" log="$2" st=0
  "${bin}" --version >"${log}" 2>&1 || st=$?
  if [[ ${st} -ne 0 ]]; then
    die "compiler --version failed with exit status ${st}"
  fi
  [[ -s "${log}" ]] || die "compiler --version produced no identity"
}

probe_compiler_print() {
  local bin="$1" flag="$2" log="$3" st=0
  "${bin}" "${flag}" >"${log}" 2>&1 || st=$?
  if [[ ${st} -ne 0 ]]; then
    die "compiler ${flag} failed with exit status ${st}"
  fi
  [[ -s "${log}" ]] || die "compiler ${flag} produced no identity"
}

require_not_user_substitutable() {
  local path="$1" label="$2"
  [[ -e "${path}" ]] || die "${label} is missing: ${path}"
  if [[ -w "${path}" ]]; then
    die "owner/environment blocker: same-user substitution cannot be prevented for ${label} (${path})"
  fi
  local uid
  uid="$("${STAT_BIN}" -f '%u' "${path}")" || die "stat failed for ${path}"
  [[ "${uid}" == "0" ]] || die "owner/environment blocker: ${label} is not uid 0 (${path})"
}

resolve_authenticated_cxx() {
  local os auth requested
  os="$(host_os)"
  [[ "${os}" == "Darwin" ]] || die "owner/environment blocker: toolchain custody has no authenticated CXX executable for ${os}; PATH compilers are refused"

  require_system_tool "${STAT_BIN}"
  require_system_tool "${FIND_BIN}"
  require_system_tool "${SORT_BIN}"
  require_system_tool "${SHASUM_BIN}"
  require_system_tool "${AWK_BIN}"
  require_system_tool "${READLINK_BIN}"
  require_system_tool "${UNAME_BIN}"
  require_system_tool "${PLUTIL_BIN}"
  require_system_tool "${HEAD_BIN}"

  [[ -f "${PIN_MANIFEST}" ]] || die "toolchain custody manifest is missing: ${PIN_MANIFEST}"
  local pyver
  pyver="$("${PLUTIL_BIN}" -extract tools.python.version raw -o - "${PIN_MANIFEST}")" ||
    die "cannot read existing toolchain custody from ${PIN_MANIFEST}"
  [[ -n "${pyver}" ]] || die "toolchain custody python version is empty"
  if "${PLUTIL_BIN}" -extract tools.cxx raw -o - "${PIN_MANIFEST}" >/dev/null 2>&1; then
    die "toolchain-pins.json now carries tools.cxx; this gate must bind that pin rather than the established Xcode clang++ path"
  fi

  auth="$(authenticated_cxx_path)"
  if [[ -n "${CXX+x}" ]]; then
    requested="${CXX}"
    if [[ "${requested}" == *[[:space:]]* ]]; then
      die "PATH compilers are refused: CXX must be the exact authenticated compiler path"
    fi
    case "${requested}" in
      ''|c++|clang++|g++|cc|clang)
        die "PATH compilers are refused: CXX=${requested} is a basename, not the authenticated compiler"
        ;;
    esac
    if [[ "${requested}" != "${auth}" ]]; then
      die "arbitrary CXX is refused: ${requested} is not the authenticated compiler ${auth}"
    fi
  fi
  CXX_BIN="${auth}"
  AUTH_TOOLCHAIN="$(authenticated_toolchain_root)"
  AUTH_SDK="$(authenticated_sdk_path)"
}

bind_compiler_runtime() {
  local target real_dir version_log resource_log search_log tree_log
  require_not_user_substitutable "${CXX_BIN}" "authenticated CXX"
  require_not_user_substitutable "${AUTH_TOOLCHAIN}" "compiler support tree"
  require_not_user_substitutable "${AUTH_SDK}" "compiler SDK"

  if [[ -L "${CXX_BIN}" ]]; then
    target="$("${READLINK_BIN}" "${CXX_BIN}")" || die "readlink failed for ${CXX_BIN}"
    [[ "${target}" == "clang" ]] || die "authenticated clang++ must be a same-directory symlink to clang (got ${target})"
    real_dir="$(dirname "${CXX_BIN}")"
    CXX_REAL="${real_dir}/clang"
  else
    CXX_REAL="${CXX_BIN}"
  fi
  [[ -f "${CXX_REAL}" && ! -L "${CXX_REAL}" ]] || die "authenticated compiler bytes are not a regular file: ${CXX_REAL}"
  require_not_user_substitutable "${CXX_REAL}" "authenticated compiler bytes"

  unset DEVELOPER_DIR CCC_OVERRIDE_OPTIONS CPATH CPLUS_INCLUDE_PATH C_INCLUDE_PATH LIBRARY_PATH || true
  export SDKROOT="${AUTH_SDK}"
  export CLANG_NO_DEFAULT_CONFIG=1

  version_log="${WORK_DIR}/compiler-version.txt"
  probe_compiler_version "${CXX_BIN}" "${version_log}"
  COMPILER_VERSION_LINE="$("${HEAD_BIN}" -n 1 "${version_log}")" || die "head failed on compiler --version output"
  [[ -n "${COMPILER_VERSION_LINE}" ]] || die "compiler --version first line is empty"

  resource_log="${WORK_DIR}/compiler-resource-dir.txt"
  probe_compiler_print "${CXX_BIN}" "-print-resource-dir" "${resource_log}"
  COMPILER_RESOURCE_DIR="$("${HEAD_BIN}" -n 1 "${resource_log}")" || die "head failed on -print-resource-dir"
  COMPILER_RESOURCE_DIR="${COMPILER_RESOURCE_DIR%$'\r'}"
  case "${COMPILER_RESOURCE_DIR}" in
    "${AUTH_TOOLCHAIN}"/*) ;;
    *) die "compiler resource dir ${COMPILER_RESOURCE_DIR} is outside the authenticated support tree" ;;
  esac
  require_not_user_substitutable "${COMPILER_RESOURCE_DIR}" "compiler resource dir"

  search_log="${WORK_DIR}/compiler-search-dirs.txt"
  probe_compiler_print "${CXX_BIN}" "-print-search-dirs" "${search_log}"

  COMPILER_BYTES_SHA256="$(file_sha256 "${CXX_REAL}")"
  COMPILER_BYTES_IDENTITY="$(file_identity "${CXX_REAL}")"
  COMPILER_DRIVER_IDENTITY="$(file_identity "${CXX_BIN}")"
  SDK_IDENTITY="$(file_identity "${AUTH_SDK}")"
  tree_log="${WORK_DIR}/support-tree-stat.txt"
  COMPILER_SUPPORT_TREE_SHA256="$(support_tree_fingerprint "${AUTH_TOOLCHAIN}/usr/lib" "${tree_log}")"
  require_not_user_substitutable "${AUTH_TOOLCHAIN}/usr/include" "compiler include tree"

  printf '  compiler:  %s\n' "${COMPILER_VERSION_LINE}"
  printf '  cxx:       %s\n' "${CXX_BIN}"
  printf '  bytes:     %s sha256=%s identity=%s\n' "${CXX_REAL}" "${COMPILER_BYTES_SHA256}" "${COMPILER_BYTES_IDENTITY}"
  printf '  resource:  %s\n' "${COMPILER_RESOURCE_DIR}"
  printf '  sdk:       %s identity=%s\n' "${AUTH_SDK}" "${SDK_IDENTITY}"
  printf '  support:   %s sha256=%s\n' "${AUTH_TOOLCHAIN}/usr/lib" "${COMPILER_SUPPORT_TREE_SHA256}"
  printf '  bind:      compiler bytes and support tree are uid 0 and not user-writable; same-user substitution is prevented through execution\n'
}

assert_compiler_identity_unchanged() {
  local now
  now="$(file_identity "${CXX_REAL}")"
  [[ "${now}" == "${COMPILER_BYTES_IDENTITY}" ]] ||
    die "authenticated compiler identity changed during execution (${CXX_REAL})"
  now="$(file_identity "${CXX_BIN}")"
  [[ "${now}" == "${COMPILER_DRIVER_IDENTITY}" ]] ||
    die "authenticated clang++ identity changed during execution (${CXX_BIN})"
  now="$(file_identity "${AUTH_SDK}")"
  [[ "${now}" == "${SDK_IDENTITY}" ]] ||
    die "authenticated SDK identity changed during execution (${AUTH_SDK})"
  now="$(file_sha256 "${CXX_REAL}")"
  [[ "${now}" == "${COMPILER_BYTES_SHA256}" ]] ||
    die "authenticated compiler bytes changed during execution (${CXX_REAL})"
}

# ---------------------------------------------------------------------------
# Build + run one test. Prints a verdict word on stdout: PASS / FAIL / SKIP
# ---------------------------------------------------------------------------
run_one() { # source | extras | pkgs   -> echoes verdict, writes log to $4
  local src="$1" extras="$2" pkgs="$3" logfile="$4"
  local name; name="$(basename "${src}" .cc)"
  local bin="${WORK_DIR}/${name}"
  local cflags=() ldflags=()

  if [[ "${src}" == "linux/runner/winsvpn_bypass_bpf_test.cc" &&
        "$(host_os)" != "Linux" ]]; then
    printf 'SKIP: %s requires Linux kernel BPF headers and a Linux host.\n' \
      "${name}" > "${logfile}"
    printf 'SKIP'; return 0
  fi

  if [[ -n "${pkgs}" ]]; then
    if ! command -v pkg-config >/dev/null 2>&1; then
      printf 'SKIP: pkg-config is absent, so %s cannot be configured.\n' "${name}" > "${logfile}"
      printf 'SKIP'; return 0
    fi
    if ! pkg-config --exists ${pkgs} 2>/dev/null; then
      printf 'SKIP: %s needs %s, which this host does not provide.\n' "${name}" "${pkgs}" > "${logfile}"
      printf 'SKIP'; return 0
    fi
    # Word splitting is wanted here: these are compiler flag lists.
    # shellcheck disable=SC2207
    cflags=($(pkg-config --cflags ${pkgs}))
    # shellcheck disable=SC2207
    ldflags=($(pkg-config --libs ${pkgs}))
  fi

  if ! "${CXX_BIN}" -std=c++17 -Wall -Wextra \
        -isysroot "${AUTH_SDK}" \
        -I linux/runner -I windows/runner \
        "${cflags[@]+"${cflags[@]}"}" \
        -o "${bin}" "${src}" ${extras} \
        "${ldflags[@]+"${ldflags[@]}"}" > "${logfile}" 2>&1; then
    printf '\n--- the above is a COMPILE failure, the test never ran ---\n' >> "${logfile}"
    printf 'FAIL'; return 0
  fi
  assert_compiler_identity_unchanged
  [[ -x "${bin}" ]] || {
    printf '\n--- compiler returned success without producing an executable ---\n' >> "${logfile}"
    printf 'FAIL'; return 0
  }

  if "${bin}" >> "${logfile}" 2>&1; then
    printf 'PASS'; return 0
  fi
  printf '\n--- the above is a RUNTIME failure; the test built and its assertions failed ---\n' >> "${logfile}"
  printf 'FAIL'
}

format_host_verdict() {
  printf 'Host-scoped verdict (%s): portable/macOS coverage %s (%d passed, %d known-red, %d skipped, %d newly failing, %d stale ratchet entries)\n' \
    "${HOST_OS}" "${HOST_PORTABLE_STATUS}" \
    "${passed}" "${known_red}" "${skipped}" "${failed}" "${stale}"
  printf 'REQUIRED RECEIPT/BLOCKER: Linux libsecret (%s)\n' "${LIBSECRET_COVERAGE}"
  printf 'REQUIRED RECEIPT/BLOCKER: Linux BPF (%s)\n' "${BPF_COVERAGE}"
  printf 'REQUIRED RECEIPT/BLOCKER: Windows production-host coverage (%s)\n' "${WINDOWS_PRODUCTION_COVERAGE}"
  printf 'One executed test cannot satisfy universal release coverage.\n'
  printf 'Standalone native tests: host-scoped coverage only. This is not universal release coverage.\n'
}

# ---------------------------------------------------------------------------
# --self-test: prove the ratchet, compiler bind, and host-scope can fail
# ---------------------------------------------------------------------------
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-native-standalone.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT
KNOWN_RED_FILE="${KNOWN_RED_FILE:-tools/native_standalone_tests_known_red.txt}"

if [[ "${1:-}" == "--self-test" ]]; then
  fails=0
  scenario() { printf '  %-52s %s\n' "$1" "$2"; }
  THIS_BASH="${BASH:-/bin/bash}"
  tmp_list="${WORK_DIR}/known-red-selftest.txt"

  [[ ${#TESTS[@]} -eq ${EXPECTED_TEST_COUNT} ]] || {
    scenario "exact 11-test inventory" "WRONG (${#TESTS[@]})"
    fails=$((fails + 1))
  }
  if [[ ${#TESTS[@]} -eq ${EXPECTED_TEST_COUNT} ]]; then
    scenario "exact 11-test inventory" "held"
  fi

  # 1. an entry with no reason must be refused
  printf 'some_test\n' > "${tmp_list}"
  if KNOWN_RED_FILE="${tmp_list}" "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-load >/dev/null 2>&1; then
    scenario "entry with no reason" "ACCEPTED — WRONG"; fails=$((fails + 1))
  else
    scenario "entry with no reason" "rejected"
  fi

  # 2. an entry naming a test that does not exist must be refused
  printf 'no_such_test  because reasons\n' > "${tmp_list}"
  if KNOWN_RED_FILE="${tmp_list}" "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-load >/dev/null 2>&1; then
    scenario "entry naming a nonexistent test" "ACCEPTED — WRONG"; fails=$((fails + 1))
  else
    scenario "entry naming a nonexistent test" "rejected"
  fi

  # 3. Bash 3.2 known-red index: a listed GREEN name must be found at index 0
  #    so a stale entry fails the ratchet instead of being treated as unlisted.
  printf 'winn3_posture_test  fabricated: this test is green, so this entry is stale\n' > "${tmp_list}"
  idx_out="${WORK_DIR}/probe-index.out"
  idx_err="${WORK_DIR}/probe-index.err"
  idx_st=0
  KNOWN_RED_FILE="${tmp_list}" "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-index winn3_posture_test \
    >"${idx_out}" 2>"${idx_err}" || idx_st=$?
  if [[ ${idx_st} -ne 0 || "$(cat "${idx_out}")" != "0" ]]; then
    scenario "stale known-red" "INDEX MISSED — WRONG (status=${idx_st} out=$(cat "${idx_out}"))"
    fails=$((fails + 1))
  else
    scenario "stale known-red" "index 0 found; ratchet would fail a green listed entry"
  fi

  # 4. an EMPTY list must be accepted
  : > "${tmp_list}"
  if KNOWN_RED_FILE="${tmp_list}" "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-load >/dev/null 2>&1; then
    scenario "empty list (the goal state) loads cleanly" "accepted"
  else
    scenario "empty list (the goal state) loads cleanly" "REFUSED — WRONG"; fails=$((fails + 1))
  fi

  # 5. fake-CXX copies of /usr/bin/true must fail closed as arbitrary CXX
  require_system_tool "${TRUE_BIN}"
  require_system_tool "${CP_BIN}"
  require_system_tool "${CHMOD_BIN}"
  fake_cxx="${WORK_DIR}/fake-c++"
  "${CP_BIN}" "${TRUE_BIN}" "${fake_cxx}"
  "${CHMOD_BIN}" 0755 "${fake_cxx}"
  fake_st=0
  fake_err="${WORK_DIR}/fake-cxx.err"
  CXX="${fake_cxx}" "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-cxx >/dev/null 2>"${fake_err}" || fake_st=$?
  if [[ ${fake_st} -eq 0 ]] || ! grep -q 'arbitrary CXX is refused' "${fake_err}"; then
    scenario "fake-CXX copies-/usr/bin/true" "ACCEPTED — WRONG (status=${fake_st})"
    fails=$((fails + 1))
  else
    scenario "fake-CXX copies-/usr/bin/true" "rejected"
  fi

  path_st=0
  path_err="${WORK_DIR}/path-cxx.err"
  CXX=c++ "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-cxx >/dev/null 2>"${path_err}" || path_st=$?
  if [[ ${path_st} -eq 0 ]] || ! grep -q 'PATH compilers are refused' "${path_err}"; then
    scenario "PATH CXX basename" "ACCEPTED — WRONG (status=${path_st})"
    fails=$((fails + 1))
  else
    scenario "PATH CXX basename" "rejected"
  fi

  tramp_st=0
  tramp_err="${WORK_DIR}/tramp-cxx.err"
  CXX=/usr/bin/c++ "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-cxx >/dev/null 2>"${tramp_err}" || tramp_st=$?
  if [[ ${tramp_st} -eq 0 ]] || ! grep -q 'arbitrary CXX is refused' "${tramp_err}"; then
    scenario "Apple /usr/bin/c++ trampoline" "ACCEPTED — WRONG (status=${tramp_st})"
    fails=$((fails + 1))
  else
    scenario "Apple /usr/bin/c++ trampoline" "rejected"
  fi

  # 6. failed --version must surface its exit status (never masked)
  badver="${WORK_DIR}/failed-version"
  printf '#!/bin/sh\necho failed-version-probe >&2\nexit 9\n' > "${badver}"
  "${CHMOD_BIN}" 0755 "${badver}"
  ver_st=0
  ver_err="${WORK_DIR}/failed-version.err"
  "${THIS_BASH}" "${BASH_SOURCE[0]}" --probe-version "${badver}" >/dev/null 2>"${ver_err}" || ver_st=$?
  if [[ ${ver_st} -eq 0 ]] || ! grep -q 'compiler --version failed with exit status 9' "${ver_err}"; then
    scenario "failed --version" "MASKED — WRONG (status=${ver_st})"
    fails=$((fails + 1))
  else
    scenario "failed --version" "exit status 9 preserved"
  fi

  # 7. host-vacuity: one PASS never becomes universal coverage
  HOST_OS="Darwin"
  HOST_PORTABLE_STATUS="PASS"
  passed=1; known_red=0; skipped=10; failed=0; stale=0
  LIBSECRET_COVERAGE="skipped; receipt required"
  BPF_COVERAGE="skipped; receipt required"
  WINDOWS_PRODUCTION_COVERAGE="not a Windows production host; receipt required"
  vacuity="${WORK_DIR}/host-vacuity.txt"
  format_host_verdict > "${vacuity}"
  if grep -q 'universal release coverage' "${vacuity}" &&
     grep -q 'REQUIRED RECEIPT/BLOCKER: Linux libsecret' "${vacuity}" &&
     grep -q 'REQUIRED RECEIPT/BLOCKER: Linux BPF' "${vacuity}" &&
     grep -q 'REQUIRED RECEIPT/BLOCKER: Windows production-host coverage' "${vacuity}" &&
     grep -q 'not universal release coverage' "${vacuity}" &&
     ! grep -q 'Standalone native tests: gate satisfied.' "${vacuity}"; then
    scenario "host-vacuity" "one PASS stays host-scoped with required receipts"
  else
    scenario "host-vacuity" "UNIVERSAL CLAIM — WRONG"
    fails=$((fails + 1))
  fi

  # 8. seam-key fixture in the Apple v1 harness
  if grep -q '<REDACTED_WG_KEY>' "${APPLE_SEAM_HARNESS}"; then
    scenario "seam-key" "REDACTED SENTINEL STILL PRESENT — WRONG"
    fails=$((fails + 1))
  elif grep -q "${DETERMINISTIC_WG_KEY}" "${APPLE_SEAM_HARNESS}"; then
    scenario "seam-key" "deterministic 32-byte non-secret fixture"
  else
    scenario "seam-key" "VALID KEY MISSING — WRONG"
    fails=$((fails + 1))
  fi

  if [[ ${fails} -ne 0 ]]; then
    printf '\nSELF-TEST FAILED: %d scenario(s) went the wrong way.\n' "${fails}" >&2
    exit 70
  fi
  printf '\nSelf-test passed: fake-CXX copies-/usr/bin/true, failed --version, stale known-red, host-vacuity, and seam-key regressions hold, and the ratchet accepts an empty list.\n'
  exit 0
fi

# Internal hooks used only by --self-test.
if [[ "${1:-}" == "--probe-load" ]]; then
  load_known_red
  exit 0
fi

if [[ "${1:-}" == "--probe-index" ]]; then
  load_known_red
  known_red_index "${2:-}"
  exit $?
fi

if [[ "${1:-}" == "--probe-cxx" ]]; then
  resolve_authenticated_cxx
  printf '%s\n' "${CXX_BIN}"
  exit 0
fi

if [[ "${1:-}" == "--probe-version" ]]; then
  probe_compiler_version "${2:-}" "${WORK_DIR}/probe-version.log"
  exit 0
fi

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
resolve_authenticated_cxx
load_known_red
check_completeness
bind_compiler_runtime

printf 'Standalone native tests\n'
printf '  known-red: %s (%d entr%s)\n\n' "${KNOWN_RED_FILE}" "${KNOWN_RED_COUNT}" \
  "$([[ ${KNOWN_RED_COUNT} -eq 1 ]] && printf 'y' || printf 'ies')"

passed=0; failed=0; skipped=0; known_red=0; stale=0
portable_executed=0
LIBSECRET_COVERAGE="not executed; receipt required"
BPF_COVERAGE="not executed; receipt required"
WINDOWS_PRODUCTION_COVERAGE="not a Windows production host; receipt required"
HOST_OS="$(host_os)"
if [[ "${HOST_OS}" == "Linux" ]]; then
  die "owner/environment blocker: Linux production coverage requires an authenticated CXX pin and a Linux host receipt; this Darwin-scoped gate does not invent a PATH compiler"
fi

for entry in "${TESTS[@]}"; do
  IFS='|' read -r src extras pkgs coverage <<< "${entry}"
  [[ -n "${coverage}" ]] || die "TESTS entry ${src} is missing a coverage class"
  name="$(basename "${src}" .cc)"
  logfile="${WORK_DIR}/${name}.log"
  verdict="$(run_one "${src}" "${extras}" "${pkgs}" "${logfile}")"

  listed=0
  idx=""
  if idx="$(known_red_index "${name}")"; then
    listed=1
  fi

  case "${verdict}" in
    PASS)
      if [[ ${listed} -eq 1 ]]; then
        printf '  STALE  %-38s passes, but %s still lists it.\n' "${name}" "${KNOWN_RED_FILE}" >&2
        printf '         Delete that entry. Reason it carried: %s\n' "${KNOWN_RED_REASONS[$idx]}" >&2
        stale=$((stale + 1))
      else
        printf '  ok     %-38s built and passed\n' "${name}"
        passed=$((passed + 1))
      fi
      ;;
    FAIL)
      if [[ ${listed} -eq 1 ]]; then
        printf '  RED    %-38s KNOWN-RED: %s\n' "${name}" "${KNOWN_RED_REASONS[$idx]}"
        known_red=$((known_red + 1))
      else
        printf '  FAIL   %-38s failed and is NOT in %s\n' "${name}" "${KNOWN_RED_FILE}" >&2
        sed 's/^/           /' "${logfile}" >&2
        failed=$((failed + 1))
      fi
      ;;
    SKIP)
      printf '  skip   %-38s %s\n' "${name}" "$(sed 's/^SKIP: //' "${logfile}" | tr -d '\n')"
      skipped=$((skipped + 1))
      ;;
    *)
      die "test ${name} produced an unknown verdict '${verdict}'"
      ;;
  esac

  case "${coverage}" in
    portable|portable_windows_source)
      if [[ "${verdict}" == "PASS" || "${verdict}" == "FAIL" ]]; then
        portable_executed=$((portable_executed + 1))
      elif [[ "${verdict}" == "SKIP" ]]; then
        die "portable test ${name} was skipped; portable coverage cannot be an honest skip on this host"
      fi
      ;;
    linux_libsecret)
      if [[ "${verdict}" == "PASS" || "${verdict}" == "FAIL" ]]; then
        LIBSECRET_COVERAGE="executed on this host"
      else
        LIBSECRET_COVERAGE="skipped; receipt required"
      fi
      ;;
    linux_bpf)
      if [[ "${verdict}" == "PASS" || "${verdict}" == "FAIL" ]]; then
        BPF_COVERAGE="executed on this host"
      else
        BPF_COVERAGE="skipped; receipt required"
      fi
      ;;
    *)
      die "TESTS entry ${src} has unknown coverage class ${coverage}"
      ;;
  esac
done

assert_compiler_identity_unchanged

printf '\n  %d passed, %d known-red, %d skipped, %d newly failing, %d stale ratchet entr%s\n' \
  "${passed}" "${known_red}" "${skipped}" "${failed}" "${stale}" \
  "$([[ ${stale} -eq 1 ]] && printf 'y' || printf 'ies')"

if [[ ${portable_executed} -eq 0 ]]; then
  die "host-vacuous: no portable test executed; one skip-loop cannot satisfy this host either."
fi

if [[ ${failed} -ne 0 || ${stale} -ne 0 ]]; then
  HOST_PORTABLE_STATUS="FAIL"
  format_host_verdict
  exit 1
fi

HOST_PORTABLE_STATUS="PASS"
format_host_verdict
exit 0
