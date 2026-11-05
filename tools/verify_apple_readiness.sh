#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLUTTER_BIN="${FLUTTER_BIN:-}"
POD_BIN="${POD_BIN:-}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# SINGLE SOURCE OF TRUTH: read every toolchain pin from
# tools/toolchain-pins.json at run time instead of a literal. A literal that
# happens to agree today is still a defect -- the next pin bump silently
# desynchronises this gate from every other build. Fail loudly so a missing
# pin file or parser never selects an unreviewed toolchain silently.
read_wins_toolchain_pin() {
  local pin_key="${1:?read_wins_toolchain_pin: missing key}"
  [[ -f "${ROOT_DIR}/tools/toolchain-pins.json" ]] || {
    printf 'TOOLCHAIN PIN ERROR: %s does not exist; cannot resolve %s.\n' \
      "${ROOT_DIR}/tools/toolchain-pins.json" "${pin_key}" >&2
    exit 65
  }
  "${PYTHON_BIN}" - "${ROOT_DIR}/tools/toolchain-pins.json" "${pin_key}" <<'WINS_PIN_EOF'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
sys.stdout.write(str(value))
WINS_PIN_EOF
}

REQUIRED_FLUTTER_VERSION="$(read_wins_toolchain_pin tools.flutter.version)"
REQUIRED_FLUTTER_REVISION="$(read_wins_toolchain_pin tools.flutter.revision)"
REQUIRED_COCOAPODS_VERSION="$(read_wins_toolchain_pin tools.cocoapods.version)"
XCODE_TOOLCHAIN_BIN="/Applications/Xcode.app/Contents/Developer/usr/bin"
XCODE_SWIFTC="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
XCODE_MACOS_SDK="/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"

if [[ -x "${XCODE_TOOLCHAIN_BIN}/git" ]]; then
  export PATH="${XCODE_TOOLCHAIN_BIN}:${PATH}"
fi

if [[ -z "${SWIFTC_BIN:-}" && -x "${XCODE_SWIFTC}" && -d "${XCODE_MACOS_SDK}" ]]; then
  SWIFTC_BIN="${XCODE_SWIFTC}"
  SWIFTC_SDK="${SWIFTC_SDK:-${XCODE_MACOS_SDK}}"
else
  SWIFTC_BIN="${SWIFTC_BIN:-swiftc}"
  SWIFTC_SDK="${SWIFTC_SDK:-}"
fi

SWIFTC_ARGS=()
if [[ -n "${SWIFTC_SDK}" ]]; then
  export SDKROOT="${SWIFTC_SDK}"
  SWIFTC_ARGS=(-sdk "${SWIFTC_SDK}")
fi

cd "${ROOT_DIR}"

# All Swift sources in the shared WinsTunnelCore module, derived from the
# directory rather than hand-listed, so a newly added core file can never
# silently drop out of the swiftc typecheck coverage below. Regression guard:
# a hand-maintained list previously omitted WinsSecureStateStore.swift, which
# made every -typecheck below fail with "cannot find 'WinsSecureStateStore' in
# scope" once the host bridges (AppDelegate.swift / MainFlutterWindow.swift)
# started using it. Evaluated after the cd above so the glob resolves against
# the repo root.
WINS_TUNNEL_CORE_SOURCES=(apple/WinsTunnelCore/*.swift)
if [[ ! -e "${WINS_TUNNEL_CORE_SOURCES[0]}" ]]; then
  printf 'FATAL: no apple/WinsTunnelCore/*.swift sources found (unexpected repo layout?).\n' >&2
  exit 1
fi

case "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" in
  0|1) ;;
  *)
    printf 'WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH must be 0 or 1.\n' >&2
    exit 1
    ;;
esac

if [[ "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  for conflicting_flag in \
    WINS_APPLE_RELEASE_CANDIDATE_REBUILD \
    WINS_APPLE_RUNTIME_EVIDENCE_REFRESH \
    WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH \
    WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH \
    WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH \
    WINS_APPLE_LIVE_TUNNEL_SMOKE \
    WINS_IOS_LIVE_TUNNEL_SMOKE \
    WINS_IOS_ARCHIVE_SMOKE \
    WINS_MACOS_ARCHIVE_SMOKE \
    WINS_IOS_DEBUGGING_EXPORT_SMOKE \
    WINS_MACOS_DEBUGGING_EXPORT_SMOKE \
    WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE \
    WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE \
    WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE \
    WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE \
    WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE \
    WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE \
    WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY; do
    if [[ "${!conflicting_flag:-0}" == "1" ]]; then
      printf 'WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH=1 cannot be combined with %s=1.\n' "${conflicting_flag}" >&2
      exit 1
    fi
  done
fi

section() {
  printf '\n== %s ==\n' "$*"
}

sanitize_apple_log_output() {
  "${PYTHON_BIN}" -c '
import re
import sys

patterns = [
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"), "<uuid>"),
    (re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}\b"), "<device-udid>"),
]

for line in sys.stdin:
    for pattern, replacement in patterns:
        line = pattern.sub(replacement, line)
    line = re.sub(
        r"((?:\"(?:serialNumber|ecid|udid)\"|\b(?:serialNumber|ecid|udid)\b)\s*[:=]\s*)(\"[^\"]*\"|\d+|[^,\s}]+)",
        "\\1\"<redacted>\"",
        line,
        flags=re.IGNORECASE,
    )
    sys.stdout.write(line)
'
}

run_optional() {
  printf '+ %s\n' "$*" | sanitize_apple_log_output
  set +e
  "$@" 2>&1 | sanitize_apple_log_output
  set -e
  return 0
}

# fail() aborts the CURRENT SECTION, not the whole script. See the section
# isolation block below: every section body runs inside its own subshell, so
# `exit 65` here ends that subshell and the driver moves on to the next section.
# The failure is recorded first so it survives the subshell and is re-announced
# in the summary. Called from the prelude (outside any section) it still exits
# the script, which is correct -- nothing has been set up at that point.
fail() {
  defer_failure "${WINS_CURRENT_SECTION:-PRELUDE}" "$*"
  printf 'APPLE READINESS ERROR: %s\n' "$*" >&2
  exit 65
}

# ---------------------------------------------------------------------------
# Deferred failures.
#
# A toolchain-identity mismatch used to `fail` (exit 65) before a single section
# ran, which made this script unusable on any machine whose toolchain had
# drifted -- lanes were extracting sections and hand-running them. The pin is
# deliberate and matches the Windows build host, so it must NOT be relaxed;
# instead the failure is recorded, announced immediately under a distinct label,
# and re-announced at exit, while the source sections still run. The script
# still exits non-zero.
#
# 2026-08-06 (section isolation lane): the store is now FILE-backed rather than
# a bash array. Section bodies run in subshells (see run_section below), and an
# array appended to inside a subshell is discarded when that subshell exits --
# the failure that actually killed the section would have been the one failure
# the summary never mentioned.
# ---------------------------------------------------------------------------
WINS_READINESS_STATE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/wins-apple-readiness.XXXXXX")"
WINS_READINESS_FAILURES_FILE="${WINS_READINESS_STATE_DIR}/failures"
WINS_READINESS_SECTIONS_FILE="${WINS_READINESS_STATE_DIR}/sections"
: >"${WINS_READINESS_FAILURES_FILE}"
: >"${WINS_READINESS_SECTIONS_FILE}"
DEFERRED_FAILURES_REPORTED=0

defer_failure() {
  local label="$1"
  shift
  # Newlines would corrupt the one-record-per-line store; collapse them.
  local message
  message="$(printf '%s' "$*" | tr '\n' ' ')"
  printf '%s|%s\n' "${label}" "${message}" >>"${WINS_READINESS_FAILURES_FILE}"
  printf 'APPLE READINESS DEFERRED FAILURE [%s]: %s\n' "${label}" "${message}" >&2
  printf '  (remaining sections still run; this script will exit non-zero.)\n' >&2
}

deferred_failure_count() {
  if [[ ! -f "${WINS_READINESS_FAILURES_FILE}" ]]; then
    printf '0\n'
    return 0
  fi
  awk 'END { print NR + 0 }' "${WINS_READINESS_FAILURES_FILE}"
}

report_deferred_failures() {
  if [[ "${DEFERRED_FAILURES_REPORTED}" == "1" ]]; then
    return 0
  fi
  DEFERRED_FAILURES_REPORTED=1
  if [[ "$(deferred_failure_count)" -eq 0 ]]; then
    return 0
  fi
  printf '\n== Deferred Failures ==\n' >&2
  local entry label message
  while IFS= read -r entry; do
    [[ -n "${entry}" ]] || continue
    label="${entry%%|*}"
    message="${entry#*|}"
    printf 'APPLE READINESS FAILURE [%s]: %s\n' "${label}" "${message}" >&2
  done <"${WINS_READINESS_FAILURES_FILE}"
  return 0
}

report_section_summary() {
  printf '\n== Section Summary ==\n'
  local line status name
  while IFS=$'\t' read -r status name; do
    [[ -n "${name}" ]] || continue
    printf '  %-4s %s\n' "${status}" "${name}"
  done <"${WINS_READINESS_SECTIONS_FILE}"
  return 0
}

wins_readiness_on_exit() {
  local dir
  for dir in \
    "${CONFIG_TMP:-}" \
    "${HOST_TMP:-}" \
    "${CONTAINMENT_TMP:-}" \
    "${IOS_CONTAINMENT_TMP:-}" \
    "${IOS_XCTEST_TMP:-}" \
    "${WATCHOS_XCTEST_TMP:-}" \
    "${MACOS_XCTEST_TMP:-}"; do
    if [[ -n "${dir}" && -d "${dir}" ]]; then
      rm -rf "${dir}"
    fi
  done
  report_deferred_failures
  if [[ -n "${WINS_READINESS_STATE_DIR:-}" && -d "${WINS_READINESS_STATE_DIR}" ]]; then
    rm -rf "${WINS_READINESS_STATE_DIR}"
  fi
}
trap wins_readiness_on_exit EXIT

# ---------------------------------------------------------------------------
# Section isolation.
#
# Until 2026-08-06 this script was a flat top-level sequence under `set -e`, so
# the FIRST failing command ended the run. On this workstation that command was
# `pod install --deployment` in "Locked CocoaPods Prerequisites" (CocoaPods
# 1.17.0 crashing on a non-UTF-8 locale), which meant that every section from
# "Flutter macOS XCTest Configuration" onward -- all four Swift typecheck
# sections, both dev-containment gates, both compiled Release-absence proofs,
# the XCTest inventory and the submission-package checks -- had never actually
# executed here. A readiness gate that stops at its first failure reports the
# health of one check and stays silent about the other twenty-three.
#
# Each section body now runs in its own subshell. A failure aborts THAT section
# and is recorded; the driver continues. The script still exits non-zero if any
# section failed, so this is strictly more reporting, never more leniency.
#
# WARNING -- do NOT rewrite the call below as `if ! ( "$fn" ); then`.
# Bash ignores errexit for any command in an `if` condition, and that
# suppression propagates INTO the subshell. Verify for yourself:
#
#     bash -c 'set -Eeuo pipefail; body() { false; echo REACHED; };
#              if ! ( body ); then :; fi'
#
# prints REACHED. Written that way, every `test -f`, `grep -q` and `plutil
# -lint` in every section below would stop aborting its section -- roughly a
# thousand guards silently inert, which is the same class of bug as the `!
# grep -q` absence guards documented further down. The explicit
# `set +e` / capture `$?` / `set -e` form below has no ignoring context, and
# the subshell re-arms `set -Eeuo pipefail` itself.
# ---------------------------------------------------------------------------
WINS_CURRENT_SECTION=""

# Most guards in this file are silent on success AND on failure -- `test -f X`
# and `grep -q PATTERN FILE` print nothing either way. "Section N failed" with
# no command named is barely more useful than the early abort it replaced, so
# the ERR trap below records the exact command and line. `set -E` (errtrace) is
# already on at the top of this file, which is what makes the trap fire inside
# functions; the trap fires under exactly the same rules as errexit, so the
# FIRST record for a section is the command that actually failed.
wins_record_err() {
  local file="$1" lineno="$2" command="$3" flattened
  # Truncated: several guards here are 150-line python heredocs, and
  # $BASH_COMMAND carries the whole body. The first line and the line number
  # identify the guard; the full text is already in the section output above.
  flattened="$(printf '%s' "${command}" | tr '\n' ' ')"
  if [[ "${#flattened}" -gt 160 ]]; then
    flattened="${flattened:0:160}... [truncated]"
  fi
  printf '%s\t%s\n' "${lineno}" "${flattened}" >>"${file}"
}

run_section() {
  local name="$1" fn="$2" rc=0 failures_before failures_after err_file first_err
  failures_before="$(deferred_failure_count)"
  err_file="${WINS_READINESS_STATE_DIR}/err.$$"
  : >"${err_file}"
  set +e
  (
    set -Eeuo pipefail
    WINS_CURRENT_SECTION="${name}"
    trap 'wins_record_err "'"${err_file}"'" "${LINENO}" "${BASH_COMMAND}"' ERR
    # The parent EXIT trap does not fire for a `( ... )` subshell, so a section
    # that creates a temp dir and then aborts would leak it. Clean up here.
    trap 'for _d in "${CONFIG_TMP:-}" "${HOST_TMP:-}" "${CONTAINMENT_TMP:-}" "${IOS_CONTAINMENT_TMP:-}" \
            "${IOS_XCTEST_TMP:-}" "${WATCHOS_XCTEST_TMP:-}" "${MACOS_XCTEST_TMP:-}"; do
            [[ -n "${_d}" && -d "${_d}" ]] && rm -rf "${_d}"
          done' EXIT
    "${fn}"
  )
  rc=$?
  set -e
  failures_after="$(deferred_failure_count)"
  if [[ "${rc}" -eq 0 ]]; then
    rm -f "${err_file}"
    printf '%s\t%s\n' "PASS" "${name}" >>"${WINS_READINESS_SECTIONS_FILE}"
    return 0
  fi
  # A section that died on a bare `test -f` / `grep -q` under errexit never
  # reached fail(), so nothing was recorded. Record it, or the summary would
  # name a failed section with no reason attached.
  if [[ "${failures_after}" == "${failures_before}" ]]; then
    first_err="$(awk -F'\t' 'NR == 1 { printf "line %s: %s", $1, $2 }' "${err_file}")"
    defer_failure "${name}" \
      "section aborted with exit status ${rc} at ${first_err:-<no ERR trap record; the section exited without a failing command, e.g. an explicit exit>} (${BASH_SOURCE[0]})."
  fi
  rm -f "${err_file}"
  printf '%s\t%s\n' "FAIL" "${name}" >>"${WINS_READINESS_SECTIONS_FILE}"
  printf 'APPLE READINESS: section %s FAILED (exit %s); continuing with the remaining sections.\n' \
    "${name}" "${rc}" >&2
  return 0
}

# ---------------------------------------------------------------------------
# Absence guards ("this must NOT be present").
#
# NEVER write an absence guard as `! grep -q PATTERN FILE`.
#
# Under `set -e` bash does NOT exit for a pipeline whose status is inverted with
# `!` -- POSIX specifies that errexit is ignored there. Verify for yourself:
#
#     bash -c 'set -Eeuo pipefail; ! grep -q root /etc/passwd; echo REACHED'
#
# prints REACHED and exits 0. A guard written that way RUNS, FINDS the forbidden
# text, and still lets this script continue to a green exit. 77 absence guards
# in this file were inert exactly this way until 2026-08-06 -- including every
# redaction guard and every raw-write guard, i.e. precisely the class that keeps
# sensitive strings from leaking, and therefore precisely the class whose silent
# failure nobody notices.
#
# Use refute_match / refute_match_in_swift_method below. Both fail loudly and
# name the guard, and both fail when the subject file is missing so a guard can
# never pass vacuously because its target moved.
# ---------------------------------------------------------------------------

# refute_match [-E|-F|-i|-Ei|-Fi] PATTERN FILE
#   Fails when PATTERN is present in FILE.
refute_match() {
  local grep_mode='-q'
  case "${1:-}" in
    -E|-F|-i|-Ei|-Fi)
      grep_mode="${1}q"
      shift
      ;;
  esac
  if [[ "$#" -ne 2 || -z "${1:-}" || -z "${2:-}" ]]; then
    fail "refute_match usage: refute_match [-E|-F|-i] PATTERN FILE (got: $*)"
  fi
  local pattern="$1" file="$2"
  if [[ ! -f "${file}" ]]; then
    fail "Absence guard cannot be evaluated: ${file} does not exist (forbidden pattern: ${pattern})."
  fi
  if grep "${grep_mode}" -- "${pattern}" "${file}"; then
    fail "Forbidden pattern present in ${file}: ${pattern}"
  fi
}

# refute_match_in_swift_method METHOD PATTERN FILE
#   Fails when PATTERN is present inside the body of Swift method METHOD in
#   FILE. Use this instead of refute_match whenever a whole-file pattern would
#   also match unrelated call sites: a guard that fires on unrelated code is how
#   the next person learns to ignore failures.
refute_match_in_swift_method() {
  if [[ "$#" -ne 3 || -z "${1:-}" || -z "${2:-}" || -z "${3:-}" ]]; then
    fail "refute_match_in_swift_method usage: METHOD PATTERN FILE (got: $*)"
  fi
  local method="$1" pattern="$2" file="$3" body
  if [[ ! -f "${file}" ]]; then
    fail "Absence guard cannot be evaluated: ${file} does not exist (guard: ${method}() / ${pattern})."
  fi
  body="$(awk -v marker="func ${method}(" '
    index($0, marker) > 0 { inside = 1; print; next }
    inside && /^[[:space:]]*(private |fileprivate |internal |public |open )?(static |class |final |override |@objc )*func [A-Za-z_]/ { inside = 0 }
    inside { print }
  ' "${file}")"
  if [[ -z "${body}" ]]; then
    fail "Absence guard cannot be evaluated: no Swift method '${method}' found in ${file} (forbidden pattern: ${pattern})."
  fi
  if grep -q -- "${pattern}" <<<"${body}"; then
    fail "Forbidden pattern present in ${file} inside ${method}(): ${pattern}"
  fi
}

# ---------------------------------------------------------------------------
# Binary content probes ("this literal must / must not be in this Mach-O").
#
# NEVER write one as `strings BINARY | grep -q PATTERN` in this file.
#
# `set -o pipefail` is on at the top. `grep -q` exits the instant it matches,
# which closes the pipe and kills `strings` with SIGPIPE (exit 141). pipefail
# then reports the WHOLE PIPELINE as 141 -- non-zero -- even though grep found
# the pattern and exited 0. Whether this happens is a race between grep's exit
# and strings finishing its write, so the same check on the same binary gives
# different answers on different runs.
#
# Measured on 2026-08-06 against the DEBUG-shaped Packet Tunnel binary, with a
# pattern that IS present, 30 consecutive trials of the old form:
#
#     `if strings BIN | grep -q PAT; then FATAL; fi`  ->  fired 13/30
#
# i.e. the release-absence guards MISSED A PRESENT STRING 57% of the time. That
# is the dangerous direction: those three guards exist to prove the dev
# containment path is compiled out of a Release appex, and more often than not
# they would have passed a Release binary that still contained it. The
# positive-control guards fail the other way -- they report a present string as
# missing -- and that is how this was finally noticed, when
# "Packet Tunnel Dev Containment Release Absence (compiled proof)" aborted on
# its own DEBUG positive control the first time section isolation let it run.
#
# The helper materialises the strings output to a file first, so there is no
# pipeline and no SIGPIPE, and the result is deterministic. `strings -a` scans
# the whole file rather than only the sections strings(1) picks by default,
# which is the conservative choice for an absence proof: it cannot miss a
# literal that lives in a section the default scan skips.
#
# Returns 0 if PATTERN is present, 1 if absent. Fails loudly if the binary is
# missing, so a probe can never pass vacuously because its target moved.
# ---------------------------------------------------------------------------
wins_binary_contains() {
  local binary="$1" pattern="$2" dump rc=0
  if [[ ! -f "${binary}" ]]; then
    printf 'FATAL: wins_binary_contains: no such binary: %s\n' "${binary}" >&2
    exit 1
  fi
  dump="$(mktemp "${TMPDIR:-/tmp}/wins-strings.XXXXXX")" || {
    printf 'FATAL: wins_binary_contains: mktemp failed.\n' >&2
    exit 1
  }
  # A failing strings(1) must NOT read as "the literal is absent". This function
  # backs three release-ABSENCE proofs, and for those an empty dump is
  # indistinguishable from a clean binary -- the exact "guard that does not
  # guard" shape this helper was written to remove. Fail loudly instead.
  if ! strings -a "${binary}" >"${dump}"; then
    printf 'FATAL: wins_binary_contains: strings(1) failed on %s\n' "${binary}" >&2
    rm -f "${dump}"
    exit 1
  fi
  # Likewise an empty dump: every Mach-O this is pointed at has string content,
  # so zero bytes means the probe learned nothing rather than found nothing.
  if [[ ! -s "${dump}" ]]; then
    printf 'FATAL: wins_binary_contains: strings(1) produced no output for %s\n' "${binary}" >&2
    rm -f "${dump}"
    exit 1
  fi
  grep -qF -- "${pattern}" "${dump}" || rc=$?
  rm -f "${dump}"
  return "${rc}"
}

resolve_reviewed_flutter_bin() {
  local configured="${FLUTTER_BIN}" candidate
  if [[ -n "${configured}" ]]; then
    if [[ "${configured}" == */* ]]; then
      [[ -x "${configured}" ]] || return 1
      printf '%s\n' "${configured}"
      return 0
    fi
    candidate="$(command -v "${configured}" 2>/dev/null || true)"
    [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="${HOME}/Library/Application Support/WinsVPN/toolchains/flutter-${REQUIRED_FLUTTER_VERSION}-extract/flutter/bin/flutter"
  if [[ -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="$(command -v flutter 2>/dev/null || true)"
  [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
  printf '%s\n' "${candidate}"
}

require_reviewed_flutter_toolchain() {
  local resolved identity flutter_version flutter_revision flutter_dir
  resolved="$(resolve_reviewed_flutter_bin || true)"
  if [[ -z "${resolved}" || ! -x "${resolved}" ]]; then
    defer_failure "TOOLCHAIN/flutter" \
      "Reviewed Flutter ${REQUIRED_FLUTTER_VERSION} is unavailable. Install it under ~/Library/Application Support/WinsVPN/toolchains or set FLUTTER_BIN explicitly. Sections that do not need Flutter still ran below."
    return 0
  fi
  FLUTTER_BIN="${resolved}"
  export FLUTTER_BIN
  flutter_dir="$(dirname "${FLUTTER_BIN}")"
  case ":${PATH}:" in
    *":${flutter_dir}:"*) ;;
    *) PATH="${flutter_dir}:${PATH}" ;;
  esac
  export PATH
  if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    defer_failure "TOOLCHAIN/python" "Python is unavailable at ${PYTHON_BIN}."
    return 0
  fi
  identity="$("${FLUTTER_BIN}" --version --machine 2>/dev/null | "${PYTHON_BIN}" -c '
import json
import sys
raw = sys.stdin.read()
start = raw.find("{")
end = raw.rfind("}")
if start < 0 or end < start:
    raise SystemExit("Flutter version JSON was not found")
value = json.loads(raw[start : end + 1])
print(value.get("frameworkVersion", ""), value.get("frameworkRevision", ""))
')" || {
    defer_failure "TOOLCHAIN/flutter" "Unable to read the reviewed Flutter toolchain identity from ${FLUTTER_BIN}."
    return 0
  }
  read -r flutter_version flutter_revision <<<"${identity}"
  # The pin is deliberate and matches the Windows build host. Do NOT relax it to
  # make this pass -- that would leave the guard green while the machine runs an
  # unreviewed toolchain. A mismatch is recorded as a distinct labelled failure
  # so the source sections below still run and this script still exits non-zero.
  if [[ "${flutter_version}" != "${REQUIRED_FLUTTER_VERSION}" \
    || "${flutter_revision}" != "${REQUIRED_FLUTTER_REVISION}" ]]; then
    defer_failure "TOOLCHAIN/flutter" \
      "Apple readiness requires Flutter ${REQUIRED_FLUTTER_VERSION} (${REQUIRED_FLUTTER_REVISION}); found ${flutter_version:-unknown} (${flutter_revision:-unknown}) at ${FLUTTER_BIN}. Source sections below still ran, but their results are NOT a reviewed-toolchain result."
    return 0
  fi
  printf 'Reviewed Flutter toolchain: %s (%s) at %s\n' \
    "${flutter_version}" "${flutter_revision}" "${FLUTTER_BIN}"
}

resolve_reviewed_pod_bin() {
  local configured="${POD_BIN}" candidate ruby_bin gem_user_dir
  if [[ -n "${configured}" ]]; then
    if [[ "${configured}" == */* ]]; then
      [[ -x "${configured}" ]] || return 1
      printf '%s\n' "${configured}"
      return 0
    fi
    candidate="$(command -v "${configured}" 2>/dev/null || true)"
    [[ -n "${candidate}" && -x "${candidate}" ]] || return 1
    printf '%s\n' "${candidate}"
    return 0
  fi

  # Managed reviewed-toolchain probe, mirroring resolve_reviewed_flutter_bin's
  # ~/Library/Application Support/WinsVPN/toolchains probe.
  #
  # 2026-08-06: CocoaPods 1.16.2 WAS already provisioned on this workstation --
  # side by side with the ambient 1.17.0, in an isolated gem tree with a `pod`
  # shim that scopes GEM_HOME/GEM_PATH (see tools/toolchain-pins.json
  # tools.cocoapods.host_provisioning). Nothing looked for it. `command -v pod`
  # found the 1.17.0 binstub first, so the gate reported the pin unmet on a
  # machine where the pinned version was installed and one directory away.
  # Flutter had a managed-path probe and CocoaPods did not; that asymmetry was
  # the whole defect.
  #
  # This is a RESOLUTION change, not a relaxation: the path is parameterised by
  # REQUIRED_COCOAPODS_VERSION, so it can only ever find the pinned version, and
  # the exact-match check in require_reviewed_cocoapods still runs afterwards
  # against whatever this returns.
  candidate="${HOME}/.local/cocoapods-${REQUIRED_COCOAPODS_VERSION}/reviewed-bin/pod"
  if [[ -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  candidate="$(command -v pod 2>/dev/null || true)"
  if [[ -n "${candidate}" && -x "${candidate}" ]]; then
    printf '%s\n' "${candidate}"
    return 0
  fi

  ruby_bin="$(command -v ruby 2>/dev/null || true)"
  if [[ -n "${ruby_bin}" ]]; then
    gem_user_dir="$("${ruby_bin}" -rrubygems -e 'print Gem.user_dir' 2>/dev/null || true)"
    candidate="${gem_user_dir}/bin/pod"
    if [[ -n "${gem_user_dir}" && -x "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  fi
  return 1
}

require_reviewed_cocoapods() {
  local resolved pod_version pod_dir
  resolved="$(resolve_reviewed_pod_bin || true)"
  if [[ -z "${resolved}" || ! -x "${resolved}" ]]; then
    defer_failure "TOOLCHAIN/cocoapods" \
      "CocoaPods ${REQUIRED_COCOAPODS_VERSION} is unavailable. Provision it side by side at ~/.local/cocoapods-${REQUIRED_COCOAPODS_VERSION}/reviewed-bin/pod (see tools/toolchain-pins.json) or set POD_BIN explicitly. Sections that do not need CocoaPods still ran below."
    return 0
  fi
  pod_version="$("${resolved}" --version 2>/dev/null | awk 'NF { print $1; exit }')"
  POD_BIN="${resolved}"
  export POD_BIN
  pod_dir="$(dirname "${POD_BIN}")"
  case ":${PATH}:" in
    *":${pod_dir}:"*) ;;
    *) PATH="${pod_dir}:${PATH}" ;;
  esac
  export PATH
  export COCOAPODS_DISABLE_STATS=true
  # Same reasoning as the Flutter pin above: record, do not relax, do not exit
  # before the source sections have run.
  if [[ "${pod_version}" != "${REQUIRED_COCOAPODS_VERSION}" ]]; then
    defer_failure "TOOLCHAIN/cocoapods" \
      "Apple readiness requires CocoaPods ${REQUIRED_COCOAPODS_VERSION}; found ${pod_version:-unknown} at ${POD_BIN}."
    return 0
  fi
  printf 'Reviewed CocoaPods: %s at %s\n' "${pod_version}" "${POD_BIN}"
}

require_reviewed_flutter_toolchain
require_reviewed_cocoapods

wins_readiness_section_01_apple_toolchain() {
section "Apple Toolchain"
run_optional xcode-select -p
run_optional xcodebuild -version
run_optional xcrun simctl list devices available
run_optional "${FLUTTER_BIN}" doctor -v
run_optional "${FLUTTER_BIN}" devices -v
"${FLUTTER_BIN}" pub get

}

wins_readiness_section_02_locked_cocoapods_prerequisites() {
section "Locked CocoaPods Prerequisites"
# A pristine reviewed Flutter checkout does not contain platform engine
# artifacts yet. Podfile post-install hooks inspect Flutter.xcframework, so
# CocoaPods must never run before the exact pinned SDK has populated those
# deterministic caches.
printf '+ %s precache --ios --macos\n' "${FLUTTER_BIN}"
"${FLUTTER_BIN}" precache --ios --macos
printf '+ (cd ios && %s install --deployment)\n' "${POD_BIN}"
(
  cd ios
  "${POD_BIN}" install --deployment
)
printf '+ (cd macos && %s install --deployment)\n' "${POD_BIN}"
(
  cd macos
  "${POD_BIN}" install --deployment
)

}

wins_readiness_section_03_flutter_macos_xctest_configuration() {
section "Flutter macOS XCTest Configuration"
"${FLUTTER_BIN}" build ios --debug --config-only --no-codesign
"${FLUTTER_BIN}" build macos --debug --config-only
expected_flutter_root="$(cd "$(dirname "${FLUTTER_BIN}")/.." && pwd -P)"
grep -Fqx "FLUTTER_ROOT=${expected_flutter_root}" ios/Flutter/Generated.xcconfig
grep -Fqx "FLUTTER_ROOT=${expected_flutter_root}" macos/Flutter/ephemeral/Flutter-Generated.xcconfig
test -f macos/Flutter/ephemeral/FlutterInputs.xcfilelist
test -f macos/Flutter/ephemeral/FlutterOutputs.xcfilelist

}

wins_readiness_section_04_flutter_apple_build_plumbing() {
section "Flutter Apple Build Plumbing"
test -f ios/Podfile
test -f macos/Podfile
grep -q "platform :ios, '15.0'" ios/Podfile
grep -q "platform :osx, '13.0'" macos/Podfile
grep -q 'flutter_install_all_ios_pods' ios/Podfile
grep -q 'flutter_install_all_macos_pods' macos/Podfile
grep -q "line.split('=', 2)" ios/Podfile
grep -q "line.split('=', 2)" macos/Podfile
grep -q "stripped.start_with?('#', '//')" ios/Podfile
grep -q "stripped.start_with?('#', '//')" macos/Podfile
grep -q 'Pods-Runner.debug.xcconfig' ios/Flutter/Debug.xcconfig
grep -q 'Pods-Runner.release.xcconfig' ios/Flutter/Release.xcconfig
grep -q 'Pods-Runner.profile.xcconfig' ios/Flutter/Profile.xcconfig
grep -q 'Profile.xcconfig' ios/Runner.xcodeproj/project.pbxproj
grep -q 'Pods-Runner.debug.xcconfig' macos/Runner/Configs/AppInfo-Debug.xcconfig
grep -q 'Pods-Runner.release.xcconfig' macos/Runner/Configs/AppInfo-Release.xcconfig
grep -q 'Pods-Runner.profile.xcconfig' macos/Runner/Configs/AppInfo-Profile.xcconfig
grep -q 'AppInfo-Debug.xcconfig' macos/Runner.xcodeproj/project.pbxproj
grep -q 'AppInfo-Release.xcconfig' macos/Runner.xcodeproj/project.pbxproj
grep -q 'AppInfo-Profile.xcconfig' macos/Runner.xcodeproj/project.pbxproj
grep -q 'GeneratedPluginRegistrant.m in Sources' ios/Runner.xcodeproj/project.pbxproj
grep -q 'GeneratedPluginRegistrant.swift in Sources' macos/Runner.xcodeproj/project.pbxproj
grep -q 'RunnerUITests.xctest' ios/Runner.xcodeproj/project.pbxproj
grep -q 'productType = "com.apple.product-type.bundle.ui-testing"' ios/Runner.xcodeproj/project.pbxproj
grep -q 'TEST_TARGET_NAME = Runner' ios/Runner.xcodeproj/project.pbxproj
grep -q 'VpnPermissionUITests.swift in Sources' ios/Runner.xcodeproj/project.pbxproj
test -f ios/Runner/GeneratedPluginRegistrant.h
test -f ios/Runner/GeneratedPluginRegistrant.m
test -f ios/RunnerUITests/VpnPermissionUITests.swift
test -f ios/Flutter/Generated.xcconfig
test -f macos/Flutter/GeneratedPluginRegistrant.swift
test -f macos/Flutter/ephemeral/Flutter-Generated.xcconfig
grep -q 'targetEnvironment(simulator)' ios/Runner/AppDelegate.swift
grep -q 'APPLE_TUNNEL_UNSUPPORTED' ios/Runner/AppDelegate.swift
grep -q 'packet_tunnel_requires_signed_physical_device' ios/Runner/AppDelegate.swift
test "$(grep -c 'run_flutter_build build macos --debug --config-only' tools/apple_runtime_smoke.sh)" -ge 2

}

wins_readiness_section_05_apple_app_icons() {
section "Apple App Icons"
test -f "assets/icon/Win Empire.png"
test -f macos/Runner/Assets.xcassets/AppIcon.appiconset/Contents.json
test -f ios/Runner/Assets.xcassets/AppIcon.appiconset/Contents.json
test -f ios/Runner/Assets.xcassets/CalculatorIcon.appiconset/Contents.json
test -f tools/generate_ios_calculator_icon.swift
command -v sips >/dev/null
"${PYTHON_BIN}" - <<'PY'
import json
import hashlib
import struct
from pathlib import Path


def png_info(path):
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise SystemExit(f"{path}: not a readable PNG")
    width, height = struct.unpack(">II", data[16:24])
    return width, height, data[25]


def expected_pixels(size, scale):
    width = float(size.split("x", 1)[0])
    multiplier = int(scale.removesuffix("x"))
    return int(width * multiplier)


def verify_iconset(iconset, *, allow_alpha):
    manifest_path = iconset / "Contents.json"
    manifest = json.loads(manifest_path.read_text())
    for entry in manifest.get("images", []):
        filename = entry.get("filename")
        if not filename:
            raise SystemExit(f"{manifest_path}: app icon entry missing filename")
        path = iconset / filename
        if not path.is_file():
            raise SystemExit(f"{manifest_path}: missing app icon asset {filename}")
        expected = expected_pixels(entry["size"], entry["scale"])
        actual_width, actual_height, color_type = png_info(path)
        actual = (actual_width, actual_height)
        if actual != (expected, expected):
            raise SystemExit(
                f"{path}: expected {expected}x{expected}, got {actual[0]}x{actual[1]}"
            )
        if not allow_alpha and color_type in (4, 6):
            raise SystemExit(f"{path}: iOS app icons must not include an alpha channel")


source_size = png_info("assets/icon/Win Empire.png")[:2]
if source_size != (1024, 1024):
    raise SystemExit(
        f"assets/icon/Win Empire.png: expected 1024x1024 source art, got {source_size}"
    )

verify_iconset(Path("macos/Runner/Assets.xcassets/AppIcon.appiconset"), allow_alpha=True)
verify_iconset(Path("ios/Runner/Assets.xcassets/AppIcon.appiconset"), allow_alpha=False)
verify_iconset(Path("ios/Runner/Assets.xcassets/CalculatorIcon.appiconset"), allow_alpha=False)

ios_marketing_icon = Path(
    "ios/Runner/Assets.xcassets/AppIcon.appiconset/Icon-App-1024x1024@1x.png"
)
ios_marketing_sha256 = hashlib.sha256(ios_marketing_icon.read_bytes()).hexdigest()
# Owner ruling 2026-10-16 (calculator disguise kept): reviewed iOS marketing icon.
expected_ios_marketing_sha256 = (
    "0b8e4f2a0f9c75ba120bba8d7a034477199a7c6ce757f8368a26bcf3dca51e77"
)
if ios_marketing_sha256 != expected_ios_marketing_sha256:
    raise SystemExit(
        f"{ios_marketing_icon}: expected reviewed marketing icon sha256 "
        f"{expected_ios_marketing_sha256}, got {ios_marketing_sha256}"
    )

calculator_marketing_icon = Path(
    "ios/Runner/Assets.xcassets/CalculatorIcon.appiconset/Calculator-1024.png"
)
calculator_marketing_sha256 = hashlib.sha256(calculator_marketing_icon.read_bytes()).hexdigest()
expected_calculator_marketing_sha256 = (
    "0f99ca6b3165229ff19a2b3f44bfe4dfdcee48fa9eef8297f2beb7ef74376fb2"
)
if calculator_marketing_sha256 != expected_calculator_marketing_sha256:
    raise SystemExit(
        f"{calculator_marketing_icon}: expected calculator alternate icon sha256 "
        f"{expected_calculator_marketing_sha256}, got {calculator_marketing_sha256}"
    )
PY
icon_tmp="$(mktemp -d "${TMPDIR:-/tmp}/wins-appicon.XXXXXX")"
# The brand master since 8567582 (2026-09-29, Guardian red-panda logo); the
# older Win Empire artwork is no longer the shipped icon.
sips -z 1024 1024 "assets/icon/external_launcher.png" --out "${icon_tmp}/app_icon_1024.png" >/dev/null
cmp -s "${icon_tmp}/app_icon_1024.png" macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_1024.png
rm -rf "${icon_tmp}"
test -x tools/ensure_macos_app_icon.sh
grep -q 'Normalize macOS App Icon' macos/Runner.xcodeproj/project.pbxproj
grep -q 'ensure_macos_app_icon.sh' macos/Runner.xcodeproj/project.pbxproj
grep -q 'require_macos_app_icon' tools/apple_runtime_smoke.sh
grep -q 'require_ios_app_icon_asset_catalog' tools/apple_runtime_smoke.sh
grep -q 'compiled iOS AppIcon and CalculatorIcon asset catalogs verified' tools/apple_runtime_smoke.sh
grep -q 'compiled iOS AppIcon marketing digest changed' tools/apple_runtime_smoke.sh
grep -q 'compiled iOS CalculatorIcon marketing digest changed' tools/apple_runtime_smoke.sh
grep -q '3FE5426220052BD3E70D93F319453838AE0F0D9D9D784E6F3662C13B4B227EA8' tools/apple_runtime_smoke.sh
grep -q 'B831D95142B06ECF20BC38BBC9E005AFD4D6BE7DFBE253BF884BFCB004923903' tools/apple_runtime_smoke.sh
grep -q 'compiled macOS AppIcon.icns is incomplete' tools/apple_runtime_smoke.sh
grep -q 'compiled macOS AppIcon.icns 1024 slot does not match' tools/apple_runtime_smoke.sh
grep -q 'refresh_macos_app_registration' tools/apple_runtime_smoke.sh
grep -q 'Refreshing macOS LaunchServices registration' tools/apple_runtime_smoke.sh
grep -q 'lsregister.* -u ' tools/apple_runtime_smoke.sh
grep -q 'pluginkit -a' tools/apple_runtime_smoke.sh
grep -q 'Registered macOS PacketTunnel extension from current signed app' tools/apple_runtime_smoke.sh
grep -q 'open -W -n --env WINS_APPLE_LIVE_TUNNEL_SMOKE=1' tools/apple_runtime_smoke.sh
grep -q 'LaunchServices did not keep the signed macOS app running' tools/apple_runtime_smoke.sh
grep -q 'ENABLE_DEBUG_DYLIB = NO;' macos/Runner.xcodeproj/project.pbxproj
macos_icon_tmp="$(mktemp -d "${TMPDIR:-/tmp}/wins-macos-icon.XXXXXX")"
SRCROOT="${ROOT_DIR}/macos" \
  TARGET_BUILD_DIR="${macos_icon_tmp}/build" \
  UNLOCALIZED_RESOURCES_FOLDER_PATH="Win.app/Contents/Resources" \
  DERIVED_FILE_DIR="${macos_icon_tmp}/derived" \
  tools/ensure_macos_app_icon.sh >/dev/null
iconutil -c iconset "${macos_icon_tmp}/build/Win.app/Contents/Resources/AppIcon.icns" \
  -o "${macos_icon_tmp}/AppIcon.iconset"
for required_macos_icon in \
  icon_16x16.png \
  icon_16x16@2x.png \
  icon_32x32.png \
  icon_32x32@2x.png \
  icon_128x128.png \
  icon_128x128@2x.png \
  icon_256x256.png \
  icon_256x256@2x.png \
  icon_512x512.png \
  icon_512x512@2x.png; do
  test -f "${macos_icon_tmp}/AppIcon.iconset/${required_macos_icon}"
done
sips -s format bmp \
  macos/Runner/Assets.xcassets/AppIcon.appiconset/app_icon_1024.png \
  --out "${macos_icon_tmp}/source.bmp" >/dev/null
sips -s format bmp \
  "${macos_icon_tmp}/AppIcon.iconset/icon_512x512@2x.png" \
  --out "${macos_icon_tmp}/compiled.bmp" >/dev/null
cmp -s "${macos_icon_tmp}/source.bmp" "${macos_icon_tmp}/compiled.bmp"
rm -rf "${macos_icon_tmp}"

}

wins_readiness_section_06_apple_plists_and_entitlements() {
section "Apple Plists And Entitlements"
plutil -lint \
  ios/Runner/Info.plist \
  ios/Runner/Runner.entitlements \
  ios/Runner/PrivacyInfo.xcprivacy \
  ios/PacketTunnel/Info.plist \
  ios/PacketTunnel/PacketTunnel.entitlements \
  ios/PacketTunnel/PrivacyInfo.xcprivacy \
  'ios/WinsWatch Watch App/Info.plist' \
  'ios/WinsWatch Watch App/WinsWatch.entitlements' \
  'ios/WinsWatch Watch App/PrivacyInfo.xcprivacy' \
  macos/Runner/Info.plist \
  macos/Runner/DebugProfile.entitlements \
  macos/Runner/Release.entitlements \
  macos/Runner/PrivacyInfo.xcprivacy \
  macos/PacketTunnel/Info.plist \
  macos/PacketTunnel/PacketTunnel.entitlements \
  macos/PacketTunnel/PrivacyInfo.xcprivacy

}

wins_readiness_section_07_apple_export_options() {
section "Apple Export Options"
plutil -lint \
  apple/ExportOptions/ios-app-store-connect.plist \
  apple/ExportOptions/ios-testflight-internal.plist \
  apple/ExportOptions/ios-app-store-local.plist \
  apple/ExportOptions/ios-debugging-local.plist \
  apple/ExportOptions/ios-release-testing.plist \
  apple/ExportOptions/macos-debugging-local.plist \
  apple/ExportOptions/macos-app-store-connect.plist \
  apple/ExportOptions/macos-developer-id.plist
"${PYTHON_BIN}" - <<'PY'
import plistlib
from pathlib import Path


expected = {
    "apple/ExportOptions/ios-app-store-connect.plist": {
        "destination": "upload",
        "manageAppVersionAndBuildNumber": False,
        "method": "app-store-connect",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "uploadSymbols": True,
    },
    "apple/ExportOptions/ios-testflight-internal.plist": {
        "destination": "upload",
        "manageAppVersionAndBuildNumber": False,
        "method": "app-store-connect",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "testFlightInternalTestingOnly": True,
        "uploadSymbols": True,
    },
    "apple/ExportOptions/ios-app-store-local.plist": {
        "destination": "export",
        "manageAppVersionAndBuildNumber": False,
        "method": "app-store-connect",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "uploadSymbols": False,
    },
    "apple/ExportOptions/ios-debugging-local.plist": {
        "destination": "export",
        "method": "debugging",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "thinning": "<none>",
    },
    "apple/ExportOptions/ios-release-testing.plist": {
        "destination": "export",
        "method": "release-testing",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "thinning": "<none>",
    },
    "apple/ExportOptions/macos-app-store-connect.plist": {
        "destination": "upload",
        "installerSigningCertificate": "3rd Party Mac Developer Installer",
        "manageAppVersionAndBuildNumber": False,
        "method": "app-store-connect",
        "signingCertificate": "Apple Distribution",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "uploadSymbols": True,
    },
    "apple/ExportOptions/macos-app-store-local.plist": {
        "destination": "export",
        "installerSigningCertificate": "3rd Party Mac Developer Installer",
        "manageAppVersionAndBuildNumber": False,
        "method": "app-store-connect",
        "signingCertificate": "Apple Distribution",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
        "uploadSymbols": False,
    },
    "apple/ExportOptions/macos-debugging-local.plist": {
        "destination": "export",
        "method": "debugging",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
    },
    "apple/ExportOptions/macos-developer-id.plist": {
        "destination": "export",
        "installerSigningCertificate": "Developer ID Installer",
        "method": "developer-id",
        "signingCertificate": "Developer ID Application",
        "signingStyle": "automatic",
        "stripSwiftSymbols": True,
        "teamID": "5YT8H4U72M",
    },
}

APPLEDOUBLE_MAGIC = b"\x00\x05\x16\x07"


def is_appledouble_sidecar(path):
    """True only for a PROVED macOS resource-fork sidecar.

    macOS writes `._<name>` beside a real file to carry resource forks and
    extended attributes across a volume that cannot store them. ~62,000 exist
    in this tree, none are tracked (`.gitignore`: `._*`, `**/._*`), nothing in
    any Apple build reads them, and the owner asked on 2026-08-03 that they be
    set aside rather than deleted. `tools/release_dependency_freeze.py` already
    excludes them from the release input set for the same reason.

    This glob enumerated them as ExportOptions templates, so the "changed
    unexpectedly" guard reported 19 plists where 9 exist and failed on every
    run. The guard itself is right and is kept EXACTLY as strict -- what
    changes is that a sidecar no longer counts as a template.

    The exclusion is proved, not assumed. A file is skipped only when a real
    sibling exists beside it AND it carries the AppleDouble magic. Anything
    merely NAMED `._x.plist` stays in the compared set and still trips the
    mismatch, so this cannot become a way to smuggle an unreviewed export
    template past the guard -- which is strictly more than the old glob could
    tell apart.
    """
    if not path.name.startswith("._"):
        return False
    if not path.with_name(path.name[2:]).exists():
        return False
    with path.open("rb") as handle:
        return handle.read(4) == APPLEDOUBLE_MAGIC


export_dir = Path("apple/ExportOptions")
actual_paths = {
    str(path)
    for path in export_dir.glob("*.plist")
    if not is_appledouble_sidecar(path)
}
if actual_paths != set(expected):
    raise SystemExit(
        "Apple ExportOptions plists changed unexpectedly: "
        f"got {sorted(actual_paths)}, expected {sorted(expected)}"
    )

for path_string, fields in expected.items():
    path = Path(path_string)
    with path.open("rb") as handle:
        options = plistlib.load(handle)

    for key, value in fields.items():
        if options.get(key) != value:
            raise SystemExit(f"{path}: {key}={options.get(key)!r}, expected {value!r}")

    for forbidden in ("provisioningProfiles", "manifest", "iCloudContainerEnvironment"):
        if forbidden in options:
            raise SystemExit(f"{path}: do not hard-code {forbidden} in shared export options")

    if "testflight-internal" not in path.name and options.get("testFlightInternalTestingOnly") is True:
        raise SystemExit(f"{path}: internal-only TestFlight flag must stay out of release templates")

    if options.get("destination") == "upload" and options.get("method") != "app-store-connect":
        raise SystemExit(f"{path}: upload destination is only expected for App Store Connect exports")

print("Apple export option templates passed.")
PY
grep -q 'WINS_IOS_RELEASE_TESTING_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'rerun_macos_pkg_install_lane_as_user_if_root' tools/apple_runtime_smoke.sh
grep -q 'Dropping root before Flutter/readiness checks' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_PKG_INSTALL_GUI_AUTH' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY' tools/apple_runtime_smoke.sh
grep -q 'clean-install verification completed without rebuilding or inspecting unrelated exports' tools/apple_runtime_smoke.sh
grep -q 'require_clean_macos_system_install_target' tools/apple_runtime_smoke.sh
grep -q 'requires no existing .* app bundle under /Applications' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_EXISTING_EXPORTS_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY' tools/apple_runtime_smoke.sh
grep -q 'ios_release_testing_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'ios_app_store_local_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'ios_testflight_internal_upload_smoke' tools/apple_runtime_smoke.sh
grep -q 'ios_app_store_connect_upload_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_app_store_local_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_app_store_connect_upload_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_app_store_pkg_install_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_developer_id_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'existing_apple_exports_smoke' tools/apple_runtime_smoke.sh
grep -q 'verify_existing_export_metadata' tools/apple_runtime_smoke.sh
grep -q 'DistributionSummary.plist' tools/apple_runtime_smoke.sh
grep -q 'ExportOptions.plist' tools/apple_runtime_smoke.sh
grep -q 'export metadata' tools/apple_runtime_smoke.sh
grep -q 'Exported existing iOS release-testing app' tools/apple_runtime_smoke.sh
grep -q 'verify_existing_ios_export_ipa' tools/apple_runtime_smoke.sh
grep -q 'verify_ios_ipa_artifact' tools/apple_runtime_smoke.sh
grep -q 'Verified %s IPA payload app' tools/apple_runtime_smoke.sh
grep -q 'verify_existing_macos_export_artifact' tools/apple_runtime_smoke.sh
grep -q 'verify_macos_pkg_artifact' tools/apple_runtime_smoke.sh
grep -q 'extract_macos_pkg_app_for_verification' tools/apple_runtime_smoke.sh
grep -q 'ditto -x --bom' tools/apple_runtime_smoke.sh
grep -q 'pkgutil --expand' tools/apple_runtime_smoke.sh
grep -q 'installer -pkg' tools/apple_runtime_smoke.sh
grep -q 'hdiutil create' tools/apple_runtime_smoke.sh
grep -q 'Installed and verified macOS App Store local package on temporary volume' tools/apple_runtime_smoke.sh
grep -q 'package declares auth=root' tools/apple_runtime_smoke.sh
grep -q 'macos_pkg_install_authorization_mode_for_values' tools/apple_runtime_smoke.sh
grep -q 'expected macOS package install root authorization mode' tools/apple_runtime_smoke.sh
grep -q 'expected macOS package install sudo authorization mode' tools/apple_runtime_smoke.sh
grep -q 'expected macOS package install GUI authorization mode' tools/apple_runtime_smoke.sh
grep -q 'expected macOS package install missing authorization mode' tools/apple_runtime_smoke.sh
grep -q 'run_macos_installer_with_gui_authorization' tools/apple_runtime_smoke.sh
grep -q '/usr/bin/cmp -s' tools/apple_runtime_smoke.sh
grep -q '/usr/sbin/installer -pkginfo -pkg' tools/apple_runtime_smoke.sh
grep -q 'Administrator-safe macOS package copy verified' tools/apple_runtime_smoke.sh
grep -q 'Existing Apple Export Artifact Smoke' tools/apple_runtime_smoke.sh
grep -q 'macos-app-store-local-direct' tools/apple_runtime_smoke.sh
grep -q 'Existing Apple exported artifacts were re-verified without rebuilding or exporting' tools/apple_runtime_smoke.sh
grep -q 'require_macos_developer_id_system_extension_migration_if_requested' tools/apple_runtime_smoke.sh
grep -q 'packet-tunnel-provider-systemextension' tools/apple_runtime_smoke.sh
grep -q 'Mac App Store export lane for the current app-extension build' tools/apple_runtime_smoke.sh
grep -q 'development_profiles=' tools/apple_runtime_smoke.sh
grep -q 'distribution_profiles=' tools/apple_runtime_smoke.sh
grep -q 'distribution_packet_tunnel=' tools/apple_runtime_smoke.sh
grep -q 'release_testing_profiles=' tools/apple_runtime_smoke.sh
grep -q 'iOS release-testing profile readiness' tools/apple_runtime_smoke.sh
grep -q 'require_distribution_profiles_for' tools/apple_runtime_smoke.sh
grep -q 'require_ios_distribution_profiles' tools/apple_runtime_smoke.sh
grep -q 'require_ios_release_testing_profiles' tools/apple_runtime_smoke.sh
grep -q 'iOS release-testing export needs device-scoped release-testing/Ad Hoc Apple Distribution profiles' tools/apple_runtime_smoke.sh
grep -q 'require_macos_distribution_profiles' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_SIGNING_KEYCHAIN_PROBE' tools/apple_runtime_smoke.sh
grep -q 'Apple Signing Keychain Probe' tools/apple_runtime_smoke.sh
grep -q 'probe_codesign_identity_access' tools/apple_runtime_smoke.sh
grep -q 'probe_productbuild_identity_access' tools/apple_runtime_smoke.sh
grep -q 'Apple signing keychain probe timed out' tools/apple_runtime_smoke.sh
grep -q 'Apple installer keychain probe timed out' tools/apple_runtime_smoke.sh
grep -q 'mac_app_store_installer_keychain_probe_needed' tools/apple_runtime_smoke.sh
grep -q 'developer_id_installer_keychain_probe_needed' tools/apple_runtime_smoke.sh
grep -q 'first_identity_matching' tools/apple_runtime_smoke.sh
grep -q '3rd Party Mac Developer Installer' tools/apple_runtime_smoke.sh
grep -q 'Developer ID Installer' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_AUTHENTICATION_KEY_PATH' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_AUTHENTICATION_KEY_ID' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_AUTHENTICATION_KEY_ISSUER_ID' tools/apple_runtime_smoke.sh
grep -q 'configure_apple_xcode_auth_args' tools/apple_runtime_smoke.sh
grep -q 'require_private_apple_auth_key_file' tools/apple_runtime_smoke.sh
grep -q 'run_xcodebuild_with_signing_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'run_xcodebuild_with_export_signing_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'run_xcodebuild_with_ios_ui_automation_diagnostics' tools/apple_runtime_smoke.sh
grep -q '__APPLE_XCODE_AUTH_ARGS__' tools/apple_runtime_smoke.sh
grep -q 'print_redacted_command' tools/apple_runtime_smoke.sh
grep -q 'sanitize_apple_log_output' tools/apple_runtime_smoke.sh
grep -q 'device-udid' tools/apple_runtime_smoke.sh
grep -q 'serialNumber' tools/apple_runtime_smoke.sh
grep -q 'sanitize_apple_log_output' tools/verify_apple_readiness.sh
grep -q 'device-udid' tools/verify_apple_readiness.sh
grep -q 'chmod 600' tools/apple_runtime_smoke.sh
grep -q 'App Store Connect authentication key' tools/apple_runtime_smoke.sh
test -f tools/apple_app_store_connect_auth_probe.py
grep -q 'probe_app_store_connect_upload_auth' tools/apple_runtime_smoke.sh
grep -q 'App Store Connect Authentication Probe' tools/apple_runtime_smoke.sh
grep -q 'api.appstoreconnect.apple.com/v1/apps' tools/apple_app_store_connect_auth_probe.py
grep -q 'must live outside the project' tools/apple_app_store_connect_auth_probe.py
grep -q 'owner-only permissions' tools/apple_app_store_connect_auth_probe.py
grep -q 'HTTP 200' tools/apple_app_store_connect_auth_probe.py
python3 -m py_compile tools/apple_app_store_connect_auth_probe.py
python3 tools/apple_app_store_connect_auth_probe.py --selftest
test -f tools/apple_app_store_connect_release_status.py
grep -q 'wins-vpn-release-status/1' tools/apple_app_store_connect_release_status.py
grep -q 'allow_missing_relationship' tools/apple_app_store_connect_release_status.py
grep -q 'both_platform_builds_processed' tools/apple_app_store_connect_release_status.py
grep -q 'privacy_policy_url_matches' tools/apple_app_store_connect_release_status.py
grep -q -- '--set-privacy-url' tools/apple_app_store_connect_release_status.py
grep -q -- '--confirm-apple-id' tools/apple_app_store_connect_release_status.py
grep -q -- '--sync-review-details' tools/apple_app_store_connect_release_status.py
grep -q 'WINS_APPLE_REVIEW_CONTACT_FIRST_NAME' tools/apple_app_store_connect_release_status.py
grep -q 'demoAccountRequired' tools/apple_app_store_connect_release_status.py
grep -q 'refusing an unexpected mutation target' tools/apple_app_store_connect_release_status.py
grep -q 'refusing an unexpected creation target' tools/apple_app_store_connect_release_status.py
python3 -m py_compile tools/apple_app_store_connect_release_status.py
python3 tools/apple_app_store_connect_release_status.py --selftest
grep -q 'WINS_APPLE_PRIVACY_ARCHIVE_REPORT' tools/apple_runtime_smoke.sh
grep -q 'Apple Archive Privacy Manifest Report' tools/apple_runtime_smoke.sh
grep -q 'archive-privacy-manifests.json' tools/apple_runtime_smoke.sh
grep -q 'local_archive_privacy_manifest_inventory' tools/apple_runtime_smoke.sh
grep -q 'require_archive_manifest_contract' tools/apple_runtime_smoke.sh
grep -q 'archive host privacy manifest' tools/apple_runtime_smoke.sh
grep -q 'archive PacketTunnel privacy manifest' tools/apple_runtime_smoke.sh
# Exercise the current per-framework contract, not an obsolete diagnostic string.
python3 tools/test_apple_privacy_release_gates.py ApplePrivacyReleaseGateTests.test_smoke_archive_framework_contract
grep -q 'physical_ios_active_unlock_blocker_or_empty' tools/apple_runtime_smoke.sh
grep -q 'require_physical_ios_active_unlock_for_launch' tools/apple_runtime_smoke.sh
grep -q 'CoreDevice display backlight is off' tools/apple_runtime_smoke.sh
grep -q 'Physical iOS active unlock is required' tools/apple_runtime_smoke.sh
grep -q 'Create/download distribution profiles' tools/apple_runtime_smoke.sh
grep -q 'return provisioned_devices and not provisions_all_devices' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/ios-release-testing.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/ios-app-store-local.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/ios-testflight-internal.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/ios-app-store-connect.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/macos-app-store-local.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/macos-app-store-connect.plist' tools/apple_runtime_smoke.sh
grep -q 'apple/ExportOptions/macos-developer-id.plist' tools/apple_runtime_smoke.sh
grep -q 'without uploading' tools/apple_runtime_smoke.sh
grep -q 'require_app_store_connect_upload_auth' tools/apple_runtime_smoke.sh
grep -q 'force_archive_privacy_report_for_app_store_upload' tools/apple_runtime_smoke.sh
grep -q 'require_owner_signoff_for_app_store_upload' tools/apple_runtime_smoke.sh
grep -q 'require_valid_apple_submission_package_for_upload' tools/apple_runtime_smoke.sh
grep -q 'App Store Connect upload lanes require a valid Apple submission package' tools/apple_runtime_smoke.sh
test -x tools/apple_upload_exact_release_candidates.py
grep -q 'require_clean_macos_install' tools/apple_upload_exact_release_candidates.py
grep -q 'validate_owner_signoff(ROOT, require_approved=True)' tools/apple_upload_exact_release_candidates.py
grep -q -- '--upload-app' tools/apple_upload_exact_release_candidates.py
python3 -m py_compile tools/apple_upload_exact_release_candidates.py
python3 tools/apple_upload_exact_release_candidates.py --selftest
python3 tools/test_apple_release_candidate_state.py
test -f tools/freeze_apple_release_candidates.py
python3 -m py_compile tools/freeze_apple_release_candidates.py
grep -q 'os.replace(temp_path, manifest_path)' tools/freeze_apple_release_candidates.py
grep -q 'require_archive_export_markers(archive_log)' tools/freeze_apple_release_candidates.py
grep -q 'verification log predates the candidate' tools/freeze_apple_release_candidates.py
grep -q 'fsync_directory(manifest_path.parent)' tools/freeze_apple_release_candidates.py
grep -q 'messages = validate_artifact_manifest(' tools/freeze_apple_release_candidates.py
grep -q 'verified_receipts={"ios": ios_receipt_result, "macos": macos_receipt_result}' tools/freeze_apple_release_candidates.py
grep -q 'tools/build_apple_release_candidates.sh' tools/run_apple_release_candidate_rebuild.applescript
grep -q 'tools/freeze_apple_release_candidates.py' tools/build_apple_release_candidates.sh
grep -q 'WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY=1' tools/build_apple_release_candidates.sh
grep -q -- '--release-input-index "${RELEASE_INDEX}"' tools/build_apple_release_candidates.sh
grep -q -- '--ios-build-receipt "${IOS_RECEIPT}"' tools/build_apple_release_candidates.sh
grep -q -- '--macos-build-receipt "${MACOS_RECEIPT}"' tools/build_apple_release_candidates.sh
# The validated upload status needs current candidates and release-ready store
# metadata, which a rebuild or evidence refresh is about to produce; asking for
# it first made every honest rebuild fail here.
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring exact release-candidate upload dry run until the requested signed evidence refresh completes.\n'
else
  apple_release_upload_status="$(
    "${PYTHON_BIN}" tools/apple_upload_exact_release_candidates.py \
      --print-validated-upload-status
  )"
  if [[ "${apple_release_upload_status}" == "uploaded_processed_and_attached" ]]; then
    printf 'Exact Apple release candidates are already processed and attached; validating the recorded manifest in the submission-package gate.\n'
  else
    python3 tools/apple_upload_exact_release_candidates.py
  fi
fi
test -x tools/apple_upload_exact_screenshots.py
grep -q 'validated_upload_operations' tools/apple_upload_exact_screenshots.py
grep -q 'sourceFileChecksum' tools/apple_upload_exact_screenshots.py
grep -q 'validate_owner_signoff(ROOT, require_approved=True)' tools/apple_upload_exact_screenshots.py
python3 -m py_compile tools/apple_upload_exact_screenshots.py
python3 tools/apple_upload_exact_screenshots.py --selftest
python3 tools/apple_upload_exact_screenshots.py
test -x tools/apple_attach_processed_builds.py
grep -q 'processing_state' tools/apple_attach_processed_builds.py
grep -q 'already selects a different build' tools/apple_attach_processed_builds.py
grep -q 'patch_relationship' tools/apple_attach_processed_builds.py
python3 -m py_compile tools/apple_attach_processed_builds.py
python3 tools/apple_attach_processed_builds.py --selftest
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring processed-build attachment dry run until the requested signed evidence refresh completes.\n'
else
  python3 tools/apple_attach_processed_builds.py
fi
test -x tools/apple_set_all_storefront_availability.py
grep -q 'ALL_175_ACTIVE_STOREFRONTS' tools/apple_set_all_storefront_availability.py
grep -q 'preOrderEnabled' tools/apple_set_all_storefront_availability.py
grep -q 'require_dsa_verified' tools/apple_set_all_storefront_availability.py
python3 -m py_compile tools/apple_set_all_storefront_availability.py
python3 tools/apple_set_all_storefront_availability.py --selftest
python3 tools/apple_set_all_storefront_availability.py
test -x tools/apple_submit_for_app_review.py
grep -q 'EXPECTED_SUBMIT_CONFIRMATION' tools/apple_submit_for_app_review.py
grep -q "APP_VERSION.replace('.', '_')" tools/apple_submit_for_app_review.py
grep -q 'require_build_encryption_declarations' tools/apple_submit_for_app_review.py
grep -q 'non_app_store_version_item_count' tools/apple_submit_for_app_review.py
grep -q 'same-run cleanup completed' tools/apple_submit_for_app_review.py
python3 -m py_compile tools/apple_submit_for_app_review.py
python3 tools/apple_submit_for_app_review.py --selftest
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring App Review submission dry run until the requested signed evidence refresh completes.\n'
else
  python3 tools/apple_submit_for_app_review.py
fi
grep -q 'validate_apple_owner_signoff.py --require-approved' tools/apple_runtime_smoke.sh
grep -q 'REQUIRED_APPROVED_VALUE_MARKERS' tools/validate_apple_owner_signoff.py
grep -q 'missing required marker' tools/validate_apple_owner_signoff.py
grep -q 'owner_packet_approval_values' tools/validate_apple_owner_signoff.py
grep -q 'print-owner-approval-template' tools/validate_apple_owner_signoff.py
grep -q 'dry-run-owner-approval' tools/validate_apple_owner_signoff.py
grep -q 'TemporaryDirectory' tools/validate_apple_owner_signoff.py
grep -q 'validate_owner_review_packet_cross_references' tools/validate_apple_submission_package.py
grep -q '_artifact_bundle_ids' tools/validate_apple_submission_package.py
grep -q 'apple_release_runtime_sources_v2' tools/validate_apple_submission_package.py
grep -q 'Runner.xcodeproj" / "project.pbxproj' tools/validate_apple_submission_package.py
grep -q 'Runner.xcscheme' tools/validate_apple_submission_package.py
refute_match 'predates runtime source' tools/validate_apple_submission_package.py
grep -q 'runtime source fingerprint changed; rebuild the release artifact' tools/validate_apple_submission_package.py
grep -q 'validate_formal_build_receipt_binding' tools/validate_apple_submission_package.py
grep -q 'build_receipt_anchor_sha256' tools/validate_apple_submission_package.py
grep -q 'pkgutil.*--expand-full' tools/validate_apple_submission_package.py
grep -q 'superseded_pending_universal_rebuild' tools/validate_apple_submission_package.py
grep -q 'ios current-candidate live tunnel evidence' tools/validate_apple_submission_package.py
grep -q 'run_selftest' tools/validate_apple_submission_package.py
grep -q 'cross-reference self-test rejects stale evidence text' tools/validate_apple_submission_package.py
grep -q 'screenshot visual sanity self-test rejects blank PNGs' tools/validate_apple_submission_package.py
grep -q 'runtime transition self-test enforces pending and current macOS evidence states' tools/validate_apple_submission_package.py
grep -q 'require_screenshot_visual_sanity' tools/validate_apple_submission_package.py
grep -q 'owner review packet cross-references current metadata' tools/validate_apple_submission_package.py
python3 -m py_compile tools/validate_apple_submission_package.py
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring submission-package integration self-test until the requested evidence refresh completes.\n'
else
  python3 tools/validate_apple_submission_package.py --selftest
fi
grep -q 'expected upload lanes to force the archive privacy report' tools/apple_runtime_smoke.sh
grep -q 'must not force the archive privacy report for local-only exports' tools/apple_runtime_smoke.sh
grep -q 'App Store Connect upload lanes require WINS_APPLE_AUTHENTICATION_KEY_PATH' tools/apple_runtime_smoke.sh
grep -q 'expected missing upload auth rejection' tools/apple_runtime_smoke.sh
grep -q 'expected upload lanes to run the full Apple submission package validator' tools/apple_runtime_smoke.sh
grep -q 'must not classify local export lanes as App Store Connect upload lanes' tools/apple_runtime_smoke.sh
printf 'PASS: upload lanes run the full Apple submission package validator\n'
test -f app_store/apple/review/owner_signoff.json
python3 -m py_compile tools/validate_apple_owner_signoff.py
python3 tools/validate_apple_owner_signoff.py --selftest
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring live owner-signoff cross-reference validation until the requested signed evidence refresh completes.\n'
else
  python3 tools/validate_apple_owner_signoff.py
  python3 tools/validate_apple_owner_signoff.py --print-owner-approval-template | python3 -m json.tool >/dev/null
  python3 tools/validate_apple_owner_signoff.py --dry-run-owner-approval
fi
python3 -m py_compile tools/website_security_audit.py
python3 tools/website_security_audit.py --selftest
python3 tools/website_security_audit.py
grep -q 'audit_apple_public_release_gate' tools/website_security_audit.py
grep -q 'APPLE_DEMO_RELEASE_REQUIREMENTS' tools/website_security_audit.py
grep -q 'Website security self-test passed' tools/website_security_audit.py
grep -q 'MIN_APPLE_DEMO_MP4_BYTES = 700_000' tools/website_security_audit.py
grep -q 'public download/demo links remain gated until matching demo videos exist' tools/website_security_audit.py
grep -q 'winsvpn-ios-demo.mp4' tools/website_security_audit.py
grep -q 'winsvpn-macos-demo.mp4' tools/website_security_audit.py
grep -q 'audit_inline_csp_consistency' tools/website_security_audit.py
grep -q 'inline CSP consistency gate' tools/website_security_audit.py
python3 -m py_compile web/verify_inline_csp.py
python3 web/verify_inline_csp.py
test -s web/assets/demo/winsvpn-ios-demo.mp4
test -s web/assets/demo/winsvpn-ios-demo.webp
test -s web/assets/demo/winsvpn-macos-demo.mp4
test -s web/assets/demo/winsvpn-macos-demo.webp
grep -q 'Matching demo videos exist for each Apple OS before public website download/demo links are enabled' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
python3 -m py_compile tools/apple_profile_manager.py
python3 tools/apple_profile_manager.py --selftest
grep -q 'iOS release-testing profile readiness' tools/apple_profile_manager.py
grep -q 'macOS universal profile readiness' tools/apple_profile_manager.py
grep -q 'macos_readiness_for' tools/apple_profile_manager.py
grep -q 'require-macos' tools/apple_profile_manager.py
grep -q 'device-scoped release-testing profile' tools/apple_profile_manager.py
grep -q 'IOS_PACKET_TUNNEL_BUNDLE_ID' tools/apple_profile_manager.py
grep -q 'packet-tunnel-provider' tools/apple_profile_manager.py
grep -q 'group.org.winsvpn.app' tools/apple_profile_manager.py
grep -q '5YT8H4U72M' tools/apple_profile_manager.py
grep -q 'watch-seconds' tools/apple_profile_manager.py
grep -q 'Timed out after' tools/apple_profile_manager.py
grep -q 'write-macos-development-xcconfig' tools/apple_profile_manager.py
grep -q 'PROVISIONING_PROFILE_SPECIFIER = \$(WINS_PROFILE_\$(TARGET_NAME))' tools/apple_profile_manager.py
grep -q 'macOS development xcconfig must live outside the project folder' tools/apple_profile_manager.py
grep -q 'tools/apple_profile_manager.py --source ~/Downloads --install' apple/ExportOptions/README.md
grep -q 'tools/apple_profile_manager.py --source ~/Downloads --install --watch-seconds 600' apple/ExportOptions/README.md
grep -q 'tools/apple_profile_manager.py --source ~/Downloads --install --require-macos' apple/ExportOptions/README.md
grep -q 'keychain-access-groups' ios/Runner/Runner.entitlements
grep -q 'keychain-access-groups' ios/PacketTunnel/PacketTunnel.entitlements
grep -q 'keychain-access-groups' macos/Runner/DebugProfile.entitlements
grep -q 'keychain-access-groups' macos/Runner/Release.entitlements
grep -q 'keychain-access-groups' macos/PacketTunnel/PacketTunnel.entitlements
grep -q 'org.winsvpn.shared' ios/Runner/Runner.entitlements
grep -q 'org.winsvpn.shared' ios/PacketTunnel/PacketTunnel.entitlements
grep -q 'org.winsvpn.shared' macos/Runner/DebugProfile.entitlements
grep -q 'org.winsvpn.shared' macos/Runner/Release.entitlements
grep -q 'org.winsvpn.shared' macos/PacketTunnel/PacketTunnel.entitlements
grep -q 'WinsAppleSharedKeychainAccessGroup' ios/Runner/Info.plist
grep -q 'WinsAppleSharedKeychainAccessGroup' ios/PacketTunnel/Info.plist
grep -q 'WinsAppleSharedKeychainAccessGroup' macos/Runner/Info.plist
grep -q 'WinsAppleSharedKeychainAccessGroup' macos/PacketTunnel/Info.plist
# Since ee48a2f the iOS plists read the group from WINS_KEYCHAIN_ACCESS_GROUP
# (Debug signs with org.winsvpn.shared.debug), so the literal is no longer in
# them; check the reference and the value in every iOS configuration instead.
grep -Fq '<string>$(WINS_KEYCHAIN_ACCESS_GROUP)</string>' ios/Runner/Info.plist
grep -Fq '<string>$(WINS_KEYCHAIN_ACCESS_GROUP)</string>' ios/PacketTunnel/Info.plist
"${PYTHON_BIN}" - ios/Runner.xcodeproj/project.pbxproj <<'PY'
import re
import sys
from pathlib import Path

PLISTS = ("Runner/Info.plist", "PacketTunnel/Info.plist")
CONFIGURATIONS = ("Debug", "Profile", "Release")
text = Path(sys.argv[1]).read_text(encoding="utf-8")
seen = set()
for match in re.finditer(
    r"/\* (\w+) \*/ = \{\s*isa = XCBuildConfiguration;(.*?)\n\t\t\};", text, re.S
):
    name, body = match.groups()
    plist = re.search(r'INFOPLIST_FILE = "?([^";]+)"?;', body)
    if plist is None or plist.group(1) not in PLISTS:
        continue
    groups = re.findall(r'WINS_KEYCHAIN_ACCESS_GROUP = "([^"]*)";', body)
    expected = "$(AppIdentifierPrefix)org.winsvpn.shared" + (
        ".debug" if name == "Debug" else ""
    )
    if groups != [expected] or (plist.group(1), name) in seen:
        raise SystemExit(
            f"iOS {plist.group(1)} {name}: WINS_KEYCHAIN_ACCESS_GROUP is {groups}, "
            f"expected exactly {expected!r}"
        )
    seen.add((plist.group(1), name))
expected_pairs = {(plist, name) for plist in PLISTS for name in CONFIGURATIONS}
if seen != expected_pairs:
    raise SystemExit(
        f"iOS keychain group configurations {sorted(seen)} != {sorted(expected_pairs)}"
    )
print(
    "iOS keychain access group is $(AppIdentifierPrefix)org.winsvpn.shared in every "
    "Profile and Release configuration and its .debug group in Debug."
)
PY
grep -q '\$(AppIdentifierPrefix)org.winsvpn.shared' macos/Runner/Info.plist
grep -q '\$(AppIdentifierPrefix)org.winsvpn.shared' macos/PacketTunnel/Info.plist
grep -q 'com.apple.security.network.server' macos/PacketTunnel/PacketTunnel.entitlements

}

wins_readiness_section_08_apple_privacy_manifests() {
section "Apple Privacy Manifests"
"${PYTHON_BIN}" - <<'PY'
import plistlib
from pathlib import Path


FILE_TIMESTAMP = "NSPrivacyAccessedAPICategoryFileTimestamp"
USER_DEFAULTS = "NSPrivacyAccessedAPICategoryUserDefaults"
SYSTEM_BOOT_TIME = "NSPrivacyAccessedAPICategorySystemBootTime"
APP_FUNCTIONALITY = "NSPrivacyCollectedDataTypePurposeAppFunctionality"
EXPECTED_HOST_COLLECTED_DATA = {
    "NSPrivacyCollectedDataTypeCoarseLocation",
    "NSPrivacyCollectedDataTypeDeviceID",
    "NSPrivacyCollectedDataTypeUserID",
    "NSPrivacyCollectedDataTypeProductInteraction",
}


def load(path):
    with Path(path).open("rb") as handle:
        return plistlib.load(handle)


def api_reasons(manifest):
    result = {}
    for item in manifest.get("NSPrivacyAccessedAPITypes") or []:
        api_type = item.get("NSPrivacyAccessedAPIType")
        reasons = set(item.get("NSPrivacyAccessedAPITypeReasons") or [])
        if api_type:
            result[api_type] = reasons
    return result


def collected_types(manifest, label):
    result = {}
    for item in manifest.get("NSPrivacyCollectedDataTypes") or []:
        data_type = item.get("NSPrivacyCollectedDataType")
        if not isinstance(data_type, str) or not data_type:
            raise SystemExit(f"{label}: collected data type must be a string")
        if data_type in result:
            raise SystemExit(f"{label}: duplicate collected data type {data_type}")
        result[data_type] = item
    return result


def require_api_reason(path, manifest, api_type, reason):
    reasons = api_reasons(manifest).get(api_type, set())
    if reason not in reasons:
        raise SystemExit(f"{path}: missing privacy reason {reason} for {api_type}")


def require_host_collected_data(path, manifest):
    collected = collected_types(manifest, path)
    expected = set(EXPECTED_HOST_COLLECTED_DATA)
    actual = set(collected)
    if actual != expected:
        raise SystemExit(f"{path}: collected data types {sorted(actual)!r}, expected {sorted(expected)!r}")
    for data_type in sorted(expected):
        item = collected[data_type]
        if item.get("NSPrivacyCollectedDataTypeLinked") is not True:
            raise SystemExit(f"{path}: {data_type} must be marked linked to the user/account")
        if item.get("NSPrivacyCollectedDataTypeTracking") is not False:
            raise SystemExit(f"{path}: {data_type} must not be marked for tracking")
        purposes = set(item.get("NSPrivacyCollectedDataTypePurposes") or [])
        if purposes != {APP_FUNCTIONALITY}:
            raise SystemExit(f"{path}: {data_type} must include app functionality purpose")


def require_no_collection(path, manifest, subject):
    collected = collected_types(manifest, path)
    if collected:
        raise SystemExit(f"{path}: {subject} should not declare collected data: {sorted(collected)!r}")


def verify(path, host, require_file_timestamp=True, subject="extension"):
    manifest = load(path)
    if manifest.get("NSPrivacyTracking") is not False:
        raise SystemExit(f"{path}: NSPrivacyTracking must be false")
    if manifest.get("NSPrivacyTrackingDomains") not in ([], None):
        raise SystemExit(f"{path}: NSPrivacyTrackingDomains must be empty")
    if require_file_timestamp:
        require_api_reason(path, manifest, FILE_TIMESTAMP, "C617.1")
    elif api_reasons(manifest):
        raise SystemExit(f"{path}: must not declare unused required-reason APIs")
    if host:
        require_api_reason(path, manifest, USER_DEFAULTS, "CA92.1")
        require_api_reason(path, manifest, SYSTEM_BOOT_TIME, "35F9.1")
        require_host_collected_data(path, manifest)
    else:
        require_no_collection(path, manifest, subject)


for path, host in [
    ("ios/Runner/PrivacyInfo.xcprivacy", True),
    ("macos/Runner/PrivacyInfo.xcprivacy", True),
    ("ios/PacketTunnel/PrivacyInfo.xcprivacy", False),
    ("macos/PacketTunnel/PrivacyInfo.xcprivacy", False),
]:
    verify(path, host)

verify(
    "ios/WinsWatch Watch App/PrivacyInfo.xcprivacy",
    False,
    require_file_timestamp=False,
    subject="watch companion app",
)
print("Apple privacy manifest contract passed.")
PY

}

wins_readiness_section_09_apple_app_privacy_label_audit() {
section "Apple App Privacy Label Audit"
test -f docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Data Used to Track You: No' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Identifiers: User ID' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Identifiers: Device ID' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Coarse Location: linked to the user for app functionality' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Usage Data: Product Interaction' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Live App Store Connect still omits Product Interaction' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Purchase History: not collected by the Apple app' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'stale live portal declaration must be removed' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'No analytics, ads, or crash-reporting SDK' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'PacketTunnel extension: no separate data collection' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'The archive privacy report lane now fails' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'PacketTunnel extension: no separate data collection' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -qF "Premium Access Info button opens the developer's home page, https://www.winsvpn.org" docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'Generate Xcode privacy report' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
grep -q 'App Store Connect' docs/APPLE_APP_PRIVACY_LABEL_AUDIT.md
# Owner ruling 2026-10-24: the premium button opens exactly the home page.
grep -qF "const String kPremiumAccessHomePageUrl = 'https://www.winsvpn.org';" lib/premium_access_link.dart
grep -qF 'Future<void> _openPremiumAccessHomePage() async {' lib/main.dart
grep -q 'premium access opens the website home page in every build' test/widget_test.dart
grep -q 'flutter_map:' pubspec.yaml
grep -q 'latlong2:' pubspec.yaml
test -f assets/wallpaper/offline_world_map.webp
grep -q 'OfflineWorldMapBackdrop' lib/offline_world_map_backdrop.dart
grep -q 'InteractiveViewer' lib/offline_world_map_backdrop.dart
grep -q 'Image.asset' lib/offline_world_map_backdrop.dart
grep -q 'Natural Earth (public domain)' lib/offline_world_map_backdrop.dart
grep -q 'FORBIDDEN_MAP_RUNTIME_MARKERS' tools/validate_apple_submission_package.py
grep -q '_assert_payload_has_no_forbidden_map_markers' tools/validate_apple_submission_package.py
grep -q "https://www.winsvpn.org" lib/pre_vpn_geo.dart
grep -q "path: '/api/site/geo-scene'" lib/pre_vpn_geo.dart
# The live record flips to the source labels only at release-ready
# (tools/apple_store_listing_metadata.py _require_privacy), which needs current
# candidates; until then that gate requires the recorded stale snapshot, so
# demanding the flipped record here made every honest rebuild fail. A rebuild or
# evidence refresh checks the exact pre-flip record instead; the uploader's
# validate_apple_submission_package.py --release-ready enforces the live match.
# The split follows the Apple Submission Package section: an App Store Connect
# upload lane runs after the flip and validates --release-ready there, so it
# demands the exact live labels here; a plain run pairs with the pre-flip
# validator, so it checks the pre-flip record. The package-root-gate and
# source-readiness refreshes defer that section like the other refreshes, so
# they check the pre-flip record too.
privacy_live_check="recorded-pre-flip"
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" \
  || "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH:-0}" == "1" \
  || "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  privacy_live_check="recorded-pre-flip"
elif [[ "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE:-0}" == "1" \
  || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
  privacy_live_check="exact-live-match"
fi
"${PYTHON_BIN}" - "${privacy_live_check}" <<'PY'
import json
import sys
from pathlib import Path

REQUIRED_LABELS = {
    "Coarse Location",
    "Device ID",
    "User ID",
    "Product Interaction",
}
# The recorded pre-flip portal answers, in the order the listing gate requires.
STALE_LIVE_LABELS = (
    "Coarse Location",
    "User ID",
    "Device ID",
    "Purchase History",
)
check = sys.argv[1]
if check not in {"exact-live-match", "recorded-pre-flip"}:
    raise SystemExit(f"unknown privacy label check {check!r}")

manifest = json.loads(
    Path("app_store/apple/review/privacy_label_manifest.json").read_text(
        encoding="utf-8"
    )
)
live = manifest.get("live_app_store_connect_sync")
if not isinstance(live, dict):
    raise SystemExit(
        "privacy_label_manifest.json live_app_store_connect_sync must be an object"
    )
published = live.get("published_data_types")
if not isinstance(published, list) or not all(
    isinstance(item, str) and item for item in published
):
    raise SystemExit(
        "privacy_label_manifest.json published_data_types must be strings"
    )
if len(published) != len(set(published)):
    raise SystemExit(
        "privacy_label_manifest.json published_data_types must not contain duplicates"
    )
if check == "recorded-pre-flip":
    if (
        live.get("app_store_connect_updated") is not False
        or tuple(published) != STALE_LIVE_LABELS
    ):
        raise SystemExit(
            "privacy_label_manifest.json must keep the recorded stale portal labels "
            "until the release-ready flip; validate_apple_submission_package.py "
            "--release-ready enforces the live match."
        )
    print(
        "Deferring the live App Store Connect privacy label match to the "
        "release-ready flip; the recorded pre-flip snapshot is exact."
    )
    raise SystemExit(0)
published_set = set(published)
if published_set != REQUIRED_LABELS:
    missing = sorted(REQUIRED_LABELS - published_set)
    extra = sorted(published_set - REQUIRED_LABELS)
    parts = ["live App Store Connect privacy labels are stale"]
    if missing:
        parts.append("add " + ", ".join(missing))
    if extra:
        parts.append("remove " + ", ".join(extra))
    raise SystemExit(
        "; ".join(parts)
        + ". This gate does not claim App Store Connect was updated."
    )
print("Live App Store Connect privacy labels match source truth.")
PY
"${PYTHON_BIN}" - <<'PY'
import re
from pathlib import Path

APPLEDOUBLE_MAGIC = b"\x00\x05\x16\x07"


def is_appledouble_sidecar(path):
    """True only for a PROVED macOS resource-fork sidecar. See section 7.

    `lib/._main.dart` and ~150 siblings are AppleDouble metadata, not Dart:
    they are untracked (`.gitignore`: `._*`), never compiled, and carry a
    binary header, so `Path("lib").rglob("*.dart").read_text("utf-8")` died
    here with `UnicodeDecodeError: 0xb0 in position 37` before the forbidden-
    endpoint scan below inspected a single real source file. The scan is right
    to exist; enumerating xattr sidecars as Dart sources is the defect.

    Skipping is conditional on proof -- a real sibling must exist and the
    AppleDouble magic must be present -- so a genuine, unreviewed source file
    named `._x.dart` is NOT skipped. It is reported by name below instead of
    crashing the section with a decoder traceback.
    """
    if not path.name.startswith("._"):
        return False
    if not path.with_name(path.name[2:]).exists():
        return False
    with path.open("rb") as handle:
        return handle.read(4) == APPLEDOUBLE_MAGIC


allowed_osm_source = Path("lib/public_ip_map_backdrop.dart")
source = allowed_osm_source.read_text(encoding="utf-8")
first_party_tile_marker = "https://www.winsvpn.org/api/site/map-tile/"
if source.count(first_party_tile_marker) != 1:
    raise SystemExit(
        "The intentional non-Apple first-party map endpoint must occur exactly once."
    )
direct_osm_marker = "tile.openstreetmap.org"

apple_gate = source.find("if (Platform.isIOS || Platform.isMacOS)")
tile_validation = source.find(
    "if (!PublicIpMapBackdrop.isValidTileUrlTemplate("
)
tile_construction = source.find("FlutterMap(")
if min(apple_gate, tile_validation, tile_construction) < 0:
    raise SystemExit("Shared map source is missing its audited platform boundary.")
if not apple_gate < tile_validation < tile_construction:
    raise SystemExit(
        "Apple MapKit routing must occur before non-Apple tile validation and construction."
    )

scanned_dart = 0
scanned_paths = set()
for path in sorted(Path("lib").rglob("*.dart")):
    if is_appledouble_sidecar(path):
        continue
    if path.name.startswith("._"):
        raise SystemExit(
            f"{path} is named like an AppleDouble sidecar but is not one "
            "(no real sibling, or missing the AppleDouble magic). Real Dart "
            "sources must not use the `._` prefix -- it is gitignored, so this "
            "file would never be reviewed or shipped."
        )
    text = path.read_text(encoding="utf-8")
    scanned_dart += 1
    scanned_paths.add(path)
    if re.search(r"ipapi\.co|ipwho\.is", text, re.IGNORECASE):
        raise SystemExit(f"Direct third-party geolocation endpoint found in {path}.")
    if direct_osm_marker in text.lower():
        raise SystemExit(f"Direct OpenStreetMap tile endpoint found in {path}.")

# Positive control. The scan above is an ABSENCE proof, and an absence proof
# over an empty (or near-empty) file set passes vacuously -- exactly the shape
# of hole that made 77 `! grep -q` guards and 8 `strings | grep` guards in this
# file inert. If a future skip rule ever swallows the real sources the way the
# AppleDouble crash swallowed them, this fails instead of reporting success.
# Measured 2026-08-06: 42 real Dart sources under lib/, plus 24 AppleDouble
# sidecars that are correctly not counted. The floor is an anti-vacuity bound,
# not a census, so it sits well below the real number.
if scanned_dart < 25:
    raise SystemExit(
        f"forbidden-endpoint scan only inspected {scanned_dart} Dart sources "
        "under lib/; that is too few for the result to mean anything."
    )
for required in ("lib/main.dart", "lib/public_ip_map_backdrop.dart"):
    if Path(required) not in scanned_paths:
        raise SystemExit(
            f"forbidden-endpoint scan never inspected {required}; the audit's "
            "own subject was skipped, so its verdict means nothing."
        )

for root in (Path("ios"), Path("macos")):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".swift", ".m", ".mm", ".h"}:
            if is_appledouble_sidecar(path):
                continue
            if direct_osm_marker in path.read_text(encoding="utf-8", errors="ignore").lower():
                raise SystemExit(
                    f"Apple native source must use MapKit, not OpenStreetMap: {path}."
                )

print(
    "Apple native/non-Apple labeled-map boundary passed "
    f"({scanned_dart} Dart sources scanned)."
)
PY
grep -q "Owner: Win's VPN Inc engineering" docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'Apple MapKit' docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'OpenStreetMap Standard raster tiles' docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'Cloudflare speed/metadata service' docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'Non-Apple and no-coordinate real-world map fallback' docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'rendered locally with Flutter' docs/THIRD_PARTY_NOTICES_AND_COMPONENT_INVENTORY.md
grep -q 'all builds render a local real-world map before connection' test/widget_test.dart
grep -q 'WinsAppleMapRegion.region(from: arguments)' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleMapRegion.region(from: arguments)' macos/Runner/MainFlutterWindow.swift
grep -q 'MKCircle(center: requestedRegion.center, radius: requestedRadiusMeters)' ios/Runner/AppDelegate.swift
grep -q 'MKCircle(center: requestedRegion.center, radius: requestedRadiusMeters)' macos/Runner/MainFlutterWindow.swift
grep -q 'rendererFor overlay: MKOverlay' ios/Runner/AppDelegate.swift
grep -q 'rendererFor overlay: MKOverlay' macos/Runner/MainFlutterWindow.swift
grep -q 'MKCircleRenderer(circle: circle)' ios/Runner/AppDelegate.swift
grep -q 'MKCircleRenderer(circle: circle)' macos/Runner/MainFlutterWindow.swift
grep -q 'override func layoutSubviews()' ios/Runner/AppDelegate.swift
grep -q 'override func layout()' macos/Runner/MainFlutterWindow.swift
if grep -Eq '27\.9506|-82\.4572' ios/Runner/AppDelegate.swift macos/Runner/MainFlutterWindow.swift; then
  printf 'Native Apple map must not contain a Tampa-area coordinate fallback.\n' >&2
  exit 1
fi
if grep -q 'PreVpnMapBackdropPainter' lib/main.dart; then
  printf 'Legacy hand-drawn map painter must not remain in the shared app.\n' >&2
  exit 1
fi

grep -q 'kSecUseDataProtectionKeychain' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'guard !isRunningInAppExtension' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'useDataProtectionKeychain: false' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'Data Protection' apple/WinsTunnelCore/WinsTunnelConfig.swift

}

wins_readiness_section_10_apple_packaging_metadata() {
section "Apple Packaging Metadata"
"${PYTHON_BIN}" - <<'PY'
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def load_plist(path):
    with Path(path).open("rb") as handle:
        return plistlib.load(handle)


def expect(value, expected, label):
    if value != expected:
        raise SystemExit(f"{label}: got {value!r}, expected {expected!r}")


ios_runner = load_plist("ios/Runner/Info.plist")
ios_packet = load_plist("ios/PacketTunnel/Info.plist")
watch_app = load_plist("ios/WinsWatch Watch App/Info.plist")
macos_runner = load_plist("macos/Runner/Info.plist")
macos_packet = load_plist("macos/PacketTunnel/Info.plist")
macos_app_info = Path("macos/Runner/Configs/AppInfo.xcconfig").read_text()
macos_project = Path("macos/Runner.xcodeproj/project.pbxproj").read_text()


tracked_signing_identity = None
for signing_line in Path(
    "macos/Runner/Configs/Signing.defaults.xcconfig"
).read_text(encoding="utf-8").splitlines():
    if signing_line.split("=", 1)[0].strip() == "WINS_APPLE_CODE_SIGN_IDENTITY":
        tracked_signing_identity = signing_line.split("=", 1)[1].strip()


def require_release_signing_identity(entitlements_path, label):
    blocks = re.finditer(
        r"\b[A-F0-9]+ /\* [^*]+ \*/ = \{\n(?P<body>.*?)\n\t\t\};",
        macos_project,
        re.S,
    )
    marker = f"CODE_SIGN_ENTITLEMENTS = {entitlements_path};"
    for match in blocks:
        body = match.group("body")
        if (
            "isa = XCBuildConfiguration;" in body
            and "name = Release;" in body
            and marker in body
        ):
            # The Runner configurations sign through $(WINS_APPLE_CODE_SIGN_IDENTITY),
            # whose tracked value lives in Signing.defaults.xcconfig (R11a).
            indirect = (
                'CODE_SIGN_IDENTITY = "$(WINS_APPLE_CODE_SIGN_IDENTITY)";' in body
                and tracked_signing_identity == "Apple Development"
            )
            if 'CODE_SIGN_IDENTITY = "Apple Development";' not in body and not indirect:
                raise SystemExit(
                    f"{label} Release config must sign with Apple Development "
                    "so `flutter build macos --release` can sign entitlement-bearing bundles"
                )
            return
    raise SystemExit(f"{label} Release config with {entitlements_path} was not found")

expect(ios_runner.get("CFBundlePackageType"), "APPL", "iOS Runner package type")

# ---------------------------------------------------------------------------
# iOS app name. Owner ruling 2026-10-25: the iPhone, iPad, and Apple Watch apps
# are named "Win's VPN" (CFBundleName and CFBundleDisplayName), matching the
# macOS app and the App Store record; the PacketTunnel extension is
# "Win's VPN Helper". App Store Connect refused the 1.0.16 (33) upload named
# "Calculator" with ITMS-90129 (the name of Apple's own app). The calculator
# safety screen and the CalculatorIcon alternate icon are unchanged, and the
# VPN profile keeps disguisedTunnelDescription while the disguise is armed.
#
# Known trade-off, accepted by that ruling: iOS has no runtime API to change
# the displayed name (`setAlternateIconName` swaps the IMAGE only), so while
# the safety screen is armed the home screen shows the calculator icon
# captioned "Win's VPN", the mismatch that
# `docs/handoff/CAMOUFLAGE_SURFACE_AUDIT_AND_FIXES_20260806.md` describes.
#
# The two name fields must still agree: CFBundleName is the fallback iOS uses
# in iPhone Storage and some share sheets.
IOS_APP_NAME = "Win's VPN"
expect(ios_runner.get("CFBundleDisplayName"), IOS_APP_NAME, "iOS Runner display name")
expect(ios_runner.get("CFBundleName"), IOS_APP_NAME, "iOS Runner bundle name")
if ios_runner.get("CFBundleDisplayName") != ios_runner.get("CFBundleName"):
    raise SystemExit(
        "iOS CFBundleDisplayName and CFBundleName must be identical."
    )
for key in ("CFBundleDisplayName", "CFBundleName"):
    expect(ios_packet.get(key), f"{IOS_APP_NAME} Helper", f"iOS PacketTunnel {key}")
expect(ios_runner.get("CFBundleShortVersionString"), "$(FLUTTER_BUILD_NAME)", "iOS Runner version name")
expect(ios_runner.get("CFBundleVersion"), "$(FLUTTER_BUILD_NUMBER)", "iOS Runner build number")
expect(macos_runner.get("CFBundleShortVersionString"), "$(FLUTTER_BUILD_NAME)", "macOS Runner version name")
expect(macos_runner.get("CFBundleVersion"), "$(FLUTTER_BUILD_NUMBER)", "macOS Runner build number")
expect(ios_runner.get("UILaunchStoryboardName"), "LaunchScreen", "iOS launch storyboard")
scene_configs = (
    ios_runner.get("UIApplicationSceneManifest", {})
    .get("UISceneConfigurations", {})
    .get("UIWindowSceneSessionRoleApplication", [])
)
if not scene_configs:
    raise SystemExit("iOS Runner is missing UIWindow scene configuration")
expect(
    scene_configs[0].get("UISceneDelegateClassName"),
    "$(PRODUCT_MODULE_NAME).SceneDelegate",
    "iOS scene delegate",
)

expect(watch_app.get("CFBundlePackageType"), "APPL", "watch app package type")
expect(watch_app.get("CFBundleDisplayName"), IOS_APP_NAME, "watch app display name")
expect(watch_app.get("CFBundleName"), IOS_APP_NAME, "watch app bundle name")
expect(watch_app.get("CFBundleShortVersionString"), "$(FLUTTER_BUILD_NAME)", "watch app version name")
expect(watch_app.get("CFBundleVersion"), "$(FLUTTER_BUILD_NUMBER)", "watch app build number")
expect(
    watch_app.get("WKCompanionAppBundleIdentifier"),
    "$(WK_COMPANION_APP_BUNDLE_IDENTIFIER)",
    "watch companion app id",
)
expect(watch_app.get("WKRunsIndependentlyOfCompanionApp"), False, "watch companion-only mode")
for label, plist in (
    ("iOS PacketTunnel", ios_packet),
    ("macOS PacketTunnel", macos_packet),
):
    expect(plist.get("CFBundlePackageType"), "XPC!", f"{label} package type")
    expect(plist.get("CFBundleShortVersionString"), "$(FLUTTER_BUILD_NAME)", f"{label} version name")
    expect(plist.get("CFBundleVersion"), "$(FLUTTER_BUILD_NUMBER)", f"{label} build number")
    extension = plist.get("NSExtension") or {}
    expect(
        extension.get("NSExtensionPointIdentifier"),
        "com.apple.networkextension.packet-tunnel",
        f"{label} extension point",
    )
    expect(
        extension.get("NSExtensionPrincipalClass"),
        "$(PRODUCT_MODULE_NAME).PacketTunnelProvider",
        f"{label} principal class",
    )

expect(macos_runner.get("CFBundlePackageType"), "APPL", "macOS Runner package type")
expect(macos_runner.get("CFBundleDisplayName"), "Win's VPN", "macOS Runner display name")
expect(macos_runner.get("CFBundleName"), "Win's VPN", "macOS Runner bundle name")
expect(macos_runner.get("CFBundleIconFile"), "AppIcon", "macOS Runner icon file")
expect(macos_runner.get("CFBundleIconName"), "AppIcon", "macOS Runner icon name")
expect(macos_runner.get("LSApplicationCategoryType"), "public.app-category.utilities", "macOS app category")
expect(macos_runner.get("LSMinimumSystemVersion"), "$(MACOSX_DEPLOYMENT_TARGET)", "macOS minimum version")
expect(macos_runner.get("NSMainNibFile"), "MainMenu", "macOS main nib")
expect(macos_runner.get("NSPrincipalClass"), "NSApplication", "macOS principal class")
if "PRODUCT_NAME = Win's VPN" not in macos_app_info:
    raise SystemExit("macOS AppInfo.xcconfig must set PRODUCT_NAME = Win's VPN")
require_release_signing_identity(
    "Runner/Release.entitlements",
    "macOS Runner",
)
require_release_signing_identity(
    "PacketTunnel/PacketTunnel.entitlements",
    "macOS PacketTunnel",
)

scheme_expectations = {
    "ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme": "xcode_backend.sh",
    "macos/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme": "macos_assemble.sh",
}
for scheme_path, prepare_script in scheme_expectations.items():
    root = ET.parse(scheme_path).getroot()
    scripts = " ".join(
        content.get("scriptText", "")
        for content in root.findall(".//ActionContent")
    )
    if prepare_script not in scripts or "prepare" not in scripts:
        raise SystemExit(f"{scheme_path} is missing Flutter prepare pre-action")
    expect(
        root.find("./LaunchAction").get("buildConfiguration"),
        "Debug",
        f"{scheme_path} launch configuration",
    )
    expect(
        root.find("./ArchiveAction").get("buildConfiguration"),
        "Release",
        f"{scheme_path} archive configuration",
    )
    buildables = root.findall(".//BuildableReference")
    if not any(buildable.get("BlueprintName") == "Runner" for buildable in buildables):
        raise SystemExit(f"{scheme_path} does not build the Runner target")

for workspace_path in (
    "ios/Runner.xcworkspace/contents.xcworkspacedata",
    "macos/Runner.xcworkspace/contents.xcworkspacedata",
):
    workspace = Path(workspace_path).read_text(encoding="utf-8")
    if "group:Runner.xcodeproj" not in workspace:
        raise SystemExit(f"{workspace_path} does not reference Runner.xcodeproj")

pbx_expectations = {
    "ios/Runner.xcodeproj/project.pbxproj": {
        "IPHONEOS_DEPLOYMENT_TARGET = 15.0;": 6,
        "APPLICATION_EXTENSION_API_ONLY = YES;": 3,
        "SKIP_INSTALL = YES;": 3,
        # Was `"...= org.winsvpn.app.PacketTunnel;": 3` -- one per build
        # configuration. iOS no longer works that way: Debug installs under
        # its own identifier so a dev session cannot destroy the App Store
        # build, so the shipping identifier now appears twice (Release,
        # Profile) and the dev identifier once. Section 16 asserts that exact
        # split, per configuration, by parsing the project properly -- this
        # count contradicted it and was the older of the two. See the exact
        # totals below.
        "PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.PacketTunnel;": 2,
        "PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.debug.PacketTunnel;": 1,
        "-lWinsAmneziaWGPacketEngine": 3,
        "-lWinsXrayVlessWsTransport": 3,
        "EngineArtifacts/ios/iphoneos": 3,
        "EngineArtifacts/ios/iphonesimulator": 3,
    },
    "macos/Runner.xcodeproj/project.pbxproj": {
        "MACOSX_DEPLOYMENT_TARGET = 13.0;": 6,
        "APPLICATION_EXTENSION_API_ONLY = YES;": 3,
        "SKIP_INSTALL = YES;": 3,
        "PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.PacketTunnel;": 3,
        "-lWinsAmneziaWGPacketEngine": 3,
        "-lWinsXrayVlessWsTransport": 3,
        "EngineArtifacts/macos": 3,
        "@executable_path/../../../../Frameworks": 3,
    },
}
for pbx_path, required_counts in pbx_expectations.items():
    text = Path(pbx_path).read_text(encoding="utf-8")
    for needle, minimum in required_counts.items():
        actual = text.count(needle)
        if actual < minimum:
            raise SystemExit(f"{pbx_path} has {actual} occurrences of {needle!r}, expected at least {minimum}")

# Exact totals, because every count above is a FLOOR and a floor cannot detect
# the failure that matters here. "At least 2 release identifiers" is satisfied
# by a project whose Debug configuration has been quietly merged back onto the
# shipping identifier -- which is precisely the cross-contamination the dev/
# release split exists to prevent, and precisely what the previous ">= 3" form
# was asserting as *desirable*. One PacketTunnel identifier per build
# configuration, no more and no fewer, with the dev variant on iOS only.
packet_tunnel_id_totals = {
    "ios/Runner.xcodeproj/project.pbxproj": {
        "org.winsvpn.app.PacketTunnel": 2,
        "org.winsvpn.app.debug.PacketTunnel": 1,
    },
    "macos/Runner.xcodeproj/project.pbxproj": {
        # macOS separates dev from release by App Group, not by bundle id.
        "org.winsvpn.app.PacketTunnel": 3,
        "org.winsvpn.app.debug.PacketTunnel": 0,
    },
}
for pbx_path, totals in packet_tunnel_id_totals.items():
    text = Path(pbx_path).read_text(encoding="utf-8")
    for identifier, expected_count in totals.items():
        needle = f"PRODUCT_BUNDLE_IDENTIFIER = {identifier};"
        actual = text.count(needle)
        if actual != expected_count:
            raise SystemExit(
                f"{pbx_path} has {actual} occurrences of {needle!r}, "
                f"expected exactly {expected_count}"
            )
    total = sum(totals.values())
    if total != 3:
        raise SystemExit(
            f"{pbx_path}: PacketTunnel must carry exactly one bundle "
            f"identifier per build configuration (3), got {total}"
        )
PY

}

wins_readiness_section_11_xcode_project_wiring() {
section "Xcode Project Wiring"
plutil -lint ios/Runner.xcodeproj/project.pbxproj macos/Runner.xcodeproj/project.pbxproj
grep -q 'PacketTunnel.appex' ios/Runner.xcodeproj/project.pbxproj
grep -q 'productType = "com.apple.product-type.app-extension"' ios/Runner.xcodeproj/project.pbxproj
grep -q 'Embed App Extensions' ios/Runner.xcodeproj/project.pbxproj
grep -q 'CODE_SIGN_ENTITLEMENTS = Runner/Runner.entitlements' ios/Runner.xcodeproj/project.pbxproj
grep -q 'CODE_SIGN_ENTITLEMENTS = PacketTunnel/PacketTunnel.entitlements' ios/Runner.xcodeproj/project.pbxproj
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app;' ios/Runner.xcodeproj/project.pbxproj
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.PacketTunnel;' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WinsTunnelConfig.swift' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WinsPacketTunnelEngine.swift' ios/Runner.xcodeproj/project.pbxproj
grep -q 'processContainsLinkedArtifact' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'linkedProcessHandle' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'Stage Apple Engine Artifacts' ios/Runner.xcodeproj/project.pbxproj
grep -q 'stage_apple_engine_artifacts.sh' ios/Runner.xcodeproj/project.pbxproj
grep -q 'PrivacyInfo.xcprivacy in Resources' ios/Runner.xcodeproj/project.pbxproj
grep -q 'Embed Watch Content' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WinsWatch.app in Embed Watch Content' ios/Runner.xcodeproj/project.pbxproj
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.watchkitapp;' ios/Runner.xcodeproj/project.pbxproj
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.debug.watchkitapp;' ios/Runner.xcodeproj/project.pbxproj
refute_match 'WinsWatchExtension|WinsWatch Extension|watchkitapp\.extension|com\.apple\.product-type\.watchkit2-extension' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WK_COMPANION_APP_BUNDLE_IDENTIFIER = org.winsvpn.app.debug;' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WK_COMPANION_APP_BUNDLE_IDENTIFIER = org.winsvpn.app;' ios/Runner.xcodeproj/project.pbxproj
grep -q 'WINS_IOS_APPROVE_VPN_PERMISSION' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_APPROVE_VPN_PERMISSION_BEST_EFFORT' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_VPN_PERMISSION_SETTLE_SECONDS' tools/apple_runtime_smoke.sh
grep -q 'permission-triggering smoke to finish and disconnect' tools/apple_runtime_smoke.sh
grep -q 'RunnerUITests/VpnPermissionUITests/testApprovesVpnConfigurationPermissionIfPresented' tools/apple_runtime_smoke.sh
grep -q 'run_with_ios_ui_automation_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'Timed out while enabling automation mode' tools/apple_runtime_smoke.sh
grep -q 'devicectl_ios_lock_state_report' tools/apple_runtime_smoke.sh
grep -q 'device info lockState' tools/apple_runtime_smoke.sh
grep -q 'physical iOS lock state' tools/apple_runtime_smoke.sh
grep -q 'iOS VPN configuration permission' ios/RunnerUITests/VpnPermissionUITests.swift
grep -q 'Complete Face ID or device-passcode authentication' ios/RunnerUITests/VpnPermissionUITests.swift
grep -q 'authentication window active for 45 seconds' ios/RunnerUITests/VpnPermissionUITests.swift
grep -q 'XCTSkip' ios/RunnerUITests/VpnPermissionUITests.swift
grep -q 'WINS_IOS_APPROVE_VPN_PERMISSION=1 xcrun xcodebuild' tools/apple_runtime_smoke.sh
grep -q -- '-scheme RunnerPermissionUITests' tools/apple_runtime_smoke.sh
grep -q -- '-configuration Profile' tools/apple_runtime_smoke.sh
grep -q 'RunnerPermissionUITests' tools/apple_runtime_smoke.sh
test -f ios/Runner.xcodeproj/xcshareddata/xcschemes/RunnerPermissionUITests.xcscheme
grep -q 'RunnerUITests.xctest' ios/Runner.xcodeproj/xcshareddata/xcschemes/RunnerPermissionUITests.xcscheme
grep -q 'buildConfiguration = "Profile"' ios/Runner.xcodeproj/xcshareddata/xcschemes/RunnerPermissionUITests.xcscheme
grep -q 'key = "WINS_IOS_APPROVE_VPN_PERMISSION"' ios/Runner.xcodeproj/xcshareddata/xcschemes/RunnerPermissionUITests.xcscheme
grep -q 'did not enable XCTest automation mode' tools/apple_runtime_smoke.sh
grep -q 'Continuing physical iOS live tunnel smoke after XCTest automation-mode failure' tools/apple_runtime_smoke.sh
refute_match 'RunnerUITests.xctest' ios/Runner.xcodeproj/xcshareddata/xcschemes/Runner.xcscheme
grep -q '"WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST": "1"' ios/RunnerUITests/VpnPermissionUITests.swift
"${PYTHON_BIN}" - <<'PY'
from pathlib import Path

text = Path("tools/apple_runtime_smoke.sh").read_text(encoding="utf-8")
signed_ios = text.split("signed_ios_build()", 1)[1].split("build_apple_apps()", 1)[0]
permission_helper = text.split("ios_vpn_permission_ui_approval()", 1)[1].split(
    "read_apple_live_tunnel_smoke_status()", 1
)[0]
if "-scheme Runner \\" not in signed_ios:
    raise SystemExit("signed iOS builds must use the Runner scheme")
if "-scheme RunnerPermissionUITests" not in permission_helper:
    raise SystemExit("iOS VPN permission helper must use RunnerPermissionUITests")
if "-configuration Profile" not in permission_helper:
    raise SystemExit("iOS VPN permission helper must use Profile so Flutter can launch outside flutter run")
if "devicectl device install app" in permission_helper:
    raise SystemExit(
        "iOS VPN permission helper must not reinstall the app after approving the system VPN dialog"
    )
PY
grep -q 'Runner/PrivacyInfo.xcprivacy' <(find ios/Runner -maxdepth 1 -name PrivacyInfo.xcprivacy -print)
grep -q 'PacketTunnel/PrivacyInfo.xcprivacy' <(find ios/PacketTunnel -maxdepth 1 -name PrivacyInfo.xcprivacy -print)
grep -q 'WinsWatch Watch App/PrivacyInfo.xcprivacy' <(find 'ios/WinsWatch Watch App' -maxdepth 1 -name PrivacyInfo.xcprivacy -print)
test -f ios/WinsWatchTests/ChannelTests.swift
test ! -e 'ios/WinsWatch Extension'
test ! -e 'ios/WinsWatch Watch App/WKInterfaceControllerCompliance.swift'
python3 tools/test_apple_bundle_version_contract.py
python3 tools/test_apple_standalone_v3_wiring.py
grep -q 'PacketTunnel.appex' macos/Runner.xcodeproj/project.pbxproj
grep -q 'productType = "com.apple.product-type.app-extension"' macos/Runner.xcodeproj/project.pbxproj
grep -q 'Embed App Extensions' macos/Runner.xcodeproj/project.pbxproj
grep -q 'CODE_SIGN_ENTITLEMENTS = PacketTunnel/PacketTunnel.entitlements' macos/Runner.xcodeproj/project.pbxproj
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app' macos/Runner/Configs/AppInfo.xcconfig
grep -q 'PRODUCT_BUNDLE_IDENTIFIER = org.winsvpn.app.PacketTunnel;' macos/Runner.xcodeproj/project.pbxproj
grep -q 'WinsTunnelConfig.swift' macos/Runner.xcodeproj/project.pbxproj
grep -q 'WinsPacketTunnelEngine.swift' macos/Runner.xcodeproj/project.pbxproj
grep -q 'Stage Apple Engine Artifacts' macos/Runner.xcodeproj/project.pbxproj
grep -q 'stage_apple_engine_artifacts.sh' macos/Runner.xcodeproj/project.pbxproj
grep -q 'PrivacyInfo.xcprivacy in Resources' macos/Runner.xcodeproj/project.pbxproj
grep -q 'Runner/PrivacyInfo.xcprivacy' <(find macos/Runner -maxdepth 1 -name PrivacyInfo.xcprivacy -print)
grep -q 'PacketTunnel/PrivacyInfo.xcprivacy' <(find macos/PacketTunnel -maxdepth 1 -name PrivacyInfo.xcprivacy -print)
test -f apple/EngineArtifacts/README.md
test -f tools/stage_apple_engine_artifacts.sh
grep -q 'WINS_STAGE_APPLE_ENGINE_SELFTEST' tools/stage_apple_engine_artifacts.sh
grep -q 'WINS_REQUIRE_APPLE_ENGINE' tools/stage_apple_engine_artifacts.sh
grep -q 'Missing required Apple engine artifacts' tools/stage_apple_engine_artifacts.sh
grep -q 'LC_BUILD_VERSION platform metadata' tools/stage_apple_engine_artifacts.sh
grep -q 'must not contain symbolic links' tools/stage_apple_engine_artifacts.sh
grep -q 'SYMBOL_CONTRACT_VERSION=1' tools/stage_apple_engine_artifacts.sh
grep -q 'component_required_symbols' tools/stage_apple_engine_artifacts.sh
grep -q 'require_component_symbols' tools/stage_apple_engine_artifacts.sh
grep -q 'require_component_dependencies' tools/stage_apple_engine_artifacts.sh
grep -q 'wins_amneziawg_packet_engine_start' tools/stage_apple_engine_artifacts.sh
grep -q 'wins_xray_vless_ws_transport_configure' tools/stage_apple_engine_artifacts.sh
grep -q '@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' tools/stage_apple_engine_artifacts.sh
grep -q 'FRAMEWORKS_FOLDER_PATH' tools/stage_apple_engine_artifacts.sh
grep -q 'containing app, not a nested app extension' tools/stage_apple_engine_artifacts.sh
grep -q "missing required Win's VPN C ABI symbols" tools/stage_apple_engine_artifacts.sh
grep -q 'WinnTunnelCreateWinn3' tools/stage_apple_engine_artifacts.sh
grep -q 'wins_winn_packet_engine_awg_seam_port' tools/stage_apple_engine_artifacts.sh
grep -q 'symbol_contract_version' tools/stage_apple_engine_artifacts.sh
grep -q 'Apple engine artifact staging skipped missing components' tools/stage_apple_engine_artifacts.sh
grep -q 'did not skip missing engines on unsigned dry-run' tools/stage_apple_engine_artifacts.sh
grep -q 'IOS_DEBUG_BUNDLE_ID' tools/apple_runtime_smoke.sh
grep -q 'WatchSimulator' tools/apple_runtime_smoke.sh
grep -q 'WATCHSIMULATOR' tools/apple_runtime_smoke.sh
grep -q 'WK_COMPANION_APP_BUNDLE_IDENTIFIER' 'ios/WinsWatch Watch App/Info.plist'
test -f tools/build_apple_wg_go_bridge.sh
bash -n tools/build_apple_wg_go_bridge.sh
test -f tools/apple_release_symbol_custody.py
python3 -m py_compile tools/apple_release_symbol_custody.py tools/test_apple_release_hardening.py
python3 tools/apple_release_symbol_custody.py self-test
python3 tools/test_apple_release_hardening.py
grep -q 'AMNEZIAWG_APPLE_TAG="v3.1.20260814"' tools/build_apple_wg_go_bridge.sh
grep -q 'AMNEZIAWG_APPLE_COMMIT="fe2e2d7ebb835a0a2ad1d8de75094a6de134da4d"' tools/build_apple_wg_go_bridge.sh
grep -q 'AMNEZIAWG_APPLE_TREE="24183de0cc22b957ff9e34ac3494a80f515ac565"' tools/build_apple_wg_go_bridge.sh
grep -q 'AMNEZIAWG_APPLE_GENERATION="3.1"' tools/build_apple_wg_go_bridge.sh
grep -q 'REVIEWED_GO_VERSION="1.27.1"' tools/build_apple_wg_go_bridge.sh
grep -q 'APPLE_WG_GO_PROVENANCE_FILE' tools/build_apple_wg_go_bridge.sh
grep -q 'LibXrayRunXray' tools/build_apple_wg_go_bridge.sh
grep -q 'LibXraySetSockCallback' tools/build_apple_wg_go_bridge.sh
grep -q 'validate_platform' tools/build_apple_wg_go_bridge.sh
grep -q 'IOSSIMULATOR' tools/build_apple_wg_go_bridge.sh
grep -q 'GOOS_iphonesimulator=ios' tools/build_apple_wg_go_bridge.sh
grep -q 'validate_simulator_cgo_helpers' tools/build_apple_wg_go_bridge.sh
grep -q 'platform_archs' tools/build_apple_wg_go_bridge.sh
grep -q 'arm64 x86_64' tools/build_apple_wg_go_bridge.sh
test -f tools/build_apple_engine_wrappers.sh
bash -n tools/build_apple_engine_wrappers.sh
grep -q 'WINS_SKIP_APPLE_WG_GO_BUILD' tools/build_apple_engine_wrappers.sh
grep -q 'WinsAmneziaWGPacketEngine.m' tools/build_apple_engine_wrappers.sh
grep -q 'WinsXrayVlessWsTransport.m' tools/build_apple_engine_wrappers.sh
grep -q 'force_load' tools/build_apple_engine_wrappers.sh
grep -q '@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' tools/build_apple_engine_wrappers.sh
grep -q 'LibXrayRunXray' tools/build_apple_engine_wrappers.sh
grep -q 'LibXraySetSockCallback' tools/build_apple_engine_wrappers.sh
grep -q 'require_symbols' tools/build_apple_engine_wrappers.sh
grep -q 'platform_archs' tools/build_apple_engine_wrappers.sh
# Universal-binary creation must go through the ONCE-resolved lipo, not a bare
# `lipo` re-resolved at the call site. This guard used to read
# `grep -q 'lipo -create'`, which the toolchain-resolution hardening broke by
# doing exactly what this same section demands elsewhere: every bare tool name
# in that script became "${TOOL_BIN}", so the literal it looked for is gone
# while the behaviour it stands for is stronger than before. Two guards in one
# section contradicting each other; this is the stale one.
grep -qF '"${LIPO_BIN}" -create -output' tools/build_apple_engine_wrappers.sh
test -f apple/EngineWrappers/WinsAmneziaWGPacketEngine.m
test -f apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'com.apple.net.utun_control' apple/EngineWrappers/WinsAmneziaWGPacketEngine.m
grep -q 'wgTurnOn' apple/EngineWrappers/WinsAmneziaWGPacketEngine.m
grep -q 'wgTurnOff' apple/EngineWrappers/WinsAmneziaWGPacketEngine.m
grep -q 'wins_amneziawg_packet_engine_start' apple/EngineWrappers/WinsAmneziaWGPacketEngine.m
grep -q 'LibXrayRunXray' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q '@"protocol": @"tunnel"' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q '@"network": @"udp"' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q '@"address": remote_awg_host' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q '@"port": remote_awg_port' apple/EngineWrappers/WinsXrayVlessWsTransport.m
refute_match -E 'allowedNetwork|rewriteAddress|rewritePort' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'vless-ws-out' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'wins_xray_required_string_value' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'wins_xray_required_port_value' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'wins_xray_valid_host_name_or_address' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'initWithUUIDString' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'config == nil' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'wins_xray_vless_ws_transport_start' apple/EngineWrappers/WinsXrayVlessWsTransport.m
grep -q 'build_apple_engine_wrappers.sh' apple/EngineArtifacts/README.md
grep -q 'wins_amneziawg_packet_engine_start' apple/EngineArtifacts/README.md
grep -q 'wins_xray_vless_ws_transport_configure' apple/EngineArtifacts/README.md

}

wins_readiness_section_12_apple_tunnel_config_parser() {
section "Apple Tunnel Config Parser"
CONFIG_TMP="$(mktemp -d)"
# Cleanup is handled once by wins_readiness_on_exit (installed near the top),
# which removes every temp dir and always reports deferred failures.
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  tools/verify_apple_tunnel_config.swift \
  -o "${CONFIG_TMP}/verify_apple_tunnel_config"
"${CONFIG_TMP}/verify_apple_tunnel_config"

}

wins_readiness_section_13_packet_tunnel_swift_type_checks() {
section "Packet Tunnel Swift Type Checks"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck "${WINS_TUNNEL_CORE_SOURCES[@]}" ios/PacketTunnel/PacketTunnelProvider.swift
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck "${WINS_TUNNEL_CORE_SOURCES[@]}" macos/PacketTunnel/PacketTunnelProvider.swift
# The DEV-ONLY containment branch lives inside `#if DEBUG`, so the check above --
# which compiles the Release shape -- never sees it. Type-check the Debug shape
# too, or the one path that exists to stop a dev session blackholing the host
# would be the one path nothing compiles.
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck -D DEBUG "${WINS_TUNNEL_CORE_SOURCES[@]}" macos/PacketTunnel/PacketTunnelProvider.swift

}

wins_readiness_section_14_packet_tunnel_dev_containment_gate() {
section "Packet Tunnel Dev Containment Gate"
# THE GATE. Containment must be reachable ONLY from a Debug appex carrying an
# explicit marker. These greps pin the two halves in the source, so a future
# edit that widens either one fails here rather than in production.
#
# 2026-08-11: macOS no longer has dev containment; it is iOS-only by design.
# The mac provider now uses the staged winn/3 proof and kill-switch instead.
# This gate validates the new design when the old containment is absent.
if grep -q 'Dev containment is an iOS-provider construct' macos/PacketTunnel/PacketTunnelProvider.swift; then
  printf 'macOS dev containment correctly absent (iOS-only by design); staged proof and kill-switch active.
'
  grep -q 'WinsWinnDatapathProofGate' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'WinsKillSwitch' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'makeWinnStagedStartPlan' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'winnDatapathProofPromotionHeld' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'winn_datapath_proof_hold' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'config.appleIncludedIPv4Routes' macos/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'winn_memory_gate_macos_unknown_headroom_allowed' macos/PacketTunnel/PacketTunnelProvider.swift
  refute_match 'makeContainedDevNetworkSettings' macos/PacketTunnel/PacketTunnelProvider.swift
  refute_match 'if containmentPlan.requested' macos/PacketTunnel/PacketTunnelProvider.swift
  refute_match 'return NEIPv4Route.default\(\)' macos/PacketTunnel/PacketTunnelProvider.swift
  refute_match 'winn_memory_gate_macos_unknown_headroom_allowed' ios/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'return "appex_available_memory_unknown"' ios/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'makeContainedDevNetworkSettings' ios/PacketTunnel/PacketTunnelProvider.swift
  grep -q 'releaseTunnelNetworkSettings(context: "stop_tunnel")' ios/PacketTunnel/PacketTunnelProvider.swift
  grep -q '!devContainmentActive' apple/WinsTunnelCore/WinsTunnelConfig.swift
  grep -q 'provider_dev_containment_active' macos/Runner/MainFlutterWindow.swift
  grep -q 'kWinnDevSessionContainmentSection' lib/winn_protocol_dev_session.dart
  refute_match 'WinsDevContainment' lib/main.dart
  printf 'macOS containment absence validated.
'
  return 0
fi
# 1. The marker is required: the contained branch is entered only when the
#    parsed config asks for it.
grep -q 'if containmentPlan.requested {' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'return try makeContainedDevNetworkSettings(from: config, plan: containmentPlan)' macos/PacketTunnel/PacketTunnelProvider.swift
# 2. That call site, the contained settings builder, and the absence probe are
#    ALL inside `#if DEBUG`. Exactly two `#if DEBUG` blocks, exactly two `#endif`.
[ "$(grep -cE '^ *#if DEBUG$' macos/PacketTunnel/PacketTunnelProvider.swift)" = "2" ]
[ "$(grep -cE '^ *#endif$' macos/PacketTunnel/PacketTunnelProvider.swift)" = "2" ]
# No other conditional compilation shape may guard containment -- an `#if !DEBUG`
# or a `#if DEBUG || SOMETHING` would quietly widen the gate.
[ "$(grep -cE '^ *#if ' macos/PacketTunnel/PacketTunnelProvider.swift)" = "2" ]
grep -q 'WINS_DEV_CONTAINMENT_ABSENCE_PROBE_7b21e4c6' macos/PacketTunnel/PacketTunnelProvider.swift
# 3. The Xcode project defines DEBUG for the Debug configuration only. The
#    PacketTunnel target sets no SWIFT_ACTIVE_COMPILATION_CONDITIONS of its own,
#    so it inherits that single project-level definition and Release/Profile
#    compile the containment path out entirely.
[ "$(grep -c 'SWIFT_ACTIVE_COMPILATION_CONDITIONS' macos/Runner.xcodeproj/project.pbxproj)" = "1" ]
grep -q 'SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG;' macos/Runner.xcodeproj/project.pbxproj
# 4. Contained settings install no default route, no IPv6 and no DNS.
grep -q 'settings.ipv6Settings deliberately left nil' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'settings.dnsSettings deliberately left nil' macos/PacketTunnel/PacketTunnelProvider.swift
# 5. Production full-tunnel leak protection is untouched: the shipping branch
#    still installs the default route, the IPv6 sink and full-tunnel DNS.
grep -q 'return NEIPv4Route.default()' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'ipv6Settings.includedRoutes = \[NEIPv6Route.default()\]' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'dnsSettings.matchDomains = config.dnsMatchDomains' macos/PacketTunnel/PacketTunnelProvider.swift
# 6. A contained session can never report a passing full-tunnel posture.
grep -q '!devContainmentActive' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'provider_dev_containment_active' macos/Runner/MainFlutterWindow.swift
# 7. The only writer of the marker is the dev-only Dart path, which a release
#    Flutter build does not compile at all, and lib/main.dart must never emit it.
grep -q 'kWinnDevSessionContainmentSection' lib/winn_protocol_dev_session.dart
refute_match 'WinsDevContainment' lib/main.dart
# 8. The provider hands the host's routing/IPv6/DNS back on stop rather than
#    relying on process teardown to reclaim them -- and RECORDS what the system
#    answered rather than assuming it worked. Measured 2026-08-06 on macOS 26.6:
#    the answer is a refusal (NEAgentErrorDomain code 1), because the session is
#    already in NESMVPNSessionStateStopping before stopTunnel is even entered.
grep -q 'setTunnelNetworkSettings(nil)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'releaseTunnelNetworkSettings($' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'then: completionHandler$' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'private func writeNetworkSettingsReleaseStatus(' macos/PacketTunnel/PacketTunnelProvider.swift
#    The redacted failure message says "See provider_error_domain and
#    provider_error_code", which the host maps from the status document's
#    error_domain/error_code. Those are written ONLY if the release path passes
#    its error to writeProviderStatus. A release path that merely os_logs points
#    a reader at fields nothing writes -- the defect this replaced.
awk '/private func writeNetworkSettingsReleaseStatus\(/,/^  \}$/' \
  macos/PacketTunnel/PacketTunnelProvider.swift \
  | awk '/writeProviderStatus\(/,0' \
  | grep -q 'error: releaseError,'
grep -q 'outcome: releaseError == nil ? .released : .failed,' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'outcome: .deadline,' macos/PacketTunnel/PacketTunnelProvider.swift
#    A rejection and a deadline expiry demand different fixes, so a compacted
#    status write must not be able to drop the fields that tell them apart.
COMPACT_EXTRA_KEYS="$(awk '/private static let compactExtraKeys: Set<String> = \[/,/^  \]$/' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift)"
for release_key in \
  network_settings_release_requested \
  network_settings_release_outcome \
  network_settings_release_completed \
  network_settings_release_failed \
  network_settings_release_elapsed_ms \
  network_settings_release_deadline_ms \
  network_settings_release_error_domain \
  network_settings_release_error_code \
  dev_containment_at_stop; do
  if ! printf '%s\n' "${COMPACT_EXTRA_KEYS}" | grep -q "\"${release_key}\","; then
    printf 'FATAL: %s is missing from compactExtraKeys; a compacted stop status would drop it.\n' \
      "${release_key}" >&2
    exit 1
  fi
done
# 9. The TERMINAL document says whether the run was contained. It is the artifact
#    a reviewer actually reads, and an uncontained session on this codebase
#    blackholed a machine, so "was this run contained?" must be answerable from
#    it. The stop path carries the dev_containment_* fields through under their
#    own names -- NOT renamed to previous_*_before_stop, which would switch off
#    the leak-protection check that reads dev_containment_active.
grep -q 'WinsDevContainmentStopCarry.fields(' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectedStatusGeneration: statusGeneration' macos/PacketTunnel/PacketTunnelProvider.swift
#    NOTE the shape of this negative check. `! grep -q ... ` does NOT abort under
#    `set -e` -- bash exempts any command whose status is inverted with `!` -- so
#    every `! grep` guard in this file is currently unable to fail. Verified:
#      bash -c 'set -Eeuo pipefail; ! grep -q root /etc/passwd; echo REACHED'
#    prints REACHED. Written as an explicit if/exit so this one can.
if grep -q 'previous_dev_containment' macos/PacketTunnel/PacketTunnelProvider.swift; then
  printf 'FATAL: containment was renamed to previous_*_before_stop instead of carried; the leak-protection check reads dev_containment_active and would stop seeing it on the terminal document.\n' >&2
  exit 1
fi
#    Absence must never be the answer. An unreadable previous document returns
#    the tri-state marker rather than an empty dictionary, so "not contained" and
#    "cannot tell" stay distinguishable from each other and from a build that
#    never carried the fields at all.
awk '/private func previousProviderStatusFieldsBeforeStop\(/,/^  \}$/' \
  macos/PacketTunnel/PacketTunnelProvider.swift \
  | grep -q 'return WinsDevContainmentStopCarry.fields(previousStatus: nil)'
if awk '/private func previousProviderStatusFieldsBeforeStop\(/,/^  \}$/' \
  macos/PacketTunnel/PacketTunnelProvider.swift | grep -qE '^ *return \[:\]$'; then
  printf 'FATAL: the stop path can still return an empty field set, so a terminal status document can go silent about containment.\n' >&2
  exit 1
fi
# 10. The containment claim is MEASURED off the settings object that was built,
#     not derived from the plan -- and the measurement reaches the app.
#     Added 2026-08-06 (containment observability lane).
#
#     Until then macOS published intent fields only. The consequence was not
#     theoretical. The dev traffic harness re-confirms containment from the
#     provider readback before it will send a packet, and it requires the
#     `_observed_` fields specifically -- deliberately, because an intent field
#     cannot detect a settings builder that widened. macOS emitted none of them,
#     so the harness read null and refused to send on EVERY contained macOS
#     session, while reporting `observed_contained=false
#     included_route_count=null` -- which reads as "containment failed" but
#     actually meant "nothing measured it". These greps are what stop that
#     from silently coming back.
grep -q 'let observation = WinsDevContainmentObservation(settings: settings)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'guard observation.isContained else {' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'provider_dev_containment_observed_contained' macos/Runner/MainFlutterWindow.swift
#     The read-back must be able to FAIL. An `isContained` that cannot return
#     false is a stamp wearing a measurement's name.
grep -q 'includedRoutePrefixLengths == \[32\]' macos/PacketTunnel/PacketTunnelProvider.swift

}

wins_readiness_section_15_packet_tunnel_dev_containment_release_absence_compiled_proof() {
section "Packet Tunnel Dev Containment Release Absence (compiled proof)"
# 2026-08-11: macOS containment is iOS-only; skip compiled proof when absent.
if grep -q 'Dev containment is an iOS-provider construct' macos/PacketTunnel/PacketTunnelProvider.swift; then
  printf 'macOS containment absence probe not applicable (iOS-only); skipping compiled proof.
'
  return 0
fi
# THE CLAIM, COMPILED AND MEASURED RATHER THAN DOCUMENTED.
#
# Everything above is source inspection. It proves the containment path is
# written behind `#if DEBUG`, but not that a Release compile actually drops it.
# The greps also cannot catch the failure mode that matters most: someone adding
# a target-level `SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG` to the PacketTunnel
# target's Release configuration would make containment reachable in a shipped
# appex with every assertion above still passing.
#
# So compile the REAL provider source twice -- once in each build shape -- and
# check the absence probe with strings(1). Release must not contain it. Debug
# must. A build shape that ever inverts this fails here, loudly, before anything
# reaches a user in Myanmar.
CONTAINMENT_TMP="$(mktemp -d)"
# Cleanup is handled once by wins_readiness_on_exit (installed near the top),
# which removes every temp dir and always reports deferred failures.
cat > "${CONTAINMENT_TMP}/containment_probe_main.swift" <<'SWIFT'
import Foundation
@main
struct WinsContainmentProbeMain {
  static func main() { print("containment probe") }
}
SWIFT
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -O "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  macos/PacketTunnel/PacketTunnelProvider.swift \
  "${CONTAINMENT_TMP}/containment_probe_main.swift" \
  -o "${CONTAINMENT_TMP}/appex_release_shape"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -O -D DEBUG "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  macos/PacketTunnel/PacketTunnelProvider.swift \
  "${CONTAINMENT_TMP}/containment_probe_main.swift" \
  -o "${CONTAINMENT_TMP}/appex_debug_shape"

# Release: the probe, the contained log line and the contained builder are all
# absent. If any of these ever appears, a shipped appex can contain a session.
if wins_binary_contains "${CONTAINMENT_TMP}/appex_release_shape" 'WINS_DEV_CONTAINMENT_ABSENCE_PROBE_7b21e4c6'; then
  printf 'FATAL: the dev containment absence probe is present in a RELEASE-shaped Packet Tunnel binary.\n' >&2
  printf '       A shipped appex could enter contained mode. Check for a target-level\n' >&2
  printf '       SWIFT_ACTIVE_COMPILATION_CONDITIONS override in macos/Runner.xcodeproj.\n' >&2
  exit 1
fi
if wins_binary_contains "${CONTAINMENT_TMP}/appex_release_shape" 'CONTAINED dev packet tunnel'; then
  printf 'FATAL: the contained-session log line is present in a RELEASE-shaped Packet Tunnel binary.\n' >&2
  exit 1
fi
# The containment READ-BACK is dev-only too (added 2026-08-06). Note the string
# chosen: `dev_containment_observed_contained` also appears in
# WinsPacketTunnelEngine.compactExtraKeys, which is NOT dev-only, so grepping
# for it would match a Release binary and this check would fail forever for the
# wrong reason. `..._included_route_prefix_lengths` is emitted only by the
# provider's observation, so it is the string that actually discriminates.
if wins_binary_contains "${CONTAINMENT_TMP}/appex_release_shape" 'dev_containment_observed_included_route_prefix_lengths'; then
  printf 'FATAL: the dev containment read-back is present in a RELEASE-shaped Packet Tunnel binary.\n' >&2
  exit 1
fi

# Debug: the probe IS there. Without this half the check above would also pass
# if the probe string were simply deleted, which would prove nothing.
if ! wins_binary_contains "${CONTAINMENT_TMP}/appex_debug_shape" 'WINS_DEV_CONTAINMENT_ABSENCE_PROBE_7b21e4c6'; then
  printf 'FATAL: the dev containment absence probe is missing from a DEBUG-shaped Packet Tunnel binary.\n' >&2
  printf '       The release-absence check above is therefore vacuous.\n' >&2
  exit 1
fi
if ! wins_binary_contains "${CONTAINMENT_TMP}/appex_debug_shape" 'CONTAINED dev packet tunnel'; then
  printf 'FATAL: the contained-session log line is missing from a DEBUG-shaped Packet Tunnel binary.\n' >&2
  exit 1
fi

}

wins_readiness_section_16_ios_packet_tunnel_dev_containment_gate() {
section "iOS Packet Tunnel Dev Containment Gate"
# The iOS half, added 2026-08-06. iOS is NOT a copy of the macOS gate above, and
# the differences are the point -- see each numbered check.
#
# The Debug shape has to be type-checked explicitly, exactly as macOS does, or
# the one path that exists to stop a dev session blackholing a PHONE would be
# the one path nothing compiles.
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck -D DEBUG "${WINS_TUNNEL_CORE_SOURCES[@]}" ios/PacketTunnel/PacketTunnelProvider.swift

# 1. The marker is READ unconditionally, and the contained branch needs it.
grep -q 'let containmentPlan = config.devContainmentPlan' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'if containmentPlan.requested {' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'return try makeContainedDevNetworkSettings(from: config, plan: containmentPlan)' ios/PacketTunnel/PacketTunnelProvider.swift

# 2. FAIL CLOSED -- the difference from macOS that matters most.
#    On macOS the whole `requested` test sits inside `#if DEBUG`, so a Release
#    appex ignores the marker and starts a full tunnel. On iOS the test is
#    OUTSIDE `#if DEBUG` and the non-Debug arm THROWS. There is no build shape
#    of the iOS provider in which a config that asked to be contained silently
#    gets a full tunnel. If this assertion ever fails, that guarantee is gone.
"${PYTHON_BIN}" - <<'PY'
import re, sys
src = open('ios/PacketTunnel/PacketTunnelProvider.swift', encoding='utf-8').read()
m = re.search(
    r'let containmentPlan = config\.devContainmentPlan\n'
    r'\s*if containmentPlan\.requested \{\n'
    r'\s*#if DEBUG\n'
    r'\s*return try makeContainedDevNetworkSettings\(from: config, plan: containmentPlan\)\n'
    r'\s*#else\n'
    r'\s*throw Self\.providerError\(',
    src,
)
if not m:
    sys.stderr.write(
        'FATAL: the iOS containment branch is not in the required fail-closed shape.\n'
        '       Required: `if containmentPlan.requested` OUTSIDE #if DEBUG, with the\n'
        '       non-Debug arm THROWING. Without it a build that lacks the DEBUG\n'
        '       compilation condition would silently start a FULL TUNNEL on a phone\n'
        '       for a config that asked to be contained.\n')
    raise SystemExit(1)
print('iOS containment branch is fail-closed.')
PY

# 3. THE BUILD SETTING, CHECKED STRUCTURALLY RATHER THAN BY grep -c.
#    macOS can assert "SWIFT_ACTIVE_COMPILATION_CONDITIONS appears exactly once"
#    because it is set once, at PBXProject level. iOS cannot: the string also
#    appears on the RunnerTests and RunnerUITests targets, and it appeared there
#    BEFORE this lane -- while the PacketTunnel target had none, so `#if DEBUG`
#    in the iOS appex was false even in a Debug build. A naive grep would have
#    reported that state as healthy. So parse the project and assert per target
#    and per configuration.
"${PYTHON_BIN}" - <<'PY'
import re, sys

src = open('ios/Runner.xcodeproj/project.pbxproj', encoding='utf-8').read()

blocks = {}
for m in re.finditer(
    r'\n\t\t([0-9A-F]{24}) /\* (\w+) \*/ = \{\n\t\t\tisa = XCBuildConfiguration;(.*?)\n\t\t\};',
    src, re.S):
    blocks[m.group(1)] = (m.group(2), m.group(3))

target_configs = {}
for m in re.finditer(
    r'\n\t\t[0-9A-F]{24} /\* Build configuration list for (\w+) "(.*?)" \*/ = \{\n'
    r'\t\t\tisa = XCConfigurationList;\n\t\t\tbuildConfigurations = \((.*?)\);',
    src, re.S):
    target_configs[(m.group(1), m.group(2))] = re.findall(
        r'([0-9A-F]{24}) /\* (\w+) \*/', m.group(3))

def sacc(cfg_id):
    _, body = blocks.get(cfg_id, ('', ''))
    m = re.search(r'SWIFT_ACTIVE_COMPILATION_CONDITIONS = (.*?);', body)
    return m.group(1) if m else None

def setting(cfg_id, name):
    _, body = blocks.get(cfg_id, ('', ''))
    m = re.search(re.escape(name) + r' = (.*?);', body)
    return m.group(1) if m else None

failed = False

# BOTH iOS targets must agree about DEBUG. `WinsAppleAppGroup.identifier` picks
# the dev App Group under `#elseif DEBUG`, and it is compiled into the app AND
# the appex. If only one target defined DEBUG they would use DIFFERENT App Group
# containers, the app would never find the provider's status document, and the
# failure would look like "the provider never started" rather than like a build
# misconfiguration.
for target in ('Runner', 'PacketTunnel'):
    key = ('PBXNativeTarget', target)
    if key not in target_configs:
        sys.stderr.write('FATAL: no %s target found in ios/Runner.xcodeproj.\n' % target)
        raise SystemExit(1)
    for cfg_id, cfg_name in target_configs[key]:
        value = sacc(cfg_id)
        if cfg_name == 'Debug':
            if value != 'DEBUG':
                sys.stderr.write(
                    'FATAL: the iOS %s target Debug configuration does not define\n'
                    '       SWIFT_ACTIVE_COMPILATION_CONDITIONS = DEBUG (found %r).\n'
                    '       Both iOS targets must define it: the appex needs it for the\n'
                    '       containment path, and app+appex must agree on the App Group\n'
                    '       that `#elseif DEBUG` selects. Verify with:\n'
                    '         xcodebuild -showBuildSettings -project ios/Runner.xcodeproj \\\n'
                    '           -target %s -configuration Debug\n' % (target, value, target))
                failed = True
        elif value is not None:
            sys.stderr.write(
                'FATAL: the iOS %s %s configuration defines\n'
                '       SWIFT_ACTIVE_COMPILATION_CONDITIONS = %s. A shipped build must NOT\n'
                '       compile the containment path or the dev App Group in.\n'
                % (target, cfg_name, value))
            failed = True

# THE COEXISTENCE INVARIANT. Debug installs alongside the App Store build under
# its own identifier so a dev session cannot destroy the review build; Release
# and Profile must keep the shipping identifiers exactly.
expected_ids = {
    ('Runner', 'Debug'): 'org.winsvpn.app.debug',
    ('Runner', 'Release'): 'org.winsvpn.app',
    ('Runner', 'Profile'): 'org.winsvpn.app',
    ('PacketTunnel', 'Debug'): 'org.winsvpn.app.debug.PacketTunnel',
    ('PacketTunnel', 'Release'): 'org.winsvpn.app.PacketTunnel',
    ('PacketTunnel', 'Profile'): 'org.winsvpn.app.PacketTunnel',
    ('WinsWatch', 'Debug'): 'org.winsvpn.app.debug.watchkitapp',
    ('WinsWatch', 'Release'): 'org.winsvpn.app.watchkitapp',
    ('WinsWatch', 'Profile'): 'org.winsvpn.app.watchkitapp',
}
expected_entitlements = {
    ('Runner', 'Debug'): 'Runner/RunnerDebug.entitlements',
    ('Runner', 'Release'): 'Runner/Runner.entitlements',
    ('Runner', 'Profile'): 'Runner/Runner.entitlements',
    ('PacketTunnel', 'Debug'): 'PacketTunnel/PacketTunnelDebug.entitlements',
    ('PacketTunnel', 'Release'): 'PacketTunnel/PacketTunnel.entitlements',
    ('PacketTunnel', 'Profile'): 'PacketTunnel/PacketTunnel.entitlements',
}
for target in ('Runner', 'PacketTunnel'):
    for cfg_id, cfg_name in target_configs[('PBXNativeTarget', target)]:
        got_id = setting(cfg_id, 'PRODUCT_BUNDLE_IDENTIFIER')
        want_id = expected_ids[(target, cfg_name)]
        if got_id != want_id:
            sys.stderr.write(
                'FATAL: iOS %s %s PRODUCT_BUNDLE_IDENTIFIER is %r, expected %r.\n'
                % (target, cfg_name, got_id, want_id))
            failed = True
        got_ent = setting(cfg_id, 'CODE_SIGN_ENTITLEMENTS')
        want_ent = expected_entitlements[(target, cfg_name)]
        if got_ent != want_ent:
            sys.stderr.write(
                'FATAL: iOS %s %s CODE_SIGN_ENTITLEMENTS is %r, expected %r.\n'
                % (target, cfg_name, got_ent, want_ent))
            failed = True

# Watch companion IDs must follow the same Debug/Release split as the iPhone
# host. A hardcoded shipping companion ID would make Debug watch content
# refuse to pair with org.winsvpn.app.debug.
for target in ('WinsWatch',):
    key = ('PBXNativeTarget', target)
    if key not in target_configs:
        sys.stderr.write('FATAL: no %s target found in ios/Runner.xcodeproj.\n' % target)
        failed = True
        continue
    for cfg_id, cfg_name in target_configs[key]:
        got_id = setting(cfg_id, 'PRODUCT_BUNDLE_IDENTIFIER')
        want_id = expected_ids[(target, cfg_name)]
        if got_id != want_id:
            sys.stderr.write(
                'FATAL: iOS %s %s PRODUCT_BUNDLE_IDENTIFIER is %r, expected %r.\n'
                % (target, cfg_name, got_id, want_id))
            failed = True
        companion = setting(cfg_id, 'WK_COMPANION_APP_BUNDLE_IDENTIFIER')
        want_companion = expected_ids[('Runner', cfg_name)]
        if companion != want_companion:
            sys.stderr.write(
                'FATAL: iOS %s %s WK_COMPANION_APP_BUNDLE_IDENTIFIER is %r, expected %r.\n'
                % (target, cfg_name, companion, want_companion))
            failed = True

# The appex identifier must remain a child of the app identifier in every
# configuration, or NetworkExtension will not load the provider at all.
for cfg in ('Debug', 'Release', 'Profile'):
    app_id = expected_ids[('Runner', cfg)]
    appex_id = expected_ids[('PacketTunnel', cfg)]
    if not appex_id.startswith(app_id + '.'):
        sys.stderr.write(
            'FATAL: iOS %s appex id %r is not a child of app id %r.\n'
            % (cfg, appex_id, app_id))
        failed = True
    watch_id = expected_ids[('WinsWatch', cfg)]
    if not watch_id.startswith(app_id + '.'):
        sys.stderr.write(
            'FATAL: iOS %s watch id %r is not a child of app id %r.\n'
            % (cfg, watch_id, app_id))
        failed = True

# The project level must stay clean, so the setting cannot leak to every target.
for cfg_id, cfg_name in target_configs.get(('PBXProject', 'Runner'), []):
    if sacc(cfg_id) is not None:
        sys.stderr.write(
            'FATAL: the iOS PBXProject %s configuration now defines\n'
            '       SWIFT_ACTIVE_COMPILATION_CONDITIONS. This lane deliberately scoped it\n'
            '       to the PacketTunnel target only.\n' % (cfg_name,))
        failed = True

if failed:
    raise SystemExit(1)
print('iOS: DEBUG on both targets Debug-only; dev/release bundle ids and '
      'entitlements correctly split.')
PY

# THE APP GROUP MUST BE ISOLATED. A dev build that shared the production App
# Group would overwrite the shipping app's Tunnel/latest_tunnel.conf and
# Tunnel/latest_status.json — both are keyed only by path inside the container —
# which is exactly the cross-contamination the separate bundle id exists to
# prevent.
grep -q 'group.org.winsvpn.devicecheck' ios/Runner/RunnerDebug.entitlements
grep -q 'group.org.winsvpn.devicecheck' ios/PacketTunnel/PacketTunnelDebug.entitlements
refute_match 'group.org.winsvpn.app<' ios/Runner/RunnerDebug.entitlements
refute_match 'group.org.winsvpn.app<' ios/PacketTunnel/PacketTunnelDebug.entitlements
# ...and the shipping entitlements must still name the production group.
grep -q 'group.org.winsvpn.app' ios/Runner/Runner.entitlements
grep -q 'group.org.winsvpn.app' ios/PacketTunnel/PacketTunnel.entitlements
# Every entitlements file still grants packet-tunnel-provider, or the provider
# cannot be loaded at all.
for f in ios/Runner/Runner.entitlements ios/Runner/RunnerDebug.entitlements \
         ios/PacketTunnel/PacketTunnel.entitlements ios/PacketTunnel/PacketTunnelDebug.entitlements; do
  grep -q 'packet-tunnel-provider' "$f" || {
    printf 'FATAL: %s does not grant packet-tunnel-provider.\n' "$f" >&2; exit 1; }
  "${PYTHON_BIN}" -c "import plistlib,sys; plistlib.load(open(sys.argv[1],'rb'))" "$f" || {
    printf 'FATAL: %s is not a valid plist.\n' "$f" >&2; exit 1; }
done
# The keychain access group is deliberately the SAME in dev and release: it is
# what lets a dev session use the client key pair the gateway already knows,
# instead of provisioning a new credential against the live control plane.
grep -q 'org.winsvpn.shared' ios/Runner/RunnerDebug.entitlements
grep -q 'org.winsvpn.shared' ios/PacketTunnel/PacketTunnelDebug.entitlements

# The dev App Group is selected in shared code under `#elseif DEBUG`, AFTER the
# os(macOS) branch, so macOS is unreachable from it in either build shape.
"${PYTHON_BIN}" - <<'PY'
import re, sys
src = open('apple/WinsTunnelCore/WinsTunnelConfig.swift', encoding='utf-8').read()
m = re.search(
    r'static var identifier: String \{\n'
    r'\s*#if os\(macOS\)\n'
    r'.*?\n'
    r'\s*#elseif DEBUG\n'
    r'\s*return devIdentifier\n'
    r'\s*#else\n'
    r'\s*return baseIdentifier\n'
    r'\s*#endif',
    src, re.S)
if not m:
    sys.stderr.write(
        'FATAL: WinsAppleAppGroup.identifier is not in the required shape.\n'
        '       os(macOS) MUST be tested first so the dev App Group can never be\n'
        '       reached on macOS, and the non-Debug non-macOS arm MUST still return\n'
        '       the production group.\n')
    raise SystemExit(1)
print('App Group selection: macOS first, dev group Debug-only, release group intact.')
PY

# 4. Contained settings install no default route, no IPv6 and no DNS -- and iOS
#    additionally READS BACK what it built rather than trusting the plan.
grep -q 'settings.ipv6Settings deliberately left nil' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'settings.dnsSettings deliberately left nil' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'let observation = WinsDevContainmentObservation(settings: settings)' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'guard observation.isContained else {' ios/PacketTunnel/PacketTunnelProvider.swift

# 5. Production full-tunnel leak protection is untouched: the shipping branch
#    still installs the default route, the IPv6 sink and full-tunnel DNS.
grep -q 'return NEIPv4Route.default()' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'ipv6Settings.includedRoutes = \[NEIPv6Route.default()\]' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'dnsSettings.matchDomains = config.dnsMatchDomains' ios/PacketTunnel/PacketTunnelProvider.swift

# 6. A contained iOS session can never report a passing full-tunnel posture:
#    the app-side mapping has to forward the field the verdict reads.
grep -q 'provider_dev_containment_active' ios/Runner/AppDelegate.swift
grep -q 'provider_dev_containment_observed_contained' ios/Runner/AppDelegate.swift

# 7. Teardown. iOS AWAITS the release and records the real NSError, rather than
#    racing a deadline and logging a phrase. `then completion: @escaping ([String: Any]) -> Void`
#    is what makes the outcome reach the status document at all.
grep -q 'setTunnelNetworkSettings(nil)' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'then completion: @escaping (\[String: Any\]) -> Void' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_release_error_domain' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_release_error_code' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_release_outcome' ios/PacketTunnel/PacketTunnelProvider.swift
# The release must be awaited: the stop completion is called from INSIDE the
# release callback, never alongside it.
grep -q 'releaseTunnelNetworkSettings(context: "stop_tunnel") { releaseFields in' ios/PacketTunnel/PacketTunnelProvider.swift
# The deadline must be INTEGER MILLISECONDS. `safeStatusNumber` accepts only
# integer objCType codes and returns nil for "d", so a Double of seconds is
# SILENTLY DISCARDED on a compacted write -- precisely the truncated-document
# path this field exists for.
grep -q 'network_settings_release_deadline_ms' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'network_settings_release_deadline_seconds' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'dev_containment_self_cancel_deadline_seconds' ios/PacketTunnel/PacketTunnelProvider.swift
# No status field anywhere in this provider may be a Double.
"${PYTHON_BIN}" - <<'PY'
import re, sys
src = open('ios/PacketTunnel/PacketTunnelProvider.swift', encoding='utf-8').read()
# Any `"key": <expr>` whose expression is a bare Double-typed constant.
bad = re.findall(r'"([a-z0-9_]+)": *Self\.[A-Za-z]*Seconds\b', src)
bad += re.findall(r'"([a-z0-9_]+)": *[0-9]+\.[0-9]+\b', src)
if bad:
    sys.stderr.write(
        'FATAL: these status fields carry Double values and would be silently\n'
        '       discarded by safeStatusNumber on a compacted write: %s\n'
        '       Use integer milliseconds instead.\n' % ', '.join(sorted(set(bad))))
    raise SystemExit(1)
print('No Double-valued status fields in the iOS provider.')
PY

# THE SELF-CANCEL IS THE PRIMARY TEARDOWN LEVER, and its release must be issued
# while the session is still RUNNING.
#
# `-[NESMVPNSessionStateStopping handleClearConfiguration]` returns NO with no
# path to YES: the NE agent refuses clear-configuration for ANY stopping
# session, so a release issued from `stopTunnel` is structurally incapable of
# succeeding. The self-cancel path reaches the agent before the session has been
# asked to stop, which is the only state where it can succeed. The release must
# therefore come BEFORE cancelTunnelWithError, and its outcome must be written
# to disk BEFORE the cancel, because the process may not survive the cancel.
grep -q 'cancelTunnelWithError' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'releaseTunnelNetworkSettings(context: "self_cancel_running")' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_release_context' ios/PacketTunnel/PacketTunnelProvider.swift
"${PYTHON_BIN}" - <<'PY'
import sys
src = open('ios/PacketTunnel/PacketTunnelProvider.swift', encoding='utf-8').read()
release = src.index('releaseTunnelNetworkSettings(context: "self_cancel_running")')
write = src.index('self.writeProviderStatus(', release)
cancel = src.index('self.cancelTunnelWithError(', release)
if not (release < write < cancel):
    sys.stderr.write(
        'FATAL: the contained self-cancel must (1) release network settings while the\n'
        '       session is still RUNNING, (2) write the outcome to disk, and only then\n'
        '       (3) cancelTunnelWithError. Any other order loses the one release\n'
        '       attempt that can actually succeed, or loses its evidence.\n')
    raise SystemExit(1)
print('Self-cancel ordering: release (running) -> persist outcome -> cancel.')
PY

# POST-HOC EVIDENCE. The `stopped` document must carry the containment fields.
# The macOS sibling drops them (previousProviderStatusFieldsBeforeStop copies a
# fixed list that omits them), so the final document of a contained run does not
# record that it was contained -- which is the first thing a reviewer looks for.
"${PYTHON_BIN}" - <<'PY'
import re, sys
src = open('ios/PacketTunnel/PacketTunnelProvider.swift', encoding='utf-8').read()
i = src.index('private func previousProviderStatusFieldsBeforeStop')
j = src.index('\n  }', i)
body = src[i:j]
required = [
    'dev_containment_active',
    'dev_containment_observed_contained',
    'dev_containment_default_ipv4_route_installed',
    'dev_containment_ipv6_settings_installed',
    'dev_containment_dns_settings_installed',
]
missing = [k for k in required if k not in body]
if missing:
    sys.stderr.write(
        'FATAL: the stopped document would not record that a contained session was\n'
        '       contained. Missing from previousProviderStatusFieldsBeforeStop: %s\n'
        % ', '.join(missing))
    raise SystemExit(1)
# They must keep their own names -- dev_containment_active is the term the
# leak-protection verdict reads, and renaming it would let a stopped contained
# session read as a passing full-tunnel posture.
if 'copy(containmentKey, as: containmentKey)' not in body:
    sys.stderr.write(
        'FATAL: containment fields must be copied under their OWN names into the\n'
        '       stopped document, not renamed to previous_*_before_stop.\n')
    raise SystemExit(1)
print('Stopped document retains containment evidence under its own key names.')
PY
# Every field the release and the memory gate can write must survive a compacted
# status write, or a teardown that produced a large document would lose exactly
# the evidence it was written for.
for key in \
  network_settings_release_outcome \
  network_settings_release_error_domain \
  network_settings_release_error_code \
  winn_memory_gate_refusal_reason \
  winn_memory_gate_available_bytes \
  dev_containment_observed_contained \
  dev_containment_supported_by_build; do
  grep -q "\"${key}\"," apple/WinsTunnelCore/WinsPacketTunnelEngine.swift || {
    printf 'FATAL: %s is not in WinsPacketTunnelProviderStatus.compactExtraKeys, so a\n' "${key}" >&2
    printf '       compacted status write would silently drop it.\n' >&2
    exit 1
  }
done

# 8. The winn/3 appex memory gate. NE providers get ~50 MB only on iOS 15+; on
#    iOS 13/14 the limit is roughly 15 MB and this project ships
#    IPHONEOS_DEPLOYMENT_TARGET = 13.0. The gate must be a RUNTIME query, must
#    refuse by name, and must not let the direct-awg measurement vouch for the
#    unmeasured carrier path.
grep -q 'os_proc_available_memory()' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'winn_memory_gate_refusal_reason' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'winn_carrier_memory_profile_unmeasured' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appex_available_memory_below_winn_datapath_requirement' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appex_available_memory_unknown' ios/PacketTunnel/PacketTunnelProvider.swift
# The gate must run BEFORE any network settings are installed, or a refusal
# would arrive after the phone's routing was already taken.
"${PYTHON_BIN}" - <<'PY'
import sys
src = open('ios/PacketTunnel/PacketTunnelProvider.swift', encoding='utf-8').read()
gate = src.index('if let memoryGate = winnAppexMemoryGate(for: parsedConfig) {')
apply_settings = src.index('let networkSettingsResult = try makeNetworkSettings(from: parsedConfig)')
if gate > apply_settings:
    sys.stderr.write(
        'FATAL: the winn/3 memory gate runs AFTER makeNetworkSettings. It must refuse\n'
        '       before any network settings are built or installed.\n')
    raise SystemExit(1)
print('winn/3 memory gate precedes network settings construction.')
PY
# IPHONEOS_DEPLOYMENT_TARGET is deliberately NOT raised -- that is a market
# decision belonging to the owner, and raising it would silently drop devices.
grep -q 'IPHONEOS_DEPLOYMENT_TARGET = 15.0;' ios/Runner.xcodeproj/project.pbxproj

}

wins_readiness_section_17_ios_packet_tunnel_dev_containment_release_absence_compiled_proof() {
section "iOS Packet Tunnel Dev Containment Release Absence (compiled proof)"
# The same measured proof macOS gets, with an iOS-specific probe literal so a
# strings(1) hit names which platform's appex it came from and one platform's
# probe can never vouch for the other's.
IOS_CONTAINMENT_TMP="$(mktemp -d)"
# Cleanup is handled once by wins_readiness_on_exit (installed near the top),
# which removes every temp dir and always reports deferred failures.
cat > "${IOS_CONTAINMENT_TMP}/ios_containment_probe_main.swift" <<'SWIFT'
import Foundation
@main
struct WinsIOSContainmentProbeMain {
  static func main() { print("ios containment probe") }
}
SWIFT
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -O "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  ios/PacketTunnel/PacketTunnelProvider.swift \
  "${IOS_CONTAINMENT_TMP}/ios_containment_probe_main.swift" \
  -o "${IOS_CONTAINMENT_TMP}/ios_appex_release_shape"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -O -D DEBUG "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  ios/PacketTunnel/PacketTunnelProvider.swift \
  "${IOS_CONTAINMENT_TMP}/ios_containment_probe_main.swift" \
  -o "${IOS_CONTAINMENT_TMP}/ios_appex_debug_shape"

if wins_binary_contains "${IOS_CONTAINMENT_TMP}/ios_appex_release_shape" 'WINS_IOS_DEV_CONTAINMENT_ABSENCE_PROBE_3d9f52a1'; then
  printf 'FATAL: the iOS dev containment absence probe is present in a RELEASE-shaped appex.\n' >&2
  printf '       Check for a SWIFT_ACTIVE_COMPILATION_CONDITIONS override on the\n' >&2
  printf '       PacketTunnel target Release/Profile configuration in ios/Runner.xcodeproj.\n' >&2
  exit 1
fi
if ! wins_binary_contains "${IOS_CONTAINMENT_TMP}/ios_appex_debug_shape" 'WINS_IOS_DEV_CONTAINMENT_ABSENCE_PROBE_3d9f52a1'; then
  printf 'FATAL: the iOS dev containment absence probe is missing from a DEBUG-shaped appex.\n' >&2
  printf '       The release-absence check above is therefore vacuous.\n' >&2
  exit 1
fi
# The two platforms' probes must stay distinct, so neither can vouch for the other.
if wins_binary_contains "${IOS_CONTAINMENT_TMP}/ios_appex_debug_shape" 'WINS_DEV_CONTAINMENT_ABSENCE_PROBE_7b21e4c6'; then
  printf 'FATAL: the macOS containment probe literal appears in the iOS appex.\n' >&2
  exit 1
fi

}

wins_readiness_section_18_apple_host_bridge_swift_type_checks() {
section "Apple Host Bridge Swift Type Checks"
"${PYTHON_BIN}" tools/verify_apple_method_channel_contract.py
grep -q 'manager.loadFromPreferences { loadError in' ios/Runner/AppDelegate.swift
awk 'index($0, "manager.connection.startVPNTunnel(") > 0 {
        if (getline > 0 && index($0, "options: WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(") > 0) found = 1
      } END { exit found ? 0 : 1 }' ios/Runner/AppDelegate.swift
refute_match 'self.loadTunnelManager { persistedManager, loadError in' ios/Runner/AppDelegate.swift
grep -q 'self.loadTunnelManager { persistedManager, loadError in' macos/Runner/MainFlutterWindow.swift
awk 'index($0, "persistedManager.connection.startVPNTunnel(") > 0 {
        if (getline > 0 && index($0, "options: WinsWinn3SelectedNodeCaller.packetTunnelStartOptions(") > 0) found = 1
      } END { exit found ? 0 : 1 }' macos/Runner/MainFlutterWindow.swift
grep -q 'shared_config_path' ios/Runner/AppDelegate.swift
grep -q 'shared_config_path' macos/Runner/MainFlutterWindow.swift
grep -q 'shared_config_private_key_redacted' ios/Runner/AppDelegate.swift
grep -q 'shared_config_private_key_redacted' macos/Runner/MainFlutterWindow.swift
grep -q 'latest_status.json' ios/Runner/AppDelegate.swift
grep -q 'latest_status.json' macos/Runner/MainFlutterWindow.swift
grep -q 'providerHealthProbeFields' ios/Runner/AppDelegate.swift
grep -q 'providerHealthProbeFields' macos/Runner/MainFlutterWindow.swift
grep -q 'NETunnelProviderSession' ios/Runner/AppDelegate.swift
grep -q 'NETunnelProviderSession' macos/Runner/MainFlutterWindow.swift
grep -q 'sendProviderMessage' ios/Runner/AppDelegate.swift
grep -q 'sendProviderMessage' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_message_probe_healthy' ios/Runner/AppDelegate.swift
grep -q 'provider_message_probe_healthy' macos/Runner/MainFlutterWindow.swift
grep -q 'healthProbeResponseStatusFields' ios/Runner/AppDelegate.swift
grep -q 'healthProbeResponseStatusFields' macos/Runner/MainFlutterWindow.swift
grep -q 'responseData: nil' ios/Runner/AppDelegate.swift
grep -q 'responseData: nil' macos/Runner/MainFlutterWindow.swift
grep -q 'healthProbeResponseStatusFields' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'maxResponseMessageBytes' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'healthCommand = "health"' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'command == Self.healthCommand' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'app_message_command_is_health' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'provider_message_probe_command_is_health' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'provider_message_probe_response_schema_supported' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
refute_match '"ping"' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
refute_match 'JSONSerialization.jsonObject(with: responseData)' ios/Runner/AppDelegate.swift
refute_match 'JSONSerialization.jsonObject(with: responseData)' macos/Runner/MainFlutterWindow.swift
grep -q 'static func safeResponseCommand' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelProviderAppMessage.safeResponseCommand' tools/verify_apple_tunnel_config.swift
grep -q 'health /tmp/latest_status.json' tools/verify_apple_tunnel_config.swift
refute_match 'safeProviderProbeCommand' ios/Runner/AppDelegate.swift
refute_match 'safeProviderProbeCommand' macos/Runner/MainFlutterWindow.swift
grep -q 'Platform.isAndroid || Platform.isIOS || Platform.isMacOS' lib/main.dart
grep -q 'launchExternalUrl' lib/main.dart
grep -q 'WinsAppleExternalUrl.safeUrl' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleExternalUrl.safeUrl' macos/Runner/MainFlutterWindow.swift
grep -q 'enum WinsAppleExternalUrl' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'maxLength = 2_048' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'controlCharacters' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'url.user == nil' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'url.password == nil' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'directSchemePayload' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'safeDirectSchemePayload' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'directPayloadLooksLocalOrScript' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'phonePayloadScalars' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q '"mailto"' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q '"tel"' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q '"sms"' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectExternalUrlValidation' tools/verify_apple_tunnel_config.swift
grep -q 'javascript:alert' tools/verify_apple_tunnel_config.swift
grep -q 'mailto:/etc/passwd' tools/verify_apple_tunnel_config.swift
grep -q 'tel:../../root' tools/verify_apple_tunnel_config.swift
grep -q 'sms:../../root' tools/verify_apple_tunnel_config.swift
grep -q '+1-800-WINSVPN' tools/verify_apple_tunnel_config.swift
grep -q 'https://user:secret@winsvpn.org' tools/verify_apple_tunnel_config.swift
grep -q 'mailto:' tools/verify_apple_tunnel_config.swift
grep -q 'tel:' tools/verify_apple_tunnel_config.swift
grep -q 'sms:' tools/verify_apple_tunnel_config.swift
# Retargeted 2026-08-06. These two guards forbid the pre-validation shape of the
# EXTERNAL URL LAUNCH path -- reading args["url"] straight into a URL instead of
# routing it through WinsAppleExternalUrl.safeUrl (asserted positively above).
# They were written when launchExternalUrl was the only args["url"] consumer.
# The speed-test bridges measureDownloadMbps/measureUploadMbps have since been
# added and legitimately use exactly that shape for an app-supplied throughput
# endpoint, so the whole-file pattern had drifted onto unrelated code. It never
# fired only because `! grep` is inert under set -e; made real as a whole-file
# check it would have failed on the speed-test methods, which is how people
# learn to ignore failures. Scoped to the method the guard was written for.
refute_match_in_swift_method launchExternalUrl 'let rawUrl = args\["url"\] as? String' ios/Runner/AppDelegate.swift
refute_match_in_swift_method launchExternalUrl 'let rawUrl = args\["url"\] as? String' macos/Runner/MainFlutterWindow.swift
refute_match 'private static func safeExternalUrl' ios/Runner/AppDelegate.swift
refute_match 'private static func safeExternalUrl' macos/Runner/MainFlutterWindow.swift
grep -q 'if (_hasNativeTunnelBridge)' lib/main.dart
grep -q 'WinsAppleShare.sharePayload' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleShare.sharePayload' macos/Runner/MainFlutterWindow.swift
grep -q 'enum WinsAppleShare' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'maxTextLength = 4_000' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectShareTextValidation' tools/verify_apple_tunnel_config.swift
refute_match 'let text = args\["text"\] as? String' ios/Runner/AppDelegate.swift
refute_match 'let text = args\["text"\] as? String' macos/Runner/MainFlutterWindow.swift
grep -q 'import UserNotifications' ios/Runner/AppDelegate.swift
grep -q 'import UserNotifications' macos/Runner/MainFlutterWindow.swift
grep -q 'showAnnouncementNotification(call.arguments, result: result)' ios/Runner/AppDelegate.swift
grep -q 'showAnnouncementNotification(call.arguments, result: result)' macos/Runner/MainFlutterWindow.swift
grep -q 'UNMutableNotificationContent' ios/Runner/AppDelegate.swift
grep -q 'UNMutableNotificationContent' macos/Runner/MainFlutterWindow.swift
grep -q 'UNUserNotificationCenter.current' ios/Runner/AppDelegate.swift
grep -q 'UNUserNotificationCenter.current' macos/Runner/MainFlutterWindow.swift
grep -q 'requestAuthorization(options:' ios/Runner/AppDelegate.swift
grep -q 'requestAuthorization(options:' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsAppleNotification.announcementPayload' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleNotification.announcementPayload' macos/Runner/MainFlutterWindow.swift
grep -q 'enum WinsAppleNotification' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'maxTitleLength = 80' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'maxBodyLength = 900' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectNotificationTextValidation' tools/verify_apple_tunnel_config.swift
refute_match 'boundedNotificationText' ios/Runner/AppDelegate.swift
refute_match 'boundedNotificationText' macos/Runner/MainFlutterWindow.swift
grep -q 'responseSchemaVersion == schemaVersion' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'rawPayloadRedacted' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'commandIsHealth' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'adapterStartContractCode = 1004' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'statusFieldsUserInfoKey' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'missingNativeEngineCode = 1003' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_packet_flow_attached' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_awg_started' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_xray_started' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_contract_failed' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_engine_ready_reported' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_engine_running_reported' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'running packet flow' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'Adapter packet-flow contract did not fail closed' tools/verify_apple_tunnel_config.swift
grep -q 'expectAdapterContractFailureStatus' tools/verify_apple_tunnel_config.swift
grep -q 'engine_start_failed' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_start_failed' tools/verify_apple_tunnel_config.swift
grep -q 'Apple VPN engine did not become ready' lib/apple_tunnel_diagnostics.dart
grep -q 'adapter start contract failures are distinct from missing engine' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_stage' ios/Runner/AppDelegate.swift
grep -q 'provider_stage' macos/Runner/MainFlutterWindow.swift
grep -q 'network_extension_connected' ios/Runner/AppDelegate.swift
grep -q 'network_extension_connected' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsAppleReadiness.providerReady' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleReadiness.providerReady' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_current' ios/Runner/AppDelegate.swift
grep -q 'provider_status_current' macos/Runner/MainFlutterWindow.swift
grep -Fq 'readiness["provider_status_current"] = WinsAppleReadiness.providerStatusCurrent(readiness)' ios/Runner/AppDelegate.swift
grep -Fq 'readiness["provider_status_current"] = WinsAppleReadiness.providerStatusCurrent(readiness)' macos/Runner/MainFlutterWindow.swift
grep -Fq 'readiness["provider_ready"] = WinsAppleReadiness.providerReady(readiness)' ios/Runner/AppDelegate.swift
grep -Fq 'readiness["provider_ready"] = WinsAppleReadiness.providerReady(readiness)' macos/Runner/MainFlutterWindow.swift
grep -q '"provider_status_current": false' ios/Runner/AppDelegate.swift
grep -q '"provider_status_current": false' macos/Runner/MainFlutterWindow.swift
grep -q '"provider_ready": false' ios/Runner/AppDelegate.swift
grep -q '"provider_ready": false' macos/Runner/MainFlutterWindow.swift
grep -q 'internet_probe_attempted' ios/Runner/AppDelegate.swift
grep -q 'internet_probe_attempted' macos/Runner/MainFlutterWindow.swift
grep -q 'internet_probe_blocked_by_provider_readiness' ios/Runner/AppDelegate.swift
grep -q 'internet_probe_blocked_by_provider_readiness' macos/Runner/MainFlutterWindow.swift
grep -q 'internet_probe_blocked_by_leak_protection_config' ios/Runner/AppDelegate.swift
grep -q 'internet_probe_blocked_by_leak_protection_config' macos/Runner/MainFlutterWindow.swift
grep -q 'internet_probe_url_kind' ios/Runner/AppDelegate.swift
grep -q 'internet_probe_url_kind' macos/Runner/MainFlutterWindow.swift
grep -q 'fullTunnelLeakProtectionConfigFields' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'fullTunnelLeakProtectionConfigFields' ios/Runner/AppDelegate.swift
grep -q 'fullTunnelLeakProtectionConfigFields' macos/Runner/MainFlutterWindow.swift
grep -q 'leak_protection_config_passed' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'leak_protection_default_route_enabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'leak_protection_dns_full_tunnel_match_enabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'leak_protection_engine_dns_full_tunnel_match_enabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'leak_protection_ipv6_enabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'leak_protection_engine_ipv6_enabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsAppleReadiness.bool(response, "leak_protection_config_passed")' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleReadiness.bool(response, "leak_protection_config_passed")' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsAppleExternalLeakAudit.request' ios/Runner/AppDelegate.swift
grep -q 'WinsAppleExternalLeakAudit.request' macos/Runner/MainFlutterWindow.swift
grep -q 'enum WinsAppleExternalLeakAudit' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'public_https_hostname_canary' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'external_leak_audit_passed' ios/Runner/AppDelegate.swift
grep -q 'external_leak_audit_passed' macos/Runner/MainFlutterWindow.swift
grep -q 'vpn_manager_invalid_after_config_save' ios/Runner/AppDelegate.swift
grep -q 'vpn_configuration_permission_pending' ios/Runner/AppDelegate.swift
grep -q 'vpn_manager_invalid_after_config_save' lib/apple_tunnel_diagnostics.dart
grep -q 'vpn_configuration_permission_pending' lib/apple_tunnel_diagnostics.dart
grep -q 'Approve the iOS VPN configuration permission' lib/apple_tunnel_diagnostics.dart
grep -q 'iOS permission pending state is explicit after config save' test/apple_tunnel_diagnostics_test.dart
grep -q 'enum WinsAppleReadiness' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectAppleReadinessValidation' tools/verify_apple_tunnel_config.swift
grep -q '"engine_ready": false' ios/Runner/AppDelegate.swift
grep -q '"engine_ready": false' macos/Runner/MainFlutterWindow.swift
grep -q '"tunnel_healthy": false' ios/Runner/AppDelegate.swift
grep -q '"tunnel_healthy": false' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_schema_version' ios/Runner/AppDelegate.swift
grep -q 'provider_status_schema_version' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_schema_supported' ios/Runner/AppDelegate.swift
grep -q 'provider_status_schema_supported' macos/Runner/MainFlutterWindow.swift
grep -q 'schemaVersion == 2' ios/Runner/AppDelegate.swift
grep -q 'schemaVersion == 2' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_generation' ios/Runner/AppDelegate.swift
grep -q 'provider_status_generation' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_generation_invalid' ios/Runner/AppDelegate.swift
grep -q 'provider_status_generation_invalid' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_expected_status_generation_invalid' ios/Runner/AppDelegate.swift
grep -q 'provider_expected_status_generation_invalid' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_stale' ios/Runner/AppDelegate.swift
grep -q 'provider_status_stale' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_bundle_mismatch' ios/Runner/AppDelegate.swift
grep -q 'provider_status_bundle_mismatch' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_extension_type_mismatch' ios/Runner/AppDelegate.swift
grep -q 'provider_status_extension_type_mismatch' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_timestamp_invalid' ios/Runner/AppDelegate.swift
grep -q 'provider_status_timestamp_invalid' macos/Runner/MainFlutterWindow.swift
grep -q 'validProviderStatusTimestamp' ios/Runner/AppDelegate.swift
grep -q 'validProviderStatusTimestamp' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_stage_invalid' ios/Runner/AppDelegate.swift
grep -q 'provider_status_stage_invalid' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsPacketTunnelProviderStatus.validStage' ios/Runner/AppDelegate.swift
grep -q 'WinsPacketTunnelProviderStatus.validStage' macos/Runner/MainFlutterWindow.swift
grep -q 'knownStages' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'validStage' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'maxStatusFileBytes' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'provider_status_container_available' ios/Runner/AppDelegate.swift
grep -q 'provider_status_container_available' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_file_present' ios/Runner/AppDelegate.swift
grep -q 'provider_status_file_present' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_file_readable' ios/Runner/AppDelegate.swift
grep -q 'provider_status_file_readable' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_json_valid' ios/Runner/AppDelegate.swift
grep -q 'provider_status_json_valid' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_file_too_large' ios/Runner/AppDelegate.swift
grep -q 'provider_status_file_too_large' macos/Runner/MainFlutterWindow.swift
grep -q 'readData(ofLength: maxStatusFileBytes + 1)' ios/Runner/AppDelegate.swift
grep -q 'readData(ofLength: maxStatusFileBytes + 1)' macos/Runner/MainFlutterWindow.swift
grep -q 'expectProviderStatusStageValidation' tools/verify_apple_tunnel_config.swift
grep -q 'safeMappedStatusValue' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'safeStatusGeneration' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'safeStatusByteCount' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'safeStatusNumber' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'isNativeStatusScalar' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'safeStatusGeneration' ios/Runner/AppDelegate.swift
grep -q 'safeStatusGeneration' macos/Runner/MainFlutterWindow.swift
grep -q 'safeStatusByteCount' ios/Runner/AppDelegate.swift
grep -q 'safeStatusByteCount' macos/Runner/MainFlutterWindow.swift
grep -q 'rawProviderStatusGeneration' ios/Runner/AppDelegate.swift
grep -q 'rawProviderStatusGeneration' macos/Runner/MainFlutterWindow.swift
grep -q 'safeMappedStatusValue' ios/Runner/AppDelegate.swift
grep -q 'safeMappedStatusValue' macos/Runner/MainFlutterWindow.swift
grep -q 'activeStatusGeneration' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'activeStatusGeneration' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'currentStatusGeneration' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'currentStatusGeneration' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectProviderStatusGenerationSanitization' tools/verify_apple_tunnel_config.swift
grep -q 'expectProviderRuntimeInputSelection' tools/verify_apple_tunnel_config.swift
grep -q 'expectProviderStatusMappedValueSanitization' tools/verify_apple_tunnel_config.swift
grep -q 'Provider status mapped sanitizer accepted unsafe number' tools/verify_apple_tunnel_config.swift
grep -q 'Provider status byte-count sanitizer did not clamp' tools/verify_apple_tunnel_config.swift
grep -q 'secret-stage' tools/verify_apple_tunnel_config.swift
refute_match 'validProviderStatusStage' ios/Runner/AppDelegate.swift
refute_match 'validProviderStatusStage' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_expected_status_generation' ios/Runner/AppDelegate.swift
grep -q 'provider_expected_status_generation' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsPacketTunnelProviderStatus.payload' ios/Runner/AppDelegate.swift
grep -q 'WinsPacketTunnelProviderStatus.payload' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_source' ios/Runner/AppDelegate.swift
grep -q 'provider_config_source' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_file_too_large' ios/Runner/AppDelegate.swift
grep -q 'provider_config_file_too_large' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_utf8_valid' ios/Runner/AppDelegate.swift
grep -q 'provider_config_utf8_valid' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_app_group_container_available' ios/Runner/AppDelegate.swift
grep -q 'provider_config_app_group_container_available' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_app_group_id_allowed' ios/Runner/AppDelegate.swift
grep -q 'provider_config_app_group_id_allowed' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_shared_keychain_private_key_available' ios/Runner/AppDelegate.swift
grep -q 'provider_shared_keychain_private_key_available' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_write_limited' ios/Runner/AppDelegate.swift
grep -q 'provider_status_write_limited' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_write_payload_too_large' ios/Runner/AppDelegate.swift
grep -q 'provider_status_write_payload_too_large' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_private_key_source' ios/Runner/AppDelegate.swift
grep -q 'provider_private_key_source' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_client_key_pair_verification_required' ios/Runner/AppDelegate.swift
grep -q 'provider_client_key_pair_verification_required' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_expected_client_public_key_available' ios/Runner/AppDelegate.swift
grep -q 'provider_expected_client_public_key_available' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_expected_client_public_key_source' ios/Runner/AppDelegate.swift
grep -q 'provider_expected_client_public_key_source' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_expected_client_public_key_valid' ios/Runner/AppDelegate.swift
grep -q 'provider_expected_client_public_key_valid' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_client_key_pair_verified' ios/Runner/AppDelegate.swift
grep -q 'provider_client_key_pair_verified' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_network_settings_applied' ios/Runner/AppDelegate.swift
grep -q 'provider_network_settings_applied' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_default_route_enabled' ios/Runner/AppDelegate.swift
grep -q 'provider_default_route_enabled' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_dns_match_domains' ios/Runner/AppDelegate.swift
grep -q 'provider_dns_match_domains' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_dns_full_tunnel_match_enabled' ios/Runner/AppDelegate.swift
grep -q 'provider_dns_full_tunnel_match_enabled' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_transport_endpoint_kind' ios/Runner/AppDelegate.swift
grep -q 'provider_transport_endpoint_kind' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_network_settings_remote_address_kind' ios/Runner/AppDelegate.swift
grep -q 'provider_network_settings_remote_address_kind' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_network_settings_remote_address_source' ios/Runner/AppDelegate.swift
grep -q 'provider_network_settings_remote_address_source' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_transport_ipv4_route_excluded' ios/Runner/AppDelegate.swift
grep -q 'provider_transport_ipv4_route_excluded' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_transport_ipv4_exclusion_route_present' ios/Runner/AppDelegate.swift
grep -q 'provider_transport_ipv4_exclusion_route_present' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_ipv6_leak_protection_enabled' ios/Runner/AppDelegate.swift
grep -q 'provider_ipv6_leak_protection_enabled' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_ipv6_sink_address_present' ios/Runner/AppDelegate.swift
grep -q 'provider_ipv6_sink_address_present' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_adapter_available' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_adapter_available' macos/Runner/MainFlutterWindow.swift
refute_match '"peer_endpoint": "provider_peer_endpoint"' ios/Runner/AppDelegate.swift
refute_match '"peer_endpoint": "provider_peer_endpoint"' macos/Runner/MainFlutterWindow.swift
refute_match '"transport_endpoint_host": "provider_transport_endpoint_host"' ios/Runner/AppDelegate.swift
refute_match '"transport_endpoint_host": "provider_transport_endpoint_host"' macos/Runner/MainFlutterWindow.swift
refute_match '"network_settings_remote_address": "provider_network_settings_remote_address"' ios/Runner/AppDelegate.swift
refute_match '"network_settings_remote_address": "provider_network_settings_remote_address"' macos/Runner/MainFlutterWindow.swift
grep -q 'wins_manager_signature' ios/Runner/AppDelegate.swift
grep -q 'wins_manager_signature' macos/Runner/MainFlutterWindow.swift
grep -q 'client_public_key' ios/Runner/AppDelegate.swift
grep -q 'client_public_key' macos/Runner/MainFlutterWindow.swift
grep -q 'status_generation' ios/Runner/AppDelegate.swift
grep -q 'status_generation' macos/Runner/MainFlutterWindow.swift
grep -q 'expectedStatusGeneration' ios/Runner/AppDelegate.swift
grep -q 'expectedStatusGeneration' macos/Runner/MainFlutterWindow.swift
grep -q 'providerSchemaSupported' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'appleTunnelProviderSchemaSupported' lib/apple_tunnel_diagnostics.dart
grep -q 'removeStaleTunnelManagers' ios/Runner/AppDelegate.swift
grep -q 'removeStaleTunnelManagers' macos/Runner/MainFlutterWindow.swift
grep -q 'removeStaleTunnelManagers(managers, keeping: signedManager) {' ios/Runner/AppDelegate.swift
grep -q 'removeStaleTunnelManagers(managers, keeping: signedManager) {' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsTunnelManagerIdentity.currentSignature()' ios/Runner/AppDelegate.swift
grep -q 'WinsTunnelManagerIdentity.currentSignature()' macos/Runner/MainFlutterWindow.swift
grep -q 'schemaVersion = 3' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'CFBundleShortVersionString' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'CFBundleVersion' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'bundlePath.hasPrefix("/Applications/")' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'SHA256.hash(data: Data(path.utf8))' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'removeStaleTunnelManagers(managers, keeping: nil) {' ios/Runner/AppDelegate.swift
grep -q 'removeStaleTunnelManagers(managers, keeping: nil) {' macos/Runner/MainFlutterWindow.swift
if grep -q 'keeping: legacyManager' ios/Runner/AppDelegate.swift \
  || grep -q 'keeping: legacyManager' macos/Runner/MainFlutterWindow.swift; then
  printf 'Legacy Apple tunnel managers must be recreated instead of reused after an extension update.\n' >&2
  exit 1
fi
grep -q 'latest_tunnel.conf' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'latest_tunnel.conf' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsBoundedUTF8FileReader' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsSharedConfigPathGuard' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsAppleAppGroup' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsAppGroupFileWriter' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'removeSymbolicLinkIfPresent' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'ensureDirectory' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'writeString' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'writeData' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'symbolicLinkCode' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'destinationOfSymbolicLink' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'destinationOfSymbolicLink' ios/Runner/AppDelegate.swift
grep -q 'destinationOfSymbolicLink' macos/Runner/MainFlutterWindow.swift
grep -q 'validateSharedConfigPath' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'validateSharedConfigPath' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsAppleAppGroup.validate' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsAppleAppGroup.validate' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'providerAppGroupValidation' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'providerAppGroupValidation' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appGroupValidationProviderError' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appGroupValidationProviderError' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'source: "transient_start_options"' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'source: "transient_start_options"' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'forSecurityApplicationGroupIdentifier: appGroupId' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'forSecurityApplicationGroupIdentifier: appGroupId' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_file_symbolic_link' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_file_symbolic_link' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_shared_path_allowed' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_shared_path_allowed' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_app_group_id_allowed' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_app_group_id_allowed' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'provider_status_file_symbolic_link' ios/Runner/AppDelegate.swift
grep -q 'provider_status_file_symbolic_link' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_file_symbolic_link' ios/Runner/AppDelegate.swift
grep -q 'provider_config_file_symbolic_link' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_status_file_symbolic_link' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_config_file_symbolic_link' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_file_symbolic_link=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_config_file_symbolic_link=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'WinsAppGroupFileWriter.writeString' ios/Runner/AppDelegate.swift
grep -q 'WinsAppGroupFileWriter.writeString' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsAppGroupFileWriter.writeData' ios/Runner/AppDelegate.swift
grep -q 'WinsAppGroupFileWriter.writeData' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsAppGroupFileWriter.writeData' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsAppGroupFileWriter.writeData' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectAppGroupFileWriter' tools/verify_apple_tunnel_config.swift
refute_match 'redactedConfig.write(to:' ios/Runner/AppDelegate.swift
refute_match 'redactedConfig.write(to:' macos/Runner/MainFlutterWindow.swift
refute_match 'metadataData.write(to:' ios/Runner/AppDelegate.swift
refute_match 'metadataData.write(to:' macos/Runner/MainFlutterWindow.swift
refute_match 'data.write(to: statusUrl' ios/Runner/AppDelegate.swift
refute_match 'data.write(to: statusUrl' macos/Runner/MainFlutterWindow.swift
refute_match 'data.write(to: statusUrl' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'data.write(to: statusUrl' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'provider_config_shared_path_allowed' ios/Runner/AppDelegate.swift
grep -q 'provider_config_shared_path_allowed' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_config_shared_path_allowed' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_config_shared_path_allowed=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_config_app_group_id_allowed' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_config_app_group_id_allowed=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_config_source=transient_start_options' test/apple_tunnel_diagnostics_test.dart
grep -q 'expectSharedConfigPathGuard' tools/verify_apple_tunnel_config.swift
grep -q 'expectAppGroupValidation' tools/verify_apple_tunnel_config.swift
refute_match 'URL(fileURLWithPath: sharedConfigPath)' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'URL(fileURLWithPath: sharedConfigPath)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'maxRuntimeConfigFileBytes' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'runtimeConfigTooLargeCode' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'validateRuntimeConfigSize(rawConfig)' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectBoundedUTF8FileReader' tools/verify_apple_tunnel_config.swift
grep -q 'expectRuntimeConfigSizeValidation' tools/verify_apple_tunnel_config.swift
grep -q 'runtimeConfigFileContents' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'runtimeConfigFileContents' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'providerStatusFields(from:' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'providerStatusFields(from:' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusFields.merge(Self.providerStatusFields(from: error))' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusFields.merge(Self.providerStatusFields(from: error))' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngineError.statusFieldsUserInfoKey' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngineError.statusFieldsUserInfoKey' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_file_too_large' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_file_too_large' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_utf8_valid' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_utf8_valid' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config_app_group_container_available' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'appGroupValidation.statusFields' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appGroupValidation.statusFields' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'shared_keychain_private_key_available' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'shared_keychain_private_key_available' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'String(contentsOf: fileUrl' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'String(contentsOf: fileUrl' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'containsRedactedPrivateKey' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'containsRedactedPrivateKey' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsClientKeyStore.loadExisting' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsClientKeyStore.loadExisting' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'restoredRuntimeConfig' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'restoredRuntimeConfig' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'latest_status.json' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'latest_status.json' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'status_generation' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'status_generation' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusGenerationFields' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusGenerationFields' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusGeneration(options: nil)' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusGeneration(options: nil)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'preferredStatusGeneration' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'preferredStatusGeneration' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'preferredStatusGeneration' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'savedProviderConfigurationString("status_generation")' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'savedProviderConfigurationString("status_generation")' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelProviderStatus.writableData' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelProviderStatus.writableData' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'static func writableData' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'status_write_payload_too_large' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'expectProviderStatusWritableDataLimit' tools/verify_apple_tunnel_config.swift
grep -q 'WinsPacketTunnelProviderAppMessage' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelProviderAppMessage' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'activeEngineStatusFields' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'activeEngineStatusFields' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'self.activeEngineStatusFields = statusFields' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'self.activeEngineStatusFields = statusFields' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusFields.merge(message.statusFields)' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'statusFields.merge(message.statusFields)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appMessageReady' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'appMessageReady' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'message.accepted' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'message.accepted' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelProviderLifecycle.statusFields' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelProviderLifecycle.statusFields' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'stage: "sleeping"' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'stage: "sleeping"' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'stage: "woke"' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'stage: "woke"' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineReady: false' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineReady: false' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'networkSettingsReady: false' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'networkSettingsReady: false' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'app_message_command_is_health' ios/Runner/AppDelegate.swift
grep -q 'app_message_command_is_health' macos/Runner/MainFlutterWindow.swift
refute_match 'completionHandler?(messageData)' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'completionHandler?(messageData)' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'payloadStatusGeneration' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_missing' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_missing' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineFailureStage' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineFailureStage' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_start_failed' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_start_failed' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'missingNativeEngineCode' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'missingNativeEngineCode' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'provider_engine_runtime_contract_failed' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_contract_failed' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_runtime_packet_flow_attached' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_packet_flow_attached' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_runtime_engine_ready_reported' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_engine_ready_reported' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_runtime_engine_running_reported' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_engine_running_reported' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_runtime_awg_started' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_awg_started' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_runtime_xray_started' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_runtime_xray_started' macos/Runner/MainFlutterWindow.swift
grep -q 'engine_runtime_contract_failed=' lib/apple_tunnel_diagnostics.dart
grep -q 'engine_runtime_packet_flow_attached=' lib/apple_tunnel_diagnostics.dart
grep -q 'engine_runtime_awg_started=' lib/apple_tunnel_diagnostics.dart
grep -q 'engine_runtime_xray_started=' lib/apple_tunnel_diagnostics.dart
grep -q 'network_settings_failed' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_failed' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'writeProviderStatus' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'writeProviderStatus' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'status_schema_version' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelProviderStatus' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'setTunnelNetworkSettings' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'setTunnelNetworkSettings' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'ProviderRuntimeConfig' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'ProviderRuntimeConfig' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'private_key_source' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'private_key_source' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'client_key_pair_verification_required' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'client_key_pair_verification_required' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_available' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_available' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_source' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_source' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_source' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'expected_client_public_key_valid' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_valid' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expected_client_public_key_valid' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'expectedClientPublicKeyValid' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectedClientPublicKeyValid' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'client_key_pair_verified' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'client_key_pair_verified' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectedClientPublicKey' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'expectedClientPublicKey' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'preferredClientPublicKey' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'preferredClientPublicKeySource' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'preferredClientPublicKeySelection' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'preferredClientPublicKey' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'preferredClientPublicKey' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'savedProviderConfigurationString("client_public_key")' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'savedProviderConfigurationString("client_public_key")' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'validateInterfacePrivateKeyMatchesPublicKey' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'validateInterfacePrivateKeyMatchesPublicKey' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_applied' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'network_settings_applied' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'default_route_enabled' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'ipv6_leak_protection_enabled' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'ipv6_sink_address_present' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'dns_match_domains' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'dns_full_tunnel_match_enabled' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'transport_endpoint_kind' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'network_settings_remote_address_kind' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'Validated packet tunnel config summary peer_kind=' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'Validated packet tunnel config summary peer_kind=' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsTunnelDiagnostics.redactedProviderErrorMessage' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsTunnelDiagnostics.redactedProviderErrorMessage' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsTunnelDiagnostics' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'redactedProviderErrorMessage' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsTunnelDiagnostics.redactedProviderErrorMessage(error)' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'safeControlledErrorMessage' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'containsUnsafeControlledErrorFragment' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'containsIPv6Literal' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'expectProviderErrorRedaction' tools/verify_apple_tunnel_config.swift
grep -q 'expectProviderStatusPayload' tools/verify_apple_tunnel_config.swift
grep -q 'redactedSystemErrorMessage' tools/verify_apple_tunnel_config.swift
grep -q 'Unsafe controlled provider error was not redacted' tools/verify_apple_tunnel_config.swift
grep -q 'Unsafe controlled host error was not redacted' tools/verify_apple_tunnel_config.swift
grep -q 'stream.winsvpn.org' tools/verify_apple_tunnel_config.swift
grep -q '2001:db8::1' tools/verify_apple_tunnel_config.swift
grep -q 'Redacted host error fields leaked unsafe fragment' tools/verify_apple_tunnel_config.swift
grep -q 'See provider_error_domain and provider_error_code' apple/WinsTunnelCore/WinsTunnelConfig.swift
refute_match 'Validated packet tunnel config for endpoint' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'Validated packet tunnel config for endpoint' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'parsedConfig.peerEndpoint,' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'parsedConfig.peerEndpoint,' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'parsedConfig.interfaceIPv4Address,' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'parsedConfig.interfaceIPv4Address,' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["error_message"\] = nsError.localizedDescription' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["error_message"\] = nsError.localizedDescription' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'adapterFailure(error.localizedDescription' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'transport_ipv4_route_excluded' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'transport_ipv4_exclusion_route_present' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
refute_match 'payload\["peer_endpoint"\]' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["peer_endpoint"\]' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["transport_endpoint_host"\]' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["transport_endpoint_host"\]' macos/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["network_settings_remote_address"\]' ios/PacketTunnel/PacketTunnelProvider.swift
refute_match 'payload\["network_settings_remote_address"\]' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'transport_mode' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'required_engine_components' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelEngine' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngine' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngineFactory.makeEngine' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngineFactory.makeEngine' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'packetFlow: self.packetFlow' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'packetFlow: self.packetFlow' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'lifecycleGate.invalidate' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'lifecycleGate.invalidate' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineAtStop?.stop' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engineAtStop?.stop' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'performIfCurrent(lifecycleToken' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'performIfCurrent(lifecycleToken' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_started' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_started' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsPacketTunnelEngineBundleProbe' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelEngineBundleProbe.probe' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'privateFrameworksURL' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_bundle_probe' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_bundle_missing_components' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_bundle_all_required_components_present' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'native_engine_adapter_missing' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'native packet engine adapter was not available at runtime' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_required_components' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_launch_contract_version' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelEngineLaunchDescriptor' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_launch_descriptor_schema_version' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_launch_descriptor_secret_material_redacted' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_interface_private_key_redacted' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_peer_public_key_redacted' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_awg_obfuscation_field_count' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_packet_flow_required' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_packet_flow_available' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'packetFlow: AnyObject' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'packetFlowAvailable: packetFlow != nil' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_ipv6_leak_protection_enabled' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_ipv6_sink_prefix_length' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_xray_transport_required' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelEngineStartResult' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'protocol WinsPacketTunnelEngine' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'protocol WinsPacketTunnelEngineAdapter' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelEngineFactory' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsMissingPacketTunnelEngine' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsAdapterBackedPacketTunnelEngine' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsNativePacketTunnelEngineAdapter' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'dlopen' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'dlsym' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'wins_amneziawg_packet_engine_create' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'wins_xray_vless_ws_transport_configure' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'ne_packet_tunnel_flow_opaque_pointer' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'adapter: WinsNativePacketTunnelEngineAdapter' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'adapter: WinsNativePacketTunnelEngineAdapter' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'engine_adapter_available' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_lifecycle_state' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelProviderAppMessage' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'app_message_raw_payload_redacted' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'maxAcceptedMessageBytes' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'WinsPacketTunnelProviderLifecycle' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'lifecycle_suspended' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'xray_local_port_present' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'NEPacketTunnelNetworkSettings' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEPacketTunnelNetworkSettings' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'allowedIPv4Routes' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'allowedIPv4Routes' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv4Route.default' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv4Route.default' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv6Settings' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv6Settings' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv6Route.default' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEIPv6Route.default' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'excludedRoutes' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'excludedRoutes' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEDNSSettings' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'NEDNSSettings' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'matchDomains' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'matchDomains' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'WinsTunnelConfig.parseAndValidate' ios/Runner/AppDelegate.swift
grep -q 'WinsTunnelConfig.parseAndValidate' macos/Runner/MainFlutterWindow.swift
grep -q 'validateInterfacePrivateKeyMatches' ios/Runner/AppDelegate.swift
grep -q 'validateInterfacePrivateKeyMatches' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsClientKeyStore.loadOrCreate' ios/Runner/AppDelegate.swift
grep -q 'WinsClientKeyStore.loadOrCreate' macos/Runner/MainFlutterWindow.swift
grep -q 'loadOrCreateClientKeyPair' lib/main.dart
grep -q '_configMatchesLocalClientKeys' lib/main.dart
grep -q 'Apple native Keychain client key pair is required' lib/main.dart
grep -q '_isApplePlatform' lib/main.dart
grep -q '_latestTunnelReadiness' lib/main.dart
grep -q '_recordAppleTunnelFailure' lib/main.dart
grep -q 'appleTunnelReady' lib/main.dart
grep -q 'if (_isApplePlatform) {' lib/main.dart
grep -q "state == AppLifecycleState.resumed" lib/main.dart
grep -q '_statusHeartbeatRunning ||' lib/main.dart
grep -Fq 'if (!Platform.isAndroid && !_isApplePlatform) return;' lib/main.dart
grep -q '_statusHeartbeatRunning = true' lib/main.dart
grep -q '_statusHeartbeatRunning = false' lib/main.dart
# Since d20b5db the native-readiness platform list spans several lines and also
# names Windows and Linux; Android and the Apple platforms must stay in it.
awk '/bool get _supportsNativeTunnelReadiness =>/,/;$/' lib/main.dart \
  | grep -q 'Platform.isAndroid ||'
awk '/bool get _supportsNativeTunnelReadiness =>/,/;$/' lib/main.dart \
  | grep -q '_isApplePlatform;'
grep -Fq '_supportsNativeTunnelReadiness ? nativeActive : _isConnected;' lib/main.dart
refute_match -F '_isConnected || nativeActive' lib/main.dart
grep -q 'provider-aware truth check; raw OS' lib/main.dart
grep -q '"connected" state is not enough to prove VPN traffic is protected' lib/main.dart
grep -q "appleReadinessBool(readiness, 'provider_engine_ready')" lib/main.dart
grep -q "appleReadinessBool(readiness, 'provider_healthy')" lib/main.dart
grep -q "appleReadinessBool(readiness, 'network_extension_connected')" lib/main.dart
grep -q 'appleTunnelUserFailureStatus' lib/main.dart
grep -q 'appleTunnelDebugFailureSummary' lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE' lib/main.dart
grep -q 'apple_live_tunnel_smoke.json' lib/main.dart
grep -q 'result_filename' lib/main.dart
grep -q 'created_at_epoch' lib/main.dart
grep -q 'apple_live_tunnel_smoke_' tools/apple_runtime_smoke.sh
grep -q 'created_at_epoch' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_FILENAME' lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_DIRECTORY' lib/main.dart
grep -q 'WINS_APPLE_EXTERNAL_LEAK_AUDIT' lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN' lib/main.dart
grep -q "'double_vpn_verified': doubleVpnVerified" lib/main.dart
grep -q "'double_vpn_core_id': doubleVpnCoreId" lib/main.dart
grep -q "'double_vpn_exit_slug': doubleVpnExitSlug" lib/main.dart
grep -q 'externalLeakAuditUrls' lib/main.dart
grep -q 'externalLeakAuditMinimumEndpoints' lib/main.dart
grep -q '_emitAppleLiveTunnelSmokeHarnessLine' lib/main.dart
grep -q 'stdout.writeln(message)' lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST' lib/main.dart
grep -q 'apple_live_tunnel_smoke_request.json' lib/main.dart
grep -q 'apple_live_tunnel_smoke_request_pointer.json' lib/main.dart
grep -q 'request_filename' lib/main.dart
grep -q '_runAppleLiveTunnelSmoke' lib/main.dart
grep -q 'secret_material_redacted' lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_EXPECT_DOUBLE_VPN' tools/apple_runtime_smoke.sh
grep -q -- '--dart-define=WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN=' tools/apple_runtime_smoke.sh
grep -q 'DEVICECTL_CHILD_WINS_APPLE_LIVE_TUNNEL_SMOKE_DOUBLE_VPN' tools/apple_runtime_smoke.sh
grep -q 'passed Double VPN result is missing required true field' tools/apple_runtime_smoke.sh
grep -q 'DEVICECTL_CHILD_WINS_APPLE_EXTERNAL_LEAK_AUDIT_URLS' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_FORCE_XRAY' tools/apple_runtime_smoke.sh
grep -q -- '--dart-define=WINS_FORCE_XRAY=' tools/apple_runtime_smoke.sh
grep -Fq 'if [[ "${WINS_APPLE_FORCE_XRAY}" == "1" ]]' tools/apple_runtime_smoke.sh
grep -Fq 'printf '\''%s\n'\'' "--dart-define=WINS_FORCE_XRAY=true"' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_FORCE_XRAY' tools/run_apple_current_live_runtime.applescript
grep -q 'WINS_APPLE_FORCE_XRAY' tools/run_apple_current_ios_live_and_macos_build.applescript
grep -q 'WINS_APPLE_FORCE_XRAY' tools/run_apple_macos_installed_development_live.applescript
grep -q 'WINS_APPLE_EXPECT_DOUBLE_VPN' tools/run_apple_macos_installed_development_live.applescript
grep -q 'WINS_APPLE_EXPECT_DOUBLE_VPN' tools/run_apple_current_ios_live_only.applescript
grep -q 'WINS_APPLE_FORCE_XRAY' tools/run_apple_current_macos_build_only.applescript
grep -q 'quoted form of forceXray' tools/run_apple_current_macos_build_only.applescript
grep -q 'macos_live_tunnel_smoke' tools/apple_runtime_smoke.sh
grep -q 'Apple live tunnel smoke' tools/apple_runtime_smoke.sh
grep -q 'force_macos_flutter_assemble' tools/apple_runtime_smoke.sh
grep -q 'Flutter App.framework is older than lib/main.dart' tools/apple_runtime_smoke.sh
grep -q '.dart_tool/flutter_build' tools/apple_runtime_smoke.sh
grep -q 'local_paths' tools/apple_runtime_smoke.sh
grep -Fq 'if [[ "${WINS_MACOS_LAUNCH_RELEASE}" != "1" ]]' tools/apple_runtime_smoke.sh
grep -q "Build/Products/Debug/Win's VPN.app" tools/apple_runtime_smoke.sh
grep -q 'Build/Products/Debug/wins_vpn.app' tools/apple_runtime_smoke.sh
grep -q 'Library/Group Containers/${APPLE_MACOS_APP_GROUP_ID}' tools/apple_runtime_smoke.sh
grep -q 'Library/Containers/${MACOS_BUNDLE_ID}' tools/apple_runtime_smoke.sh
grep -q '/usr/bin/open' tools/apple_runtime_smoke.sh
grep -q -- '--env WINS_APPLE_LIVE_TUNNEL_SMOKE=1' tools/apple_runtime_smoke.sh
grep -q -- '--env WINS_APPLE_LIVE_TUNNEL_SMOKE_REQUEST=1' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_FILENAME' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT_DIRECTORY' tools/apple_runtime_smoke.sh
grep -q 'read_apple_live_tunnel_smoke_status' tools/apple_runtime_smoke.sh
grep -q 'validate_apple_live_tunnel_smoke_result' tools/apple_runtime_smoke.sh
grep -q 'read_apple_live_tunnel_smoke_log_status' tools/apple_runtime_smoke.sh
grep -q 'validate_apple_live_tunnel_smoke_log_result' tools/apple_runtime_smoke.sh
grep -q 'iOS VPN configuration permission pending on the device' tools/apple_runtime_smoke.sh
grep -q 'manager_invalid_after_config_save' tools/apple_runtime_smoke.sh
grep -q 'vpn_permission_pending' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_RESULT ' lib/main.dart
grep -q '(kReleaseMode && !_appleLiveTunnelSmokeEnabled)' lib/main.dart
grep -q "apple_live_tunnel_smoke_pin_missing_or_invalid" lib/main.dart
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN="${WINS_APPLE_LIVE_TUNNEL_SMOKE_PIN:-}"' tools/apple_runtime_smoke.sh
flutter_build_define_args_contract="$(
  awk '
    /^flutter_build_define_args\(\) \{/ { capture=1 }
    /^log_winn3_descriptor_pubkey_status_for_defines\(\) \{/ { capture=0 }
    capture { print }
  ' tools/apple_runtime_smoke.sh
)"
printf '%s\n' "${flutter_build_define_args_contract}" \
  | grep -Fq 'Apple distribution archives must not compile live-tunnel smoke defines.'
printf '%s\n' "${flutter_build_define_args_contract}" \
  | grep -Fq '|| "${WINS_MACOS_DEVELOPER_ID_EXPORT_SMOKE}" == "1"'
grep -q 'WINS_APPLE_LIVE_TUNNEL_SMOKE=0' tools/build_apple_release_candidates.sh
grep -q 'WINS_IOS_LIVE_TUNNEL_SMOKE=0' tools/build_apple_release_candidates.sh
if grep -q "defaultValue: '8642'" lib/main.dart \
  || grep -q "return pinPolicyRejectionReason(pin) == null ? pin : '830472'" lib/main.dart; then
  printf 'Apple release smoke must not embed a default PIN.\n' >&2
  exit 1
fi
grep -q 'appleTunnelReady' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelProviderStatusCurrent' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelProviderAppMessageTrusted' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelProviderLifecycleTrusted' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelProviderSchemaUnsupported' lib/apple_tunnel_diagnostics.dart
grep -q 'appleSafeDiagnosticString' lib/apple_tunnel_diagnostics.dart
grep -q '_appleRawDiagnosticFragments' lib/apple_tunnel_diagnostics.dart
grep -q '_appleDiagnosticListMaxCount' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelUserFailureStatus' lib/apple_tunnel_diagnostics.dart
grep -q 'appleTunnelDebugFailureSummary' lib/apple_tunnel_diagnostics.dart
grep -q 'appleLiveTunnelSmokeReadinessSnapshot' lib/main.dart
grep -q 'appleLiveTunnelSmokeProbeSnapshot' lib/main.dart
grep -q 'appleLiveTunnelSmokeReadinessSnapshot' lib/apple_tunnel_diagnostics.dart
grep -q 'appleLiveTunnelSmokeProbeSnapshot' lib/apple_tunnel_diagnostics.dart
grep -q '_appleLiveTunnelSmokeProbeFallbackSummary' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_failed' lib/apple_tunnel_diagnostics.dart
grep -q 'live tunnel smoke readiness snapshot' test/apple_tunnel_diagnostics_test.dart
grep -q 'live tunnel smoke probe snapshot' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_status_file_too_large' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_json_valid' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_container_available' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_file_readable' lib/apple_tunnel_diagnostics.dart
grep -q 'provider status file diagnostics' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_status_write_payload_too_large' lib/apple_tunnel_diagnostics.dart
grep -q 'provider status write limiting' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_config_file_too_large' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_config_utf8_valid' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_config_app_group_container_available' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_shared_keychain_private_key_available' lib/apple_tunnel_diagnostics.dart
grep -q 'provider config handoff diagnostics' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_engine_bundle_probe' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_bundle_missing_components' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_bundle_available_components' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_bundle_all_required_components_present' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_adapter_available' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_launch_descriptor_ready' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_launch_descriptor_secret_material_redacted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_awg_uapi_config_ready' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_awg_uapi_secret_material_redacted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_interface_private_key_redacted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_peer_public_key_redacted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_awg_obfuscation_field_count' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_required_components' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_launch_contract_version' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_packet_flow_required' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_packet_flow_available' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_xray_transport_required' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_ipv6_leak_protection_enabled' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_ipv6_leak_protection_enabled' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_transport_ipv4_exclusion_route_present' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_network_settings_remote_address_kind' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_network_settings_remote_address_source' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_transport_endpoint_kind' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_dns_full_tunnel_match_enabled' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_client_key_pair_verification_required' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_expected_client_public_key_source' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_expected_client_public_key_valid' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_client_key_pair_verified' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_lifecycle_event' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_app_message_command_is_health' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_app_message_raw_payload_redacted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_engine_was_running_before_stop' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_attempted' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_healthy' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_command_is_health' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_response_schema_supported' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_response_json_valid' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_message_probe_response_too_large' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_current' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_ready' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_attempted' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_blocked_by_provider_readiness' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_blocked_by_leak_protection_config' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_url_kind' lib/apple_tunnel_diagnostics.dart
grep -q 'internet_probe_status_code' lib/apple_tunnel_diagnostics.dart
grep -q 'external_leak_audit_requested' lib/apple_tunnel_diagnostics.dart
grep -q 'external_leak_audit_passed' lib/apple_tunnel_diagnostics.dart
grep -q 'external_leak_audit_non_google_cloudflare_only' lib/apple_tunnel_diagnostics.dart
grep -q 'leak_protection_config_checked' lib/apple_tunnel_diagnostics.dart
grep -q 'leak_protection_config_kind' lib/apple_tunnel_diagnostics.dart
grep -q 'leak_protection_config_passed' lib/apple_tunnel_diagnostics.dart
grep -q 'leak_protection_dns_count' lib/apple_tunnel_diagnostics.dart
grep -q 'leak_protection_engine_dns_count' lib/apple_tunnel_diagnostics.dart
grep -q 'Apple VPN network probe failed' lib/main.dart
grep -q 'Apple VPN provider did not respond to health check' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_bundle_mismatch' lib/apple_tunnel_diagnostics.dart
grep -q 'Apple VPN provider readiness came from the wrong extension' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_extension_type_mismatch' lib/apple_tunnel_diagnostics.dart
grep -q 'Apple VPN provider readiness came from the wrong Network Extension type' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_timestamp_invalid' lib/apple_tunnel_diagnostics.dart
grep -q 'Apple VPN provider returned an invalid readiness timestamp' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_stage_invalid' lib/apple_tunnel_diagnostics.dart
grep -q 'Apple VPN provider returned an unknown readiness stage' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_stale' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_expected_status_generation' lib/apple_tunnel_diagnostics.dart
grep -q 'appleReadinessStatusGeneration' lib/apple_tunnel_diagnostics.dart
grep -q 'provider_status_generation_invalid=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_missing' test/apple_tunnel_diagnostics_test.dart
grep -q 'Apple VPN engine is not ready in this build yet' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_start_failed' test/apple_tunnel_diagnostics_test.dart
grep -q 'network_settings_failed' test/apple_tunnel_diagnostics_test.dart
grep -q 'APPLE_TUNNEL_CONFIG_INVALID' test/apple_tunnel_diagnostics_test.dart
grep -q 'transport_exclusion_present=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'missing_bundle_components=' test/apple_tunnel_diagnostics_test.dart
grep -q 'available_bundle_components=' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_adapter_available=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_launch_secrets_redacted=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_awg_uapi_ready=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_awg_uapi_secrets_redacted=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'unknown provider status stages are not current readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_stage_invalid=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'appleTunnelProviderAppMessageTrusted' test/apple_tunnel_diagnostics_test.dart
grep -q 'appleTunnelProviderLifecycleTrusted' test/apple_tunnel_diagnostics_test.dart
grep -q 'Apple VPN provider is suspended' test/apple_tunnel_diagnostics_test.dart
grep -q 'Apple VPN provider did not accept health check' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('secret-stage'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_interface_key_redacted=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_peer_key_redacted=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_awg_fields=11' test/apple_tunnel_diagnostics_test.dart
grep -q 'lifecycle=wake' test/apple_tunnel_diagnostics_test.dart
grep -q 'app_message_is_health=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'app_message_redacted=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'previous_app_message_accepted_before_stop=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'previous_app_message_engine_running_before_stop=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'previous_app_message_command_before_stop' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'provider_previous_app_message_command_before_stop' lib/apple_tunnel_diagnostics.dart
grep -q "isNot(contains('secret raw payload'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'provider health message probe gates Apple readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider health probe oversized response stays sanitized' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider health probe contract failures stay not ready' test/apple_tunnel_diagnostics_test.dart
grep -q 'internet probe diagnostics stay provider-gated and sanitized' test/apple_tunnel_diagnostics_test.dart
grep -q 'internet_probe_blocked_by_provider_readiness=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'internet_probe_blocked_by_leak_protection_config=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'leak_protection_config_passed=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'internet probe exposes leak-protection config block safely' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('https://www.winsvpn.org'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_message_probe_timeout=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_message_probe_accepted=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_message_probe_command=readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_message_probe_command_is_health=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_message_probe_schema_supported=true' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('secret raw response'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_runtime_awg_started=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_runtime_xray_started=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'native_engine_adapter_missing' test/apple_tunnel_diagnostics_test.dart
grep -q 'network_remote_kind=ipv4' test/apple_tunnel_diagnostics_test.dart
grep -q 'isNot(contains' test/apple_tunnel_diagnostics_test.dart
grep -q 'dns_full_tunnel_match=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'ipv6_leak_protection=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'engine_ipv6_leak_protection=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_status_stale=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider bundle mismatches are not current readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_bundle_mismatch=true' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('com.example.wrong.PacketTunnel'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'provider extension type mismatches are not current readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_extension_type_mismatch=true' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('app_proxy'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'invalid provider status timestamps are not current readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_timestamp_invalid=true' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('not-a-timestamp'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'unsupported provider status schema is not current readiness' test/apple_tunnel_diagnostics_test.dart
grep -q 'provider_status_schema_unsupported=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'client key verification failures stay visible in diagnostics' test/apple_tunnel_diagnostics_test.dart
grep -q 'client_key_verification_required=true' test/apple_tunnel_diagnostics_test.dart
grep -q 'expected_client_key_source=saved_tunnel_preference' test/apple_tunnel_diagnostics_test.dart
grep -q 'expected_client_key_valid=false' test/apple_tunnel_diagnostics_test.dart
grep -q 'Apple VPN client key is invalid' test/apple_tunnel_diagnostics_test.dart
grep -q 'apple tunnel ready requires current provider health' test/apple_tunnel_diagnostics_test.dart
grep -q 'hostOnlyConnected' test/apple_tunnel_diagnostics_test.dart
grep -q 'WinsInstallIdentityStore.loadOrCreate' ios/Runner/AppDelegate.swift
grep -q 'WinsInstallIdentityStore.loadOrCreate' macos/Runner/MainFlutterWindow.swift
grep -q 'loadOrCreateInstallId' lib/main.dart
grep -q 'redactedForStorage' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'validateInterfacePrivateKeyMatches' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'validateInterfacePrivateKeyMatchesPublicKey' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'validWireGuardPublicKey' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'infoPlistAccessGroupKey' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'preferredFromInfoPlist' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q '#if os(macOS)' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'kSecAttrAccessGroup' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsAwgObfuscation' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WinsXrayRuntimeConfig' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'requiredEngineComponents' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'dnsMatchDomains' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'fullTunnelDNSMatchEnabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'defaultIPv4RouteEnabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'ipv6LeakProtectionEnabled' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'ipv6SinkAddress' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'transportEndpointHost' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'transportEndpointKind' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'networkSettingsRemoteAddress' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'networkSettingsRemoteAddressKind' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'networkSettingsRemoteAddressSource' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'interface_gateway_ipv4' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'transportIPv4ExclusionRoute' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'ipv4NetworkAddress' apple/WinsTunnelCore/WinsTunnelConfig.swift
# Winn Protocol is ADDITIVE to AmneziaWG on Apple, never a replacement for it.
# packetCarrierComponent used to select winn_packet_engine INSTEAD of
# amneziawg_packet_engine, which would have handed raw tun packets to a datapath
# with no AmneziaWG implementation in it. These anchor the corrected shape.
grep -q 'winnSeamComponent' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'winnEndpointHost' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'rewritingEndpointTo' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'loopbackHost' apple/WinsTunnelCore/WinsTunnelConfig.swift
refute_match 'winnEnabled ? "winn_packet_engine" : "amneziawg_packet_engine"' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'winnSeamPortSymbol' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'wins_winn_packet_engine_awg_seam_port' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_winn_seam_bound' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'engine_runtime_winn_awg_uapi_repointed' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
grep -q 'static let all = \[amneziaWG, winn\]' apple/WinsTunnelCore/WinsPacketTunnelEngine.swift
# The Apple ABI builds direct-awg AND http3-connect-udp -- the latter through
# WinnTunnelCreateWithCarrier (apple/EngineWrappers/WinnTunnel.h), which takes
# the carrier profile document as a second C string. This comment used to say
# "the Apple ABI builds direct-awg only", which was true before that entry point
# existed and is not true now. The greps below were always about the CARRIER
# GATE rather than about which carriers exist, and they are unchanged.
#
# A config naming a carrier this build does not support must be REFUSED at both
# layers, never normalized to direct-awg: that would replace an authenticated
# post-quantum outer transport with plain UDP while the tunnel still came up,
# which no winn/3 version gate would catch.
grep -q 'supportedWinnCarrier' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'WINS_WINN_SUPPORTED_CARRIER' apple/EngineWrappers/WinsWinnPacketEngine.m
grep -q 'isEqualToString:@WINS_WINN_SUPPORTED_CARRIER' apple/EngineWrappers/WinsWinnPacketEngine.m
refute_match '"carrier":"direct-awg"' apple/EngineWrappers/WinsWinnPacketEngine.m
grep -q 'validAwgObfuscation' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'validXraySecurity' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'provider_engine_required_components' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_required_components' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_launch_contract_version' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_launch_contract_version' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_packet_flow_required' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_packet_flow_required' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_packet_flow_available' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_packet_flow_available' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_engine_ipv6_leak_protection_enabled' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_ipv6_leak_protection_enabled' macos/Runner/MainFlutterWindow.swift
grep -q 'activeConfig' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'activeConfig' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config: activeConfig' ios/PacketTunnel/PacketTunnelProvider.swift
grep -q 'config: activeConfig' macos/PacketTunnel/PacketTunnelProvider.swift
grep -q 'provider_engine_xray_transport_required' ios/Runner/AppDelegate.swift
grep -q 'provider_engine_xray_transport_required' macos/Runner/MainFlutterWindow.swift
grep -q 'provider_xray_local_port_present' ios/Runner/AppDelegate.swift
grep -q 'provider_xray_local_port_present' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsTunnelDiagnostics.redactedAppleErrorMessage' ios/Runner/AppDelegate.swift
grep -q 'WinsTunnelDiagnostics.redactedAppleErrorMessage' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsTunnelDiagnostics.redactedAppleErrorFields' ios/Runner/AppDelegate.swift
grep -q 'WinsTunnelDiagnostics.redactedAppleErrorFields' macos/Runner/MainFlutterWindow.swift
grep -q 'WinsTunnelDiagnostics.nativeErrorDetails' ios/Runner/AppDelegate.swift
grep -q 'WinsTunnelDiagnostics.nativeErrorDetails' macos/Runner/MainFlutterWindow.swift
grep -q 'redactedAppleErrorMessage' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'maxControlledErrorMessageLength' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'nativeErrorDetails' apple/WinsTunnelCore/WinsTunnelConfig.swift
grep -q 'redactedAppleSystemErrorMessage' tools/verify_apple_tunnel_config.swift
grep -q 'platformExceptionNativeDetails' lib/apple_tunnel_diagnostics.dart
grep -q 'native bridge error summaries keep structured codes but not raw paths' test/apple_tunnel_diagnostics_test.dart
grep -q 'diagnostic scalar and list values fail closed when unsafe' test/apple_tunnel_diagnostics_test.dart
grep -q '_appleHostnameLikePattern' lib/apple_tunnel_diagnostics.dart
grep -q '_appleUuidLikePattern' lib/apple_tunnel_diagnostics.dart
grep -q 'stream.winsvpn.org' test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('stream.winsvpn.org'))" test/apple_tunnel_diagnostics_test.dart
grep -q "isNot(contains('00000000-0000-0000-0000-000000000000'))" test/apple_tunnel_diagnostics_test.dart
grep -q 'native bridge error summaries redact unsafe messages' test/apple_tunnel_diagnostics_test.dart
grep -q 'native_domain=NEVPNErrorDomain' test/apple_tunnel_diagnostics_test.dart
refute_match 'error\.localizedDescription' ios/Runner/AppDelegate.swift
refute_match 'error\.localizedDescription' macos/Runner/MainFlutterWindow.swift
refute_match 'saveError\.localizedDescription' ios/Runner/AppDelegate.swift
refute_match 'saveError\.localizedDescription' macos/Runner/MainFlutterWindow.swift
refute_match 'loadError\.localizedDescription' ios/Runner/AppDelegate.swift
refute_match 'loadError\.localizedDescription' macos/Runner/MainFlutterWindow.swift
refute_match 'removalError\.localizedDescription' ios/Runner/AppDelegate.swift
refute_match 'removalError\.localizedDescription' macos/Runner/MainFlutterWindow.swift
HOST_TMP="$(mktemp -d)"
# Cleanup is handled once by wins_readiness_on_exit (installed near the top),
# which removes every temp dir and always reports deferred failures.
cat > "${HOST_TMP}/FlutterMacOS.swift" <<'SWIFT'
import Cocoa

public protocol FlutterBinaryMessenger {}
public typealias FlutterResult = (Any?) -> Void
public class FlutterError: NSObject { public init(code: String, message: String?, details: Any?) {} }
public let FlutterMethodNotImplemented = NSObject()
public class FlutterMethodCall: NSObject {
  public let method: String
  public let arguments: Any?
  public init(method: String, arguments: Any?) {
    self.method = method
    self.arguments = arguments
  }
}
public class FlutterMethodChannel: NSObject {
  public init(name: String, binaryMessenger: FlutterBinaryMessenger) {}
  public func setMethodCallHandler(_ handler: ((FlutterMethodCall, @escaping FlutterResult) -> Void)?) {}
}
public protocol FlutterMessageCodec: AnyObject {}
public class FlutterStandardMessageCodec: NSObject, FlutterMessageCodec {
  public static func sharedInstance() -> FlutterStandardMessageCodec { FlutterStandardMessageCodec() }
}
public protocol FlutterPlatformViewFactory {
  func createArgsCodec() -> (FlutterMessageCodec & NSObjectProtocol)?
  func create(withViewIdentifier viewIdentifier: Int64, arguments args: Any?) -> NSView
}
public class FlutterPluginRegistrar: NSObject {
  public func register(_ factory: FlutterPlatformViewFactory, withId factoryId: String) {}
}
private final class DummyMessenger: FlutterBinaryMessenger {}
public class FlutterEngine: NSObject { public let binaryMessenger: FlutterBinaryMessenger = DummyMessenger() }
public class FlutterViewController: NSViewController {
  public let engine = FlutterEngine()
  public func registrar(forPlugin pluginKey: String) -> FlutterPluginRegistrar { FlutterPluginRegistrar() }
}
public func RegisterGeneratedPlugins(registry: Any) {}
SWIFT

cat > "${HOST_TMP}/MacHostSupport.swift" <<'SWIFT'
import Foundation

// MainFlutterWindow shares this logger with AppDelegate. The isolated host
// bridge type-check deliberately excludes AppDelegate, so model only the one
// API the window consumes while compiling the real RouteAudit implementation.
enum WinsAppLifecycle {
  static func note(_ message: String) {}
}
SWIFT

"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -emit-module -module-name FlutterMacOS "${HOST_TMP}/FlutterMacOS.swift" -o "${HOST_TMP}/FlutterMacOS.swiftmodule"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck -I "${HOST_TMP}" \
  "${WINS_TUNNEL_CORE_SOURCES[@]}" \
  macos/Runner/RouteAudit.swift \
  "${HOST_TMP}/MacHostSupport.swift" \
  macos/Runner/MainFlutterWindow.swift

cat > "${HOST_TMP}/UIKit.swift" <<'SWIFT'
import Foundation
import CoreGraphics

open class UIApplication: NSObject {
  public struct LaunchOptionsKey: Hashable, RawRepresentable {
    public var rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
  }
  public static let shared = UIApplication()
  open var connectedScenes: Set<UIScene> = []
  open var supportsAlternateIcons: Bool { true }
  open var alternateIconName: String? { nil }
  open func setAlternateIconName(_ alternateIconName: String?, completionHandler: ((Error?) -> Void)? = nil) {
    completionHandler?(nil)
  }
  open func open(_ url: URL, options: [AnyHashable: Any] = [:], completionHandler completion: ((Bool) -> Void)? = nil) {
    completion?(true)
  }
}
open class UIDevice: NSObject {
  public static let current = UIDevice()
  open var systemName: String { "iOS" }
  open var systemVersion: String { "0" }
}
open class UIScene: NSObject {}
open class UIWindowScene: UIScene { open var windows: [UIWindow] = [] }
open class UIWindow: NSObject {
  open var isKeyWindow: Bool = false
  open var rootViewController: UIViewController?
}
open class UIView: NSObject { open var bounds: CGRect = .zero }
open class UIViewController: NSObject {
  open var view = UIView()
  open var presentedViewController: UIViewController?
  open func present(_ viewControllerToPresent: UIViewController, animated flag: Bool, completion: (() -> Void)? = nil) {
    completion?()
  }
}
public struct UIPopoverArrowDirection: OptionSet {
  public let rawValue: UInt
  public init(rawValue: UInt) { self.rawValue = rawValue }
}
open class UIPopoverPresentationController: NSObject {
  open var sourceView: UIView?
  open var sourceRect: CGRect = .zero
  open var permittedArrowDirections: UIPopoverArrowDirection = []
}
open class UIActivityViewController: UIViewController {
  open var popoverPresentationController: UIPopoverPresentationController? = UIPopoverPresentationController()
  public init(activityItems: [Any], applicationActivities: [Any]?) {}
}
SWIFT

cat > "${HOST_TMP}/Flutter.swift" <<'SWIFT'
import Foundation
import UIKit

public protocol FlutterBinaryMessenger {}
public typealias FlutterResult = (Any?) -> Void
public class FlutterError: NSObject { public init(code: String, message: String?, details: Any?) {} }
public let FlutterMethodNotImplemented = NSObject()
public class FlutterMethodCall: NSObject {
  public let method: String
  public let arguments: Any?
  public init(method: String, arguments: Any?) {
    self.method = method
    self.arguments = arguments
  }
}
public class FlutterMethodChannel: NSObject {
  public init(name: String, binaryMessenger: FlutterBinaryMessenger) {}
  public func setMethodCallHandler(_ handler: ((FlutterMethodCall, @escaping FlutterResult) -> Void)?) {}
}
public protocol FlutterMessageCodec: AnyObject {}
public class FlutterStandardMessageCodec: NSObject, FlutterMessageCodec {
  public static func sharedInstance() -> FlutterStandardMessageCodec { FlutterStandardMessageCodec() }
}
public protocol FlutterPlatformView { func view() -> UIView }
public protocol FlutterPlatformViewFactory {
  func createArgsCodec() -> FlutterMessageCodec & NSObjectProtocol
  func create(withFrame frame: CGRect, viewIdentifier viewId: Int64, arguments args: Any?) -> FlutterPlatformView
}
public protocol FlutterPluginRegistry { func registrar(forPlugin pluginKey: String) -> FlutterPluginRegistrar? }
public class FlutterPluginRegistrar: NSObject {
  private final class DummyMessenger: FlutterBinaryMessenger {}
  public func messenger() -> FlutterBinaryMessenger { DummyMessenger() }
  public func register(_ factory: FlutterPlatformViewFactory, withId factoryId: String) {}
}
public class FlutterImplicitEngineBridge: NSObject {
  public let pluginRegistry: FlutterPluginRegistry
  public init(pluginRegistry: FlutterPluginRegistry) { self.pluginRegistry = pluginRegistry }
}
public protocol FlutterImplicitEngineDelegate {}
open class FlutterAppDelegate: NSObject {
  open func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool { true }
}
SWIFT

cat > "${HOST_TMP}/GeneratedPluginRegistrant.swift" <<'SWIFT'
import Flutter
final class GeneratedPluginRegistrant {
  static func register(with registry: FlutterPluginRegistry) {}
}
SWIFT

sed '/^@main$/d' ios/Runner/AppDelegate.swift > "${HOST_TMP}/AppDelegateCheck.swift"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -emit-module -module-name UIKit "${HOST_TMP}/UIKit.swift" -o "${HOST_TMP}/UIKit.swiftmodule"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -emit-module -module-name Flutter -I "${HOST_TMP}" "${HOST_TMP}/Flutter.swift" -o "${HOST_TMP}/Flutter.swiftmodule"
"${SWIFTC_BIN}" "${SWIFTC_ARGS[@]}" -typecheck -I "${HOST_TMP}" "${WINS_TUNNEL_CORE_SOURCES[@]}" "${HOST_TMP}/GeneratedPluginRegistrant.swift" "${HOST_TMP}/AppDelegateCheck.swift"

}

wins_readiness_section_19_apple_native_xctest() {
section "Apple Native XCTest"
test -f ios/RunnerTests/RunnerTests.swift
test -f macos/RunnerTests/RunnerTests.swift
test -f ios/WinsWatchTests/ChannelTests.swift
grep -q '@testable import Runner' ios/RunnerTests/RunnerTests.swift
grep -q '@testable import Win_s_VPN' macos/RunnerTests/RunnerTests.swift
if grep -q 'func testExample' ios/RunnerTests/RunnerTests.swift || \
   grep -q 'func testExample' macos/RunnerTests/RunnerTests.swift; then
  printf 'Generated placeholder Apple XCTest remains in the release test suites.\n' >&2
  exit 1
fi
ios_native_test_count="$(grep -c '^  func test' ios/RunnerTests/RunnerTests.swift)"
macos_native_test_count="$(grep -c '^  func test' macos/RunnerTests/RunnerTests.swift)"
watch_native_test_count="$(grep -c '^    func test' ios/WinsWatchTests/ChannelTests.swift)"
if (( ios_native_test_count < 10 || macos_native_test_count < 10 || watch_native_test_count < 10 )); then
  printf 'Expected at least 10 native tests per Apple platform; found iOS=%s macOS=%s watchOS=%s.\n' \
    "${ios_native_test_count}" "${macos_native_test_count}" "${watch_native_test_count}" >&2
  exit 1
fi
for ios_only_test_marker in \
  testCalculatorCamouflageUsesAlternateIconAndUnlockRestoresPrimaryIcon \
  testIOSPrivateConfigStoreCreatesAndReplacesProtectedOwnerOnlyFile \
  testIOSPrivateConfigStoreRejectsSymlinkDestination \
  testIOSPrivateConfigStoreRejectsSymlinkDirectory \
  testIOSPrivateConfigStoreHardensLegacyFileWithoutChangingBytes \
  testIOSPrivateConfigStoreRejectsOversizedReadAndSafeDeleteRejectsSymlink; do
  grep -q "func ${ios_only_test_marker}" ios/RunnerTests/RunnerTests.swift
done
for macos_only_test_marker in \
  testMacOSPrivateConfigWriterAtomicallyCreatesOwnerOnlyFile \
  testMacOSPrivateConfigWriterRejectsSymbolicLinkDestination \
  testMacOSPrivateConfigWriterRejectsSymbolicLinkDirectory \
  testMacOSPrivateConfigWriterHardensLegacyRegularFileOnly; do
  grep -q "func ${macos_only_test_marker}" macos/RunnerTests/RunnerTests.swift
done
for native_test_marker in \
  testValidatedFullTunnelConfigProducesSafeNetworkPlan \
  testConfigRedactionAndRestorationRoundTrip \
  testConfigRejectsInvalidEndpointAndOversizedInput \
  testHealthMessageRequiresTrustedRedactedResponse \
  testTunnelOperationGateRejectsStaleAsyncCompletions \
  testProviderStatusSerializationIsBoundedAndDropsUnknownSecrets \
  testEngineRuntimeContractRejectsDetachedPacketFlow \
  testEngineRuntimeContractSanitizesAdapterStatus \
  testReadinessRequiresCurrentHealthyFullTunnelEvidence \
  testExternalInputGuardsRejectUnsafeURLsAndLeakCanaries \
  testDiagnosticsNeverExposeSystemOrConfigurationDetails \
  testBundleProbeNormalizesAndDeduplicatesComponentIdentifiers \
  testMapRegionUsesOnlyProvidedPreVPNCoordinates; do
  grep -q "func ${native_test_marker}" ios/RunnerTests/RunnerTests.swift
  grep -q "func ${native_test_marker}" macos/RunnerTests/RunnerTests.swift
done
printf 'Apple native XCTest source gate passed with iOS=%s, macOS=%s, and watchOS=%s tests.\n' \
  "${ios_native_test_count}" "${macos_native_test_count}" "${watch_native_test_count}"

if [[ "${WINS_SKIP_APPLE_NATIVE_XCTESTS:-0}" != "1" && \
      -x "${XCODE_TOOLCHAIN_BIN}/xcodebuild" ]] && \
   xcrun simctl list -j devices available >/dev/null 2>&1; then
  simulator_inventory="$(mktemp "${TMPDIR:-/tmp}/wins-ios-simulators.XXXXXX")"
  xcrun simctl list -j devices available >"${simulator_inventory}"
  ios_native_test_destination="$(${PYTHON_BIN} - "${simulator_inventory}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    inventory = json.load(handle)

devices = []
for runtime_devices in inventory.get("devices", {}).values():
    for device in runtime_devices:
        if not device.get("isAvailable", True):
            continue
        name = str(device.get("name") or "")
        udid = str(device.get("udid") or "")
        if name.startswith("iPhone") or name.startswith("WinsVPN-iPhone"):
            devices.append((device.get("state") != "Booted", name != "WinsVPN-iPhone-16-Pro-Max", name, udid))

devices.sort()
print(devices[0][3] if devices else "")
PY
)"
  if [[ -z "${ios_native_test_destination}" ]]; then
    printf 'Full Xcode is present but no available iPhone simulator was found.\n' >&2
    exit 1
  fi

  watch_native_test_destination="$(${PYTHON_BIN} - "${simulator_inventory}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    inventory = json.load(handle)

devices = []
for runtime_devices in inventory.get("devices", {}).values():
    for device in runtime_devices:
        if not device.get("isAvailable", True):
            continue
        name = str(device.get("name") or "")
        udid = str(device.get("udid") or "")
        if name.startswith("Apple Watch") or name.startswith("WinsVPN-Watch"):
            devices.append((name, udid))

devices.sort()
print(devices[0][1] if devices else "")
PY
)"
  rm -f "${simulator_inventory}"
  if [[ -z "${watch_native_test_destination}" ]]; then
    printf 'Full Xcode is present but no available Apple Watch simulator was found.\n' >&2
    exit 1
  fi

  # Xcode 26.6 can wait indefinitely for a selected shutdown simulator instead
  # of booting it itself. Boot and block on readiness before invoking XCTest.
  xcrun simctl boot "${ios_native_test_destination}" >/dev/null 2>&1 || true
  xcrun simctl bootstatus "${ios_native_test_destination}" -b
  # Run on the booted, ready device itself, not on a freshly cloned one: a new
  # parallel-testing clone can refuse the first app launch with SpringBoard
  # "Busy (Application failed preflight checks)" (seen 3 of 5 runs, 2026-11-03).

  if [[ -n "${WINS_IOS_XCTEST_DERIVED_DATA:-}" ]]; then
    ios_xctest_derived_data="${WINS_IOS_XCTEST_DERIVED_DATA}"
  else
    IOS_XCTEST_TMP="$(mktemp -d "${TMPDIR:-/private/tmp}/winsvpn-ios-xctest-readiness.XXXXXX")"
    ios_xctest_derived_data="${IOS_XCTEST_TMP}"
  fi
  "${XCODE_TOOLCHAIN_BIN}/xcodebuild" -quiet test \
    -workspace ios/Runner.xcworkspace \
    -scheme Runner \
    -destination "platform=iOS Simulator,id=${ios_native_test_destination}" \
    -destination-timeout 60 \
    -derivedDataPath "${ios_xctest_derived_data}" \
    -parallel-testing-enabled NO \
    CODE_SIGNING_ALLOWED=NO \
    -only-testing:RunnerTests \
    -test-timeouts-enabled YES \
    -default-test-execution-time-allowance 60 \
    -maximum-test-execution-time-allowance 120 2>&1 | sanitize_apple_log_output
  printf 'iOS native XCTest passed with %s tests.\n' "${ios_native_test_count}"
  if [[ -n "${IOS_XCTEST_TMP:-}" ]]; then
    rm -rf "${IOS_XCTEST_TMP}"
    IOS_XCTEST_TMP=""
  fi

  xcrun simctl boot "${watch_native_test_destination}" >/dev/null 2>&1 || true
  xcrun simctl bootstatus "${watch_native_test_destination}" -b

  if [[ -n "${WINS_WATCHOS_XCTEST_DERIVED_DATA:-}" ]]; then
    watchos_xctest_derived_data="${WINS_WATCHOS_XCTEST_DERIVED_DATA}"
  else
    WATCHOS_XCTEST_TMP="$(mktemp -d "${TMPDIR:-/private/tmp}/winsvpn-watchos-xctest-readiness.XXXXXX")"
    watchos_xctest_derived_data="${WATCHOS_XCTEST_TMP}"
  fi

  "${XCODE_TOOLCHAIN_BIN}/xcodebuild" -quiet test \
    -project ios/Runner.xcodeproj \
    -scheme WinsWatch \
    -destination "platform=watchOS Simulator,id=${watch_native_test_destination}" \
    -destination-timeout 60 \
    -derivedDataPath "${watchos_xctest_derived_data}" \
    CODE_SIGNING_ALLOWED=NO \
    -only-testing:WinsWatchTests \
    -test-timeouts-enabled YES \
    -default-test-execution-time-allowance 60 \
    -maximum-test-execution-time-allowance 120 2>&1 | sanitize_apple_log_output
  printf 'watchOS native XCTest passed with %s tests.\n' "${watch_native_test_count}"
  if [[ -n "${WATCHOS_XCTEST_TMP:-}" ]]; then
    rm -rf "${WATCHOS_XCTEST_TMP}"
    WATCHOS_XCTEST_TMP=""
  fi

  if [[ -n "${WINS_MACOS_XCTEST_DERIVED_DATA:-}" ]]; then
    macos_xctest_derived_data="${WINS_MACOS_XCTEST_DERIVED_DATA}"
  else
    MACOS_XCTEST_TMP="$(mktemp -d "${TMPDIR:-/private/tmp}/winsvpn-macos-xctest-readiness.XXXXXX")"
    macos_xctest_derived_data="${MACOS_XCTEST_TMP}"
  fi

  "${XCODE_TOOLCHAIN_BIN}/xcodebuild" -quiet test \
    -workspace macos/Runner.xcworkspace \
    -scheme Runner \
    -destination "platform=macOS,arch=$(uname -m)" \
    -derivedDataPath "${macos_xctest_derived_data}" \
    CODE_SIGNING_ALLOWED=NO \
    -only-testing:RunnerTests 2>&1 | sanitize_apple_log_output
  printf 'macOS native XCTest passed with %s tests.\n' "${macos_native_test_count}"
  if [[ -n "${MACOS_XCTEST_TMP:-}" ]]; then
    rm -rf "${MACOS_XCTEST_TMP}"
    MACOS_XCTEST_TMP=""
  fi
elif [[ "${WINS_SKIP_APPLE_NATIVE_XCTESTS:-0}" == "1" ]]; then
  printf 'Apple native XCTest execution explicitly skipped; source gate still passed.\n'
else
  printf 'Full Xcode/simulator runtime unavailable; Apple native XCTest source gate passed.\n'
fi

}

wins_readiness_section_20_flutter_static_checks() {
section "Flutter Static Checks"
if [[ -x "${FLUTTER_BIN}" ]]; then
  "${FLUTTER_BIN}" analyze
  "${FLUTTER_BIN}" test
else
  printf 'Skipping Flutter checks because Flutter is not installed at %s\n' "${FLUTTER_BIN}"
fi

}

wins_readiness_section_21_apple_submission_package() {
section "Apple Submission Package"
if [[ "${WINS_APPLE_RELEASE_CANDIDATE_REBUILD:-0}" == "1" ]]; then
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" != "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" != "1" ]]; then
    printf 'WINS_APPLE_RELEASE_CANDIDATE_REBUILD=1 is restricted to a paired iOS/macOS App Store local export run.\n' >&2
    exit 1
  fi
  printf 'Deferring stale release-candidate hash validation until the paired IPA/PKG rebuild completes.\n'
elif [[ "${WINS_APPLE_RUNTIME_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  if [[ "${WINS_APPLE_LIVE_TUNNEL_SMOKE:-0}" != "1" \
    && "${WINS_IOS_LIVE_TUNNEL_SMOKE:-0}" != "1" ]]; then
    printf 'WINS_APPLE_RUNTIME_EVIDENCE_REFRESH=1 is restricted to a signed live-tunnel smoke run.\n' >&2
    exit 1
  fi
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
    printf 'WINS_APPLE_RUNTIME_EVIDENCE_REFRESH=1 cannot be combined with export or upload lanes.\n' >&2
    exit 1
  fi
  printf 'Deferring stale runtime-evidence validation until this signed live-tunnel refresh completes.\n'
elif [[ "${WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  if [[ "${WINS_APPLE_VERIFY_EXISTING_EXPORTS_ONLY:-0}" != "1" \
      && "${WINS_APPLE_VERIFY_APP_STORE_EXPORTS_ONLY:-0}" != "1" ]]; then
    printf 'WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH=1 requires the existing-exports-only verification lane.\n' >&2
    exit 1
  fi
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
    printf 'WINS_APPLE_EXISTING_EXPORT_EVIDENCE_REFRESH=1 cannot be combined with export or upload lanes.\n' >&2
    exit 1
  fi
  printf 'Deferring stale artifact-log validation until this existing-export evidence refresh completes.\n'
elif [[ "${WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH:-0}" == "1" ]]; then
  if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY:-0}" != "1" \
    || "${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE:-0}" != "1" \
    || "${WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET:-0}" == "1" ]]; then
    printf 'WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH=1 is restricted to the temporary-volume package-install-only root-boundary lane.\n' >&2
    exit 1
  fi
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
    printf 'WINS_MACOS_APP_STORE_PKG_ROOT_GATE_REFRESH=1 cannot be combined with export or upload lanes.\n' >&2
    exit 1
  fi
  printf 'Deferring the pending root-boundary evidence check until this temporary-volume package verification reaches its authorization gate.\n'
elif [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  if [[ "${WINS_MACOS_APP_STORE_PKG_INSTALL_ONLY:-0}" != "1" \
    || "${WINS_MACOS_APP_STORE_PKG_INSTALL_SMOKE:-0}" != "1" \
    || "${WINS_MACOS_APP_STORE_PKG_INSTALL_SYSTEM_TARGET:-0}" != "1" ]]; then
    printf 'WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH=1 is restricted to the clean system-target package-install-only lane.\n' >&2
    exit 1
  fi
  if [[ "${WINS_IOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE:-0}" == "1" \
    || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
    || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
    printf 'WINS_MACOS_APP_STORE_PKG_INSTALL_EVIDENCE_REFRESH=1 cannot be combined with export or upload lanes.\n' >&2
    exit 1
  fi
  printf 'Deferring the pending clean-install evidence check until this system-target package verification completes.\n'
elif [[ "${WINS_APPLE_SOURCE_READINESS_EVIDENCE_REFRESH:-0}" == "1" ]]; then
  printf 'Deferring source-readiness log validation until the current source-only verification log is complete.\n'
elif [[ "${WINS_IOS_TESTFLIGHT_INTERNAL_UPLOAD_SMOKE:-0}" == "1" \
  || "${WINS_IOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" \
  || "${WINS_MACOS_APP_STORE_CONNECT_UPLOAD_SMOKE:-0}" == "1" ]]; then
  # An App Store Connect upload runs after the release-ready flip (owner
  # approval, current candidates, the updated live privacy record); the plain
  # validator below demands the pre-flip state and would refuse it.
  "${PYTHON_BIN}" tools/validate_apple_submission_package.py --release-ready
else
  "${PYTHON_BIN}" tools/validate_apple_submission_package.py
fi

}

wins_readiness_section_22_live_hub_apple_metadata() {
section "Live Hub Apple Metadata"
"${PYTHON_BIN}" - <<'PY'
import json
import time
import urllib.request

CURRENT_APPLE_RELEASE_BLOCKERS = {
    "app_store_metadata_owner_review",
    "app_store_connect_privacy_labels",
    "xcode_privacy_report_review",
    "testflight_or_app_store_upload",
    "app_store_review_submission",
    "macos_app_store_package_install_smoke",
}

LEGACY_LIVE_APPLE_RELEASE_BLOCKERS = {
    "macos_app_store_package_export",
    "app_store_connect_privacy_labels",
    "xcode_privacy_report_review",
    "testflight_or_app_store_upload",
    "external_dns_ip_leak_audit",
}

def fetch(url):
    last_error = None
    for attempt in range(1, 4):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "WinsVPN-Apple-Readiness/1.0",
                "Connection": "close",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = response.read(1024 * 1024 + 1)
                status = getattr(response, "status", 200)
            if status != 200:
                raise RuntimeError(f"HTTP {status}")
            if len(payload) > 1024 * 1024:
                raise RuntimeError("response exceeded 1 MiB read ceiling")
            return json.loads(payload.decode("utf-8"))
        except Exception as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(attempt)
    raise SystemExit(f"failed to fetch {url}: {last_error}")

for platform in ("ios", "macos"):
    nodes = fetch(f"https://sync.winsvpn.org/nodes?platform={platform}")
    support = nodes.get("platform_support") or {}
    if support.get("platform") != platform:
        raise SystemExit(f"missing platform_support for {platform} /nodes")
    free = fetch(f"https://sync.winsvpn.org/free/status?platform={platform}")
    free_support = free.get("platform_support") or {}
    if free_support.get("platform") != platform:
        raise SystemExit(f"missing platform_support for {platform} /free/status")
    for source, metadata in (("/nodes", support), ("/free/status", free_support)):
        if metadata.get("schema_version") != 2:
            raise SystemExit(f"{platform} {source} has unexpected schema_version={metadata.get('schema_version')!r}")
        apple = metadata.get("apple") or {}
        if apple.get("applies") is not True:
            raise SystemExit(f"{platform} {source} missing apple.applies=true")
        if apple.get("network_extension_required") is not True:
            raise SystemExit(f"{platform} {source} missing network_extension_required=true")
        if apple.get("packet_tunnel_provider_required") is not True:
            raise SystemExit(f"{platform} {source} missing packet_tunnel_provider_required=true")
        if apple.get("keychain_storage_required") is not True:
            raise SystemExit(f"{platform} {source} missing keychain_storage_required=true")
        if apple.get("production_ready") is not False:
            raise SystemExit(
                f"{platform} {source} must report apple.production_ready=false "
                "until App Store Connect upload/submission, final privacy and metadata review, "
                "and clean Mac package-install smoke are current"
            )
        release_blockers = apple.get("release_blockers")
        if release_blockers is not None:
            if not isinstance(release_blockers, list) or not all(isinstance(item, str) for item in release_blockers):
                raise SystemExit(f"{platform} {source} apple.release_blockers must be a string list when present")
            release_blocker_set = set(release_blockers)
            if not (
                CURRENT_APPLE_RELEASE_BLOCKERS.issubset(release_blocker_set)
                or LEGACY_LIVE_APPLE_RELEASE_BLOCKERS.issubset(release_blocker_set)
            ):
                current_missing = sorted(CURRENT_APPLE_RELEASE_BLOCKERS.difference(release_blocker_set))
                legacy_missing = sorted(LEGACY_LIVE_APPLE_RELEASE_BLOCKERS.difference(release_blocker_set))
                raise SystemExit(
                    f"{platform} {source} apple.release_blockers missing current={current_missing!r} "
                    f"or legacy={legacy_missing!r}"
                )
        production_ready_reason = apple.get("production_ready_reason")
        if production_ready_reason is not None and not isinstance(production_ready_reason, str):
            raise SystemExit(f"{platform} {source} apple.production_ready_reason must be a string when present")
        bundle_ids = apple.get("bundle_ids") or {}
        expected_bundle_ids = {
            "ios_app": "org.winsvpn.app",
            "ios_packet_tunnel": "org.winsvpn.app.PacketTunnel",
            "macos_app": "org.winsvpn.app",
            "macos_packet_tunnel": "org.winsvpn.app.PacketTunnel",
        }
        for key, expected in expected_bundle_ids.items():
            if bundle_ids.get(key) != expected:
                raise SystemExit(
                    f"{platform} {source} bundle_ids.{key}={bundle_ids.get(key)!r}, expected {expected!r}"
                )
        capabilities = metadata.get("capabilities") or {}
        for capability in ("direct_awg", "xray_fallback", "free_access", "smart_protocol"):
            if capabilities.get(capability) is not True:
                raise SystemExit(f"{platform} {source} missing capability {capability}=true")
    print(
        f"{platform}: schema={support.get('schema_version')} "
        f"apple.production_ready={support.get('apple', {}).get('production_ready')}"
    )
PY

}

wins_readiness_section_23_apple_runtime_smoke_harness() {
section "Apple Runtime Smoke Harness"
test -f tools/apple_runtime_smoke.sh
bash -n tools/apple_runtime_smoke.sh
grep -q 'tools/verify_apple_readiness.sh' tools/apple_runtime_smoke.sh
grep -q 'xcodebuild -version' tools/apple_runtime_smoke.sh
grep -q 'xcrun -f simctl' tools/apple_runtime_smoke.sh
grep -q 'xcrun -f devicectl' tools/apple_runtime_smoke.sh
grep -q 'xcrun simctl list devices available' tools/apple_runtime_smoke.sh
grep -q 'xcrun xctrace list devices' tools/apple_runtime_smoke.sh
grep -q 'devices -v' tools/apple_runtime_smoke.sh
grep -q 'devices --machine' tools/apple_runtime_smoke.sh
grep -q 'WINS_PREFLIGHT_ONLY' tools/apple_runtime_smoke.sh
grep -q 'WINS_PRE_RELEASE_SOURCE_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST' tools/apple_runtime_smoke.sh
grep -q 'require_pre_release_source_smoke_safe' tools/apple_runtime_smoke.sh
grep -q 'release mutation or release-evidence lane' tools/apple_runtime_smoke.sh
grep -q 'WINS_SKIP_IOS_DEVICE' tools/apple_runtime_smoke.sh
grep -q 'WINS_REQUIRE_IOS_DEVICE' tools/apple_runtime_smoke.sh
grep -q 'runtime_preflight_report' tools/apple_runtime_smoke.sh
grep -q 'USB iOS/iPadOS hardware hint' tools/apple_runtime_smoke.sh
grep -q 'usb_ios_device_hint_source_or_empty' tools/apple_runtime_smoke.sh
grep -q 'ioreg -p IOUSB' tools/apple_runtime_smoke.sh
grep -q 'SupportsIPhoneOS' tools/apple_runtime_smoke.sh
grep -q 'physical_ios_device_id_or_empty' tools/apple_runtime_smoke.sh
grep -q 'usb_ios_device_hint' tools/apple_runtime_smoke.sh
grep -q 'codesigning_identity_count' tools/apple_runtime_smoke.sh
grep -q 'valid Apple code-signing identities' tools/apple_runtime_smoke.sh
grep -q 'development_signing_lane_requested' tools/apple_runtime_smoke.sh
grep -q 'apple_development_keychain_probe_needed' tools/apple_runtime_smoke.sh
grep -q 'Apple Development private-key probe' tools/apple_runtime_smoke.sh
grep -q 'print_keychain_prompt_state' tools/apple_runtime_smoke.sh
grep -q 'Apple keychain prompt state' tools/apple_runtime_smoke.sh
grep -q 'Apple keychain prompt detail' tools/apple_runtime_smoke.sh
grep -q 'wants to access key' tools/apple_runtime_smoke.sh
grep -q 'password_field=' tools/apple_runtime_smoke.sh
grep -q 'print_keychain_prompt_state >&2' tools/apple_runtime_smoke.sh
grep -q 'apple_signing_preflight_report' tools/apple_runtime_smoke.sh
grep -q 'com.apple.application-identifier' tools/apple_runtime_smoke.sh
grep -q 'has_expected_app_group' tools/apple_runtime_smoke.sh
grep -q 'profile_app_group=' tools/apple_runtime_smoke.sh
grep -Fq 'f"{team_prefix}.*"' tools/apple_runtime_smoke.sh
grep -q 'require_signed_entitlement_contract' tools/apple_runtime_smoke.sh
grep -q 'codesign", "-d", "--entitlements", ":-"' tools/apple_runtime_smoke.sh
grep -q 'not has_expected_app_group' tools/apple_runtime_smoke.sh
grep -q 'Signed iOS and macOS debug builds now pass actual `codesign` entitlement verification' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
grep -q 'iOS App Store distribution profiles for `org.winsvpn.app` and `org.winsvpn.app.PacketTunnel` are installed' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
grep -q 'matching Mac App Store distribution profiles are installed locally for both bundle IDs' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
grep -q 'macOS Developer ID profiles are not release-ready' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
grep -q 'app_store_metadata_owner_review' server/wins_control_plane_setup_ONETOUCH.sh
grep -q 'app_store_connect_privacy_labels' server/wins_control_plane_setup_ONETOUCH.sh
grep -q 'xcode_privacy_report_review' server/wins_control_plane_setup_ONETOUCH.sh
grep -q 'testflight_or_app_store_upload' server/wins_control_plane_setup_ONETOUCH.sh
grep -q 'app_store_review_submission' server/wins_control_plane_setup_ONETOUCH.sh
refute_match 'macos_app_store_screenshot' server/wins_control_plane_setup_ONETOUCH.sh
grep -q 'macos_app_store_package_install_smoke' server/wins_control_plane_setup_ONETOUCH.sh
refute_match '"macos_app_store_package_export"' server/wins_control_plane_setup_ONETOUCH.sh
refute_match '"external_dns_ip_leak_audit"' server/wins_control_plane_setup_ONETOUCH.sh
refute_match 'no valid signing identity, provisioning profile, production App Group' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
refute_match 'iOS Runner, iOS PacketTunnel, macOS Runner, and macOS PacketTunnel signing assets' docs/APPLE_PLATFORM_IMPLEMENTATION_PLAN.md
grep -q 'explain_apple_signing_failure' tools/apple_runtime_smoke.sh
grep -q 'run_with_signing_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'run_with_export_signing_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'manual_distribution_export_options_plist' tools/apple_runtime_smoke.sh
grep -q 'write_macos_app_store_archive_xcconfig' tools/apple_runtime_smoke.sh
grep -q 'manual_macos_app_store_archive_xcconfig' tools/apple_runtime_smoke.sh
grep -q 'macos_app_store_archive_signing_requested' tools/apple_runtime_smoke.sh
grep -q 'macOS App Store archive requires the exact Apple Distribution identity hash' tools/apple_runtime_smoke.sh
grep -q 'PROVISIONING_PROFILE_SPECIFIER = \$(WINS_PROFILE_\$(TARGET_NAME))' tools/apple_runtime_smoke.sh
grep -q 'identity_hash_for("Apple Distribution:")' tools/apple_runtime_smoke.sh
grep -q 'identity_hash_for("3rd Party Mac Developer Installer:")' tools/apple_runtime_smoke.sh
grep -q 'options\["installerSigningCertificate"\]' tools/apple_runtime_smoke.sh
grep -q 'PackageInfo metadata verified' tools/apple_runtime_smoke.sh
grep -q '"install-location": "/Applications"' tools/apple_runtime_smoke.sh
grep -q '"auth": "root"' tools/apple_runtime_smoke.sh
grep -q 'hostArchitectures' tools/apple_runtime_smoke.sh
grep -q 'require-scripts' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_MANUAL_DISTRIBUTION_EXPORTS' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_EXPORT_TIMEOUT_SECONDS' tools/apple_runtime_smoke.sh
grep -q 'Manual export options cannot be generated' tools/apple_runtime_smoke.sh
grep -q 'run_with_ios_device_launch_diagnostics' tools/apple_runtime_smoke.sh
grep -q 'SpringBoard refused to launch it' tools/apple_runtime_smoke.sh
grep -q 'physical iOS active-unlock note' tools/apple_runtime_smoke.sh
grep -q 'physical iOS display state' tools/apple_runtime_smoke.sh
grep -q 'physical iOS screen viewing' tools/apple_runtime_smoke.sh
grep -q 'iPhone Mirroring automation state' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_SIMULATOR_SCREENSHOT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'verify_ios_simulator_screenshot_transition' tools/apple_runtime_smoke.sh
grep -q 'iOS simulator screenshot transition' tools/apple_runtime_smoke.sh
grep -q 'did not visibly replace the home screen' tools/apple_runtime_smoke.sh
grep -q 'com.apple.springboard' tools/apple_runtime_smoke.sh
grep -q 'WINS_SIGNING_DIAGNOSIS_SELFTEST' tools/apple_runtime_smoke.sh
grep -q 'run_signing_diagnostics_selftest' tools/apple_runtime_smoke.sh
grep -q 'assert_signing_diagnosis' tools/apple_runtime_smoke.sh
grep -q 'WINS_ENGINE_ARTIFACT_SELFTEST' tools/apple_runtime_smoke.sh
grep -q 'WINS_REQUIRE_APPLE_ENGINE' tools/apple_runtime_smoke.sh
grep -q 'run_engine_artifact_selftest' tools/apple_runtime_smoke.sh
grep -q 'label.startswith("Signed") or label.startswith("Exported")' tools/apple_runtime_smoke.sh
grep -q 'Exported engine artifact self-test app' tools/apple_runtime_smoke.sh
grep -q 'expected exported unsigned entitlement failure' tools/apple_runtime_smoke.sh
grep -q 'missing required Apple engine artifacts' tools/apple_runtime_smoke.sh
grep -q 'partial Apple engine artifacts verified' tools/apple_runtime_smoke.sh
grep -q 'Apple engine artifact gate self-test passed' tools/apple_runtime_smoke.sh
grep -q 'WINS_LIVE_TUNNEL_RESULT_SELFTEST' tools/apple_runtime_smoke.sh
grep -q 'run_live_tunnel_result_selftest' tools/apple_runtime_smoke.sh
grep -q 'Apple Live Tunnel Result Validator Self-Test' tools/apple_runtime_smoke.sh
grep -q 'Apple live tunnel result validator self-test passed' tools/apple_runtime_smoke.sh
grep -q 'Apple live tunnel result self-test expected secret payload rejection' tools/apple_runtime_smoke.sh
grep -q 'Apple live tunnel result self-test expected weak external audit rejection' tools/apple_runtime_smoke.sh
grep -q 'passed result did not use public HTTPS hostname canaries' tools/apple_runtime_smoke.sh
grep -q 'payload contains unredacted IPv4 literal' tools/apple_runtime_smoke.sh
grep -q 'payload contains unredacted IPv6 literal' tools/apple_runtime_smoke.sh
grep -q 'payload contains unredacted hostname-like identifier' tools/apple_runtime_smoke.sh
grep -q 'payload contains unredacted UUID-like identifier' tools/apple_runtime_smoke.sh
grep -q 'expected IPv6 literal rejection' tools/apple_runtime_smoke.sh
grep -q 'expected hostname-like identifier rejection' tools/apple_runtime_smoke.sh
grep -q 'expected UUID-like identifier rejection' tools/apple_runtime_smoke.sh
grep -q 'Personal development teams.*Network Extensions capability' tools/apple_runtime_smoke.sh
grep -q 'matching provisioning profiles are missing' tools/apple_runtime_smoke.sh
grep -q 'this Mac is not registered' tools/apple_runtime_smoke.sh
grep -q 'exportArchive No Accounts' tools/apple_runtime_smoke.sh
grep -q 'could not access an Apple Developer account' tools/apple_runtime_smoke.sh
grep -q 'Apple Development identities' tools/apple_runtime_smoke.sh
grep -q 'Developer ID Application identities' tools/apple_runtime_smoke.sh
grep -q 'provisioning profiles installed' tools/apple_runtime_smoke.sh
grep -q 'Library" / "Developer" / "Xcode" / "UserData" / "Provisioning Profiles' tools/apple_runtime_smoke.sh
grep -q 'expected_platform not in platforms' tools/apple_runtime_smoke.sh
grep -q 'distribution profile guard has unknown platform scope' tools/apple_runtime_smoke.sh
grep -q 'xcode_target_development_team_summary' tools/apple_runtime_smoke.sh
grep -q 'print_target_development_team_status' tools/apple_runtime_smoke.sh
grep -q 'require_target_development_team' tools/apple_runtime_smoke.sh
grep -q 'print_target_development_team_status "iOS Runner"' tools/apple_runtime_smoke.sh
grep -q 'print_target_development_team_status "iOS PacketTunnel"' tools/apple_runtime_smoke.sh
grep -q 'print_target_development_team_status "macOS Runner"' tools/apple_runtime_smoke.sh
grep -q 'print_target_development_team_status "macOS PacketTunnel"' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_SIGNED_BUILD' tools/apple_runtime_smoke.sh
grep -q 'require_ios_signing_prereqs' tools/apple_runtime_smoke.sh
grep -q 'require_ios_signed_runtime_prereqs' tools/apple_runtime_smoke.sh
grep -q 'require_macos_signing_prereqs' tools/apple_runtime_smoke.sh
grep -q 'require_requested_signed_prereqs' tools/apple_runtime_smoke.sh
grep -q 'require_valid_codesigning_identity' tools/apple_runtime_smoke.sh
grep -q 'require_physical_ios_developer_services' tools/apple_runtime_smoke.sh
grep -q 'developerModeStatus' tools/apple_runtime_smoke.sh
grep -q 'ddiServicesAvailable' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_SIMULATOR_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'build ios --simulator --debug' tools/apple_runtime_smoke.sh
grep -q 'simctl install' tools/apple_runtime_smoke.sh
grep -q 'simctl launch' tools/apple_runtime_smoke.sh
grep -q 'iOS simulator app process' tools/apple_runtime_smoke.sh
grep -q 'iOS simulator launch did not report a process id' tools/apple_runtime_smoke.sh
grep -q 'iOS simulator app did not stay running after launch' tools/apple_runtime_smoke.sh
grep -q 'simctl terminate "${simulator_id}" "${IOS_DEBUG_BUNDLE_ID}"' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_LAUNCH_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_LAUNCH_RELEASE' tools/apple_runtime_smoke.sh
grep -q 'macos_launch_smoke' tools/apple_runtime_smoke.sh
grep -q 'latest_macos_debug_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'latest_macos_launch_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'project_release_root' tools/apple_runtime_smoke.sh
grep -q 'build" / "macos" / "Build" / "Products" / "Release"' tools/apple_runtime_smoke.sh
grep -Fq 'if [[ "${WINS_MACOS_LAUNCH_RELEASE}" == "1" ]]' tools/apple_runtime_smoke.sh
grep -q 'latest_ios_device_debug_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'latest_ios_device_profile_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'latest_macos_release_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'latest_ios_device_release_app_or_empty' tools/apple_runtime_smoke.sh
grep -q 'Build/Products/Profile-iphoneos/Runner.app' tools/apple_runtime_smoke.sh
grep -q 'verify_apple_app_bundle' tools/apple_runtime_smoke.sh
grep -Fq 'host app and embedded PacketTunnel{watch_summary} verified' tools/apple_runtime_smoke.sh
grep -q 'host app bundle id' tools/apple_runtime_smoke.sh
grep -q 'CFBundleSupportedPlatforms' tools/apple_runtime_smoke.sh
grep -q 'expected_supported_platform' tools/apple_runtime_smoke.sh
grep -q 'supported platforms' tools/apple_runtime_smoke.sh
grep -q 'iPhoneOS' tools/apple_runtime_smoke.sh
grep -q 'iPhoneSimulator' tools/apple_runtime_smoke.sh
grep -q 'MacOSX' tools/apple_runtime_smoke.sh
grep -q 'require_macho_platform' tools/apple_runtime_smoke.sh
grep -q 'xcrun", "vtool", "-show-build"' tools/apple_runtime_smoke.sh
grep -q 'LC_BUILD_VERSION platform is missing' tools/apple_runtime_smoke.sh
grep -q 'IOSSIMULATOR' tools/apple_runtime_smoke.sh
grep -q 'MACOS' tools/apple_runtime_smoke.sh
grep -q 'Mach-O platforms' tools/apple_runtime_smoke.sh
grep -q 'verify_engine_artifacts' tools/apple_runtime_smoke.sh
grep -q 'engine_artifact_names_by_component' tools/apple_runtime_smoke.sh
grep -q 'require_engine_dependencies' tools/apple_runtime_smoke.sh
grep -q 'WinsAmneziaWGPacketEngine' tools/apple_runtime_smoke.sh
grep -q 'WinsXrayVlessWsTransport' tools/apple_runtime_smoke.sh
grep -q '@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine' tools/apple_runtime_smoke.sh
grep -q 'iOS app extensions cannot contain standalone dynamic libraries' tools/apple_runtime_smoke.sh
grep -q 'no Apple AWG/Xray/Winn engine artifacts bundled yet' tools/apple_runtime_smoke.sh
grep -q 'verified Apple engine artifacts' tools/apple_runtime_smoke.sh
grep -q 'require_complete_engine' tools/apple_runtime_smoke.sh
grep -q 'host app executable is missing' tools/apple_runtime_smoke.sh
grep -q 'host app shared keychain group marker' tools/apple_runtime_smoke.sh
grep -q 'NSExtensionPointIdentifier' tools/apple_runtime_smoke.sh
grep -q 'com.apple.networkextension.packet-tunnel' tools/apple_runtime_smoke.sh
grep -q 'WinsAppleSharedKeychainAccessGroup' tools/apple_runtime_smoke.sh
grep -q 'Unsigned iOS device debug app' tools/apple_runtime_smoke.sh
grep -q 'iOS simulator debug app' tools/apple_runtime_smoke.sh
grep -q 'Unsigned macOS debug app' tools/apple_runtime_smoke.sh
grep -q 'signed_ios_xcode_destination' tools/apple_runtime_smoke.sh
grep -q 'signed_ios_build' tools/apple_runtime_smoke.sh
grep -q 'generic/platform=iOS' tools/apple_runtime_smoke.sh
grep -q 'CGWindowListCopyWindowInfo' tools/apple_runtime_smoke.sh
grep -q 'macOS app window' tools/apple_runtime_smoke.sh
grep -q 'WINS_SIGNED_MACOS_BUILD' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_DEVELOPMENT_XCCONFIG' tools/apple_runtime_smoke.sh
grep -q '__APPLE_MACOS_DEVELOPMENT_SIGNING_ARGS__' tools/apple_runtime_smoke.sh
grep -q 'private external xcconfig' tools/apple_runtime_smoke.sh
grep -q 'CODE_SIGNING_ALLOWED=NO' tools/apple_runtime_smoke.sh
grep -q -- '-allowProvisioningUpdates' tools/apple_runtime_smoke.sh
grep -Fq '"${POD_BIN}" install --deployment' tools/apple_runtime_smoke.sh
grep -q 'build ios --debug --no-codesign' tools/apple_runtime_smoke.sh
grep -q 'build ios --debug' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_LIVE_TUNNEL_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'flutter_mode="--profile"' tools/apple_runtime_smoke.sh
grep -q 'xcode_configuration="Profile"' tools/apple_runtime_smoke.sh
grep -q 'build ios "${flutter_mode}" --config-only' tools/apple_runtime_smoke.sh
grep -q 'devicectl device install app' tools/apple_runtime_smoke.sh
grep -q 'Physical iOS app process' tools/apple_runtime_smoke.sh
grep -q 'Physical iOS app did not report a process id after launch' tools/apple_runtime_smoke.sh
grep -q 'Physical iOS app did not stay running after launch' tools/apple_runtime_smoke.sh
grep -q 'wait_for_ios_app_pid' tools/apple_runtime_smoke.sh
grep -q -- '--json-output "${launch_json}"' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_LAUNCH' tools/apple_runtime_smoke.sh
grep -q 'signed_ios_build_lane_label' tools/apple_runtime_smoke.sh
grep -q 'Signed iOS profile build' tools/apple_runtime_smoke.sh
grep -q 'Signed iOS debug build' tools/apple_runtime_smoke.sh
grep -q 'build macos --debug' tools/apple_runtime_smoke.sh
grep -q 'build macos --debug --config-only' tools/apple_runtime_smoke.sh
grep -q 'WINS_RELEASE_SHELL_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'release_shell_smoke' tools/apple_runtime_smoke.sh
grep -q 'build ios --release --no-codesign' tools/apple_runtime_smoke.sh
grep -q 'run_flutter_build build macos --release' tools/apple_runtime_smoke.sh
grep -q 'APPLE_RELEASE_SYMBOL_ROOT' tools/apple_runtime_smoke.sh
grep -q 'prepare_apple_release_symbols' tools/apple_runtime_smoke.sh
grep -q 'require_apple_release_symbols' tools/apple_runtime_smoke.sh
grep -q 'record_apple_release_obfuscation' tools/apple_runtime_smoke.sh
grep -q -- '--obfuscate --split-debug-info=' tools/apple_runtime_smoke.sh
grep -q 'DART_OBFUSCATION=true' tools/apple_runtime_smoke.sh
grep -q 'SPLIT_DEBUG_INFO="${symbols}"' tools/apple_runtime_smoke.sh
grep -q 'Unsigned iOS device release app' tools/apple_runtime_smoke.sh
grep -q 'Signed macOS release app' tools/apple_runtime_smoke.sh
grep -q 'codesign --verify --deep --strict --verbose=2 "${app_path}"' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_ARCHIVE_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_ARCHIVE_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_DEBUGGING_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_DEBUGGING_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'WINS_MACOS_APP_STORE_LOCAL_EXPORT_SMOKE' tools/apple_runtime_smoke.sh
grep -q 'APPLE_ARCHIVE_DIR' tools/apple_runtime_smoke.sh
grep -q 'APPLE_EXPORT_DIR' tools/apple_runtime_smoke.sh
grep -q 'signed_ios_archive_path' tools/apple_runtime_smoke.sh
grep -q 'signed_macos_archive_path' tools/apple_runtime_smoke.sh
grep -q 'ios_archive_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_archive_smoke' tools/apple_runtime_smoke.sh
grep -q 'ios_debugging_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_debugging_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'macos_app_store_local_export_smoke' tools/apple_runtime_smoke.sh
grep -q 'wins-vpn-ios.xcarchive' tools/apple_runtime_smoke.sh
grep -q 'wins-vpn-macos.xcarchive' tools/apple_runtime_smoke.sh
grep -q 'ios-debugging-local.plist' tools/apple_runtime_smoke.sh
grep -q 'ios-release-testing' tools/apple_runtime_smoke.sh
grep -q 'macos-debugging-local.plist' tools/apple_runtime_smoke.sh
grep -q 'macos-app-store-local.plist' tools/apple_runtime_smoke.sh
grep -q 'Apple archive/export smoke requires a legacy engine gate or WINS_APPLE_WINN3_RELEASE=1.' tools/apple_runtime_smoke.sh
grep -q -- '-destination '\''generic/platform=iOS'\''' tools/apple_runtime_smoke.sh
grep -q -- '-destination '\''generic/platform=macOS'\''' tools/apple_runtime_smoke.sh
grep -q -- '-archivePath "${archive_path}"' tools/apple_runtime_smoke.sh
grep -q -- '-exportArchive' tools/apple_runtime_smoke.sh
grep -q -- '-exportPath "${export_path}"' tools/apple_runtime_smoke.sh
grep -q 'WINS_APPLE_CODE_SIGN_IDENTITY="${WINS_APPLE_CODE_SIGN_IDENTITY:-Apple Development}"' tools/apple_runtime_smoke.sh
grep -q 'CODE_SIGN_IDENTITY="${WINS_APPLE_CODE_SIGN_IDENTITY}"' tools/apple_runtime_smoke.sh
grep -q -- '-xcconfig "${archive_xcconfig}"' tools/apple_runtime_smoke.sh
grep -q 'Signed iOS archive app' tools/apple_runtime_smoke.sh
grep -q 'Signed macOS archive app' tools/apple_runtime_smoke.sh
grep -q 'Exported iOS debugging app' tools/apple_runtime_smoke.sh
grep -q 'Exported macOS debugging app' tools/apple_runtime_smoke.sh
grep -q 'WINS_IOS_INSTALL' tools/apple_runtime_smoke.sh
WINS_STAGE_APPLE_ENGINE_SELFTEST=1 bash tools/stage_apple_engine_artifacts.sh
WINS_SIGNING_DIAGNOSIS_SELFTEST=1 bash tools/apple_runtime_smoke.sh
WINS_PRE_RELEASE_SOURCE_SMOKE_SELFTEST=1 bash tools/apple_runtime_smoke.sh
WINS_ENGINE_ARTIFACT_SELFTEST=1 bash tools/apple_runtime_smoke.sh
WINS_LIVE_TUNNEL_RESULT_SELFTEST=1 bash tools/apple_runtime_smoke.sh

}

# --- Section driver (2026-08-06 section-isolation lane) ---------------------
# Every section runs, in file order, each inside its own subshell via
# run_section. A failing section is recorded and the run continues, so one
# broken check can no longer mask every check behind it. The script still
# exits non-zero if anything failed -- see the Result section below.
run_section "Apple Toolchain" wins_readiness_section_01_apple_toolchain
run_section "Locked CocoaPods Prerequisites" wins_readiness_section_02_locked_cocoapods_prerequisites
run_section "Flutter macOS XCTest Configuration" wins_readiness_section_03_flutter_macos_xctest_configuration
run_section "Flutter Apple Build Plumbing" wins_readiness_section_04_flutter_apple_build_plumbing
run_section "Apple App Icons" wins_readiness_section_05_apple_app_icons
run_section "Apple Plists And Entitlements" wins_readiness_section_06_apple_plists_and_entitlements
run_section "Apple Export Options" wins_readiness_section_07_apple_export_options
run_section "Apple Privacy Manifests" wins_readiness_section_08_apple_privacy_manifests
run_section "Apple App Privacy Label Audit" wins_readiness_section_09_apple_app_privacy_label_audit
run_section "Apple Packaging Metadata" wins_readiness_section_10_apple_packaging_metadata
run_section "Xcode Project Wiring" wins_readiness_section_11_xcode_project_wiring
run_section "Apple Tunnel Config Parser" wins_readiness_section_12_apple_tunnel_config_parser
run_section "Packet Tunnel Swift Type Checks" wins_readiness_section_13_packet_tunnel_swift_type_checks
run_section "Packet Tunnel Dev Containment Gate" wins_readiness_section_14_packet_tunnel_dev_containment_gate
run_section "Packet Tunnel Dev Containment Release Absence (compiled proof)" wins_readiness_section_15_packet_tunnel_dev_containment_release_absence_compiled_proof
run_section "iOS Packet Tunnel Dev Containment Gate" wins_readiness_section_16_ios_packet_tunnel_dev_containment_gate
run_section "iOS Packet Tunnel Dev Containment Release Absence (compiled proof)" wins_readiness_section_17_ios_packet_tunnel_dev_containment_release_absence_compiled_proof
run_section "Apple Host Bridge Swift Type Checks" wins_readiness_section_18_apple_host_bridge_swift_type_checks
run_section "Apple Native XCTest" wins_readiness_section_19_apple_native_xctest
run_section "Flutter Static Checks" wins_readiness_section_20_flutter_static_checks
run_section "Apple Submission Package" wins_readiness_section_21_apple_submission_package
run_section "Live Hub Apple Metadata" wins_readiness_section_22_live_hub_apple_metadata
run_section "Apple Runtime Smoke Harness" wins_readiness_section_23_apple_runtime_smoke_harness

section "Result"
report_section_summary
if [[ "$(deferred_failure_count)" -ne 0 ]]; then
  printf '\nApple source sections completed, but this run is NOT a pass.\n' >&2
  report_deferred_failures
  exit 65
fi
printf 'Apple source checks completed. Use tools/apple_runtime_smoke.sh with WINS_REQUIRE_APPLE_ENGINE=1 and the signed runtime flags to verify build, install, launch, and bundled AWG/Xray/Winn artifacts on this machine.\n'
