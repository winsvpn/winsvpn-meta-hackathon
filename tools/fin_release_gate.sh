#!/bin/bash -p
#
# fin_release_gate.sh — THE single release gate for Win's VPN carrying standalone
# Winn Protocol v3 (Myanmar threat model).
#
# One command. It runs every check between source and a shippable artifact and
# FAILS LOUDLY on any gap. The whole point is that a gate that cannot go red is
# worse than no gate, so every gate below is independently provably-failable.
#
# ===========================================================================
# EXIT SEMANTICS (do not read a pipeline; this script owns its own status)
# ===========================================================================
#   0  every gate PASSED  — a release may proceed
#   1  at least one gate FAILED — stop-ship; the failing gate's message is printed
#   2  at least one gate is BLOCKED (a required resource/check is absent or
#      unverifiable) — treated exactly like a FAIL for release purposes. An
#      honest BLOCKED beats a green you cannot defend.
#   3  usage error / internal error
#
# ===========================================================================
# WHY IT LOOKS LIKE THIS
# ===========================================================================
# The catalogue of false greens in this repo is long, and every entry is a
# reason this gate refuses to trust a green it cannot make red:
#   * go test cache  -> every `go test` uses -count=1
#   * `cmd | head`   -> every tool status is captured before any pipe
#   * bare ./gradlew -> the Android build is broken tree-wide (workmanager/AGP9);
#                       this gate does not run it, it gates what CAN gate and
#                       marks the device/signing gates BLOCKED-honestly
#   * prose outruns evidence -> every check that previously lived only as a
#     doc claim (gate_state vocabulary, promotion predicate, path_mtu default,
#     standalone imports, ARB parity, dependency-verification lenient flag) is
#     now an EXECUTABLE grep gate here.
#   * a test name is a claim -> the mutation harness (--prove) reintroduces each
#     defect it guards and requires the gate to go red naming what broke.
#
# STATIC GREP GATES READ A ROOT DIRECTORY FROM $WIN_DIR (no /tmp, in-tree only)
# so the mutation harness can point them at a PRIVATE COPY and never touches the
# shared tree. The Go/Cargo/Flutter gates run against $WIN_DIR in place because
# compiling a private copy in this tree is not the point; their teeth are proven
# two ways: (a) the conform suite already ships a `go test -overlay` negative
# control, and (b) --prove runs a mutation that must go red.
#
# ===========================================================================
# USAGE
# ===========================================================================
#   tools/fin_release_gate.sh                  run every gate (recommended)
#   tools/fin_release_gate.sh G01 G07          run only the named gates
#   tools/fin_release_gate.sh --prove          run the mutation proof battery
#   tools/fin_release_gate.sh --list           enumerate gates with one-line desc
#   WIN_DIR=... tools/fin_release_gate.sh      point static gates at a ROOT
#
case "$-" in
    *p*) ;;
    *) printf 'fin release gate: invoke with /bin/bash -p to disable BASH_ENV and imported functions\n' >&2; exit 126 ;;
esac
unset BASH_ENV ENV CDPATH GLOBIGNORE
# Ambient PATH Go, ISCC, Flutter, Dart, Java, Python, browser, Node, OpenSSL,
# and packaging tools cannot be selected. Custody wrappers bind the only
# candidate executables. GitHub remains backup storage only.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
hash -r 2>/dev/null || true
set -uo pipefail

# ---------------------------------------------------------------------------
# Locality: static gates read $WIN_DIR (in-tree), never /tmp.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
WIN_DIR="${WIN_DIR:-"$(cd "${SCRIPT_DIR}/.." && pwd)"}"
MODULE_DIR="${WIN_DIR}/winn_protocol_experimental"
PIN_MANIFEST="${SCRIPT_DIR}/toolchain-pins.json"
INNO_CUSTODY_TOOL="${SCRIPT_DIR}/release_inno_toolchain_custody.py"
source "${SCRIPT_DIR}/release_python_archive_custody.sh" || exit 3
source "${SCRIPT_DIR}/release_android_toolchain_archive_custody.sh" || exit 3
source "${SCRIPT_DIR}/release_openssl_archive_custody.sh" || exit 3
source "${SCRIPT_DIR}/release_node_archive_custody.sh" || exit 3
source "${SCRIPT_DIR}/release_browser_archive_custody.sh" || exit 3
source "${SCRIPT_DIR}/release_go_archive_custody.sh" || exit 3
RELEASE_PYTHON=""
RELEASE_FLUTTER=""
RELEASE_PYTHON_CUSTODY_DIR=""
RELEASE_PYTHON_AUTHENTICATED=0
RELEASE_GO_AUTHENTICATED=0
RELEASE_ANDROID_AUTHENTICATED=0
RELEASE_TOOLS_AUTHENTICATED=0
RELEASE_INNO_AUTHENTICATED=0
RELEASE_NODE_REQUIRED=0
RELEASE_BROWSER_REQUIRED=0
RELEASE_OPENSSL_REQUIRED=0

PASS=0
FAIL=1
BLOCKED=2

# ---------------------------------------------------------------------------
# Result plumbing. One writer. Each gate writes exactly one [_status].
# ---------------------------------------------------------------------------
record() {
    # record <GATE> <PASS|FAIL|BLOCKED> <message...>
    local g="$1" st="$2"; shift 2
    printf -v "_results_${g}" '%s' "$st"
    printf -v "_messages_${g}" '%s' "$*"
}

mark_provenable() { printf -v "_provenable_${1}" '%s' yes; }

cleanup_release_custody() {
    wins_release_browser_cleanup || true
    wins_release_node_cleanup || true
    wins_release_openssl_cleanup || true
    wins_release_go_cleanup || true
    wins_release_android_toolchains_cleanup || true
    wins_release_python_cleanup || true
    RELEASE_PYTHON_CUSTODY_DIR=""
    RELEASE_PYTHON=""
    RELEASE_FLUTTER=""
    RELEASE_PYTHON_AUTHENTICATED=0
    RELEASE_GO_AUTHENTICATED=0
    RELEASE_ANDROID_AUTHENTICATED=0
    RELEASE_TOOLS_AUTHENTICATED=0
    RELEASE_INNO_AUTHENTICATED=0
    RELEASE_NODE_REQUIRED=0
    RELEASE_BROWSER_REQUIRED=0
    RELEASE_OPENSSL_REQUIRED=0
}
cleanup_release_python_custody() { cleanup_release_custody; }

trap cleanup_release_custody EXIT

_require_sourced_custody_wrappers() {
    local missing=() fn
    for fn in \
      wins_release_python_prepare wins_release_python_run wins_release_python_cleanup \
      wins_release_android_toolchains_prepare wins_release_android_toolchains_verify \
      wins_release_android_toolchains_cleanup wins_release_android_flutter \
      wins_release_android_jdk_tool \
      wins_release_openssl_prepare wins_release_openssl_verify \
      wins_release_openssl_run wins_release_openssl_cleanup \
      wins_release_node_prepare wins_release_node_verify \
      wins_release_node_run wins_release_node_cleanup \
      wins_release_browser_prepare wins_release_browser_verify \
      wins_release_browser_run wins_release_browser_cleanup \
      wins_release_go_prepare wins_release_go_verify \
      wins_release_go_run wins_release_go_cleanup
    do
        declare -F "$fn" >/dev/null 2>&1 || missing+=("$fn")
    done
    [[ -f "$INNO_CUSTODY_TOOL" && ! -L "$INNO_CUSTODY_TOOL" ]] ||
      missing+=("release_inno_toolchain_custody.py")
    [[ ${#missing[@]} -eq 0 ]]
}

verify_release_python_custody() {
    [[ "$RELEASE_PYTHON_AUTHENTICATED" == 1 &&
       -n "${WINS_RELEASE_PYTHON_RUNTIME:-}" &&
       -n "${WINS_RELEASE_PYTHON_RUNTIME_ID:-}" &&
       -n "${WINS_RELEASE_PYTHON_BIN:-}" &&
       "$RELEASE_PYTHON" == "$WINS_RELEASE_PYTHON_BIN" &&
       -d "$WINS_RELEASE_PYTHON_RUNTIME" && ! -L "$WINS_RELEASE_PYTHON_RUNTIME" &&
       "$(_wins_rp_dir_identity "$WINS_RELEASE_PYTHON_RUNTIME")" == "$WINS_RELEASE_PYTHON_RUNTIME_ID" &&
       -f "$RELEASE_PYTHON" && ! -L "$RELEASE_PYTHON" && -x "$RELEASE_PYTHON" ]]
}

run_release_python() {
    verify_release_python_custody || return 126
    wins_release_python_run "$@"
    local rc=$?
    verify_release_python_custody || return 126
    return "$rc"
}

verify_release_go_custody() {
    [[ "$RELEASE_GO_AUTHENTICATED" == 1 ]] || return 1
    wins_release_go_verify
}

run_release_go() {
    verify_release_go_custody || return 126
    wins_release_go_run "$@"
    local rc=$?
    verify_release_go_custody || return 126
    return "$rc"
}

verify_release_android_custody() {
    [[ "$RELEASE_ANDROID_AUTHENTICATED" == 1 ]] || return 1
    wins_release_android_toolchains_verify
}

run_release_flutter() {
    verify_release_android_custody || return 126
    wins_release_android_flutter "$@"
    local rc=$?
    verify_release_android_custody || return 126
    return "$rc"
}

run_release_java() {
    verify_release_android_custody || return 126
    wins_release_android_jdk_tool java "$@"
    local rc=$?
    verify_release_android_custody || return 126
    return "$rc"
}

run_release_openssl() {
    [[ "$RELEASE_OPENSSL_REQUIRED" == 1 ]] || return 126
    verify_release_tools_custody || return 126
    wins_release_openssl_run "$@"
    local rc=$?
    verify_release_tools_custody || return 126
    return "$rc"
}

run_release_node() {
    [[ "$RELEASE_NODE_REQUIRED" == 1 ]] || return 126
    verify_release_tools_custody || return 126
    wins_release_node_run "$@"
    local rc=$?
    verify_release_tools_custody || return 126
    return "$rc"
}

run_release_browser() {
    [[ "$RELEASE_BROWSER_REQUIRED" == 1 ]] || return 126
    verify_release_tools_custody || return 126
    wins_release_browser_run "$@"
    local rc=$?
    verify_release_tools_custody || return 126
    return "$rc"
}

run_release_inno_verify_pins() {
    verify_release_python_custody || return 126
    [[ -f "$INNO_CUSTODY_TOOL" && ! -L "$INNO_CUSTODY_TOOL" ]] || return 1
    run_release_python "$INNO_CUSTODY_TOOL" verify-pins
    local rc=$?
    verify_release_python_custody || return 126
    return "$rc"
}

verify_release_tools_custody() {
    [[ "$RELEASE_TOOLS_AUTHENTICATED" == 1 ]] || return 1
    verify_release_android_custody &&
      { [[ "$RELEASE_OPENSSL_REQUIRED" != 1 ]] || wins_release_openssl_verify; } &&
      { [[ "$RELEASE_NODE_REQUIRED" != 1 ]] || wins_release_node_verify; } &&
      { [[ "$RELEASE_BROWSER_REQUIRED" != 1 ]] || wins_release_browser_verify; }
}

_cleanup_partial_release_tools() {
    wins_release_browser_cleanup || true
    wins_release_node_cleanup || true
    wins_release_openssl_cleanup || true
    wins_release_android_toolchains_cleanup || true
    RELEASE_ANDROID_AUTHENTICATED=0
    RELEASE_TOOLS_AUTHENTICATED=0
}

authenticate_release_android() {
    if [[ "$RELEASE_ANDROID_AUTHENTICATED" == 1 ]]; then
        verify_release_android_custody
        return $?
    fi
    verify_release_python_custody || return 1
    local pin="${WIN_DIR}/tools/toolchain-pins.json"
    [[ -f "$pin" && ! -L "$pin" ]] || return 1
    wins_release_android_toolchains_prepare "$pin" || return 1
    if ! wins_release_android_toolchains_verify; then
        wins_release_android_toolchains_cleanup || true
        return 1
    fi
    RELEASE_ANDROID_AUTHENTICATED=1
    RELEASE_FLUTTER="${WINS_RELEASE_FLUTTER_BIN:-}"
    verify_release_android_custody
}

authenticate_release_go() {
    if [[ "$RELEASE_GO_AUTHENTICATED" == 1 ]]; then
        verify_release_go_custody
        return $?
    fi
    verify_release_python_custody || return 1
    wins_release_go_prepare \
      "${SCRIPT_DIR}/release_go_archive_custody.py" \
      "$PIN_MANIFEST" || return 1
    if ! wins_release_go_verify; then
        wins_release_go_cleanup || true
        return 1
    fi
    RELEASE_GO_AUTHENTICATED=1
    verify_release_go_custody
}

authenticate_release_inno() {
    if [[ "$RELEASE_INNO_AUTHENTICATED" == 1 ]]; then
        verify_release_python_custody
        return $?
    fi
    verify_release_python_custody || return 1
    local out rc
    out="$(run_release_inno_verify_pins 2>&1)"; rc=$?
    printf '%s\n' "$out"
    if [[ $rc -ne 0 ]]; then
        return 1
    fi
    RELEASE_INNO_AUTHENTICATED=1
    verify_release_python_custody
}

authenticate_release_tools() {
    if [[ "$RELEASE_TOOLS_AUTHENTICATED" == 1 ]]; then
        verify_release_tools_custody
        return $?
    fi
    verify_release_python_custody || return 1
    RELEASE_OPENSSL_REQUIRED=1
    local failed=0
    local pin="${WIN_DIR}/tools/toolchain-pins.json"
    authenticate_release_android || failed=1
    if ! wins_release_openssl_prepare \
         "${SCRIPT_DIR}/release_openssl_archive_custody.py" \
         "$pin"; then
        failed=1
    fi
    if [[ "$RELEASE_NODE_REQUIRED" == 1 ]] &&
       ! wins_release_node_prepare \
         "${SCRIPT_DIR}/release_node_archive_custody.py" \
         "$pin"; then
        failed=1
    fi
    if [[ "$RELEASE_BROWSER_REQUIRED" == 1 ]] &&
       ! wins_release_browser_prepare \
         "${SCRIPT_DIR}/release_browser_archive_custody.py" \
         "$PIN_MANIFEST"; then
        failed=1
    fi
    if [[ "$failed" != 0 ]]; then
        _cleanup_partial_release_tools
        return 1
    fi
    RELEASE_TOOLS_AUTHENTICATED=1
    verify_release_tools_custody
}

run_release_python_with_release_tools() {
    verify_release_python_custody && verify_release_tools_custody || return 126
    wins_release_python_run_with_release_tools "$@"
    local rc=$?
    verify_release_python_custody && verify_release_tools_custody || return 126
    return "$rc"
}

run_release_python_with_release_browser() {
    verify_release_python_custody && verify_release_tools_custody || return 126
    wins_release_python_run_with_release_browser "$@"
    local rc=$?
    verify_release_python_custody && verify_release_tools_custody || return 126
    return "$rc"
}

authenticate_release_python() {
    if [[ "$RELEASE_PYTHON_AUTHENTICATED" == 1 ]]; then
        verify_release_python_custody
        return $?
    fi
    local identity rc
    wins_release_python_prepare "$WIN_DIR/tools/toolchain-pins.json" || return 1
    RELEASE_PYTHON="$WINS_RELEASE_PYTHON_BIN"
    RELEASE_PYTHON_CUSTODY_DIR="$WINS_RELEASE_PYTHON_RUNTIME"
    RELEASE_PYTHON_AUTHENTICATED=1
    identity="$(run_release_python - "$WIN_DIR/tools/toolchain-pins.json" <<'PY'
import json
import sys

def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        pins = json.load(handle, object_pairs_hook=reject_duplicates)
    expected = pins["tools"]["python"]
    actual_version = ".".join(str(value) for value in sys.version_info[:3])
    if (
        sys.version_info.releaselevel != "final"
        or sys.version_info.serial != 0
        or actual_version != expected["version"]
        or sys.implementation.name != expected["implementation"]
        or "site" in sys.modules
    ):
        raise SystemExit(1)
    print(actual_version)
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
PY
    )"; rc=$?
    if [[ $rc -eq 0 && -n "$identity" ]]; then
        verify_release_python_custody
        return $?
    fi
    cleanup_release_python_custody
    return 1
}

# ---------------------------------------------------------------------------
# Gate G00 — environment / reviewed toolchain identity
# ---------------------------------------------------------------------------
gate_G00() {
    local g="G00"
    mark_provenable "$g"
    local missing=()
    if ! _require_sourced_custody_wrappers; then
        record "$g" "$FAIL" "required custody wrappers are not sourced"
        return
    fi
    authenticate_release_python || missing+=("authenticated release Python custody")
    for t in grep awk sed; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        record "$g" "$FAIL" "missing tool(s): ${missing[*]}"
        return
    fi
    if [[ ! -d "$WIN_DIR" || ! -f "${WIN_DIR}/pubspec.yaml" ]]; then
        record "$g" "$FAIL" "WIN_DIR=${WIN_DIR} is not a Flutter app root (no pubspec.yaml)"
        return
    fi
    local pin_file="${WIN_DIR}/tools/toolchain-pins.json"
    if [[ ! -f "$pin_file" || -L "$pin_file" ]]; then
        record "$g" "$FAIL" "reviewed toolchain pin manifest missing or symbolic: ${pin_file}"
        return
    fi
    local pins rc
    pins="$(run_release_python - "$pin_file" <<'PY'
import json
import re
import sys

def reject_duplicates(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise ValueError(f"duplicate JSON key: {key}")
        record[key] = value
    return record

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        manifest = json.load(handle, object_pairs_hook=reject_duplicates)
    tools = manifest["tools"]
    values = (
        tools["python"]["version"],
        tools["python"]["implementation"],
        tools["go"]["version"],
        tools["flutter"]["version"],
        tools["flutter"]["revision"],
        tools["flutter"]["dart_version"],
        tools["cocoapods"]["version"],
    )
except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
    print(f"invalid reviewed toolchain pin manifest: {exc}", file=sys.stderr)
    raise SystemExit(1)
if (
    not all(isinstance(value, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
            for value in (values[0], values[2], values[3], values[5], values[6]))
    or not isinstance(values[1], str)
    or not re.fullmatch(r"[a-z][a-z0-9_]*", values[1])
    or not isinstance(values[4], str)
    or not re.fullmatch(r"[0-9a-f]{40}", values[4])
):
    print("reviewed toolchain pin manifest has malformed exact versions", file=sys.stderr)
    raise SystemExit(1)
print("\t".join(values))
PY
    )"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        record "$g" "$FAIL" "reviewed toolchain pin manifest is invalid"
        return
    fi
    local expected_python expected_python_implementation expected_go expected_flutter expected_flutter_revision expected_dart expected_pod
    IFS=$'\t' read -r expected_python expected_python_implementation expected_go expected_flutter expected_flutter_revision expected_dart expected_pod <<<"$pins"
    local actual_python actual_python_implementation python_identity
    python_identity="$(run_release_python - <<'PY'
import sys

version = sys.version_info
implementation = sys.implementation.name
if version.releaselevel != "final" or version.serial != 0:
    raise SystemExit(1)
print(f"{version.major}.{version.minor}.{version.micro}\t{implementation}")
PY
    )"
    rc=$?
    if [[ $rc -ne 0 ]]; then
        record "$g" "$FAIL" "archive-derived release Python identity is unresolved or not final: ${RELEASE_PYTHON}"
        return
    fi
    IFS=$'\t' read -r actual_python actual_python_implementation <<<"$python_identity"
    local mismatches=()
    [[ "$actual_python" == "$expected_python" ]] || mismatches+=("python expected=${expected_python} actual=${actual_python:-unresolved}")
    [[ "$actual_python_implementation" == "$expected_python_implementation" ]] || mismatches+=("python_implementation expected=${expected_python_implementation} actual=${actual_python_implementation:-unresolved}")
    if [[ ${#mismatches[@]} -gt 0 ]]; then
        record "$g" "$FAIL" "reviewed toolchain pin mismatch: ${mismatches[*]}"
        return
    fi
    record "$g" "$PASS" "reviewed python custody matches pins python=${actual_python}/${actual_python_implementation}; go=${expected_go} flutter=${expected_flutter}+${expected_flutter_revision} dart=${expected_dart} cocoapods=${expected_pod} require authenticated custody before execution"
}

# ---------------------------------------------------------------------------
# Gate G01 — Go protocol module BUILDS
# ---------------------------------------------------------------------------
gate_G01() {
    local g="G01"
    mark_provenable "$g"
    if [[ ! -d "$MODULE_DIR" ]]; then record "$g" "$BLOCKED" "module dir missing: ${MODULE_DIR}"; return; fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G01 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_go; then
        record "$g" "$BLOCKED" "G01 requires authenticated archive-derived release Go custody"
        return
    fi
    if pushd "$MODULE_DIR" >/dev/null 2>&1; then
        local out rc
        out="$(run_release_go build ./... 2>&1)"; rc=$?
        popd >/dev/null 2>&1 || true
        if [[ $rc -eq 0 ]]; then record "$g" "$PASS" "go build ./... clean in ${MODULE_DIR}"; else record "$g" "$FAIL" "go build ./... FAILED (rc=$rc):"; fi
    else
        record "$g" "$BLOCKED" "cannot enter ${MODULE_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# Gate G02 — Go protocol module VETS (Printf arity, etc.)
# ---------------------------------------------------------------------------
gate_G02() {
    local g="G02"
    mark_provenable "$g"
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G02 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_go; then
        record "$g" "$BLOCKED" "G02 requires authenticated archive-derived release Go custody"
        return
    fi
    if pushd "$MODULE_DIR" >/dev/null 2>&1; then
        local out rc
        out="$(run_release_go vet ./... 2>&1)"; rc=$?
        popd >/dev/null 2>&1 || true
        if [[ $rc -eq 0 ]]; then record "$g" "$PASS" "go vet ./... clean"; else record "$g" "$FAIL" "go vet ./... found issues (rc=$rc)"; fi
    else record "$g" "$BLOCKED" "cannot enter ${MODULE_DIR}"; fi
}

# ---------------------------------------------------------------------------
# Gate G03 — complete Go protocol and Windows relay tests (-count=1, race)
# ---------------------------------------------------------------------------
gate_G03() {
    local g="G03"
    mark_provenable "$g"
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G03 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_go; then
        record "$g" "$BLOCKED" "G03 requires authenticated archive-derived release Go custody"
        return
    fi
    if pushd "$MODULE_DIR" >/dev/null 2>&1; then
        local out rc
        out="$(run_release_go test -count=1 -race ./... 2>&1)"; rc=$?
        popd >/dev/null 2>&1 || true
        if [[ $rc -ne 0 ]]; then
            printf '%s\n' "$out" >&2
            record "$g" "$FAIL" "complete Winn protocol Go suite failed (rc=${rc})"
            return
        fi
        local relay="${WIN_DIR}/windows/winn3_engine"
        if [[ ! -d "$relay" || -L "$relay" ]]; then
            record "$g" "$BLOCKED" "Windows Winn relay Go module missing or symbolic: ${relay}"
            return
        fi
        if pushd "$relay" >/dev/null 2>&1; then
            out="$(run_release_go test -count=1 -race ./... 2>&1)"; rc=$?
            popd >/dev/null 2>&1 || true
            if [[ $rc -eq 0 ]]; then
                record "$g" "$PASS" "complete Winn protocol and Windows relay Go suites pass uncached with race detection"
            else
                printf '%s\n' "$out" >&2
                record "$g" "$FAIL" "Windows Winn relay Go suite failed (rc=${rc})"
            fi
        else
            record "$g" "$BLOCKED" "cannot enter Windows Winn relay module"
        fi
    else record "$g" "$BLOCKED" "cannot enter ${MODULE_DIR}"; fi
}

# ---------------------------------------------------------------------------
# Gate G04 — Cross-host conformance pins (conform suite). THE dispersal gate.
# The conform suite reintroduces silent-refusal defects and requires refusal.
# ---------------------------------------------------------------------------
gate_G04() {
    local g="G04"
    mark_provenable "$g"
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G04 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_go; then
        record "$g" "$BLOCKED" "G04 requires authenticated archive-derived release Go custody"
        return
    fi
    if pushd "$MODULE_DIR" >/dev/null 2>&1; then
        local out rc
        out="$(run_release_go test -count=1 ./winn3/conform/ 2>&1)"; rc=$?
        popd >/dev/null 2>&1 || true
        if [[ $rc -eq 0 ]]; then record "$g" "$PASS" "winn3/conform conformance pins all hold (this is the dispersal gate that fails if the fleet diverges)";
        else record "$g" "$FAIL" "winn3/conform conformance pins DID NOT ALL HOLD (rc=$rc) — see log for the silent-refusal defeat"; fi
    else record "$g" "$BLOCKED" "cannot enter ${MODULE_DIR}"; fi
}

# ---------------------------------------------------------------------------
# Gate G05 — Cross-host conformance script (Go+Kotlin+Swift hosts). If a host
# toolchain is absent the script exits 2 = host unreachable = BLOCKED, never PASS.
# ---------------------------------------------------------------------------
gate_G05() {
    local g="G05"
    mark_provenable "$g"
    local script="${WIN_DIR}/tools/verify_winn3_conformance.sh"
    if [[ ! -f "$script" || -L "$script" ]]; then record "$g" "$BLOCKED" "canonical conformance script missing or symbolic (${script})"; return; fi
    local out rc
    out="$(bash "$script" --strict 2>&1)"; rc=$?
    # The script collapses "host diverged" and "host unreachable" both to exit 1
    # under --strict. They are not the same thing: a host not reached (missing
    # toolchain, e.g. kotlinc) is UNPROVEN, never a divergence. Distinguish by
    # the script's own words so we never report a fabricated fail/skip.
    if [[ "$out" == *"NOT COVERED on this run"* || "$out" == *"UNPROVEN"* ]]; then
        # a host was not reached; if nothing diverged this is BLOCKED-unproven
        if [[ "$out" == *"FAIL: at least one host diverges"* ]]; then
            record "$g" "$FAIL" "cross-host conformance DIVERGED and a host was also unreachable"
        else
            record "$g" "$BLOCKED" "cross-host conformance unproven: a host was not reached (missing toolchain, likely kotlinc) — unproven is not pass"
        fi
        return
    fi
    case $rc in
        0) record "$g" "$PASS" "all reachable hosts agreed";;
        1) record "$g" "$FAIL" "cross-host conformance DIVERGED (rc=1)";;
        2) record "$g" "$BLOCKED" "a host could not be reached (toolchain missing) — unproven is not pass (rc=2)";;
        *) record "$g" "$FAIL" "cross-host conformance errored (rc=$rc)";;
    esac
}

# ---------------------------------------------------------------------------
# Gate G06 — current-repository Winn security core test gate. The historical
# version of this gate compiled a sibling Rust checkout, so its result
# depended on where the repository happened to be cloned. Standalone Winn v3's
# security boundary now lives in this repository and is tested here directly.
# ---------------------------------------------------------------------------
gate_G06() {
    local g="G06"
    mark_provenable "$g"
    local core_dir="${MODULE_DIR}/winn3/core"
    local replaystore_dir="${core_dir}/replaystore"
    if [[ -L "$MODULE_DIR" || -L "$core_dir" || -L "$replaystore_dir" ]]; then
        record "$g" "$FAIL" "canonical Winn security package path is symbolic"
        return
    fi
    if [[ ! -d "$core_dir" || ! -d "$replaystore_dir" ]]; then
        record "$g" "$BLOCKED" "canonical Winn security packages missing under ${core_dir}"
        return
    fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G06 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_go; then
        record "$g" "$BLOCKED" "G06 requires authenticated archive-derived release Go custody"
        return
    fi
    if pushd "$MODULE_DIR" >/dev/null 2>&1; then
        local out rc
        out="$(run_release_go test -count=1 ./winn3/core ./winn3/core/replaystore 2>&1)"; rc=$?
        popd >/dev/null 2>&1 || true
        if [[ $rc -eq 0 ]]; then
            record "$g" "$PASS" "canonical Winn security packages pass go test -count=1"
        else
            printf '%s\n' "$out" >&2
            record "$g" "$FAIL" "canonical Winn security package tests FAILED (rc=$rc)"
        fi
    else record "$g" "$BLOCKED" "cannot enter ${MODULE_DIR}"; fi
}

# ---------------------------------------------------------------------------
# Gate G07 — authenticate the exact reviewed Flutter checkout, analyze and
# compile the real lib/main.dart, then run the complete package test suite.
# Callers cannot replace the tool with a self-reporting shim or narrow tests.
# ---------------------------------------------------------------------------
gate_G07() {
    local g="G07"
    mark_provenable "$g"
    local mainfile="${WIN_DIR}/lib/main.dart"
    if [[ ! -f "$mainfile" || -L "$mainfile" ]]; then
        record "$g" "$BLOCKED" "canonical lib/main.dart is missing or symbolic"
        return
    fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G07 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! authenticate_release_android; then
        record "$g" "$BLOCKED" "G07 requires authenticated archive-derived Android/Flutter custody"
        return
    fi
    local out rc
    out="$(cd "$WIN_DIR" && run_release_flutter analyze --no-pub lib/main.dart 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "canonical lib/main.dart analysis failed (rc=${rc})"
        return
    fi
    out="$(cd "$WIN_DIR" && run_release_flutter build bundle --release --no-pub --target lib/main.dart 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "canonical lib/main.dart release compilation failed (rc=${rc})"
        return
    fi
    out="$(cd "$WIN_DIR" && run_release_flutter test --no-pub 2>&1)"; rc=$?
    if [[ $rc -ne 0 ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "complete Flutter package test suite failed (rc=${rc})"
        return
    fi
    record "$g" "$PASS" "authenticated Flutter analyzed and release-compiled lib/main.dart; complete Flutter test suite passed"
}

# ---------------------------------------------------------------------------
# Gate G08 — STATIC: gate_state anti-downgrade. The fail-open `?: CARRYING`
# elvis (a host that promotes on an unrecognised name) must not exist in any
# host's fromWire. The full 6-name vocabulary cross-host check is owned by the
# winn3/conform Go suite (gate G04); this gate makes the cheap, provable half
# of the prose claim executable. Read from $WIN_DIR.
# ---------------------------------------------------------------------------
gate_G08() {
    local g="G08"
    mark_provenable "$g"
    local bad=()
    # A `?: StateCarrying`/`?: CARRYING` elvis default would promote on an
    # unrecognised name. Forbid it in every HOST's production source. The
    # winn3/conform suite is EXCLUDED: it is the guard that by design *states*
    # these needles to prove it rejects them, so matching its own text is a
    # false positive. Build an exclude list of test files and the conform suite.
    local hosts=""
    for dir in "$WIN_DIR/winn_protocol_experimental" "$WIN_DIR/android" "$WIN_DIR/apple" "$WIN_DIR/linux" "$WIN_DIR/windows"; do
        [[ -d "$dir" ]] && hosts+=" $dir"
    done
    local f; while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -E '\?\s*:\s*(State)?CARRYING\b' --include='*.go' --include='*.kt' --include='*.swift' --include='*.cc' --include='*.cpp' --include='*.h' $hosts 2>/dev/null | grep -v '\.bak' | grep -v '/winn3/conform/' | grep -vE '/[^/]*_test\.(go|kt|swift|cc|cpp|h):' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "no fail-open '?: CARRYING' elvis in any host production source (full vocabulary handled by G04/conform)"; else record "$g" "$FAIL" "gate_state anti-downgrade VIOLATION (fail-open elvis) in: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G09 — STATIC: promotion predicate counts DELIVERIES (RxPackets), never
# ARRIVALS (RxOffered). A `carrying && RxOffered>0` would promote on a dead port.
# ---------------------------------------------------------------------------
gate_G09() {
    local g="G09"
    mark_provenable "$g"
    local bad=()
    local hosts=""
    for dir in "$WIN_DIR/winn_protocol_experimental" "$WIN_DIR/android" "$WIN_DIR/apple" "$WIN_DIR/linux" "$WIN_DIR/windows"; do
        [[ -d "$dir" ]] && hosts+=" $dir"
    done
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -E 'RxOffered\s*>\s*0|rxOffered\s*>\s*0' --include='*.go' --include='*.kt' --include='*.swift' --include='*.cc' --include='*.cpp' $hosts 2>/dev/null | grep -v '\.bak' | grep -v '/winn3/conform/' | grep -vE '/[^/]*_test\.(go|kt|swift|cc|cpp):' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "no promotion predicate gates on arrival counter (RxOffered>0) in production source"; else record "$g" "$FAIL" "promotion predicates gate on ARRIVALS in production: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G10 — STATIC: path_mtu default. Defaults must flow through
# carrier.DefaultPathMTU (1450), never a bare tun.IPv6MinLinkMTU (1280) default
# that silently converts cannot-promote into cannot-connect. Read from $WIN_DIR.
# ---------------------------------------------------------------------------
gate_G10() {
    local g="G10"
    mark_provenable "$g"
    local bad=()
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -E 'pathMTU\s*=\s*tun\.IPv6MinLinkMTU|path_mtu\s*=\s*tun\.IPv6MinLinkMTU|pathMTU[[:space:]]*=[[:space:]]*1280\b|DefaultPathMTU[[:space:]]*=[[:space:]]*(1388|1500|1139)' --include='*.go' "$MODULE_DIR" 2>/dev/null | grep -v '\.bak' | grep -v '/winn3/conform/' | grep -vE '/[^/]*_test\.go:' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "no path_mtu entry bypasses carrier.DefaultPathMTU (1450)"; else record "$g" "$FAIL" "path_mtu default bypass in: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G11 — STATIC: standalone v3. winn3 must not import AmneziaWG/Xray.
# ---------------------------------------------------------------------------
gate_G11() {
    local g="G11"
    mark_provenable "$g"
    local bad=()
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -E 'golang\.zx2c4\.com/|github\.com/amnezia|github\.com/x-tray|github\.com/xtls|xray' --include='*.go' "$MODULE_DIR/winn3" 2>/dev/null | grep -v '\.bak' | grep -v '/winn3/conform/' | grep -vE '/[^/]*_test\.go:' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "winn3 is standalone (no AmneziaWG/Xray import in the v3 core)"; else record "$g" "$FAIL" "winn3 has a banned dependency in: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G12 — STATIC: ARB parity (English vs Burmese). The ARB key sets must be
# identical; a missing/divergent Burmese ARB is a stop-ship (Burmese ships, and
# a plausible wrong string removes the marker that it needed attention).
# ---------------------------------------------------------------------------
gate_G12() {
    local g="G12"
    mark_provenable "$g"
    # Bind the release gate to this repository's shipping localization inputs.
    # Searching parent/sibling trees can silently validate another product or
    # checkout and produce a location-dependent green.
    local en="${WIN_DIR}/lib/l10n/app_en.arb"
    local my="${WIN_DIR}/lib/l10n/app_my.arb"
    if [[ ! -f "$en" && ! -f "$my" ]]; then record "$g" "$BLOCKED" "canonical ARB pair missing under ${WIN_DIR}/lib/l10n"; return; fi
    if [[ -L "$en" || -L "$my" ]]; then record "$g" "$FAIL" "canonical ARB inputs must not be symbolic links"; return; fi
    if [[ ! -f "$en" ]]; then record "$g" "$FAIL" "app_en.arb MISSING (Burmese app_my.arb exists at ${my})"; return; fi
    if [[ ! -f "$my" ]]; then record "$g" "$FAIL" "app_my.arb MISSING (English app_en.arb exists at ${en}) — Burmese localisation cannot be verified"; return; fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G12 requires authenticated archive-derived release Python custody"
        return
    fi
    run_release_python - "$en" "$my" <<'PY'
import json,sys
en,my=sys.argv[1:3]
try:
    # ARB @keys are template metadata, not translatable messages. Flutter's
    # localized catalogs must share the message-key set; translated ARBs are
    # not required to duplicate every template metadata record.
    k_en={key for key in json.load(open(en)).keys() if not key.startswith("@")}
    k_my={key for key in json.load(open(my)).keys() if not key.startswith("@")}
except Exception as e:
    print("ARB_PARSE_FAIL", e); sys.exit(1)
only_en=sorted(k_en-k_my); only_my=sorted(k_my-k_en)
if only_en or only_my:
    print("ARB_MISMATCH only_en=%d only_my=%d"%(len(only_en),len(only_my)))
    print(" sample only_en:", only_en[:5], "only_my:", only_my[:5])
    sys.exit(1)
print("ARB_PARITY_OK keys=%d"%(len(k_en)))
PY
    local rc=$?
    if [[ $rc -eq 0 ]]; then record "$g" "$PASS" "app_en.arb / app_my.arb key parity holds ($(basename "$en") vs $(basename "$my"))"; else record "$g" "$FAIL" "ARB key parity broken (see above)"; fi
}

# ---------------------------------------------------------------------------
# Gate G13 — STATIC: dependency verification must not be relaxed. Forbidding
# -Dorg.gradle.dependency.verification=lenient anywhere in the build scripts.
# ---------------------------------------------------------------------------
gate_G13() {
    local g="G13"
    mark_provenable "$g"
    local bad=()
    local scan=""
    for dir in "$WIN_DIR/android" "$WIN_DIR/tools" "$WIN_DIR/installer"; do [[ -d "$dir" ]] && scan+=" $dir"; done
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -F 'org.gradle.dependency.verification=lenient' --include='*.gradle' --include='*.gradle.kts' --include='*.sh' --include='*.ps1' --include='*.yml' $scan 2>/dev/null | grep -v '\.bak' | grep -v '/tools/fin_release_gate.sh' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "dependency-verification is never relaxed to lenient"; else record "$g" "$FAIL" "lenient verification flag found in: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G14 — STATIC: no `?`: CARRYING` elvis in Kotlin specifically (the host
# the conform suite caught this on). Belt-and-braces over G08's language-wide
# sweep, so the two disagree if one breaks.
# ---------------------------------------------------------------------------
gate_G14() {
    local g="G14"
    mark_provenable "$g"
    local bad=()
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rn -E '\?\s*:\s*[A-Z_]*CARRYING' --include='*.kt' "$WIN_DIR/android" 2>/dev/null | grep -v '\.bak' || true)
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "no '?: CARRYING' fail-open elvis in Kotlin fromWire"; else record "$g" "$FAIL" "Kotlin fail-open elvis in: ${bad[*]}"; fi
}

# ---------------------------------------------------------------------------
# Gate G15 — STATIC: untracked-but-deployed dirs are fatal gaps if absent.
# The winn3/gateway and winn3/conform dirs live only in the working tree; a
# `git clean` deletes the entire conformance suite. This gate refuses a missing
# dir (an absent guard is the worst guard).
# ---------------------------------------------------------------------------
gate_G15() {
    local g="G15"
    mark_provenable "$g"
    local missing=()
    for d in "$MODULE_DIR/winn3/conform" "$MODULE_DIR/winn3/gateway" "$MODULE_DIR/winn3/netlab"; do
        [[ -d "$d" ]] || missing+=("$d")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then record "$g" "$PASS" "winn3 untracked-but-deployed dirs (conform/gateway/netlab) all present"; else record "$g" "$FAIL" "missing winn3 dir(s): ${missing[*]} (one git clean deletes the conformance suite — protect them)"; fi
}

# ---------------------------------------------------------------------------
# Gate G16 — STATIC: no key material printed or staged. This gate refuses key
# *content* patterns in the tree that could be a leaked private key, excluding
# the obviously-named public fixtures and test vectors. Read-only.
# ---------------------------------------------------------------------------
gate_G16() {
    local g="G16"
    mark_provenable "$g"
    local bad=()
    local scan=""
    for dir in "$WIN_DIR/lib" "$WIN_DIR/android/app/src" "$WIN_DIR/apple" "$WIN_DIR/linux/runner" "$WIN_DIR/windows/runner" "$WIN_DIR/assets"; do
        [[ -d "$dir" ]] && scan+=" $dir"
    done
    # App-source key-content scan. The winn_protocol_experimental Go module is
    # deliberately NOT swept here: it is all source with a huge tree, and keys
    # would surface in the app-facing dirs; scanning it costs ~100s for nothing.
    while IFS= read -r f; do [[ -z "$f" ]] && continue; bad+=("$f"); done < <(grep -rIn -l -E 'BEGIN [A-Z]* ?PRIVATE KEY|BEGIN OPENSSH PRIVATE KEY|PRIVATE KEY-----' $scan 2>/dev/null | grep -v '\.bak' | grep -vE 'testdata|_test\.|/tests/|fixtures|\.pem\.pub|known_good|pubkey|\.dart_tool|/build/|\.artifacts' | grep -v '/.git/' | grep -v 'tools/fin_release_gate.sh' || true)
    # Report only the actual private-key content markers, not the exclusion gut.
    if [[ ${#bad[@]} -eq 0 ]]; then record "$g" "$PASS" "no private-key content found in non-fixture tree paths"; else record "$g" "$FAIL" "possible key material in: ${bad[*]:0:8}"; fi
}

# ---------------------------------------------------------------------------
# Gate G17 — immutable source freeze. A source fingerprint without its matching
# lock is only an observation, not release evidence. This runs read-only and
# deliberately never creates a replacement lock while writers are active.
# ---------------------------------------------------------------------------
gate_G17() {
    local g="G17"
    local verifier="${WIN_DIR}/tools/release_source_freeze.py"
    if [[ ! -f "$verifier" || -L "$verifier" ]]; then
        record "$g" "$BLOCKED" "release-source verifier missing or symbolic: ${verifier}"
        return
    fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G17 requires authenticated archive-derived release Python custody"
        return
    fi
    local out rc
    out="$(run_release_python "$verifier" --repo "$WIN_DIR" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then
        record "$g" "$PASS" "immutable release-source lock verifies"
    elif [[ "$out" == *"No immutable APP_SOURCE_LOCK"* || "$out" == *"owner blocked:"* || "$out" == *"missing pin:"* ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$BLOCKED" "missing current APP_SOURCE_LOCK is an owner/external blocker (rc=${rc})"
    else
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "immutable release-source lock is stale or invalid (rc=${rc})"
    fi
}

# ---------------------------------------------------------------------------
# Gate G18 — immutable dependency input index. Never select an index by glob:
# a release invocation must name the intended current index explicitly, and the
# verifier replays every frozen input before any artifact receipt is trusted.
# ---------------------------------------------------------------------------
gate_G18() {
    local g="G18"
    local verifier="${WIN_DIR}/tools/release_dependency_freeze.py"
    if [[ ! -f "$verifier" || -L "$verifier" ]]; then
        record "$g" "$BLOCKED" "release-dependency verifier missing or symbolic: ${verifier}"
        return
    fi
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G18 requires authenticated archive-derived release Python custody"
        return
    fi
    local index="${WINS_RELEASE_INPUT_INDEX:-}"
    if [[ -z "$index" ]]; then
        record "$g" "$BLOCKED" "WINS_RELEASE_INPUT_INDEX must explicitly name the immutable RELEASE_INPUT_INDEX.json"
        return
    fi
    if [[ "$(basename "$index")" != "RELEASE_INPUT_INDEX.json" ]]; then
        record "$g" "$FAIL" "WINS_RELEASE_INPUT_INDEX must name RELEASE_INPUT_INDEX.json exactly"
        return
    fi
    local out rc
    out="$(run_release_python "$verifier" verify-index --repo "$WIN_DIR" --index "$index" 2>&1)"; rc=$?
    if [[ $rc -eq 0 ]]; then
        record "$g" "$PASS" "explicit immutable dependency input index verifies"
    elif [[ "$out" == *"No immutable APP_SOURCE_LOCK"* || "$out" == *"owner blocked:"* || "$out" == *"missing pin:"* ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$BLOCKED" "missing current source/dependency/toolchain receipts are an owner/external blocker (rc=${rc})"
    else
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "explicit dependency input index is stale or invalid (rc=${rc})"
    fi
}

# ---------------------------------------------------------------------------
# Gate G19 -- all application release-critical Python suites. Discovery and
# execution are delegated to one deterministic runner that owns the explicit
# approved roots and fixture exclusions. Do not reintroduce a hand-maintained
# subset here: that caused router, GCP-suffix, dashboard, and extension suites
# to silently fall outside the release gate.
# ---------------------------------------------------------------------------
gate_G19() {
    local g="G19"
    local runner listed relative absolute list_count unique_count out rc bootstrap_test bootstrap_out release_tools_needed=0 browser_out browser_rc
    RELEASE_NODE_REQUIRED=0
    RELEASE_BROWSER_REQUIRED=0
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G19 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! run_release_python -c 'import pytest, sys; raise SystemExit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
        record "$g" "$BLOCKED" "the archive-derived release Python runtime must provide pytest"
        return
    fi
    runner="${WIN_DIR}/tools/run_test_suite.py"
    if [[ ! -f "$runner" || -L "$runner" ]]; then
        record "$g" "$BLOCKED" "authoritative Python suite runner missing or symbolic: ${runner}"
        return
    fi
    for bootstrap_test in \
      "${WIN_DIR}/tools/test_release_python_archive_custody.py" \
      "${WIN_DIR}/tools/test_release_gate_determinism.py"; do
        if [[ ! -f "$bootstrap_test" || -L "$bootstrap_test" ]]; then
            record "$g" "$BLOCKED" "required Python custody bootstrap suite missing or symbolic: ${bootstrap_test}"
            return
        fi
        bootstrap_out="$(wins_release_python_run_bootstrap_test "$bootstrap_test" 2>&1)"; rc=$?
        if [[ $rc -ne 0 ]]; then
            printf '%s\n' "$bootstrap_out" >&2
            record "$g" "$FAIL" "Python custody bootstrap suite failed: ${bootstrap_test} (rc=${rc})"
            return
        fi
    done
    listed="$(cd "$WIN_DIR" && PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='' run_release_python "$runner" --list --exclude-python-custody-bootstrap 2>&1)"; rc=$?
    if [[ $rc -ne 0 || -z "$listed" ]]; then
        printf '%s\n' "$listed" >&2
        record "$g" "$FAIL" "authoritative Python suite discovery failed (rc=${rc})"
        return
    fi
    list_count="$(printf '%s\n' "$listed" | LC_ALL=C wc -l | tr -d ' ')"
    unique_count="$(printf '%s\n' "$listed" | LC_ALL=C sort -u | LC_ALL=C wc -l | tr -d ' ')"
    if [[ "$list_count" != "$unique_count" ]]; then
        record "$g" "$FAIL" "authoritative Python suite discovery emitted duplicate test paths"
        return
    fi
    while IFS= read -r relative; do
        [[ -n "$relative" && "$relative" != /* && "$relative" != *".."* && "$relative" == *.py ]] || {
            record "$g" "$FAIL" "authoritative Python suite discovery emitted unsafe path: ${relative}"
            return
        }
        absolute="${WIN_DIR}/${relative}"
        if [[ ! -f "$absolute" || -L "$absolute" ]]; then
            record "$g" "$BLOCKED" "authoritative Python suite path missing or symbolic: ${relative}"
            return
        fi
        case "$relative" in
            extension/tools/core_tests.py|\
            server/test_winn3_descriptor_hub.py|\
            server/test_winn3_sign_descriptor_tool.py|\
            test/web_download_asset_decision_test.py|\
            tools/test_rate_limiter_hardening.py|\
            tools/test_wear_os_signed_aab_receipt.py)
                release_tools_needed=1
                ;;
        esac
        case "$relative" in
            test/web_download_asset_decision_test.py|tools/test_rate_limiter_hardening.py)
                RELEASE_NODE_REQUIRED=1
                ;;
        esac
        case "$relative" in
            extension/tools/core_tests.py)
                RELEASE_BROWSER_REQUIRED=1
                ;;
        esac
    done <<< "$listed"

    if [[ "$release_tools_needed" == 1 ]]; then
        if ! authenticate_release_tools; then
            record "$g" "$BLOCKED" "G19 requires authenticated OpenSSL, Java, Flutter, Pub-cache, and every discovered Node/browser runtime"
            return
        fi
        if [[ "$RELEASE_BROWSER_REQUIRED" == 1 ]]; then
            out="$(cd "$WIN_DIR" && PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='' run_release_python_with_release_tools "$runner" --release-critical --exclude-python-custody-bootstrap --exclude-browser-runtime 2>&1)"; rc=$?
            if [[ $rc -eq 0 ]]; then
                browser_out="$(cd "$WIN_DIR" && PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='' run_release_python_with_release_browser "$runner" --release-critical --exclude-python-custody-bootstrap --browser-runtime-only 2>&1)"; browser_rc=$?
                out="${out}"$'\n'"${browser_out}"
                rc=$browser_rc
            fi
        else
            out="$(cd "$WIN_DIR" && PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='' run_release_python_with_release_tools "$runner" --release-critical --exclude-python-custody-bootstrap 2>&1)"; rc=$?
        fi
    else
        out="$(cd "$WIN_DIR" && PYTHONDONTWRITEBYTECODE=1 PYTEST_ADDOPTS='' run_release_python "$runner" --release-critical --exclude-python-custody-bootstrap 2>&1)"; rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
        local readiness="${WIN_DIR}/tools/cross_store_upload_readiness.py"
        local evidence="${WINS_CROSS_STORE_READINESS_EVIDENCE:-}"
        local index="${WINS_RELEASE_INPUT_INDEX:-}"
        if [[ ! -f "$readiness" || -L "$readiness" ]]; then
            record "$g" "$BLOCKED" "cross-store readiness verifier missing or symbolic: ${readiness}"
            return
        fi
        if [[ -z "$evidence" ]]; then
            record "$g" "$BLOCKED" "WINS_CROSS_STORE_READINESS_EVIDENCE must explicitly name current exact-artifact readiness evidence"
            return
        fi
        if [[ ! -f "$evidence" || -L "$evidence" ]]; then
            record "$g" "$BLOCKED" "cross-store readiness evidence missing or symbolic: ${evidence}"
            return
        fi
        if [[ -z "$index" ]]; then
            record "$g" "$BLOCKED" "WINS_RELEASE_INPUT_INDEX is required to bind cross-store readiness to G18 inputs"
            return
        fi
        out="$(run_release_python "$readiness" verify --repo "$WIN_DIR" --evidence "$evidence" --index "$index" 2>&1)"; rc=$?
        if [[ $rc -eq 0 ]]; then
            record "$g" "$PASS" "all ${list_count} discovered release-critical Python suites and exact cross-store artifact evidence pass"
        else
            printf '%s\n' "$out" >&2
            record "$g" "$FAIL" "cross-store exact-artifact readiness verification failed (rc=${rc})"
        fi
    else
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "release-critical Python suites failed (rc=${rc})"
    fi
}

# ---------------------------------------------------------------------------
# Gate G20 -- hermetic shell regressions that exercise shipped gateway and
# Linux producer logic without root, network, host package, or firewall state.
# Linux-native/runtime and destructive installer rehearsals remain exact-target
# evidence requirements in the cross-store receipt gate; they must never be
# auto-run on a workstation merely because an environment variable says so.
# ---------------------------------------------------------------------------
gate_G20() {
    local g="G20"
    mark_provenable "$g"
    local -a suites=(
        "server/test_winn3_gateway_preflight_exit.sh"
        "tools/test_deployment_package_recovery.sh"
        "tools/test_harden_live_hub_zram.sh"
        "tools/test_linux_build_path_scan.sh"
        "tools/test_linux_installer_uid_selection.sh"
    )
    local relative script out rc scratch
    for relative in "${suites[@]}"; do
        script="${WIN_DIR}/${relative}"
        if [[ ! -f "$script" || -L "$script" ]]; then
            record "$g" "$BLOCKED" "hermetic shell suite missing or symbolic: ${relative}"
            return
        fi
        out="$(bash "$script" 2>&1)"; rc=$?
        if [[ $rc -ne 0 ]]; then
            printf '%s\n' "$out" >&2
            record "$g" "$FAIL" "hermetic shell suite failed: ${relative} (rc=${rc})"
            return
        fi
    done

    relative="server/test_winn3_gateway_udp_buffers.sh"
    script="${WIN_DIR}/${relative}"
    if [[ ! -f "$script" || -L "$script" ]]; then
        record "$g" "$BLOCKED" "hermetic shell suite missing or symbolic: ${relative}"
        return
    fi
    scratch="$(/usr/bin/mktemp -d /tmp/wins-g20-udp.XXXXXX 2>/dev/null)" || {
        record "$g" "$BLOCKED" "cannot create isolated UDP-buffer suite scratch"
        return
    }
    if [[ "$scratch" != /tmp/wins-g20-udp.* || -L "$scratch" ]]; then
        record "$g" "$BLOCKED" "unsafe UDP-buffer suite scratch path"
        return
    fi
    out="$(WINN3_UDP_BUF_WORKDIR="$scratch" bash "$script" 2>&1)"; rc=$?
    /bin/chmod -R u+rwX "$scratch" 2>/dev/null || true
    /bin/rm -rf -- "$scratch"
    if [[ $rc -ne 0 ]]; then
        printf '%s\n' "$out" >&2
        record "$g" "$FAIL" "hermetic shell suite failed: ${relative} (rc=${rc})"
        return
    fi
    record "$g" "$PASS" "all six hermetic gateway/deployment/Linux producer shell regressions pass"
}

# ---------------------------------------------------------------------------
# Gate G21 -- owner/external blockers that must never be skipped: current
# APP_SOURCE_LOCK and freeze receipts, Apple installer identity, Windows
# trust/ISCC identity, final reviews, and the 6-hour GCP acceptance window.
# This gate never starts GCP proof, never deploys production, and never uses
# GitHub as a release authority.
# ---------------------------------------------------------------------------
gate_G21() {
    local g="G21"
    local blockers=()
    blockers+=("S6 GCP deployment contract retarget is pending after S4; existing receipts cannot certify this tree")
    if ! authenticate_release_python; then
        record "$g" "$BLOCKED" "G21 requires authenticated archive-derived release Python custody"
        return
    fi
    if ! _require_sourced_custody_wrappers; then
        record "$g" "$BLOCKED" "G21 requires sourced Python, Android/Flutter, Go, browser, Node, OpenSSL, and Inno custody wrappers"
        return
    fi

    local inno_out inno_rc
    inno_out="$(run_release_inno_verify_pins 2>&1)"; inno_rc=$?
    printf '%s\n' "$inno_out" >&2
    if [[ $inno_rc -ne 0 ]]; then
        blockers+=("Windows Inno toolchain pins failed verification")
    fi

    if [[ -z "${WINS_FINAL_REVIEWS_RECEIPT:-}" || ! -f "${WINS_FINAL_REVIEWS_RECEIPT}" || -L "${WINS_FINAL_REVIEWS_RECEIPT}" ]]; then
        blockers+=("final Fable 5, GLM 5.3, and Daybreak Blue reviews are an owner/external blocker; GCP proof must not start")
    fi
    if [[ -z "${WINS_APPLE_INSTALLER_IDENTITY_PROOF:-}" || ! -f "${WINS_APPLE_INSTALLER_IDENTITY_PROOF}" || -L "${WINS_APPLE_INSTALLER_IDENTITY_PROOF}" ]]; then
        blockers+=("Apple installer identity is an owner/external blocker")
    fi
    if [[ -z "${WINS_RELEASE_INPUT_INDEX:-}" ]]; then
        blockers+=("current source/dependency/toolchain receipts are an owner/external blocker")
    fi

    local gcp_out gcp_rc
    gcp_out="$(run_release_python - "${SCRIPT_DIR}/gcp_proof_fleet.py" <<'PY'
import ast
import importlib.util
import os
import sys
from datetime import timedelta
from pathlib import Path

fleet = Path(sys.argv[1])
window_ok = False
try:
    spec = importlib.util.spec_from_file_location("gcp_proof_fleet", fleet)
    module = importlib.util.module_from_spec(spec)
    if spec.loader is None:
        raise RuntimeError("gcp_proof_fleet loader is missing")
    spec.loader.exec_module(module)
    window_ok = module.MAX_EVIDENCE_AGE == timedelta(hours=6)
except Exception:
    source = fleet.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if "MAX_EVIDENCE_AGE" not in names or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        if not isinstance(func, ast.Name) or func.id != "timedelta":
            continue
        kwargs = {keyword.arg: keyword.value for keyword in node.value.keywords}
        hours = kwargs.get("hours")
        window_ok = isinstance(hours, ast.Constant) and hours.value == 6
        break
if not window_ok:
    raise SystemExit("GCP acceptance receipt window is not six hours")
print("gcp-receipt-window-hours=6")
receipt = os.environ.get("WINS_GCP_PROOF_ACCEPTANCE_RECEIPT", "").strip()
reviews = os.environ.get("WINS_FINAL_REVIEWS_RECEIPT", "").strip()
if receipt and not reviews:
    raise SystemExit(3)
if not receipt:
    raise SystemExit(2)
path = Path(receipt)
if not path.is_absolute() or not path.is_file() or path.is_symlink():
    raise SystemExit(2)
print("gcp-acceptance-receipt-present")
PY
    )"; gcp_rc=$?
    printf '%s\n' "$gcp_out" >&2
    if [[ $gcp_rc -eq 3 ]]; then
        record "$g" "$FAIL" "final reviews must complete before GCP proof; production deployment is refused"
        return
    fi
    if [[ $gcp_rc -ne 0 || "$gcp_out" != *"gcp-receipt-window-hours=6"* ]]; then
        blockers+=("GCP acceptance proof is an owner/external blocker; 6-hour receipt window cannot be skipped")
    fi

    if [[ ${#blockers[@]} -gt 0 ]]; then
        record "$g" "$BLOCKED" "${blockers[*]}; no production deployment"
        return
    fi
    record "$g" "$PASS" "owner/external proofs are present; 6-hour GCP receipt window holds; no production deployment"
}

# ---------------------------------------------------------------------------
# PROOF / MUTATION BATTERY  (--prove)
#
# Proves a gate can FAIL by reintroducing the defect it guards, scored inverted
# (the mutation MUST make the gate go red, else the gate is vacuous). Mutates a
# PRIVATE COPY in .spark_lanes/scratch/fin_release_gate/ — never the shared tree.
# ---------------------------------------------------------------------------
_mutate_file() { # src dst needle replacement  -> applies if needle occurs exactly once
    local src="$1" dst="$2" needle="$3" replacement="$4"
    local content; content="$(cat "$src")"
    local n; n="$(grep -F -o "$needle" <<<"$content" | wc -l | tr -d ' ')"
    if [[ "$n" != "1" ]]; then echo "NOT_APPLIED needle=$needle occurs=$n"; return 0; fi
    local out; out="${content//$needle/$replacement}"
    mkdir -p "$(dirname "$dst")"
    printf '%s' "$out" > "$dst"
    echo "APPLIED $needle"
}

# seed_file <gatedir> <relative> <content>   -- write a REAL file in the private
# root (never a symlink), so a mutated needle cannot escape into the shared tree.
seed_file() {
    local gatedir="$1" rel="$2" content="$3"
    mkdir -p "$(dirname "${gatedir}/${rel}")"
    printf '%s' "$content" > "${gatedir}/${rel}"
}

# seed_clean_tree <gatedir> -- the baseline (unmutated) private root state each
# static gate would PASS against, so the mutation is the ONLY change.
seed_clean_tree() {
    local gatedir="$1"
    seed_file "$gatedir" "android/a/ok.kt" "package a\nval state = 0\n"
    seed_file "$gatedir" "android/b/ok.swift" "// nothing\n"
    seed_file "$gatedir" "winn_protocol_experimental/ok.go" "package ok\n"
    seed_file "$gatedir" "winn_protocol_experimental/winn3/ok.go" "package ok\n"
    seed_file "$gatedir" "apple/c/ok.cc" "// nothing\n"
    seed_file "$gatedir" "linux/d/ok.cc" "// nothing\n"
    seed_file "$gatedir" "windows/e/ok.h" "// nothing\n"
    mkdir -p "$gatedir/android/lenient-scan"
    # G15 clean baseline: the three untracked-but-deployed dirs present
    mkdir -p "$gatedir/winn_protocol_experimental/winn3/conform" \
             "$gatedir/winn_protocol_experimental/winn3/gateway" \
             "$gatedir/winn_protocol_experimental/winn3/netlab"
    # G12 clean baseline: an in-parity ARB pair so the parity control is green
    seed_file "$gatedir" "lib/l10n/app_en.arb" '{"keyA":"h","keyB":"e"}'
    seed_file "$gatedir" "lib/l10n/app_my.arb" '{"keyA":"x","keyB":"y"}'
}

prove_one() { # prove_one <GATE> <label>
    local g="$1" label="$2"
    local scratch="${WIN_DIR}/../.spark_lanes/scratch/fin_release_gate/prove/${label}"
    rm -rf "$scratch"; mkdir -p "$scratch"
    local gatedir="${scratch}/gate"
    mkdir -p "$gatedir"
    seed_clean_tree "$gatedir"

    # Each mutation is written as a REAL file inside the private root only.
    case "$g" in
        G08) seed_file "$gatedir" "android/v/KotlinHost.kt" "val x = state ?: CARRYING\n" ;;
        G09) seed_file "$gatedir" "winn_protocol_experimental/winn3/core/promote.go" "func _p() bool { return gate == tun.StateCarrying && rxOffered > 0 }\n" ;;
        G10) seed_file "$gatedir" "winn_protocol_experimental/winn3/carrier/pipe.go" "var _q = pathMTU = tun.IPv6MinLinkMTU\n" ;;
        G11) seed_file "$gatedir" "winn_protocol_experimental/winn3/core/doc.go" "import _ \"github.com/amnezia/foo\"\n" ;;
        G13) seed_file "$gatedir" "android/lenient-scan/lenient.gradle" "org.gradle.dependency.verification=lenient\n" ;;
        G15) rm -rf "$gatedir/winn_protocol_experimental/winn3/netlab" ;;
        G16) seed_file "$gatedir" "lib/support/leaked_secret.pem" "-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n" ;;
        G12)
            seed_file "$gatedir" "lib/l10n/app_en.arb" '{"keyA":"h","keyB":"e"}'
            seed_file "$gatedir" "lib/l10n/app_my.arb" '{"keyA":"x"}'   # missing keyB
            ;;
        G14) seed_file "$gatedir" "android/v/KotlinHost.kt" "val x = a ?: CARRYING\n" ;;
        *) return 2 ;;  # no static mutation for this gate — proven by Go suite itself
    esac

    # run the named gate against the private root only
    WIN_DIR="$gatedir" /bin/bash -p "$SCRIPT_DIR/fin_release_gate.sh" "$g" >/dev/null 2>&1
    local rc=$?
    if [[ $rc -eq 1 || $rc -eq 2 ]]; then
        echo "PROVEN  ${g} ${label}: mutation made the gate go red (rc=$rc)  [inverted-scored OK]"
        return 0
    else
        echo "VACUOUS ${g} ${label}: mutation did NOT trip the gate (rc=$rc)  [inverted-scored FAIL]"
        return 1
    fi
}

# prove_clean <GATE> <label> — positive control: the UNMUTATED private tree must
# make the gate PASS, else the mutation table means nothing.
prove_clean() {
    local g="$1" label="$2"
    local scratch="${WIN_DIR}/../.spark_lanes/scratch/fin_release_gate/prove/${label}"
    rm -rf "$scratch"; mkdir -p "$scratch"
    local gatedir="${scratch}/gate"
    mkdir -p "$gatedir"
    seed_clean_tree "$gatedir"
    WIN_DIR="$gatedir" /bin/bash -p "$SCRIPT_DIR/fin_release_gate.sh" "$g" >/dev/null 2>&1
    local rc=$?
    if [[ $rc -eq 0 ]]; then echo "CLEAN   ${g} ${label}: unmutated tree PASSES (rc=0)  [control OK]"; return 0
    else echo "BROKEN  ${g} ${label}: unmutated tree FAILED (rc=$rc) — control FAIL"; return 1; fi
}

prove_all() {
    local n=0 tot=0 clean_ok=0
    for g in G08 G09 G10 G11 G12 G13 G14 G15 G16; do
        tot=$((tot+1))
        if prove_one "$g" "mut_${g}"; then n=$((n+1)); fi
        prove_clean "$g" "ctl_${g}" && clean_ok=$((clean_ok+1))
    done
    echo "[prove] ${n}/${tot} static gates proven able to fail (mutation==red, inverted-scored)."
    echo "[prove] clean controls passed: ${clean_ok}/${tot} (unmutated private tree is green)."
    echo "[prove] Gates G00-G07 are proven by (a) the conform overlay negative control shipped in winn3-conformance.yml and (b) live measurement against this tree."
    if [[ $n -eq $tot && $clean_ok -eq $tot ]]; then return 0; else return 1; fi
}

# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
run_gate() {
    case "$1" in
        G00) gate_G00;; G01) gate_G01;; G02) gate_G02;; G03) gate_G03;;
        G04) gate_G04;; G05) gate_G05;; G06) gate_G06;; G07) gate_G07;;
        G08) gate_G08;; G09) gate_G09;; G10) gate_G10;; G11) gate_G11;;
        G12) gate_G12;; G13) gate_G13;; G14) gate_G14;; G15) gate_G15;;
        G16) gate_G16;; G17) gate_G17;; G18) gate_G18;; G19) gate_G19;;
        G20) gate_G20;; G21) gate_G21;;
        *) echo "unknown gate $1" >&2; return 3;;
    esac
}

_CANONICAL_GATES=(G00 G01 G02 G03 G04 G05 G06 G07 G08 G09 G10 G11 G12 G13 G14 G15 G16 G17 G18 G19 G20 G21)

_list() {
    local g
    for g in "${_CANONICAL_GATES[@]}"; do
        echo "$g: $(_description "$g")"
    done
}

_description() {
    case "$1" in
        G00) echo "environment / reviewed toolchain identity" ;;
        G01) echo "Go protocol module builds clean" ;;
        G02) echo "Go protocol module vets clean" ;;
        G03) echo "complete Winn protocol and Windows relay Go suites pass uncached with race detection" ;;
        G04) echo "cross-host conformance pins (winn3/conform) all hold - the dispersal gate" ;;
        G05) echo "cross-host conformance script (Go+Kotlin+Swift), unproven is not pass" ;;
        G06) echo "canonical Winn security core tests pass" ;;
        G07) echo "Dart: lib/main.dart compiles + load-bearing Dart suites pass" ;;
        G08) echo "STATIC gate_state vocabulary anti-downgrade (no fail-open elvis)" ;;
        G09) echo "STATIC promotion predicate counts deliveries (RxPackets), not arrivals" ;;
        G10) echo "STATIC path_mtu default flows through carrier.DefaultPathMTU (1450)" ;;
        G11) echo "STATIC winn3 is standalone (no AmneziaWG/Xray import)" ;;
        G12) echo "STATIC ARB English/Burmese key parity" ;;
        G13) echo "STATIC dependency verification never lenient" ;;
        G14) echo "STATIC no '?: CARRYING' fail-open elvis in Kotlin" ;;
        G15) echo "STATIC untracked-but-deployed winn3 dirs present" ;;
        G16) echo "STATIC no private-key content in non-fixture tree paths" ;;
        G17) echo "immutable app-source lock verifies current source state" ;;
        G18) echo "explicit immutable dependency input index verifies current inputs" ;;
        G19) echo "release-critical Python suites and exact cross-store artifact evidence pass" ;;
        G20) echo "hermetic gateway/deployment/Linux producer shell regressions pass" ;;
        G21) echo "owner/external blockers, 6-hour GCP receipt window, reviews before GCP, no production" ;;
        *) return 1 ;;
    esac
}

main() {
    local prove=0
    local want=()
    for a in "$@"; do
        case "$a" in
            --prove) prove=1;;
            --list) _list; exit 0;;
            G*) want+=("$a");;
            *) echo "unknown arg $a" >&2; exit 3;;
        esac
    done
    if [[ $prove -eq 1 ]]; then prove_all; exit $?; fi
    if [[ ${#want[@]} -eq 0 ]]; then
        want=("${_CANONICAL_GATES[@]}")
    else
        local -a ordered=() canonical requested
        for canonical in "${_CANONICAL_GATES[@]}"; do
            for requested in "${want[@]}"; do
                if [[ "$requested" == "$canonical" ]]; then
                    ordered+=("$canonical")
                fi
            done
        done
        if [[ ${#ordered[@]} -ne ${#want[@]} ]]; then
            echo "unknown gate in request" >&2
            exit 3
        fi
        want=("${ordered[@]}")
    fi

    local worst=0
    for g in "${want[@]}"; do
        if ! run_gate "$g"; then
            return 3
        fi
        local result_variable="_results_${g}"
        local message_variable="_messages_${g}"
        local st msg
        eval "st=\${${result_variable}:-BLOCKED}"
        eval "msg=\${${message_variable}:-(no result recorded)}"
        printf '%-4s %-7s  %s\n' "$g" "$st" "$msg"
        case "$st" in
            "$FAIL")   worst=1;;
            "$BLOCKED") [[ $worst -lt 2 ]] && worst=2;;
        esac
    done

    echo "------------------------------------------------------------------"
    echo "RELEASE GATE RESULT: $([ $worst -eq 0 ] && echo ALL-PASS || ([ $worst -eq 1 ] && echo FAIL-STOP-SHIP || echo BLOCKED-STOP-SHIP))"
    return $worst
}

main "$@"
exit $?
