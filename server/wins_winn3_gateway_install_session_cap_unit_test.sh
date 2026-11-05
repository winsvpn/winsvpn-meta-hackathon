#!/usr/bin/env bash
# Prove the OI-K4 session-count cap (Round K, 2026-09-23) in
# wins_winn3_gateway_install.sh:
#   - unset WINN3_GATEWAY_MAX_SESSIONS derives min(64, fit), fit being what
#     half of MemTotal carries at 208 MiB + 64 MiB per session (96 MiB + 40 MiB
#     before TUNNEL-SPEED-2, 2026-10-10), and flows into
#     the unit's -max-sessions, the env file and MemoryMax;
#   - a derived value below 4 refuses;
#   - an explicit value that does not fit refuses and names the largest that
#     fits, unless WINN3_GATEWAY_MEMORY_OVERCOMMIT=1;
#   - an explicitly empty count is invalid; explicit fitting counts of 1 to 3
#     stay permitted;
#   - an effective MemoryMax from the override triplet is held to the same cap;
#   - an unreadable, missing or malformed meminfo fails closed, overcommit or not;
#   - the value validate_config resolves is the one the unit and env file carry.
# Host memory comes from fixtures under testdata/winn3_gateway_meminfo through
# WINN3_GATEWAY_MEMINFO; one case checks production still reads /proc/meminfo.
# Run it on Linux, the production target: on macOS with Homebrew bash 5.3 the
# installer's override path fails at random (about 7% of runs, pre-existing in
# the live installer, not reproduced on Linux bash 5.2), which makes the
# override cases flaky there.
# Mutates a PRIVATE copy under scratch, never the shared tree. Does not call
# iptables, systemctl or write_unit.
#
# The rule is Round K OI-K4 as ratified in Turn 2. Controls: no-mutation and
# comment-only must PASS; every K mutant must FAIL.
#
# Usage:
#   bash wins_winn3_gateway_install_session_cap_unit_test.sh [/path/to/wins_winn3_gateway_install.sh]
set -euo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
FIX="${HERE}/testdata/winn3_gateway_meminfo"
WORKDIR="${WINN3_SESSION_CAP_UNIT_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/winn3_session_cap/unit_test}"
mkdir -p "${WORKDIR}"
# TUNNEL-SPEED-2 OI-4: WINN3_GATEWAY_DEDICATED defaults to 1 (no cgroup cap);
# every expectation here is the capped formula's, so it runs with 0. The
# payment-server probe points at a path that does not exist.
export WINN3_GATEWAY_DEDICATED=0
export WINN3_GATEWAY_PAYMENT_UNIT="${WORKDIR}/absent/monero-wallet-rpc.service"

printf 'MemTotal:              0 kB\n' > "${WORKDIR}/meminfo_zero"
printf 'MemTotal:        04062208 kB\n' > "${WORKDIR}/meminfo_leading_zero"
printf 'MemTotal:        1234567890123456 kB\n' > "${WORKDIR}/meminfo_huge"
printf 'MemTotal:        4062208 kB\nMemTotal:        4062208 kB\n' > "${WORKDIR}/meminfo_twice"
cp "${FIX}/france" "${WORKDIR}/meminfo_unreadable"
chmod 000 "${WORKDIR}/meminfo_unreadable"
rm -f "${WORKDIR}/no_such_meminfo"

PASS=0
FAIL=0
fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }

SUITE_FAIL=0
SUITE_PASS=0
sfail() { SUITE_FAIL=$((SUITE_FAIL + 1)); printf '  FAIL: %s\n' "$*"; }
spass() { SUITE_PASS=$((SUITE_PASS + 1)); printf '  PASS: %s\n' "$*"; }

# Independent oracle: the unit's MemoryMax for n sessions.
want_max() {
  local kib=$((208 * 1024 + 65536 * $1))
  if (( kib % 1024 == 0 )); then printf 'MemoryMax=%dM' $((kib / 1024)); else printf 'MemoryMax=%dK' "${kib}"; fi
}

# run_emit <script> <meminfo> <sessions|-|EMPTY> <overcommit|-> [max high gomem]
# Emits the unit then the env file in ONE shell, as --install does, into
# ${WORKDIR}/out.{unit,env,err}; returns the shell's exit status.
run_emit() {
  local script="$1" meminfo="$2" n="$3" oc="$4" mx="${5:-}" hi="${6:-}" go="${7:-}"
  local -a envs=(WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp WINN3_GATEWAY_MEMINFO="${meminfo}")
  if [[ "${n}" == "EMPTY" ]]; then envs+=(WINN3_GATEWAY_MAX_SESSIONS=); elif [[ "${n}" != "-" ]]; then envs+=(WINN3_GATEWAY_MAX_SESSIONS="${n}"); fi
  [[ "${oc}" != "-" ]] && envs+=(WINN3_GATEWAY_MEMORY_OVERCOMMIT="${oc}")
  [[ -n "${mx}" ]] && envs+=(WINN3_GATEWAY_MEMORY_MAX="${mx}" WINN3_GATEWAY_MEMORY_HIGH="${hi}" WINN3_GATEWAY_GOMEMLIMIT="${go}")
  local rc=0
  env -u WINN3_GATEWAY_MAX_SESSIONS -u WINN3_GATEWAY_MEMORY_OVERCOMMIT \
      -u WINN3_GATEWAY_MEMORY_MAX -u WINN3_GATEWAY_MEMORY_HIGH -u WINN3_GATEWAY_GOMEMLIMIT \
      "${envs[@]}" bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_RESOLVER=0
    emit_unit_text > "$2.unit"
    emit_env_text > "$2.env"
  ' _ "${script}" "${WORKDIR}/out" 2>"${WORKDIR}/out.err" || rc=$?
  return "${rc}"
}

# expect_sessions <script> <label> <meminfo> <sessions|-> <overcommit|-> <want_n> <log_regex> [override triple]
expect_sessions() {
  local script="$1" label="$2" meminfo="$3" n="$4" oc="$5" want="$6" logre="$7"
  shift 7
  rm -f "${WORKDIR}"/out.*
  if ! run_emit "${script}" "${meminfo}" "${n}" "${oc}" "$@"; then
    sfail "${label}: refused, want ${want} sessions: $(tr '\n' ' ' < "${WORKDIR}/out.err" | tail -c 400)"
    return 0
  fi
  local ok=1
  grep -F -q -- "-max-sessions ${want} " "${WORKDIR}/out.unit" || grep -E -q -- "-max-sessions ${want}( |\\\\|$)" "${WORKDIR}/out.unit" || { ok=0; sfail "${label}: unit lacks -max-sessions ${want}"; }
  grep -F -x -q "WINN3_GATEWAY_MAX_SESSIONS=${want}" "${WORKDIR}/out.env" || { ok=0; sfail "${label}: env file lacks WINN3_GATEWAY_MAX_SESSIONS=${want}"; }
  if [[ $# -eq 0 ]]; then
    grep -F -x -q "$(want_max "${want}")" "${WORKDIR}/out.unit" || { ok=0; sfail "${label}: unit lacks $(want_max "${want}")"; }
  fi
  grep -E -q -- "${logre}" "${WORKDIR}/out.err" || { ok=0; sfail "${label}: stderr lacks /${logre}/"; }
  if grep -F -q "host fit:" "${WORKDIR}/out.unit" "${WORKDIR}/out.env"; then
    ok=0; sfail "${label}: the derivation log leaked into the unit or env text"
  fi
  (( ok )) && spass "${label}: ${want} sessions"
  return 0
}

# expect_refusal <script> <label> <meminfo> <sessions|-> <overcommit|-> <err_regex> [override triple]
expect_refusal() {
  local script="$1" label="$2" meminfo="$3" n="$4" oc="$5" re="$6"
  shift 6
  rm -f "${WORKDIR}"/out.*
  if run_emit "${script}" "${meminfo}" "${n}" "${oc}" "$@"; then
    sfail "${label}: accepted, want a refusal matching /${re}/"
    return 0
  fi
  if grep -E -q -- "${re}" "${WORKDIR}/out.err"; then
    spass "${label}: refused"
  else
    sfail "${label}: refused without /${re}/: $(tr '\n' ' ' < "${WORKDIR}/out.err" | head -c 300)"
  fi
}

check_once_logged() {
  local script="$1" label="$2" rc=0
  env -u WINN3_GATEWAY_MAX_SESSIONS WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp \
      WINN3_GATEWAY_MEMINFO="${FIX}/france" bash -c '
    set -euo pipefail
    source "$1"
    resolve_gateway_memory; resolve_gateway_memory; resolve_gateway_memory
    printf "%s\n" "${WINN3_GATEWAY_MAX_SESSIONS}"
  ' _ "${script}" >"${WORKDIR}/once.out" 2>"${WORKDIR}/once.err" || rc=$?
  local lines
  lines="$(grep -c "host fit: sessions 27 (derived" "${WORKDIR}/once.err" || true)"
  if [[ "${rc}" -eq 0 && "${lines}" == "1" && "$(cat "${WORKDIR}/once.out" 2>/dev/null || true)" == "27" ]]; then
    spass "${label}: three resolutions log once and keep 27"
  else
    sfail "${label}: rc=${rc} log lines=${lines} value=$(cat "${WORKDIR}/once.out" 2>/dev/null)"
  fi
}

check_production_source() {
  local script="$1" label="$2"
  if grep -F -x -q 'WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-/proc/meminfo}"' "${script}" \
     && grep -F -q 'local meminfo="${WINN3_GATEWAY_MEMINFO:-/proc/meminfo}"' "${script}"; then
    spass "${label}: production reads /proc/meminfo"
  else
    sfail "${label}: the default host memory source is not /proc/meminfo"
  fi
  # On a Linux host, prove the real file path end to end.
  if [[ -r /proc/meminfo ]]; then
    local mem cap fit want
    mem="$(awk '$1 == "MemTotal:" {print $2; exit}' /proc/meminfo)"
    cap=$((mem / 2)); fit=$(( cap > 212992 ? (cap - 212992) / 65536 : 0 )); want=$(( fit < 64 ? fit : 64 ))
    if (( want >= 4 )); then
      expect_sessions "${script}" "${label} real /proc/meminfo" /proc/meminfo - - "${want}" "host fit: sessions ${want} \(derived"
    else
      expect_refusal "${script}" "${label} real /proc/meminfo" /proc/meminfo - - "needs at least 4"
    fi
  fi
}

# check_consistency: the value validate_config resolves (it calls
# resolve_gateway_memory) equals what emit_unit_text and emit_env_text carry,
# each in its own fresh process as --preflight and --install run them.
check_consistency() {
  local script="$1" label="$2" fixture="$3" want="$4"
  local pre unit_n env_n unit_max pre_max rc=0
  awk '/^validate_config\(\) \{/{f=1} f{print} f && /^}/{exit}' "${script}" | grep 'if ! resolve_gateway_memory; then' > /dev/null \
    || { sfail "${label}: validate_config does not resolve through resolve_gateway_memory"; return 0; }
  pre="$(env -u WINN3_GATEWAY_MAX_SESSIONS WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp \
      WINN3_GATEWAY_MEMINFO="${fixture}" bash -c '
    set -euo pipefail
    source "$1"
    resolve_gateway_memory 2>/dev/null
    printf "%s %s\n" "${WINN3_GATEWAY_MAX_SESSIONS}" "${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}"
  ' _ "${script}")" || rc=$?
  rm -f "${WORKDIR}"/out.*
  run_emit "${script}" "${fixture}" - - || rc=$?
  unit_n="$(grep -Eo -- '-max-sessions [0-9]+' "${WORKDIR}/out.unit" 2>/dev/null | awk '{print $2}' | head -1 || true)"
  env_n="$(sed -n 's/^WINN3_GATEWAY_MAX_SESSIONS=//p' "${WORKDIR}/out.env" 2>/dev/null || true)"
  unit_max="$(sed -n 's/^MemoryMax=//p' "${WORKDIR}/out.unit" 2>/dev/null || true)"
  pre_max="${pre#* }"
  if [[ "${rc}" -eq 0 && "${pre%% *}" == "${want}" && "${unit_n}" == "${want}" && "${env_n}" == "${want}" && "${unit_max}" == "${pre_max}" ]]; then
    spass "${label}: preflight, unit and env agree on ${want} sessions and MemoryMax=${unit_max}"
  else
    sfail "${label}: rc=${rc} preflight='${pre}' unit=${unit_n}/${unit_max} env=${env_n}, want ${want}"
  fi
}

# check_before_first_write: --install and --start resolve and log host fit
# before main's first installation write (mark_winn3_role).
check_before_first_write() {
  local script="$1" label="$2" body r w
  body="$(awk '/^main\(\) \{/{f=1} f{print} f && /^}/{exit}' "${script}")"
  r="$(printf '%s\n' "${body}" | grep -n 'resolve_gateway_memory || winn3gw_die' | head -1 | cut -d: -f1 || true)"
  w="$(printf '%s\n' "${body}" | grep -n '^    mark_winn3_role$' | head -1 | cut -d: -f1 || true)"
  if [[ -n "${r}" && -n "${w}" ]] && (( r < w )); then
    spass "${label}: host fit is resolved before the first installation write"
  else
    sfail "${label}: main does not resolve host fit before mark_winn3_role (resolve line '${r}', write line '${w}')"
  fi
}

run_suite() {
  local script="$1" label="$2"
  SUITE_FAIL=0
  SUITE_PASS=0
  if ! bash -n "${script}" 2>"${WORKDIR}/bash_n.err"; then
    sfail "${label}: bash -n failed"
    return 0
  fi
  local d="host fit: sessions"
  # Unset: exact 2/4/8/12 GiB hosts, then the fleet's MemTotal (MiB * 1024).
  # fit = floor((MemTotal/2 - 212992) / 65536): 2 GiB 12.75, 4 GiB 28.75,
  # 8 GiB 60.75, 12 GiB 92.75, chicago 12.12, france 27.74, singapore 27.34,
  # netherlands 58.78, uk 87.97.
  expect_sessions "${script}" "${label} unset 2 GiB" "${FIX}/host_2gib" - - 12 "${d} 12 \(derived"
  expect_sessions "${script}" "${label} unset 4 GiB" "${FIX}/host_4gib" - - 28 "${d} 28 \(derived"
  expect_sessions "${script}" "${label} unset 8 GiB" "${FIX}/host_8gib" - - 60 "${d} 60 \(derived"
  expect_sessions "${script}" "${label} unset 12 GiB" "${FIX}/host_12gib" - - 64 "${d} 64 \(derived"
  expect_sessions "${script}" "${label} unset chicago" "${FIX}/chicago" - - 12 "${d} 12 \(derived"
  expect_sessions "${script}" "${label} unset france" "${FIX}/france" - - 27 "${d} 27 \(derived"
  expect_sessions "${script}" "${label} unset singapore" "${FIX}/singapore" - - 27 "${d} 27 \(derived"
  expect_sessions "${script}" "${label} unset netherlands" "${FIX}/netherlands" - - 58 "${d} 58 \(derived"
  expect_sessions "${script}" "${label} unset uk" "${FIX}/uk" - - 64 "${d} 64 \(derived"
  # The four-session boundary.
  expect_sessions "${script}" "${label} unset floor exactly 4" "${FIX}/floor_4" - - 4 "${d} 4 \(derived"
  expect_refusal "${script}" "${label} unset below the floor" "${FIX}/below_floor" - - "fits only 3 session.*needs at least 4"
  # Empty explicit.
  expect_refusal "${script}" "${label} explicit empty" "${FIX}/uk" EMPTY - "set but empty"
  # Explicit fitting, including counts of 1 to 3 on a host too small to auto-select.
  expect_sessions "${script}" "${label} explicit 20 on france" "${FIX}/france" 20 - 20 "${d} 20 \(explicit\)"
  expect_sessions "${script}" "${label} explicit 27 on france (largest fit)" "${FIX}/france" 27 - 27 "${d} 27 \(explicit\)"
  expect_sessions "${script}" "${label} explicit 3 below the auto floor" "${FIX}/below_floor" 3 - 3 "${d} 3 \(explicit\)"
  expect_sessions "${script}" "${label} explicit 1 below the auto floor" "${FIX}/below_floor" 1 - 1 "${d} 1 \(explicit\)"
  # Explicit too large, with and without overcommit.
  expect_refusal "${script}" "${label} explicit 28 on france" "${FIX}/france" 28 - "largest count that fits is 27"
  expect_refusal "${script}" "${label} explicit 4 below the auto floor" "${FIX}/below_floor" 4 - "largest count that fits is 3"
  expect_refusal "${script}" "${label} explicit 64 on chicago" "${FIX}/chicago" 64 - "largest count that fits is 12"
  expect_sessions "${script}" "${label} explicit 64 on chicago, overcommit" "${FIX}/chicago" 64 1 64 "Installing anyway: WINN3_GATEWAY_MEMORY_OVERCOMMIT=1"
  expect_refusal "${script}" "${label} explicit 64 on chicago, overcommit=0" "${FIX}/chicago" 64 0 "largest count that fits is 12"
  expect_refusal "${script}" "${label} overcommit=yes is refused" "${FIX}/uk" 16 yes "OVERCOMMIT must be 1, 0 or unset"
  # Overcommit waives host fit only, never input validation or ordering.
  expect_refusal "${script}" "${label} overcommit does not waive shape" "${FIX}/chicago" 064 1 "positive base-10 integer"
  expect_refusal "${script}" "${label} overcommit does not waive range" "${FIX}/chicago" 1000001 1 "exceeds 1000000"
  expect_refusal "${script}" "${label} overcommit does not waive ordering" "${FIX}/france" 4 1 "GOMEMLIMIT < MemoryHigh < MemoryMax" 8G 6G 7GiB
  # Oversized memory overrides (Astra's reproduction), with and without overcommit.
  expect_refusal "${script}" "${label} override 8G/6G/4GiB, n=4, france" "${FIX}/france" 4 - "Effective MemoryMax 8G .* above half of host RAM" 8G 6G 4GiB
  expect_sessions "${script}" "${label} override 8G/6G/4GiB, n=4, france, overcommit" "${FIX}/france" 4 1 4 "Effective MemoryMax 8G .*Installing anyway" 8G 6G 4GiB
  expect_sessions "${script}" "${label} override within half" "${FIX}/france" 8 - 8 "${d} 8 \(explicit\)" 1G 768M 600MiB
  expect_refusal "${script}" "${label} override does not lift the count cap" "${FIX}/chicago" 64 - "largest count that fits is 12" 900M 700M 500MiB
  # Fail closed: missing, unreadable, malformed, overcommit or not.
  expect_refusal "${script}" "${label} missing meminfo, unset" "${WORKDIR}/no_such_meminfo" - - "fails closed"
  expect_refusal "${script}" "${label} missing meminfo, explicit" "${WORKDIR}/no_such_meminfo" 8 - "fails closed"
  expect_refusal "${script}" "${label} missing meminfo, explicit, overcommit" "${WORKDIR}/no_such_meminfo" 8 1 "fails closed"
  expect_refusal "${script}" "${label} no MemTotal line" "${FIX}/no_memtotal" - - "fails closed"
  expect_refusal "${script}" "${label} MemTotal not in kB" "${FIX}/wrong_unit" - - "fails closed"
  expect_refusal "${script}" "${label} MemTotal zero" "${WORKDIR}/meminfo_zero" - - "fails closed"
  expect_refusal "${script}" "${label} MemTotal leading zero" "${WORKDIR}/meminfo_leading_zero" - - "fails closed"
  expect_refusal "${script}" "${label} MemTotal beyond 15 digits" "${WORKDIR}/meminfo_huge" 8 1 "fails closed"
  expect_refusal "${script}" "${label} two MemTotal lines" "${WORKDIR}/meminfo_twice" - - "fails closed"
  if [[ "$(id -u)" != "0" ]]; then
    expect_refusal "${script}" "${label} unreadable meminfo" "${WORKDIR}/meminfo_unreadable" - - "fails closed"
  else
    spass "${label}: unreadable meminfo not testable as root (the missing-file cases cover the same branch)"
  fi
  check_consistency "${script}" "${label} consistency france" "${FIX}/france" 27
  check_consistency "${script}" "${label} consistency chicago" "${FIX}/chicago" 12
  check_before_first_write "${script}" "${label}"
  check_once_logged "${script}" "${label}"
  check_production_source "${script}" "${label}"
}

apply_once() {
  python3 -c '
import pathlib, sys
path, needle, repl, name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
text = pathlib.Path(path).read_text()
n = text.count(needle)
if n != 1:
    sys.exit(f"{name}: needle occurs {n}x, refusing")
pathlib.Path(path).write_text(text.replace(needle, repl, 1))
print(f"{name}: applied")
' "$@"
}

control() {
  local name="$1" want="$2"
  if [[ "${want}" == pass ]]; then
    if [[ "${SUITE_FAIL}" -eq 0 ]]; then pass "control ${name}: suite passed (inner pass=${SUITE_PASS})"
    else fail "control ${name}: suite did not pass (inner fail=${SUITE_FAIL})"; fi
  else
    if [[ "${SUITE_FAIL}" -ge 1 ]]; then pass "control ${name}: suite went red (inner fail=${SUITE_FAIL}) as required"
    else fail "control ${name}: suite stayed green"; fi
  fi
}

echo "=== no-mutation ==="
echo "script=${INSTALL}"
run_suite "${INSTALL}" "no-mutation"
control no-mutation pass

LIVE_COPY="${WORKDIR}/live.sh"
cat "${INSTALL}" > "${LIVE_COPY}"
COPY="${WORKDIR}/comment_only.sh"
{ printf '#!/usr/bin/env bash\n# comment-only mutation control\n'; tail -n +2 "${LIVE_COPY}"; } > "${COPY}"
echo "=== comment-only ==="
run_suite "${COPY}" "comment-only"
control comment-only pass

mutant() {
  local name="$1" needle="$2" repl="$3"
  local m="${WORKDIR}/${name}.sh"
  cat "${LIVE_COPY}" > "${m}"
  echo "=== ${name} (must FAIL) ==="
  apply_once "${m}" "${needle}" "${repl}" "${name}"
  run_suite "${m}" "${name}"
  control "${name}" fail
}

mutant K1_unset_ignores_host_ram '    n="${fit}"
    (( n > 64 )) && n=64' '    n=64'
mutant K2_no_64_clamp '    (( n > 64 )) && n=64
' ''
mutant K3_no_floor 'if (( fit < 4 )); then' 'if (( fit < 0 )); then'
mutant K4_explicit_unchecked '  if (( need_kib > cap_kib )); then' '  if (( 0 )); then'
mutant K5_overcommit_ignored '    if [[ "${WINN3_GATEWAY_MEMORY_OVERCOMMIT}" != "1" ]]; then
      winn3gw_err "WINN3_GATEWAY_MAX_SESSIONS=' '    if [[ "${WINN3_GATEWAY_MEMORY_OVERCOMMIT}" != "never" ]]; then
      winn3gw_err "WINN3_GATEWAY_MAX_SESSIONS='
mutant K6_missing_meminfo_fails_open '    winn3gw_err "Cannot read ${meminfo}; host fit cannot be established, so the install fails closed."
    return 1' '    printf "%s" 999999999999
    return 0'
mutant K7_cap_is_all_of_ram '  cap_kib=$((mem_kib / 2))' '  cap_kib=$((mem_kib))'
mutant K8_override_bypasses_cap '  if (( max_bytes > cap_bytes )); then' '  if (( 0 )); then'
mutant K9_derived_value_not_used '    WINN3_GATEWAY_MAX_SESSIONS="${n}"
    WINN3_GATEWAY_HOST_SOURCE="derived' '    WINN3_GATEWAY_MAX_SESSIONS="64"
    WINN3_GATEWAY_HOST_SOURCE="derived'
mutant K10_unset_defaulted_early 'WINN3_GATEWAY_MAX_SESSIONS="${WINN3_GATEWAY_MAX_SESSIONS-}"' 'WINN3_GATEWAY_MAX_SESSIONS="${WINN3_GATEWAY_MAX_SESSIONS:-64}"'
mutant K11_base_not_subtracted '  numerator=$((cap_kib - 212992))' '  numerator=$((cap_kib))'
mutant K12_empty_explicit_derives '    if [[ "${WINN3_GATEWAY_MAX_SESSIONS_SUPPLIED}" == "1" ]]; then' '    if [[ 0 == 1 ]]; then'
mutant K13_malformed_memtotal_accepted '^MemTotal:[[:space:]]+([0-9]+)[[:space:]]+kB[[:space:]]*$' '^MemTotal:[[:space:]]+([0-9]+)'
mutant K14_unit_bypasses_host_fit '  resolve_gateway_memory || return 1

  local desc_suffix exec_tail' '  derive_gateway_memory || return 1

  local desc_suffix exec_tail'
mutant K15_log_leaks_into_unit 'overcommit ${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}" >&2' 'overcommit ${WINN3_GATEWAY_HOST_OVERCOMMIT_USED}"'
mutant K17_first_write_before_host_fit '  if [[ "${WINN3_GATEWAY_MODE}" == "install" || "${WINN3_GATEWAY_MODE}" == "start" ]]; then
    resolve_gateway_memory || winn3gw_die "Host fit refused the configuration; nothing was written."
  fi
' ''
mutant K16_overcommit_waives_ordering '    if ! (( gomem_bytes < high_bytes && high_bytes < max_bytes )); then' '    if ! (( gomem_bytes < high_bytes && high_bytes < max_bytes )) && [[ "${WINN3_GATEWAY_MEMORY_OVERCOMMIT}" != "1" ]]; then'

echo
echo "SUMMARY pass=${PASS} fail=${FAIL}"
echo "WORKDIR=${WORKDIR}"
[[ "${FAIL}" -eq 0 ]]
