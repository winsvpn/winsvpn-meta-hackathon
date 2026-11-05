#!/usr/bin/env bash
# Prove emit_unit_text / emit_env_text derive MemoryMax, MemoryHigh and
# GOMEMLIMIT from WINN3_GATEWAY_MAX_SESSIONS (session-derived, not host-RAM).
# Mutates a PRIVATE copy under scratch — never the shared tree. Does not call
# iptables, mktemp-install, systemctl, or write_unit.
#
# Controls:
#   no-mutation   (live script)     must PASS
#   comment-only  (private copy)    must PASS
#   M1 hardcoded MemoryMax=256M     must FAIL
#   M2 MemoryHigh 90% not 75%       must FAIL
#   M3 env file omits GOMEMLIMIT    must FAIL
#   M4 formula ignores session count must FAIL
#   M5 GOMEMLIMIT 100% of MemoryHigh must FAIL
#   M6 GOMEMLIMIT 80% of MemoryMax (above High) must FAIL
#   M7 dedicated default ignored (0)        must FAIL
#   M8 other WINN3_GATEWAY_DEDICATED values accepted must FAIL
#   M9 payment-server exception ignored     must FAIL
#   M10 dedicated overrides the explicit triplet must FAIL
#
# Usage:
#   bash wins_winn3_gateway_install_memory_unit_test.sh
#   bash wins_winn3_gateway_install_memory_unit_test.sh /path/to/wins_winn3_gateway_install.sh
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
WORKDIR="${WINN3_MEMORY_UNIT_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/perf_memory_derived_limits/unit_test}"
mkdir -p "${WORKDIR}"
# TUNNEL-SPEED-2 OI-4: WINN3_GATEWAY_DEDICATED defaults to 1 on every data
# plane (no cgroup cap), so the formula cases below run with it set to 0;
# check_dedicated unsets or sets it per case. The payment-server probe points
# at a path that does not exist unless a case creates it, so a host that
# really runs monero-wallet-rpc.service cannot change these results.
export WINN3_GATEWAY_DEDICATED=0
export WINN3_GATEWAY_PAYMENT_UNIT="${WORKDIR}/absent/monero-wallet-rpc.service"

PASS=0
FAIL=0
BUILD_FAIL=0

fail() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }
pass() { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
build_fail() { BUILD_FAIL=$((BUILD_FAIL + 1)); printf 'BUILD_FAIL: %s\n' "$*"; }

SUITE_FAIL=0
SUITE_PASS=0
SUITE_BUILD=0

sfail() { SUITE_FAIL=$((SUITE_FAIL + 1)); printf '  FAIL: %s\n' "$*"; }
spass() { SUITE_PASS=$((SUITE_PASS + 1)); printf '  PASS: %s\n' "$*"; }
sbuild() { SUITE_BUILD=$((SUITE_BUILD + 1)); printf '  BUILD_FAIL: %s\n' "$*"; }

# Independent oracle — the spec, not a copy of the script's output.
oracle() {
  local n="$1"
  local max_kib high_kib gomem
  # OI-3 (Round 36 treaty): keep this oracle in lockstep with
  # derive_gateway_memory in wins_winn3_gateway_install.sh. The per-session
  # cost dropped from 14336 KiB to 1536 KiB when the gateway moved to
  # zero-allocation fixed slabs. Round K (2026-09-23) rebilled it against the
  # real configured send queue, the widened uplink token window and aggregate
  # live memory: 96 MiB base and 40960 KiB per session. TUNNEL-SPEED-2
  # (2026-10-10) deepened the uplink inbox to 8192 and rebilled it: 208 MiB
  # base and 65536 KiB per session. High at 75 percent of Max and
  # GOMEMLIMIT at 80 percent of High are unchanged.
  max_kib=$((208 * 1024 + 65536 * n))
  high_kib=$((max_kib * 75 / 100))
  gomem=$((high_kib * 1024 * 80 / 100))
  local max_s high_s gomem_s
  if (( max_kib % 1024 == 0 )); then
    max_s="$((max_kib / 1024))M"
  else
    max_s="${max_kib}K"
  fi
  if (( high_kib % 1024 == 0 )); then
    high_s="$((high_kib / 1024))M"
  else
    high_s="${high_kib}K"
  fi
  if (( gomem % 1048576 == 0 )); then
    gomem_s="$((gomem / 1048576))MiB"
  else
    gomem_s="${gomem}"
  fi
  printf '%s %s %s' "${max_s}" "${high_s}" "${gomem_s}"
}

# cgroup_bytes parses a systemd MemoryMax=/MemoryHigh= line to bytes.
# systemd M/K are 1024-based.
cgroup_bytes() {
  local spec="$1" v="${1#*=}"
  if [[ "${v}" == *M ]]; then
    printf '%s' $(( ${v%M} * 1048576 ))
  elif [[ "${v}" == *K ]]; then
    printf '%s' $(( ${v%K} * 1024 ))
  else
    printf '0'
  fi
}

# gomem_bytes_parse parses GOMEMLIMIT=96MiB or GOMEMLIMIT=41209036.
gomem_bytes_parse() {
  local v="${1##*=}"
  if [[ "${v}" == *MiB ]]; then
    printf '%s' $(( ${v%MiB} * 1048576 ))
  elif [[ "${v}" =~ ^[0-9]+$ ]]; then
    printf '%s' "${v}"
  else
    printf '0'
  fi
}

emit_pair() {
  local script="$1" n="$2" unit_out="$3" env_out="$4"
  local rc=0
  env WINN3_GATEWAY_MAX_SESSIONS="${n}" WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp bash -c '
    set -euo pipefail
    # shellcheck disable=SC1090
    source "$1"
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_RESOLVER=0
    WINN3_GATEWAY_MAX_SESSIONS="$2"
    emit_unit_text
  ' _ "${script}" "${n}" >"${unit_out}" 2>"${unit_out}.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sbuild "emit_unit_text N=${n} exited ${rc}: $(tr '\n' ' ' < "${unit_out}.err")"
    return 1
  fi
  rc=0
  env WINN3_GATEWAY_MAX_SESSIONS="${n}" WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp bash -c '
    set -euo pipefail
    source "$1"
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_RESOLVER=0
    WINN3_GATEWAY_MAX_SESSIONS="$2"
    emit_env_text
  ' _ "${script}" "${n}" >"${env_out}" 2>"${env_out}.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sbuild "emit_env_text N=${n} exited ${rc}: $(tr '\n' ' ' < "${env_out}.err")"
    return 1
  fi
  return 0
}

check_n() {
  local script="$1" n="$2" label="$3"
  local unit="${WORKDIR}/unit_n${n}.service"
  local envf="${WORKDIR}/env_n${n}.env"
  emit_pair "${script}" "${n}" "${unit}" "${envf}" || return 0

  local want_max want_high want_gomem
  read -r want_max want_high want_gomem <<<"$(oracle "${n}")"

  local got_max got_high got_envgomem got_unitgomem got_sessions
  got_max="$(grep -E '^MemoryMax=' "${unit}" | head -1 || true)"
  got_high="$(grep -E '^MemoryHigh=' "${unit}" | head -1 || true)"
  got_unitgomem="$(grep -E '^Environment=GOMEMLIMIT=' "${unit}" | head -1 || true)"
  got_envgomem="$(grep -E '^GOMEMLIMIT=' "${envf}" | head -1 || true)"
  got_sessions="$(grep -E '^[[:space:]]+-max-sessions[[:space:]]+[0-9]+([[:space:]]+\\)?$' "${unit}" | head -1 || true)"
  got_sessions="${got_sessions% \\}"

  if [[ "${got_max}" == "MemoryMax=${want_max}" ]]; then
    spass "${label} N=${n}: MemoryMax=${want_max}"
  else
    sfail "${label} N=${n}: MemoryMax is '${got_max}', want MemoryMax=${want_max}"
  fi
  if [[ "${got_high}" == "MemoryHigh=${want_high}" ]]; then
    spass "${label} N=${n}: MemoryHigh=${want_high}"
  else
    sfail "${label} N=${n}: MemoryHigh is '${got_high}', want MemoryHigh=${want_high}"
  fi
  if [[ "${got_unitgomem}" == "Environment=GOMEMLIMIT=${want_gomem}" ]]; then
    spass "${label} N=${n}: unit Environment=GOMEMLIMIT=${want_gomem}"
  else
    sfail "${label} N=${n}: unit GOMEMLIMIT is '${got_unitgomem}', want Environment=GOMEMLIMIT=${want_gomem}"
  fi
  if [[ "${got_envgomem}" == "GOMEMLIMIT=${want_gomem}" ]]; then
    spass "${label} N=${n}: env GOMEMLIMIT=${want_gomem}"
  else
    sfail "${label} N=${n}: env GOMEMLIMIT is '${got_envgomem}', want GOMEMLIMIT=${want_gomem}"
  fi
  if [[ "${got_sessions}" == *" -max-sessions ${n}" ]]; then
    spass "${label} N=${n}: -max-sessions baked as ${n}"
  else
    sfail "${label} N=${n}: -max-sessions line is '${got_sessions}', want baked ${n}"
  fi
  if grep -F -q '${WINN3_GATEWAY_MAX_SESSIONS}' "${unit}"; then
    sfail "${label} N=${n}: unit still expands \${WINN3_GATEWAY_MAX_SESSIONS} (desyncs from MemoryMax)"
  else
    spass "${label} N=${n}: -max-sessions is not an env-file expansion"
  fi

  # Independent of the oracle strings: GOMEMLIMIT must sit strictly below
  # MemoryHigh. 80% of MemoryMax is 80>75 and would pass a string oracle that
  # had been updated to match it; this byte comparison still goes red.
  local high_b gomem_b
  high_b="$(cgroup_bytes "${got_high}")"
  gomem_b="$(gomem_bytes_parse "${got_envgomem}")"
  if [[ "${high_b}" != 0 && "${gomem_b}" != 0 ]] && (( gomem_b < high_b )); then
    spass "${label} N=${n}: GOMEMLIMIT ${gomem_b} < MemoryHigh ${high_b}"
  else
    sfail "${label} N=${n}: GOMEMLIMIT ${gomem_b} is not below MemoryHigh ${high_b} (got_high=${got_high} got_gomem=${got_envgomem})"
  fi
}

check_rejects() {
  local script="$1" label="$2" n="$3"
  local rc=0
  env WINN3_GATEWAY_MAX_SESSIONS="${n}" WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp bash -c '
    set -euo pipefail
    source "$1"
    WINN3_GATEWAY_MAX_SESSIONS="$2"
    derive_gateway_memory
  ' _ "${script}" "${n}" >"${WORKDIR}/reject_${n}.out" 2>"${WORKDIR}/reject_${n}.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    spass "${label}: WINN3_GATEWAY_MAX_SESSIONS='${n}' is refused (exit ${rc})"
  else
    sfail "${label}: WINN3_GATEWAY_MAX_SESSIONS='${n}' was accepted"
  fi
}

check_not_host_derived() {
  local script="$1" label="$2"
  local fn="${WORKDIR}/derive_fn.txt"
  # Only derive_gateway_memory is in scope. The installer also reads MemTotal
  # to tier nf_conntrack_max -- that is a different knob, not MemoryMax.
  awk '/^derive_gateway_memory\(\)/,/^}$/' "${script}" > "${fn}"
  if [[ ! -s "${fn}" ]]; then
    sfail "${label}: derive_gateway_memory not found"
    return 0
  fi
  if grep -E 'MemTotal|/proc/meminfo|sysconf' "${fn}" >/dev/null; then
    sfail "${label}: derive_gateway_memory reads host RAM"
  else
    spass "${label}: derive_gateway_memory does not read host RAM"
  fi
  if grep -E -q '208 \* 1024 \+ 65536 \* n' "${fn}"; then
    spass "${label}: formula is 208MiB + 64MiB * sessions"
  else
    sfail "${label}: session-derived formula 208*1024 + 65536*n is missing from derive_gateway_memory"
  fi
  if grep -F -q 'gomem_bytes=$((high_kib * 1024 * 80 / 100))' "${fn}"; then
    spass "${label}: GOMEMLIMIT is 80% of MemoryHigh"
  else
    sfail "${label}: GOMEMLIMIT is not 80% of MemoryHigh (must sit below the cgroup throttle)"
  fi
}

# check_dedicated: WINN3_GATEWAY_DEDICATED (mythos_t9_4; default 1 on every
# data plane, owner rulings 2026-10-10) writes MemoryMax=infinity and
# MemoryHigh=infinity into the unit and GOMEMLIMIT = the larger of the
# formula's figure and half of MemTotal into the unit and the env file, still
# bakes the session count, lets an explicit override triplet win and refuses
# any value but 0 and 1. Where the payment server's unit exists and the
# variable is unset, the default renders 0 (Claude seat, Turn 10).
FIXDIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo"

# dedicated_emit SCRIPT FN MEMINFO SESSIONS OUT [VAR=value...]: run one emitter
# with WINN3_GATEWAY_DEDICATED unset unless a VAR=value sets it.
dedicated_emit() {
  local script="$1" fn="$2" meminfo="$3" n="$4" out="$5"
  shift 5
  env -u WINN3_GATEWAY_DEDICATED WINN3_GATEWAY_MEMINFO="${meminfo}" WINN3_GATEWAY_MAX_SESSIONS="${n}" \
    WINN3_GATEWAY_PATH_MTU=1450 WINN3_GATEWAY_PLAN=udp "$@" bash -c '
    set -euo pipefail
    source "$1"
    WINN3_GATEWAY_FORWARD=0
    WINN3_GATEWAY_RESOLVER=0
    "$2"
  ' _ "${script}" "${fn}" >"${out}" 2>"${out}.err"
}

# dedicated_want_gomem MEMINFO N: the oracle for a dedicated GOMEMLIMIT, the
# larger of the formula's 80% of MemoryHigh and half of MemTotal, formatted as
# the installer formats it (whole MiB as NMiB, otherwise bytes).
dedicated_want_gomem() {
  local meminfo="$1" n="$2" mem_kib half formula max_kib high_kib want
  mem_kib="$(awk '$1 == "MemTotal:" {print $2; exit}' "${meminfo}")"
  half=$(( (mem_kib / 2) * 1024 ))
  max_kib=$((208 * 1024 + 65536 * n))
  high_kib=$((max_kib * 75 / 100))
  formula=$((high_kib * 1024 * 80 / 100))
  want=$(( formula > half ? formula : half ))
  if (( want % 1048576 == 0 )); then printf '%dMiB' $((want / 1048576)); else printf '%d' "${want}"; fi
}

# expect_dedicated_output LABEL UNIT ENVF MAX HIGH GOMEM N: compare the
# rendered unit and env file with the wanted triplet and session count.
expect_dedicated_output() {
  local label="$1" unit="$2" envf="$3" want_max="$4" want_high="$5" want_gomem="$6" n="$7"
  if grep -x -q "MemoryMax=${want_max}" "${unit}" && grep -x -q "MemoryHigh=${want_high}" "${unit}" \
     && grep -x -q "Environment=GOMEMLIMIT=${want_gomem}" "${unit}" && grep -x -q "GOMEMLIMIT=${want_gomem}" "${envf}"; then
    spass "${label}: MemoryMax=${want_max} MemoryHigh=${want_high} GOMEMLIMIT=${want_gomem}"
  else
    sfail "${label}: want MemoryMax=${want_max} MemoryHigh=${want_high} GOMEMLIMIT=${want_gomem}; got $(grep -E '^(MemoryMax|MemoryHigh|Environment=GOMEMLIMIT)=' "${unit}" | tr '\n' ' ') env $(grep -E '^GOMEMLIMIT=' "${envf}")"
  fi
  if grep -E -q "^[[:space:]]+-max-sessions[[:space:]]+${n}([[:space:]]+\\\\)?\$" "${unit}" && grep -x -q "WINN3_GATEWAY_MAX_SESSIONS=${n}" "${envf}"; then
    spass "${label}: still bakes -max-sessions ${n}"
  else
    sfail "${label}: lost the session count ${n}"
  fi
}

# dedicated_case LABEL MEMINFO N MAX HIGH GOMEM LOGRE [VAR=value...]
dedicated_case() {
  local script="$1" label="$2" meminfo="$3" n="$4" want_max="$5" want_high="$6" want_gomem="$7" logre="$8"
  shift 8
  local tag unit envf
  tag="$(printf '%s' "${label}" | tr -c 'A-Za-z0-9' '_')"
  unit="${WORKDIR}/ded_${tag}.service"
  envf="${WORKDIR}/ded_${tag}.env"
  if ! dedicated_emit "${script}" emit_unit_text "${meminfo}" "${n}" "${unit}" "$@" \
     || ! dedicated_emit "${script}" emit_env_text "${meminfo}" "${n}" "${envf}" "$@"; then
    sfail "${label}: an emitter failed: $(cat "${unit}.err" "${envf}.err" 2>/dev/null | tr '\n' ' ')"
    return 0
  fi
  expect_dedicated_output "${label}" "${unit}" "${envf}" "${want_max}" "${want_high}" "${want_gomem}" "${n}"
  if grep -E -q "${logre}" "${unit}.err"; then
    spass "${label}: host-fit log matches '${logre}'"
  else
    sfail "${label}: host-fit log does not match '${logre}': $(tr '\n' ' ' < "${unit}.err")"
  fi
}

check_dedicated() {
  local script="$1" label="$2" rc v payment
  local large="${FIXDIR}/large" chicago="${FIXDIR}/chicago"
  # Unset: the data-plane default writes no cgroup cap; on the 128 TiB
  # fixture half of MemTotal is the larger GOMEMLIMIT figure.
  dedicated_case "${script}" "${label} dedicated unset" "${large}" 64 infinity infinity \
    "$(dedicated_want_gomem "${large}" 64)" 'dedicated 1; MemoryMax=infinity'
  # Explicit 1 on chicago with 64 sessions (overcommit waives host fit): the
  # formula's 2707842662 B is above half of MemTotal, so the formula wins.
  dedicated_case "${script}" "${label} dedicated 1 formula floor" "${chicago}" 64 infinity infinity \
    "$(dedicated_want_gomem "${chicago}" 64)" 'dedicated 1; MemoryMax=infinity' \
    WINN3_GATEWAY_DEDICATED=1 WINN3_GATEWAY_MEMORY_OVERCOMMIT=1
  if [[ "$(dedicated_want_gomem "${chicago}" 64)" == 2707842662 ]]; then
    spass "${label}: the chicago case exercises the formula side of the maximum"
  else
    sfail "${label}: the chicago case no longer exercises the formula side ($(dedicated_want_gomem "${chicago}" 64))"
  fi
  # An explicit override triplet still wins under dedicated 1.
  dedicated_case "${script}" "${label} dedicated 1 override wins" "${large}" 8 1G 768M 600MiB \
    'dedicated 1; MemoryMax=1G MemoryHigh=768M GOMEMLIMIT=600MiB' \
    WINN3_GATEWAY_DEDICATED=1 WINN3_GATEWAY_MEMORY_MAX=1G WINN3_GATEWAY_MEMORY_HIGH=768M WINN3_GATEWAY_GOMEMLIMIT=600MiB
  # 0 restores the capped formula.
  dedicated_case "${script}" "${label} dedicated 0" "${large}" 64 4304M 3228M 2707842662 \
    'dedicated 0; MemoryMax=4304M' WINN3_GATEWAY_DEDICATED=0
  # Any other value is refused, the set-but-empty value included.
  for v in 2 yes true EMPTY; do
    rc=0
    if [[ "${v}" == EMPTY ]]; then set -- WINN3_GATEWAY_DEDICATED=; else set -- WINN3_GATEWAY_DEDICATED="${v}"; fi
    env WINN3_GATEWAY_MEMINFO="${large}" WINN3_GATEWAY_MAX_SESSIONS=8 "$@" bash -c '
      set -euo pipefail
      source "$1"
      resolve_gateway_memory
    ' _ "${script}" >/dev/null 2>"${WORKDIR}/dedicated_bad_${v}.err" || rc=$?
    if [[ "${rc}" -ne 0 ]] && grep -q 'WINN3_GATEWAY_DEDICATED must be 1, 0 or unset' "${WORKDIR}/dedicated_bad_${v}.err"; then
      spass "${label}: WINN3_GATEWAY_DEDICATED=${v} is refused"
    else
      sfail "${label}: WINN3_GATEWAY_DEDICATED=${v} was accepted (exit ${rc})"
    fi
  done
  # The payment-server exception (Spain): the unit's presence renders 0 when
  # the variable is unset, and an explicit 1 still wins.
  payment="${WORKDIR}/payment/monero-wallet-rpc.service"
  mkdir -p "${WORKDIR}/payment"
  : > "${payment}"
  dedicated_case "${script}" "${label} payment server present" "${large}" 64 4304M 3228M 2707842662 \
    'dedicated 0 \(payment server present\); MemoryMax=4304M' WINN3_GATEWAY_PAYMENT_UNIT="${payment}"
  dedicated_case "${script}" "${label} payment server present, explicit 1" "${large}" 64 infinity infinity \
    "$(dedicated_want_gomem "${large}" 64)" 'dedicated 1; MemoryMax=infinity' \
    WINN3_GATEWAY_PAYMENT_UNIT="${payment}" WINN3_GATEWAY_DEDICATED=1
  rm -f -- "${payment}"
}

run_suite() {
  local script="$1" label="$2"
  SUITE_FAIL=0
  SUITE_PASS=0
  SUITE_BUILD=0

  if ! bash -n "${script}" 2>"${WORKDIR}/bash_n.err"; then
    sbuild "${label}: bash -n failed: $(tr '\n' ' ' < "${WORKDIR}/bash_n.err")"
    return 0
  fi
  spass "${label}: bash -n clean"

  if ! grep -E -q '^[[:space:]]*main( |$)' "${script}"; then
    spass "${label}: extracted block has no main call"
  else
    sfail "${label}: extracted block calls main"
  fi

  check_n "${script}" 1 "${label}"
  check_n "${script}" 64 "${label}"
  check_n "${script}" 200 "${label}"
  check_rejects "${script}" "${label}" 0
  check_rejects "${script}" "${label}" abc
  check_rejects "${script}" "${label}" 064
  check_not_host_derived "${script}" "${label}"
  check_dedicated "${script}" "${label}"
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

echo "=== no-mutation (live script) ==="
echo "script=${INSTALL}"
run_suite "${INSTALL}" "no-mutation"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "control no-mutation: suite passed (inner pass=${SUITE_PASS})"
else
  fail "control no-mutation: suite did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

LIVE_COPY="${WORKDIR}/live.sh"
cat "${INSTALL}" > "${LIVE_COPY}"

echo "=== comment-only (private copy) ==="
COMMENT_COPY="${WORKDIR}/comment_only.sh"
cat "${LIVE_COPY}" > "${COMMENT_COPY}"
python3 -c '
import pathlib, sys
p = pathlib.Path(sys.argv[1])
text = p.read_text()
old = "#!/usr/bin/env bash\n"
if not text.startswith(old):
    sys.exit("shebang not at start")
p.write_text(old + "# comment-only mutation control; no behaviour change\n" + text[len(old):])
' "${COMMENT_COPY}"
run_suite "${COMMENT_COPY}" "comment-only"
if [[ "${SUITE_FAIL}" -eq 0 && "${SUITE_BUILD}" -eq 0 ]]; then
  pass "control comment-only: suite passed (inner pass=${SUITE_PASS})"
else
  fail "control comment-only: suite did not pass (inner fail=${SUITE_FAIL} build_fail=${SUITE_BUILD})"
fi

echo "=== M1: hardcoded MemoryMax=256M (must FAIL) ==="
M1="${WORKDIR}/m1_hardcoded.sh"
cat "${LIVE_COPY}" > "${M1}"
apply_once "${M1}" \
  'MemoryMax=${WINN3_GATEWAY_EFFECTIVE_MEMORY_MAX}
MemoryHigh=${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH}' \
  'MemoryMax=256M
MemoryHigh=${WINN3_GATEWAY_EFFECTIVE_MEMORY_HIGH}' \
  "M1"
run_suite "${M1}" "M1"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M1: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M1: suite stayed green after hardcoding MemoryMax=256M"
fi

echo "=== M2: MemoryHigh 90% not 75% (must FAIL) ==="
M2="${WORKDIR}/m2_high90.sh"
cat "${LIVE_COPY}" > "${M2}"
apply_once "${M2}" \
  'high_kib=$((max_kib * 75 / 100))' \
  'high_kib=$((max_kib * 90 / 100))' \
  "M2"
run_suite "${M2}" "M2"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M2: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M2: suite stayed green after MemoryHigh=90%"
fi

echo "=== M3: env file omits GOMEMLIMIT (must FAIL) ==="
M3="${WORKDIR}/m3_no_gomem.sh"
cat "${LIVE_COPY}" > "${M3}"
apply_once "${M3}" \
  '# sails into MemoryHigh.
GOMEMLIMIT=${WINN3_GATEWAY_EFFECTIVE_GOMEMLIMIT}' \
  '# sails into MemoryHigh.
# GOMEMLIMIT omitted by mutation' \
  "M3"
run_suite "${M3}" "M3"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M3: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M3: suite stayed green after dropping GOMEMLIMIT from the env file"
fi

echo "=== M4: formula ignores session count (must FAIL) ==="
M4="${WORKDIR}/m4_fixed.sh"
cat "${LIVE_COPY}" > "${M4}"
apply_once "${M4}" \
  'max_kib=$((208 * 1024 + 65536 * n))' \
  'max_kib=$((256 * 1024))' \
  "M4"
run_suite "${M4}" "M4"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M4: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M4: suite stayed green after a session-independent MemoryMax"
fi

echo "=== M5: GOMEMLIMIT 100% of MemoryHigh (must FAIL) ==="
M5="${WORKDIR}/m5_gomem100.sh"
cat "${LIVE_COPY}" > "${M5}"
apply_once "${M5}" \
  'gomem_bytes=$((high_kib * 1024 * 80 / 100))' \
  'gomem_bytes=$((high_kib * 1024 * 100 / 100))' \
  "M5"
run_suite "${M5}" "M5"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M5: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M5: suite stayed green after GOMEMLIMIT=100% of MemoryHigh"
fi

echo "=== M6: GOMEMLIMIT 80% of MemoryMax, above High (must FAIL) ==="
M6="${WORKDIR}/m6_gomem_of_max.sh"
cat "${LIVE_COPY}" > "${M6}"
apply_once "${M6}" \
  'gomem_bytes=$((high_kib * 1024 * 80 / 100))' \
  'gomem_bytes=$((max_kib * 1024 * 80 / 100))' \
  "M6"
run_suite "${M6}" "M6"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M6: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M6: suite stayed green after GOMEMLIMIT=80% of MemoryMax (above MemoryHigh)"
fi

echo "=== M7: dedicated default ignored (must FAIL) ==="
M7="${WORKDIR}/m7_dedicated_default_ignored.sh"
cat "${LIVE_COPY}" > "${M7}"
apply_once "${M7}" \
  'WINN3_GATEWAY_DEDICATED="${WINN3_GATEWAY_DEDICATED-1}"' \
  'WINN3_GATEWAY_DEDICATED="${WINN3_GATEWAY_DEDICATED-0}"' \
  "M7"
run_suite "${M7}" "M7"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M7: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M7: suite stayed green when an unset WINN3_GATEWAY_DEDICATED derived capped limits"
fi

echo "=== M8: other WINN3_GATEWAY_DEDICATED values accepted (must FAIL) ==="
M8="${WORKDIR}/m8_dedicated_values_accepted.sh"
cat "${LIVE_COPY}" > "${M8}"
apply_once "${M8}" \
  '    *) winn3gw_err "WINN3_GATEWAY_DEDICATED must be 1, 0 or unset."; return 1 ;;' \
  '    *) ;;' \
  "M8"
run_suite "${M8}" "M8"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M8: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M8: suite stayed green when WINN3_GATEWAY_DEDICATED accepted values other than 0 and 1"
fi

echo "=== M9: payment-server exception ignored (must FAIL) ==="
M9="${WORKDIR}/m9_payment_exception_ignored.sh"
cat "${LIVE_COPY}" > "${M9}"
apply_once "${M9}" \
  'if [[ -z "${WINN3_GATEWAY_DEDICATED+x}" && -e "${WINN3_GATEWAY_PAYMENT_UNIT}" ]]; then' \
  'if [[ 0 == 1 ]]; then' \
  "M9"
run_suite "${M9}" "M9"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M9: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M9: suite stayed green when the payment-server exception was ignored"
fi

echo "=== M10: dedicated overrides the explicit triplet (must FAIL) ==="
M10="${WORKDIR}/m10_dedicated_beats_override.sh"
cat "${LIVE_COPY}" > "${M10}"
apply_once "${M10}" \
  'if [[ "${WINN3_GATEWAY_DEDICATED}" == "1" && -z "${WINN3_GATEWAY_MEMORY_MAX:-}" ]]; then' \
  'if [[ "${WINN3_GATEWAY_DEDICATED}" == "1" ]]; then' \
  "M10"
run_suite "${M10}" "M10"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M10: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M10: suite stayed green when dedicated mode ignored an explicit override triplet"
fi

echo
echo "SUMMARY pass=${PASS} fail=${FAIL} build_fail=${BUILD_FAIL}"
echo "WORKDIR=${WORKDIR}"

if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
