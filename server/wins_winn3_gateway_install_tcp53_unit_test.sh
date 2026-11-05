#!/usr/bin/env bash
# Prove emit_unit_text's four-variant capability matrix (D21 / design E) and
# the narrow TCP/53 INPUT matchers (design F). Mutates a PRIVATE copy under
# scratch — never the shared tree. Does not call iptables, mktemp-install,
# systemctl, or write_unit.
#
# Controls:
#   no-mutation   (live script)     must PASS
#   comment-only  (private copy)    must PASS
#   M1 F=0 R=1 gains bind-service   must FAIL (WAN open-resolver grant)
#   M2 F=1 R=1 forgets bind-service must FAIL
#   M3 F=1 R=1 bounding not ambient must FAIL
#   M4 F=1 R=0 gains bind-service   must FAIL
#   M5 matchers omit -d             must FAIL (too broad)
#   M6 matchers omit -i             must FAIL (too broad)
#
# Usage:
#   bash wins_winn3_gateway_install_tcp53_unit_test.sh
#   bash wins_winn3_gateway_install_tcp53_unit_test.sh /path/to/wins_winn3_gateway_install.sh
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
WORKDIR="${WINN3_TCP53_UNIT_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/gateway_resolver_tcp53_impl/unit_test}"
mkdir -p "${WORKDIR}"

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

emit_unit() {
  local script="$1" forward="$2" resolver="$3" out="$4"
  local rc=0
  env \
    WINN3_GATEWAY_PATH_MTU=1450 \
    WINN3_GATEWAY_PLAN=udp \
    WINN3_GATEWAY_INNER_V4=10.10.0.1 \
    WINN3_GATEWAY_FORWARD_IF=winn3gw0 \
    WINN3_GATEWAY_FORWARD_CIDR=10.10.0.0/24 \
    WINN3_GATEWAY_RESOLVER_UPSTREAM=127.0.0.1:53 \
    WINN3_GATEWAY_RESOLVER_TIMEOUT=5s \
    bash -c '
      set -euo pipefail
      # shellcheck disable=SC1090
      source "$1"
      WINN3_GATEWAY_FORWARD="$2"
      WINN3_GATEWAY_RESOLVER="$3"
      emit_unit_text
    ' _ "${script}" "${forward}" "${resolver}" >"${out}" 2>"${out}.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sbuild "emit_unit F=${forward} R=${resolver} exited ${rc}: $(tr '\n' ' ' < "${out}.err")"
    return 1
  fi
  return 0
}

cap_line() {
  local file="$1" key="$2"
  grep -E "^${key}=" "${file}" | head -1 || true
}

has_exec_flag() {
  local file="$1" flag="$2"
  grep -E "^[[:space:]]+${flag}([[:space:]]*\\\\)?$" "${file}" >/dev/null
}

check_variant() {
  local script="$1" f="$2" r="$3" label="$4"
  local unit="${WORKDIR}/unit_F${f}_R${r}.service"
  emit_unit "${script}" "${f}" "${r}" "${unit}" || return 0

  local bound ambient
  bound="$(cap_line "${unit}" CapabilityBoundingSet)"
  ambient="$(cap_line "${unit}" AmbientCapabilities)"

  case "${f}${r}" in
    00)
      if [[ "${bound}" == "CapabilityBoundingSet=" ]]; then
        spass "${label} F=0 R=0: bounding empty"
      else
        sfail "${label} F=0 R=0: bounding is '${bound}', want CapabilityBoundingSet="
      fi
      if [[ "${ambient}" == "AmbientCapabilities=" ]]; then
        spass "${label} F=0 R=0: ambient empty"
      else
        sfail "${label} F=0 R=0: ambient is '${ambient}', want AmbientCapabilities="
      fi
      if grep -F -q 'CAP_NET_BIND_SERVICE' "${unit}"; then
        sfail "${label} F=0 R=0: unit contains CAP_NET_BIND_SERVICE"
      else
        spass "${label} F=0 R=0: no CAP_NET_BIND_SERVICE"
      fi
      if grep -F -q 'CAP_NET_ADMIN' "${unit}"; then
        sfail "${label} F=0 R=0: unit contains CAP_NET_ADMIN"
      else
        spass "${label} F=0 R=0: no CAP_NET_ADMIN"
      fi
      if has_exec_flag "${unit}" '-forward'; then
        sfail "${label} F=0 R=0: ExecStart has -forward"
      else
        spass "${label} F=0 R=0: no -forward flag"
      fi
      if has_exec_flag "${unit}" '-resolver'; then
        sfail "${label} F=0 R=0: ExecStart has -resolver"
      else
        spass "${label} F=0 R=0: no -resolver flag"
      fi
      ;;
    10)
      if [[ "${bound}" == "CapabilityBoundingSet=CAP_NET_ADMIN" ]]; then
        spass "${label} F=1 R=0: bounding CAP_NET_ADMIN only"
      else
        sfail "${label} F=1 R=0: bounding is '${bound}', want CapabilityBoundingSet=CAP_NET_ADMIN"
      fi
      if [[ "${ambient}" == "AmbientCapabilities=CAP_NET_ADMIN" ]]; then
        spass "${label} F=1 R=0: ambient CAP_NET_ADMIN only"
      else
        sfail "${label} F=1 R=0: ambient is '${ambient}', want AmbientCapabilities=CAP_NET_ADMIN"
      fi
      if grep -F -q 'CAP_NET_BIND_SERVICE' "${unit}"; then
        sfail "${label} F=1 R=0: unit contains CAP_NET_BIND_SERVICE (nothing binds 53 without resolver)"
      else
        spass "${label} F=1 R=0: no CAP_NET_BIND_SERVICE"
      fi
      if has_exec_flag "${unit}" '-forward'; then
        spass "${label} F=1 R=0: has -forward"
      else
        sfail "${label} F=1 R=0: missing -forward"
      fi
      if grep -F -q -- '-accept-transit=true' "${unit}"; then
        spass "${label} F=1 R=0: has -accept-transit=true"
      else
        sfail "${label} F=1 R=0: missing -accept-transit=true"
      fi
      if has_exec_flag "${unit}" '-resolver'; then
        sfail "${label} F=1 R=0: ExecStart has -resolver"
      else
        spass "${label} F=1 R=0: no -resolver flag"
      fi
      ;;
    01)
      if [[ "${bound}" == "CapabilityBoundingSet=" ]]; then
        spass "${label} F=0 R=1: bounding empty"
      else
        sfail "${label} F=0 R=1: bounding is '${bound}', want empty (WAN open-resolver if bind-service is granted)"
      fi
      if [[ "${ambient}" == "AmbientCapabilities=" ]]; then
        spass "${label} F=0 R=1: ambient empty"
      else
        sfail "${label} F=0 R=1: ambient is '${ambient}', want empty"
      fi
      if grep -F -q 'CAP_NET_BIND_SERVICE' "${unit}"; then
        sfail "${label} F=0 R=1: unit contains CAP_NET_BIND_SERVICE (WAN open-resolver grant)"
      else
        spass "${label} F=0 R=1: no CAP_NET_BIND_SERVICE"
      fi
      if grep -F -q 'CAP_NET_ADMIN' "${unit}"; then
        sfail "${label} F=0 R=1: unit contains CAP_NET_ADMIN"
      else
        spass "${label} F=0 R=1: no CAP_NET_ADMIN"
      fi
      if has_exec_flag "${unit}" '-resolver'; then
        spass "${label} F=0 R=1: has -resolver"
      else
        sfail "${label} F=0 R=1: missing -resolver"
      fi
      if grep -F -q -- '-resolver-upstream' "${unit}"; then
        spass "${label} F=0 R=1: has -resolver-upstream"
      else
        sfail "${label} F=0 R=1: missing -resolver-upstream"
      fi
      if has_exec_flag "${unit}" '-forward'; then
        sfail "${label} F=0 R=1: ExecStart has -forward"
      else
        spass "${label} F=0 R=1: no -forward flag"
      fi
      ;;
    11)
      if [[ "${bound}" == "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE" ]]; then
        spass "${label} F=1 R=1: bounding CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
      else
        sfail "${label} F=1 R=1: bounding is '${bound}', want CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
      fi
      if [[ "${ambient}" == "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE" ]]; then
        spass "${label} F=1 R=1: ambient CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
      else
        sfail "${label} F=1 R=1: ambient is '${ambient}', want AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE (non-root User cannot bind 53 with bounding only)"
      fi
      if [[ "${bound}" == *CAP_NET_BIND_SERVICE* && "${bound}" != *CAP_NET_ADMIN* ]]; then
        sfail "${label} F=1 R=1: bind-service without admin (forward still needs tun)"
      fi
      if has_exec_flag "${unit}" '-forward' && has_exec_flag "${unit}" '-resolver'; then
        spass "${label} F=1 R=1: has both -forward and -resolver"
      else
        sfail "${label} F=1 R=1: missing -forward or -resolver"
      fi
      if grep -F -q -- '-accept-transit=true' "${unit}"; then
        spass "${label} F=1 R=1: has -accept-transit=true"
      else
        sfail "${label} F=1 R=1: missing -accept-transit=true"
      fi
      if grep -F -q -- '-resolver-upstream' "${unit}"; then
        spass "${label} F=1 R=1: has -resolver-upstream"
      else
        sfail "${label} F=1 R=1: missing -resolver-upstream"
      fi
      ;;
    *)
      sfail "${label}: unknown variant F=${f} R=${r}"
      ;;
  esac

  if [[ "${f}" == "1" ]]; then
    if grep -F -q -- '-peer-registry /etc/winn/winn3-peers.json' "${unit}"; then
      spass "${label} F=${f} R=${r}: authenticated peer registry is mandatory"
    else
      sfail "${label} F=${f} R=${r}: missing -peer-registry /etc/winn/winn3-peers.json"
    fi
  elif grep -F -q -- '-peer-registry' "${unit}"; then
    sfail "${label} F=${f} R=${r}: reflector unexpectedly reads a peer registry"
  else
    spass "${label} F=${f} R=${r}: reflector has no peer-registry flag"
  fi

  if grep -F -q 'NoNewPrivileges=yes' "${unit}"; then
    spass "${label} F=${f} R=${r}: NoNewPrivileges=yes"
  else
    sfail "${label} F=${f} R=${r}: missing NoNewPrivileges=yes"
  fi
  if grep -F -q 'PrivateDevices=yes' "${unit}"; then
    spass "${label} F=${f} R=${r}: PrivateDevices=yes"
  else
    sfail "${label} F=${f} R=${r}: missing PrivateDevices=yes"
  fi
  if grep -F -q 'PrivateDevices=no' "${unit}"; then
    sfail "${label} F=${f} R=${r}: PrivateDevices=no is set (must not be)"
  else
    spass "${label} F=${f} R=${r}: PrivateDevices=no is absent"
  fi
  if grep -E -q '^User=winn3-gateway$' "${unit}"; then
    spass "${label} F=${f} R=${r}: User=winn3-gateway"
  else
    sfail "${label} F=${f} R=${r}: User is not winn3-gateway"
  fi
}

check_input_matchers() {
  local script="$1" label="$2"
  local out="${WORKDIR}/matchers.out" errf="${WORKDIR}/matchers.err" rc=0
  env bash -c '
    set -euo pipefail
    source "$1"
    resolver_tcp53_input_matchers winn3gw0 10.10.0.1
  ' _ "${script}" >"${out}" 2>"${errf}" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sfail "${label}: resolver_tcp53_input_matchers exited ${rc}: $(tr '\n' ' ' < "${errf}")"
  else
    local got
    got="$(cat "${out}")"
    if [[ "${got}" == "-i winn3gw0 -d 10.10.0.1 -p tcp --dport 53" ]]; then
      spass "${label}: matchers exact -i IFACE -d INNER -p tcp --dport 53"
    else
      sfail "${label}: matchers are '${got}', want '-i winn3gw0 -d 10.10.0.1 -p tcp --dport 53'"
    fi
    if [[ "${got}" == *-i* && "${got}" == *-d* ]]; then
      spass "${label}: matchers contain both -i and -d"
    else
      sfail "${label}: matchers missing -i or -d (too broad: open resolver on WAN)"
    fi
  fi

  rc=0
  env bash -c '
    set -euo pipefail
    source "$1"
    resolver_tcp53_input_matchers "" 10.10.0.1
  ' _ "${script}" >"${WORKDIR}/matchers_empty_i.out" 2>"${WORKDIR}/matchers_empty_i.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    spass "${label}: empty iface is refused (exit ${rc})"
  else
    sfail "${label}: empty iface was accepted; a too-broad TCP/53 rule would ship"
  fi

  rc=0
  env bash -c '
    set -euo pipefail
    source "$1"
    resolver_tcp53_input_matchers winn3gw0 ""
  ' _ "${script}" >"${WORKDIR}/matchers_empty_d.out" 2>"${WORKDIR}/matchers_empty_d.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    spass "${label}: empty inner-v4 is refused (exit ${rc})"
  else
    sfail "${label}: empty inner-v4 was accepted; a too-broad TCP/53 rule would ship"
  fi

  local line stripped
  while IFS= read -r line; do
    stripped="${line#"${line%%[![:space:]]*}"}"
    if [[ "${stripped}" == \#* ]]; then
      continue
    fi
    if [[ "${line}" == *'dport 53'* ]]; then
      if [[ "${line}" == *-i* && "${line}" == *-d* ]]; then
        :
      else
        sfail "${label}: dport 53 line missing -i or -d: ${line}"
      fi
    fi
  done < "${script}"
  spass "${label}: every non-comment dport 53 line carries both -i and -d"

  if grep -E -q '^[[:space:]]+apply_winn3gw_input_firewall \|\| return 1$' "${script}"; then
    spass "${label}: apply_forwarding_firewall calls apply_winn3gw_input_firewall"
  else
    sfail "${label}: apply_winn3gw_input_firewall is never called"
  fi
  # F-GW: the chain now carries the icmp echo trio unconditionally and the
  # 53 accepts ONLY inside the RESOLVER=1 guard. F=1 R=0 must not open
  # either 53 -- check the function body's ordering, not a comment.
  awk '
    $0 == "apply_winn3gw_input_firewall() {" {p=1}
    p {print}
    p && $0 == "}" {exit}
  ' "${script}" > "${WORKDIR}/winn3gw_body.txt"
  local guard_n udp_n tcp_n icmp_n drop_n
  guard_n="$(grep -n -F 'if [[ "${WINN3_GATEWAY_RESOLVER}" == "1" ]]; then' "${WORKDIR}/winn3gw_body.txt" | cut -d: -f1 | head -1)"
  udp_n="$(grep -n -F -- '-p udp --dport 53 -j ACCEPT' "${WORKDIR}/winn3gw_body.txt" | cut -d: -f1 | head -1)"
  tcp_n="$(grep -n -F -- '-p tcp --dport 53 -j ACCEPT' "${WORKDIR}/winn3gw_body.txt" | cut -d: -f1 | head -1)"
  icmp_n="$(grep -n -F -- '-p icmp --icmp-type echo-request -j ACCEPT' "${WORKDIR}/winn3gw_body.txt" | cut -d: -f1 | head -1)"
  drop_n="$(grep -n -F -- 'WINN3GW-INPUT -j DROP' "${WORKDIR}/winn3gw_body.txt" | cut -d: -f1 | head -1)"
  if [[ -n "${guard_n}" && -n "${udp_n}" && -n "${tcp_n}" && -n "${icmp_n}" && -n "${drop_n}" \
     && "${icmp_n}" -lt "${guard_n}" \
     && "${udp_n}" -gt "${guard_n}" && "${tcp_n}" -gt "${guard_n}" \
     && "${udp_n}" -lt "${drop_n}" && "${tcp_n}" -lt "${drop_n}" ]]; then
    spass "${label}: F-GW WINN3GW-INPUT shape: icmp echo trio before the RESOLVER=1 guard; udp/53+tcp/53 inside the guard; all accepts before the trailing DROP"
  else
    sfail "${label}: WINN3GW-INPUT ordering wrong (icmp=${icmp_n:-?} guard=${guard_n:-?} udp53=${udp_n:-?} tcp53=${tcp_n:-?} drop=${drop_n:-?}); want icmp < guard < 53s < DROP"
  fi
  local calls
  calls="$(grep -E -c '^[[:space:]]+apply_winn3gw_input_firewall( \|\||$)' "${script}" || true)"
  if [[ "${calls}" -eq 1 ]]; then
    spass "${label}: apply_winn3gw_input_firewall is called exactly once"
  else
    sfail "${label}: apply_winn3gw_input_firewall call count is ${calls}, want 1"
  fi
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

  check_variant "${script}" 0 0 "${label}"
  check_variant "${script}" 1 0 "${label}"
  check_variant "${script}" 0 1 "${label}"
  check_variant "${script}" 1 1 "${label}"
  check_input_matchers "${script}" "${label}"
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

echo "=== M1: F=0 R=1 gains CAP_NET_BIND_SERVICE (must FAIL) ==="
M1="${WORKDIR}/m1_r1_bind.sh"
cat "${LIVE_COPY}" > "${M1}"
apply_once "${M1}" \
  '      desc_suffix="reflector + resolver at ${WINN3_GATEWAY_INNER_V4}:53"' \
  '      desc_suffix="reflector + resolver at ${WINN3_GATEWAY_INNER_V4}:53"
      cap_bound="CAP_NET_BIND_SERVICE"
      cap_ambient="CAP_NET_BIND_SERVICE"' \
  "M1"
run_suite "${M1}" "M1"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M1: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M1: suite stayed green after granting bind-service to F=0 R=1"
fi

echo "=== M2: F=1 R=1 forgets CAP_NET_BIND_SERVICE (must FAIL) ==="
M2="${WORKDIR}/m2_no_bind.sh"
cat "${LIVE_COPY}" > "${M2}"
apply_once "${M2}" \
  '      cap_bound="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
      cap_ambient="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"' \
  '      cap_bound="CAP_NET_ADMIN"
      cap_ambient="CAP_NET_ADMIN"' \
  "M2"
run_suite "${M2}" "M2"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M2: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M2: suite stayed green after dropping bind-service from F=1 R=1"
fi

echo "=== M3: F=1 R=1 bounding but not ambient (must FAIL) ==="
M3="${WORKDIR}/m3_no_ambient.sh"
cat "${LIVE_COPY}" > "${M3}"
apply_once "${M3}" \
  '      cap_ambient="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"' \
  '      cap_ambient="CAP_NET_ADMIN"' \
  "M3"
run_suite "${M3}" "M3"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M3: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M3: suite stayed green after omitting bind-service from AmbientCapabilities"
fi

echo "=== M4: F=1 R=0 gains CAP_NET_BIND_SERVICE (must FAIL) ==="
M4="${WORKDIR}/m4_fwd_bind.sh"
cat "${LIVE_COPY}" > "${M4}"
apply_once "${M4}" \
  '    cap_bound="CAP_NET_ADMIN"
    cap_ambient="CAP_NET_ADMIN"' \
  '    cap_bound="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"
    cap_ambient="CAP_NET_ADMIN CAP_NET_BIND_SERVICE"' \
  "M4"
run_suite "${M4}" "M4"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M4: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M4: suite stayed green after granting bind-service to F=1 R=0"
fi

echo "=== M5: matchers omit -d (must FAIL) ==="
M5="${WORKDIR}/m5_no_d.sh"
cat "${LIVE_COPY}" > "${M5}"
apply_once "${M5}" \
  "  printf -- '-i %s -d %s -p tcp --dport 53' \"\${iface}\" \"\${inner}\"" \
  "  printf -- '-i %s -p tcp --dport 53' \"\${iface}\"" \
  "M5"
run_suite "${M5}" "M5"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M5: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M5: suite stayed green after omitting -d from TCP/53 matchers"
fi

echo "=== M6: matchers omit -i (must FAIL) ==="
M6="${WORKDIR}/m6_no_i.sh"
cat "${LIVE_COPY}" > "${M6}"
apply_once "${M6}" \
  "  printf -- '-i %s -d %s -p tcp --dport 53' \"\${iface}\" \"\${inner}\"" \
  "  printf -- '-d %s -p tcp --dport 53' \"\${inner}\"" \
  "M6"
run_suite "${M6}" "M6"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M6: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M6: suite stayed green after omitting -i from TCP/53 matchers"
fi

echo
echo "SUMMARY pass=${PASS} fail=${FAIL} build_fail=${BUILD_FAIL}"
echo "WORKDIR=${WORKDIR}"

if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
