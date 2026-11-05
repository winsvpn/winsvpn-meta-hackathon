#!/usr/bin/env bash
# Prove emit_unit_text's SocketBind matrix and that SystemCallFilter stays
# off pending the unit's own three-step observation. Mutates a PRIVATE copy
# under scratch — never the shared tree. Does not call iptables, mktemp-install,
# systemctl, or write_unit.
#
# Controls:
#   no-mutation              (live script)     must PASS
#   comment-only             (private copy)    must PASS
#   M1 omit SocketBindDeny                     must FAIL
#   M2 F=1 R=1 forgets tcp:53                  must FAIL
#   M3 F=0 R=1 gains tcp:53                    must FAIL
#   M4 allow udp:51833 instead of listen port  must FAIL
#   M5 invent knockd ~@privileged filter       must FAIL
#   M6 PrivateDevices=no                       must FAIL
#   M7 F=1 omits BindPaths                     must FAIL
#
# Usage:
#   bash wins_winn3_gateway_install_socketbind_unit_test.sh
#   bash wins_winn3_gateway_install_socketbind_unit_test.sh /path/to/wins_winn3_gateway_install.sh
set -euo pipefail
# OI-K4 (Round K): the installer reads MemTotal for host fit and fails closed
# without it. These cases test other properties, so they run against a
# 128 TiB fixture on which every explicit session count fits and an unset
# count still selects 64.
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
UNIT_REF="${HERE}/../winn_protocol_experimental/deploy/systemd/winn3-gateway.service"
WORKDIR="${WINN3_SOCKETBIND_UNIT_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/sec_socketbind_and_syscallfilter/unit_test}"
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
  local listen="${5:-}"
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
      if [[ -n "${4:-}" ]]; then
        WINN3_GATEWAY_LISTEN="$4"
      fi
      emit_unit_text
    ' _ "${script}" "${forward}" "${resolver}" "${listen}" >"${out}" 2>"${out}.err" || rc=$?
  if [[ "${rc}" -ne 0 ]]; then
    sbuild "emit_unit F=${forward} R=${resolver} exited ${rc}: $(tr '\n' ' ' < "${out}.err")"
    return 1
  fi
  return 0
}

has_line() {
  local file="$1" line="$2"
  grep -F -x -q -- "${line}" "${file}"
}

check_variant() {
  local script="$1" f="$2" r="$3" label="$4"
  local unit="${WORKDIR}/unit_F${f}_R${r}.service"
  emit_unit "${script}" "${f}" "${r}" "${unit}" || return 0

  if has_line "${unit}" "SocketBindDeny=any"; then
    spass "${label} F=${f} R=${r}: SocketBindDeny=any"
  else
    sfail "${label} F=${f} R=${r}: missing SocketBindDeny=any"
  fi
  if has_line "${unit}" "SocketBindAllow=udp:9111"; then
    spass "${label} F=${f} R=${r}: SocketBindAllow=udp:9111"
  else
    sfail "${label} F=${f} R=${r}: missing SocketBindAllow=udp:9111 (port is 9111, not 51833)"
  fi
  if has_line "${unit}" "SocketBindAllow=tcp:9111"; then
    spass "${label} F=${f} R=${r}: SocketBindAllow=tcp:9111"
  else
    sfail "${label} F=${f} R=${r}: missing SocketBindAllow=tcp:9111 (cover TLS binds the public port)"
  fi
  if grep -E -q '^SocketBindAllow=udp:51833$' "${unit}"; then
    sfail "${label} F=${f} R=${r}: SocketBindAllow=udp:51833 (old default; must not ship)"
  else
    spass "${label} F=${f} R=${r}: no udp:51833"
  fi

  case "${f}${r}" in
    11)
      if has_line "${unit}" "SocketBindAllow=tcp:53"; then
        spass "${label} F=1 R=1: SocketBindAllow=tcp:53"
      else
        sfail "${label} F=1 R=1: missing SocketBindAllow=tcp:53"
      fi
      ;;
    *)
      if grep -E -q '^SocketBindAllow=tcp:53$' "${unit}"; then
        sfail "${label} F=${f} R=${r}: has SocketBindAllow=tcp:53 (only F=1 R=1 binds TCP/53)"
      else
        spass "${label} F=${f} R=${r}: no tcp:53"
      fi
      ;;
  esac

  if grep -E -q '^SocketBindAllow=udp:53$' "${unit}"; then
    sfail "${label} F=${f} R=${r}: has SocketBindAllow=udp:53 (UDP DNS is TUN-path, not a kernel bind)"
  else
    spass "${label} F=${f} R=${r}: no udp:53"
  fi

  if grep -E -q '^SystemCallFilter=' "${unit}"; then
    sfail "${label} F=${f} R=${r}: active SystemCallFilter= (must stay off until the unit's three-step observation)"
  else
    spass "${label} F=${f} R=${r}: no active SystemCallFilter"
  fi
  if grep -F -q 'SystemCallFilter=~@privileged' "${unit}"; then
    sfail "${label} F=${f} R=${r}: invented knockd SystemCallFilter=~@privileged"
  else
    spass "${label} F=${f} R=${r}: no ~@privileged filter"
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

  if [[ "${f}" == "1" ]]; then
    if grep -E -q '^BindPaths=/dev/net/tun$' "${unit}"; then
      spass "${label} F=1 R=${r}: BindPaths=/dev/net/tun"
    else
      sfail "${label} F=1 R=${r}: missing BindPaths=/dev/net/tun"
    fi
    if grep -E -q '^DeviceAllow=/dev/net/tun rw$' "${unit}"; then
      spass "${label} F=1 R=${r}: DeviceAllow=/dev/net/tun rw"
    else
      sfail "${label} F=1 R=${r}: missing DeviceAllow=/dev/net/tun rw"
    fi
  else
    if grep -E -q '^BindPaths=' "${unit}"; then
      sfail "${label} F=0 R=${r}: unexpected BindPaths"
    else
      spass "${label} F=0 R=${r}: no BindPaths"
    fi
  fi
}

check_custom_listen_port() {
  local script="$1" label="$2"
  local unit="${WORKDIR}/unit_custom_port.service"
  emit_unit "${script}" 0 0 "${unit}" "0.0.0.0:9999" || return 0
  if has_line "${unit}" "SocketBindAllow=udp:9999"; then
    spass "${label}: custom LISTEN 0.0.0.0:9999 -> SocketBindAllow=udp:9999"
  else
    sfail "${label}: custom LISTEN did not emit SocketBindAllow=udp:9999"
  fi
  if has_line "${unit}" "SocketBindAllow=tcp:9999"; then
    spass "${label}: custom LISTEN -> SocketBindAllow=tcp:9999"
  else
    sfail "${label}: custom LISTEN did not emit SocketBindAllow=tcp:9999"
  fi
  if has_line "${unit}" "SocketBindAllow=udp:9111"; then
    sfail "${label}: custom LISTEN still emitted udp:9111 (would lock the process out of its own bind)"
  else
    spass "${label}: custom LISTEN does not emit udp:9111"
  fi
}

check_static_unit_procedure() {
  local unit="$1" label="$2"
  if [[ ! -f "${unit}" ]]; then
    sfail "${label}: static unit not found at ${unit}"
    return 0
  fi
  if grep -E -q '^SystemCallFilter=' "${unit}"; then
    sfail "${label}: static unit has active SystemCallFilter= (observation window not done)"
  else
    spass "${label}: static unit has no active SystemCallFilter"
  fi
  if grep -E -q '^# SystemCallFilter=@system-service$' "${unit}"; then
    spass "${label}: commented enable line is exactly # SystemCallFilter=@system-service"
  else
    sfail "${label}: missing commented line # SystemCallFilter=@system-service"
  fi
  if grep -F -q 'systemctl edit winn3-gateway' "${unit}" \
     && grep -F -q 'systemctl restart winn3-gateway' "${unit}" \
     && grep -F -q 'journalctl -u winn3-gateway -n 50' "${unit}"; then
    spass "${label}: three-step procedure present (edit / restart / journalctl)"
  else
    sfail "${label}: unit's own three-step procedure is missing or altered"
  fi
  if grep -E -q '^SystemCallFilter=~@privileged' "${unit}"; then
    sfail "${label}: static unit invented knockd SystemCallFilter=~@privileged"
  else
    spass "${label}: static unit has no active ~@privileged filter"
  fi
  if grep -E -q '^SocketBindDeny=any$' "${unit}"; then
    spass "${label}: default-shape SocketBindDeny=any"
  else
    sfail "${label}: default-shape missing SocketBindDeny=any"
  fi
  if grep -E -q '^SocketBindAllow=udp:9111$' "${unit}"; then
    spass "${label}: default-shape SocketBindAllow=udp:9111"
  else
    sfail "${label}: default-shape missing SocketBindAllow=udp:9111"
  fi
  if grep -E -q '^SocketBindAllow=tcp:9111$' "${unit}"; then
    spass "${label}: default-shape SocketBindAllow=tcp:9111"
  else
    sfail "${label}: default-shape missing SocketBindAllow=tcp:9111"
  fi
  if grep -E -q '^SocketBindAllow=tcp:53$' "${unit}"; then
    sfail "${label}: default-shape has tcp:53 (this file is F=0 R=0 only)"
  else
    spass "${label}: default-shape has no tcp:53"
  fi
  if grep -F -q 'PrivateDevices=yes' "${unit}"; then
    spass "${label}: PrivateDevices=yes retained"
  else
    sfail "${label}: PrivateDevices=yes missing from static unit"
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
  check_custom_listen_port "${script}" "${label}"
  check_static_unit_procedure "${UNIT_REF}" "${label}"
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
echo "unit_ref=${UNIT_REF}"
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

echo "=== M1: omit SocketBindDeny=any (must FAIL) ==="
M1="${WORKDIR}/m1_no_deny.sh"
cat "${LIVE_COPY}" > "${M1}"
apply_once "${M1}" \
  '  socket_bind_lines="SocketBindDeny=any
SocketBindAllow=udp:${listen_port}
SocketBindAllow=tcp:${listen_port}
"' \
  '  socket_bind_lines="SocketBindAllow=udp:${listen_port}
SocketBindAllow=tcp:${listen_port}
"' \
  "M1"
run_suite "${M1}" "M1"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M1: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M1: suite stayed green after omitting SocketBindDeny=any"
fi

echo "=== M2: F=1 R=1 forgets tcp:53 (must FAIL) ==="
M2="${WORKDIR}/m2_no_tcp53.sh"
cat "${LIVE_COPY}" > "${M2}"
apply_once "${M2}" \
  '  if [[ "${WINN3_GATEWAY_FORWARD}" == "1" && "${WINN3_GATEWAY_RESOLVER}" == "1" ]]; then
    socket_bind_lines+="SocketBindAllow=tcp:53
"
  fi' \
  '  if false; then
    socket_bind_lines+="SocketBindAllow=tcp:53
"
  fi' \
  "M2"
run_suite "${M2}" "M2"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M2: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M2: suite stayed green after dropping tcp:53 from F=1 R=1"
fi

echo "=== M3: F=0 R=1 gains tcp:53 (must FAIL) ==="
M3="${WORKDIR}/m3_r1_tcp53.sh"
cat "${LIVE_COPY}" > "${M3}"
apply_once "${M3}" \
  '  if [[ "${WINN3_GATEWAY_FORWARD}" == "1" && "${WINN3_GATEWAY_RESOLVER}" == "1" ]]; then
    socket_bind_lines+="SocketBindAllow=tcp:53
"
  fi' \
  '  if [[ "${WINN3_GATEWAY_RESOLVER}" == "1" ]]; then
    socket_bind_lines+="SocketBindAllow=tcp:53
"
  fi' \
  "M3"
run_suite "${M3}" "M3"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M3: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M3: suite stayed green after granting tcp:53 to resolver-without-forward"
fi

echo "=== M4: SocketBindAllow=udp:51833 instead of listen port (must FAIL) ==="
M4="${WORKDIR}/m4_old_port.sh"
cat "${LIVE_COPY}" > "${M4}"
apply_once "${M4}" \
  'SocketBindAllow=udp:${listen_port}' \
  'SocketBindAllow=udp:51833' \
  "M4"
run_suite "${M4}" "M4"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M4: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M4: suite stayed green after shipping the old 51833 bind allow"
fi

echo "=== M5: invent knockd SystemCallFilter=~@privileged (must FAIL) ==="
M5="${WORKDIR}/m5_knockd_filter.sh"
cat "${LIVE_COPY}" > "${M5}"
apply_once "${M5}" \
  'SystemCallArchitectures=native' \
  'SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources' \
  "M5"
run_suite "${M5}" "M5"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M5: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M5: suite stayed green after inventing knockd's extra syscall filter"
fi

echo "=== M6: PrivateDevices=no (must FAIL) ==="
M6="${WORKDIR}/m6_privdev_no.sh"
cat "${LIVE_COPY}" > "${M6}"
apply_once "${M6}" \
  'PrivateDevices=yes
PrivateTmp=yes' \
  'PrivateDevices=no
PrivateTmp=yes' \
  "M6"
run_suite "${M6}" "M6"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M6: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M6: suite stayed green after dropping PrivateDevices=yes"
fi

echo "=== M7: F=1 omits BindPaths (must FAIL) ==="
M7="${WORKDIR}/m7_no_bindpaths.sh"
cat "${LIVE_COPY}" > "${M7}"
apply_once "${M7}" \
  "    bind_paths_line=\$'BindPaths=/dev/net/tun\\n'" \
  "    bind_paths_line=\$''" \
  "M7"
run_suite "${M7}" "M7"
if [[ "${SUITE_FAIL}" -ge 1 ]]; then
  pass "control M7: suite went red (inner fail=${SUITE_FAIL}) as required"
else
  fail "control M7: suite stayed green after omitting BindPaths on FORWARD=1"
fi

echo
echo "SUMMARY pass=${PASS} fail=${FAIL} build_fail=${BUILD_FAIL}"
echo "WORKDIR=${WORKDIR}"

if [[ "${FAIL}" -ne 0 || "${BUILD_FAIL}" -ne 0 ]]; then
  exit 1
fi
exit 0
