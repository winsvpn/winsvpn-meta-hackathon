#!/usr/bin/env bash
# Prove that wins_winn3_gateway_install.sh ships rmem_max/wmem_max for
# gateway-only nodes, calls ensure_udp_socket_buffers on --install/--start
# outside the FORWARD=1 block, and that --preflight only reports.
#
# Mutates a PRIVATE copy under scratch — never the shared tree.
#
# Controls:
#   no-mutation   (live script)     must PASS
#   comment-only  (private copy)    must PASS
#   deliberate break (private copy) must FAIL, naming what broke
#
# Usage:
#   bash test_winn3_gateway_udp_buffers.sh
#   bash test_winn3_gateway_udp_buffers.sh /path/to/a/copy/of/the/standalone/installer
set -euo pipefail

HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
# Slice S6: wins_winn3_gateway_install.sh is a tombstone. This suite proves the
# standalone installer's own UDP buffer code, so it reads the frozen copy of it
# (deleted with the tombstone; the merged data-plane sysctls are held by
# tools/test_sysctl_single_owner.py).
INSTALL="${1:-${HERE}/testdata/winn3_gateway_install_retired/wins_winn3_gateway_install.sh.snapshot}"
WORKDIR="${WINN3_UDP_BUF_WORKDIR:-${HERE}/../../../.spark_lanes/scratch/perf_udp_socket_buffers/install_test}"
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

  if grep -F -q 'ensure_udp_socket_buffers() {' "${script}"; then
    spass "${label}: ensure_udp_socket_buffers is defined"
  else
    sfail "${label}: ensure_udp_socket_buffers() is missing"
  fi
  if grep -F -q 'preflight_udp_socket_buffers() {' "${script}"; then
    spass "${label}: preflight_udp_socket_buffers is defined"
  else
    sfail "${label}: preflight_udp_socket_buffers() is missing"
  fi

  if grep -F -q 'local target=134217728' "${script}" \
     && grep -F -q 'net.core.rmem_max = ${target}' "${script}"; then
    spass "${label}: persists net.core.rmem_max via target=134217728 (data-plane match)"
  else
    sfail "${label}: rmem_max persist is missing target=134217728 or net.core.rmem_max = \${target}"
  fi
  if grep -F -q 'net.core.wmem_max = ${target}' "${script}"; then
    spass "${label}: persists net.core.wmem_max via \${target} (data-plane match)"
  else
    sfail "${label}: net.core.wmem_max = \${target} is missing from the script"
  fi

  awk '
    $0 == "main() {" {p=1}
    p {print}
    p && $0 == "}" {exit}
  ' "${script}" > "${WORKDIR}/main_body.txt"

  local calls
  calls="$(grep -E -c '^[[:space:]]+ensure_udp_socket_buffers$' "${WORKDIR}/main_body.txt" || true)"
  if [[ "${calls}" -ge 1 ]]; then
    spass "${label}: main() calls ensure_udp_socket_buffers ${calls} time(s)"
  else
    sfail "${label}: main() does not call ensure_udp_socket_buffers (a defined-but-uncalled function is a false green)"
  fi

  # The call must NOT live only inside WINN3_GATEWAY_FORWARD=1: the UDP
  # listener exists in reflector mode too.
  awk '
    $0 ~ /if \[\[ "\$\{WINN3_GATEWAY_FORWARD\}" == "1" \]\]; then/ {p=1}
    p {print}
    p && $0 ~ /^  fi$/ {exit}
  ' "${WORKDIR}/main_body.txt" > "${WORKDIR}/forward_block.txt"
  local fwd_calls
  fwd_calls="$(grep -E -c '^[[:space:]]+ensure_udp_socket_buffers$' "${WORKDIR}/forward_block.txt" || true)"
  if [[ "${fwd_calls}" -eq 0 ]]; then
    spass "${label}: ensure_udp_socket_buffers is not inside the FORWARD=1 block"
  else
    sfail "${label}: ensure_udp_socket_buffers is inside FORWARD=1; a reflector-only node would not get the sysctls"
  fi

  local pf_calls
  pf_calls="$(grep -E -c '^[[:space:]]+preflight_udp_socket_buffers$' "${WORKDIR}/main_body.txt" || true)"
  if [[ "${pf_calls}" -ge 1 ]]; then
    spass "${label}: main() calls preflight_udp_socket_buffers ${pf_calls} time(s)"
  else
    sfail "${label}: main() does not call preflight_udp_socket_buffers"
  fi

  if grep -F -q 'sysctl -w' "${script}"; then
    # Must exist in ensure_udp_socket_buffers, must NOT exist in preflight_udp_socket_buffers.
    awk '
      $0 == "preflight_udp_socket_buffers() {" {p=1}
      p {print}
      p && $0 == "}" {exit}
    ' "${script}" > "${WORKDIR}/preflight_udp_body.txt"
    if grep -E -q 'sysctl[[:space:]]+(-w|--write)|sysctl[[:space:]]+[A-Za-z0-9._]+=' "${WORKDIR}/preflight_udp_body.txt"; then
      sfail "${label}: preflight_udp_socket_buffers writes a sysctl"
    else
      spass "${label}: preflight_udp_socket_buffers does not write sysctls"
    fi
  else
    sfail "${label}: no sysctl -w anywhere; ensure_udp_socket_buffers cannot raise rmem_max"
  fi
}

score_live() {
  run_suite "${INSTALL}" "live"
  if [[ "${SUITE_BUILD}" -gt 0 ]]; then
    build_fail "live suite had ${SUITE_BUILD} build failures"
    return
  fi
  if [[ "${SUITE_FAIL}" -eq 0 ]]; then
    pass "no-mutation: ${SUITE_PASS} checks"
  else
    fail "no-mutation: ${SUITE_FAIL} failed, ${SUITE_PASS} passed"
  fi
}

score_comment_only() {
  local copy="${WORKDIR}/comment_only.sh"
  python3 - "${INSTALL}" "${copy}" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text()
needle = "ensure_udp_socket_buffers() {"
if src.count(needle) != 1:
    raise SystemExit(f"needle count {src.count(needle)}")
src = src.replace(needle, needle + "\n  # comment-only control: rmem_max=0 must not count\n", 1)
pathlib.Path(sys.argv[2]).write_text(src)
PY
  run_suite "${copy}" "comment-only"
  if [[ "${SUITE_BUILD}" -gt 0 ]]; then
    build_fail "comment-only suite had ${SUITE_BUILD} build failures"
    return
  fi
  if [[ "${SUITE_FAIL}" -eq 0 ]]; then
    pass "comment-only: ${SUITE_PASS} checks"
  else
    fail "comment-only: ${SUITE_FAIL} failed (a comment must not trip the suite)"
  fi
}

score_break_call() {
  local copy="${WORKDIR}/break_call.sh"
  python3 - "${INSTALL}" "${copy}" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text()
old = "  ensure_udp_socket_buffers\n"
if src.count(old) < 1:
    raise SystemExit("no ensure_udp_socket_buffers call to comment out")
src = src.replace(old, "  # ensure_udp_socket_buffers\n", 1)
pathlib.Path(sys.argv[2]).write_text(src)
PY
  run_suite "${copy}" "break-call"
  if [[ "${SUITE_BUILD}" -gt 0 ]]; then
    build_fail "break-call suite had ${SUITE_BUILD} build failures"
    return
  fi
  if [[ "${SUITE_FAIL}" -gt 0 ]]; then
    pass "break-call: suite went red (${SUITE_FAIL} failed) as required"
  else
    fail "break-call: commenting out the main() call still passed; the suite is a zero-clause"
  fi
}

score_break_rmem() {
  local copy="${WORKDIR}/break_rmem.sh"
  python3 - "${INSTALL}" "${copy}" <<'PY'
import pathlib, sys
src = pathlib.Path(sys.argv[1]).read_text()
old = "net.core.rmem_max = ${target}"
if old not in src:
    raise SystemExit("rmem_max persist line missing")
src = src.replace(old, "net.core.rmem_max = 262144", 1)
pathlib.Path(sys.argv[2]).write_text(src)
PY
  run_suite "${copy}" "break-rmem"
  if [[ "${SUITE_BUILD}" -gt 0 ]]; then
    build_fail "break-rmem suite had ${SUITE_BUILD} build failures"
    return
  fi
  if [[ "${SUITE_FAIL}" -gt 0 ]]; then
    pass "break-rmem: suite went red (${SUITE_FAIL} failed) as required"
  else
    fail "break-rmem: persisting rmem_default still passed; the suite is a zero-clause"
  fi
}

score_live
score_comment_only
score_break_call
score_break_rmem

printf '\nPASS=%s FAIL=%s BUILD_FAIL=%s\n' "${PASS}" "${FAIL}" "${BUILD_FAIL}"
if [[ "${FAIL}" -gt 0 || "${BUILD_FAIL}" -gt 0 ]]; then
  exit 1
fi
exit 0
