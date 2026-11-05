#!/usr/bin/env bash
# WINN3_GATEWAY_TCP_INGRESS unit tests (lane L70, 2026-09-26). Round W's
# server path (v3 over TCP on the gateway port) sits behind the binary's
# -tcp-ingress, default off. The installer's value defaults to 0, accepts only
# 0 and 1, reaches the env file, and is on the root firewall's closed name
# allowlist. Pure functions and the generated firewall script against stubbed
# stat and iptables; never invokes installer main, a gateway, or the host's
# real firewall. Same shape as the listener_df case of
# wins_winn3_gateway_install_egress_mtu_unit_test.sh.
# The WINN3_GATEWAY_* assignments are read by the sourced installer.
# shellcheck disable=SC2034
set -euo pipefail
# In the bash macOS ships as /bin/bash (3.2.57) a failing [[ ]] does not stop
# set -e, which silences every assertion below except the last of each case.
# Refuse such a bash instead of passing in it.
if "${BASH}" -c 'set -e; [[ 1 == 2 ]]; exit 0'; then
  printf 'refusing to run: in %s (%s) a failing [[ ]] does not stop set -e\n' "${BASH}" "${BASH_VERSION}" >&2
  exit 2
fi
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != --case ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
  FIXTURES="$(mktemp -d "${TMPDIR:-/tmp}/winn3-tcp-ingress.XXXXXX")"
  trap 'rm -rf "${FIXTURES}"' EXIT
  for test_case in default on invalid firewall; do
    env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
      FIXTURES="${FIXTURES}" "${BASH}" "$0" --case "${test_case}" "${INSTALL}"
    printf 'PASS %s\n' "${test_case}"
  done
  exit
fi
test_case="$2"
INSTALL="$3"
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1400
WINN3_GATEWAY_INNER_V4=192.0.2.1
WINN3_GATEWAY_PLAN=udp
WINN3_GATEWAY_MAX_SESSIONS=64
# shellcheck disable=SC1090
source "${INSTALL}"

must_fail() {
  local out
  if out="$("$@" 2>/dev/null)"; then
    printf 'expected failure: %s (printed %s)\n' "$*" "${out}" >&2
    exit 1
  fi
  [[ -z "${out}" ]]
}

# A fresh source with the variable exported, the way an operator runs it.
# shellcheck disable=SC2016  # "$1" is expanded by the child bash
probe() {
  env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
    WINN3_GATEWAY_ID=synthetic-test WINN3_GATEWAY_INNER_V4=192.0.2.1 \
    WINN3_GATEWAY_PATH_MTU=1400 WINN3_GATEWAY_PLAN=udp WINN3_GATEWAY_MAX_SESSIONS=64 \
    WINN3_GATEWAY_TCP_INGRESS="$1" \
    "${BASH}" -c 'set -euo pipefail; source "$1"; validate_tcp_ingress; emit_env_text' _ "${INSTALL}"
}

# $1 a fresh fixture directory, $2 env file text. Runs the generated root
# firewall script (the literal heredoc body) against it with stubbed stat and
# iptables, which logs to $1/iptables.log. Prints its output; returns its exit
# code.
run_firewall() {
  local fw="$1"
  mkdir -p "${fw}/bin"
  awk "/^  cat <<'EOF' # the boot helper: \/usr\/local\/sbin\/winn3-gateway-firewall\$/{f=1; next} f && /^EOF\$/{exit} f{print}" \
    "${INSTALL}" > "${fw}/firewall"
  [[ -s "${fw}/firewall" ]]
  printf '#!/bin/sh\nprintf "0:600\\n"\n' > "${fw}/bin/stat"
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s/iptables.log"\nexit 0\n' "${fw}" > "${fw}/bin/iptables"
  chmod 755 "${fw}/bin/stat" "${fw}/bin/iptables"
  # The helper holds the shared firewall lock (design v17 2.2 item 1). Under
  # env -i only the fakes, /usr/bin and /bin are on PATH, so the fake flock
  # execs this shell's python3.
  printf '#!/bin/sh\nexec %q %q "$@"\n' "$(command -v python3)" "${HERE}/testdata/winn3_gateway_fake_flock.py" > "${fw}/bin/flock"
  chmod 755 "${fw}/bin/flock"
  printf '%s\n' "$2" > "${fw}/winn3-gateway.env"
  chmod 600 "${fw}/winn3-gateway.env"
  env -i PATH="${fw}/bin:/usr/bin:/bin" LC_ALL=C WINN3_GATEWAY_ENV_FILE="${fw}/winn3-gateway.env" \
    WINS_FIREWALL_LOCK="${fw}/wins-firewall.lock" \
    "${BASH}" "${fw}/firewall" 2>&1
}

case "${test_case}" in
  default)
    # Default off: the env -i driver leaves WINN3_GATEWAY_TCP_INGRESS unset.
    [[ "${WINN3_GATEWAY_TCP_INGRESS}" == 0 ]]
    validate_tcp_ingress
    env_text="$(emit_env_text)"
    [[ "${env_text}" == *$'\nWINN3_GATEWAY_TCP_INGRESS=0\n'* ]]
    [[ "$(grep -c '^WINN3_GATEWAY_TCP_INGRESS=' <<< "${env_text}")" == 1 ]]
    # The env file is the one transport: the unit reads it and bakes no flag.
    unit="$(emit_unit_text)"
    [[ "${unit}" == *$'\nEnvironmentFile='* && "${unit}" != *'tcp-ingress'* ]]
    # Empty is unset, as for WINN3_GATEWAY_LISTENER_DF.
    [[ "$(probe '')" == *$'\nWINN3_GATEWAY_TCP_INGRESS=0\n'* ]]
    [[ "$(probe 0)" == *$'\nWINN3_GATEWAY_TCP_INGRESS=0\n'* ]]
    msg="$(validate_config 2>&1 || true)"
    [[ "${msg}" != *'WINN3_GATEWAY_TCP_INGRESS'* ]]
    ;;
  on)
    on_text="$(probe 1)"
    [[ "${on_text}" == *$'\nWINN3_GATEWAY_TCP_INGRESS=1\n'* ]]
    [[ "$(grep -c '^WINN3_GATEWAY_TCP_INGRESS=' <<< "${on_text}")" == 1 ]]
    WINN3_GATEWAY_TCP_INGRESS=1
    validate_tcp_ingress
    msg="$(validate_config 2>&1 || true)"
    [[ "${msg}" != *'WINN3_GATEWAY_TCP_INGRESS'* ]]
    [[ "$(emit_unit_text)" != *'tcp-ingress'* ]]
    # The other boolean beside it is untouched.
    [[ "${on_text}" == *$'\nWINN3_GATEWAY_LISTENER_DF=0\n'* ]]
    ;;
  invalid)
    # Only the installer's boolean values; everything else is refused, and
    # emit_env_text refuses on its own, not only through validate_config.
    for bad in true false yes no on off TRUE 2 00 01 ' 1' '1 ' $'1\nPATH=/tmp/x'; do
      must_fail probe "${bad}"
      msg="$(probe "${bad}" 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_TCP_INGRESS='*'must be 0 or 1.'* ]]
      WINN3_GATEWAY_TCP_INGRESS="${bad}"
      must_fail validate_tcp_ingress
      must_fail emit_env_text
      msg="$(validate_config 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_TCP_INGRESS='*'must be 0 or 1.'* ]]
    done
    ;;
  firewall)
    # The root firewall unit sources the env file only if every name is on its
    # closed allowlist. Without the name the firewall refuses and the gateway,
    # which Requires it, never starts.
    for value in 1 0; do
      text="$(probe "${value}")"
      fw_rc=0
      msg="$(run_firewall "${FIXTURES}/fw_${value}" "${text}")" || fw_rc=$?
      if [[ "${msg}" == *'not one of the gateway env keys'* || "${fw_rc}" != 0 ]]; then
        printf 'generated firewall refused the emitted env file with TCP_INGRESS=%s (rc %s): %s\n' \
          "${value}" "${fw_rc}" "${msg}" >&2
        exit 1
      fi
      [[ -s "${FIXTURES}/fw_${value}/iptables.log" ]]
    done
    # Control: the same run refuses a name that is not on the allowlist, so the
    # pass above is the allowlist admitting WINN3_GATEWAY_TCP_INGRESS.
    fw_rc=0
    msg="$(run_firewall "${FIXTURES}/fw_control" "$(probe 1)"$'\nWINN3_GATEWAY_TCP_INGRESX=1')" || fw_rc=$?
    [[ "${fw_rc}" != 0 && "${msg}" == *"variable 'WINN3_GATEWAY_TCP_INGRESX' is not one of the gateway env keys"* ]]
    [[ ! -e "${FIXTURES}/fw_control/iptables.log" ]]
    ;;
  *) exit 2 ;;
esac
