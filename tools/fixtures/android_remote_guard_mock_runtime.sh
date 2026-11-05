#!/usr/bin/env bash
# Isolated, non-root mocked runtime for android_remote_route_guard.sh. This is
# test evidence only; production root execution cannot enter the guard's test
# seam.

set -Eeuo pipefail

mock_root() { printf '%s/mock' "${WINSVPN_ANDROID_GUARD_TEST_ROOT:?}"; }
mock_log() {
  local item
  {
    printf '%s' "$(basename "$0")"
    for item in "$@"; do printf ' <%s>' "${item}"; done
    printf '\n'
  } >>"$(mock_root)/argv.log"
}

mock_iptables_restore() {
  mock_log "$@"
  [[ ! -e $(mock_root)/fail-iptables-restore ]] || exit 73
  command dd of="$(mock_root)/rules.txt" status=none
}

mock_iptables() {
  mock_log "$@"
  local rules chain line comment index=0
  rules=$(mock_root)/rules.txt
  if [[ ${3:-} == -S ]]; then
    if [[ -f ${rules} ]]; then
      command grep -E -- "^-A |^:WARG" "${rules}" || true
    fi
    return
  fi
  if [[ ${3:-} == -L ]]; then
    chain=${4:-}
    [[ ! -e $(mock_root)/fail-observe || ${chain} == PREROUTING || ${chain} == INPUT ]] || exit 74
    if [[ ${chain} == PREROUTING ]]; then
      if [[ -f ${rules} ]] && command grep -q -- '-A PREROUTING .*WARGM_' "${rules}"; then
        printf '1 0 0 WARGM_test all -- * * 0.0.0.0/0 0.0.0.0/0\n'
      fi
      return
    fi
    if [[ ${chain} == INPUT ]]; then
      if [[ -f ${rules} ]] && command grep -q -- '-A INPUT .*WARGF_' "${rules}"; then
        printf '1 0 0 WARGF_test all -- * * 0.0.0.0/0 0.0.0.0/0\n'
      fi
      return
    fi
    printf 'Chain %s (1 references)\nnum pkts bytes target prot opt in out source destination\n' "${chain}"
    [[ -f ${rules} ]] || return
    while IFS= read -r line; do
      [[ ${line} == "-A ${chain} "* ]] || continue
      ((index += 1))
      comment=${line#*--comment \"}
      comment=${comment%%\"*}
      if [[ ${line} == *' -j DROP' ]]; then
        printf '%d 5 500 DROP all -- * * 0.0.0.0/0 0.0.0.0/0 /* %s */\n' "${index}" "${comment}"
      elif [[ ${line} == *'--comment '* ]]; then
        printf '%d 7 700 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0 /* %s */\n' "${index}" "${comment}"
      else
        printf '%d 0 0 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0\n' "${index}"
      fi
    done <"${rules}"
    return
  fi
  if [[ ${3:-} == -X && ${4:-} == WARG* ]]; then
    : >"${rules}"
  fi
}

mock_conntrack() { mock_log "$@"; return 0; }

mock_systemd_run() {
  mock_log "$@"
  [[ ! -e $(mock_root)/fail-systemd-run ]] || exit 75
  : >"$(mock_root)/timer.unit"
}

mock_systemctl() {
  mock_log "$@"
  case ${1:-} in
    list-units|list-unit-files)
      if [[ -e $(mock_root)/orphan.unit || -e $(mock_root)/timer.unit ]]; then
        printf 'winsvpn-android-route-guard-deadbeefcafe.timer loaded active waiting mock\n'
      fi
      ;;
    stop)
      rm -f -- "$(mock_root)/timer.unit"
      ;;
  esac
}

dispatch_mock() {
  case $(basename "$0") in
    iptables-restore) mock_iptables_restore "$@" ;;
    iptables) mock_iptables "$@" ;;
    conntrack) mock_conntrack "$@" ;;
    systemd-run) mock_systemd_run "$@" ;;
    systemctl) mock_systemctl "$@" ;;
    *) printf 'unknown mock command\n' >&2; exit 76 ;;
  esac
}

if [[ $(basename "$0") != android_remote_guard_mock_runtime.sh ]]; then
  dispatch_mock "$@"
  exit
fi

case_name=${1:-}
readonly operation_id=0123456789abcdef0123456789abcdef
fixture_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
guard_source=$(cd -- "${fixture_dir}/.." && pwd)/android_remote_route_guard.sh
root=$(mktemp -d "/tmp/winsvpn-route-guard-test-${case_name}.XXXXXX")
trap 'chmod -R u+rwX "${root}" 2>/dev/null || true; rm -rf -- "${root}"' EXIT
chmod 0700 "${root}"
mkdir -p "${root}/usr/local/sbin" "${root}/run" "${root}/fakebin"
chmod 0755 "${root}/usr" "${root}/usr/local" "${root}/usr/local/sbin" "${root}/run" "${root}/fakebin"
mkdir -m 0700 "${root}/mock"
cp -- "${guard_source}" "${root}/usr/local/sbin/winsvpn-android-route-guard"
chmod 0755 "${root}/usr/local/sbin/winsvpn-android-route-guard"
for command_name in iptables iptables-restore conntrack systemd-run systemctl; do
  ln -s -- "${fixture_dir}/android_remote_guard_mock_runtime.sh" "${root}/fakebin/${command_name}"
done
: >"${root}/mock/argv.log"
: >"${root}/mock/rules.txt"

export WINSVPN_ANDROID_GUARD_TEST_MODE=1
export WINSVPN_ANDROID_GUARD_TEST_ROOT=${root}
guard=${root}/usr/local/sbin/winsvpn-android-route-guard
state_root=${root}/run/winsvpn-android-route-guard

payload() {
  printf '%s' '{"schema_version":1,"contract":"winsvpn-android-route-control-apply-v1","source_ipv4":"8.8.8.8","watchdog_seconds":180,"observations":[{"id":"selected","protocol":"tcp","port":80}],"blocks":[{"protocol":"udp","port":9110}]}'
}

assert_clean() {
  [[ ! -s ${root}/mock/rules.txt ]]
  [[ ! -e ${root}/mock/timer.unit ]]
  [[ ! -d ${state_root} || -z $(find "${state_root}" -maxdepth 1 -type f ! -name guard.lock -print -quit) ]]
}

case ${case_name} in
  oversize)
    if command python3 -c 'import sys;sys.stdout.write("x"*32769)' | "${guard}" apply "${operation_id}" >/dev/null 2>&1; then
      exit 10
    fi
    assert_clean
    ;;
  invalid-payload)
    if printf '{invalid' | "${guard}" apply "${operation_id}" >/dev/null 2>&1; then
      exit 11
    fi
    assert_clean
    ;;
  unsafe-symlink)
    ln -s -- "${root}/mock" "${state_root}"
    if "${guard}" snapshot >/dev/null 2>&1; then exit 12; fi
    ;;
  unsafe-owner)
    sudo -n chown root:root "${guard}"
    if "${guard}" snapshot >/dev/null 2>&1; then exit 13; fi
    ;;
  orphan-rule)
    printf '%s\n' '-A WARGM_deadbeefcafe -m comment --comment "winsvpn-android-release-guard:orphan" -j RETURN' >"${root}/mock/rules.txt"
    if "${guard}" snapshot >/dev/null 2>&1; then exit 14; fi
    ;;
  orphan-unit)
    : >"${root}/mock/orphan.unit"
    if "${guard}" snapshot >/dev/null 2>&1; then exit 15; fi
    ;;
  systemd-run-rollback)
    : >"${root}/mock/fail-systemd-run"
    if payload | "${guard}" apply "${operation_id}" >/dev/null 2>&1; then exit 16; fi
    assert_clean
    ;;
  observe-failure-rollback)
    payload | "${guard}" apply "${operation_id}" >/dev/null
    : >"${root}/mock/fail-observe"
    if "${guard}" observe "${operation_id}" >/dev/null 2>&1; then exit 17; fi
    assert_clean
    ;;
  no-observe-argv-leak)
    payload | "${guard}" apply "${operation_id}" >/dev/null
    "${guard}" observe "${operation_id}" >/dev/null
    if command grep -F -- '8.8.8.8' "${root}/mock/argv.log"; then exit 18; fi
    if command grep -E -- '\*mangle|winsvpn-android-release-guard:.*:(observe|block)' "${root}/mock/argv.log"; then exit 19; fi
    command grep -F -- 'iptables <-t> <mangle> <-L> <WARGM_0123456789ab>' "${root}/mock/argv.log" >/dev/null
    command grep -F -- 'systemd-run <--collect>' "${root}/mock/argv.log" >/dev/null
    "${guard}" restore "${operation_id}" >/dev/null
    assert_clean
    ;;
  *)
    printf 'unknown case: %s\n' "${case_name}" >&2
    exit 20
    ;;
esac
