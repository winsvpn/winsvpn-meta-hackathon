#!/usr/bin/env bash
# Pure explicit-teardown lifecycle simulation. No installer entrypoint or host commands.
set -euo pipefail
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}")"
# Compile the actual function definitions into this test shell only: the two
# teardown functions, the locked body, and the installer's shared firewall
# lock pair (the boot helper heredoc carries its own wins_fw_lock; skipped).
definitions="$(awk '
  index($0, "# the boot helper: /usr/local/sbin/winn3-gateway-firewall") { helper=1; next }
  helper { if ($0 == "EOF") helper=0; next }
  /^teardown_winn3gw_input_firewall\(\) \{$/ || /^teardown_forwarding_firewall(_locked)?\(\) \{$/ \
    || /^wins_fw_(un)?lock\(\) \{$/ { copy=1; count++ }
  copy { print }
  copy && /^\}$/ { copy=0 }
  END { if (count != 5) exit 1 }
' "${INSTALL}")"
eval "${definitions}"
unset definitions
declare -F teardown_winn3gw_input_firewall >/dev/null
declare -F teardown_forwarding_firewall >/dev/null
declare -F teardown_forwarding_firewall_locked >/dev/null
# teardown_forwarding_firewall holds the shared firewall lock (design v17 2.2
# item 1). This simulation runs no host command, so it uses the documented
# convention of a caller that already holds the lock. The interactions suite
# runs the real lock.
export WINS_FIREWALL_LOCK_HELD=1
winn3gw_log() { :; }
winn3gw_warn() { :; }
winn3gw_err() { :; }
WINN3_GATEWAY_FORWARD_IF=testtun
WINN3_GATEWAY_INNER_V4=192.0.2.1
WINN3_GATEWAY_AWG_CIDR=198.51.100.0/24
# No command fallback is permitted: the only route call is an inert response.
ip() {
  [[ "$*" == '-o route show default' ]] || return 99
  printf '%s\n' 'default via 192.0.2.2 dev testwan'
}
ipt_gw() {
  case "$*" in
    '-t mangle -D FORWARD -j WINN3GW-MANGLE-FORWARD')
      [[ "${block_delete}" == 0 ]] || return 2
      if (( jumps > 0 )); then jumps=$((jumps - 1)); deletes=$((deletes + 1)); return 0; fi
      return 1 ;;
    '-t mangle -L WINN3GW-MANGLE-FORWARD -n')
      [[ "${block_list}" == 0 ]] || return 2
      (( chain == 1 )) ;;
    '-t mangle -S')
      [[ "${block_snapshot}" == 0 ]] || return 2
      printf '%s\n' '-P PREROUTING ACCEPT' '-P INPUT ACCEPT' '-P FORWARD ACCEPT' '-P OUTPUT ACCEPT' '-P POSTROUTING ACCEPT'
      if (( chain == 1 )); then printf '%s\n' '-N WINN3GW-MANGLE-FORWARD'; fi
      if (( jumps > 0 )); then printf '%s\n' '-A FORWARD -j WINN3GW-MANGLE-FORWARD'; fi
      return 0 ;;
    '-t mangle -C FORWARD -j WINN3GW-MANGLE-FORWARD') (( jumps > 0 )) ;;
    '-t mangle -F WINN3GW-MANGLE-FORWARD')
      [[ "${block_flush}" == 0 ]] || return 2
      flushed=1 ;;
    '-t mangle -X WINN3GW-MANGLE-FORWARD')
      (( flushed == 1 && jumps == 0 && references == 0 )) || return 2
      chain=0 ;;
    '-S INPUT')
      [[ "${block_input_snapshot}" == 0 ]] || return 2
      if (( input_present )); then printf '%s\n' '-A INPUT -i testtun -j DROP'; fi
      return 0 ;;
    '-D INPUT -i testtun -j DROP'|\
    '-D INPUT -i testtun -d 192.0.2.1 -j WINN3GW-INPUT'|\
    '-D INPUT -i testtun -d 192.0.2.1 -p tcp --dport 53 -j WINN3GW-INPUT'|\
    '-D FORWARD -i testtun -j WINN3GW-FORWARD'|\
    '-D FORWARD -o testtun -j WINN3GW-FORWARD'|\
    '-t nat -D POSTROUTING -j WINN3GW-NAT-POSTROUTING'|\
    '-L WINN3GW-INPUT -n'|'-L WINN3GW-FORWARD -n'|\
    '-t nat -L WINN3GW-NAT-POSTROUTING -n') return 1 ;;
    '-L WINVPN-FORWARD -n'|\
    '-t nat -C WINVPN-NAT-POSTROUTING -s 198.51.100.0/24 -o testwan -j MASQUERADE') return 0 ;;
    *) unexpected=$((unexpected + 1)); printf 'unlisted firewall command: %s\n' "$*" >&2; return 99 ;;
  esac
}
# OI-5: the IPv6 drops for the tunnel interface. The filter table is readable,
# every delete finds nothing and every check finds nothing, so the teardown's
# v6_left stays 0; anything else is an unlisted command.
ipt6_gw() {
  case "$*" in
    '-S INPUT') return 0 ;;
    '-D INPUT -i testtun -j DROP'|'-D FORWARD -i testtun -j DROP'|'-D FORWARD -o testtun -j DROP'|\
    '-C INPUT -i testtun -j DROP'|'-C FORWARD -i testtun -j DROP'|'-C FORWARD -o testtun -j DROP') return 1 ;;
    *) unexpected=$((unexpected + 1)); printf 'unlisted ip6tables command: %s\n' "$*" >&2; return 99 ;;
  esac
}
fail() { printf "FAIL: %s\n" "${scenario}" >&2; exit 1; }
for scenario in absent duplicates rejected_delete rejected_flush residual_reference list_unavailable inspection_unavailable snapshot_unavailable_absent input_remains input_inspection_unavailable; do
  chain=1; jumps=2; deletes=0; flushed=0; references=0
  block_delete=0; block_flush=0; block_list=0; block_snapshot=0; unexpected=0
  input_present=0; block_input_snapshot=0
  case "${scenario}" in
    absent) chain=0; jumps=0 ;;
    rejected_delete) block_delete=1 ;;
    rejected_flush) block_flush=1 ;;
    residual_reference) references=1 ;;
    list_unavailable) block_list=1 ;;
    inspection_unavailable) block_delete=1; block_list=1; block_snapshot=1 ;;
    snapshot_unavailable_absent) chain=0; jumps=0; block_snapshot=1 ;;
    input_remains) input_present=1 ;;
    input_inspection_unavailable) block_input_snapshot=1 ;;
  esac
  rc=0
  teardown_forwarding_firewall || rc=$?
  [[ "${unexpected}" == 0 ]] || fail
  case "${scenario}" in
    absent) [[ "${rc}" == 0 && "${chain}" == 0 && "${deletes}" == 0 ]] || fail ;;
    duplicates)
      [[ "${rc}" == 0 && "${chain}" == 0 && "${jumps}" == 0 && "${deletes}" == 2 && "${flushed}" == 1 ]] || fail
      teardown_forwarding_firewall || fail
      [[ "${deletes}" == 2 && "${unexpected}" == 0 ]] || fail ;;
    rejected_delete) [[ "${rc}" == 1 && "${chain}" == 1 && "${jumps}" == 2 ]] || fail ;;
    rejected_flush) [[ "${rc}" == 1 && "${chain}" == 1 && "${flushed}" == 0 ]] || fail ;;
    residual_reference) [[ "${rc}" == 1 && "${chain}" == 1 && "${references}" == 1 ]] || fail ;;
    list_unavailable) [[ "${rc}" == 1 && "${chain}" == 1 ]] || fail ;;
    inspection_unavailable) [[ "${rc}" == 1 && "${chain}" == 1 && "${jumps}" == 2 ]] || fail ;;
    snapshot_unavailable_absent) [[ "${rc}" == 1 && "${chain}" == 0 ]] || fail ;;
    input_remains|input_inspection_unavailable)
      [[ "${rc}" == 1 && "${chain}" == 0 && "${jumps}" == 0 && "${deletes}" == 2 && "${flushed}" == 1 ]] || fail ;;
  esac
  printf 'PASS: %s\n' "${scenario}"
done
