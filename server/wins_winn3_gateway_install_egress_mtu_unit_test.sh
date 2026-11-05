#!/usr/bin/env bash
# Round CM (2026-09-26) unit tests: the plan-aware path MTU floor and the
# egress MTU check. Pure functions against fixtures; never invokes installer
# main, a gateway, or the host's real routing (every check case points
# WINN3_GATEWAY_IP_CMD at a stub ip and WINN3_GATEWAY_SYS_CLASS_NET at a
# sysfs fixture).
# Round CM2 retro (GPT-6 Sol OI-CM2-1a/2, lane L80): the check compares the
# plan's widest IPv4 datagram with the device `ip route get` names for the
# listener's own flow (route_lookup, check, tls_on_1400, policy_routed).
# The same check against a real kernel with policy rules runs in the lane's
# Linux netns harness, not here.
# Round CM2 (OI-CM2-1a) adds listener_df: WINN3_GATEWAY_LISTENER_DF defaults
# to 0, accepts only 0 and 1, and reaches the env file and the root firewall's
# name allowlist. The generated firewall runs against stubbed stat and
# iptables only.
# The WINN3_GATEWAY_* assignments are read by the sourced installer.
# shellcheck disable=SC2034
set -euo pipefail
# In the bash macOS ships as /bin/bash (3.2.57, measured 2026-09-26) a failing
# [[ ]] does not stop set -e, which silences every assertion below except the
# last of each case. Refuse such a bash instead of passing in it, and run the
# cases in the bash that runs this driver.
if "${BASH}" -c 'set -e; [[ 1 == 2 ]]; exit 0'; then
  printf 'refusing to run: in %s (%s) a failing [[ ]] does not stop set -e\n' "${BASH}" "${BASH_VERSION}" >&2
  exit 2
fi
export WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO:-$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/testdata/winn3_gateway_meminfo/large}"
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"
if [[ "${1:-}" != --case ]]; then
  INSTALL="$(python3 -B "${HERE}/../tools/winn3_gateway_test_source.py" "${1:-${HERE}/wins_data_plane_setup_ONETOUCH.sh}" --legacy-compat)"
  FIXTURES="$(mktemp -d "${TMPDIR:-/tmp}/winn3-egress-mtu.XXXXXX")"
  trap 'rm -rf "${FIXTURES}"' EXIT
  for test_case in floors mtu_by_plan emitters route_lookup check tls_on_1400 policy_routed client_prefix rule_selectors unaccountable_routing interrupted_listing output_rewrite wiring listener_df; do
    env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
      FIXTURES="${FIXTURES}" "${BASH}" "$0" --case "${test_case}" "${INSTALL}"
    printf 'PASS %s\n' "${test_case}"
  done
  exit
fi
test_case="$2"
INSTALL="$3"
WINN3_GATEWAY_ID=synthetic-test
WINN3_GATEWAY_PATH_MTU=1450
WINN3_GATEWAY_INNER_V4=192.0.2.1
# shellcheck disable=SC1090
source "${INSTALL}"

# Netfilter readers for every case (Round CM3 Turn 7): an empty ruleset, so
# the output-rewrite check passes unless a case supplies its own.
# $1 name, $2 nft JSON, $3 iptables-save text, $4 iptables-save stderr,
# $5 legacy text ("none" for no legacy reader). Sets the three reader variables.
netfilter_stub() {
  local dir="${FIXTURES}/nf_$1"
  mkdir -p "${dir}"
  printf '%s\n' "$2" > "${dir}/nft.out"
  printf '%s\n' "$3" > "${dir}/ipt.out"
  printf '%s' "$4" > "${dir}/ipt.err"
  printf '%s\n' "$5" > "${dir}/legacy.out"
  printf '#!%s\ncat %q\n' "${BASH}" "${dir}/nft.out" > "${dir}/nft"
  printf '#!%s\ncat %q\n[[ -s %q ]] && cat %q >&2\nexit 0\n' "${BASH}" "${dir}/ipt.out" "${dir}/ipt.err" "${dir}/ipt.err" > "${dir}/iptables-save"
  printf '#!%s\ncat %q\n' "${BASH}" "${dir}/legacy.out" > "${dir}/iptables-legacy-save"
  chmod 755 "${dir}/nft" "${dir}/iptables-save" "${dir}/iptables-legacy-save"
  WINN3_GATEWAY_NFT_CMD="${dir}/nft"
  WINN3_GATEWAY_IPTABLES_SAVE_CMD="${dir}/iptables-save"
  WINN3_GATEWAY_IPTABLES_LEGACY_SAVE_CMD="${dir}/iptables-legacy-save"
  [[ "$5" != none ]] || WINN3_GATEWAY_IPTABLES_LEGACY_SAVE_CMD=none
}
NFT_EMPTY='{"nftables": [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}}]}'
IPT_EMPTY=$'*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT'
netfilter_stub empty "${NFT_EMPTY}" "${IPT_EMPTY}" "" none

# $1 name, then device=mtu pairs; writes a sysfs-shaped tree and returns it.
sysnet_fixture() {
  local name="$1" pair
  shift
  for pair in "$@"; do
    mkdir -p "${FIXTURES}/${name}/net/${pair%%=*}"
    printf '%s\n' "${pair#*=}" > "${FIXTURES}/${name}/net/${pair%%=*}/mtu"
  done
  mkdir -p "${FIXTURES}/${name}/net"
  printf '%s\n' "${FIXTURES}/${name}/net"
}

# $1 name, $2 the body of a bash case statement on "$*" (the arguments ip
# was given). Writes an ip stub that logs every call to <dir>/args.log and
# answers from that case statement; returns the stub's path. Unless $3 is
# "nodefaults", `ip -4 rule show` answers the three default rules and
# `ip -4 -o route show table all` answers nothing (arms in $2 come first). An
# arm that matches nothing fails like the kernel does for an unreachable
# destination.
ip_stub() {
  local dir="${FIXTURES}/$1" defaults=""
  mkdir -p "${dir}"
  if [[ "${3:-}" != nodefaults ]]; then
    # shellcheck disable=SC2016
    defaults='  *"rule show"*) printf "%s\n" "0:	from all lookup local" "32766:	from all lookup main" "32767:	from all lookup default" ;;
  *"route show table all"*) : ;;
  *"addr show"*) printf "%s\n" "2: eth0    inet 192.0.2.125/24 scope global eth0" "3: ens3    inet 192.0.2.126/24 scope global ens3" "4: ens4    inet 10.0.2.2/24 scope global ens4" ;;'
  fi
  {
    printf '#!%s\n' "${BASH}"
    printf 'printf "%%s\\n" "$*" >> %q\n' "${dir}/args.log"
    printf 'case "$*" in\n%s\n%s\n' "$2" "${defaults}"
    printf '  *) echo "RTNETLINK answers: Network is unreachable" >&2; exit 2 ;;\nesac\n'
  } > "${dir}/ip"
  chmod 755 "${dir}/ip"
  printf '%s\n' "${dir}/ip"
}

# Every destination via eth0, the shape of `ip route get` on us-chicago1
# (documentation addresses). Stub bodies are literal shell for the stub, so
# "$3" and "$*" stay unexpanded here.
# shellcheck disable=SC2016
CHICAGO_ANSWER='  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;'

must_fail() {
  local out
  if out="$("$@" 2>/dev/null)"; then
    printf 'expected failure: %s (printed %s)\n' "$*" "${out}" >&2
    exit 1
  fi
  [[ -z "${out}" ]]
}

CHICAGO_DEFAULT=$'eth0\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0'
CHICAGO_LINK=$'eth0\t000200C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0'

case "${test_case}" in
  floors)
    # Same numbers as the hub's winn3_plan_floor_threshold.
    [[ "$(gateway_plan_floor udp)" == 1357 ]]
    [[ "$(gateway_plan_floor tcp)" == 1399 ]]
    [[ "$(gateway_plan_floor udp,tcp)" == 1399 ]]
    [[ "$(gateway_plan_floor tls)" == 1421 ]]
    [[ "$(gateway_plan_floor udp,tls)" == 1421 ]]
    [[ "$(gateway_plan_floor tcp,tls,udp)" == 1421 ]]
    [[ "$(gateway_plan_floor '')" == 1421 ]]
    ;;
  mtu_by_plan)
    for mtu in 1357 1400 1450 1500; do
      [[ "$(canonical_gateway_path_mtu "${mtu}" udp)" == "${mtu}" ]]
    done
    for mtu in 1356 1280 1501 01400 abc ''; do
      must_fail canonical_gateway_path_mtu "${mtu}" udp
    done
    [[ "$(canonical_gateway_path_mtu 1399 udp,tcp)" == 1399 ]]
    must_fail canonical_gateway_path_mtu 1398 udp,tcp
    [[ "$(canonical_gateway_path_mtu 1421 udp,tls)" == 1421 ]]
    must_fail canonical_gateway_path_mtu 1420 udp,tls
    must_fail canonical_gateway_path_mtu 1400 udp,tcp,tls
    # No plan keeps the pre-Round CM floor.
    must_fail canonical_gateway_path_mtu 1400
    [[ "$(canonical_gateway_path_mtu 1421)" == 1421 ]]
    # The refusal names the plan's own range.
    msg="$(canonical_gateway_path_mtu 1300 udp 2>&1 || true)"
    [[ "${msg}" == *'1357..1500 for plan udp'* ]]
    ;;
  emitters)
    # us-chicago1 after OI-CM-1: udp at 1400 renders; before Round CM it was refused.
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1400
    WINN3_GATEWAY_MAX_SESSIONS=64
    unit="$(emit_unit_text)"
    env_text="$(emit_env_text)"
    [[ "${unit}" == *'  -path-mtu 1400 '* && "${unit}" == *'  -plan udp '* ]]
    # Round CM3 Turn 4: AF_NETLINK in every mode, forward off included; the
    # egress checks ask the kernel over rtnetlink and fail closed without it.
    [[ "${WINN3_GATEWAY_FORWARD}" == 0 && "${unit}" == *$'\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n'* ]]
    [[ "${env_text}" == *$'\nWINN3_GATEWAY_PATH_MTU=1400\n'* ]]
    for emitter in emit_unit_text emit_env_text; do
      WINN3_GATEWAY_PLAN=udp,tls
      must_fail "${emitter}"
      WINN3_GATEWAY_PLAN=udp,tcp
      "${emitter}" >/dev/null 2>&1
      WINN3_GATEWAY_PATH_MTU=1398
      must_fail "${emitter}"
      WINN3_GATEWAY_PLAN=udp
      WINN3_GATEWAY_PATH_MTU=1356
      must_fail "${emitter}"
      WINN3_GATEWAY_PATH_MTU=1400
    done
    ;;
  route_lookup)
    net="$(sysnet_fixture lookup eth0=1400 ens3=1500 ens4=1500)"
    stub="$(ip_stub lookup "${CHICAGO_ANSWER}")"
    out="$(gateway_egress_routes "${stub}" "${net}" 0.0.0.0:9111 no-such-user-l80)"
    [[ "$(printf '%s\n' "${out}" | wc -l | tr -d ' ')" == "${#WINN3_GATEWAY_EGRESS_PROBES[@]}" ]]
    [[ "${out}" == $'ok 1.1.1.1 eth0 1400 1400 0 0\nok 8.8.8.8 eth0 1400 1400 0 0\nok 9.9.9.9 eth0 1400 1400 0 0\nok 208.67.222.222 eth0 1400 1400 0 0' ]]
    # The flow asked about: a wildcard listener sends no source, and without
    # the service user no uid; UDP and the port always.
    [[ "$(head -1 "${FIXTURES}/lookup/args.log")" == '-4 route get 1.1.1.1 ipproto udp sport 9111' ]]
    # A named listener address is the lookup's source; an existing user's uid
    # is carried (the kernel then matches uidrange rules for it).
    : > "${FIXTURES}/lookup/args.log"
    gateway_egress_routes "${stub}" "${net}" 203.0.113.7:9112 "$(id -un)" >/dev/null
    [[ "$(head -1 "${FIXTURES}/lookup/args.log")" == "-4 route get 1.1.1.1 from 203.0.113.7 ipproto udp sport 9112 uid $(id -u)" ]]
    # A route's own mtu metric lowers the device's; "mtu lock" too; one above
    # the device does not raise it.
    stub="$(ip_stub metric '  *" 1.1.1.1 "*) echo "1.1.1.1 via 10.0.0.1 dev ens3 table 100 src 10.0.0.2 uid 0"; echo "    cache mtu 1380" ;;
  *" 8.8.8.8 "*) echo "8.8.8.8 via 10.0.0.1 dev ens3 src 10.0.0.2 uid 0 \    cache mtu lock 1300" ;;
  *" 9.9.9.9 "*) echo "9.9.9.9 via 10.0.0.1 dev ens3 src 10.0.0.2 uid 0 \    cache mtu 9000" ;;
  *" 208.67.222.222 "*) echo "208.67.222.222 via 10.0.0.1 dev ens4 src 10.0.0.2 uid 0 \    cache expires 598sec mtu 1300" ;;')"
    out="$(gateway_egress_routes "${stub}" "${net}" 0.0.0.0:9111 no-such-user-l80)"
    [[ "${out}" == $'ok 1.1.1.1 ens3 1380 1500 1380 0\nok 8.8.8.8 ens3 1300 1500 1300 0\nok 9.9.9.9 ens3 1500 1500 9000 0\nok 208.67.222.222 ens4 1500 1500 0 1300' ]]
    # Failures are per destination: unreachable, no dev, a device without an
    # mtu file, a hostile device name.
    stub="$(ip_stub fails '  *" 1.1.1.1 "*) echo "1.1.1.1 via 10.0.0.1 src 10.0.0.2" ;;
  *" 8.8.8.8 "*) echo "8.8.8.8 via 10.0.0.1 dev eth9 src 10.0.0.2" ;;
  *" 9.9.9.9 "*) echo "9.9.9.9 dev ../../x src 10.0.0.2" ;;')"
    out="$(gateway_egress_routes "${stub}" "${net}" 0.0.0.0:9111 no-such-user-l80)"
    [[ "${out}" == *'fail 1.1.1.1 no output device in: 1.1.1.1 via 10.0.0.1 src 10.0.0.2'* ]]
    [[ "${out}" == *"fail 8.8.8.8 cannot read an MTU for eth9"* ]]
    [[ "${out}" == *'fail 9.9.9.9 no output device in:'* ]]
    [[ "${out}" == *'fail 208.67.222.222 RTNETLINK answers: Network is unreachable'* ]]
    [[ "${out}" != *'ok '* ]]
    ;;
  check)
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture check eth0=1400)"
    WINN3_GATEWAY_IP_CMD="$(ip_stub check "${CHICAGO_ANSWER}")"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    # us-chicago1 before OI-CM-1: refused, naming the device, both numbers and the hub.
    WINN3_GATEWAY_PATH_MTU=1450
    msg=''
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Plan udp at WINN3_GATEWAY_PATH_MTU=1450 emits 1430-byte IPv4 datagrams'* ]]
    [[ "${msg}" == *'eth0 (MTU 1400) at the widest'* && "${msg}" == *'1.1.1.1 via eth0 mtu 1400'* ]]
    # A udp plan's datagram is PATH_MTU - 20, so 1420 is the widest that fits 1400.
    [[ "${msg}" == *'1357..1420'* && "${msg}" == *'nodes.path_mtu'* ]]
    # After OI-CM-1: accepted, and the log names the hub value.
    WINN3_GATEWAY_PATH_MTU=1400
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok: plan udp at WINN3_GATEWAY_PATH_MTU 1400 emits at most 1380-byte IPv4 datagrams <= eth0 mtu 1400'* ]]
    [[ "${msg}" == *"nodes.path_mtu for this node must be 1400"* ]]
    # The boundary: a 1400-byte datagram fits, 1401 does not.
    WINN3_GATEWAY_PATH_MTU=1420
    check_gateway_egress_mtu >/dev/null 2>&1
    WINN3_GATEWAY_PATH_MTU=1421
    if check_gateway_egress_mtu >/dev/null 2>&1; then exit 1; fi
    WINN3_GATEWAY_PATH_MTU=1357
    check_gateway_egress_mtu >/dev/null 2>&1
    # udp,tcp: message PATH_MTU - 90, so 1450 is a 1388-byte datagram.
    WINN3_GATEWAY_PLAN=udp,tcp
    WINN3_GATEWAY_PATH_MTU=1450
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'emits at most 1388-byte IPv4 datagrams'* ]]
    # The plan floor stays its own check.
    WINN3_GATEWAY_PLAN=udp,tls
    WINN3_GATEWAY_PATH_MTU=1420
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'WINN3_GATEWAY_PATH_MTU=1420 is below the floor 1421 of plan udp,tls'* ]]
    # A device narrower than the floor's datagram (1337 for every plan) has no legal path MTU.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture narrow eth0=1336)"
    WINN3_GATEWAY_PATH_MTU=1421
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'No WINN3_GATEWAY_PATH_MTU plan udp,tls accepts fits: at its floor 1421 the datagram is'*'1337 bytes'* ]]
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture narrow2 eth0=1337)"
    check_gateway_egress_mtu >/dev/null 2>&1
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture check2 eth0=1400)"
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1400
    # Fails closed on missing input on a host with a route lookup.
    WINN3_GATEWAY_IP_CMD="$(ip_stub none '')"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'fails closed: the kernel routed none of 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222'* ]]
    WINN3_GATEWAY_IP_CMD="${FIXTURES}/absent/ip"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'is not on PATH'* ]]
    WINN3_GATEWAY_IP_CMD="$(ip_stub check3 "${CHICAGO_ANSWER}")"
    WINN3_GATEWAY_SYS_CLASS_NET="${FIXTURES}/absent/net"
    if check_gateway_egress_mtu >/dev/null 2>&1; then exit 1; fi
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture check3 eth0=1400)"
    WINN3_GATEWAY_PATH_MTU=abc
    if check_gateway_egress_mtu >/dev/null 2>&1; then exit 1; fi
    WINN3_GATEWAY_PATH_MTU=1400
    WINN3_GATEWAY_LISTEN='0.0.0.0'
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'WINN3_GATEWAY_LISTEN is not <ipv4>:<port>'* ]]
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    check_gateway_egress_mtu >/dev/null 2>&1
    # With no stub a non-Linux host skips with a warning. On Linux the
    # unstubbed path asks the real kernel, which this unit test never does.
    if [[ "$(uname -s)" != Linux ]]; then
      WINN3_GATEWAY_IP_CMD=''
      WINN3_GATEWAY_PATH_MTU=1450
      msg="$(check_gateway_egress_mtu 2>&1)"
      [[ "${msg}" == *'Egress MTU not checked'* ]]
    fi
    ;;
  tls_on_1400)
    # Sol's OI-CM2-2 case: a TLS-inclusive plan at 1450 has message
    # 1450 - 112 = 1338, so its widest IPv4 UDP datagram is 1366 bytes, which
    # fits a 1400-byte device. Round CM2's installer refused it twice (1450 >
    # 1400 and device 1400 < floor 1421).
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture tls eth0=1400)"
    WINN3_GATEWAY_IP_CMD="$(ip_stub tls "${CHICAGO_ANSWER}")"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    for WINN3_GATEWAY_PLAN in udp,tls udp,tcp,tls tls; do
      WINN3_GATEWAY_PATH_MTU=1450
      msg="$(check_gateway_egress_mtu 2>&1)"
      [[ "${msg}" == *"Egress MTU ok: plan ${WINN3_GATEWAY_PLAN} at WINN3_GATEWAY_PATH_MTU 1450 emits at most 1366-byte IPv4 datagrams <= eth0 mtu 1400"* ]]
      # Its boundary on 1400: 1484 (datagram 1400) fits, 1485 does not.
      WINN3_GATEWAY_PATH_MTU=1484
      check_gateway_egress_mtu >/dev/null 2>&1
      WINN3_GATEWAY_PATH_MTU=1485
      if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
      [[ "${msg}" == *'emits 1401-byte IPv4 datagrams'* && "${msg}" == *'1421..1484'* ]]
    done
    # The same plan and path MTU through the emitters (floor 1421 holds).
    WINN3_GATEWAY_PLAN=udp,tls
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_MAX_SESSIONS=64
    [[ "$(emit_env_text)" == *$'\nWINN3_GATEWAY_PATH_MTU=1450\n'* ]]
    ;;
  policy_routed)
    # Sol's OI-CM2-1a shape: the main table's default is eth0 (1400) and a
    # policy rule sends UDP from port 9111 through ens4 (1500). The stub
    # answers the way the kernel does for that rule set (the Linux netns
    # harness runs the same check against a real kernel).
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture policy eth0=1400 ens4=1500)"
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub policy '  *" sport 9111"*) printf "%s via 10.0.2.1 dev ens4 table 100 src 10.0.2.2 uid 0 \n    cache \n" "$3" ;;
  *" route get "*) printf "%s via 10.0.1.1 dev eth0 src 10.0.1.2 uid 0 \n    cache \n" "$3" ;;')"
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok: plan udp at WINN3_GATEWAY_PATH_MTU 1450 emits at most 1430-byte IPv4 datagrams <= ens4 mtu 1500'* ]]
    # Control: a listener the rule does not match leaves through eth0 and is refused.
    WINN3_GATEWAY_LISTEN=0.0.0.0:9112
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'eth0 (MTU 1400) at the widest'* ]]
    # The reverse arrangement: main 1500, the listener's UDP through 1400.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture reverse eth0=1500 ens4=1400)"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'ens4 (MTU 1400) at the widest'* ]]
    # Destinations that disagree: warned, not refused.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture split eth0=1400 ens4=1500)"
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub split '  *" 1.1.1.1 "*) echo "1.1.1.1 via 10.0.1.1 dev eth0 src 10.0.1.2 uid 0" ;;
  *" route get "*) printf "%s via 10.0.2.1 dev ens4 src 10.0.2.2 uid 0\n" "$3" ;;')"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU AMBIGUOUS'* && "${msg}" == *'through eth0 (MTU 1400) will be fragmented'* ]]
    [[ "${msg}" != *'Egress MTU ok'* ]]
    # Some destinations unroutable, the rest wide enough: ok with a warning.
    WINN3_GATEWAY_IP_CMD="$(ip_stub partial '  *" 1.1.1.1 "*) echo "1.1.1.1 via 10.0.2.1 dev ens4 src 10.0.2.2 uid 0" ;;')"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress lookup failed for some destinations: 8.8.8.8 RTNETLINK'* && "${msg}" == *'Egress MTU ok'* ]]
    # A cached path MTU to one destination is not the egress.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub pmtu '  *" route get "*) printf "%s via 10.0.2.1 dev ens4 src 10.0.2.2 uid 0 \n    cache expires 598sec mtu 1300 \n" "$3" ;;')"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok'* && "${msg}" == *'[cached path mtu 1300 to this destination, not compared]'* ]]
    ;;
  client_prefix)
    # Round CM3, GPT-6 Sol OI-CM3-1, exactly: a 1500-byte default and a
    # 1400-byte route to a client prefix outside the four probes. The probe
    # check passes (fail safe: the gateway refuses each such client at
    # runtime); the install names the narrow prefix so the operator sees it.
    [[ "$(ipv4_prefix_is_nonglobal 10.1.2.0/24 && echo y || echo n)" == y ]]
    [[ "$(ipv4_prefix_is_nonglobal 0.0.0.0/0 && echo y || echo n)" == n ]]
    [[ "$(ipv4_prefix_is_nonglobal 45.0.0.0/16 && echo y || echo n)" == n ]]
    [[ "$(ipv4_prefix_is_nonglobal 100.64.0.0/10 && echo y || echo n)" == y ]]
    [[ "$(ipv4_prefix_is_nonglobal 100.0.0.0/8 && echo y || echo n)" == n ]]
    [[ "$(ipv4_prefix_is_nonglobal 224.0.0.0/4 && echo y || echo n)" == y ]]
    [[ "$(ipv4_prefix_is_nonglobal 172.32.0.0/16 && echo y || echo n)" == n ]]
    [[ "$(ipv4_prefix_is_nonglobal 192.0.2.0/24 && echo y || echo n)" == y ]]
    [[ "$(ipv4_prefix_is_nonglobal 8.8.8.8/32 && echo y || echo n)" == n ]]
    [[ "$(ipv4_prefix_is_nonglobal bogus && echo y || echo n)" == n ]]
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture prefix eth0=1500 ts1=1400 awg0=1280 lo=65536)"
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub prefix '  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;
  *"route show table all"*) printf "%s\n" "default via 192.0.2.1 dev eth0 proto static" \
    "45.0.0.0/16 via 10.0.1.1 dev ts1" \
    "10.8.0.0/24 dev awg0 proto kernel scope link src 10.8.0.1" \
    "192.0.2.0/24 dev eth0 proto kernel scope link src 192.0.2.125" \
    "46.0.0.0/16 via 192.0.2.1 dev eth0 table 100 mtu lock 1400" \
    "unreachable 47.0.0.0/16 table 100" \
    "local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1" ;;')"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU NARROW FOR SOME CLIENTS'* && "${msg}" == *'1430-byte datagrams of plan udp'* ]]
    [[ "${msg}" == *'45.0.0.0/16 ts1 1400 main'* && "${msg}" == *'46.0.0.0/16 eth0 1400 100'* ]]
    [[ "${msg}" == *'egress_mtu_refused'* && "${msg}" == *'Egress MTU ok: plan udp at WINN3_GATEWAY_PATH_MTU 1450'* ]]
    [[ "${msg}" != *'10.8.0.0'* && "${msg}" != *'192.0.2.0/24'* && "${msg}" != *'47.0.0.0'* && "${msg}" != *'127.0.0.1 lo'* ]]
    # At 1420 the datagram is 1400 and fits both narrow routes: no warning.
    WINN3_GATEWAY_PATH_MTU=1420
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" != *'NARROW FOR SOME CLIENTS'* && "${msg}" == *'Egress MTU ok'* ]]
    # A route table that cannot be listed is said so, and (Round CM3 Turn 4)
    # the check fails closed on it, as the gateway does.
    WINN3_GATEWAY_IP_CMD="$(ip_stub prefix2 "${CHICAGO_ANSWER}" nodefaults)"
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture prefix2 eth0=1400)"
    WINN3_GATEWAY_PATH_MTU=1400
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Route table not listed'* && "${msg}" == *'Policy rules or routes could not be listed'* ]]
    ;;
  rule_selectors)
    # Round CM3 Turn 2, GPT-6 Sol: a `dport 40000` rule. The probes cannot
    # carry a client port; the install lists every rule that selects replies
    # by port, protocol or uid, and only those (fwmark: unaccountable_routing).
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture rules eth0=1500 ts1=1400)"
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub rules '  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;
  *"route show table all"*) echo "default via 192.0.2.1 dev eth0 proto static" ;;
  *"rule show"*) printf "%s\n" "0:	from all lookup local" \
    "100:	from all ipproto udp dport 40000 lookup 100" \
    "101:	from all sport 9111 lookup 100" \
    "102:	from all uidrange 994-994 lookup 100" \
    "104:	from all ipproto tcp lookup 100" \
    "106:	from all dport 40001 lookup 100" \
    "105:	from 10.8.0.0/24 lookup 100" \
    "32766:	from all lookup main" "32767:	from all lookup default" ;;')"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Policy rules select some replies by port, protocol or uid'* && "${msg}" == *'Egress MTU ok'* ]]
    for want in 'dport 40000' 'dport 40001' 'sport 9111' 'uidrange 994-994' 'ipproto tcp'; do
      [[ "${msg}" == *"${want} lookup 100"* ]]
    done
    [[ "${msg}" != *'10.8.0.0/24 lookup'* && "${msg}" != *'lookup main'* && "${msg}" != *'lookup local'* ]]
    # Only the default rules: no warning.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub rules2 '  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;
  *"route show table all"*) echo "default via 192.0.2.1 dev eth0 proto static" ;;
  *"rule show"*) printf "%s\n" "0:	from all lookup local" "32766:	from all lookup main" "32767:	from all lookup default" ;;')"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" != *'Policy rules'* && "${msg}" == *'Egress MTU ok'* ]]
    # Rules that cannot be listed: the check fails closed.
    WINN3_GATEWAY_IP_CMD="$(ip_stub rules3 "${CHICAGO_ANSWER}" nodefaults)"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Policy rules or routes could not be listed'* ]]
    ;;
  unaccountable_routing)
    # Round CM3 Turn 4, GPT-6 Sol: a netfilter OUTPUT mark (or TOS) plus a
    # rule or route selecting on it moves replies where no check looks. The
    # install refuses exactly what the gateway refuses to start with.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture unacc eth0=1500)"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    # shellcheck disable=SC2016
    get='  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;'
    n=0
    for rule in "100:	from all fwmark 0x1 lookup 100" "101:	not from all fwmark 0x2/0xff lookup 100" \
      "102:	from all tos 0x10 lookup 100" "103:	from all dsfield 0x10 lookup 100"; do
      n=$((n + 1))
      # shellcheck disable=SC2016
      WINN3_GATEWAY_IP_CMD="$(ip_stub "unacc${n}" "${get}
  *\"rule show\"*) printf \"%s\\n\" \"0:	from all lookup local\" \"${rule}\" \"32766:	from all lookup main\" ;;")"
      if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
      [[ "${msg}" == *'Policy routing selects on the packet mark or TOS'* && "${msg}" == *"rule: ${rule}"* ]]
      [[ "${msg}" != *'Egress MTU ok'* ]]
    done
    # A route keyed on tos.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub unacc_route "${get}
  *\"route show table all\"*) echo \"45.0.0.0/16 tos 0x10 dev eth0 scope link\" ;;")"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'route: 45.0.0.0/16 tos 0x10 dev eth0 scope link'* ]]
    # Selectors the per-client lookup carries are not refused.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub acc "${get}
  *\"rule show\"*) printf \"%s\\n\" \"100:	from all iif lo lookup 100\" \"101:	from all oif eth0 lookup 100\" \"102:	from all ipproto udp dport 40000 lookup 100\" ;;")"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok'* && "${msg}" != *'selects on the packet mark or TOS'* ]]
    # Round CM3 Turn 6: dscp, tun_id and l3mdev rules, as the gateway's allowlist.
    for rule in "104:	from all dscp 10 lookup 100" "105:	from all tun_id 5 lookup 100" \
      "1000:	from all lookup [l3mdev-table]"; do
      n=$((n + 1))
      # shellcheck disable=SC2016
      WINN3_GATEWAY_IP_CMD="$(ip_stub "unacc${n}" "${get}
  *\"rule show\"*) printf \"%s\\n\" \"0:	from all lookup local\" \"${rule}\" \"32766:	from all lookup main\" ;;")"
      if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
      [[ "${msg}" == *'Policy routing selects on the packet mark or TOS'* && "${msg}" == *"rule: ${rule}"* ]]
    done
    ;;
  interrupted_listing)
    # Round CM3 Turn 6, GPT-6 Sol: iproute2 prints "Dump was interrupted and
    # may be inconsistent." on stderr and exits 0. A listing counts only with
    # an empty stderr; it is taken three times, then the check fails closed.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture intr eth0=1500)"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    # shellcheck disable=SC2016
    get='  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;'
    for what in "rule show" "route show table all"; do
      for warning in "Dump was interrupted and may be inconsistent." "Message truncated"; do
        # shellcheck disable=SC2016
        WINN3_GATEWAY_IP_CMD="$(ip_stub intr "${get}
  *\"${what}\"*) printf \"%s\\n\" \"0:	from all lookup local\" \"32766:	from all lookup main\"; echo \"${warning}\" >&2 ;;")"
        : > "${FIXTURES}/intr/args.log"
        if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
        [[ "${msg}" == *'Policy rules or routes could not be listed'* && "${msg}" == *"${warning}"* && "${msg}" == *'(3 attempts)'* ]]
        [[ "${msg}" != *'Egress MTU ok'* ]]
        (( $(grep -c -F -- "${what}" "${FIXTURES}/intr/args.log") >= 3 ))
      done
    done
    # Interrupted once, then complete: the complete listing is used.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub intr_once "${get}
  *\"rule show\"*) n=\$(cat ${FIXTURES}/intr_once/n 2>/dev/null || echo 0); echo \$((n + 1)) > ${FIXTURES}/intr_once/n
    printf \"%s\\n\" \"0:	from all lookup local\" \"32766:	from all lookup main\"
    [[ \$n -gt 0 ]] || echo \"Dump was interrupted and may be inconsistent.\" >&2 ;;")"
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok'* && "${msg}" != *'could not be listed'* ]]
    # A rule set that differs between two reads (a change during the dump,
    # which the kernel does not always flag) is never complete.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub intr_moving "${get}
  *\"rule show\"*) n=\$(cat ${FIXTURES}/intr_moving/n 2>/dev/null || echo 0); echo \$((n + 1)) > ${FIXTURES}/intr_moving/n
    printf \"%s\\n\" \"0:	from all lookup local\" \"\$((1000 + n)):	from 10.200.0.1 lookup 100\" \"32766:	from all lookup main\" ;;")"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Policy rules or routes could not be listed'* && "${msg}" == *'the listing changed between two reads'* ]]
    # A failing listing with a clean stderr (exit status only) also refuses.
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub intr_rc "${get}
  *\"rule show\"*) exit 1 ;;")"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Policy rules or routes could not be listed (exit 1: '* ]]
    ;;
  output_rewrite)
    # Round CM3 Turn 7, GPT-6 Sol: an OUTPUT rewrite re-routes the reply and a
    # POSTROUTING rewrite restores the address a connected client expects.
    # The check refuses any rule that could rewrite the replies and is not
    # provably excluded; the fleet's rules (read-only, 2026-09-27) pass.
    WINN3_GATEWAY_SYS_CLASS_NET="$(sysnet_fixture rw eth0=1500)"
    WINN3_GATEWAY_LISTEN=0.0.0.0:9111
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1450
    # shellcheck disable=SC2016
    get='  *" route get "*) printf "%s via 192.0.2.1 dev eth0 src 192.0.2.125 uid 994 \n    cache \n" "$3" ;;'
    # shellcheck disable=SC2016
    WINN3_GATEWAY_IP_CMD="$(ip_stub rw "${get}
  *\"route show table all\"*) printf \"%s\\n\" \"default via 192.0.2.1 dev eth0 proto static\" \"10.10.0.0/24 dev winn3gw0 proto kernel scope link src 10.10.0.1\" \"172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1\" ;;
  *\"addr show\"*) printf \"%s\\n\" \"2: eth0    inet 192.0.2.125/24 scope global eth0\" \"3: winn3gw0    inet 10.10.0.1/24 scope global winn3gw0\" ;;")"
    fleet=$'*nat\n:OUTPUT ACCEPT [1:2]\n:POSTROUTING ACCEPT [3:4]\n:DOCKER - [0:0]\n:WINN3GW-NAT-POSTROUTING - [0:0]\n-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER\n-A POSTROUTING -j WINN3GW-NAT-POSTROUTING\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE\n-A WINN3GW-NAT-POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE\nCOMMIT'
    legacy_warning="# Warning: iptables-legacy tables present, use iptables-legacy-save to see them"
    netfilter_stub fleet "${NFT_EMPTY}" "${fleet}" "${legacy_warning}" $'*nat\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT'
    msg="$(check_gateway_egress_mtu 2>&1)"
    [[ "${msg}" == *'Egress MTU ok'* && "${msg}" != *'Netfilter rules'* ]]
    # One refusal per rewrite type: nat OUTPUT DNAT, nat POSTROUTING
    # MASQUERADE of the gateway's own source, a legacy DNAT, an nft route
    # chain rewriting the source, an nft postrouting restore.
    netfilter_stub dnat "${NFT_EMPTY}" "${fleet/COMMIT/-A OUTPUT -p udp -m udp --sport 9111 -j DNAT --to-destination 198.51.100.5
COMMIT}" "" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Netfilter rules could rewrite the gateway'* && "${msg}" == *'--sport 9111 -j DNAT'* ]]
    netfilter_stub masq "${NFT_EMPTY}" "${fleet/COMMIT/-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT}" "" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'-A POSTROUTING -o eth0 -j MASQUERADE'* ]]
    netfilter_stub legacy "${NFT_EMPTY}" "${fleet}" "${legacy_warning}" $'*nat\n:OUTPUT ACCEPT [0:0]\n-A OUTPUT -p udp -j DNAT --to-destination 198.51.100.5\nCOMMIT'
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'iptables-legacy nat OUTPUT'* ]]
    route_rewrite='{"nftables": [{"metainfo": {"version": "1.0.9"}}, {"table": {"family": "inet", "name": "l80"}}, {"chain": {"family": "inet", "table": "l80", "name": "out", "type": "route", "hook": "output", "prio": -150, "policy": "accept"}}, {"rule": {"family": "inet", "table": "l80", "chain": "out", "handle": 3, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "sport"}}, "right": 9111}}, {"mangle": {"key": {"payload": {"protocol": "ip", "field": "saddr"}}, "value": "192.0.2.126"}}]}}]}'
    netfilter_stub nftroute "${route_rewrite}" "${fleet}" "" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'nft inet l80 out (route hook output): rule handle 3 (mangle)'* ]]
    netfilter_stub nftpost "${route_rewrite//\"output\"/\"postrouting\"}" "${fleet}" "" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'(route hook postrouting): rule handle 3 (mangle)'* ]]
    # Readers that do not give a complete answer fail closed.
    netfilter_stub incompatible "${NFT_EMPTY}" "${fleet}"$'\n'"# Table \`nat' is incompatible, use 'nft' tool." "" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'Netfilter rules could not be read or analysed'* && "${msg}" == *incompatible* ]]
    netfilter_stub othererr "${NFT_EMPTY}" "${fleet}" "iptables: something else" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'could not be read or analysed'*'something else'* ]]
    # The legacy notice without a legacy reader is not accepted either.
    netfilter_stub nolegacy "${NFT_EMPTY}" "${fleet}" "${legacy_warning}" none
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'could not be read or analysed'*'iptables-legacy tables present'* ]]
    netfilter_stub nfterr "${NFT_EMPTY}" "${fleet}" "" none
    printf '#!%s\necho "Error: cache initialization failed" >&2\nexit 1\n' "${BASH}" > "${FIXTURES}/nf_nfterr/nft"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'could not be read or analysed'*'cache initialization failed'* ]]
    # nft that exits 0 but warns on stderr.
    netfilter_stub nftwarn "${NFT_EMPTY}" "${fleet}" "" none
    printf '#!%s\ncat %q\necho "Warning: table ip nat was created by a newer version of nftables" >&2\n' "${BASH}" "${FIXTURES}/nf_nftwarn/nft.out" > "${FIXTURES}/nf_nftwarn/nft"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'could not be read or analysed'*'newer version of nftables'* ]]
    # A ruleset that changes between the two reads.
    netfilter_stub moving "${NFT_EMPTY}" "${fleet}" "" none
    printf '#!%s\nn=$(cat %q 2>/dev/null || echo 0); echo $((n + 1)) > %q\nif (( n %% 2 )); then cat %q; else cat %q; fi\n' "${BASH}" \
      "${FIXTURES}/nf_moving/n" "${FIXTURES}/nf_moving/n" "${FIXTURES}/nf_dnat/ipt.out" "${FIXTURES}/nf_moving/ipt.out" > "${FIXTURES}/nf_moving/iptables-save"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'changed between two reads'* ]]
    # A missing reader.
    netfilter_stub gone "${NFT_EMPTY}" "${fleet}" "" none
    WINN3_GATEWAY_NFT_CMD="${FIXTURES}/nf_gone/no-such-nft"
    if msg="$(check_gateway_egress_mtu 2>&1)"; then exit 1; fi
    [[ "${msg}" == *'is not installed'* ]]
    netfilter_stub empty "${NFT_EMPTY}" "${IPT_EMPTY}" "" none
    ;;
  wiring)
    # main runs the check in --preflight (feeding the missing summary) and
    # dies on it before the first binary, env or unit write in --install/--start.
    body="$(awk '/^main\(\) \{/{f=1} f{print} f && /^}/{exit}' "${INSTALL}")"
    [[ "${body}" == *'check_gateway_egress_mtu || egress_ok=1'* ]]
    # shellcheck disable=SC2016  # a literal line of installer source
    [[ "${body}" == *'[[ "${egress_ok}" -eq 0 ]] || missing+=("egress MTU'* ]]
    after_config="${body#*Refusing to install with an incomplete configuration.}"
    before_verify="${after_config%%verify_staged_binary*}"
    # shellcheck disable=SC1003  # the backslash is the installer's line continuation
    [[ "${before_verify}" == *'check_gateway_egress_mtu \'* ]]
    [[ "${before_verify}" == *'|| winn3gw_die "Refusing to install: WINN3_GATEWAY_PATH_MTU does not fit the egress device'* ]]
    ;;
  listener_df)
    # Default off: the env -i driver leaves WINN3_GATEWAY_LISTENER_DF unset.
    [[ "${WINN3_GATEWAY_LISTENER_DF}" == 0 ]]
    validate_listener_df
    WINN3_GATEWAY_PLAN=udp
    WINN3_GATEWAY_PATH_MTU=1400
    WINN3_GATEWAY_MAX_SESSIONS=64
    env_text="$(emit_env_text)"
    [[ "${env_text}" == *$'\nWINN3_GATEWAY_LISTENER_DF=0\n'* ]]
    # The env file is the one transport: the unit reads it and bakes no flag.
    unit="$(emit_unit_text)"
    [[ "${unit}" == *$'\nEnvironmentFile='* && "${unit}" != *'listener-df'* ]]
    # A fresh source with the variable exported, the way an operator runs it.
    # shellcheck disable=SC2016  # "$1" is expanded by the child bash
    probe() {
      env -i PATH=/usr/bin:/bin LC_ALL=C WINN3_GATEWAY_MEMINFO="${WINN3_GATEWAY_MEMINFO}" \
        WINN3_GATEWAY_ID=synthetic-test WINN3_GATEWAY_INNER_V4=192.0.2.1 \
        WINN3_GATEWAY_PATH_MTU=1400 WINN3_GATEWAY_PLAN=udp WINN3_GATEWAY_MAX_SESSIONS=64 \
        WINN3_GATEWAY_LISTENER_DF="$1" \
        "${BASH}" -c 'set -euo pipefail; source "$1"; validate_listener_df; emit_env_text' _ "${INSTALL}"
    }
    on_text="$(probe 1)"
    [[ "${on_text}" == *$'\nWINN3_GATEWAY_LISTENER_DF=1\n'* ]]
    [[ "$(probe 0)" == *$'\nWINN3_GATEWAY_LISTENER_DF=0\n'* ]]
    # Empty is unset, as for WINN3_GATEWAY_FORWARD and _RESOLVER.
    [[ "$(probe '')" == *$'\nWINN3_GATEWAY_LISTENER_DF=0\n'* ]]
    # Only the installer's boolean values; everything else is refused, and
    # emit_env_text refuses on its own, not only through validate_config.
    for bad in true false yes no on TRUE 2 00 01 ' 1' '1 ' $'1\nPATH=/tmp/x'; do
      must_fail probe "${bad}"
      msg="$(probe "${bad}" 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_LISTENER_DF='*'must be 0 or 1.'* ]]
      WINN3_GATEWAY_LISTENER_DF="${bad}"
      must_fail emit_env_text
      msg="$(validate_config 2>&1 || true)"
      [[ "${msg}" == *'WINN3_GATEWAY_LISTENER_DF='*'must be 0 or 1.'* ]]
    done
    for good in 0 1; do
      WINN3_GATEWAY_LISTENER_DF="${good}"
      msg="$(validate_config 2>&1 || true)"
      [[ "${msg}" != *'WINN3_GATEWAY_LISTENER_DF'* ]]
    done
    WINN3_GATEWAY_LISTENER_DF=0
    # The root firewall unit sources the env file only if every name is on its
    # closed allowlist. Run the generated script (the literal heredoc body)
    # against the env file emit_env_text wrote with DF on.
    fw="${FIXTURES}/listener_df_fw"
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
    printf '%s\n' "${on_text}" > "${fw}/winn3-gateway.env"
    chmod 600 "${fw}/winn3-gateway.env"
    fw_rc=0
    msg="$(env -i PATH="${fw}/bin:/usr/bin:/bin" LC_ALL=C WINN3_GATEWAY_ENV_FILE="${fw}/winn3-gateway.env" \
      WINS_FIREWALL_LOCK="${fw}/wins-firewall.lock" \
      "${BASH}" "${fw}/firewall" 2>&1)" || fw_rc=$?
    if [[ "${msg}" == *'not one of the gateway env keys'* || "${fw_rc}" != 0 ]]; then
      printf 'generated firewall refused the emitted env file (rc %s): %s\n' "${fw_rc}" "${msg}" >&2
      exit 1
    fi
    [[ -s "${fw}/iptables.log" ]]
    ;;
  *) exit 2 ;;
esac
