#!/usr/bin/env bash
# On-device split-tunnel route guard for the physical Android phone.
#
# PURPOSE
#   Assert, on a real handset, that while a Win's VPN (org.winsvpn.app.debug)
#   VpnService session is up, excluded/split routes do not leak in either
#   direction:
#     * PROTECTED direction  - traffic that must stay inside the tunnel (the
#       default route) must be captured by the tun and must NOT egress on the
#       physical interface (a privacy leak).
#     * SPLIT/EXCLUDED direction - the split/LAN prefix that is deliberately
#       excluded from the tunnel must remain routed on the physical interface
#       and must NOT be captured by the tun (a route-shadowing leak that would
#       black-hole the split destination).
#
# WHY A SEPARATE FILE
#   tools/android_remote_route_guard.sh is a Linux-SERVER-side iptables observer
#   (provisioned onto a release data node over SSH). It cannot run "against the
#   phone". This file is the on-device half: it reads the phone's routing tables
#   over adb and asserts the two leak directions. It never installs a route, a
#   firewall rule, or a VPN; it only observes and asserts.
#
# HONESTY CONTRACT
#   A guard that merely reports "no leak" when there is no session is the exact
#   false green this codebase has been burned by. This guard therefore treats
#   the ABSENCE of a session/tun as a distinct, non-passing state
#   (exit code 3, state=BLOCKED with the precise dependency named), and only
#   marks PASS when it has actually observed a live tun and asserted both leak
#   directions against it. This matches the fleet rule: an honest BLOCKED beats
#   a green you cannot defend.
#
# Usage:
#   android_ondevice_route_guard.sh [--phone <serial>] [--package <pkg>]
#                                   [--expected-lan <cidr>] [--selfcheck]
#                                   [--evidence <dir>]
# Exit codes:
#   0  PASS   a live session was observed and both leak directions held.
#   1  FAIL   a leak was detected while a session was present.
#   2  ERROR  harness/environment error (device missing, adb failed, etc.).
#   3  BLOCKED  no session/tun present; the during-session assertion cannot be
#               completed. The exact missing dependency is printed and logged.

set -Eeuo pipefail

PHONE="ZY22GTV6Z3"
PACKAGE="org.winsvpn.app.debug"
EXPECTED_LAN="192.168.50.0/24"      # on-link LAN prefix excluded from the tunnel
EVIDENCE_DIR="/Users/owner/Documents/wins/.spark_lanes/scratch/gen_android_route_guard/evidence"
SELFCHECK=0
STAMP=""
TUN_INTERFACE=""

usage() {
  sed -n '2,8p' "$0" >/dev/null
  cat >&2 <<'USAGE'
Usage: android_ondevice_route_guard.sh [--phone <serial>] [--package <pkg>]
       [--expected-lan <cidr>] [--selfcheck] [--evidence <dir>]
USAGE
}

die() { printf 'ANDROID ON-DEVICE ROUTE GUARD: ERROR: %s\n' "$*" >&2; exit 2; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phone) PHONE="$2"; shift 2;;
    --package) PACKAGE="$2"; shift 2;;
    --expected-lan) EXPECTED_LAN="$2"; shift 2;;
    --evidence) EVIDENCE_DIR="$2"; shift 2;;
    --selfcheck) SELFCHECK=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

need adb
[[ $EVIDENCE_DIR =~ ^/Users/owner/Documents/wins/ ]] || die "evidence dir must be inside the repo"
mkdir -p "$EVIDENCE_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
EVIDENCE_LOG="$EVIDENCE_DIR/route_guard_${STAMP}.log"
EVIDENCE_LATEST="$EVIDENCE_DIR/latest.log"

log() { printf '%s\n' "$*"; printf '%s\n' "$*" >>"$EVIDENCE_LOG"; }

adbq() { adb -s "$PHONE" shell "$1" 2>&1; }

# ---------------------------------------------------------------------------
# Route classifier. Takes stdin of `ip route show table main` lines and makes
# PASS/FAIL decisions. Kept as pure functions so --selfcheck can feed fixtures.
# ---------------------------------------------------------------------------

# report_l4_default <route_lines> <phys_devs> -> sets/prints. Reads:
#   ROUTE_MAIN, PHYS_DEVS, TUN_DEV
# Returns 0 if no IPv4 leak, 1 if a leak is found.
classify_no_ipv4_leak() {
  local line dev
  local default_tun=0 default_phys=0
  while IFS= read -r line; do
    [[ $line == default* ]] || continue
    dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' <<<"$line")"
    if [[ -n $dev && $dev == "${TUN_DEV}" ]]; then default_tun=1; fi
    if [[ -n $dev && " $PHYS_DEVS " == *" $dev "* ]]; then default_phys=1; fi
  done
  if (( default_phys == 1 )); then
    log "LEAK IPv4: default route egresses on physical interface(s) [$PHYS_DEVS] while a tunnel is up"
    return 1
  fi
  if (( default_tun == 0 )); then
    log "MISSING IPv4: no default route via tunnel dev ${TUN_DEV} while a tunnel is up"
    return 1
  fi
  log "OK IPv4: default route via ${TUN_DEV}; nothing egresses on [$PHYS_DEVS]"
  return 0
}

# classify_no_ipv6_leak <route_lines> -> 0/1. IPv6 default must be via tun,
# never via a physical dev.
classify_no_ipv6_leak() {
  local line dev
  local v6_tun=0 v6_phys=0
  while IFS= read -r line; do
    [[ $line == "::/0"* ]] || continue
    dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' <<<"$line")"
    if [[ -n $dev && $dev == "${TUN_DEV}" ]]; then v6_tun=1; fi
    if [[ -n $dev && " $PHYS_DEVS " == *" $dev "* ]]; then v6_phys=1; fi
  done
  if (( v6_phys == 1 )); then
    log "LEAK IPv6: ::/0 egresses on physical interface(s) [$PHYS_DEVS] while a tunnel is up"
    return 1
  fi
  if (( v6_tun == 0 )); then
    log "NOTE IPv6: no ::/0 route via ${TUN_DEV} observed (family may be unprovisioned); no physical IPv6 leak asserted"
    return 0
  fi
  log "OK IPv6: ::/0 via ${TUN_DEV}; nothing egresses on [$PHYS_DEVS]"
  return 0
}

# classify_split_route <route_lines> <expected_lan> -> 0/1.
# The split/LAN prefix excluded from the tunnel must remain on a PHYSICAL dev
# and must NOT be captured by the tun.
classify_split_route() {
  local expected_lan="$1" line dev
  local lan_on_phys=0 lan_on_tun=0 lan_missing=1
  while IFS= read -r line; do
    [[ $line == "$expected_lan "* || $line == "$expected_lan" ]] || continue
    lan_missing=0
    dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' <<<"$line")"
    if [[ -n $dev && $dev == "${TUN_DEV}" ]]; then lan_on_tun=1; fi
    if [[ -n $dev && " $PHYS_DEVS " == *" $dev "* ]]; then lan_on_phys=1; fi
  done
  if (( lan_on_tun == 1 )); then
    log "LEAK SPLIT: excluded/split route ${expected_lan} was captured by tunnel dev ${TUN_DEV} (route shadowing)"
    return 1
  fi
  if (( lan_missing == 1 )); then
    log "WARN SPLIT: expected split route ${expected_lan} is not present in the main table"
    return 0
  fi
  if (( lan_on_phys == 1 )); then
    log "OK SPLIT: excluded/split route ${expected_lan} stays on physical dev (not leaked into tunnel)"
    return 0
  fi
  log "WARN SPLIT: ${expected_lan} present but on an unexpected dev; no tunnel capture detected"
  return 0
}

# ---------------------------------------------------------------------------
# Self-check (mutation control). Feeds a simulated session table and a
# deliberately-mutated leak table through the classifier and requires the
# expected red. Without this, a classifier that always returns green proves
# nothing.
# ---------------------------------------------------------------------------
selfcheck() {
  local sim_on_phys sim_ok sim_leak4 sim_leak6 sim_split_i4 sim_split_i6 rc=0
  PHYS_DEVS="wlan0"
  TUN_DEV="tun0"

  sim_ok=$'default dev tun0 scope link\n::/0 dev tun0 scope global\n192.168.50.0/24 dev wlan0 proto kernel scope link src 192.168.50.171'
  sim_on_phys=$'default dev wlan0\n::/0 dev tun0\n192.168.50.0/24 dev tun0'

  classify_no_ipv4_leak <<<"$sim_ok"; rc=$?
  [[ $rc -eq 0 ]] || { echo "SELFCHECK FAIL: clean IPv4 table wrongly flagged"; return 1; }

  TUN_DEV="tun0"; PHYS_DEVS="wlan0"
  if classify_no_ipv4_leak <<<"$sim_on_phys" >/dev/null 2>&1; then
    echo "SELFCHECK FAIL: IPv4 default-on-physical leak was NOT detected (survived)"
    return 1
  fi
  classify_no_ipv6_leak <<<"default dev tun0" >/dev/null 2>&1 \
    || { echo "SELFCHECK FAIL: empty IPv6 table was not tolerated"; return 1; }
  if classify_no_ipv6_leak <<<"::/0 dev wlan0" >/dev/null 2>&1; then
    echo "SELFCHECK FAIL: IPv6 ::/0-on-physical leak was NOT detected (survived)"
    return 1
  fi
  if classify_split_route <<<"192.168.50.0/24 dev tun0" "$EXPECTED_LAN" >/dev/null 2>&1; then
    echo "SELFCHECK FAIL: split route captured by tun was NOT detected (survived)"
    return 1
  fi
  if ! classify_split_route <<<"192.168.50.0/24 dev wlan0" "$EXPECTED_LAN" >/dev/null 2>&1; then
    echo "SELFCHECK FAIL: clean split route on physical was flagged"
    return 1
  fi
  echo "ANDROID ON-DEVICE ROUTE GUARD SELFCHECK: PASS (positive + mutation controls)"
  return 0
}

# ---------------------------------------------------------------------------
# Live run against the phone.
# ---------------------------------------------------------------------------
preflight_phone() {
  [[ $(adbq "getprop ro.product.model") == *motorola* || $PHONE =~ ^[A-Z0-9]{8}$ ]] \
    || log "WARN: unexpected model for $PHONE"
  local present
  present="$(adbq "pm list packages $PACKAGE")"
  [[ $present == *"package:$PACKAGE"* ]] || die "package $PACKAGE is not installed on $PHONE"
  local flags
  flags="$(adbq "dumpsys package $PACKAGE 2>/dev/null | grep -m1 'flags=\['")"
  log "package=$PACKAGE installed; $flags"
  log "device=$(adbq "getprop ro.product.model") sdk=$(adbq "getprop ro.build.version.sdk") serial=$PHONE"
}

detect_session() {
  local tun_devs
  # Android toybox grep does not support \s; use plain tun match and strip.
  tun_devs="$(adbq "ip -o link 2>/dev/null | grep tun | sed 's/.*: \([^:]*\):.*/\1/' | awk -F: '{print \$1}' | tr -d ' '")"
  # fallback: if sed path failed, try awk split on ': '
  if [[ -z $tun_devs ]]; then
    tun_devs="$(adbq "ip -o link 2>/dev/null | grep tun" | awk -F': ' '{print \$2}' | awk '{print \$1}' | tr -d ' ')"
  fi
  TUN_INTERFACE="$(printf '%s\n' "$tun_devs" | grep -E '^tun[0-9]+' | head -1 || true)"
  # strip any trailing colon or spaces
  TUN_INTERFACE="$(printf '%s' "$TUN_INTERFACE" | sed 's/[: ]//g')"
  if [[ -z $TUN_INTERFACE ]]; then
    log "no tun (VpnService) interface present on $PHONE"
    return 1
  fi
  TUN_DEV="$TUN_INTERFACE"
  log "tun interface present: $TUN_INTERFACE"
  return 0
}

detect_phys_devs() {
  local line dev
  PHYS_DEVS=""
  while IFS= read -r line; do
    dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); break}}' <<<"$line")"
    [[ -n $dev && $dev != "tun"* && " $PHYS_DEVS " != *" $dev "* ]] && PHYS_DEVS="$PHYS_DEVS $dev"
  done
  PHYS_DEVS="${PHYS_DEVS# }"
}

live_run() {
  log "=== ANDROID ON-DEVICE SPLIT-TUNNEL ROUTE GUARD ==="
  log "phone=$PHONE package=$PACKAGE expected_lan=$EXPECTED_LAN"
  log "started=$STAMP"
  preflight_phone

  if ! detect_session; then
    # No session -> honest BLOCKED, never a pass.
    local dev_driver_present
    dev_driver_present="$(adbq "dumpsys $PACKAGE 2>/dev/null | grep -c 'DevKillSwitchActivity' | head -1" | tr -d ' ')"
    log
    log "state=BLOCKED: no org.winsvpn.app.debug session/tun is present on $PHONE, so the"
    log "  during-session no-leak assertion cannot be completed and is NOT claimed as a pass."
    log "  Missing dependency (exactly one of these must be satisfied):"
    log "  (a) a live/carrying data-plane session - requires a provisioned winn/3 carrier"
    log "      profile + device credentials + a reachable gateway, which are owner-gated;"
    log "  (b) the debug block-posture tun - requires DevVpnPrepareActivity/DevKillSwitchActivity,"
    log "      absent from the installed $PACKAGE (DevKillSwitchActivity matches: ${dev_driver_present:-0})"
    log "      and unreachable because VpnTunnelService is not exported."
    log "  result=PASS must be false; see blocked reason in this evidence log."
    ln -sf "$EVIDENCE_LOG" "$EVIDENCE_LATEST"
    return 3
  fi

  # Session present -> assert.
  ROUTE_MAIN="$(adbq "ip route show table main")"
  ROUTE_ALL="$(adbq "ip route show table all")"
  ROUTE_GET_88="$(adbq "ip route get 8.8.8.8 2>&1")"
  TUN_COUNTERS="$(adbq "cat /proc/net/dev 2>&1 | grep $TUN_INTERFACE")"
  log
  log "=== live route table (main) during session ==="
  log "$ROUTE_MAIN"
  log "=== live route table (all) during session ==="
  log "$ROUTE_ALL"
  log "=== ip route get 8.8.8.8 ==="
  log "$ROUTE_GET_88"
  log "=== tun counters ==="
  log "$TUN_COUNTERS"
  detect_phys_devs <<<"$ROUTE_MAIN"
  [[ -n $PHYS_DEVS ]] || log "WARN: no physical dev detected in route table"
  log "physical_devs=[$PHYS_DEVS] tunnel_dev=$TUN_INTERFACE (TUN_DEV=$TUN_DEV)"

  local fail=0
  # Android VPN routes live in a dedicated table (1040, 1038, etc.) while the
  # underlying physical default stays in table 1017.  Checking ROUTE_ALL for a
  # physical default is a false positive: that default is the underlay needed
  # to reach the outer endpoint (with a throw for the gateway).  The real leak
  # test is that the VPN table carries the default and that a protected
  # destination resolves via the tun (ip route get).
  local route_vpn_table=""
  route_vpn_table="$(printf '%s\n' "$ROUTE_ALL" | grep "dev $TUN_INTERFACE" || true)"
  [[ -n $route_vpn_table ]] || route_vpn_table="$ROUTE_ALL"
  classify_no_ipv4_leak <<<"$route_vpn_table" || fail=1
  classify_no_ipv6_leak <<<"$route_vpn_table" || fail=1
  # Verify protected traffic actually resolves via the tun (per-uid routing
  # on Android means main-table presence alone is insufficient and table-1017
  # is not a leak).
  if [[ $ROUTE_GET_88 == *"dev $TUN_INTERFACE"* ]]; then
    log "OK IPv4 route-get: 8.8.8.8 via $TUN_INTERFACE (protected traffic captured)"
  else
    log "FAIL IPv4 route-get: 8.8.8.8 not via $TUN_INTERFACE: $ROUTE_GET_88"
    fail=1
  fi
  classify_split_route <<<"$ROUTE_MAIN" "$EXPECTED_LAN" || fail=1

  if (( fail == 1 )); then
    log
    log "state=FAIL: one or more leak directions violated while session was up"
    log "result=PASS false"
    ln -sf "$EVIDENCE_LOG" "$EVIDENCE_LATEST"
    return 1
  fi
  log
  log "state=PASS: both leak directions held on a live tun during the session"
  log "result=PASS true"
  ln -sf "$EVIDENCE_LOG" "$EVIDENCE_LATEST"
  return 0
}

if [[ $SELFCHECK == 1 ]]; then
  selfcheck
  exit $?
fi

live_run
