#!/system/bin/sh
set -u

find_disconnect_center() {
  xml_path="$1"
  node_line="$(
    tr '>' '\n' <"${xml_path}" |
      grep -m 1 'content-desc="Disconnect VPN"' || true
  )"
  [ -n "${node_line}" ] || return 1
  bounds="$(
    printf '%s\n' "${node_line}" |
      sed -n 's/.*bounds="\[\([0-9][0-9]*\),\([0-9][0-9]*\)\]\[\([0-9][0-9]*\),\([0-9][0-9]*\)\]".*/\1 \2 \3 \4/p'
  )"
  set -- ${bounds}
  [ "$#" -eq 4 ] || return 1
  [ "$3" -gt "$1" ] && [ "$4" -gt "$2" ] || return 1
  printf '%s %s\n' "$((($1 + $3) / 2))" "$((($2 + $4) / 2))"
}

if [ "${1:-}" = "--self-test" ]; then
  fixture="$(mktemp)"
  trap 'rm -f "${fixture}"' EXIT HUP INT TERM
  printf '%s\n' '<hierarchy><node bounds="[19,41][219,341]" content-desc="Disconnect VPN" /></hierarchy>' >"${fixture}"
  [ "$(find_disconnect_center "${fixture}")" = '119 191' ] || {
    printf 'ANDROID WIRELESS MONITOR SELF-TEST: FAIL\n' >&2
    exit 1
  }
  printf '%s\n' '<hierarchy><node bounds="[19,41][219,341]" content-desc="Connect VPN" /></hierarchy>' >"${fixture}"
  if find_disconnect_center "${fixture}" >/dev/null 2>&1; then
    printf 'ANDROID WIRELESS MONITOR SELF-TEST: FAIL\n' >&2
    exit 1
  fi
  printf 'ANDROID WIRELESS MONITOR SELF-TEST: PASS\n'
  exit 0
fi

if [ "${1:-}" = "--background" ]; then
  shift
  # Fork on the device, where Android's shell owns all quoting and redirection.
  # Passing a host-built `sh -c "... &"` string through adb is not portable on
  # Windows and can report success even though no monitor was started.
  nohup sh "$0" --foreground "$@" </dev/null >/dev/null 2>&1 &
  exit 0
fi
if [ "${1:-}" = "--foreground" ]; then
  shift
fi

package_name="${1:-org.winsvpn.app}"
browser_package="${2:-com.android.chrome}"
canary_url="${3:-https://api.ipify.org}"
output_dir="/data/local/tmp/winsvpn-wireless-live"

rm -rf "${output_dir}"
mkdir -p "${output_dir}"
chmod 700 "${output_dir}"

# The host-side wireless ADB transport may disappear as soon as Android moves
# the default route into the VPN.  This monitor is deliberately launched by the
# already-authorized shell identity before connect, then gathers only local
# device evidence and performs the UI disconnect without depending on the LAN.
sleep 35

am start -W -a android.intent.action.VIEW -d "${canary_url}" \
  -p "${browser_package}" >/dev/null 2>&1 || true
sleep 12
uiautomator dump "${output_dir}/egress.xml" >/dev/null 2>&1 || true

{
  printf 'schema_version=1\n'
  printf 'phase=connected_probe\n'
  if grep -q '^[[:space:]]*tun0:' /proc/net/dev; then
    printf 'tun_present=1\n'
    awk '/^[[:space:]]*tun0:/ {print "tun_counters=" $2 "," $10}' /proc/net/dev
  else
    printf 'tun_present=0\n'
  fi
  if ps -A | grep -Eq 'libxray|/xray([[:space:]]|$)'; then
    printf 'xray_present=1\n'
  else
    printf 'xray_present=0\n'
  fi
  if dumpsys activity services "${package_name}" 2>/dev/null | grep -q 'VpnTunnelService'; then
    printf 'vpn_service_present=1\n'
  else
    printf 'vpn_service_present=0\n'
  fi
} >"${output_dir}/connected-state.txt"

monkey -p "${package_name}" -c android.intent.category.LAUNCHER 1 \
  >/dev/null 2>&1 || true
sleep 3
uiautomator dump "${output_dir}/connected-ui.xml" >/dev/null 2>&1 || true

disconnect_control_found=0
disconnect_center="$(find_disconnect_center "${output_dir}/connected-ui.xml" || true)"
if [ -n "${disconnect_center}" ]; then
  set -- ${disconnect_center}
  input tap "$1" "$2"
  disconnect_control_found=1
fi
sleep 15

cleanup_fallback=0
if grep -q '^[[:space:]]*tun0:' /proc/net/dev || \
   dumpsys activity services "${package_name}" 2>/dev/null | grep -q 'VpnTunnelService'; then
  cleanup_fallback=1
  am force-stop "${package_name}" >/dev/null 2>&1 || true
  sleep 8
fi

{
  printf 'schema_version=1\n'
  printf 'phase=post_disconnect\n'
  printf 'disconnect_control_found=%s\n' "${disconnect_control_found}"
  printf 'cleanup_fallback=%s\n' "${cleanup_fallback}"
  if grep -q '^[[:space:]]*tun0:' /proc/net/dev; then
    printf 'tun_present=1\n'
  else
    printf 'tun_present=0\n'
  fi
  if ps -A | grep -Eq 'libxray|/xray([[:space:]]|$)'; then
    printf 'xray_present=1\n'
  else
    printf 'xray_present=0\n'
  fi
  if dumpsys activity services "${package_name}" 2>/dev/null | grep -q 'VpnTunnelService'; then
    printf 'vpn_service_present=1\n'
  else
    printf 'vpn_service_present=0\n'
  fi
  printf 'completed=1\n'
} >"${output_dir}/post-state.txt"

exit 0
