#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$(id -u)" == 0 ]]
if ip link show winsvpn >/dev/null 2>&1; then
  echo "The Win's VPN interface remains after disconnect." >&2
  exit 1
fi
if ip -4 rule show | grep -Eq 'uidrange [0-9]+-[0-9]+ lookup main'; then
  echo "An Xray UID policy rule remains after disconnect." >&2
  exit 1
fi
if iptables-save | grep -Eq 'winsvpn-(xray|app-bypass)'; then
  echo "A Win's VPN transport or split rule remains after disconnect." >&2
  exit 1
fi
if ip6tables-save | grep -Eq 'winsvpn-(xray|app-bypass)'; then
  echo "A Win's VPN IPv6 split rule remains after disconnect." >&2
  exit 1
fi
[[ ! -e /run/wins-vpn-xray ]]
[[ -d /run/wins-vpn && "$(stat -c '%a:%U:%G' /run/wins-vpn)" == 700:root:root ]]
[[ -z "$(find /run/wins-vpn -mindepth 1 -maxdepth 1 -print -quit)" ]]
if pgrep -f '/opt/wins-vpn/(xray|winsvpn-bypass-bpf)' >/dev/null 2>&1; then
  echo "A protected transport helper remains after disconnect." >&2
  exit 1
fi

printf '%s\n' \
  'AWG_INTERFACE_REMOVED=PASS' \
  'XRAY_POLICY_REMOVED=PASS' \
  'SPLIT_BPF_AND_RULES_REMOVED=PASS' \
  'OWNER_ONLY_RUNTIME_STATE_EMPTY=PASS'
