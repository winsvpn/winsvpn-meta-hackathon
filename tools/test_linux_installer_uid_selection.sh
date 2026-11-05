#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/linux/packaging/install.sh"

# Exercise the exact function bodies shipped by the installer, but replace
# host account and firewall commands with deterministic in-process fixtures.
functions="$({
  awk '
    /^firewall_references_uid\(\)/ { capture = 1 }
    /^if id -u winsvpn-xray/ { capture = 0 }
    capture { print }
  ' "$INSTALLER"
})"
[[ "$functions" == *"select_unreferenced_system_uid()"* ]] || {
  echo "Could not extract the installer UID-selection functions." >&2
  exit 1
}

die() {
  echo "$*" >&2
  return 1
}
eval "$functions"

uid_min=100
uid_max=999
if [[ -r /etc/login.defs ]]; then
  while read -r key value _; do
    case "$key" in
      SYS_UID_MIN) [[ "$value" =~ ^[0-9]+$ ]] && uid_min="$value" ;;
      SYS_UID_MAX) [[ "$value" =~ ^[0-9]+$ ]] && uid_max="$value" ;;
    esac
  done < /etc/login.defs
fi
(( uid_max - uid_min >= 4 )) || {
  echo "The test host system UID range is too small." >&2
  exit 1
}

fixture_mode=combined
getent() {
  [[ "$1" == passwd ]] || return 2
  if [[ "$fixture_mode" == combined && "$2" == "$uid_max" ]]; then
    printf 'occupied:x:%s:%s::/nonexistent:/usr/sbin/nologin\n' "$2" "$2"
    return 0
  fi
  return 2
}
iptables-save() {
  case "$fixture_mode" in
    combined)
      printf -- '-A OUTPUT -m owner --uid-owner %s -j REJECT\n' "$((uid_max - 1))"
      ;;
    range)
      printf -- '-A OUTPUT -m owner --uid-owner %s-%s -j REJECT\n' \
        "$((uid_max - 2))" "$uid_max"
      ;;
  esac
}
ip6tables-save() { :; }
nft() {
  if [[ "$fixture_mode" == combined ]]; then
    printf 'meta skuid { %s, %s } reject\n' "$((uid_max - 2))" "$((uid_max - 4))"
  fi
}

selected="$(select_unreferenced_system_uid)"
[[ "$selected" == "$((uid_max - 3))" ]] || {
  echo "Combined account, iptables, and nftables collision test failed." >&2
  exit 1
}

fixture_mode=range
selected="$(select_unreferenced_system_uid)"
[[ "$selected" == "$((uid_max - 3))" ]] || {
  echo "iptables UID-range collision test failed." >&2
  exit 1
}

fixture_mode=empty
selected="$(select_unreferenced_system_uid)"
[[ "$selected" == "$uid_max" ]] || {
  echo "Highest free and unreferenced UID selection test failed." >&2
  exit 1
}

echo "Linux installer UID-selection simulation passed."
