#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_DISTRO="${WINS_FRESH_INSTALL_TEST_DISTRO:-WinsVPN-Rehearsal-Noble}"
case "$EXPECTED_DISTRO" in
  WinsVPN-Rehearsal-Noble|Ubuntu-24.04) ;;
  *)
    echo "Refusing an unapproved fresh-install rehearsal distro." >&2
    exit 64
    ;;
esac
ARTIFACT="${1:-}"
[[ "${WSL_DISTRO_NAME:-}" == "$EXPECTED_DISTRO" ]] || {
  echo "Refusing destructive rehearsal outside ${EXPECTED_DISTRO}." >&2
  exit 64
}
[[ "$(id -u)" == 0 ]] || {
  echo "The fresh-install rehearsal must run as root." >&2
  exit 77
}
[[ -f "$ARTIFACT" ]] || {
  echo "Pass the exact Linux candidate archive as argument 1." >&2
  exit 66
}
[[ "$(readlink -f /opt/wins-vpn)" == /opt/wins-vpn ]] || {
  echo "The rehearsal application target is unexpected." >&2
  exit 65
}

work="$(mktemp -d)"
added_collision_rule=0
cleanup() {
  status=$?
  rm -rf -- "$work"
  if [[ "$added_collision_rule" == 1 ]]; then
    iptables -D OUTPUT -m owner --uid-owner 999 -j REJECT 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

if ! iptables-save | grep -Fq -- '--uid-owner 999'; then
  iptables -I OUTPUT 1 -m owner --uid-owner 999 -j REJECT
  added_collision_rule=1
fi
baseline_rule_count="$(iptables-save | grep -Fc -- '--uid-owner 999')"

if id -u winsvpn-xray >/dev/null 2>&1; then
  old_uid="$(id -u winsvpn-xray)"
  pkill -u "$old_uid" 2>/dev/null || true
  userdel winsvpn-xray
fi
if getent group winsvpn-xray >/dev/null 2>&1; then
  groupdel winsvpn-xray
fi

rm -rf -- /opt/wins-vpn
rm -f -- \
  /usr/local/bin/wins_vpn \
  /usr/share/applications/org.winsvpn.app.desktop \
  /usr/share/metainfo/org.winsvpn.app.metainfo.xml \
  /usr/share/icons/hicolor/512x512/apps/org.winsvpn.app.png

tar -xzf "$ARTIFACT" -C "$work"
DEBIAN_FRONTEND=noninteractive bash "$work/install.sh"

installed_uid="$(id -u winsvpn-xray)"
[[ "$installed_uid" -ne 999 ]]
[[ "$(getent passwd winsvpn-xray | cut -d: -f6)" == /nonexistent ]]
[[ "$(getent passwd winsvpn-xray | cut -d: -f7)" == "$(command -v nologin)" ]]
shadow="$(getent shadow winsvpn-xray | cut -d: -f2)"
[[ "$shadow" == '!'* || "$shadow" == '*'* ]]
cmp -s "$work/wins_vpn" /opt/wins-vpn/wins_vpn
cmp -s "$work/install.sh" /opt/wins-vpn/install.sh
[[ "$(readlink -f /usr/local/bin/wins_vpn)" == /opt/wins-vpn/wins_vpn ]]
cmp -s "$work/share/applications/org.winsvpn.app.desktop" \
  /usr/share/applications/org.winsvpn.app.desktop
cmp -s "$work/share/metainfo/org.winsvpn.app.metainfo.xml" \
  /usr/share/metainfo/org.winsvpn.app.metainfo.xml
cmp -s "$work/share/icons/hicolor/512x512/apps/org.winsvpn.app.png" \
  /usr/share/icons/hicolor/512x512/apps/org.winsvpn.app.png
final_rule_count="$(iptables-save | grep -Fc -- '--uid-owner 999')"
[[ "$final_rule_count" == "$baseline_rule_count" ]]

printf '%s\n' \
  'FRESH_INSTALL=PASS' \
  'COLLISION_UID_AVOIDED=PASS' \
  'LOCKED_IDENTITY=PASS' \
  'EXACT_BINARY=PASS' \
  'DESKTOP_INTEGRATION=PASS' \
  'ORIGINAL_FIREWALL_RULE_PRESERVED=PASS'
