#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_DISTRO="${WINS_FRESH_INSTALL_TEST_DISTRO:-WinsVPN-Rehearsal-Noble}"
ARTIFACT="${1:-}"
INSTALLER_SOURCE="${2:-}"

[[ "${WSL_DISTRO_NAME:-}" == "$EXPECTED_DISTRO" ]] || {
  echo "Refusing installer rollback rehearsal outside ${EXPECTED_DISTRO}." >&2
  exit 64
}
[[ "$(id -u)" == 0 ]] || {
  echo "Installer rollback rehearsal must run as root." >&2
  exit 77
}
[[ -f "$ARTIFACT" && -f "$INSTALLER_SOURCE" ]] || {
  echo "Pass the exact Linux archive and installer source as arguments." >&2
  exit 66
}

work="$(mktemp -d)"
saved="$work/saved"
bundle="$work/bundle"
mkdir -p -- "$saved" "$bundle"

target=/opt/wins-vpn
launcher=/usr/local/bin/wins_vpn
desktop=/usr/share/applications/org.winsvpn.app.desktop
metainfo=/usr/share/metainfo/org.winsvpn.app.metainfo.xml
icon_parent=/usr/share/icons/hicolor/512x512/apps
icon_parent_backup="${icon_parent}.winsvpn-rollback-test.$$"
had_xray_user=0
had_xray_group=0
id -u winsvpn-xray >/dev/null 2>&1 && had_xray_user=1
getent group winsvpn-xray >/dev/null 2>&1 && had_xray_group=1

save_path() {
  local path="$1" name="$2"
  if [[ -e "$path" || -L "$path" ]]; then
    mv -- "$path" "$saved/$name"
  fi
}

restore_path() {
  local path="$1" name="$2"
  rm -rf -- "$path"
  if [[ -e "$saved/$name" || -L "$saved/$name" ]]; then
    mv -- "$saved/$name" "$path"
  fi
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  restore_path "$target" target
  restore_path "$launcher" launcher
  restore_path "$desktop" desktop
  restore_path "$metainfo" metainfo
  rm -rf -- "$icon_parent"
  if [[ -e "$icon_parent_backup" ]]; then
    mv -- "$icon_parent_backup" "$icon_parent"
  fi
  if [[ "$had_xray_user" == 0 ]] && id -u winsvpn-xray >/dev/null 2>&1; then
    userdel winsvpn-xray >/dev/null 2>&1 || true
  fi
  if [[ "$had_xray_group" == 0 ]] && getent group winsvpn-xray >/dev/null 2>&1; then
    groupdel winsvpn-xray >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

save_path "$target" target
save_path "$launcher" launcher
save_path "$desktop" desktop
save_path "$metainfo" metainfo
if [[ -e "$icon_parent" ]]; then
  mv -- "$icon_parent" "$icon_parent_backup"
fi
mkdir -p -- "$(dirname "$icon_parent")"
printf 'intentional installer failure fixture\n' >"$icon_parent"

tar -xzf "$ARTIFACT" -C "$bundle"
install -m 0755 -- "$INSTALLER_SOURCE" "$bundle/install.sh"
if bash "$bundle/install.sh" >"$work/install.stdout" 2>"$work/install.stderr"; then
  echo "Installer unexpectedly succeeded with an obstructed icon target." >&2
  exit 1
fi

residue=0
for path in "$target" "$launcher" "$desktop" "$metainfo"; do
  if [[ -e "$path" || -L "$path" ]]; then
    printf 'Unexpected failed-install residue: %s\n' "$path" >&2
    residue=1
  fi
done
if [[ "$had_xray_user" == 0 ]] && id -u winsvpn-xray >/dev/null 2>&1; then
  echo "Unexpected failed-install residue: winsvpn-xray user" >&2
  residue=1
fi
if [[ "$had_xray_group" == 0 ]] && getent group winsvpn-xray >/dev/null 2>&1; then
  echo "Unexpected failed-install residue: winsvpn-xray group" >&2
  residue=1
fi
if [[ "$residue" != 0 ]]; then
  tail -n 20 "$work/install.stderr" >&2 || true
  exit 1
fi

printf '%s\n' \
  'INJECTED_POST_STAGE_FAILURE=PASS' \
  'APPLICATION_ROLLBACK=PASS' \
  'INTEGRATION_ROLLBACK=PASS' \
  'SERVICE_IDENTITY_ROLLBACK=PASS'
