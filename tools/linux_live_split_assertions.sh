#!/usr/bin/env bash
set -Eeuo pipefail

[[ "$(id -u)" == 0 ]]
state=/run/wins-vpn
mapfile -t canaries < <(
  # Each logind runtime directory is normally its own tmpfs mount.  Starting
  # at /run/user with -xdev therefore skipped every real desktop-user canary.
  # The strict path, owner, mode, PID, and cgroup checks below remain the
  # security boundary.
  find /run/user -mindepth 2 -maxdepth 2 -type f \
    -name winsvpn-split-canary.json -print 2>/dev/null
)
[[ "${#canaries[@]}" -eq 1 ]] || {
  echo 'Expected exactly one active desktop-user split canary.' >&2
  exit 1
}
canary="${canaries[0]}"
[[ "${canary}" =~ ^/run/user/([1-9][0-9]*)/winsvpn-split-canary\.json$ ]]
desktop_uid="${BASH_REMATCH[1]}"
[[ "$(stat -c '%u:%a' -- "${canary}")" == "${desktop_uid}:600" ]]
[[ -s "$canary" && -s "$state/app-bypass-mark" && -s "$state/app-bypass-bpf.pid" ]]

read -r canary_pid canary_mark canary_cgroup < <(
  python3 - "$canary" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert data["schema_version"] == 1
assert isinstance(data["pid"], int) and data["pid"] > 1
assert isinstance(data["socket_mark"], int) and data["socket_mark"] > 0
assert "winsvpn-bypass.slice" in data["cgroup"]
print(data["pid"], data["socket_mark"], data["cgroup"])
PY
)
[[ -e "/proc/$canary_pid" ]]
[[ "$(stat -c '%u' -- "/proc/$canary_pid")" == "${desktop_uid}" ]]
actual_canary_cgroup="$(awk -F: '$1 == "0" {print $3; exit}' "/proc/$canary_pid/cgroup")"
[[ "${actual_canary_cgroup}" == "${canary_cgroup}" \
  && "${actual_canary_cgroup}" == *winsvpn-bypass.slice* ]]

routing_mark="$(cat "$state/app-bypass-mark")"
routing_mark_decimal="$((routing_mark))"
[[ "$canary_mark" == "$routing_mark_decimal" ]]
ip -4 route get 1.1.1.1 | grep -Eq ' dev winsvpn( |$)'
if ip -4 route get 1.1.1.1 mark "$routing_mark" | grep -Eq ' dev winsvpn( |$)'; then
  echo "A bypass-marked socket still resolves through the VPN." >&2
  exit 1
fi

bpf_pid="$(cat "$state/app-bypass-bpf.pid")"
[[ "$bpf_pid" =~ ^[1-9][0-9]*$ && -e "/proc/$bpf_pid/exe" ]]
[[ "$(readlink -f "/proc/$bpf_pid/exe")" == /opt/wins-vpn/winsvpn-bypass-bpf ]]
grep -qx READY "$state/app-bypass-bpf.log"
iptables -t mangle -C OUTPUT -m cgroup \
  --path "$(cat "$state/app-bypass-cgroup")" \
  -m comment --comment winsvpn-app-bypass \
  -j MARK --set-mark "$routing_mark"

printf '%s\n' \
  'LIVE_CANARY_PROCESS_EXISTS=PASS' \
  'LIVE_CANARY_IN_BYPASS_CGROUP=PASS' \
  'LIVE_CANARY_SOCKET_MARK=PASS' \
  'ORDINARY_ROUTE_USES_WINVPN=PASS' \
  'BYPASS_MARK_ROUTE_USES_PHYSICAL=PASS' \
  'BPF_FAIL_SAFE_HELPER_RUNNING=PASS'
