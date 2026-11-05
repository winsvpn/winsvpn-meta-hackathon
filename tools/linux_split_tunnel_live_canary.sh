#!/usr/bin/env bash
set -euo pipefail

# Live Linux split-tunnel canary. It performs no network request. The canary
# records the cgroup-created socket mark so a release test can prove, with
# `ip route get`, that the selected launcher resolves to the physical route
# while ordinary application sockets remain on the VPN route.
umask 077

runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
output_path="${WINS_SPLIT_CANARY_OUTPUT:-${runtime_dir}/winsvpn-split-canary.json}"
temporary_path="${output_path}.tmp.$$"

cleanup() {
  rm -f -- "${temporary_path}"
}
trap cleanup EXIT HUP INT TERM

cgroup_path="$(awk -F: '$1 == "0" {print $3; exit}' /proc/self/cgroup)"
[[ "${cgroup_path}" == *winsvpn-bypass.slice* ]] || {
  echo 'Split-tunnel canary was not launched in the Win s VPN bypass slice.' >&2
  exit 1
}
socket_mark="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    print(probe.getsockopt(socket.SOL_SOCKET, socket.SO_MARK))
PY
)"
[[ "${socket_mark}" =~ ^[1-9][0-9]*$ ]] || {
  echo 'Split-tunnel canary socket did not receive a bypass mark.' >&2
  exit 1
}

printf '{"schema_version":1,"socket_mark":%s,"cgroup":"%s","pid":%d}\n' \
  "${socket_mark}" "${cgroup_path//\"/}" "$$" >"${temporary_path}"
chmod 600 "${temporary_path}"
mv -f -- "${temporary_path}" "${output_path}"

# Keep the scope alive long enough for a cross-machine release harness to
# verify that the selected process belongs to the launcher-scoped cgroup.
sleep 120
