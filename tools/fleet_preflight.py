#!/usr/bin/env python3
"""Sanitized SSH preflight for Win's VPN fleet.

Reads JSON from stdin:
[
  {
    "name": "...",
    "host": "...",
    "user": "wins-preflight",
    "known_hosts": "/path/to/per-host-known_hosts",
    "identity_file": "/path/to/private_key",
    "port": 22
  }
]

Every entry MUST supply "known_hosts" (an OpenSSH known_hosts-format file
already pinned with the target's real host key, via a channel you already
trust -- never populated by connecting to the host itself) and
"identity_file" (a private key for a constrained, non-root account). Host
keys are verified strictly against that file (unknown or changed keys abort
the connection before authentication) and authentication is key-only: this
script never accepts or sends a password, to a fleet host or otherwise.

No credentials are written to disk or printed.
"""

from __future__ import annotations

import json
import socket
import sys
import traceback
from typing import Any

import paramiko


REMOTE_SCRIPT = r"""
set -u
root_src="$(findmnt -no SOURCE / 2>/dev/null || true)"
root_fstype="$(findmnt -no FSTYPE / 2>/dev/null || true)"
root_real="$(readlink -f "${root_src}" 2>/dev/null || printf '%s' "${root_src}")"
if [[ -n "${root_real}" ]] && lsblk -spno TYPE "${root_real}" 2>/dev/null | grep -qx crypt; then
  root_luks=yes
else
  root_luks=no
fi
swap_plain=no
swap_list="$(swapon --noheadings --raw --show=NAME 2>/dev/null | paste -sd ',' - || true)"
if [[ -n "${swap_list}" ]]; then
  swap_plain=unknown
fi
ipv4_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
ipv6_disabled="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo unknown)"
default_if="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
default_ip="$(ip -o -4 addr show "${default_if:-}" 2>/dev/null | awk '{print $4}' | head -n1)"
os_pretty="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}" || echo unknown)"
virt="$(systemd-detect-virt 2>/dev/null || echo unknown)"
printf '{'
printf '"hostname":%s,' "$(python3 -c 'import json, socket; print(json.dumps(socket.gethostname()))' 2>/dev/null || echo '""')"
printf '"os":%s,' "$(printf '%s' "${os_pretty}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"kernel":%s,' "$(uname -r | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')"
printf '"virt":%s,' "$(printf '%s' "${virt}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"cpu_cores":%s,' "$(nproc 2>/dev/null || echo 0)"
printf '"mem_kb":%s,' "$(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
printf '"root_source":%s,' "$(printf '%s' "${root_src}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"root_fstype":%s,' "$(printf '%s' "${root_fstype}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"root_luks":%s,' "$(if [[ "${root_luks}" == yes ]]; then echo true; else echo false; fi)"
printf '"swap_active":%s,' "$(if [[ -n "${swap_list}" ]]; then echo true; else echo false; fi)"
printf '"swap_plain_status":%s,' "$(printf '%s' "${swap_plain}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"ipv4_forward":%s,' "$(printf '%s' "${ipv4_forward}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"ipv6_disabled":%s,' "$(printf '%s' "${ipv6_disabled}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"default_interface":%s,' "$(printf '%s' "${default_if}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '"default_ipv4":%s' "$(printf '%s' "${default_ip}" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
printf '}\n'
"""


def run_preflight(entry: dict[str, Any]) -> dict[str, Any]:
    name = entry["name"]
    host = entry["host"]
    user = entry.get("user", "wins-preflight")
    known_hosts = entry.get("known_hosts")
    identity_file = entry.get("identity_file")
    result: dict[str, Any] = {"name": name, "host": host, "user": user, "ok": False}

    # Fail closed and say why, rather than silently falling back to
    # AutoAddPolicy (trust-on-first-use, a classic MITM exposure) or password
    # authentication (sends a root/admin secret over the wire on every run).
    if not known_hosts or not identity_file:
        result["error"] = (
            "inventory entry is missing required known_hosts and/or "
            "identity_file; password authentication to fleet hosts is no "
            "longer supported"
        )
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.load_host_keys(known_hosts)
        client.connect(
            hostname=host,
            username=user,
            key_filename=identity_file,
            password=None,
            port=int(entry.get("port", 22)),
            look_for_keys=False,
            allow_agent=False,
            timeout=12,
            banner_timeout=12,
            auth_timeout=12,
        )
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=25)
        stdin.write(REMOTE_SCRIPT)
        stdin.channel.shutdown_write()
        raw = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        status = stdout.channel.recv_exit_status()
        if status == 0 and raw:
            result.update(json.loads(raw.splitlines()[-1]))
            result["ok"] = True
        else:
            result["error"] = f"remote status {status}: {err[-400:]}"
    except (paramiko.SSHException, socket.error, TimeoutError, json.JSONDecodeError) as exc:
        result["error"] = str(exc)
    except Exception as exc:  # defensive: still do not print credentials
        result["error"] = str(exc)
        result["trace"] = traceback.format_exc(limit=1)
    finally:
        client.close()
    return result


def main() -> int:
    entries = json.load(sys.stdin)
    results = [run_preflight(entry) for entry in entries]
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(item.get("ok") for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
