#!/usr/bin/env python3
"""Per authenticated AWG address policing, invoked only by management code.

The installers embed these bytes. No account identifier is stored on a node.
Existing owned filters are retained on reconnect, including their token state.
"""

import ipaddress
import json
import pathlib
import re
import subprocess
import sys

RATE_PATH = pathlib.Path("/etc/winsvpn/free-bandwidth-mbps")
STATE = pathlib.Path("/run/winsvpn-freecap")
PREF = "49100"


def burst_bytes(rate_mbit):
    """One hundred milliseconds of the rate: mbps * 125000 B/s / 10.

    Same rule as the v3 gateway's freeBandwidthBurstBytes, so both planes on
    one node always agree. A policer whose burst cannot cover one path round
    trip starves a single TCP flow well below the advertised rate, so the
    burst is derived from the rate and has no operator knob of its own.
    """
    burst = int(rate_mbit) * 12500
    return min(max(burst, 1), 67108864)


def tc(*args):
    return subprocess.run(
        ["tc", *args], check=True, text=True, capture_output=True,
        stdin=subprocess.DEVNULL, timeout=5,
    ).stdout


def action_index(filters, handle, field, address, index=None):
    for entry in filters:
        options = entry.get("options") or {}
        try:
            actual = int(str(options.get("handle", "0")), 0)
        except ValueError:
            continue
        if actual != handle:
            continue
        keys = options.get("keys") or {}
        if keys.get(field) not in {address, address + "/32"}:
            continue
        actions = options.get("actions") or []
        if len(actions) == 1 and actions[0].get("kind") == "police":
            actual_index = actions[0].get("index")
            if isinstance(actual_index, int) and actual_index > 0 and (index is None or actual_index == index):
                return actual_index
    return None


def apply(iface, address, tier):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", iface):
        raise ValueError("invalid interface")
    addr = ipaddress.IPv4Address(address)
    if addr not in ipaddress.IPv4Network("10.0.0.0/8") or str(addr) != address:
        raise ValueError("invalid tunnel address")
    if tier not in {"free", "premium"}:
        raise ValueError("invalid traffic tier")
    rate = int(RATE_PATH.read_text().strip())
    if not 0 <= rate <= 100000:
        raise ValueError("invalid free rate")
    ifindex = int(pathlib.Path("/sys/class/net", iface, "ifindex").read_text())
    handle = int(addr)
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = STATE / (iface + "." + address)
    try:
        previous = json.loads(record.read_text())
    except (FileNotFoundError, ValueError):
        previous = None
    directions = (("ingress", "src_ip"), ("egress", "dst_ip"))
    if tier == "premium" or rate == 0:
        for direction, _ in directions:
            filters = json.loads(tc("-j", "filter", "show", "dev", iface, direction, "pref", PREF))
            for entry in filters:
                options = entry.get("options") or {}
                if int(str(options.get("handle", "0")), 0) == handle:
                    tc("filter", "delete", "dev", iface, direction, "protocol", "ip",
                       "pref", PREF, "handle", hex(handle), "flower")
                    break
        record.unlink(missing_ok=True)
        return
    qdiscs = json.loads(tc("-j", "qdisc", "show", "dev", iface))
    if not any(item.get("kind") == "clsact" for item in qdiscs):
        # Refuse an occupied ingress slot instead of replacing another owner.
        tc("qdisc", "add", "dev", iface, "clsact")
    wanted = {"ifindex": ifindex, "rate": rate}
    indices = {}
    for direction, field in directions:
        filters = json.loads(tc("-j", "filter", "show", "dev", iface, direction, "pref", PREF))
        index = (previous or {}).get("indices", {}).get(direction)
        same_config = previous and all(previous.get(key) == value for key, value in wanted.items())
        if same_config and index and action_index(filters, handle, field, address, index) is not None:
            indices[direction] = index
            continue
        tc("filter", "replace", "dev", iface, direction, "protocol", "ip",
           "pref", PREF, "handle", hex(handle), "flower", "skip_hw", field, address + "/32",
           "action", "police", "rate", str(rate) + "mbit", "burst", str(burst_bytes(rate)),
           "mtu", "65535", "conform-exceed", "drop/ok")
        # Kernel action indices are global in the namespace, not per interface.
        # Let the kernel allocate one so identical IPs on two interfaces cannot
        # accidentally share a directional budget.
        index = action_index(json.loads(tc("-j", "filter", "show", "dev", iface, direction,
                                          "pref", PREF)), handle, field, address)
        if index is None:
            raise ValueError("free filter readback failed")
        indices[direction] = index
    wanted["indices"] = indices
    temporary = record.with_suffix(record.suffix + ".new")
    temporary.write_text(json.dumps(wanted, sort_keys=True))
    temporary.replace(record)


def main():
    try:
        if len(sys.argv) != 4:
            raise ValueError("expected interface, address and traffic tier")
        apply(*sys.argv[1:])
    except (OSError, ValueError, subprocess.SubprocessError):
        print("free bandwidth policy failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
