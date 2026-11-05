#!/usr/bin/env python3
"""Both data-plane sysctl.d files set the same UDP socket default.

setup_sysctl writes 99-winsvpn-node.conf and apply_sysctl writes
99-winsvpn-edge.conf. Whichever file systemd-sysctl loads last decides
net.core.rmem_default/wmem_default at boot. This is a configuration
consistency check: the two files must agree so no load order can change the
result. It certifies nothing about capacity or memory use. Static read of the
installer; no network.
"""
from __future__ import annotations

import _toolchain  # noqa: F401  (V-01 preflight)
import os
import re
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "wins_data_plane_setup_ONETOUCH.sh")
WANT = "33554432"
FAILURES = []
PASSED = [0]


def check(name, fn):
    try:
        fn()
    except Exception:
        FAILURES.append((name, traceback.format_exc()))
        print(f"  FAIL  {name}")
    else:
        PASSED[0] += 1
        print(f"  ok    {name}")


def sysctl_body(conf_name: str) -> dict:
    src = open(SCRIPT, encoding="utf-8").read()
    m = re.search(r"cat > [^\n]*" + re.escape(conf_name) + r"[^\n]*<<'?(\w+)'?\n(.*?)\n\1\n", src, re.S)
    assert m, f"no heredoc writing {conf_name}"
    out = {}
    for line in m.group(2).splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def test_node_conf_udp_default():
    body = sysctl_body("99-winsvpn-node.conf")
    assert body.get("net.core.rmem_default") == WANT, body.get("net.core.rmem_default")
    assert body.get("net.core.wmem_default") == WANT, body.get("net.core.wmem_default")


def test_edge_conf_udp_default():
    body = sysctl_body("99-winsvpn-edge.conf")
    assert body.get("net.core.rmem_default") == WANT, body.get("net.core.rmem_default")
    assert body.get("net.core.wmem_default") == WANT, body.get("net.core.wmem_default")


def test_defaults_fit_under_max():
    for conf in ("99-winsvpn-node.conf", "99-winsvpn-edge.conf"):
        body = sysctl_body(conf)
        assert int(body["net.core.rmem_default"]) <= int(body["net.core.rmem_max"]), conf
        assert int(body["net.core.wmem_default"]) <= int(body["net.core.wmem_max"]), conf


TESTS = [test_node_conf_udp_default, test_edge_conf_udp_default, test_defaults_fit_under_max]


def main():
    print("data-plane sysctl UDP socket default")
    for fn in TESTS:
        check(fn.__name__, fn)
    print()
    print(f"{PASSED[0]} passed, {len(FAILURES)} failed")
    for name, tb in FAILURES:
        print("=" * 70)
        print(name)
        print(tb)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
