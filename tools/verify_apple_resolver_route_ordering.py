#!/usr/bin/env python3
"""A-01 guard: the resolver /32 loop must never follow the settings copy.

`NEPacketTunnelNetworkSettings.IPv4Settings` is `@property (copy)`, so any
route appended to the local NEIPv4Settings after `settings.ipv4Settings = ...`
is discarded. For every resolver-append site, this walks UPWARD to the nearest
enclosing function start and fails if a copy assignment sits between them.

A naive two-marker line-number comparison is NOT sufficient here and will report
a false pass: both providers assign `settings.ipv4Settings` at more than one
site, so a scan that keeps the last match compares against an assignment in a
different function entirely.
"""
import re
import sys

ASSIGN = "settings.ipv4Settings = ipv4Settings"
APPEND = "for server in config.dnsServers where Self.isIPv4Literal"
FUNC = re.compile(r"^\s*(?:private\s+|public\s+|internal\s+|static\s+|final\s+)*func\s")

failures = 0
checked = 0
paths = sys.argv[1:] or [
    "ios/PacketTunnel/PacketTunnelProvider.swift",
    "macos/PacketTunnel/PacketTunnelProvider.swift",
]
for path in paths:
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    for index, line in enumerate(lines):
        if APPEND not in line:
            continue
        checked += 1
        start = 0
        for back in range(index - 1, -1, -1):
            if FUNC.match(lines[back]):
                start = back
                break
        offending = [
            back + 1 for back in range(start, index) if ASSIGN in lines[back]
        ]
        if offending:
            failures += 1
            print(
                f"FAIL {path}:{index + 1} resolver /32 loop runs AFTER the copy "
                f"assignment at line(s) {offending}; those routes are discarded"
            )
        else:
            print(f"PASS {path}:{index + 1} resolver /32 loop precedes the copy assignment")

if checked == 0:
    print("FAIL no resolver /32 loop found; the leak guard has been removed entirely")
    sys.exit(1)
sys.exit(1 if failures else 0)
