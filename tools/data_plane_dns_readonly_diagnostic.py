#!/usr/bin/env python3
"""Emit address-free DNS health facts for a managed Win's VPN data plane.

Run through ``infrastructure_readonly_relay.py`` with the data role.  The
diagnostic performs ordinary A-record queries against loopback and the VPN
interfaces that clients actually use.  It deliberately does not require DNS
on unrelated private bridges such as Docker, which the host firewall should
keep isolated.  It never prints an address, DNS answer, configuration value,
credential, key, or journal line.
"""

from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import stat
import struct
import subprocess
import time
from pathlib import Path


def run(args: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout
    except Exception:
        return 255, ""


def query_packet(name: str, identifier: int) -> bytes:
    labels = name.rstrip(".").split(".")
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
    return struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0) + encoded + b"\0" + struct.pack("!HH", 1, 1)


def udp_query(address: str) -> dict[str, object]:
    identifier = random.SystemRandom().randrange(1, 65536)
    packet = query_packet("api.ipify.org", identifier)
    started = time.monotonic()
    try:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(4)
            client.sendto(packet, (address, 53))
            response = client.recv(4096)
        if len(response) < 12:
            raise ValueError("short response")
        response_id, flags, _, answers, _, _ = struct.unpack("!HHHHHH", response[:12])
        rcode = flags & 0xF
        return {
            "ok": response_id == identifier and rcode == 0 and answers > 0,
            "rcode": rcode,
            "answer_count": answers,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error_type": type(exc).__name__,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }


def required_targets() -> list[tuple[str, str, str]]:
    targets: list[tuple[str, str, str]] = [("127.0.0.1", "loopback", "lo")]
    code, output = run(["ip", "-j", "-4", "address", "show"])
    if code != 0:
        return targets
    try:
        interfaces = json.loads(output)
    except Exception:
        return targets
    for interface in interfaces:
        name = str(interface.get("ifname", ""))
        # Only the client-facing AWG interface is a required DNS path. Docker,
        # management, and WAN bridges are intentionally excluded by firewall
        # policy and must not turn a secure deployment into a false alarm.
        if not re.fullmatch(r"awg[0-9]{1,2}", name):
            continue
        for entry in interface.get("addr_info", []):
            value = str(entry.get("local", ""))
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                continue
            if parsed.version == 4 and parsed.is_private and not parsed.is_loopback:
                targets.append((value, "private", name))
    return targets


def _yaml_list(text: str, key: str) -> list[str]:
    """Read one bounded two-space YAML list without exposing other values."""
    lines = text.splitlines()
    marker = f"  {key}:"
    try:
        start = next(index for index, line in enumerate(lines) if line == marker)
    except StopIteration:
        return []
    values: list[str] = []
    for line in lines[start + 1 :]:
        if re.match(r"^  [A-Za-z0-9_]+:", line):
            break
        match = re.fullmatch(r"    -\s+['\"]?([^'\"\s]+)['\"]?\s*", line)
        if match:
            values.append(match.group(1))
    return values


def adguard_policy() -> dict[str, object]:
    """Return policy booleans only; never return configured upstream values."""
    path = Path("/opt/AdGuardHome/AdGuardHome.yaml")
    try:
        info = path.lstat()
        secure = (
            stat.S_ISREG(info.st_mode)
            and not stat.S_ISLNK(info.st_mode)
            and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) & 0o077 == 0
            and 0 < info.st_size <= 1024 * 1024
        )
        if not secure:
            return {"available": True, "owner_only": False, "policy_match": False}
        text = path.read_text(encoding="utf-8", errors="strict")
    except FileNotFoundError:
        return {"available": False, "owner_only": False, "policy_match": False}
    except Exception as exc:
        return {
            "available": "unknown",
            "owner_only": False,
            "policy_match": False,
            "error_type": type(exc).__name__,
        }

    primary = _yaml_list(text, "upstream_dns")
    fallback = _yaml_list(text, "fallback_dns")
    expected_scalars = (
        "  upstream_mode: load_balance",
        "  enable_dnssec: true",
        "  anonymize_client_ip: true",
        "  aaaa_disabled: true",
        "  ratelimit_subnet_len_ipv4: 32",
        "  ratelimit_subnet_len_ipv6: 128",
    )
    result = {
        "available": True,
        "owner_only": True,
        "quad9_primary_exact": primary == ["https://dns.quad9.net/dns-query"],
        "opendns_fallback_present": "https://dns.opendns.com/dns-query" in fallback,
        "dnssec_enabled": "  enable_dnssec: true" in text.splitlines(),
        "ipv6_answers_disabled": "  aaaa_disabled: true" in text.splitlines(),
        "client_ips_anonymized": "  anonymize_client_ip: true" in text.splitlines(),
        "per_client_rate_limit": all(
            line in text.splitlines()
            for line in (
                "  ratelimit_subnet_len_ipv4: 32",
                "  ratelimit_subnet_len_ipv6: 128",
            )
        ),
    }
    result["policy_match"] = (
        result["quad9_primary_exact"]
        and result["opendns_fallback_present"]
        and all(line in text.splitlines() for line in expected_scalars)
    )
    return result


def main() -> int:
    checks = []
    for address, scope, interface in required_targets():
        result = udp_query(address)
        result.update({"scope": scope, "interface": interface})
        checks.append(result)

    rules_code, rules = run(["iptables", "-nvx", "-L", "WINVPN-INPUT"], 15)
    inspected_chain = "WINVPN-INPUT"
    if rules_code != 0:
        _, rules = run(["iptables", "-nvx", "-L", "INPUT"], 15)
        inspected_chain = "INPUT"
    dns_rules = [line for line in rules.splitlines() if re.search(r"dpt:53(?:\s|$)", line)]
    packet_sum = 0
    for line in dns_rules:
        fields = line.split()
        if fields and fields[0].isdigit():
            packet_sum += int(fields[0])

    _, journal = run(
        ["journalctl", "-u", "AdGuardHome", "--since", "15 minutes ago", "--no-pager"],
        20,
    )
    warning_lines = sum(
        bool(re.search(r"error|warn|fail|timeout|refus", line, re.IGNORECASE))
        for line in journal.splitlines()
    )
    active_code, active = run(["systemctl", "is-active", "AdGuardHome"], 8)
    interfaces_code, interfaces = run(["awg", "show", "interfaces"], 8)
    awg_interfaces = sorted(
        value
        for value in interfaces.split()
        if re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", value)
    ) if interfaces_code == 0 else []
    if not awg_interfaces:
        awg_interfaces = sorted(
            {str(check["interface"]) for check in checks if str(check["interface"]).startswith("awg")}
        )
    all_required_resolvers_ok = bool(checks) and any(
        str(check.get("interface", "")).startswith("awg") for check in checks
    ) and all(bool(check.get("ok")) for check in checks)
    udp_rule = run(
        [
            "iptables", "-C", "WINVPN-INPUT", "-i", "awg0", "-p", "udp",
            "--dport", "53", "-j", "ACCEPT",
        ],
        8,
    )[0] == 0
    tcp_rule = run(
        [
            "iptables", "-C", "WINVPN-INPUT", "-i", "awg0", "-p", "tcp",
            "--dport", "53", "-j", "ACCEPT",
        ],
        8,
    )[0] == 0

    print(
        json.dumps(
            {
                "role": "data",
                "contract": "winsvpn-data-plane-dns-readonly-v1",
                "adguard_active": active_code == 0 and active.strip() == "active",
                "adguard_policy": adguard_policy(),
                "resolver_checks": checks,
                "all_required_resolvers_ok": all_required_resolvers_ok,
                # Backward-compatible alias for existing evidence consumers.
                "all_private_resolvers_ok": all_required_resolvers_ok,
                "awg_interfaces": awg_interfaces,
                "input_dns_accept_rule_count": len(dns_rules),
                "input_dns_accept_packet_sum": packet_sum,
                "input_chain_inspected": inspected_chain,
                "awg0_udp_dns_accept": udp_rule,
                "awg0_tcp_dns_accept": tcp_rule,
                "recent_adguard_warning_line_count": warning_lines,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
