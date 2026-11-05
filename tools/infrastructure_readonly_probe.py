#!/usr/bin/env python3
"""Sanitized, mutation-free live role probe for Win's VPN infrastructure.

Pipe this file to an authenticated root SSH session as ``python3 -``.  It
reports service and policy facts, public protocol ports, and file hashes; it
never emits configuration contents, credentials, peer keys, or IP addresses.
Set WINS_PROBE_INCLUDE_MANAGEMENT_TARGETS=1 only for an in-memory orchestrator
that removes the ``management_targets`` field before persisting or printing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import stat
import subprocess
import time
import glob
import urllib.parse
from typing import Any, Callable


class ConfiguredRuleInvalid(RuntimeError):
    """A configured Suricata rule path is unsafe for release evidence."""


class ConfiguredRuleRaced(RuntimeError):
    """A configured Suricata rule changed while it was being inspected."""


def run(args: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except Exception as exc:
        return 255, "", type(exc).__name__


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_state(value: str) -> dict[str, Any]:
    path = pathlib.Path(value)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return {"exists": True, "symlink": True}
        result: dict[str, Any] = {
            "exists": True,
            "symlink": False,
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "uid": info.st_uid,
            "size": info.st_size,
        }
        if stat.S_ISREG(info.st_mode):
            result["sha256"] = sha256_file(path)
        return result
    except FileNotFoundError:
        return {"exists": False}
    except Exception as exc:
        return {"exists": "unknown", "error": type(exc).__name__}


def unit(name: str) -> dict[str, Any]:
    active = run(["systemctl", "is-active", name], 8)[1] or "unknown"
    enabled = run(["systemctl", "is-enabled", name], 8)[1] or "unknown"
    properties = {}
    for prop in (
        "Result",
        "ExecMainStatus",
        "NRestarts",
        "ActiveEnterTimestamp",
        "LastTriggerUSec",
    ):
        value = run(["systemctl", "show", name, "-p", prop, "--value"], 8)[1]
        if value:
            properties[prop] = value
    return {"active": active, "enabled": enabled, "properties": properties}


def resources() -> dict[str, Any]:
    memory = {}
    for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        memory[key] = int(value.strip().split()[0]) * 1024
    disk = os.statvfs("/")
    return {
        "cpu_cores": os.cpu_count() or 0,
        "memory_bytes": memory.get("MemTotal", 0),
        "memory_available_bytes": memory.get("MemAvailable", 0),
        "swap_bytes": memory.get("SwapTotal", 0),
        "swap_free_bytes": memory.get("SwapFree", 0),
        "root_total_bytes": disk.f_blocks * disk.f_frsize,
        "root_free_bytes": disk.f_bavail * disk.f_frsize,
        "load1": os.getloadavg()[0],
        "uptime_seconds": int(float(pathlib.Path("/proc/uptime").read_text().split()[0])),
    }


def storage() -> dict[str, Any]:
    source = run(["findmnt", "-no", "SOURCE", "/"])[1]
    fstype = run(["findmnt", "-no", "FSTYPE", "/"])[1]
    real = run(["readlink", "-f", source])[1] or source
    chain = run(["lsblk", "-spno", "TYPE", real])[1].splitlines() if real else []
    swaps = run(["swapon", "--noheadings", "--raw", "--show=NAME"])[1].splitlines()
    swap_classes: dict[str, int] = {}
    for source in swaps:
        value = source.strip()
        if value.startswith(("/dev/zram", "/dev/ram")):
            kind = "ram_backed"
        else:
            real_swap = run(["readlink", "-f", value])[1] or value
            if pathlib.Path(real_swap).is_block_device():
                backing = real_swap
            else:
                filesystem = run(["findmnt", "-no", "FSTYPE", "-T", real_swap])[1]
                if filesystem in {"tmpfs", "ramfs"}:
                    kind = "ram_backed"
                    swap_classes[kind] = swap_classes.get(kind, 0) + 1
                    continue
                backing_source = run(
                    ["findmnt", "-no", "SOURCE", "-T", real_swap]
                )[1]
                backing = run(["readlink", "-f", backing_source])[1] or backing_source
            chain = run(["lsblk", "-spno", "TYPE", backing])[1].splitlines()
            kind = "encrypted_backing" if "crypt" in chain else "unprotected"
        swap_classes[kind] = swap_classes.get(kind, 0) + 1
    unprotected_swap_count = swap_classes.get("unprotected", 0)
    return {
        "root_fstype": fstype,
        "root_luks": "crypt" in chain,
        "swap_active": bool(swaps),
        "swap_count": len(swaps),
        "swap_classes": swap_classes,
        "unprotected_swap_count": unprotected_swap_count,
        "protected_swap_only": bool(swaps) and unprotected_swap_count == 0,
    }


def listeners() -> list[dict[str, Any]]:
    observed: set[tuple[str, int, str, str]] = set()
    for line in run(["ss", "-H", "-lntup"], 15)[1].splitlines():
        columns = line.split()
        if len(columns) < 5:
            continue
        match = re.search(r":([0-9]+)$", columns[4])
        if not match:
            continue
        address = columns[4][: match.start()]
        normalized = address.strip("[]")
        if normalized in {"127.0.0.1", "::1"}:
            scope = "loopback"
            address_class = "loopback"
        elif address in {"0.0.0.0", "*", "[::]", "::"}:
            scope = "wildcard"
            address_class = "wildcard"
        else:
            scope = "specific"
            try:
                parsed = ipaddress.ip_address(normalized.split("%", 1)[0])
                if parsed.is_loopback:
                    address_class = "loopback"
                elif parsed.is_private:
                    address_class = "private"
                elif parsed.is_link_local:
                    address_class = "link_local"
                elif parsed.is_global:
                    address_class = "global"
                else:
                    address_class = "other"
            except ValueError:
                address_class = "other"
        observed.add((columns[0], int(match.group(1)), scope, address_class))
    return [
        {
            "protocol": protocol,
            "port": port,
            "scope": scope,
            "address_class": address_class,
        }
        for protocol, port, scope, address_class in sorted(observed)
    ]


def iptables_vpn_data_path(
    rules: str, counter_rules: str
) -> dict[str, Any]:
    """Return address-free VPN forwarding and NAT proof from iptables-save."""

    def present(pattern: str) -> bool:
        return bool(re.search(pattern, rules, re.M))

    def packet_total(pattern: str) -> int:
        total = 0
        for line in counter_rules.splitlines():
            match = re.match(r"^\[([0-9]+):[0-9]+\]\s+(.*)$", line)
            if match and re.search(pattern, match.group(2)):
                total += int(match.group(1))
        return total

    forward_accept = r"^-A WINVPN-FORWARD\b.*-i awg0\b.*-o \S+\b.*-j ACCEPT\b"
    forward_return = (
        r"^-A WINVPN-FORWARD\b.*--ctstate "
        r"(?:RELATED,ESTABLISHED|ESTABLISHED,RELATED)\b.*-j ACCEPT\b"
    )
    masquerade = (
        r"^-A WINVPN-NAT-POSTROUTING\b.*-s \S+\b.*-o \S+\b"
        r".*-j MASQUERADE\b"
    )
    return {
        "counter_inspection_complete": bool(counter_rules),
        "forward_chain_present": present(r"^:WINVPN-FORWARD\b"),
        "nat_postrouting_chain_present": present(
            r"^:WINVPN-NAT-POSTROUTING\b"
        ),
        "forward_jump_in_awg0": present(
            r"^-A FORWARD\b.*-i awg0\b.*-j WINVPN-FORWARD\b"
        ),
        "forward_jump_out_awg0": present(
            r"^-A FORWARD\b.*-o awg0\b.*-j WINVPN-FORWARD\b"
        ),
        "forward_return_established_accept": present(forward_return),
        "forward_awg0_to_wan_accept": present(forward_accept),
        "masquerade_present": present(masquerade),
        "dns_udp_redirect_present": present(
            r"^-A WINVPN-NAT-PREROUTING\b.*-i awg0\b.*-p udp\b"
            r".*--dport 53\b.*-j REDIRECT\b"
        ),
        "dns_tcp_redirect_present": present(
            r"^-A WINVPN-NAT-PREROUTING\b.*-i awg0\b.*-p tcp\b"
            r".*--dport 53\b.*-j REDIRECT\b"
        ),
        "tcp_mss_policy_present": present(
            r"^-A WINVPN-MANGLE-FORWARD\b.*--tcp-flags SYN,RST SYN\b"
            r".*-j TCPMSS\b"
        ),
        "forward_awg0_to_wan_packets": packet_total(forward_accept),
        "forward_return_packets": packet_total(forward_return),
        "masquerade_packets": packet_total(masquerade),
    }


def iptables_origin_exposure(rules: str) -> dict[str, Any]:
    """Summarize hub ingress exposure without emitting source networks."""

    ssh_rules: list[str] = []
    web_rules: list[str] = []
    for line in rules.splitlines():
        if not line.startswith("-A WINVPN-HUB-INPUT ") or "-j ACCEPT" not in line:
            continue
        if re.search(r"(?:--dport|--dports)\s+(?:[^ ]*,)?22(?:,|\s)", line):
            ssh_rules.append(line)
        if (
            re.search(r"--dport\s+(?:80|443)(?:\s|$)", line)
            or re.search(r"--dports\s+(?:80,443|443,80)(?:\s|$)", line)
        ):
            web_rules.append(line)

    def source_restricted(line: str) -> bool:
        return bool(re.search(r"(?:^|\s)-s\s+\S+", line))

    return {
        "hub_input_chain_present": bool(
            re.search(r"^:WINVPN-HUB-INPUT\b", rules, re.M)
        ),
        "hub_input_jump_present": bool(
            re.search(
                r"^-A INPUT\b.*-j WINVPN-HUB-INPUT\b", rules, re.M
            )
        ),
        "hub_input_terminal_drop_present": bool(
            re.search(r"^-A WINVPN-HUB-INPUT\s+-j DROP\b", rules, re.M)
        ),
        "ssh_accept_rule_count": len(ssh_rules),
        "ssh_source_restricted_rule_count": sum(
            source_restricted(line) for line in ssh_rules
        ),
        "ssh_unrestricted_accept_present": any(
            not source_restricted(line) for line in ssh_rules
        ),
        "web_accept_rule_count": len(web_rules),
        "web_source_restricted_rule_count": sum(
            source_restricted(line) for line in web_rules
        ),
        "web_unrestricted_accept_present": any(
            not source_restricted(line) for line in web_rules
        ),
    }


def firewall() -> tuple[dict[str, Any], str, str, str]:
    nft = run(["nft", "list", "ruleset"], 20)[1]
    iptables = run(["iptables-save"], 20)[1]
    iptables_counters = run(["iptables-save", "-c"], 20)[1]
    ip6tables = run(["ip6tables-save"], 20)[1]
    combined = nft + "\n" + iptables
    inspected = bool(nft or iptables or ip6tables)
    result = {
        "inspection_complete": inspected,
        "nft_sha256": hashlib.sha256(nft.encode()).hexdigest() if nft else "",
        "iptables_sha256": hashlib.sha256(iptables.encode()).hexdigest()
        if iptables
        else "",
        "ip6tables_sha256": hashlib.sha256(ip6tables.encode()).hexdigest()
        if ip6tables
        else "",
        "input_drop": (
            bool(re.search(r"hook input[^}]*policy drop", nft, re.I | re.S))
            or ":INPUT DROP" in iptables
        )
        if inspected
        else None,
        "forward_drop": (
            bool(re.search(r"hook forward[^}]*policy drop", nft, re.I | re.S))
            or ":FORWARD DROP" in iptables
        )
        if inspected
        else None,
        "output_drop_ipv6": (
            ":OUTPUT DROP" in ip6tables
            or bool(
                re.search(
                    r"family ip6[\s\S]*hook output[^}]*policy drop", nft, re.I
                )
            )
        )
        if inspected
        else None,
        "nfqueue0_rules": len(
            re.findall(r"(?:queue num 0|--queue-num 0)", combined)
        ),
        "queue_bypass": bool(
            re.search(r"queue[-_ ]bypass|--queue-bypass", combined, re.I)
        ),
        "ipv4_forward": run(["sysctl", "-n", "net.ipv4.ip_forward"])[1],
        "ipv6_disabled": run(
            ["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"]
        )[1],
        "vpn_interface_awg0_present": run(
            ["ip", "link", "show", "dev", "awg0"]
        )[0]
        == 0,
        "default_route_present": bool(
            run(["ip", "route", "show", "default"])[1]
        ),
        "vpn_data_path": iptables_vpn_data_path(
            iptables, iptables_counters
        ),
        "origin_exposure": iptables_origin_exposure(iptables),
    }
    return result, nft, iptables, ip6tables


def resolve_suricata_rule_paths(
    config_path: pathlib.Path,
    yaml_loader: Callable[[str], Any] | None = None,
) -> tuple[list[pathlib.Path], list[str], str, str]:
    """Resolve only configured Suricata rules, or fail inconclusive.

    Never substitute installer-default paths after a parser/config error: that
    could turn drift into a false green release result.
    """

    try:
        if yaml_loader is None:
            import yaml  # type: ignore

            yaml_loader = yaml.safe_load
        data = yaml_loader(config_path.read_text(errors="strict")) or {}
        if not isinstance(data, dict):
            raise TypeError("suricata_config_not_mapping")
        default_value = str(data.get("default-rule-path") or "").strip()
        configured = data.get("rule-files")
        if not default_value or not isinstance(configured, list) or not configured:
            raise ValueError("suricata_rule_contract_missing")
        default_rule_path = pathlib.Path(default_value)
        if default_rule_path.is_symlink():
            raise ConfiguredRuleInvalid("default_rule_path_symlink")
        declared_root = default_rule_path.resolve()
        names: list[str] = []
        resolved: list[pathlib.Path] = []
        for value in configured:
            name = str(value).strip()
            if not name:
                raise ValueError("suricata_rule_name_empty")
            names.append(pathlib.Path(name).name)
            pattern = pathlib.Path(name)
            if not pattern.is_absolute():
                pattern = default_rule_path / pattern
            matches: list[pathlib.Path] = []
            for item in glob.glob(str(pattern)):
                candidate = pathlib.Path(item)
                info = candidate.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                    raise ConfiguredRuleInvalid("configured_rule_not_regular")
                resolved_path = candidate.resolve()
                try:
                    resolved_path.relative_to(declared_root)
                except ValueError as exc:
                    raise ConfiguredRuleInvalid(
                        "configured_rule_outside_declared_path"
                    ) from exc
                matches.append(resolved_path)
            if not matches:
                raise FileNotFoundError("configured_suricata_rule_unresolved")
            resolved.extend(matches)
        tree = (
            "runtime"
            if str(default_rule_path).startswith("/var/lib/suricata/rules")
            else "other"
        )
        return sorted(set(resolved)), sorted(set(names)), tree, ""
    except Exception as exc:
        return [], [], "unresolved", type(exc).__name__


def read_configured_rule(path: pathlib.Path) -> str:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ConfiguredRuleInvalid("configured_rule_not_regular")
    data = path.read_bytes()
    after = path.lstat()
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_mode,
    )
    if before_identity != after_identity:
        raise ConfiguredRuleRaced("configured_rule_changed_during_read")
    return data.decode("utf-8", errors="replace")


def suricata(firewall_state: dict[str, Any]) -> dict[str, Any]:
    rule_paths: list[pathlib.Path] = []
    configured_rule_names: list[str] = []
    configured_rule_tree = "unknown"
    config_path = pathlib.Path("/etc/suricata/suricata.yaml")
    (
        rule_paths,
        configured_rule_names,
        configured_rule_tree,
        resolution_error,
    ) = resolve_suricata_rule_paths(config_path)
    policy_conclusive = not resolution_error and bool(rule_paths)
    actions = {"alert": 0, "drop": 0, "reject": 0, "pass": 0}
    drop_sids = []
    sid_2210057_locations: list[dict[str, Any]] = []
    configured_payloads: list[tuple[pathlib.Path, str]] = []
    if policy_conclusive:
        try:
            configured_payloads = [
                (path, read_configured_rule(path)) for path in sorted(set(rule_paths))
            ]
        except Exception as exc:
            policy_conclusive = False
            resolution_error = type(exc).__name__
            configured_payloads = []
    for path, payload in configured_payloads:
        try:
            lines = payload.splitlines()
        except Exception as exc:
            policy_conclusive = False
            resolution_error = type(exc).__name__
            actions = {"alert": 0, "drop": 0, "reject": 0, "pass": 0}
            drop_sids = []
            sid_2210057_locations = []
            break
        for line in lines:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            action = value.split(None, 1)[0].lower()
            if action in actions:
                actions[action] += 1
            sid_match = re.search(r"\bsid\s*:\s*([0-9]+)", value)
            if sid_match and int(sid_match.group(1)) == 2210057:
                sid_2210057_locations.append(
                    {"tree": "configured", "action": action, "loaded": True}
                )
            if action == "drop":
                if sid_match:
                    drop_sids.append(int(sid_match.group(1)))
    if policy_conclusive:
        packaged = pathlib.Path("/etc/suricata/rules")
        try:
            for path in packaged.glob("*.rules"):
                if path.resolve() in rule_paths:
                    continue
                for line in path.read_text(errors="replace").splitlines():
                    if not re.search(r"\bsid\s*:\s*2210057\b", line):
                        continue
                    match = re.match(r"^\s*([A-Za-z]+)", line)
                    sid_2210057_locations.append(
                        {
                            "tree": "packaged",
                            "action": match.group(1).lower() if match else "unknown",
                            "loaded": False,
                        }
                    )
        except OSError:
            pass
    version = run(["suricata", "-V"], 20)[1]
    return {
        "installed": run(["sh", "-c", "command -v suricata >/dev/null"])[0] == 0,
        "version": version.splitlines()[:1],
        "config_test_passed": run(
            ["suricata", "-T", "-c", "/etc/suricata/suricata.yaml"], 90
        )[0]
        == 0,
        "action_policy_conclusive": policy_conclusive,
        "rule_resolution_error": resolution_error,
        "actions": actions if policy_conclusive else None,
        "drop_sids": sorted(set(drop_sids)) if policy_conclusive else None,
        "configured_rule_tree": configured_rule_tree,
        "configured_rule_files": sorted(set(configured_rule_names)),
        "sid_2210057_locations": sid_2210057_locations
        if policy_conclusive
        else [],
        "nfqueue0": firewall_state["nfqueue0_rules"] > 0,
        "queue_bypass": firewall_state["queue_bypass"],
    }


def adguard(listener_state: list[dict[str, Any]]) -> dict[str, Any]:
    path = pathlib.Path("/opt/AdGuardHome/AdGuardHome.yaml")
    state = file_state(str(path))
    installed = state.get("exists") is True
    result: dict[str, Any] = {"installed": installed, "config": state}
    if installed:
        text = path.read_text(errors="replace")
        result.update(
            {
                "quad9": "dns.quad9.net" in text or "9.9.9.9" in text,
                "opendns": "doh.opendns.com" in text or "208.67.222.222" in text,
                "public_port53": any(
                    item["port"] == 53
                    and item["address_class"] in {"global", "wildcard"}
                    for item in listener_state
                ),
                "private_port53": any(
                    item["port"] == 53 and item["address_class"] == "private"
                    for item in listener_state
                ),
            }
        )
    return result


def ssh_policy() -> dict[str, str]:
    returncode, output, _ = run(["sshd", "-T"], 20)
    wanted = {
        "permitrootlogin",
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "pubkeyauthentication",
        "allowtcpforwarding",
    }
    result = {"inspection_complete": str(returncode == 0).lower()}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in wanted:
            result[parts[0]] = parts[1]
    return result


def role_files(role: str) -> list[str]:
    common = ["/etc/rclone.conf", "/root/.config/rclone/rclone.conf"]
    if role == "control":
        return common + [
            "/root/vpn_auth/main.py",
            "/etc/systemd/system/wins-hub.service",
            "/etc/nginx/sites-available/wins-hub.conf",
            "/etc/systemd/system/wins-control-tunnel.service",
            "/usr/local/bin/wins-gateway-canary",
            "/usr/local/bin/wins-winn3-canary-requests",
            "/usr/local/bin/wins-security-alert-monitor",
            "/usr/local/bin/wins-paypal-sync",
            "/usr/local/bin/wins-hub-backup",
            "/usr/local/bin/wins-hub-restore-preflight",
            "/etc/winsvpn/hub-install-contract.env",
            "/etc/systemd/zram-generator.conf",
            "/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf",
        ]
    if role == "data":
        return common + [
            "/usr/local/bin/wins-edge-hardening",
            "/usr/local/bin/wins-node-canary",
            "/usr/local/bin/wins-node-backup",
            "/usr/local/bin/wins-node-restore-preflight",
            "/etc/winsvpn/node-install-contract.env",
            "/etc/systemd/system/suricata.service.d/30-wins-inline-ips.conf",
            "/etc/systemd/system/wins-node-management-tunnel.service",
            "/etc/systemd/system/xray.service",
            "/etc/nginx/sites-available/wins-node.conf",
        ]
    return common + [
        "/usr/local/bin/wins-core-sync",
        "/etc/systemd/system/wins-core-management-tunnel.service",
        "/etc/systemd/system/xray.service",
        "/etc/nginx/sites-available/wins-core.conf",
    ]


def role_units(role: str) -> list[str]:
    if role == "control":
        return [
            "wins-hub.service",
            "nginx.service",
            "wins-control-tunnel.service",
            "suricata.service",
            "fail2ban.service",
            "wins-security-alert-monitor.timer",
            "wins-threat-triage-report.timer",
            "wins-suricata-update.timer",
            "wins-weekly-maintenance.timer",
            "wins-gateway-canary.timer",
            "wins-winn3-canary-requests.path",
            "wins-winn3-canary-requests.service",
            "wins-paypal-sync.timer",
            "wins-hub-backup.timer",
            "wins-hub-backup.service",
            "unattended-upgrades.service",
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
        ]
    if role == "data":
        return [
            "docker.service",
            "nginx.service",
            "xray.service",
            "AdGuardHome.service",
            "suricata.service",
            "fail2ban.service",
            "wins-node-management-tunnel.service",
            "wins-node-register.timer",
            "wins-node-canary.timer",
            "wins-node-backup.timer",
            "wins-node-backup.service",
            "wins-edge-hardening.timer",
            "wins-suricata-update.timer",
            "wins-weekly-maintenance.timer",
        ]
    return [
        "docker.service",
        "nginx.service",
        "xray.service",
        "fail2ban.service",
        "ollama.service",
        "wins-core-management-tunnel.service",
        "wins-core-sync.service",
        "wins-core-sync.timer",
        "wins-core-ai-tunnel.service",
        "wins-core-performance-mode.service",
    ]


def hardening(role: str) -> dict[str, str]:
    service = {"control": "wins-hub.service", "data": "xray.service", "core": "xray.service"}[role]
    return {
        prop: run(["systemctl", "show", service, "-p", prop, "--value"], 8)[1]
        for prop in (
            "User",
            "Group",
            "NoNewPrivileges",
            "ProtectSystem",
            "ProtectHome",
            "PrivateTmp",
            "PrivateDevices",
            "RestrictSUIDSGID",
            "RestrictNamespaces",
            "RestrictAddressFamilies",
            "LockPersonality",
            "MemoryDenyWriteExecute",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "SystemCallArchitectures",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "ProtectControlGroups",
            "ProtectClock",
            "ProtectHostname",
            "LimitNOFILE",
            "TasksMax",
        )
    }


def control_integration_material(
    path: pathlib.Path = pathlib.Path("/root/vpn_auth/.env"),
    *,
    require_root_owner: bool = True,
    enforce_owner_only: bool = True,
) -> dict[str, Any]:
    """Report only secret presence and contract booleans, never values."""

    result: dict[str, Any] = {
        "environment_present": False,
        "environment_owner_only": False,
        "secret_values_emitted": False,
    }
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return result
        result["environment_present"] = True
        result["environment_owner_only"] = (
            not enforce_owner_only
            or (
                (not require_root_owner or info.st_uid == 0)
                and stat.S_IMODE(info.st_mode) & 0o077 == 0
            )
        )
        if not result["environment_owner_only"]:
            return result
        values: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8", errors="strict").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
                raw = value.strip()
                if len(raw) >= 2 and raw.startswith("'") and raw.endswith("'"):
                    raw = raw[1:-1].replace("'\"'\"'", "'")
                values[key] = raw
    except Exception as exc:
        result["inspection_error"] = type(exc).__name__
        return result

    def present(key: str) -> bool:
        return bool(values.get(key, ""))

    paypal_webhook = urllib.parse.urlsplit(values.get("PAYPAL_WEBHOOK_URL", ""))
    paypal_urls = (
        "PAYPAL_LIFETIME_SUPPORT_URL",
        "PAYPAL_LIFETIME_NO_SUPPORT_URL",
    )
    paypal_hosted_urls_valid = all(
        (lambda parsed: parsed.scheme == "https" and bool(parsed.hostname)
         and (
             parsed.hostname == "paypal.com"
             or parsed.hostname.endswith(".paypal.com")
         ))(urllib.parse.urlsplit(values.get(key, "")))
        for key in paypal_urls
    )
    smtp_server_matches = (
        values.get("SMTP_SERVER", "").lower() == "mail.smtp2go.com"
    )
    smtp_port_supported = values.get("SMTP_PORT", "") in {
        "25", "80", "2525", "587", "8025"
    }
    smtp_user_present = present("SMTP_USER")
    smtp_pass_present = present("SMTP_PASS")
    smtp_complete = all(
        (
            smtp_server_matches,
            smtp_port_supported,
            smtp_user_present,
            smtp_pass_present,
        )
    )
    paypal_complete = all(
        (
            values.get("PAYPAL_MODE", "").lower() == "live",
            present("PAYPAL_PUBLIC_CLIENT_ID"),
            present("PAYPAL_CLIENT_ID"),
            values.get("PAYPAL_PUBLIC_CLIENT_ID", "")
            == values.get("PAYPAL_CLIENT_ID", ""),
            present("PAYPAL_CLIENT_SECRET"),
            present("PAYPAL_WEBHOOK_ID"),
            values.get("PAYPAL_WEBHOOK_AUTO_ENSURE", "") == "1",
            values.get("PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS", "").lower()
            != "true",
            paypal_webhook.scheme == "https",
            bool(paypal_webhook.hostname),
            paypal_webhook.path == "/webhook/paypal",
            all(
                present(key)
                for key in (
                    "PAYPAL_PLAN_1M",
                    "PAYPAL_PLAN_1Y",
                    "PAYPAL_PLAN_PERSONAL",
                    "PAYPAL_LIFETIME_SUPPORT_AMOUNT",
                    "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT",
                )
            ),
            values.get("PAYPAL_LIFETIME_CURRENCY", "").isalpha(),
            len(values.get("PAYPAL_LIFETIME_CURRENCY", "")) == 3,
            paypal_hosted_urls_valid,
        )
    )
    cloudflare_complete = all(
        present(key)
        for key in (
            "CLOUDFLARE_TUNNEL_ACCOUNT_ID",
            "CLOUDFLARE_TUNNEL_API_TOKEN",
            "CLOUDFLARE_WINS_API_TOKEN",
            "CLOUDFLARE_WINSVPN_ORG_ZONE_ID",
            "CLOUDFLARE_WINSVPN_COM_ZONE_ID",
            "CLOUDFLARE_ACCESS_API_TOKEN",
            "CLOUDFLARE_ACCESS_SERVICE_TOKEN_UUID",
        )
    )
    gist_required = values.get(
        "ENABLE_ACTIVE_GATEWAY_GIST_WRITE", "0"
    ) == "1"
    gist_complete = present("GITHUB_GIST_TOKEN") and present(
        "ACTIVE_GATEWAY_GIST_ID"
    )
    admin_present = present("ADMIN_TOKEN")
    result.update(
        {
            "admin_token_present": admin_present,
            "smtp2go_server_matches": smtp_server_matches,
            "smtp2go_port_supported": smtp_port_supported,
            "smtp2go_username_present": smtp_user_present,
            "smtp2go_password_present": smtp_pass_present,
            "smtp2go_complete": smtp_complete,
            "paypal_mode_live": values.get("PAYPAL_MODE", "").lower()
            == "live",
            "paypal_public_client_id_present": present(
                "PAYPAL_PUBLIC_CLIENT_ID"
            ),
            "paypal_client_id_present": present("PAYPAL_CLIENT_ID"),
            "paypal_client_ids_match": bool(
                present("PAYPAL_PUBLIC_CLIENT_ID")
                and values.get("PAYPAL_PUBLIC_CLIENT_ID", "")
                == values.get("PAYPAL_CLIENT_ID", "")
            ),
            "paypal_client_secret_present": present("PAYPAL_CLIENT_SECRET"),
            "paypal_webhook_url_valid": all(
                (
                    paypal_webhook.scheme == "https",
                    bool(paypal_webhook.hostname),
                    paypal_webhook.path == "/webhook/paypal",
                )
            ),
            "paypal_plan_1m_present": present("PAYPAL_PLAN_1M"),
            "paypal_plan_1y_present": present("PAYPAL_PLAN_1Y"),
            "paypal_plan_personal_present": present("PAYPAL_PLAN_PERSONAL"),
            "paypal_lifetime_urls_valid": paypal_hosted_urls_valid,
            "paypal_lifetime_support_amount_present": present(
                "PAYPAL_LIFETIME_SUPPORT_AMOUNT"
            ),
            "paypal_lifetime_no_support_amount_present": present(
                "PAYPAL_LIFETIME_NO_SUPPORT_AMOUNT"
            ),
            "paypal_lifetime_currency_valid": (
                values.get("PAYPAL_LIFETIME_CURRENCY", "").isalpha()
                and len(values.get("PAYPAL_LIFETIME_CURRENCY", "")) == 3
            ),
            "paypal_live_complete": paypal_complete,
            "paypal_webhook_material_present": present("PAYPAL_WEBHOOK_ID"),
            "paypal_unverified_webhooks_forbidden": values.get(
                "PAYPAL_ALLOW_UNVERIFIED_WEBHOOKS", ""
            ).lower()
            != "true",
            "cloudflare_management_complete": cloudflare_complete,
            "gist_write_required": gist_required,
            "gist_write_complete": gist_complete if gist_required else True,
            "one_touch_material_complete": all(
                (
                    admin_present,
                    smtp_complete,
                    paypal_complete,
                    cloudflare_complete,
                    gist_complete if gist_required else True,
                )
            ),
        }
    )
    return result


def database_summary(include_targets: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    summary: dict[str, Any] = {}
    targets: dict[str, Any] = {}
    path = pathlib.Path("/root/vpn_auth/vpn_users.db")
    if not path.exists():
        return summary, targets
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        summary["integrity_ok"] = connection.execute("pragma integrity_check").fetchone()[0] == "ok"
        tables = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type='table'"
            )
        }
        for table in ("nodes", "core_servers", "double_vpn_assignments"):
            if table in tables:
                summary[f"{table}_count"] = connection.execute(
                    f"select count(*) from {table}"
                ).fetchone()[0]
        for table, target_name, online_name in (
            ("nodes", "data", "online_nodes"),
            ("core_servers", "core", "online_cores"),
        ):
            if table not in tables:
                continue
            columns = {
                row[1] for row in connection.execute(f"pragma table_info({table})")
            }
            selected = [
                name
                for name in (
                    "slug",
                    "core_id",
                    "status",
                    "runtime_ready",
                    "management_status",
                    "management_ssh_host",
                    "management_host",
                    "ssh_host",
                    "ssh_port",
                    "peer_count",
                    "max_peers",
                    "current_peers",
                    "max_customers",
                )
                if name in columns
            ]
            rows = [
                dict(row)
                for row in connection.execute(
                    f"select {','.join(selected)} from {table}"
                )
            ]
            online = [
                row
                for row in rows
                if row.get("status") == "online"
                and row.get("management_status") == "ok"
            ]
            summary[online_name] = len(online)
            summary[f"management_healthy_{target_name}"] = sum(
                1 for row in rows if row.get("management_status") == "ok"
            )
            if target_name == "core":
                summary["runtime_ready_cores"] = sum(
                    1 for row in rows if bool(row.get("runtime_ready"))
                )
            if include_targets and rows:
                # Reachability diagnosis must still be possible after a
                # heartbeat expires. Prefer an online record, then a record
                # with a managed SSH host, without ever printing the address
                # in the default probe output.
                managed = [
                    row
                    for row in rows
                    if str(
                        row.get("management_ssh_host")
                        or row.get("management_host")
                        or row.get("ssh_host")
                        or ""
                    ).strip()
                ]
                candidates = online or managed or rows
                targets[target_name] = candidates[0]
        connection.close()
    except Exception as exc:
        summary["error"] = type(exc).__name__
    return summary, targets


def role_runtime(role: str, listener_state: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if role == "data":
        result["xray_version"] = run(["xray", "version"], 15)[1].splitlines()[:1]
        result["adguard_version"] = run(
            ["/opt/AdGuardHome/AdGuardHome", "--version"], 15
        )[1].splitlines()[:1]
        result["awg_container_running"] = (
            run(["docker", "inspect", "-f", "{{.State.Running}}", "amnezia-awg2"], 15)[1]
            == "true"
        )
        interfaces = run(
            ["docker", "exec", "amnezia-awg2", "awg", "show", "interfaces"], 15
        )[1].split()
        result["awg_interfaces"] = sorted(interfaces)
        result["awg_peer_count"] = len(
            run(
                ["docker", "exec", "amnezia-awg2", "awg", "show", "awg0", "peers"],
                15,
            )[1].splitlines()
        )
        result["deployment_ready"] = pathlib.Path(
            "/var/lib/winsvpn/node-deployment-ready"
        ).is_file()
    elif role == "core":
        result["xray_version"] = run(["xray", "version"], 15)[1].splitlines()[:1]
        result["core_interfaces"] = sorted(
            run(["sh", "-c", "ip -o link show | sed -n 's/^[0-9]*: \\(corex[0-9]*\\):.*/\\1/p'"], 15)[1].splitlines()
        )
    result["expected_public_ports_present"] = {
        str(port): any(
            item["port"] == port and item["scope"] != "loopback"
            for item in listener_state
        )
        for port in ({9110, 80, 443} if role == "data" else ({9210, 80, 443} if role == "core" else set()))
    }
    return result


def main() -> int:
    role_path = pathlib.Path("/etc/winsvpn/role")
    role_override = os.getenv("WINS_PROBE_ROLE_OVERRIDE", "").strip()
    marker_exists: bool | str
    try:
        marker_exists = role_path.is_file()
    except OSError:
        marker_exists = "unknown"
    marker_readable = False
    marker_value = ""
    if marker_exists is True:
        try:
            marker_value = role_path.read_text().strip()
            marker_readable = True
        except OSError:
            pass
    role = marker_value or role_override
    if role not in {"control", "data", "core"}:
        raise SystemExit("role marker is invalid")
    os_release = {}
    for line in pathlib.Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    listener_state = listeners()
    firewall_state, _, _, _ = firewall()
    include_targets = os.getenv("WINS_PROBE_INCLUDE_MANAGEMENT_TARGETS") == "1"
    if role == "control":
        database, management_targets = database_summary(include_targets)
    else:
        database, management_targets = {}, {}
    result = {
        "schema_version": 1,
        "contract": "winsvpn-infrastructure-readonly-probe-v1",
        "role": role,
        "role_marker": {
            "exists": marker_exists,
            "readable": marker_readable,
            "matches": marker_value == role if marker_value else False,
        },
        "captured_epoch": int(time.time()),
        "os": {
            "id": os_release.get("ID"),
            "version": os_release.get("VERSION_ID"),
            "kernel": os.uname().release,
        },
        "resources": resources(),
        "storage": storage(),
        "ssh_policy": ssh_policy(),
        "services": {name: unit(name) for name in role_units(role)},
        "listeners": listener_state,
        "firewall": firewall_state,
        "suricata": suricata(firewall_state),
        "adguard": adguard(listener_state),
        "files": {path: file_state(path) for path in role_files(role)},
        "hardening": hardening(role),
        "database": database,
        "runtime": role_runtime(role, listener_state),
        "integrations": control_integration_material()
        if role == "control"
        else {},
    }
    if include_targets:
        result["management_targets"] = management_targets
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        frame = exc.__traceback__
        while frame and frame.tb_next:
            frame = frame.tb_next
        print(
            json.dumps(
                {
                    "schema_version": 1,
                    "contract": "winsvpn-infrastructure-readonly-probe-v1",
                    "role": os.getenv("WINS_PROBE_ROLE_OVERRIDE", "unknown"),
                    "probe_error": {
                        "type": type(exc).__name__,
                        "function": frame.tb_frame.f_code.co_name if frame else "unknown",
                        "line": frame.tb_lineno if frame else 0,
                    },
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
