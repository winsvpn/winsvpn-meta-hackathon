#!/usr/bin/env python3
"""Sanitized, mutation-free diagnosis for a Win's VPN Core sync failure.

Run through infrastructure_readonly_relay.py. The result contains only
allow-listed systemd properties and source-defined failure classes. Raw logs,
addresses, endpoint metadata, keys, and assignment identifiers are never
returned.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import time


def run(args: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=timeout,
        )
        return result.returncode, result.stdout
    except Exception:
        return 255, ""


def service_properties() -> dict[str, str]:
    allowed = (
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainCode",
        "ExecMainStatus",
        "NRestarts",
        "InactiveExitTimestamp",
        "ActiveEnterTimestamp",
    )
    # Fetch the allow-listed properties atomically. Besides avoiding a
    # time-of-check/time-of-use mixture, one bounded systemctl call keeps the
    # diagnostic usable across a higher-latency restricted SSH relay.
    args = ["systemctl", "show", "wins-core-sync.service"]
    for name in allowed:
        args.extend(["-p", name])
    rc, output = run(args, 12)
    parsed: dict[str, str] = {}
    if rc == 0:
        for line in output.splitlines():
            if "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name in allowed and name not in parsed:
                parsed[name] = value.strip()[:128]
    values = {name: parsed.get(name, "") for name in allowed}
    return values


RUNTIME_VALIDATION_CLASSES = (
    "assignment_identity_invalid",
    "assignment_routing_metadata_invalid",
    "assignment_revision_invalid",
    "ingress_peer_missing",
    "ingress_allowed_ip_mismatch",
    "ingress_psk_mismatch",
    "client_policy_rule_mismatch",
    "exit_default_route_mismatch",
    "ingress_container_down",
    "ingress_key_mismatch",
    "ingress_stale_peer_present",
    "exit_interface_invalid",
    "exit_container_down",
    "exit_key_mismatch",
    "exit_transport_state_invalid",
    "exit_stealth_config_missing",
    "exit_stealth_config_invalid",
    "exit_stealth_service_inactive",
    "exit_handshake_stale",
    "exit_handshake_recovery_failed",
    "forwarding_firewall_rule_missing",
    "nat_firewall_rule_missing",
    "assignment_runtime_invalid",
)


HANDSHAKE_RECOVERY_CLASSES = (
    "exit_handshake_recovery_non_stealth",
    "exit_handshake_recovery_cooldown",
    "exit_handshake_recovery_stamp_create_failed",
    "exit_handshake_recovery_stamp_write_failed",
    "exit_handshake_recovery_stamp_permissions_failed",
    "exit_handshake_recovery_stamp_install_failed",
    "exit_handshake_recovery_xray_restart_failed",
    "exit_handshake_recovery_xray_inactive",
    "exit_handshake_recovery_container_restart_failed",
    "exit_handshake_recovery_interface_missing_after_restart",
    "exit_handshake_recovery_route_metadata_invalid",
    "exit_handshake_recovery_route_restore_failed",
    "exit_handshake_recovery_timeout",
)


FAILURE_PATTERNS = (
    ("assignment_payload_invalid", r"assignment synchronization failed class=assignment_payload_invalid"),
    ("exit_interface_setup_failed", r"assignment synchronization failed class=exit_interface_setup_failed"),
    ("ingress_peer_update_failed", r"assignment synchronization failed class=ingress_peer_update_failed"),
    ("client_policy_rule_update_failed", r"assignment synchronization failed class=client_policy_rule_update_failed"),
    ("exit_metadata_invalid", r"Core exit setup failed class=exit_metadata_invalid"),
    ("exit_state_directory_failed", r"Core exit setup failed class=exit_state_directory_failed"),
    ("exit_local_port_invalid", r"Core exit setup failed class=exit_local_port_invalid"),
    ("exit_xray_selection_failed", r"Core exit setup failed class=exit_xray_selection_failed"),
    ("exit_transport_state_write_failed", r"Core exit setup failed class=exit_transport_state_write_failed"),
    ("exit_config_staging_failed", r"Core exit setup failed class=exit_config_staging_failed"),
    ("exit_container_replace_failed", r"Core exit setup failed class=exit_container_replace_failed"),
    ("exit_config_install_failed", r"Core exit setup failed class=exit_config_install_failed"),
    ("exit_image_unavailable", r"Core exit setup failed class=exit_image_unavailable"),
    ("exit_container_start_failed", r"Core exit setup failed class=exit_container_start_failed"),
    ("exit_interface_restart_failed", r"Core exit setup failed class=exit_interface_restart_failed"),
    ("exit_interface_missing_after_restart", r"Core exit setup failed class=exit_interface_missing_after_restart"),
    ("exit_route_update_failed", r"Core exit setup failed class=exit_route_update_failed"),
    ("management_path_failed", r"hub could not verify its outbound management path"),
    ("assignment_sync_failed", r"assignment sync failed"),
    ("assignment_set_failed", r"one or more assignments failed to synchronize"),
    (
        "runtime_validation_failed",
        r"Core remains unavailable because runtime validation failed",
    ),
    ("ingress_container_down", r"Core ingress container is not running"),
    ("ingress_key_mismatch", r"Core ingress runtime key does not match"),
    ("exit_container_down", r"Double VPN exit container is not running"),
    ("exit_key_mismatch", r"does not use the persisted Core exit key"),
    ("transport_state_invalid", r"has no validated transport state"),
    ("exit_handshake_stale", r"Double VPN exit handshake is not fresh"),
    ("xray_preflight_failed", r"Xray exit preflight (?:failed|rejected)"),
) + tuple(
    (
        name,
        rf"Core runtime validation failed class={re.escape(name)}(?:\s|$)",
    )
    for name in RUNTIME_VALIDATION_CLASSES
) + tuple(
    (
        name,
        rf"Core handshake recovery failed class={re.escape(name)}(?:\s|$)",
    )
    for name in HANDSHAKE_RECOVERY_CLASSES
)


def failure_classes() -> dict[str, object]:
    rc, text = run(
        [
            "journalctl",
            "-u",
            "wins-core-sync.service",
            "--since",
            "-20 minutes",
            "--no-pager",
            "-o",
            "cat",
            "-n",
            "500",
        ],
        20,
    )
    classes = sorted({
        name for name, pattern in FAILURE_PATTERNS if re.search(pattern, text, re.I)
    })
    allowed_stages = {
        "prerequisites",
        "management-verification",
        "assignment-fetch",
        "assignment-sync",
        "stale-cleanup",
        "runtime-validation",
        "ready-registration",
        "complete",
    }
    stages = re.findall(r"Core sync failed during stage=([a-z-]+)", text)
    latest_stage = stages[-1] if stages and stages[-1] in allowed_stages else ""
    return {
        "journal_readable": rc == 0,
        "failure_classes": classes,
        "latest_failure_stage": latest_stage,
        "unclassified_failure_present": bool(
            rc == 0
            and re.search(r"(?:failed|unavailable|not running|does not|invalid)", text, re.I)
            and not classes
        ),
    }


CORE_EXIT_STATE_DIR = Path("/etc/amnezia/wins-core")
CORE_EXIT_CONFIG_DIR = Path("/usr/local/etc/xray/core-exits")
CORE_SYNC_AGENT = Path("/usr/local/bin/wins-core-sync")
CORE_EXIT_PATTERN = re.compile(r"^corex([0-9]+)$")
MAX_OBSERVED_EXITS = 128
MAX_STATE_FILE_BYTES = 262_144
FRESH_HANDSHAKE_MAX_AGE_SECONDS = 150

XRAY_FAILURE_PATTERNS = (
    ("authentication_failure", r"(?:unauthorized|authentication failed|invalid user|rejected user)"),
    ("configuration_failure", r"(?:failed to (?:load|build|read|parse) config|invalid config)"),
    ("connection_refused", r"(?:connection refused|actively refused)"),
    ("connection_timeout", r"(?:i/o timeout|connection timed out|context deadline exceeded)"),
    ("dns_failure", r"(?:no such host|name resolution|temporary failure in name resolution)"),
    ("service_failure", r"(?:failed to start|main process exited|failed with result)"),
    ("tls_failure", r"(?:tls handshake|certificate (?:verify|verification)|unknown authority)"),
    ("transport_closed", r"(?:connection reset|broken pipe|unexpected eof|use of closed network connection)"),
    ("websocket_failure", r"(?:websocket.*(?:failed|rejected|status)|bad handshake|unexpected http response)"),
)


def _read_small_text(path: Path) -> str:
    """Read a bounded regular file without ever returning its content."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_STATE_FILE_BYTES:
            return ""
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(MAX_STATE_FILE_BYTES + 1)
    except OSError:
        return ""


def _expected_exit_names(state_dir: Path) -> tuple[list[str], bool]:
    try:
        names = sorted({
            path.stem
            for path in state_dir.glob("corex*.conf")
            if CORE_EXIT_PATTERN.fullmatch(path.stem)
        })
    except OSError:
        return [], False
    return names[:MAX_OBSERVED_EXITS], len(names) > MAX_OBSERVED_EXITS


def _transport_mode(state_dir: Path, name: str) -> str:
    text = _read_small_text(state_dir / f"{name}.transport")
    match = re.search(r"(?m)^mode=(direct|stealth)$", text)
    return match.group(1) if match else ""


def _route_table(state_dir: Path, name: str) -> str:
    text = _read_small_text(state_dir / f"{name}.conf")
    match = re.search(
        rf"(?m)^PostUp = ip route replace default dev {re.escape(name)} table ([0-9]+)$",
        text,
    )
    return match.group(1) if match else ""


def _xray_listener_port(config_dir: Path, name: str) -> int | None:
    text = _read_small_text(config_dir / f"{name}.json")
    try:
        config = json.loads(text)
        inbounds = config.get("inbounds")
        if not isinstance(inbounds, list) or len(inbounds) != 1:
            return None
        inbound = inbounds[0]
        if not isinstance(inbound, dict) or inbound.get("listen") != "127.0.0.1":
            return None
        port = inbound.get("port")
        return port if isinstance(port, int) and 1 <= port <= 65535 else None
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _xray_mux_contract(config_dir: Path, name: str) -> str:
    """Classify a config privately; return one of three allow-listed labels."""
    text = _read_small_text(config_dir / f"{name}.json")
    try:
        config = json.loads(text)
        inbounds = config.get("inbounds")
        outbounds = config.get("outbounds")
        udp_tunnel = any(
            isinstance(inbound, dict)
            and inbound.get("protocol") == "tunnel"
            and isinstance(inbound.get("settings"), dict)
            and inbound["settings"].get("network") == "udp"
            for inbound in inbounds
        )
        vless = next(
            outbound
            for outbound in outbounds
            if isinstance(outbound, dict)
            and outbound.get("protocol") == "vless"
            and outbound.get("tag") == "vless-ws-out"
        )
        mux = vless.get("mux")
        if not udp_tunnel or not isinstance(mux, dict):
            return "other"
        if (
            mux.get("enabled") is False
            and type(mux.get("concurrency")) is int
            and mux["concurrency"] == 0
            and type(mux.get("xudpConcurrency")) is int
            and mux["xudpConcurrency"] == 0
            and mux.get("xudpProxyUDP443") == "skip"
        ):
            return "native_udp"
        if (
            mux.get("enabled") is True
            and type(mux.get("concurrency")) is int
            and mux["concurrency"] == -1
            and type(mux.get("xudpConcurrency")) is int
            and mux["xudpConcurrency"] == 16
            and mux.get("xudpProxyUDP443") == "allow"
        ):
            return "legacy_xudp"
    except (AttributeError, StopIteration, TypeError, ValueError, json.JSONDecodeError):
        pass
    return "other"


def _installed_sync_agent_contract(path: Path = CORE_SYNC_AGENT) -> str:
    """Return an allow-listed contract class, never installed source content."""
    text = _read_small_text(path)
    if not text:
        return "unreadable"
    native = 'mux:{enabled:false,concurrency:0,xudpConcurrency:0,xudpProxyUDP443:"skip"}'
    legacy = 'mux:{enabled:true,concurrency:-1,xudpConcurrency:16,xudpProxyUDP443:"allow"}'
    if native in text and legacy not in text:
        return "native_udp"
    if legacy in text and native not in text:
        return "legacy_xudp"
    return "other"


def _loopback_udp_listener_ports() -> tuple[set[int], bool]:
    rc, output = run(["ss", "-H", "-l", "-u", "-n"], 8)
    ports: set[int] = set()
    if rc == 0:
        for line in output.splitlines():
            # Only retain the numeric local-loopback port. Socket details are
            # deliberately discarded and never included in the result.
            match = re.search(r"(?:^|\s)127\.0\.0\.1:([0-9]+)(?:\s|$)", line)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
    return ports, rc == 0


def _fresh_handshake(name: str, now_epoch: int) -> bool:
    rc, output = run(
        ["docker", "exec", f"wins-core-exit-{name}", "awg", "show", name, "latest-handshakes"],
        8,
    )
    if rc != 0:
        return False
    latest = 0
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[1].isdigit():
            continue
        latest = max(latest, int(fields[1]))
    return latest > 0 and 0 <= now_epoch - latest <= FRESH_HANDSHAKE_MAX_AGE_SECONDS


def _xray_journal_categories() -> tuple[list[str], bool]:
    rc, journal = run(
        [
            "journalctl",
            "--unit=wins-core-xray-exit@*.service",
            "--since",
            "-20 minutes",
            "--no-pager",
            "-o",
            "cat",
            "-n",
            "500",
        ],
        20,
    )
    categories = sorted({
        name for name, pattern in XRAY_FAILURE_PATTERNS if re.search(pattern, journal, re.I)
    })
    return categories, rc == 0


def _stale_handshake_cause(counts: dict[str, int], categories: list[str], truncated: bool) -> str:
    expected = counts["expected_exits_count"]
    stealth = counts["stealth_exits_count"]
    if truncated:
        return "observation_limit_reached"
    if expected == 0:
        return "no_expected_exits"
    if counts["running_containers_count"] < expected:
        return "exit_container_incomplete"
    if counts["host_interfaces_count"] < expected:
        return "host_interface_incomplete"
    if counts["valid_routes_count"] < expected:
        return "exit_route_incomplete"
    if counts["valid_transport_states_count"] < expected:
        return "transport_state_incomplete"
    if counts["active_xray_services_count"] < stealth:
        return "xray_service_incomplete"
    if counts["valid_xray_configs_count"] < stealth:
        return "xray_config_incomplete"
    if counts["local_loopback_listeners_count"] < stealth:
        return "xray_listener_incomplete"
    if counts["fresh_handshakes_count"] < expected:
        return "xray_runtime_failure" if stealth and categories else "transport_ready_handshake_stale"
    return "healthy"


def transport_predicates(
    state_dir: Path = CORE_EXIT_STATE_DIR,
    config_dir: Path = CORE_EXIT_CONFIG_DIR,
    now_epoch: int | None = None,
    sync_agent: Path = CORE_SYNC_AGENT,
) -> dict[str, object]:
    """Return only aggregate, allow-listed transport health observations."""
    names, truncated = _expected_exit_names(state_dir)
    now = int(time.time()) if now_epoch is None else now_epoch
    listener_ports, listeners_readable = _loopback_udp_listener_ports()
    categories, xray_journal_readable = _xray_journal_categories()
    counts = {
        "expected_exits_count": len(names),
        "running_containers_count": 0,
        "host_interfaces_count": 0,
        "valid_routes_count": 0,
        "valid_transport_states_count": 0,
        "stealth_exits_count": 0,
        "active_xray_services_count": 0,
        "valid_xray_configs_count": 0,
        "native_udp_mux_disabled_configs_count": 0,
        "legacy_xudp_enabled_configs_count": 0,
        "other_mux_configs_count": 0,
        "local_loopback_listeners_count": 0,
        "fresh_handshakes_count": 0,
    }
    for name in names:
        container = f"wins-core-exit-{name}"
        running_rc, running = run(["docker", "inspect", "-f", "{{.State.Running}}", container], 8)
        if running_rc == 0 and running.strip() == "true":
            counts["running_containers_count"] += 1
        if run(["ip", "link", "show", "dev", name], 8)[0] == 0:
            counts["host_interfaces_count"] += 1
        table = _route_table(state_dir, name)
        if table:
            route_rc, route = run(["ip", "-4", "route", "show", "table", table, "default"], 8)
            if route_rc == 0 and re.search(rf"(?:^|\s)dev {re.escape(name)}(?:\s|$)", route):
                counts["valid_routes_count"] += 1
        mode = _transport_mode(state_dir, name)
        if mode:
            counts["valid_transport_states_count"] += 1
        if mode == "stealth":
            counts["stealth_exits_count"] += 1
            unit = f"wins-core-xray-exit@{name}.service"
            if run(["systemctl", "is-active", "--quiet", unit], 8)[0] == 0:
                counts["active_xray_services_count"] += 1
            config = config_dir / f"{name}.json"
            if config.is_file() and run(["xray", "-test", "-config", str(config)], 8)[0] == 0:
                counts["valid_xray_configs_count"] += 1
            mux_contract = _xray_mux_contract(config_dir, name)
            if mux_contract == "native_udp":
                counts["native_udp_mux_disabled_configs_count"] += 1
            elif mux_contract == "legacy_xudp":
                counts["legacy_xudp_enabled_configs_count"] += 1
            else:
                counts["other_mux_configs_count"] += 1
            port = _xray_listener_port(config_dir, name)
            if port is not None and port in listener_ports:
                counts["local_loopback_listeners_count"] += 1
        if _fresh_handshake(name, now):
            counts["fresh_handshakes_count"] += 1
    return {
        **counts,
        "observation_limit_reached": truncated,
        "listener_snapshot_readable": listeners_readable,
        "xray_journal_readable": xray_journal_readable,
        "xray_failure_categories": categories,
        "installed_sync_agent_contract": _installed_sync_agent_contract(sync_agent),
        "stale_handshake_cause": _stale_handshake_cause(counts, categories, truncated),
    }


def main() -> int:
    properties = service_properties()
    journal = failure_classes()
    transport = transport_predicates()
    print(
        json.dumps(
            {
                "contract": "winsvpn-core-runtime-readonly-diagnostic-v1",
                "role": "core",
                "service": properties,
                "journal": journal,
                "transport": transport,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
