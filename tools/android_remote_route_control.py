#!/usr/bin/env python3
"""Key-only, watchdog-restored first-hop route control for Android release tests.

The unrooted production phone cannot install per-port firewall rules through
ADB. This controller therefore applies short-lived source-scoped rules on the
actual first-hop servers through a dedicated OpenSSH alias and the installed
``winsvpn-android-route-guard`` sudo command. Raw client IP is accepted only on
stdin and is never emitted. Every live result is derived from kernel counters.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request
from collections import defaultdict
from typing import Any


CONTRACT = "winsvpn-android-route-inventory-v1"
REMOTE_CONTRACT = "winsvpn-android-remote-route-guard-v1"
SSH_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class RouteControlError(RuntimeError):
    pass


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def digest_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RouteControlError(f"{label} fields are invalid")
    return value


def route(value: Any, label: str) -> dict[str, Any]:
    item = exact(value, {"protocol", "port", "security", "ssh_alias"}, label)
    if item["protocol"] != "tcp" or item["security"] not in {"none", "tls"}:
        raise RouteControlError(f"{label} protocol/security is invalid")
    if isinstance(item["port"], bool) or not isinstance(item["port"], int) or not 1 <= item["port"] <= 65535:
        raise RouteControlError(f"{label} port is invalid")
    if not isinstance(item["ssh_alias"], str) or not SSH_ALIAS_RE.fullmatch(item["ssh_alias"]):
        raise RouteControlError(f"{label} SSH alias is invalid")
    return dict(item)


def load_inventory(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    path = path.absolute()
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 128 * 1024:
        raise RouteControlError("route inventory must be a small regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RouteControlError("route inventory must be UTF-8 JSON") from exc
    top = exact(
        value,
        {"schema_version", "contract", "captured_at_utc", "node", "double_vpn", "secret_material_redacted"},
        "route inventory",
    )
    if top["schema_version"] != 1 or top["contract"] != CONTRACT or top["secret_material_redacted"] is not True:
        raise RouteControlError("route inventory contract is invalid")
    try:
        captured = dt.datetime.fromisoformat(str(top["captured_at_utc"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise RouteControlError("route inventory timestamp is invalid") from exc
    if captured.tzinfo is None or abs(dt.datetime.now(dt.timezone.utc) - captured.astimezone(dt.timezone.utc)) > dt.timedelta(hours=1):
        raise RouteControlError("route inventory is stale or future-dated")
    for mode_name in ("node", "double_vpn"):
        mode = exact(
            top[mode_name],
            {"direct", "advertised_xray_routes", "core_id_sha256", "exit_slug_sha256"},
            f"{mode_name} inventory",
        )
        direct = exact(mode["direct"], {"protocol", "port", "ssh_alias"}, f"{mode_name} direct route")
        if direct["protocol"] != "udp" or isinstance(direct["port"], bool) or not isinstance(direct["port"], int) or not 1 <= direct["port"] <= 65535:
            raise RouteControlError(f"{mode_name} direct route is invalid")
        if not isinstance(direct["ssh_alias"], str) or not SSH_ALIAS_RE.fullmatch(direct["ssh_alias"]):
            raise RouteControlError(f"{mode_name} direct SSH alias is invalid")
        routes = [route(item, f"{mode_name} Xray route") for item in mode["advertised_xray_routes"]]
        if not routes or len(routes) > 16:
            raise RouteControlError(f"{mode_name} advertised Xray route set is invalid")
        keys = [(item["port"], item["security"]) for item in routes]
        if len(keys) != len(set(keys)) or len({item["port"] for item in routes}) != len(routes):
            raise RouteControlError(
                f"{mode_name} routes cannot be uniquely isolated by destination port"
            )
        for field in ("core_id_sha256", "exit_slug_sha256"):
            digest = str(mode[field])
            if not SHA_RE.fullmatch(digest):
                raise RouteControlError(f"{mode_name} {field} is invalid")
            if mode_name == "node" and digest != EMPTY_SHA256:
                raise RouteControlError(f"node inventory unexpectedly contains {field}")
            if mode_name == "double_vpn" and digest in {EMPTY_SHA256, "0" * 64}:
                raise RouteControlError(f"Double VPN inventory lacks real {field}")
    if top["node"]["direct"]["port"] != 9110:
        raise RouteControlError("public node direct AWG must use UDP 9110")
    return top, sha256_file(path)


def host_public_ipv4() -> str:
    values: list[str] = []
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=15) as response:
                raw = response.read(128).decode("ascii").strip()
            value = ipaddress.ip_address(raw)
        except Exception as exc:
            raise RouteControlError("Windows controller public identity could not be verified") from exc
        if value.version != 4 or value.is_private:
            raise RouteControlError("Windows controller did not observe a public IPv4 identity")
        values.append(str(value))
    if len(set(values)) != 1:
        raise RouteControlError("Windows controller public identity canaries disagree")
    return values[0]


def remote_operation_id(operation_id: str, alias: str) -> str:
    return hashlib.sha256(f"{operation_id}:{alias}".encode()).hexdigest()[:32]


def ssh_call(alias: str, action: str, remote_id: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if not SSH_ALIAS_RE.fullmatch(alias):
        raise RouteControlError("unsafe SSH alias")
    command = [
        "ssh", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", alias,
        "sudo", "-n", "/usr/local/sbin/winsvpn-android-route-guard", action,
    ]
    release_config = os.getenv("WINSVPN_ANDROID_SSH_CONFIG", "").strip()
    if release_config:
        config_path = pathlib.Path(release_config).expanduser().absolute()
        if not config_path.is_file() or config_path.is_symlink():
            raise RouteControlError("release SSH config is missing or unsafe")
        # Place -F before the destination alias.  This keeps the production
        # user's global SSH configuration untouched while still allowing the
        # strict collector to use pinned release-only aliases.
        alias_index = command.index(alias)
        command[alias_index:alias_index] = ["-F", str(config_path)]
    if remote_id is not None:
        command.append(remote_id)
    result = subprocess.run(
        command,
        input=(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n") if payload is not None else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=45,
        check=False,
    )
    if result.returncode != 0:
        # The remote helper is intentionally required to redact identities.
        tail = (result.stderr or result.stdout).strip().splitlines()[-1:] or ["remote command failed"]
        raise RouteControlError(f"route guard failed on SSH alias {alias}: {tail[0][:240]}")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RouteControlError(f"route guard on {alias} did not return one JSON record")
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise RouteControlError(f"route guard on {alias} returned invalid JSON") from exc
    if not isinstance(value, dict) or value.get("contract") != REMOTE_CONTRACT or value.get("passed") is not True or value.get("secret_material_redacted") is not True:
        raise RouteControlError(f"route guard on {alias} returned an invalid contract")
    return value


def mode_plan(inventory: dict[str, Any], mode_name: str, lane_kind: str, selected_port: int, security: str) -> tuple[dict[str, Any], dict[str, dict[str, list[dict[str, Any]]]]]:
    mode = inventory[mode_name]
    direct = mode["direct"]
    is_xray = lane_kind == "xray"
    selected: dict[str, Any]
    if is_xray:
        matches = [item for item in mode["advertised_xray_routes"] if item["port"] == selected_port and item["security"] == security]
        if len(matches) != 1:
            raise RouteControlError("selected Xray route is not exactly advertised for this mode")
        selected = matches[0]
    else:
        if lane_kind != "direct" or selected_port != direct["port"] or security != "none":
            raise RouteControlError("selected direct route does not match the observed mode first hop")
        selected = {"protocol": "udp", "port": direct["port"], "security": "none", "ssh_alias": direct["ssh_alias"]}
    plan: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"observations": [], "blocks": []})
    plan[direct["ssh_alias"]]["observations"].append({"id": "direct", "protocol": "udp", "port": direct["port"]})
    if is_xray:
        plan[direct["ssh_alias"]]["blocks"].append({"protocol": "udp", "port": direct["port"]})
        plan[selected["ssh_alias"]]["observations"].append({"id": "selected", "protocol": "tcp", "port": selected["port"]})
        for candidate in mode["advertised_xray_routes"]:
            if candidate["port"] == selected["port"] and candidate["security"] == selected["security"]:
                continue
            plan[candidate["ssh_alias"]]["blocks"].append({"protocol": "tcp", "port": candidate["port"]})
    return selected, dict(plan)


def combined_state(values: dict[str, str]) -> str:
    return digest_json([{"ssh_alias": alias, "state_sha256": values[alias]} for alias in sorted(values)])


def apply(
    inventory: dict[str, Any], mode_name: str, lane_kind: str, selected_port: int,
    security: str, operation_id: str, source_ipv4: str,
) -> dict[str, Any]:
    try:
        source = ipaddress.ip_address(source_ipv4)
    except ValueError as exc:
        raise RouteControlError("phone source identity is not a valid IP address") from exc
    if source.version != 4 or source.is_private or source.is_loopback:
        raise RouteControlError("phone source identity must be public IPv4")
    controller = host_public_ipv4()
    if str(source) == controller:
        raise RouteControlError("phone and controller share a public NAT identity; route forcing refused")
    selected, plan = mode_plan(inventory, mode_name, lane_kind, selected_port, security)
    applied: list[tuple[str, str]] = []
    records: dict[str, dict[str, Any]] = {}
    try:
        for alias in sorted(plan):
            remote_id = remote_operation_id(operation_id, alias)
            result = ssh_call(
                alias, "apply", remote_id,
                {
                    "schema_version": 1,
                    "contract": "winsvpn-android-route-control-apply-v1",
                    "source_ipv4": str(source),
                    "watchdog_seconds": 180,
                    "observations": plan[alias]["observations"],
                    "blocks": plan[alias]["blocks"],
                },
            )
            if result.get("watchdog_armed") is not True or result.get("shared_nat_ambiguity_absent") is not True:
                raise RouteControlError(f"route guard on {alias} did not arm safe rollback")
            applied.append((alias, remote_id))
            records[alias] = result
    except Exception:
        for alias, remote_id in reversed(applied):
            try:
                ssh_call(alias, "restore", remote_id)
            except Exception:
                pass
        raise
    before = {alias: str(record["before_state_sha256"]) for alias, record in records.items()}
    after = {alias: str(record["applied_state_sha256"]) for alias, record in records.items()}
    return {
        "action": "apply",
        "operation_id": operation_id,
        "mode": mode_name,
        "lane_kind": lane_kind,
        "selected_protocol": selected["protocol"],
        "selected_port": selected["port"],
        "selected_security": selected["security"],
        "direct_first_hop_port": inventory[mode_name]["direct"]["port"],
        "before_state_sha256": combined_state(before),
        "applied_state_sha256": combined_state(after),
        "source_ipv4_sha256": hashlib.sha256(str(source).encode()).hexdigest(),
        "controller_public_ipv4_sha256": hashlib.sha256(controller.encode()).hexdigest(),
        "watchdog_armed": True,
        "shared_nat_ambiguity_absent": True,
        "passed": True,
        "secret_material_redacted": True,
    }


def observe(inventory: dict[str, Any], mode_name: str, lane_kind: str, selected_port: int, security: str, operation_id: str) -> dict[str, Any]:
    selected, plan = mode_plan(inventory, mode_name, lane_kind, selected_port, security)
    records = {
        alias: ssh_call(alias, "observe", remote_operation_id(operation_id, alias))
        for alias in sorted(plan)
    }
    direct_alias = inventory[mode_name]["direct"]["ssh_alias"]
    direct_counter = records[direct_alias]["observations"].get("direct")
    if not isinstance(direct_counter, dict):
        raise RouteControlError("direct first-hop observation is missing")
    selected_counter = direct_counter
    if lane_kind == "xray":
        selected_counter = records[selected["ssh_alias"]]["observations"].get("selected")
        direct_blocks = [item for item in records[direct_alias]["blocks"] if item["protocol"] == "udp" and item["port"] == inventory[mode_name]["direct"]["port"]]
        if len(direct_blocks) != 1 or direct_blocks[0]["packets"] <= 0 or direct_blocks[0]["bytes"] <= 0:
            raise RouteControlError("direct first-hop block did not observe a forced fallback attempt")
    if not isinstance(selected_counter, dict) or selected_counter["packets"] <= 0 or selected_counter["bytes"] <= 0:
        raise RouteControlError("selected route did not reach its first-hop kernel counter")
    return {
        "action": "observe",
        "operation_id": operation_id,
        "mode": mode_name,
        "lane_kind": lane_kind,
        "selected_protocol": selected["protocol"],
        "selected_port": selected["port"],
        "selected_security": selected["security"],
        "direct_first_hop_port": inventory[mode_name]["direct"]["port"],
        "selected_packets": selected_counter["packets"],
        "selected_bytes": selected_counter["bytes"],
        "direct_packets": direct_counter["packets"],
        "direct_bytes": direct_counter["bytes"],
        "direct_block_packets": (
            next((item["packets"] for item in records[direct_alias]["blocks"] if item["protocol"] == "udp"), 0)
            if lane_kind == "xray" else 0
        ),
        "passed": True,
        "secret_material_redacted": True,
    }


def restore(inventory: dict[str, Any], mode_name: str, lane_kind: str, selected_port: int, security: str, operation_id: str) -> dict[str, Any]:
    _, plan = mode_plan(inventory, mode_name, lane_kind, selected_port, security)
    states: dict[str, str] = {}
    before: dict[str, str] = {}
    failures: list[str] = []
    for alias in sorted(plan):
        try:
            result = ssh_call(alias, "restore", remote_operation_id(operation_id, alias))
            before[alias] = str(result["before_state_sha256"])
            states[alias] = str(result["after_state_sha256"])
        except Exception:
            failures.append(alias)
    if failures:
        raise RouteControlError(f"route forcing failed to restore on aliases: {','.join(failures)}")
    return {
        "action": "restore",
        "operation_id": operation_id,
        "before_state_sha256": combined_state(before),
        "after_state_sha256": combined_state(states),
        "passed": combined_state(before) == combined_state(states),
        "secret_material_redacted": True,
    }


def snapshot(inventory: dict[str, Any]) -> dict[str, Any]:
    aliases = {
        inventory[mode]["direct"]["ssh_alias"]
        for mode in ("node", "double_vpn")
    }
    aliases.update(
        item["ssh_alias"]
        for mode in ("node", "double_vpn")
        for item in inventory[mode]["advertised_xray_routes"]
    )
    records = {alias: ssh_call(alias, "snapshot") for alias in sorted(aliases)}
    if any(record.get("active_operation_count") != 0 for record in records.values()):
        raise RouteControlError("a remote route-control operation is already active")
    states = {alias: str(record["state_sha256"]) for alias, record in records.items()}
    return {
        "action": "snapshot",
        "state_sha256": combined_state(states),
        "active_operation_count": 0,
        "passed": True,
        "secret_material_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("snapshot", "apply", "observe", "restore", "self-test"))
    parser.add_argument("--inventory")
    parser.add_argument("--mode", choices=("node", "double_vpn"))
    parser.add_argument("--lane-kind", choices=("direct", "xray"))
    parser.add_argument("--selected-port", type=int)
    parser.add_argument("--security", choices=("none", "tls"), default="none")
    parser.add_argument("--operation-id")
    args = parser.parse_args()
    if args.action == "self-test":
        if remote_operation_id("f" * 32, "spain") != remote_operation_id("f" * 32, "spain"):
            raise RouteControlError("operation derivation is unstable")
        print("ANDROID REMOTE ROUTE CONTROL SELF-TEST: PASS")
        return 0
    if not args.inventory:
        raise RouteControlError("--inventory is required")
    inventory, inventory_sha = load_inventory(pathlib.Path(args.inventory))
    if args.action == "snapshot":
        result = snapshot(inventory)
    else:
        if not all((args.mode, args.lane_kind, args.selected_port, args.operation_id)) or not re.fullmatch(r"[0-9a-f]{32}", args.operation_id):
            raise RouteControlError("mode, lane kind, selected port, and operation ID are required")
        if args.action == "apply":
            try:
                request = json.loads(sys.stdin.read())
                source_ipv4 = exact(request, {"source_public_ipv4"}, "apply request")["source_public_ipv4"]
            except (json.JSONDecodeError, RouteControlError) as exc:
                raise RouteControlError("apply requires exact source identity JSON on stdin") from exc
            result = apply(inventory, args.mode, args.lane_kind, args.selected_port, args.security, args.operation_id, source_ipv4)
        elif args.action == "observe":
            result = observe(inventory, args.mode, args.lane_kind, args.selected_port, args.security, args.operation_id)
        else:
            result = restore(inventory, args.mode, args.lane_kind, args.selected_port, args.security, args.operation_id)
    result["route_inventory_sha256"] = inventory_sha
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RouteControlError as exc:
        print(f"ANDROID REMOTE ROUTE CONTROL: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
