#!/usr/bin/env python3
"""Regression checks for the release-only live observation collectors."""

from __future__ import annotations

import importlib.util
import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name: str):
    path = ROOT / "tools" / name
    spec = importlib.util.spec_from_file_location(name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    compile(module.TARGET, f"{name}:TARGET", "exec")
    return module


def parse_ss_lunt_ports(text: str) -> set[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) <= 4:
            continue
        try:
            ports.add(int(fields[4].rsplit(":", 1)[1]))
        except (ValueError, IndexError):
            pass
    return ports


def main() -> int:
    core = load("windows_core_live_observation.py")
    spain = load("windows_spain_live_observation.py")
    load("windows_spain_http_fingerprint_observation.py")
    fixture = "\n".join((
        "udp UNCONN 0 0 0.0.0.0:9210 0.0.0.0:*",
        "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:*",
        "tcp LISTEN 0 4096 127.0.0.1:10110 0.0.0.0:*",
    ))
    assert parse_ss_lunt_ports(fixture) == {80, 9210, 10110}
    assert 'value=fields[4]' in core.TARGET
    assert 'fields[0].lower().startswith("tcp")' not in core.TARGET
    nginx_fixture = "listen 80 default_server;\nlisten 127.0.0.1:443 ssl;"
    primary = [line for line in nginx_fixture.splitlines() if re.search(r"(?:^|[\s:])80(?:\s|;)", line)]
    assert primary == ["listen 80 default_server;"]
    assert r'(?:^|[\s:])' in spain.TARGET
    assert 'WINS_OBSERVATION_NONCE' in (
        ROOT / 'tools' / 'windows_core_live_observation.py'
    ).read_text(encoding='utf-8')
    assert 'WINS_OBSERVATION_NONCE' in (
        ROOT / 'tools' / 'windows_spain_live_observation.py'
    ).read_text(encoding='utf-8')
    assert 'observation_window_nonce' in core.TARGET
    for field in (
        'exact_ingress_peer_match_count_after',
        'exact_ingress_allowed_ip',
        'exact_ingress_peer_rx_delta',
        'client_policy_rule_matches',
        'client_route_uses_corex',
        'unexpected_core_direct_egress',
        'exit_peer_match_count_before',
        'exit_peer_match_count_after',
        'exit_peer_endpoint_loopback_matches_xray',
        'exit_peer_handshake_advanced',
        'exit_peer_handshake_fresh_after',
        'exit_peer_rx_delta',
        'exit_peer_tx_delta',
        'xray_exit_config_read',
        'xray_exit_local_inbound_valid',
        'xray_exit_unit_matches_config_path',
    ):
        assert field in core.TARGET
    assert 'wins-core-exit-"+ctx["exit_iface"]' in core.TARGET
    assert '"endpoint")==expected_loopback' in core.TARGET
    assert '"protocol")=="tunnel"' in core.TARGET
    assert 'settings.get("network")=="udp"' in core.TARGET
    assert 'systemctl","show","--property=ExecStart"' in core.TARGET
    assert 'transport=="unknown" and last_exit_peer' in core.TARGET
    core_source = (ROOT / 'tools' / 'windows_core_live_observation.py').read_text(
        encoding='utf-8'
    )
    for field in (
        'assignment_revision_ready',
        'assignment_runtime_validated_fresh',
        'core_registration_fresh',
    ):
        assert field in core_source
    assert 'observation_window_nonce' in spain.TARGET
    assert 'ip","-j","addr","show","dev","awg0"' in spain.TARGET
    assert 'echo_socket.bind((echo_gateway,ctx["probe_echo_port"]))' in spain.TARGET
    assert 'probe_gateway_digest_matches' in spain.TARGET
    assert 'probe_echo_bound_private_ipv4' in spain.TARGET
    assert 'if payload!=expected_echo:continue' in spain.TARGET
    assert 'probe_echo_port not in {0, 49152}' in (
        ROOT / 'tools' / 'windows_spain_live_observation.py'
    ).read_text(encoding='utf-8')
    assert 'WINS_PROBE_GATEWAY_DIGEST' in (
        ROOT / 'tools' / 'windows_spain_live_observation.py'
    ).read_text(encoding='utf-8')
    assert 'awg_container_image_matches_release_pin' in spain.TARGET
    assert 'amneziavpn/amneziawg-go@sha256:' in spain.TARGET
    for field in (
        'forwarding_inspection_complete',
        'ipv4_forward_enabled',
        'vpn_to_wan_accept_present',
        'return_established_accept_present',
        'masquerade_present',
        'forward_in_packet_delta',
        'forward_return_packet_delta',
        'masquerade_packet_delta',
    ):
        assert field in spain.TARGET
    assert 'iptables-save","-c"' in spain.TARGET
    assert 'run(["sysctl","-n","net.ipv4.ip_forward"]).stdout' in spain.TARGET
    assert 'run(["sysctl","-n","net.ipv4.ip_forward"])[1]' not in spain.TARGET
    print("live observation collector tests passed: 30/30")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
