#!/usr/bin/env python3
"""Focused fail-closed tests for the root-owned protocol-attempt broker.

Tests use temp roots and TEST_ONLY fake exact-tuple runners. They never invoke
gcloud, never start real units, and never point ProductionHost at a fake runner
that can emit PASS.
"""

from __future__ import annotations

import os
import socket
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

TOOLS = Path(__file__).resolve().parent


def load_module(name: str, path: Path) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


subject = load_module("gcp_proof_attempt_broker_under_test", TOOLS / "gcp_proof_attempt_broker.py")
helper = load_module("gcp_proof_remote_action_for_attempt_broker", TOOLS / "gcp_proof_remote_action.py")
installer = load_module(
    "gcp_proof_remote_install_for_attempt_broker",
    TOOLS / "gcp_proof_remote_install.py",
)

PROJECT = "winsproof123"
FLEET = "123456789abc"
CONTROL = "proof-control-a1"
WINN3 = "proof-winn3-a1"
COVER = "proof-cover-a1"
SESSION = "session-20260823-a"
CORR = "correlation-20260823-a"
CORR_B = "correlation-20260823-b"
SESSION_B = "session-20260823-b"
HEX64 = "a" * 64
HEX3904 = "b" * 3904
AWG_PRIVATE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
AWG_PEER = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
WINN3_GW = "10.240.0.10:443"
XRAY_PEER = "10.10.0.1"
XRAY_UUID = "550e8400-e29b-41d4-a716-446655440000"
XRAY_ADDRESS = "10.240.0.20"
PING_BIN = "/usr/bin/ping"
WINN3_FRAGMENT = "/lib/systemd/system/winsvpn-proof-winn3-probe.service"
AWG_FRAGMENT = "/lib/systemd/system/winsvpn-proof-awg-client.service"
XRAY_FRAGMENT = "/lib/systemd/system/winsvpn-proof-xray-client.service"
XRAY_PROBE_FRAGMENT = "/lib/systemd/system/winsvpn-proof-xray-probe.service"
FORBIDDEN_ARGV_TOKENS = (
    "/bin/sh",
    "/bin/bash",
    "-c",
    "curl",
    "wget",
    "python",
    "nc",
    "ncat",
    "bash",
    "zsh",
    "eval",
    "reboot",
    "docker",
)


def test_protocol_runtime_paths_match_authenticated_runtime_installer() -> None:
    assert subject.AMNEZIAWG_GO_BIN == os.fspath(
        installer.CLIENT_RUNTIME_INSTALL_PATHS["amneziawg-go"]
    )
    assert subject.BIN_AWG == os.fspath(installer.CLIENT_RUNTIME_INSTALL_PATHS["awg"])
    assert subject.XRAY_BIN == os.fspath(installer.CLIENT_RUNTIME_INSTALL_PATHS["xray"])
    assert subject.ARGV_AWG_SETCONF[0] == subject.BIN_AWG
    assert subject.ARGV_AWG_HANDSHAKES[0] == subject.BIN_AWG
    assert subject.ARGV_AWG_TRANSFER[0] == subject.BIN_AWG
    assert subject.ARGV_AWG_ENDPOINTS[0] == subject.BIN_AWG


class FixtureHost:
    TEST_ONLY = True

    def __init__(self) -> None:
        self.root_uid = os.getuid()
        self.root_gid = os.getgid()
        self.peer_uid = 0
        self.runs: list[tuple[str, ...]] = []
        self.commands: dict[tuple[str, ...], Any] = {}
        self.files = {
            subject.WINN3_PROBE_BIN: b"\x7fELFwinn3\n",
            subject.AMNEZIAWG_GO_BIN: b"\x7fELFawggo\n",
            subject.XRAY_BIN: b"\x7fELFxray\n",
            subject.BIN_AWG: b"\x7fELFawg\n",
            PING_BIN: b"\x7fELFping\n",
        }
        self._mono = 1_000_000_000
        self._utc_index = 0

    def monotonic_ns(self) -> int:
        self._mono += 1_000_000_000
        return self._mono

    def utc_now(self) -> str:
        self._utc_index += 1
        stamp = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc) + timedelta(
            seconds=self._utc_index
        )
        return stamp.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")

    def run(self, argv: list[str]) -> subject.CommandResult:
        key = tuple(argv)
        self.runs.append(key)
        queued = self.commands.get(key)
        if isinstance(queued, list):
            if not queued:
                return subject.CommandResult(b"", b"absent\n", 127)
            return queued.pop(0)
        if queued is not None:
            return queued
        return subject.CommandResult(b"", b"absent\n", 127)

    def hash_executable(self, path: str) -> str:
        subject._forbid_credential_path(path)
        if path not in self.files:
            raise subject.AttemptBrokerError(f"process executable {path} is unreadable")
        return subject.sha256_bytes(self.files[path])

    def peer_credentials(self, conn: socket.socket) -> tuple[int, int, int]:
        return (1, self.peer_uid, self.root_gid)

    def fchown(self, fd: int) -> None:
        os.fchown(fd, self.root_uid, self.root_gid)

    def chown(self, path: str) -> None:
        os.chown(path, self.root_uid, self.root_gid)


def fleet_binding() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "contract": subject.FLEET_BINDING_CONTRACT,
        "project": PROJECT,
        "fleet_id": FLEET,
        "control": {"instance": CONTROL, "zone": "us-east1-b"},
        "data-winn3": {"instance": WINN3, "zone": "us-central1-a"},
        "data-cover": {"instance": COVER, "zone": "us-east1-b"},
    }


def show_oneshot(unit: str, fragment: str, pid: int = 0) -> bytes:
    return (
        f"Id={unit}\nFragmentPath={fragment}\nMainPID={pid}\nActiveState=inactive\n"
        f"Result=success\nExecMainStatus=0\nType=oneshot\n"
    ).encode("ascii")


def show_oneshot_failed(unit: str, fragment: str, pid: int = 0) -> bytes:
    return (
        f"Id={unit}\nFragmentPath={fragment}\nMainPID={pid}\nActiveState=failed\n"
        f"Result=exit-code\nExecMainStatus=1\nType=oneshot\n"
    ).encode("ascii")


def show_simple(unit: str, pid: int, fragment: str) -> bytes:
    return (
        f"Id={unit}\nFragmentPath={fragment}\nMainPID={pid}\nActiveState=active\n"
        f"Result=\nExecMainStatus=0\nType=simple\n"
    ).encode("ascii")


def inactive() -> subject.CommandResult:
    return subject.CommandResult(b"inactive\n", b"", 3)


def winn3_probe_output(*, gateway: str = WINN3_GW) -> bytes:
    host, port = gateway.rsplit(":", 1)
    return (
        f"v3probe: dialed {host}:{port}, inner 10.10.0.2, target 10.10.0.1, inner MTU 1373\n"
        "v3probe: SENT  ipv4 10.10.0.2 -> 10.10.0.1 proto=1 len=84\n"
        "v3probe: RECV  ipv4 10.10.0.1 -> 10.10.0.2 proto=1 len=84\n"
        "v3probe: sent=1 received=1 unmatched=0\n"
        "v3probe: tunnel stats tx=84 rx=84 rx_dropped_invalid=0 tx_dropped_invalid=0\n"
        "v3probe: HANDSHAKE ok state=carrying epoch=1 session=established\n"
        "v3probe: VERDICT a matching reply came back through the winn/3 session\n"
    ).encode("ascii")


def winn3_failed_probe_output(*, gateway: str = WINN3_GW) -> bytes:
    host, port = gateway.rsplit(":", 1)
    return (
        f"v3probe: dialed {host}:{port}, inner 10.10.0.2, target 10.10.0.1, inner MTU 1373\n"
        "v3probe: HANDSHAKE absent state=initiating wait=20s\n"
    ).encode("ascii")


def xray_probe_output(*, peer: str = XRAY_PEER) -> bytes:
    return (
        f"PING {peer} ({peer}) 56(84) bytes of data.\n"
        f"64 bytes from {peer}: icmp_seq=1 ttl=64 time=0.1 ms\n"
        "2 packets transmitted, 2 received, 0% packet loss\n"
    ).encode("ascii")


def ip_stats_xray(*, rx: int = 128, tx: int = 128) -> bytes:
    return (
        "3: xray0: <POINTOPOINT,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN\n"
        "    link/none\n"
        "    RX: bytes  packets  errors  dropped overrun mcast\n"
        f"    {rx}        2        0       0       0       0\n"
        "    TX: bytes  packets  errors  dropped carrier collsns\n"
        f"    {tx}        2        0       0       0       0\n"
    ).encode("ascii")


def _write_owned(path: str, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def make_env(tmp_path: Path, *, role: str = "control") -> tuple[FixtureHost, subject.Paths]:
    paths = subject.Paths.overlay(str(tmp_path))
    os.makedirs(paths.run_dir, exist_ok=True)
    os.makedirs(os.path.dirname(paths.role), exist_ok=True)
    os.makedirs(os.path.dirname(paths.fleet_binding), exist_ok=True)
    os.makedirs(paths.proof_client_dir, exist_ok=True)
    os.chmod(paths.run_dir, 0o700)
    os.chmod(os.path.dirname(paths.role), 0o700)
    os.chmod(os.path.dirname(paths.fleet_binding), 0o700)
    os.chmod(os.path.dirname(paths.proof_client_dir), 0o700)
    os.chmod(paths.proof_client_dir, 0o700)
    _write_owned(paths.role, (role + "\n").encode("ascii"), 0o400)
    _write_owned(paths.fleet_binding, subject.canonical_bytes(fleet_binding()), 0o400)
    return FixtureHost(), paths


def request_bytes(
    action: str,
    protocol: str,
    node: str,
    *,
    session_id: str = SESSION,
    correlation_id: str = CORR,
    extra: dict[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "contract": subject.ATTEMPT_REQUEST_CONTRACT,
        "action": action,
        "correlation_id": correlation_id,
        "node": node,
        "protocol": protocol,
        "session_id": session_id,
    }
    if extra:
        payload.update(extra)
    return subject.canonical_bytes(payload)


def provision_winn3(paths: subject.Paths, *, gateway: str = WINN3_GW, output: bytes | None = None) -> None:
    for name, size, _pattern in subject.PROOF_CLIENT_FILES:
        fill = HEX64 if size == 64 else HEX3904
        _write_owned(os.path.join(paths.proof_client_dir, name), fill.encode("ascii"), 0o400)
    env = (
        f"WINN3_PROOF_GW={gateway}\n"
        "WINN3_PROOF_GATEWAY_ID=" + WINN3 + "\n"
        f"WINN3_PROOF_ED_PUB={HEX64}\n"
        f"WINN3_PROOF_ML_PUB={HEX3904}\n"
    )
    _write_owned(paths.winn3_probe_env, env.encode("ascii"), 0o400)
    _write_owned(
        paths.winn3_probe_out,
        winn3_probe_output(gateway=gateway) if output is None else output,
        0o400,
    )


def provision_awg(paths: subject.Paths) -> None:
    conf = (
        "[Interface]\n"
        f"Address = {subject.PROOF_CLIENT_INNER_V4}/32\n"
        f"PrivateKey = {AWG_PRIVATE}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {AWG_PEER}\n"
        "Endpoint = 10.240.0.20:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )
    _write_owned(paths.awg_client_conf, conf.encode("ascii"), 0o400)


def provision_xray(
    paths: subject.Paths, *, peer: str = XRAY_PEER, output: bytes | None = None
) -> None:
    config = subject.canonical_bytes(
        {
            "inbounds": [
                {"protocol": "tun", "settings": {"name": "xray0"}, "tag": "tun-in"}
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": XRAY_ADDRESS,
                                "port": 443,
                                "users": [{"encryption": "none", "id": XRAY_UUID}],
                            }
                        ]
                    },
                    "streamSettings": {"network": "ws", "wsSettings": {"path": "/ws"}},
                    "tag": "proxy",
                }
            ],
        }
    )
    _write_owned(paths.xray_client_conf, config, 0o400)
    _write_owned(paths.xray_probe_env, f"XRAY_PROOF_PEER={peer}\n".encode("ascii"), 0o400)
    _write_owned(
        paths.xray_probe_out,
        xray_probe_output(peer=peer) if output is None else output,
        0o400,
    )


def seed_winn3(host: FixtureHost, paths: subject.Paths) -> None:
    provision_winn3(paths)
    host.commands[subject.ARGV_SYSTEMCTL_START_WINN3_PROBE] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_WINN3_PROBE] = subject.CommandResult(
        show_oneshot(subject.UNIT_WINN3_PROBE, WINN3_FRAGMENT)
    )
    host.commands[subject.ARGV_SYSTEMCTL_STOP_WINN3_PROBE] = subject.CommandResult()


def seed_winn3_failed(host: FixtureHost, paths: subject.Paths) -> None:
    provision_winn3(paths, output=winn3_failed_probe_output())
    host.commands[subject.ARGV_SYSTEMCTL_START_WINN3_PROBE] = subject.CommandResult(
        b"", b"probe failed\n", 1
    )
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_WINN3_PROBE] = subject.CommandResult(
        show_oneshot_failed(subject.UNIT_WINN3_PROBE, WINN3_FRAGMENT)
    )
    host.commands[subject.ARGV_SYSTEMCTL_STOP_WINN3_PROBE] = subject.CommandResult()


def seed_awg(
    host: FixtureHost,
    paths: subject.Paths,
    *,
    present: bool = True,
    handshake: int = 0,
    rx: int = 0,
    tx: int = 0,
    leftover: bool = False,
) -> None:
    provision_awg(paths)
    if leftover:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT] = subject.CommandResult(
            b"active\n"
        )
    else:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT] = inactive()
    host.commands[subject.ARGV_SYSTEMCTL_START_AWG_CLIENT] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_AWG_CLIENT] = subject.CommandResult(
        show_simple(subject.UNIT_AWG_CLIENT, 3002, AWG_FRAGMENT)
    )
    host.commands[subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT] = subject.CommandResult()
    host.commands[subject.ARGV_AWG_SETCONF] = subject.CommandResult()
    host.commands[subject.ARGV_IP_LINK_UP_AWG] = subject.CommandResult()
    if present:
        host.commands[subject.ARGV_IP_LINK_AWG] = subject.CommandResult(
            b"awg0: <POINTOPOINT,UP>\n"
        )
        host.commands[subject.ARGV_AWG_HANDSHAKES] = subject.CommandResult(
            f"{AWG_PEER} {handshake}\n".encode("ascii")
        )
        host.commands[subject.ARGV_AWG_TRANSFER] = subject.CommandResult(
            f"{AWG_PEER} {rx} {tx}\n".encode("ascii")
        )
        host.commands[subject.ARGV_AWG_ENDPOINTS] = subject.CommandResult(
            f"{AWG_PEER} (none)\n".encode("ascii")
        )
    else:
        host.commands[subject.ARGV_IP_LINK_AWG] = subject.CommandResult(b"", b"absent\n", 1)


def seed_xray(
    host: FixtureHost,
    paths: subject.Paths,
    *,
    background: bool = False,
    leftover_client: bool = False,
    rx: int = 128,
    tx: int = 128,
) -> None:
    provision_xray(paths)
    if background:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_SERVER] = subject.CommandResult(
            b"active\n"
        )
    else:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_SERVER] = inactive()
    if leftover_client:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT] = subject.CommandResult(
            b"active\n"
        )
    else:
        host.commands[subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT] = inactive()
    host.commands[subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_XRAY_CLIENT] = subject.CommandResult(
        show_simple(subject.UNIT_XRAY_CLIENT, 3001, XRAY_FRAGMENT)
    )
    host.commands[subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_STOP_XRAY_PROBE] = subject.CommandResult()
    host.commands[subject.ARGV_IP_LINK_XRAY] = subject.CommandResult(
        b"xray0: <POINTOPOINT,UP>\n"
    )
    host.commands[subject.ARGV_SYSTEMCTL_START_XRAY_PROBE] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_XRAY_PROBE] = subject.CommandResult(
        show_oneshot(subject.UNIT_XRAY_PROBE, XRAY_PROBE_FRAGMENT)
    )
    host.commands[subject.ARGV_IP_STATS_XRAY] = subject.CommandResult(
        ip_stats_xray(rx=rx, tx=tx)
    )


def assert_closed_runs(host: FixtureHost) -> None:
    for argv in host.runs:
        joined = " ".join(argv)
        assert argv in subject.ALLOWED_COMMANDS
        for token in FORBIDDEN_ARGV_TOKENS:
            assert token not in argv
            if token == "-c":
                continue
            assert f" {token} " not in f" {joined} "
        assert "sh -c" not in joined
        assert "--host" not in argv
        assert "--port" not in argv
        assert "--path" not in argv
        assert "--success" not in argv
        assert "--command" not in argv
        assert CONTROL not in argv
        assert WINN3 not in argv
        assert COVER not in argv


def read_journal_bytes(paths: subject.Paths) -> bytes:
    fd = os.open(paths.journal, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        return os.read(fd, 1024 * 1024)
    finally:
        os.close(fd)


def test_contracts_match_helper_consumer() -> None:
    assert subject.ATTEMPT_JOURNAL_CONTRACT == helper.ATTEMPT_JOURNAL_CONTRACT
    assert subject.ATTEMPT_REQUEST_CONTRACT == helper.ATTEMPT_REQUEST_CONTRACT
    assert subject.ATTEMPT_ACK_CONTRACT == helper.ATTEMPT_ACK_CONTRACT
    assert subject.ATTEMPT_JOURNAL_PATH == helper.ATTEMPT_JOURNAL_PATH
    assert subject.ATTEMPT_SOCKET_PATH == helper.ATTEMPT_SOCKET_PATH
    assert subject.ATTEMPT_JOURNAL_KEYS == helper.ATTEMPT_JOURNAL_KEYS
    assert subject.ATTEMPT_EVENT_KEYS == helper.ATTEMPT_EVENT_KEYS
    assert subject.ROLE_FILE == helper.ROLE_FILE
    assert subject.FLEET_BINDING_PATH == helper.FLEET_BINDING_PATH
    assert "nonce" not in helper.ATTEMPT_EVENT_KEYS
    assert "role" not in helper.ATTEMPT_EVENT_KEYS


def test_winn3_invokes_installed_action_path_and_records_timestamps(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    ack = subject.execute_attempt(
        request_bytes("connect-primary", "winn3", WINN3), host, paths
    )
    assert ack == {
        "action": "connect-primary",
        "contract": subject.ATTEMPT_ACK_CONTRACT,
        "correlation_id": CORR,
        "node": WINN3,
        "protocol": "winn3",
        "session_id": SESSION,
        "state": "completed",
    }
    assert host.runs == [
        subject.ARGV_SYSTEMCTL_START_WINN3_PROBE,
        subject.ARGV_SYSTEMCTL_SHOW_WINN3_PROBE,
    ]
    assert_closed_runs(host)
    journal = subject.load_attempt_journal(host, paths)
    helper.exact_keys(journal, helper.ATTEMPT_JOURNAL_KEYS, "protocol attempt journal")
    events = journal["events"]
    assert len(events) == 2
    assert events[0]["phase"] == "started"
    assert events[0]["result"] == "pending"
    assert events[1]["phase"] == "finished"
    assert events[1]["result"] == "connected"
    assert events[0]["protocol"] == "winn3"
    assert events[1]["node"] == WINN3
    assert events[0]["monotonic_ns"] < events[1]["monotonic_ns"]
    assert helper.parse_utc(events[0]["utc"]) < helper.parse_utc(events[1]["utc"])
    for event in events:
        helper.exact_keys(event, helper.ATTEMPT_EVENT_KEYS, "protocol attempt event")
        assert event["action"] == "connect-primary"
        assert event["correlation_id"] == CORR
        assert event["session_id"] == SESSION


def test_new_attempt_start_must_follow_previous_finish(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    previous = {
        "schema_version": 1,
        "contract": subject.ATTEMPT_JOURNAL_CONTRACT,
        "events": [
            {
                "action": "connect-primary",
                "correlation_id": CORR_B,
                "monotonic_ns": 1_000_000_000,
                "node": WINN3,
                "phase": "started",
                "protocol": "winn3",
                "result": "pending",
                "session_id": SESSION_B,
                "utc": "2026-08-24T11:59:59Z",
            },
            {
                "action": "connect-primary",
                "correlation_id": CORR_B,
                "monotonic_ns": 2_500_000_000,
                "node": WINN3,
                "phase": "finished",
                "protocol": "winn3",
                "result": "connected",
                "session_id": SESSION_B,
                "utc": "2026-08-24T12:00:00.5Z",
            },
        ],
    }
    original = subject.canonical_bytes(previous)
    _write_owned(paths.journal, original, 0o400)

    with pytest.raises(subject.AttemptBrokerError, match="strictly ordered"):
        subject.execute_attempt(
            request_bytes("connect-primary", "winn3", WINN3), host, paths
        )

    assert host.runs == [
        subject.ARGV_SYSTEMCTL_START_WINN3_PROBE,
        subject.ARGV_SYSTEMCTL_SHOW_WINN3_PROBE,
    ]
    assert Path(paths.journal).read_bytes() == original


def test_awg_then_xray_records_observed_failure_then_connect(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths)
    awg_ack = subject.execute_attempt(
        request_bytes("probe-awg-block", "awg", COVER), host, paths
    )
    assert awg_ack["protocol"] == "awg"
    assert awg_ack["state"] == "completed"
    after_awg = subject.load_attempt_journal(host, paths)
    assert [event["protocol"] for event in after_awg["events"]] == ["awg", "awg"]
    assert after_awg["events"][1]["result"] == "failed"
    xray_ack = subject.execute_attempt(
        request_bytes("probe-awg-block", "xray", COVER), host, paths
    )
    assert xray_ack["protocol"] == "xray"
    journal = subject.load_attempt_journal(host, paths)
    events = journal["events"]
    expected = (
        ("awg", "started", "pending"),
        ("awg", "finished", "failed"),
        ("xray", "started", "pending"),
        ("xray", "finished", "connected"),
    )
    assert len(events) == 4
    last_mono = 0
    last_utc = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
    for event, (protocol, phase, result) in zip(events, expected):
        helper.exact_keys(event, helper.ATTEMPT_EVENT_KEYS, "protocol attempt event")
        assert event["protocol"] == protocol
        assert event["phase"] == phase
        assert event["result"] == result
        assert event["node"] == COVER
        assert event["action"] == "probe-awg-block"
        assert event["session_id"] == SESSION
        assert event["correlation_id"] == CORR
        assert last_mono < event["monotonic_ns"]
        stamp = helper.parse_utc(event["utc"])
        assert last_utc < stamp
        last_mono = event["monotonic_ns"]
        last_utc = stamp
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT in host.runs
    assert subject.ARGV_AWG_HANDSHAKES in host.runs
    assert subject.ARGV_IP_LINK_AWG in host.runs
    assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT in host.runs
    assert subject.ARGV_SYSTEMCTL_START_XRAY_PROBE in host.runs
    assert_closed_runs(host)
    info = os.lstat(paths.journal)
    assert stat.S_ISREG(info.st_mode)
    assert info.st_nlink == 1
    assert info.st_uid == os.getuid()
    assert info.st_gid == os.getgid()
    assert stat.S_IMODE(info.st_mode) == 0o400
    raw = read_journal_bytes(paths)
    raw.decode("ascii")
    assert raw.endswith(b"\n")
    assert raw == subject.canonical_bytes(journal)


def test_winn3_block_then_distinct_cover_awg_is_journal_proven(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3_failed(host, paths)
    seed_awg(host, paths, handshake=1, rx=128, tx=256)
    subject.execute_attempt(
        request_bytes("probe-winn3-block", "winn3", WINN3), host, paths
    )
    subject.execute_attempt(
        request_bytes("probe-winn3-block", "awg", COVER), host, paths
    )
    events = subject.load_attempt_journal(host, paths)["events"]
    assert [
        (event["protocol"], event["node"], event["phase"], event["result"])
        for event in events
    ] == [
        ("winn3", WINN3, "started", "pending"),
        ("winn3", WINN3, "finished", "failed"),
        ("awg", COVER, "started", "pending"),
        ("awg", COVER, "finished", "connected"),
    ]


def test_cover_withdrawn_winn3_failure_is_journal_proven(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3_failed(host, paths)
    subject.execute_attempt(
        request_bytes("probe-cover-withdrawn", "winn3", WINN3), host, paths
    )
    events = subject.load_attempt_journal(host, paths)["events"]
    assert [event["result"] for event in events] == ["pending", "failed"]
    assert all(event["action"] == "probe-cover-withdrawn" for event in events)
    assert all(event["node"] == WINN3 for event in events)


def test_failed_winn3_witness_refuses_connected_or_extra_output(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3_failed(host, paths)
    replacement = winn3_failed_probe_output() + b"unexpected prose\n"
    os.chmod(paths.winn3_probe_out, 0o600)
    os.remove(paths.winn3_probe_out)
    _write_owned(paths.winn3_probe_out, replacement, 0o400)
    with pytest.raises(subject.AttemptBrokerError, match="malformed"):
        subject.execute_attempt(
            request_bytes("probe-winn3-block", "winn3", WINN3), host, paths
        )
    assert not os.path.exists(paths.journal)


def test_injection_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    extras = (
        {"command": "/bin/sh"},
        {"cmd": "reboot"},
        {"shell": "bash"},
        {"host": "evil.example"},
        {"port": "22"},
        {"path": "/tmp/x"},
        {"success": True},
        {"ok": True},
        {"bytes_rx": 999999},
        {"argv": ["/bin/sh", "-c", "reboot"]},
        {"role": "control"},
        {"nonce": "abc"},
    )
    for extra in extras:
        with pytest.raises(subject.AttemptBrokerError, match="schema fields|forbidden"):
            subject.execute_attempt(
                request_bytes("connect-primary", "winn3", WINN3, extra=extra),
                host,
                paths,
            )
        assert host.runs == []
    with pytest.raises(subject.AttemptBrokerError, match="invalid"):
        subject.execute_attempt(
            request_bytes("connect-primary", "winn3", "proof-cover-a1;reboot"),
            host,
            paths,
        )
    with pytest.raises(subject.AttemptBrokerError, match="not allowlisted|unsupported"):
        subject.execute_attempt(
            request_bytes("connect-primary", "awg", COVER), host, paths
        )
    assert host.runs == []
    assert not os.path.exists(paths.journal)


def test_replay_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    payload = request_bytes("connect-primary", "winn3", WINN3)
    subject.execute_attempt(payload, host, paths)
    first = subject.load_attempt_journal(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="duplicate"):
        subject.execute_attempt(payload, host, paths)
    second = subject.load_attempt_journal(host, paths)
    assert second == first


def test_reordered_fallback_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="AWG-first"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)
    subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    crafted = subject.load_attempt_journal(host, paths)
    crafted["events"][1]["result"] = "connected"
    os.remove(paths.journal)
    subject._atomic_write_journal(host, paths, crafted)
    with pytest.raises(subject.AttemptBrokerError, match="AWG-first"):
        subject.execute_attempt(
            request_bytes("probe-awg-block", "xray", COVER), host, paths
        )


def test_absent_awg_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths, present=False)
    with pytest.raises(subject.AttemptBrokerError, match="absent AWG"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT in host.runs
    assert subject.ARGV_IP_LINK_AWG in host.runs
    assert not os.path.exists(paths.journal)


def test_background_xray_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths, background=True)
    subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    before = subject.load_attempt_journal(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="background Xray"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT not in host.runs
    after = subject.load_attempt_journal(host, paths)
    assert after == before


def test_symlink_journal_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    decoy = tmp_path / "decoy-journal.json"
    decoy.write_bytes(subject.canonical_bytes({"schema_version": 1, "contract": subject.ATTEMPT_JOURNAL_CONTRACT, "events": []}))
    os.symlink(decoy, paths.journal)
    with pytest.raises(subject.AttemptBrokerError, match="regular single-link"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert stat.S_ISLNK(os.lstat(paths.journal).st_mode)


def test_hardlink_journal_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    linked = str(tmp_path / "journal.hardlink")
    os.link(paths.journal, linked)
    assert os.lstat(paths.journal).st_nlink == 2
    with pytest.raises(subject.AttemptBrokerError, match="regular single-link"):
        subject.execute_attempt(
            request_bytes(
                "connect-primary",
                "winn3",
                WINN3,
                correlation_id=CORR_B,
            ),
            host,
            paths,
        )


def test_path_swap_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    real_lstat = os.lstat
    seen = {"n": 0}

    def swap_after_lstat(path: str | bytes | os.PathLike[str], *args: Any, **kwargs: Any) -> os.stat_result:
        info = real_lstat(path, *args, **kwargs)
        if os.fspath(path) == paths.journal:
            seen["n"] += 1
            if seen["n"] == 2:
                planted = paths.journal + ".planted"
                planted_fd = os.open(
                    planted,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o400,
                )
                try:
                    os.write(
                        planted_fd,
                        subject.canonical_bytes(
                            {
                                "schema_version": 1,
                                "contract": subject.ATTEMPT_JOURNAL_CONTRACT,
                                "events": [],
                            }
                        ),
                    )
                    os.fchmod(planted_fd, 0o400)
                finally:
                    os.close(planted_fd)
                os.replace(planted, paths.journal)
        return info

    monkey = pytest.MonkeyPatch()
    monkey.setattr(os, "lstat", swap_after_lstat)
    try:
        with pytest.raises(subject.AttemptBrokerError, match="changed while being read"):
            subject.execute_attempt(
                request_bytes("connect-primary", "winn3", WINN3, correlation_id=CORR_B),
                host,
                paths,
            )
    finally:
        monkey.undo()

    swapped = tmp_path / "swapped-root"
    swapped.mkdir()
    host2, paths2 = make_env(swapped)
    seed_winn3(host2, paths2)
    decoy_dir = swapped / "decoy-run"
    decoy_dir.mkdir()
    os.chmod(decoy_dir, 0o700)
    os.remove(paths2.winn3_probe_out)
    os.rmdir(paths2.run_dir)
    os.symlink(decoy_dir, paths2.run_dir)
    with pytest.raises(subject.AttemptBrokerError, match="unsafe"):
        subject.execute_attempt(
            request_bytes("connect-primary", "winn3", WINN3), host2, paths2
        )


def test_non_root_peer_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    host.peer_uid = 1
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        left.sendall(request_bytes("connect-primary", "winn3", WINN3))
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(subject.AttemptBrokerError, match="peer is not root"):
            subject.handle_connection(right, host, paths)
    finally:
        left.close()
        right.close()
    assert host.runs == []
    assert not os.path.exists(paths.journal)


def test_stale_journal_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    _write_owned(
        paths.journal,
        subject.canonical_bytes(
            {
                "schema_version": 1,
                "contract": "winsvpn-gcp-proof-protocol-attempts-stale",
                "events": [],
            }
        ),
        0o400,
    )
    with pytest.raises(subject.AttemptBrokerError, match="stale|invalid"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)

    os.remove(paths.journal)
    unpaired = {
        "schema_version": 1,
        "contract": subject.ATTEMPT_JOURNAL_CONTRACT,
        "events": [
            {
                "action": "probe-awg-block",
                "correlation_id": CORR,
                "monotonic_ns": 2_000_000_000,
                "node": COVER,
                "phase": "started",
                "protocol": "awg",
                "result": "pending",
                "session_id": SESSION,
                "utc": "2026-08-24T12:00:01Z",
            }
        ],
    }
    _write_owned(paths.journal, subject.canonical_bytes(unpaired), 0o400)
    with pytest.raises(subject.AttemptBrokerError, match="stale"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)


def test_test_only_host_cannot_emit_production_output() -> None:
    host = FixtureHost()
    code, stdout, stderr = subject.run_argv([], host)
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"test host cannot emit production output" in stderr
    stderr.decode("ascii")
    assert b"PASS" not in stderr


def test_production_host_cannot_emit_pass_from_this_workstation() -> None:
    assert subject.ProductionHost.TEST_ONLY is False
    code, stdout, stderr = subject.run_argv([])
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    stderr.decode("ascii")
    assert b"PASS" not in stderr
    code, stdout, stderr = subject.run_argv(["--command=/bin/sh", "--path=/tmp"])
    assert code == subject.REFUSAL_EXIT
    assert stdout == b""
    assert b"argv must be empty" in stderr


def test_data_winn3_rejects_awg_and_xray(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path, role="data-winn3")
    seed_awg(host, paths)
    seed_xray(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="unexpected role"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="unexpected role"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    assert host.runs == []
    seed_winn3(host, paths)
    ack = subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert ack["protocol"] == "winn3"


def test_data_cover_rejects_winn3(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path, role="data-cover")
    seed_winn3(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="unexpected role"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert host.runs == []
    seed_awg(host, paths)
    ack = subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert ack["protocol"] == "awg"


def test_same_node_and_wrong_role_fallback_are_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    seed_awg(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="wrong-role"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", COVER), host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="wrong-role|same-node"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", WINN3), host, paths)
    os.remove(paths.fleet_binding)
    same = fleet_binding()
    same["data-cover"]["instance"] = WINN3
    _write_owned(paths.fleet_binding, subject.canonical_bytes(same), 0o400)
    with pytest.raises(subject.AttemptBrokerError, match="same-node"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_WINN3_PROBE not in host.runs
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs


def test_awg_handshake_success_is_not_recorded_as_failure(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(
        host,
        paths,
        handshake=int(datetime(2026, 8, 24, 12, 0, 1, tzinfo=timezone.utc).timestamp()),
    )
    with pytest.raises(subject.AttemptBrokerError, match="handshake"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert not os.path.exists(paths.journal)


def test_root_peer_roundtrip_writes_ack(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    host.peer_uid = 0
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        left.sendall(request_bytes("connect-primary", "winn3", WINN3))
        left.shutdown(socket.SHUT_WR)
        subject.handle_connection(right, host, paths)
        ack = helper.exact_keys(
            helper.strict_json(left.recv(65536), "protocol attempt acknowledgement"),
            {
                "action",
                "contract",
                "correlation_id",
                "node",
                "protocol",
                "session_id",
                "state",
            },
            "protocol attempt acknowledgement",
        )
        assert ack["state"] == "completed"
        assert ack["contract"] == helper.ATTEMPT_ACK_CONTRACT
    finally:
        left.close()
        right.close()


def test_closed_action_table_contains_only_exact_tuples() -> None:
    assert not hasattr(subject, "BIN_DOCKER")
    assert not hasattr(subject, "WINN3_ACTION_PATH")
    assert subject.ACTION_TABLE.keys() == {
        ("connect-primary", "winn3"),
        ("connect-cover-awg", "awg"),
        ("connect-cover-xray", "xray"),
        ("probe-awg-block", "awg"),
        ("probe-awg-block", "xray"),
        ("probe-winn3-block", "winn3"),
        ("probe-winn3-block", "awg"),
        ("probe-cover-withdrawn", "winn3"),
    }
    assert subject.ACTION_TABLE[("connect-primary", "winn3")]["executable"] == subject.WINN3_PROBE_BIN
    assert subject.ACTION_TABLE[("probe-awg-block", "awg")]["executable"] == subject.AMNEZIAWG_GO_BIN
    assert subject.ACTION_TABLE[("probe-awg-block", "xray")]["executable"] == subject.XRAY_BIN
    assert subject.ACTION_TABLE[("connect-primary", "winn3")]["finished_result"] == "connected"
    assert subject.ACTION_TABLE[("connect-cover-awg", "awg")]["finished_result"] == "connected"
    assert subject.ACTION_TABLE[("connect-cover-xray", "xray")]["finished_result"] == "connected"
    assert subject.ACTION_TABLE[("probe-awg-block", "awg")]["finished_result"] == "failed"
    assert subject.ACTION_TABLE[("probe-awg-block", "xray")]["finished_result"] == "connected"
    assert subject.ACTION_TABLE[("probe-winn3-block", "winn3")]["finished_result"] == "failed"
    assert subject.ACTION_TABLE[("probe-winn3-block", "awg")]["finished_result"] == "connected"
    assert subject.ACTION_TABLE[("probe-cover-withdrawn", "winn3")]["finished_result"] == "failed"
    assert (subject.BIN_SYSTEMCTL, "start", subject.UNIT_XRAY_SERVER) not in subject.ALLOWED_COMMANDS
    assert (subject.BIN_SYSTEMCTL, "start", "docker.service") not in subject.ALLOWED_COMMANDS
    for argv in subject.ALLOWED_COMMANDS:
        assert argv[0] in {subject.BIN_SYSTEMCTL, subject.BIN_IP, subject.BIN_AWG}
        assert all(isinstance(item, str) and item for item in argv)
        joined = " ".join(argv)
        assert "/bin/sh" not in joined
        assert " -c " not in f" {joined} "
        assert "docker" not in joined
        assert CONTROL not in argv
        assert WINN3 not in argv
        assert COVER not in argv


def test_docker_shell_and_arbitrary_path_commands_are_rejected() -> None:
    host = FixtureHost()
    forbidden = (
        ("/usr/bin/docker", "start", "amnezia-awg2"),
        ("/bin/sh", "-c", "true"),
        ("/usr/local/libexec/winn/winn3-gateway",),
        ("/tmp/winsvpn-proof-action", "--path=/etc/winn/credentials"),
        (subject.WINN3_PROBE_BIN, "--success"),
        (subject.BIN_SYSTEMCTL, "start", "docker.service"),
        (subject.BIN_SYSTEMCTL, "start", "xray.service"),
    )
    for argv in forbidden:
        with pytest.raises(subject.AttemptBrokerError, match="not allowlisted"):
            subject.run_allowlisted(host, argv)
        assert argv not in subject.ALLOWED_COMMANDS
    assert host.runs == []


def test_unprovisioned_winn3_material_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    host.commands[subject.ARGV_SYSTEMCTL_START_WINN3_PROBE] = subject.CommandResult()
    host.commands[subject.ARGV_SYSTEMCTL_SHOW_WINN3_PROBE] = subject.CommandResult(
        show_oneshot(subject.UNIT_WINN3_PROBE, WINN3_FRAGMENT)
    )
    with pytest.raises(subject.AttemptBrokerError, match="unreadable|unprovisioned|empty"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert host.runs == []
    assert not os.path.exists(paths.journal)


def test_leftover_awg_client_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths, leftover=True)
    with pytest.raises(subject.AttemptBrokerError, match="leftover AWG"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_xray_after_mismatched_awg_session_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths)
    subject.execute_attempt(
        request_bytes("probe-awg-block", "awg", COVER, session_id=SESSION_B),
        host,
        paths,
    )
    before = subject.load_attempt_journal(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="AWG-first"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT not in host.runs
    after = subject.load_attempt_journal(host, paths)
    assert after == before


def test_winn3_peer_mismatch_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    os.remove(paths.winn3_probe_out)
    _write_owned(
        paths.winn3_probe_out,
        winn3_probe_output(gateway="10.240.0.11:443"),
        0o400,
    )
    with pytest.raises(subject.AttemptBrokerError, match="inconsistent"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert not os.path.exists(paths.journal)


def test_xray_zero_byte_stats_are_not_synthetic_success(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths, rx=0, tx=0)
    subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    before = subject.load_attempt_journal(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="carried-byte"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    after = subject.load_attempt_journal(host, paths)
    assert after == before
    assert [event["result"] for event in after["events"]] == ["pending", "failed"]


def test_documentation_winn3_gateway_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    provision_winn3(paths, gateway="192.0.2.10:443")
    with pytest.raises(subject.AttemptBrokerError, match="unprovisioned"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert host.runs == []
    assert not os.path.exists(paths.journal)


def test_winn3_gateway_id_must_match_fleet_data_winn3(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    provision_winn3(paths)
    env = (
        f"WINN3_PROOF_GW={WINN3_GW}\n"
        "WINN3_PROOF_GATEWAY_ID=gateway-01\n"
        f"WINN3_PROOF_ED_PUB={HEX64}\n"
        f"WINN3_PROOF_ML_PUB={HEX3904}\n"
    )
    os.remove(paths.winn3_probe_env)
    _write_owned(paths.winn3_probe_env, env.encode("ascii"), 0o400)
    with pytest.raises(subject.AttemptBrokerError, match="unprovisioned"):
        subject.execute_attempt(request_bytes("connect-primary", "winn3", WINN3), host, paths)
    assert host.runs == []
    assert not os.path.exists(paths.journal)


def test_placeholder_awg_config_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    os.remove(paths.awg_client_conf)
    _write_owned(
        paths.awg_client_conf,
        (TOOLS / "gcp_proof_attempt_broker" / "awg0.conf.example").read_bytes(),
        0o400,
    )
    with pytest.raises(subject.AttemptBrokerError, match="unprovisioned"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_awg_config_missing_key_beside_an_extra_key_is_unprovisioned() -> None:
    # R22 Y3-11: provisioned configs always carry PersistentKeepalive, so a
    # strict-subset test never fired and a missing key became KeyError.
    valid = (
        "[Interface]\n"
        f"Address = {subject.PROOF_CLIENT_INNER_V4}/32\n"
        f"PrivateKey = {AWG_PRIVATE}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {AWG_PEER}\n"
        "Endpoint = 10.240.0.20:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
        "PersistentKeepalive = 25\n"
    )
    assert "Peer.PersistentKeepalive" in subject._parse_awg_client_conf(valid.encode("ascii"))
    for line in (
        "AllowedIPs = 0.0.0.0/0\n",
        "Endpoint = 10.240.0.20:51820\n",
        f"PublicKey = {AWG_PEER}\n",
        f"PrivateKey = {AWG_PRIVATE}\n",
    ):
        assert line in valid
        with pytest.raises(subject.AttemptBrokerError, match="unprovisioned"):
            subject._parse_awg_client_conf(valid.replace(line, "").encode("ascii"))


def test_placeholder_xray_config_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    seed_xray(host, paths)
    os.remove(paths.xray_client_conf)
    _write_owned(
        paths.xray_client_conf,
        (TOOLS / "gcp_proof_attempt_broker" / "xray-client.json").read_bytes(),
        0o400,
    )
    subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    before = subject.load_attempt_journal(host, paths)
    with pytest.raises(subject.AttemptBrokerError, match="unprovisioned"):
        subject.execute_attempt(request_bytes("probe-awg-block", "xray", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT not in host.runs
    after = subject.load_attempt_journal(host, paths)
    assert after == before


def _track_simple_unit(
    host: FixtureHost,
    *,
    start: tuple[str, ...],
    stop: tuple[str, ...],
    active: tuple[str, ...],
    stop_exit: int = 0,
) -> dict[str, bool]:
    state = {"up": False}
    real_run = host.run

    def run(argv: list[str]) -> subject.CommandResult:
        key = tuple(argv)
        if key == start:
            result = real_run(argv)
            if result.exit_code == 0:
                state["up"] = True
            return result
        if key == stop:
            host.runs.append(key)
            if stop_exit == 0:
                state["up"] = False
            return subject.CommandResult(b"", b"failed\n" if stop_exit else b"", stop_exit)
        if key == active:
            if state["up"]:
                host.runs.append(key)
                return subject.CommandResult(b"active\n")
            return real_run(argv)
        return real_run(argv)

    host.run = run  # type: ignore[method-assign]
    return state


def test_hostile_world_readable_proof_client_material_is_rejected(tmp_path: Path) -> None:
    assert subject.PROOF_CLIENT_MODE == 0o400
    cases: list[tuple[str, str, str, str, Any, Any, int]] = []
    for mode, tag in ((0o444, "world"), (0o404, "other"), (0o440, "group"), (0o600, "owner-write")):
        cases.append(
            (
                f"awg-conf-{tag}",
                "probe-awg-block",
                "awg",
                COVER,
                seed_awg,
                lambda paths: paths.awg_client_conf,
                mode,
            )
        )
        cases.append(
            (
                f"xray-conf-{tag}",
                "connect-cover-xray",
                "xray",
                COVER,
                seed_xray,
                lambda paths: paths.xray_client_conf,
                mode,
            )
        )
    cases.extend(
        (
            (
                f"winn3-{name}",
                "connect-primary",
                "winn3",
                WINN3,
                seed_winn3,
                lambda paths, leaf=name: os.path.join(paths.proof_client_dir, leaf),
                0o444,
            )
            for name, _size, _pattern in subject.PROOF_CLIENT_FILES
        )
    )
    cases.extend(
        [
            (
                "winn3-env",
                "connect-primary",
                "winn3",
                WINN3,
                seed_winn3,
                lambda paths: paths.winn3_probe_env,
                0o444,
            ),
            (
                "xray-env",
                "connect-cover-xray",
                "xray",
                COVER,
                seed_xray,
                lambda paths: paths.xray_probe_env,
                0o444,
            ),
        ]
    )
    for label, action, protocol, node, seeder, path_of, mode in cases:
        host, paths = make_env(tmp_path / label)
        seeder(host, paths)
        target = path_of(paths)
        os.chmod(target, mode)
        assert stat.S_IMODE(os.lstat(target).st_mode) == mode
        with pytest.raises(subject.AttemptBrokerError, match="ownership or mode"):
            subject.execute_attempt(request_bytes(action, protocol, node), host, paths)
        assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
        assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT not in host.runs
        assert subject.ARGV_SYSTEMCTL_START_WINN3_PROBE not in host.runs
        assert not os.path.exists(paths.journal)


def test_proof_client_wrong_owner_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    host.root_gid = host.root_gid + 1
    with pytest.raises(subject.AttemptBrokerError, match="ownership or mode"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_journal_write_failure_stops_awg_and_allows_retry(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_AWG_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
    )
    monkey = pytest.MonkeyPatch()
    monkey.setattr(
        subject,
        "_atomic_write_journal",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subject.AttemptBrokerError("protocol attempt journal write failed")
        ),
    )
    try:
        with pytest.raises(subject.AttemptBrokerError, match="journal write failed"):
            subject.execute_attempt(
                request_bytes("probe-awg-block", "awg", COVER), host, paths
            )
        assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT in host.runs
        assert subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT in host.runs
        assert state["up"] is False
        assert not os.path.exists(paths.journal)
    finally:
        monkey.undo()
    ack = subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert ack["protocol"] == "awg"
    assert ack["state"] == "completed"
    journal = subject.load_attempt_journal(host, paths)
    assert [event["result"] for event in journal["events"]] == ["pending", "failed"]


def test_journal_write_failure_stops_xray_and_allows_retry(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_xray(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT,
    )
    monkey = pytest.MonkeyPatch()
    monkey.setattr(
        subject,
        "_atomic_write_journal",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            subject.AttemptBrokerError("protocol attempt journal write failed")
        ),
    )
    try:
        with pytest.raises(subject.AttemptBrokerError, match="journal write failed"):
            subject.execute_attempt(
                request_bytes("connect-cover-xray", "xray", COVER), host, paths
            )
        assert subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT in host.runs
        assert subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT in host.runs
        assert subject.ARGV_SYSTEMCTL_STOP_XRAY_PROBE in host.runs
        assert state["up"] is False
        assert not os.path.exists(paths.journal)
    finally:
        monkey.undo()
    ack = subject.execute_attempt(
        request_bytes("connect-cover-xray", "xray", COVER), host, paths
    )
    assert ack["protocol"] == "xray"
    assert ack["state"] == "completed"
    journal = subject.load_attempt_journal(host, paths)
    assert [event["result"] for event in journal["events"]] == ["pending", "connected"]


def test_journal_validation_failure_stops_awg_and_allows_retry(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_AWG_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
    )
    original_utc = host.utc_now
    host.utc_now = lambda: "2026-08-24T12:00:01.000000000Z"
    try:
        with pytest.raises(subject.AttemptBrokerError, match="strictly ordered"):
            subject.execute_attempt(
                request_bytes("probe-awg-block", "awg", COVER), host, paths
            )
        assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT in host.runs
        assert subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT in host.runs
        assert state["up"] is False
        assert not os.path.exists(paths.journal)
    finally:
        host.utc_now = original_utc
    ack = subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert ack["state"] == "completed"
    assert state["up"] is False


def test_identity_binds_uid_gid_and_inode(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    info = os.lstat(paths.role)
    ident = subject._identity(info)
    assert ident[0] == info.st_dev
    assert ident[1] == info.st_ino
    assert ident[2] == info.st_uid
    assert ident[3] == info.st_gid
    assert ident[2] == host.root_uid
    assert ident[3] == host.root_gid


def test_production_hash_executable_accepts_ubuntu_0755_and_refuses_writable(
    tmp_path: Path,
) -> None:
    host = subject.ProductionHost()
    host.root_uid = os.getuid()
    host.root_gid = os.getgid()
    payload = b"\x7fELFping-ubuntu\n"
    path = str(tmp_path / "ping")
    _write_owned(path, payload, 0o755)
    digest = host.hash_executable(path)
    assert digest == subject.sha256_bytes(payload)
    os.chmod(path, 0o555)
    assert host.hash_executable(path) == digest
    os.chmod(path, 0o755)
    bound = os.lstat(path)
    ident = subject._identity(bound)
    assert ident[1] == bound.st_ino
    assert ident[2] == host.root_uid
    assert ident[3] == host.root_gid
    for mode in (0o775, 0o757, 0o777, 0o644):
        os.chmod(path, mode)
        with pytest.raises(subject.AttemptBrokerError, match="ownership or mode"):
            host.hash_executable(path)


def test_stop_exit_1_surfaces_cleanup_failure_and_is_not_false_success(
    tmp_path: Path,
) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_AWG_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
        stop_exit=1,
    )
    with pytest.raises(subject.AttemptBrokerError, match="runtime cleanup failed|unable to stop"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT in host.runs
    assert subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT in host.runs
    assert state["up"] is True
    assert not os.path.exists(paths.journal)
    with pytest.raises(subject.AttemptBrokerError, match="leftover AWG|runtime cleanup failed|unable to stop"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)


def test_stop_exit_127_surfaces_cleanup_failure(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_AWG_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
        stop_exit=127,
    )
    with pytest.raises(subject.AttemptBrokerError, match="runtime cleanup failed|absent tool"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT in host.runs
    assert state["up"] is True
    assert not os.path.exists(paths.journal)


def test_xray_cleanup_attempts_all_units_when_probe_stop_fails(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_xray(host, paths)
    host.commands[subject.ARGV_SYSTEMCTL_STOP_XRAY_PROBE] = subject.CommandResult(
        b"", b"failed\n", 1
    )
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT,
    )
    with pytest.raises(subject.AttemptBrokerError, match="runtime cleanup failed"):
        subject.execute_attempt(request_bytes("connect-cover-xray", "xray", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_STOP_XRAY_PROBE in host.runs
    assert subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT in host.runs
    assert state["up"] is False
    assert not os.path.exists(paths.journal)


def test_successful_awg_phases_release_runtime_unit_before_ack(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths, handshake=1, rx=128, tx=256)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_AWG_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_AWG_CLIENT,
    )
    first = subject.execute_attempt(
        request_bytes("connect-cover-awg", "awg", COVER), host, paths
    )
    assert first["state"] == "completed"
    assert first["action"] == "connect-cover-awg"
    assert state["up"] is False
    assert subject.ARGV_SYSTEMCTL_STOP_AWG_CLIENT in host.runs
    host.commands[subject.ARGV_AWG_HANDSHAKES] = subject.CommandResult(
        f"{AWG_PEER} 0\n".encode("ascii")
    )
    host.commands[subject.ARGV_AWG_TRANSFER] = subject.CommandResult(
        f"{AWG_PEER} 0 0\n".encode("ascii")
    )
    second = subject.execute_attempt(
        request_bytes("probe-awg-block", "awg", COVER, correlation_id=CORR_B),
        host,
        paths,
    )
    assert second["state"] == "completed"
    assert second["action"] == "probe-awg-block"
    assert state["up"] is False
    events = subject.load_attempt_journal(host, paths)["events"]
    assert [
        (event["action"], event["protocol"], event["result"], event["phase"])
        for event in events
    ] == [
        ("connect-cover-awg", "awg", "pending", "started"),
        ("connect-cover-awg", "awg", "connected", "finished"),
        ("probe-awg-block", "awg", "pending", "started"),
        ("probe-awg-block", "awg", "failed", "finished"),
    ]
    assert_closed_runs(host)


def test_successful_xray_releases_runtime_unit_before_ack(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_xray(host, paths)
    state = _track_simple_unit(
        host,
        start=subject.ARGV_SYSTEMCTL_START_XRAY_CLIENT,
        stop=subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT,
        active=subject.ARGV_SYSTEMCTL_ACTIVE_XRAY_CLIENT,
    )
    ack = subject.execute_attempt(
        request_bytes("connect-cover-xray", "xray", COVER), host, paths
    )
    assert ack["state"] == "completed"
    assert state["up"] is False
    assert subject.ARGV_SYSTEMCTL_STOP_XRAY_CLIENT in host.runs
    assert subject.ARGV_SYSTEMCTL_STOP_XRAY_PROBE in host.runs
    assert_closed_runs(host)


def test_proof_client_symlink_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    real = paths.proof_client_dir + ".real"
    os.rename(paths.proof_client_dir, real)
    os.symlink(real, paths.proof_client_dir)
    with pytest.raises(subject.AttemptBrokerError, match="unsafe"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_proof_client_parent_symlink_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    parent = os.path.dirname(paths.proof_client_dir)
    real = parent + ".real"
    os.rename(parent, real)
    os.symlink(real, parent)
    with pytest.raises(subject.AttemptBrokerError, match="unsafe"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_proof_client_0777_directory_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    os.chmod(paths.proof_client_dir, 0o777)
    with pytest.raises(subject.AttemptBrokerError, match="ownership or mode|unsafe"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_SYSTEMCTL_START_AWG_CLIENT not in host.runs
    assert not os.path.exists(paths.journal)


def test_proof_client_path_swap_before_setconf_is_rejected(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_awg(host, paths)
    original = Path(paths.awg_client_conf).read_bytes()
    real_run = host.run

    def swap_after_start(argv: list[str]) -> subject.CommandResult:
        key = tuple(argv)
        if key == subject.ARGV_SYSTEMCTL_START_AWG_CLIENT:
            planted = paths.awg_client_conf + ".planted"
            planted_fd = os.open(
                planted,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o400,
            )
            try:
                os.write(planted_fd, original + b"# swapped\n")
                os.fchmod(planted_fd, 0o400)
            finally:
                os.close(planted_fd)
            os.replace(planted, paths.awg_client_conf)
        return real_run(argv)

    host.run = swap_after_start  # type: ignore[method-assign]
    with pytest.raises(subject.AttemptBrokerError, match="changed while being used"):
        subject.execute_attempt(request_bytes("probe-awg-block", "awg", COVER), host, paths)
    assert subject.ARGV_AWG_SETCONF not in host.runs
    assert not os.path.exists(paths.journal)


def test_role_fleet_journal_and_probe_out_modes_are_enforced(tmp_path: Path) -> None:
    cases: list[tuple[str, str, Any, int]] = [
        ("role", "connect-primary", seed_winn3, 0o444),
        ("fleet_binding", "connect-primary", seed_winn3, 0o444),
        ("journal", "connect-primary", seed_winn3, 0o444),
        ("winn3_probe_out", "connect-primary", seed_winn3, 0o444),
        ("role", "connect-primary", seed_winn3, 0o600),
        ("fleet_binding", "probe-awg-block", seed_awg, 0o644),
    ]
    for attr, action, seeder, mode in cases:
        host, paths = make_env(tmp_path / f"{attr}-{mode:o}")
        seeder(host, paths)
        protocol = "awg" if action == "probe-awg-block" else "winn3"
        node = COVER if protocol == "awg" else WINN3
        if attr == "journal":
            _write_owned(
                paths.journal,
                subject.canonical_bytes(
                    {
                        "schema_version": 1,
                        "contract": subject.ATTEMPT_JOURNAL_CONTRACT,
                        "events": [],
                    }
                ),
                0o400,
            )
        target = getattr(paths, attr)
        os.chmod(target, mode)
        assert stat.S_IMODE(os.lstat(target).st_mode) == mode
        with pytest.raises(subject.AttemptBrokerError, match="ownership or mode"):
            subject.execute_attempt(request_bytes(action, protocol, node), host, paths)
        if attr in {"role", "fleet_binding", "journal"}:
            assert host.runs == []
        if attr != "journal":
            assert not os.path.exists(paths.journal)


def test_probe_out_0600_is_accepted(tmp_path: Path) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    os.chmod(paths.winn3_probe_out, 0o600)
    ack = subject.execute_attempt(
        request_bytes("connect-primary", "winn3", WINN3), host, paths
    )
    assert ack["state"] == "completed"


def test_journal_temp_unlink_failure_is_not_swallowed_as_retryable_write(
    tmp_path: Path,
) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)

    def rename_fail(*args: Any, **kwargs: Any) -> None:
        raise OSError("injected rename failure")

    real_unlink = os.unlink

    def unlink_guard(path: str, *args: Any, **kwargs: Any) -> None:
        name = path if isinstance(path, str) else str(path)
        if name.startswith(".protocol-attempts."):
            raise OSError("injected unlink failure")
        return real_unlink(path, *args, **kwargs)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(os, "rename", rename_fail)
    monkey.setattr(os, "unlink", unlink_guard)
    try:
        with pytest.raises(subject.AttemptBrokerError, match="journal cleanup failed"):
            subject.execute_attempt(
                request_bytes("connect-primary", "winn3", WINN3), host, paths
            )
        assert not os.path.exists(paths.journal)
    finally:
        monkey.undo()


def test_parent_fsync_failure_after_rename_is_not_retryable_generic_write(
    tmp_path: Path,
) -> None:
    host, paths = make_env(tmp_path)
    seed_winn3(host, paths)
    request = request_bytes("connect-primary", "winn3", WINN3)
    real_fsync = os.fsync

    def fsync_fail_directory(fd: int) -> None:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            raise OSError("injected parent fsync failure")
        return real_fsync(fd)

    monkey = pytest.MonkeyPatch()
    monkey.setattr(os, "fsync", fsync_fail_directory)
    try:
        with pytest.raises(
            subject.AttemptBrokerError,
            match="committed but directory fsync is uncertain",
        ) as first:
            subject.execute_attempt(request, host, paths)
        message = str(first.value)
        assert "journal write failed" not in message
        assert "journal cleanup failed" not in message
        journal = subject.load_attempt_journal(host, paths)
        assert [event["result"] for event in journal["events"]] == ["pending", "connected"]
        leftovers = [
            name
            for name in os.listdir(paths.run_dir)
            if name.startswith(".protocol-attempts.")
        ]
        assert leftovers == []
    finally:
        monkey.undo()
    with pytest.raises(
        subject.AttemptBrokerError, match="duplicate protocol attempt is forbidden"
    ) as retry:
        subject.execute_attempt(request, host, paths)
    assert "journal write failed" not in str(retry.value)
    after = subject.load_attempt_journal(host, paths)
    assert after == journal


BROKER_UNIT = (
    TOOLS / "gcp_proof_attempt_broker" / "winsvpn-gcp-proof-attempt-broker.service"
)


def _broker_unit_assignments() -> dict[str, str]:
    assignments: dict[str, str] = {}
    for raw in BROKER_UNIT.read_text(encoding="ascii").splitlines():
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        assignments[key] = value
    return assignments


def test_broker_unit_allows_netlink_witness_with_minimum_cap_net_admin() -> None:
    unit = _broker_unit_assignments()
    assert unit["RestrictAddressFamilies"] == "AF_UNIX AF_NETLINK"
    assert unit["CapabilityBoundingSet"] == "CAP_NET_ADMIN"
    assert unit["AmbientCapabilities"] == ""
    assert unit["NoNewPrivileges"] == "yes"
    assert unit["PrivateTmp"] == "yes"
    assert unit["PrivateDevices"] == "yes"
    assert unit["ProtectHome"] == "yes"
    assert unit["ProtectSystem"] == "strict"
    assert unit["MemoryDenyWriteExecute"] == "yes"
    assert unit["RestrictNamespaces"] == "yes"


def test_hostile_broker_unit_rejects_extra_families_and_ambient_admin() -> None:
    unit = _broker_unit_assignments()
    families = unit["RestrictAddressFamilies"].split()
    assert families == ["AF_UNIX", "AF_NETLINK"]
    assert unit["CapabilityBoundingSet"].split() == ["CAP_NET_ADMIN"]
    assert unit["AmbientCapabilities"] == ""
    assert "AF_INET" not in families
    assert "AF_INET6" not in families
    assert "AF_PACKET" not in families
    caps = unit["CapabilityBoundingSet"].split()
    assert "CAP_NET_RAW" not in caps
    assert "CAP_SYS_ADMIN" not in caps
    assert "CAP_NET_BIND_SERVICE" not in caps
